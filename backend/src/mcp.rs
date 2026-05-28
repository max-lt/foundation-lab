//! MCP server (HTTP+SSE transport) exposing ql-link-lab to a model client.
//!
//! Topology:  Claude (mcp client) ──HTTP+SSE──► THIS ──(rpc/chat)──► device
//!
//! Two endpoints:
//!
//!   GET  /sse                   — opens the SSE stream the client reads
//!                                 server-pushed JSON-RPC messages from
//!                                 (notifications + responses). On open
//!                                 the server emits an `endpoint` event
//!                                 with the URL the client must POST to.
//!   POST /messages?id=<uuid>    — client→server JSON-RPC (initialize,
//!                                 tools/list, tools/call). Responses are
//!                                 delivered back through the SSE stream.
//!
//! Tools exposed:
//!   - `chat_send(text)`         — push a ChatPush to the device
//!   - `session_status()`        — current PeerStatus + bt_connected
//!   - `chat_history(limit)`     — last N messages we've seen
//!
//! Notifications pushed by the server (over SSE):
//!   - `notifications/message`   — JSON payload describing each backend
//!                                 event (chat received, echo handled,
//!                                 status change, benchmark completed).
//!
//! Designed for a single concurrent MCP client; localhost-only, no auth.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use ql_api::{route, EchoRequest};
use ql_fsm::PeerStatus;
use ql_runtime::RuntimeHandle;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

/// Events the backend emits and the MCP server forwards to the model.
#[derive(Clone, Debug)]
pub enum BackendEvent {
    ChatReceived { text: String },
    ChatPushed { text: String },
    EchoHandled { request: String, response: String, ms: u128 },
    StatusChanged { state: PeerStatus, bt_connected: bool, peer_known: bool },
    BenchmarkCompleted { bytes: usize, secs: f64 },
    DownloadCompleted { bytes: usize, secs: f64, sha256_hex: String },
}

impl BackendEvent {
    fn to_json(&self) -> Value {
        match self {
            BackendEvent::ChatReceived { text } => json!({
                "event": "chat.received",
                "text": text,
            }),
            BackendEvent::ChatPushed { text } => json!({
                "event": "chat.pushed",
                "text": text,
            }),
            BackendEvent::EchoHandled { request, response, ms } => json!({
                "event": "echo.handled",
                "request": request,
                "response": response,
                "ms": ms,
            }),
            BackendEvent::StatusChanged { state, bt_connected, peer_known } => json!({
                "event": "session.status_changed",
                "state": format!("{state:?}"),
                "bt_connected": bt_connected,
                "peer_known": peer_known,
            }),
            BackendEvent::BenchmarkCompleted { bytes, secs } => json!({
                "event": "benchmark.completed",
                "bytes": bytes,
                "secs": secs,
                "kibs": (*bytes as f64 / 1024.0) / secs,
            }),
            BackendEvent::DownloadCompleted { bytes, secs, sha256_hex } => json!({
                "event": "download.completed",
                "bytes": bytes,
                "secs": secs,
                "sha256": sha256_hex,
            }),
        }
    }
}

/// Cap of in-memory chat history (oldest are dropped past this).
const CHAT_HISTORY_LIMIT: usize = 512;

#[derive(Clone)]
pub struct McpState {
    /// Broadcast of all backend events. Each SSE session subscribes.
    pub events_tx: broadcast::Sender<BackendEvent>,
    /// Active QL2 runtime handle, used to invoke RPC from MCP tools.
    pub handle: RuntimeHandle,
    /// Rolling chat history (so a freshly-connected client can replay).
    pub history: Arc<Mutex<Vec<ChatEntry>>>,
    /// Last known session status snapshot.
    pub status: Arc<Mutex<StatusSnapshot>>,
    /// Per-SSE-session response queue. POSTed JSON-RPC results land here.
    sessions: Arc<Mutex<HashMap<Uuid, mpsc::Sender<SseEvent>>>>,
    /// Most recently active SSE session — server-initiated requests
    /// (e.g. `sampling/createMessage`) target this one.
    primary_session: Arc<Mutex<Option<mpsc::Sender<SseEvent>>>>,
    /// JSON-RPC id counter for server-initiated requests.
    next_request_id: Arc<AtomicI64>,
    /// Pending server-initiated requests, keyed by JSON-RPC id. When the
    /// client POSTs a response, we look it up here and unblock the waiter.
    pending: Arc<Mutex<HashMap<i64, oneshot::Sender<Value>>>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatEntry {
    pub direction: ChatDirection,
    pub text: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatDirection {
    DeviceToBackend,
    BackendToDevice,
}

#[derive(Clone, Debug, Default)]
pub struct StatusSnapshot {
    pub peer_status: Option<PeerStatus>,
    pub bt_connected: bool,
    pub peer_known: bool,
}

impl McpState {
    pub fn new(handle: RuntimeHandle, events_tx: broadcast::Sender<BackendEvent>) -> Self {
        Self {
            events_tx,
            handle,
            history: Arc::new(Mutex::new(Vec::new())),
            status: Arc::new(Mutex::new(StatusSnapshot::default())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            primary_session: Arc::new(Mutex::new(None)),
            next_request_id: Arc::new(AtomicI64::new(1)),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn record_chat(&self, entry: ChatEntry) {
        let mut h = self.history.lock().unwrap();
        h.push(entry);
        let len = h.len();
        if len > CHAT_HISTORY_LIMIT {
            h.drain(..len - CHAT_HISTORY_LIMIT);
        }
    }

    /// Send `sampling/createMessage` to the active MCP client and await the
    /// model's reply. Requires a client that implements the sampling
    /// capability (MCP Inspector, Cline, ContinueDev; NOT Claude Code as of
    /// 2026-05). Times out after 60s.
    pub async fn sample(
        &self,
        prompt: &str,
        system_prompt: Option<&str>,
        max_tokens: u32,
    ) -> Result<String, String> {
        let session_tx = self
            .primary_session
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "no MCP client connected".to_string())?;

        let id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (resp_tx, resp_rx) = oneshot::channel::<Value>();
        self.pending.lock().unwrap().insert(id, resp_tx);

        let mut params = json!({
            "messages": [{
                "role": "user",
                "content": {"type": "text", "text": prompt},
            }],
            "maxTokens": max_tokens,
        });
        if let Some(sys) = system_prompt {
            params["systemPrompt"] = json!(sys);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "sampling/createMessage",
            "params": params,
        });

        if session_tx
            .send(SseEvent::default().event("message").data(request.to_string()))
            .await
            .is_err()
        {
            self.pending.lock().unwrap().remove(&id);
            return Err("SSE session closed before sampling request sent".to_string());
        }

        let response = tokio::time::timeout(Duration::from_secs(60), resp_rx)
            .await
            .map_err(|_| {
                self.pending.lock().unwrap().remove(&id);
                "sampling timed out (60s)".to_string()
            })?
            .map_err(|_| "sampling response channel closed".to_string())?;

        if let Some(err) = response.get("error") {
            return Err(format!("sampling client error: {err}"));
        }
        response
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
            .map(String::from)
            .ok_or_else(|| format!("unexpected sampling response shape: {response}"))
    }
}

/// Auto-reply task: when a chat message comes in from the device, ask
/// the connected MCP client's LLM for a reply via `sampling/createMessage`
/// and push it to the device as a `ChatPush`. Requires a sampling-capable
/// MCP client (MCP Inspector, Cline, etc. — not Claude Code yet).
pub async fn run_chat_auto_reply(state: McpState) {
    let mut rx = state.events_tx.subscribe();
    let system_prompt =
        "You are an AI assistant chatting with a KeyOS Passport Prime hardware wallet user. \
         Keep replies short (one or two sentences), warm, and informational. \
         You are bridged via QL v2 → relay → ql-link-lab backend → MCP sampling.";
    while let Ok(event) = rx.recv().await {
        if let BackendEvent::ChatReceived { text } = event {
            log::info!("[auto-reply] device → backend: {text:?} — calling sampling");
            match state.sample(&text, Some(system_prompt), 200).await {
                Ok(reply) => {
                    log::info!("[auto-reply] sampling reply: {reply:?}");
                    #[cfg(feature = "chat")]
                    {
                        match state.handle.rpc().notification::<crate::ChatPush>(&reply).await {
                            Ok(()) => {
                                let _ = state
                                    .events_tx
                                    .send(BackendEvent::ChatPushed { text: reply });
                            }
                            Err(e) => log::warn!("[auto-reply] ChatPush failed: {e:?}"),
                        }
                    }
                }
                Err(e) => log::warn!("[auto-reply] sampling failed: {e}"),
            }
        }
    }
}

/// Wire the broadcast events into the rolling history + status snapshot.
/// Run alongside any subscribers so disconnected clients don't drop events.
pub async fn run_event_recorder(state: McpState) {
    let mut rx = state.events_tx.subscribe();
    while let Ok(event) = rx.recv().await {
        match &event {
            BackendEvent::ChatReceived { text } => state.record_chat(ChatEntry {
                direction: ChatDirection::DeviceToBackend,
                text: text.clone(),
            }),
            BackendEvent::ChatPushed { text } => state.record_chat(ChatEntry {
                direction: ChatDirection::BackendToDevice,
                text: text.clone(),
            }),
            BackendEvent::StatusChanged { state: peer_state, bt_connected, peer_known } => {
                let mut s = state.status.lock().unwrap();
                s.peer_status = Some(*peer_state);
                s.bt_connected = *bt_connected;
                s.peer_known = *peer_known;
            }
            _ => {}
        }
    }
}

pub async fn serve(addr: SocketAddr, state: McpState) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/sse", get(sse_handler))
        .route("/messages", post(messages_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("[mcp] server listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

// ===== SSE endpoint =====

async fn sse_handler(
    State(state): State<McpState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let session_id = Uuid::new_v4();
    let (tx, rx) = mpsc::channel::<SseEvent>(64);

    // Initial `endpoint` event tells the MCP client where to POST.
    let endpoint_url = format!("/messages?id={session_id}");
    let _ = tx
        .send(SseEvent::default().event("endpoint").data(endpoint_url))
        .await;

    // Register this session so POST /messages can route replies back here.
    state.sessions.lock().unwrap().insert(session_id, tx.clone());
    // Also make this the primary session for server-initiated requests
    // (sampling/createMessage). Last writer wins — fine for our single-
    // client localhost setup.
    *state.primary_session.lock().unwrap() = Some(tx.clone());

    // Spawn a task that forwards backend events as MCP notifications.
    let mut events_rx = state.events_tx.subscribe();
    let notif_tx = tx.clone();
    tokio::spawn(async move {
        while let Ok(event) = events_rx.recv().await {
            let payload = json!({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": "info",
                    "data": event.to_json(),
                },
            });
            let sse = SseEvent::default()
                .event("message")
                .data(payload.to_string());
            if notif_tx.send(sse).await.is_err() {
                break;
            }
        }
    });

    // Cleanup on disconnect: drop the session entry.
    let sessions_for_cleanup = state.sessions.clone();
    let stream = ReceiverStream::new(rx).map(Ok::<_, Infallible>).chain(
        // When the channel closes, run cleanup (this branch never yields).
        futures_lite::stream::iter(std::iter::empty()).map(move |_: ()| {
            sessions_for_cleanup.lock().unwrap().remove(&session_id);
            unreachable!()
        }),
    );

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

// ===== POST /messages — JSON-RPC requests OR responses from the client =====

#[derive(Deserialize)]
struct MsgQuery {
    id: Uuid,
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

async fn messages_handler(
    State(state): State<McpState>,
    Query(query): Query<MsgQuery>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let session_tx = match state.sessions.lock().unwrap().get(&query.id).cloned() {
        Some(tx) => tx,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown session id"})),
            )
                .into_response();
        }
    };

    // A JSON-RPC payload with `method` is a request from client to server.
    // A payload with `result` or `error` (and no `method`) is a response
    // to a server-initiated request — route it to the pending waiter.
    if body.get("method").is_some() {
        let req: JsonRpcRequest = match serde_json::from_value(body) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("malformed JSON-RPC request: {e}")})),
                )
                    .into_response();
            }
        };
        let response = dispatch(&state, &req).await;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "result": response,
        });
        let sse = SseEvent::default().event("message").data(payload.to_string());
        let _ = session_tx.send(sse).await;
    } else if let Some(id) = body.get("id").and_then(|v| v.as_i64()) {
        // Response to a server-initiated request (e.g. sampling/createMessage).
        if let Some(waiter) = state.pending.lock().unwrap().remove(&id) {
            let _ = waiter.send(body);
        } else {
            log::warn!("[mcp] response for unknown request id={id}");
        }
    } else {
        log::warn!("[mcp] payload is neither request nor response: {body}");
    }

    StatusCode::ACCEPTED.into_response()
}

async fn dispatch(state: &McpState, req: &JsonRpcRequest) -> Value {
    match req.method.as_str() {
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {},
                "logging": {},
            },
            "serverInfo": {
                "name": "ql-link-lab",
                "version": env!("CARGO_PKG_VERSION"),
            },
        }),
        "tools/list" => json!({
            "tools": [
                {
                    "name": "chat_send",
                    "description": "Push a one-line chat message from the backend to the paired KeyOS device (route 101 / ChatPush).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "description": "Message body"},
                        },
                        "required": ["text"],
                    },
                },
                {
                    "name": "session_status",
                    "description": "Return the current QL v2 session status (peer state, bt link, peer known).",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chat_history",
                    "description": "Return the last N chat messages (both directions) the backend has seen since startup.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "minimum": 1, "maximum": 512, "default": 50},
                        },
                    },
                },
                {
                    "name": "send_echo",
                    "description": "Drive the device's Echo RPC (route 1). Useful to verify round-trip.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string"},
                        },
                        "required": ["text"],
                    },
                },
                {
                    "name": "sample",
                    "description": "Issue a sampling/createMessage request back to the connected MCP client and return its reply. Requires a sampling-capable client (MCP Inspector, Cline, etc).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "prompt": {"type": "string"},
                            "system_prompt": {"type": "string"},
                            "max_tokens": {"type": "integer", "minimum": 1, "maximum": 4096, "default": 200},
                        },
                        "required": ["prompt"],
                    },
                },
            ],
        }),
        "tools/call" => tool_call(state, &req.params).await,
        _ => json!({"error": format!("unknown method: {}", req.method)}),
    }
}

async fn tool_call(state: &McpState, params: &Value) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    let result = match name {
        "chat_send" => tool_chat_send(state, &args).await,
        "session_status" => tool_session_status(state),
        "chat_history" => tool_chat_history(state, &args),
        "send_echo" => tool_send_echo(state, &args).await,
        "sample" => tool_sample(state, &args).await,
        _ => Err(format!("unknown tool: {name}")),
    };
    match result {
        Ok(text) => json!({
            "content": [{"type": "text", "text": text}],
            "isError": false,
        }),
        Err(err) => json!({
            "content": [{"type": "text", "text": err}],
            "isError": true,
        }),
    }
}

async fn tool_chat_send(state: &McpState, args: &Value) -> Result<String, String> {
    #[cfg(feature = "chat")]
    {
        let text = args
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing 'text' argument".to_string())?
            .to_string();
        state
            .handle
            .rpc()
            .notification::<crate::ChatPush>(&text)
            .await
            .map_err(|e| format!("chat push failed: {e:?}"))?;
        let _ = state.events_tx.send(BackendEvent::ChatPushed { text: text.clone() });
        Ok(format!("pushed: {text:?}"))
    }
    #[cfg(not(feature = "chat"))]
    {
        let _ = (state, args);
        Err("backend built without the 'chat' feature".to_string())
    }
}

fn tool_session_status(state: &McpState) -> Result<String, String> {
    let s = state.status.lock().unwrap().clone();
    Ok(serde_json::to_string_pretty(&json!({
        "peer_status": s.peer_status.map(|p| format!("{p:?}")),
        "bt_connected": s.bt_connected,
        "peer_known": s.peer_known,
    }))
    .unwrap())
}

fn tool_chat_history(state: &McpState, args: &Value) -> Result<String, String> {
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .min(512) as usize;
    let h = state.history.lock().unwrap();
    let n = h.len();
    let slice = if n > limit { &h[n - limit..] } else { &h[..] };
    Ok(serde_json::to_string_pretty(slice).unwrap())
}

async fn tool_sample(state: &McpState, args: &Value) -> Result<String, String> {
    let prompt = args
        .get("prompt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'prompt' argument".to_string())?;
    let system_prompt = args.get("system_prompt").and_then(|v| v.as_str());
    let max_tokens = args
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(200) as u32;
    state.sample(prompt, system_prompt, max_tokens).await
}

async fn tool_send_echo(state: &McpState, args: &Value) -> Result<String, String> {
    let text = args
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'text' argument".to_string())?
        .to_string();
    let started = std::time::Instant::now();
    let reply = state
        .handle
        .rpc()
        .request::<route::Echo>(&EchoRequest { message: text.clone() })
        .await
        .map_err(|e| format!("echo failed: {e:?}"))?;
    let ms = started.elapsed().as_millis();
    let _ = state.events_tx.send(BackendEvent::EchoHandled {
        request: text.clone(),
        response: reply.message.clone(),
        ms,
    });
    Ok(format!("echo {text:?} → {:?}  ({ms} ms)", reply.message))
}
