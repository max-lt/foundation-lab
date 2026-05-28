//! MCP server (HTTP+SSE transport) exposing ql-link-lab to a model client.
//!
//! Lets an external AI agent (Claude Desktop, MCP Inspector, Cline, …)
//! drive the device side of the QL v2 session — push chat messages,
//! query history, drive Echo/Benchmark — and receive a live event
//! stream when things happen (chat received, status change, …).
//!
//! Topology:
//!
//!     Claude (MCP client) ──HTTP+SSE──► THIS ──(rpc/chat)──► device
//!
//! Two HTTP endpoints, mirroring the original MCP HTTP transport:
//!
//!   GET  /sse                   Opens the persistent SSE stream the
//!                               client reads server-pushed JSON-RPC
//!                               messages from (tool responses, server
//!                               notifications, and server-initiated
//!                               requests like `sampling/createMessage`).
//!                               On open, the server emits an `endpoint`
//!                               event with the URL the client must POST
//!                               replies/requests to.
//!
//!   POST /messages?id=<uuid>    Client → server JSON-RPC. Carries both
//!                               client-initiated requests (initialize,
//!                               tools/list, tools/call) and client
//!                               responses to server-initiated requests
//!                               (sampling, elicitation, etc.).
//!
//! Tools exposed (callable by the client via `tools/call`):
//!   - `chat_send(text)`: push ChatPush to the device (route 101).
//!   - `chat_history(limit)`: last N chat entries seen.
//!   - `session_status()`: current PeerStatus + BT link state.
//!   - `send_echo(text)`: drive Echo RPC (route 1) on the device.
//!   - `sample(prompt, …)`: issue sampling/createMessage to the
//!     connected client and return the reply.
//!
//! Notifications pushed by the server over SSE:
//!   - `notifications/message`: wraps a `BackendEvent` as JSON. Emitted
//!     on every chat in/out, status change, echo handled, benchmark
//!     done, etc.
//!
//! Single-client, localhost, no auth. Designed for development demos and
//! for the day Claude Code/Desktop add the `sampling` capability — until
//! then the auto-reply task is best exercised via MCP Inspector.

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

// =============================================================================
// Backend events — emitted by handlers, forwarded to the model over SSE.
// =============================================================================

/// Anything the backend wants the model to know about. Every handler that
/// reacts to device traffic (chat, echo, benchmark, download, status)
/// publishes one of these on the shared broadcast channel. The MCP server
/// subscribes from each SSE session and turns them into JSON-RPC
/// `notifications/message` events.
#[derive(Clone, Debug)]
pub enum BackendEvent {
    /// Device → backend chat line received on route 100 (ChatSend).
    ChatReceived { text: String },

    /// Backend → device chat push we just issued on route 101 (ChatPush).
    ChatPushed { text: String },

    /// Device echo round-trip completed by our RouterState handler.
    EchoHandled {
        request: String,
        response: String,
        ms: u128,
    },

    /// QL2 peer status moved (Disconnected ↔ Initiator ↔ Connected ↔ …).
    StatusChanged {
        state: PeerStatus,
        bt_connected: bool,
        peer_known: bool,
    },

    /// Subscription benchmark finished (we sent `bytes` over `secs`).
    BenchmarkCompleted { bytes: usize, secs: f64 },

    /// Download benchmark finished — includes the SHA-256 of the payload
    /// so the model can quote integrity verification to the user.
    DownloadCompleted {
        bytes: usize,
        secs: f64,
        sha256_hex: String,
    },
}

impl BackendEvent {
    /// Wire-shape each variant takes inside `notifications/message`. The
    /// `event` discriminator lets clients dispatch with a flat match.
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

            BackendEvent::EchoHandled {
                request,
                response,
                ms,
            } => json!({
                "event": "echo.handled",
                "request": request,
                "response": response,
                "ms": ms,
            }),

            BackendEvent::StatusChanged {
                state,
                bt_connected,
                peer_known,
            } => json!({
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

            BackendEvent::DownloadCompleted {
                bytes,
                secs,
                sha256_hex,
            } => json!({
                "event": "download.completed",
                "bytes": bytes,
                "secs": secs,
                "sha256": sha256_hex,
            }),
        }
    }
}

// =============================================================================
// Server state — shared across the SSE/POST handlers and the auto-reply task.
// =============================================================================

/// Max in-memory chat entries. Older ones are dropped when this is crossed.
const CHAT_HISTORY_LIMIT: usize = 512;

/// Everything the MCP server needs at runtime, all wrapped in `Arc` so it
/// can be cloned cheaply into spawned tasks. There is one `McpState` per
/// process; SSE sessions and pending requests live inside it.
#[derive(Clone)]
pub struct McpState {
    /// Broadcast of every `BackendEvent` the rest of the backend emits.
    /// Each SSE session subscribes; the auto-reply and history recorder
    /// also subscribe.
    pub events_tx: broadcast::Sender<BackendEvent>,

    /// Active QL2 runtime handle. Tools (chat_send, send_echo) and the
    /// auto-reply task call `.rpc()` on this to talk to the device.
    pub handle: RuntimeHandle,

    /// Rolling chat history. Capped at `CHAT_HISTORY_LIMIT`; oldest go.
    /// Lets a newly-connected client replay the conversation via
    /// `chat_history`.
    pub history: Arc<Mutex<Vec<ChatEntry>>>,

    /// Last known QL2 session status. Refreshed by the recorder task
    /// every time a `StatusChanged` event flies by.
    pub status: Arc<Mutex<StatusSnapshot>>,

    /// Active SSE sessions keyed by their UUID. POST /messages looks the
    /// session up here to route replies back through the right SSE stream.
    sessions: Arc<Mutex<HashMap<Uuid, mpsc::Sender<SseEvent>>>>,

    /// Most-recently-opened session — server-initiated requests
    /// (`sampling/createMessage` and friends) target this one. Simple
    /// "last writer wins" since this is a single-client localhost setup.
    primary_session: Arc<Mutex<Option<mpsc::Sender<SseEvent>>>>,

    /// JSON-RPC id counter for server-initiated requests. Monotonic so
    /// responses can be matched even across concurrent in-flight calls.
    next_request_id: Arc<AtomicI64>,

    /// In-flight server-initiated requests, keyed by JSON-RPC id. The
    /// `sample()` method registers a oneshot here before sending the
    /// request; `messages_handler` unblocks it when the response lands.
    pending: Arc<Mutex<HashMap<i64, oneshot::Sender<Value>>>>,
}

/// One row of the chat history. Direction is which way the message flew.
#[derive(Clone, Debug, Serialize)]
pub struct ChatEntry {
    pub direction: ChatDirection,
    pub text: String,
}

/// Direction tag. Stays lowercase on the wire so clients can match easily.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatDirection {
    DeviceToBackend,
    BackendToDevice,
}

/// Snapshot of the QL2 session, updated as `StatusChanged` events arrive.
/// Returned verbatim by the `session_status` tool.
#[derive(Clone, Debug, Default)]
pub struct StatusSnapshot {
    pub peer_status: Option<PeerStatus>,
    pub bt_connected: bool,
    pub peer_known: bool,
}

impl McpState {
    /// Fresh state with empty history, no sessions, and a clean id counter.
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

    /// Append one chat entry and evict the oldest if we cross the cap.
    pub fn record_chat(&self, entry: ChatEntry) {
        let mut h = self.history.lock().unwrap();
        h.push(entry);

        let len = h.len();

        if len > CHAT_HISTORY_LIMIT {
            h.drain(..len - CHAT_HISTORY_LIMIT);
        }
    }

    /// Send `sampling/createMessage` to the active MCP client and await
    /// the model's reply. The flow is:
    ///
    ///   1. Pick the primary SSE session (fails if no client connected).
    ///   2. Mint a fresh JSON-RPC id and register a oneshot waiter.
    ///   3. Push the request through the SSE stream as an MCP message.
    ///   4. Block on the oneshot until the client POSTs back the answer
    ///      (or the 60 s timeout fires).
    ///
    /// Requires a sampling-capable client (MCP Inspector, Cline,
    /// ContinueDev). Claude Code/Desktop don't implement it yet — issue
    /// anthropics/claude-code#1785 tracks that.
    pub async fn sample(
        &self,
        prompt: &str,
        system_prompt: Option<&str>,
        max_tokens: u32,
    ) -> Result<String, String> {
        // Need a client to talk to.
        let session_tx = self
            .primary_session
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "no MCP client connected".to_string())?;

        // Allocate an id and prepare the oneshot before sending — that
        // way an extremely-fast reply can't race us.
        let id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let (resp_tx, resp_rx) = oneshot::channel::<Value>();
        self.pending.lock().unwrap().insert(id, resp_tx);

        // Build the JSON-RPC request body matching the MCP spec.
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

        // Push it through the SSE stream. If the channel is gone the
        // client disappeared between us checking and sending — cleanup
        // the pending entry so it doesn't leak.
        if session_tx
            .send(
                SseEvent::default()
                    .event("message")
                    .data(request.to_string()),
            )
            .await
            .is_err()
        {
            self.pending.lock().unwrap().remove(&id);
            return Err("SSE session closed before sampling request sent".to_string());
        }

        // Block until messages_handler dispatches the response to our
        // oneshot, or the timeout fires.
        let response = tokio::time::timeout(Duration::from_secs(60), resp_rx)
            .await
            .map_err(|_| {
                self.pending.lock().unwrap().remove(&id);
                "sampling timed out (60s)".to_string()
            })?
            .map_err(|_| "sampling response channel closed".to_string())?;

        // Either the client sent us an error object, or we look for the
        // text part of the model's reply at the expected JSON path.
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

// =============================================================================
// Background tasks — recorder and optional auto-reply.
// =============================================================================

/// Auto-reply loop: each `ChatReceived` event triggers a
/// `sampling/createMessage` round-trip whose reply is then pushed back
/// to the device as a `ChatPush`. Useful as a "minimum viable AI agent
/// in the loop" demo.
///
/// Requires:
///   - feature `chat` (so the ChatPush type is defined and routable),
///   - an MCP client that implements the sampling capability (MCP
///     Inspector, Cline, …). With Claude Code today, sampling errors
///     out and the loop just logs warnings.
pub async fn run_chat_auto_reply(state: McpState) {
    let mut rx = state.events_tx.subscribe();

    // A modest system prompt so replies stay short and informational.
    let system_prompt =
        "You are an AI assistant chatting with a KeyOS Passport Prime hardware wallet user. \
         Keep replies short (one or two sentences), warm, and informational. \
         You are bridged via QL v2 → relay → ql-link-lab backend → MCP sampling.";

    while let Ok(event) = rx.recv().await {
        // Only react to inbound chat — anything else is someone else's job.
        let BackendEvent::ChatReceived { text } = event else {
            continue;
        };

        log::info!("[auto-reply] device → backend: {text:?} — calling sampling");

        match state.sample(&text, Some(system_prompt), 200).await {
            Ok(reply) => {
                log::info!("[auto-reply] sampling reply: {reply:?}");

                // Push the model's reply back to the device as a
                // notification. `ChatPush` is feature-gated, so this
                // branch is only compiled when `chat` is on.
                #[cfg(feature = "chat")]
                {
                    match state
                        .handle
                        .rpc()
                        .notification::<crate::ChatPush>(&reply)
                        .await
                    {
                        Ok(()) => {
                            // Mirror the outgoing message into the
                            // history + event stream so a watching
                            // model sees a coherent transcript.
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

/// Always-on recorder: drains the event broadcast into the rolling
/// history + status snapshot. Runs whether or not anyone is connected
/// so disconnected clients don't lose context when they come back.
pub async fn run_event_recorder(state: McpState) {
    let mut rx = state.events_tx.subscribe();

    while let Ok(event) = rx.recv().await {
        match &event {
            // Both directions land in the history list.
            BackendEvent::ChatReceived { text } => state.record_chat(ChatEntry {
                direction: ChatDirection::DeviceToBackend,
                text: text.clone(),
            }),

            BackendEvent::ChatPushed { text } => state.record_chat(ChatEntry {
                direction: ChatDirection::BackendToDevice,
                text: text.clone(),
            }),

            // Status updates rewrite the snapshot in place.
            BackendEvent::StatusChanged {
                state: peer_state,
                bt_connected,
                peer_known,
            } => {
                let mut s = state.status.lock().unwrap();
                s.peer_status = Some(*peer_state);
                s.bt_connected = *bt_connected;
                s.peer_known = *peer_known;
            }

            // Other events are pure broadcast — the recorder doesn't
            // need to materialize them anywhere; they're surfaced as
            // they happen via the SSE notification stream.
            _ => {}
        }
    }
}

// =============================================================================
// HTTP server bootstrap.
// =============================================================================

/// Bind the MCP server on `addr` and run it forever. Two routes only —
/// the SSE upgrade and the messages POST.
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

// =============================================================================
// GET /sse — the persistent server-to-client channel.
// =============================================================================

/// Opens a new SSE session. The lifecycle is:
///
///   1. Mint a session id and an mpsc channel for outbound SSE events.
///   2. Push the initial `endpoint` event telling the client where to POST.
///   3. Register the sender in `state.sessions` (for response routing)
///      and as the `primary_session` (for server-initiated requests).
///   4. Spawn a forwarder task subscribed to the broadcast that turns
///      each `BackendEvent` into a `notifications/message`.
///   5. Return the SSE stream (with keepalive) — when the client
///      disconnects, the channel closes and the spawned task winds down.
async fn sse_handler(
    State(state): State<McpState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let session_id = Uuid::new_v4();
    let (tx, rx) = mpsc::channel::<SseEvent>(64);

    // The MCP spec says we MUST send an `endpoint` event first; the
    // client uses it to know where to POST its JSON-RPC messages.
    let endpoint_url = format!("/messages?id={session_id}");
    let _ = tx
        .send(SseEvent::default().event("endpoint").data(endpoint_url))
        .await;

    // Register this session so POST /messages can find the right channel.
    state
        .sessions
        .lock()
        .unwrap()
        .insert(session_id, tx.clone());

    // Server-initiated requests (sampling, …) target whoever connected
    // most recently — fine for the single-client localhost case.
    *state.primary_session.lock().unwrap() = Some(tx.clone());

    // Forwarder: each backend event becomes a `notifications/message`.
    // Stops automatically when the SSE channel closes (client gone).
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

    // Cleanup the session entry when the stream ends. The trailing
    // `chain` is a never-yielding tail whose only purpose is to run the
    // closure on stream drop.
    let sessions_for_cleanup = state.sessions.clone();
    let stream = ReceiverStream::new(rx).map(Ok::<_, Infallible>).chain(
        futures_lite::stream::iter(std::iter::empty()).map(move |_: ()| {
            sessions_for_cleanup.lock().unwrap().remove(&session_id);
            unreachable!()
        }),
    );

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

// =============================================================================
// POST /messages — receives both client→server requests AND client→server
// responses to our server-initiated requests.
// =============================================================================

/// Query string carries the session id so we can route replies to the
/// right SSE channel.
#[derive(Deserialize)]
struct MsgQuery {
    id: Uuid,
}

/// JSON-RPC request shape for the request path. (Responses are decoded
/// as raw `Value` because we don't need to validate their schema —
/// only the `id` and the absence of `method` matter.)
#[derive(Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Single entry point for both directions of JSON-RPC on the SSE-paired
/// HTTP channel:
///
///   - Body has a `method` field → it's a request from the client.
///     Dispatch it (initialize, tools/list, tools/call) and push the
///     response back through the SSE stream.
///
///   - Body has `result` or `error` (and no `method`) → it's a reply
///     to one of our server-initiated requests (e.g. sampling). Look
///     the id up in `pending` and unblock the waiter.
async fn messages_handler(
    State(state): State<McpState>,
    Query(query): Query<MsgQuery>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Find the SSE channel for this session — we need it to ship back
    // request responses below.
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

    // Branch by JSON-RPC shape: request (has `method`) vs response.
    if body.get("method").is_some() {
        // ----- client request → dispatch + reply through SSE -----
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

        let sse = SseEvent::default()
            .event("message")
            .data(payload.to_string());
        let _ = session_tx.send(sse).await;
    } else if let Some(id) = body.get("id").and_then(|v| v.as_i64()) {
        // ----- client response → wake the awaiting sample() call -----
        if let Some(waiter) = state.pending.lock().unwrap().remove(&id) {
            let _ = waiter.send(body);
        } else {
            log::warn!("[mcp] response for unknown request id={id}");
        }
    } else {
        log::warn!("[mcp] payload is neither request nor response: {body}");
    }

    // SSE transport: the actual reply travels over the SSE stream, so
    // the POST itself just ACKs.
    StatusCode::ACCEPTED.into_response()
}

// =============================================================================
// MCP method dispatch — initialize, tools/list, tools/call.
// =============================================================================

/// Top-level dispatch by JSON-RPC method name. Unknown methods get a
/// shaped error result (the client interprets it).
async fn dispatch(state: &McpState, req: &JsonRpcRequest) -> Value {
    match req.method.as_str() {
        // Standard MCP handshake. We declare which capabilities we
        // expose (tools, resources, logging). No sampling capability is
        // claimed here because we don't *consume* sampling, we *issue*
        // it (the server side requirement is no special declaration).
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

        // Static manifest of the tools the client can invoke. Each one
        // gets a JSON-schema input spec so the model can call it
        // correctly.
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

        // Run a tool by name with the supplied arguments.
        "tools/call" => tool_call(state, &req.params).await,

        // Anything else is an error — we don't implement resources/list,
        // prompts/list, etc. yet.
        _ => json!({"error": format!("unknown method: {}", req.method)}),
    }
}

// =============================================================================
// Tool implementations — one function per tool, plus a shared dispatcher.
// =============================================================================

/// Lookup the tool by name in `params.name`, run it with `params.arguments`,
/// and wrap the result/error into the MCP tool-call response shape.
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

/// `chat_send(text)` — push a ChatPush notification (route 101) to the
/// device. Records the outbound message in history via a ChatPushed event.
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

        // Mirror into the event stream so the recorder picks it up.
        let _ = state
            .events_tx
            .send(BackendEvent::ChatPushed { text: text.clone() });

        Ok(format!("pushed: {text:?}"))
    }

    #[cfg(not(feature = "chat"))]
    {
        let _ = (state, args);
        Err("backend built without the 'chat' feature".to_string())
    }
}

/// `session_status()` — return the latest known QL2 status snapshot.
fn tool_session_status(state: &McpState) -> Result<String, String> {
    let s = state.status.lock().unwrap().clone();

    Ok(serde_json::to_string_pretty(&json!({
        "peer_status": s.peer_status.map(|p| format!("{p:?}")),
        "bt_connected": s.bt_connected,
        "peer_known": s.peer_known,
    }))
    .unwrap())
}

/// `chat_history(limit)` — last N chat entries (both directions).
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

/// `sample(prompt, system_prompt?, max_tokens?)` — issue
/// sampling/createMessage to the connected client and forward its reply
/// verbatim. The actual mechanics live in `McpState::sample`.
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

/// `send_echo(text)` — drive the device's Echo RPC (route 1) as the
/// initiator. Emits an `EchoHandled` event with timing so observers can
/// chart round-trip latency.
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
        .request::<route::Echo>(&EchoRequest {
            message: text.clone(),
        })
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
