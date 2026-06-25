//! QuantumLink v2 backend — the "web service" peer.
//!
//! Topology:  device-sim ──TCP:8765──► relay ──TCP:8766──► THIS
//!
//! This process is the QL v2 *initiator*. Two modes, auto-selected by
//! whether the state file (`--state`) exists:
//!
//!   * XX (no state file): fresh pairing. Runs the XX handshake with the
//!     out-of-band token the device printed (`QLV2_PAIRING_QR ...`), then
//!     persists our identity + the device's PeerBundle to the state file.
//!   * IK (state file present): reconnect to an already-known peer.
//!     Loads the saved identity + bundle, does `bind_peer` + `connect` —
//!     no token needed. This is what a real companion does on every
//!     connection after the one-time pairing.
//!
//! Either way, once the session is up it drives the device's RPC surface
//! as a client: an `Echo` round-trip then a `BytesBenchmark` download.
//!
//! Wire stack mirrors the device exactly:
//!   QL2 record  ⇄  btp chunk(s)  ⇄  4-byte length-prefixed TCP frame
//!
//! The QL2 session is end-to-end; the relay only ever sees ciphertext.

use std::{
    future::Future,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender};
use futures_lite::Stream;
use ql_api::{
    route, BenchmarkEvent, BenchmarkRequest, DownloadBenchmarkHeader, DownloadBenchmarkPartHeader,
    DownloadBenchmarkRequest, EchoRequest, EchoResponse, ExchangeRate, ExchangeRateHistory,
    ExchangeRateHistoryRequest, ExchangeRateSubscriptionRequest,
};
use ql_common::{StreamInfo, QID};
#[cfg(feature = "chat")]
use ql_common::{RouteId, ServiceId};
use ql_fsm::{PairingInvite, PeerStatus, QlFsmConfig};
#[cfg(feature = "chat")]
use ql_rpc::{notification::Notification, request::Request, Route};
use ql_rpc::{
    DownloadHandler, DownloadStart, RequestHandler, Response, Router, RpcStream, SendSpawner,
    Spawner, SubscriptionHandler, SubscriptionResponder,
};
use ql_runtime::{
    new_runtime, QlInbound, QlStream, QlPlatform, QlTimer, RuntimeConfig, RuntimeHandle,
};
use ql_wire::{
    generate_identity, MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, Nonce,
    PairingToken, PeerBundle, QlAead, QlHash, QlIdentity, QlKem, QlRandom, SessionKey,
    SoftwareCrypto, WireDecode, WireEncode,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Sleep,
};

#[cfg(feature = "mcp")]
mod mcp;

/// Default TCP peer for the backend to dial. Points at the relay listening
/// on 8766; override with `--connect-to 127.0.0.1:8765` to skip the relay
/// and talk to the sim's `os/bt` bridge directly.
const DEFAULT_PEER: &str = "127.0.0.1:8766";
#[cfg(feature = "mcp")]
const DEFAULT_MCP_ADDR: &str = "127.0.0.1:8780";
/// Persisted (identity ‖ peer bundle) — its presence selects IK vs XX mode.
const DEFAULT_STATE: &str = "/tmp/foundation-lab-peer.state";

// ===== RPC surface =====
//
// Echo / BytesBenchmark / DownloadBenchmark are the canonical Route types
// from `ql-api`. They match KeyOS-dev/test-apps/gui-app-qlv2/src/rpc.rs by
// construction (both sides import them from the same crate).
//
// ChatSend / ChatPush are custom routes used only by the chat demo
// (test-apps/gui-app-chat); they are not in ql-api so we define them locally
// with the same constants the device uses.

// ===== Chat (feature-gated) RPC types =====
//
// Mirrors `KeyOS-dev/test-apps/gui-app-chat/src/rpc.rs`. ChatSend is a Request
// (device → backend) because api/ql exposes `request` but not `notification`.
// ChatPush is a Notification (backend → device).

#[cfg(feature = "chat")]
pub struct ChatSend;
// The device's os/ql does not yet populate the outbound stream service_id from
// Route::SERVICE -- it emits 0 for every stream, like the built-in routes. So
// Chat lives on the system service (0) for now, not its own app id.
#[cfg(feature = "chat")]
const CHAT_SERVICE: ServiceId = ServiceId([0; 16]);
#[cfg(feature = "chat")]
impl Route for ChatSend {
    const SERVICE: ServiceId = CHAT_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(100);
}
#[cfg(feature = "chat")]
impl Request for ChatSend {
    type Error = std::str::Utf8Error;
    type Request = String;
    type Response = String;
}

#[cfg(feature = "chat")]
pub struct ChatPush;
#[cfg(feature = "chat")]
impl Route for ChatPush {
    const SERVICE: ServiceId = CHAT_SERVICE;
    const ROUTE: RouteId = RouteId::from_u32(101);
}
#[cfg(feature = "chat")]
impl Notification for ChatPush {
    type Error = std::str::Utf8Error;
    type Payload = String;
}

// ===== RPC server side (serve mode) =====
//
// When the *device* initiates ("Send Echo" in gui-app-qlv2), it is the RPC
// client and we must answer. A `Router` dispatches each inbound stream to a
// handler. `RouterState` is stateless — Echo just reflects the payload.

#[derive(Clone, Default)]
struct RouterState {
    #[cfg(feature = "mcp")]
    events: Option<tokio::sync::broadcast::Sender<mcp::BackendEvent>>,
}

#[cfg(feature = "mcp")]
impl RouterState {
    fn emit(&self, event: mcp::BackendEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.send(event);
        }
    }
}

/// Backend-side spawner for the Router. The new ql-rpc API requires the
/// user to provide a `SendSpawner` (replaces the old built-in `SendSpawn`).
#[derive(Clone, Copy)]
struct TokioSendSpawn;

impl Spawner for TokioSendSpawn {
    type Handle = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

impl SendSpawner for TokioSendSpawn {
    fn spawn<F>(&self, fut: F) -> Self::Handle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Box::pin(fut)
    }
}

impl RequestHandler<route::Echo, QlStream> for RouterState {
    async fn handle(
        self,
        _context: ql_rpc::Context,
        request: EchoRequest,
        responder: Response<EchoResponse, <QlStream as RpcStream>::Writer>,
    ) {
        println!(
            "[backend] ← inbound Echo {:?} — responding",
            request.message
        );
        let echoed = request.message.clone();
        #[cfg(feature = "mcp")]
        let started = Instant::now();
        match responder
            .respond(EchoResponse {
                message: echoed.clone(),
            })
            .await
        {
            Ok(()) => {
                println!("[backend]   .. respond OK ({echoed:?})");
                #[cfg(feature = "mcp")]
                self.emit(mcp::BackendEvent::EchoHandled {
                    request: request.message,
                    response: echoed,
                    ms: started.elapsed().as_millis(),
                });
            }
            Err(e) => eprintln!("[backend]   .. respond FAILED ({echoed:?}): {e:?}"),
        }
    }
}

// Stream `request.length` bytes back to the subscriber in 4 KiB chunks.
const BENCHMARK_CHUNK_LEN: usize = 4 * 1024;

impl SubscriptionHandler<route::BytesBenchmark, QlStream> for RouterState {
    async fn handle(
        self,
        _context: ql_rpc::Context,
        request: BenchmarkRequest,
        mut responder: SubscriptionResponder<BenchmarkEvent, <QlStream as RpcStream>::Writer>,
    ) {
        let total = request.length as usize;
        println!("[backend] ← inbound BytesBenchmark subscription, length={total} — streaming");
        let started = Instant::now();
        let mut remaining = total;
        while remaining > 0 {
            let n = remaining.min(BENCHMARK_CHUNK_LEN);
            if let Err(e) = responder
                .send(BenchmarkEvent {
                    bytes: vec![0u8; n],
                })
                .await
            {
                eprintln!(
                    "[backend]   .. BytesBenchmark send failed at {} B: {e:?}",
                    total - remaining
                );
                return;
            }
            remaining -= n;
        }
        match responder.finish().await {
            Ok(()) => {
                let secs = started.elapsed().as_secs_f64();
                println!("[backend]   .. BytesBenchmark OK ({total} B in {secs:.2}s)");
                #[cfg(feature = "mcp")]
                self.emit(mcp::BackendEvent::BenchmarkCompleted { bytes: total, secs });
            }
            Err(e) => eprintln!("[backend]   .. BytesBenchmark finish FAILED: {e:?}"),
        }
    }
}

// gui-app-launcher subscribes to exchange rates on connect and retries with no
// backoff whenever the route resets, so an unhandled route 701 floods the
// session and tears it down. Park the subscription: send one rate, then hold
// the stream open so the launcher stops storming. A real companion would stream
// live rates here.
impl SubscriptionHandler<route::ExchangeRateSubscription, QlStream> for RouterState {
    async fn handle(
        self,
        _context: ql_rpc::Context,
        _request: ExchangeRateSubscriptionRequest,
        mut responder: SubscriptionResponder<ExchangeRate, <QlStream as RpcStream>::Writer>,
    ) {
        println!("[backend] ← inbound ExchangeRateSubscription — parking the stream");
        let _ = responder
            .send(ExchangeRate {
                currency_code: "USD".into(),
                rate: 0.0,
                timestamp: 0,
            })
            .await;
        std::future::pending::<()>().await;
    }
}

// The launcher also requests exchange-rate history (route 702) on connect.
// Answer with an empty history so the request completes instead of resetting.
impl RequestHandler<route::ExchangeRateHistory, QlStream> for RouterState {
    async fn handle(
        self,
        _context: ql_rpc::Context,
        request: ExchangeRateHistoryRequest,
        responder: Response<ExchangeRateHistory, <QlStream as RpcStream>::Writer>,
    ) {
        let _ = responder
            .respond(ExchangeRateHistory {
                history: Vec::new(),
                currency_code: request.currency_code,
            })
            .await;
    }
}

#[cfg(feature = "chat")]
impl RequestHandler<ChatSend, QlStream> for RouterState {
    async fn handle(
        self,
        _context: ql_rpc::Context,
        message: String,
        responder: Response<String, <QlStream as RpcStream>::Writer>,
    ) {
        println!("[backend] chat ← from device: {message:?}");
        #[cfg(feature = "mcp")]
        self.emit(mcp::BackendEvent::ChatReceived {
            text: message.clone(),
        });
        // Ack with the same text — keeps the device UI flow simple and
        // confirms end-to-end delivery.
        let _ = responder.respond(message).await;
    }
}

impl DownloadHandler<route::DownloadBenchmark, QlStream> for RouterState {
    async fn handle(
        self,
        _context: ql_rpc::Context,
        request: DownloadBenchmarkRequest,
        download: DownloadStart<route::DownloadBenchmark, <QlStream as RpcStream>::Writer>,
    ) {
        let total = request.length as usize;
        println!(
            "[backend] ← inbound DownloadBenchmark, length={total} — preparing payload + sha256"
        );
        // Build the deterministic payload (zeros) and its SHA-256 so the
        // device can verify integrity if it wants.
        let payload = vec![0u8; total];
        let hash = SoftwareCrypto.sha256(&[&payload]).to_vec();
        let started = Instant::now();
        let mut writer = match download.start(DownloadBenchmarkHeader { hash }).await {
            Ok(w) => w,
            Err(e) => {
                eprintln!("[backend]   .. DownloadBenchmark header send FAILED: {e:?}");
                return;
            }
        };
        // Single part: body delivered in 4 KiB chunks.
        let mut part = match writer.start_part(DownloadBenchmarkPartHeader {}).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[backend]   .. DownloadBenchmark start_part FAILED: {e:?}");
                return;
            }
        };
        let mut remaining = total;
        let mut offset = 0;
        while remaining > 0 {
            let n = remaining.min(BENCHMARK_CHUNK_LEN);
            let chunk = bytes::Bytes::copy_from_slice(&payload[offset..offset + n]);
            if let Err(e) = part.send(chunk).await {
                eprintln!("[backend]   .. DownloadBenchmark body send failed at {offset} B: {e:?}");
                return;
            }
            offset += n;
            remaining -= n;
        }
        if let Err(e) = part.finish().await {
            eprintln!("[backend]   .. DownloadBenchmark part.finish FAILED: {e:?}");
            return;
        }
        match writer.finish().await {
            Ok(()) => {
                let secs = started.elapsed().as_secs_f64();
                println!("[backend]   .. DownloadBenchmark OK ({total} B in {secs:.2}s)");
                #[cfg(feature = "mcp")]
                self.emit(mcp::BackendEvent::DownloadCompleted {
                    bytes: total,
                    secs,
                    sha256_hex: hex::encode(SoftwareCrypto.sha256(&[&vec![0u8; total]])),
                });
            }
            Err(e) => eprintln!("[backend]   .. DownloadBenchmark finish FAILED: {e:?}"),
        }
    }
}

// ===== entry point =====

pub async fn run(args: Vec<String>) {
    // Surface ql-runtime's internal handshake tracing by default; override
    // with RUST_LOG. This is the only window into why pairing stalls — the
    // device side logs nothing at INFO during the handshake.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,ql_runtime=debug,backend=debug"),
    )
    .init();

    let mut args = args.into_iter();
    let mut peer = DEFAULT_PEER.to_string();
    let mut token_hex: Option<String> = None;
    let mut bench_len: u32 = 256 * 1024;
    let mut state_path = DEFAULT_STATE.to_string();
    let mut serve = false;
    let mut fresh = false;
    #[cfg(feature = "mcp")]
    let mut mcp_addr: Option<String> = None;
    #[cfg(feature = "mcp")]
    let mut mcp_auto_reply = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Address to dial — either a relay or the sim's bt-server bridge directly.
            "--connect-to" => peer = args.next().expect("--connect-to needs an address"),
            "--token" => token_hex = Some(args.next().expect("--token needs a value")),
            "--state" => state_path = args.next().expect("--state needs a path"),
            "--serve" => serve = true,
            // Discard any saved state so this run does a fresh XX pairing.
            "--fresh" => fresh = true,
            "--bench-bytes" => {
                bench_len = args
                    .next()
                    .expect("--bench-bytes needs a value")
                    .parse()
                    .expect("--bench-bytes must be a u32")
            }
            #[cfg(feature = "mcp")]
            "--mcp" => mcp_addr = Some(args.next().unwrap_or_else(|| DEFAULT_MCP_ADDR.to_string())),
            #[cfg(feature = "mcp")]
            "--auto-reply" => mcp_auto_reply = true,
            other => panic!("unknown arg: {other}"),
        }
    }

    if fresh {
        let _ = std::fs::remove_file(&state_path);
    }

    // The presence of the state file selects the mode: a saved
    // (identity ‖ peer bundle) means we've paired before → reconnect IK.
    let ik_mode = Path::new(&state_path).exists();

    println!("[backend] connecting to {peer}");
    let stream = TcpStream::connect(&peer)
        .await
        .unwrap_or_else(|e| panic!("[backend] cannot reach {peer}: {e}"));
    stream.set_nodelay(true).ok();

    // IK mode reuses the identity the device already knows; XX mints a fresh one.
    let (identity, ik_bundle) = if ik_mode {
        let (id, bundle) = load_state(&state_path);
        println!("[backend] IK mode — reconnecting to known peer (state: {state_path})");
        (id, Some(bundle))
    } else {
        println!("[backend] XX mode — fresh pairing (no state at {state_path})");
        let id = generate_identity(&SoftwareCrypto, "foundation-lab backend")
            .expect("generate_identity failed");
        (id, None)
    };
    let identity_to_save = identity.clone();

    #[cfg(feature = "mcp")]
    let (mcp_events_tx, _mcp_events_rx_keepalive) =
        tokio::sync::broadcast::channel::<mcp::BackendEvent>(256);

    let (platform, plumbing) = BackendPlatform::new();
    #[cfg(feature = "mcp")]
    let platform = if mcp_addr.is_some() {
        platform.with_mcp_events(mcp_events_tx.clone())
    } else {
        platform
    };
    let (runtime, handle) = new_runtime(identity, platform, ble_config());

    tokio::spawn(async move {
        runtime.run().await;
        log::error!("runtime.run() RETURNED — the QL runtime stopped (this should never happen mid-session)");
    });
    spawn_tcp_btp_bridge(plumbing.outbound_rx, plumbing.inbound_tx, stream);

    let what = if let Some(bundle) = ik_bundle {
        handle.bind_peer(bundle);
        handle.connect();
        "IK reconnect"
    } else {
        let invite = parse_invite(&token_hex.expect(
            "XX mode needs --token <hex>  (the part after the last ':' in the \
             sim's `QLV2_PAIRING_QR 12:34:56:78:9A:BC:<hex>` log line)",
        ));
        handle.start_pairing(invite);
        "XX pairing"
    };

    match await_status(
        &plumbing.status_rx,
        PeerStatus::Connected,
        Duration::from_secs(30),
    )
    .await
    {
        Ok(()) => println!("[backend] *** QL v2 session ESTABLISHED ({what} complete) ***"),
        Err(()) => {
            eprintln!("[backend] {what} did not complete within 30s — aborting");
            std::process::exit(1);
        }
    }

    // After a fresh XX pairing, persist (our identity ‖ device bundle) so
    // the next run reconnects via IK with no token — the steady-state path.
    if !ik_mode {
        match tokio::time::timeout(Duration::from_secs(3), plumbing.peer_rx.recv()).await {
            Ok(Ok(bundle)) => {
                save_state(&state_path, &identity_to_save, &bundle);
                println!("[backend] saved peer state to {state_path} — next run reconnects via IK");
            }
            _ => eprintln!("[backend] warning: no peer bundle captured — cannot save IK state"),
        }
    }

    // Serve mode: become a daemon. Stand up a Router and answer RPC the
    // *device* initiates (e.g. "Send Echo" in gui-app-qlv2). Runs forever.
    if serve {
        println!(
            "[backend] serve mode — Router up (Echo). Waiting for device-initiated RPC; Ctrl-C to stop."
        );
        let router_state = RouterState {
            #[cfg(feature = "mcp")]
            events: mcp_addr.as_ref().map(|_| mcp_events_tx.clone()),
        };
        let builder = Router::<RouterState, QlStream, TokioSendSpawn>::builder_send(TokioSendSpawn)
            .request::<route::Echo>()
            .subscription::<route::BytesBenchmark>()
            .subscription::<route::ExchangeRateSubscription>()
            .request::<route::ExchangeRateHistory>()
            .download::<route::DownloadBenchmark>();
        #[cfg(feature = "chat")]
        let builder = builder.request::<ChatSend>();
        let router = builder.build(router_state);

        #[cfg(feature = "chat")]
        {
            let push_handle = handle.clone();
            tokio::spawn(chat_input_loop(push_handle, "127.0.0.1:9999".to_string()));
        }

        #[cfg(feature = "mcp")]
        if let Some(addr_str) = mcp_addr.clone() {
            let addr: std::net::SocketAddr =
                addr_str.parse().expect("--mcp address must be host:port");
            let mcp_state = mcp::McpState::new(handle.clone(), mcp_events_tx.clone());
            tokio::spawn(mcp::run_event_recorder(mcp_state.clone()));
            if mcp_auto_reply {
                println!("[mcp] auto-reply enabled (device chats are forwarded to MCP sampling)");
                tokio::spawn(mcp::run_chat_auto_reply(mcp_state.clone()));
            }
            tokio::spawn(async move {
                if let Err(e) = mcp::serve(addr, mcp_state).await {
                    eprintln!("[mcp] server error: {e}");
                }
            });
        }
        loop {
            match plumbing.inbound_streams_rx.recv().await {
                Ok((info, stream)) => match router.handle(info, stream) {
                    Some((route, fut)) => {
                        println!("[backend] serving inbound RPC on {route:?}");
                        tokio::spawn(fut);
                    }
                    None => eprintln!("[backend] inbound stream for an unrouted route — dropped"),
                },
                Err(_) => {
                    eprintln!("[backend] inbound stream channel closed — session gone, exiting");
                    return;
                }
            }
        }
    }

    run_echo(&handle).await;
    run_benchmark(&handle, bench_len).await;

    println!("[backend] done — closing session");
}

/// Persist `(identity ‖ peer bundle)`. Identity wire size is variable
/// (includes a name), so prefix it with a u32 length to split cleanly on
/// load.
fn save_state(path: &str, identity: &QlIdentity, bundle: &PeerBundle) {
    let id_buf = identity.encode_vec();
    let bundle_buf = bundle.encode_vec();
    let mut buf = Vec::with_capacity(4 + id_buf.len() + bundle_buf.len());
    buf.extend_from_slice(&(id_buf.len() as u32).to_be_bytes());
    buf.extend_from_slice(&id_buf);
    buf.extend_from_slice(&bundle_buf);
    std::fs::write(path, &buf).unwrap_or_else(|e| panic!("cannot write state {path}: {e}"));
}

fn load_state(path: &str) -> (QlIdentity, PeerBundle) {
    let buf = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read state {path}: {e}"));
    assert!(buf.len() >= 4, "state file {path} truncated");
    let id_len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    assert!(
        buf.len() >= 4 + id_len,
        "state file {path} truncated (need {} got {})",
        4 + id_len,
        buf.len()
    );
    let identity = QlIdentity::decode_exact(&buf[4..4 + id_len])
        .unwrap_or_else(|e| panic!("decode identity from state: {e:?}"));
    let bundle = PeerBundle::decode_exact(&buf[4 + id_len..])
        .unwrap_or_else(|e| panic!("decode peer bundle from state: {e:?}"));
    (identity, bundle)
}

async fn run_echo(handle: &RuntimeHandle) {
    let msg = "hello from the backend over QL v2".to_string();
    println!("[backend] echo → {msg:?}");
    let started = Instant::now();
    match handle
        .rpc()
        .request::<route::Echo>(&EchoRequest {
            message: msg.clone(),
        })
        .await
    {
        Ok(reply) => {
            let ok = reply.message == msg;
            println!(
                "[backend] echo ← {:?}  ({:.1} ms round-trip, match={ok})",
                reply.message,
                started.elapsed().as_secs_f64() * 1000.0
            );
            assert!(ok, "echo reply did not match request");
        }
        Err(e) => {
            eprintln!("[backend] echo failed: {e:?}");
            std::process::exit(1);
        }
    }
}

async fn run_benchmark(handle: &RuntimeHandle, length: u32) {
    println!("[backend] benchmark → requesting {length} bytes from device");
    let started = Instant::now();
    let mut sub = match handle
        .rpc()
        .subscribe::<route::BytesBenchmark>(&BenchmarkRequest { length })
        .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[backend] benchmark subscribe failed: {e:?}");
            return;
        }
    };

    let mut received = 0usize;
    while let Some(event) = sub.next_event().await {
        match event {
            Ok(chunk) => received += chunk.bytes.len(),
            Err(e) => {
                eprintln!("[backend] benchmark stream error after {received} B: {e:?}");
                return;
            }
        }
    }

    let secs = started.elapsed().as_secs_f64();
    let kbps = (received as f64 / 1024.0) / secs;
    println!(
        "[backend] benchmark ← {received} bytes in {secs:.2}s = {kbps:.1} KiB/s \
         end-to-end (device → backend, QL v2)"
    );
}

fn parse_invite(raw: &str) -> PairingInvite {
    // Accept either the bare invite hex or the whole QR payload
    // `12:34:56:78:9A:BC:<hex>` — invite is whatever follows the last ':'.
    // Format: 1 byte version (==1) + 16 byte QID + 16 byte PairingToken.
    let hex_part = raw.rsplit(':').next().unwrap_or(raw).trim();
    let bytes = hex::decode(hex_part)
        .unwrap_or_else(|e| panic!("invite is not valid hex ({e}): {hex_part:?}"));
    let expected = 1 + QID::SIZE + PairingToken::SIZE;
    assert_eq!(
        bytes.len(),
        expected,
        "invite must be {expected} bytes (1 ver + {} qid + {} token), got {}",
        QID::SIZE,
        PairingToken::SIZE,
        bytes.len()
    );
    assert_eq!(
        bytes[0],
        PairingInvite::VERSION,
        "invite version must be {}",
        PairingInvite::VERSION
    );
    let qid_arr: [u8; QID::SIZE] = bytes[1..1 + QID::SIZE].try_into().unwrap();
    let token_arr: [u8; PairingToken::SIZE] = bytes[1 + QID::SIZE..].try_into().unwrap();
    PairingInvite {
        qid: QID(qid_arr),
        token: PairingToken(token_arr),
    }
}

fn ble_config() -> RuntimeConfig {
    RuntimeConfig {
        fsm: QlFsmConfig {
            handshake_timeout: Duration::from_secs(10),
            session_record_retransmit_timeout: Duration::from_secs(2),
            session_keepalive_interval: Duration::ZERO,
            session_peer_timeout: Duration::ZERO,
            ..Default::default()
        },
        ..Default::default()
    }
}

// ===== TCP + BTP transport bridge =====
//
// Outbound: each QL2 record the runtime emits is btp-chunked; every chunk
// goes out as one 4-byte big-endian length-prefixed TCP frame — exactly
// what the device's `os/bt` hosted bridge expects (one frame == one
// BlePacket).
//
// Inbound: read those frames back, btp-decode each, feed the dechunker,
// and hand any fully reassembled QL2 record to the runtime.

fn spawn_tcp_btp_bridge(outbound: Receiver<Vec<u8>>, inbound: Sender<Vec<u8>>, stream: TcpStream) {
    let (mut rd, mut wr) = stream.into_split();

    tokio::spawn(async move {
        let (mut records, mut frames) = (0u64, 0u64);
        while let Ok(record) = outbound.recv().await {
            records += 1;
            let mut n = 0u64;
            for chunk in btp::chunk(&record) {
                let len = (chunk.len() as u32).to_be_bytes();
                if wr.write_all(&len).await.is_err() || wr.write_all(&chunk).await.is_err() {
                    log::error!("[tx] transport write failed — link down");
                    return;
                }
                n += 1;
                frames += 1;
            }
            log::debug!(
                "[tx] record #{records} ({} B) → {n} btp frames (total {frames} frames out)",
                record.len()
            );
        }
        log::warn!("[tx] outbound channel closed (runtime dropped sender)");
    });

    tokio::spawn(async move {
        let mut dechunker = btp::MasterDechunker::<10>::default();
        let (mut frames, mut decoded, mut errs, mut records) = (0u64, 0u64, 0u64, 0u64);
        loop {
            let mut len_buf = [0u8; 4];
            if rd.read_exact(&mut len_buf).await.is_err() {
                log::error!("[rx] transport closed by peer (after {frames} frames in)");
                return;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            if rd.read_exact(&mut payload).await.is_err() {
                log::error!("[rx] transport truncated mid-frame");
                return;
            }
            frames += 1;
            let chunk = match btp::Chunk::decode(&payload) {
                Ok(c) => c,
                Err(e) => {
                    errs += 1;
                    log::warn!("[rx] bad btp chunk (frame {frames}, {len} B): {e:?}");
                    continue;
                }
            };
            decoded += 1;
            let h = chunk.header;
            log::debug!(
                "[rx] frame {frames}: btp chunk msg_id={} idx={}/{} data_len={}",
                h.message_id,
                h.index,
                h.total_chunks,
                h.data_len
            );
            if let Some(record) = dechunker.insert_chunk(chunk) {
                records += 1;
                log::debug!(
                    "[rx] reassembled record #{records} ({} B) [{frames} frames, {decoded} decoded, {errs} errs]",
                    record.len()
                );
                if inbound.send(record).await.is_err() {
                    return;
                }
            }
        }
    });
}

// ===== QlPlatform (channel-backed, crypto delegated to SoftwareCrypto) =====
//
// Same shape as ql-bench-v2's BenchPlatform / ql-runtime's TestPlatform:
// the runtime talks to channels, the bridge above lifts those onto TCP.

struct Plumbing {
    outbound_rx: Receiver<Vec<u8>>,
    inbound_tx: Sender<Vec<u8>>,
    status_rx: Receiver<PeerStatus>,
    peer_rx: Receiver<PeerBundle>,
    inbound_streams_rx: Receiver<(StreamInfo, QlStream)>,
}

struct BackendPlatform {
    outbound: Sender<Vec<u8>>,
    inbound: Option<Receiver<Vec<u8>>>,
    status: Sender<PeerStatus>,
    peer: Sender<PeerBundle>,
    inbound_streams: Sender<(StreamInfo, QlStream)>,
    crypto: SoftwareCrypto,
    #[cfg(feature = "mcp")]
    mcp_events: Option<tokio::sync::broadcast::Sender<mcp::BackendEvent>>,
}

impl BackendPlatform {
    fn new() -> (Self, Plumbing) {
        let (outbound_tx, outbound_rx) = async_channel::unbounded();
        let (inbound_tx, inbound_rx) = async_channel::unbounded();
        let (status_tx, status_rx) = async_channel::unbounded();
        let (peer_tx, peer_rx) = async_channel::unbounded();
        let (inbound_streams_tx, inbound_streams_rx) = async_channel::unbounded();
        (
            Self {
                outbound: outbound_tx,
                inbound: Some(inbound_rx),
                status: status_tx,
                peer: peer_tx,
                inbound_streams: inbound_streams_tx,
                crypto: SoftwareCrypto,
                #[cfg(feature = "mcp")]
                mcp_events: None,
            },
            Plumbing {
                outbound_rx,
                inbound_tx,
                status_rx,
                peer_rx,
                inbound_streams_rx,
            },
        )
    }

    #[cfg(feature = "mcp")]
    fn with_mcp_events(mut self, tx: tokio::sync::broadcast::Sender<mcp::BackendEvent>) -> Self {
        self.mcp_events = Some(tx);
        self
    }
}

struct BackendInbound {
    rx: Receiver<Vec<u8>>,
}

impl QlInbound for BackendInbound {
    fn poll_recv(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        let rx = unsafe { self.as_mut().map_unchecked_mut(|this| &mut this.rx) };
        match rx.poll_next(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(bytes),
            // Channel closed: park forever rather than panic. The runtime
            // is being torn down (transport bridge dropped its sender on
            // shutdown); a panic here is a cleanup race, not a real fault.
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }
}

struct TokioTimer {
    sleep: Pin<Box<Sleep>>,
}

fn parked_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60 * 60 * 24 * 365 * 100)
}

impl QlTimer for TokioTimer {
    fn set_deadline(mut self: Pin<&mut Self>, deadline: Option<std::time::Instant>) {
        let deadline = deadline.map_or_else(parked_deadline, tokio::time::Instant::from_std);
        self.as_mut().get_mut().sleep.as_mut().reset(deadline);
    }

    fn poll_wait(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.as_mut().get_mut().sleep.as_mut().poll(cx)
    }
}

impl QlRandom for BackendPlatform {
    fn fill_random_bytes(&self, data: &mut [u8]) {
        self.crypto.fill_random_bytes(data);
    }
}

impl QlHash for BackendPlatform {
    fn sha256(&self, parts: &[&[u8]]) -> [u8; 32] {
        self.crypto.sha256(parts)
    }
}

impl QlAead for BackendPlatform {
    fn aes256_gcm_encrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE] {
        self.crypto.aes256_gcm_encrypt(key, nonce, aad, buffer)
    }

    fn aes256_gcm_decrypt(
        &self,
        key: &SessionKey,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        auth_tag: &[u8; ql_wire::ENCRYPTED_MESSAGE_AUTH_SIZE],
    ) -> bool {
        self.crypto
            .aes256_gcm_decrypt(key, nonce, aad, buffer, auth_tag)
    }
}

impl QlKem for BackendPlatform {
    fn mlkem_generate_keypair(&self) -> MlKemKeyPair {
        self.crypto.mlkem_generate_keypair()
    }

    fn mlkem_encapsulate(&self, public_key: &MlKemPublicKey) -> (MlKemCiphertext, SessionKey) {
        self.crypto.mlkem_encapsulate(public_key)
    }

    fn mlkem_decapsulate(&self, pk: &MlKemPrivateKey, cipher: &MlKemCiphertext) -> SessionKey {
        self.crypto.mlkem_decapsulate(pk, cipher)
    }
}

impl QlPlatform for BackendPlatform {
    type Timer = TokioTimer;
    type WriteMessageFut<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
    type Inbound = BackendInbound;

    fn write_message(&self, message: Vec<u8>) -> Self::WriteMessageFut<'_> {
        let outbound = self.outbound.clone();
        Box::pin(async move { outbound.send(message).await.is_ok() })
    }

    fn inbound(&mut self) -> Self::Inbound {
        BackendInbound {
            rx: self
                .inbound
                .take()
                .expect("BackendPlatform::inbound may only be called once"),
        }
    }

    fn timer(&self) -> Self::Timer {
        TokioTimer {
            sleep: Box::pin(tokio::time::sleep_until(parked_deadline())),
        }
    }

    fn persist_peer(&self, peer: PeerBundle) {
        log::info!("[peer] runtime persisted a peer bundle (XX pairing established a new peer)");
        let _ = self.peer.try_send(peer);
    }

    fn handle_peer_status(&self, peer: Option<QID>, status: PeerStatus) {
        log::info!("[status] peer={peer:?} status={status:?}");
        let _ = self.status.try_send(status);
        #[cfg(feature = "mcp")]
        if let Some(tx) = &self.mcp_events {
            let _ = tx.send(mcp::BackendEvent::StatusChanged {
                state: status,
                bt_connected: matches!(status, PeerStatus::Connected | PeerStatus::Initiator),
                peer_known: peer.is_some(),
            });
        }
    }

    fn handle_inbound(&self, info: StreamInfo, stream: QlStream) {
        // The peer opened a stream to us (device-initiated RPC). Hand it
        // to the serve loop; if no one is serving, it's simply dropped.
        let _ = self.inbound_streams.try_send((info, stream));
    }
}

async fn await_status(
    rx: &Receiver<PeerStatus>,
    target: PeerStatus,
    timeout: Duration,
) -> Result<(), ()> {
    let fut = async {
        loop {
            match rx.recv().await {
                Ok(s) if s == target => return,
                Ok(_) => continue,
                Err(_) => panic!("status channel closed before pairing completed"),
            }
        }
    };
    tokio::time::timeout(timeout, fut).await.map_err(|_| ())
}

/// Chat input loop: listens on TCP, reads lines, pushes each as a ChatPush
/// notification to the connected device. Pipe a line to the listener to send
/// (e.g. `echo "hi" | nc 127.0.0.1 9999`).
#[cfg(feature = "chat")]
async fn chat_input_loop(handle: RuntimeHandle, addr: String) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[backend] chat input: cannot bind {addr}: {e}");
            return;
        }
    };
    println!(
        "[backend] chat input: pipe a line to {addr} \
         (e.g. `echo hi | nc 127.0.0.1 9999`) to push to the device"
    );

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[backend] chat input accept: {e}");
                continue;
            }
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(sock).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.is_empty() {
                    continue;
                }
                println!("[backend] chat → device (from {peer}): {line:?}");
                if let Err(e) = handle.rpc().notification::<ChatPush>(&line).await {
                    eprintln!("[backend] chat push failed: {e:?}");
                }
            }
        });
    }
}
