//! QuantumLink v2 backend — the "web service" peer.
//!
//! Topology:  device-sim ──TCP:8765──► relay ──TCP:8766──► THIS
//!
//! This process is the QL v2 *initiator*. It:
//!   1. connects to the relay (which forwards opaquely to the sim's BLE
//!      bridge),
//!   2. runs the XX *pairing* handshake using the out-of-band pairing
//!      token the device printed (`QLV2_PAIRING_QR <ble>:<hex token>`),
//!   3. once the session is up, drives the device's RPC surface as a
//!      client: an `Echo` round-trip, then a `BytesBenchmark` download to
//!      measure end-to-end throughput across the real three-hop path.
//!
//! Wire stack mirrors the device exactly:
//!   QL2 record  ⇄  btp chunk(s)  ⇄  4-byte length-prefixed TCP frame
//!
//! The QL2 session is end-to-end; the relay only ever sees ciphertext.

use std::{
    future::Future,
    pin::Pin,
    str::Utf8Error,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender};
use bytes::{Buf, BufMut};
use futures_lite::Stream;
use ql_fsm::{PeerStatus, QlFsmConfig};
use ql_rpc::{request::Request, subscription::Subscription, RouteId, RpcCodec};
use ql_runtime::{
    new_runtime, QlInbound, QlPlatform, QlStream, QlTimer, RuntimeConfig, RuntimeHandle,
};
use ql_wire::{
    test_identity, MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, Nonce,
    PairingToken, PeerBundle, QlAead, QlHash, QlKem, QlRandom, SessionKey, SoftwareCrypto, XID,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Sleep,
};

const DEFAULT_RELAY: &str = "127.0.0.1:8766";

// ===== RPC surface (must match KeyOS-dev/test-apps/gui-app-qlv2/src/rpc.rs) =====

struct Echo;

impl Request for Echo {
    type Error = Utf8Error;
    type Request = String;
    type Response = String;

    const ROUTE: RouteId = RouteId(1);
}

struct BytesBenchmark;

impl Subscription for BytesBenchmark {
    type Error = std::convert::Infallible;
    type Event = Vec<u8>;
    type Request = BenchmarkRequest;

    const ROUTE: RouteId = RouteId(2);
}

#[derive(Clone)]
struct BenchmarkRequest {
    length: u32,
}

impl RpcCodec for BenchmarkRequest {
    type Error = std::convert::Infallible;

    fn encode_value<B: BufMut + ?Sized>(&self, out: &mut B) {
        out.put_u32(self.length);
    }

    fn decode_value<B: Buf>(bytes: &mut B) -> Result<Self, Self::Error> {
        Ok(BenchmarkRequest {
            length: bytes.get_u32(),
        })
    }
}

// ===== entry point =====

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Surface ql-runtime's internal handshake tracing by default; override
    // with RUST_LOG. This is the only window into why pairing stalls — the
    // device side logs nothing at INFO during the handshake.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,ql_runtime=debug,backend=debug"),
    )
    .init();

    let mut args = std::env::args().skip(1);
    let mut relay = DEFAULT_RELAY.to_string();
    let mut token_hex: Option<String> = None;
    let mut bench_len: u32 = 256 * 1024;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--relay" => relay = args.next().expect("--relay needs an address"),
            "--token" => token_hex = Some(args.next().expect("--token needs a value")),
            "--bench-bytes" => {
                bench_len = args
                    .next()
                    .expect("--bench-bytes needs a value")
                    .parse()
                    .expect("--bench-bytes must be a u32")
            }
            other => panic!("unknown arg: {other}"),
        }
    }

    let token = parse_token(&token_hex.expect(
        "pass --token <hex>  (the part after the last ':' in the sim's \
         `QLV2_PAIRING_QR 12:34:56:78:9A:BC:<hex>` log line)",
    ));

    println!("[backend] connecting to relay {relay}");
    let stream = TcpStream::connect(&relay)
        .await
        .unwrap_or_else(|e| panic!("[backend] cannot reach relay {relay}: {e}"));
    stream.set_nodelay(true).ok();
    println!("[backend] relay link up; starting XX pairing");

    let identity = test_identity(&SoftwareCrypto);
    let (platform, plumbing) = BackendPlatform::new();
    let (runtime, handle) = new_runtime(identity, platform, ble_config());

    tokio::spawn(async move {
        runtime.run().await;
        log::error!("runtime.run() RETURNED — the QL runtime stopped (this should never happen mid-session)");
    });
    spawn_tcp_btp_bridge(plumbing.outbound_rx, plumbing.inbound_tx, stream);

    handle.start_pairing(token);

    match await_status(&plumbing.status_rx, PeerStatus::Connected, Duration::from_secs(30)).await {
        Ok(()) => println!("[backend] *** QL v2 session ESTABLISHED (XX pairing complete) ***"),
        Err(()) => {
            eprintln!("[backend] pairing did not complete within 30s — aborting");
            std::process::exit(1);
        }
    }

    run_echo(&handle).await;
    run_benchmark(&handle, bench_len).await;

    println!("[backend] done — closing session");
}

async fn run_echo(handle: &RuntimeHandle) {
    let msg = "hello from the backend over QL v2".to_string();
    println!("[backend] echo → {msg:?}");
    let started = Instant::now();
    match handle.rpc().request::<Echo>(&msg).await {
        Ok(reply) => {
            let ok = reply == msg;
            println!(
                "[backend] echo ← {reply:?}  ({:.1} ms round-trip, match={ok})",
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
        .subscribe::<BytesBenchmark>(&BenchmarkRequest { length })
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
            Ok(chunk) => received += chunk.len(),
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
         end-to-end (device → relay → backend, QL v2)"
    );
}

fn parse_token(raw: &str) -> PairingToken {
    // Accept either the bare hex token or the whole QR payload
    // `12:34:56:78:9A:BC:<hex>` — the token is whatever follows the last ':'.
    let hex_part = raw.rsplit(':').next().unwrap_or(raw).trim();
    let bytes = hex::decode(hex_part)
        .unwrap_or_else(|e| panic!("token is not valid hex ({e}): {hex_part:?}"));
    let arr: [u8; PairingToken::SIZE] = bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "token must be {} bytes, got {}",
            PairingToken::SIZE,
            bytes.len()
        )
    });
    PairingToken(arr)
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

fn spawn_tcp_btp_bridge(
    outbound: Receiver<Vec<u8>>,
    inbound: Sender<Vec<u8>>,
    stream: TcpStream,
) {
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
                log::error!("[rx] transport closed by relay (after {frames} frames in)");
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
                h.message_id, h.index, h.total_chunks, h.data_len
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
}

struct BackendPlatform {
    outbound: Sender<Vec<u8>>,
    inbound: Option<Receiver<Vec<u8>>>,
    status: Sender<PeerStatus>,
    crypto: SoftwareCrypto,
}

impl BackendPlatform {
    fn new() -> (Self, Plumbing) {
        let (outbound_tx, outbound_rx) = async_channel::unbounded();
        let (inbound_tx, inbound_rx) = async_channel::unbounded();
        let (status_tx, status_rx) = async_channel::unbounded();
        (
            Self {
                outbound: outbound_tx,
                inbound: Some(inbound_rx),
                status: status_tx,
                crypto: SoftwareCrypto,
            },
            Plumbing {
                outbound_rx,
                inbound_tx,
                status_rx,
            },
        )
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
        self.crypto.aes256_gcm_decrypt(key, nonce, aad, buffer, auth_tag)
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

    fn persist_peer(&self, _peer: PeerBundle) {}

    fn handle_peer_status(&self, peer: Option<XID>, status: PeerStatus) {
        log::info!("[status] peer={peer:?} status={status:?}");
        let _ = self.status.try_send(status);
    }

    fn handle_inbound(&self, _stream: QlStream) {}
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
