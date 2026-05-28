//! Foundation Link — the QLRP relay.
//!
//! This is a pure, opaque byte forwarder. It connects the device side
//! (the KeyOS hosted-sim BLE bridge, which LISTENS on 127.0.0.1:8765) to
//! the backend side (which connects to the relay on 127.0.0.1:8766) and
//! shovels bytes between them without ever looking inside.
//!
//! The QL v2 session is end-to-end between the device and the backend:
//! the relay holds no keys and cannot decrypt anything it carries. The
//! byte counters it prints are the proof — it only ever sees ciphertext.
//!
//! Topology (no central router, three hops):
//!
//!   device-sim  ──TCP:8765──►  relay  ──TCP:8766──►  backend
//!     (bridge listens)                (relay listens)

use std::time::Instant;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};

const BACKEND_LISTEN: &str = "127.0.0.1:8766";
const DEVICE_BRIDGE: &str = "127.0.0.1:8765";

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind(BACKEND_LISTEN)
        .await
        .unwrap_or_else(|e| panic!("[relay] cannot bind {BACKEND_LISTEN}: {e}"));
    println!("[relay] Foundation Link up — backend connects on {BACKEND_LISTEN}, device bridge at {DEVICE_BRIDGE}");

    loop {
        let (backend, backend_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("[relay] accept error: {e}");
                continue;
            }
        };
        println!(
            "[relay] backend connected from {backend_addr}; dialing device bridge {DEVICE_BRIDGE}"
        );

        let device = match TcpStream::connect(DEVICE_BRIDGE).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[relay] cannot reach device bridge {DEVICE_BRIDGE}: {e} — dropping backend"
                );
                continue;
            }
        };
        println!("[relay] link established: {backend_addr} <──opaque QLRP──> {DEVICE_BRIDGE}");

        // One pairing at a time — handle this link to completion, then
        // loop for the next backend (mirrors the bridge, which accepts a
        // single relay connection).
        tokio::spawn(handle_link(backend, device, backend_addr.to_string()));
    }
}

async fn handle_link(mut backend: TcpStream, mut device: TcpStream, who: String) {
    let _ = backend.set_nodelay(true);
    let _ = device.set_nodelay(true);

    let started = Instant::now();
    match copy_bidirectional(&mut backend, &mut device).await {
        Ok((backend_to_device, device_to_backend)) => {
            println!(
                "[relay] link {who} closed after {:.1}s — forwarded {backend_to_device} B backend→device, \
                 {device_to_backend} B device→backend (all opaque ciphertext, never decrypted)",
                started.elapsed().as_secs_f64()
            );
        }
        Err(e) => {
            eprintln!(
                "[relay] link {who} error after {:.1}s: {e}",
                started.elapsed().as_secs_f64()
            );
        }
    }
}
