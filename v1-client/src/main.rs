//! QuantumLink v1 (GSTP) client -- the Envoy/companion peer.
//!
//! Inverse of KeyOS-dev os/quantum-link/src/main.rs (the Passport peer):
//! seals an EnvoyMessage to the device, unseals the device's PassportMessage.
//!
//!   companion (this)  --PairingRequest-->  device
//!   companion (this)  <--PairingResponse-- device
//!   companion (this)  --EnvoyStatus------>  device   (one demo message)
//!
//! Wire stack: GSTP envelope CBOR <-> btp chunk(s) <-> 4-byte len-prefixed TCP.

mod transport;

use chrono::Utc;
use foundation_api::{
    bc_envelope::{prelude::CBOR, Envelope},
    bc_xid::XIDDocument,
    dcbor::CBOREncodable,
    message::{EnvoyMessage, PassportMessage, QuantumLinkMessage, PROTOCOL_VERSION},
    pairing::PairingRequest,
    quantum_link::{ARIDCache, QuantumLink, QuantumLinkIdentity},
    status::EnvoyStatus,
};

use crate::transport::Transport;

const DEFAULT_ADDR: &str = "127.0.0.1:8765";

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let addr = std::env::var("QL_V1_BRIDGE_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());

    // The device only decrypts a PairingRequest sealed to its own XID. v1 has no
    // over-the-wire XID exchange (the device shows it as an on-screen QR), so it
    // must be supplied out-of-band as hex of the XIDDocument CBOR.
    let device_xid = load_device_xid()?;

    let me = QuantumLinkIdentity::generate();
    let my_priv = me.private_keys.clone().expect("generate() always sets private_keys");
    log::info!("companion XID generated; dialing {addr}");

    let mut t = Transport::connect(&addr)?;
    let mut replay = ARIDCache::new();

    // 1. PairingRequest carrying our XID document (CBOR bytes), sealed to the device.
    let pairing = QuantumLinkMessage::PairingRequest(PairingRequest {
        xid_document: me.xid_document.to_cbor_data(),
        device_name: "ql-link-lab v1".to_string(),
    });
    send(&mut t, pairing, &my_priv, &me.xid_document, &device_xid)?;
    log::info!("sent PairingRequest, awaiting PairingResponse");

    // 2. Receive loop: unseal each PassportMessage and react.
    loop {
        let cbor = t.recv_envelope()?;
        let envelope = Envelope::try_from_cbor(CBOR::try_from_data(&cbor)?)?;
        let (msg, sender) =
            PassportMessage::unseal_passport_message_with_replay_check(&envelope, &my_priv, &mut replay)?;
        log::info!("device -> {:?}", msg.message);

        match msg.message {
            QuantumLinkMessage::PairingResponse(resp) => {
                log::info!("paired with {sender:?}: {resp:?}");
                // 3. One demo message after pairing, then exit.
                let status = QuantumLinkMessage::EnvoyStatus(EnvoyStatus {
                    version: "ql-link-lab/0.1".to_string(),
                });
                send(&mut t, status, &my_priv, &me.xid_document, &device_xid)?;
                log::info!("sent EnvoyStatus; done");
                return Ok(());
            }
            other => log::info!("ignoring pre-pairing message: {other:?}"),
        }
    }
}

fn send(
    t: &mut Transport,
    msg: QuantumLinkMessage,
    my_priv: &foundation_api::bc_components::PrivateKeys,
    my_xid: &XIDDocument,
    device_xid: &XIDDocument,
) -> anyhow::Result<()> {
    let envoy = EnvoyMessage {
        message: msg,
        timestamp: Utc::now().timestamp() as u32,
        protocol_version: Some(PROTOCOL_VERSION),
    };
    let envelope = QuantumLink::seal(envoy, (my_priv, my_xid), device_xid);
    t.send_envelope(&envelope.to_cbor_data())?;
    Ok(())
}

/// Device XID from `QL_V1_DEVICE_XID` (hex of XIDDocument CBOR) or
/// `--device-xid <path>` (file of the same hex).
fn load_device_xid() -> anyhow::Result<XIDDocument> {
    let hex_str = if let Ok(h) = std::env::var("QL_V1_DEVICE_XID") {
        h
    } else if let Some(path) = std::env::args().skip_while(|a| a != "--device-xid").nth(1) {
        std::fs::read_to_string(path)?
    } else {
        anyhow::bail!(
            "device XID required: set QL_V1_DEVICE_XID=<hex of XIDDocument CBOR> or pass \
             --device-xid <file>. v1 has no over-the-wire XID exchange; the device shows it \
             as an on-screen QR (ql_utils::animated_qr)."
        );
    };
    let bytes = hex::decode(hex_str.trim())?;
    Ok(XIDDocument::try_from(CBOR::try_from_data(&bytes)?)?)
}
