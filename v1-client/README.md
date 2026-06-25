# v1-client — QL v1 (GSTP) test client

A standalone QL v1 companion/Envoy peer that pairs with the hosted KeyOS sim over
the BLE-over-TCP bridge (`KeyOS-dev/os/bt/src/hosted.rs`, `:8765`). It seals a
`PairingRequest` to the device, completes the v1 handshake, and sends one
`EnvoyStatus`. Standalone workspace because v1 pins `foundation-api`/`btp` @ tag
5.7.0, which conflicts with the parent foundation-lab (v2) crates' btp.

## Run

The device shows its XID only as an on-screen QR (no over-the-wire exchange), so
supply it out-of-band. With the sim running (bridge listening on `:8765`):

    QL_V1_DEVICE_XID=<hex of XIDDocument CBOR> cargo run

Override the bridge address with `QL_V1_BRIDGE_ADDR` (default `127.0.0.1:8765`).

See `FOUNDATION/.memory/ql-implementations.md` for the full reproduce recipe
(device-XID emission, os-version stub, disk wipe).
