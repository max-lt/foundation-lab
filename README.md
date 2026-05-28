# ql-link-lab

A laboratory for running an end-to-end **QuantumLink v2** session against
the KeyOS hosted simulator, without a real Passport Prime device.

It's the QL2 _initiator_ side (the "companion app" peer) plus a minimal
opaque-byte relay, so the full wire stack — XX/IK handshake, btp
chunking, ql-rpc routes — can be exercised on a laptop with just the
KeyOS sim running.

A small **MCP server** is wired in too, so an AI agent (Claude
Desktop, MCP Inspector, Cline, …) can read live events and drive the
device through tool calls — the same pattern Foundation is building
into FoundationOS/Hydra, in miniature.

## Topology

```
   ┌──────────────────┐
   │  KeyOS sim       │   ── TCP:8765 ───┐
   │  (hosted-mode    │                  │
   │   keyos-kernel)  │                  │
   └──────────────────┘                  │
                                         ▼
                                    ┌─────────┐
                                    │ relay   │   pure opaque byte forwarder.
                                    │ (8765↔  │   sees only ciphertext.
                                    │  8766)  │
                                    └─────────┘
                                         ▲
                                         │ TCP:8766
   ┌──────────────────┐                  │
   │  backend         │  ────────────────┘
   │  (this crate)    │
   │                  │
   │  ┌────────────┐  │
   │  │ MCP server │  │  HTTP+SSE on :8780
   │  │ HTTP+SSE   │  │  ◄─────────────── MCP client (Claude / Inspector / …)
   │  └────────────┘  │
   └──────────────────┘
```

The QL2 session is **end-to-end** between sim and backend; the relay
just shovels bytes and prints counters as proof it never decrypts.

## Crates

| Crate      | What                                                                                                               |
| ---------- | ------------------------------------------------------------------------------------------------------------------ |
| `relay/`   | Opaque TCP forwarder, no QL2 awareness. Run first.                                                                 |
| `backend/` | The QL2 initiator. Drives XX pairing or IK reconnect, exposes the device-side Router, and (optionally) serves MCP. |

## Quick start

In three terminals:

```bash
# 1. KeyOS sim (in the KeyOS-dev workspace, on the qlv2-hosted-fixes branch)
cd path/to/KeyOS-dev
just sim
# Open the QL-V2 app in the simulator UI and grab the pairing QR
# (logged as `gui_app_qlv2: QLV2_PAIRING_QR 12:34:56:78:9A:BC:<hex>`).

# 2. Relay
cd ql-link-lab
cargo run --release --bin relay

# 3. Backend (first-time XX pairing, with MCP)
cd ql-link-lab
cargo run --release --bin backend --features mcp -- \
    --serve --mcp 127.0.0.1:8780 \
    --token 12:34:56:78:9A:BC:01a094fe40eb1392b66b1529555756108a<…>
```

On a successful XX handshake the backend will log:

```
[backend] *** QL v2 session ESTABLISHED (XX pairing complete) ***
[backend] saved peer state to /tmp/ql-link-lab-peer.state — next run reconnects via IK
[backend] serve mode — Router up (Echo). Waiting for device-initiated RPC; Ctrl-C to stop.
[mcp] server listening on http://127.0.0.1:8780
```

Subsequent runs reconnect via **IK** with no token — just
`cargo run --release --bin backend -- --serve --mcp 127.0.0.1:8780`.

## What the backend does

**As an RPC server** (when `--serve`):

| Route                      | Trait        | Behavior                                            |
| -------------------------- | ------------ | --------------------------------------------------- |
| `route::Echo`              | Request      | Reflects the message back.                          |
| `route::BytesBenchmark`    | Subscription | Streams N bytes of zeros in 4 KiB chunks.           |
| `route::DownloadBenchmark` | Download     | Single-part download of N bytes + SHA-256 header.   |
| `ChatSend` (route 100)     | Request      | Echoes the chat text as ack (used by gui-app-chat). |

**As an RPC client** (when not `--serve`):

Runs once: Echo round-trip + BytesBenchmark download, prints
throughput, exits.

**Pairing state** is persisted to `/tmp/ql-link-lab-peer.state` after a
successful XX. Delete this file to force fresh pairing.

## MCP server (`--mcp`)

Behind a `mcp` feature (enabled by default).

### Endpoints

```
GET  /sse                  Persistent SSE stream. First event is an
                           `endpoint` event with the URL to POST to.
                           Subsequent events are MCP JSON-RPC messages:
                           - notifications/message (server → client)
                           - sampling/createMessage (server → client)
                           - tool/method responses (server → client)
POST /messages?id=<uuid>   Client → server JSON-RPC. Accepts both
                           client-initiated requests (initialize,
                           tools/list, tools/call) AND client
                           responses to server-initiated requests
                           (replies to sampling/createMessage).
```

### Tools

| Name                                          | What                                                               |
| --------------------------------------------- | ------------------------------------------------------------------ |
| `chat_send(text)`                             | Push a ChatPush to the device on route 101.                        |
| `chat_history(limit?)`                        | Last N chat entries the backend has seen.                          |
| `session_status()`                            | Current PeerStatus + BT link + peer-known flag.                    |
| `send_echo(text)`                             | Drive the device's Echo RPC (route 1).                             |
| `sample(prompt, system_prompt?, max_tokens?)` | Issue `sampling/createMessage` to the client and return its reply. |

### Notifications

Every backend handler that reacts to traffic publishes a `BackendEvent`
on a shared broadcast channel; the MCP server wraps each one as a
`notifications/message` and pushes it on every active SSE stream.

Event kinds: `chat.received`, `chat.pushed`, `echo.handled`,
`session.status_changed`, `benchmark.completed`, `download.completed`.

### Auto-reply mode (`--auto-reply`)

When this flag is on, the backend runs a loop that:

1. Watches for `BackendEvent::ChatReceived`,
2. Issues `sampling/createMessage` to the connected MCP client,
3. Pushes the client's reply back to the device via ChatPush.

This is the "AI agent in the loop" demo — minimum viable Hydra. It
needs a client that implements the MCP sampling capability (MCP
Inspector, Cline, ContinueDev). Claude Code/Desktop **don't** yet —
see [anthropics/claude-code#1785](https://github.com/anthropics/claude-code/issues/1785).

### Registering the server

With Claude Code:

```bash
claude mcp add ql-link-lab http://127.0.0.1:8780/sse --transport sse
```

With Claude Desktop, edit `claude_desktop_config.json` similarly.

With MCP Inspector (recommended for sampling tests):

```bash
npx @modelcontextprotocol/inspector
# then Connect to http://127.0.0.1:8780/sse, transport SSE
```

## Wire stack

```
ql-rpc framed values
        │
        ▼
QL2 records (XX/IK handshake, then encrypted session)
        │
        ▼
btp chunks (Bluetooth Transport Protocol, here over TCP)
        │
        ▼
4-byte length-prefixed TCP frame
        │
        ▼
TCP loopback (sim ↔ relay ↔ backend)
```

The QL2 session is post-quantum (ML-KEM-1024) and authenticated with
ML-DSA-44; AES-256-GCM is used for the record cipher. The relay is
opaque: it ships bytes between two sockets and never sees plaintext.

## Caveats

- **Single concurrent MCP client.** `primary_session` keeps a "last
  writer wins" reference; that's fine for the demo, not for multi-tenant
  use.
- **Initial status events leak.** The recorder is spawned after the QL2
  handshake finishes, so the first `Disconnected → Initiator → Connected`
  flurry isn't reflected in `session_status` until the next status
  change fires.
- **Auto-reply needs a sampling-capable client.** With Claude Code today
  the loop just logs warnings on every chat — the round-trip can't
  complete.
- **State file is plaintext.** The persisted `(identity ‖ peer bundle)`
  in `/tmp/ql-link-lab-peer.state` is not encrypted. Fine for local dev.

## File layout

```
ql-link-lab/
├── Cargo.toml            workspace + dep pins
├── README.md             this file
├── relay/
│   └── src/main.rs       opaque byte forwarder (8765↔8766)
└── backend/
    ├── Cargo.toml        deps + `chat` and `mcp` features
    └── src/
        ├── main.rs       QL2 initiator + Router + serve loop
        └── mcp.rs        MCP server (HTTP+SSE, tools, sampling)
```
