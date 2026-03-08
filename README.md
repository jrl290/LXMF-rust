# LXMF-rust

A Rust implementation of the [LXMF](https://github.com/markqvist/LXMF) (Lightweight Extensible Message Format) protocol for [Reticulum](https://reticulum.network/) networks. LXMF provides reliable, encrypted, store-and-forward messaging over any transport that Reticulum supports — from LoRa and packet radio to TCP and I2P.

## About

LXMF-rust is a from-scratch Rust port of the [Python LXMF reference implementation](https://github.com/markqvist/LXMF) (achieving module parity), built on top of [Rusticulum](https://github.com/jrl290/Rusticulum) (the Rust Reticulum transport layer). It provides the same messaging capabilities as the Python version with the performance and safety benefits of Rust — a ~5 MB statically-linked binary with near-zero startup time.

### AI-Assisted Development

This codebase was generated with significant assistance from **GitHub Copilot (Claude)**, acting as an AI pair-programming partner. The AI translated protocol logic from the Python LXMF reference implementation into idiomatic Rust, designed the module architecture, and helped debug interoperability issues during live hardware testing. All code was reviewed, tested, and validated by the human developer against the reference implementation and real Reticulum network hardware.

## Features

### Message Delivery Methods

| Method | Description | Transport |
|--------|-------------|-----------|
| **Opportunistic** | Send when a path is available | Direct packet via Reticulum path |
| **Direct** | Establish a dedicated encrypted link | Link-based, with resource transfer for large messages |
| **Propagated** | Store-and-forward via propagation nodes | Peer sync protocol |
| **Paper** | QR-code encodable messages | Offline transfer |

### Message Lifecycle

Messages are tracked through a full state machine: `GENERATING` → `OUTBOUND` → `SENDING` → `SENT` → `DELIVERED`, with error states for `REJECTED`, `CANCELLED`, and `FAILED`. Delivery proofs confirm receipt end-to-end.

### Core Protocol

- **LXMessage** — Full message type with title, content, timestamps, signatures, file attachments, and extensible fields (telemetry, images, audio, threading, group chat, commands)
- **LXMRouter** — Central routing engine with delivery processing, path management, retry logic (up to 5 attempts), and 30-day message expiry
- **LXMPeer** — Per-peer synchronization state with transfer rate tracking, backoff, and error handling
- **Stamping** — Proof-of-work system (HKDF-SHA256 workblocks) for DoS resistance with configurable difficulty
- **Tickets** — Delivery/propagation tickets that reduce stamp cost for trusted senders (21-day expiry, 14-day renewal)

### Propagation Node

LXMF-rust includes a full propagation node (`lxmd`) for store-and-forward infrastructure:

- Automatic peer discovery and synchronization
- Configurable storage limits, stamp costs, and peering costs
- Static and auto-peered node relationships (max depth control)
- Bandwidth-aware sync with per-transfer and per-sync byte limits
- Access control lists (allowed, ignored, prioritised destinations)
- Persistent storage across restarts

### Protocol Fields

Rich message content via MessagePack-encoded fields:

| Field | Description |
|-------|-------------|
| `FILE_ATTACHMENTS` | Binary file data with filenames |
| `IMAGE` / `AUDIO` | Media content with codec support |
| `TELEMETRY` | Sensor data and telemetry streams |
| `THREAD` | Conversation threading |
| `COMMANDS` / `RESULTS` | RPC command execution |
| `GROUP` | Group messaging metadata |
| `TICKET` | Delivery cost reduction tickets |
| `RENDERER` | Display hints (Plain, Micron, Markdown, BBCode) |

### Audio Codec Support

Codec2 (450–3200 bps) and Opus (LBW through Lossless) codec identifiers for audio messaging over bandwidth-constrained links.

### FFI (Foreign Function Interface)

Handle-based C-compatible API for integration with Android (JNI), iOS, and other languages. `ReceivedMessage` structs provide plain-data snapshots safe for marshalling across language boundaries.

## CLI Binaries

### lxmf_send

Send LXMF messages from the command line:

```bash
# Send a text message
lxmf_send --net=local --message "Hello from Rust"

# Send with file attachment
lxmf_send --to=<destination_hash> --direct --attach=document.pdf

# Generate bulk test traffic
lxmf_send --size-mb=1.5 --repeat=10

# Read content from stdin
echo "Message body" | lxmf_send --net=rpi
```

Options: `--direct`, `--opportunistic`, `--auto` (delivery method), `--net=local|rpi` (network config), `--timeout=<seconds>`, `--size-mb=<float>` (synthetic payload).

### lxmf_recv

Receive and display LXMF messages:

```bash
# Start receiver with default identity
lxmf_recv

# Custom display name and announce interval
lxmf_recv --name "My Node" --announce-interval 60

# Verbose output with all fields
lxmf_recv --verbose
```

Displays source/destination hashes, title, content, timestamps, signal metrics (RSSI, SNR, link quality), and delivery confirmations.

### lxmd

Run a propagation node:

```bash
# Basic propagation node
lxmd

# Production configuration
lxmd --name "My Propagation Node" \
     --storage-limit 500 \
     --stamp-cost 16 \
     --announce-interval 360 \
     --announce-at-start \
     --static-peer <peer_hash>
```

Options: `--config <dir>`, `--rnsconfig <dir>`, `--identity <file>`, `--autopeer` / `--no-autopeer`, `--autopeer-maxdepth <N>`, `--peering-cost <N>`, `--max-peers <N>`, `--from-static-only`, `-v` / `-q` (verbosity).

## Docker Deployment

Deploy a propagation node with Docker:

```bash
cd docker
cp .env.example .env
# Edit .env with your settings
docker compose up -d
```

Features:
- **Multi-stage build** — Rust 1.82 builder + Debian slim runtime
- **Bandwidth limiting** — Kernel `tc` traffic control (e.g., `10mbit`, `500kbit`)
- **Non-root execution** — Runs as dedicated `lxmd` user
- **Persistent volumes** — Identity and message store survive restarts
- **Port 37428** — Standard Reticulum network port

See [docker/README.md](docker/README.md) for full configuration.

## Building

```bash
# Release build
cargo build --release

# The Reticulum-rust dependency is expected at ../Reticulum-rust/
# (path dependency in Cargo.toml)
```

### Dependencies

Requires Rust 2021 edition. Key dependencies:
- **[Rusticulum](https://github.com/jrl290/Rusticulum)** — Rust Reticulum transport layer (path dependency)
- **Serialization**: rmp-serde, rmpv (MessagePack — wire-compatible with Python LXMF)
- **Cryptography**: hkdf, sha2 (stamp workblock generation)
- **Runtime**: tokio (async), ctrlc (signal handling)

## Testing

### Cross-Implementation Interoperability

LXMF-rust has been tested extensively for interoperability with the Python Reticulum/LXMF ecosystem:

- **Python LXMF ↔ Rust LXMF** — Bidirectional message delivery between Python and Rust nodes, verifying wire-format compatibility of MessagePack-encoded messages, signatures, and delivery proofs
- **Sideband mobile client** — Messages sent from Rust nodes received and displayed correctly on Sideband (Android), and vice versa
- **Python rnsd** — Rust LXMF binaries communicating through Python Reticulum daemon infrastructure

### Hardware Testing

- **RNode boundary nodes** (Heltec V4, GAT562) — LXMF message delivery over LoRa via KISS-framed RNode links
- **TCP transport** — LAN and WAN message delivery with link establishment and resource transfer
- **Resource transfer** — Large message delivery (multi-packet) with compression over linked connections, testing the PACKET → RESOURCE auto-escalation

### Test Harnesses

Dedicated test infrastructure in the development workspace:

- **Sender/receiver pairs** — Automated `lxmf_send` / `lxmf_recv` test configurations against multiple network topologies
- **Propagation node testing** — `lxmd` daemon tested with peer discovery, message sync, and store-and-forward scenarios
- **CLI test scripts** — V3 boundary node message exchange, bulk message generation, attachment delivery, and delivery method coverage

## Project Structure

```
src/
├── lib.rs              # Library root: exports, key decode helper
├── lx_message.rs       # Message types, states, delivery methods, wire format
├── lxm_router.rs       # Central routing engine, delivery processing, retry logic
├── lxm_peer.rs         # Per-peer sync state, transfer tracking, error handling
├── lxmf.rs             # Protocol constants, field types, codec IDs
├── lx_stamper.rs       # Proof-of-work stamping (HKDF-SHA256 workblocks)
├── handlers.rs         # Announce handlers for delivery and propagation
├── cli_util.rs         # CLI argument parsing and formatting helpers
├── ffi.rs              # C/JNI FFI bindings with ReceivedMessage snapshots
├── utilities.rs        # Daemon utilities
├── version.rs          # Version constant (0.9.4)
└── bin/
    ├── lxmf_send.rs    # Message sender CLI
    ├── lxmf_recv.rs    # Message receiver daemon
    └── lxmd.rs         # Propagation node daemon
docker/
├── Dockerfile          # Multi-stage build (Rust builder + Debian runtime)
├── docker-compose.yml  # Production deployment with bandwidth limiting
├── entrypoint.sh       # Startup with tc traffic control
├── .env.example        # Environment variable template
└── README.md           # Docker deployment guide
```

## Status

**Active development (v0.9.4).** The core protocol has full module parity with the Python LXMF reference implementation and has been validated in real network scenarios including cross-implementation messaging with Sideband and Python LXMF nodes.

## Related Projects

- [LXMF](https://github.com/markqvist/LXMF) — The original Python reference implementation this project is based on
- [Rusticulum](https://github.com/jrl290/Rusticulum) — Rust implementation of the Reticulum Network Stack (transport layer for this project)
- [Reticulum](https://github.com/markqvist/Reticulum) — The Python Reticulum reference implementation
- [Sideband](https://github.com/markqvist/Sideband) — Mobile LXMF client tested for interoperability

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

- **Mark Qvist** — Creator of [LXMF](https://github.com/markqvist/LXMF) and the [Reticulum Network Stack](https://reticulum.network/)
- **GitHub Copilot (Claude, Anthropic)** — AI pair-programming assistant that helped generate and debug the Rust implementation
