# lxmd — LXMF Propagation Node (Rust)

A lightweight, containerised LXMF store-and-forward propagation node built in
Rust.  Uses the `lxmf_rust` and `reticulum_rust` crates for a ~5 MB static
binary with near-zero startup time and minimal memory footprint.

## Quick Start

```bash
cd LXMF-rust/docker

# Copy and edit the environment file
cp .env.example .env

# Build and run
docker compose up -d

# View logs
docker compose logs -f lxmd

# Stop
docker compose down
```

## What It Does

The container runs `lxmd`, a Rust binary that:

1. Initialises a Reticulum transport instance
2. Creates (or loads) a persistent LXMF identity
3. Starts an LXMF propagation node that:
   - Stores and forwards messages for offline peers
   - Automatically peers with other propagation nodes
   - Announces itself at configurable intervals
   - Persists messages and identity across container restarts
4. Applies a kernel-level egress bandwidth cap (default: **10 Mbit/s**)

## Configuration

All settings are controlled via environment variables or CLI flags.

| Variable | Default | Description |
|---|---|---|
| `LXMD_NODE_NAME` | `Rust Propagation Node` | Display name in announces |
| `LXMD_ANNOUNCE_INTERVAL` | `360` | Announce interval (minutes) |
| `LXMD_STORAGE_LIMIT_MB` | `500` | Message store size limit |
| `LXMD_PORT` | `37428` | Host port for Reticulum |
| `LXMD_STATIC_PEERS` | *(empty)* | Comma-separated peer hashes |
| `LXMD_BANDWIDTH_LIMIT` | `10mbit` | Max egress bandwidth (`0` or `none` to disable) |

## Bandwidth Limiting

The container uses Linux `tc` (traffic control) to enforce a Token Bucket
Filter on the container's default network interface.  This caps **egress**
throughput at the configured rate, preventing the node from saturating your
uplink.

```bash
# Default: 10 Mbit/s
LXMD_BANDWIDTH_LIMIT=10mbit

# Slower link (e.g. LoRa gateway)
LXMD_BANDWIDTH_LIMIT=500kbit

# Disable limiting entirely
LXMD_BANDWIDTH_LIMIT=none
```

Any `tc`-compatible rate string is accepted: `10mbit`, `1mbit`, `500kbit`,
`100kbit`, etc.

> **Note:** The container requires the `NET_ADMIN` capability (already set in
> `docker-compose.yml`) so that `tc` can configure the queueing discipline.
> The `lxmd` binary itself still runs as the unprivileged `lxmd` user — only
> the entrypoint script needs root briefly for the `tc` call.

## Volumes

| Mount | Purpose |
|---|---|
| `lxmd-data` → `/data/lxmd` | Identity, message store, peer state |
| `rns-data` → `/data/reticulum` | Reticulum config and transport state |

## Reticulum Network Config

To connect to the wider Reticulum network, you need a Reticulum config file
with at least one TCP interface. On first run the container creates a default
config. You can then edit it:

```bash
# Find the volume
docker volume inspect docker_rns-data

# Edit the config (path from Mountpoint above)
sudo vim /var/lib/docker/volumes/docker_rns-data/_data/config

# Add a TCP interface, e.g.:
# [[TCP Client Interface]]
#   type = TCPClientInterface
#   enabled = yes
#   target_host = reticulum.betweentheborders.com
#   target_port = 4242

# Restart to pick up changes
docker compose restart lxmd
```

## Running Without Docker

```bash
cd LXMF-rust
cargo build --release --bin lxmd

# Run directly
./target/release/lxmd \
  --config ~/.lxmd \
  --name "My Node" \
  --announce-at-start \
  --storage-limit 1000
```

## CLI Reference

```
lxmd [OPTIONS]

  --config <DIR>            Config/storage directory (default: ~/.lxmd)
  --rnsconfig <DIR>         Reticulum config directory
  --identity <FILE>         Identity file path (default: <config>/identity)
  --name <NAME>             Node display name
  --announce-interval <MIN> Announce interval in minutes (default: 360)
  --announce-at-start       Announce on startup (default)
  --no-announce-at-start    Skip startup announce
  --autopeer                Enable auto-peering (default)
  --no-autopeer             Disable auto-peering
  --autopeer-maxdepth <N>   Max peering depth (default: 4)
  --storage-limit <MB>      Storage limit in MB (default: 500)
  --static-peer <HASH>      Add static peer (repeatable)
  --from-static-only        Only accept from static peers
  --stamp-cost <N>          Stamp cost target (default: 16)
  --stamp-flexibility <N>   Stamp cost flexibility (default: 3)
  --peering-cost <N>        Peering cost (default: 18)
  --max-peering-cost <N>    Max remote peering cost (default: 26)
  --max-peers <N>           Max auto-peers (default: 20)
  -v, --verbose             Increase verbosity
  -q, --quiet               Decrease verbosity
  -h, --help                Show help
```
