#!/bin/bash
set -e

# ── Bandwidth limiting via tc (traffic control) ──────────────────
# Default: 10mbit.  Set LXMD_BANDWIDTH_LIMIT=0 or =none to disable.
BW="${LXMD_BANDWIDTH_LIMIT:-10mbit}"

if [ "$BW" != "0" ] && [ "$BW" != "none" ]; then
    IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$IFACE" ]; then
        # Token Bucket Filter: rate=limit, burst=bucket size, latency=max wait
        tc qdisc replace dev "$IFACE" root tbf \
            rate "$BW" burst 256kbit latency 400ms 2>/dev/null || \
            echo "[entrypoint] Warning: could not apply bandwidth limit (need NET_ADMIN)"
        echo "[entrypoint] Bandwidth limit: ${BW} on ${IFACE}"
    else
        echo "[entrypoint] Warning: no default interface found, skipping bandwidth limit"
    fi
else
    echo "[entrypoint] Bandwidth limiting disabled"
fi

# ── Generate Reticulum config if missing ─────────────────────────
# Docker's bridge network kills AutoInterface (multicast).  We need
# a TCPServerInterface so clients can reach us, plus TCPClientInterface
# connections to public transport nodes so announces propagate.
RNS_CONFIG="/data/reticulum/config"

if [ ! -f "$RNS_CONFIG" ]; then
    echo "[entrypoint] Generating Reticulum config with TCP interfaces..."
    mkdir -p /data/reticulum 2>/dev/null || true
    cat > "$RNS_CONFIG" << 'RNSEOF'
# Reticulum configuration — auto-generated for Docker propagation node

[reticulum]
  enable_transport = Yes
  share_instance = Yes
  instance_name = default

[logging]
  loglevel = 4

[interfaces]

  # ── Inbound: let clients connect to this node ──────────────
  [[Propagation TCP Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 37428

  # ── Outbound: connect to a public transport node ────────────
  [[RNS Testnet BetweenTheBorders]]
    type = TCPClientInterface
    enabled = yes
    target_host = reticulum.betweentheborders.com
    target_port = 4242

RNSEOF
    echo "[entrypoint] Reticulum config written to ${RNS_CONFIG}"
else
    echo "[entrypoint] Using existing Reticulum config at ${RNS_CONFIG}"
fi

# ── Run lxmd ──────────────────────────────────────────────────────
exec lxmd "$@"
