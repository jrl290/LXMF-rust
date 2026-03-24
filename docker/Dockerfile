# ── Stage 1: Build ────────────────────────────────────────────────
FROM rust:1.82-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev libudev-dev libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy both crates (flat in build dir)
COPY Reticulum-rust/ Reticulum-rust/
COPY LXMF-rust/ LXMF-rust/

# Build only the lxmd binary in release mode
RUN cd LXMF-rust && cargo build --release --bin lxmd \
    && strip target/release/lxmd

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 libdbus-1-3 iproute2 gosu \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd --create-home --shell /bin/bash lxmd

# Copy the built binary
COPY --from=builder /build/LXMF-rust/target/release/lxmd /usr/local/bin/lxmd

# Copy the entrypoint (sits alongside Dockerfile in build dir)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Data directories (will be volume-mounted for persistence)
RUN mkdir -p /data/lxmd /data/reticulum && chown -R lxmd:lxmd /data

# Runs as root initially so tc can set bandwidth limits,
# then entrypoint.sh drops to the lxmd user via gosu.

# Reticulum shared-instance port
EXPOSE 37428

# Entrypoint applies bandwidth shaping then execs lxmd as non-root
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--config", "/data/lxmd", "--rnsconfig", "/data/reticulum"]
