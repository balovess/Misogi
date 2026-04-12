# =============================================================================
# Misogi (禊) — Multi-Stage Docker Build
# =============================================================================
# Cross-network secure file transfer system with CDR sanitization.
#
# Usage:
#   docker build -t misogi .
#   docker run -p 3001:3001 misogi                          # sender (default)
#   docker run -p 3002:3002 -p 9000:9000 --entrypoint misogi-receiver misogi  # receiver
#   docker compose up -d                                    # both services
#
# Environment Variables:
#   All MISOGI_* variables are supported for runtime configuration.
#   See docker/env.example for full reference.
# =============================================================================

# ---- Stage 1: Builder -------------------------------------------------------
FROM rust:1.85-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

ARG BUILD_PROFILE=release
RUN cargo build --profile ${BUILD_PROFILE} --workspace

# ---- Stage 2: Runtime (Sender) ----------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r misogi && useradd -r -g misogi -d /data -s /sbin/nologin misogi \
    && mkdir -p /data/uploads /data/staging /data/chunks /data/downloads \
    && chown -R misogi:misogi /data

WORKDIR /data

COPY --from=builder /app/target/release/misogi-sender /usr/local/bin/
COPY --from=builder /app/target/release/misogi-receiver /usr/local/bin/

USER misogi

EXPOSE 3001 3002 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/curl", "-f", "http://localhost:${MISOGI_PORT:-3001}/api/v1/health"] || exit 1

ENV MISOGI_SERVER_ADDR="0.0.0.0:3001" \
    MISOGI_UPLOAD_DIR="/data/uploads" \
    MISOGI_STAGING_DIR="/data/staging" \
    MISOGI_LOG_LEVEL="info"

ENTRYPOINT ["misogi-sender"]
CMD ["--mode", "server"]
