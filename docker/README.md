[English](README.md) | [日本語](README_ja.md)

# Misogi (禊) — Docker Deployment Guide

Complete reference for building, deploying, configuring, operating, and
troubleshooting Misogi via Docker and Docker Compose.

---

## Table of Contents

1. [Overview & Architecture](#1-overview--architecture)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start](#3-quick-start)
4. [Build Reference](#4-build-reference)
5. [docker-compose.yml Complete Reference](#5-docker-composeyml-complete-reference)
6. [Environment Variable Reference](#6-environment-variable-reference)
7. [API Endpoints](#7-api-endpoints)
8. [Volume & Data Management](#8-volume--data-management)
9. [Networking Guide](#9-networking-guide)
10. [Security Hardening (Production Checklist)](#10-security-hardening-production-checklist)
11. [Operations & Monitoring](#11-operations--monitoring)
12. [Troubleshooting](#12-troubleshooting)
13. [Advanced Deployment Patterns](#13-advanced-deployment-patterns)

---

## 1. Overview & Architecture

### What is Misogi?

Misogi (禊) is a cross-network **secure file transfer system** with built-in
**Content Disarm & Reconstruction (CDR)** sanitization. It is designed for
Japanese government / enterprise environments requiring LGWAN compliance,
PII detection, PPAP elimination, and audit-trail-grade logging.

The system consists of two nodes:

| Node | Binary | Role | Default Port |
|------|--------|------|-------------|
| **Sender** | `misogi-sender` | File upload, CDR sanitization, transfer initiation | 3001 (HTTP), gRPC |
| **Receiver** | `misogi-receiver` | File reception, chunk reassembly, storage | 3002 (HTTP), 9000 (tunnel) |

### Docker Deployment Topology

```
                        ┌─────────────────────────────────────┐
                        │         Docker Host                │
                        │                                     │
   Host ──:3001────────┤  ┌──────────────┐                  │
                        │  │   sender     │  misogi-sender    │
   Host ──:3002────────┤  │  :3001        │                   │
                        │  └──────┬───────┘                  │
   Host ──:9000────────┤         │ misogi-net (bridge)       │
                        │  ┌──────┴───────┐                  │
                        │  │   receiver   │  misogi-receiver  │
                        │  │  :3002 :9000 │                   │
                        │  └──────────────┘                  │
                        │                                     │
                        │  Volumes:                            │
                        │  ├── sender_uploads → /data/uploads │
                        │  ├── sender_staging → /data/staging │
                        │  ├── receiver_chunks → /data/chunks │
                        │  └── receiver_downloads → /data/...  │
                        └─────────────────────────────────────┘
```

### Multi-Stage Build Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Stage 1: Builder (rust:1.85-slim)                               │
│                                                                 │
│   • Install protobuf-compiler (for tonic-build)                 │
│   • Copy workspace source + Cargo.toml/Cargo.lock               │
│   • cargo build --release --workspace                           │
│   • Output: target/release/{misogi-sender,misogi-receiver}      │
│                                                                 │
│   Size: ~2 GB (build cache) — discarded after build             │
├─────────────────────────────────────────────────────────────────┤
│ Stage 2: Runtime (debian:bookworm-slim)                          │
│                                                                 │
│   • Install ca-certificates + curl (for health checks)          │
│   • Create non-root user 'misogi'                               │
│   • Copy only compiled binaries from builder                    │
│   • Set up data directories under /data                         │
│                                                                 │
│   Final image size: ~80 MB                                      │
└─────────────────────────────────────────────────────────────────┘
```

### Why These Base Images?

| Stage | Image | Rationale |
|-------|-------|-----------|
| Builder | `rust:1.85-slim` | Official Rust toolchain with `cargo`, `rustc`; slim variant excludes docs to save ~200 MB |
| Runtime | `debian:bookworm-slim` | Minimal glibc-based distro (~30 MB base); compatible with Rust's default musl/glibc linking; wide package availability for production extensions |

---

## 2. Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| Docker Engine | ≥ 24.0 | Multi-stage build support required |
| Docker Compose | V2 (`docker compose` subcommand) | Not legacy `docker-compose` Python package |
| Disk space (build) | ≥ 4 GB free | Rust toolchain + dependencies + compilation artifacts |
| RAM (build) | ≥ 2 GB recommended | Cargo parallel compilation is memory-hungry |
| CPU | 2+ cores recommended | Workspace has 5 crates; parallelism speeds build significantly |

### OS Compatibility

| OS | Status | Notes |
|----|--------|-------|
| Linux (x86_64/aarch64) | ✅ Fully supported | Native Docker performance |
| macOS (Apple Silicon / Intel) | ✅ Fully supported | Build may be slower due to filesystem layer |
| Windows (WSL2) | ✅ Recommended | Use WSL2 backend for best performance |
| Windows (Hyper-V) | ⚠️ Supported | Volume performance may degrade with many small files |

---

## 3. Quick Start

Three commands to a running Misogi deployment:

```bash
# Step 1: Clone the repository
git clone https://github.com/your-org/misogi.git
cd misogi

# Step 2: (Optional) Customize configuration
cp docker/env.example .env
# Edit .env with your settings (see Section 6 for full variable list)

# Step 3: Build and start both services
docker compose up -d --build
```

### Verify Deployment

```bash
# Check both containers are running
docker compose ps

# Expected output:
# NAME            IMAGE       STATUS                    PORTS
# misogi-sender   misogi      Up (healthy)              0.0.0.0:3001->3001/tcp
# misogi-receiver misogi      Up (healthy)              0.0.0.0:3002->3002/tcp, 0.0.0.0:9000->9000/tcp

# Check health endpoints
curl http://localhost:3001/api/v1/health
# {"status":"ok","role":"sender"}

curl http://localhost:3002/api/v1/health
# {"status":"ok","role":"receiver"}

# Tail logs from both services
docker compose logs -f
```

### Start Individual Services

```bash
# Only sender (upload endpoint)
docker compose up -d sender

# Only receiver (download endpoint)
docker compose up -d receiver
```

---

## 4. Build Reference

### Manual Build Commands

```bash
# Build with default release profile
docker build -t misogi .

# Build with custom tag and no cache (clean rebuild)
docker build --no-cache -t misogi:v0.1.0 .

# Build debug profile (smaller binaries, useful for troubleshooting)
docker build --build-arg BUILD_PROFILE=debug -t misogi:debug .

# Build for specific platform (cross-compile)
docker build --platform linux/amd64 -t misogi:amd64 .
docker build --platform linux/arm64 -t misogi:arm64 .
```

### Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `BUILD_PROFILE` | `release` | Cargo profile (`release` or `debug`). Use `debug` for faster builds during development. |

### Build Caching Strategy

Docker layers are cached by content hash. The following order minimizes cache misses:

```
Layer 1: apt-get install protoc (changes rarely)           ← cached
Layer 2: COPY Cargo.toml Cargo.lock (changes on dep update) ← cached
Layer 3: COPY crates/ (changes on code edit)                ← rebuilt
Layer 4: cargo build (depends on layers 2+3)                ← rebuilt
```

**To force full rebuild**: `docker build --no-cache`

**To invalidate only dependency layer**: touch `Cargo.toml` or change `Cargo.lock`

### Why `protoc` in the Builder Stage?

The [`misogi-core/build.rs`](../crates/misogi-core/build.rs) invokes `tonic_build::compile_protos()` which requires the Protocol Buffer compiler (`protoc`) at build time to compile [`proto/file_transfer.proto`](../crates/misogi-core/proto/file_transfer.proto) into Rust source code. Without `protobuf-compiler` installed, the build fails with:

```
error: failed to run custom build command for `misogi-core` (v0.1.0)
Caused by: could not find protocol compiler
```

---

## 5. docker-compose.yml Complete Reference

### Service: sender

| Field | Value | Explanation |
|-------|-------|-------------|
| `image` | `misogi:latest` | Built locally from project Dockerfile |
| `container_name` | `misogi-sender` | Fixed name for predictable `docker exec` access |
| `restart` | `unless-stopped` | Auto-restart on crash or host reboot; respects manual stop |
| `entrypoint` | `misogi-sender` | Override Dockerfile default (same value, explicit for clarity) |
| `command` | `--mode server` | Run as HTTP API server (not daemon mode) |
| `ports` | `${SENDER_PORT:-3001}:3001` | Map host port 3001 (configurable via .env) to container port 3001 |
| `volumes` | `sender_uploads:/data/uploads` | Persist uploaded files across container restarts |
| `volumes` | `sender_staging:/data/staging` | Persist CDR staging area across restarts |
| `healthcheck.test` | `curl -f http://localhost:3001/api/v1/health` | HTTP GET to health endpoint |
| `healthcheck.interval` | 30s | Poll every 30 seconds |
| `healthcheck.timeout` | 5s | Fail if response takes > 5s |
| `healthcheck.retries` | 3 | Mark unhealthy after 3 consecutive failures |
| `healthcheck.start_period` | 10s | Grace period before health check counts toward retries |
| `networks` | `misogi-net` | Join shared bridge network for inter-container communication |

### Service: receiver

| Field | Value | Explanation |
|-------|-------|-------------|
| `ports` | `${RECEIVER_PORT:-3002}:3002` | Receiver HTTP API |
| `ports` | `${TUNNEL_PORT:-9000}:9000` | Reverse tunnel listener for sender connections |
| `volumes` | `receiver_chunks:/data/chunks` | Incoming transfer chunks storage |
| `volumes` | `receiver_downloads:/data/downloads` | Completed download storage |
| `healthcheck.test` | `curl -f http://localhost:3002/api/v1/health` | Same pattern as sender, different port |

### Volumes

| Volume Name | Container Path | Contents | Persistence |
|-------------|----------------|----------|-------------|
| `sender_uploads` | `/data/uploads` | Uploaded files awaiting processing | Named volume (survives recreate) |
| `sender_staging` | `/data/staging` | Files undergoing CDR sanitization | Named volume (survives recreate) |
| `receiver_chunks` | `/data/chunks` | Received file chunks during transfer | Named volume (survives recreate) |
| `receiver_downloads` | `/data/downloads` | Completed, reassembled files | Named volume (survives recreate) |

### Network

| Network | Driver | Purpose |
|---------|--------|---------|
| `misogi-net` | bridge | Isolated L2 network for sender ↔ receiver communication |

### Scaling Considerations

- **Multiple senders**: Yes, scale horizontally by deploying additional sender instances behind a load balancer. Each sender maintains its own upload state.
- **Multiple receivers**: Partially supported. Each receiver has independent chunk/download storage. Use consistent volume mounts or shared storage for state coherence.
- **Shared image**: Both services use the same `misogi:latest` image containing both binaries. No separate images needed.

---

## 6. Environment Variable Reference

### Precedence Order

Configuration resolution follows this priority chain (highest wins):

```
CLI Arguments (--flag)          # Highest priority
    ↓
Environment Variables (MISOGI_*) # docker compose env / docker run -e
    ↓
Dockerfile ENV defaults         # Built into image
    ↓
Application built-in defaults   # Hardcoded in config.rs Default impl
```

When using `docker compose`, `.env` file values override `docker-compose.yml` defaults:

```
.env file > docker-compose.yml ${VAR:-default} > Dockerfile ENV > app defaults
```

### General Variables

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `MISOGI_LOG_LEVEL` | `info` | Tracing verbosity: `trace`, `debug`, `info`, `warn`, `error` | `debug` |
| `RUST_LOG` | `info` | Rust tracing subscriber filter (overrides MISOGI_LOG_LEVEL if more granular) | `misogi_sender=trace,tower_http=debug` |
| `MISOGI_LOG_FORMAT` | `json` | Audit log format: `json`, `syslog`, `cef`, `custom` | `cef` |

### Sender-Specific Variables

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `MISOGI_SERVER_ADDR` | `0.0.0.0:3001` | HTTP bind address | `0.0.0.0:8080` |
| `MISOGI_UPLOAD_DIR` | `/data/uploads` | Directory for uploaded files | `/mnt/nfs/uploads` |
| `MISOGI_STAGING_DIR` | `/data/staging` | CDR processing staging area | `/mnt/nfs/staging` |
| `MISOGI_TRANSFER_DRIVER_TYPE` | `direct_tcp` | Transfer backend: `direct_tcp`, `storage_relay`, `external_command` | `storage_relay` |
| `MISOGI_TUNNEL_REMOTE_ADDR` | *(empty)* | Remote tunnel server address | `relay.example.com:9000` |
| `MISOGI_TUNNEL_AUTH_TOKEN` | *(empty)* | Tunnel authentication token | `secret-token-abc123` |
| `MISOGI_PII_ENABLED` | `false` | Enable PII scanning on uploads | `true` |
| `MISOGI_VENDOR_ISOLATION_ENABLED` | `false` | Enable multi-tenant vendor isolation | `true` |
| `MISOGI_SENDER_DRIVER_TYPE` | `direct_tcp` | Compose-specific alias for MISOGI_TRANSFER_DRIVER_TYPE (sender service) | `storage_relay` |

### Receiver-Specific Variables

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `MISOGI_SERVER_ADDR` | `0.0.0.0:3002` | HTTP bind address (receiver context) | `0.0.0.0:8080` |
| `MISOGI_CHUNK_DIR` | `/data/chunks` | Directory for incoming transfer chunks | `/mnt/nfs/chunks` |
| `MISOGI_DOWNLOAD_DIR` | `/data/downloads` | Directory for completed downloads | `/mnt/nfs/downloads` |
| `MISOGI_RECEIVER_DRIVER_TYPE` | `direct_tcp` | Transfer backend: `direct_tcp`, `storage_relay` | `storage_relay` |
| `MISOGI_TUNNEL_AUTH_TOKEN` | *(empty)* | Tunnel auth token (must match sender) | `secret-token-abc123` |

### Compose Port Override Variables

| Variable | Default | Maps To |
|----------|---------|---------|
| `SENDER_PORT` | `3001` | Host port for sender HTTP API |
| `RECEIVER_PORT` | `3002` | Host port for receiver HTTP API |
| `TUNNEL_PORT` | `9000` | Host port for receiver tunnel listener |

### Quick Configuration Template

Copy and customize:

```bash
cp docker/env.example .env
```

Then edit `.env`:

```env
# Production example
MISOGI_LOG_LEVEL=warn
RUST_LOG=misogi_sender=info
MISOGI_LOG_FORMAT=cef
MISOGI_PII_ENABLED=true
SENDER_PORT=3001
RECEIVER_PORT=3002
TUNNEL_PORT=9000
MISOGI_SENDER_DRIVER_TYPE=direct_tcp
MISOGI_TUNNEL_REMOTE_ADDR=
```

---

## 7. API Endpoints

All endpoints return JSON. CORS is enabled permissive by default.
Every response includes `X-Request-ID` header for request tracing.

### Sender API — Port 3001

| Method | Path | Description | Request Body | Example |
|--------|------|-------------|--------------|---------|
| `POST` | `/api/v1/upload` | Upload file (multipart) | `multipart/form-data: file` | `curl -F "file=@doc.pdf" http://localhost:3001/api/v1/upload` |
| `GET` | `/api/v1/files` | List uploaded files | Query: `?page=1&per_page=20&status=ready` | `curl 'http://localhost:3001/api/v1/files?page=1&per_page=10'` |
| `GET` | `/api/v1/files/:file_id` | Get file metadata | — | `curl http://localhost:3001/api/v1/files/abc-123` |
| `POST` | `/api/v1/files/:file_id` | Trigger transfer to receiver | — | `curl -X POST http://localhost:3001/api/v1/files/abc-123` |
| `POST` | `/api/v1/sanitize/:file_id` | Manually trigger CDR sanitization | — | `curl -X POST http://localhost:3001/api/v1/sanitize/abc-123` |
| `GET` | `/api/v1/sanitize/policies` | List available CDR policies | — | `curl http://localhost:3001/api/v1/sanitize/policies` |
| `GET` | `/api/v1/health` | Health check probe | — | `curl http://localhost:3001/api/v1/health` |
| `POST` | `/api/v1/transfers` | Create approval-required transfer | JSON body | `curl -X POST -H "Content-Type: application/json" -d '{"file_id":"..."}' http://localhost:3001/api/v1/transfers` |
| `GET` | `/api/v1/transfers` | List all transfers | — | `curl http://localhost:3001/api/v1/transfers` |
| `GET` | `/api/v1/transfers/pending` | List pending approvals | — | `curl http://localhost:3001/api/v1/transfers/pending` |
| `GET` | `/api/v1/transfers/:request_id` | Get transfer details | — | `curl http://localhost:3001/api/v1/transfers/req-001` |
| `POST` | `/api/v1/transfers/:request_id/approve` | Approve pending transfer | — | `curl -X POST http://localhost:3001/api/v1/transfers/req-001/approve` |
| `POST` | `/api/v1/transfers/:request_id/reject` | Reject pending transfer | — | `curl -X POST http://localhost:3001/api/v1/transfers/req-001/reject` |
| `POST` | `/api/v1/ppap/detect` | Scan file for PPAP indicators | `multipart/form-data: file` | `curl -F "file=@archive.zip" http://localhost:3001/api/v1/ppap/detect` |

#### Key Response Examples

**Upload response:**
```json
{
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ready",
  "filename": "report.pdf",
  "total_size": 1048576,
  "chunk_count": 1
}
```

**Health response:**
```json
{"status": "ok", "role": "sender"}
```

### Receiver API — Port 3002

| Method | Path | Description | Example |
|--------|------|-------------|---------|
| `GET` | `/api/v1/files` | List received files | `curl http://localhost:3002/api/v1/files` |
| `GET` | `/api/v1/download/:file_id` | Download completed file (binary) | `curl -o output.pdf http://localhost:3002/download/abc-123` |
| `GET` | `/api/v1/files/:file_id/status` | Get transfer status for a file | `curl http://localhost:3002/api/v1/files/abc-123/status` |
| `POST` | `/api/v1/files/:file_id/reassemble` | Manually reassemble chunks into final file | `curl -X POST http://localhost:3002/api/v1/files/abc-123/reassemble` |
| `GET` | `/api/v1/health` | Health check probe | `curl http://localhost:3002/api/v1/health` |

#### Health response:
```json
{"status": "ok", "role": "receiver"}
```

---

## 8. Volume & Data Management

### Volume Layout Inside Containers

```
/data/
├── uploads/     ← sender: incoming user uploads (before CDR)
├── staging/     ← sender: files being sanitized (CDR pipeline)
├── chunks/      ← receiver: incoming transfer chunks
└── downloads/   ← receiver: completed, reassembled output files
```

### Inspecting Volume Contents

```bash
# List named volumes created by compose
docker volume ls | grep misogi

# Inspect volume details (mountpoint, driver, etc.)
docker volume inspect misogi_sender_uploads

# Browse files inside a volume (read-only mount into temp container)
docker run --rm -v misogi_sender_uploads:/data busybox ls -la /data/

# Browse interactively
docker run --rm -it -v misogi_sender_uploads:/data busybox sh
```

### Backup Procedure

```bash
# Create backup archive of all Misogi volumes
docker run --rm \
  -v misogi_sender_uploads:/src/uploads \
  -v misogi_sender_staging:/src/staging \
  -v misogi_receiver_chunks:/src/chunks \
  -v misogi_receiver_downloads:/src/downloads \
  -v $(pwd):/backup \
  alpine tar czf /backup/misogi-data-backup-$(date +%Y%m%d).tar.gz -C /src .
```

### Restore Procedure

```bash
# Stop services first
docker compose down

# Extract backup into new volumes
docker run --rm \
  -v misogi_sender_uploads:/dst/uploads \
  -v misogi_sender_staging:/dst/staging \
  -v misogi_receiver_chunks:/dst/chunks \
  -v misogi_receiver_downloads:/dst/downloads \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/misogi-data-backup-YYYYMMDD.tar.gz -C /dst"

# Restart
docker compose up -d
```

### Using Bind Mounts Instead of Named Volumes

For development or when you need direct host filesystem access, modify `docker-compose.yml`:

```yaml
# Replace:
#   - sender_uploads:/data/uploads
# With:
  - ./data/sender/uploads:/data/uploads
```

**Trade-off:** Bind mounts preserve permissions from the host but don't auto-initialize directories. Named volumes are managed entirely by Docker and survive container recreation.

### Data Lifecycle

| Command | Effect on Volumes |
|---------|-------------------|
| `docker compose down` | Stops containers; **volumes preserved** |
| `docker compose down -v` | Stops containers; **volumes deleted permanently** |
| `docker compose up -d` | Recreates containers; **existing volumes reused** |
| `docker volume prune` | Removes all unused volumes (dangerous) |

> **⚠ WARNING**: `docker compose down -v` destroys all persisted file data irrecoverably unless backed up.

---

## 9. Networking Guide

### Default Bridge Network (`misogi-net`)

Both containers join the same bridge network. They can communicate using
service names as hostnames:

```
From sender container:
  curl http://receiver:3002/api/v1/health    ✅ Works (same network)

From host machine:
  curl http://localhost:3002/api/v1/health    ✅ Works (published ports)
```

### Inter-Container Communication

Sender can reach receiver for direct TCP transfers:

```
sender (misogi-net: 172.x.x.2)
    │
    └──► receiver (misogi-net: 172.x.x.3):3002  (HTTP)
    └──► receiver (misogi-net: 172.x.x.3):9000  (tunnel)
```

Configure `MISOGI_TUNNEL_REMOTE_ADDR` so sender knows how to reach receiver:

```env
# For intra-Docker communication, use service name:
MISOGI_TUNNEL_REMOTE_ADDR=receiver:9000
```

### Tunnel Mode (Port 9000)

When sender cannot directly open a connection to receiver (e.g., receiver is
behind NAT), the receiver exposes a **reverse tunnel** on port 9000. The sender
connects to this tunnel port, and traffic is forwarded internally.

```
  Sender                              Receiver
  ┌──────────┐                     ┌────────────┐
  │          │  TCP connect ──────►│  :9000     │
  │  :3001   │    to tunnel port   │  (tunnel   │
  │          │ ◄────────────────── │   handler) │
  └──────────┘  forwarded traffic  └────────────┘
```

### Custom Network Configuration

For production, you may want separate networks:

```yaml
# Add to docker-compose.yml:
services:
  sender:
    networks:
      - frontend    # Exposes port 3001 to load balancer
      - internal    # Communicates with receiver

  receiver:
    networks:
      - internal    # Only accessible from sender (no published port needed)

networks:
  frontend:
    driver: bridge
    # Attach to external network for reverse proxy integration
    # external: true
    # name: proxy_network
  internal:
    driver: bridge
    internal: true  # No external access (no internet routing)
```

---

## 10. Security Hardening (Production Checklist)

### Already Implemented in Dockerfile

- [x] **Non-root user**: Container runs as `misogi` (UID/GID auto-assigned), not root
- [x] **Minimal runtime image**: `debian:bookworm-slim` reduces attack surface vs. full OS
- [x] **Health checks**: Automated unhealthy container detection

### Recommended Production Additions

#### Resource Limits

Add to each service in `docker-compose.yml`:

```yaml
services:
  sender:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
  receiver:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

#### Read-Only Root Filesystem

```yaml
services:
  sender:
    read_only: true
    tmpfs:
      - /tmp:size=64M,mode=1777
```

> **Note:** The application writes to `/data/*` which are volume mounts, not the root filesystem. Read-only root prevents accidental or compromised writes to system paths.

#### Secrets Management

**Never commit tokens to `.env`** for production. Options:

1. **Docker Secrets** (Swarm mode):
   ```yaml
   environment:
     - MISOGI_TUNNEL_AUTH_TOKEN=/run/secrets/tunnel_token
   secrets:
     - tunnel_token
   ```

2. **External secret store** (HashiCorp Vault, AWS Secrets Manager):
   Inject at runtime via `docker run -e` or orchestration platform.

3. **`.env` file with restricted permissions** (development only):
   ```bash
   chmod 600 .env
   ```

#### TLS Termination (Reverse Proxy)

Place a reverse proxy (nginx / Caddy / Traefik) in front of both services:

**Example: Caddy automatic HTTPS**

```
# Caddyfile
file.example.com {
    reverse_proxy misogi-sender:3001
}

download.example.com {
    reverse_proxy misogi-receiver:3002
}
```

**Example: nginx**

```nginx
server {
    listen 443 ssl;
    server_name file.example.com;

    ssl_certificate     /etc/ssl/certs/misogi.crt;
    ssl_certificate_key /etc/ssl/private/misogi.key;

    location / {
        proxy_pass http://misogi-sender:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Connect the reverse proxy to `misogi-net` network:

```yaml
# In docker-compose.yml, add to networks:
networks:
  misogi-net:
    external: false
    # Or attach existing proxy network:
    # external: true
    # name: your_proxy_network
```

#### Log Aggregation

Docker captures stdout/stderr by default. Configure log driver for production:

```yaml
services:
  sender:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
  receiver:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

For centralized logging, switch to `fluentd`, `syslog`, or `awslogs` driver.

---

## 11. Operations & Monitoring

### Viewing Logs

```bash
# All services, tailing
docker compose logs -f

# Single service
docker compose logs -f sender
docker compose logs -f receiver

# Since last N lines
docker compose logs --tail=100 sender

# With timestamps
docker compose logs -t -f

# Filter by log level (application outputs JSON logs)
docker compose logs sender | grep '"level":"error"'
```

### Health Check Interpretation

| State | Meaning | Action |
|-------|---------|--------|
| `healthy` | Service responding to `/api/v1/health` within timeout | Normal operation |
| `unhealthy` | 3 consecutive failed health checks | Check logs: `docker compose logs sender` |
| `starting` | Within `start-period` grace period (10s) | Wait; not yet evaluated |

```bash
# Inspect current health status
docker inspect --format='{{.State.Health.Status}}' misogi-sender
```

### Restart Behavior

Policy: `unless-stopped`

| Event | Behavior |
|-------|----------|
| Container crashes | Auto-restarted immediately |
| Docker daemon restart | Auto-restarted when daemon comes back up |
| Manual `docker compose stop` | Stays stopped (won't auto-restart until `docker compose up`) |
| `docker compose down` | Removed (must `up` again to start) |

### Graceful Shutdown

Both services handle SIGTERM (sent by `docker stop`):

1. HTTP server stops accepting new connections
2. In-flight requests complete (up to Docker's 10s default grace period)
3. Transfer tasks in progress receive cancellation signal
4. Process exits cleanly

```bash
# Graceful stop (waits for in-flight work, 10s default timeout)
docker compose stop

# Force kill (immediate, may lose in-flight data)
docker compose kill
```

### Resource Monitoring

```bash
# Live resource usage
docker stats

# Single container
docker stats misogi-sender --no-stream
```

### Zero-Downtime Redeploy

```bash
# Rebuild and redeploy single service without downtime
docker compose up -d --build --no-deps sender

# This: builds new image → stops old container → starts new container
# If you have a load balancer in front, it drains connections gracefully.
```

### Scaling Out

**Multiple receivers behind one sender:**

```bash
# Scale receiver to 3 instances
docker compose up -d --scale receiver=3
```

> **Note:** Each receiver instance gets its own anonymous volume. For shared
> storage, use named volumes or an external NFS/S3 backend configured via
> `MISOGI_DOWNLOAD_DIR`.

---

## 12. Troubleshooting

### Container Won't Start

**Symptom:** `docker compose ps` shows status `Exited` or `Restarting`.

**Diagnose:**

```bash
# Check container exit code
docker compose ps -a

# View startup logs
docker compose logs sender

# Common causes:
# 1. Port already in use:
#    Error: address already in use 0.0.0.0:3001
#    Fix: Change SENDER_PORT in .env or stop conflicting process

# 2. Volume permission denied (rare with named volumes):
#    Fix: docker compose down -v && docker compose up -d

# 3. Invalid environment variable format:
#    Fix: Validate .env syntax (no spaces around =)
```

### Build Fails

**Symptom:** `docker build` exits with non-zero code.

**Common causes:**

```bash
# 1. protoc not found (shouldn't happen — installed in Dockerfile)
#    If you see: "could not find protocol compiler"
#    Fix: Ensure Dockerfile line 21 has `protobuf-compiler`

# 2. Out of disk space during compilation
#    Error: "no space left on device"
#    Fix: docker system prune -af (frees build cache)

# 3. Rust compilation error (code issue)
#    Fix: Review compiler output; test locally first with `cargo build`

# 4. Cargo.lock missing (dependency resolution mismatch)
#    Fix: Ensure .dockerignore does NOT exclude Cargo.lock
```

### Health Check Failing

**Symptom:** Container runs but status shows `(unhealthy)`.

**Diagnose:**

```bash
# Test health endpoint manually from inside container
docker compose exec sender curl -f http://localhost:3001/api/v1/health

# If curl not found in PATH:
docker compose exec sender /usr/bin/curl -f http://localhost:3001/api/v1/health

# If that works but Docker healthcheck still fails:
# - Check healthcheck timing: service may need longer start_period
# - Verify MISOGI_SERVER_ADDR matches exposed port
```

### File Upload Fails

**Symptom:** `POST /api/v1/upload` returns 500 error.

**Diagnose:**

```bash
# Check volume has free space inside container
docker compose exec sender df -h /data/uploads

# Check volume is writable
docker compose exec sender touch /data/uploads/.test_write && \
  docker compose exec sender rm /data/uploads/.test_write

# Review sender logs for I/O errors
docker compose logs --tail=50 sender | grep -i error
```

### Sender Cannot Reach Receiver

**Symptom:** Transfer triggered but stuck in `transferring` status forever.

**Diagnose:**

```bash
# Verify both containers are on same network
docker network inspect misogi_net

# Test connectivity from sender to receiver
docker compose exec sender wget -qO- http://receiver:3002/api/v1/health
# or:
docker compose exec sender curl -f http://receiver:3002/api/v1/health

# If using tunnel mode, verify port 9000 is accessible
docker compose exec sender nc -zv receiver 9000
```

### Debug Mode

Enable verbose logging to trace issues:

```env
# Add to .env:
MISOGI_LOG_LEVEL=debug
RUST_LOG=misogi_sender=trace,misogi_core=debug,tower_http=debug
```

Then:

```bash
docker compose up -d  # Restart with new env vars
docker compose logs -f sender | head -100
```

### Shell Access for Debugging

```bash
# Get interactive shell inside running container
docker compose exec sender sh

# From shell, test:
# - Network: wget/curl to other services
# - Filesystem: ls -la /data/
# - Process: ps aux
# - Environment: env | grep MISOGI
```

---

## 13. Advanced Deployment Patterns

### Development Mode with Hot Reload

For rapid development iteration, mount the source code and use `cargo watch`:

```yaml
# docker-compose.dev.yml (override file)
services:
  sender:
    build:
      context: .
      dockerfile: Dockerfile.dev
    volumes:
      - ./crates/misogi-sender/src:/app/src:ro
      - ./crates/misogi-core/src:/app/core_src:ro
      - ./crates/misogi-cdr/src:/app/cdr_src:ro
      - ./target:/app/target
    environment:
      - MISOGI_LOG_LEVEL=debug
      - RUST_LOG=misogi_sender=trace
    command: ["cargo", "watch", "-x", "run", "--bin", "misogi-sender", "--", "--mode", "server"]

# Usage:
# docker compose -f docker-compose.yml -f docker-compose.dev.yml up sender
```

### Air-Gapped Deployment (Storage Relay Mode)

For networks where sender and receiver have **no TCP connectivity**, use the
`storage_relay` driver with a shared directory:

```yaml
# docker-compose.airgapped.yml
services:
  sender:
    environment:
      - MISOGI_SENDER_DRIVER_TYPE=storage_relay
      - MISOGI_TRANSFER_OUTPUT_DIR=/shared/outbound
    volumes:
      - relay_shared:/shared

  receiver:
    environment:
      - MISOGI_RECEIVER_DRIVER_TYPE=storage_relay
      - MISOGI_TRANSFER_INPUT_DIR=/shared/inbound
    volumes:
      - relay_shared:/shared

volumes:
  relay_shared:
    driver: local

# Usage:
# docker compose -f docker-compose.yml -f docker-compose.airgapped.yml up -d
#
# Flow:
# 1. Sender deposits file manifest to /shared/outbound/
# 2. Receiver polls /shared/inbound/ for new manifests
# 3. Files transferred via shared volume, zero network required
```

### External Command Driver Integration

If your organization uses a mandated secure transfer tool (e.g., government
gateway), configure it as an external command:

```yaml
services:
  sender:
    environment:
      - MISOGI_SENDER_DRIVER_TYPE=external_command
    volumes:
      - /usr/local/bin/secure-transfer-tool:/usr/local/bin/secure-transfer-tool:ro
    # The external command must be mounted read-only into the container
```

Corresponding TOML configuration (if using config file instead of env vars):

```toml
[transfer_driver]
type = "external_command"
send_command = "/usr/local/bin/secure-transfer-tool send --input %s --dest %d"
status_command = "/usr/local/bin/secure-transfer-tool status %s"
timeout_secs = 120
```

### Kubernetes Migration

Convert `docker-compose.yml` concepts to Kubernetes manifests:

```yaml
# k8s/deployment-sender.yaml (excerpt)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: misogi-sender
spec:
  replicas: 2
  selector:
    matchLabels:
      app: misogi-sender
  template:
    metadata:
      labels:
        app: misogi-sender
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 9999
      containers:
      - name: sender
        image: misogi:latest
        ports:
        - containerPort: 3001
        env:
        - name: MISOGI_SERVER_ADDR
          value: "0.0.0.0:3001"
        - name: MISOGI_UPLOAD_DIR
          value: "/data/uploads"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 3001
          initialDelaySeconds: 10
          periodSeconds: 30
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: uploads
          mountPath: /data/uploads
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: misogi-uploads-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: misogi-sender-service
spec:
  selector:
    app: misogi-sender
  ports:
  - port: 3001
    targetPort: 3001
  type: ClusterIP
```

### CI/CD Pipeline Example (GitHub Actions)

```yaml
# .github/workflows/docker-ci.yml
name: Docker CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t misogi:${{ github.sha }} .

      - name: Start services
        run: docker compose up -d

      - name: Health check
        run: |
          for i in {1..30}; do
            if curl -sf http://localhost:3001/api/v1/health > /dev/null && \
               curl -sf http://localhost:3002/api/v1/health > /dev/null; then
              echo "✅ Both services healthy"
              exit 0
            fi
            echo "Waiting... ($i/30)"
            sleep 2
          done
          echo "❌ Health check timed out"
          docker compose logs
          exit 1

      - name: Run integration tests
        run: |
          # Upload test file
          UPLOAD=$(curl -s -F "file=@README.md" http://localhost:3001/api/v1/upload)
          echo "Upload response: $UPLOAD"

          # Extract file_id and verify listing
          FILE_ID=$(echo "$UPLOAD" | jq -r '.file_id')
          curl -sf "http://localhost:3001/api/v1/files/$FILE_ID" | jq .

      - name: Push to registry (main branch only)
        if: github.ref == 'refs/heads/main'
        run: |
          echo "${{ secrets.REGISTRY_PASSWORD }}" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin
          docker tag misogi:${{ github.sha }} ghcr.io/${{ github.repository }}:latest
          docker push ghcr.io/${{ github.repository }}:latest

      - name: Cleanup
        if: always()
        run: docker compose down -v
```

---

## File Index

| File | Purpose |
|------|---------|
| [`Dockerfile`](../Dockerfile) | Multi-stage build definition |
| [`docker-compose.yml`](../docker-compose.yml) | Service orchestration (sender + receiver) |
| [`.dockerignore`](../.dockerignore) | Build context exclusions |
| [`docker/env.example`](./env.example) | Environment variable template (copy to `.env`) |
| **This file** | Complete deployment documentation |
