# Misogi Getting Started Guide

**Misogi (禊)** — High-performance secure file transfer with built-in CDR sanitization.

This guide will help you get Misogi up and running in minutes.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Deployment Options](#deployment-options)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### For Docker Deployment (Recommended)

| Requirement | Minimum Version | How to Check |
|-------------|-----------------|--------------|
| Docker | 24.0+ | `docker --version` |
| Docker Compose | V2 | `docker compose version` |

### For Source Build

| Requirement | Minimum Version | How to Check |
|-------------|-----------------|--------------|
| Rust | 1.85+ | `rustc --version` |
| protoc | 3.0+ | `protoc --version` |
| OpenSSL | 1.1+ | `openssl version` |

### Optional Dependencies

| Tool | Purpose |
|------|---------|
| LibreOffice | JTD (Ichitaro) file conversion |
| ClamAV | Antivirus scanning |
| Git | Repository management |

---

## Quick Start

### Option 1: One-Command Setup (Fastest)

**Linux/macOS:**
```bash
git clone https://github.com/balovess/Misogi.git && cd Misogi
./scripts/quickstart.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/balovess/Misogi.git; cd Misogi
.\scripts\quickstart.ps1
```

This will automatically:
- ✅ Check all dependencies
- ✅ Create configuration files
- ✅ Generate RSA keypair
- ✅ Start Docker services
- ✅ Verify health status

### Option 2: Interactive Configuration

For guided setup with compliance presets:

```bash
# Run the configuration wizard
misogi-sender --init

# Follow the prompts to:
# 1. Select deployment mode
# 2. Choose compliance preset
# 3. Configure network settings
# 4. Enable optional features
```

### Option 3: Manual Docker Setup

```bash
# 1. Clone and enter directory
git clone https://github.com/balovess/Misogi.git && cd Misogi

# 2. Copy configuration template
cp config/misogi.toml.default misogi.toml

# 3. (Optional) Copy environment file
cp docker/env.example .env

# 4. Start services
docker compose up -d --build

# 5. Verify
curl http://localhost:3001/api/v1/health
```

---

## Configuration

### Configuration Files

| File | Purpose |
|------|---------|
| `misogi.toml` | Main configuration file |
| `.env` | Environment variables for Docker |
| `keys/private.pem` | RSA private key for JWT |
| `keys/public.pem` | RSA public key for JWT |

### Configuration Layers (Priority Order)

1. **CLI Arguments** — `--flag` (highest priority)
2. **Environment Variables** — `MISOGI_*`
3. **TOML File** — `misogi.toml`
4. **Built-in Defaults** (lowest priority)

### Compliance Presets

Misogi includes pre-configured compliance profiles:

| Preset | Description | Key Settings |
|--------|-------------|--------------|
| `minimal` | Development/testing | Basic CDR, no approval |
| `lgwan` | Japanese local government | Full approval, PII detection, CEF logging |
| `medical` | Healthcare (HIPAA-Japan) | Dual approval, patient PII protection |
| `enterprise` | General business | Balanced security, optional features |

**Using a preset:**

```bash
# During quickstart
./scripts/quickstart.sh --preset lgwan

# Or copy directly
cp config/examples/lgwan.toml misogi.toml
```

### Key Configuration Sections

```toml
# Server settings (required)
[server]
addr = "0.0.0.0:3001"

# Storage paths (required)
[storage]
upload_dir = "./data/uploads"
staging_dir = "./data/staging"

# Transfer driver
[transfer_driver]
type = "direct_tcp"  # or "storage_relay", "external_command"

# PII detection (optional)
[pii_detector]
enabled = true

# Audit logging (optional)
[log]
format = "json"  # or "syslog", "cef"
```

---

## Deployment Options

### Docker Compose (Development/Staging)

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down
```

### Kubernetes (Production)

```bash
# Using Helm
helm install misogi ./helm/misogi \
  --set sender.replicas=2 \
  --set receiver.replicas=2
```

### Bare Metal (Air-Gapped)

```bash
# Build release binaries
cargo build --release --bins

# Generate keys
cargo run --package misogi-auth --example generate-keys -- ./keys

# Run sender
./target/release/misogi-sender --config misogi.toml

# Run receiver (separate terminal)
./target/release/misogi-receiver --config misogi.toml
```

---

## Verification

### Health Checks

```bash
# Check sender health
curl http://localhost:3001/api/v1/health
# Expected: {"status":"ok","role":"sender"}

# Check receiver health
curl http://localhost:3002/api/v1/health
# Expected: {"status":"ok","role":"receiver"}
```

### Test File Upload

```bash
# Upload a test file
curl -F "file=@test.pdf" http://localhost:3001/api/v1/upload

# Expected response:
# {"file_id":"...","status":"ready","filename":"test.pdf",...}
```

### Check Dependencies

```bash
misogi-sender --check-deps
```

Output:
```
╔═══════════════════════════════════════════════════════════════╗
║                  Dependency Check                              ║
╚═══════════════════════════════════════════════════════════════╝

[✓] Docker: 24.0.5 (required: 24.0+)
[✓] Docker Compose: available
[✓] OpenSSL: 3.0.11 (required for key generation)
[✓] Git: available
[✓] curl: available
[!] LibreOffice: not found (optional, for JTD conversion)

[✓] All required dependencies satisfied.
```

---

## Troubleshooting

### Common Issues

#### 1. Port Already in Use

**Error:** `address already in use 0.0.0.0:3001`

**Solution:**
```bash
# Change port in .env
echo "SENDER_PORT=3003" >> .env

# Or stop conflicting service
lsof -i :3001  # Find process
kill -9 <PID>
```

#### 2. Docker Not Running

**Error:** `Cannot connect to the Docker daemon`

**Solution:**
```bash
# Start Docker Desktop (Windows/macOS)
# Or start Docker service (Linux)
sudo systemctl start docker
```

#### 3. Configuration File Not Found

**Error:** `Configuration file not found: misogi.toml`

**Solution:**
```bash
# Create from template
cp config/misogi.toml.default misogi.toml

# Or run init wizard
misogi-sender --init
```

#### 4. Permission Denied

**Error:** `Permission denied: ./scripts/quickstart.sh`

**Solution:**
```bash
chmod +x scripts/quickstart.sh
```

#### 5. Key Generation Failed

**Error:** `Failed to generate RSA keypair`

**Solution:**
```bash
# Ensure OpenSSL is installed
apt install openssl  # Linux
brew install openssl # macOS

# Generate keys manually
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### Getting Help

1. **Check logs:** `docker compose logs -f`
2. **Validate config:** `misogi-sender --validate-config misogi.toml`
3. **Check dependencies:** `misogi-sender --check-deps`
4. **Read documentation:** `docs/` directory

---

## Next Steps

After getting Misogi running:

1. **Configure authentication** — Set up JWT, LDAP, or OIDC
2. **Enable CDR policies** — Configure sanitization rules
3. **Set up audit logging** — Choose log format (JSON/Syslog/CEF)
4. **Deploy to production** — Use Kubernetes/Helm for scaling

For detailed configuration options, see `config/misogi.toml.default`.
