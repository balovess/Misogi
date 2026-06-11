# Relay Mesh Configuration Guide

## Overview

The Multi-Tier Relay Mesh provides secure file transfer across network boundaries through a chain of relay nodes. Each relay node acts as a hop in the transfer path, enabling transfers between isolated network segments.

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Source  │────▶│  Relay 1 │────▶│  Relay 2 │────▶│   Dest   │
│  Node    │     │          │     │          │     │  Node    │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                │                │
     └────────────────┴────────────────┴────────────────┘
                         Heartbeat Monitoring
```

---

## Configuration Structure

### RelayConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Master switch for relay mesh functionality |
| `default_strategy` | `String` | `"direct"` | Default routing strategy |
| `max_hops` | `u32` | `5` | Maximum number of relay hops allowed |
| `heartbeat_interval_secs` | `u64` | `30` | Interval between heartbeat messages |
| `circuit_breaker_threshold` | `u32` | `5` | Consecutive failures before circuit opens |

---

## TOML Configuration

### Basic Configuration

```toml
[relay]
enabled = true
default_strategy = "direct"
max_hops = 5
heartbeat_interval_secs = 30
circuit_breaker_threshold = 5
```

### Production Configuration

```toml
[relay]
enabled = true
default_strategy = "adaptive"
max_hops = 3
heartbeat_interval_secs = 60
circuit_breaker_threshold = 3
```

### Multi-Region Configuration

```toml
[relay]
enabled = true
default_strategy = "fixed_path"
max_hops = 4
heartbeat_interval_secs = 45
circuit_breaker_threshold = 2

[relay.paths]
internal_to_dmz = ["relay-internal-1", "relay-dmz-1"]
dmz_to_external = ["relay-dmz-1", "relay-external-1"]
```

---

## Routing Strategies

### `direct`

Direct transfer without relay nodes. Use when source and destination are in the same network segment.

```
Source ──────────────▶ Destination
```

**Use Case**: Same network segment transfers

---

### `adaptive`

Automatically select optimal path based on network conditions. The mesh evaluates latency, bandwidth, and reliability for each potential path.

```
┌──────────┐
│  Source  │───┬───▶ Path A (Low Latency)
└──────────┘   │
               ├───▶ Path B (High Bandwidth)
               │
               └───▶ Path C (Most Reliable)
```

**Use Case**: Dynamic network environments, multi-path redundancy

---

### `fixed_path`

Use predefined relay chain specified in configuration. Provides predictable routing for compliance requirements.

```
Source ──▶ Relay A ──▶ Relay B ──▶ Destination
          (Fixed Path)
```

**Use Case**: Compliance-mandated paths, audit trail requirements

---

## Circuit Breaker

The circuit breaker prevents cascading failures by temporarily disabling routes to unhealthy relay nodes.

### States

```
         ┌─────────────────────────────────────┐
         │                                     │
         ▼                                     │
    ┌─────────┐   Failures > Threshold   ┌─────────┐
    │  CLOSED │ ───────────────────────▶ │   OPEN  │
    └─────────┘                          └────┬────┘
         ▲                                    │
         │         Timeout Elapsed            │
         └────────────────────────────────────┘
                    (Half-Open State)
```

| State | Behavior |
|-------|----------|
| CLOSED | Normal operation, requests pass through |
| OPEN | Requests fail fast, no attempts to relay |
| HALF-OPEN | Limited requests allowed to test recovery |

### Configuration

```toml
[relay.circuit_breaker]
threshold = 5              # Failures before opening
reset_timeout_secs = 60    # Time before attempting recovery
half_open_max_calls = 3    # Test requests in half-open state
```

---

## Heartbeat

Heartbeat messages monitor relay node health and detect silent failures.

### Message Flow

```
┌──────────┐                    ┌──────────┐
│  Node A  │ ──── PING ───────▶ │  Node B  │
│          │ ◀─── PONG ──────── │          │
└──────────┘                    └──────────┘

Interval: heartbeat_interval_secs
Timeout: heartbeat_interval_secs * 2
```

### Health Status

| Status | Condition |
|--------|-----------|
| Healthy | PONG received within timeout |
| Degraded | PONG delayed but received |
| Unhealthy | No PONG within timeout |

---

## Best Practices

### Performance

- Set `max_hops <= 5` to minimize latency
- Use `heartbeat_interval_secs = 60` for stable networks
- Use `heartbeat_interval_secs = 30` for unstable networks

### Reliability

- Set `circuit_breaker_threshold = 3` for production
- Configure multiple relay paths for redundancy
- Monitor relay health metrics

### Security

- Enable TLS for all relay connections
- Use certificate pinning for relay authentication
- Log all relay hop decisions for audit

### Compliance

- Use `fixed_path` strategy for audit trail requirements
- Document all relay node locations
- Maintain relay configuration in version control

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Transfer timeout | Too many hops | Reduce `max_hops` |
| Circuit breaker open | Relay node failure | Check relay health, wait for reset |
| High latency | Suboptimal path | Use `adaptive` strategy |
| Connection refused | Relay not running | Verify relay service status |

### Diagnostic Commands

```bash
# Check relay mesh status
misogi relay status

# View active connections
misogi relay connections

# Test relay path
misogi relay test --path relay-1,relay-2,relay-3

# View circuit breaker state
misogi relay circuit-breaker
```

---

## Related Documentation

- [architecture-overview.md](architecture-overview.md) - System architecture
- [enterprise-deployment.md](enterprise-deployment.md) - Deployment guide
- [integrity-config.md](integrity-config.md) - Integrity layer configuration
