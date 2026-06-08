# ADR-0002: Purification-First Domain Model

## Status

Accepted

## Context

The name "Misogi" (禊ぎ) refers to the Shinto purification ritual. This naming is intentional and reflects a philosophical stance on how the system should treat incoming files.

Two domain models were considered:

1. **Transfer-First**: File transfer is the core capability; CDR is an optional security layer
2. **Purification-First**: Purification is the core capability; transfer is merely delivery

### Decision Drivers

| Driver | Transfer-First | Purification-First |
|--------|----------------|-------------------|
| Security posture | ⚠️ Opt-in | ✅ Mandatory |
| Zero-trust alignment | ❌ Weak | ✅ Strong |
| Compliance (LGWAN) | ❌ Requires config | ✅ Default compliant |
| User experience | ✅ Familiar | ⚠️ Requires education |
| Audit simplicity | ⚠️ Conditional | ✅ Unconditional |

## Decision

**We adopt Purification-First as the core domain model.**

Every file entering the system is assumed malicious until proven clean. No file bypasses purification. Transfer is the delivery mechanism, not the core value.

### Domain Principle

```
∀ File F entering Misogi:
  Assume F is malicious
  Apply CDR(F) → Sanitized S
  Only S may exit the system
```

### Architectural Implications

1. **No bypass**: There is no "skip CDR" option. This is intentional.
2. **Error handling**: CDR failure blocks transfer; transfer failure does not affect CDR
3. **Monitoring**: Threat interception rate is primary metric; throughput is secondary
4. **API design**: Sanitization is implicit in upload; explicit sanitization-only endpoint exists

### Code Manifestations

```rust
// Every upload goes through CDR
pub async fn upload(&self, file: File) -> Result<TransferId> {
    // Step 1: PURIFY (mandatory)
    let sanitized = self.cdr_engine.sanitize(&file).await?;
    
    // Step 2: TRANSFER (delivery)
    let transfer_id = self.transfer_engine.send(sanitized).await?;
    
    Ok(transfer_id)
}
```

## Consequences

### Positive

- **Zero-trust by default**: No configuration needed for security
- **Compliance built-in**: LGWAN requirements satisfied automatically
- **Simpler audit**: Every file has a SanitizationReport
- **Clear mental model**: "Purify then transfer"

### Negative

- **No flexibility**: Cannot disable CDR for trusted sources
- **Processing latency**: Every file incurs CDR overhead
- **Format limitations**: Unsupported formats are rejected

### Mitigations

- **Trusted sources**: Use separate network segment, not CDR bypass
- **Performance**: Streaming CDR, parallel processing, WASM edge
- **Format support**: Extensible parser registry

## Alternatives Considered

### Alternative 1: Transfer-First with Optional CDR

Rejected. Violates zero-trust principle. Creates compliance burden.

### Alternative 2: Policy-Based CDR (per-source)

Considered but rejected:
- Policy complexity increases with number of sources
- Audit trail becomes conditional
- "Trusted source" is an oxymoron in zero-trust architecture

### Alternative 3: CDR-Only (No Transfer)

Rejected. Transfer is necessary for practical deployment. Purification without delivery serves no business purpose.

## References

- [CONTEXT.md](../../CONTEXT.md) — Domain glossary
- [ADR-0001](./0001-true-cdr-over-signature-scanning.md) — True CDR implementation

---

## History

| Date | Change |
|------|--------|
| 2026-06-08 | Initial ADR creation |
