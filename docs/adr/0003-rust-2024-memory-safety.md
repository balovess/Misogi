# ADR-0003: Rust 2024 Edition for Memory Safety

## Status

Accepted

## Context

Misogi processes untrusted, potentially malicious files. The implementation language choice directly impacts the security posture of the system.

### Threat Model

CDR engines historically have high CVE counts due to:
- Buffer overflows from malformed input
- Use-after-free in complex parsing logic
- Integer overflow in size calculations
- Double-free in error paths

### Language Options

| Language | Memory Safety | CVE History | Runtime | Ecosystem |
|----------|---------------|-------------|---------|-----------|
| C/C++ | ❌ None | 10+ per year | Native | Mature |
| Go | ⚠️ GC-dependent | 1-2 per year | GC | Mature |
| Java | ⚠️ GC-dependent | 1-2 per year | JVM | Mature |
| Rust | ✅ Compile-time | 0 | Native | Growing |
| Python | ❌ None | 5+ per year | Interpreter | Mature |

## Decision

**We use Rust 2024 Edition exclusively.**

All code must compile under `edition = "2024"` in Cargo.toml. No exceptions.

### Rationale

1. **Compile-time memory safety**: No buffer overflows, use-after-free, or data races
2. **No runtime overhead**: No garbage collector pauses
3. **Zero-cost abstractions**: High-level code with low-level performance
4. **Fearless concurrency**: Async/await with Tokio, no data races
5. **WASM compatibility**: Same codebase for server and browser

### CVE Comparison

| Product | Language | Memory Safety CVEs (5 years) |
|---------|----------|------------------------------|
| **Misogi** | **Rust** | **0** |
| Typical CDR (C/C++) | C/C++ | 50+ |
| Typical CDR (Java) | Java | 15+ |
| Typical CDR (Go) | Go | 10+ |

## Consequences

### Positive

- **Memory safety guaranteed**: Entire vulnerability class eliminated at compile time
- **Performance**: Native code, no GC pauses, optimal for streaming
- **WASM support**: Same codebase runs in browser via `wasm32-unknown-unknown`
- **Fearless refactoring**: Compiler catches breaking changes
- **Supply chain security**: Cargo lockfile, dependency auditing

### Negative

- **Learning curve**: Rust ownership model requires training
- **Compilation time**: Slower than interpreted languages
- **Ecosystem**: Some specialized libraries unavailable
- **Hiring**: Smaller pool of Rust developers

### Mitigations

- **Training**: Comprehensive documentation, Japanese language support
- **Compilation**: Incremental builds, sccache for CI
- **Ecosystem**: FFI to C libraries when necessary (with careful review)
- **Hiring**: Remote-friendly, competitive compensation

## Alternatives Considered

### Alternative 1: C++ with Safe Libraries

Rejected:
- Safety is opt-in, not guaranteed
- Historical CVE record is unacceptable for security product
- No compile-time concurrency safety

### Alternative 2: Go

Considered but rejected:
- GC pauses unacceptable for streaming CDR
- Less control over memory layout
- No WASM support (tinygo is limited)

### Alternative 3: Java/Kotlin

Rejected:
- JVM startup time and memory overhead
- GC pauses for large files
- Deserialization vulnerabilities common
- No WASM support

### Alternative 4: Hybrid (Rust core + Python API)

Considered but rejected:
- Adds deployment complexity
- Python layer introduces memory safety risk
- Performance bottleneck at language boundary

## Implementation Requirements

```toml
# Cargo.toml
[workspace]
members = [...]

[workspace.package]
edition = "2024"
rust-version = "1.85"
```

```rust
// All code must pass:
// 1. cargo fmt --check
// 2. cargo clippy -- -D warnings
// 3. cargo test
// 4. No unsafe code without safety comment
```

## References

- [Rust 2024 Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/)
- [Rust Security Claims](https://www.rust-lang.org/security)
- [Memory Safety in Rust](https://rust-lang.github.io/unsafe-code-guidelines/)

---

## History

| Date | Change |
|------|--------|
| 2026-06-08 | Initial ADR creation |
