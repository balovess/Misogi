# misogi-wasm

**Dual-target WASM runtime: server-side plugin sandbox + browser-side CDR sanitization**

![Rust 2024](https://img.shields.io/badge/Rust-2024-orange) ![WASM](https://img.shields.io/badge/wasm32--unknown--unknown-green) ![License](https://img.shields.io/badge/License-Apache--2.0-blue)

## Architecture

This crate supports **two compilation targets** with distinct use cases:

| Target | Feature Flag | Use Case | Key Dependencies |
|--------|-------------|----------|-----------------|
| `x86_64-pc-windows-msvc` / `x86_64-unknown-linux-gnu` | `native` (**default**) | Server-side WASM plugin runtime via wasmi interpreter | `wasmi`, `tokio` |
| `wasm32-unknown-unknown` | `browser` | Browser/Edge CDR sanitization via wasm-bindgen FFI | `wasm-bindgen`, `js-sys` |

Core sanitizer logic in [`wasm_compat`](src/wasm_compat.rs) is **target-agnostic** —
shared by both compilation paths. FFI bindings and the wasmi plugin system are
conditionally compiled per target.

```
misogi-wasm/
├── src/
│   ├── lib.rs              # Conditional module exports (feature-gated)
│   ├── wasm_compat.rs      # Target-agnostic: WasmPdfSanitizer, WasmOfficeSanitizer, PII
│   ├── ffi.rs              # [browser] wasm-bindgen FFI bindings
│   ├── js_glue.rs          # [browser] JS interop helpers
│   ├── abi.rs              # [native] WASM plugin ABI definitions
│   ├── adapter.rs          # [native] CDR parser → WASM adapter
│   ├── error.rs            # [native] Error types for plugin runtime
│   ├── manager.rs          # [native] Plugin lifecycle manager
│   └── sandbox.rs          # [native] Security sandbox (memory/CPU limits)
├── benches/
│   ├── wasm_perf.rs        # Criterion benchmark suite (8 groups, 26 benchmarks)
│   └── generators.rs       # Synthetic test data generators
├── tests/browser_compat/   # Playwright browser compatibility tests
└── Cargo.toml              # Dual-feature configuration
```

## Building

### Native Target (default)

```bash
cargo build -p misogi-wasm
# or
cargo check -p misogi-wasm --features native
```

### WASM Browser Target

```bash
# Install prerequisites (one-time)
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build with browser features only
wasm-pack build crates/misogi-wasm \
  --target web --release \
  --out-dir crates/misogi-wasm/pkg \
  -- --no-default-features --features browser
```

Output:
```
crates/misogi-wasm/pkg/
├── misogi_wasm.js         # ES module JS glue code
├── misogi_wasm_bg.wasm    # Optimized WASM binary (271 KB)
├── misogi_wasm.d.ts       # TypeScript type definitions
└── package.json           # NPM package metadata
```

## Exported API (Browser Target)

All functions are exposed via `wasm_bindgen` and callable from JavaScript:

| Function | Signature | Description |
|----------|-----------|-------------|
| [`sanitize_pdf`](src/ffi.rs) | `(data: Box<[u8]>, policy: String) -> SanitizeResult` | PDF True CDR: remove JS/OpenAction/AcroForm threats |
| [`sanitize_office`](src/ffi.rs) | `(data: Box<[u8]>, policy: String) -> SanitizeResult` | Office CDR: strip VBA macros from DOCX/XLSX/PPTX |
| [`scan_pii`](src/ffi.rs) | `(data: Box<[u8]>) -> PiiScanResult` | PII detection (My Number, email, phone, postal code) |
| [`detect_file_type`](src/ffi.rs) | `(header: Box<[u8]>) -> FileTypeResult` | Magic byte file type identification |
| [`init`](src/ffi.rs) | `()` | Panic hook setup (auto-called via `#[wasm_bindgen(start)]`) |

### Return Types

#### `SanitizeResult`
```typescript
{
  success: boolean;          // Operation completed without error
  output_data: Uint8Array;    // Sanitized file bytes (getter method)
  report: string;             // JSON audit report (pretty-printed)
  threats_found: number;      // Count of removed threats
  error_message: string;      // Empty on success, Japanese on failure
  processing_time_ms: number; // Wall-clock elapsed time
}
```

#### `PiiScanResult`
```typescript
{
  found: boolean;
  matches: string;            // JSON array of match details
  recommended_action: string; // "block" | "mask" | "alert_only"
  bytes_scanned: number;
  scan_duration_ms: number;
}
```

#### `FileTypeResult`
```typescript
{
  detected_type: string;     // MIME type (e.g., "application/pdf")
  extension: string;         // Lowercase extension (e.g., "pdf")
  confidence: number;        // 0.0–1.0
  is_blocked: boolean;
  block_reason: string | null;
}
```

### Policy Enum Values

| Value | Label (JA) | Description |
|-------|------------|-------------|
| `StripActiveContent` | アクティブコンテンツ除去 | Remove JS/VBA/macros, preserve formatting (default) |
| `ConvertToFlat` | フラット変換 | Destroy all interactive elements (maximum security) |
| `TextOnly` | テキストのみ抽出 | Strip formatting, images, layout (minimum output) |

## JS Glue API ([`js_glue.rs`](src/js_glue.rs))

Browser-side utility functions bridging Rust semantics to JavaScript:

| Function | Signature | Description |
|----------|-----------|-------------|
| [`localize_error`](src/js_glue.rs) | `(code: &str, detail: &str) -> String` | Map error codes to user-facing Japanese messages |
| [`allocate_buffer`](src/js_glue.rs) | `(size: usize) -> i32` | Allocate WASM linear memory for large file transfers |
| [`deallocate_buffer`](src/js_glue.rs) | `(ptr: i32, size: usize)` | Free previously allocated memory |
| [`console_log`](src/js_glue.rs) | `(level: &str, message: &str)` | Bridge Rust tracing to browser console |
| [`detect_wasm_features`](src/js_glue.rs) | `() -> String` | JSON feature support report (`{webassembly, shared_array_buffer, bigint}`) |
| [`version`](src/js_glue.rs) | `() -> String` | Crate version string (semver) |

## Performance Benchmarks

Run the criterion benchmark suite:

```bash
cargo bench -p misogi-wasm --bench wasm_perf
# Quick mode (fewer samples):
cargo bench -p misogi-wasm --bench wasm_perf -- --sample-size 10
```

### Established Baseline (native target, approximate)

| Benchmark Group | Test Case | Result |
|-----------------|----------|--------|
| PDF analyze (clean) | 1 MB PDF | **~200 MiB/s** throughput |
| PDF analyze (malicious) | 1 MB PDF, 5% JS density | ~180 MiB/s |
| PDF sanitize (full) | 1 MB PDF, end-to-end | **~5 MB/s**, P50 < 5ms |
| Office ZIP rebuild | 1 MB OOXML | **~2 MB/s** |
| PII scan (5% density) | 100 KB text | **~20 MB/s** |
| MD5 hash baseline | 1 MB data | ~400 MiB/s |
| SHA-256 hash baseline | 1 MB data | ~150 MiB/s |
| Memory peak (PDF) | 10 MB input | < 50 MB heap usage |

> Results are available as HTML reports in `target/criterion/wasm_perf/`
> and machine-readable JSON in `target/criterion/wasm_perf/*/new/estimates.json`.

## Binary Size Budget

| Metric | Limit | Actual | Status |
|--------|-------|--------|--------|
| Raw `.wasm` | < 8 MB | **271.2 KB** (3.4%) | ✅ Pass |
| Gzip compressed | < 3 MB | **~75 KB** (2.5%) | ✅ Pass |

Optimization pipeline: `wasm-opt -Oz` + `--remove-name-section --remove-dwarf`.
See [`scripts/optimize-wasm.sh`](../../scripts/optimize-wasm.sh).

## Browser Compatibility

Automated Playwright tests validate compatibility across major browsers:

| Browser | Versions Tested | Status |
|---------|-----------------|--------|
| Chrome | latest + stable (Chromium) | ✅ Full pass |
| Firefox | latest + ESR | ✅ Full pass |
| Safari | latest (WebKit) | ✅ Full pass |
| Edge | latest (Chromium-based) | ✅ Full pass |

Test coverage (16 test cases × 4 browsers = **64 test points**):

- WASM module loading (error-free init, FFI availability, loading indicator)
- PDF sanitization E2E (clean/malicious flow, error handling)
- Office sanitization E2E (DOCX VBA stripping)
- PII scan display (Japanese context rendering)
- Download functionality (Blob URL, MIME correctness)
- Error display (Japanese messages, user-friendly)
- Large file handling (~10 MB, no OOM)
- COOP/COEP fallback (graceful degradation)

Run compatibility tests:
```bash
cd crates/misogi-wasm/tests/browser_compat
npm install && npx playwright install chromium
npm test
# Headed mode (visible browser):
npm run test:headed
```

See [`tests/browser_compat/`](tests/browser_compat/) for full test source.

## CI/CD Pipeline

The [`wasm-ci.yml`](../../.github/workflows/wasm-ci.yml) workflow provides 4 stages:

```
native-check ──→ wasm-build ──┬──→ benchmarks (artifact: 90d retention)
                │               └──→ browser-compat (artifact: 30d retention)
                │
                └──→ Size enforcement (raw < 8MB, gzip < 3MB, blocks merge if exceeded)
```

## Security Model

### Native Target (wasmi plugin runtime)
- Memory limit: Configurable heap size (default 64 MB, max 500 MB)
- CPU timeout: Execution time limits (default 30 seconds)
- No filesystem access exposed to plugins
- No network access exposed to plugins
- Controlled imports: Only memory allocation and logging functions
- Maximum concurrent plugins: 256

### Browser Target (wasm-bindgen)
- All processing within browser sandbox (zero server dependency)
- Maximum file size: 500 MiB enforced by `MAX_WASM_FILE_SIZE_BYTES`
- WASM memory isolated per-tab, cleared on page navigation
- Blob URLs revoked after download to prevent memory leaks
- COOP/COEP headers enable Cross-Origin Isolation for advanced WASM features
- Graceful degradation when SharedArrayBuffer unavailable

## License

Licensed under Apache License, Version 2.0 — see [LICENSE](../../LICENSE).
