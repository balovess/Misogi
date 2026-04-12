# misogi-macros

**Misogi Procedural Macro SDK** — Declarative plugin development for the Misogi CDR system.

Eliminate ~240 lines of trait implementation boilerplate. Write elegant, concise plugins using pure attribute macros.

## Quick Start (5 Minutes)

### 1. Add Dependency

```toml
# Cargo.toml
[dependencies]
misogi-macros = { path = "../misogi-macros" }
misogi-core = { path = "../misogi-core" }
```

### 2. Write Your Plugin

```rust
use misogi_macros::prelude::*;

#[misogi_plugin(name = "my_compliance_rule", version = "1.0.0")]
pub struct MyComplianceRule;

#[on_file_stream]
async fn inspect_chunk(chunk: &mut [u8]) -> Result<(), Error> {
    // Your custom logic here
    Ok(())
}
```

### 3. Build & Run

```bash
cargo build
```

That's it. The macro automatically generates:

- ✅ `PluginMetadata` impl (name, version, description)
- ✅ `CDRStrategy` impl (if `#[on_file_stream]` used)
- ✅ `PIIDetector` impl (if `#[on_scan_content]` used)
- ✅ `FileTypeDetector` impl (if `#[on_metadata]` used)
- ✅ `LogFormatter` impl (if `#[on_format_log]` used)
- ✅ `ApprovalTrigger` impl (if `#[on_approval_event]` used)
- ✅ Stub impls for remaining traits
- ✅ `#[ctor]` auto-registration into `GLOBAL_REGISTRY`

---

## Reference

### `#[misogi_plugin]` — Main Attribute Macro

The primary macro that transforms a struct into a full Misogi plugin.

| Parameter    | Required | Type   | Description                              |
|-------------|----------|--------|------------------------------------------|
| `name`      | Yes      | string | Unique kebab-case identifier              |
| `version`   | Yes      | string | SemVer version (`"MAJOR.MINOR.PATCH"`)   |
| `description`| No      | string | Human-readable description                |

#### Example: Full Configuration

```rust
#[misogi_plugin(
    name = "acsc_au_scanner",
    version = "2.1.0",
    description = "ACSC (Australian Cyber Security Centre) Essential Eight compliance scanner"
)]
pub struct AcscEssentialEightPlugin;
```

#### Example: Minimal Configuration

```rust
#[misogi_plugin(name = "simple_rule", version = "0.1.0")]
pub struct SimpleRule;
```

---

### Lifecycle Hook Macros

These macros mark functions as pipeline event handlers. Apply them to any function
within the same module as your `#[misogi_plugin]` struct.

#### `#[on_file_stream]` — Raw Chunk Processing

Fires for every raw byte chunk flowing through the CDR pipeline.

**Signature:**
```rust
#[on_file_stream]
async fn handler(chunk: &mut [u8]) -> Result<(), Error> { ... }
```

| Parameter | Type         | Description                        |
|-----------|-------------|------------------------------------|
| `chunk`   | `&mut [u8]` | Mutable slice of received bytes    |
| Returns   | `Result<(), E>` | `Ok(())` to allow, `Err` to block |

**Use cases:** Byte-level transformation, real-time scanning, format detection.

#### `#[on_metadata]` — Filename Classification

Receives the filename before content scanning.

**Signature:**
```rust
#[on_metadata]
fn classifier(filename: &str) -> FileCategory { ... }
```

| Parameter  | Type    | Description                    |
|------------|---------|--------------------------------|
| `filename` | `&str`  | Original filename (basename only) |
| Returns    | Classification type | Category assignment |

**Use cases:** Custom file type detection, region-specific format handling.

#### `#[on_scan_content]` — PII Content Scanning

Receives full decoded content after sanitization.

**Signature:**
```rust
#[on_scan_content]
async fn scanner(content: &[u8]) -> Result<PiiScanResult, Error> { ... }
```

| Parameter | Type     | Description                       |
|-----------|----------|-----------------------------------|
| `content` | `&[u8]`  | Decoded file content bytes        |
| Returns   | Scan result with findings           |

**Use cases:** Region-specific PII pattern matching, GDPR/CCPA compliance.

#### `#[on_format_log]` — Custom Log Formatting

Override or augment default audit log output.

**Signature:**
```rust
#[on_format_log]
fn formatter(entry: &AuditLogEntry) -> FormattedLog { ... }
```

| Parameter | Type              | Description             |
|-----------|-------------------|-------------------------|
| `entry`   | `&AuditLogEntry`  | Log event data          |
| Returns   | Formatted log output                 |

**Use cases:** Custom log formats, SIEM integration, regulatory log schemas.

#### `#[on_approval_event]` — Workflow Trigger

Fires when a transfer requires approval.

**Signature:**
```rust
#[on_approval_event]
async fn approver(event: &ApprovalEvent) -> Result<ApprovalAction, Error> { ... }
```

| Parameter | Type              | Description            |
|-----------|-------------------|------------------------|
| `event`   | `&ApprovalEvent`  | Approval request data |
| Returns   | Decision action                           |

**Use cases:** External policy engine consultation, multi-level approval.

---

## Migration Guide: From Manual Traits to Macros

### Before (~240 lines of boilerplate)

```rust
pub struct MyPlugin;

impl PluginMetadata for MyPlugin {
    fn name(&self) -> &'static str { "my_plugin" }
    fn version(&self) -> &'static str { "1.0.0" }
    // ...
}

impl CDRStrategy for MyPlugin {
    async fn sanitize_chunk(&self, chunk: &mut [u8], ...) -> Result<SanitizationAction, Error> {
        // 50+ lines of implementation
    }
    async fn sanitize_complete(&self, ...) -> Result<Vec<ReportEntry>, Error> { ... }
    // ... 6 more methods
}

impl PIIDetector for MyPlugin {
    async fn detect_pii(&self, content: &[u8], ...) -> Result<PiiScanResult, Error> { ... }
    // ... 4 more methods
}

// ... FileTypeDetector, LogFormatter, ApprovalTrigger, CalendarProvider, EncodingHandler
// Total: ~240 lines of repetitive trait implementations
```

### After (~15 lines)

```rust
use misogi_macros::prelude::*;

#[misogi_plugin(name = "my_plugin", version = "1.0.0")]
pub struct MyPlugin;

#[on_file_stream]
async fn inspect_chunk(chunk: &mut [u8]) -> Result<(), Error> {
    // Just your business logic
    Ok(())
}
```

---

## Advanced Usage

### Combining Multiple Hooks

```rust
#[misogi_plugin(name = "full_featured", version = "1.0.0")]
pub struct FullFeaturedPlugin;

#[on_metadata]
fn classify(filename: &str) -> FileCategory { /* ... */ }

#[on_file_stream]
async fn scan_stream(chunk: &mut [u8]) -> Result<(), Error> { /* ... */ }

#[on_scan_content]
async fn deep_scan(content: &[u8]) -> Result<PiiScanResult, Error> { /* ... */ }

#[on_approval_event]
async fn approve(event: &ApprovalEvent) -> Result<ApprovalAction, Error> { /* ... */ }
```

### Custom Error Types

```rust
#[derive(Debug, thiserror::Error)]
enum PluginError {
    #[error("Pattern not found")]
    PatternNotFound,

    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

#[on_file_stream]
async fn inspect(chunk: &mut [u8]) -> Result<(), PluginError> {
    Err(PluginError::InvalidFormat("bad".into()))
}
```

### Querying the Global Registry

```rust
use misogi_core::plugin_registry::GLOBAL_REGISTRY;

// List all loaded plugins
for plugin in GLOBAL_REGISTRY.list_plugins() {
    println!("{} v{}", plugin.name, plugin.version);
}

// Check if a specific plugin is loaded
if GLOBAL_REGISTRY.has_plugin("korea_fss_compliance") {
    println!("Korea FSS plugin is active!");
}
```

---

## Troubleshooting

### "trait not implemented" error after adding `#[on_file_stream]`

Ensure the function signature matches exactly:
- Must be `async fn`
- First parameter must be `&mut [u8]`
- Return type must be `Result<(), SomeError>`

### Duplicate plugin name error at runtime

Each plugin's `name` must be globally unique across all loaded plugins.
Check for name collisions between your plugin and built-in ones.

### Macro doesn't expand in IDE

Proc macros require compilation to expand. Run `cargo check` once to trigger
macro expansion, then IDE features (go-to-definition, autocomplete) should work.

---

## License

Part of the Misogi CDR project. See main repository for license details.
