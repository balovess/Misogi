# misogi-macros

**Misogi Procedural Macro SDK** — Declarative plugin development for the Misogi CDR system.

Eliminate ~240 lines of trait implementation boilerplate. Write elegant, concise plugins using pure attribute macros.

## Key Public API

- **`#[misogi_plugin]`** — Main attribute macro (name, version, description)
- **`#[on_file_stream]`** — Raw chunk processing handler
- **`#[on_metadata]`** — Filename classification handler
- **`#[on_scan_content]`** — PII content scanning handler
- **`#[on_format_log]`** — Custom log formatting handler
- **`#[on_approval_event]`** — Workflow trigger handler

## Key Dependencies

- `misogi-core`: Core types and plugin registry
- `syn`/`quote`: Proc macro internals
- `proc-macro2`: Token stream handling

## Quick Example

```rust
use misogi_macros::prelude::*;

#[misogi_plugin(name = "my_plugin", version = "1.0.0")]
pub struct MyPlugin;

#[on_file_stream]
async fn inspect_chunk(chunk: &mut [u8]) -> Result<(), Error> {
    Ok(())
}
```

## Full Documentation

For complete API reference, migration guide, advanced usage patterns, and troubleshooting, see the [root README](../../README.md).
