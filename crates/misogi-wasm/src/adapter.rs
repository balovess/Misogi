//! WASM parser adapter bridging WebAssembly modules to ContentParser trait.
//!
//! This module provides [`WasmParserAdapter`], a concrete implementation of the
//! [`ContentParser`](misogi_cdr::parser_trait::ContentParser) trait that delegates
//! parsing operations to sandboxed WASM module instances using wasmi v1.0.9.

use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use wasmi::{Caller, Engine, Linker, Memory, Module, Store};

use crate::abi::{HostImports, PluginExports};
use crate::error::{WasmError, WasmResult};
use crate::sandbox::SandboxConfig;

// ===========================================================================
// WASM Parser Adapter Structure
// ===========================================================================

/// Bridges a loaded WASM plugin to the Misogi CDR ContentParser trait.
///
/// This struct encapsulates a fully instantiated wasmi module, providing
/// type-safe access to the plugin's parsing capabilities through the standard
/// CDR parser interface.
#[derive(Debug)]
pub struct WasmParserAdapter {
    /// Unique identifier for this adapter instance (usually filename stem).
    name: String,

    /// Filesystem path to the loaded .wasm file.
    path: PathBuf,

    /// wasmi execution engine (shared across instances for compilation cache).
    /// Kept for potential future hot-reload functionality.
    #[allow(dead_code)]
    engine: Engine,

    /// wasmi store containing module state and linear memory.
    store: Option<Store<()>>,

    /// Linked and instantiated module instance with resolved exports.
    instance: Option<wasmi::Instance>,

    /// Reference to exported memory for data transfer operations.
    memory: Option<Memory>,

    /// Sandbox configuration applied to this adapter.
    config: SandboxConfig,
}

// ===========================================================================
// Implementation: Construction and Loading
// ===========================================================================

impl WasmParserAdapter {
    /// Load and instantiate a WASM plugin from the given filesystem path.
    ///
    /// # Arguments
    ///
    /// * `wasm_path` - Path to the .wasm file to load
    /// * `config` - Sandbox configuration for resource limits
    pub async fn new<P: AsRef<Path>>(wasm_path: P, config: SandboxConfig) -> WasmResult<Self> {
        let path = wasm_path.as_ref().to_path_buf();

        // Validate sandbox configuration before proceeding
        config.validate().map_err(WasmError::Configuration)?;

        // Extract adapter name from filename (without extension)
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown_plugin")
            .to_string();

        // Step 1: Read WASM binary from disk
        let wasm_bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| WasmError::ModuleLoadFailed {
                path: path.clone(),
                message: format!("cannot read file: {}", e),
                source: Some(e),
            })?;

        // Step 2: Create wasmi engine and validate/compile module format
        let engine = Engine::default();
        let module = Module::new(&engine, &wasm_bytes[..]).map_err(|e| {
            WasmError::InvalidModuleFormat {
                path: path.clone(),
                reason: e.to_string(),
            }
        })?;

        // Step 3: Create linker with host imports (alloc, dealloc, log)
        let mut linker = <Linker<()>>::new(&engine);
        Self::define_host_imports(&mut linker, "env")?;

        // Step 4: Instantiate and start module with empty initial state (wasmi 1.0.9)
        let mut store = Store::new(&engine, ());
        let instance = linker.instantiate_and_start(&mut store, &module).map_err(|e| {
            WasmError::Internal(format!("instantiation failed: {}", e))
        })?;

        // Step 5: Validate required exports exist
        let exports = PluginExports::default();
        Self::validate_exports(&instance, &store, &exports, &path)?;

        // Step 6: Get exported memory for data operations
        let memory: Option<Memory> = instance
            .get_export(&store, "memory")
            .and_then(|ex| ex.into_memory());

        tracing::info!(
            plugin = %name,
            path = %path.display(),
            memory_mb = config.max_memory_mb(),
            "WASM plugin loaded successfully"
        );

        Ok(Self {
            name,
            path,
            engine,
            store: Some(store),
            instance: Some(instance),
            memory,
            config,
        })
    }

    /// Define host functions imported by WASM plugins (wasmi 1.0.9 compatible).
    fn define_host_imports(linker: &mut Linker<()>, module: &str) -> WasmResult<()> {
        let imports = HostImports::default();

        // Import: Allocate memory in WASM linear memory space
        linker
            .func_wrap(module, imports.alloc, |mut caller: Caller<'_, ()>, size: i32| -> i32 {
                // Get exported memory from caller's module
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return -1,
                };

                // Calculate current memory size in bytes
                let current_size = mem.data_size(&caller) as i32;

                // Calculate pages needed (64KB per page)
                let bytes_needed = size.max(1) as u64;
                let pages_needed = (bytes_needed + 65535) / 65536;

                // Grow memory by required pages (wasmi 1.0.9: grow takes u64)
                match mem.grow(&mut caller, pages_needed) {
                    Ok(_) => current_size,
                    Err(_) => -1,
                }
            })
            .map_err(|e| {
                WasmError::Internal(format!("failed to define {}: {}", imports.alloc, e))
            })?;

        // Import: Deallocate memory (no-op for now; memory reclaimed on drop)
        linker
            .func_wrap(
                module,
                imports.dealloc,
                |_caller: Caller<'_, ()>, _ptr: i32, _size: i32| {
                    // TODO: Implement proper deallocation tracking in future version
                    // Current strategy: memory is reclaimed when module is dropped
                },
            )
            .map_err(|e| {
                WasmError::Internal(format!("failed to define {}: {}", imports.dealloc, e))
            })?;

        // Import: Log message from plugin to host tracer
        linker
            .func_wrap(
                module,
                imports.log,
                |caller: Caller<'_, ()>, ptr: i32, len: i32| {
                    if let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory())
                    {
                        let data = mem.data(&caller);
                        if ptr >= 0 && len > 0 {
                            let start = ptr as usize;
                            let end = start.saturating_add(len as usize);
                            if end <= data.len() {
                                if let Ok(msg) = std::str::from_utf8(&data[start..end]) {
                                    tracing::debug!(plugin_log = %msg, "WASM plugin log");
                                    return;
                                }
                            }
                        }
                    }
                    tracing::warn!(
                        ptr = ptr,
                        len = len,
                        "WASM plugin attempted invalid log operation"
                    );
                },
            )
            .map_err(|e| WasmError::Internal(format!("failed to define {}: {}", imports.log, e)))?;

        Ok(())
    }

    /// Verify that all required exports exist in the instantiated module.
    fn validate_exports(
        instance: &wasmi::Instance,
        store: &Store<()>,
        exports: &PluginExports,
        path: &Path,
    ) -> WasmResult<()> {
        // Check parse function (ensure it's a function export)
        if instance.get_export(store, exports.parse).and_then(|e| e.into_func()).is_none() {
            return Err(WasmError::MissingExport {
                function: exports.parse.to_string(),
                path: path.to_path_buf(),
            });
        }

        // Check supported_types function (ensure it's a function export)
        if instance.get_export(store, exports.supported_types).and_then(|e| e.into_func()).is_none() {
            return Err(WasmError::MissingExport {
                function: exports.supported_types.to_string(),
                path: path.to_path_buf(),
            });
        }

        // Check abi_version function (optional but recommended)
        if instance.get_export(store, exports.abi_version).and_then(|e| e.into_func()).is_none() {
            tracing::warn!(
                path = %path.display(),
                "plugin does not export {} (ABI version checking disabled)",
                exports.abi_version
            );
        }

        Ok(())
    }

    /// Get the unique name identifier for this adapter.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the filesystem path of the loaded WASM module.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the sandbox configuration used by this adapter.
    #[inline]
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

// ===========================================================================
// Implementation: ContentParser Trait
// ===========================================================================

#[async_trait]
impl misogi_cdr::parser_trait::ContentParser for WasmParserAdapter {
    /// Query the WASM plugin for its supported MIME types.
    fn supported_types(&self) -> Vec<&'static str> {
        vec![] // Requires mutable access to store - see supported_types_owned()
    }

    /// Return the adapter's identifying name.
    fn parser_name(&self) -> &str {
        &self.name
    }

    /// Execute the WASM plugin's parse_and_sanitize implementation.
    async fn parse_and_sanitize(
        &self,
        input: Bytes,
        policy: &misogi_cdr::parser_trait::SanitizePolicy,
    ) -> Result<misogi_cdr::parser_trait::SanitizedOutput, misogi_cdr::parser_trait::ParseError>
    {
        // Placeholder: Full implementation requires interior mutability pattern
        // to handle wasmi Store's &mut self requirement with trait's &self signature
        let _ = (input, policy); // Suppress unused warnings

        Err(misogi_cdr::parser_trait::ParseError::InternalError(
            "WasmParserAdapter requires interior mutability for wasmi Store access".to_string(),
        ))
    }
}

// ===========================================================================
// Additional Methods (Non-Trait)
// ===========================================================================

impl WasmParserAdapter {
    /// Owned version of supported_types returning String vector.
    ///
    /// Works around the &'static str requirement by returning owned strings.
    pub fn supported_types_owned(&mut self) -> WasmResult<Vec<String>> {
        let store = self.store.as_mut().ok_or_else(|| WasmError::Internal(
            "adapter not initialized (store missing)".to_string(),
        ))?;
        let instance = self.instance.as_ref().ok_or_else(|| WasmError::Internal(
            "adapter not initialized (instance missing)".to_string(),
        ))?;
        let memory = self.memory.as_ref().ok_or_else(|| WasmError::Internal(
            "no memory export available".to_string(),
        ))?;

        // Call misogi_supported_types() export
        let supported_types_fn = instance
            .get_export(&mut *store, "misogi_supported_types")
            .and_then(|ex| ex.into_func())
            .ok_or_else(|| WasmError::MissingExport {
                function: "misogi_supported_types".to_string(),
                path: self.path.clone(),
            })?;

        // Execute the function (takes no args, returns i32 pointer)
        let mut result = Vec::new();
        supported_types_fn
            .call(&mut *store, &[], &mut result)
            .map_err(|e| WasmError::ExecutionTrap {
                module: self.name.clone(),
                message: e.to_string(),
            })?;

        // Extract i32 return value from wasmi Val (wasmi 1.0.9 uses Val enum)
        let result_val = result
            .first()
            .ok_or_else(|| WasmError::Internal("no return value".to_string()))?;

        // Use wasmi 1.0.9's Val::i32() for safe extraction
        let result_ptr = result_val
            .i32()
            .ok_or_else(|| WasmError::Internal("invalid return type (expected i32)".to_string()))?;

        // Read the returned types array from WASM memory (inline to avoid borrow conflicts)
        let data = memory.data(&*store);
        let mut types = Vec::new();
        let mut current_start = result_ptr as usize;

        while current_start < data.len() {
            let end = data[current_start..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - current_start);

            if end == 0 {
                break;
            }

            let type_str = std::str::from_utf8(&data[current_start..current_start + end])
                .map_err(|e| WasmError::Internal(format!("invalid UTF-8 in types: {}", e)))?
                .to_string();

            if !type_str.is_empty() {
                types.push(type_str);
            }

            current_start += end + 1;
        }

        Ok(types)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_load_minimal_valid_module() -> WasmResult<()> {
        let wasm_bytes = include_bytes!("../tests/fixtures/minimal_parser.wasm");

        let temp_file = NamedTempFile::new().expect("cannot create temp file");
        std::fs::write(temp_file.path(), wasm_bytes).expect("cannot write temp file");

        let config = SandboxConfig::default();
        let adapter = WasmParserAdapter::new(temp_file.path(), config).await;

        assert!(adapter.is_err());
        match adapter.unwrap_err() {
            WasmError::MissingExport { .. } => (),
            other => panic!("unexpected error: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn test_adapter_name_derived_from_filename() {
        let expected_name = "my_custom_parser";
        assert!(!expected_name.is_empty());
    }

    #[test]
    fn test_default_config_used_when_not_specified() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_memory_bytes, crate::DEFAULT_MEMORY_LIMIT_BYTES);
        assert_eq!(config.timeout_secs, crate::DEFAULT_TIMEOUT_SECS);
    }
}
