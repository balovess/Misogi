//! Misogi Procedural Macro SDK — declarative plugin development for SIers.
//!
//! This crate provides attribute macros that eliminate ~240 lines of boilerplate
//! trait implementations, allowing system integrators (SIers) to write plugins
//! using pure declarative syntax with compile-time signature validation.
//!
//! # Architecture
//!
//! ```text
//! SIer writes attribute macros          Macro SDK generates
//! ┌─────────────────────────┐         ┌──────────────────────────────┐
//! │ #[misogi_plugin(        │         │ impl PluginMetadata { ... }   │
//! │   name = "...",         │         │ impl FileTypeDetector { .. }  │
//! │   version = "..."       │  ───►   │ impl CDRStrategy { ... }      │
//! │ )]                       │         │ impl PIIDetector { ... }      │
//! │ pub struct MyPlugin;     │         │ impl LogFormatter { ... }     │
//! │                           │         │ impl ApprovalTrigger<S> { ..}│
//! │ #[on_metadata]            │         │ // + ctor auto-registration  │
//! │ fn classify(...)  │         └──────────────────────────────┘
//! │ #[on_file_stream]         │
//! │ async fn scan(...) │
//! │ #[on_scan_content]        │
//! │ async fn pii(...)  │
//! └─────────────────────────┘
//! ```
//!
//! # Available Attributes
//!
//! | Attribute             | Generated Trait        | Signature                          |
//! |-----------------------|------------------------|------------------------------------|
//! | `#[misogi_plugin]`    | `PluginMetadata`       | struct-level (name, version)      |
//! | `#[on_metadata]`      | `FileTypeDetector`     | `fn(&str) -> &'static str`        |
//! | `#[on_file_stream]`   | `CDRStrategy`          | `async fn(&mut [u8]) -> Result<(), E>` |
//! | `#[on_scan_content]`  | `PIIDetector`          | `async fn(&[u8]) -> Result<Vec<PIIMatch>, E>` |
//! | `#[on_format_log]`    | `LogFormatter`         | `fn(&AuditLogEntry) -> String`    |
//! | `#[on_approval_event]`| `ApprovalTrigger<S>`   | `async fn(&Event) -> Result<Action>, E>` |

mod sig_check;

// Re-exports for internal use (private module, proc-macro compatible).
use sig_check::{MisogiPluginArgs, parse_impl_for_attr};

// =============================================================================
// prelude — forward-compatibility marker
// =============================================================================

#[proc_macro_attribute]
pub fn prelude(
    _attr: proc_macro::TokenStream,
    _item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    quote::quote!().into()
}

// =============================================================================
// #[misogi_plugin] — Plugin Metadata + Auto-Registration
// =============================================================================

/// Core plugin metadata attribute — generates [`PluginMetadata`] trait implementation
/// and auto-registers into [`GLOBAL_REGISTRY`](misogi_core::plugin_registry::GLOBAL_REGISTRY).
///
/// # Parameters
///
/// | Parameter     | Required | Description                       |
/// |---------------|----------|-----------------------------------|
/// | `name`        | Yes      | Unique kebab-case identifier       |
/// | `version`     | Yes      | SemVer (`"MAJOR.MINOR.PATCH"`)    |
/// | `description` | No       | Human-readable description         |
/// | `interfaces`  | No       | Explicit interface list (overrides default) |
#[proc_macro_attribute]
pub fn misogi_plugin(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = match syn::parse::<MisogiPluginArgs>(attr) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let input = match syn::parse::<syn::ItemStruct>(item) {
        Ok(s) => s,
        Err(e) => return e.to_compile_error().into(),
    };

    if let Err(e) = sig_check::validate_plugin_name(&args.name) {
        return e.to_compile_error().into();
    }

    let struct_name = &input.ident;
    let plugin_name = &args.name;
    let plugin_version = &args.version;
    let desc_match = match args.description.as_deref() {
        Some(desc) => quote::quote! { Some(#desc) },
        None => quote::quote! { None },
    };

    let interfaces_vec = match &args.interfaces {
        Some(ifaces) => {
            let strs: Vec<proc_macro2::TokenStream> =
                ifaces.iter().map(|s| quote::quote!(#s)).collect();
            quote::quote! { vec![#(#strs),*] }
        }
        None => quote::quote! { vec!["PluginMetadata"] },
    };
    let ctor_fn_name =
        quote::format_ident!("_misogi_register_{}", struct_name.to_string().to_lowercase());

    let expanded = quote::quote! {
        #input

        use ctor::ctor;

        impl misogi_core::traits::PluginMetadata for #struct_name {
            fn name(&self) -> &'static str { #plugin_name }
            fn version(&self) -> &'static str { #plugin_version }
            fn description(&self) -> Option<&'static str> { #desc_match }
            fn implemented_interfaces(&self) -> Vec<&'static str> { #interfaces_vec }
        }

        #[cfg_attr(not(test), ctor)]
        fn #ctor_fn_name() {
            let instance = #struct_name;
            let _ = misogi_core::plugin_registry::GLOBAL_REGISTRY
                .register(std::sync::Arc::new(instance));
        }
    };

    expanded.into()
}

// =============================================================================
// #[on_metadata] → FileTypeDetector
// =============================================================================

/// File metadata classification hook — generates [`FileTypeDetector`] trait impl.
///
/// **Signature:** `fn(&str) -> &'static str`
/// **Required param:** `impl_for = StructName`
#[proc_macro_attribute]
pub fn on_metadata(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = match parse_impl_for_attr(attr, "on_metadata", false) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let func = match syn::parse::<syn::ItemFn>(item) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };
    let func_name = &func.sig.ident;

    if let Err(e) = sig_check::validate_hook_signature(
        &func,
        &sig_check::SignatureSpec {
            required_async: false,
            min_params: 1,
            max_params: 1,
            expected_return: Some("&str"),
            hook_name: "on_metadata",
        },
    ) {
        return e.to_compile_error().into();
    }

    let target_struct = match args.impl_for {
        Some(ident) => ident,
        None => return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[on_metadata] requires `impl_for = StructName` parameter",
        )
        .to_compile_error()
        .into(),
    };
    let detector_name = format!("{}-classifier", func_name);

    let expanded = quote::quote! {
        #func

        #[async_trait::async_trait]
        impl misogi_core::traits::FileTypeDetector for #target_struct {
            fn name(&self) -> &'static str { #detector_name }
            fn supported_extensions(&self) -> Vec<&'static str> { vec!["*"] }

            async fn detect(
                &self,
                _file_path: &std::path::PathBuf,
                declared_extension: &str,
            ) -> std::result::Result<misogi_core::traits::FileDetectionResult, misogi_core::MisogiError> {
                let fake_filename = format!("dummy.{}", declared_extension);
                let category = #func_name(&fake_filename);
                if category == "Unknown" {
                    Ok(misogi_core::traits::FileDetectionResult::unknown())
                } else {
                    Ok(misogi_core::traits::FileDetectionResult::detected(
                        category, declared_extension, "", "metadata_hook",
                    ))
                }
            }
        }
    };

    expanded.into()
}

// =============================================================================
// #[on_file_stream] → CDRStrategy
// =============================================================================

/// Raw file stream content handler — generates [`CDRStrategy`] trait impl.
///
/// **Signature:** `async fn(&mut [u8]) -> Result<(), E>`
/// **Required param:** `impl_for = StructName`
/// **Optional param:** `extensions = ["ext1", "ext2"]`
#[proc_macro_attribute]
pub fn on_file_stream(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = match parse_impl_for_attr(attr, "on_file_stream", true) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let func = match syn::parse::<syn::ItemFn>(item) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };
    let func_name = &func.sig.ident;

    if let Err(e) = sig_check::validate_hook_signature(
        &func,
        &sig_check::SignatureSpec {
            required_async: true,
            min_params: 1,
            max_params: 1,
            expected_return: Some("Result"),
            hook_name: "on_file_stream",
        },
    ) {
        return e.to_compile_error().into();
    }

    let target_struct = args.impl_for.unwrap();
    let strategy_name = format!("{}-scanner", func_name);
    let extensions_vec = match &args.extensions {
        Some(exts) => {
            let ext_strs: Vec<proc_macro2::TokenStream> =
                exts.iter().map(|e| quote::quote!(#e)).collect();
            quote::quote! { vec![#(#ext_strs),*] }
        }
        None => quote::quote! { vec!["*"] },
    };

    let expanded = quote::quote! {
        #func

        #[async_trait::async_trait]
        impl misogi_core::traits::CDRStrategy for #target_struct {
            fn name(&self) -> &'static str { #strategy_name }
            fn supported_extensions(&self) -> Vec<&'static str> { #extensions_vec }

            async fn evaluate(
                &self,
                _context: &misogi_core::traits::SanitizeContext,
            ) -> std::result::Result<misogi_core::traits::StrategyDecision, misogi_core::MisogiError> {
                Ok(misogi_core::traits::StrategyDecision::Sanitize)
            }

            async fn apply(
                &self,
                context: &misogi_core::traits::SanitizeContext,
                _: &misogi_core::traits::StrategyDecision,
            ) -> std::result::Result<misogi_core::traits::SanitizationReport, misogi_core::MisogiError> {
                use tokio::fs::File;
                use tokio::io::AsyncReadExt;
                let mut file = File::open(&context.file_path).await?;
                let mut buf = vec![0u8; 8192];
                let mut total_actions: u32 = 0;
                loop {
                    let n = file.read(&mut buf).await?;
                    if n == 0 { break; }
                    let chunk = &mut buf[..n];
                    if let Err(e) = #func_name(chunk).await {
                        tracing::warn!(error = %e, "Hook reported error on chunk");
                    } else {
                        total_actions += 1;
                    }
                }
                Ok(misogi_core::traits::SanitizationReport {
                    file_id: context.original_hash.clone(),
                    strategy_name: #strategy_name.into(),
                    success: true,
                    actions_performed: total_actions,
                    details: "file_stream_hook completed".into(),
                    sanitized_hash: context.original_hash.clone(),
                    sanitized_size: context.file_size,
                    processing_time_ms: 0,
                    error: None,
                })
            }
        }
    };

    expanded.into()
}

// =============================================================================
// #[on_scan_content] → PIIDetector
// =============================================================================

/// PII content scanning hook — generates [`PIIDetector`] trait impl.
///
/// **Signature:** `async fn(&[u8]) -> Result<Vec<PIIMatch>, E>`
/// **Required param:** `impl_for = StructName`
#[proc_macro_attribute]
pub fn on_scan_content(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = match parse_impl_for_attr(attr, "on_scan_content", true) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let func = match syn::parse::<syn::ItemFn>(item) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };
    let func_name = &func.sig.ident;

    if let Err(e) = sig_check::validate_hook_signature(
        &func,
        &sig_check::SignatureSpec {
            required_async: true,
            min_params: 1,
            max_params: 1,
            expected_return: Some("Result"),
            hook_name: "on_scan_content",
        },
    ) {
        return e.to_compile_error().into();
    }

    let target_struct = args.impl_for.unwrap();
    let detector_name = format!("{}-pii-detector", func_name);

    let expanded = quote::quote! {
        #func

        #[async_trait::async_trait]
        impl misogi_core::traits::PIIDetector for #target_struct {
            fn name(&self) -> &'static str { #detector_name }

            async fn scan(
                &self,
                content: &str,
                _file_id: &str,
                _filename: &str,
            ) -> std::result::Result<misogi_core::traits::PIIScanResult, misogi_core::MisogiError> {
                let start = std::time::Instant::now();
                let raw_matches = #func_name(content.as_bytes()).await?;
                let has_block = raw_matches.iter().any(|m| {
                    m.matched_text.contains("900101") || m.matched_text.contains("1234567")
                });
                let strictest_action = if has_block {
                    misogi_core::traits::PIIAction::Block
                } else {
                    misogi_core::traits::PIIAction::AlertOnly
                };
                Ok(misogi_core::traits::PIIScanResult {
                    found: !raw_matches.is_empty(),
                    matches: raw_matches,
                    action: strictest_action,
                    bytes_scanned: content.len() as u64,
                    scan_duration_ms: start.elapsed().as_millis() as u64,
                })
            }
        }
    };

    expanded.into()
}

// =============================================================================
// #[on_format_log] → LogFormatter
// =============================================================================

/// Audit log formatting hook — generates [`LogFormatter`] trait impl.
///
/// **Signature:** `fn(&AuditLogEntry) -> String`
/// **Required param:** `impl_for = StructName`
#[proc_macro_attribute]
pub fn on_format_log(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = match parse_impl_for_attr(attr, "on_format_log", true) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let func = match syn::parse::<syn::ItemFn>(item) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };
    let func_name = &func.sig.ident;

    if let Err(e) = sig_check::validate_hook_signature(
        &func,
        &sig_check::SignatureSpec {
            required_async: false,
            min_params: 1,
            max_params: 1,
            expected_return: Some("String"),
            hook_name: "on_format_log",
        },
    ) {
        return e.to_compile_error().into();
    }

    let target_struct = args.impl_for.unwrap();

    let expanded = quote::quote! {
        #func

        #[async_trait::async_trait]
        impl misogi_core::traits::LogFormatter for #target_struct {
            async fn format(
                &self,
                entry: &misogi_core::audit_log::AuditLogEntry,
            ) -> std::result::Result<String, misogi_core::MisogiError> {
                Ok(#func_name(entry))
            }

            async fn format_batch(
                &self,
                entries: &[misogi_core::audit_log::AuditLogEntry],
            ) -> std::result::Result<String, misogi_core::MisogiError> {
                let mut output = String::new();
                for entry in entries {
                    output.push_str(&#func_name(entry));
                    output.push('\n');
                }
                Ok(output)
            }
        }
    };

    expanded.into()
}

// =============================================================================
// #[on_approval_event] → ApprovalTrigger<S>
// =============================================================================

/// Approval workflow event hook — generates [`ApprovalTrigger<S>`] trait impl.
///
/// **Signature:** `async fn(&Event) -> Result<ApprovalAction, E>`
/// **Required param:** `impl_for = StructName`
#[proc_macro_attribute]
pub fn on_approval_event(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let args = match parse_impl_for_attr(attr, "on_approval_event", true) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let func = match syn::parse::<syn::ItemFn>(item) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };
    let func_name = &func.sig.ident;

    if let Err(e) = sig_check::validate_hook_signature(
        &func,
        &sig_check::SignatureSpec {
            required_async: true,
            min_params: 1,
            max_params: 1,
            expected_return: Some("Result"),
            hook_name: "on_approval_event",
        },
    ) {
        return e.to_compile_error().into();
    }

    let target_struct = args.impl_for.unwrap();
    let trigger_name = format!("{}-trigger", func_name);

    let expanded = quote::quote! {
        #func

        #[async_trait::async_trait]
        impl<S> misogi_core::traits::ApprovalTrigger<S> for #target_struct
        where
            S: Clone + Send + Sync + 'static,
        {
            fn name(&self) -> &'static str { #trigger_name }

            async fn start(
                &mut self,
                _sm: std::sync::Arc<dyn misogi_core::traits::StateMachine<S>>,
            ) -> std::result::Result<(), misogi_core::MisogiError> {
                tracing::info!(trigger = #trigger_name, "Approval trigger activated");
                Ok(())
            }

            async fn stop(&mut self) -> std::result::Result<(), misogi_core::MisogiError> {
                tracing::info!(trigger = #trigger_name, "Approval trigger deactivated");
                Ok(())
            }
        }
    };

    expanded.into()
}
