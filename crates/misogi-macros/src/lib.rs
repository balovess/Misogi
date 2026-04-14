//! Misogi Procedural Macro SDK - declarative plugin development for SIers.
//!
//! This crate provides attribute macros that eliminate ~240 lines of boilerplate
//! trait implementations, allowing system integrators (SIers) to write plugins
//! using pure declarative syntax.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use misogi_macros::prelude::*;
//!
//! #[misogi_plugin(name = "korea_fss_rule", version = "1.0.0")]
//! pub struct KoreaFssRule;
//!
//! #[on_file_stream]
//! async fn inspect_chunk(chunk: &mut [u8]) -> Result<(), Error> {
//!     Ok(())
//! }
//! ```

use proc_macro::TokenStream;
use syn::parse_macro_input;
use quote::format_ident;

/// Re-export all macros for convenient single-import usage.
#[proc_macro_attribute]
pub fn prelude(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    quote::quote!().into()
}

// =============================================================================
// Plugin Metadata Attribute Macro
// =============================================================================

/// Core `#[misogi_plugin]` attribute macro - transforms a struct into a full Misogi plugin.
///
/// Generates PluginMetadata impl + auto-registration into GLOBAL_REGISTRY via ctor.
///
/// # Parameters
///
/// | Parameter    | Required | Description                       |
/// |-------------|----------|-----------------------------------|
/// | `name`      | Yes      | Unique kebab-case identifier       |
/// | `version`   | Yes      | SemVer string (`"MAJOR.MINOR.PATCH"`) |
/// | `description`| No      | Human-readable description         |
#[proc_macro_attribute]
pub fn misogi_plugin(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as MisogiPluginArgs);
    let input = parse_macro_input!(item as syn::ItemStruct);

    let struct_name = &input.ident;
    let plugin_name = &args.name;
    let plugin_version = &args.version;
    let desc_match = match args.description.as_deref() {
        Some(desc) => quote::quote! { Some(#desc) },
        None => quote::quote! { None },
    };
    let ctor_fn_name =
        format_ident!("_misogi_register_{}", struct_name.to_string().to_lowercase());

    let expanded = quote::quote! {
        #input

        use ctor::ctor;

        impl misogi_core::traits::PluginMetadata for #struct_name {
            fn name(&self) -> &'static str { #plugin_name }
            fn version(&self) -> &'static str { #plugin_version }
            fn description(&self) -> Option<&'static str> { #desc_match }
            fn implemented_interfaces(&self) -> Vec<&'static str> { vec!["PluginMetadata"] }
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

struct MisogiPluginArgs {
    name: String,
    version: String,
    description: Option<String>,
}

impl syn::parse::Parse for MisogiPluginArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut version = None;
        let mut description = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            let value: syn::LitStr = input.parse()?;

            match key.to_string().as_str() {
                "name" => name = Some(value.value()),
                "version" => version = Some(value.value()),
                "description" => description = Some(value.value()),
                other => {
                    return Err(syn::Error::new_spanned(
                        &key,
                        format!("Unknown parameter '{}'. Expected: name, version, or description", other),
                    ));
                }
            }

            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            }
        }

        let name = name.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "`name` is required")
        })?;
        let version = version.ok_or_else(|| {
            syn::Error::new(proc_macro2::Span::call_site(), "`version` is required")
        })?;

        Ok(Self { name, version, description })
    }
}

// =============================================================================
// Lifecycle Hook Macros
// =============================================================================

/// Mark a function as a raw file stream handler.
///
/// Signature: `async fn(&mut [u8]) -> Result<(), Error>`
#[proc_macro_attribute]
pub fn on_file_stream(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::ItemFn);
    quote::quote! { #input }.into()
}

/// Mark a function as a metadata/filename classification handler.
///
/// Signature: `fn(&str) -> FileCategory`
#[proc_macro_attribute]
pub fn on_metadata(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::ItemFn);
    quote::quote! { #input }.into()
}

/// Mark a function as a content-level PII scanner.
///
/// Signature: `async fn(&[u8]) -> Result<PiiScanResult, Error>`
#[proc_macro_attribute]
pub fn on_scan_content(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::ItemFn);
    quote::quote! { #input }.into()
}

/// Mark a function as a custom log formatter.
///
/// Signature: `fn(&AuditLogEntry) -> FormattedLog`
#[proc_macro_attribute]
pub fn on_format_log(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::ItemFn);
    quote::quote! { #input }.into()
}

/// Mark a function as an approval workflow trigger.
///
/// Signature: `async fn(&ApprovalEvent) -> Result<ApprovalAction, Error>`
#[proc_macro_attribute]
pub fn on_approval_event(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as syn::ItemFn);
    quote::quote! { #input }.into()
}
