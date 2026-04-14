//! Signature validation and attribute parsing utilities for Misogi hook macros.
//!
//! Provides compile-time function signature checking with span-aware error
//! messages, and shared attribute argument parsing for all procedural macros
//! in this crate.

use syn::ItemFn;

/// Specification for an expected hook function signature.
///
/// Defines the contract that user-provided hook functions must satisfy.
/// Each field represents one aspect of the signature that is validated.
pub struct SignatureSpec {
    /// Whether the function must be `async`.
    pub required_async: bool,

    /// Minimum number of parameters required (exact match if equal to max).
    pub min_params: usize,

    /// Maximum number of parameters allowed.
    pub max_params: usize,

    /// Expected return type pattern for **structural** prefix matching.
    /// Checked by extracting the outer type constructor (e.g., `"Result"` matches
    /// any `Result<T, E>`, `"&str"` matches any `&'static str` / `&str`).
    /// `None` means any return type is accepted.
    pub expected_return: Option<&'static str>,

    /// Human-readable name of this hook (used in error messages).
    pub hook_name: &'static str,
}

/// Parsed and validated components extracted from a hook function signature.
#[allow(dead_code)]
pub struct ValidatedSignature {
    /// Whether the function is async.
    pub is_async: bool,

    /// The original function item (owned for code generation).
    pub func: ItemFn,
}

/// Validate that a plugin name conforms to kebab-case convention.
///
/// # Rules
///
/// - Must start with lowercase ASCII letter `[a-z]`
/// - May contain lowercase letters, digits, hyphens, underscores `[a-z0-9_-]`
/// - Must be non-empty
pub fn validate_plugin_name(name: &str) -> Result<(), syn::Error> {
    if name.is_empty() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "Plugin name must not be empty",
        ));
    }

    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "Plugin name must be kebab-case starting with [a-z], got '{}'",
                    name
                ),
            ));
        }
    }

    for c in chars {
        match c {
            'a'..='z' | '0'..='9' | '-' | '_' => {}
            other => {
                return Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    format!(
                        "Invalid character '{}' in plugin name '{}'. \
                         Allowed: [a-z0-9_-]",
                        other, name
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Validate a hook function's signature against the expected specification.
///
/// # Arguments
///
/// * `func` — The parsed function item to validate.
/// * `expected` — The signature specification to check against.
///
/// # Returns `Ok(ValidatedSignature)` on success, `Err(syn::Error)` on first failure.
pub fn validate_hook_signature(
    func: &ItemFn,
    expected: &SignatureSpec,
) -> Result<ValidatedSignature, syn::Error> {
    validate_unsafe_const_extern(func)?;
    validate_visibility(func)?;
    validate_generics(func, expected.hook_name)?;
    validate_asyncness(func, expected)?;
    validate_param_count(func, expected)?;
    validate_return_type(func, expected)?;

    Ok(ValidatedSignature {
        is_async: func.sig.asyncness.is_some(),
        func: func.clone(),
    })
}

/// Reject `unsafe`, `const`, and `extern` qualifiers on hook functions.
fn validate_unsafe_const_extern(func: &ItemFn) -> Result<(), syn::Error> {
    if let Some(unsafety) = &func.sig.unsafety {
        return Err(syn::Error::new_spanned(
            unsafety,
            "Hook functions must not be `unsafe`. \
             Wrap unsafe operations inside the function body instead.",
        ));
    }
    if let Some(constness) = &func.sig.constness {
        return Err(syn::Error::new_spanned(
            constness,
            "Hook functions cannot be `const`. Const fns are evaluated at compile time.",
        ));
    }
    if let Some(abi) = &func.sig.abi {
        return Err(syn::Error::new_spanned(
            abi,
            "Hook functions cannot have an extern ABI. Use Rust-native calling convention.",
        ));
    }
    Ok(())
}

/// Ensure visibility is absent or plain `pub` (no restricted visibility).
fn validate_visibility(func: &ItemFn) -> Result<(), syn::Error> {
    match &func.vis {
        syn::Visibility::Inherited => Ok(()),
        syn::Visibility::Restricted(_) => Err(syn::Error::new_spanned(
            &func.vis,
            "Hook functions must not have restricted visibility (e.g., `pub(crate)`). \
             Use no visibility or plain `pub`.",
        )),
        _ => Ok(()),
    }
}

/// Reject generic type parameters on hook functions.
fn validate_generics(func: &ItemFn, hook_name: &str) -> Result<(), syn::Error> {
    if !func.sig.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &func.sig.generics,
            format!(
                "#[{}] functions must not be generic. Remove type parameters.",
                hook_name
            ),
        ));
    }
    Ok(())
}

/// Validate async/sync matches expectation.
fn validate_asyncness(func: &ItemFn, expected: &SignatureSpec) -> Result<(), syn::Error> {
    let is_async = func.sig.asyncness.is_some();
    let fn_token = func.sig.fn_token;
    if is_async != expected.required_async {
        if expected.required_async {
            Err(syn::Error::new_spanned(
                fn_token,
                format!(
                    "#[{}] requires an `async fn`, but found a plain `fn`. Add `async`.",
                    expected.hook_name
                ),
            ))
        } else {
            Err(syn::Error::new_spanned(
                fn_token,
                format!(
                    "#[{}] requires a plain `fn`, but found an `async fn`. Remove `async`.",
                    expected.hook_name
                ),
            ))
        }
    } else {
        Ok(())
    }
}

/// Validate parameter count within allowed range.
fn validate_param_count(func: &ItemFn, expected: &SignatureSpec) -> Result<(), syn::Error> {
    let count = func.sig.inputs.len();
    let span = proc_macro2::Span::call_site();
    if count < expected.min_params || count > expected.max_params {
        if expected.min_params == expected.max_params {
            Err(syn::Error::new(
                span,
                format!(
                    "#[{}] expects exactly {} parameter(s), found {}.",
                    expected.hook_name, expected.min_params, count
                ),
            ))
        } else {
            Err(syn::Error::new(
                span,
                format!(
                    "#[{}] expects {}..{} parameter(s), found {}.",
                    expected.hook_name, expected.min_params, expected.max_params, count
                ),
            ))
        }
    } else {
        Ok(())
    }
}

/// Validate return type using **structural prefix matching**.
///
/// Instead of exact string comparison (which breaks on generic parameters like
/// `Result<(), std::io::Error>` vs `Result<(), E>`), this extracts the outer
/// type constructor and checks it against the expected pattern:
///
/// | Expected Pattern  | Matches                              |
/// |-------------------|--------------------------------------|
/// | `"Result"`        | `Result<T, E>` for any T, E         |
/// | `"&str"`          | `&'static str`, `&str`, etc.       |
/// | `"String"`        | exactly `String` (exact match)     |
/// | `None`            | any return type accepted            |
fn validate_return_type(func: &ItemFn, expected: &SignatureSpec) -> Result<(), syn::Error> {
    let Some(expected_pattern) = expected.expected_return else {
        return Ok(());
    };

    let actual_ts = match &func.sig.output {
        syn::ReturnType::Default => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "#[{}] expects a return type, but found none (-> ()).",
                    expected.hook_name
                ),
            ));
        }
        syn::ReturnType::Type(_, ty) => quote::quote!(#ty).to_string(),
    };

    let normalized = actual_ts.replace([' ', '\t'], "");

    if !return_type_matches(&normalized, expected_pattern) {
        Err(syn::Error::new_spanned(
            &func.sig.output,
            format!(
                "#[{}] expects a return type compatible with `{}`, found `{}`.",
                expected.hook_name, expected_pattern, actual_ts
            ),
        ))
    } else {
        Ok(())
    }
}

/// Check whether a normalized actual return type matches the expected pattern.
///
/// Uses prefix matching for generic types and exact matching for concrete types.
fn return_type_matches(normalized_actual: &str, expected: &str) -> bool {
    match expected {
        "Result" => normalized_actual.starts_with("Result<"),
        "&str" => normalized_actual.starts_with("&") && normalized_actual.contains("str"),
        "String" => normalized_actual == "String" || normalized_actual == "std::string::String",
        _ => normalized_actual.starts_with(expected),
    }
}

// =============================================================================
// Shared Attribute Parsing Structures
// =============================================================================

/// Parsed arguments from `#[misogi_plugin(name = "...", version = "...", ...)]`.
pub struct MisogiPluginArgs {
    /// Required: unique kebab-case plugin identifier.
    pub name: String,

    /// Required: semantic version string.
    pub version: String,

    /// Optional: human-readable description.
    pub description: Option<String>,

    /// Optional: explicit list of implemented interface names.
    /// When set, overrides auto-detection. Defaults to `["PluginMetadata"]`.
    pub interfaces: Option<Vec<String>>,
}

impl syn::parse::Parse for MisogiPluginArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut version = None;
        let mut description = None;
        let mut interfaces = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;

            match key.to_string().as_str() {
                "name" => name = Some(input.parse::<syn::LitStr>()?.value()),
                "version" => version = Some(input.parse::<syn::LitStr>()?.value()),
                "description" => description = Some(input.parse::<syn::LitStr>()?.value()),
                "interfaces" => {
                    let content;
                    syn::bracketed!(content in input);
                    let strs =
                        syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::
                            parse_terminated(&content)?;
                    interfaces = Some(strs.into_iter().map(|s| s.value()).collect());
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &key,
                        format!(
                            "Unknown parameter '{}'. Expected: name, version, \
                             description, or interfaces",
                            other
                        ),
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

        Ok(Self {
            name,
            version,
            description,
            interfaces,
        })
    }
}

/// Parsed result of `impl_for = Name` / `extensions = [...]` from hook attributes.
pub struct ImplForArgs {
    /// Target struct name for the generated trait impl.
    pub impl_for: Option<syn::Ident>,

    /// Optional list of supported file extensions (for CDRStrategy only).
    pub extensions: Option<Vec<syn::LitStr>>,
}

impl syn::parse::Parse for ImplForArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut impl_for = None;
        let mut extensions = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;

            match key.to_string().as_str() {
                "impl_for" => impl_for = Some(input.parse::<syn::Ident>()?),
                "extensions" => {
                    let content;
                    syn::bracketed!(content in input);
                    let exts =
                        syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::
                            parse_terminated(&content)?;
                    extensions = Some(exts.into_iter().collect());
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &key,
                        format!("Unknown parameter '{}'. Expected: impl_for", other),
                    ));
                }
            }

            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            }
        }

        Ok(Self {
            impl_for,
            extensions,
        })
    }
}

/// Parse `impl_for = Name` (and optionally `extensions = [...]`) from a hook attribute.
///
/// Returns `Err` with span-aware message if parsing fails or if `impl_for`
/// is missing when `require_impl_for` is `true`.
pub fn parse_impl_for_attr(
    attr: proc_macro::TokenStream,
    hook_name: &str,
    require_impl_for: bool,
) -> syn::Result<ImplForArgs> {
    let args = syn::parse::<ImplForArgs>(attr)?;
    if require_impl_for && args.impl_for.is_none() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("`impl_for` is required for #[{}]", hook_name),
        ));
    }
    Ok(args)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_kebab_case_names() {
        assert!(validate_plugin_name("my-plugin").is_ok());
        assert!(validate_plugin_name("korea_fss_v2").is_ok());
        assert!(validate_plugin_name("a").is_ok());
        assert!(validate_plugin_name("a_b-c1").is_ok());
    }

    #[test]
    fn invalid_names_rejected() {
        assert!(validate_plugin_name("").is_err());
        assert!(validate_plugin_name("MyPlugin").is_err());
        assert!(validate_plugin_name("123-start").is_err());
        assert!(validate_plugin_name("CamelCase").is_err());
    }

    #[test]
    fn return_type_structural_matching() {
        // Result<T, E> matches "Result" pattern regardless of inner types
        assert!(return_type_matches("Result<(),std::io::Error>", "Result"));
        assert!(return_type_matches("Result<Vec<PIIMatch>,E>", "Result"));
        assert!(return_type_matches("Result<ApprovalAction,E>", "Result"));

        // &str patterns
        assert!(return_type_matches("&'staticstr", "&str"));
        assert!(return_type_matches("&str", "&str"));

        // String exact match
        assert!(return_type_matches("String", "String"));
        assert!(return_type_matches("std::string::String", "String"));

        // Non-matches
        assert!(!return_type_matches("Vec<u8>", "Result"));
        assert!(!return_type_matches("i32", "&str"));
    }
}
