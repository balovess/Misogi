//! Downgrade adapter — strips unknown fields from v2 requests when targeting v1 receiver.
//!
//! Implements a **unidirectional downgrade** transformation that removes fields not
//! present in the target version's schema, ensuring backward compatibility when
//! newer clients communicate with older receivers.
//!
//! # Design Principles
//!
//! | Concern              | Strategy                                    |
//! |----------------------|---------------------------------------------|
//! | Unknown field policy | Configurable strict vs lenient mode         |
//! | Nested object depth  | Recursive stripping at arbitrary depth      |
//! | Array element handling| Per-element field filtering                 |
//! | Audit trail          | Optional logging of stripped field names    |
//!
//! # Usage Example
//!
//! ```ignore
//! let adapter = DowngradeBuilder::new()
//!     .with_known_fields(vec!["applicant_id", "file_hash"])
//!     .with_strict_mode(false)
//!     .build();
//!
//! let v2_request = r#"{"applicant_id":"A001","file_hash":"abc","new_v2_field":42}"#;
//! let cleaned = adapter.adapt_request(
//!     v2_request.as_bytes().to_vec(),
//!     &ApiVersion::new(2, 0, 0),
//!     &ApiVersion::new(1, 0, 0),
//! )?;
//! // cleaned contains only applicant_id + file_hash
//! ```

use crate::versioning::api_semver::ApiVersion;
use crate::versioning::protocol_adapter::{AdapterError, ProtocolAdapter};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

// =============================================================================
// Default known field set — standard Misogi protocol v1 fields
// =============================================================================

/// Returns the default set of field names recognised by Misogi protocol v1.
///
/// This list is derived from the canonical v1 API specification and should be
/// updated whenever new stable fields are added to the baseline version.
#[inline]
#[must_use]
pub fn default_v1_fields() -> HashSet<String> {
    [
        "applicant_id",
        "file_hash",
        "file_name",
        "file_size",
        "mime_type",
        "checksum_sha256",
        "timestamp",
        "request_id",
        "operation",
        "status_code",
        "message",
        "metadata",
    ]
    .map(String::from)
    .into()
}

// =============================================================================
// DowngradeAdapter — Core struct
// =============================================================================

/// Unidirectional protocol downgrader that strips unknown fields from payloads.
///
/// When a v2 client sends a request containing extension fields unknown to a
/// v1 receiver, this adapter removes those fields before forwarding the payload.
/// The behaviour on encountering unknown fields depends on [`strict_mode`]:
///
/// - **Strict mode** (`true`): Rejects the entire payload with
///   [`AdapterError::UnknownField`], suitable for environments where schema
///   conformance must be enforced at the gateway level.
/// - **Lenient mode** (`false`): Silently drops unknown fields and continues,
///   suitable for gradual migration scenarios where clients may send optional
///   extensions.
///
/// # Thread Safety
///
/// This type is `Send + Sync` and contains no interior mutability, making it
/// safe for concurrent use across async tasks without locking.
#[derive(Debug)]
pub struct DowngradeAdapter {
    /// Field names that are valid in the target (older) version's schema.
    known_v1_fields: HashSet<String>,

    /// When `true`, any unknown field causes an immediate error return.
    strict_mode: bool,

    /// The oldest version this adapter can target (typically v1.0.0).
    target_version: ApiVersion,

    /// When `true`, stripped field names are emitted via `tracing::info!`.
    log_stripped_fields: bool,

    /// Versions this adapter declares support for in negotiation.
    supported: Vec<ApiVersion>,
}

impl DowngradeAdapter {
    /// Create a new adapter from an explicit configuration.
    ///
    /// Prefer using [`DowngradeBuilder`] for ergonomic construction; this
    /// constructor exists for cases where programmatic assembly is required.
    #[inline]
    #[must_use]
    pub fn new(
        known_v1_fields: HashSet<String>,
        strict_mode: bool,
        target_version: ApiVersion,
        log_stripped_fields: bool,
        supported: Vec<ApiVersion>,
    ) -> Self {
        Self {
            known_v1_fields,
            strict_mode,
            target_version,
            log_stripped_fields,
            supported,
        }
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Strip unknown keys from a JSON object recursively.
    ///
    /// Traverses the entire `Value` tree:
    /// - Top-level object keys are filtered against [`known_v1_fields`].
    /// - Nested objects are recursed into (same filter applied).
    /// - Arrays are iterated element-wise; each element that is an object
    ///   receives the same recursive treatment.
    ///
    /// Returns `(cleaned_value, Vec<stripped_field_names>)`.
    fn strip_unknown_fields(
        &self,
        value: &Value,
    ) -> Result<(Value, Vec<String>), AdapterError> {
        match value {
            Value::Object(map) => {
                let mut cleaned = serde_json::Map::with_capacity(map.len());
                let mut stripped = Vec::new();

                for (key, val) in map {
                    if self.known_v1_fields.contains(key) {
                        // Recurse into known nested structures.
                        let (filtered, nested_stripped) =
                            self.strip_unknown_fields(val)?;
                        cleaned.insert(key.clone(), filtered);
                        stripped.extend(nested_stripped);
                    } else if self.strict_mode {
                        return Err(AdapterError::UnknownField(key.clone()));
                    } else {
                        stripped.push(key.clone());
                    }
                }

                Ok((Value::Object(cleaned), stripped))
            }
            Value::Array(arr) => {
                let mut cleaned_arr = Vec::with_capacity(arr.len());
                let mut all_stripped = Vec::new();

                for elem in arr {
                    let (filtered, elem_stripped) = self.strip_unknown_fields(elem)?;
                    cleaned_arr.push(filtered);
                    all_stripped.extend(elem_stripped);
                }

                Ok((Value::Array(cleaned_arr), all_stripped))
            }
            // Primitives pass through unchanged.
            _ => Ok((value.clone(), Vec::new())),
        }
    }

    /// Emit audit log entries for each stripped field name.
    fn log_stripped(&self, stripped: &[String]) {
        if !stripped.is_empty() && self.log_stripped_fields {
            for name in stripped {
                tracing::info!(
                    adapter = "downgrade-v2-to-v1",
                    action = "field_stripped",
                    field_name = %name,
                    "Unknown field removed during protocol downgrade"
                );
            }
        }
    }

    /// Common adaptation logic shared by request and response paths.
    fn adapt_payload(
        &self,
        payload: Vec<u8>,
        from_version: &ApiVersion,
        to_version: &ApiVersion,
        direction: &str,
    ) -> Result<Vec<u8>, AdapterError> {
        // No-op when source and target versions are identical.
        if from_version == to_version {
            tracing::debug!(
                adapter = "downgrade-v2-to-v1",
                direction = %direction,
                version = %to_version,
                "Versions match — skipping adaptation"
            );
            return Ok(payload);
        }

        // Validate that both endpoints are within our supported range.
        if !self.supported.contains(from_version) || !self.supported.contains(to_version) {
            return Err(AdapterError::UnsupportedVersion(*from_version, *to_version));
        }

        // Step 1: Deserialize raw bytes into a generic JSON value.
        let value: Value = serde_json::from_slice(&payload)
            .map_err(|e| AdapterError::DeserializationFailed(e.to_string()))?;

        // Step 2: Strip unknown fields according to mode.
        let (cleaned, stripped) = self.strip_unknown_fields(&value)?;

        // Step 3: Emit audit log if configured.
        self.log_stripped(&stripped);

        // Step 4: Serialize back to wire format.
        let output = serde_json::to_vec(&cleaned)
            .map_err(|e| AdapterError::SerializationFailed(e.to_string()))?;

        tracing::debug!(
            adapter = "downgrade-v2-to-v1",
            direction = %direction,
            from = %from_version,
            to = %to_version,
            stripped_count = stripped.len(),
            output_bytes = output.len(),
            "Downgrade adaptation complete"
        );

        Ok(output)
    }
}

impl ProtocolAdapter for DowngradeAdapter {
    fn adapt_request(
        &self,
        request: Vec<u8>,
        from_version: &ApiVersion,
        to_version: &ApiVersion,
    ) -> Result<Vec<u8>, AdapterError> {
        self.adapt_payload(request, from_version, to_version, "request")
    }

    fn adapt_response(
        &self,
        response: Vec<u8>,
        from_version: &ApiVersion,
        to_version: &ApiVersion,
    ) -> Result<Vec<u8>, AdapterError> {
        self.adapt_payload(response, from_version, to_version, "response")
    }

    #[inline]
    fn supported_versions(&self) -> Vec<ApiVersion> {
        self.supported.clone()
    }

    #[inline]
    fn adapter_name(&self) -> &'static str {
        "downgrade-v2-to-v1"
    }
}

// =============================================================================
// DowngradeBuilder — Fluent constructor
// =============================================================================

/// Builder for [`DowngradeAdapter`] with sensible defaults.
///
/// Defaults:
/// - `known_v1_fields`: [`default_v1_fields()`] (standard Misogi v1 fields)
/// - `strict_mode`: `false` (lenient — silently drop unknowns)
/// - `target_version`: `ApiVersion::new(1, 0, 0)`
/// - `log_stripped_fields`: `true`
/// - `supported`: `[v1.0.0, v2.0.0]`
///
/// # Example
///
/// ```ignore
/// let adapter = DowngradeBuilder::new()
///     .with_known_fields(vec!["id", "name"])
///     .with_strict_mode(true)
///     .build();
/// ```
#[derive(Debug)]
pub struct DowngradeBuilder {
    known_v1_fields: HashSet<String>,
    strict_mode: bool,
    target_version: ApiVersion,
    log_stripped_fields: bool,
    supported: Vec<ApiVersion>,
}

impl Default for DowngradeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DowngradeBuilder {
    /// Create a builder pre-populated with standard Misogi defaults.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            known_v1_fields: default_v1_fields(),
            strict_mode: false,
            target_version: ApiVersion::new(1, 0, 0),
            log_stripped_fields: true,
            supported: vec![ApiVersion::new(1, 0, 0), ApiVersion::new(2, 0, 0)],
        }
    }

    /// Override the set of field names considered valid for the target version.
    #[inline]
    #[must_use]
    pub fn with_known_fields(mut self, fields: Vec<&str>) -> Self {
        self.known_v1_fields = fields.into_iter().map(String::from).collect();
        self
    }

    /// Set whether unknown fields trigger an error or are silently dropped.
    #[inline]
    #[must_use]
    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    /// Set the minimum target version this adapter will produce.
    #[inline]
    #[must_use]
    pub fn with_target_version(mut self, version: ApiVersion) -> Self {
        self.target_version = version;
        self
    }

    /// Enable or disable audit logging of stripped field names.
    #[inline]
    #[must_use]
    pub fn with_log_stripped(mut self, enabled: bool) -> Self {
        self.log_stripped_fields = enabled;
        self
    }

    /// Override the full list of supported versions.
    #[inline]
    #[must_use]
    pub fn with_supported_versions(mut self, versions: Vec<ApiVersion>) -> Self {
        self.supported = versions;
        self
    }

    /// Consume the builder and produce a fully-configured [`DowngradeAdapter`].
    #[inline]
    #[must_use]
    pub fn build(self) -> DowngradeAdapter {
        DowngradeAdapter::new(
            self.known_v1_fields,
            self.strict_mode,
            self.target_version,
            self.log_stripped_fields,
            self.supported,
        )
    }
}

// =============================================================================
// Display impl for diagnostic clarity
// =============================================================================

impl fmt::Display for DowngradeAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DowngradeAdapter(name={}, strict={}, target={}, known_fields={})",
            self.adapter_name(),
            self.strict_mode,
            self.target_version,
            self.known_v1_fields.len(),
        )
    }
}

// =============================================================================
// Tests — comprehensive coverage of all adaptation paths
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------
    // Helper: build a lenient adapter with a minimal known-field set
    // -----------------------------------------------------------------

    fn make_adapter(fields: Vec<&str>, strict: bool) -> DowngradeAdapter {
        DowngradeBuilder::new()
            .with_known_fields(fields)
            .with_strict_mode(strict)
            .with_log_stripped(false)
            .build()
    }

    fn make_default_adapter() -> DowngradeAdapter {
        DowngradeBuilder::new()
            .with_log_stripped(false)
            .build()
    }

    // ====================================================================
    // Test 1: Field stripping — v2 request with extra fields → clean v1
    // ====================================================================

    #[test]
    fn test_strip_extra_fields_from_v2_request() {
        let adapter = make_adapter(vec!["applicant_id", "file_hash"], false);

        let v2_input = json!({
            "applicant_id": "A001",
            "file_hash": "sha256-abc123",
            "new_v2_extension": 42,
            "another_unknown": "drop_me"
        });

        let input_bytes = serde_json::to_vec(&v2_input).unwrap();
        let result = adapter.adapt_request(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok(), "adaptation should succeed in lenient mode");
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();

        assert_eq!(output.get("applicant_id").unwrap(), "A001");
        assert_eq!(output.get("file_hash").unwrap(), "sha256-abc123");
        assert!(output.get("new_v2_extension").is_none());
        assert!(output.get("another_unknown").is_none());
        assert_eq!(output.as_object().unwrap().len(), 2);
    }

    // ====================================================================
    // Test 2: Strict mode rejects any unknown field
    // ====================================================================

    #[test]
    fn test_strict_mode_rejects_unknown_field() {
        let adapter = make_adapter(vec!["id"], true);

        let input = json!({ "id": 1, "extra": "bad" });
        let input_bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_err());

        match result.unwrap_err() {
            AdapterError::UnknownField(field) => {
                assert_eq!(field, "extra");
            }
            other => panic!("Expected UnknownField, got {:?}", other),
        }
    }

    // ====================================================================
    // Test 3: Lenient mode silently strips unknowns
    // ====================================================================

    #[test]
    fn test_lenient_mode_silently_strips() {
        let adapter = make_adapter(vec!["ok"], false);

        let input = json!({ "ok": true, "unknown1": 1, "unknown2": "x" });
        let input_bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(output.get("ok").unwrap(), true);
        assert_eq!(output.as_object().unwrap().len(), 1);
    }

    // ====================================================================
    // Test 4: No-op when source and target versions match
    // ====================================================================

    #[test]
    fn test_noop_when_versions_match() {
        let adapter = make_adapter(vec!["a"], false);

        let input = json!({ "a": 1, "b": 2 });
        let original_bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            original_bytes.clone(),
            &ApiVersion::new(1, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        // Payload must be returned verbatim — no parsing, no modification.
        assert_eq!(result.unwrap(), original_bytes);
    }

    // ====================================================================
    // Test 5: Nested object handling — recursive stripping
    // ====================================================================

    #[test]
    fn test_nested_object_stripping() {
        let adapter = make_adapter(vec!["top", "inner_ok"], false);

        let input = json!({
            "top": {
                "inner_ok": "keep",
                "inner_bad": "strip"
            },
            "outer_bad": "gone"
        });

        let input_bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();

        // Outer bad key removed
        assert!(output.get("outer_bad").is_none());
        // Inner object preserved but inner_bad stripped
        let top = output.get("top").unwrap().as_object().unwrap();
        assert!(top.contains_key("inner_ok"));
        assert!(!top.contains_key("inner_bad"));
    }

    // ====================================================================
    // Test 6: Array element handling — per-element filtering
    // ====================================================================

    #[test]
    fn test_array_element_stripping() {
        let adapter = make_adapter(vec!["items", "name"], false);

        let input = json!({
            "items": [
                { "name": "alice", "age": 30 },
                { "name": "bob", "score": 99 }
            ]
        });

        let input_bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        let items = output.get("items").unwrap().as_array().unwrap();

        assert_eq!(items.len(), 2);
        for item in items {
            let obj = item.as_object().unwrap();
            assert!(obj.contains_key("name"));
            assert!(!obj.contains_key("age") && !obj.contains_key("score"));
        }
    }

    // ====================================================================
    // Test 7: Response adaptation mirrors request logic
    // ====================================================================

    #[test]
    fn test_adapt_response_strips_fields() {
        let adapter = make_adapter(vec!["status", "data"], false);

        let v2_response = json!({
            "status": "ok",
            "data": [1, 2, 3],
            "v2_meta": {"trace_id": "xyz"}
        });

        let input_bytes = serde_json::to_vec(&v2_response).unwrap();
        let result = adapter.adapt_response(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert!(output.get("v2_meta").is_none());
        assert_eq!(output.get("status").unwrap(), "ok");
    }

    // ====================================================================
    // Test 8: Unsupported version pair returns correct error
    // ====================================================================

    #[test]
    fn test_unsupported_version_pair() {
        let adapter = make_adapter(vec!["x"], false);

        let result = adapter.adapt_request(
            b"{}".to_vec(),
            &ApiVersion::new(9, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            AdapterError::UnsupportedVersion(from, to) => {
                assert_eq!(from, ApiVersion::new(9, 0, 0));
                assert_eq!(to, ApiVersion::new(1, 0, 0));
            }
            other => panic!("Expected UnsupportedVersion, got {:?}", other),
        }
    }

    // ====================================================================
    // Test 9: Adapter metadata — name and supported versions
    // ====================================================================

    #[test]
    fn test_adapter_metadata() {
        let adapter = make_default_adapter();
        assert_eq!(adapter.adapter_name(), "downgrade-v2-to-v1");

        let versions = adapter.supported_versions();
        assert_eq!(versions.len(), 2);
        assert!(versions.contains(&ApiVersion::new(1, 0, 0)));
        assert!(versions.contains(&ApiVersion::new(2, 0, 0)));
    }

    // ====================================================================
    // Test 10: Builder default values sanity check
    // ====================================================================

    #[test]
    fn test_builder_defaults() {
        let adapter = DowngradeBuilder::new().build();
        assert_eq!(adapter.adapter_name(), "downgrade-v2-to-v1");
        assert!(!adapter.strict_mode); // default is lenient
        assert!(adapter.log_stripped_fields); // default logs
        assert!(!adapter.known_v1_fields.is_empty()); // has default fields
    }

    // ====================================================================
    // Test 11: Deeply nested structure (3+ levels)
    // ====================================================================

    #[test]
    fn test_deeply_nested_structure() {
        let adapter = make_adapter(vec!["level1", "level2", "leaf"], false);

        let input = json!({
            "level1": {
                "level2": {
                    "leaf": "keep_me",
                    "garbage": "remove"
                },
                "sibling_garbage": 999
            },
            "root_garbage": true
        });

        let input_bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            input_bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();

        // Root garbage gone
        assert!(output.get("root_garbage").is_none());

        let l1 = output.get("level1").unwrap().as_object().unwrap();
        assert!(!l1.contains_key("sibling_garbage"));

        let l2 = l1.get("level2").unwrap().as_object().unwrap();
        assert!(l2.contains_key("leaf"));
        assert!(!l2.contains_key("garbage"));
    }

    // ====================================================================
    // Test 12: Empty payload / empty object edge case
    // ====================================================================

    #[test]
    fn test_empty_object_payload() {
        let adapter = make_adapter(vec!["x"], false);

        let result = adapter.adapt_request(
            b"{}".to_vec(),
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(output.as_object().unwrap().len(), 0);
    }

    // ====================================================================
    // Test 13: Display trait produces useful summary
    // ====================================================================

    #[test]
    fn test_display_format() {
        let adapter = make_adapter(vec!["a", "b"], true);
        let display = format!("{}", adapter);
        assert!(display.contains("downgrade-v2-to-v1"));
        assert!(display.contains("strict=true"));
    }

    // ====================================================================
    // Test 14: Trait object safety — usable as dyn ProtocolAdapter
    // ====================================================================

    #[test]
    fn test_trait_object_safety() {
        let adapter: Box<dyn ProtocolAdapter> =
            Box::new(make_default_adapter());
        assert_eq!(adapter.adapter_name(), "downgrade-v2-to-v1");

        let input = json!({"applicant_id": "T01"});
        let bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );
        assert!(result.is_ok());
    }

    // ====================================================================
    // Test 15: Strict mode with ALL-known fields passes cleanly
    // ====================================================================

    #[test]
    fn test_strict_mode_all_known_passes() {
        let adapter = make_adapter(vec!["alpha", "beta"], true);

        let input = json!({ "alpha": 1, "beta": 2 });
        let bytes = serde_json::to_vec(&input).unwrap();
        let result = adapter.adapt_request(
            bytes,
            &ApiVersion::new(2, 0, 0),
            &ApiVersion::new(1, 0, 0),
        );

        assert!(result.is_ok());
        let output: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(output.as_object().unwrap().len(), 2);
    }
}
