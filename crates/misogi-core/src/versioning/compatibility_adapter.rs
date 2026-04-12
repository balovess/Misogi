//! Cross-version data format converter for graceful migration.
//!
//! When a v2 client sends data with extended fields to a v1 receiver,
//! this adapter strips/transforms unknown fields into v1-compatible format.
//! Conversely, when v1 data arrives at a v2 endpoint, it wraps with defaults.
//!
//! # Design Principles
//!
//! 1. **Forward-compatible**: v2 → v1 always succeeds (strip unknown fields)
//! 2. **Backward-compatible**: v1 → v2 wraps with sensible defaults
//! 3. **Zero-downtime**: No restart needed when rolling out v2
//! 4. **Audit trail**: Every conversion is logged with `[COMPAT]` prefix
//!
//! # Core Scenario
//!
//! ```text
//! External node (v2 sender)
//!   └── ChunkV2 { data, file_id, content_type_hint, metadata } ──►
//!                                                              │
//!                                                    CompatibilityAdapter
//!                                                              │ (downgrade)
//!                                                              ▼
//! Internal node (v1 receiver)
//!   ◄── Chunk { data, file_id, chunk_index, chunk_md5 } ─────┘
//! ```

use serde::{Deserialize, Serialize};

use super::api_version::ApiVersion;

/// Direction of cross-version adaptation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdaptDirection {
    /// v2 data being consumed by a v1 system (strip extensions).
    DowngradeV2toV1,

    /// v1 data being consumed by a v2 system (wrap with defaults).
    UpgradeV1toV2,
}

/// Result of a cross-version adaptation with full audit metadata.
///
/// Contains both the converted payload and diagnostic information
/// useful for compliance logging and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptedResult<T: Serialize> {
    /// The converted payload in the target version's format.
    pub payload: T,

    /// Names of fields that were transformed during conversion.
    pub transformed_fields: Vec<String>,

    /// Original version of the incoming data.
    pub source_version: ApiVersion,

    /// Target version after conversion.
    pub target_version: ApiVersion,
}

/// Converter between V1 and V2 chunk formats.
///
/// Handles bidirectional adaptation:
///
/// | Direction | Operation | Field Mapping |
/// |-----------|-----------|---------------|
/// | V2→V1 | Strip extensions | Drop fields 5-7 |
/// | V1→V2 | Fill defaults | Set fields 5-7 to safe values |
pub struct ChunkCompatAdapter;

impl ChunkCompatAdapter {
    /// Adapt a V2-style extended chunk into V1-compatible format.
    ///
    /// Used when the receiver is running V1 but the sender has upgraded to V2.
    /// Extended metadata (content_type_hint, metadata map, AI flag) is
    /// stripped and logged as `[COMPAT]` audit entries.
    ///
    /// # Arguments
    /// * `data` - Raw bytes of the chunk payload.
    /// * `file_id` - File identifier string.
    /// * `chunk_index` - Sequential index of this chunk.
    /// * `chunk_md5` - MD5 hash of the payload.
    /// * `content_type_hint` - MIME type hint (will be dropped).
    /// * `requires_ai_sanitization` - AI processing flag (will be dropped).
    ///
    /// # Returns
    /// An [`AdaptedResult`] containing the V1-compatible representation.
    pub fn downgrade_chunk(
        data: &[u8],
        file_id: &str,
        chunk_index: u32,
        chunk_md5: &str,
        content_type_hint: Option<&str>,
        requires_ai_sanitization: bool,
    ) -> AdaptedResult<CompatChunkV1> {
        let mut transformed = Vec::new();

        if content_type_hint.is_some() {
            transformed.push("content_type_hint".to_string());
            tracing::warn!(
                "[COMPAT] Dropped field 'content_type_hint' = {:?} (V2→V1 downgrade)",
                content_type_hint
            );
        }

        if requires_ai_sanitization {
            transformed.push("requires_ai_sanitization".to_string());
            tracing::warn!(
                "[COMPAT] Dropped flag 'requires_ai_sanitization' = {} (V2→V1 downgrade)",
                requires_ai_sanitization
            );
        }

        tracing::info!(
            "[COMPAT] Downgraded V2→V1 chunk: file_id={}, dropped {} extension(s)",
            file_id,
            transformed.len()
        );

        AdaptedResult {
            payload: CompatChunkV1 {
                data: data.to_vec(),
                file_id: file_id.to_string(),
                chunk_index,
                chunk_md5: chunk_md5.to_string(),
            },
            transformed_fields: transformed,
            source_version: ApiVersion::V2,
            target_version: ApiVersion::V1,
        }
    }

    /// Adapt a V1-style basic chunk into V2 format with safe defaults.
    ///
    /// Used when the receiver is running V2 but a legacy sender still uses V1.
    /// Missing V2 fields are populated with conservative defaults that
    /// preserve existing behavior.
    ///
    /// # Default Value Strategy
    ///
    /// | V2 Field | Default | Rationale |
    /// |----------|--------|-----------|
    /// | content_type_hint | `"application/octet-stream"` | Generic binary |
    /// | metadata | `{}` | No annotations |
    /// | requires_ai_sanitization | `false` | No AI unless requested |
    ///
    /// # Returns
    /// An [`AdaptedResult`] containing the V2-wrapped representation.
    pub fn upgrade_chunk(
        data: &[u8],
        file_id: &str,
        chunk_index: u32,
        chunk_md5: &str,
    ) -> AdaptedResult<CompatChunkV2> {
        tracing::info!(
            "[COMPAT] Upgraded V1→V2 chunk: file_id={}, filled defaults for fields 5-7",
            file_id
        );

        AdaptedResult {
            payload: CompatChunkV2 {
                data: data.to_vec(),
                file_id: file_id.to_string(),
                chunk_index,
                chunk_md5: chunk_md5.to_string(),
                content_type_hint: "application/octet-stream".to_string(),
                metadata: std::collections::HashMap::new(),
                requires_ai_sanitization: false,
            },
            transformed_fields: vec![
                "content_type_hint".to_string(),
                "metadata".to_string(),
                "requires_ai_sanitization".to_string(),
            ],
            source_version: ApiVersion::V1,
            target_version: ApiVersion::V2,
        }
    }
}

/// V1-compatible internal chunk representation (after downgrade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatChunkV1 {
    pub data: Vec<u8>,
    pub file_id: String,
    pub chunk_index: u32,
    pub chunk_md5: String,
}

/// V2-compatible internal chunk representation (after upgrade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatChunkV2 {
    pub data: Vec<u8>,
    pub file_id: String,
    pub chunk_index: u32,
    pub chunk_md5: String,
    pub content_type_hint: String,
    pub metadata: std::collections::HashMap<String, String>,
    pub requires_ai_sanitization: bool,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_downgrade_strips_content_type() {
        let result = ChunkCompatAdapter::downgrade_chunk(
            b"hello",
            "file-001",
            0,
            "abc123",
            Some("application/pdf"),
            false,
        );
        assert_eq!(result.source_version, ApiVersion::V2);
        assert_eq!(result.target_version, ApiVersion::V1);
        assert!(result.transformed_fields.contains(&"content_type_hint".to_string()));
        assert_eq!(result.payload.file_id, "file-001");
        assert_eq!(result.payload.data, b"hello");
    }

    #[test]
    fn test_downgrade_no_extensions() {
        let result = ChunkCompatAdapter::downgrade_chunk(
            b"data",
            "f1",
            5,
            "md5",
            None,
            false,
        );
        assert!(result.transformed_fields.is_empty());
    }

    #[test]
    fn test_downgrade_drops_ai_flag() {
        let result = ChunkCompatAdapter::downgrade_chunk(
            b"data",
            "f1",
            0,
            "md5",
            None,
            true,
        );
        assert!(result.transformed_fields.contains(&"requires_ai_sanitization".to_string()));
    }

    #[test]
    fn test_upgrade_fills_defaults() {
        let result = ChunkCompatAdapter::upgrade_chunk(
            b"legacy_data",
            "legacy-file",
            0,
            "legacy-md5",
        );
        assert_eq!(result.source_version, ApiVersion::V1);
        assert_eq!(result.target_version, ApiVersion::V2);
        assert_eq!(result.payload.content_type_hint, "application/octet-stream");
        assert!(!result.payload.requires_ai_sanitization);
        assert!(result.payload.metadata.is_empty());
        assert_eq!(result.transformed_fields.len(), 3);
    }

    #[test]
    fn test_adapt_direction_serialization() {
        let d = AdaptDirection::DowngradeV2toV1;
        let json = serde_json::to_string(&d).unwrap();
        let decoded: AdaptDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, AdaptDirection::DowngradeV2toV1);
    }

    #[test]
    fn test_compat_chunk_v1_serialization() {
        let c = CompatChunkV1 {
            data: vec![1, 2, 3],
            file_id: "test".to_string(),
            chunk_index: 42,
            chunk_md5: "hash".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"chunk_index\":42"));
    }
}
