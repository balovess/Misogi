use serde::{Deserialize, Serialize};

/// Three-tier sanitization policy matching MIC (Ministry of Internal Affairs and Communications)
/// guidelines for Japanese government agencies.
///
/// ## Policy Hierarchy (strictest to most permissive)
/// 1. **ConvertToFlat**: Maximum security - destroys ALL embedded logic, converts to flat representation
/// 2. **StripActiveContent**: Balanced - removes JS/VBA/macros while preserving editability (VOTIRO-compatible mode)
/// 3. **TextOnly**: Minimal - extracts plain text only, discards all formatting and structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SanitizationPolicy {
    /// Strip active content (JavaScript, VBA macros, embedded scripts) while preserving document editability.
    /// This is the default mode compatible with VOTIRO's standard behavior.
    StripActiveContent,

    /// Convert document to flat/read-only format, destroying all interactive elements including:
    /// form fields, annotations, hyperlinks, bookmarks, and embedded fonts.
    ConvertToFlat,

    /// Extract text content only, discarding all formatting, images, tables, and layout information.
    TextOnly,
}

impl Default for SanitizationPolicy {
    fn default() -> Self {
        Self::StripActiveContent
    }
}
