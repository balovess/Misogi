//! Constants and utility functions for PDF content stream validation.
//!
//! This module defines all whitelist/blacklist constants used by the PDF True CDR
//! engine to validate content stream operators, inline image encodings, color spaces,
//! and detect obfuscated operator names.
//!
//! ## Performance Design
//!
//! All operator/encoding lookup tables use **compile-time perfect hashing**
//! (`phf::Set`) for **O(1)** amortized lookup instead of O(n) linear scan.
//! These functions are on the hot path of content stream processing and
//! are called once per operator (thousands of times per document).
//!
//! All items are `pub(super)` — visible only within the parent module and its sub-modules.

use phf::phf_set;

// =============================================================================
// Whitelisted PDF Content Operators
// =============================================================================

/// Compile-time perfect-hashing set of PDF content stream operators that are safe to preserve.
///
/// These operators define text rendering, graphics operations, and color management.
/// Dangerous operators (JavaScript invocation, external links, etc.) are excluded.
///
/// # Performance
///
/// Uses `phf::Set` for **O(1)** amortized lookup via compile-time perfect hash function.
/// Replaces the previous `&[&str]` + `.contains()` pattern which was O(n) per call.
#[cfg(feature = "pdf-cdr")]
pub(super) static SAFE_OPERATORS: phf::Set<&'static str> = phf_set! {
    // Text showing operators
    "Tj", "TJ", "'", "\"",
    // Graphics state operators
    "q", "Q", "cm", "w", "J", "j", "M", "d", "ri", "i", "gs",
    // Color space operators
    "cs", "CS", "sc", "SCN", "scn", "G", "g", "rg", "k", "K",
    // Path construction operators
    "m", "l", "c", "v", "y", "re", "h",
    // Path painting operators
    "S", "s", "f", "f*", "B", "b", "B*", "b*", "n", "W", "W*",
    // XObject invocation (validated separately)
    "Do",
    // Text state operators
    "Tc", "Tw", "Tz", "TL", "Tf", "Tr", "Ts", "Td", "TD", "Tm", "T*",
    // Inline image operators (validated separately)
    "BI", "ID", "EI",
    // Marked content operators (structure tags)
    "BMC", "BDC", "EMC", "MP", "DP",
};

/// Check if a PDF content operator is in the whitelist.
///
/// # Performance
///
/// **O(1)** amortized lookup via `phf::Set::contains()`.
/// Called once per operator in every content stream — must be as fast as possible.
#[cfg(feature = "pdf-cdr")]
#[inline]
pub(super) fn is_safe_operator(operator: &str) -> bool {
    SAFE_OPERATORS.contains(operator)
}

// =============================================================================
// Inline Image Validation Constants
// =============================================================================

/// Compile-time set of allowed inline image encodings considered safe.
///
/// These encodings do not support arbitrary payload hiding and are
/// well-specified for image data transport only.
#[cfg(feature = "pdf-cdr")]
pub(super) static SAFE_INLINE_IMAGE_ENCODINGS: phf::Set<&'static str> = phf_set! {
    "ASCIIHexDecode",   // /AHx — hex-encoded raw bytes
    "ASCII85Decode",    // /A85 — base85-encoded raw bytes
    "DCTDecode",        // /DCT — JPEG compression
    "CCITTFaxDecode",   // /CCF — fax compression
};

/// Short aliases for inline image encodings (as they appear in BI dictionaries).
#[cfg(feature = "pdf-cdr")]
pub(super) static SAFE_INLINE_IMAGE_ENCODING_ALIASES: phf::Set<&'static str> = phf_set! {
    "AHx", "A85", "DCT", "CCF",
};

/// Compile-time set of blocked inline image encodings that can hide steganographic payloads.
///
/// FlateDecode (/Fl) is particularly dangerous because it can compress arbitrary
/// data streams that may contain hidden scripts or payloads.
#[cfg(feature = "pdf-cdr")]
pub(super) static BLOCKED_INLINE_IMAGE_ENCODINGS: phf::Set<&'static str> = phf_set! {
    "FlateDecode",      // /Fl — can hide arbitrary compressed payloads
    "LZWDecode",        // /LZW — deprecated, can be abused
    "RunLengthDecode",  // /RL — can encode arbitrary data
};

/// Check if an inline image encoding is in the safe list.
///
/// # Performance
///
/// **O(1)** amortized dual-set lookup (primary + alias set).
#[cfg(feature = "pdf-cdr")]
#[inline]
pub(super) fn is_safe_inline_image_encoding(encoding: &str) -> bool {
    SAFE_INLINE_IMAGE_ENCODINGS.contains(encoding)
        || SAFE_INLINE_IMAGE_ENCODING_ALIASES.contains(encoding)
}

/// Check if an inline image encoding is blocked.
///
/// # Performance
///
/// **O(1)** amortized lookup via `phf::Set::contains()`.
#[cfg(feature = "pdf-cdr")]
#[inline]
pub(super) fn is_blocked_inline_image_encoding(encoding: &str) -> bool {
    BLOCKED_INLINE_IMAGE_ENCODINGS.contains(encoding)
}

// =============================================================================
// Obfuscated Operator Detection Constants
// =============================================================================

/// Compile-time set of dangerous operator names that attackers might obfuscate using hex encoding.
///
/// PDF specification allows names to use `#HH` hex escape sequences, which
/// can be used to evade simple string-matching detection. This set contains
/// the decoded forms of such dangerous operators.
///
/// # Performance
///
/// Uses `phf::Set` for **O(1)** lookup when checking decoded operator names
/// against known dangerous patterns.
#[cfg(feature = "pdf-cdr")]
pub(super) static DANGEROUS_OBFUSCATED_OPERATORS: phf::Set<&'static str> = phf_set! {
    // JavaScript invocation
    "JS", "JavaScript",
    // Auto-execution triggers
    "OpenAction", "AA",  // Additional Actions
    // Dangerous action types
    "SubmitForm", "Launch", "RichMedia", "EmbeddedFile",
    // URI actions (can exfiltrate data)
    "URI", "GoToR",  // Remote go-to
    // Hidden data vectors
    "AcroForm", "XFA",
};

/// Decode hex-encoded PDF name string (`#HH` patterns → ASCII characters).
///
/// PDF allows name tokens to contain `#HH` escape sequences where HH is
/// a two-digit hexadecimal value representing a byte. This function decodes
/// all such sequences to produce the canonical form.
///
/// # Performance
///
/// **Optimized**: Operates at byte level without allocating intermediate `Vec<char>`
/// or `String` for character collection. Pre-allocates output `String` with capacity
/// hint from input length (worst case: same size; typical case: shorter due to
/// `#HH` → single-byte collapsing).
///
/// Iterates through the byte slice directly, detecting `#` followed by two valid
/// hex digits and decoding them inline. Non-escape bytes are copied verbatim.
///
/// # Arguments
/// * `encoded_name` - The potentially hex-encoded operator/name string.
///
/// # Returns
/// The fully decoded string with all `#HH` sequences replaced by their
/// corresponding ASCII characters. Invalid sequences are preserved as-is.
///
/// # Example
/// ```ignore
/// assert_eq!(decode_hex_encoded_name("#4A#53"), "JS");  // 0x4A='J', 0x53='S'
/// assert_eq!(decode_hex_encoded_name("Tj"), "Tj");       // No encoding
/// ```
pub(super) fn decode_hex_encoded_name(encoded_name: &str) -> String {
    let bytes = encoded_name.as_bytes();
    let mut result = String::with_capacity(encoded_name.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'#' && i.saturating_add(2) < bytes.len() {
            let hi = bytes[i + 1];
            let lo = bytes[i + 2];

            // Fast-path: check ASCII hex digit ranges without char conversion
            let hi_val = match hi {
                b'0'..=b'9' => hi - b'0',
                b'a'..=b'f' => hi - b'a' + 10,
                b'A'..=b'F' => hi - b'A' + 10,
                _ => {
                    result.push(bytes[i] as char);
                    i += 1;
                    continue;
                }
            };

            let lo_val = match lo {
                b'0'..=b'9' => lo - b'0',
                b'a'..=b'f' => lo - b'a' + 10,
                b'A'..=b'F' => lo - b'A' + 10,
                _ => {
                    result.push(bytes[i] as char);
                    i += 1;
                    continue;
                }
            };

            result.push((hi_val << 4 | lo_val) as char);
            i += 3;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    result
}

// =============================================================================
// Color Space Validation Constants
// =============================================================================

/// Compile-time set of allowed color space names for PDF content reconstruction.
///
/// These color spaces are well-defined and do not support embedding
/// arbitrary lookup tables or ICC profiles that could hide payloads.
#[cfg(feature = "pdf-cdr")]
pub(super) static ALLOWED_COLOR_SPACES: phf::Set<&'static str> = phf_set! {
    "DeviceRGB",
    "DeviceCMYK",
    "DeviceGray",
    "CalRGB",
    "CalGRAY",
    "Pattern",
};

/// Compile-time set of color space types requiring additional validation.
///
/// These can embed custom data (ICC profiles, lookup tables, etc.) and
/// need deeper inspection during analysis phase.
#[cfg(feature = "pdf-cdr")]
pub(super) static SUSPICIOUS_COLOR_SPACES: phf::Set<&'static str> = phf_set! {
    "ICCBased",   // Can embed arbitrary ICC profile data
    "Lab",        // CIE-based with range arrays
    "Separation", // Can reference arbitrary tint transform functions
    "DeviceN",    // Multi-channel with custom alternate space
    "Indexed",    // Lookup table that could contain steganographic data
    "I",          // DeviceGray shorthand (allowed, but validate context)
};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Unit Tests for Operator Whitelist
    // =========================================================================

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_safe_operators_contains_text_showing() {
        assert!(is_safe_operator("Tj"));
        assert!(is_safe_operator("TJ"));
        assert!(is_safe_operator("'"));
        assert!(is_safe_operator("\""));
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_safe_operators_contains_graphics_state() {
        assert!(is_safe_operator("q"));
        assert!(is_safe_operator("Q"));
        assert!(is_safe_operator("cm"));
        assert!(is_safe_operator("w"));
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_safe_operators_rejects_dangerous() {
        assert!(!is_safe_operator("JS"));
        assert!(!is_safe_operator("JavaScript"));
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_safe_operators_all_documented() {
        assert!(SAFE_OPERATORS.len() > 40);
    }

    // =========================================================================
    // Enhancement 2: Inline Image Encoding Validation Tests
    // =========================================================================

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_safe_inline_image_encodings() {
        assert!(is_safe_inline_image_encoding("ASCIIHexDecode"));
        assert!(is_safe_inline_image_encoding("AHx"));
        assert!(is_safe_inline_image_encoding("ASCII85Decode"));
        assert!(is_safe_inline_image_encoding("A85"));
        assert!(is_safe_inline_image_encoding("DCTDecode"));
        assert!(is_safe_inline_image_encoding("DCT"));
        assert!(is_safe_inline_image_encoding("CCITTFaxDecode"));
        assert!(is_safe_inline_image_encoding("CCF"));

        assert!(!is_safe_inline_image_encoding("FlateDecode"));
        assert!(!is_safe_inline_image_encoding("LZWDecode"));
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_blocked_inline_image_encodings() {
        assert!(is_blocked_inline_image_encoding("FlateDecode"));
        assert!(is_blocked_inline_image_encoding("LZWDecode"));
        assert!(is_blocked_inline_image_encoding("RunLengthDecode"));

        assert!(!is_blocked_inline_image_encoding("ASCIIHexDecode"));
        assert!(!is_blocked_inline_image_encoding("DCTDecode"));
        assert!(!is_blocked_inline_image_encoding("CCITTFaxDecode"));
    }

    // =========================================================================
    // Enhancement 3: Obfuscated Operator Detection Tests
    // =========================================================================

    #[test]
    fn test_decode_hex_encoded_name_basic() {
        assert_eq!(decode_hex_encoded_name("#4A#53"), "JS");
        assert_eq!(decode_hex_encoded_name("#54#6A"), "Tj");
    }

    #[test]
    fn test_decode_hex_encoded_name_no_encoding() {
        assert_eq!(decode_hex_encoded_name("Tj"), "Tj");
        assert_eq!(decode_hex_encoded_name("q"), "q");
        assert_eq!(decode_hex_encoded_name(""), "");
    }

    #[test]
    fn test_decode_hex_encoded_name_mixed() {
        assert_eq!(
            decode_hex_encoded_name("#4F#70#65#6E#41#63#74#69#6F#6E"),
            "OpenAction"
        );
    }

    #[test]
    fn test_decode_hex_encoded_name_invalid_sequences() {
        assert_eq!(decode_hex_encoded_name("#ZZ"), "#ZZ");
        assert_eq!(decode_hex_encoded_name("#4"), "#4");
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_dangerous_obfuscated_operators_list() {
        assert!(DANGEROUS_OBFUSCATED_OPERATORS.contains("JS"));
        assert!(DANGEROUS_OBFUSCATED_OPERATORS.contains("JavaScript"));
        assert!(DANGEROUS_OBFUSCATED_OPERATORS.contains("OpenAction"));
        assert!(DANGEROUS_OBFUSCATED_OPERATORS.contains("AA"));
        assert!(DANGEROUS_OBFUSCATED_OPERATORS.contains("URI"));
        assert!(DANGEROUS_OBFUSCATED_OPERATORS.contains("AcroForm"));
    }

    // =========================================================================
    // Enhancement 4: Color Space Validation Tests
    // =========================================================================

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_allowed_color_spaces() {
        assert!(ALLOWED_COLOR_SPACES.contains("DeviceRGB"));
        assert!(ALLOWED_COLOR_SPACES.contains("DeviceCMYK"));
        assert!(ALLOWED_COLOR_SPACES.contains("DeviceGray"));
        assert!(ALLOWED_COLOR_SPACES.contains("CalRGB"));
        assert!(ALLOWED_COLOR_SPACES.contains("CalGRAY"));
        assert!(ALLOWED_COLOR_SPACES.contains("Pattern"));
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_suspicious_color_spaces() {
        assert!(SUSPICIOUS_COLOR_SPACES.contains("ICCBased"));
        assert!(SUSPICIOUS_COLOR_SPACES.contains("Lab"));
        assert!(SUSPICIOUS_COLOR_SPACES.contains("Separation"));
        assert!(SUSPICIOUS_COLOR_SPACES.contains("DeviceN"));
        assert!(SUSPICIOUS_COLOR_SPACES.contains("Indexed"));
    }

    #[test]
    #[cfg(feature = "pdf-cdr")]
    fn test_allowed_and_suspicious_are_disjoint() {
        for allowed in ALLOWED_COLOR_SPACES.iter() {
            assert!(
                !SUSPICIOUS_COLOR_SPACES.contains(*allowed),
                "Color space '{}' is in both allowed and suspicious lists — logic error",
                allowed
            );
        }
    }
}
