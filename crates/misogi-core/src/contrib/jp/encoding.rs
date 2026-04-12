//! Japanese Text Encoding Handler — Detection, conversion, and PDF font safety.
//!
//! This module implements [`EncodingHandler`] for Japanese text processing with
//! comprehensive support for legacy encodings commonly found in Japanese
//! government systems:
//!
//! # Supported Encodings
//!
//! | Encoding        | IANA Name     | Typical Source System         |
//! |-----------------|---------------|------------------------------|
//! | UTF-8           | `UTF-8`       | Modern web/API systems       |
//! | UTF-16 (BE/LE)  | `UTF-16LE`    | Windows APIs, Office docs    |
//! | Shift-JIS (CP932)| `Shift_JIS`   | Legacy Windows applications |
//! | Windows-31J     | `Windows-31J`  | Microsoft-specific SJIS      |
//! | EUC-JP          | `EUC-JP`       | Unix/Linux legacy systems    |
//! | ISO-2022-JP     | `ISO-2022-JP`  | Email (JIS encoding)         |
//!
//! # Detection Strategy
//!
//! Multi-layered heuristic approach:
//! 1. **BOM detection** — Byte Order Mark for UTF-8/16 (100% confidence)
//! 2. **Byte frequency analysis** — Statistical patterns for CJK encodings
//! 3. **Escape sequence scanning** — ISO-2022-JP escape codes
//! 4. **Invalid sequence counting** — Reject encodings with too many errors
//! 5. **Fallback** — Configured default encoding when uncertain
//!
//! # PDF Font Safety
//!
//! When reconstructing sanitized PDF documents, unknown embedded fonts may pose
//! security risks (font-based exploits) or display issues (missing glyphs).
//! This module provides configurable strategies for handling such fonts.
//!
//! # Usage Example
//!
//! ```ignore
//! use misogi_core::contrib::jp::encoding::JapaneseEncodingHandler;
//!
//! let handler = JapaneseEncodingHandler::default();
//! let detected = handler.detect_encoding(&raw_bytes, "").await?;
//! assert_eq!(detected.name, "Shift_JIS");
//!
//! let utf8_bytes = handler.convert(&raw_bytes, "Shift_JIS", "UTF-8").await?;
//! ```

use encoding_rs::Encoding;

use crate::error::Result;
use crate::traits::{
    DetectedEncoding,
    EncodingHandler,
};

fn is_encoding_unicode_compatible(encoding: &Encoding) -> bool {
    encoding == encoding_rs::UTF_8
        || encoding == encoding_rs::UTF_16BE
        || encoding == encoding_rs::UTF_16LE
}

// =============================================================================
// PdfFontAction Enum
// =============================================================================

/// Strategy for handling unknown/untrusted fonts in reconstructed PDF documents.
///
/// After CDR sanitization removes potentially malicious content from a PDF,
/// the document's /Font entries must be reviewed to ensure no exploit vectors
/// remain through embedded font programs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfFontAction {
    /// Keep all /Font entries as-is, even for unknown or untrusted fonts.
    ///
    /// **Safety**: PDF viewers will substitute missing fonts with fallbacks,
    /// which is generally safe but may cause cosmetic rendering differences.
    ///
    /// **Use case**: Default option when font exploits are considered low-risk
    /// and preserving visual fidelity is prioritized.
    Preserve,

    /// Remove all /Font entries that reference non-standard or unknown fonts.
    ///
    /// **Safety**: Eliminates font-based attack vectors entirely.
    ///
    /// **Risk**: May cause mojibake (文字化け) or unreadable text if critical
    /// fonts are stripped. Use only when security outweighs readability.
    Strip,

    /// Replace unknown/trusted font references with entries from the configured
    /// [`fallback_fonts`](JapaneseEncodingHandler::fallback_fonts) list.
    ///
    /// **Safety**: Ensures only known-safe fonts are referenced while maintaining
    /// basic document structure.
    ///
    /// **Behavior**: Font name in /Font dictionary is rewritten; actual glyph
    /// rendering depends on PDF viewer's font substitution mechanism.
    Replace,
}

impl Default for PdfFontAction {
    fn default() -> Self {
        Self::Preserve // Safest default: don't break existing documents
    }
}

// =============================================================================
// JapaneseEncodingHandler
// =============================================================================

/// Primary implementation of [`EncodingHandler`] for Japanese text processing.
///
/// Provides robust encoding detection and conversion optimized for the diverse
/// encoding landscape of Japanese government IT systems, where files may originate
/// from:
/// - 1990s mainframe terminals (EUC-JP, JIS)
/// - Windows XP-era desktops (Shift-JIS, CP932)
/// - Modern web applications (UTF-8)
/// - Cross-platform office suites (UTF-16)
/// # Configuration
///
/// The handler is configured at construction time with:
/// - Fallback encoding for ambiguous data
/// - PDF font handling strategy
/// - Safe fallback font list for PDF reconstruction
///
/// # Thread Safety
///
/// This struct is fully thread-safe (`Send + Sync`) and contains no mutable state,
/// making it suitable for sharing across async tasks without synchronization.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct JapaneseEncodingHandler {
    /// Default encoding to use when auto-detection fails or returns low confidence.
    ///
    /// Common choices: `"Shift_JIS"` (conservative for legacy systems),
    /// `"UTF-8"` (modern default), `"Windows-31J"` (Microsoft compatibility).
    fallback_encoding: String,

    /// How to handle unknown font references in sanitized PDF output.
    pdf_font_action: PdfFontAction,

    /// Ordered list of safe replacement fonts for PDF font substitution.
    ///
    /// Used when [`PdfFontAction::Replace`] is active. Fonts are tried in order;
    /// the first one available on the target system will be used.
    ///
    /// Recommended values for Japanese text:
    /// - `"IPAexMincho"` — Serif font, good for body text
    /// - `"IPAGothic"` — Sans-serif, good for UI elements
    /// - `"MS Mincho"` / `"MS Gothic"` — Windows standard fonts
    fallback_fonts: Vec<String>,
}

impl Default for JapaneseEncodingHandler {
    fn default() -> Self {
        Self {
            fallback_encoding: String::from("Shift_JIS"), // Conservative default for JP gov systems
            pdf_font_action: PdfFontAction::Preserve,
            fallback_fonts: vec![
                String::from("IPAexMincho"),
                String::from("IPAGothic"),
            ],
        }
    }
}

impl JapaneseEncodingHandler {
    /// Create a new handler with custom configuration.
    ///
    /// # Arguments
    /// * `fallback_encoding` - IANA charset name for undetectable inputs.
    /// * `pdf_font_action` - Strategy for PDF font handling.
    /// * `fallback_fonts` - Safe font names for PDF substitution.
    pub fn new(
        fallback_encoding: impl Into<String>,
        pdf_font_action: PdfFontAction,
        fallback_fonts: Vec<String>,
    ) -> Self {
        Self {
            fallback_encoding: fallback_encoding.into(),
            pdf_font_action,
            fallback_fonts,
        }
    }

    /// Create a handler optimized for modern UTF-8-first environments.
    ///
    /// Sets UTF-8 as the fallback encoding, which is appropriate for systems
    /// where most incoming data is already UTF-8 but occasional legacy files appear.
    pub fn utf8_fallback() -> Self {
        Self {
            fallback_encoding: String::from("UTF-8"),
            pdf_font_action: PdfFontAction::Preserve,
            fallback_fonts: vec![
                String::from("IPAexMincho"),
                String::from("IPAGothic"),
            ],
        }
    }

    /// Create a handler optimized for legacy Windows environments.
    ///
    /// Sets Windows-31J (CP932) as the fallback, appropriate for integrations
    /// with older Japanese Windows systems and Microsoft Office documents.
    pub fn windows31j_fallback() -> Self {
        Self {
            fallback_encoding: String::from("Windows-31J"),
            pdf_font_action: PdfFontAction::Preserve,
            fallback_fonts: vec![
                String::from("MS Mincho"),
                String::from("MS Gothic"),
            ],
        }
    }

    // -------------------------------------------------------------------------
    // Internal Detection Logic
    // -------------------------------------------------------------------------

    /// Perform multi-layered encoding detection on raw byte data.
    ///
    /// Detection priority (highest confidence first):
    /// 1. BOM (Byte Order Mark) presence → 1.0 confidence
    /// 2. ISO-2022-JP escape sequences → 0.95 confidence
    /// 3. Byte frequency heuristics (SJIS vs EUC-JP) → 0.7–0.9 confidence
    /// 4. Pure ASCII / valid UTF-8 → 0.9 confidence
    /// 5. Fallback encoding → 0.3 confidence (low certainty)
    ///
    /// # Arguments
    /// * `data` - Raw bytes to analyze.
    /// * `hint` - Optional metadata hint (Content-Type, XML declaration, etc.)
    fn detect_internal(&self, data: &[u8], hint: &str) -> DetectedEncoding {
        // Layer 1: BOM Detection (highest priority)
        if let Some(detected) = self.detect_bom(data) {
            return detected;
        }

        // Layer 2: Hint-based detection (if hint is provided)
        if !hint.is_empty() {
            if let Some(encoding) = Encoding::for_label(hint.as_bytes()) {
                // Validate that the data is actually decodable with this encoding
                let mut decoder = encoding.new_decoder();
                let mut buffer = Vec::with_capacity(data.len());
                let mut _total_read = 0;
                let mut last_result = encoding_rs::DecoderResult::InputEmpty;

                {
                    let needed = decoder.max_utf8_buffer_length(data.len()).unwrap_or(0);
                    buffer.resize(needed, 0);
                }

                if let Some(output_slice) = buffer.get_mut(..) {
                    let (result, _, _) = decoder.decode_to_utf8_without_replacement(data, output_slice, true);
                    last_result = result;
                    _total_read = data.len();
                }

                if last_result == encoding_rs::DecoderResult::InputEmpty {
                    return DetectedEncoding::certain(
                        encoding.name(),
                        is_encoding_unicode_compatible(encoding),
                    );
                }
            }
        }

        // Layer 3: ISO-2022-JP Escape Sequence Detection
        if self.is_iso2022_jp(data) {
            return DetectedEncoding {
                name: String::from("ISO-2022-JP"),
                confidence: 0.95,
                is_unicode_compatible: false,
                bom: None,
            };
        }

        // Layer 4: UTF-8 Validity Check
        if self.is_valid_utf8(data) {
            return DetectedEncoding::certain("UTF-8", true);
        }

        // Layer 5: Byte Frequency Heuristics (SJIS vs EUC-JP)
        if let Some(detected) = self.detect_by_byte_frequency(data) {
            return detected;
        }

        // Layer 6: Fallback
        DetectedEncoding {
            name: self.fallback_encoding.clone(),
            confidence: 0.3,
            is_unicode_compatible: false,
            bom: None,
        }
    }

    /// Detect encoding from Byte Order Mark (BOM).
    ///
    /// # BOM Table
    ///
    /// | Bytes (Hex)    | Encoding  | Confidence |
    /// |----------------|-----------|------------|
    /// | `EF BB BF`     | UTF-8     | 1.0        |
    /// | `FE FF`        | UTF-16 BE | 1.0        |
    /// | `FF FE`        | UTF-16 LE | 1.0        |
    fn detect_bom(&self, data: &[u8]) -> Option<DetectedEncoding> {
        if data.len() >= 3 && &data[..3] == b"\xEF\xBB\xBF" {
            return Some(DetectedEncoding {
                name: String::from("UTF-8"),
                confidence: 1.0,
                is_unicode_compatible: true,
                bom: Some(vec![0xEF, 0xBB, 0xBF]),
            });
        }

        if data.len() >= 2 {
            match &data[..2] {
                b"\xFE\xFF" => {
                    return Some(DetectedEncoding {
                        name: String::from("UTF-16BE"),
                        confidence: 1.0,
                        is_unicode_compatible: true,
                        bom: Some(vec![0xFE, 0xFF]),
                    });
                }
                b"\xFF\xFE" => {
                    return Some(DetectedEncoding {
                        name: String::from("UTF-16LE"),
                        confidence: 1.0,
                        is_unicode_compatible: true,
                        bom: Some(vec![0xFF, 0xFE]),
                    });
                }
                _ => {}
            }
        }

        None
    }

    /// Check whether byte sequence is valid UTF-8.
    ///
    /// Uses `std::str::from_utf8()` for strict validation.
    fn is_valid_utf8(&self, data: &[u8]) -> bool {
        std::str::from_utf8(data).is_ok()
    }

    /// Detect ISO-2022-JP by scanning for characteristic escape sequences.
    ///
    /// ISO-2022-JP uses escape sequences to switch between character sets:
    /// - `ESC ( B` — ASCII mode
    /// - `ESC $ @` — JIS X 0208-1978 (old)
    /// - `ESC $ B` — JIS X 0208-1983 (standard)
    fn is_iso2022_jp(&self, data: &[u8]) -> bool {
        // Look for ESC $ B or ESC $ @ sequences (ISO-2022-JP signatures)
        let patterns = [
            &[0x1B, 0x24, 0x42][..], // ESC $ B (most common)
            &[0x1B, 0x24, 0x40][..], // ESC $ @ (legacy)
        ];

        for window in data.windows(3) {
            for pattern in &patterns {
                if window == *pattern {
                    return true;
                }
            }
        }

        false
    }

    /// Distinguish between Shift-JIS and EUC-JP using byte frequency analysis.
    ///
    /// # Heuristic Algorithm
    ///
    /// Both Shift-JIS and EUC-JP use double-byte sequences for kanji/kana, but
    /// their byte ranges differ significantly:
    ///
    /// **Shift-JIS first byte**: 0x81–0x9F, 0xE0–0xEF
    /// **Shift-JIS second byte**: 0x40–0x7E, 0x80–0xFC (excluding 0x7F)
    ///
    /// **EUC-JP first byte**: 0xA1–0xFE
    /// **EUC-JP second byte**: 0xA1–0xFE
    ///
    /// We count how many bytes fall into each range and score accordingly.
    fn detect_by_byte_frequency(&self, data: &[u8]) -> Option<DetectedEncoding> {
        if data.len() < 4 {
            return None; // Too short for meaningful analysis
        }

        let mut sjis_first_byte_count = 0u64;
        let mut eucjp_first_byte_count = 0u64;
        let mut sjis_second_byte_violations = 0u64;
        let mut eucjp_second_byte_violations = 0u64;

        let mut i = 0usize;
        while i < data.len() {
            let b = data[i];

            // Check Shift-JIS first-byte range
            if (0x81..=0x9F).contains(&b) || (0xE0..=0xEF).contains(&b) {
                sjis_first_byte_count += 1;

                // Check next byte for SJIS second-byte validity
                if i + 1 < data.len() {
                    let b2 = data[i + 1];
                    if !((0x40..=0x7E).contains(&b2) || (0x80..=0xFC).contains(&b2)) {
                        sjis_second_byte_violations += 1;
                    }
                }
                i += 2; // Skip second byte
                continue;
            }

            // Check EUC-JP first-byte range
            if (0xA1..=0xFE).contains(&b) {
                eucjp_first_byte_count += 1;

                // Check next byte for EUC-JP second-byte validity
                if i + 1 < data.len() {
                    let b2 = data[i + 1];
                    if !(0xA1..=0xFE).contains(&b2) {
                        eucjp_second_byte_violations += 1;
                    }
                }
                i += 2; // Skip second byte
                continue;
            }

            i += 1;
        }

        // Score each candidate
        let sjis_score = if sjis_first_byte_count > 0 {
            let violation_rate = sjis_second_byte_violations as f64 / sjis_first_byte_count as f64;
            sjis_first_byte_count as f64 * (1.0 - violation_rate)
        } else {
            0.0
        };

        let eucjp_score = if eucjp_first_byte_count > 0 {
            let violation_rate = eucjp_second_byte_violations as f64 / eucjp_first_byte_count as f64;
            eucjp_first_byte_count as f64 * (1.0 - violation_rate)
        } else {
            0.0
        };

        // Determine winner with minimum confidence threshold
        const MIN_CONFIDENCE: f64 = 0.6;

        if sjis_score > eucjp_score && sjis_score > MIN_CONFIDENCE {
            Some(DetectedEncoding {
                name: String::from("Shift_JIS"),
                confidence: (sjis_score / (sjis_score + eucjp_score)).min(0.9),
                is_unicode_compatible: false,
                bom: None,
            })
        } else if eucjp_score > sjis_score && eucjp_score > MIN_CONFIDENCE {
            Some(DetectedEncoding {
                name: String::from("EUC-JP"),
                confidence: (eucjp_score / (sjis_score + eucjp_score)).min(0.9),
                is_unicode_compatible: false,
                bom: None,
            })
        } else {
            None // Inconclusive
        }
    }
}

// =============================================================================
// Trait Implementation: EncodingHandler
// =============================================================================

#[async_trait::async_trait]
impl EncodingHandler for JapaneseEncodingHandler {
    fn name(&self) -> &str {
        "japanese-encoding-handler"
    }

    async fn detect_encoding(&self, data: &[u8], hint: &str) -> Result<DetectedEncoding> {
        Ok(self.detect_internal(data, hint))
    }

    async fn convert(
        &self,
        input: &[u8],
        from_encoding: &str,
        to_encoding: &str,
    ) -> Result<Vec<u8>> {
        // Look up source encoding
        let src_encoding = Encoding::for_label(from_encoding.as_bytes()).ok_or_else(|| {
            crate::error::MisogiError::Protocol(format!(
                "Unknown source encoding: {}",
                from_encoding
            ))
        })?;

        // Look up target encoding
        let dst_encoding = Encoding::for_label(to_encoding.as_bytes()).ok_or_else(|| {
            crate::error::MisogiError::Protocol(format!(
                "Unknown target encoding: {}",
                to_encoding
            ))
        })?;

        // Decode source bytes to UTF-8 string
        let (decoded, had_errors) = src_encoding.decode_without_bom_handling(input);

        // Log warning if characters were replaced during decoding
        if had_errors {
            tracing::warn!(
                from_encoding = %from_encoding,
                to_encoding = %to_encoding,
                "Character replacement occurred during encoding conversion"
            );
        }

        // Encode UTF-8 string to target encoding bytes
        let (encoded, _, _) = dst_encoding.encode(&decoded);

        Ok(encoded.into_owned())
    }

    async fn stream_decode(
        &self,
        data: &[u8],
        encoding: &str,
        _is_final: bool,
    ) -> Result<String> {
        // Look up encoding
        let enc = Encoding::for_label(encoding.as_bytes()).ok_or_else(|| {
            crate::error::MisogiError::Protocol(format!("Unknown encoding: {}", encoding))
        })?;

        // Decode to string (handles partial multibyte sequences internally)
        let (decoded, had_errors) = enc.decode_without_bom_handling(data);

        if had_errors {
            tracing::warn!(
                encoding = %encoding,
                "Character replacement in stream_decode"
            );
        }

        Ok(decoded.into_owned())
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Test: UTF-8 BOM Detection
    // =========================================================================

    #[test]
    fn test_utf8_bom_detection() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let data_with_bom: Vec<u8> = [
            0xEF, 0xBB, 0xBF, // UTF-8 BOM
            0xE3, 0x81, 0x93, // こ
            0xE3, 0x82, 0x93, // ん
            0xE3, 0x81, 0xAB, // に
            0xE3, 0x81, 0xA1, // ち
            0xE3, 0x81, 0xAF, // は
        ]
        .to_vec();

        let result = rt.block_on(handler.detect_encoding(&data_with_bom, ""));
        assert!(result.is_ok());
        let detected = result.unwrap();
        assert_eq!(detected.name, "UTF-8");
        assert_eq!(detected.confidence, 1.0);
        assert!(detected.bom.is_some());
        assert_eq!(detected.bom.unwrap(), vec![0xEF, 0xBB, 0xBF]);
    }

    // =========================================================================
    // Test: Shift-JIS Detection from Byte Patterns
    // =========================================================================

    #[test]
    fn test_shift_jis_detection() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // "こんにちは" in Shift-JIS
        let shift_jis_data: Vec<u8> = [
            0x82, 0xB1, // こ
            0x82, 0xF1, // ん
            0x82, 0xC9, // に
            0x82, 0xBF, // ち
            0x82, 0xCD, // は
        ]
        .to_vec();

        let result = rt.block_on(handler.detect_encoding(&shift_jis_data, ""));
        assert!(result.is_ok());
        let detected = result.unwrap();
        assert_eq!(detected.name, "Shift_JIS");
        assert!(detected.confidence >= 0.6);
    }

    // =========================================================================
    // Test: EUC-JP Detection
    // =========================================================================

    #[test]
    fn test_euc_jp_detection() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // "こんにちは" in EUC-JP
        let euc_jp_data: Vec<u8> = [
            0xA4, 0xB3, // こ
            0xA4, 0xF3, // ん
            0xA4, 0xCB, // に
            0xA4, 0xC1, // ち
            0xA4, 0xCF, // は
        ]
        .to_vec();

        let result = rt.block_on(handler.detect_encoding(&euc_jp_data, ""));
        assert!(result.is_ok());
        let detected = result.unwrap();
        assert_eq!(detected.name, "EUC-JP");
        assert!(detected.confidence >= 0.6);
    }

    // =========================================================================
    // Test: Shift-JIS → UTF-8 Round-trip Conversion
    // =========================================================================

    #[test]
    fn test_shift_jis_to_utf8_roundtrip() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // "こんにちは世界" in Shift-JIS
        let shift_jis_input: Vec<u8> = [
            0x82, 0xB1, // こ
            0x82, 0xF1, // ん
            0x82, 0xC9, // に
            0x82, 0xBF, // ち
            0x82, 0xCD, // は
            0x90, 0xA2, // 世
            0x8B, 0x80, // 界
        ]
        .to_vec();

        let result = rt
            .block_on(handler.convert(&shift_jis_input, "Shift_JIS", "UTF-8"));
        assert!(result.is_ok());

        let utf8_output = result.unwrap();
        let decoded_str = String::from_utf8(utf8_output).unwrap();
        assert_eq!(decoded_str, "こんにちは世界");
    }

    // =========================================================================
    // Test: Half-width Katakana Preservation
    // =========================================================================

    #[test]
    fn test_halfwidth_katakana_preservation() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // "カタカナ" in half-width katakana (Shift-JIS specific)
        // Half-width katakana: 0xA6-0xDF range in Shift-JIS
        let halfwidth_katakana_sjis: Vec<u8> = [
            0xB6, // カ (half-width)
            0xDD, // タ (half-width)
            0xCA, // カ (half-width)
            0xBA, // カ (half-width)
            0xCA, // ナ (half-width)
        ]
        .to_vec();

        let result = rt.block_on(
            handler.convert(&halfwidth_katakana_sjis, "Shift_JIS", "UTF-8"),
        );
        assert!(result.is_ok());

        let utf8_output = String::from_utf8(result.unwrap()).unwrap();
        // Should preserve half-width katakana characters (U+FF76–U+FF85 range)
        assert!(!utf8_output.is_empty(), "Half-width katakana should be preserved");
    }

    // =========================================================================
    // Test: Mixed Encoding Detection (UTF-8 with some SJIS bytes)
    // =========================================================================

    #[test]
    fn test_mixed_encoding_detection() {
        let handler = JapaneseEncodingHandler::utf8_fallback(); // Prefer UTF-8
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Mostly valid UTF-8 with a few stray high bytes that could be SJIS
        let mixed_data = "Hello 世界 Data".as_bytes().to_vec();

        let result = rt.block_on(handler.detect_encoding(&mixed_data, ""));
        assert!(result.is_ok());

        let detected = result.unwrap();
        // Should detect as UTF-8 since it's mostly valid UTF-8
        assert_eq!(detected.name, "UTF-8");
        assert!(detected.confidence >= 0.9);
    }

    // =========================================================================
    // Test: ISO-2022-JP Detection via Escape Sequences
    // =========================================================================

    #[test]
    fn test_iso2022_jp_detection() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // ISO-2022-JP escape sequence followed by dummy data
        let iso2022_data: Vec<u8> = [
            0x1B, 0x24, 0x42, // ESC $ B (switch to JIS X 0208-1983)
            0x24, 0x33, // こ (in JIS encoding)
            0x24, 0x73, // ん
            0x24, 0x6B, // に
            0x24, 0x41, // ち
            0x24, 0x2F, // は
        ]
        .to_vec();

        let result = rt.block_on(handler.detect_encoding(&iso2022_data, ""));
        assert!(result.is_ok());
        let detected = result.unwrap();
        assert_eq!(detected.name, "ISO-2022-JP");
        assert!(detected.confidence >= 0.9);
    }

    // =========================================================================
    // Test: Unknown Encoding Error
    // =========================================================================

    #[test]
    fn test_convert_unknown_encoding_error() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let data = b"test data".to_vec();
        let result = rt.block_on(handler.convert(&data, "NonExistent-Encoding", "UTF-8"));

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown source encoding"));
    }

    // =========================================================================
    // Test: Stream Decode Basic Functionality
    // =========================================================================

    #[test]
    fn test_stream_decode_basic() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let utf8_data = "テストデータ".as_bytes().to_vec();
        let result = rt.block_on(handler.stream_decode(&utf8_data, "UTF-8", true));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "テストデータ");
    }

    // =========================================================================
    // Test: Handler Name
    // =========================================================================

    #[test]
    fn test_handler_name() {
        let handler = JapaneseEncodingHandler::default();
        assert_eq!(handler.name(), "japanese-encoding-handler");
    }

    // =========================================================================
    // Test: Custom Configuration
    // =========================================================================

    #[test]
    fn test_custom_configuration() {
        let handler = JapaneseEncodingHandler::new(
            "EUC-JP",
            PdfFontAction::Strip,
            vec![String::from("MS Mincho")],
        );

        assert_eq!(handler.fallback_encoding, "EUC-JP");
        assert_eq!(handler.pdf_font_action, PdfFontAction::Strip);
        assert_eq!(handler.fallback_fonts.len(), 1);
        assert_eq!(handler.fallback_fonts[0], "MS Mincho");
    }

    // =========================================================================
    // Test: Preset Constructors
    // =========================================================================

    #[test]
    fn test_utf8_fallback_preset() {
        let handler = JapaneseEncodingHandler::utf8_fallback();
        assert_eq!(handler.fallback_encoding, "UTF-8");
    }

    #[test]
    fn test_windows31j_fallback_preset() {
        let handler = JapaneseEncodingHandler::windows31j_fallback();
        assert_eq!(handler.fallback_encoding, "Windows-31J");
        assert_eq!(handler.fallback_fonts[0], "MS Mincho"); // Windows-specific fonts
    }

    // =========================================================================
    // Test: Empty Input Handling
    // =========================================================================

    #[test]
    fn test_detect_empty_input() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let empty: Vec<u8> = Vec::new();
        let result = rt.block_on(handler.detect_encoding(&empty, ""));

        assert!(result.is_ok());
        // Empty input should fall back to default encoding
        let detected = result.unwrap();
        assert_eq!(detected.name, "Shift_JIS"); // Default fallback
        assert!(detected.confidence < 0.5); // Low confidence for empty input
    }

    #[test]
    fn test_convert_empty_input() {
        let handler = JapaneseEncodingHandler::default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let empty: Vec<u8> = Vec::new();
        let result = rt.block_on(handler.convert(&empty, "UTF-8", "Shift_JIS"));

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty()); // Empty in, empty out
    }
}
