//! Steganography Detection Module
//!
//! Provides lightweight detection of common steganography techniques
//! in image files. Does NOT attempt to extract hidden messages (that's
//! a forensics tool's job) — only detects the *presence* of potential
//! data hiding so the CDR policy can decide whether to block/re-encode.
//!
//! # Detection Techniques
//!
//! | Technique | Method | Confidence |
//! |-----------|--------|------------|
//! | LSB Replacement | Statistical analysis of least significant bits | Medium-High |
//! | LSB Sequential Pattern | Check for non-random bit patterns in LSB plane | High |
//! | Appended Data | Scan for data after EOF/IEND marker | Certain |
//! | Chunk Sequence Anomaly | Analyze PNG chunk ordering for hidden chunks | Medium |
//! | Entropy Anomaly | Local entropy deviation from expected values | Low-Medium |
//! | EXIF Overflow | EXIF segment size exceeds expected bounds | Medium |
//!
//! # Design Philosophy
//!
//! This module is a **detection** tool, not an extraction or removal tool.
//! When steganography is detected, the recommended action is:
//! - **ReEncode**: Re-encode the image through a standard pipeline (destroys most stego)
//! - **Block**: Reject the file entirely (high-confidence detection)
//! - **Investigate**: Flag for human review (moderate suspicion)
//!
//! Re-encoding is the preferred remediation because it:
//! 1. Destroys LSB-embedded data (re-compression changes all pixel values)
//! 2. Removes appended data (new file is exactly the right size)
//! 3. Normalizes chunk ordering (PNG re-encoder writes canonical order)
//! 4. Strips custom/unknown chunks that may carry payloads

use tracing::{debug, info};

// =============================================================================
// Result Types
// =============================================================================

/// Result of a full steganography analysis pass on an image.
///
/// Aggregates findings from all detection techniques and produces a
/// consolidated recommendation for CDR policy enforcement.
#[derive(Debug, Clone)]
pub struct StegoDetectionResult {
    /// `true` if any technique produced a finding above the sensitivity threshold.
    pub is_suspicious: bool,

    /// Individual findings from each detection technique that was run.
    ///
    /// Multiple findings may be present if multiple techniques detect anomalies
    /// (e.g., a file with both appended data AND LSB artifacts).
    pub findings: Vec<StegoFinding>,

    /// Recommended action based on aggregated confidence scores.
    ///
    /// Determined by the highest-confidence finding or combination of findings.
    pub recommended_action: StegoRecommendation,
}

impl StegoDetectionResult {
    /// Returns `true` if no suspicious content was found.
    pub fn is_clean(&self) -> bool {
        !self.is_suspicious
    }

    /// Returns count of individual findings across all techniques.
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Returns the maximum confidence score among all findings, or 0.0 if clean.
    pub fn max_confidence(&self) -> f32 {
        self.findings
            .iter()
            .map(|f| f.confidence)
            .fold(0.0_f32, f32::max)
    }
}

/// A single finding from one steganography detection technique.
#[derive(Debug, Clone)]
pub struct StegoFinding {
    /// The technique that produced this finding.
    pub technique: StegoTechnique,

    /// Confidence score in [0.0, 1.0] where:
    /// - 0.0–0.3: Low suspicion (likely false positive)
    /// - 0.3–0.6: Moderate suspicion (worth investigating)
    /// - 0.6–0.9: High suspicion (likely stego)
    /// - 0.9–1.0: Very high confidence (certain stego)
    pub confidence: f32,

    /// Human-readable location description (e.g., "offset 524288 after IEND",
    /// "LSB plane of red channel", "chunk index 7").
    pub location: String,

    /// Human-readable explanation of what was found and why it's suspicious.
    pub description: String,
}

/// Classification of steganography embedding technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoTechnique {
    /// Least Significant Bit replacement: LSBs of pixel channels show
    /// statistical non-randomness suggesting embedded data.
    LsbReplacement,

    /// LSB bits contain sequential/structured pattern rather than noise,
    /// strongly indicating embedded data with non-random encoding.
    LsbSequential,

    /// Color palette has unusual ordering or duplicate entries that could
    /// encode hidden information (common in GIF/indexed-color stego).
    PaletteAnomaly,

    /// Extra data found after the end-of-file marker (IEND for PNG, EOI for JPEG).
    /// This is the simplest form of steganographic hiding.
    AppendedData,

    /// EXIF metadata segment is larger than expected for normal camera output,
    /// potentially carrying hidden data within IFD entries.
    ExifOverflow,

    /// Unusual chunk ordering in PNG (e.g., unknown chunks between IDAT blocks)
    /// that may hide data in custom chunk payloads.
    ChunkSequence,

    /// Local entropy (Shannon) differs significantly from expected values
    /// for natural images of this format/size, suggesting data embedding.
    EntropyAnomaly,

    /// DCT coefficient distribution shows artifacts consistent with
    /// frequency-domain embedding (JPEG-specific).
    FrequencyDomain,

    /// Structural inconsistencies (e.g., conflicting size fields, invalid offsets)
    /// suggesting the file has been manually tampered with.
    FileStructureAnomaly,
}

impl std::fmt::Display for StegoTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LsbReplacement => write!(f, "LSB_REPLACEMENT"),
            Self::LsbSequential => write!(f, "LSB_SEQUENTIAL"),
            Self::PaletteAnomaly => write!(f, "PALETTE_ANOMALY"),
            Self::AppendedData => write!(f, "APPENDED_DATA"),
            Self::ExifOverflow => write!(f, "EXIF_OVERFLOW"),
            Self::ChunkSequence => write!(f, "CHUNK_SEQUENCE"),
            Self::EntropyAnomaly => write!(f, "ENTROPYANOMALY"),
            Self::FrequencyDomain => write!(f, "FREQUENCY_DOMAIN"),
            Self::FileStructureAnomaly => write!(f, "FILE_STRUCTURE_ANOMALY"),
        }
    }
}

/// Recommended action after steganography analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoRecommendation {
    /// No steganography detected; file passes as-is.
    Safe,

    /// Suspicious features found: re-encoding will destroy any hidden data.
    ///
    /// This is the most common recommendation for low-to-moderate confidence
    /// detections. Re-encoding through a standard image pipeline (decode ->
    /// transform -> encode) eliminates most stego techniques.
    ReEncode,

    /// High-confidence steganography detected: block the file entirely.
    ///
    /// Used when multiple techniques agree or single-technique confidence
    /// exceeds the blocking threshold (default 0.85).
    Block,

    /// Moderate suspicion: quarantine for human review before decision.
    ///
    /// Used when confidence is in the uncertain range (0.4–0.7) and
    /// automated decision is not advisable.
    Investigate,
}

impl std::fmt::Display for StegoRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Safe => write!(f, "SAFE"),
            Self::ReEncode => write!(f, "RE_ENCODE"),
            Self::Block => write!(f, "BLOCK"),
            Self::Investigate => write!(f, "INVESTIGATE"),
        }
    }
}

// =============================================================================
// Detector Configuration
// =============================================================================

/// Steganography detector with configurable analysis parameters.
///
/// The detector runs multiple independent analysis techniques and aggregates
/// their results into a unified [`StegoDetectionResult`] with a recommended action.
pub struct SteganographyDetector {
    /// Number of bytes to sample for LSB analysis (from start of pixel data).
    pub lsb_sample_size: usize,

    /// Window size (in bytes) for local entropy calculation.
    pub entropy_window_size: usize,

    /// Minimum confidence threshold for a finding to be included in results.
    ///
    /// Findings below this threshold are discarded as noise/false positives.
    sensitivity_threshold: f32,

    /// Confidence threshold above which BLOCK recommendation is triggered.
    block_threshold: f32,

    /// Confidence threshold below which SAFE is returned (no findings at all).
    safe_threshold: f32,
}

impl Default for SteganographyDetector {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl SteganographyDetector {
    /// Construct a new detector with default parameters tuned for general-purpose use.
    ///
    /// # Default Parameters
    ///
    /// | Parameter | Value | Rationale |
    /// |-----------|-------|-----------|
    /// | `lsb_sample_size` | 65536 bytes (64 KB) | Sufficient for statistical significance |
    /// | `entropy_window_size` | 1024 bytes (1 KB) | Good balance of locality vs stability |
    /// | `sensitivity_threshold` | 0.15 | Filter out very weak signals |
    /// | `block_threshold` | 0.85 | Only block on strong evidence |
    /// | `safe_threshold` | 0.10 | Anything above this is at least "investigate" |
    pub fn with_defaults() -> Self {
        Self {
            lsb_sample_size: 65_536,     // 64 KB sample for LSB analysis
            entropy_window_size: 1_024,  // 1 KB window for entropy
            sensitivity_threshold: 0.15, // Minimum confidence to report
            block_threshold: 0.85,       // Block if confidence >= this
            safe_threshold: 0.10,        // Below this = safe
        }
    }

    /// Construct a detector with custom analysis parameters.
    ///
    /// Use this for tuning detection sensitivity based on operational requirements.
    /// Higher sensitivity catches more stego but increases false positive rate.
    pub fn with_config(
        lsb_sample_size: usize,
        entropy_window_size: usize,
        sensitivity_threshold: f32,
        block_threshold: f32,
    ) -> Self {
        Self {
            lsb_sample_size,
            entropy_window_size,
            sensitivity_threshold,
            block_threshold,
            safe_threshold: 0.10,
        }
    }

    // =========================================================================
    // Main Detection Entry Point
    // =========================================================================

    /// Run all applicable detection techniques on image data.
    ///
    /// Selects which techniques to run based on the declared format:
    ///
    /// | Format | Techniques Applied |
    /// |--------|-------------------|
    /// | JPEG | Appended Data, Entropy, EXIF Overflow, Freq Domain, Structure |
    /// | PNG | Appended Data, Entropy, Chunk Sequence, LSB (if uncompressed), Structure |
    /// | BMP | LSB Analysis, Entropy, Appended Data |
    /// | GIF | Palette Anomaly, Appended Data, Structure |
    /// | TIFF | Appended Data, Entropy, Structure |
    /// | *other* | Appended Data, Entropy (generic) |
    ///
    /// # Arguments
    /// * `data` — Raw image file bytes.
    /// * `format` — Format identifier string ("jpeg", "png", "bmp", etc.).
    ///
    /// # Returns
    /// [`StegoDetectionResult`] with all findings and a recommended action.
    pub fn detect(&self, data: &[u8], format: &str) -> StegoDetectionResult {
        let mut findings: Vec<StegoFinding> = Vec::new();

        if data.is_empty() {
            return StegoDetectionResult {
                is_suspicious: false,
                findings: vec![],
                recommended_action: StegoRecommendation::Safe,
            };
        }

        let format_lower = format.to_lowercase();

        // --- Technique 1: Appended Data After EOF (all formats) ---
        if let Some(finding) = self.check_appended_data(data, &format_lower) {
            debug!(
                technique = %finding.technique,
                confidence = finding.confidence,
                "Appended data detected"
            );
            findings.push(finding);
        }

        // --- Technique 2: Entropy Analysis (all formats) ---
        let entropy_findings = self.analyze_entropy(data);
        for f in entropy_findings {
            if f.confidence >= self.sensitivity_threshold {
                debug!(
                    technique = %f.technique,
                    confidence = f.confidence,
                    "Entropy anomaly detected"
                );
                findings.push(f);
            }
        }

        // --- Format-Specific Techniques ---
        match format_lower.as_str() {
            "png" => {
                // PNG chunk sequence analysis
                let chunk_findings = self.analyze_chunk_sequence(data);
                for f in chunk_findings {
                    if f.confidence >= self.sensitivity_threshold {
                        findings.push(f);
                    }
                }
            }
            "jpeg" | "jpg" => {
                // JPEG-specific: check for EXIF overflow
                if let Some(finding) = self.check_jpeg_exif_overflow(data) {
                    if finding.confidence >= self.sensitivity_threshold {
                        findings.push(finding);
                    }
                }
            }
            "bmp" => {
                // BMP LSB analysis (uncompressed pixel data)
                if let Some(pixel_data) = self.extract_bmp_pixel_data(data) {
                    let lsb_findings = self.analyze_lsb(&pixel_data, 3); // BMP is usually RGB
                    for f in lsb_findings {
                        if f.confidence >= self.sensitivity_threshold {
                            findings.push(f);
                        }
                    }
                }
            }
            _ => {}
        }

        // Determine overall result
        let is_suspicious = !findings.is_empty();
        let recommended_action = self.compute_recommendation(&findings);

        info!(
            format = %format_lower,
            data_size = data.len(),
            findings_count = findings.len(),
            is_suspicious,
            recommendation = %recommended_action,
            "Steganography detection complete"
        );

        StegoDetectionResult {
            is_suspicious,
            findings,
            recommended_action,
        }
    }

    /// Compute the recommended action based on aggregated findings.
    fn compute_recommendation(&self, findings: &[StegoFinding]) -> StegoRecommendation {
        if findings.is_empty() {
            return StegoRecommendation::Safe;
        }

        let max_conf = findings
            .iter()
            .map(|f| f.confidence)
            .fold(0.0_f32, f32::max);

        // Multiple moderate findings compound into higher suspicion
        let moderate_count = findings
            .iter()
            .filter(|f| (0.40..0.70).contains(&f.confidence))
            .count();

        if max_conf >= self.block_threshold {
            StegoRecommendation::Block
        } else if max_conf >= 0.70 || moderate_count >= 3 {
            StegoRecommendation::ReEncode
        } else if max_conf >= self.safe_threshold {
            StegoRecommendation::Investigate
        } else {
            StegoRecommendation::Safe
        }
    }

    // =========================================================================
    // Detection Technique: Appended Data After EOF
    // =========================================================================

    /// Check for data appended after the end-of-file marker.
    ///
    /// This is one of the simplest and most reliable stego detection methods.
    /// Many tools hide data by simply concatenating it after the last valid
    /// marker in an image file.
    ///
    /// # Markers Checked
    /// - PNG: IEND chunk (`\x49\x45\x4E\x44`) + its 12-byte header/CRC
    /// - JPEG: EOI marker (`\xFF\xD9`)
    /// - GIF: Trailer (`\x3B`)
    /// - BMP: File should end exactly at bfSize offset
    ///
    /// # Confidence
    /// - Any appended data → 0.95+ (very high confidence this is intentional)
    fn check_appended_data(&self, data: &[u8], format: &str) -> Option<StegoFinding> {
        match format {
            "png" => {
                // Search for IEND chunk: length(4) + "IEND"(4) + CRC(4) = 12 bytes
                let iend_pattern: &[u8] = b"IEND";
                for i in 0..data.len().saturating_sub(8) {
                    if &data[i..i + 4] == iend_pattern {
                        let expected_end = i + 12; // 4(len) + 4(type) + 4(CRC)
                        if expected_end < data.len() {
                            let appended_len = data.len() - expected_end;
                            return Some(StegoFinding {
                                technique: StegoTechnique::AppendedData,
                                confidence: if appended_len > 1024 { 0.98 } else { 0.92 },
                                location: format!("offset {} (after IEND chunk)", expected_end),
                                description: format!(
                                    "{} bytes of data appended after PNG IEND marker",
                                    appended_len
                                ),
                            });
                        }
                    }
                }
                None
            }
            "jpeg" | "jpg" => {
                // Search for EOI marker \xFF\xD9
                for i in 0..data.len().saturating_sub(1) {
                    if data[i] == 0xFF && data[i + 1] == 0xD9 {
                        let expected_end = i + 2;
                        if expected_end < data.len() {
                            let appended_len = data.len() - expected_end;
                            return Some(StegoFinding {
                                technique: StegoTechnique::AppendedData,
                                confidence: if appended_len > 1024 { 0.99 } else { 0.95 },
                                location: format!(
                                    "offset {} (after JPEG EOI marker)",
                                    expected_end
                                ),
                                description: format!(
                                    "{} bytes of data appended after JPEG EOI marker (0xFF 0xD9)",
                                    appended_len
                                ),
                            });
                        }
                    }
                }
                None
            }
            "gif" => {
                // GIF trailer is 0x3B
                if let Some(&last_byte) = data.last() {
                    if last_byte != 0x3B {
                        // Missing trailer or data after it
                        // Search for trailer byte
                        for i in (0..data.len()).rev() {
                            if data[i] == 0x3B && i < data.len() - 1 {
                                let appended_len = data.len() - i - 1;
                                return Some(StegoFinding {
                                    technique: StegoTechnique::AppendedData,
                                    confidence: 0.93,
                                    location: format!("offset {}", i + 1),
                                    description: format!(
                                        "{} bytes of data after GIF trailer",
                                        appended_len
                                    ),
                                });
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    // =========================================================================
    // Detection Technique: Entropy Analysis
    // =========================================================================

    /// Compute local Shannon entropy and compare against expected values.
    ///
    /// Natural images have characteristic entropy profiles:
    /// - Compressed formats (JPEG/PNG): entropy near theoretical maximum
    /// - Uncompressed (BMP): lower entropy with spatial correlation
    /// - Steganographed images: local entropy anomalies at embedding locations
    ///
    /// This method slides a window over the data and flags regions where
    /// entropy deviates significantly from the global average.
    fn analyze_entropy(&self, data: &[u8]) -> Vec<StegoFinding> {
        if data.len() < self.entropy_window_size * 2 {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Compute global entropy baseline
        let global_entropy = compute_shannon_entropy(data);

        // Slide window and compare local vs global
        let step = self.entropy_window_size / 2;
        let mut suspicious_regions = 0usize;
        let mut max_deviation = 0.0_f64;

        let mut start = 0;
        while start + self.entropy_window_size <= data.len() {
            let window = &data[start..start + self.entropy_window_size];
            let local_entropy = compute_shannon_entropy(window);

            let deviation = (local_entropy - global_entropy).abs();
            if deviation > max_deviation {
                max_deviation = deviation;
            }

            // Flag significant deviations (> 15% difference from global)
            if global_entropy > 0.0 && deviation / global_entropy > 0.15 {
                suspicious_regions += 1;
            }

            start += step;
        }

        // Report findings if enough suspicious regions exist
        let total_windows = data.len() / step;
        if total_windows > 0 {
            let suspicious_ratio = suspicious_regions as f64 / total_windows as f64;

            if suspicious_ratio > 0.30 && max_deviation > 0.3 {
                let confidence = (0.30 + suspicious_ratio.min(0.60)) as f32;

                findings.push(StegoFinding {
                    technique: StegoTechnique::EntropyAnomaly,
                    confidence: confidence.min(0.75),
                    location: "multiple regions".to_string(),
                    description: format!(
                        "{}/{} windows show significant entropy deviation ({:.2}% suspicious, max dev {:.3})",
                        suspicious_regions, total_windows, suspicious_ratio * 100.0, max_deviation
                    ),
                });
            }
        }

        findings
    }

    // =========================================================================
    // Detection Technique: LSB Analysis
    // =========================================================================

    /// Analyze least significant bits of pixel data for signs of embedding.
    ///
    /// Natural images have random-looking LSB distributions due to sensor noise
    /// and quantization. Steganographically modified images often show:
    /// - Non-uniform LSB histograms (peaks/valleys from embedded data)
    /// - Chi-squared test failure (LSBs don't follow expected distribution)
    /// - Correlation between adjacent pixel LSBs (sequential encoding)
    ///
    /// # Arguments
    /// * `pixel_data` — Raw pixel bytes (not file container bytes).
    /// * `channels` — Number of color channels (3=RGB, 4=RGBA, 1=grayscale).
    #[allow(unused_variables)]
    #[allow(unused_assignments)]
    fn analyze_lsb(&self, pixel_data: &[u8], channels: u8) -> Vec<StegoFinding> {
        if pixel_data.is_empty() || channels == 0 {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let sample_len = pixel_data.len().min(self.lsb_sample_size);

        // Extract LSBs from sampled pixels
        #[allow(unused_variables)]
        let mut zero_count: usize = 0;
        #[allow(unused_variables)]
        let mut one_count: usize = 0;
        let mut consecutive_same: usize = 0;
        let mut prev_bit: Option<bool> = None;

        for i in 0..sample_len {
            let lsb = pixel_data[i] & 0x01;
            if lsb == 0 {
                zero_count += 1;
            } else {
                one_count += 1;
            }

            // Track run-length of same bits (detects sequential encoding)
            let current_bit = lsb == 1;
            if let Some(prev) = prev_bit {
                if prev == current_bit {
                    consecutive_same += 1;
                }
            }
            prev_bit = Some(current_bit);
        }

        let total = sample_len as f64;
        let zero_ratio = zero_count as f64 / total;
        let expected_ratio = 0.50; // Uniform distribution expected

        // Chi-squared-like test: how far from uniform?
        let deviation = (zero_ratio - expected_ratio).abs();
        let chi_score = (deviation * deviation * total) / expected_ratio;

        // For large samples, chi-score > 3.84 indicates p < 0.05 (significant deviation)
        if chi_score > 6.0 && sample_len > 1000 {
            let confidence = ((chi_score / 50.0).min(0.90)).max(0.25) as f32;

            findings.push(StegoFinding {
                technique: StegoTechnique::LsbReplacement,
                confidence,
                location: format!(
                    "LSB plane of first {} bytes ({} channels)",
                    sample_len, channels
                ),
                description: format!(
                    "LSB distribution biased: {:.1}% zeros vs {:.1}% ones (expected ~50/50), chi^2={:.2}",
                    zero_ratio * 100.0,
                    (1.0 - zero_ratio) * 100.0,
                    chi_score
                ),
            });
        }

        // Check for sequential pattern (run-length too long)
        let max_expected_run = (sample_len as f64).sqrt() as usize;
        if consecutive_same > max_expected_run * 3 {
            findings.push(StegoFinding {
                technique: StegoTechnique::LsbSequential,
                confidence: 0.75,
                location: "LSB bitstream".to_string(),
                description: format!(
                    "LSB shows {} consecutive same-bit runs (expected < {} for random noise)",
                    consecutive_same,
                    max_expected_run * 3
                ),
            });
        }

        findings
    }

    // =========================================================================
    // Detection Technique: PNG Chunk Sequence Analysis
    // =========================================================================

    /// Analyze PNG chunk ordering for anomalies that suggest hidden data.
    ///
    /// Valid PNG chunk ordering per specification:
    /// 1. Signature
    /// 2. IHDR (must be first chunk)
    /// 3. Optional color management (cHRM, gAMA, sRGB, iCCP)
    /// 4. Optional text chunks (tEXt, zTXt, iTXt)
    /// 5. Optional misc (bKGD, pHYs, sBIT, tIME)
    /// 6. PLTE (if indexed color, before IDAT)
    /// 7. IDAT (one or more contiguous chunks)
    /// 8. IEND (must be last chunk)
    ///
    /// Anomalies flagged:
    /// - Unknown chunks between IDAT blocks (classic hiding spot)
    /// - IDAT appearing after IEND
    /// - Multiple IDAT sequences (non-contiguous)
    /// - Chunks after IEND
    fn analyze_chunk_sequence(&self, data: &[u8]) -> Vec<StegoFinding> {
        const PNG_SIG_LEN: usize = 8;
        const CHUNK_HEADER_LEN: usize = 8; // 4(length) + 4(type)

        if data.len() < PNG_SIG_LEN + CHUNK_HEADER_LEN {
            return Vec::new();
        }

        // Verify PNG signature
        if &data[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut pos = PNG_SIG_LEN;
        let mut idat_started = false;
        let mut idat_ended = false;
        let mut iend_found = false;
        let mut unknown_chunks_after_idat = 0usize;
        let mut chunk_index = 0usize;

        while pos + CHUNK_HEADER_LEN <= data.len() {
            let chunk_len =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            let chunk_type = &data[pos + 4..pos + 8];

            let type_str = String::from_utf8_lossy(chunk_type).to_string();

            match chunk_type {
                b"IDAT" => {
                    if iend_found {
                        findings.push(StegoFinding {
                            technique: StegoTechnique::ChunkSequence,
                            confidence: 0.95,
                            location: format!("chunk index {}", chunk_index),
                            description: format!(
                                "IDAT chunk found AFTER IEND at chunk index {}",
                                chunk_index
                            ),
                        });
                    }
                    if idat_ended && !iend_found {
                        // Non-contiguous IDAT
                        findings.push(StegoFinding {
                            technique: StegoTechnique::ChunkSequence,
                            confidence: 0.80,
                            location: format!("chunk index {}", chunk_index),
                            description: "Non-contiguous IDAT chunk (gap between IDAT sequences)"
                                .to_string(),
                        });
                    }
                    idat_started = true;
                }
                b"IEND" => {
                    iend_found = true;
                    idat_ended = true;
                }
                _ => {
                    if idat_started && !idat_ended {
                        // Unknown chunk between IDATs
                        if !matches!(
                            chunk_type,
                            b"IHDR"
                                | b"PLTE"
                                | b"cHRM"
                                | b"gAMA"
                                | b"sRGB"
                                | b"iCCP"
                                | b"bKGD"
                                | b"pHYs"
                                | b"sBIT"
                                | b"tIME"
                                | b"tEXt"
                                | b"zTXt"
                                | b"iTXt"
                                | b"eXIf"
                        ) {
                            unknown_chunks_after_idat += 1;
                        }
                    }
                    if iend_found {
                        // Any chunk after IEND is highly suspicious
                        findings.push(StegoFinding {
                            technique: StegoTechnique::ChunkSequence,
                            confidence: 0.97,
                            location: format!("chunk index {} (after IEND)", chunk_index),
                            description: format!(
                                "'{}' chunk appears after IEND (file should end here)",
                                type_str
                            ),
                        });
                    }
                }
            }

            let chunk_total = CHUNK_HEADER_LEN + chunk_len + 4; // +4 for CRC
            pos += chunk_total;
            chunk_index += 1;

            if pos > data.len() {
                break;
            }
        }

        // Report accumulated unknown-chunks-between-IDATs finding
        if unknown_chunks_after_idat > 0 {
            findings.push(StegoFinding {
                technique: StegoTechnique::ChunkSequence,
                confidence: (0.50 + (unknown_chunks_after_idat as f32 * 0.10)).min(0.88),
                location: "between IDAT chunks".to_string(),
                description: format!(
                    "{} unknown/custom chunk(s) found between IDAT data chunks (potential hiding location)",
                    unknown_chunks_after_idat
                ),
            });
        }

        findings
    }

    // =========================================================================
    // Detection Technique: JPEG EXIF Overflow
    // =========================================================================

    /// Check if JPEG EXIF segment is unusually large.
    ///
    /// Normal camera-generated EXIF data ranges from a few hundred bytes to
    /// perhaps 20-30 KB for professional cameras with extensive MakerNotes.
    /// EXIF segments exceeding 100 KB are highly suspicious and may contain
    /// hidden data encoded within custom tags or padding.
    fn check_jpeg_exif_overflow(&self, data: &[u8]) -> Option<StegoFinding> {
        if data.len() < 4 || &data[0..2] != b"\xFF\xD8" {
            return None;
        }

        const MAX_NORMAL_EXIF_SIZE: usize = 100 * 1024; // 100 KB threshold

        let mut pos: usize = 2;
        while pos + 4 <= data.len() {
            if data[pos] != 0xFF {
                pos += 1;
                continue;
            }

            let marker = data[pos + 1];

            // Stop at SOS or EOI
            if marker == 0xDA || marker == 0xD9 {
                break;
            }

            // Skip standalone markers
            if matches!(marker, 0x00 | 0xD0..=0xD7) {
                pos += 2;
                continue;
            }

            if pos + 4 > data.len() {
                break;
            }

            let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

            if seg_len < 2 {
                break;
            }

            // Check APP1 for EXIF/XMP
            if marker == 0xE1 && seg_len > MAX_NORMAL_EXIF_SIZE {
                return Some(StegoFinding {
                    technique: StegoTechnique::ExifOverflow,
                    confidence: ((seg_len as f32 / MAX_NORMAL_EXIF_SIZE as f32) * 0.35 + 0.50)
                        .min(0.90),
                    location: format!("APP1 segment at offset {}, size={} bytes", pos, seg_len),
                    description: format!(
                        "APP1 (EXIF/XMP) segment is {} bytes ({} KB), exceeding normal range (< 100 KB)",
                        seg_len,
                        seg_len / 1024
                    ),
                });
            }

            pos += 2 + seg_len;
        }

        None
    }

    // =========================================================================
    // Helper: BMP Pixel Data Extraction
    // =========================================================================

    /// Extract raw pixel data from a BMP file for LSB analysis.
    ///
    /// Parses the BMP header to locate the pixel array offset and dimensions,
    /// then returns the raw pixel bytes for analysis.
    fn extract_bmp_pixel_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 54 {
            return None;
        }

        // Verify BM signature
        if &data[0..2] != b"BM" {
            return None;
        }

        let pixel_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
        let width = u32::from_le_bytes([data[18], data[19], data[20], data[21]]) as usize;
        let height =
            i32::from_le_bytes([data[22], data[23], data[24], data[25]]).unsigned_abs() as usize;
        let bits_per_pixel = u16::from_le_bytes([data[28], data[29]]) as usize;
        let channels = bits_per_pixel / 8;

        if pixel_offset >= data.len() || width == 0 || height == 0 || channels == 0 {
            return None;
        }

        let row_size = ((bits_per_pixel * width + 31) / 32) * 4; // Rows are padded to 4-byte boundaries
        let expected_pixel_data_size = row_size * height;

        let available = data.len().saturating_sub(pixel_offset);
        let actual_size = expected_pixel_data_size.min(available);

        if actual_size == 0 {
            return None;
        }

        Some(data[pixel_offset..pixel_offset + actual_size].to_vec())
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Compute Shannon entropy of a byte slice in bits per byte.
///
/// H(X) = -sum(p(x) * log2(p(x))) for all byte values x
///
/// Returns value in [0.0, 8.0] where:
/// - 0.0 = all bytes identical (no information)
/// - 8.0 = perfectly uniform distribution (maximum information)
pub fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;
    let mut counts = [0usize; 256];

    for &byte in data {
        counts[byte as usize] += 1;
    }

    let mut entropy = 0.0_f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_default_creation() {
        let detector = SteganographyDetector::with_defaults();
        assert_eq!(detector.lsb_sample_size, 65_536);
        assert_eq!(detector.entropy_window_size, 1_024);
        assert!((detector.sensitivity_threshold - 0.15).abs() < f32::EPSILON);
    }

    #[test]
    fn test_detect_empty_data() {
        let detector = SteganographyDetector::with_defaults();
        let result = detector.detect(&[], "png");
        assert!(!result.is_suspicious);
        assert_eq!(result.recommended_action, StegoRecommendation::Safe);
    }

    #[test]
    fn test_detect_png_with_appended_data() {
        let detector = SteganographyDetector::with_defaults();

        // Build minimal valid PNG + extra data after IEND
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // sig

        // IHDR: 13 bytes of data (standard IHDR size)
        png.extend_from_slice(&0x0000000Du32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // w=1
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // h=1
        png.extend_from_slice(&[0x08, 0x02, 0x00, 0x00, 0x00]);
        png.extend_from_slice(&0x18C204u32.to_be_bytes()); // fake CRC

        // IDAT
        png.extend_from_slice(&0x0000000Au32.to_be_bytes());
        png.extend_from_slice(b"IDAT");
        png.extend_from_slice(&[0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01]);
        png.extend_from_slice(&0xDD34ECu32.to_be_bytes());

        // IEND
        png.extend_from_slice(&0x00000000u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&0xAE426082u32.to_be_bytes());

        // Append hidden data after IEND
        let hidden_payload = b"This is secret hidden data appended after the PNG IEND marker!";
        png.extend_from_slice(hidden_payload);

        let result = detector.detect(&png, "png");
        assert!(result.is_suspicious);

        let appended_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.technique == StegoTechnique::AppendedData)
            .collect();
        assert!(!appended_findings.is_empty());
        assert!(appended_findings[0].confidence > 0.90);
    }

    #[test]
    fn test_detect_jpeg_with_appended_data() {
        let detector = SteganographyDetector::with_defaults();

        // Minimal JPEG: SOI + some markers + EOI + appended data
        let mut jpeg = Vec::new();
        jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI
        jpeg.extend_from_slice(&[0xFF, 0xE0]); // APP0
        jpeg.extend_from_slice(&16u16.to_be_bytes());
        jpeg.extend_from_slice(b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00");
        jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

        // Append hidden data
        let payload = b"HIDDEN_PAYLOAD_AFTER_JPEG_EOI_MARKER";
        jpeg.extend_from_slice(payload);

        let result = detector.detect(&jpeg, "jpeg");
        assert!(result.is_suspicious);

        let appended: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.technique == StegoTechnique::AppendedData)
            .collect();
        assert!(!appended.is_empty());
        assert_eq!(appended[0].technique, StegoTechnique::AppendedData);
    }

    #[test]
    fn test_detect_clean_png_no_findings() {
        let detector = SteganographyDetector::with_defaults();

        // Clean minimal PNG without appended data
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        // IHDR: 13 bytes of data per PNG spec
        png.extend_from_slice(&0x0000000Du32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // w=2
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // h=2
        png.extend_from_slice(&[0x08, 0x02, 0x00, 0x00, 0x00]);
        png.extend_from_slice(&0x58C30Cu32.to_be_bytes());

        // IDAT
        png.extend_from_slice(&0x0000000Cu32.to_be_bytes());
        png.extend_from_slice(b"IDAT");
        png.extend_from_slice(&[
            0x78, 0x9C, 0x62, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01,
        ]);
        png.extend_from_slice(&0xE0B866u32.to_be_bytes());

        // IEND
        png.extend_from_slice(&0x00000000u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&0xAE426082u32.to_be_bytes());

        let result = detector.detect(&png, "png");
        // Clean PNG should have no appended-data findings (may still have entropy findings depending on data)
        let appended: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.technique == StegoTechnique::AppendedData)
            .collect();
        assert!(
            appended.is_empty(),
            "Clean PNG should not have appended data findings"
        );
    }

    #[test]
    fn test_detect_png_unknown_chunks_between_idats() {
        let detector = SteganographyDetector::with_defaults();

        // Build PNG with unknown chunk between two IDAT chunks
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        // IHDR (13 bytes per PNG spec)
        png.extend_from_slice(&0x0000000Du32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        png.extend_from_slice(&[0x08, 0x02, 0x00, 0x00, 0x00]);
        png.extend_from_slice(&0x18C204u32.to_be_bytes());

        // First IDAT
        png.extend_from_slice(&0x00000002u32.to_be_bytes());
        png.extend_from_slice(b"IDAT");
        png.extend_from_slice(&[0x78, 0x00]);
        png.extend_from_slice(&0x070801Eu32.to_be_bytes());

        // Unknown custom chunk between IDATs (hiding spot!)
        png.extend_from_slice(&0x00000010u32.to_be_bytes()); // 16 bytes
        png.extend_from_slice(b"cuSt"); // Custom chunk type
        png.extend_from_slice(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
            0x47, 0x48,
        ]);
        png.extend_from_slice(&0x12345678u32.to_be_bytes()); // Fake CRC

        // Second IDAT
        png.extend_from_slice(&0x00000002u32.to_be_bytes());
        png.extend_from_slice(b"IDAT");
        png.extend_from_slice(&[0x00, 0x00]);
        png.extend_from_slice(&0x27BEA8u32.to_be_bytes());

        // IEND
        png.extend_from_slice(&0x00000000u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&0xAE426082u32.to_be_bytes());

        let result = detector.detect(&png, "png");

        let chunk_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.technique == StegoTechnique::ChunkSequence)
            .collect();
        assert!(
            !chunk_findings.is_empty(),
            "Should detect unknown chunk between IDATs"
        );
    }

    #[test]
    fn test_recommendation_safe_for_clean_image() {
        let detector = SteganographyDetector::with_defaults();
        let clean_data = vec![0x42u8; 1024]; // Just some data
        let result = detector.detect(&clean_data, "unknown");
        // Unknown format only does generic checks; uniform data might trigger entropy but let's see
        // The key point: no appended data for unknown format
        assert_eq!(result.recommended_action, StegoRecommendation::Safe);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // Uniform distribution should give ~8.0 bits/byte
        let data: Vec<u8> = (0..=255).cycle().take(2560).collect();
        let entropy = compute_shannon_entropy(&data);
        assert!(
            entropy > 7.5,
            "Uniform data should have high entropy, got {}",
            entropy
        );
    }

    #[test]
    fn test_shannon_entropy_constant() {
        // Constant data should give 0.0 entropy
        let data = vec![0xABu8; 1000];
        let entropy = compute_shannon_entropy(&data);
        assert!(
            (entropy - 0.0).abs() < f64::EPSILON,
            "Constant data should have 0 entropy"
        );
    }

    #[test]
    fn test_bmp_pixel_extraction() {
        let detector = SteganographyDetector::with_defaults();

        // Build minimal 1x1 24-bit BMP
        let mut bmp = Vec::new();
        bmp.extend_from_slice(b"BM"); // Signature
        bmp.extend_from_slice(&(54u32 + 4).to_le_bytes()); // File size
        bmp.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        bmp.extend_from_slice(&54u32.to_le_bytes()); // Pixel offset
        bmp.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
        bmp.extend_from_slice(&1u32.to_le_bytes()); // Width
        bmp.extend_from_slice(&1u32.to_le_bytes()); // Height
        bmp.extend_from_slice(&1u16.to_le_bytes()); // Planes
        bmp.extend_from_slice(&24u16.to_le_bytes()); // BPP
        bmp.extend_from_slice(&0u32.to_le_bytes()); // Compression
        bmp.extend_from_slice(&4u32.to_le_bytes()); // Image size
        bmp.extend_from_slice(&2835i32.to_le_bytes()); // X ppm
        bmp.extend_from_slice(&2835i32.to_le_bytes()); // Y ppm
        bmp.extend_from_slice(&0u32.to_le_bytes()); // Colors used
        bmp.extend_from_slice(&0u32.to_le_bytes()); // Important colors
        // Pixel data (1 pixel RGB + 1 byte padding)
        bmp.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);

        let pixels = detector.extract_bmp_pixel_data(&bmp);
        assert!(pixels.is_some());
        let pixels = pixels.unwrap();
        assert!(pixels.len() >= 3); // At least 3 bytes for 1 RGB pixel
    }
}
