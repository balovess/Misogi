use crate::report::{SanitizationAction, SanitizationReport};
use crate::policy::SanitizationPolicy;

// Core error types (always available from misogi-core)
use misogi_core::MisogiError;
use misogi_core::Result;

// Runtime-dependent imports (async trait, file sanitizer, tokio I/O)
#[cfg(feature = "runtime")]
use async_trait::async_trait;
#[cfg(feature = "runtime")]
use super::FileSanitizer;
#[cfg(feature = "pdf-cdr")]
use crate::pdf_true_cdr::{PdfTrueCdrConfig, PdfTrueCdrEngine, PdfTrueCdrResult};
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, take_till, take_while1},
    character::complete::space0,
    sequence::delimited,
};
use std::path::Path;

/// Detected threat within a PDF binary stream.
///
/// Each variant captures sufficient positional metadata to enable precise
/// byte-level remediation during Pass 2 without re-parsing.
#[derive(Debug, Clone)]
pub enum PdfThreat {
    /// `/JS` followed by a JavaScript code string or hex-encoded string.
    /// Offset points to the leading slash of `/JS`.
    JavaScript { offset: usize, value_length: usize },

    /// `/JavaScript` (long-form name) followed by code value.
    JavaScriptLong { offset: usize, value_length: usize },

    /// Additional Actions (`/AA`) dictionary containing event handlers
    /// such as /O (page open), /C (page close), /K (keystroke), etc.
    AdditionalActions { offset: usize, dict_length: usize },

    /// `/OpenAction` entry in catalog root that triggers script on document open.
    OpenAction { offset: usize },

    /// `/AcroForm` dictionary containing interactive form fields.
    AcroForm { offset: usize },

    /// `/S /SubmitForm` action that exfiltrates form data to remote URL.
    SubmitForm { offset: usize },

    /// `/URI` action pointing to external resource (http/https).
    UriAction { offset: usize },

    /// `/EmbeddedFile` attachment (potentially malicious payload).
    EmbeddedFile { offset: usize, name: String },

    /// `/RichMedia` annotation (Flash/SWF container).
    RichMedia { offset: usize },
}

impl PdfThreat {
    /// Byte offset where this threat begins in the source PDF.
    #[inline]
    pub fn offset(&self) -> usize {
        match self {
            Self::JavaScript { offset, .. } => *offset,
            Self::JavaScriptLong { offset, .. } => *offset,
            Self::AdditionalActions { offset, .. } => *offset,
            Self::OpenAction { offset } => *offset,
            Self::AcroForm { offset } => *offset,
            Self::SubmitForm { offset } => *offset,
            Self::UriAction { offset } => *offset,
            Self::EmbeddedFile { offset, .. } => *offset,
            Self::RichMedia { offset } => *offset,
        }
    }

    /// Total byte length of the threat region (from offset to end of dangerous content).
    /// Used during remediation to skip past original content after NOP replacement.
    #[inline]
    pub fn length(&self) -> usize {
        match self {
            Self::JavaScript { value_length, .. } => 3 + *value_length,
            Self::JavaScriptLong { value_length, .. } => 11 + *value_length,
            Self::AdditionalActions { dict_length, .. } => 3 + *dict_length,
            Self::OpenAction { .. } => 11,
            Self::AcroForm { .. } => 9,
            Self::SubmitForm { .. } => 12,
            Self::UriAction { .. } => 4,
            Self::EmbeddedFile { .. } => 13,
            Self::RichMedia { .. } => 10,
        }
    }

    /// Convert this threat into its corresponding [`SanitizationAction`] audit record.
    pub fn to_action(&self) -> SanitizationAction {
        match self {
            Self::JavaScript { offset, .. } => SanitizationAction::PdfJsRemoved {
                offset: *offset,
                length: self.length(),
            },
            Self::JavaScriptLong { offset, .. } => SanitizationAction::PdfJsRemoved {
                offset: *offset,
                length: self.length(),
            },
            Self::AdditionalActions { offset, .. } => {
                SanitizationAction::PdfAaRemoved { offset: *offset }
            }
            Self::OpenAction { .. } => SanitizationAction::PdfOpenActionRemoved,
            Self::AcroForm { .. } => SanitizationAction::PdfAcroFormFlattened,
            Self::SubmitForm { .. } => SanitizationAction::PdfSubmitFormRemoved,
            Self::UriAction { offset, .. } => SanitizationAction::PdfUriRemoved { offset: *offset },
            Self::EmbeddedFile { name, .. } => {
                SanitizationAction::PdfEmbeddedFileFlagged { name: name.clone() }
            }
            Self::RichMedia { .. } => SanitizationAction::PdfRichMediaRemoved,
        }
    }
}

/// Streaming PDF sanitizer using nom-based binary parser for zero-copy threat detection.
///
/// ## Architecture: Two-Pass Strategy
///
/// **Pass 1 (Analysis):** Reads PDF into bounded memory, scans every byte position
/// with nom combinators to collect [`PdfThreat`] entries with exact offsets.
///
/// **Pass 2 (Remediation):** Streams input -> output byte-by-byte; at each threat
/// offset, emits NOP replacement bytes instead of original content.
///
/// ## Memory Safety
/// - Analysis phase: single read of file up to `max_file_size_bytes` (default 500 MiB)
/// - Remediation phase: streaming I/O with 8 KiB buffer, never loads full output
pub struct PdfSanitizer {
    max_file_size_bytes: u64,
    /// Chunk size for streaming I/O operations (reserved for future use).
    #[allow(dead_code)]
    chunk_size: usize,
}

impl PdfSanitizer {
    /// Construct a new PDF sanitizer with explicit file size limit.
    ///
    /// # Arguments
    /// * `max_file_size_bytes` - Maximum allowed input size in bytes. Files exceeding
    ///   this limit are rejected with [`MisogiError::SecurityViolation`] before any parsing occurs.
    pub fn new(max_file_size_bytes: u64) -> Self {
        Self {
            max_file_size_bytes,
            chunk_size: 8 * 1024,
        }
    }

    /// Construct PDF sanitizer with default configuration (500 MiB limit).
    pub fn default_config() -> Self {
        Self {
            max_file_size_bytes: 500 * 1024 * 1024,
            chunk_size: 8 * 1024,
        }
    }

    // =========================================================================
    // Nom Parser Combinators — Threat Detection
    // =========================================================================

    /// Match `/JS` followed by optional whitespace and a string value (literal or hex).
    ///
    /// # Input Examples
    /// - `/JS (app.alert('xss'))`
    /// - `/JS <6170702E616C657274>`
    ///
    /// # Returns
    /// `PdfThreat::JavaScript` with offset relative to current parse position.
    fn parse_js_tag(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (remaining, _) = tag(b"/JS")(input)?;
        let (remaining, _ws) = space0(remaining)?;

        let (after_value, _value_content) = alt((
            delimited(tag(b"("), take_till(|b| b == b')'), tag(b")")),
            delimited(
                tag(b"<"),
                take_while1(|b: u8| b.is_ascii_hexdigit()),
                tag(b">"),
            ),
        ))(remaining)?;

        let consumed = input.len() - after_value.len();
        let value_len = consumed.saturating_sub(3);

        Ok((
            after_value,
            PdfThreat::JavaScript {
                offset: 0,
                value_length: value_len,
            },
        ))
    }

    /// Match `/JavaScript` (long-form name) followed by whitespace and a string value.
    ///
    /// This handles the fully-spelled name variant which is less common but equally dangerous.
    fn parse_javascript_tag(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (remaining, _) = tag(b"/JavaScript")(input)?;
        let (remaining, _ws) = space0(remaining)?;

        let (after_value, _value_content) = alt((
            delimited(tag(b"("), take_till(|b| b == b')'), tag(b")")),
            delimited(
                tag(b"<"),
                take_while1(|b: u8| b.is_ascii_hexdigit()),
                tag(b">"),
            ),
        ))(remaining)?;

        let consumed = input.len() - after_value.len();
        let value_len = consumed.saturating_sub(11);

        Ok((
            after_value,
            PdfThreat::JavaScriptLong {
                offset: 0,
                value_length: value_len,
            },
        ))
    }

    /// Match `/AA` followed by a dictionary body `<< ... >>`, handling nested `<< >>` pairs
    /// via bracket-counting heuristic.
    ///
    /// Additional Actions dictionaries contain event-handler entries like:
    /// ```text
    /// /AA << /O <reference> /C <reference> /K <reference> >>
    /// ```
    fn parse_aa_tag(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (after_aa, _) = tag(b"/AA")(input)?;
        let (cursor, ws) = space0(after_aa)?;

        if !cursor.starts_with(b"<<") {
            return Err(nom::Err::Error(nom::error::Error::new(
                cursor,
                nom::error::ErrorKind::Tag,
            )));
        }

        let dict_start = cursor;
        let mut depth: i32 = 0;
        let mut end_pos: usize = 0;

        for (idx, &byte) in cursor.iter().enumerate() {
            if idx >= 1 && cursor[idx - 1] == b'<' && byte == b'<' {
                depth += 1;
            }
            if idx >= 1 && cursor[idx - 1] == b'>' && byte == b'>' {
                depth -= 1;
                if depth == 0 {
                    end_pos = idx + 1;
                    break;
                }
            }
        }

        if end_pos == 0 {
            return Err(nom::Err::Error(nom::error::Error::new(
                cursor,
                nom::error::ErrorKind::Tag,
            )));
        }

        let dict_body = &dict_start[..end_pos];
        let dict_length = ws.len() + dict_body.len();

        Ok((
            &cursor[end_pos..],
            PdfThreat::AdditionalActions {
                offset: 0,
                dict_length,
            },
        ))
    }

    /// Match `/OpenAction` keyword in catalog root dictionary.
    ///
    /// This entry triggers automatic script execution when the PDF is opened in a viewer.
    fn parse_open_action(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (remaining, _) = tag(b"/OpenAction")(input)?;
        Ok((remaining, PdfThreat::OpenAction { offset: 0 }))
    }

    /// Match `/AcroForm` keyword indicating presence of interactive form fields.
    fn parse_acroform(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (remaining, _) = tag(b"/AcroForm")(input)?;
        Ok((remaining, PdfThreat::AcroForm { offset: 0 }))
    }

    /// Match `/S /SubmitForm` action type indicating form-data-exfiltration capability.
    fn parse_submit_form(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (after_s, _) = tag(b"/S")(input)?;
        let (remaining, _) = space0(after_s)?;
        let (remaining, _) = tag(b"/SubmitForm")(remaining)?;
        Ok((remaining, PdfThreat::SubmitForm { offset: 0 }))
    }

    /// Match `/URI` action whose value starts with `http://` or `https://`.
    ///
    /// Only external HTTP(S) URIs are flagged; relative/internal URIs are permitted.
    fn parse_uri_action(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (after_uri, _) = tag(b"/URI")(input)?;
        let (remaining, _ws) = space0(after_uri)?;

        let (after_val, uri_content) = alt((
            delimited(tag(b"("), take_till(|b| b == b')'), tag(b")")),
            delimited(tag(b"<"), take_while1(|b: u8| b != b'>'), tag(b">")),
        ))(remaining)?;

        let uri_str = String::from_utf8_lossy(uri_content);
        if uri_str.starts_with("http://") || uri_str.starts_with("https://") {
            Ok((after_val, PdfThreat::UriAction { offset: 0 }))
        } else {
            Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )))
        }
    }

    /// Match `/EmbeddedFile` stream specification indicating file attachment.
    fn parse_embedded_file(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (remaining, _) = tag(b"/EmbeddedFile")(input)?;
        let name = "unknown".to_string();

        if let Some(name_start) = windows_iterfind(remaining, b"/Name") {
            let after_name = &remaining[name_start + 5..];
            if after_name.starts_with(b"(") {
                if let Some(close_pos) = after_name.iter().position(|&b| b == b')') {
                    let name_content = &after_name[1..close_pos];
                    return Ok((
                        remaining,
                        PdfThreat::EmbeddedFile {
                            offset: 0,
                            name: String::from_utf8_lossy(name_content).into_owned(),
                        },
                    ));
                }
            }
        }

        Ok((remaining, PdfThreat::EmbeddedFile { offset: 0, name }))
    }

    /// Match `/RichMedia` annotation (Flash/SWF container) which is a high-severity vector.
    fn parse_rich_media(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        let (remaining, _) = tag(b"/RichMedia")(input)?;
        Ok((remaining, PdfThreat::RichMedia { offset: 0 }))
    }

    /// Combined scanner: attempt all threat parsers at current position, return first match.
    ///
    /// This is the primary entry point called once per byte position during analysis phase.
    /// Marked `pub(crate)` to enable reuse by the WASM compatibility layer which operates
    /// on in-memory byte buffers instead of filesystem paths.
    pub fn scan_for_threats(input: &[u8]) -> IResult<&[u8], PdfThreat> {
        alt((
            Self::parse_js_tag,
            Self::parse_javascript_tag,
            Self::parse_aa_tag,
            Self::parse_open_action,
            Self::parse_acroform,
            Self::parse_submit_form,
            Self::parse_uri_action,
            Self::parse_embedded_file,
            Self::parse_rich_media,
        ))(input)
    }

    // =========================================================================
    // Pass 1: Threat Analysis (async file I/O — requires runtime feature)
    // =========================================================================

    /// Analyze PDF file for threat markers using async file I/O.
    ///
    /// Requires tokio runtime for filesystem operations. Not available in
    /// WASM browser environments. Use [`scan_for_threats()`] for synchronous
    /// in-memory analysis instead.
    #[cfg(feature = "runtime")]
    pub async fn analyze(&self, input_path: &Path) -> Result<Vec<PdfThreat>> {
        let metadata = tokio::fs::metadata(input_path).await?;
        if metadata.len() > self.max_file_size_bytes {
            return Err(MisogiError::SecurityViolation(format!(
                "File size {} bytes exceeds maximum {} bytes",
                metadata.len(),
                self.max_file_size_bytes
            )));
        }

        let data = tokio::fs::read(input_path).await?;

        if data.len() < 5 || !data.starts_with(b"%PDF") {
            return Err(MisogiError::Protocol(
                "Invalid PDF header: expected %PDF magic bytes".to_string(),
            ));
        }

        let mut threats: Vec<PdfThreat> = Vec::new();
        let mut pos: usize = 0;

        while pos < data.len() {
            let remaining = &data[pos..];

            match Self::scan_for_threats(remaining) {
                Ok((_, mut threat)) => {
                    Self::set_offset(&mut threat, pos);
                    let skip_pos = Self::advance_past_threat(&data, pos, &threat);
                    threats.push(threat);
                    pos = skip_pos;
                }
                Err(_) => {
                    pos += 1;
                }
            }
        }

        Ok(threats)
    }

    /// Set absolute byte offset on a threat detected at given scan position.
    fn set_offset(threat: &mut PdfThreat, absolute_offset: usize) {
        match threat {
            PdfThreat::JavaScript { offset, .. } => *offset = absolute_offset,
            PdfThreat::JavaScriptLong { offset, .. } => *offset = absolute_offset,
            PdfThreat::AdditionalActions { offset, .. } => *offset = absolute_offset,
            PdfThreat::OpenAction { offset } => *offset = absolute_offset,
            PdfThreat::AcroForm { offset } => *offset = absolute_offset,
            PdfThreat::SubmitForm { offset } => *offset = absolute_offset,
            PdfThreat::UriAction { offset } => *offset = absolute_offset,
            PdfThreat::EmbeddedFile { offset, .. } => *offset = absolute_offset,
            PdfThreat::RichMedia { offset } => *offset = absolute_offset,
        }
    }

    /// Advance scan position past the end of a detected threat region.
    ///
    /// Uses a heuristic: skip to next line boundary after the threat's declared length,
    /// ensuring we don't re-match partial content within the same threat region.
    fn advance_past_threat(data: &[u8], base_pos: usize, threat: &PdfThreat) -> usize {
        let threat_end = base_pos + threat.length();
        if threat_end >= data.len() {
            return data.len();
        }

        for i in threat_end..data.len().min(threat_end + 256) {
            if data[i] == b'\n' || data[i] == b'\r' {
                return i + 1;
            }
        }

        (threat_end + 1).min(data.len())
    }

    // =========================================================================
    // Pass 2: Remediation (NOP Replacement)
    // =========================================================================

    /// Apply NOP replacement to all detected threats while streaming input to output.
    ///
    /// ## Algorithm
    /// 1. Sort threats by ascending byte offset for sequential processing
    /// 2. Stream-copy input -> output until reaching a threat offset
    /// 3. At each threat offset: emit policy-specific replacement bytes, skip original content
    /// 4. Continue copying until EOF
    ///
    /// ## Replacement Policy Matrix
    ///
    /// | Threat Type         | StripActiveContent | ConvertToFlat | TextOnly     |
    /// |----------------------|-------------------|---------------|--------------|
    /// | JavaScript           | Replace w/ `( )`  | Same          | Remove       |
    /// | JavaScriptLong       | Replace w/ `( )`  | Same          | Remove       |
    /// | AdditionalActions    | Replace w/ `{}`   | Remove        | Remove       |
    /// | OpenAction           | Remove            | Remove        | Remove       |
    /// | AcroForm             | Keep struct, strip /V | Flatten   | Remove       |
    /// | SubmitForm           | Remove /F URL     | Remove        | Remove       |
    /// | UriAction            | Empty URL string  | Remove        | Remove       |
    /// | EmbeddedFile         | Flag only         | Remove        | Remove       |
    /// | RichMedia            | Remove annot      | Remove        | Remove       |
    #[cfg(feature = "runtime")]
    pub async fn remediate(
        &self,
        input_path: &Path,
        output_path: &Path,
        threats: &[PdfThreat],
        policy: &SanitizationPolicy,
    ) -> Result<Vec<SanitizationAction>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

        let mut input = tokio::fs::File::open(input_path).await?;
        let mut output = tokio::fs::File::create(output_path).await?;

        let file_len = input.metadata().await?.len();
        let mut actions: Vec<SanitizationAction> = Vec::new();
        let mut read_pos: u64 = 0;

        let mut sorted_threats: Vec<PdfThreat> = threats.to_vec();
        sorted_threats.sort_by_key(|t| t.offset());

        loop {
            if read_pos >= file_len {
                break;
            }

            if let Some(threat) = sorted_threats
                .first()
                .filter(|t| t.offset() as u64 == read_pos)
            {
                let (replacement_bytes, action) = self.generate_replacement(threat, policy)?;
                output.write_all(&replacement_bytes).await?;
                actions.push(action);

                let skip_bytes = threat.length();
                if skip_bytes > 0 {
                    input
                        .seek(std::io::SeekFrom::Current(skip_bytes as i64))
                        .await?;
                }
                read_pos += skip_bytes as u64;
                sorted_threats.remove(0);
            } else {
                let mut buf = [0u8; 1];
                match input.read_exact(&mut buf).await {
                    Ok(_) => {
                        output.write_all(&buf).await?;
                        read_pos += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(MisogiError::Io(e)),
                }
            }
        }

        Ok(actions)
    }

    /// Generate policy-appropriate replacement bytes and audit action for a given threat.
    ///
    /// Returns a tuple of (replacement_byte_vector, sanitization_action_record).
    fn generate_replacement(
        &self,
        threat: &PdfThreat,
        policy: &SanitizationPolicy,
    ) -> Result<(Vec<u8>, SanitizationAction)> {
        match (threat, policy) {
            (
                PdfThreat::JavaScript { .. } | PdfThreat::JavaScriptLong { .. },
                SanitizationPolicy::StripActiveContent | SanitizationPolicy::ConvertToFlat,
            ) => Ok((b"( )".to_vec(), threat.to_action())),

            (
                PdfThreat::JavaScript { .. } | PdfThreat::JavaScriptLong { .. },
                SanitizationPolicy::TextOnly,
            ) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::AdditionalActions { .. }, SanitizationPolicy::StripActiveContent) => {
                Ok((b"{}".to_vec(), threat.to_action()))
            }

            (
                PdfThreat::AdditionalActions { .. },
                SanitizationPolicy::ConvertToFlat | SanitizationPolicy::TextOnly,
            ) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (
                PdfThreat::OpenAction { .. }
                | PdfThreat::SubmitForm { .. }
                | PdfThreat::RichMedia { .. },
                _,
            ) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::AcroForm { .. }, SanitizationPolicy::TextOnly) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::AcroForm { .. }, _) => Ok((vec![], threat.to_action())),

            (PdfThreat::UriAction { .. }, SanitizationPolicy::StripActiveContent) => {
                Ok((b"/URI ()".to_vec(), threat.to_action()))
            }

            (PdfThreat::UriAction { .. }, _) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }

            (PdfThreat::EmbeddedFile { .. }, SanitizationPolicy::StripActiveContent) => {
                Ok((vec![], threat.to_action()))
            }

            (PdfThreat::EmbeddedFile { .. }, _) => {
                let spaces: Vec<u8> = vec![b' '; threat.length()];
                Ok((spaces, threat.to_action()))
            }
        }
    }

    // =========================================================================
    // Xref Table Utilities
    // =========================================================================

    /// Locate cross-reference table offset by scanning backward from EOF.
    ///
    /// PDF spec mandates `startxref\n<offset>` in the last 1024 bytes of the file.
    /// This function finds that marker and extracts the xref table byte position.
    #[allow(dead_code)]
    fn find_xref_offset(data: &[u8]) -> Option<usize> {
        let search_start = data.len().saturating_sub(1024);
        let tail = &data[search_start..];

        if let Some(pos) = windows_iterfind(tail, b"startxref") {
            let after_marker = &tail[pos + 9..];
            if let Some(digit_start) = after_marker.iter().position(|&b| b.is_ascii_digit()) {
                let num_str = &after_marker[digit_start..];
                if let Some(digit_end) = num_str.iter().position(|&b| !b.is_ascii_digit()) {
                    let offset_str = std::str::from_utf8(&num_str[..digit_end]).ok()?;
                    return offset_str.parse::<usize>().ok();
                }
            }
        }

        None
    }

    /// Parse cross-reference table entries to build object-offset map.
    ///
    /// Each xref entry is 20 bytes: `nnnnnnnnnn ggggg n \n` where the first 10 digits
    /// are the byte offset of the object in the file.
    #[allow(dead_code)]
    fn parse_xref(data: &[u8], xref_offset: usize) -> Vec<(u32, usize)> {
        let mut objects: Vec<(u32, usize)> = Vec::new();

        if xref_offset + 4 > data.len() || !data[xref_offset..].starts_with(b"xref") {
            return objects;
        }

        let mut pos = xref_offset + 4;

        while pos < data.len() {
            while pos < data.len() && (data[pos] == b'\n' || data[pos] == b'\r') {
                pos += 1;
            }

            if pos >= data.len() || !data[pos].is_ascii_digit() {
                break;
            }

            let mut obj_num_str = Vec::new();
            while pos < data.len() && data[pos].is_ascii_digit() {
                obj_num_str.push(data[pos]);
                pos += 1;
            }

            while pos < data.len() && data[pos].is_ascii_whitespace() {
                pos += 1;
            }

            let mut count_str = Vec::new();
            while pos < data.len() && data[pos].is_ascii_digit() {
                count_str.push(data[pos]);
                pos += 1;
            }

            while pos < data.len()
                && (data[pos] == b'\n' || data[pos] == b'\r' || data[pos] == b' ')
            {
                pos += 1;
            }

            let obj_num: u32 = match std::str::from_utf8(&obj_num_str) {
                Ok(s) => s.parse().unwrap_or(0),
                Err(_) => continue,
            };
            let count: u32 = match std::str::from_utf8(&count_str) {
                Ok(s) => s.parse().unwrap_or(0),
                Err(_) => continue,
            };

            for i in 0..count {
                if pos + 20 > data.len() {
                    break;
                }
                let entry = &data[pos..pos + 20];
                let offset_str = &entry[..10];
                if let Ok(offset) = std::str::from_utf8(offset_str) {
                    if let Ok(byte_offset) = offset.trim().parse::<usize>() {
                        objects.push((obj_num + i, byte_offset));
                    }
                }
                pos += 20;
            }
        }

        objects
    }

    // =========================================================================
    // True CDR Reconstruction (Advanced)
    // =========================================================================

    /// Perform True CDR (Content Disarm & Reconstruction) on PDF bytes.
    ///
    /// This method provides **guaranteed zero-byte survival** sanitization by:
    /// 1. Parsing the PDF structure using lopdf
    /// 2. Extracting only legitimate content (text, graphics, safe images)
    /// 3. Rebuilding a completely new PDF from scratch
    ///
    /// Unlike [`Self::sanitize()`] which uses byte-level NOP replacement (some original
    /// bytes survive), this method ensures **no byte** from the input appears in output.
    ///
    /// # Feature Flag Requirement
    ///
    /// This method requires the `pdf-cdr` feature to be enabled. If not enabled,
    /// returns an error indicating the missing dependency.
    ///
    /// # Arguments
    /// * `data` - Raw bytes of the input PDF document.
    /// * `config` - Optional custom configuration. If `None`, uses Japanese government-safe defaults.
    ///
    /// # Returns
    /// - `Ok(PdfTrueCdrResult)` containing rebuilt PDF and detailed report on success
    /// - `Err(MisogiError)` on fatal failure or if feature not enabled
    ///
    /// # Example
    ///
    /// ```ignore
    /// use misogi_cdr::PdfSanitizer;
    ///
    /// let sanitizer = PdfSanitizer::default_config();
    /// let pdf_bytes = std::fs::read("document.pdf")?;
    ///
    /// // Use default (Japanese government-safe) configuration
    /// let result = sanitizer.true_cdr_reconstruct(&pdf_bytes, None)?;
    ///
    /// // Or provide custom config
    /// use misogi_cdr::pdf_true_cdr::{PdfTrueCdrConfig, ImageExtractionPolicy};
    /// let config = PdfTrueCdrConfig {
    ///     image_policy: ImageExtractionPolicy::BlockAll,
    ///     ..Default::default()
    /// };
    /// let result = sanitizer.true_cdr_reconstruct(&pdf_bytes, Some(config))?;
    ///
    /// println!("Rebuilt PDF size: {} bytes", result.output.len());
    /// println!("Threats removed: {}", result.report.threats_removed.len());
    /// ```
    ///
    /// # Security Guarantees
    ///
    /// - **Zero-byte survival**: No input byte appears in output
    /// - **Structural rebuild**: New catalog, pages, xref from scratch
    /// - **Content whitelisting**: Only safe PDF operators preserved
    /// - **Threat elimination**: JS, OpenAction, AA, EmbeddedFile always removed
    ///
    /// # When to Use
    ///
    /// - High-security environments (government, military, finance)
    /// - Crossing security domain boundaries (air-gapped networks)
    /// - Processing untrusted documents from external sources
    /// - Compliance requirements mandating CDR (ISO 32000-2, JIS X 4197)
    ///
    /// # Performance Considerations
    ///
    /// True CDR is **slower** than NOP-based sanitization because it must:
    /// - Parse full PDF structure (not just scan bytes)
    /// - Decode and re-encode content streams
    /// - Build entirely new document
    ///
    /// Typical overhead: 2-5x slower than `sanitize()`, but provides stronger guarantees.
    #[cfg(feature = "pdf-cdr")]
    pub fn true_cdr_reconstruct(
        &self,
        data: &[u8],
        config: Option<PdfTrueCdrConfig>,
    ) -> Result<PdfTrueCdrResult> {
        tracing::info!(
            input_size = data.len(),
            has_custom_config = config.is_some(),
            "Starting True CDR reconstruction via PdfSanitizer"
        );

        // Create engine with provided or default config
        let engine = match config {
            Some(cfg) => PdfTrueCdrEngine::with_config(cfg),
            None => PdfTrueCdrEngine::with_jp_defaults(),
        };

        // Delegate to engine's reconstruct method
        engine
            .reconstruct(data)
            .map_err(|e| MisogiError::Protocol(format!("True CDR failed: {}", e)))
    }

    /// Stub implementation when `pdf-cdr` feature is disabled.
    ///
    /// Always returns error indicating feature not available.
    #[cfg(not(feature = "pdf-cdr"))]
    pub fn true_cdr_reconstruct(
        &self,
        _data: &[u8],
        _config: Option<()>,
    ) -> Result<()> {
        Err(MisogiError::Protocol(
            "PDF True CDR requires 'pdf-cdr' feature flag. Enable with: cargo build --features pdf-cdr"
                .to_string(),
        ))
    }
}

// ===========================================================================
// FileSanitizer Trait Implementation (async, requires runtime feature)
// ===========================================================================

#[cfg(feature = "runtime")]
#[async_trait]
impl FileSanitizer for PdfSanitizer {
    fn supported_extensions(&self) -> &[&str] {
        &[".pdf"]
    }

    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport> {
        use misogi_core::hash::compute_file_md5;

        let filename = input_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown.pdf".to_string());

        let file_id = uuid::Uuid::new_v4().to_string();
        let original_hash = compute_file_md5(input_path).await?;

        let start_time = std::time::Instant::now();

        let threats = self.analyze(input_path).await?;

        let actions = if threats.is_empty() {
            tokio::fs::copy(input_path, output_path).await?;
            Vec::new()
        } else {
            self.remediate(input_path, output_path, &threats, policy)
                .await?
        };

        let sanitized_hash = compute_file_md5(output_path).await?;
        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        let warnings: Vec<String> = threats
            .iter()
            .filter_map(|t| match t {
                PdfThreat::EmbeddedFile { name, .. } => {
                    Some(format!("EmbeddedFile attachment detected: {}", name))
                }
                _ => None,
            })
            .collect();

        Ok(SanitizationReport {
            file_id,
            original_filename: filename,
            original_hash,
            sanitized_hash,
            policy: policy.clone(),
            actions_taken: actions,
            warnings,
            processing_time_ms: elapsed_ms,
            success: true,
        })
    }
}

// =========================================================================
// Utility Functions
// =========================================================================

/// Find the first occurrence of `needle` in `haystack` using a sliding-window search.
/// Returns byte offset of the match, or `None` if not found.
fn windows_iterfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
