//! Constants, thresholds, and security pattern definitions for OOXML True CDR.

/// Default maximum file size for OOXML processing (100 MB).
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum allowed ZIP bomb expansion ratio (10x).
pub const MAX_ZIP_EXPANSION_RATIO: u64 = 10;

/// Stream buffer size for copying ZIP entries.
#[allow(dead_code)]
pub const STREAM_BUFFER_SIZE: usize = 8192;

/// Known dangerous entry patterns to skip entirely.
pub const DANGEROUS_ENTRY_PATTERNS: &[&str] = &[
    "vbaProject.bin",
    "vbaData.xml",
    "activeX",
    "activex",
    "oleObject",
    "oleObject.bin",
];

/// Content type strings that indicate macro/ActiveX/OLE functionality.
pub const DANGEROUS_CONTENT_TYPES: &[&str] = &[
    // VBA macro project
    "application/vnd.ms-office.vbaProject",
    // ActiveX controls
    "application/vnd.ms-office.activeX",
    "application/vnd.ms-office.activeX+xml",
    // OLE embeddings
    "application/vnd.ms-office.oleObject",
    "application/vnd.ms-office.oleObject+xml",
    // Custom XML data parts (potential script injection)
    "application/xml",
];

/// Dangerous XML attribute names to strip from all elements.
pub const DANGEROUS_ATTRIBUTES: &[&str] = &[
    "onload", "onclick", "onmouseover", "onmouseout", "onfocus", "onblur",
    "onchange", "onsubmit", "onreset", "onkeydown", "onkeyup", "onkeypress",
    "onerror", "onabort", "ondrag", "ondrop", "onscroll", "onresize",
    "w:macro", "w:macroName", "w:macroEnabled",
    "o:cmd", "o:ole", "o:object",
    "javascript:", "vbscript:", "data:",
];

// =============================================================================
// Threat Detection Patterns
// =============================================================================

/// DDE (Dynamic Data Exchange) attack payload patterns.
///
/// These patterns detect malicious formula-based code execution vectors
/// commonly used in Excel-based malware campaigns. When a cell value or
/// formula matches any of these patterns, it indicates an attempt to
/// execute arbitrary commands via the DDE protocol.
///
/// # References
///
/// - CVE-2017-0199 / CVE-2017-11882 — DDE-based code execution
/// - MITRE ATT&CK T1059 (Command and Scripting Interpreter)
pub const DDE_PATTERNS: &[&str] = &[
    r"(?i)=CMD\|",       // DDE command execution via CMD pipe
    r"(?i)=EXEC\(",      // DDE EXEC function call (parenthesis escaped for regex)
    r"(?i)=MSQUERY",     // MSQUERY external data query (code exec vector)
];

/// Blocked URL protocols for hyperlink/external reference validation.
///
/// These protocols are known to enable script execution or local file access
/// when used as hyperlink targets or external reference URLs within OOXML
/// documents. Any reference using these protocols is stripped.
pub const BLOCKED_URL_PROTOCOLS: &[&str] = &[
    "file://",
    "javascript:",
    "vbscript:",
    "data:",
];

/// Script injection patterns for deep-scanning text content fields.
///
/// Used to detect embedded script commands in instrText (Word), cmd elements
/// (PowerPoint), and other text-bearing elements that could be abused for
/// code execution beyond traditional VBA macros.
pub const SCRIPT_INJECTION_PATTERNS: &[&str] = &[
    r"(?i)powershell",
    r"(?i)cmd\.exe",
    r"(?i)cmd /c",
    r"(?i)cmd /k",
    r"(?i)vbscript:",
    r"(?i)jscript:",
    r"(?i)wscript\.shell",
    r"(?i)shell\.execute",
    r"(?i)eval\s*\(",
    r"(?i)document\.write",
];

// =============================================================================
// Element Whitelists (Static Definitions)
// =============================================================================

/// Elements allowed in word/document.xml body content.
///
/// This whitelist follows ECMA-376 Part 1 (OOXML specification) and removes:
/// - `w:mc` (AlternateContent) — can hide macros
/// - `w:sdt` (Structured Document Tags) — can embed executable content
/// - `v:*` namespace elements (VML legacy markup) — frequently abused
/// - Any element with `w:macroAttr` or similar macro-related attributes
/// - `o:*` namespace elements (Office OLE embeddings)
pub const DOCX_BODY_WHITELIST: &[&str] = &[
    // Document root and body structure (both prefixed and unprefixed for compatibility)
    "w:document", "document",
    "w:body", "body",
    // Paragraph and run structure
    "w:p", "p", "w:r", "r", "w:t", "t", "w:br", "br", "w:tab", "tab", "w:cr", "cr",
    // Properties
    "w:pPr", "pPr", "w:rPr", "rPr", "w:rStyle", "rStyle", "w:pStyle", "pStyle",
    // Character formatting
    "w:b", "b", "w:i", "i", "w:u", "u", "w:strike", "strike", "w:vertAlign", "vertAlign",
    "w:ins", "ins", "w:del", "del", "w:sz", "sz", "w:szCs", "szCs", "w:color", "color",
    "w:highlight", "highlight", "w:lang", "lang", "w:rFonts", "rFonts",
    // Drawings and images (safe subset)
    "w:drawing", "drawing", "wp:inline", "inline", "wp:anchor", "anchor",
    "a:blip", "blip", "pic:pic", "pic", "a:xfrm", "xfrm", "a:off", "off", "a:ext", "ext", "a:prstGeom", "prstGeom",
    // Tables
    "w:tbl", "tbl", "w:tr", "tr", "w:tc", "tc", "w:tblGrid", "tblGrid", "w:gridCol", "gridCol",
    "w:tblPr", "tblPr", "w:tblCellMar", "tblCellMar", "w:tcPr", "tcPr",
    // Hyperlinks (kept but target validated separately)
    "w:hyperlink", "hyperlink",
    // Section properties
    "w:sectPr", "sectPr", "w:pgSz", "pgSz", "w:pgMar", "pgMar",
    "w:headerReference", "headerReference", "w:footerReference", "footerReference",
    // Numbering and lists
    "w:numPr", "numPr", "w:ilvl", "ilvl", "w:numId", "numId", "w:spacing", "spacing",
    // Fields (simple fields only, no macros)
    "w:fldChar", "fldChar", "w:instrText", "instrText", "w:fldData", "fldData",
    // Breaks and spacing
    "w:jc", "jc", "w:ind", "ind", "w:pBdr", "pBdr", "w:shd", "shd",
    // Math (OfficeMath ML — safe subset)
    "m:oMath", "oMath", "m:oMathPara", "oMathPara", "m:f", "f", "m:num", "num", "m:den", "den", "m:rad", "rad", "m:sSup", "sSup", "m:sSub", "sSub",
];

/// Elements allowed in SpreadsheetML worksheet content.
///
/// Removes:
/// - `pivotTable` / `pivotCache` — can reference external data sources
/// - `externalReference` — obvious external data connection
/// - `ddeLink` — Dynamic Data Exchange (DDE), a code execution vector!
/// - Any element referencing macros or scripts
pub const XLSX_SHEET_WHITELIST: &[&str] = &[
    // Root element
    "worksheet",
    // Core worksheet structure
    "sheetData", "row", "c", "v", "f",
    // Cell content types
    "is", "t", "s", "r", "definedName",
    // Merged cells
    "mergeCell", "mergeCells",
    // Column dimensions
    "col", "cols",
    // Sheet properties
    "sheetFormatPr", "sheetViews", "sheetView",
    "sheetPr", "tabColor", "outlinePr", "pageSetUpPr",
    // Data validation (safe — no code execution)
    "dataValidations", "dataValidation",
    // Conditional formatting (safe)
    "conditionalFormatting", "cfRule",
    // Sorting and filtering (safe)
    "autoFilter", "sortState", "sortCondition", "filterColumn",
    // Print settings
    "printOptions", "pageMargins", "pageSetup",
    "headerFooter", "oddHeader", "oddFooter",
    // Dimension
    "dimension",
    // Protection (view-only, not macro-related)
    "sheetProtection",
    // Sparklines (safe inline charts)
    "sparklineGroups", "sparklineGroup", "sparklines", "sparkline",
];

/// Elements allowed in PresentationML slide content.
///
/// Removes:
/// - ActiveX control references
/// - OLE object embeddings
/// - Media elements with external script URLs
/// - Any element capable of executing code
pub const PPTX_SLIDE_WHITELIST: &[&str] = &[
    // Slide structure
    "sld", "cSld", "spTree",
    // Shapes
    "sp", "nvSpPr", "spPr", "txBody",
    "nvPr", "cNvPr", "cNvSpPr", "cNvPicPr",
    // Shape geometry
    "xfrm", "off", "ext", "prstGeom", "avLst", "gd",
    // Text runs
    "p", "r", "t", "rPr", "pPr", "endParaRPr",
    // Pictures
    "pic", "blipFill", "blip", "stretch", "fillRect",
    // Graphic frames (for charts/diagrams — safe subset)
    "graphicFrame", "graphic", "chart", "c:chart",
    // Groups
    "grpSp", "grpSpPr",
    // Connections (for connectors between shapes)
    "cxnSp", "cxnSpPr",
    // Color mappings
    "clrMapOvr", "clrMap", "srgbClr", "schemeClr",
    // Styles
    "style", "lnRef", "fillRef", "effectRef", "fontRef",
    "ln", "noFill", "solidFill", "gradFill",
    // Transitions (basic animations only)
    "transition", "snd",
    // Timing (basic animations — safe subset)
    "timing", "tnLst", "par", "cTn", "anim",
    "animEffect", "animMotion",
];
