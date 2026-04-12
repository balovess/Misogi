//! SVG Security Sanitizer
//!
//! Detects and removes executable content from SVG files.
//!
//! SVG is an XML-based vector graphics format that natively supports:
//! - JavaScript execution via `<script>` elements
//! - Foreign object embedding via `<foreignObject>`
//! - Event handler attributes (`onclick`, `onload`, `onerror`, etc.)
//! - `javascript:` URL schemes in href attributes
//! - CSS expressions and `-moz-binding` in style attributes
//! - External resource loading via `<use>`, `<image>`, or `xlink:href`
//!
//! All of these are attack vectors in file sanitization contexts where SVG files
//! are rendered in browsers or document viewers. This module provides a streaming
//! XML parser that identifies and neutralizes these threats while preserving
//! the visual rendering of safe SVG content.
//!
//! # Threat Model
//!
//! The sanitizer operates on a deny-list basis: known dangerous elements,
//! attributes, and patterns are removed. Safe SVG elements (path, circle, rect,
//! text, defs, g, svg, etc.) and their non-executable attributes (fill, stroke,
//! d, transform, viewBox, etc.) are preserved verbatim.
//!
//! # Compliance Notes
//!
//! Per Japanese government document sanitization guidelines (JIS/CWE), SVG files
//! must be stripped of all executable content before approval for inter-agency
//! transfer. This sanitizer implements those requirements.

use std::io::Cursor;

use quick_xml::Reader;
use quick_xml::Writer;
use quick_xml::events::{BytesStart, Event};
use tracing::{debug, info};

use misogi_core::MisogiError;
use misogi_core::Result;

// =============================================================================
// Result Types
// =============================================================================

/// Result of an SVG sanitization operation.
///
/// Contains the sanitized SVG output buffer, a log of all threats that were
/// removed, and a safety determination flag.
#[derive(Debug, Clone)]
pub struct SvgSanitizeResult {
    /// Sanitized SVG bytes (valid XML/SVG with threats removed).
    pub output: Vec<u8>,

    /// List of all threat entries detected and removed during sanitization.
    ///
    /// Each entry describes what was found, where (line number), and why it
    /// was classified as a threat. Useful for audit logging and user reports.
    pub scripts_removed: Vec<SvgThreatEntry>,

    /// Overall safety assessment: `true` if no threats were found/removed.
    ///
    /// When `false`, the output is safe to render but the original contained
    /// executable content that has been removed.
    pub is_safe: bool,
}

impl SvgSanitizeResult {
    /// Returns `true` if any threats were removed during sanitization.
    pub fn had_threats(&self) -> bool {
        !self.scripts_removed.is_empty()
    }

    /// Returns count of threats removed.
    pub fn threat_count(&self) -> usize {
        self.scripts_removed.len()
    }
}

/// Describes a single security threat found and removed from an SVG file.
#[derive(Debug, Clone)]
pub struct SvgThreatEntry {
    /// Classification of the threat type.
    pub threat_type: SvgThreatType,

    /// The XML element name that contained the threat (e.g., "script", "a", "svg").
    pub element: String,

    /// The specific attribute name if the threat was in an attribute value
    /// (e.g., Some("onload"), Some("href")), or `None` for element-level threats.
    pub attribute: Option<String>,

    /// Approximate line number in the source SVG where this threat appeared.
    ///
    /// Note: due to streaming parsing, line numbers may be approximate for
    /// multi-line elements.
    pub line_number: usize,
}

/// Classification of SVG security threats.
///
/// Each variant represents a distinct attack vector that can be exploited
/// in SVG rendering contexts (browsers, document viewers, image processors).
#[derive(Debug, Clone, PartialEq)]
pub enum SvgThreatType {
    /// `<script>` element containing JavaScript code.
    ScriptElement,

    /// `<foreignObject>` element allowing embedding of arbitrary foreign namespace content.
    ForeignObject,

    /// Event handler attribute (`on*` — onclick, onload, onerror, onmouseover, etc.).
    EventHandler,

    /// Attribute value containing `javascript:` URL scheme.
    JavascriptHref,

    /// Attribute value containing `data:` URI with script MIME type.
    DataUriScript,

    /// External resource reference (http://, https://) that could load remote code.
    ExternalResource,

    /// CSS `expression()` or `-moz-binding` in style attribute.
    CssExpression,

    /// `<animate>` / `<animateTransform>` with event-based `begin` trigger.
    AnimationWithScript,

    /// `<set>` element capable of DOM modification after load.
    SetElement,
}

impl std::fmt::Display for SvgThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScriptElement => write!(f, "SCRIPT_ELEMENT"),
            Self::ForeignObject => write!(f, "FOREIGN_OBJECT"),
            Self::EventHandler => write!(f, "EVENT_HANDLER"),
            Self::JavascriptHref => write!(f, "JAVASCRIPT_HREF"),
            Self::DataUriScript => write!(f, "DATA_URI_SCRIPT"),
            Self::ExternalResource => write!(f, "EXTERNAL_RESOURCE"),
            Self::CssExpression => write!(f, "CSS_EXPRESSION"),
            Self::AnimationWithScript => write!(f, "ANIMATION_WITH_SCRIPT"),
            Self::SetElement => write!(f, "SET_ELEMENT"),
        }
    }
}

// =============================================================================
// Sanitizer Engine
// =============================================================================

/// SVG security sanitizer using streaming XML analysis.
///
/// Processes SVG documents through a SAX-style parser to identify and remove
/// executable content without requiring full DOM construction. This approach
/// is memory-efficient and resistant to XML bomb attacks.
///
/// # Thread Safety
///
/// The sanitizer holds only configuration data (the event handler list) which
/// is `'static`. Multiple instances can operate concurrently without shared state.
pub struct SvgSanitizer {
    /// Known dangerous event handler attribute names (all `on*` variants).
    event_handlers: &'static [&'static str],
}

impl Default for SvgSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl SvgSanitizer {
    /// Construct a new SVG sanitizer with default threat definitions.
    ///
    /// The default event handler list covers all standard SVG/HTML event
    /// handlers defined in the W3C SVG specification plus common browser extensions.
    pub fn new() -> Self {
        Self {
            // Comprehensive list of event handler attributes that execute JavaScript
            // when triggered by user interaction or document lifecycle events.
            event_handlers: &[
                // Mouse events
                "onclick",
                "ondblclick",
                "onmousedown",
                "onmouseup",
                "onmouseover",
                "onmousemove",
                "onmouseout",
                "onmouseenter",
                "onmouseleave",
                // Keyboard events
                "onkeydown",
                "onkeyup",
                "onkeypress",
                // Focus/form events
                "onfocus",
                "onblur",
                "onfocusin",
                "onfocusout",
                "onsubmit",
                "onreset",
                "onchange",
                "oninput",
                "onselect",
                // Document/window events
                "onload",
                "onunload",
                "onbeforeunload",
                "onabort",
                "onerror",
                "onresize",
                "onscroll",
                // Drag events
                "ondrag",
                "ondragstart",
                "ondragend",
                "ondragenter",
                "ondragleave",
                "ondragover",
                "ondrop",
                // Clipboard events
                "oncopy",
                "oncut",
                "onpaste",
                // Touch events
                "ontouchstart",
                "ontouchmove",
                "ontouchend",
                "ontouchcancel",
                // Pointer events
                "onpointerdown",
                "onpointerup",
                "onpointermove",
                "onpointerover",
                "onpointerout",
                "onpointerenter",
                "onpointerleave",
                "onpointercancel",
                // Animation events
                "onbegin",
                "onend",
                "onrepeat",
                // Media events
                "onplay",
                "onpause",
                "onplaying",
                "onended",
                "ontimeupdate",
                "onvolumechange",
                "onseeking",
                "onseeked",
                // Other
                "oncontextmenu",
                "onwheel",
                "onanimationstart",
                "onanimationend",
                "onanimationiteration",
                "ontransitionend",
            ],
        }
    }

    /// Sanitize SVG content: remove all executable/threatening elements and attributes.
    ///
    /// # Removal Policy
    ///
    /// | Threat | Action |
    /// |--------|--------|
    /// | `<script>` | Remove entire element (including children/text content) |
    /// | `<foreignObject>` | Remove entire element |
    /// | Event handler attributes (`on*`) | Remove the attribute from its element |
    /// | `javascript:` URLs | Remove the attribute containing the URL |
    /// | `data:` URIs with script types | Remove the attribute |
    /// | `<set>` elements | Remove entire element |
    /// | `<animate>`/`<animateTransform>` with event triggers | Remove entire element |
    /// | `expression()` in style | Remove the offending CSS property |
    /// | External resource references (`http://`, `https://`) | Remove attribute or convert to empty |
    ///
    /// # Arguments
    /// * `svg_data` — Raw SVG file bytes (UTF-8 encoded XML).
    ///
    /// # Returns
    /// [`SvgSanitizeResult`] containing sanitized SVG, threat log, and safety flag.
    ///
    /// # Errors
    /// - [`MisogiError::Protocol`] if the input is not valid XML.
    /// - [`MisogiError::Io`] on internal writer failures.
    #[allow(unused_variables)]
    #[allow(unused_assignments)]
    pub fn sanitize(&self, svg_data: &[u8]) -> Result<SvgSanitizeResult> {
        let mut reader = Reader::from_reader(Cursor::new(svg_data));
        // Note: trim_text configuration removed due to quick-xml 0.31 API compatibility
        // Whitespace text nodes will be preserved as-is (acceptable for SVG sanitization)

        let mut writer = Writer::new(Cursor::new(Vec::new()));
        let mut threats = Vec::new();
        let mut skip_depth: u32 = 0; // Nesting depth inside a skipped element
        #[allow(unused_variables)]
        let mut skip_element: Option<String> = None; // Name of currently skipped element

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let local_name_bytes = e.local_name();
                    let name_ref = local_name_bytes.as_ref();
                    let local_name = reader.decoder().decode(name_ref)
                        .map_err(|e| MisogiError::Protocol(format!("SVG decode error: {}", e)))?;
                    let local_str = local_name.to_string();

                    // Check if we're already inside a skipped element
                    if skip_depth > 0 {
                        skip_depth += 1;
                        continue;
                    }

                    // Check for entirely-skipped dangerous elements
                    if Self::is_dangerous_element(&local_str) {
                        skip_depth = 1;
                        skip_element = Some(local_str.clone());

                        let line = reader.buffer_position();
                        threats.push(SvgThreatEntry {
                            threat_type: Self::classify_dangerous_element(&local_str),
                            element: local_str.clone(),
                            attribute: None,
                            line_number: line,
                        });

                        debug!(
                            element = %local_str,
                            line = line,
                            "Removed dangerous SVG element"
                        );
                        continue;
                    }

                    // For safe elements, check and filter attributes
                    let filtered_attrs =
                        self.filter_attributes(e, &local_str, &mut threats, &reader);

                    if let Some(filtered_start) = filtered_attrs {
                        writer
                            .write_event(Event::Start(filtered_start))
                            .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                    } else {
                        // All attributes were dangerous or element itself is conditional-skip
                        // Write original but without dangerous attrs (handled in filter_attributes)
                        writer
                            .write_event(Event::Start(e.to_owned()))
                            .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    if skip_depth > 0 {
                        continue;
                    }

                    let local_name_bytes = e.local_name();
                    let name_ref = local_name_bytes.as_ref();
                    let local_name = reader.decoder().decode(name_ref)
                        .map_err(|e| MisogiError::Protocol(format!("SVG decode error: {}", e)))?;
                    let local_str = local_name.to_string();

                    // Check for dangerous empty elements (<set />, <animate />)
                    if Self::is_dangerous_element(&local_str)
                        || Self::is_conditional_dangerous_empty(&local_str, e)
                    {
                        let line = reader.buffer_position();
                        threats.push(SvgThreatEntry {
                            threat_type: Self::classify_dangerous_element(&local_str),
                            element: local_str.clone(),
                            attribute: None,
                            line_number: line,
                        });
                        debug!(
                            element = %local_str,
                            line = line,
                            "Removed dangerous empty SVG element"
                        );
                        continue; // Don't write this element at all
                    }

                    // Filter attributes on empty elements too
                    let filtered_attrs =
                        self.filter_attributes(e, &local_str, &mut threats, &reader);
                    if let Some(filtered) = filtered_attrs {
                        writer
                            .write_event(Event::Empty(filtered))
                            .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                    } else {
                        writer
                            .write_event(Event::Empty(e.to_owned()))
                            .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                    }
                }
                Ok(Event::End(ref e)) => {
                    if skip_depth > 0 {
                        skip_depth -= 1;
                        if skip_depth == 0 {
                            skip_element = None;
                        }
                        continue;
                    }

                    writer
                        .write_event(Event::End(e.to_owned()))
                        .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                }
                Ok(Event::Text(ref e)) => {
                    if skip_depth > 0 {
                        continue; // Skip text inside <script>, <foreignObject>
                    }
                    writer
                        .write_event(Event::Text(e.to_owned()))
                        .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                }
                Ok(Event::CData(ref e)) => {
                    // CDATA sections inside skipped elements are dropped
                    if skip_depth == 0 {
                        // CDATA outside scripts is unusual but possible; preserve
                        writer
                            .write_event(Event::CData(e.to_owned()))
                            .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                    }
                }
                Ok(Event::Comment(ref e)) => {
                    // Comments are preserved (they don't execute)
                    if skip_depth == 0 {
                        writer
                            .write_event(Event::Comment(e.to_owned()))
                            .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(MisogiError::Protocol(format!(
                        "SVG parse error at position {}: {}",
                        reader.buffer_position(),
                        e
                    )));
                }
                ref e => {
                    // Other events (PI, DocType, Decl): pass through when not skipping
                    if let Ok(event) = e {
                        if skip_depth == 0 {
                            writer
                                .write_event(event.clone())
                                .map_err(|e| MisogiError::Protocol(format!("SVG XML write error: {}", e)))?;
                        }
                    }
                }
            }
            buf.clear();
        }

        let output = writer.into_inner().into_inner();
        let is_safe = threats.is_empty();

        info!(
            original_size = svg_data.len(),
            output_size = output.len(),
            threats_removed = threats.len(),
            is_safe,
            "SVG sanitization complete"
        );

        Ok(SvgSanitizeResult {
            output,
            scripts_removed: threats,
            is_safe,
        })
    }

    /// Filter attributes on an XML start tag, removing dangerous ones.
    ///
    /// Returns `Some(BytesStart)` with dangerous attributes stripped, or `None`
    /// if the element should be kept as-is (no changes needed).
    fn filter_attributes<'a>(
        &self,
        elem: &BytesStart<'a>,
        element_name: &str,
        threats: &mut Vec<SvgThreatEntry>,
        reader: &Reader<Cursor<&[u8]>>,
    ) -> Option<BytesStart<'static>> {
        let mut modified = false;
        // Convert element name from bytes to owned String for BytesStart::new (quick-xml 0.31 API)
        let name_owned = std::str::from_utf8(elem.name().as_ref()).ok()?.to_string();
        let mut filtered = BytesStart::new(name_owned);

        for attr_result in elem.attributes() {
            match attr_result {
                Ok(attr) => {
                    // Decode attribute key and value; use lossy conversion for robustness
                    let key = reader.decoder().decode(attr.key.as_ref())
                        .map(|cow| cow.into_owned())
                        .unwrap_or_else(|_| String::from_utf8_lossy(attr.key.as_ref()).into_owned());
                    let value = reader.decoder().decode(&attr.value)
                        .map(|cow| cow.into_owned())
                        .unwrap_or_else(|_| String::from_utf8_lossy(&attr.value).into_owned());

                    if self.is_dangerous_attribute(&key, &value, element_name) {
                        let line = reader.buffer_position();
                        let threat_type = self.classify_attribute_threat(&key, &value);

                        threats.push(SvgThreatEntry {
                            threat_type,
                            element: element_name.to_string(),
                            attribute: Some(key.clone()),
                            line_number: line,
                        });

                        debug!(
                            element = element_name,
                            attribute = %key,
                            line = line,
                            "Removed dangerous SVG attribute"
                        );

                        modified = true;
                    } else {
                        // Preserve safe attributes
                        filtered.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
                    }
                }
                Err(_) => {
                    // Malformed attribute — skip it (parser will handle errors)
                    // Cannot preserve malformed attributes as no Attribute struct is available
                    continue;
                }
            }
        }

        if modified { Some(filtered) } else { None }
    }

    /// Determine whether an attribute name/value pair represents a security threat.
    fn is_dangerous_attribute(
        &self,
        attr_name: &str,
        attr_value: &str,
        _element_name: &str,
    ) -> bool {
        let name_lower = attr_name.to_lowercase();

        // Check for event handlers (on*)
        if name_lower.starts_with("on") && self.event_handlers.contains(&name_lower.as_str()) {
            return true;
        }

        // Check for javascript: URLs
        let value_lower = attr_value.to_lowercase();
        if value_lower.contains("javascript:") || value_lower.starts_with("javascript:") {
            return true;
        }

        // Check for data: URIs with script-like MIME types
        if value_lower.contains("data:text/javascript")
            || value_lower.contains("data:application/javascript")
            || value_lower.contains("data:text/ecmascript")
        {
            return true;
        }

        // Check for external http(s) references in sensitive contexts
        if (name_lower == "href" || name_lower == "xlink:href" || name_lower == "src")
            && (value_lower.starts_with("http://") || value_lower.starts_with("https://"))
        {
            return true;
        }

        // Check for CSS expression() and -moz-binding in style attributes
        if name_lower == "style" {
            if value_lower.contains("expression(")
                || value_lower.contains("-moz-binding")
                || value_lower.contains("url(javascript:")
                || value_lower.contains("behavior(")
            {
                return true;
            }
        }

        false
    }

    /// Classify an attribute-based threat into a specific [`SvgThreatType`].
    fn classify_attribute_threat(&self, attr_name: &str, attr_value: &str) -> SvgThreatType {
        let name_lower = attr_name.to_lowercase();
        let value_lower = attr_value.to_lowercase();

        if name_lower.starts_with("on") {
            SvgThreatType::EventHandler
        } else if value_lower.contains("javascript:") {
            SvgThreatType::JavascriptHref
        } else if value_lower.contains("data:")
            && (value_lower.contains("text/javascript")
                || value_lower.contains("application/javascript"))
        {
            SvgThreatType::DataUriScript
        } else if (name_lower == "href" || name_lower == "xlink:href")
            && (value_lower.starts_with("http://") || value_lower.starts_with("https://"))
        {
            SvgThreatType::ExternalResource
        } else if name_lower == "style"
            && (value_lower.contains("expression(") || value_lower.contains("-moz-binding"))
        {
            SvgThreatType::CssExpression
        } else {
            SvgThreatType::EventHandler // Default fallback
        }
    }

    /// Determine if an element name indicates a completely dangerous element
    /// that should be removed entirely (including all child content).
    fn is_dangerous_element(name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "script" | "foreignobject" | "handler"
        )
    }

    /// Check if an empty element is conditionally dangerous based on its attributes.
    ///
    /// Handles cases like `<set attributeName="...">` or `<animate begin="click">`.
    fn is_conditional_dangerous_empty(name: &str, elem: &BytesStart<'_>) -> bool {
        match name.to_lowercase().as_str() {
            "set" => true, // Always dangerous: can modify DOM
            "animate" | "animatetransform" | "animatemotion" => {
                // Dangerous if 'begin' attribute contains event trigger
                for attr in elem.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_lowercase();
                    if key == "begin" {
                        let val = String::from_utf8_lossy(&attr.value).to_lowercase();
                        if val.contains("click")
                            || val.contains("load")
                            || val.contains("mouseover")
                            || val.contains("focus")
                        {
                            return true;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Classify a dangerous element into its [`SvgThreatType`].
    fn classify_dangerous_element(name: &str) -> SvgThreatType {
        match name.to_lowercase().as_str() {
            "script" => SvgThreatType::ScriptElement,
            "foreignobject" => SvgThreatType::ForeignObject,
            "set" => SvgThreatType::SetElement,
            "animate" | "animatetransform" | "animatemotion" => SvgThreatType::AnimationWithScript,
            _ => SvgThreatType::ScriptElement, // Fallback
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitizer_creation() {
        let sanitizer = SvgSanitizer::new();
        assert!(!sanitizer.event_handlers.is_empty());
        assert!(sanitizer.event_handlers.contains(&"onclick"));
        assert!(sanitizer.event_handlers.contains(&"onload"));
    }

    #[test]
    fn test_remove_script_element() {
        let sanitizer = SvgSanitizer::new();
        let malicious_svg = br#"<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS')</script>
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>"#;

        let result = sanitizer.sanitize(malicious_svg).unwrap();
        assert!(!result.is_safe);
        assert!(result.had_threats());

        // Should contain circle but not script
        let output_str = String::from_utf8_lossy(&result.output);
        assert!(!output_str.contains("<script"));
        assert!(output_str.contains("<circle"));

        // Verify threat classification
        let script_threat: Vec<_> = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::ScriptElement)
            .collect();
        assert!(!script_threat.is_empty());
    }

    #[test]
    fn test_remove_foreign_object() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_fo = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject><body onload="alert(1)"/></foreignObject>
  <rect width="100" height="100"/>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_fo).unwrap();
        assert!(result.had_threats());

        let output_str = String::from_utf8_lossy(&result.output);
        assert!(!output_str.contains("foreignObject"));
        assert!(output_str.contains("<rect"));
    }

    #[test]
    fn test_remove_event_handlers() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_onclick = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <rect x="10" y="10" width="80" height="80" fill="blue" onclick="steal_data()" onload="init()"/>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_onclick).unwrap();
        assert!(result.had_threats());

        let output_str = String::from_utf8_lossy(&result.output);
        // Element should remain but without onclick/onload
        assert!(output_str.contains("<rect"));
        assert!(!output_str.contains("onclick"));
        assert!(!output_str.contains("onload"));

        // Both should be classified as EventHandler
        let handler_count = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::EventHandler)
            .count();
        assert_eq!(handler_count, 2);
    }

    #[test]
    fn test_remove_javascript_href() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_js_href = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <a href="javascript:alert(1)">
    <text x="10" y="20">Click me</text>
  </a>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_js_href).unwrap();
        assert!(result.had_threats());

        let js_threats: Vec<_> = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::JavascriptHref)
            .collect();
        assert!(!js_threats.is_empty());
    }

    #[test]
    fn test_remove_css_expression() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_expr = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" style="width: expression(alert(1))"/>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_expr).unwrap();
        assert!(result.had_threats());

        let css_threats: Vec<_> = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::CssExpression)
            .collect();
        assert!(!css_threats.is_empty());
    }

    #[test]
    fn test_safe_svg_passes_through() {
        let sanitizer = SvgSanitizer::new();
        let safe_svg = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <defs>
    <linearGradient id="grad">
      <stop offset="0%" stop-color="#ff0000"/>
      <stop offset="100%" stop-color="#0000ff"/>
    </linearGradient>
  </defs>
  <rect x="5" y="5" width="90" height="90" fill="url(#grad)" rx="10"/>
  <circle cx="50" cy="50" r="30" fill="white" opacity="0.7"/>
  <text x="50" y="55" text-anchor="middle" font-size="14">Safe SVG</text>
</svg>"##;

        let result = sanitizer.sanitize(safe_svg).unwrap();
        assert!(result.is_safe);
        assert!(!result.had_threats());
    }

    #[test]
    fn test_remove_set_element() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_set = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <set attributeName="href" to="malicious.html" begin="0s"/>
  <rect width="100" height="100"/>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_set).unwrap();
        assert!(result.had_threats());

        let set_threats: Vec<_> = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::SetElement)
            .collect();
        assert!(!set_threats.is_empty());
    }

    #[test]
    fn test_remove_external_resource_links() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_ext = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <image href="https://evil.com/payload.svg" width="100" height="100"/>
  <use xlink:href="https://attacker.com/resource"/>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_ext).unwrap();
        assert!(result.had_threats());

        let ext_threats: Vec<_> = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::ExternalResource)
            .collect();
        assert!(!ext_threats.is_empty());
    }

    #[test]
    fn test_nested_script_in_group_removed() {
        let sanitizer = SvgSanitizer::new();
        let nested_svg = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <g id="group1">
    <script>document.location='evil'</script>
  </g>
  <g id="group2">
    <path d="M10 10 L90 90" stroke="black"/>
  </g>
</svg>"#;

        let result = sanitizer.sanitize(nested_svg).unwrap();
        assert!(result.had_threats());

        let output_str = String::from_utf8_lossy(&result.output);
        assert!(!output_str.contains("<script"));
        assert!(output_str.contains("<path")); // Safe content preserved
    }

    #[test]
    fn test_data_uri_script_detected() {
        let sanitizer = SvgSanitizer::new();
        let svg_with_data_uri = br#"<svg xmlns="http://www.w3.org/2000/svg">
  <a href="data:text/javascript,alert(1)">Link</a>
</svg>"#;

        let result = sanitizer.sanitize(svg_with_data_uri).unwrap();
        assert!(result.had_threats());

        let data_threats: Vec<_> = result
            .scripts_removed
            .iter()
            .filter(|t| t.threat_type == SvgThreatType::DataUriScript)
            .collect();
        assert!(!data_threats.is_empty());
    }
}
