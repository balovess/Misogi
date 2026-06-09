// =============================================================================
// CDR Engine v2 — Abstract Syntax Tree (AST) Representation
// =============================================================================
// This module defines the document tree structure used by CDR Engine v2 to
// represent parsed documents in a format-agnostic, hierarchical form.
//
// Design Principles:
// - The AST is a lossy representation: it captures structural and semantic
//   elements relevant to security analysis, not pixel-perfect rendering data.
// - ActiveContent nodes are first-class citizens — every piece of executable
//   content is explicitly represented, never hidden in opaque byte blobs.
// - The tree is mutable during pipeline processing: stages may add, remove,
//   or modify nodes as they apply sanitization actions.
//
// Memory Safety:
// - All string fields use owned String (no lifetimes) for AST serializability.
// - Raw active content bytes are stored as Option<Vec<u8>> — only populated
//   when deep inspection is required; None for lightweight scans.
// =============================================================================

use crate::cdr_v2::types::{ActiveContentRef, ActiveContentType, DocumentFormat, ThreatSeverity};

/// Node in the document Abstract Syntax Tree.
///
/// Each variant represents a distinct structural element that can appear
/// within a parsed document. The enum is deliberately non-exhaustive in
/// practice (Unknown variant catches unhandled element types).
#[derive(Debug, Clone)]
pub enum AstNode {
    /// Root document node containing all top-level children.
    Document {
        /// Ordered list of child nodes (pages, metadata, etc.)
        children: Vec<AstNode>,
    },

    /// A single page/sheet/slide within the document.
    Page {
        /// Zero-based page index within the document.
        index: u32,

        /// Child elements on this page.
        children: Vec<AstNode>,
    },

    /// Text content node with extracted string value.
    Text {
        /// Extracted text content (UTF-8 normalized).
        content: String,
    },

    /// Image / graphic element with dimension metadata.
    Image {
        /// Width in pixels (or points for vector formats).
        width: u32,

        /// Height in pixels (or points for vector formats).
        height: u32,

        /// Image format identifier (e.g., "png", "jpeg", "svg").
        format: String,
    },

    /// Active (potentially executable) content requiring sanitization.
    ///
    /// This is the most security-critical node type. Every instance found
    /// during parsing MUST be accounted for in the final report.
    ActiveContent {
        /// Reference linking this node to the threat intelligence record.
        #[allow(dead_code)]
        ref_item: ActiveContentRef,

        /// Raw bytes of the active content (None if not yet extracted).
        raw_data: Option<Vec<u8>>,
    },

    /// Document metadata key-value pair (author, title, creation date, etc.)
    Metadata {
        /// Metadata field name (e.g., "Title", "Author", "Creator").
        key: String,

        /// Metadata field value.
        value: String,
    },

    /// Generic container node for grouping child elements.
    Container {
        /// Semantic name of the container (e.g., "annotations", "headers").
        name: String,

        /// Child nodes within this container.
        children: Vec<AstNode>,
    },

    /// Unknown / unrecognized element type — preserved for audit fidelity.
    Unknown {
        /// Tag or element name from the source format.
        tag: String,
    },
}

impl AstNode {
    /// Count total descendant nodes including self.
    ///
    /// Used for resource-limit validation and progress estimation.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Document { children }
            | Self::Page { children, .. }
            | Self::Container { children, .. } => {
                1 + children.iter().map(|c| c.node_count()).sum::<usize>()
            }
            _ => 1,
        }
    }

    /// Collect all [`ActiveContent`] descendants into a flat vector.
    ///
    /// Performs recursive tree traversal. Returns references to the
    /// embedded `ActiveContentRef` items for threat aggregation.
    pub fn collect_active_contents(&self) -> Vec<&ActiveContentRef> {
        let mut results = Vec::new();
        self._collect_active_contents_recursive(&mut results);
        results
    }

    fn _collect_active_contents_recursive<'a>(&'a self, out: &mut Vec<&'a ActiveContentRef>) {
        match self {
            Self::ActiveContent { ref_item, .. } => {
                out.push(ref_item);
            }
            Self::Document { children }
            | Self::Page { children, .. }
            | Self::Container { children, .. } => {
                for child in children {
                    child._collect_active_contents_recursive(out);
                }
            }
            _ => {}
        }
    }

    /// Check whether this node or any descendant contains active content.
    #[must_use]
    pub fn has_active_content(&self) -> bool {
        matches!(self, Self::ActiveContent { .. })
            || match self {
                Self::Document { children }
                | Self::Page { children, .. }
                | Self::Container { children, .. } => {
                    children.iter().any(|c| c.has_active_content())
                }
                _ => false,
            }
    }
}

/// Metadata describing the original input document (not its contents).
///
/// Captured at parse time before any modification, providing provenance
/// information for the audit trail.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DocumentMetadata {
    /// Original filename as provided by the uploader (without directory path).
    pub original_filename: String,

    /// Total file size in bytes of the original (unsanitized) file.
    pub file_size_bytes: u64,

    /// Detected document format.
    pub format: DocumentFormat,

    /// ISO8601 timestamp of original file creation (from filesystem or
    /// document-internal metadata). `None` if unavailable.
    pub created_at: Option<String>,

    /// ISO8601 timestamp of last modification. `None` if unavailable.
    pub modified_at: Option<String>,
}

impl DocumentMetadata {
    /// Create new document metadata with required fields.
    #[must_use]
    pub fn new(
        original_filename: impl Into<String>,
        file_size_bytes: u64,
        format: DocumentFormat,
    ) -> Self {
        Self {
            original_filename: original_filename.into(),
            file_size_bytes,
            format,
            created_at: None,
            modified_at: None,
        }
    }

    /// Set the creation timestamp (builder pattern).
    pub fn with_created_at(mut self, ts: impl Into<String>) -> Self {
        self.created_at = Some(ts.into());
        self
    }

    /// Set the modification timestamp (builder pattern).
    pub fn with_modified_at(mut self, ts: impl Into<String>) -> Self {
        self.modified_at = Some(ts.into());
        self
    }
}

/// Top-level AST representation of a fully parsed document.
///
/// This structure is the central data object passed between CDR pipeline
/// stages. It combines the structural tree, metadata, and an indexed
/// collection of all detected active content for efficient access.
#[derive(Debug, Clone)]
pub struct DocumentAst {
    /// Format of the parsed document.
    pub format: DocumentFormat,

    /// Root node of the document tree (always a Document variant).
    pub root: AstNode,

    /// Provenance metadata captured at parse time.
    pub metadata: DocumentMetadata,

    /// Flat index of all active content references found during parsing.
    ///
    /// This redundant index enables O(1) lookups without tree traversal
    /// during policy evaluation. Kept in sync with tree modifications
    /// by pipeline stages.
    pub active_contents: Vec<ActiveContentRef>,
}

impl DocumentAst {
    /// Create a new empty document AST for the given format.
    ///
    /// Initializes with an empty Document root node and no active content.
    ///
    /// # Arguments
    /// * `format` - Detected document format.
    /// * `metadata` - Document provenance information.
    #[must_use]
    pub fn new(format: DocumentFormat, metadata: DocumentMetadata) -> Self {
        Self {
            format,
            root: AstNode::Document {
                children: Vec::new(),
            },
            metadata,
            active_contents: Vec::new(),
        }
    }

    /// Find active content references matching optional type filter.
    ///
    /// When `content_type` is `Some(t)`, returns only references whose
    /// type matches exactly. When `None`, returns all active contents.
    ///
    /// # Arguments
    /// * `content_type` - Optional filter by content type.
    ///
    /// # Returns
    /// Vector of matching `ActiveContentRef` references.
    #[must_use]
    pub fn find_active_contents(
        &self,
        content_type: Option<ActiveContentType>,
    ) -> Vec<&ActiveContentRef> {
        match content_type {
            Some(filter) => self
                .active_contents
                .iter()
                .filter(|ac| ac.content_type == filter)
                .collect(),
            None => self.active_contents.iter().collect(),
        }
    }

    /// Return the total count of active content entries.
    #[must_use]
    pub fn active_content_count(&self) -> usize {
        self.active_contents.len()
    }

    /// Return the maximum severity level across all active content entries.
    ///
    /// Returns `None` when no active content has been detected.
    /// Uses `Ord::max()` for deterministic worst-case selection.
    #[must_use]
    pub fn max_severity(&self) -> Option<ThreatSeverity> {
        self.active_contents.iter().map(|ac| ac.severity).max()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdr_v2::types::ContentLocation;

    // -----------------------------------------------------------------
    // DocumentMetadata Tests
    // -----------------------------------------------------------------

    #[test]
    fn document_metadata_new_creates_instance() {
        let meta = DocumentMetadata::new("test.pdf", 1024, DocumentFormat::Pdf);
        assert_eq!(meta.original_filename, "test.pdf");
        assert_eq!(meta.file_size_bytes, 1024);
        assert_eq!(meta.format, DocumentFormat::Pdf);
        assert!(meta.created_at.is_none());
        assert!(meta.modified_at.is_none());
    }

    #[test]
    fn document_metadata_builder_pattern() {
        let meta = DocumentMetadata::new("doc.docx", 2048, DocumentFormat::Docx)
            .with_created_at("2024-01-01T00:00:00Z")
            .with_modified_at("2024-06-15T12:00:00Z");

        assert_eq!(meta.created_at.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(meta.modified_at.as_deref(), Some("2024-06-15T12:00:00Z"));
    }

    // -----------------------------------------------------------------
    // DocumentAst Construction Tests
    // -----------------------------------------------------------------

    #[test]
    fn document_ast_new_creates_empty_ast() {
        let meta = DocumentMetadata::new("empty.pdf", 0, DocumentFormat::Pdf);
        let ast = DocumentAst::new(DocumentFormat::Pdf, meta);

        assert_eq!(ast.format, DocumentFormat::Pdf);
        assert_eq!(ast.active_content_count(), 0);
        assert!(ast.max_severity().is_none());
    }

    #[test]
    fn document_ast_with_active_contents() {
        let meta = DocumentMetadata::new("malicious.pdf", 4096, DocumentFormat::Pdf);
        let js_ref = ActiveContentRef::new(
            ActiveContentType::JavaScript,
            ContentLocation::new("/document/js[0]"),
            ThreatSeverity::Critical,
        );
        let macro_ref = ActiveContentRef::new(
            ActiveContentType::VBMacro,
            ContentLocation::new("/document/macros[0]"),
            ThreatSeverity::High,
        );

        let ast = DocumentAst {
            format: DocumentFormat::Pdf,
            root: AstNode::Document { children: vec![] },
            metadata: meta,
            active_contents: vec![js_ref, macro_ref],
        };

        assert_eq!(ast.active_content_count(), 2);
        assert_eq!(ast.max_severity(), Some(ThreatSeverity::Critical));
    }

    // -----------------------------------------------------------------
    // find_active_contents Tests
    // -----------------------------------------------------------------

    #[test]
    fn find_active_contents_filters_by_type() {
        let js = ActiveContentRef::new(
            ActiveContentType::JavaScript,
            ContentLocation::new("/js"),
            ThreatSeverity::Critical,
        );
        let ole = ActiveContentRef::new(
            ActiveContentType::OLEEmbeddedObject,
            ContentLocation::new("/ole"),
            ThreatSeverity::High,
        );

        let ast = DocumentAst {
            format: DocumentFormat::Pdf,
            root: AstNode::Document { children: vec![] },
            metadata: DocumentMetadata::new("t.pdf", 100, DocumentFormat::Pdf),
            active_contents: vec![js, ole],
        };

        let js_only = ast.find_active_contents(Some(ActiveContentType::JavaScript));
        assert_eq!(js_only.len(), 1);
        assert_eq!(js_only[0].content_type, ActiveContentType::JavaScript);

        let all = ast.find_active_contents(None);
        assert_eq!(all.len(), 2);
    }

    // -----------------------------------------------------------------
    // max_severity Tests
    // -----------------------------------------------------------------

    #[test]
    fn max_severity_returns_highest_level() {
        let refs = vec![
            ActiveContentRef::new(
                ActiveContentType::HyperlinkExternal,
                ContentLocation::new("/link"),
                ThreatSeverity::Low,
            ),
            ActiveContentRef::new(
                ActiveContentType::JavaScript,
                ContentLocation::new("/js"),
                ThreatSeverity::Critical,
            ),
            ActiveContentRef::new(
                ActiveContentType::EmbeddedFont,
                ContentLocation::new("/font"),
                ThreatSeverity::Medium,
            ),
        ];

        let ast = DocumentAst {
            format: DocumentFormat::Pdf,
            root: AstNode::Document { children: vec![] },
            metadata: DocumentMetadata::new("t.pdf", 100, DocumentFormat::Pdf),
            active_contents: refs,
        };

        assert_eq!(ast.max_severity(), Some(ThreatSeverity::Critical));
    }

    #[test]
    fn max_severity_none_when_empty() {
        let ast = DocumentAst::new(
            DocumentFormat::Png,
            DocumentMetadata::new("clean.png", 512, DocumentFormat::Png),
        );

        assert!(ast.max_severity().is_none());
    }

    // -----------------------------------------------------------------
    // AstNode Tree Traversal Tests
    // -----------------------------------------------------------------

    #[test]
    fn ast_node_collect_active_contents_traverses_tree() {
        let tree = AstNode::Document {
            children: vec![
                AstNode::Page {
                    index: 0,
                    children: vec![
                        AstNode::Text {
                            content: "Hello".into(),
                        },
                        AstNode::ActiveContent {
                            ref_item: ActiveContentRef::new(
                                ActiveContentType::JavaScript,
                                ContentLocation::new("/p0/js"),
                                ThreatSeverity::High,
                            ),
                            raw_data: None,
                        },
                    ],
                },
                AstNode::Page {
                    index: 1,
                    children: vec![AstNode::ActiveContent {
                        ref_item: ActiveContentRef::new(
                            ActiveContentType::ActionForm,
                            ContentLocation::new("/p1/form"),
                            ThreatSeverity::Medium,
                        ),
                        raw_data: None,
                    }],
                },
            ],
        };

        let collected = tree.collect_active_contents();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].severity, ThreatSeverity::High);
        assert_eq!(collected[1].severity, ThreatSeverity::Medium);
    }

    #[test]
    fn ast_node_has_active_content_detects_nested() {
        let tree_with_ac = AstNode::Document {
            children: vec![AstNode::ActiveContent {
                ref_item: ActiveContentRef::new(
                    ActiveContentType::VBMacro,
                    ContentLocation::new("/vba"),
                    ThreatSeverity::High,
                ),
                raw_data: None,
            }],
        };
        assert!(tree_with_ac.has_active_content());

        let clean_tree = AstNode::Document {
            children: vec![AstNode::Text {
                content: "safe".into(),
            }],
        };
        assert!(!clean_tree.has_active_content());
    }

    #[test]
    fn ast_node_node_counts_correctly() {
        let tree = AstNode::Document {
            children: vec![
                AstNode::Text {
                    content: "a".into(),
                },
                AstNode::Page {
                    index: 0,
                    children: vec![
                        AstNode::Image {
                            width: 100,
                            height: 200,
                            format: "png".into(),
                        },
                        AstNode::Metadata {
                            key: "Author".into(),
                            value: "Test".into(),
                        },
                    ],
                },
            ],
        };

        // Document(1) + Text(1) + Page(1) + Image(1) + Metadata(1) = 5
        assert_eq!(tree.node_count(), 5);
    }
}
