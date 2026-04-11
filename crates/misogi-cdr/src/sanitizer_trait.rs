use async_trait::async_trait;
use std::path::Path;
use crate::policy::SanitizationPolicy;
use crate::report::SanitizationReport;
use misogi_core::Result;

/// Unified interface for file content disarmament and reconstruction.
/// Each sanitizer implementation handles a specific file format,
/// providing streaming-safe processing with bounded memory usage.
#[async_trait]
pub trait FileSanitizer: Send + Sync {
    /// Returns list of file extensions this sanitizer can handle (e.g., [".pdf"])
    fn supported_extensions(&self) -> &[&str];

    /// Sanitize an input file according to the given policy.
    ///
    /// # Memory Safety Guarantee
    /// Implementations MUST NOT load entire file into memory.
    /// Use streaming/chunked I/O for files larger than configured threshold.
    ///
    /// # Arguments
    /// * `input_path` - Path to original (potentially malicious) file
    /// * `output_path` - Path where sanitized output will be written
    /// * `policy` - Sanitization strategy (StripActiveContent / ConvertToFlat / TextOnly)
    ///
    /// # Returns
    /// Detailed report of actions taken during sanitization
    async fn sanitize(
        &self,
        input_path: &Path,
        output_path: &Path,
        policy: &SanitizationPolicy,
    ) -> Result<SanitizationReport>;
}
