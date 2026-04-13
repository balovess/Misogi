//! Hash computation utilities for Misogi CDR pipeline.
//!
//! Provides both pure in-memory hashing (WASM-compatible) and async file-based
//! hashing (requires tokio runtime). The [`compute_md5`] and [`compute_sha256`]
//! functions operate on byte slices and are safe for use in WebAssembly browser
//! environments. File-based variants are gated behind the "runtime" feature.

use crate::error::Result;
use md5::{Digest, Md5};
use sha2::Sha256;

// ===========================================================================
// Pure In-Memory Hashing (WASM-compatible, no tokio dependency)
// ===========================================================================

/// Compute MD5 digest of arbitrary byte data (pure Rust, WASM-compatible).
///
/// Operates entirely on heap-allocated byte slices with no filesystem I/O.
/// Safe for use in `wasm32-unknown-unknown` browser sandbox environments.
///
/// # Arguments
/// * `data` - Arbitrary byte slice to hash.
///
/// # Returns
/// Lowercase hexadecimal MD5 digest string (32 characters).
///
/// # Example
/// ```ignore
/// let hash = misogi_core::hash::compute_md5(b"hello world");
/// assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
/// ```
pub fn compute_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Compute SHA-256 digest of arbitrary byte data (pure Rust, WASM-compatible).
///
/// Uses the RustCrypto `sha2` crate which is fully compatible with
/// `wasm32-unknown-unknown` (pure software implementation, no ASM).
///
/// # Arguments
/// * `data` - Arbitrary byte slice to hash.
///
/// # Returns
/// Lowercase hexadecimal SHA-256 digest string (64 characters).
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ===========================================================================
// Async File-Based Hashing (requires tokio runtime)
// ===========================================================================

/// Compute MD5 hash of a file on disk using async I/O.
///
/// Streams file contents through MD5 hasher with 8 KiB buffer to avoid
/// loading entire file into memory. Requires tokio async runtime.
///
/// # Arguments
/// * `path` - File system path to the input file.
///
/// # Returns
/// Lowercase hexadecimal MD5 digest string.
///
/// # Errors
/// - [`MisogiError::Io`] if file cannot be opened or read
/// - Only available when "runtime" feature is enabled
#[cfg(feature = "runtime")]
pub async fn compute_file_md5<P: AsRef<std::path::Path>>(path: P) -> Result<String> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute SHA-256 hash of a file on disk using async I/O.
///
/// Streams file contents through SHA-256 hasher with 8 KiB buffer.
/// Requires tokio async runtime.
///
/// # Arguments
/// * `path` - File system path to the input file.
///
/// # Returns
/// Lowercase hexadecimal SHA-256 digest string.
///
/// # Errors
/// - [`MisogiError::Io`] if file cannot be opened or read
/// - Only available when "runtime" feature is enabled
#[cfg(feature = "runtime")]
pub async fn compute_file_sha256<P: AsRef<std::path::Path>>(path: P) -> Result<String> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_md5_known_answer() {
        assert_eq!(compute_md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(compute_md5(b"hello world"), "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_compute_sha256_known_answer() {
        assert_eq!(
            compute_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            compute_sha256(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_empty_input() {
        // Both functions should handle empty input gracefully
        assert!(!compute_md5(b"").is_empty());
        assert!(!compute_sha256(b"").is_empty());
        assert_eq!(compute_md5(b"").len(), 32);  // MD5 = 32 hex chars
        assert_eq!(compute_sha256(b"").len(), 64);  // SHA-256 = 64 hex chars
    }
}
