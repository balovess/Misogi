//! Semantic version identifier following [SemVer 2.0.0](https://semver.org/) specification.
//!
//! Provides a strongly-typed representation of protocol versions used for
//! cross-version negotiation and compatibility checking.
//!
//! # Component Semantics
//!
/// | Component | Range | Change Meaning |
/// |-----------|-------|----------------|
/// | MAJOR | 0..=u32::MAX | Incompatible API changes |
/// | MINOR | 0..=u32::MAX | Backward-compatible additions |
/// | PATCH | 0..=u32::MAX | Backward-compatible bug fixes |

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

// =============================================================================
// ApiVersion — SemVer-compliant version identifier
// =============================================================================

/// Semantic version identifier (`MAJOR.MINOR.PATCH`) for protocol negotiation.
///
/// # Memory Layout
///
/// This type is `Copy` and occupies exactly 12 bytes (3 × u32), making it
/// suitable for hot-path comparisons and hash map keys without heap allocation.
///
/// # Examples
///
/// ```
/// let v1 = ApiVersion::new(1, 0, 0);
/// let v2 = ApiVersion::new(2, 1, 3);
///
/// assert!(v2 > v1);
/// assert!(!v1.is_compatible(&v2)); // Different major versions
/// assert_eq!(v2.to_string(), "2.1.3");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiVersion {
    /// Major version component — breaking changes only.
    pub major: u32,

    /// Minor version component — backward-compatible features.
    pub minor: u32,

    /// Patch version component — bug fixes only.
    pub patch: u32,
}

impl ApiVersion {
    /// Construct a new semantic version from components.
    #[inline]
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Parse a version string in `MAJOR.MINOR.PATCH` format.
    ///
    /// # Errors
    /// Returns [`ParseVersionError`] if the string does not conform to SemVer format.
    #[must_use]
    pub fn parse(s: &str) -> Result<Self, ParseVersionError> {
        s.parse()
    }

    /// Check semantic compatibility with another version (same major = compatible).
    #[inline]
    #[must_use]
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Convert to dotted string representation `"MAJOR.MINOR.PATCH"`.
    #[must_use]
    pub fn to_version_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Check if this version represents a pre-release (major == 0).
    #[inline]
    #[must_use]
    pub const fn is_prerelease(&self) -> bool {
        self.major == 0
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for ApiVersion {
    type Err = ParseVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() != 3 {
            return Err(ParseVersionError::InvalidFormat(s.to_string()));
        }

        if parts.iter().any(|p| p.is_empty()) {
            return Err(ParseVersionError::InvalidFormat(s.to_string()));
        }

        let major: u32 = parts[0]
            .parse()
            .map_err(|_| ParseVersionError::InvalidComponent("major".to_string()))?;

        let minor: u32 = parts[1]
            .parse()
            .map_err(|_| ParseVersionError::InvalidComponent("minor".to_string()))?;

        let patch: u32 = parts[2]
            .parse()
            .map_err(|_| ParseVersionError::InvalidComponent("patch".to_string()))?;

        Ok(Self::new(major, minor, patch))
    }
}

impl PartialOrd for ApiVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApiVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

impl Default for ApiVersion {
    fn default() -> Self {
        Self::new(0, 1, 0)
    }
}

// =============================================================================
// ParseVersionError
// =============================================================================

/// Error returned when a version string cannot be parsed into [`ApiVersion`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseVersionError {
    /// Input does not match `MAJOR.MINOR.PATCH` format.
    InvalidFormat(String),

    /// A specific component failed to parse as unsigned integer.
    InvalidComponent(String),
}

impl fmt::Display for ParseVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(s) => {
                write!(f, "Invalid version format '{}': expected MAJOR.MINOR.PATCH", s)
            }
            Self::InvalidComponent(comp) => {
                write!(f, "Invalid '{}' component: not a valid u32", comp)
            }
        }
    }
}

impl std::error::Error for ParseVersionError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction_and_display() {
        let v = ApiVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
        assert_eq!(v.to_version_string(), "1.2.3");
    }

    #[test]
    fn test_parsing_valid() {
        assert_eq!("0.0.0".parse::<ApiVersion>(), Ok(ApiVersion::new(0, 0, 0)));
        assert_eq!("10.20.30".parse::<ApiVersion>(), Ok(ApiVersion::new(10, 20, 30)));
    }

    #[test]
    fn test_parsing_invalid() {
        assert!("".parse::<ApiVersion>().is_err());
        assert!("1.0".parse::<ApiVersion>().is_err());
        assert!("a.b.c".parse::<ApiVersion>().is_err());
        assert!("1..3".parse::<ApiVersion>().is_err());
    }

    #[test]
    fn test_comparison_ordering() {
        let v100 = ApiVersion::new(1, 0, 0);
        let v110 = ApiVersion::new(1, 1, 0);
        let v200 = ApiVersion::new(2, 0, 0);

        assert!(v100 < v110);
        assert!(v110 < v200);

        let mut versions = vec![v200, v100, v110];
        versions.sort();
        assert_eq!(versions, vec![v100, v110, v200]);
    }

    #[test]
    fn test_compatibility_checking() {
        let v1_0 = ApiVersion::new(1, 0, 0);
        let v1_9 = ApiVersion::new(1, 9, 9);
        let v2_0 = ApiVersion::new(2, 0, 0);

        assert!(v1_0.is_compatible(&v1_9));
        assert!(!v1_0.is_compatible(&v2_0));
    }

    #[test]
    fn test_prerelease_detection() {
        assert!(ApiVersion::new(0, 1, 0).is_prerelease());
        assert!(!ApiVersion::new(1, 0, 0).is_prerelease());
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = ApiVersion::new(3, 2, 1);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ApiVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_default_is_initial_dev() {
        let v = ApiVersion::default();
        assert_eq!(v, ApiVersion::new(0, 1, 0));
    }

    #[test]
    fn test_parse_error_display() {
        let err = ParseVersionError::InvalidFormat("abc".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("abc"));
    }
}
