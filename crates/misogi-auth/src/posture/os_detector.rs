//! Operating System Detection & Version Parsing
//!
//! Parses User-Agent strings and client-reported OS information to determine
//! platform type and extract version numbers for policy comparison.

use super::types::{OsPlatform, OsPosture};

/// Parse OS platform and version from a User-Agent string.
///
/// Extracts operating system family and version number from common browser
/// User-Agent formats. This is a best-effort parser — for authoritative
/// OS detection, prefer client-side reporting.
///
/// # Supported Formats
///
/// - Windows: `Windows NT 10.0; Win64; x64` → Windows 10.0
/// - macOS: `Macintosh; Intel Mac OS X 10_15_7` → macOS 10.15.7
/// - Linux: `X11; Linux x86_64` → Linux
///
/// # Returns
///
/// An [`OsPosture`] with platform, version, and support status fields populated.
/// The `is_supported` field defaults to `true` — use [`PostureChecker`] to
/// evaluate against policy requirements.
pub fn parse_os_from_user_agent(user_agent: &str) -> OsPosture {
    let ua_lower = user_agent.to_lowercase();

    // Check mobile platforms FIRST (their UAs contain desktop OS strings)
    if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        return OsPosture {
            platform: OsPlatform::Ios,
            version: extract_ios_version(user_agent),
            build_number: String::new(),
            is_supported: true,
            minimum_required_version: None,
        };
    }

    if ua_lower.contains("android") {
        return OsPosture {
            platform: OsPlatform::Android,
            version: extract_android_version(user_agent),
            build_number: String::new(),
            is_supported: true,
            minimum_required_version: None,
        };
    }

    // Desktop platforms
    if ua_lower.contains("windows") {
        return parse_windows_ua(user_agent);
    }
    if ua_lower.contains("mac os x") || ua_lower.contains("macos") {
        return parse_macos_ua(user_agent);
    }
    if ua_lower.contains("linux") {
        return OsPosture {
            platform: OsPlatform::Linux,
            version: extract_linux_version(user_agent),
            build_number: String::new(),
            is_supported: true,
            minimum_required_version: None,
        };
    }

    OsPosture {
        platform: OsPlatform::Unknown("browser".to_string()),
        version: String::new(),
        build_number: String::new(),
        is_supported: true,
        minimum_required_version: None,
    }
}

fn parse_windows_ua(ua: &str) -> OsPosture {
    let version = extract_windows_nt_version(ua);
    let build_number = version.split('.').nth(2).unwrap_or("").to_string();

    OsPosture {
        platform: OsPlatform::Windows,
        version,
        build_number,
        is_supported: true,
        minimum_required_version: None,
    }
}

fn parse_macos_ua(ua: &str) -> OsPosture {
    let version = extract_macos_version(ua);

    OsPosture {
        platform: OsPlatform::MacOS,
        version,
        build_number: String::new(),
        is_supported: true,
        minimum_required_version: None,
    }
}

/// Extract Windows NT version from User-Agent string.
///
/// Looks for pattern `Windows NT X.Y` in the UA string.
fn extract_windows_nt_version(ua: &str) -> String {
    let pattern = "windows nt ";
    let lower = ua.to_lowercase();

    lower
        .find(pattern)
        .and_then(|start| {
            let ver_start = start + pattern.len();
            let ver_slice = &ua[ver_start..];
            let end = ver_slice
                .find(|c: char| c == ';' || c == ')')
                .unwrap_or(ver_slice.len());
            Some(ver_slice[..end].trim().to_string())
        })
        .unwrap_or_default()
}

/// Extract macOS version from User-Agent string.
///
/// Looks for pattern `Mac OS X X_Y_Z` or `Mac OS X X.Y.Z`.
fn extract_macos_version(ua: &str) -> String {
    let patterns = ["mac os x ", "macos "];

    for pattern in &patterns {
        if let Some(start) = ua.to_lowercase().find(pattern) {
            let ver_start = start + pattern.len();
            let ver_slice = &ua[ver_start..];
            let end = ver_slice
                .find(|c: char| c == ';' || c == ')' || c == ' ')
                .unwrap_or(ver_slice.len());

            let raw = ver_slice[..end].trim();
            // Convert underscores to dots: 10_15_7 → 10.15.7
            let version = raw.replace('_', ".");
            if !version.is_empty() {
                return version;
            }
        }
    }

    String::new()
}

fn extract_linux_version(_ua: &str) -> String {
    "unknown".to_string()
}

fn extract_ios_version(ua: &str) -> String {
    let pattern = "cpu iphone os ";
    ua.to_lowercase()
        .find(pattern)
        .and_then(|start| {
            let ver_start = start + pattern.len();
            let ver_slice = &ua[ver_start..];
            let end = ver_slice
                .find(|c: char| c == '_' || c == ' ')
                .unwrap_or(ver_slice.len());
            Some(ver_slice[..end].replace('_', "."))
        })
        .unwrap_or_default()
}

fn extract_android_version(ua: &str) -> String {
    let pattern = "android ";
    ua.to_lowercase()
        .find(pattern)
        .and_then(|start| {
            let ver_start = start + pattern.len();
            let ver_slice = &ua[ver_start..];
            let end = ver_slice
                .find(|c: char| c == ';' || c == ')')
                .unwrap_or(ver_slice.len());
            Some(ver_slice[..end].trim().to_string())
        })
        .unwrap_or_default()
}

/// Compare two OS version strings (semantic version comparison).
///
/// Supports `X`, `X.Y`, `X.Y.Z` formats. Returns:
/// - `Ordering::Less` if `a < b`
/// - `Ordering::Equal` if versions are equivalent
/// - `Ordering::Greater` if `a > b`
pub fn compare_os_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parts_a: Vec<u32> = a
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let parts_b: Vec<u32> = b
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    let max_len = parts_a.len().max(parts_b.len());

    for i in 0..max_len {
        let va = parts_a.get(i).copied().unwrap_or(0);
        let vb = parts_b.get(i).copied().unwrap_or(0);
        match va.cmp(&vb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_windows_11_ua() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let os = parse_os_from_user_agent(ua);
        assert_eq!(os.platform, OsPlatform::Windows);
        assert!(os.version.starts_with("10.0"));
    }

    #[test]
    fn test_parse_macos_ua() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
        let os = parse_os_from_user_agent(ua);
        assert_eq!(os.platform, OsPlatform::MacOS);
        assert!(os.version.contains("10.15.7"));
    }

    #[test]
    fn test_parse_linux_ua() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
        let os = parse_os_from_user_agent(ua);
        assert_eq!(os.platform, OsPlatform::Linux);
    }

    #[test]
    fn test_parse_ios_ua() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X)";
        let os = parse_os_from_user_agent(ua);
        assert_eq!(os.platform, OsPlatform::Ios);
    }

    #[test]
    fn test_parse_android_ua() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8)";
        let os = parse_os_from_user_agent(ua);
        assert_eq!(os.platform, OsPlatform::Android);
        assert!(os.version.contains("14"));
    }

    #[test]
    fn test_compare_versions_equal() {
        assert_eq!(compare_os_versions("10.0", "10.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_greater() {
        assert_eq!(
            compare_os_versions("10.0.19045", "10.0.19044"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_compare_versions_less() {
        assert_eq!(
            compare_os_versions("12.0", "13.0"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compare_versions_different_lengths() {
        assert_eq!(
            compare_os_versions("10.0", "10.0.19045"),
            std::cmp::Ordering::Less
        );
    }
}
