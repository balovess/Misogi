//! JavaScript interoperability helpers for the WASM browser target.
//!
//! Provides utility functions that bridge Rust semantics to JavaScript
//! conventions: error message localization, memory management wrappers,
//! and console logging bridges.
//!
//! ## Usage
//!
//! These functions are called from the browser demo's app.js to provide
//! Japanese-localized error messages and feature detection for graceful
//! degradation on older browsers.

use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use crate::wasm_compat::MAX_WASM_FILE_SIZE_BYTES;

// ===========================================================================
// Error Message Localization (Japanese)
// ===========================================================================

/// Map internal error codes to user-facing Japanese messages.
///
/// These messages are displayed in the browser demo UI error banner.
/// All messages follow the project's Japanese-primary documentation convention.
///
/// # Arguments
///
/// * `error_code` - Machine-readable error category identifier.
/// * `detail` - Optional human-readable detail string (e.g., file size).
///
/// # Returns
///
/// Localized Japanese error message suitable for direct UI display.
#[wasm_bindgen]
pub fn localize_error(error_code: &str, detail: &str) -> String {
    match error_code {
        "file_too_large" => format!(
            "ファイルサイズが制限を超えています（{}）。500 MB 以内のファイルを使用してください。",
            detail
        ),
        "invalid_pdf" => format!("無効な PDF ファイルです: {}", detail),
        "invalid_office" => format!("無効な Office ドキュメントです: {}", detail),
        "zip_bomb" => {
            "ZIP 爆弾が検出されました。このファイルは処理できません。".to_string()
        }
        "memory_exceeded" => {
            "メモリ制限を超えました。ブラウザのタブを再読み込みしてください。".to_string()
        }
        "timeout" => {
            "処理タイムアウトしました。ファイルサイズを小さくしてください。".to_string()
        }
        "unsupported_format" => {
            format!("このファイル形式はサンポートされていません: {}", detail)
        }
        _ => format!("エラー: {}", detail),
    }
}

// ===========================================================================
// Memory Management
// ===========================================================================

/// Allocate a buffer in WASM linear memory for large file transfers.
///
/// Returns a pointer to the allocated region. The caller must call
/// [`deallocate_buffer`] when done to prevent memory leaks.
///
/// # Arguments
///
/// * `size` - Number of bytes to allocate.
///
/// # Returns
///
/// Pointer to allocated memory (non-negative), or `-1` on failure
/// (size exceeds maximum or allocation failed).
#[wasm_bindgen]
pub fn allocate_buffer(size: usize) -> i32 {
    if size == 0 {
        return 0;
    }

    if size > MAX_WASM_FILE_SIZE_BYTES as usize {
        return -1;
    }

    // Use Vec allocation as the WASM linear memory allocator.
    let mut buffer = Vec::with_capacity(size);

    // SAFETY: We immediately leak the Vec below, so the pointer remains valid.
    // The caller must call deallocate_buffer with the same size to free it.
    //
    // On wasm32-unknown-unknown, pointers are 32-bit and fit exactly in i32.
    // This is guaranteed by the WebAssembly specification: linear memory indices
    // are i32, and all allocations return valid 32-bit addresses.
    #[cfg(target_arch = "wasm32")]
    {
        let ptr = buffer.as_mut_ptr();
        std::mem::forget(buffer);
        // Use transmute to convert pointer to integer (safe on wasm32)
        unsafe { std::mem::transmute::<*mut u8, i32>(ptr) }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let ptr = buffer.as_mut_ptr();
        std::mem::forget(buffer);
        ptr as i32
    }
}

/// Deallocate a previously allocated buffer, freeing WASM linear memory.
///
/// # Safety
///
/// * `ptr` must be a valid pointer returned by [`allocate_buffer`].
/// * `size` must match the original allocation size.
/// * This function must be called exactly once per allocation.
///
/// # Arguments
///
/// * `ptr` - Pointer from [`allocate_buffer`].
/// * `size` - Original allocation size in bytes.
#[wasm_bindgen]
pub fn deallocate_buffer(ptr: i32, size: usize) {
    if ptr <= 0 || size == 0 {
        return;
    }

    unsafe {
        // Reconstruct the leaked Vec from its pointer and capacity,
        // then drop it to properly deallocate the memory.
        let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size);
    }
}

// ===========================================================================
// Console Logging Bridge
// ===========================================================================

/// Log a message to the browser console at the specified level.
///
/// Bridges Rust tracing output to browser developer tools console.
/// All messages are prefixed with `[misogi-wasm]` for easy filtering.
///
/// # Arguments
///
/// * `level` - Log level: `"log"`, `"warn"`, `"error"`, or `"debug"`.
/// * `message` - Message text to emit.
#[wasm_bindgen]
pub fn console_log(level: &str, message: &str) {
    let formatted = format!("[misogi-wasm] {}", message);

    match level {
        "error" => web_sys::console::error_1(&JsValue::from_str(&formatted)),
        "warn" => web_sys::console::warn_1(&JsValue::from_str(&formatted)),
        "debug" => web_sys::console::debug_1(&JsValue::from_str(&formatted)),
        _ => web_sys::console::log_1(&JsValue::from_str(&formatted)),
    }
}

// ===========================================================================
// Feature Detection
// ===========================================================================

/// Detect which WebAssembly features are available in the current browser.
///
/// Returns a JSON object describing feature support status. Used by
/// `app.js` for graceful degradation decisions when required features
/// are unavailable.
///
/// # Returns
///
/// JSON string with boolean flags for each detected capability:
/// ```json
/// {
///   "webassembly": true,
///   "shared_array_buffer": true,
///   "bigint": true
/// }
/// ```
#[wasm_bindgen]
pub fn detect_wasm_features() -> String {
    let mut features = HashMap::new();

    // WebAssembly global object (always available if this code is running)
    features.insert("webassembly".to_string(), true);

    // SharedArrayBuffer (required for multi-threaded WASM)
    let has_sab = js_sys::Reflect::has(
        &js_sys::global(),
        &JsValue::from_str("SharedArrayBuffer"),
    )
    .unwrap_or(false);
    features.insert("shared_array_buffer".to_string(), has_sab);

    // BigInt (required for 64-bit integer passing between JS/WASM)
    let has_bigint =
        js_sys::Reflect::has(&js_sys::global(), &JsValue::from_str("BigInt")).unwrap_or(false);
    features.insert("bigint".to_string(), has_bigint);

    serde_json::to_string(&features).unwrap_or_else(|_| "{}".to_string())
}

// ===========================================================================
// Version Information
// ===========================================================================

/// Return the WASM module version string for display in the browser UI.
///
/// # Returns
///
/// Version string in semver format (e.g., "0.1.0").
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test: Error Localization
    // -----------------------------------------------------------------------

    #[test]
    fn test_localize_file_too_large() {
        let msg = localize_error("file_too_large", "600 MB");
        assert!(msg.contains("500 MB"));
        assert!(msg.contains("制限"));
    }

    #[test]
    fn test_localize_invalid_pdf() {
        let msg = localize_error("invalid_pdf", "not a PDF");
        assert!(msg.contains("PDF"));
        assert!(msg.contains("not a PDF"));
    }

    #[test]
    fn test_localize_zip_bomb() {
        let msg = localize_error("zip_bomb", "");
        assert!(msg.contains("ZIP 爆弾"));
    }

    #[test]
    fn test_localize_unknown_error() {
        let msg = localize_error("some_random_error", "detail here");
        assert!(msg.contains("エラー"));
        assert!(msg.contains("detail here"));
    }

    // -----------------------------------------------------------------------
    // Test: Feature Detection JSON Output
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_wasm_features_returns_valid_json() {
        let json = detect_wasm_features();
        let parsed: HashMap<String, bool> =
            serde_json::from_str(&json).expect("should be valid JSON");

        assert!(parsed.get("webassembly").unwrap());
        // SharedArrayBuffer and BigInt depend on test environment
        assert!(parsed.contains_key("shared_array_buffer"));
        assert!(parsed.contains_key("bigint"));
    }

    // -----------------------------------------------------------------------
    // Test: Version
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_returns_string() {
        let v = version();
        assert!(!v.is_empty());
        // Should be semver-like (contains dots)
        assert!(v.contains('.'));
    }
}
