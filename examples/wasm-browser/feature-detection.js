/* =============================================================================
 * Misogi WASM Browser Demo — Feature Detection Module
 * =============================================================================
 * Provides browser capability detection for WebAssembly and related APIs.
 * All functions are synchronous where possible for immediate feedback.
 *
 * ## Exports
 *
 * - detectWasmSupport()        — Check WebAssembly availability
 * - detectSharedArrayBuffer()   — Check SAB and cross-origin isolation
 * - detectCoopCoep()            — Async server header detection
 * - localizeError()             — Japanese error message translation
 *
 * ## Usage
 *
 * import { detectWasmSupport, localizeError } from './feature-detection.js';
 * ============================================================================= */

// =============================================================================
// WebAssembly Support Detection
// =============================================================================

/**
 * Detect WebAssembly support in the current browser.
 *
 * Checks for the presence of the WebAssembly global object and basic
 * instantiation capability. Returns a structured result with support status
 * and human-readable reason if unsupported.
 *
 * @returns {{ supported: boolean, reason: string|null }} Detection result.
 */
export function detectWasmSupport() {
    if (!window.WebAssembly) {
        return {
            supported: false,
            reason:
                "このブラウザは WebAssembly に対応していません。" +
                "最新版のブラウザ（Chrome, Firefox, Edge, Safari）を使用してください。",
        };
    }
    if (typeof WebAssembly.instantiate !== "function") {
        return {
            supported: false,
            reason:
                "WebAssembly のインスタンス化機能が利用できません。" +
                "ブラウザを更新してください。",
        };
    }
    return { supported: true, reason: null };
}

// =============================================================================
// SharedArrayBuffer & Cross-Origin Isolation Detection
// =============================================================================

/**
 * Detect SharedArrayBuffer availability and COOP/COEP header status.
 *
 * SharedArrayBuffer requires both browser support AND proper COOP/COEP headers
 * to be set (for cross-origin isolation). This function checks both conditions
 * and returns detailed diagnostic information.
 *
 * @returns {{
 *   hasSharedArrayBuffer: boolean,
 *   crossOriginIsolated: boolean,
 *   warning: string|null
 * }} Detection result with optional warning message.
 */
export function detectSharedArrayBuffer() {
    const hasSAB = typeof SharedArrayBuffer !== "undefined";
    const coopCoepSet = window.crossOriginIsolated === true;

    let warning = null;
    if (hasSAB && !coopCoepSet) {
        warning =
            "SharedArrayBuffer は利用可能ですが、" +
            "COOP/COEP ヘッダーが設定されていないため、" +
            "マルチスレッド機能は制限されます。";
    }

    return {
        hasSharedArrayBuffer: hasSAB,
        crossOriginIsolated: coopCoepSet,
        warning: warning,
    };
}

// =============================================================================
// COOP/COEP Server Header Detection (Async)
// =============================================================================

/**
 * Dynamically detect COOP/COEP response headers from the server.
 *
 * Performs a HEAD request to check if the server is sending the required
 * Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy headers.
 * Note: Meta tags provide client-side hints, but server headers are required
 * for full cross-origin isolation.
 *
 * @returns {Promise<{
 *   coop: string,
 *   coep: string,
 *   bothSet: boolean,
 *   error?: string
 * }>} Header detection result or error information.
 */
export async function detectCoopCoep() {
    try {
        const response = await fetch(window.location.href, {
            method: "HEAD",
            cache: "no-store",
        });
        const coop = response.headers.get("Cross-Origin-Opener-Policy");
        const coep = response.headers.get("Cross-Origin-Embedder-Policy");

        return {
            coop: coop || "(未設定)",
            coep: coep || "(未設定)",
            bothSet: !!(coop && coep),
        };
    } catch (e) {
        return { error: e.message };
    }
}

// =============================================================================
// Error Localization (English -> Japanese)
// =============================================================================

/** Common error pattern mappings for localization. */
const ERROR_MAP = {
    // WASM loading errors
    "Failed to fetch dynamically imported module":
        "WASM モジュールの読み込みに失敗しました。" +
        "ネットワーク接続を確認するか、ページを再読み込みしてください。",
    "Not found":
        "WASM ファイルが見つかりません。ビルドが必要です。",
    "Unexpected token":
        "WASM ファイルの形式が正しくありません。再ビルドしてください。",
    "WebAssembly.instantiate()":
        "WASM の初期化に失敗しました。ブラウザの互換性を確認してください。",

    // File processing errors
    "FileReader error":
        "ファイルの読み込み中にエラーが発生しました。",
    "Out of memory":
        "メモリ不足です。ファイルサイズを小さくするか、他のタブを閉じてください。",
    "Array buffer allocation failed":
        "メモリ割り当てに失敗しました。ブラウザを再起動してください。",

    // Sanitization errors
    "Unsupported file format":
        "このファイル形式には対応していません。",
    "Invalid PDF structure":
        "PDF ファイルの構造が無効です。",
    "Corrupt Office document":
        "Office ドキュメントが破損しています。",
};

/**
 * Translate error codes or technical messages into user-friendly Japanese.
 *
 * Provides localized error messages for common WASM and file processing errors.
 * Falls back to the original message if no translation is available.
 *
 * @param {string} errorMessage - The original error message or code.
 * @returns {string} Localized Japanese error message.
 */
export function localizeError(errorMessage) {
    // Check for exact matches first
    if (ERROR_MAP[errorMessage]) {
        return ERROR_MAP[errorMessage];
    }

    // Check for partial matches (substring, case-insensitive)
    const lowerMessage = errorMessage.toLowerCase();
    for (const [pattern, translation] of Object.entries(ERROR_MAP)) {
        if (lowerMessage.includes(pattern.toLowerCase())) {
            return translation;
        }
    }

    // Return original message if no translation found
    return errorMessage;
}
