/* =============================================================================
 * Misogi WASM Browser Demo — WASM Loader Module
 * =============================================================================
 * Handles WebAssembly module initialization, loading state management,
 * timeout protection, and progressive UI enhancement.
 *
 * ## Exports
 *
 * - initializeWasm()          — Main initialization entry point
 * - hideWasmLoadingOverlay()   — Hide loading screen with animation
 * - showWasmLoadError()        — Display fatal error message
 * - enableInteractiveFeatures() — Enable UI after WASM ready
 * - startWasmTimeout()         — Start load timeout timer
 * - clearWasmTimeout()         — Cancel timeout timer
 *
 * ## Dependencies
 *
 * - feature-detection.js (detectWasmSupport, detectSharedArrayBuffer,
 *                         detectCoopCoep, localizeError)
 * ============================================================================= */

import {
    detectWasmSupport,
    detectSharedArrayBuffer,
    detectCoopCoep,
    localizeError,
} from "./feature-detection.js";

// =============================================================================
// Constants
// =============================================================================

/** WASM module load timeout in milliseconds (30 seconds). */
export const WASM_LOAD_TIMEOUT_MS = 30000;

// =============================================================================
// WASM Loading Timeout Management
// =============================================================================

/** Timeout handle for WASM loading (module-scoped for cancellation). */
let wasmLoadTimeout = null;

/**
 * Start a timeout timer for WASM module loading.
 *
 * If WASM initialization takes longer than WASM_LOAD_TIMEOUT_MS (30 seconds),
 * the callback is invoked with a timeout error. This prevents indefinite
 * waiting on slow networks or hung connections.
 *
 * @param {Function} callback - Function to call when timeout expires.
 */
export function startWasmTimeout(callback) {
    clearWasmTimeout();
    wasmLoadTimeout = setTimeout(() => {
        callback(
            new Error(
                "WASM モジュールの読み込みがタイムアウトしました（30秒）。" +
                "ネットワーク接続を確認するか、後でもう一度お試しください。"
            )
        );
    }, WASM_LOAD_TIMEOUT_MS);
}

/**
 * Clear the WASM loading timeout timer.
 *
 * Safe to call multiple times (idempotent). Should be called once WASM
 * initialization completes successfully or fails with a different error.
 */
export function clearWasmTimeout() {
    if (wasmLoadTimeout) {
        clearTimeout(wasmLoadTimeout);
        wasmLoadTimeout = null;
    }
}

// =============================================================================
// WASM Initialization
// =============================================================================

/**
 * Initialize the Misogi WASM module on page load.
 *
 * Implements progressive loading strategy:
 * 1. Run feature detection immediately (non-blocking)
 * 2. Show UI without waiting for WASM (progressive enhancement)
 * 3. Start WASM import with timeout protection
 * 4. Enable interactive features once WASM is ready
 *
 * @param {Object} dom - Cached DOM element references.
 * @param {Object} state - Application state object to update.
 *
 * ## Error Handling
 *
 * - Browser not supported: Shows capability error with upgrade guidance
 * - Network/timeout: Shows localized Japanese error with retry suggestion
 * - Build missing: Shows build instructions for developers
 */
export async function initializeWasm(dom, state) {
    // --- Step 1: Feature Detection (synchronous, immediate) ---
    const wasmSupport = detectWasmSupport();
    if (!wasmSupport.supported) {
        console.error("[misogi] WebAssembly not supported:", wasmSupport.reason);
        showWasmLoadError(dom, new Error(wasmSupport.reason));
        return;
    }

    // Log SharedArrayBuffer and COOP/COEP status (informational)
    const sabStatus = detectSharedArrayBuffer();
    console.log("[misogi] SharedArrayBuffer status:", sabStatus);
    if (sabStatus.warning) {
        console.warn("[misogi]", sabStatus.warning);
    }

    // Async COOP/COEP header detection (non-blocking, informational)
    detectCoopCoep().then((headers) => {
        console.log("[misogi] Server COOP/COEP headers:", headers);
        if (!headers.error && !headers.bothSet) {
            console.info(
                "[misogi] Note: Server COOP/COEP headers not fully set. " +
                    `COOP: ${headers.coep} COEP: ${headers.coep}`
            );
        }
    });

    // --- Step 2: Start WASM loading with timeout ---
    startWasmTimeout((timeoutError) => {
        console.error("[misogi] WASM load timeout:", timeoutError.message);
        showWasmLoadError(dom, timeoutError);
    });

    try {
        // Import the WASM module from the relative pkg/ directory.
        // Path is relative to this JS file location (examples/wasm-browser/app.js).
        const {
            default: init,
            sanitize_pdf,
            sanitize_office,
            scan_pii,
            detect_file_type,
        } = await import("../pkg/misogi_wasm.js");

        // Initialize the WASM instance (loads .wasm binary into memory).
        await init();

        // Clear timeout since loading completed successfully
        clearWasmTimeout();

        // Store references to WASM functions for later use
        state.wasmFunctions = { sanitize_pdf, sanitize_office, scan_pii, detect_file_type };
        state.wasmReady = true;

        // Hide the loading overlay with fade-out animation
        hideWasmLoadingOverlay(dom);

        // Enable action buttons now that WASM is ready
        enableInteractiveFeatures(dom);

        console.log("[misogi] WASM module initialized successfully.");
    } catch (err) {
        // Clear timeout to prevent duplicate error display
        clearWasmTimeout();
        console.error("[misogi] Failed to initialize WASM module:", err);

        // Localize error message before displaying
        const localizedMessage = localizeError(err.message || err.toString());
        const localizedErr = new Error(localizedMessage);
        localizedErr.originalError = err; // Preserve original for debugging

        showWasmLoadError(dom, localizedErr);
    }
}

// =============================================================================
// Loading Overlay Management
// =============================================================================

/**
 * Hide the WASM loading overlay with a CSS transition.
 *
 * @param {Object} dom - Cached DOM element references.
 */
export function hideWasmLoadingOverlay(dom) {
    if (!dom?.wasmLoadingOverlay) return;
    dom.wasmLoadingOverlay.classList.add("wasm-loading-overlay--hidden");
    // Remove from DOM after transition completes to free memory.
    setTimeout(() => {
        if (dom.wasmLoadingOverlay && dom.wasmLoadingOverlay.parentNode) {
            dom.wasmLoadingOverlay.style.display = "none";
        }
    }, 500);
}

/**
 * Display a fatal error message when WASM cannot be loaded.
 *
 * Shows an error in the loading overlay with either build instructions
 * (for import errors) or the raw error message (for other errors).
 *
 * @param {Object} dom - Cached DOM element references.
 * @param {Error} err - The caught exception from the import/init call.
 */
export function showWasmLoadError(dom, err) {
    if (!dom?.wasmLoadingSpinner || !dom?.wasmLoadingText || !dom?.wasmLoadingError) return;

    dom.wasmLoadingSpinner.style.display = "none";
    dom.wasmLoadingText.textContent = "WASM モジュールの読み込みに失敗しました";

    const errorMessage = err.message || "";
    const isImportError =
        errorMessage.includes("Failed to fetch") ||
        errorMessage.includes("Not found") ||
        errorMessage.includes("Unexpected token");

    if (isImportError) {
        dom.wasmLoadingError.innerHTML = `
            <strong>ビルドが必要です</strong><br><br>
            以下のコマンドで WASM パッケージをビルドしてください：<br>
            <code style="background:#222;padding:4px 8px;border-radius:4px;display:inline-block;margin-top:4px;">
                wasm-pack build --target web crates/misogi-wasm
            </code>
            <br><br>
            詳細: ${escapeHtml(errorMessage)}
        `;
    } else {
        dom.wasmLoadingError.textContent = `エラー: ${errorMessage}`;
    }

    dom.wasmLoadingError.style.display = "block";
}

// =============================================================================
// Interactive Features Enablement
// =============================================================================

/**
 * Enable interactive UI features after WASM initialization completes.
 *
 * Called once WASM is ready to allow user interaction with file upload,
 * sanitization, and other features. Removes disabled states and shows
 * capability information if applicable.
 *
 * @param {Object} dom - Cached DOM element references.
 */
export function enableInteractiveFeatures(dom) {
    // Enable sanitize button (may have been disabled during loading)
    if (dom?.sanitizeBtn) {
        dom.sanitizeBtn.disabled = false;
        dom.sanitizeBtn.setAttribute("aria-busy", "false");
    }

    // Enable drop zone
    if (dom?.dropZone) {
        dom.dropZone.classList.remove("drop-zone--disabled");
        dom.dropZone.setAttribute("aria-disabled", "false");
    }

    console.log("[misogi] Interactive features enabled.");
}

// =============================================================================
// Utility
// =============================================================================

/**
 * Escape HTML special characters to prevent XSS when inserting user-provided
 * strings into innerHTML.
 *
 * @param {string} str - Raw string potentially containing HTML characters.
 * @returns {string} Escaped string safe for innerHTML insertion.
 */
function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}
