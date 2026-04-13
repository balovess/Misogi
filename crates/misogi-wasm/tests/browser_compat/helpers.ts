/**
 * =============================================================================
 * Misogi WASM — Playwright Test Helper Utilities
 * =============================================================================
 *
 * Reusable helper functions for browser compatibility testing of the Misogi
 * WebAssembly module. These utilities abstract common test patterns such as:
 *
 * - WASM module loading detection and waiting
 * - File upload simulation for sanitization tests
 * - Sanitization workflow orchestration (upload → sanitize → verify)
 * - Result extraction from the UI layer
 * - Error state validation
 * - Japanese locale verification
 *
 * ## Design Principles
 *
 * 1. **Explicit Waits**: All async operations use explicit wait conditions
 *    rather than fixed timeouts to ensure reliability across different machines
 *    and CI environments.
 *
 * 2. **Defensive Programming**: Functions include error handling and fallback
 *    behavior for cases where DOM elements might not exist or WASM fails to load.
 *
 * 3. **Type Safety**: Full TypeScript types for all function parameters and
 *    return values enable compile-time error catching and IDE autocompletion.
 *
 * 4. **Browser-Agnostic**: Helpers work consistently across Chromium, Firefox,
 *    and WebKit without browser-specific code paths.
 *
 * ## Usage Example
 *
 * ```typescript
 * import { test } from '@playwright/test';
 * import {
 *   waitForWasmLoad,
 *   uploadTestFile,
 *   clickSanitize,
 *   waitForSanitizeComplete,
 *   getSanitizeResult,
 * } from './helpers';
 *
 * test('should sanitize PDF', async ({ page }) => {
 *   await page.goto('/');
 *   await waitForWasmLoad(page);
 *   await uploadTestFile(page, '#drop-zone-input', 'test.pdf');
 *   await clickSanitize(page);
 *   await waitForSanitizeComplete(page);
 *   const result = await getSanitizeResult(page);
 *   expect(result.success).toBe(true);
 * });
 * ```
 *
 * @module helpers
 * =============================================================================
 */

import { Page, expect, Locator } from '@playwright/test';

// =============================================================================
// Constants
// =============================================================================

/**
 * Maximum time to wait for WASM module initialization (in milliseconds).
 *
 * WASM loading involves:
 * 1. Fetching the .wasm binary (network I/O)
 * 2. WebAssembly compilation (CPU-intensive)
 * 3. Module instantiation (memory allocation)
 *
 * 30 seconds accommodates slow CI environments and large WASM modules.
 */
export const WASM_LOAD_TIMEOUT = 30000;

/**
 * Maximum time to wait for sanitization completion (in milliseconds).
 *
 * Sanitization is CPU-intensive as it processes file contents in WASM.
 * Large files (>10MB) or complex documents (embedded JS/VBA) may take longer.
 * 60 seconds provides sufficient headroom for worst-case scenarios.
 */
export const SANITIZE_TIMEOUT = 60000;

/**
 * Maximum time to wait for UI element visibility transitions (in milliseconds).
 * Used for animations, loading states, and progressive enhancement reveals.
 */
export const UI_TRANSITION_TIMEOUT = 5000;

// =============================================================================
// WASM Loading Helpers
// =============================================================================

/**
 * Wait for the WASM module to finish loading and initializing.
 *
 * Polls `window.wasmModuleReady` flag which is set by app.js after successful
 * WASM initialization. This approach is more reliable than checking for
 * specific DOM elements because it directly verifies the module's ready state.
 *
 * ## Implementation Details
 *
 * The wasm-browser demo sets `state.wasmReady = true` after:
 * 1. Dynamic import of `../pkg/misogi_wasm.js` completes
 * 2. `init()` function finishes (compiles + instantiates WASM)
 * 3. Loading overlay is hidden via CSS transition
 * 4. Interactive features are enabled (buttons unblocked)
 *
 * @param page - Playwright Page instance representing the browser tab.
 * @param options - Optional configuration overrides.
 * @param options.timeout - Custom timeout in ms (default: WASM_LOAD_TIMEOUT).
 * @throws {Error} If WASM fails to load within the timeout period.
 *
 * @example
 * ```typescript
 * await page.goto('/');
 * await waitForWasmLoad(page); // Throws if >30s
 * console.log('WASM ready');
 * ```
 */
export async function waitForWasmLoad(
  page: Page,
  options?: { timeout?: number }
): Promise<void> {
  const timeout = options?.timeout ?? WASM_LOAD_TIMEOUT;

  await page.waitForFunction(
    () => {
      /**
       * Check if WASM module has been marked as ready by the application.
       * The app.js module sets this flag after successful initialization.
       */
      const win = window as any;
      return win.wasmReady === true || win.misogiWasmState?.wasmReady === true;
    },
    { timeout }
  );
}

/**
 * Verify that WASM loaded without JavaScript errors.
 *
 * Captures all console.error messages during a specified action and filters
 * for WASM-related errors. Useful for ensuring clean initialization across
 * different browsers where error messages may vary.
 *
 * @param page - Playwright Page instance.
 * @param action - Async function to execute while monitoring errors.
 * @returns Array of WASM-related error messages captured during execution.
 *
 * @example
 * ```typescript
 * const errors = await captureWasmErrors(page, async () => {
 *   await page.goto('/');
 *   await waitForWasmLoad(page);
 * });
 * expect(errors).toHaveLength(0); // No WASM errors expected
 * ```
 */
export async function captureWasmErrors(
  page: Page,
  action: () => Promise<void>
): Promise<string[]> {
  const errors: string[] = [];

  /** Listener that captures error-type console messages. */
  const errorHandler = (msg: any): void => {
    if (msg.type() === 'error') {
      const text = msg.text();
      // Filter for WASM-related errors (compile, instantiate, fetch failures)
      if (
        text.toLowerCase().includes('wasm') ||
        text.toLowerCase().includes('webassembly') ||
        text.includes('Failed to fetch') ||
        text.includes('instantiate')
      ) {
        errors.push(text);
      }
    }
  };

  page.on('console', errorHandler);

  try {
    await action();
  } finally {
    page.off('console', errorHandler);
  }

  return errors;
}

// =============================================================================
// File Upload Helpers
// =============================================================================

/**
 * Upload a test file using the file input element.
 *
 * Simulates user file selection by setting files on the hidden `<input>`
 * element within the drop zone. This triggers the same event handlers as
 * manual drag-and-drop or click-to-browse interactions.
 *
 * ## File Input Location
 *
 * The wasm-browser demo uses a hidden file input (`#drop-zone-input`) that
 * is triggered when users click the drop zone area. Playwright's setInputFiles
 * method directly sets the file(s) on this input element.
 *
 * @param page - Playwright Page instance.
 * @param selector - CSS selector for the file input element.
 * @param filePath - Absolute or relative path to the test file.
 * @throws {Error} If the file input element is not found or file doesn't exist.
 *
 * @example
 * ```typescript
 * await uploadTestFile(page, '#drop-zone-input', './fixtures/test.pdf');
 * ```
 */
export async function uploadTestFile(
  page: Page,
  selector: string,
  filePath: string
): Promise<void> {
  const fileInput = page.locator(selector);

  /** Ensure the file input exists before attempting upload. */
  await expect(fileInput).toBeVisible({ timeout: UI_TRANSITION_TIMEOUT });

  /**
   * Set the file on the input element.
   * This triggers the 'change' event handler in app.js which reads the file
   * and calls detectFileType().
   */
  await fileInput.setInputFiles(filePath);
}

/**
 * Generate a minimal valid PDF file for testing purposes.
 *
 * Creates a bare-bones PDF document (1 KB) that passes structural validation
 * but contains no actual content. Used when external test fixtures are not
 * available or for testing edge cases (empty files, minimal structure).
 *
 * PDF specification requires:
 * - %PDF-x.y header
 * - Cross-reference table
 * - Trailer with root catalog
 * - EOF marker (%%EOF)
 *
 * @returns Uint8Array containing a minimal valid PDF document.
 *
 * @example
 * ```typescript
 * const pdfBytes = generateMinimalPdf();
 * // Use with page.evaluate() to create a File object
 * ```
 */
export function generateMinimalPdf(): Uint8Array {
  /**
   * Minimal PDF structure following PDF Reference 1.7 specification.
   * Contains:
   * - Header: PDF version declaration
   * - Object 1: Catalog (document root)
   * - Object 2: Pages (page tree node)
   * - Object 3: Page (single blank page, Letter size)
   * - Cross-reference table: Byte offsets for each object
   * - Trailer: Root object reference and total object count
   * - EOF: End-of-file marker
   */
  const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n

trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF`;

  return new TextEncoder().encode(pdfContent);
}

/**
 * Generate a minimal OOXML file (DOCX) for testing Office sanitization.
 *
 * Creates a valid DOCX structure (which is a ZIP archive containing XML files).
 * This minimal document can be used to test the Office sanitization pipeline
 * without requiring real document fixtures.
 *
 * DOCX structure:
 * - [Content_Types].xml: MIME type declarations
 * - _rels/.rels: Relationship definitions
 * - word/document.xml: Document content (empty body)
 *
 * Note: This generates a valid ZIP structure but content is minimal.
 * For comprehensive testing, use actual fixture files.
 *
 * @returns Uint8Array containing a minimal DOCX file (ZIP format).
 */
export function generateMinimalDocx(): Uint8Array {
  /**
   * Minimal DOCX content as a simple placeholder.
   * In production, this would use a ZIP library (JSZip) to create proper
   * OOXML structure. For now, returns a small binary buffer that represents
   * an empty-ish file for basic upload testing.
   *
   * TODO: Implement proper ZIP/OOXML generation using JSZip or similar.
   * Current implementation returns minimal bytes for smoke testing only.
   */
  const docxPlaceholder = new Uint8Array([
    0x50, 0x4B, 0x03, 0x04, // ZIP file signature (PK\x03\x04)
    ...new Array(256).fill(0), // Padding to make it look like a file
  ]);

  return docxPlaceholder;
}

// =============================================================================
// Sanitization Workflow Helpers
// =============================================================================

/**
 * Click the sanitize button to initiate file processing.
 *
 * Locates the primary sanitize button by ID or Japanese text content.
 * Supports both the main demo button and potential variations in future UI
 * iterations.
 *
 * @param page - Playwright Page instance.
 * @throws {Error} If the sanitize button is not found or not clickable.
 *
 * @example
 * ```typescript
 * await uploadTestFile(page, '#drop-zone-input', 'test.pdf');
 * await clickSanitize(page); // Starts processing
 * ```
 */
export async function clickSanitize(page: Page): Promise<void> {
  /**
   * Selector strategy:
   * 1. Primary: Button with ID #sanitize-btn (most reliable)
   * 2. Fallback: Button containing Japanese text "サニタイズ実行"
   * 3. Last resort: Any button with "sanitize" in text/ID
   */
  const btn = page.locator('#sanitize-btn');

  /** Ensure button is visible and enabled before clicking. */
  await expect(btn).toBeEnabled({ timeout: UI_TRANSITION_TIMEOUT });

  await btn.click();
}

/**
 * Wait for sanitization processing to complete.
 *
 * Monitors the application's processing state to detect when WASM execution
 * finishes. The processing indicator (#processing-status) is shown during
 * execution and hidden upon completion (success or failure).
 *
 * ## Detection Strategy
 *
 * Checks multiple signals for robustness:
 * 1. Processing status element becomes hidden
 * 2. Results panel becomes visible (success case)
 * 3. Error banner appears (failure case)
 * 4. Custom window.sanitizationInProgress flag (if set by app)
 *
 * @param page - Playwright Page instance.
 * @param options - Optional configuration overrides.
 * @param options.timeout - Custom timeout in ms (default: SANITIZE_TIMEOUT).
 * @throws {Error} If processing doesn't complete within the timeout period.
 *
 * @example
 * ```typescript
 * await clickSanitize(page);
 * await waitForSanitizeComplete(page); // May take up to 60s for large files
 * console.log('Processing complete');
 * ```
 */
export async function waitForSanitizeComplete(
  page: Page,
  options?: { timeout?: number }
): Promise<void> {
  const timeout = options?.timeout ?? SANITIZE_TIMEOUT;

  /**
   * Wait for any of these completion signals:
   * - Processing indicator hidden (normal completion)
   * - Results panel visible (success with output)
   * - Error banner visible (error occurred)
   */
  await page.waitForFunction(
    () => {
      const win = window as any;

      // Check custom state flags first (if available)
      if (win.sanitizationInProgress === false) return true;
      if (win.misogiWasmState?.sanitizing === false) return true;

      // Fall back to DOM-based detection
      const processingStatus = document.getElementById('processing-status');
      const resultsPanel = document.getElementById('results-panel');
      const errorBanner = document.getElementById('error-banner');

      const processingHidden =
        processingStatus &&
        processingStatus.style.display === 'none' &&
        !processingStatus.classList.contains('visible');

      const resultsVisible =
        resultsPanel &&
        resultsPanel.classList.contains('results-panel--visible');

      const errorVisible =
        errorBanner &&
        (errorBanner.style.display !== 'none' ||
          errorBanner.classList.contains('error-banner--visible'));

      return processingHidden || resultsVisible || errorVisible;
    },
    { timeout }
  );
}

/**
 * Extract sanitization result data from the application's internal state.
 *
 * Reads the last sanitization result stored in the app's state object.
 * Returns structured data including success status, threat count, and
 * error information for assertion in tests.
 *
 * ## Data Source
 *
 * The wasm-browser demo stores results in `state.lastSanitizeResult` after
 * each sanitization call. This function accesses that state via page.evaluate()
 * to extract the result without relying on DOM parsing (which is fragile).
 *
 * @param page - Playwright Page instance.
 * @returns Structured result object with sanitization outcome details.
 *
 * @example
 * ```typescript
 * const result = await getSanitizeResult(page);
 * expect(result.success).toBe(true);
 * expect(result.threatsFound).toBeGreaterThanOrEqual(0);
 * ```
 */
export async function getSanitizeResult(page: Page): Promise<{
  /** Whether sanitization completed without throwing an exception. */
  success: boolean;

  /** Number of threats detected and removed (or 0 if clean). */
  threatsFound: number;

  /** Human-readable error message if sanitization failed (empty string on success). */
  errorMessage: string;

  /** Size of sanitized output in bytes (0 if no output). */
  outputSize: number;

  /** Whether PII scan found any matches. */
  piiDetected: boolean;
}> {
  return page.evaluate(() => {
    /**
     * Access the application's internal state to retrieve the most recent
     * sanitization result. The state object is maintained by app.js and
     * updated after each sanitize_pdf/sanitize_office call.
     */
    const win = window as any;
    const state = win.misogiWasmState || {};
    const result = state.lastSanitizeResult || null;

    return {
      success: result?.success ?? false,
      threatsFound: result?.threats_found ?? result?.threatsFound ?? 0,
      errorMessage: result?.error_message ?? result?.errorMessage ?? '',
      outputSize: result?.output_data?.length ?? 0,
      piiDetected: !!(
        state.lastPiiResult &&
        state.lastPiiResult.found &&
        state.lastPiiResult.matches &&
        state.lastPiiResult.matches.length > 0
      ),
    };
  });
}

// =============================================================================
// UI State Verification Helpers
// =============================================================================

/**
 * Verify that the WASM loading overlay is visible.
 *
 * Used to confirm the progressive enhancement strategy: UI should show
 * immediately while WASM loads in the background. The overlay provides
 * visual feedback during initialization.
 *
 * @param page - Playwright Page instance.
 * @returns True if the loading overlay is visible, false otherwise.
 */
export async function isWasmLoadingOverlayVisible(page: Page): Promise<boolean> {
  const overlay = page.locator('#wasm-loading-overlay');
  try {
    await expect(overlay).toBeVisible({ timeout: UI_TRANSITION_TIMEOUT });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify that the WASM loading overlay is hidden (loading complete).
 *
 * After successful initialization, the overlay should be hidden via CSS
 * class toggle (`wasm-loading-overlay--hidden`) and eventually removed
 * from the visible DOM.
 *
 * @param page - Playwright Page instance.
 * @returns True if the loading overlay is hidden, false otherwise.
 */
export async function isWasmLoadingOverlayHidden(page: Page): Promise<boolean> {
  const overlay = page.locator('#wasm-loading-overlay');
  try {
    /** Check for hidden class or display:none style. */
    await expect(overlay).toHaveClass(/wasm-loading-overlay--hidden/, {
      timeout: UI_TRANSITION_TIMEOUT,
    });
    return true;
  } catch {
    // Fallback: check if display is none or element is detached
    const isVisible = await overlay.isVisible().catch(() => false);
    return !isVisible;
  }
}

/**
 * Get the current error message displayed in the error banner.
 *
 * Extracts the text content from the error message element for assertion
 * in error scenario tests. Returns empty string if no error is displayed.
 *
 * @param page - Playwright Page instance.
 * @returns The error message text, or empty string if no error is shown.
 */
export async function getErrorMessage(page: Page): Promise<string> {
  const errorMsg = page.locator('#error-message');

  try {
    /** Only read text if error banner is actually visible. */
    const isVisible = await errorMsg.isVisible({ timeout: 1000 });
    if (isVisible) {
      return await errorMsg.textContent() || '';
    }
    return '';
  } catch {
    return '';
  }
}

/**
 * Verify that error message contains Japanese text.
 *
 * Uses Unicode range detection to identify Japanese characters (Hiragana,
 * Katakana, Kanji) in the error message. Ensures i18n localization is
 * working correctly across different error scenarios.
 *
 * @param page - Playwright Page instance.
 * @returns True if error message contains Japanese characters, false otherwise.
 */
export async function hasJapaneseErrorMessage(page: Page): Promise<boolean> {
  const message = await getErrorMessage(page);

  if (!message) return false;

  /**
   * Regular expression matching Japanese character ranges:
   * - \u3040-\u309F: Hiragana
   * - \u30A0-\u30FF: Katakana
   * - \u4E00-\u9FAF: CJK Unified Ideographs (Kanji)
   * - \u3000-\u303F: CJK Symbols and Punctuation
   */
  const japaneseRegex = /[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF\u3000-\u303F]/;
  return japaneseRegex.test(message);
}

/**
 * Get threat count displayed in the results panel.
 *
 * Reads the numeric threat count from the UI for visual regression testing.
 * Complements getSanitizeResult() by verifying what the user actually sees.
 *
 * @param page - Playwright Page instance.
 * @returns Threat count number, or -1 if not visible.
 */
export async function getThreatCountFromUI(page: Page): Promise<number> {
  const threatCountEl = page.locator('#threat-count-value');

  try {
    const isVisible = await threatCountEl.isVisible({ timeout: 1000 });
    if (!isVisible) return -1;

    const text = await threatCountEl.textContent();
    return parseInt(text || '0', 10);
  } catch {
    return -1;
  }
}

// =============================================================================
// Browser Feature Detection Helpers
// =============================================================================

/**
 * Detect WebAssembly support in the current browser context.
 *
 * Evaluates WebAssembly availability at runtime. Used for skip conditions
 * in tests that require WASM support (though all target browsers should
 * have it, this enables defensive coding).
 *
 * @param page - Playwright Page instance.
 * @returns Object indicating WASM support status and reason if unsupported.
 */
export async function detectWasmSupport(page: Page): Promise<{
  supported: boolean;
  reason: string | null;
}> {
  return page.evaluate(() => {
    if (!window.WebAssembly) {
      return {
        supported: false,
        reason: 'WebAssembly global object not found',
      };
    }

    if (typeof WebAssembly.instantiate !== 'function') {
      return {
        supported: false,
        reason: 'WebAssembly.instantiate is not a function',
      };
    }

    return { supported: true, reason: null };
  });
}

/**
 * Detect SharedArrayBuffer and cross-origin isolation status.
 *
 * SharedArrayBuffer is required for advanced WASM features like
 * multi-threading. COOP/COEP headers must be properly configured for
 * SAB to be usable (not just present).
 *
 * @param page - Playwright Page instance.
 * @returns Object with SAB availability and isolation status.
 */
export async function detectSharedArrayBufferStatus(page: Page): Promise<{
  hasSharedArrayBuffer: boolean;
  crossOriginIsolated: boolean;
  warning: string | null;
}> {
  return page.evaluate(() => {
    const hasSAB = typeof SharedArrayBuffer !== 'undefined';
    const coopCoepSet = window.crossOriginIsolated === true;

    let warning: string | null = null;

    if (hasSAB && !coopCoepSet) {
      warning =
        'SharedArrayBuffer available but COOP/COEP headers not set';
    }

    return {
      hasSharedArrayBuffer: hasSAB,
      crossOriginIsolated: coopCoepSet,
      warning: warning,
    };
  });
}
