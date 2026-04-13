/**
 * =============================================================================
 * Misogi WASM — WebAssembly Module Loading Tests
 * =============================================================================
 *
 * Comprehensive test suite verifying that the WebAssembly module loads
 * correctly across different browsers (Chromium, Firefox, WebKit/Safari).
 * These tests validate the critical first step of the application lifecycle:
 * fetching, compiling, and instantiating the WASM binary.
 *
 * ## Test Categories
 *
 * 1. **Error-Free Loading**: Verify no console errors during initialization
 * 2. **FFI Function Availability**: Confirm all exported functions exist
 * 3. **Loading UI States**: Validate progressive enhancement behavior
 * 4. **Browser Compatibility**: Ensure consistent behavior across engines
 * 5. **Feature Detection**: Verify browser capability detection works
 * 6. **Performance Bounds**: Check loading completes within time limits
 *
 * ## Why These Tests Matter
 *
 * WASM loading is the foundation of the entire application. If this step fails:
 * - File upload UI is non-functional (buttons remain disabled)
 * - Sanitization features are completely unavailable
 * - Users see only an error screen with build instructions
 * - The product appears broken regardless of other code quality
 *
 * ## Test Strategy
 *
 * - **No external dependencies**: All tests use built-in assertions only
 * - **Explicit waits**: Use waitForWasmLoad() instead of fixed timeouts
 * - **Console monitoring**: Capture errors during load for diagnostics
 * - **DOM validation**: Verify both state flags AND visual feedback
 * - **Cross-browser**: Run on all configured Playwright projects
 *
 * @see helpers.ts - waitForWasmLoad(), captureWasmErrors()
 * @see ../examples/wasm-browser/wasm-loader.js - Initialization logic
 * =============================================================================
 */

import { test, expect, Page } from '@playwright/test';
import {
  waitForWasmLoad,
  captureWasmErrors,
  isWasmLoadingOverlayVisible,
  isWasmLoadingOverlayHidden,
  detectWasmSupport,
  detectSharedArrayBufferStatus,
  WASM_LOAD_TIMEOUT,
  UI_TRANSITION_TIMEOUT,
} from './helpers';

// =============================================================================
// Test Suite: WASM Module Loading Fundamentals
// =============================================================================

test.describe('WASM Module Loading', () => {

  // -------------------------------------------------------------------------
  // Test: Error-Free Initialization
  // -------------------------------------------------------------------------

  /**
   * Verify that WASM module loads without JavaScript console errors.
   *
   * This is the most fundamental smoke test: if WASM can't even load without
   * errors, nothing else will work. Common failure modes include:
   * - Network error: Failed to fetch .wasm binary (404, CORS)
   * - Compile error: Invalid WASM format or unsupported features
   * - Runtime error: Import/linking failures (missing memory/table imports)
   *
   * ## Browser-Specific Considerations
   *
   * - **Chromium**: Usually fastest, best error messages
   * - **Firefox**: May have different error text for same failures
   * - **WebKit**: Sometimes silently fails with vague errors
   */
  test('should load WASM module without console errors', async ({ page }) => {
    /** Collect all WASM-related console errors during page load + init. */
    const errors = await captureWasmErrors(page, async () => {
      await page.goto('/');

      /** Wait for WASM to fully initialize (or timeout). */
      await waitForWasmLoad(page);
    });

    /**
     * Assert that no WASM-related errors were captured.
     * Empty array means clean initialization.
     */
    expect(errors.filter(e =>
      e.toLowerCase().includes('wasm') ||
      e.toLowerCase().includes('webassembly')
    )).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Test: FFI Function Availability
  // -------------------------------------------------------------------------

  /**
   * Verify that all expected FFI (Foreign Function Interface) functions are
   * exposed by the WASM module after successful initialization.
   *
   * The Misogi WASM module exports four primary functions:
   * - `sanitize_pdf()`: PDF document sanitization pipeline
   * - `sanitize_office()`: Office document (DOCX/XLSX/PPTX) sanitization
   * - `scan_pii()`: PII (Personally Identifiable Information) detection
   * - `detect_file_type()`: Magic byte-based file type identification
   *
   * These functions are imported in wasm-loader.js line ~135-141 and stored
   * in state.wasmFunctions for later use by app.js.
   *
   * ## Why Check Function Types?
   *
   * Simply checking existence isn't enough — we verify they're actually
   * callable functions (not undefined, null, or other types). This catches:
   * - Tree-shaking removing unused exports
   * - Renaming/mangling during build process
   * - Conditional exports based on feature flags
   */
  test('should expose all expected FFI functions', async ({ page }) => {
    /** Navigate to demo page and wait for WASM init. */
    await page.goto('/');
    await waitForWasmLoad(page);

    /**
     * Evaluate which FFI functions are available and their types.
     * Accesses the app's internal state where function references are stored.
     */
    const functions = await page.evaluate(() => {
      const win = window as any;
      const state = win.misogiWasmState || {};
      const wasmFns = state.wasmFunctions || {};

      return {
        hasSanitizePdf: typeof wasmFns.sanitize_pdf === 'function',
        hasSanitizeOffice: typeof wasmFns.sanitize_office === 'function',
        hasScanPii: typeof wasmFns.scan_pii === 'function',
        hasDetectFileType: typeof wasmFns.detect_file_type === 'function',
      };
    });

    /** Assert all four core functions are present and callable. */
    expect(functions.hasSanitizePdf).toBe(true);
    expect(functions.hasSanitizeOffice).toBe(true);
    expect(functions.hasScanPii).toBe(true);
    expect(functions.hasDetectFileType).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Test: Loading Indicator Visibility
  // -------------------------------------------------------------------------

  /**
   * Verify that the loading overlay is shown during WASM initialization
   * and hidden after completion (progressive enhancement pattern).
   *
   * ## UX Rationale
   *
   * Users should see immediate feedback when they open the page, not a blank
   * screen while WASM downloads and compiles. The overlay provides:
   * - Visual indicator (spinner animation)
   * - Status message ("WASM モジュールを読み込み中...")
   * - Error display area if loading fails
   *
   * ## Implementation Details
   *
   * The overlay (`#wasm-loading-overlay`) starts visible via CSS and is hidden
   * by adding the class `wasm-loading-overlay--hidden` after init succeeds.
   * After a 500ms CSS transition, it's removed from layout (display:none).
   */
  test('should show loading indicator during WASM load', async ({ page }) => {
    /** Navigate to page (loading overlay should be immediately visible). */
    await page.goto('/');

    /**
     * Verify loading overlay is visible within 5 seconds of navigation.
     * Uses CSS selector matching the overlay element from index.html.
     */
    const loaderVisible = await isWasmLoadingOverlayVisible(page);
    expect(loaderVisible).toBe(true);

    /** Wait for WASM to finish initializing. */
    await waitForWasmLoad(page);

    /**
     * Verify loading overlay is now hidden after successful initialization.
     * The hideWasmLoadingOverlay() function adds the --hidden class.
     */
    const loaderHidden = await isWasmLoadingOverlayHidden(page);
    expect(loaderHidden).toBe(true);
  });

});

// =============================================================================
// Test Suite: Browser Feature Detection
// =============================================================================

test.describe('Browser Capability Detection', () => {

  /**
   * Verify that WebAssembly is supported in the current browser.
   *
   * All modern browsers (Chrome 57+, Firefox 52+, Safari 11+, Edge 16+)
   * support WebAssembly. This test ensures our feature detection logic
   * correctly identifies support and doesn't block capable browsers.
   *
   * ## When Would This Fail?
   *
   * - Very old browser versions (pre-2017)
   * - Enterprise environments with WASM disabled via group policy
   * - Headless browsers without WASM enabled
   * - Unusual embedded browser contexts
   */
  test('should detect WebAssembly support', async ({ page }) => {
    await page.goto('/');

    const support = await detectWasmSupport(page);

    /** All target browsers must support WASM for tests to proceed. */
    expect(support.supported).toBe(true);
    expect(support.reason).toBeNull();
  });

  /**
   * Verify SharedArrayBuffer detection works correctly.
   *
   * SharedArrayBuffer (SAB) is required for advanced WASM features like
   * multi-threading (via Web Workers). However, SAB requires cross-origin
   * isolation via COOP/COEP headers, which may not be set in all environments.
   *
   * ## Expected Behavior
   *
   * - **With COOP/COEP headers**: hasSharedArrayBuffer=true, crossOriginIsolated=true
   * - **Without headers**: hasSharedArrayBuffer=true, crossOriginIsolated=false, warning set
   * - **Old browsers**: hasSharedArrayBuffer=false (SAB deprecated/restricted)
   *
   * Note: We don't assert specific values here because configuration varies
   * between local development, CI, and production deployments.
   */
  test('should detect SharedArrayBuffer status', async ({ page }) => {
    await page.goto('/');

    const sabStatus = await detectSharedArrayBufferStatus(page);

    /**
     * Just verify the detection function runs without error and returns
     * a valid structure. Specific values depend on server configuration.
     */
    expect(typeof sabStatus.hasSharedArrayBuffer).toBe('boolean');
    expect(typeof sabStatus.crossOriginIsolated).toBe('boolean');
    expect(typeof sabStatus.warning).toBe('string');

    /** Log status for debugging (visible in test report). */
    console.log('[Feature Detection] SharedArrayBuffer Status:', JSON.stringify(sabStatus));
  });
});

// =============================================================================
// Test Suite: Loading Performance Bounds
// =============================================================================

test.describe('WASM Loading Performance', () => {

  /**
   * Verify that WASM loading completes within acceptable time bounds.
   *
   * While we don't enforce strict performance SLAs in compatibility tests,
   * we should ensure loading doesn't take excessively long (>30s), which
   * would indicate a problem such as:
   * - Extremely large WASM binary (should be <5MB)
   * - Slow network in CI environment
   * - WASM compilation bottleneck (should use streaming compilation)
   * - Infinite loop or deadlock in initialization code
   *
   * ## Measurement Approach
   *
   * Record timestamp before and after waitForWasmLoad() to measure actual
   * wall-clock time. Compare against the configured timeout as upper bound.
   */
  test('should complete WASM loading within timeout', async ({ page }) => {
    /** Record start time before navigation. */
    const startTime = Date.now();

    await page.goto('/');
    await waitForWasmLoad(page);

    /** Calculate elapsed time in milliseconds. */
    const elapsed = Date.now() - startTime;

    /**
     * Assert loading completed before the maximum allowed timeout.
     * Using 90% of timeout as threshold to allow margin for variance.
     */
    const maxAcceptableTime = WASM_LOAD_TIMEOUT * 0.9;
    expect(elapsed).toBeLessThan(maxAcceptableTime);

    /** Log actual timing for performance tracking. */
    console.log(`[Performance] WASM loaded in ${elapsed}ms (limit: ${maxAcceptableTime}ms)`);
  });
});

// =============================================================================
// Test Suite: DOM State Validation
// =============================================================================

test.describe('Post-Load DOM State', () => {

  /**
   * Verify that interactive UI elements are enabled after WASM loads.
   *
   * During WASM initialization, interactive elements are disabled to prevent
   * user actions that would fail (e.g., clicking sanitize before functions
   * are available). After successful load, these elements should be re-enabled.
   *
   * Elements checked:
   * - Sanitize button (#sanitize-btn): Should not have disabled attribute
   * - Drop zone (#drop-zone): Should not have aria-disabled="true"
   */
  test('should enable interactive elements after WASM ready', async ({ page }) => {
    await page.goto('/');
    await waitForWasmLoad(page);

    /** Verify sanitize button is enabled (clickable). */
    const sanitizeBtn = page.locator('#sanitize-btn');
    await expect(sanitizeBtn).toBeEnabled({ timeout: UI_TRANSITION_TIMEOUT });

    /** Verify drop zone is not marked as disabled for accessibility. */
    const dropZone = page.locator('#drop-zone');
    const ariaDisabled = await dropZone.getAttribute('aria-disabled');
    expect(ariaDisabled).not.toBe('true');
  });

  /**
   * Verify that the main application container is accessible.
   *
   * After WASM loads and the overlay hides, users should see the main app
   * interface including header, drop zone, and action buttons. This test
   * verifies the progressive enhancement strategy worked correctly.
   */
  test('should show main application interface', async ({ page }) => {
    await page.goto('/');
    await waitForWasmLoad(page);

    /** Header section should be visible. */
    const header = page.locator('.app-header');
    await expect(header).toBeVisible({ timeout: UI_TRANSITION_TIMEOUT });

    /** Drop zone (file upload area) should be visible. */
    const dropZone = page.locator('#drop-zone');
    await expect(dropZone).toBeVisible({ timeout: UI_TRANSITION_TIMEOUT });

    /** Action bar with sanitize button should be visible. */
    const actionBar = page.locator('#action-bar');
    await expect(actionBar).toBeVisible({ timeout: UI_TRANSITION_TIMEOUT });
  });
});
