/**
 * =============================================================================
 * Misogi WASM — Playwright Browser Compatibility Test Configuration
 * =============================================================================
 *
 * Configuration for automated browser compatibility testing of the WebAssembly
 * module across major browsers (Chromium, Firefox, WebKit/Safari).
 *
 * ## Test Architecture
 *
 * - **Multi-browser**: Tests run on Chromium (latest + stable), Firefox,
 *   and WebKit to ensure cross-browser compatibility
 * - **HTTP Server**: Local static server serves the wasm-browser demo at
 *   port 8080 (required for WASM loading due to CORS restrictions)
 * - **CI/CD Ready**: Configured for headless execution with retry logic
 * - **Reporting**: HTML report with screenshots on failure, JSON for CI
 *
 * ## Usage
 *
 * ```bash
 * # Run all tests
 * npm test
 *
 * # Run in headed mode (visible browser)
 * npm run test:headed
 *
 * # Interactive UI mode
 * npm run test:ui
 *
 * # Generate compatibility report
 * node generate-report.js
 * ```
 *
 * ## Prerequisites
 *
 * 1. Build WASM package:
 *    `wasm-pack build --target web crates/misogi-wasm`
 *
 * 2. Install dependencies:
 *    `npm install`
 *
 * 3. Install browsers (first time only):
 *    `npx playwright install chromium firefox webkit`
 *
 * @see https://playwright.dev/docs/test-configuration
 * =============================================================================
 */

import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for Misogi WASM browser compatibility testing.
 *
 * @type {import('@playwright/test').PlaywrightTestConfig}
 */
export default defineConfig({
  // ---------------------------------------------------------------------------
  // Test Discovery
  // ---------------------------------------------------------------------------

  /** Directory containing test files (relative to this config file). */
  testDir: './',

  /** Glob pattern for test file discovery. */
  testMatch: '*.spec.ts',

  /** Run tests in parallel across all configured browser projects. */
  fullyParallel: true,

  // ---------------------------------------------------------------------------
  // CI/CD Integration
  // ---------------------------------------------------------------------------

  /**
   * Fail if `.only` is used in test files when running in CI.
   * Prevents accidental skipping of tests in production pipelines.
   */
  forbidOnly: !!process.env.CI,

  /** Retry failed tests twice in CI environments (network flakiness). */
  retries: process.env.CI ? 2 : 0,

  /** Use single worker in CI to avoid resource contention. */
  workers: process.env.CI ? 1 : undefined,

  // ---------------------------------------------------------------------------
  // Reporting
  // ---------------------------------------------------------------------------

  /**
   * Multi-format reporting strategy:
   * - HTML: Visual report with screenshots and traces for debugging
   * - JSON: Machine-readable results for CI integration and reporting scripts
   */
  reporter: [
    ['html', {
      outputFolder: 'playwright-report',
      open: 'never',           // Don't auto-open in CI/headless mode
      host: 'localhost',
    }],
    ['json', { outputFile: 'results.json' }],
  ],

  // ---------------------------------------------------------------------------
  // Global Settings
  // ---------------------------------------------------------------------------

  use: {
    /**
     * Base URL for all page navigations.
     * Points to the local HTTP server serving the wasm-browser demo.
     */
    baseURL: 'http://localhost:8080',

    /**
     * Capture trace on first retry for debugging failed tests.
     * Traces include DOM snapshots, network requests, and console logs.
     */
    trace: 'on-first-retry',

    /**
     * Take screenshot only when a test fails.
     * Screenshots saved to test output directory for post-mortem analysis.
     */
    screenshot: 'only-on-failure',

    /** Capture video during test execution for visual regression analysis. */
    video: 'retain-on-failure',

    /** Default navigation timeout (WASM loading can be slow). */
    navigationTimeout: 60000,

    /** Default action timeout for UI interactions. */
    actionTimeout: 30000,

    /** Ignore HTTPS certificate errors (not needed for localhost HTTP). */
    ignoreHTTPSErrors: false,

    /** Capture console logs and network errors for debugging. */
    locale: 'ja-JP',          // Japanese locale for i18n testing
  },

  // ---------------------------------------------------------------------------
  // Browser Projects
  // ---------------------------------------------------------------------------

  /**
   * Browser configuration matrix.
   * Each project represents a target browser/environment combination.
   *
   * ## Project Rationale
   *
   * - **chromium-latest**: Latest Chromium (Playwright bundled) — catches
   *   bleeding-edge issues early
   * - **chromium-prev**: System-installed Chrome (stable channel) — tests
   *   against real user Chrome version
   * - **firefox-latest**: Firefox latest — ensures Gecko engine compatibility
   * - **webkit-safari**: WebKit (Safari engine) — ensures WebKit/Blink parity
   */
  projects: [
    {
      name: 'chromium-latest',
      use: {
        ...devices['Desktop Chrome'],
        // Use Playwright's bundled Chromium (latest)
      },
    },
    {
      name: 'chromium-stable',
      use: {
        ...devices['Desktop Chrome'],
        // Use system-installed Google Chrome (stable release)
        channel: 'chrome',
      },
    },
    {
      name: 'firefox-latest',
      use: {
        ...devices['Desktop Firefox'],
        // Firefox-specific settings for WASM performance
        launchOptions: {
          // Enable some Firefox prefs that help with WASM
          args: [],
        },
      },
    },
    {
      name: 'webkit-safari',
      use: {
        ...devices['Desktop Safari'],
        // WebKit/Safari specific settings
      },
    },
  ],

  // ---------------------------------------------------------------------------
  // Web Server (for WASM loading via HTTP)
  // ---------------------------------------------------------------------------

  /**
   * Local static file server configuration.
   *
   * ## Why HTTP Server?
   *
   * Browsers block WASM module loading via `file://` protocol due to security
   * restrictions (CORS, COOP/COEP headers). A local HTTP server is required
   * to properly serve the WASM binary and JavaScript glue code.
   *
   * ## Server Choice
   *
   * Using `serve` package (lightweight, zero-config static server) instead of
   * custom Node.js server. This matches the documented usage in the demo README.
   */
  webServer: {
    /**
     * Command to start the static file server.
     * Serves the wasm-browser example directory which contains index.html,
     * app.js, and references to ../pkg/misogi_wasm.js (the WASM package).
     */
    command: 'npx serve ../../../examples/wasm-browser -l 8080 --no-clipboard',

    /** Port the server listens on (must match baseURL). */
    port: 8080,

    /**
     * Reuse existing server if already running (useful during development).
     * In CI, always start fresh to ensure clean state.
     */
    reuseExistingServer: !process.env.CI,

    /**
     * Timeout for server startup (includes time for serve to install/download
     * if not present, plus actual startup time).
     */
    timeout: 120_000,

    /** Expected HTTP status code indicating server readiness. */
    expectedStatusCode: 200,
  },

  // ---------------------------------------------------------------------------
  // Output Directories
  // ---------------------------------------------------------------------------

  /** Directory for test artifacts (screenshots, traces, videos). */
  outputDir: 'test-results',

  // ---------------------------------------------------------------------------
  // Global Setup/Teardown (optional)
  // ---------------------------------------------------------------------------

  /**
   * Global setup file path (relative to config).
   * Can be used for:
   * - Checking WASM package existence before tests
   * - Generating test fixtures (PDF/OOXML files)
   * - Setting up test environment variables
   */
  // globalSetup: './global-setup.ts',

  /**
   * Global teardown file path (relative to config).
   * Can be used for cleanup after all tests complete.
   */
  // globalTeardown: './global-teardown.ts',
});
