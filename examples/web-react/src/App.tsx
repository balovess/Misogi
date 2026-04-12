/**
 * Main application component for Misogi React frontend.
 *
 * Orchestrates application layout with:
 * - Fixed header with connection status
 * - Main content area with FileUploader
 * - Error boundary for graceful error handling
 *
 * @module App
 */

import React, { useState, useCallback } from 'react';
import { useMisogiClient, ConnectionState } from './hooks/useMisogiClient';
import { Header } from './components/Header';
import { FileUploader } from './components/FileUploader';
import './index.css';

// ============================================================================
// Japanese UI string constants
// ============================================================================

/** Japanese text labels for app-level UI */
const LABELS = {
  /** Loading state message */
  LOADING: '初期化中...',
  /** Connection error title */
  CONNECTION_ERROR: '接続エラー',
  /** Connection error description */
  CONNECTION_ERROR_DESC:
    'Misogiバックエンドサーバーに接続できません。Envoyプロキシが起動しているか確認してください。',
  /** Retry button label */
  RETRY: '再試行',
  /** Application footer text */
  FOOTER: 'Misogi ファイル浄化エンジン - gRPC-Web フロントエンドサンプル',
} as const;

/**
 * Loading screen displayed during initial client initialization.
 *
 * Shows centered loading indicator while gRPC-Web client
 * is being created and connectivity is being tested.
 *
 * @returns {JSX.Element} Rendered loading component
 */
function LoadingScreen(): React.ReactElement {
  return (
    <div className="loading-screen" role="status" aria-live="polite">
      <div className="loading-spinner" aria-hidden="true" />
      <p className="loading-text">{LABELS.LOADING}</p>
    </div>
  );
}

/**
 * Error screen for failed backend connections.
 *
 * Displays when Misogi gRPC backend cannot be reached via Envoy proxy.
 * Provides retry button to attempt reconnection.
 *
 * @param {object} props - Component props
 * @param {string} props.error - Error message to display
 * @param {() => void} props.onRetry - Callback for retry action
 * @returns {JSX.Element} Rendered error component
 */
function ConnectionErrorScreen({
  error,
  onRetry,
}: {
  error: string;
  onRetry: () => void;
}): React.ReactElement {
  return (
    <div className="error-screen" role="alert">
      <h2 className="error-title">{LABELS.CONNECTION_ERROR}</h2>
      <p className="error-description">{LABELS.CONNECTION_ERROR_DESC}</p>
      {error && <pre className="error-details">{error}</pre>}
      <button onClick={onRetry} className="btn btn-primary btn-large">
        {LABELS.RETRY}
      </button>
    </div>
  );
}

/**
 * Root application component.
 *
 * Manages global state including:
 * - gRPC-Web client initialization and lifecycle
 * - Language/locale preference (stub)
 * - Layout structure (header + main content + footer)
 *
 * Uses useMisogiClient hook to establish and maintain connection
 * to Misogi backend through Envoy proxy.
 *
 * @returns {JSX.Element} Rendered application
 */
function App(): React.ReactElement {
  // Initialize gRPC-Web client and monitor connection state
  const { connection, client, error, retryConnection } = useMisogiClient();

  // Locale state (stub for future i18n implementation)
  const [locale, setLocale] = useState<string>('ja');

  /**
   * Handles locale change from Header component.
   * In production, this would trigger i18n library context update.
   */
  const handleLocaleChange = useCallback((newLocale: string): void => {
    setLocale(newLocale);
    // TODO: Integrate with i18n library (e.g., react-i18next)
    console.log(`[Stub] Locale changed to: ${newLocale}`);
  }, []);

  /**
   * Renders appropriate content based on connection state:
   * - UNKNOWN/TESTING: Show loading spinner
   * - DISCONNECTED: Show error screen with retry option
   * - CONNECTED: Show main application interface
   */
  const renderContent = (): React.ReactElement => {
    switch (connection) {
      case ConnectionState.UNKNOWN:
      case ConnectionState.TESTING:
        return <LoadingScreen />;

      case ConnectionState.DISCONNECTED:
        return (
          <ConnectionErrorScreen
            error={error ?? 'Unknown error'}
            onRetry={retryConnection}
          />
        );

      case ConnectionState.CONNECTED:
        if (!client) {
          // Should not happen in CONNECTED state, but handle gracefully
          return <ConnectionErrorScreen error="Client not initialized" onRetry={retryConnection} />;
        }
        return <FileUploader client={client} />;

      default:
        return <LoadingScreen />;
    }
  };

  return (
    <div className="app-container" lang={locale}>
      {/* Fixed header */}
      <Header
        connection={connection}
        onRetryConnection={retryConnection}
        locale={locale}
        onLocaleChange={handleLocaleChange}
      />

      {/* Scrollable main content */}
      <main className="app-main">{renderContent()}</main>

      {/* Footer */}
      <footer className="app-footer">
        <p className="footer-text">{LABELS.FOOTER}</p>
      </footer>
    </div>
  );
}

export default App;
