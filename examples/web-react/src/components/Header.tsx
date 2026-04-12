/**
 * Header component for Misogi application.
 *
 * Displays application branding, connection status to gRPC backend,
 * and language toggle control (stub for future i18n implementation).
 *
 * @module components/Header
 */

import React from 'react';
import type { ConnectionState } from '../hooks/useMisogiClient';

// ============================================================================
// Japanese UI string constants
// ============================================================================

/** Japanese text labels for header */
const LABELS = {
  /** Application title */
  TITLE: '禊',
  /** Application subtitle */
  SUBTITLE: 'ファイル浄化エンジン',
  /** Connection status labels */
  CONNECTED: '接続済み',
  DISCONNECTED: '未接続',
  TESTING: '接続中...',
  UNKNOWN: '状態不明',
  /** Language labels */
  LANGUAGE: '言語',
  JAPANESE: '日本語',
  ENGLISH: 'English',
} as const;

// ============================================================================
// Utility components
// ============================================================================

/** Props for connection status indicator */
interface ConnectionStatusProps {
  /** Current connection state */
  connection: ConnectionState;
}

/**
 * Visual indicator showing gRPC backend connection status.
 *
 * Uses color-coded dot and text label to communicate connectivity state:
 * - Green dot + "接続済み" when connected
 * - Red dot + "未接接続" when disconnected
 * - Yellow dot + "接続中..." during testing
 * - Gray dot + "状態不明" in unknown state
 *
 * @param {ConnectionStatusProps} props - Component props
 * @returns {JSX.Element} Rendered status indicator
 */
function ConnectionStatus({ connection }: ConnectionStatusProps): React.ReactElement {
  /**
   * Maps connection state to visual properties.
   */
  const getStatusConfig = (): {
    color: string;
    label: string;
    pulse: boolean;
  } => {
    switch (connection) {
      case ConnectionState.CONNECTED:
        return {
          color: '#22c55e', // green-500
          label: LABELS.CONNECTED,
          pulse: false,
        };
      case ConnectionState.DISCONNECTED:
        return {
          color: '#ef4444', // red-500
          label: LABELS.DISCONNECTED,
          pulse: false,
        };
      case ConnectionState.TESTING:
        return {
          color: '#eab308', // yellow-500
          label: LABELS.TESTING,
          pulse: true,
        };
      case ConnectionState.UNKNOWN:
      default:
        return {
          color: '#9ca3af', // gray-400
          label: LABELS.UNKNOWN,
          pulse: false,
        };
    }
  };

  const { color, label, pulse } = getStatusConfig();

  return (
    <div className="connection-status" role="status" aria-live="polite">
      <span
        className={`status-dot ${pulse ? 'pulse' : ''}`}
        style={{ backgroundColor: color }}
        aria-hidden="true"
      />
      <span className="status-label">{label}</span>
    </div>
  );
}

/** Props for language toggle button */
interface LanguageToggleProps {
  /** Currently selected locale code */
  currentLocale: string;
  /** Callback when user changes language */
  onLocaleChange: (locale: string) => void;
}

/**
 * Language toggle button (stub implementation).
 *
 * Provides UI for switching between Japanese and English locales.
 * In production, this would integrate with i18n library (react-i18next, etc.)
 * to actually change all UI strings.
 *
 * @param {LanguageToggleProps} props - Component props
 * @returns {JSX.Element} Rendered toggle button
 */
function LanguageToggle({
  currentLocale,
  onLocaleChange,
}: LanguageToggleProps): React.ReactElement {
  return (
    <div className="language-toggle">
      <span className="language-label">{LABELS.LANGUAGE}:</span>
      <button
        className={`lang-btn ${currentLocale === 'ja' ? 'active' : ''}`}
        onClick={() => onLocaleChange('ja')}
        aria-label={LABELS.JAPANESE}
        aria-pressed={currentLocale === 'ja'}
      >
        {LABELS.JAPANESE}
      </button>
      <span className="lang-separator">/</span>
      <button
        className={`lang-btn ${currentLocale === 'en' ? 'active' : ''}`}
        onClick={() => onLocaleChange('en')}
        aria-label={LABELS.ENGLISH}
        aria-pressed={currentLocale === 'en'}
      >
        {LABELS.ENGLISH}
      </button>
    </div>
  );
}

// ============================================================================
// Main component
// ============================================================================

/** Props for Header component */
interface HeaderProps {
  /** Current gRPC connection state */
  connection: ConnectionState;
  /** Callback to retry failed connection (optional) */
  onRetryConnection?: () => void;
  /** Currently selected locale */
  locale?: string;
  /** Callback when locale changes */
  onLocaleChange?: (locale: string) => void;
}

/**
 * Application header with branding and status indicators.
 *
 * Renders Misogi logo/kanji (禊), application subtitle, connection status
 * indicator, and optional language toggle. Designed for fixed positioning
 * at top of viewport.
 *
 * Layout:
 * ```
 * ┌─────────────────────────────────────────────┐
 * │ 禪  | ファイル浄化エンジン | ●接続済み | JA/EN │
 * └─────────────────────────────────────────────┘
 * ```
 *
 * @param {HeaderProps} props - Component props
 * @returns {JSX.Element} Rendered header component
 *
 * @example
 * ```tsx
 * function App() {
 *   const { connection, retryConnection } = useMisogiClient();
 *   return (
 *     <>
 *       <Header connection={connection} onRetryConnection={retryConnection} />
 *       <main>{/* content */}</main>
 *     </>
 *   );
 * }
 * ```
 */
export function Header({
  connection,
  onRetryConnection,
  locale = 'ja',
  onLocaleChange,
}: HeaderProps): React.ReactElement {
  /**
   * Handles click on connection status area.
   * Triggers retry if disconnected and handler provided.
   */
  const handleStatusClick = (): void => {
    if (connection === ConnectionState.DISCONNECTED && onRetryConnection) {
      onRetryConnection();
    }
  };

  return (
    <header className="app-header">
      {/* Branding section */}
      <div className="header-branding">
        <h1 className="header-title">{LABELS.TITLE}</h1>
        <p className="header-subtitle">{LABELS.SUBTITLE}</p>
      </div>

      {/* Status section */}
      <div
        className={`header-status ${connection === ConnectionState.DISCONNECTED ? 'clickable' : ''}`}
        onClick={handleStatusClick}
        role={connection === ConnectionState.DISCONNECTED ? 'button' : undefined}
        tabIndex={connection === ConnectionState.DISCONNECTED ? 0 : undefined}
        onKeyDown={(e) => {
          if (
            connection === ConnectionState.DISCONNECTED &&
            (e.key === 'Enter' || e.key === ' ')
          ) {
            handleStatusClick();
          }
        }}
        aria-label={
          connection === ConnectionState.DISCONNECTED
            ? `${LABELS.DISCONNECTED} - クリックして再試行`
            : undefined
        }
      >
        <ConnectionStatus connection={connection} />
      </div>

      {/* Language toggle section */}
      {onLocaleChange && (
        <div className="header-language">
          <LanguageToggle
            currentLocale={locale}
            onLocaleChange={onLocaleChange}
          />
        </div>
      )}
    </header>
  );
}
