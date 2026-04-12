/**
 * FileUploader component for Misogi file sanitization interface.
 *
 * Provides drag-and-drop file upload interface with:
 * - Drag-and-drop zone with visual feedback
 * - File selection button
 * - Selected file information display
 * - Sanitization policy selector
 * - Upload progress tracking
 * - Status display during processing
 * - Error display with retry option
 * - Download button for sanitized files
 *
 * @module components/FileUploader
 */

import React, { useCallback, useState, useRef, DragEvent } from 'react';
import { MisogigRpcClient } from '../client/grpc';
import { useSanitize, SanitizePhase } from '../hooks/useMisogiClient';
import { SanitizationPolicy, type SanitizationPolicyType } from '../types/proto';
import { SanitizationReport } from './SanitizationReport';

// ============================================================================
// Japanese UI string constants (i18n-ready)
// ============================================================================

/** Japanese text labels for UI elements */
const LABELS = {
  /** Drop zone placeholder text */
  DROP_ZONE: 'ファイルをここにドロップ、またはクリックして選択',
  /** Select file button label */
  SELECT_FILE: 'ファイルを選択',
  /** Sanitize action button label */
  SANITIZE: '浄化開始',
  /** Processing status label */
  PROCESSING: '処理中...',
  /** Ready status label */
  READY: '浄化完了',
  /** Download button label */
  DOWNLOAD: 'ダウンロード',
  /** Reset/clear button label */
  RESET: 'リセット',
  /** Retry button label */
  RETRY: '再試行',
  /** Cancel button label (future feature) */
  CANCEL: 'キャンセル',
  /** Policy selector label */
  POLICY_LABEL: '浄化ポリシー',
  /** File info section title */
  FILE_INFO: 'ファイル情報',
  /** File name label */
  FILE_NAME: 'ファイル名',
  /** File size label */
  FILE_SIZE: 'サイズ',
  /** File type label */
  FILE_TYPE: '種類',
  /** Status section title */
  STATUS: 'ステータス',
  /** Progress section title */
  PROGRESS: '進捗',
  /** Error section title */
  ERROR: 'エラー',
  /** Report section title */
  REPORT: 'レポート',
} as const;

/** Policy display names in Japanese */
const POLICY_NAMES: Record<SanitizationPolicyType, string> = {
  [SanitizationPolicy.STRIP_ACTIVE_CONTENT]: 'アクティブコンテンツ除去',
  [SanitizationPolicy.CONVERT_TO_FLAT]: 'フラット変換',
  [SanitizationPolicy.TEXT_ONLY]: 'テキストのみ抽出',
  [SanitizationPolicy.MAXIMUM_SECURITY]: '最大セキュリティ',
};

/** Phase display names in Japanese */
const PHASE_NAMES: Record<SanitizePhase, string> = {
  [SanitizePhase.IDLE]: '待機中',
  [SanitizePhase.SELECTED]: '選択済み',
  [SanitizePhase.UPLOADING]: 'アップロード中',
  [SanitizePhase.PROCESSING]: '処理中',
  [SanitizePhase.READY]: '準備完了',
  [SanitizePhase.DOWNLOADING]: 'ダウンロード中',
  [SanitizePhase.COMPLETED]: '完了',
  [SanitizePhase.ERROR]: 'エラー',
};

// ============================================================================
// Utility functions
// ============================================================================

/**
 * Formats file size to human-readable string.
 *
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size string (e.g., "1.5 MB")
 */
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const size = bytes / Math.pow(k, i);
  return `${size.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

/**
 * Gets file type icon based on extension.
 *
 * @param {string} filename - Filename to extract extension from
 * @returns {string} Emoji icon representing file type
 */
function getFileTypeIcon(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  const icons: Record<string, string> = {
    pdf: '📄',
    doc: '📝',
    docx: '📝',
    xls: '📊',
    xlsx: '📊',
    ppt: '📽️',
    pptx: '📽️',
    txt: '📃',
    csv: '📋',
    zip: '📦',
    default: '📁',
  };
  return icons[ext] ?? icons.default;
}

// ============================================================================
// Component
// ============================================================================

/** Props for FileUploader component */
interface FileUploaderProps {
  /** Initialized gRPC client instance */
  client: MisogigRpcClient;
}

/**
 * Main file upload and sanitization component.
 *
 * Provides complete UI for selecting files, choosing sanitization policies,
 * monitoring progress, and downloading sanitized results.
 *
 * @param {FileUploaderProps} props - Component props
 * @returns {JSX.Element} Rendered component
 *
 * @example
 * ```tsx
 * function App() {
 *   const { client } = useMisogiClient();
 *   return client ? <FileUploader client={client} /> : <Loading />;
 * }
 * ```
 */
export function FileUploader({ client }: FileUploaderProps): React.ReactElement {
  // State management via custom hook
  const {
    phase,
    file,
    policy,
    uploadProgress,
    fileStatus,
    report,
    error,
    selectFile,
    setPolicy,
    startSanitize,
    downloadResult,
    reset,
  } = useSanitize(client);

  // Local UI state
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // =========================================================================
  // Event handlers
  // =========================================================================

  /**
   * Handles drag enter event.
   * Sets visual feedback state.
   */
  const handleDragEnter = useCallback((e: DragEvent<HTMLDivElement>): void => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  /**
   * Handles drag leave event.
   * Clears visual feedback state.
   */
  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>): void => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  /**
   * Handles drag over event (required for drop).
   * Prevents default browser behavior.
   */
  const handleDragOver = useCallback(
    (e: DragEvent<HTMLDivElement>): void => {
      e.preventDefault();
      e.stopPropagation();
      if (!isDragOver) {
        setIsDragOver(true);
      }
    },
    [isDragOver],
  );

  /**
   * Handles file drop event.
   * Extracts first file and passes to selectFile handler.
   */
  const handleDrop = useCallback(
    (e: DragEvent<HTMLDivElement>): void => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const droppedFiles = e.dataTransfer.files;
      if (droppedFiles && droppedFiles.length > 0) {
        selectFile(droppedFiles[0]);
      }
    },
    [selectFile],
  );

  /**
   * Handles file input change event.
   * Extracts selected file and passes to selectFile handler.
   */
  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>): void => {
      const selectedFiles = e.target.files;
      if (selectedFiles && selectedFiles.length > 0) {
        selectFile(selectedFiles[0]);
      }
      // Reset input value so same file can be re-selected
      e.target.value = '';
    },
    [selectFile],
  );

  /**
   * Handles click on drop zone.
   * Triggers hidden file input click.
   */
  const handleClickDropZone = useCallback((): void => {
    fileInputRef.current?.click();
  }, []);

  /**
   * Determines if sanitize button should be disabled.
   */
  const isSanitizeDisabled =
    !file ||
    phase === SanitizePhase.UPLOADING ||
    phase === SanitizePhase.PROCESSING ||
    phase === SanitizePhase.DOWNLOADING;

  /**
   * Determines if download button should be shown/enabled.
   */
  const showDownloadButton =
    phase === SanitizePhase.READY || phase === SanitizePhase.COMPLETED;

  // =========================================================================
  // Render helpers
  // =========================================================================

  /**
   * Renders the drop zone area.
   */
  const renderDropZone = (): React.ReactElement => (
    <div
      className={`drop-zone ${isDragOver ? 'drag-over' : ''}`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      onClick={handleClickDropZone}
      role="button"
      tabIndex={0}
      aria-label={LABELS.SELECT_FILE}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          handleClickDropZone();
        }
      }}
    >
      <div className="drop-zone-content">
        <div className="drop-zone-icon">
          {file ? getFileTypeIcon(file.name) : '📤'}
        </div>
        <p className="drop-zone-text">
          {file ? file.name : LABELS.DROP_ZONE}
        </p>
        {file && (
          <p className="drop-zone-size">{formatFileSize(file.size)}</p>
        )}
      </div>
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileSelect}
        className="hidden-file-input"
        aria-hidden="true"
      />
    </div>
  );

  /**
   * Renders the policy selector dropdown.
   */
  const renderPolicySelector = (): React.ReactElement => (
    <div className="policy-selector">
      <label htmlFor="policy-select" className="policy-label">
        {LABELS.POLICY_LABEL}
      </label>
      <select
        id="policy-select"
        value={policy}
        onChange={(e) => setPolicy(e.target.value as SanitizationPolicyType)}
        disabled={
          phase === SanitizePhase.UPLOADING ||
          phase === SanitizePhase.PROCESSING
        }
        className="policy-select"
      >
        {Object.entries(POLICY_NAMES).map(([key, name]) => (
          <option key={key} value={key}>
            {name}
          </option>
        ))}
      </select>
    </div>
  );

  /**
   * Renders the action buttons row.
   */
  const renderActionButtons = (): React.ReactElement => (
    <div className="action-buttons">
      {/* Sanitize/Start button */}
      <button
        onClick={() => startSanitize()}
        disabled={isSanitizeDisabled}
        className={`btn btn-primary ${
          isSanitizeDisabled ? 'btn-disabled' : ''
        }`}
      >
        {phase === SanitizePhase.PROCESSING
          ? LABELS.PROCESSING
          : LABELS.SANITIZE}
      </button>

      {/* Download button */}
      {showDownloadButton && (
        <button
          onClick={() => downloadResult()}
          disabled={phase === SanitizePhase.DOWNLOADING}
          className="btn btn-success"
        >
          {phase === SanitizePhase.DOWNLOADING
            ? LABELS.DOWNLOADING
            : LABELS.DOWNLOAD}
        </button>
      )}

      {/* Reset button */}
      {(phase === SanitizePhase.READY ||
        phase === SanitizePhase.COMPLETED ||
        phase === SanitizePhase.ERROR) && (
        <button onClick={reset} className="btn btn-secondary">
          {LABELS.RESET}
        </button>
      )}
    </div>
  );

  /**
   * Renders progress bar during upload.
   */
  const renderProgressBar = (): React.ReactElement | null => {
    if (
      phase !== SanitizePhase.UPLOADING &&
      phase !== SanitizePhase.DOWNLOADING
    ) {
      return null;
    }

    return (
      <div className="progress-container">
        <label className="progress-label">{LABELS.PROGRESS}</label>
        <div className="progress-bar-wrapper">
          <div
            className="progress-bar-fill"
            style={{ width: `${uploadProgress}%` }}
            role="progressbar"
            aria-valuenow={Math.round(uploadProgress)}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
        <span className="progress-text">{`${Math.round(uploadProgress)}%`}</span>
      </div>
    );
  };

  /**
   * Renders status information panel.
   */
  const renderStatusPanel = (): React.ReactElement | null => {
    if (!fileStatus && phase !== SanitizePhase.PROCESSING) return null;

    return (
      <div className="status-panel">
        <h3 className="status-title">{LABELS.STATUS}</h3>
        <div className="status-content">
          <div className="status-item">
            <span className="status-label">フェーズ</span>
            <span className="status-value">{PHASE_NAMES[phase]}</span>
          </div>
          {fileStatus && (
            <>
              <div className="status-item">
                <span className="status-label">ファイルID</span>
                <span className="status-value mono">{fileStatus.file_id}</span>
              </div>
              <div className="status-item">
                <span className="status-label">状態</span>
                <span className="status-value">{fileStatus.status}</span>
              </div>
              {fileStatus.chunk_count > 0 && (
                <div className="status-item">
                  <span className="status-label">チャンク</span>
                  <span className="status-value">
                    {fileStatus.completed_chunks}/{fileStatus.chunk_count}
                  </span>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    );
  };

  /**
   * Renders error message with retry option.
   */
  const renderError = (): React.ReactElement | null => {
    if (!error || phase !== SanitizePhase.ERROR) return null;

    return (
      <div className="error-panel" role="alert">
        <h3 className="error-title">{LABELS.ERROR}</h3>
        <p className="error-message">{error}</p>
        <button onClick={() => startSanitize()} className="btn btn-warning">
          {LABELS.RETRY}
        </button>
      </div>
    );
  };

  // =========================================================================
  // Main render
  // =========================================================================

  return (
    <div className="file-uploader">
      {/* Header */}
      <div className="uploader-header">
        <h2 className="uploader-title">ファイル浄化</h2>
        <p className="uploader-subtitle">
          ファイルをアップロードしてセキュリティポリシーを適用します
        </p>
      </div>

      {/* Drop Zone */}
      {renderDropZone()}

      {/* File Info (when file is selected) */}
      {file && (
        <div className="file-info-panel">
          <h3 className="info-title">{LABELS.FILE_INFO}</h3>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">{LABELS.FILE_NAME}</span>
              <span className="info-value">{file.name}</span>
            </div>
            <div className="info-item">
              <span className="info-label">{LABELS.FILE_SIZE}</span>
              <span className="info-value">{formatFileSize(file.size)}</span>
            </div>
            <div className="info-item">
              <span className="info-label">{LABELS.FILE_TYPE}</span>
              <span className="info-value">{file.type || '不明'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Policy Selector */}
      {renderPolicySelector()}

      {/* Action Buttons */}
      {renderActionButtons()}

      {/* Progress Bar */}
      {renderProgressBar()}

      {/* Status Panel */}
      {renderStatusPanel()}

      {/* Error Display */}
      {renderError()}

      {/* Sanitization Report (when available) */}
      {report && <SanitizationReport report={report} />}
    </div>
  );
}
