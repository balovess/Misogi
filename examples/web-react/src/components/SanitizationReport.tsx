/**
 * SanitizationReport component for displaying file sanitization results.
 *
 * Shows comprehensive threat analysis including:
 * - Summary statistics by severity level
 * - Detailed threat finding list
 * - PII detection status
 * - Applied policy information
 * - Processing metadata
 *
 * @module components/SanitizationReport
 */

import React, { useState } from 'react';
import type { SanitizationReport as SanitizationReportType, ThreatFinding, ThreatSeverityType } from '../types/proto';

// ============================================================================
// Japanese UI string constants
// ============================================================================

/** Japanese text labels for report UI */
const LABELS = {
  /** Report title */
  TITLE: '浄化レポート',
  /** Expand/collapse toggle */
  EXPAND: '詳細を表示',
  COLLAPSE: '詳細を隠す',
  /** Summary section */
  SUMMARY: 'サマリー',
  /** Total findings label */
  TOTAL_FINDINGS: '検出された脅威',
  /** Severity labels */
  CRITICAL: '重大',
  HIGH: '高',
  MEDIUM: '中',
  LOW: '低',
  INFO: '情報',
  /** Details section */
  DETAILS: '詳細リスト',
  /** Finding table headers */
  SEVERITY: '重要度',
  CATEGORY: 'カテゴリー',
  DESCRIPTION: '説明',
  LOCATION: '位置',
  ACTION: '対応措置',
  /** PII section */
  PII_STATUS: '個人情報検出',
  DETECTED: '検出あり',
  NOT_DETECTED: '検出なし',
  /** Policy section */
  POLICY_APPLIED: '適用ポリシー',
  /** Metadata section */
  METADATA: '処理情報',
  PROCESSING_TIME: '処理時間',
  GENERATED_AT: '生成日時',
  FILE_ID: 'ファイルID',
  FILENAME: 'ファイル名',
} as const;

/** Action type display names in Japanese */
const ACTION_NAMES: Record<string, string> = {
  REMOVED: '削除済み',
  NEUTRALIZED: '無効化済み',
  QUARANTINED: '隔離済み',
  NONE: 'なし',
};

/** Severity color mapping for visual indicators */
const SEVERITY_COLORS: Record<ThreatSeverityType, string> = {
  CRITICAL: '#dc2626', // red-600
  HIGH: '#ea580c',     // orange-600
  MEDIUM: '#ca8a04',   // yellow-600
  LOW: '#2563eb',      // blue-600
  INFO: '#6b7280',     // gray-500
};

// ============================================================================
// Utility functions
// ============================================================================

/**
 * Formats processing time from milliseconds to human-readable string.
 *
 * @param {number} ms - Time in milliseconds
 * @returns {string} Formatted time (e.g., "1.234s" or "567ms")
 */
function formatProcessingTime(ms: number): string {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(3)}秒`;
  }
  return `${ms.toFixed(0)}ms`;
}

/**
 * Gets severity badge styling based on severity level.
 *
 * @param {ThreatSeverityType} severity - Severity level
 * @returns {object} CSS style object with background and text colors
 */
function getSeverityStyle(severity: ThreatSeverityType): React.CSSProperties {
  return {
    backgroundColor: `${SEVERITY_COLORS[severity]}20`,
    color: SEVERITY_COLORS[severity],
    border: `1px solid ${SEVERITY_COLORS[severity]}40`,
  };
}

// ============================================================================
// Sub-components
// ============================================================================

/** Props for threat summary card component */
interface ThreatSummaryCardProps {
  /** Report data to summarize */
  report: SanitizationReportType;
}

/**
 * Displays aggregated threat statistics by severity.
 *
 * Shows count of findings for each severity level in a grid layout.
 * Uses color-coded badges for quick visual assessment.
 *
 * @param {ThreatSummaryCardProps} props - Component props
 * @returns {JSX.Element} Rendered summary card
 */
function ThreatSummaryCard({ report }: ThreatSummaryCardProps): React.ReactElement {
  const { summary } = report;

  /**
   * Renders individual severity stat item.
   */
  const renderStatItem = (
    label: string,
    count: number,
    severity?: ThreatSeverityType,
  ): React.ReactElement => (
    <div className="summary-stat-item" key={label}>
      <span className="stat-label">{label}</span>
      <span
        className="stat-count"
        style={severity ? getSeverityStyle(severity) : undefined}
      >
        {count}
      </span>
    </div>
  );

  return (
    <div className="threat-summary-card">
      <h3 className="summary-title">{LABELS.SUMMARY}</h3>
      <div className="summary-grid">
        {/* Total findings */}
        <div className="summary-total">
          <span className="total-label">{LABELS.TOTAL_FINDINGS}</span>
          <span className="total-value">{summary.total_findings}</span>
        </div>

        {/* Breakdown by severity */}
        {renderStatItem(LABELS.CRITICAL, summary.critical_count, 'CRITICAL')}
        {renderStatItem(LABELS.HIGH, summary.high_count, 'HIGH')}
        {renderStatItem(LABELS.MEDIUM, summary.medium_count, 'MEDIUM')}
        {renderStatItem(LABELS.LOW, summary.low_count, 'LOW')}
        {renderStatItem(LABELS.INFO, summary.info_count, 'INFO')}
      </div>
    </div>
  );
}

/** Props for threat details table component */
interface ThreatDetailsTableProps {
  /** Array of individual threat findings */
  findings: ThreatFinding[];
}

/**
 * Displays detailed table of all detected threats.
 *
 * Each row shows severity, category, description, location (if available),
 * and action taken by the sanitizer.
 *
 * @param {ThreatDetailsTableProps} props - Component props
 * @returns {JSX.Element} Rendered table or empty state message
 */
function ThreatDetailsTable({ findings }: ThreatDetailsTableProps): React.ReactElement {
  if (findings.length === 0) {
    return (
      <div className="no-findings">
        <p>脅威は検出されませんでした</p>
      </div>
    );
  }

  return (
    <div className="threat-details-table">
      <h3 className="details-title">{LABELS.DETAILS}</h3>
      <div className="table-wrapper">
        <table className="findings-table" role="table">
          <thead>
            <tr>
              <th scope="col">{LABELS.SEVERITY}</th>
              <th scope="col">{LABELS.CATEGORY}</th>
              <th scope="col">{LABELS.DESCRIPTION}</th>
              <th scope="col">{LABELS.LOCATION}</th>
              <th scope="col">{LABELS.ACTION}</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding, index) => (
              <tr key={`${finding.category}-${index}`}>
                <td>
                  <span
                    className="severity-badge"
                    style={getSeverityStyle(finding.severity)}
                  >
                    {finding.severity}
                  </span>
                </td>
                <td>{finding.category}</td>
                <td>{finding.description}</td>
                <td>{finding.location ?? '-'}</td>
                <td>{ACTION_NAMES[finding.action_taken] ?? finding.action_taken}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ============================================================================
// Main component
// ============================================================================

/** Props for SanitizationReport component */
interface SanitizationReportProps {
  /** Complete sanitization report data */
  report: SanitizationReportType;
}

/**
 * Comprehensive sanitization report viewer component.
 *
 * Displays threat analysis results in collapsible sections:
 * - Summary card with severity breakdown
 * - Detailed findings table
 * - PII detection indicator
 * - Policy and processing metadata
 *
 * @param {SanitizationReportProps} props - Component props
 * @returns {JSX.Element} Rendered report component
 *
 * @example
 * ```tsx
 * {report && <SanitizationReport report={report} />}
 * ```
 */
export function SanitizationReport({ report }: SanitizationReportProps): React.ReactElement {
  const [isExpanded, setIsExpanded] = useState(false);

  /**
   * Toggles expanded/collapsed state of detailed view.
   */
  const toggleExpanded = (): void => {
    setIsExpanded((prev) => !prev);
  };

  return (
    <div className="sanitization-report">
      {/* Header with expand/collapse control */}
      <div className="report-header" onClick={toggleExpanded}>
        <h2 className="report-title">{LABELS.TITLE}</h2>
        <button
          className="expand-toggle"
          aria-expanded={isExpanded}
          aria-label={isExpanded ? LABELS.COLLAPSE : LABELS.EXPAND}
        >
          {isExpanded ? '▲' : '▼'} {isExpanded ? LABELS.COLLAPSE : LABELS.EXPAND}
        </button>
      </div>

      {/* Always visible: Quick summary */}
      <ThreatSummaryCard report={report} />

      {/* Collapsible: Detailed content */}
      {isExpanded && (
        <div className="report-details">
          {/* Threat findings table */}
          <ThreatDetailsTable findings={report.findings} />

          {/* PII Detection Status */}
          <div className="pii-status-section">
            <h3 className="section-subtitle">{LABELS.PII_STATUS}</h3>
            <div className={`pii-indicator ${report.pii_detected ? 'detected' : 'not-detected'}`}>
              <span className="pii-icon">
                {report.pii_detected ? '⚠️' : '✅'}
              </span>
              <span className="pii-text">
                {report.pii_detected ? LABELS.DETECTED : LABELS.NOT_DETECTED}
              </span>
            </div>
          </div>

          {/* Applied Policy */}
          <div className="policy-info-section">
            <h3 className="section-subtitle">{LABELS.POLICY_APPLIED}</h3>
            <p className="policy-value">{report.policy_applied}</p>
          </div>

          {/* Processing Metadata */}
          <div className="metadata-section">
            <h3 className="section-subtitle">{LABELS.METADATA}</h3>
            <dl className="metadata-list">
              <div className="metadata-item">
                <dt>{LABELS.FILE_ID}</dt>
                <dd className="mono">{report.file_id}</dd>
              </div>
              <div className="metadata-item">
                <dt>{LABELS.FILENAME}</dt>
                <dd>{report.filename}</dd>
              </div>
              <div className="metadata-item">
                <dt>{LABELS.PROCESSING_TIME}</dt>
                <dd>{formatProcessingTime(report.processing_time_ms)}</dd>
              </div>
              <div className="metadata-item">
                <dt>{LABELS.GENERATED_AT}</dt>
                <dd>{new Date(report.generated_at).toLocaleString('ja-JP')}</dd>
              </div>
            </dl>
          </div>
        </div>
      )}
    </div>
  );
}
