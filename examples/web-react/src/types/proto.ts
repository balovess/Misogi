// @generated
//
// This file contains manually-defined TypeScript interfaces that mirror
// the Misogi gRPC proto definitions from misogi.proto (V1 stable API).
//
// In production, these types should be generated using protoc + protoc-gen-grpc-web:
//
//   npm run generate:proto
//
// which executes:
//   protoc --proto_path=../../proto-dist/v1 \
//     --plugin=protoc-gen-grpc-web=node_modules/.bin/protoc-gen-grpc-web \
//     --grpc-web_out=import_style=commonjs+dts,mode=grpcwebtext:src/generated \
//     --js_out=import_style=commonjs,binary:src/generated \
//     misogi.proto
//
// @module types/proto
// @see ../../proto-dist/v1/misogi.proto

/**
 * Represents an uploaded data block from client to sender.
 *
 * Field numbers 1-4 are RESERVED for V1 core fields.
 * Extensions appear in V2.ChunkV2 (fields 5+).
 *
 * @interface Chunk
 */
export interface Chunk {
  /** Raw binary data of this chunk */
  data: Uint8Array;
  /** Unique file identifier assigned by server */
  file_id: string;
  /** Zero-based index of this chunk in sequence */
  chunk_index: number;
  /** MD5 hash of chunk data for integrity verification */
  chunk_md5: string;
}

/**
 * Represents a data block transferred from sender to receiver.
 *
 * @interface ChunkData
 */
export interface ChunkData {
  /** Unique file identifier */
  file_id: string;
  /** Zero-based index of this chunk */
  chunk_index: number;
  /** Raw binary data payload */
  data: Uint8Array;
  /** MD5 hash for integrity check */
  chunk_md5: string;
}

/**
 * Acknowledges receipt of a chunk from receiver.
 *
 * @interface ChunkAck
 */
export interface ChunkAck {
  /** File identifier being acknowledged */
  file_id: string;
  /** Index of acknowledged chunk */
  chunk_index: number;
  /** Whether chunk was accepted successfully */
  success: boolean;
  /** Error message if chunk was rejected */
  error?: string;
}

/**
 * Represents a downloadable file segment.
 *
 * Used in streaming download responses to deliver file content
 * in sequential chunks back to the requester.
 *
 * @interface FileChunk
 */
export interface FileChunk {
  /** Binary data payload of this segment */
  data: Uint8Array;
  /** Byte offset of this chunk within the complete file */
  offset: number;
  /** Total size of the complete file in bytes */
  total_size: number;
}

/**
 * Confirms successful upload initiation.
 *
 * Returned by SenderService.Upload after receiving initial chunks.
 *
 * @interface UploadResponse
 */
export interface UploadResponse {
  /** Unique identifier assigned to uploaded file */
  file_id: string;
  /** Current processing status of upload */
  status: UploadStatus;
}

/** Upload status enumeration values */
export enum UploadStatus {
  /** Upload is still in progress */
  UPLOADING = 'UPLOADING',
  /** All chunks received, processing started */
  PROCESSING = 'PROCESSING',
  /** File is ready for transfer/download */
  READY = 'READY',
  /** Error occurred during upload or processing */
  ERROR = 'ERROR',
}

/**
 * Identifies a file by its ID for status queries and operations.
 *
 * @interface FileIdRequest
 */
export interface FileIdRequest {
  /** Unique file identifier */
  file_id: string;
}

/**
 * Contains detailed information about a file's state on sender/receiver node.
 *
 * @interface FileStatusResponse
 */
export interface FileStatusResponse {
  /** Unique file identifier */
  file_id: string;
  /** Original filename as provided during upload */
  filename: string;
  /** Total file size in bytes */
  total_size: bigint;
  /** Total number of chunks in file */
  chunk_count: number;
  /** Number of chunks successfully received/processed */
  completed_chunks: number;
  /** Current lifecycle status of file */
  status: FileState;
  /** ISO 8601 timestamp when file was created */
  created_at: string;
}

/** File lifecycle states */
export enum FileState {
  /** File is being uploaded */
  UPLOADING = 'UPLOADING',
  /** File is undergoing sanitization processing */
  PROCESSING = 'PROCESSING',
  /** File is ready for transfer */
  READY = 'READY',
  /** Transfer is in progress to receiver */
  TRANSFERRING = 'TRANSFERRING',
  /** Transfer completed successfully */
  COMPLETED = 'COMPLETED',
  /** Operation failed */
  FAILED = 'FAILED',
}

/**
 * Supports pagination and filtering for file listing requests.
 *
 * @interface ListFilesRequest
 */
export interface ListFilesRequest {
  /** Page number (0-indexed) */
  page?: number;
  /** Number of items per page */
  per_page?: number;
  /** Filter files by status state */
  status_filter?: string;
}

/**
 * Contains paginated list of files on sender or receiver node.
 *
 * @interface ListFilesResponse
 */
export interface ListFilesResponse {
  /** Array of file status entries */
  files: FileStatusResponse[];
  /** Total count across all pages */
  total: number;
}

/**
 * Reports result of triggering a transfer operation.
 *
 * @interface TransferResponse
 */
export interface TransferResponse {
  /** Identifier of file being transferred */
  file_id: string;
  /** Status of transfer initiation */
  status: TransferStatus;
  /** Human-readable message describing outcome */
  message: string;
}

/** Transfer operation statuses */
export enum TransferStatus {
  /** Transfer initiated successfully */
  INITIATED = 'INITIATED',
  /** Transfer already in progress */
  IN_PROGRESS = 'IN_PROGRESS',
  /** Transfer completed */
  COMPLETED = 'COMPLETED',
  /** Transfer failed */
  FAILED = 'FAILED',
  /** File not found */
  NOT_FOUND = 'NOT_FOUND',
}

/**
 * Sanitization policy options for file processing.
 *
 * These policies determine how active content and potentially dangerous
 * elements are handled during file sanitization.
 *
 * @enum SanitizationPolicy
 */
export const SanitizationPolicy = {
  /**
   * Strip all active content (macros, scripts, embedded objects)
   * while preserving document structure and formatting.
   */
  STRIP_ACTIVE_CONTENT: 'STRIP_ACTIVE_CONTENT' as const,

  /**
   * Convert complex document formats to flat representation,
   * removing nested structures and embedded objects.
   */
  CONVERT_TO_FLAT: 'CONVERT_TO_FLAT' as const,

  /**
   * Extract only text content, discarding formatting,
   * images, and non-textual elements entirely.
   */
  TEXT_ONLY: 'TEXT_ONLY' as const,

  /**
   * Apply maximum security policy combining all restrictions.
   */
  MAXIMUM_SECURITY: 'MAXIMUM_SECURITY' as const,
} as const;

/** Type alias for SanitizationPolicy values */
export type SanitizationPolicyType =
  (typeof SanitizationPolicy)[keyof typeof SanitizationPolicy];

/**
 * Threat severity levels detected during sanitization.
 *
 * @enum ThreatSeverity
 */
export const ThreatSeverity = {
  /** Informational finding, no action required */
  INFO: 'INFO' as const,
  /** Low-risk element, may be safe in context */
  LOW: 'LOW' as const,
  /** Medium-risk element requiring review */
  MEDIUM: 'MEDIUM' as const,
  /** High-risk element, likely malicious */
  HIGH: 'HIGH' as const,
  /** Critical threat, must be removed immediately */
  CRITICAL: 'CRITICAL' as const,
} as const;

/** Type alias for ThreatSeverity values */
export type ThreatSeverityType =
  (typeof ThreatSeverity)[keyof typeof ThreatSeverity];

/**
 * Individual threat detection result.
 *
 * @interface ThreatFinding
 */
export interface ThreatFinding {
  /** Severity classification of this threat */
  severity: ThreatSeverityType;
  /** Category of threat (e.g., macro, script, embed) */
  category: string;
  /** Human-readable description of threat */
  description: string;
  /** Location in file where threat was found (if applicable) */
  location?: string;
  /** Action taken by sanitizer */
  action_taken: ThreatAction;
}

/** Actions taken against detected threats */
export enum ThreatAction {
  /** Threat removed completely */
  REMOVED = 'REMOVED',
  /** Threat neutralized/sanitized */
  NEUTRALIZED = 'NEUTRALIZED',
  /** Threat quarantined for manual review */
  QUARANTINED = 'QUARANTINED',
  /** No action (informational only) */
  NONE = 'NONE',
}

/**
 * Complete sanitization report for processed file.
 *
 * @interface SanitizationReport
 */
export interface SanitizationReport {
  /** File identifier this report covers */
  file_id: string;
  /** Original filename */
  filename: string;
  /** Policy applied during sanitization */
  policy_applied: SanitizationPolicyType;
  /** Array of individual threat findings */
  findings: ThreatFinding[];
  /** Summary counts by severity level */
  summary: ThreatSummary;
  /** Whether PII (Personally Identifiable Information) was detected */
  pii_detected: boolean;
  /** Processing time in milliseconds */
  processing_time_ms: number;
  /** Timestamp when report was generated */
  generated_at: string;
}

/**
 * Aggregated threat statistics by severity.
 *
 * @interface ThreatSummary
 */
export interface ThreatSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}
