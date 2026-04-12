/**
 * React hooks for Misogi gRPC-Web client integration.
 *
 * Provides custom hooks that encapsulate gRPC communication logic
 * and manage upload → status poll → download lifecycle for file
 * sanitization operations.
 *
 * @module hooks/useMisogiClient
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  MisogigRpcClient,
  getMisogiClient,
  type ProgressCallback,
} from '../client/grpc';
import type {
  File,
  SanitizationPolicyType,
  UploadResponse,
  FileStatusResponse,
  FileState,
  SanitizationReport,
  Blob as BlobType,
} from '../types/proto';

/** Polling interval in milliseconds for status checks */
const STATUS_POLL_INTERVAL = 2000;

/** Maximum number of polling attempts before giving up */
const MAX_POLL_ATTEMPTS = 60;

/**
 * Connection state enumeration for backend connectivity.
 *
 * @enum ConnectionState
 */
export enum ConnectionState {
  /** Initial state, connection not yet tested */
  UNKNOWN = 'UNKNOWN',
  /** Currently testing connection */
  TESTING = 'TESTING',
  /** Successfully connected to backend */
  CONNECTED = 'CONNECTED',
  /** Connection failed or lost */
  DISCONNECTED = 'DISCONNECTED',
}

/** State shape returned by useMisogiClient hook */
interface ClientState {
  /** Current connection state to Misogi backend */
  connection: ConnectionState;
  /** Initialized client instance (null if not ready) */
  client: MisogigRpcClient | null;
  /** Error message if connection failed */
  error: string | null;
}

/**
 * React hook for initializing and managing Misogi gRPC-Web client.
 *
 * Creates and caches a client instance, tests connectivity on mount,
 * and provides reconnection capability. Should be used at app root level
 * and passed down via context or props.
 *
 * @param {string} [host] - Envoy proxy host URL (e.g., 'http://localhost:8080')
 * @returns {ClientState} Object containing client instance and connection state
 *
 * @example
 * ```tsx
 * function App() {
 *   const { client, connection } = useMisogiClient('http://localhost:8080');
 *
 *   return (
 *     <div>
 *       <ConnectionStatus state={connection} />
 *       {client && <FileUploader client={client} />}
 *     </div>
 *   );
 * }
 * ```
 */
export function useMisogiClient(host?: string): ClientState {
  const [connection, setConnection] = useState<ConnectionState>(
    ConnectionState.UNKNOWN,
  );
  const [error, setError] = useState<string | null>(null);
  const clientRef = useRef<MisogigRpcClient | null>(null);

  // Initialize client and test connection on mount
  useEffect(() => {
    let isMounted = true;

    const initialize = async (): Promise<void> => {
      try {
        setConnection(ConnectionState.TESTING);

        // Create or get cached client
        const client = host
          ? new MisogigRpcClient(host)
          : getMisogiClient();
        clientRef.current = client;

        // Test connectivity
        const isConnected = await client.testConnection();

        if (!isMounted) return;

        if (isConnected) {
          setConnection(ConnectionState.CONNECTED);
          setError(null);
        } else {
          setConnection(ConnectionState.DISCONNECTED);
          setError('Backend server not responding');
        }
      } catch (err) {
        if (!isMounted) return;

        setConnection(ConnectionState.DISCONNECTED);
        setError(
          err instanceof Error ? err.message : 'Failed to initialize client',
        );
      }
    };

    initialize();

    // Cleanup on unmount
    return () => {
      isMounted = false;
    };
  }, [host]);

  /**
   * Manually retry connection attempt.
   * Useful for reconnect button in UI.
   */
  const retryConnection = useCallback(async (): Promise<void> => {
    setConnection(ConnectionState.TESTING);
    setError(null);

    try {
      const client = clientRef.current ?? getMisogiClient();
      const isConnected = await client.testConnection();

      setConnection(
        isConnected
          ? ConnectionState.CONNECTED
          : ConnectionState.DISCONNECTED,
      );

      if (!isConnected) {
        setError('Backend server not responding');
      }
    } catch (err) {
      setConnection(ConnectionState.DISCONNECTED);
      setError(err instanceof Error ? err.message : 'Connection failed');
    }
  }, []);

  return {
    connection,
    client: clientRef.current,
    error,
    retryConnection,
  };
}

/** Operation phase in sanitization lifecycle */
export enum SanitizePhase {
  /** Idle - no operation in progress */
  IDLE = 'IDLE',
  /** File selected, awaiting user action */
  SELECTED = 'SELECTED',
  /** Uploading file chunks to server */
  UPLOADING = 'UPLOADING',
  /** Server processing/sanitizing file */
  PROCESSING = 'PROCESSING',
  /** File ready for download */
  READY = 'READY',
  /** Downloading sanitized file */
  DOWNLOADING = 'DOWNLOADING',
  /** Download complete */
  COMPLETED = 'COMPLETED',
  /** Error occurred during operation */
  ERROR = 'ERROR',
}

/** State shape returned by useSanitize hook */
interface SanitizeState {
  /** Current phase of sanitization lifecycle */
  phase: SanitizePhase;
  /** Selected file (if any) */
  file: File | null;
  /** Selected sanitization policy */
  policy: SanitizationPolicyType;
  /** Upload progress (0-100) */
  uploadProgress: number;
  /** Server response from upload */
  uploadResponse: UploadResponse | null;
  /** Current file status from server */
  fileStatus: FileStatusResponse | null;
  /** Sanitized file blob (after download) */
  resultBlob: BlobType | null;
  /** Sanitization report with threat findings */
  report: SanitizationReport | null;
  /** Error message if operation failed */
  error: string | null;
  /** Number of bytes uploaded so far */
  bytesUploaded: number;
}

/**
 * React hook managing complete file sanitization workflow.
 *
 * Orchestrates the full lifecycle:
 * 1. File selection
 * 2. Upload with streaming + progress tracking
 * 3. Status polling until processing completes
 * 4. Download sanitized result
 *
 * Provides methods to control each phase and reset state.
 *
 * @returns {UseSanitizeReturn} State and control methods for sanitization workflow
 *
 * @example
 * ```tsx
 * function SanitizePanel() {
 *   const { phase, selectFile, startSanitize, downloadResult, reset } = useSanitize(client);
 *
 *   return (
 *     <div>
 *       <FileInput onSelect={selectFile} disabled={phase !== SanitizePhase.IDLE} />
 *       <Button onClick={startSanitize} disabled={phase !== SanitizePhase.SELECTED}>
 *         浄化開始
 *       </Button>
 *       <ProgressBar value={uploadProgress} visible={phase === SanitizePhase.UPLOADING} />
 *       <Button onClick={downloadResult} disabled={phase !== SanitizePhase.READY}>
 *         ダウンロード
 *       </Button>
 *     </div>
 *   );
 * }
 * ```
 */
export interface UseSanitizeReturn extends SanitizeState {
  /** Select a file for sanitization */
  selectFile: (file: File) => void;
  /** Change sanitization policy */
  setPolicy: (policy: SanitizationPolicyType) => void;
  /** Begin upload and sanitization process */
  startSanitize: () => Promise<void>;
  /** Download sanitized file result */
  downloadResult: (filename?: string) => Promise<void>;
  /** Reset all state to initial idle condition */
  reset: () => void;
}

export function useSanitize(
  client: MisogigRpcClient | null,
): UseSanitizeReturn {
  const [state, setState] = useState<SanitizeState>({
    phase: SanitizePhase.IDLE,
    file: null,
    policy: 'STRIP_ACTIVE_CONTENT' as SanitizationPolicyType,
    uploadProgress: 0,
    uploadResponse: null,
    fileStatus: null,
    resultBlob: null,
    report: null,
    error: null,
    bytesUploaded: 0,
  });

  const abortRef = useRef<AbortController | null>(null);

  /**
   * Select file for sanitization.
   * Resets previous operation state.
   */
  const selectFile = useCallback((file: File): void => {
    setState((prev) => ({
      ...prev,
      phase: SanitizePhase.SELECTED,
      file,
      uploadProgress: 0,
      uploadResponse: null,
      fileStatus: null,
      resultBlob: null,
      report: null,
      error: null,
      bytesUploaded: 0,
    }));
  }, []);

  /**
   * Update sanitization policy choice.
   */
  const setPolicy = useCallback((policy: SanitizationPolicyType): void => {
    setState((prev) => ({ ...prev, policy }));
  }, []);

  /**
   * Progress callback for upload tracking.
   * Updates state with current bytes sent.
   */
  const handleUploadProgress: ProgressCallback = useCallback(
    (bytesProcessed: number, totalBytes: number): void => {
      setState((prev) => ({
        ...prev,
        bytesUploaded: bytesProcessed,
        uploadProgress: totalBytes > 0 ? (bytesProcessed / totalBytes) * 100 : 0,
      }));
    },
    [],
  );

  /**
   * Start the full sanitization workflow.
   * Uploads file, polls status, prepares for download.
   */
  const startSanitize = useCallback(async (): Promise<void> => {
    if (!client || !state.file) {
      setState((prev) => ({
        ...prev,
        phase: SanitizePhase.ERROR,
        error: 'Client not initialized or no file selected',
      }));
      return;
    }

    // Create abort controller for cancellation support
    abortRef.current = new AbortController();

    try {
      // Phase 1: Upload
      setState((prev) => ({ ...prev, phase: SanitizePhase.UPLOADING }));

      const uploadResponse = await client.uploadFile(
        state.file,
        state.policy,
        handleUploadProgress,
      );

      setState((prev) => ({
        ...prev,
        uploadResponse,
        phase: SanitizePhase.PROCESSING,
      }));

      // Phase 2: Poll status until ready or error
      let attempts = 0;
      while (attempts < MAX_POLL_ATTEMPTS) {
        // Check if aborted
        if (abortRef.current?.signal.aborted) break;

        await new Promise((resolve) => setTimeout(resolve, STATUS_POLL_INTERVAL));

        const status = await client.getFileStatus(uploadResponse.file_id);
        setState((prev) => ({ ...prev, fileStatus: status }));

        // Check terminal states
        if (
          status.status === FileState.READY ||
          status.status === FileState.COMPLETED ||
          status.status === FileState.FAILED
        ) {
          if (status.status === FileState.FAILED) {
            throw new Error('Server-side processing failed');
          }

          setState((prev) => ({ ...prev, phase: SanitizePhase.READY }));
          return;
        }

        attempts++;
      }

      // Timeout
      throw new Error('Processing timeout - server did not complete in time');
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        // User cancelled - don't show error
        setState((prev) => ({ ...prev, phase: SanitizePhase.IDLE }));
        return;
      }

      setState((prev) => ({
        ...prev,
        phase: SanitizePhase.ERROR,
        error: err instanceof Error ? err.message : 'Unknown error occurred',
      }));
    }
  }, [client, state.file, state.policy, handleUploadProgress]);

  /**
   * Download the sanitized file result.
   * Triggers browser download dialog with sanitized content.
   */
  const downloadResult = useCallback(
    async (filename?: string): Promise<void> => {
      if (!client || !state.uploadResponse) {
        setState((prev) => ({
          ...prev,
          error: 'No upload response available for download',
        }));
        return;
      }

      try {
        setState((prev) => ({ ...prev, phase: SanitizePhase.DOWNLOADING }));

        const blob = await client.downloadFile(state.uploadResponse.file_id);

        // Generate download filename
        const originalName = state.file?.name ?? 'sanitized-file';
        const safeFilename =
          filename ??
          `sanitized_${originalName}`;

        // Trigger browser download
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = safeFilename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        setState((prev) => ({
          ...prev,
          phase: SanitizePhase.COMPLETED,
          resultBlob: blob,
        }));
      } catch (err) {
        setState((prev) => ({
          ...prev,
          phase: SanitizePhase.ERROR,
          error:
            err instanceof Error ? err.message : 'Download failed',
        }));
      }
    },
    [client, state.uploadResponse, state.file],
  );

  /**
   * Reset all state to initial idle condition.
   * Cancels any ongoing operations.
   */
  const reset = useCallback((): void => {
    abortRef.current?.abort();
    abortRef.current = null;

    setState({
      phase: SanitizePhase.IDLE,
      file: null,
      policy: 'STRIP_ACTIVE_CONTENT' as SanitizationPolicyType,
      uploadProgress: 0,
      uploadResponse: null,
      fileStatus: null,
      resultBlob: null,
      report: null,
      error: null,
      bytesUploaded: 0,
    });
  }, []);

  return {
    ...state,
    selectFile,
    setPolicy,
    startSanitize,
    downloadResult,
    reset,
  };
}
