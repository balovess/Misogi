/**
 * gRPC-Web client for Misogi file sanitization engine.
 *
 * Translates browser HTTP/1.1 requests to gRPC via Envoy proxy.
 * Provides high-level API for file upload, download, and status queries.
 *
 * @module client/grpc
 * @see https://grpc.io/docs/languages/web/basics/
 */

import {
  GrpcWebClientBase,
  Request,
  RpcOptions,
  UnaryResponse,
  StreamRpc,
} from '@improbable-eng/grpc-web';
import type {
  Chunk,
  FileChunk as FileChunkProto,
  UploadResponse,
  FileStatusResponse,
  ListFilesRequest,
  ListFilesResponse,
  TransferResponse,
  FileIdRequest,
  SanitizationPolicyType,
} from '../types/proto';

/** Default chunk size for file streaming (64KB) */
const DEFAULT_CHUNK_SIZE = 64 * 1024;

/** Default host for Envoy proxy */
const DEFAULT_HOST = 'http://localhost:8080';

/** gRPC service paths */
const SERVICE_PATHS = {
  /** SenderService.Upload RPC path */
  UPLOAD: '/misogi.file_transfer.v1.SenderService/Upload',
  /** SenderService.GetFileStatus RPC path */
  GET_FILE_STATUS: '/misogi.file_transfer.v1.SenderService/GetFileStatus',
  /** SenderService.ListFiles RPC path */
  LIST_FILES: '/misogi.file_transfer.v1.SenderService/ListFiles',
  /** SenderService.TriggerTransfer RPC path */
  TRIGGER_TRANSFER: '/misogi.file_transfer.v1.SenderService/TriggerTransfer',
  /** ReceiverService.DownloadFile RPC path */
  DOWNLOAD_FILE: '/misogi.file_transfer.v1.ReceiverService/DownloadFile',
} as const;

/**
 * Progress callback for upload/download operations.
 *
 * @callback ProgressCallback
 * @param {number} bytesProcessed - Number of bytes processed so far
 * @param {number} totalBytes - Total size of the operation
 */
export type ProgressCallback = (bytesProcessed: number, totalBytes: number) => void;

/**
 * Download chunk callback for streaming downloads.
 *
 * @callback DownloadChunkCallback
 * @param {ArrayBuffer} data - Binary data of received chunk
 * @param {number} offset - Byte offset of this chunk
 * @param {number} totalSize - Total expected file size
 */
export type DownloadChunkCallback = (
  data: ArrayBuffer,
  offset: number,
  totalSize: number,
) => void;

/**
 * gRPC-Web client for interacting with Misogi backend services.
 *
 * Provides typed methods for all SenderService and ReceiverService operations.
 * All requests are routed through Envoy proxy which translates gRPC-Web to native gRPC.
 *
 * @example
 * ```typescript
 * const client = new MisogigRpcClient('http://localhost:8080');
 *
 * // Upload a file with progress tracking
 * const response = await client.uploadFile(
 *   file,
 *   SanitizationPolicy.STRIP_ACTIVE_CONTENT,
 *   (sent, total) => console.log(`${sent}/${total} bytes`)
 * );
 *
 * // Check status
 * const status = await client.getFileStatus(response.file_id);
 * ```
 *
 * @class MisogigRpcClient
 */
export class MisogigRpcClient {
  /** Underlying gRPC-Web transport client */
  private client: GrpcWebClientBase;
  /** Base URL for gRPC service endpoints */
  private readonly host: string;

  /**
   * Creates a new MisogigRpcClient instance.
   *
   * @param {string} [host=DEFAULT_HOST] - Base URL of Envoy proxy (e.g., 'http://localhost:8080')
   * @throws {Error} If host URL is invalid or empty
   */
  constructor(host: string = DEFAULT_HOST) {
    if (!host || typeof host !== 'string') {
      throw new Error('Invalid host: must be a non-empty string');
    }

    this.host = host.replace(/\/+$/, ''); // Remove trailing slashes
    this.client = new GrpcWebClientBase({
      host: this.host,
    });
  }

  /**
   * Gets the current connection host.
   *
   * @returns {string} The configured host URL
   */
  getHost(): string {
    return this.host;
  }

  /**
   * Uploads a file via streaming gRPC-Web to SenderService.
   *
   * Splits the file into chunks and streams them sequentially to the server.
   * Supports progress tracking via optional callback.
   *
   * @async
   * @param {File} file - Browser File object to upload
   * @param {SanitizationPolicyType} policy - Sanitization policy to apply
   * @param {ProgressCallback} [onProgress] - Optional progress callback
   * @returns {Promise<UploadResponse>} Server response with file_id and status
   * @throws {Error} If upload fails or server returns error
   *
   * @example
   * ```typescript
   * const response = await client.uploadFile(
   *   selectedFile,
   *   SanitizationPolicy.STRIP_ACTIVE_CONTENT,
   *   (bytes, total) => updateProgressBar(bytes / total)
   * );
   * console.log(`Uploaded: ${response.file_id}`);
   * ```
   */
  async uploadFile(
    file: File,
    policy: SanitizationPolicyType,
    onProgress?: ProgressCallback,
  ): Promise<UploadResponse> {
    return new Promise((resolve, reject) => {
      let offset = 0;
      let fileId: string | null = null;

      /**
       * Creates and sends the next chunk in sequence.
       * Handles end-of-stream signaling when all chunks are sent.
       */
      const sendNextChunk = (): void => {
        if (offset >= file.size) {
          // All chunks sent - signal stream completion
          stream.end();
          return;
        }

        const end = Math.min(offset + DEFAULT_CHUNK_SIZE, file.size);
        const blob = file.slice(offset, end);

        const reader = new FileReader();
        reader.onload = () => {
          if (!reader.result) {
            reject(new Error('Failed to read file chunk'));
            return;
          }

          const arrayBuffer = reader.result as ArrayBuffer;
          const uint8Array = new Uint8Array(arrayBuffer);

          // Build chunk message
          const chunk: Chunk = {
            data: uint8Array,
            file_id: fileId ?? '',
            chunk_index: Math.floor(offset / DEFAULT_CHUNK_SIZE),
            chunk_md5: '', // Would compute MD5 in production
          };

          // Write chunk to stream
          stream.write(chunk);
          offset = end;

          // Report progress
          onProgress?.(offset, file.size);

          // Schedule next chunk (use setTimeout to prevent stack overflow)
          setTimeout(sendNextChunk, 0);
        };

        reader.onerror = () => {
          reject(new Error('Failed to read file'));
        };

        reader.readAsArrayBuffer(blob);
      };

      // Initiate streaming RPC call
      const stream = this.client.rpcCall(
        SERVICE_PATHS.UPLOAD,
        {} as Request,
        { /* metadata */ } as unknown as RpcOptions,
        (response: UnaryResponse<UploadResponse>) => {
          // Final response received after stream completes
          resolve(response.message as unknown as UploadResponse);
        },
        (error: Error) => {
          reject(error);
        },
      ) as unknown as StreamRpc<Chunk>;

      // Start sending first chunk
      // Note: In real implementation, we'd receive file_id from initial response
      // For now, generate temporary ID (server will assign actual ID)
      fileId = `temp-${Date.now()}`;
      sendNextChunk();
    });
  }

  /**
   * Retrieves status information for a specific file.
   *
   * Queries SenderService.GetFileStatus to get current state,
   * progress, and metadata for an uploaded file.
   *
   * @async
   * @param {string} fileId - Unique identifier of the file
   * @returns {Promise<FileStatusResponse>} Detailed file status information
   * @throws {Error} If file not found or query fails
   *
   * @example
   * ```typescript
   * const status = await client.getFileStatus('abc-123-def');
   * console.log(`Status: ${status.status}, Progress: ${status.completed_chunks}/${status.chunk_count}`);
   * ```
   */
  async getFileStatus(fileId: string): Promise<FileStatusResponse> {
    return new Promise((resolve, reject) => {
      const request: FileIdRequest = {
        file_id: fileId,
      };

      this.client.rpcCall(
        SERVICE_PATHS.GET_FILE_STATUS,
        request as unknown as Request,
        {} as unknown as RpcOptions,
        (err: Error | null, response: UnaryResponse<FileStatusResponse>) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(response.message as unknown as FileStatusResponse);
        },
      );
    });
  }

  /**
   * Lists files on the sender node with pagination support.
   *
   * Queries SenderService.ListFiles to retrieve paginated list
   * of uploaded files with their current statuses.
   *
   * @async
   * @param {ListFilesRequest} [params] - Optional pagination/filter parameters
   * @returns {Promise<ListFilesResponse>} Paginated list of files
   * @throws {Error} If listing fails
   *
   * @example
   * ```typescript
   * // Get first page of files
   * const result = await client.listFiles({ page: 0, per_page: 20 });
   * console.log(`Found ${result.total} files`);
   *
   * // Filter by status
   * const processing = await client.listFiles({ status_filter: 'PROCESSING' });
   * ```
   */
  async listFiles(params?: ListFilesRequest): Promise<ListFilesResponse> {
    return new Promise((resolve, reject) => {
      const request: ListFilesRequest = {
        page: params?.page ?? 0,
        per_page: params?.per_page ?? 20,
        status_filter: params?.status_filter,
      };

      this.client.rpcCall(
        SERVICE_PATHS.LIST_FILES,
        request as unknown as Request,
        {} as unknown as RpcOptions,
        (err: Error | null, response: UnaryResponse<ListFilesResponse>) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(response.message as unknown as ListFilesResponse);
        },
      );
    });
  }

  /**
   * Initiates transfer of a file from sender to receiver node.
   *
   * Calls SenderService.TriggerTransfer to start the transfer process.
   * Use getFileStatus to monitor transfer progress.
   *
   * @async
   * @param {string} fileId - Identifier of file to transfer
   * @returns {Promise<TransferResponse>} Transfer initiation result
   * @throws {Error} If transfer cannot be initiated
   *
   * @example
   * ```typescript
   * const result = await client.triggerTransfer('abc-123-def');
   * if (result.status === TransferStatus.INITIATED) {
   *   console.log('Transfer started');
   * }
   * ```
   */
  async triggerTransfer(fileId: string): Promise<TransferResponse> {
    return new Promise((resolve, reject) => {
      const request: FileIdRequest = {
        file_id: fileId,
      };

      this.client.rpcCall(
        SERVICE_PATHS.TRIGGER_TRANSFER,
        request as unknown as Request,
        {} as unknown as RpcOptions,
        (err: Error | null, response: UnaryResponse<TransferResponse>) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(response.message as unknown as TransferResponse);
        },
      );
    });
  }

  /**
   * Downloads a complete file from receiver node via streaming.
   *
   * Calls ReceiverService.DownloadFile to stream file content back.
   * Chunks can be processed individually via callback or collected into Blob.
   *
   * @async
   * @param {string} fileId - Identifier of file to download
   * @param {DownloadChunkCallback} [onChunk] - Optional per-chunk callback
   * @returns {Promise<Blob>} Complete file content as Blob
   * @throws {Error} If download fails or file not found
   *
   * @example
   * ```typescript
   * // Download with chunk processing
   * const blob = await client.downloadFile('abc-123', (data, offset, total) => {
   *   console.log(`Received ${data.byteLength} bytes at offset ${offset}`);
   * });
   *
   * // Save to disk
   * const url = URL.createObjectURL(blob);
   * const a = document.createElement('a');
   * a.href = url;
   * a.download = 'sanitized-file.bin';
   * a.click();
   * ```
   */
  async downloadFile(
    fileId: string,
    onChunk?: DownloadChunkCallback,
  ): Promise<Blob> {
    return new Promise((resolve, reject) => {
      const request: FileIdRequest = {
        file_id: fileId,
      };
      const chunks: ArrayBuffer[] = [];

      // Initiate streaming download
      const stream = this.client.serverStreaming(
        SERVICE_PATHS.DOWNLOAD_FILE,
        request as unknown as Request,
        {} as unknown as RpcOptions,
      ) as unknown as StreamRpc<FileChunkProto>;

      // Handle incoming chunks
      stream.on('data', (response: { message: FileChunkProto }) => {
        const chunk = response.message;
        const buffer = chunk.data.buffer.slice(
          chunk.data.byteOffset,
          chunk.data.byteOffset + chunk.data.byteLength,
        );

        chunks.push(buffer);
        onChunk?.(buffer, chunk.offset, chunk.total_size);
      });

      // Handle completion
      stream.on('end', () => {
        const blob = new Blob(chunks, { type: 'application/octet-stream' });
        resolve(blob);
      });

      // Handle errors
      stream.on('error', (error: Error) => {
        reject(error);
      });

      // Start receiving
      stream.start();
    });
  }

  /**
   * Tests connectivity to the Misogi backend.
   *
   * Performs a lightweight operation to verify that the gRPC-Web
   * connection through Envoy is functional.
   *
   * @async
   * @returns {Promise<boolean>} True if connection is successful
   */
  async testConnection(): Promise<boolean> {
    try {
      // Try listing files (even empty list confirms connectivity)
      await this.listFiles({ page: 0, per_page: 1 });
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Singleton instance factory for convenience.
 *
 * Returns cached client instance or creates new one.
 * Useful for applications with single backend connection.
 *
 * @param {string} [host] - Host URL (only used on first call)
 * @returns {MisogigRpcClient} Shared client instance
 *
 * @example
 * ```typescript
 * // Initialize once
 * const client = getMisogiClient('http://localhost:8080');
 *
 * // Later in codebase - same instance returned
 * const sameClient = getMisogiClient();
 * ```
 */
let _clientInstance: MisogigRpcClient | null = null;

export function getMisogiClient(
  host?: string,
): MisogigRpcClient {
  if (!_clientInstance) {
    _clientInstance = new MisogigRpcClient(host);
  }
  return _clientInstance;
}
