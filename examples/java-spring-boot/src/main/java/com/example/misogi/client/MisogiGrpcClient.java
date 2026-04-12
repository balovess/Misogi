package com.example.misogi.client;

import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import misogi.file_transfer.v1.Chunk;
import misogi.file_transfer.v1.FileChunk;
import misogi.file_transfer.v1.FileIdRequest;
import misogi.file_transfer.v1.FileStatusResponse;
import misogi.file_transfer.v1.ListFilesRequest;
import misogi.file_transfer.v1.ListFilesResponse;
import misogi.file_transfer.v1.ReceiverServiceGrpc;
import misogi.file_transfer.v1.SenderServiceGrpc;
import misogi.file_transfer.v1.TransferResponse;
import misogi.file_transfer.v1.UploadResponse;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Core gRPC client wrapper for the Misogi CDR engine.
 *
 * <p>Provides high-level methods that map 1:1 to the V1 proto service RPCs
 * defined in {@code misogi.file_transfer.v1}. Each method handles channel
 * lifecycle, streaming semantics, and error translation into
 * {@link MisogiException}.</p>
 *
 * <h2>Thread Safety</h2>
 * <p>Instances are <strong>not</strong> thread-safe for concurrent upload/download
 * calls on the same stub. Create separate instances or synchronise externally
 * if parallel access is required.</p>
 *
 * <h3>Lifecycle</h3>
 * <pre>
 *   var client = new MisogiGrpcClient("localhost", 50051);
 *   try {
 *       UploadResponse resp = client.uploadFile(path, SanitizationPolicy.DEFAULT);
 *       // ...
 *   } finally {
 *       client.shutdown();
 *   }
 * </pre>
 *
 * @see SenderServiceGrpc
 * @see ReceiverServiceGrpc
 */
public class MisogiGrpcClient {

    private static final Logger LOG = Logger.getLogger(MisogiGrpcClient.class.getName());

    private final ManagedChannel channel;
    private final SenderServiceGrpc.SenderServiceBlockingStub senderBlockingStub;
    private final SenderServiceGrpc.SenderServiceStub senderAsyncStub;
    private final ReceiverServiceGrpc.ReceiverServiceBlockingStub receiverBlockingStub;
    private final ReceiverServiceGrpc.ReceiverServiceStub receiverAsyncStub;

    /**
     * Enum representing sanitization policy choices.
     *
     * <p>Mirrors server-side policy identifiers accepted by the CDR engine.</p>
     */
    public enum SanitizationPolicy {
        DEFAULT,
        AGGRESSIVE,
        PASSTHROUGH
    }

    /** Metadata returned after a successful file download. */
    public record DownloadResult(long totalBytesWritten, String transferId) {}

    /**
     * Create a client connecting to {@code host:port} with plaintext transport.
     *
     * @param host gRPC server hostname or IP
     * @param port gRPC server port
     */
    public MisogiGrpcClient(String host, int port) {
        this(ManagedChannelBuilder.forAddress(host, port).usePlaintext().build());
    }

    /**
     * Create a client backed by an externally-supplied channel.
     *
     * <p>Useful when TLS credentials must be configured by the caller or when
     * sharing a channel across multiple client instances.</p>
     *
     * @param channel pre-configured gRPC {@code ManagedChannel}
     */
    public MisogiGrpcClient(ManagedChannel channel) {
        this.channel = channel;
        this.senderBlockingStub = SenderServiceGrpc.newBlockingStub(channel);
        this.senderAsyncStub = SenderServiceGrpc.newStub(channel);
        this.receiverBlockingStub = ReceiverServiceGrpc.newBlockingStub(channel);
        this.receiverAsyncStub = ReceiverServiceGrpc.newStub(channel);
    }

    // -----------------------------------------------------------------------
    //  SenderService operations
    // -----------------------------------------------------------------------

    /**
     * Upload a local file to the Misogi sender node via bidirectional streaming.
     *
     * <p>The file is read in configurable chunks (default 64 KiB), each wrapped
     * in a {@link Chunk} protobuf message with MD5 integrity checksum, and sent
     * through a client-streaming RPC ({@code Upload}). The server responds with
     * an {@link UploadResponse} containing the assigned {@code file_id} and
     * initial status.</p>
     *
     * @param filePath absolute or relative path to the file to upload
     * @param policy   sanitization policy applied by the CDR engine
     * @return {@link UploadResponse} from the server (contains {@code file_id})
     * @throws MisogiException if the RPC fails, the file cannot be read, or the
     *                        stream is interrupted
     */
    public UploadResponse uploadFile(Path filePath, SanitizationPolicy policy) throws MisogiException {
        if (!Files.exists(filePath)) {
            throw new MisogiException("File not found: " + filePath);
        }

        String fileId = UUID.randomUUID().toString();
        CountDownLatch finishLatch = new CountDownLatch(1);
        final UploadResponse[] responseHolder = new UploadResponse[1];
        final Throwable[] errorHolder = new Throwable[1];

        StreamObserver<UploadResponse> responseObserver = new StreamObserver<>() {

            @Override
            public void onNext(UploadResponse value) {
                responseHolder[0] = value;
                LOG.info("Upload completed: fileId=%s status=%s".formatted(value.getFileId(), value.getStatus()));
            }

            @Override
            public void onError(Throwable t) {
                errorHolder[0] = t;
                LOG.log(Level.WARNING, "Upload RPC error", t);
                finishLatch.countDown();
            }

            @Override
            public void onCompleted() {
                finishLatch.countDown();
            }
        };

        StreamObserver<Chunk> requestObserver = senderAsyncStub.upload(responseObserver);

        try (InputStream in = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[64 * 1024];
            int chunkIndex = 0;
            int bytesRead;

            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] chunkData = (bytesRead == buffer.length) ? buffer : java.util.Arrays.copyOf(buffer, bytesRead);
                String md5 = md5Hex(chunkData);

                Chunk chunk = Chunk.newBuilder()
                        .setData(com.google.protobuf.ByteString.copyFrom(chunkData))
                        .setFileId(fileId)
                        .setChunkIndex(chunkIndex++)
                        .setChunkMd5(md5)
                        .build();

                requestObserver.onNext(chunk);
            }

            requestObserver.onCompleted();

            if (!finishLatch.await(60, TimeUnit.SECONDS)) {
                throw new MisogiException("Upload timed out waiting for server response");
            }

            if (errorHolder[0] != null) {
                throw new MisogiException("Upload failed", errorHolder[0]);
            }

            if (responseHolder[0] == null) {
                throw new MisogiException("Upload returned no response");
            }

            return responseHolder[0];

        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MisogiException("Error during file upload: " + filePath, e);
        }
    }

    /**
     * Query the current processing status of a previously uploaded file.
     *
     * @param transferId the {@code file_id} returned by {@link #uploadFile}
     * @return detailed {@link FileStatusResponse} from the server
     * @throws MisogiException on RPC failure or invalid transfer ID
     */
    public FileStatusResponse getFileStatus(String transferId) throws MisogiException {
        try {
            FileIdRequest request = FileIdRequest.newBuilder()
                    .setFileId(transferId)
                    .build();

            return senderBlockingStub.getFileStatus(request);
        } catch (StatusRuntimeException e) {
            throw new MisogiException("getFileStatus failed for transferId=" + transferId, e);
        }
    }

    /**
     * List all files currently registered on the sender node.
     *
     * @return list of {@link FileStatusResponse} entries
     * @throws MisogiException on RPC failure
     */
    public List<FileStatusResponse> listFiles() throws MisogiException {
        try {
            ListFilesRequest request = ListFilesRequest.getDefaultInstance();
            ListFilesResponse response = senderBlockingStub.listFiles(request);
            return response.getFilesList();
        } catch (StatusRuntimeException e) {
            throw new MisogiException("listFiles failed", e);
        }
    }

    /**
     * Initiate a transfer of the identified file to the receiver node.
     *
     * @param transferId the {@code file_id} to trigger transfer for
     * @return {@link TransferResponse} containing outcome details
     * @throws MisogiException on RPC failure
     */
    public TransferResponse triggerTransfer(String transferId) throws MisogiException {
        try {
            FileIdRequest request = FileIdRequest.newBuilder()
                    .setFileId(transferId)
                    .build();

            return senderBlockingStub.triggerTransfer(request);
        } catch (StatusRuntimeException e) {
            throw new MisogiException("triggerTransfer failed for transferId=" + transferId, e);
        }
    }

    // -----------------------------------------------------------------------
    //  ReceiverService operations
    // -----------------------------------------------------------------------

    /**
     * Download a file from the Misogi receiver node via server-streaming RPC.
     *
     * <p>The caller provides a destination path; chunks received from the
     * {@code DownloadFile} RPC are written sequentially. The method returns
     * metadata about the download including total bytes written.</p>
     *
     * @param transferId the {@code file_id} identifying the file to download
     * @param outputPath where the downloaded content will be written
     * @return {@link DownloadResult} with byte count and transfer ID
     * @throws MisogiException on RPC failure, I/O error, or interruption
     */
    public DownloadResult downloadFile(String transferId, Path outputPath) throws MisogiException {
        try {
            FileIdRequest request = FileIdRequest.newBuilder()
                    .setFileId(transferId)
                    .build();

            long totalBytes = 0;

            try (var iterator = receiverBlockingStub.downloadFile(request)) {
                Files.createDirectories(outputPath.getParent() != null ? outputPath.getParent() : Path.of("."));

                try (var out = Files.newOutputStream(outputPath)) {
                    while (iterator.hasNext()) {
                        FileChunk chunk = iterator.next();
                        byte[] data = chunk.getData().toByteArray();
                        out.write(data);
                        totalBytes += data.length;
                    }
                }
            }

            LOG.info("Download complete: %d bytes written to %s".formatted(totalBytes, outputPath));
            return new DownloadResult(totalBytes, transferId);

        } catch (StatusRuntimeException e) {
            throw new MisogiException("downloadFile failed for transferId=" + transferId, e);
        } catch (IOException e) {
            throw new MisogiException("I/O error writing to " + outputPath, e);
        }
    }

    // -----------------------------------------------------------------------
    //  Lifecycle
    // -----------------------------------------------------------------------

    /**
     * Gracefully shut down the underlying gRPC channel.
     *
     * <p>Waits up to 5 seconds for pending RPCs to complete before forceful
     * termination. This method is idempotent — calling it multiple times is safe.</p>
     */
    public void shutdown() {
        if (!channel.isShutdown()) {
            LOG.info("Shutting down gRPC channel...");
            channel.shutdown();
            try {
                channel.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                channel.shutdownNow();
            }
        }
    }

    /**
     * Return the underlying channel for advanced use cases (e.g. interceptors).
     *
     * @return the managed gRPC channel
     */
    public Channel getChannel() {
        return channel;
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    private static String md5Hex(byte[] data) throws MisogiException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(data);
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new MisogiException("MD5 algorithm not available", e);
        }
    }
}
