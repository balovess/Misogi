package com.example.misogi.client;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import misogi.file_transfer.v1.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link MisogiGrpcClient}.
 *
 * <p>Uses gRPC's <strong>in-process</strong> server/channel to avoid network
 * overhead and external dependencies. Each test method spins up a lightweight
 * in-process server that implements the V1 service handlers, then verifies
 * that the client correctly marshals requests and unmarshals responses.</p>
 *
 * <h3>Integration Note</h3>
 * <p>These tests validate client-side logic only. End-to-end tests against
 * a live Misogi Rust server require the server binary and are out of scope
 * for this unit-test suite.</p>
 */
class MisogiGrpcClientTest {

    public GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    @TempDir
    Path tempDir;

    private Server server;
    private MisogiGrpcClient client;

    /**
     * Start an in-process Misogi server before each test.
     *
     * <p>The server provides minimal implementations of both SenderService and
     * ReceiverService — enough to verify request/response round-trips without
     * actual file processing.</p>
     */
    @BeforeEach
    void setUp() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(new SenderServiceTestImpl())
                .addService(new ReceiverServiceTestImpl())
                .build()
                .start();

        ManagedChannel channel = grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()
        );

        client = new MisogiGrpcClient((io.grpc.ManagedChannel) channel);
    }

    /** Shut down the in-process server after each test. */
    @AfterEach
    void tearDown() {
        if (server != null && !server.isShutdown()) {
            server.shutdown();
        }
    }

    // -----------------------------------------------------------------------
    //  Upload tests
    // -----------------------------------------------------------------------

    @Test
    void uploadFile_shouldReturnResponseWithFileId() throws IOException, MisogiException {
        Path testFile = tempDir.resolve("test-upload.bin");
        Files.writeString(testFile, "Hello Misogi CDR Engine!");

        var response = client.uploadFile(testFile, MisogiGrpcClient.SanitizationPolicy.DEFAULT);

        assertThat(response.getFileId()).isNotEmpty();
        assertThat(response.getStatus()).isNotNull();
    }

    @Test
    void uploadFile_shouldThrowWhenFileNotFound() {
        Path missing = tempDir.resolve("does-not-exist.bin");

        assertThatThrownBy(() -> client.uploadFile(missing, MisogiGrpcClient.SanitizationPolicy.DEFAULT))
                .isInstanceOf(MisogiException.class)
                .hasMessageContaining("not found");
    }

    // -----------------------------------------------------------------------
    //  GetFileStatus tests
    // -----------------------------------------------------------------------

    @Test
    void getFileStatus_shouldReturnPopulatedResponse() throws MisogiException {
        FileStatusResponse status = client.getFileStatus("test-transfer-123");

        assertThat(status.getFileId()).isEqualTo("test-transfer-123");
        assertThat(status.getFilename()).isEqualTo("test-file.pdf");
        assertThat(status.getTotalSize()).isEqualTo(1024);
        assertThat(status.getStatus()).isEqualTo("completed");
    }

    // -----------------------------------------------------------------------
    //  ListFiles tests
    // -----------------------------------------------------------------------

    @Test
    void listFiles_shouldReturnNonEmptyList() throws MisogiException {
        List<FileStatusResponse> files = client.listFiles();

        assertThat(files).isNotEmpty();
        assertThat(files.getFirst().getFileId()).isNotEmpty();
    }

    // -----------------------------------------------------------------------
    //  TriggerTransfer tests
    // -----------------------------------------------------------------------

    @Test
    void triggerTransfer_shouldReturnSuccessResponse() throws MisogiException {
        TransferResponse response = client.triggerTransfer("test-transfer-123");

        assertThat(response.getStatus()).isEqualTo("triggered");
        assertThat(response.getMessage()).contains("Transfer initiated");
    }

    // -----------------------------------------------------------------------
    //  Download tests
    // -----------------------------------------------------------------------

    @Test
    void downloadFile_shouldWriteContentToDisk() throws MisogiException, IOException {
        Path output = tempDir.resolve("downloaded.bin");

        var result = client.downloadFile("download-test-id", output);

        assertThat(result.totalBytesWritten()).isGreaterThan(0);
        assertThat(Files.exists(output)).isTrue();
        String content = Files.readString(output);
        assertThat(content).isEqualTo("simulated-file-content");
    }

    // -----------------------------------------------------------------------
    //  Shutdown tests
    // -----------------------------------------------------------------------

    @Test
    void shutdown_shouldBeIdempotent() {
        client.shutdown();
        client.shutdown();
        // No exception → idempotent
    }

    // =======================================================================
    //  In-process service implementations (test doubles)
    // =======================================================================

    /**
     * Minimal SenderService implementation for in-process testing.
     *
     * <p>Returns canned responses without performing any real sanitization.</p>
     */
    static class SenderServiceTestImpl extends SenderServiceGrpc.SenderServiceImplBase {

        @Override
        public StreamObserver<Chunk> upload(StreamObserver<UploadResponse> responseObserver) {
            return new StreamObserver<>() {
                int chunkCount = 0;

                @Override
                public void onNext(Chunk value) {
                    chunkCount++;
                }

                @Override
                public void onError(Throwable t) {
                    responseObserver.onError(t);
                }

                @Override
                public void onCompleted() {
                    responseObserver.onNext(UploadResponse.newBuilder()
                            .setFileId("generated-file-" + System.nanoTime())
                            .setStatus("received")
                            .build());
                    responseObserver.onCompleted();
                }
            };
        }

        @Override
        public void getFileStatus(FileIdRequest request,
                                  StreamObserver<FileStatusResponse> responseObserver) {
            responseObserver.onNext(FileStatusResponse.newBuilder()
                    .setFileId(request.getFileId())
                    .setFilename("test-file.pdf")
                    .setTotalSize(1024)
                    .setChunkCount(4)
                    .setCompletedChunks(4)
                    .setStatus("completed")
                    .setCreatedAt("2025-01-01T00:00:00Z")
                    .build());
            responseObserver.onCompleted();
        }

        @Override
        public void listFiles(ListFilesRequest request,
                              StreamObserver<ListFilesResponse> responseObserver) {
            responseObserver.onNext(ListFilesResponse.newBuilder()
                    .addFiles(FileStatusResponse.newBuilder()
                            .setFileId("file-001")
                            .setFilename("sample.pdf")
                            .setTotalSize(2048)
                            .setStatus("ready")
                            .build())
                    .setTotal(1)
                    .build());
            responseObserver.onCompleted();
        }

        @Override
        public void triggerTransfer(FileIdRequest request,
                                    StreamObserver<TransferResponse> responseObserver) {
            responseObserver.onNext(TransferResponse.newBuilder()
                    .setFileId(request.getFileId())
                    .setStatus("triggered")
                    .setMessage("Transfer initiated for " + request.getFileId())
                    .build());
            responseObserver.onCompleted();
        }
    }

    /**
     * Minimal ReceiverService implementation for in-process testing.
     */
    static class ReceiverServiceTestImpl extends ReceiverServiceGrpc.ReceiverServiceImplBase {

        @Override
        public void downloadFile(FileIdRequest request,
                                 StreamObserver<FileChunk> responseObserver) {
            byte[] content = "simulated-file-content".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            responseObserver.onNext(FileChunk.newBuilder()
                    .setData(com.google.protobuf.ByteString.copyFrom(content))
                    .setOffset(0)
                    .setTotalSize(content.length)
                    .build());
            responseObserver.onCompleted();
        }
    }
}
