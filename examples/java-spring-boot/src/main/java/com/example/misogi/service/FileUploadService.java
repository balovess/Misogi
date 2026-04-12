package com.example.misogi.service;

import com.example.misogi.client.MisogiException;
import com.example.misogi.client.MisogiGrpcClient;
import jakarta.annotation.PreDestroy;
import misogi.file_transfer.v1.FileStatusResponse;
import misogi.file_transfer.v1.TransferResponse;
import misogi.file_transfer.v1.UploadResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.nio.file.Path;
import java.util.List;

/**
 * Spring-managed service that wraps {@link MisogiGrpcClient} with lifecycle hooks.
 *
 * <p>Reads gRPC connection parameters from {@code application.yml} via
 * {@code @Value}, initialises the channel on startup ({@code @PostConstruct}),
 * and performs a graceful shutdown when the Spring context closes
 * ({@code @PreDestroy}).</p>
 *
 * <p>All public methods delegate to the underlying gRPC client while adding
 * SLF4J logging at appropriate levels for operational observability.</p>
 *
 * @see MisogiGrpcClient
 */
@Service
public class FileUploadService {

    private static final Logger LOG = LoggerFactory.getLogger(FileUploadService.class);

    @Value("${misogi.grpc.host:localhost}")
    private String grpcHost;

    @Value("${misogi.grpc.port:50051}")
    private int grpcPort;

    private MisogiGrpcClient grpcClient;

    /**
     * Initialise the gRPC channel after dependency injection completes.
     *
     * <p>Called automatically by the Spring container. Creates a plaintext
     * connection to the Misogi server at the configured host:port.</p>
     */
    @PostConstruct
    public void init() {
        LOG.info("Initialising Misogi gRPC client → {}:{}", grpcHost, grpcPort);
        this.grpcClient = new MisogiGrpcClient(grpcHost, grpcPort);
        LOG.info("Misogi gRPC client initialised successfully");
    }

    /**
     * Gracefully shut down the gRPC channel before bean destruction.
     *
     * <p>Ensures in-flight RPCs have a chance to complete (up to 5 s).</p>
     */
    @PreDestroy
    public void destroy() {
        LOG.info("Shutting down Misogi gRPC client...");
        if (grpcClient != null) {
            grpcClient.shutdown();
        }
        LOG.info("Misogi gRPC client shut down");
    }

    // -----------------------------------------------------------------------
    //  Delegated operations
    // -----------------------------------------------------------------------

    /**
     * Upload a file to the Misogi sender node.
     *
     * @param filePath path to the local file
     * @return server {@link UploadResponse} with assigned file ID
     * @throws MisogiException on communication or processing error
     */
    public UploadResponse uploadFile(Path filePath) throws MisogiException {
        LOG.info("Uploading file: {} (size: {} bytes)", filePath, filePath.toFile().length());
        UploadResponse response = grpcClient.uploadFile(filePath, MisogiGrpcClient.SanitizationPolicy.DEFAULT);
        LOG.info("Upload succeeded: fileId={}, status={}", response.getFileId(), response.getStatus());
        return response;
    }

    /**
     * Upload a file with an explicit sanitization policy.
     *
     * @param filePath path to the local file
     * @param policy   sanitization policy to apply
     * @return server {@link UploadResponse}
     * @throws MisogiException on error
     */
    public UploadResponse uploadFile(Path filePath, MisogiGrpcClient.SanitizationPolicy policy) throws MisogiException {
        LOG.info("Uploading file: {} with policy={}", filePath, policy);
        return grpcClient.uploadFile(filePath, policy);
    }

    /**
     * Query the status of a previously uploaded/transfer-initiated file.
     *
     * @param transferId file ID returned from upload or transfer trigger
     * @return detailed {@link FileStatusResponse}
     * @throws MisogiException on error
     */
    public FileStatusResponse getFileStatus(String transferId) throws MisogiException {
        LOG.debug("Querying file status: transferId={}", transferId);
        return grpcClient.getFileStatus(transferId);
    }

    /**
     * Download a file from the receiver node.
     *
     * @param transferId file identifier
     * @param outputPath destination path for downloaded content
     * @return download metadata (bytes written, transfer ID)
     * @throws MisogiException on error
     */
    public MisogiGrpcClient.DownloadResult downloadFile(String transferId, Path outputPath) throws MisogiException {
        LOG.info("Downloading file: transferId={} → {}", transferId, outputPath);
        return grpcClient.downloadFile(transferId, outputPath);
    }

    /**
     * List all files registered on the sender node.
     *
     * @return list of file status entries
     * @throws MisogiException on error
     */
    public List<FileStatusResponse> listFiles() throws MisogiException {
        LOG.debug("Listing files on sender node");
        return grpcClient.listFiles();
    }

    /**
     * Trigger transfer of a file from sender to receiver.
     *
     * @param transferId file identifier
     * @return {@link TransferResponse} with outcome details
     * @throws MisogiException on error
     */
    public TransferResponse triggerTransfer(String transferId) throws MisogiException {
        LOG.info("Triggering transfer for transferId={}", transferId);
        return grpcClient.triggerTransfer(transferId);
    }
}
