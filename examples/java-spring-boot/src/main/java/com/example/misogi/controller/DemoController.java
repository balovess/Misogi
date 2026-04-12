package com.example.misogi.controller;

import com.example.misogi.client.MisogiException;
import com.example.misogi.service.FileUploadService;
import misogi.file_transfer.v1.FileStatusResponse;
import misogi.file_transfer.v1.TransferResponse;
import misogi.file_transfer.v1.UploadResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;

/**
 * REST controller that bridges HTTP requests to Misogi gRPC operations.
 *
 * <p>This controller demonstrates how a web frontend can interact with the
 * Misogi CDR engine without speaking gRPC directly. Each endpoint accepts
 * standard HTTP payloads (JSON, multipart form-data), delegates to
 * {@link FileUploadService}, and returns conventional REST responses.</p>
 *
 * <h2>Endpoints</h2>
 * <table>
 *   <tr><th>Method</th><th>Path</th><th>Description</th></tr>
 *   <tr><td>POST</td><td>{@code /api/demo/upload}</td><td>Upload → gRPC stream</td></tr>
 *   <tr><td>GET </td><td>{@code /api/demo/status/{transferId}}</td><td>Query file status</td></tr>
 *   <tr><td>GET </td><td>{@code /api/demo/download/{transferId}}</td><td>Download via gRPC</td></tr>
 *   <tr><td>GET </td><td>{@code /api/demo/files}</td><td>List all files</td></tr>
 *   <tr><td>POST</td><td>{@code /api/demo/transfer/{transferId}}</td><td>Trigger transfer</td></tr>
 * </table>
 *
 * @see FileUploadService
 */
@RestController
@RequestMapping("/api/demo")
public class DemoController {

    private static final Logger LOG = LoggerFactory.getLogger(DemoController.class);

    private final FileUploadService fileUploadService;

    private static final Path TEMP_UPLOAD_DIR = Path.of(System.getProperty("java.io.tmpdir"), "misogi-uploads");

    public DemoController(FileUploadService fileUploadService) {
        this.fileUploadService = fileUploadService;
    }

    /**
     * Accept a multipart file upload, persist it temporarily, then stream it
     * to the Misogi sender node via gRPC.
     *
     * @param file the uploaded file from the HTTP request
     * @return JSON containing the server-assigned fileId and status
     */
    @PostMapping("/upload")
    public ResponseEntity<Map<String, String>> upload(@RequestParam("file") MultipartFile file) {
        try {
            Files.createDirectories(TEMP_UPLOAD_DIR);
            Path tempPath = TEMP_UPLOAD_DIR.resolve(file.getOriginalFilename());
            file.transferTo(tempPath.toFile());

            LOG.info("Received HTTP upload: {} ({} bytes)", file.getOriginalFilename(), file.getSize());

            UploadResponse response = fileUploadService.uploadFile(tempPath);

            return ResponseEntity.ok(Map.of(
                    "fileId", response.getFileId(),
                    "status", response.getStatus(),
                    "originalFilename", file.getOriginalFilename()
            ));
        } catch (IOException | MisogiException e) {
            LOG.error("Upload failed", e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", "Upload failed: " + e.getMessage()
            ));
        }
    }

    /**
     * Return the current processing status of a file identified by its transfer ID.
     *
     * @param transferId the file identifier
     * @return JSON representation of {@link FileStatusResponse}
     */
    @GetMapping("/status/{transferId}")
    public ResponseEntity<?> getStatus(@PathVariable String transferId) {
        try {
            FileStatusResponse status = fileUploadService.getFileStatus(transferId);
            return ResponseEntity.ok(Map.of(
                    "fileId", status.getFileId(),
                    "filename", status.getFilename(),
                    "totalSize", String.valueOf(status.getTotalSize()),
                    "chunkCount", String.valueOf(status.getChunkCount()),
                    "completedChunks", String.valueOf(status.getCompletedChunks()),
                    "status", status.getStatus(),
                    "createdAt", status.getCreatedAt()
            ));
        } catch (MisogiException e) {
            LOG.error("getStatus failed for {}", transferId, e);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Download a file from the Misogi receiver node and stream it back as an
     * HTTP attachment.
     *
     * @param transferId the file identifier
     * @return the file content as a downloadable resource
     */
    @GetMapping("/download/{transferId}")
    public ResponseEntity<Resource> download(@PathVariable String transferId) {
        try {
            Path outputPath = TEMP_UPLOAD_DIR.resolve("download-" + transferId + ".bin");
            var result = fileUploadService.downloadFile(transferId, outputPath);

            Resource resource = new UrlResource(outputPath.toUri());
            if (resource.exists()) {
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .header(HttpHeaders.CONTENT_DISPOSITION,
                                "attachment; filename=\"" + outputPath.getFileName() + "\"")
                        .body(resource);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (MisogiException | MalformedURLException e) {
            LOG.error("Download failed for {}", transferId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * List all files currently known to the Misogi sender node.
     *
     * @return JSON array of file entries
     */
    @GetMapping("/files")
    public ResponseEntity<List<Map<String, Object>>> listFiles() {
        try {
            List<FileStatusResponse> files = fileUploadService.listFiles();
            List<Map<String, Object>> result = files.stream().map(f -> Map.<String, Object>of(
                    "fileId", f.getFileId(),
                    "filename", f.getFilename(),
                    "totalSize", f.getTotalSize(),
                    "status", f.getStatus()
            )).toList();

            return ResponseEntity.ok(result);
        } catch (MisogiException e) {
            LOG.error("listFiles failed", e);
            return ResponseEntity.internalServerError().body(List.of());
        }
    }

    /**
     * Trigger a sender→receiver transfer for the given file.
     *
     * @param transferId the file identifier
     * @return JSON with transfer outcome
     */
    @PostMapping("/transfer/{transferId}")
    public ResponseEntity<Map<String, String>> triggerTransfer(@PathVariable String transferId) {
        try {
            TransferResponse response = fileUploadService.triggerTransfer(transferId);
            return ResponseEntity.ok(Map.of(
                    "fileId", response.getFileId(),
                    "status", response.getStatus(),
                    "message", response.getMessage()
            ));
        } catch (MisogiException e) {
            LOG.error("triggerTransfer failed for {}", transferId, e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "error", "Transfer failed: " + e.getMessage()
            ));
        }
    }
}
