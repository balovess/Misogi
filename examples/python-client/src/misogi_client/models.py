"""Data models and custom exceptions for the Misogi async gRPC client.

All public types use ``dataclass`` for immutability-by-convention and
include comprehensive Google-style docstrings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal


# =============================================================================
# Enumerations
# =============================================================================


class SanitizationPolicy(StrEnum):
    """Sanitization policy applied during CDR processing.

    Each value maps to a server-side sanitization strategy that controls
    how active content is removed from uploaded files.

    Attributes:
        STRIP_ACTIVE_CONTENT: Remove macros, scripts, embedded objects,
            and other executable content while preserving document structure.
            This is the default policy for most office documents.
        CONVERT_TO_FLAT: Flatten complex nested structures (e.g., nested
            OLE containers, layered PDFs) into a single-layer equivalent.
            Useful for eliminating hidden data in deep object graphs.
        TEXT_ONLY: Extract only textual content, discarding all formatting,
            images, embedded files, and non-textual metadata. Produces the
            most aggressive sanitization result suitable for plain-text export.
    """

    STRIP_ACTIVE_CONTENT = "STRIP_ACTIVE_CONTENT"
    CONVERT_TO_FLAT = "CONVERT_TO_FLAT"
    TEXT_ONLY = "TEXT_ONLY"


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(frozen=True)
class FileStatus:
    """Immutable snapshot of a file's transfer/sanitization status.

    Returned by :meth:`MisogiAsyncClient.upload_file` and
    :meth:`MisogiAsyncClient.get_file_status`.

    Attributes:
        transfer_id: Unique identifier assigned by the sender node after
            upload initiation. Used for all subsequent status queries and
            download operations.
        status: Current lifecycle status string as reported by the server
            (e.g. ``"uploaded"``, ``"processing"``, ``"sanitized"``,
            ``"failed"``).
        filename: Original basename of the uploaded file, if available
            from the server response.
        total_size: Total file size in bytes reported by the server.
        chunk_count: Total number of chunks the file was divided into.
        completed_chunks: Number of chunks that have been fully processed.
        created_at: ISO-8601 timestamp of when the upload was accepted.
    """

    transfer_id: str = ""
    status: str = ""
    filename: str = ""
    total_size: int = 0
    chunk_count: int = 0
    completed_chunks: int = 0
    created_at: str = ""

    @property
    def is_complete(self) -> bool:
        """Return ``True`` if all chunks have been processed."""
        return self.chunk_count > 0 and self.completed_chunks >= self.chunk_count

    @property
    def progress_pct(self) -> float:
        """Return processing progress as a float in [0.0, 100.0]."""
        if self.chunk_count == 0:
            return 0.0
        return min(100.0, (self.completed_chunks / self.chunk_count) * 100.0)


@dataclass(frozen=True)
class DownloadMetadata:
    """Immutable record of a completed file download operation.

    Returned by :meth:`MisogiAsyncClient.download_file`.

    Attributes:
        transfer_id: Identifier of the downloaded transfer.
        output_path: Local filesystem path where the sanitized file was written.
        bytes_written: Total number of bytes written to disk.
        checksum_server: Checksum value reported by the server (if available).
        duration_seconds: Wall-clock time spent downloading in seconds.
    """

    transfer_id: str = ""
    output_path: Path = field(default_factory=Path)
    bytes_written: int = 0
    checksum_server: str = ""
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class SanitizeResult:
    """Combined result of a one-shot sanitization workflow.

    Produced by :meth:`MisogiAsyncClient.sanitize_file` which orchestrates
    upload → poll → download as a single logical operation.

    Attributes:
        upload_status: Status snapshot after the initial upload phase.
        download_metadata: Metadata from the final download phase.
        policy: The sanitization policy that was applied.
        success: ``True`` if the entire workflow completed without error.
        threat_summary: Human-readable summary of threats found/removed
            (populated by the server after sanitization).
    """

    upload_status: FileStatus = field(default_factory=FileStatus)
    download_metadata: DownloadMetadata = field(default_factory=DownloadMetadata)
    policy: SanitizationPolicy = SanitizationPolicy.STRIP_ACTIVE_CONTENT
    success: bool = False
    threat_summary: str = ""


@dataclass(frozen=True)
class FileInfo:
    """Lightweight summary of a file listed on sender or receiver node.

    Returned by :meth:`MisogiAsyncClient.list_files`.

    Attributes:
        file_id: Server-assigned unique identifier.
        filename: Original filename.
        size_bytes: File size in bytes.
        status: Current lifecycle status string.
        created_at: ISO-8601 creation timestamp.
    """

    file_id: str = ""
    filename: str = ""
    size_bytes: int = 0
    status: str = ""
    created_at: str = ""


# =============================================================================
# Custom Exceptions
# =============================================================================


class MisogiError(Exception):
    """Base exception for all Misogi client errors."""


class MisogiConnectionError(MisogiError):
    """Raised when the gRPC channel cannot be established or is lost.

    Common causes:
        - Misogi sender/receiver service not running
        - Network unreachable or firewall blocking the port
        - TLS certificate mismatch (when using secure channels
        - Server-side graceful shutdown during an active call
    """

    def __init__(self, message: str, host: str = "", port: int = 0) -> None:
        self.host = host
        self.port = port
        detail = f"{message}"
        if host and port:
            detail += f" ({host}:{port})"
        super().__init__(detail)


class MisogiSanitizationError(MisogiError):
    """Raised when the server reports a sanitization failure.

    This indicates the CDR engine could not process the file, which may
    be due to:
        - Unsupported file format
        - Corrupt file structure
        - Policy violation (file exceeds size limits, etc.)
        - Internal server error during processing
    """

    def __init__(self, message: str, transfer_id: str = "", code: str = "") -> None:
        self.transfer_id = transfer_id
        self.code = code
        detail = message
        if transfer_id:
            detail += f" [transfer_id={transfer_id}]"
        if code:
            detail += f" (code={code})"
        super().__init__(detail)


class MisogiDownloadError(MisogiError):
    """Raised when a file download fails partway through.

    Indicates the receiver service stream was interrupted or returned
    an error chunk before completion.
    """

    def __init__(
        self,
        message: str,
        transfer_id: str = "",
        bytes_received: int = 0,
    ) -> None:
        self.transfer_id = transfer_id
        self.bytes_received = bytes_received
        detail = message
        if transfer_id:
            detail += f" [transfer_id={transfer_id}]"
        if bytes_received > 0:
            detail += f" ({bytes_received} bytes received)"
        super().__init__(detail)
