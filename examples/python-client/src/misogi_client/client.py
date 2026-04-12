"""Core async gRPC client for Misogi CDR sanitization engine.

Provides ``MisogiAsyncClient`` — an asyncio-native client wrapping both
``SenderService`` and ``ReceiverService`` gRPC stubs from
:mod:`misogi.file_transfer.v1`.

All I/O operations are asynchronous and use streaming where the protocol
supports it. The client implements the async context manager protocol for
clean resource lifecycle management.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any, Callable

import grpc
from grpc.aio import Channel, ClientStub

from misogi_client.models import (
    DownloadMetadata,
    FileStatus,
    FileInfo,
    MisogiConnectionError,
    MisogiDownloadError,
    MisogiSanitizationError,
    SanitizationPolicy,
    SanitizeResult,
)

try:
    from misogi_client.pb2 import misogi_pb2 as pb2
    from misogi_client.pb2 import misogi_pb2_grpc as pb2_grpc
except ImportError:
    raise ImportError(
        "gRPC stubs not found. Run 'bash generate_stubs.sh' (or generate_stubs.bat on Windows) "
        "to generate them from the proto definition."
    )

logger = logging.getLogger(__name__)

# Default polling interval in seconds when waiting for sanitization completion.
_DEFAULT_POLL_INTERVAL_S: float = 1.0

# Maximum number of status-polling iterations before giving up.
_MAX_POLL_ITERATIONS: int = 300


class MisogiAsyncClient:
    """Async gRPC client for Misogi file sanitization engine.

    Wraps both :class:`SenderServiceStub` and :class:`ReceiverServiceStub`
    into a single coherent API with Pythonic error handling, progress
    tracking, and type-safe return values.

    The client should be used as an async context manager to ensure the
    underlying gRPC channel is properly closed::

        async with MisogiAsyncClient("localhost", 50051) as client:
            result = await client.sanitize_file("document.pdf")

    Attributes:
        host: Sender service hostname or IP address.
        port: Sender service gRPC port number.
        receiver_host: Receiver service hostname (defaults to ``host``).
        receiver_port: Receiver service gRPC port number (defaults to ``port + 1``).
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 50051,
        receiver_host: str | None = None,
        receiver_port: int | None = None,
        options: list[tuple[str, str]] | None = None,
    ) -> None:
        """Initialize the client with connection parameters.

        Args:
            host: Sender node gRPC host (default ``"localhost"``).
            port: Sender node gRPC port (default ``50051``).
            receiver_host: Receiver node gRPC host. Defaults to *host*.
            receiver_port: Receiver node gRPC port. Defaults to *port + 1*.
            options: Additional gRPC channel options (e.g. TLS config).
        """
        self.host = host
        self.port = port
        self.receiver_host = receiver_host or host
        self.receiver_port = receiver_port if receiver_port is not None else port + 1
        self._options = options or []
        self._sender_channel: Channel | None = None
        self._receiver_channel: Channel | None = None
        self._sender_stub: pb2_grpc.SenderServiceStub | None = None
        self._receiver_stub: pb2_grpc.ReceiverServiceStub | None = None

    # -------------------------------------------------------------------------
    # Async Context Manager
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> MisogiAsyncClient:
        """Open gRPC channels to sender and receiver services.

        Returns:
            The client instance, ready for method calls.

        Raises:
            MisogiConnectionError: If either channel cannot be established.
        """
        try:
            sender_target = f"{self.host}:{self.port}"
            self._sender_channel = grpc.aio.insecure_channel(
                sender_target, options=self._options
            )
            await self._sender_channel.channel_ready()
            self._sender_stub = pb2_grpc.SenderServiceStub(self._sender_channel)
            logger.info("Sender channel established: %s", sender_target)
        except grpc.AioRpcError as exc:
            raise MisogiConnectionError(
                f"Failed to connect to sender service",
                host=self.host,
                port=self.port,
            ) from exc

        try:
            receiver_target = f"{self.receiver_host}:{self.receiver_port}"
            self._receiver_channel = grpc.aio.insecure_channel(
                receiver_target, options=self._options
            )
            await self._receiver_channel.channel_ready()
            self._receiver_stub = pb2_grpc.ReceiverServiceStub(self._receiver_channel)
            logger.info("Receiver channel established: %s", receiver_target)
        except grpc.AioRpcError as exc:
            await self._close_sender_only()
            raise MisogiConnectionError(
                f"Failed to connect to receiver service",
                host=self.receiver_host,
                port=self.receiver_port,
            ) from exc

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Close all gRPC channels gracefully."""
        await self.close()

    async def close(self) -> None:
        """Explicitly close both sender and receiver channels.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if self._sender_channel is not None:
            await self._sender_channel.close()
            self._sender_channel = None
            logger.debug("Sender channel closed")
        if self._receiver_channel is not None:
            await self._receiver_channel.close()
            self._receiver_channel = None
            logger.debug("Receiver channel closed")
        self._sender_stub = None
        self._receiver_stub = None

    async def _close_sender_only(self) -> None:
        """Internal: close only the sender channel (used during partial init)."""
        if self._sender_channel is not None:
            await self._sender_channel.close()
            self._sender_channel = None

    def _require_sender(self) -> pb2_grpc.SenderServiceStub:
        """Return the sender stub, raising if not connected."""
        if self._sender_stub is None:
            raise MisogiConnectionError(
                "Sender stub not initialized — use 'async with' context manager"
            )
        return self._sender_stub

    def _require_receiver(self) -> pb2_grpc.ReceiverServiceStub:
        """Return the receiver stub, raising if not connected."""
        if self._receiver_stub is None:
            raise MisogiConnectionError(
                "Receiver stub not initialized — use 'async with' context manager"
            )
        return self._receiver_stub

    # -------------------------------------------------------------------------
    # Upload Operations (SenderService)
    # -------------------------------------------------------------------------

    async def upload_file(
        self,
        file_path: Path | str,
        policy: SanitizationPolicy = SanitizationPolicy.STRIP_ACTIVE_CONTENT,
        chunk_size: int = 64 * 1024,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> FileStatus:
        """Upload a local file to the Misogi sender via streaming gRPC.

        Reads *file_path* in chunks of *chunk_size* bytes, computes MD5
        per-chunk for integrity verification, and streams each
        :proto-msg:`Chunk` to the server's ``Upload`` RPC.

        Args:
            file_path: Path to the file to upload and sanitize.
            policy: Sanitization policy to apply server-side.
            chunk_size: Streaming chunk size in bytes (default 64 KiB).
            progress_callback: Optional callback invoked as
                ``callback(bytes_sent, total_bytes)`` after each chunk.

        Returns:
            :class:`FileStatus` containing the server-assigned transfer ID
            and initial status after upload acceptance.

        Raises:
            MisogiConnectionError: If the gRPC call fails due to network issues.
            MisogiSanitizationError: If the server rejects the upload.
            FileNotFoundError: If *file_path* does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Not a regular file: {path}")

        total_size = path.stat().st_size
        filename = path.name
        stub = self._require_sender()

        async def _chunk_generator():
            bytes_sent = 0
            chunk_index = 0
            with open(path, "rb") as fh:
                while True:
                    data = fh.read(chunk_size)
                    if not data:
                        break
                    chunk_md5 = hashlib.md5(data).hexdigest()
                    yield pb2.Chunk(
                        data=data,
                        file_id=filename,
                        chunk_index=chunk_index,
                        chunk_md5=chunk_md5,
                    )
                    bytes_sent += len(data)
                    chunk_index += 1
                    if progress_callback is not None:
                        progress_callback(bytes_sent, total_size)

        try:
            response: pb2.UploadResponse = await stub.Upload(_chunk_generator())
        except grpc.AioRpcError as exc:
            if exc.code() == grpc.StatusCode.UNAVAILABLE:
                raise MisogiConnectionError(
                    "Upload failed — sender unavailable",
                    host=self.host,
                    port=self.port,
                ) from exc
            raise MisogiSanitizationError(
                f"Upload RPC error: {exc.details()}",
                code=str(exc.code().name),
            ) from exc

        logger.info(
            "Upload accepted: file_id=%s status=%s",
            response.file_id,
            response.status,
        )

        return FileStatus(
            transfer_id=response.file_id,
            status=response.status,
            filename=filename,
            total_size=total_size,
        )

    # -------------------------------------------------------------------------
    # Status & Listing (SenderService / ReceiverService)
    # -------------------------------------------------------------------------

    async def get_file_status(self, transfer_id: str) -> FileStatus:
        """Query the current processing status of an uploaded file.

        Args:
            transfer_id: Server-assigned identifier returned by
                :meth:`upload_file`.

        Returns:
            :class:`FileStatus` with up-to-date processing state.

        Raises:
            MisogiConnectionError: If the RPC fails.
            MisogiSanitizationError: If the server returns an error status.
        """
        stub = self._require_sender()
        request = pb2.FileIdRequest(file_id=transfer_id)

        try:
            response: pb2.FileStatusResponse = await stub.GetFileStatus(request)
        except grpc.AioRpcError as exc:
            if exc.code() == grpc.StatusCode.UNAVAILABLE:
                raise MisogiConnectionError(
                    "GetFileStatus failed — sender unavailable",
                    host=self.host,
                    port=self.port,
                ) from exc
            raise MisogiSanitizationError(
                f"GetFileStatus RPC error: {exc.details()}",
                transfer_id=transfer_id,
                code=str(exc.code().name),
            ) from exc

        return FileStatus(
            transfer_id=response.file_id,
            status=response.status,
            filename=response.filename,
            total_size=response.total_size,
            chunk_count=response.chunk_count,
            completed_chunks=response.completed_chunks,
            created_at=response.created_at,
        )

    async def list_files(
        self,
        page: int = 1,
        per_page: int = 50,
        status_filter: str = "",
    ) -> list[FileInfo]:
        """List files available on the sender node.

        Supports pagination through *page* / *per_page* parameters
        and optional filtering by lifecycle status string.

        Args:
            page: Page number (1-indexed, default ``1``).
            per_page: Number of results per page (default ``50``).
            status_filter: Filter by status string (e.g. ``"sanitized"``,
                ``"processing"``). Empty string means no filter.

        Returns:
            List of :class:`FileInfo` summaries.

        Raises:
            MisogiConnectionError: If the RPC fails.
        """
        stub = self._require_sender()
        request_kwargs: dict[str, Any] = {
            "page": page,
            "per_page": per_page,
        }
        if status_filter:
            request_kwargs["status_filter"] = status_filter
        request = pb2.ListFilesRequest(**request_kwargs)

        try:
            response: pb2.ListFilesResponse = await stub.ListFiles(request)
        except grpc.AioRpcError as exc:
            if exc.code() == grpc.StatusCode.UNAVAILABLE:
                raise MisogiConnectionError(
                    "ListFiles failed — sender unavailable",
                    host=self.host,
                    port=self.port,
                ) from exc
            raise

        return [
            FileInfo(
                file_id=f.file_id,
                filename=f.filename,
                size_bytes=f.total_size,
                status=f.status,
                created_at=f.created_at,
            )
            for f in response.files
        ]

    async def trigger_transfer(self, transfer_id: str) -> str:
        """Initiate transfer from sender to receiver node.

        After uploading and sanitizing, this tells the sender to push
        the sanitized file to the receiver so it can be downloaded.

        Args:
            transfer_id: Server-assigned upload identifier.

        Returns:
            Status string reported by the server.

        Raises:
            MisogiConnectionError: If the RPC fails.
            MisogiSanitizationError: If the server refuses the transfer.
        """
        stub = self._require_sender()
        request = pb2.FileIdRequest(file_id=transfer_id)

        try:
            response: pb2.TransferResponse = await stub.TriggerTransfer(request)
        except grpc.AioRpcError as exc:
            if exc.code() == grpc.StatusCode.UNAVAILABLE:
                raise MisogiConnectionError(
                    "TriggerTransfer failed — sender unavailable",
                    host=self.host,
                    port=self.port,
                ) from exc
            raise MisogiSanitizationError(
                f"Transfer trigger failed: {exc.details()}",
                transfer_id=transfer_id,
                code=str(exc.code().name),
            ) from exc

        logger.info("Transfer triggered: %s → status=%s", transfer_id, response.status)
        return response.status

    # -------------------------------------------------------------------------
    # Download Operations (ReceiverService)
    # -------------------------------------------------------------------------

    async def download_file(
        self,
        transfer_id: str,
        output_path: Path | str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> DownloadMetadata:
        """Download a sanitized file from the receiver via streaming gRPC.

        Streams :proto-msg:`FileChunk` messages from the receiver's
        ``DownloadFile`` RPC and writes them sequentially to *output_path*.

        Args:
            transfer_id: Server-assigned identifier of the file to download.
            output_path: Local filesystem destination path.
            progress_callback: Optional callback invoked as
                ``callback(bytes_received, total_bytes)`` after each chunk.

        Returns:
            :class:`DownloadMetadata` with write statistics.

        Raises:
            MisogiDownloadError: If the stream is interrupted or incomplete.
            MisogiConnectionError: If the RPC cannot be initiated.
        """
        out = Path(output_path)
        stub = self._require_receiver()
        request = pb2.FileIdRequest(file_id=transfer_id)

        start_time = time.monotonic()
        total_received = 0
        total_size_estimated = 0
        last_offset = 0

        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            stream: Any = stub.DownloadFile(request)

            with open(out, "wb") as fh:
                async for chunk_msg in stream:
                    data = chunk_msg.data
                    offset = chunk_msg.offset
                    total_size_estimated = chunk_msg.total_size or total_size_estimated
                    fh.seek(offset)
                    fh.write(data)
                    total_received += len(data)
                    last_offset = max(last_offset, offset + len(data))
                    if progress_callback is not None:
                        progress_callback(total_received, total_size_estimated)

        except grpc.AioRpcError as exc:
            raise MisogiDownloadError(
                f"Download stream error: {exc.details()}",
                transfer_id=transfer_id,
                bytes_received=total_received,
            ) from exc
        except OSError as exc:
            raise MisogiDownloadError(
                f"File write error at {out}: {exc}",
                transfer_id=transfer_id,
                bytes_received=total_received,
            ) from exc

        elapsed = time.monotonic() - start_time

        logger.info(
            "Download complete: %s → %s (%d bytes, %.2fs)",
            transfer_id,
            out,
            total_received,
            elapsed,
        )

        return DownloadMetadata(
            transfer_id=transfer_id,
            output_path=out.resolve(),
            bytes_written=total_received,
            duration_seconds=round(elapsed, 3),
        )

    # -------------------------------------------------------------------------
    # Convenience: One-Shot Sanitization Workflow
    # -------------------------------------------------------------------------

    async def sanitize_file(
        self,
        input_path: Path | str,
        output_path: Path | str | None = None,
        policy: SanitizationPolicy = SanitizationPolicy.STRIP_ACTIVE_CONTENT,
        poll_interval: float = _DEFAULT_POLL_INTERVAL_S,
        max_poll_iterations: int = _MAX_POLL_ITERATIONS,
    ) -> SanitizeResult:
        """Execute the full sanitization workflow in one call.

        Orchestrates three phases:

        1. **Upload** — Stream file to sender node via :meth:`upload_file`.
        2. **Poll** — Wait for sanitization to complete by periodically
           calling :meth:`get_file_status`.
        3. **Download** — Retrieve sanitized result from receiver node
           via :meth:`download_file`.

        This is the recommended entry point for simple scripts that need
        to sanitize a single file without managing individual phases.

        Args:
            input_path: Path to the source file to sanitize.
            output_path: Destination for the sanitized output. Defaults to
                ``sanitized_<original_filename>`` in the same directory.
            policy: Sanitization policy to apply.
            poll_interval: Seconds between status polls while waiting
                for sanitization to finish (default ``1.0``).
            max_poll_iterations: Maximum number of polling rounds before
                timing out (default ``300``, i.e. 5 minutes at 1s interval).

        Returns:
            :class:`SanitizeResult` combining upload status, download
            metadata, and overall success flag.

        Raises:
            FileNotFoundError: If *input_path* does not exist.
            MisogiConnectionError: On network/channel failures.
            MisogiSanitizationError: If sanitization fails server-side.
            MisogiDownloadError: If the download phase fails.
        """
        src = Path(input_path)
        dst = Path(output_path) if output_path else src.parent / f"sanitized_{src.name}"

        # Phase 1: Upload
        logger.info("Phase 1/3: Uploading %s …", src)
        upload_status = await self.upload_file(src, policy=policy)
        transfer_id = upload_status.transfer_id

        if not transfer_id:
            raise MisogiSanitizationError(
                "Server did not return a transfer ID after upload"
            )

        # Phase 2: Trigger transfer + poll for completion
        logger.info("Phase 2/3: Waiting for sanitization [transfer_id=%s] …", transfer_id)
        await self.trigger_transfer(transfer_id)

        final_status = upload_status
        for iteration in range(max_poll_iterations):
            final_status = await self.get_file_status(transfer_id)
            logger.debug(
                "Poll #%d: status=%s progress=%.1f%%",
                iteration + 1,
                final_status.status,
                final_status.progress_pct,
            )

            done_states = ("sanitized", "complete", "done", "ready")
            fail_states = ("failed", "error", "rejected")

            lower_status = final_status.status.lower()
            if any(s in lower_status for s in done_states):
                break
            if any(s in lower_status for s in fail_states):
                raise MisogiSanitizationError(
                    f"Server reports failure: {final_status.status}",
                    transfer_id=transfer_id,
                )

            await asyncio.sleep(poll_interval)
        else:
            raise MisogiSanitizationError(
                f"Sanitization timed out after {max_poll_iterations} polls "
                f"(last status: {final_status.status})",
                transfer_id=transfer_id,
            )

        # Phase 3: Download
        logger.info("Phase 3/3: Downloading sanitized file to %s …", dst)
        download_meta = await self.download_file(transfer_id, dst)

        return SanitizeResult(
            upload_status=final_status,
            download_metadata=download_meta,
            policy=policy,
            success=True,
        )


# Ensure asyncio is available for sanitize_file's sleep call.
import asyncio
