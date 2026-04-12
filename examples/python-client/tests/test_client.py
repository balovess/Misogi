"""Unit tests for Misogi async gRPC client.

Covers model serialization, argument parsing, and basic client logic.
Integration tests requiring a live server are marked appropriately.
"""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from misogi_client.models import (
    DownloadMetadata,
    FileInfo,
    FileStatus,
    MisogiConnectionError,
    MisogiDownloadError,
    MisogiSanitizationError,
    SanitizationPolicy,
    SanitizeResult,
)


# =============================================================================
# Model Tests
# =============================================================================


class TestSanitizationPolicy:
    """Tests for SanitizationPolicy enum."""

    def test_strip_active_content_value(self) -> None:
        assert SanitizationPolicy.STRIP_ACTIVE_CONTENT.value == "STRIP_ACTIVE_CONTENT"

    def test_convert_to_flat_value(self) -> None:
        assert SanitizationPolicy.CONVERT_TO_FLAT.value == "CONVERT_TO_FLAT"

    def test_text_only_value(self) -> None:
        assert SanitizationPolicy.TEXT_ONLY.value == "TEXT_ONLY"

    def test_is_string_enum(self) -> None:
        assert isinstance(SanitizationPolicy.STRIP_ACTIVE_CONTENT, str)

    def test_all_policies_iterable(self) -> None:
        policies = list(SanitizationPolicy)
        assert len(policies) == 3


class TestFileStatus:
    """Tests for FileStatus dataclass."""

    def test_default_values(self) -> None:
        status = FileStatus()
        assert status.transfer_id == ""
        assert status.status == ""
        assert status.total_size == 0
        assert status.chunk_count == 0
        assert status.completed_chunks == 0

    def test_is_complete_when_all_done(self) -> None:
        status = FileStatus(chunk_count=10, completed_chunks=10)
        assert status.is_complete is True

    def test_is_complete_when_partial(self) -> None:
        status = FileStatus(chunk_count=10, completed_chunks=5)
        assert status.is_complete is False

    def test_is_complete_when_zero_chunks(self) -> None:
        status = FileStatus(chunk_count=0, completed_chunks=0)
        assert status.is_complete is False

    def test_progress_pct_full(self) -> None:
        status = FileStatus(chunk_count=10, completed_chunks=10)
        assert status.progress_pct == pytest.approx(100.0)

    def test_progress_pct_half(self) -> None:
        status = FileStatus(chunk_count=10, completed_chunks=5)
        assert status.progress_pct == pytest.approx(50.0)

    def test_progress_pct_zero(self) -> None:
        status = FileStatus(chunk_count=10, completed_chunks=0)
        assert status.progress_pct == pytest.approx(0.0)

    def test_progress_pct_no_chunks(self) -> None:
        status = FileStatus(chunk_count=0, completed_chunks=0)
        assert status.progress_pct == pytest.approx(0.0)

    def test_frozen_immutability(self) -> None:
        status = FileStatus(transfer_id="abc")
        with pytest.raises(AttributeError):
            status.transfer_id = "xyz"

    def test_with_realistic_data(self) -> None:
        status = FileStatus(
            transfer_id="tx-001",
            status="sanitized",
            filename="report.pdf",
            total_size=1_048_576,
            chunk_count=16,
            completed_chunks=16,
            created_at="2025-01-15T10:30:00Z",
        )
        assert status.transfer_id == "tx-001"
        assert status.filename == "report.pdf"
        assert status.is_complete is True


class TestDownloadMetadata:
    """Tests for DownloadMetadata dataclass."""

    def test_default_values(self) -> None:
        meta = DownloadMetadata()
        assert meta.bytes_written == 0
        assert meta.duration_seconds == pytest.approx(0.0)

    def test_with_data(self) -> None:
        meta = DownloadMetadata(
            transfer_id="tx-001",
            output_path=Path("/tmp/safe.pdf"),
            bytes_written=999_000,
            duration_seconds=2.5,
        )
        assert meta.bytes_written == 999_000
        assert meta.duration_seconds == pytest.approx(2.5)


class TestSanitizeResult:
    """Tests for SanitizeResult dataclass."""

    def test_default_failure(self) -> None:
        result = SanitizeResult()
        assert result.success is False

    def test_success_construction(self) -> None:
        result = SanitizeResult(success=True)
        assert result.success is True

    def test_combined_workflow_result(self) -> None:
        upload = FileStatus(transfer_id="t1", status="sanitized")
        dl = DownloadMetadata(bytes_written=50000)
        result = SanitizeResult(
            upload_status=upload,
            download_metadata=dl,
            policy=SanitizationPolicy.STRIP_ACTIVE_CONTENT,
            success=True,
            threat_summary="No active content detected.",
        )
        assert result.success is True
        assert result.upload_status.transfer_id == "t1"


class TestFileInfo:
    """Tests for FileInfo dataclass."""

    def test_defaults(self) -> None:
        info = FileInfo()
        assert info.file_id == ""
        assert info.size_bytes == 0

    def test_populated(self) -> None:
        info = FileInfo(
            file_id="f-42",
            filename="data.xlsx",
            size_bytes=2048,
            status="ready",
        )
        assert info.filename == "data.xlsx"
        assert info.size_bytes == 2048


# =============================================================================
# Exception Tests
# =============================================================================


class TestExceptions:
    """Tests for custom exception hierarchy."""

    def test_misogi_connection_error_message(self) -> None:
        err = MisogiConnectionError("cannot connect")
        assert "cannot connect" in str(err)

    def test_misogi_connection_error_with_host_port(self) -> None:
        err = MisogiConnectionError("timeout", host="192.168.1.1", port=50051)
        msg = str(err)
        assert "timeout" in msg
        assert "192.168.1.1" in msg
        assert "50051" in msg

    def test_misogi_sanitization_error_with_transfer_id(self) -> None:
        err = MisogiSanitizationError("policy violation", transfer_id="tx-99")
        msg = str(err)
        assert "policy violation" in msg
        assert "tx-99" in msg

    def test_misogi_sanitization_error_with_code(self) -> None:
        err = MisogiSanitizationError("bad format", code="ERR_FORMAT")
        assert "ERR_FORMAT" in str(err)

    def test_misogi_download_error_with_bytes(self) -> None:
        err = MisogiDownloadError("stream broken", transfer_id="tx-1", bytes_received=4096)
        msg = str(err)
        assert "stream broken" in msg
        assert "4096" in msg

    def test_exception_hierarchy(self) -> None:
        from misogi_client.models import MisogiError

        assert issubclass(MisogiConnectionError, MisogiError)
        assert issubclass(MisogiSanitizationError, MisogiError)
        assert issubclass(MisogiDownloadError, MisogiError)


# =============================================================================
# CLI Argument Parsing Tests
# =============================================================================


class TestCliArgParsing:
    """Tests for CLI argument parser construction."""

    @pytest.fixture
    def parser(self):
        from misogi_client.cli import build_parser
        return build_parser()

    def test_positional_file_required(self, parser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_defaults(self, parser) -> None:
        args = parser.parse_args(["test.pdf"])
        assert args.file_path == "test.pdf"
        assert args.policy == "STRIP"
        assert args.host == "localhost"
        assert args.port == 50051
        assert args.chunk_size == 65536
        assert args.verbose is False
        assert args.no_color is False
        assert args.output is None

    def test_policy_choices(self, parser) -> None:
        for choice in ["STRIP", "FLAT", "TEXT"]:
            args = parser.parse_args(["f.pdf", "--policy", choice])
            assert args.policy == choice

    def test_invalid_policy_rejected(self, parser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["f.pdf", "--policy", "INVALID"])

    def test_all_flags(self, parser) -> None:
        args = parser.parse_args([
            "doc.pdf",
            "--policy", "TEXT",
            "--output", "/out/safe.pdf",
            "--host", "10.0.0.1",
            "--port", "50053",
            "--chunk-size", "131072",
            "--verbose",
            "--no-color",
        ])
        assert args.policy == "TEXT"
        assert args.output == "/out/safe.pdf"
        assert args.host == "10.0.0.1"
        assert args.port == 50053
        assert args.chunk_size == 131072
        assert args.verbose is True
        assert args.no_color is True

    def test_version_flag(self, parser) -> None:
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


# =============================================================================
# Policy Mapping Tests
# =============================================================================


class TestPolicyMapping:
    """Tests for CLI-to-model policy mapping utility."""

    def test_map_strip(self) -> None:
        from misogi_client.cli import _map_policy
        assert _map_policy("STRIP") == SanitizationPolicy.STRIP_ACTIVE_CONTENT

    def test_map_flat(self) -> None:
        from misogi_client.cli import _map_policy
        assert _map_policy("FLAT") == SanitizationPolicy.CONVERT_TO_FLAT

    def test_map_text(self) -> None:
        from misogi_client.cli import _map_policy
        assert _map_policy("TEXT") == SanitizationPolicy.TEXT_ONLY


# =============================================================================
# Mock gRPC Channel Tests (unit-level, no server required)
# =============================================================================


class TestClientConstruction:
    """Unit tests for client initialization that do NOT require a live server."""

    def test_default_params(self) -> None:
        from misogi_client.client import MisogiAsyncClient
        client = MisogiAsyncClient()
        assert client.host == "localhost"
        assert client.port == 50051
        assert client.receiver_host == "localhost"
        assert client.receiver_port == 50052

    def test_custom_receiver_port(self) -> None:
        from misogi_client.client import MisogiAsyncClient
        client = MisogiAsyncClient(port=50051, receiver_port=50099)
        assert client.receiver_port == 50099

    def test_stub_not_initialized_before_enter(self) -> None:
        from misogi_client.client import MisogiAsyncClient
        client = MisogiAsyncClient()
        assert client._sender_stub is None
        assert client._receiver_stub is None

    def test_require_sender_raises_without_context(self) -> None:
        from misogi_client.client import MisogiAsyncClient
        client = MisogiAsyncClient()
        with pytest.raises(MisogiConnectionError, match="not initialized"):
            client._require_sender()

    def test_require_receiver_raises_without_context(self) -> None:
        from misogi_client.client import MisogiAsyncClient
        client = MisogiAsyncClient()
        with pytest.raises(MisogiConnectionError, match="not initialized"):
            client._require_receiver()


class TestColorStatusHelper:
    """Tests for the _color_status CLI helper function."""

    def test_success_status_green(self) -> None:
        from misogi_client.cli import _color_status
        result = _color_status("sanitized")
        assert "[green bold]" in result
        assert "sanitized" in result

    def test_error_status_red(self) -> None:
        from misogi_client.cli import _color_status
        result = _color_status("failed")
        assert "[red bold]" in result

    def test_processing_status_yellow(self) -> None:
        from misogi_client.cli import _color_status
        result = _color_status("processing")
        assert "[yellow]" in result

    def test_unknown_status_plain(self) -> None:
        from misogi_client.cli import _color_status
        result = _color_status("weird_state")
        assert result == "weird_state"
