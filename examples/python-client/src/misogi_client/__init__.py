"""misogi_client — Async gRPC client for Misogi CDR sanitization engine.

This package provides a high-level, asyncio-native interface to the
Misogi gRPC services (SenderService / ReceiverService) defined in
``misogi.file_transfer.v1``.

Typical usage::

    async with MisogiAsyncClient("localhost", 50051) as client:
        result = await client.sanitize_file("document.pdf")
        print(result)
"""

__version__ = "0.1.0"
__author__ = "Misogi Contributors"

from misogi_client.client import MisogiAsyncClient
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

__all__ = [
    "MisogiAsyncClient",
    "SanitizationPolicy",
    "FileStatus",
    "DownloadMetadata",
    "SanitizeResult",
    "FileInfo",
    "MisogiConnectionError",
    "MisogiSanitizationError",
    "MisogiDownloadError",
    "__version__",
]
