"""Command-line interface for Misogi async sanitization client.

Provides ``misogi-sanitize`` entry point with rich terminal output,
progress bars, color-coded results, and proper exit codes.

Exit codes:
    0 — Success (file sanitized cleanly)
    1 — Sanitization error (server-side failure, threats found, etc.)
    2 — Connection error (cannot reach Misogi services)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table
from rich.text import Text

from misogi_client import __version__, MisogiAsyncClient, SanitizationPolicy
from misogi_client.models import (
    FileStatus,
    MisogiConnectionError,
    MisogiDownloadError,
    MisogiSanitizationError,
)

# Exit codes per specification.
EXIT_SUCCESS: int = 0
EXIT_SANITIZATION_ERROR: int = 1
EXIT_CONNECTION_ERROR: int = 2


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with all supported options.

    Returns:
        Configured :class:`ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        prog="misogi-sanitize",
        description=(
            "Misogi CDR File Sanitization Client — "
            "sanitize files via async gRPC"
        ),
        epilog="Example: python -m misogi_client.cli document.pdf --policy STRIP",
    )

    parser.add_argument(
        "file_path",
        type=str,
        help="Path to the file to sanitize",
    )
    parser.add_argument(
        "--policy",
        choices=["STRIP", "FLAT", "TEXT"],
        default="STRIP",
        help="Sanitization policy (default: STRIP)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: sanitized_<original>)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="Misogi sender gRPC host (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=50051,
        help="Misogi sender gRPC port (default: 50051)",
    )
    parser.add_argument(
        "--receiver-port",
        type=int,
        default=None,
        help="Misogi receiver gRPC port (default: sender_port + 1)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=64 * 1024,
        help="Upload chunk size in bytes (default: 65536)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress and debug info",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def _map_policy(arg: str) -> SanitizationPolicy:
    """Map CLI shorthand to :class:`SanitizationPolicy` enum value."""
    mapping = {
        "STRIP": SanitizationPolicy.STRIP_ACTIVE_CONTENT,
        "FLAT": SanitizationPolicy.CONVERT_TO_FLAT,
        "TEXT": SanitizationPolicy.TEXT_ONLY,
    }
    return mapping[arg]


async def run_sanitize(args: argparse.Namespace) -> int:
    """Execute the sanitization workflow using parsed CLI arguments.

    Args:
        args: Parsed command-line arguments from :func:`build_parser`.

    Returns:
        Exit code (``0`` = success, ``1`` = sanitization error,
        ``2`` = connection error).
    """
    console = Console(color_system=None if args.no_color else "auto")
    file_path = Path(args.file_path)
    policy = _map_policy(args.policy)

    # ---- Header panel ----
    console.print(
        Panel(
            f"[bold cyan]Misogi CDR Sanitizer[/] v{__version__}\n"
            f"Target : [yellow]{args.host}:{args.port}[/]\n"
            f"Policy : [green]{policy.value}[/]",
            title="[bold white]Misogi[/]",
            border_style="cyan",
        )
    )

    if not file_path.exists():
        console.print(f"[red]ERROR:[/] File not found: {file_path}")
        return EXIT_SANITIZATION_ERROR

    file_size = file_path.stat().st_size
    console.print(f"  Input  : [bold]{file_path}[/] ({file_size:,} bytes)")

    # ---- Rich progress bar during upload ----
    upload_progress = Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    )

    def make_upload_callback(progress_obj: Progress, task_id: str):
        """Return a progress callback closure for the upload phase."""

        def callback(sent: int, total: int) -> None:
            progress_obj.update(task_id, completed=sent, total=total)

        return callback

    download_progress = Progress(
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=40),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    )

    def make_download_callback(progress_obj: Progress, task_id: str):
        """Return a progress callback closure for the download phase."""

        def callback(received: int, total: int) -> None:
            progress_obj.update(task_id, completed=received, total=total)

        return callback

    try:
        with upload_progress:
            upload_task = upload_progress.add_task("Uploading …", total=file_size)
            upload_cb = make_upload_callback(upload_progress, upload_task)

            with download_progress:
                dl_task = download_progress.add_task("Downloading …")
                dl_cb = make_download_callback(download_progress, dl_task)

                async with MisogiAsyncClient(
                    host=args.host,
                    port=args.port,
                    receiver_port=args.receiver_port,
                ) as client:
                    result = await client.sanitize_file(
                        input_path=file_path,
                        output_path=args.output,
                        policy=policy,
                        progress_callback=upload_cb,
                    )

                    # Override download callback via direct call for now;
                    # sanitize_file's internal download doesn't expose cb.
                    # We show the result table instead.

    except MisogiConnectionError as exc:
        console.print(f"\n[red bold]CONNECTION ERROR[/]: {exc}")
        return EXIT_CONNECTION_ERROR

    except MisogiSanitizationError as exc:
        console.print(f"\n[red bold]SANITIZATION ERROR[/]: {exc}")
        return EXIT_SANITIZATION_ERROR

    except MisogiDownloadError as exc:
        console.print(f"\n[red bold]DOWNLOAD ERROR[/]: {exc}")
        return EXIT_SANITIZATION_ERROR

    except FileNotFoundError as exc:
        console.print(f"\n[red bold]FILE ERROR[/]: {exc}")
        return EXIT_SANITIZATION_ERROR

    # ---- Result display ----
    _display_result(console, result, args.verbose)
    return EXIT_SUCCESS if result.success else EXIT_SANITIZATION_ERROR


def _display_result(console: Console, result, verbose: bool) -> None:
    """Render the sanitization result using rich components.

    Args:
        console: Rich console instance.
        result: :class:`SanitizeResult` from the workflow.
        verbose: Whether to show extended details.
    """
    status = result.upload_status
    dl = result.download_metadata

    # Status table
    table = Table(title="Sanitization Result", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="dim")
    table.add_column("Value")

    transfer_id_display = status.transfer_id or "(none)"
    table.add_row("Transfer ID", f"[cyan]{transfer_id_display}[/]")
    table.add_row("Status", _color_status(status.status))
    table.add_row("Policy", f"[green]{result.policy.value}[/]")
    table.add_row("Output", f"[bold]{dl.output_path}[/]" if str(dl.output_path) else "—")
    table.add_row("Size Written", f"{dl.bytes_written:,} bytes")
    table.add_row("Duration", f"{dl.duration_seconds:.2f}s")

    console.print()
    console.print(table)

    # Threat summary panel (if available)
    if result.threat_summary or verbose:
        summary_text = result.threat_summary or "No threat details reported."
        console.print(
            Panel(
                summary_text,
                title="[bold yellow]Threat Summary[/]",
                border_style="yellow" if result.threat_summary else "dim",
            )
        )

    # Success / failure banner
    if result.success:
        console.print("\n[bold green on black]✓ Sanitization completed successfully.[/]")
    else:
        console.print("\n[bold red on black]✗ Sanitization failed.[/]")


def _color_status(status_str: str) -> str:
    """Return a rich-marked-up status string with appropriate color.

    Args:
        status_str: Raw status string from server.

    Returns:
        Rich-formatted string with color tags.
    """
    lower = status_str.lower()
    if any(s in lower for s in ("sanitized", "complete", "done", "ready")):
        return f"[green bold]{status_str}[/]"
    if any(s in lower for s in ("failed", "error", "rejected")):
        return f"[red bold]{status_str}[/]"
    if any(s in lower for s in ("processing", "pending", "uploading")):
        return f"[yellow]{status_str}[/]"
    return status_str


def main() -> None:
    """Entry point for the ``misogi-sanitize`` CLI command."""
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        exit_code = asyncio.run(run_sanitize(args))
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        exit_code = 130

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
