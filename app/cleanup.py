"""Cleanup worker: ``python -m app.cleanup [--once] [--dry-run] [--interval SECONDS]``.

Without ``--once`` it loops forever, sweeping every ``CLEANUP_INTERVAL_SECONDS`` (the
docker-compose ``cleanup`` service runs it this way). With ``--once`` it sweeps a single
time and exits, which suits cron or a Kubernetes CronJob. SIGINT/SIGTERM stop the loop
between sweeps. A failed sweep is logged and retried next interval; with ``--once`` it
exits non-zero so the scheduler can alert.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys
from collections.abc import Sequence

import structlog

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.db.session import create_engine, create_sessionmaker
from app.services.cleanup import CleanupReport, CleanupService
from app.services.storage import ObjectStorage

log = structlog.get_logger(__name__)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m app.cleanup", description=__doc__)
    parser.add_argument("--once", action="store_true", help="sweep once and exit")
    parser.add_argument("--dry-run", action="store_true", help="only count what would go")
    parser.add_argument("--interval", type=int, default=None, help="seconds between sweeps")
    args = parser.parse_args(argv)
    if args.interval is not None and args.interval < 1:
        parser.error("--interval must be at least 1")
    return args


async def run(
    settings: Settings,
    *,
    once: bool,
    dry_run: bool = False,
    interval: int | None = None,
    stop: asyncio.Event | None = None,
    storage: ObjectStorage | None = None,
) -> int:
    """Run the worker; returns the process exit code."""
    engine = create_engine(settings)
    service = CleanupService(
        create_sessionmaker(engine), storage or ObjectStorage(settings), settings
    )
    stop = stop or asyncio.Event()
    delay = interval or settings.cleanup_interval_seconds
    try:
        while True:
            try:
                report: CleanupReport | None = await service.run_once(dry_run=dry_run)
            except Exception:
                log.exception("cleanup_failed")
                report = None
            if once:
                return 0 if report is not None else 1
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=delay)
            if stop.is_set():
                return 0
    finally:
        await engine.dispose()


async def _main(args: argparse.Namespace) -> int:
    settings = get_settings()
    configure_logging(settings.log_level, json=settings.environment == "production")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    return await run(
        settings, once=args.once, dry_run=args.dry_run, interval=args.interval, stop=stop
    )


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - process entry
    return asyncio.run(_main(parse_args(argv)))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
