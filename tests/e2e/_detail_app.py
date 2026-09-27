"""E2E app whose seeded status evidence is not changed by the scheduler."""

from cert_watch.scheduler import Scheduler


def _no_start(self: Scheduler) -> None:
    return None


def _no_stop(self: Scheduler, timeout: float | None = None) -> bool:
    return True


Scheduler.start = _no_start
Scheduler.stop = _no_stop

from cert_watch.app import create_app  # noqa: E402

app = create_app()
