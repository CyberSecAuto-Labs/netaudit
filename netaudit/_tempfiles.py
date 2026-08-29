"""Temp-file lifetime for traced runs — cleanup on cancellation, sweep of leftovers.

A traced run writes strace output (and, under pytest, a markers sidecar) to a
temp file that is only removed once the run finishes. Anything that stops the
process short leaves both behind, and the trace file grows with the run —
a cancelled 8-second suite leaked 24 MB. SIGTERM is what CI cancellation,
``docker stop`` and ``timeout`` all send, so this accumulates silently.

Two defences, because no single one covers every ending:

===========  ==========================================================
Ending       Covered by
===========  ==========================================================
normal exit  the caller's own ``finally``, plus :func:`remove_tracked`
             registered with ``atexit``
SIGINT       ``atexit`` — the interpreter raises KeyboardInterrupt and
             unwinds, so the files are still parsed before removal
SIGTERM      :func:`_on_cancel`, which unlinks and then re-raises
SIGKILL      nothing, by definition — :func:`sweep_stale` on the next
             run is the only thing that can recover it
===========  ==========================================================

SIGINT deliberately has no handler: removing the trace the moment Ctrl-C
arrives would destroy the evidence the run is about to report on, and it needs
no handler — the measured leak for SIGINT is already zero.
"""

from __future__ import annotations

import atexit
import os
import re
import signal
import tempfile
import time
from pathlib import Path
from types import FrameType
from typing import Any

PREFIX = "netaudit-"
"""Filename prefix, so :func:`sweep_stale` can recognise its own leftovers."""

_SUFFIXES = (".strace", ".markers")

# The pid of the process that created the file, stamped into its name. For both
# entry points that process lives exactly as long as the file is useful — the
# CLI, or the one that became strace — so its death is what makes the file
# garbage. Age cannot tell a leftover from a long, quiet run.
_OWNER_IN_NAME = re.compile(rf"^{PREFIX}(\d+)-")

# Nothing younger than this is touched at all: it may belong to a run that is
# still going, and deleting a live trace silently disables its auditing.
_STALE_AGE_SECONDS = 24 * 60 * 60

# Past this, the file goes even if its recorded pid is still in use — pids are
# reused, and a week-old trace is not a running test suite. Without it a single
# unlucky reuse would keep a multi-megabyte file forever.
_ABANDONED_AGE_SECONDS = 7 * 24 * 60 * 60

# ``os.kill(pid, 0)`` is a liveness probe on POSIX and a *termination* on
# Windows, which has no strace and therefore none of these files either.
_CAN_PROBE_PIDS = os.name == "posix"

# Signals that end the process without unwinding. SIGHUP is absent on Windows,
# which has no strace either — the tuple is empty there and everything below
# degrades to the atexit path.
_CANCEL_SIGNALS = tuple(
    sig for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGHUP", None)) if sig
)

_TRACKED: set[Path] = set()
_PREVIOUS: dict[int, Any] = {}


def remove_tracked() -> None:
    """Unlink every registered temp file. Best-effort: never raises."""
    for path in list(_TRACKED):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # A cleanup failure must not mask whatever is actually ending the run.
            pass


def _on_cancel(signum: int, frame: FrameType | None) -> None:
    """Unlink the temp files, then let the signal do what it was going to do.

    The handler this one replaced is re-invoked rather than discarded — under
    ``coverage``'s ``sigterm = true`` that handler is what writes the coverage
    data out. With no predecessor, the default disposition is restored and the
    signal re-sent, so the process still reports dying from it.
    """
    remove_tracked()
    previous = _PREVIOUS.get(signum, signal.SIG_DFL)
    if callable(previous):
        previous(signum, frame)
        return
    signal.signal(signum, previous)
    os.kill(os.getpid(), signum)


def remove_on_cancel(*paths: Path) -> None:
    """Register *paths* for removal on normal exit and on a cancelling signal."""
    if not _TRACKED:
        atexit.register(remove_tracked)
    _TRACKED.update(paths)
    for sig in _CANCEL_SIGNALS:
        try:
            previous = signal.signal(sig, _on_cancel)
        except ValueError:
            # Not the main thread — the atexit path still applies.
            continue
        if previous is not _on_cancel:
            _PREVIOUS[sig] = previous


def create(suffix: str, directory: Path | None = None) -> Path:
    """Create an empty temp file whose lifetime this module owns.

    The descriptor is closed immediately: strace opens the path by name, and
    holding a second one only risks it outliving the process.
    """
    fd, name = tempfile.mkstemp(
        suffix=suffix,
        prefix=f"{PREFIX}{os.getpid()}-",
        dir=str(directory) if directory else None,
    )
    os.close(fd)
    path = Path(name)
    remove_on_cancel(path)
    return path


def _owner_still_running(path: Path) -> bool:
    """Whether the process that created *path* is still alive.

    False for a name with no pid in it, and on platforms where the probe is not
    safe — both fall back to the age threshold alone.
    """
    match = _OWNER_IN_NAME.match(path.name)
    if match is None or not _CAN_PROBE_PIDS:
        return False
    try:
        os.kill(int(match.group(1)), 0)
    except ProcessLookupError:
        return False
    except OSError:
        # Another user's process: it exists, we simply may not signal it.
        return True
    return True


def sweep_stale(
    directory: Path | None = None,
    max_age: float = _STALE_AGE_SECONDS,
    abandoned_age: float = _ABANDONED_AGE_SECONDS,
) -> list[Path]:
    """Delete leftover netaudit temp files older than *max_age* seconds.

    The only recovery from a SIGKILLed run, which cannot clean up after itself.
    Deleting a live run's trace would silently disable its auditing, so a file
    is only removed once it is older than *max_age* **and** its owning process
    is gone — or, past *abandoned_age*, whatever now holds that pid.

    Returns the paths removed; best-effort, so a file that vanishes underneath
    the sweep — another run doing the same thing — is not an error.
    """
    root = directory if directory is not None else Path(tempfile.gettempdir())
    now = time.time()
    removed: list[Path] = []
    for suffix in _SUFFIXES:
        for path in sorted(root.glob(f"{PREFIX}*{suffix}")):
            try:
                age = now - path.stat().st_mtime
                if age <= max_age:
                    continue
                if age <= abandoned_age and _owner_still_running(path):
                    continue
                path.unlink()
            except OSError:
                continue
            removed.append(path)
    return removed
