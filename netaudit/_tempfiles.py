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
import shutil
import signal
import stat
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
# which has no strace either. Shared with the CLI, which installs its own
# handler for the same set before this module chains onto it.
CANCEL_SIGNALS = tuple(
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
    _remove_own_directories()


def _remove_own_directories() -> None:
    """Remove the private directories the tracked files lived in, once empty.

    Derived from the tracked paths rather than remembered, because ``execvpe``
    throws away anything this module remembered: the process that made the
    directory is replaced by strace, and the pytest it forks is the one that
    cleans up. ``rmdir`` rather than a recursive delete — a directory with
    something else still in it is not one this module has finished with.
    """
    for parent in {path.parent for path in _TRACKED}:
        if not is_own_directory(parent):
            continue
        try:
            parent.rmdir()
        except OSError:
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
    for sig in CANCEL_SIGNALS:
        try:
            previous = signal.signal(sig, _on_cancel)
        except ValueError:
            # Not the main thread — the atexit path still applies.
            continue
        if previous is not _on_cancel:
            _PREVIOUS[sig] = previous


_OWN_DIRECTORY: Path | None = None


def own_directory() -> Path:
    """The private directory this process's temp files live in.

    ``mkdtemp`` makes it 0700, so nothing outside this uid can put an entry in
    it — which is what makes handing strace a *name* safe. :func:`create`
    closes its descriptor before strace reopens the path, and on a ``$TMPDIR``
    that is shared or not sticky (several CI runners point it at a
    group-writable job workspace) the name could otherwise be replaced with a
    symlink in that window, sending the trace to the link's target.

    One directory per process, holding both files, so a run that is killed
    outright leaves one thing behind rather than two.
    """
    global _OWN_DIRECTORY
    # Re-made rather than remembered blindly: a cleanup this process already
    # ran will have removed it, and a second run in the same process needs
    # somewhere to write. ``lstat`` rather than ``is_dir``, so a symlink left
    # at the remembered name is not mistaken for the directory it replaced.
    if _OWN_DIRECTORY is None or not _is_directory(_OWN_DIRECTORY):
        _OWN_DIRECTORY = Path(tempfile.mkdtemp(prefix=f"{PREFIX}{os.getpid()}-"))
    return _OWN_DIRECTORY


def _is_directory(path: Path) -> bool:
    """Whether *path* is a directory in its own right, not a link to one."""
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def create(suffix: str, directory: Path | None = None) -> Path:
    """Create an empty temp file whose lifetime this module owns.

    The descriptor is closed immediately: strace opens the path by name, and
    holding a second one only risks it outliving the process. What keeps that
    safe is the private directory, not the descriptor.
    """
    fd, name = tempfile.mkstemp(
        suffix=suffix,
        prefix=f"{PREFIX}{os.getpid()}-",
        dir=str(directory) if directory else str(own_directory()),
    )
    os.close(fd)
    path = Path(name)
    remove_on_cancel(path)
    return path


def owner_of(path: Path) -> str | None:
    """The pid stamped into *path*'s name, or None when there is none."""
    match = _OWNER_IN_NAME.match(path.name)
    return match.group(1) if match else None


def is_own_directory(path: Path) -> bool:
    """Whether *path* is a private run directory :func:`own_directory` made.

    The mode and owner are checked as well as the name. They do not separate
    this process from another of the same uid — nothing in POSIX does, and such
    a process could delete the trace directly rather than going through
    netaudit — but they do keep a directory belonging to somebody *else* on a
    shared temp dir out of reach.
    """
    return path.parent == Path(tempfile.gettempdir()) and _has_run_directory_shape(path)


def _has_run_directory_shape(path: Path) -> bool:
    """Name, mode and owner of a private run directory, wherever it sits."""
    if _OWNER_IN_NAME.match(path.name) is None:
        return False
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == os.getuid()
    )


def is_own_name(path: Path) -> bool:
    """Whether *path* is one :func:`create` could have produced.

    The trace and markers paths reach the pytest plugin through the
    environment, and it unlinks and appends to them. The plugin is registered
    globally via the ``pytest11`` entry point, so it loads in every pytest run
    on a machine where netaudit is installed — which makes an unchecked path
    from the environment an arbitrary-file delete triggered by a variable.
    Constraining the shape to this module's own names keeps the damage to
    files this module would have owned anyway.
    """
    if path.suffix not in _SUFFIXES or _OWNER_IN_NAME.match(path.name) is None:
        return False
    if not is_own_directory(path.parent):
        return False
    try:
        info = path.lstat()
    except OSError:
        return False
    # lstat rather than stat: a symlink is not a file this module created, and
    # a link count above one means the name is shared with something else.
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()


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


def _is_sweepable(path: Path, is_dir: bool) -> bool:
    """Whether *path* is a leftover of this module's and nothing else.

    The sweep deletes a whole directory tree, so what it accepts is kept
    narrow: a run directory of this uid, mode 0700, holding nothing but the
    trace and markers files that belong in one. A directory that merely shares
    the prefix — someone else's, or one with anything unexpected inside — is
    left where it is. Bare files are the layout that preceded the directory,
    and are still recovered.
    """
    if not is_dir:
        return path.suffix in _SUFFIXES and stat.S_ISREG(path.lstat().st_mode)
    if not _has_run_directory_shape(path):
        return False
    return all(
        child.suffix in _SUFFIXES
        and _OWNER_IN_NAME.match(child.name) is not None
        and stat.S_ISREG(child.lstat().st_mode)
        for child in path.iterdir()
    )


def _newest_mtime(path: Path, is_dir: bool) -> float:
    """The most recent mtime of *path* or of anything directly inside it.

    A run directory's own mtime stops moving once both files exist, while the
    trace inside it grows for the whole run. Taking the newest keeps a long,
    quiet suite from looking abandoned. ``lstat`` throughout: a symlink's own
    timestamp, never its target's.
    """
    newest = path.lstat().st_mtime
    if is_dir:
        for child in path.iterdir():
            newest = max(newest, child.lstat().st_mtime)
    return newest


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
    for path in sorted(root.glob(f"{PREFIX}*")):
        try:
            is_dir = _is_directory(path)
            if not _is_sweepable(path, is_dir):
                continue
            age = now - _newest_mtime(path, is_dir)
            if age <= max_age:
                continue
            if age <= abandoned_age and _owner_still_running(path):
                continue
            if is_dir:
                shutil.rmtree(path)
            else:
                path.unlink()
        except OSError:
            continue
        removed.append(path)
    return removed
