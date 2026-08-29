"""Integration tests for cancelled runs — require strace (Linux only).

Everything here fires a real signal at a real traced pytest run and looks at
what the OS is left holding. The unit tests can prove the handler unlinks the
files it was given; only a real SIGTERM can prove the handler is reached at all,
and nothing but a real SIGKILL can show what survives when it is not.

Measured before the fix, killing the whole process group at steady state:

    SIGINT    exit 2     survivors none     leaked 0
    SIGTERM   exit -15   survivors none     leaked 2 files
    SIGKILL   exit -9    survivors python   leaked 2 files

The trace file is strace's live output, so it grows with the run: a cancelled
8-second suite leaked 24 MB. SIGTERM is what CI cancellation, ``docker stop``
and ``timeout`` all send.

Run with: pytest -m integration
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "linux", reason="needs procfs and strace"),
    pytest.mark.skipif(shutil.which("strace") is None, reason="strace not available"),
]

_STARTED = "started"

# Long enough that the run cannot plausibly finish before the signal lands.
_SLOW_TEST = f"""
import pathlib
import time


def test_slow():
    pathlib.Path({_STARTED!r}).write_text("yes")
    time.sleep(30)
"""

_FAST_TEST = """
def test_fast():
    assert True
"""


def _write_project(root: Path, body: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "test_sample.py").write_text(body)
    return root


def _launch(project: Path, temp_dir: Path) -> subprocess.Popen[bytes]:
    """Start a traced pytest run in a session of its own, with a private tmpdir.

    The private ``TMPDIR`` is what makes the leak assertions exact: every
    ``netaudit-*`` file in it belongs to this run and no other.
    """
    env = {
        **os.environ,
        "TMPDIR": str(temp_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return subprocess.Popen(
        [sys.executable, "-m", "pytest", "--netaudit", "-p", "no:cacheprovider", "-q"],
        cwd=project,
        env=env,
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_for_steady_state(project: Path, timeout: float = 60.0) -> None:
    """Block until the traced suite is actually running a test."""
    deadline = time.monotonic() + timeout
    marker = project / _STARTED
    while time.monotonic() < deadline:
        if marker.exists():
            return
        time.sleep(0.05)
    raise AssertionError("the traced run never reached its first test")


def _members_of(group: int) -> list[int]:
    """Every live process in process group *group*, via procfs."""
    members: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat[stat.rindex(")") + 2 :].split()
            pgid = int(fields[2])
        except (OSError, ValueError, IndexError):
            continue
        if pgid == group:
            members.append(int(entry.name))
    return members


def _leftovers(temp_dir: Path) -> list[Path]:
    return sorted(temp_dir.glob("netaudit-*"))


def _reap(group: int) -> None:
    """Leave nothing running behind, whatever the test proved."""
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _cancel_with(sig: int, project: Path, temp_dir: Path) -> subprocess.Popen[bytes]:
    """Run a traced suite to steady state, signal its whole group, and wait."""
    proc = _launch(_write_project(project, _SLOW_TEST), temp_dir)
    try:
        _wait_for_steady_state(project)
        os.killpg(proc.pid, sig)
        proc.wait(timeout=30)
    finally:
        _reap(proc.pid)
    # The group dies asynchronously; give the members a moment to be reaped.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and _members_of(proc.pid):
        time.sleep(0.05)
    return proc


class TestCancellationCleansUp:
    def test_sigterm_leaves_no_temp_files(self, tmp_path: Path) -> None:
        """SIGTERM is what CI cancellation and ``docker stop`` send."""
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        _cancel_with(signal.SIGTERM, tmp_path / "project", temp_dir)
        assert _leftovers(temp_dir) == []

    def test_sigterm_still_reports_dying_from_the_signal(self, tmp_path: Path) -> None:
        """Cleaning up must not disguise the cancellation as a normal exit."""
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        proc = _cancel_with(signal.SIGTERM, tmp_path / "project", temp_dir)
        assert proc.returncode == -signal.SIGTERM

    def test_sigterm_leaves_nothing_running(self, tmp_path: Path) -> None:
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        proc = _cancel_with(signal.SIGTERM, tmp_path / "project", temp_dir)
        assert _members_of(proc.pid) == []

    def test_sigint_leaves_no_temp_files(self, tmp_path: Path) -> None:
        """Ctrl-C unwinds through sessionfinish; this pins that it stays that way."""
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        _cancel_with(signal.SIGINT, tmp_path / "project", temp_dir)
        assert _leftovers(temp_dir) == []


class TestSigkillIsRecoveredByTheNextRun:
    def test_the_next_run_sweeps_what_sigkill_left_behind(self, tmp_path: Path) -> None:
        """SIGKILL cannot clean up after itself — the sweep is the only recovery."""
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        _cancel_with(signal.SIGKILL, tmp_path / "project", temp_dir)

        leaked = _leftovers(temp_dir)
        assert leaked, "premise broken: SIGKILL is supposed to leak the temp files"
        stale = time.time() - 48 * 3600
        for path in leaked:
            os.utime(path, (stale, stale))

        second = _launch(_write_project(tmp_path / "project2", _FAST_TEST), temp_dir)
        try:
            second.wait(timeout=120)
        finally:
            _reap(second.pid)

        assert not [p for p in leaked if p.exists()], "the next run did not sweep the leftovers"

    def test_the_sweep_spares_files_from_a_run_that_may_still_be_going(
        self, tmp_path: Path
    ) -> None:
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        recent = temp_dir / "netaudit-someone-elses.strace"
        recent.write_text("a concurrent run's trace")

        run = _launch(_write_project(tmp_path / "project", _FAST_TEST), temp_dir)
        try:
            run.wait(timeout=120)
        finally:
            _reap(run.pid)

        assert recent.exists()
