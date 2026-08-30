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

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from netaudit import _tempfiles

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "linux", reason="needs procfs and strace"),
    pytest.mark.skipif(shutil.which("strace") is None, reason="strace not available"),
]

_STARTED = "started"


def _slow_test(seconds: float = 30) -> str:
    """A suite that announces it has started and then sits there.

    The default is long enough that the run cannot plausibly finish before the
    signal lands; the short form is for the case that has to run to completion.
    """
    return f"""
import pathlib
import time


def test_slow():
    pathlib.Path({_STARTED!r}).write_text("yes")
    time.sleep({seconds})
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
    """Every *running* process in process group *group*, via procfs.

    Zombies do not count: a killed process reparented to init stays in
    ``/proc`` until something reaps it, and nothing in this container does.
    It is dead, and reporting it as a survivor would be a false alarm.
    """
    members: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat[stat.rindex(")") + 2 :].split()
            state, pgid = fields[0], int(fields[2])
        except (OSError, ValueError, IndexError):
            continue
        if pgid == group and state not in ("Z", "X"):
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


@dataclass
class _Cancelled:
    returncode: int
    survivors: list[int]
    """Processes still in the run's group after it was signalled — measured
    before anything cleans up, or the assertion would be about the cleanup."""


def _cancel_with(
    sig: int,
    project: Path,
    temp_dir: Path,
    whole_group: bool = True,
    seconds: float = 30,
) -> _Cancelled:
    """Run a traced suite to steady state, signal it, and wait for it to end.

    *whole_group* is how every real cancellation arrives — CI runners kill the
    tree, ``timeout`` signals the group. Signalling the single pid instead hits
    only strace, which the re-exec turned this process into.
    """
    proc = _launch(_write_project(project, _slow_test(seconds)), temp_dir)
    try:
        _wait_for_steady_state(project)
        if whole_group:
            os.killpg(proc.pid, sig)
        else:
            os.kill(proc.pid, sig)
        proc.wait(timeout=60)
        # The group dies asynchronously; give its members a moment to be reaped.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _members_of(proc.pid):
            time.sleep(0.05)
        survivors = _members_of(proc.pid)
    finally:
        _reap(proc.pid)
    return _Cancelled(returncode=proc.returncode, survivors=survivors)


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
        cancelled = _cancel_with(signal.SIGTERM, tmp_path / "project", temp_dir)
        assert cancelled.returncode == -signal.SIGTERM

    def test_sigterm_leaves_nothing_running(self, tmp_path: Path) -> None:
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        cancelled = _cancel_with(signal.SIGTERM, tmp_path / "project", temp_dir)
        assert cancelled.survivors == []

    def test_sigkill_leaves_nothing_running(self, tmp_path: Path) -> None:
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        cancelled = _cancel_with(signal.SIGKILL, tmp_path / "project", temp_dir)
        assert cancelled.survivors == []


class TestSignallingStraceAlone:
    """The re-exec makes the top-level pid strace itself, so a signal aimed at
    "the pytest process" lands on strace and never on the suite."""

    def test_killing_strace_outright_takes_the_traced_suite_with_it(self, tmp_path: Path) -> None:
        """SIGKILL cannot be handled, so no cleanup this process could install
        would help: strace must have been asked up front to take its tracees
        down with it."""
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        cancelled = _cancel_with(signal.SIGKILL, tmp_path / "project", temp_dir, whole_group=False)
        assert cancelled.survivors == []

    def test_terminating_strace_alone_lets_the_suite_finish(self, tmp_path: Path) -> None:
        """A limitation, pinned so that changing it is a decision.

        strace detaches on SIGTERM rather than dying, which clears the kernel's
        kill-on-exit flag, so the suite it was tracing runs to completion —
        cleaning up after itself, but not cancelled. Every real cancellation
        signals the process group, which does reach the suite; this is the
        shape ``docker stop`` produces when pytest is PID 1.
        """
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        cancelled = _cancel_with(
            signal.SIGTERM, tmp_path / "project", temp_dir, whole_group=False, seconds=3
        )
        assert cancelled.returncode == 0
        assert cancelled.survivors == []
        assert _leftovers(temp_dir) == []

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


class TestInterruptDuringStartup:
    """There is a window, right after the re-exec, where nothing owns the files.

    strace creates the trace as it starts; the pytest it forks only adopts the
    files once its own ``pytest_configure`` runs, most of a second later. An
    interrupt in between kills both without either having cleaned up. Measured
    across the window, SIGINT to the process group:

        +0.00s   exit -2   leftovers 0            (files not created yet)
        +0.25s   exit -2   leftovers 2   0 B
        +0.50s   exit  1   leftovers 2   136 B
        +0.75s   exit -2   leftovers 2   232 B
        +1.00s   exit  2   leftovers 0            (adopted, cleaned up)

    Closing it would mean keeping a process of our own alive alongside strace,
    which is the design the plugin deliberately does not have — and the files
    at stake here are the ones strace has barely started writing. What is
    pinned instead is that nothing is left that the next run cannot recover,
    which is the same guarantee SIGKILL gets.

    (The interrupt is also sometimes swallowed outright in this window — exit 1
    and exit 2 above are runs that continued. strace blocks fatal signals while
    it sets up, and the option that changes that, ``-I1``, would also stop
    Ctrl-C at steady state from letting the suite report.)
    """

    @pytest.mark.parametrize("delay", [0.0, 0.25, 0.5, 0.75])
    def test_leaves_nothing_the_next_run_cannot_recover(self, tmp_path: Path, delay: float) -> None:
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        # Short, because the interrupt may be swallowed and the suite then has
        # to run to completion before this returns.
        proc = _launch(_write_project(tmp_path / "project", _slow_test(2)), temp_dir)
        time.sleep(delay)
        try:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGINT)
            proc.wait(timeout=120)
        finally:
            _reap(proc.pid)

        remaining = _leftovers(temp_dir)
        # max_age=0 is what the next run's sweep does once these have aged out:
        # the owning pid is gone, so nothing can be written to them again.
        assert sorted(_tempfiles.sweep_stale(directory=temp_dir, max_age=0)) == remaining
        assert _leftovers(temp_dir) == []


class TestCancellingTheCli:
    """``netaudit run`` has no re-exec: strace is a real child, so the CLI is
    still there to be signalled — and has to pass that on."""

    def _netaudit(self, temp_dir: Path, command: list[str]) -> subprocess.Popen[bytes]:
        binary = shutil.which("netaudit")
        if binary is None:  # pragma: no cover - the integration image installs it
            pytest.skip("netaudit console script not on PATH")
        env = {**os.environ, "TMPDIR": str(temp_dir)}
        return subprocess.Popen(
            [binary, "run", "--", *command],
            env=env,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _traced_processes(self) -> list[str]:
        """Live strace and sleep processes, whoever started them."""
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
                comm = stat[stat.index("(") + 1 : stat.rindex(")")]
                state = stat[stat.rindex(")") + 2 :].split()[0]
            except (OSError, ValueError):
                continue
            if comm in ("strace", "sleep") and state not in ("Z", "X"):
                found.append(f"{entry.name}:{comm}")
        return found

    def test_sigterm_stops_strace_and_the_command_it_traces(self, tmp_path: Path) -> None:
        """Signalling the CLI alone is what ``docker stop`` does to PID 1."""
        temp_dir = tmp_path / "tmp"
        temp_dir.mkdir()
        proc = self._netaudit(temp_dir, ["sleep", "45"])
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not self._traced_processes():
                time.sleep(0.05)
            assert self._traced_processes(), "premise broken: nothing was traced"

            os.kill(proc.pid, signal.SIGTERM)
            returncode = proc.wait(timeout=30)

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and self._traced_processes():
                time.sleep(0.1)
            assert self._traced_processes() == [], "the traced command outlived netaudit"
            assert returncode == 86, "a cancelled run has its own exit code"
            assert _leftovers(temp_dir) == []
        finally:
            _reap(proc.pid)
