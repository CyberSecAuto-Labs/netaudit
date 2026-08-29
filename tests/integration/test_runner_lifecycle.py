"""Integration tests for the non-blocking runner API — require strace (Linux only).

``StraceRunner.run()`` is exercised by the end-to-end tests; ``start()`` and
``StraceProcess.stop()`` are not, and their unit tests are entirely mock-based.
A mock can assert that ``terminate()`` was called; only a real child can show
that it actually died. Everything here checks a real process against ``/proc``.

Run with: pytest -m integration
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from netaudit import runner as runner_module
from netaudit.runner import StraceNotFoundError, StraceProcess, StraceRunner

pytestmark = pytest.mark.integration

# Long enough that the process cannot plausibly exit on its own mid-test.
_SLEEPER = [sys.executable, "-c", "import time; time.sleep(30)"]

# Windows has no SIGKILL and no strace; the constant only has to survive import
# there, since every test in this module needs a real strace to run at all.
_SIGKILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)


@pytest.fixture
def runner() -> StraceRunner:
    try:
        return StraceRunner()
    except StraceNotFoundError:
        pytest.skip("strace not available on this platform")


def _pid_of(process: StraceProcess) -> int:
    """The traced process's real pid.

    Reaching past the public API is deliberate: the point of these tests is to
    verify what happens to the OS process, which the public surface hides.
    """
    return process._proc.pid


def _is_alive(pid: int) -> bool:
    """Running, not merely present in ``/proc``.

    A killed process whose parent is gone is reparented to init and stays in
    ``/proc`` as a zombie until something reaps it — which, inside the test
    container, nothing does. Counting that as alive would report a dead tracee
    as a survivor.
    """
    return _state_of(pid) not in ("", "Z", "X")


def _state_of(pid: int) -> str:
    """The single-letter process state from procfs, or "" if the pid is gone."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return ""
    return stat[stat.rindex(")") + 2 :].split()[0]


def _children_of(pid: int) -> list[int]:
    """Direct children of *pid*, via procfs — i.e. the process strace traces."""
    children: list[int] = []
    task_dir = Path(f"/proc/{pid}/task")
    if not task_dir.exists():
        return children
    for task in task_dir.iterdir():
        listing = task / "children"
        if listing.exists():
            children.extend(int(p) for p in listing.read_text().split())
    return children


def _traced_pid(process: StraceProcess, timeout: float = 5.0) -> int:
    """Wait for strace to fork the command, and return that command's pid."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        children = _children_of(_pid_of(process))
        if children:
            return children[0]
        time.sleep(0.02)
    raise AssertionError("strace never spawned the traced command")


def _wait_until_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            return True
        time.sleep(0.02)
    return False


def _interrupt_self_after(delay: float) -> None:
    """Deliver SIGINT to this process, the way Ctrl-C would."""

    def _fire() -> None:
        time.sleep(delay)
        os.kill(os.getpid(), signal.SIGINT)

    threading.Thread(target=_fire, daemon=True).start()


# ---------------------------------------------------------------------------
# start() / stop() against a real process
# ---------------------------------------------------------------------------


class TestStartAndStop:
    def test_start_returns_before_the_command_finishes(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        started = time.monotonic()
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        elapsed = time.monotonic() - started
        try:
            assert elapsed < 5.0, "start() must not block for the traced command"
            assert _is_alive(_pid_of(process))
        finally:
            _interrupt_self_after(0.1)
            with pytest.raises(KeyboardInterrupt):
                process.stop()

    def test_stop_returns_the_commands_exit_code(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        process = runner.start([sys.executable, "-c", "raise SystemExit(7)"], tmp_path / "out.log")
        result = process.stop()
        assert result.returncode == 7

    def test_stop_captures_the_commands_stdout(self, runner: StraceRunner, tmp_path: Path) -> None:
        process = runner.start(
            [sys.executable, "-c", "print('hello from the traced process')"],
            tmp_path / "out.log",
        )
        result = process.stop()
        assert b"hello from the traced process" in result.stdout

    def test_stop_reaps_the_process(self, runner: StraceRunner, tmp_path: Path) -> None:
        process = runner.start([sys.executable, "-c", "pass"], tmp_path / "out.log")
        pid = _pid_of(process)
        process.stop()
        assert not _is_alive(pid), "a finished strace must not be left as a zombie"

    def test_traced_command_still_produces_a_trace(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        """start()/stop() must trace as thoroughly as the blocking run()."""
        out = tmp_path / "out.log"
        process = runner.start(
            [
                sys.executable,
                "-c",
                (
                    "import socket;s=socket.socket();s.settimeout(0.2);"
                    "\ntry:\n s.connect(('198.51.100.1',443))\nexcept OSError:\n pass"
                ),
            ],
            out,
        )
        process.stop()
        assert "connect(" in out.read_text()


# ---------------------------------------------------------------------------
# Interrupt handling — the sequence unit tests can only mock
# ---------------------------------------------------------------------------


class TestInterruptKillsTheChild:
    def test_interrupt_propagates_to_the_caller(self, runner: StraceRunner, tmp_path: Path) -> None:
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        _interrupt_self_after(0.3)
        with pytest.raises(KeyboardInterrupt):
            process.stop()

    def test_interrupt_actually_terminates_the_traced_process(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        """The mock test proves terminate() was called; this proves it worked."""
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        pid = _pid_of(process)
        assert _is_alive(pid)

        _interrupt_self_after(0.3)
        with pytest.raises(KeyboardInterrupt):
            process.stop()

        assert _wait_until_gone(pid), "traced process survived the interrupt"

    def test_interrupt_kills_the_command_being_traced(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        """Killing strace is not enough — the command it traced must die too.

        strace detaches on SIGTERM and exits, leaving the traced command
        running and still holding the inherited stdout/stderr pipes.
        """
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        traced = _traced_pid(process)

        _interrupt_self_after(0.3)
        with pytest.raises(KeyboardInterrupt):
            process.stop()

        assert _wait_until_gone(traced), "the traced command outlived the interrupt"

    def test_interrupt_does_not_wait_for_the_command(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        """A 30s sleeper must not hold Ctrl-C hostage for 30s."""
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        _interrupt_self_after(0.3)

        started = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            process.stop()
        assert time.monotonic() - started < 15.0

    def test_child_is_killed_when_it_outlives_the_grace_period(
        self, runner: StraceRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Force the SIGTERM -> timeout -> SIGKILL fallback with a real process.

        Shrinking the grace period rather than finding a process that ignores
        SIGTERM keeps the test fast and deterministic; the SIGKILL and the reap
        that follow it are real.
        """
        monkeypatch.setattr(runner_module, "_TERMINATE_TIMEOUT", 0.001)
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        pid = _pid_of(process)

        _interrupt_self_after(0.3)
        with pytest.raises(KeyboardInterrupt):
            process.stop()

        assert _wait_until_gone(pid), "traced process survived SIGKILL"


class TestStraceDyingOutright:
    def test_killing_strace_does_not_orphan_the_traced_command(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        """SIGKILL cannot be handled, so nothing in ``stop()`` runs.

        The process group fix from the interrupt path is unreachable here: by
        the time strace is gone there is no code of ours left to signal anyone.
        Only the kernel can take the tracee down, and only if strace asked it
        to up front.
        """
        process = runner.start(_SLEEPER, tmp_path / "out.log")
        traced = _traced_pid(process)

        os.kill(_pid_of(process), _SIGKILL_SIGNAL)
        try:
            assert _wait_until_gone(traced), "the traced command outlived strace"
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(traced, _SIGKILL_SIGNAL)
            process._proc.wait()


# ---------------------------------------------------------------------------
# strace missing
# ---------------------------------------------------------------------------


class TestStraceMissing:
    def test_constructor_raises_when_strace_is_not_on_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real which() lookup, against a real PATH that lacks strace."""
        monkeypatch.setenv("PATH", "")
        assert shutil.which("strace") is None
        with pytest.raises(StraceNotFoundError, match="strace not found on PATH"):
            StraceRunner()


# ---------------------------------------------------------------------------
# Sanity: the blocking API agrees with the non-blocking one
# ---------------------------------------------------------------------------


class TestBlockingAndNonBlockingAgree:
    def test_both_apis_report_the_same_exit_code(
        self, runner: StraceRunner, tmp_path: Path
    ) -> None:
        command = [sys.executable, "-c", "raise SystemExit(3)"]
        blocking: subprocess.CompletedProcess[bytes] = runner.run(
            command, tmp_path / "blocking.log"
        )
        non_blocking = runner.start(command, tmp_path / "non-blocking.log").stop()
        assert blocking.returncode == non_blocking.returncode == 3
