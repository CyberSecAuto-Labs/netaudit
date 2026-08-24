"""Tests for the strace subprocess runner.

These are unit tests: strace itself is never spawned. Real-subprocess
coverage lives in ``tests/integration/test_end_to_end.py``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netaudit.runner import (
    _TERMINATE_TIMEOUT,
    StraceNotFoundError,
    StraceProcess,
    StraceRunner,
    _strace_cmd,
)

_OUT = Path("/tmp/netaudit-test.log")


def _runner() -> StraceRunner:
    """Build a StraceRunner without requiring strace on PATH."""
    with patch("netaudit.runner.shutil.which", return_value="/usr/bin/strace"):
        return StraceRunner()


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestStraceCmd:
    def test_traces_connect_and_follows_forks(self) -> None:
        cmd = _strace_cmd(_OUT)
        assert cmd[0] == "strace"
        assert "-e" in cmd and "trace=connect" in cmd
        assert "-f" in cmd, "must follow forks to catch child processes"
        assert "-tt" in cmd, "timestamps are needed to correlate with markers"

    def test_writes_to_the_given_output_path(self) -> None:
        out = Path("/var/log/somewhere.log")
        cmd = _strace_cmd(out)
        assert cmd[cmd.index("-o") + 1] == str(out)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestStraceRunnerInit:
    def test_raises_when_strace_is_missing(self) -> None:
        with patch("netaudit.runner.shutil.which", return_value=None):
            with pytest.raises(StraceNotFoundError, match="strace not found on PATH"):
                StraceRunner()

    def test_succeeds_when_strace_is_present(self) -> None:
        with patch("netaudit.runner.shutil.which", return_value="/usr/bin/strace") as which:
            StraceRunner()
        which.assert_called_once_with("strace")


# ---------------------------------------------------------------------------
# run() — blocking
# ---------------------------------------------------------------------------


class TestStraceRunnerRun:
    def test_prefixes_the_command_with_strace_args(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.run") as run:
            runner.run(["echo", "hi"], _OUT)
        argv = run.call_args.args[0]
        assert argv == _strace_cmd(_OUT) + ["echo", "hi"]

    def test_captures_output(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.run") as run:
            runner.run(["echo", "hi"], _OUT)
        assert run.call_args.kwargs["capture_output"] is True

    def test_returns_the_completed_process(self) -> None:
        runner = _runner()
        expected = subprocess.CompletedProcess(
            args=["strace"], returncode=7, stdout=b"", stderr=b""
        )
        with patch("netaudit.runner.subprocess.run", return_value=expected):
            assert runner.run(["false"], _OUT) is expected


# ---------------------------------------------------------------------------
# start() — non-blocking
# ---------------------------------------------------------------------------


class TestStraceRunnerStart:
    def test_spawns_the_traced_command_with_pipes(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            handle = runner.start(["sleep", "1"], _OUT)
        argv = popen.call_args.args[0]
        assert argv == _strace_cmd(_OUT) + ["sleep", "1"]
        assert popen.call_args.kwargs["stdout"] is subprocess.PIPE
        assert popen.call_args.kwargs["stderr"] is subprocess.PIPE
        assert isinstance(handle, StraceProcess)

    def test_does_not_wait_for_the_process(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            runner.start(["sleep", "1"], _OUT)
        popen.return_value.communicate.assert_not_called()


# ---------------------------------------------------------------------------
# StraceProcess.stop()
# ---------------------------------------------------------------------------


class TestStraceProcessStop:
    def test_returns_streams_and_status_from_the_child(self) -> None:
        proc = MagicMock()
        proc.args = ["strace", "sleep", "1"]
        proc.returncode = 3
        proc.communicate.return_value = (b"out", b"err")

        result = StraceProcess(proc).stop()

        assert result.args == ["strace", "sleep", "1"]
        assert result.returncode == 3
        assert result.stdout == b"out"
        assert result.stderr == b"err"

    def test_interrupt_terminates_the_child_and_re_raises(self) -> None:
        proc = MagicMock()
        proc.communicate.side_effect = [KeyboardInterrupt(), (b"", b"")]

        with pytest.raises(KeyboardInterrupt):
            StraceProcess(proc).stop()

        proc.terminate.assert_called_once_with()
        proc.kill.assert_not_called()

    def test_interrupt_gives_the_child_a_grace_period(self) -> None:
        proc = MagicMock()
        proc.communicate.side_effect = [KeyboardInterrupt(), (b"", b"")]

        with pytest.raises(KeyboardInterrupt):
            StraceProcess(proc).stop()

        assert proc.communicate.call_args.kwargs["timeout"] == _TERMINATE_TIMEOUT

    def test_kills_the_child_when_it_ignores_sigterm(self) -> None:
        proc = MagicMock()
        proc.communicate.side_effect = [
            KeyboardInterrupt(),
            subprocess.TimeoutExpired(cmd="strace", timeout=_TERMINATE_TIMEOUT),
            (b"", b""),
        ]

        with pytest.raises(KeyboardInterrupt):
            StraceProcess(proc).stop()

        proc.terminate.assert_called_once_with()
        proc.kill.assert_called_once_with()
        assert proc.communicate.call_count == 3, "must reap the child after SIGKILL"
