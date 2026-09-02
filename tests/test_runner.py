"""Tests for the strace subprocess runner.

These are unit tests: strace itself is never spawned. Real-subprocess
coverage lives in ``tests/integration/test_end_to_end.py``.
"""

from __future__ import annotations

import signal
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest

from netaudit.runner import (
    _KILL_ON_EXIT,
    _SIGKILL,
    _TERMINATE_TIMEOUT,
    StraceNotFoundError,
    StraceProcess,
    StraceRunner,
    _strace_cmd,
    _supports_kill_on_exit,
)

_OUT = Path("/tmp/netaudit-test.log")
_GROUP_ID = 4242


@contextmanager
def _fake_process_groups(available: bool = True) -> Iterator[MagicMock]:
    """Intercept the real process-group calls.

    Without this the signalling path reaches the OS for real: ``MagicMock.pid``
    implements ``__index__`` and evaluates to 1, so ``os.getpgid`` returns
    init's group and ``os.killpg`` signals it. ``create=True`` keeps this usable
    on Windows, which has neither call.
    """
    with (
        patch("netaudit.runner._HAS_PROCESS_GROUPS", available),
        patch("netaudit.runner.os.getpgid", create=True, return_value=_GROUP_ID),
        patch("netaudit.runner.os.killpg", create=True) as killpg,
    ):
        yield killpg


def _interrupted_proc(*, ignores_sigterm: bool = False) -> MagicMock:
    """A strace process that raises KeyboardInterrupt out of communicate()."""
    proc = MagicMock()
    effects: list[object] = [KeyboardInterrupt()]
    if ignores_sigterm:
        effects.append(subprocess.TimeoutExpired(cmd="strace", timeout=_TERMINATE_TIMEOUT))
    effects.append((b"", b""))
    proc.communicate.side_effect = effects
    return proc


@pytest.fixture(autouse=True)
def unprobed_strace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer the ``--kill-on-exit`` probe without spawning anything.

    ``_strace_cmd`` probes lazily the first time it is called, so an unprimed
    cache would try to spawn a real strace from inside tests that have patched
    ``subprocess`` — and get a MagicMock back. :func:`_probe` puts the real
    function back for the tests that are about the probe itself.
    """
    monkeypatch.setattr("netaudit.runner._supports_kill_on_exit", lambda: False)


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

    def test_ends_the_flags_with_a_separator(self) -> None:
        assert _strace_cmd(_OUT)[-1] == "--"

    def test_a_command_starting_with_a_dash_is_not_read_as_an_strace_option(self) -> None:
        """Without the separator this second -o would win and empty the trace."""
        argv = _strace_cmd(_OUT) + ["-o", "/dev/null"]
        assert argv.index("--") < argv.index("-o", argv.index("--"))
        assert argv[argv.index("-o") + 1] == str(_OUT)


# ---------------------------------------------------------------------------
# --kill-on-exit — strace 5.2+, and strace has no documented minimum version
# ---------------------------------------------------------------------------


@contextmanager
def _probe(returncode: int = 0, error: Exception | None = None) -> Iterator[MagicMock]:
    """Answer the feature probe without a real strace, and leave no cache behind."""
    _supports_kill_on_exit.cache_clear()
    try:
        with (
            patch("netaudit.runner._supports_kill_on_exit", _supports_kill_on_exit),
            patch("netaudit.runner.subprocess.run") as run,
        ):
            if error is not None:
                run.side_effect = error
            else:
                run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=returncode, stdout=b"", stderr=b""
                )
            yield run
    finally:
        _supports_kill_on_exit.cache_clear()


class TestKillOnExit:
    def test_asks_the_kernel_to_take_the_tracees_down_with_strace(self) -> None:
        """SIGKILL cannot be handled, so nothing else can reach the traced process."""
        with _probe(returncode=0):
            assert _KILL_ON_EXIT in _strace_cmd(_OUT)

    def test_is_left_out_when_strace_is_too_old_to_know_it(self) -> None:
        """An unknown option makes strace refuse to start — the tool would break."""
        with _probe(returncode=1):
            assert _KILL_ON_EXIT not in _strace_cmd(_OUT)

    def test_is_left_out_when_the_probe_cannot_run_at_all(self) -> None:
        with _probe(error=FileNotFoundError("strace")):
            assert _KILL_ON_EXIT not in _strace_cmd(_OUT)

    def test_is_left_out_when_the_probe_hangs(self) -> None:
        with _probe(error=subprocess.TimeoutExpired(cmd="strace", timeout=5)):
            assert _KILL_ON_EXIT not in _strace_cmd(_OUT)

    def test_the_probe_traces_nothing_and_starts_nothing(self) -> None:
        with _probe(returncode=0) as run:
            _strace_cmd(_OUT)
        assert run.call_args.args[0] == ["strace", _KILL_ON_EXIT, "-V"]

    def test_the_probe_runs_once_however_many_commands_are_built(self) -> None:
        with _probe(returncode=0) as run:
            _strace_cmd(_OUT)
            _strace_cmd(_OUT)
            _strace_cmd(Path("/tmp/other.log"))
        assert run.call_count == 1


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
        with patch("netaudit.runner.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"", b"")
            runner.run(["echo", "hi"], _OUT)
        argv = popen.call_args.args[0]
        assert argv == _strace_cmd(_OUT) + ["echo", "hi"]

    def test_captures_output(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"out", b"err")
            result = runner.run(["echo", "hi"], _OUT)
        assert (result.stdout, result.stderr) == (b"out", b"err")

    def test_returns_the_completed_process(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            popen.return_value.communicate.return_value = (b"", b"")
            popen.return_value.returncode = 7
            assert runner.run(["false"], _OUT).returncode == 7

    def test_interrupt_signals_the_whole_traced_group(self) -> None:
        """The blocking API must not orphan what it traced either.

        Signalling strace alone leaves the command it traced running, holding
        the pipes this call is waiting on.
        """
        runner = _runner()
        with (
            patch("netaudit.runner.subprocess.Popen", return_value=_interrupted_proc()),
            _fake_process_groups() as killpg,
        ):
            with pytest.raises(KeyboardInterrupt):
                runner.run(["sleep", "30"], _OUT)
        assert killpg.call_args_list[0].args == (_GROUP_ID, signal.SIGTERM)


# ---------------------------------------------------------------------------
# start() — non-blocking
# ---------------------------------------------------------------------------


class TestStraceRunnerStart:
    def test_spawns_the_traced_command_in_its_own_session(self) -> None:
        """Own session, so stop() can signal strace and the command together."""
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            runner.start(["sleep", "1"], _OUT)
        assert popen.call_args.kwargs["start_new_session"] is True

    def test_spawns_the_traced_command_with_pipes(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            handle = runner.start(["sleep", "1"], _OUT)
        argv = popen.call_args.args[0]
        assert argv == _strace_cmd(_OUT) + ["sleep", "1"]
        assert popen.call_args.kwargs["stdout"] is subprocess.PIPE
        assert popen.call_args.kwargs["stderr"] is subprocess.PIPE
        assert isinstance(handle, StraceProcess)

    def test_rejects_an_empty_command(self) -> None:
        runner = _runner()
        with patch("netaudit.runner.subprocess.Popen") as popen:
            with pytest.raises(ValueError, match="no command"):
                runner.start([], _OUT)
        popen.assert_not_called()

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

    def test_interrupt_signals_the_whole_traced_group(self) -> None:
        """strace alone is not enough — the traced command shares its group."""
        proc = _interrupted_proc()
        with _fake_process_groups() as killpg:
            with pytest.raises(KeyboardInterrupt):
                StraceProcess(proc).stop()
        killpg.assert_called_once_with(_GROUP_ID, signal.SIGTERM)
        proc.terminate.assert_not_called()

    def test_interrupt_gives_the_group_a_grace_period(self) -> None:
        proc = _interrupted_proc()
        with _fake_process_groups():
            with pytest.raises(KeyboardInterrupt):
                StraceProcess(proc).stop()
        assert proc.communicate.call_args.kwargs["timeout"] == _TERMINATE_TIMEOUT

    def test_group_is_killed_when_it_ignores_sigterm(self) -> None:
        proc = _interrupted_proc(ignores_sigterm=True)
        with _fake_process_groups() as killpg:
            with pytest.raises(KeyboardInterrupt):
                StraceProcess(proc).stop()
        assert [c.args[1] for c in killpg.call_args_list] == [signal.SIGTERM, _SIGKILL]
        assert proc.communicate.call_count == 3, "must reap the group after SIGKILL"

    def test_falls_back_to_the_process_when_the_platform_has_no_groups(self) -> None:
        """Windows has no killpg — and no strace either, but the code must not crash."""
        proc = _interrupted_proc()
        with _fake_process_groups(available=False) as killpg:
            with pytest.raises(KeyboardInterrupt):
                StraceProcess(proc).stop()
        killpg.assert_not_called()
        proc.terminate.assert_called_once_with()
        proc.kill.assert_not_called()

    def test_falls_back_to_the_process_when_the_group_is_gone(self) -> None:
        proc = _interrupted_proc()
        with _fake_process_groups() as killpg:
            killpg.side_effect = ProcessLookupError()
            with pytest.raises(KeyboardInterrupt):
                StraceProcess(proc).stop()
        proc.terminate.assert_called_once_with()

    def test_falls_back_to_kill_when_the_group_is_gone(self) -> None:
        proc = _interrupted_proc(ignores_sigterm=True)
        with _fake_process_groups() as killpg:
            killpg.side_effect = ProcessLookupError()
            with pytest.raises(KeyboardInterrupt):
                StraceProcess(proc).stop()
        proc.terminate.assert_called_once_with()
        proc.kill.assert_called_once_with()

    def test_the_group_is_derived_from_the_strace_pid(self) -> None:
        proc = _interrupted_proc()
        proc.pid = 31337
        with _fake_process_groups() as killpg:
            with patch("netaudit.runner.os.getpgid", create=True) as getpgid:
                getpgid.return_value = _GROUP_ID
                with pytest.raises(KeyboardInterrupt):
                    StraceProcess(proc).stop()
        getpgid.assert_called_once_with(31337)
        killpg.assert_called_once_with(_GROUP_ID, signal.SIGTERM)
