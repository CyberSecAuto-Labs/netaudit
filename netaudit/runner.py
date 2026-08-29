"""strace subprocess runner — spawns a command under strace and captures output."""

from __future__ import annotations

import functools
import os
import shutil
import signal
import subprocess
from pathlib import Path

__all__ = ["StraceNotFoundError", "StraceProcess", "StraceRunner"]

_TERMINATE_TIMEOUT = 5  # seconds to wait for graceful shutdown before SIGKILL

# Signalling the process group is what reaches the traced command; without it
# only strace dies. Windows has neither call, and no strace either.
_HAS_PROCESS_GROUPS = hasattr(os, "killpg") and hasattr(os, "getpgid")
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)

# Asks the kernel to take the tracees down whenever strace goes away, however
# it goes away. This is the only thing that reaches a SIGKILLed strace, which
# by definition runs no cleanup of its own — killpg from stop() cannot help.
_KILL_ON_EXIT = "--kill-on-exit"

# Long enough for a loaded machine to start a process that only prints a version.
_PROBE_TIMEOUT = 5


class StraceNotFoundError(RuntimeError):
    """Raised when strace is not available on PATH."""


@functools.lru_cache(maxsize=1)
def _supports_kill_on_exit() -> bool:
    """Whether the strace on PATH understands ``--kill-on-exit`` (5.2+).

    strace is a documented system dependency with no minimum version, and an
    option it does not recognise makes it refuse to start — so the flag has to
    be probed rather than assumed. ``-V`` parses the options and prints the
    version, so the probe traces nothing and starts nothing; it is cached
    because the answer cannot change while the process runs.
    """
    try:
        probe = subprocess.run(
            ["strace", _KILL_ON_EXIT, "-V"],
            capture_output=True,
            timeout=_PROBE_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def _strace_cmd(output_path: Path) -> list[str]:
    cmd = ["strace", "-e", "trace=connect", "-f", "-tt", "-o", str(output_path)]
    if _supports_kill_on_exit():
        cmd.insert(1, _KILL_ON_EXIT)
    return cmd


class StraceProcess:
    """Handle to a running strace-wrapped process."""

    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self._proc = proc

    def _signal_group(self, sig: int) -> bool:
        """Signal strace and the command it traces; False if that is not possible.

        :meth:`StraceRunner.start` puts the pair in a session of their own, so
        one ``killpg`` reaches both. Returns False when the platform has no
        process groups, or the group is already gone, so the caller can fall
        back to signalling strace alone.
        """
        if not _HAS_PROCESS_GROUPS:
            return False
        try:
            os.killpg(os.getpgid(self._proc.pid), sig)
        except OSError:
            return False
        return True

    def _terminate(self) -> None:
        if not self._signal_group(signal.SIGTERM):
            self._proc.terminate()

    def _kill(self) -> None:
        if not self._signal_group(_SIGKILL):
            self._proc.kill()

    def stop(self) -> subprocess.CompletedProcess[bytes]:
        """Wait for the process to finish and return a CompletedProcess.

        On ``KeyboardInterrupt`` (Ctrl-C) the traced command and strace are both
        sent SIGTERM and given ``_TERMINATE_TIMEOUT`` seconds to exit before
        being forcibly killed. The interrupt is re-raised after cleanup so the
        caller can propagate it.

        Signalling strace alone is not enough: it detaches and exits, leaving
        the traced command running — and holding the stdout/stderr pipes it
        inherited, which would make this method block until that command
        finished on its own.
        """
        try:
            stdout, stderr = self._proc.communicate()
        except KeyboardInterrupt:
            self._terminate()
            try:
                stdout, stderr = self._proc.communicate(timeout=_TERMINATE_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._kill()
                stdout, stderr = self._proc.communicate()
            raise
        return subprocess.CompletedProcess(
            args=self._proc.args,
            returncode=self._proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )


class StraceRunner:
    """Spawns commands under strace, writing connect() events to a file."""

    def __init__(self) -> None:
        if shutil.which("strace") is None:
            raise StraceNotFoundError(
                "strace not found on PATH; install it (e.g. apt install strace)"
            )

    def run(self, command: list[str], output_path: Path) -> subprocess.CompletedProcess[bytes]:
        """Run *command* under strace, blocking until it exits.

        strace output is written to *output_path*; stdout/stderr of the wrapped
        command are captured and returned in the CompletedProcess.
        """
        return subprocess.run(
            _strace_cmd(output_path) + command,
            capture_output=True,
        )

    def start(self, command: list[str], output_path: Path) -> StraceProcess:
        """Spawn *command* under strace and return immediately.

        Call `.stop()` on the returned :class:`StraceProcess` to wait for
        completion and retrieve the result.
        """
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            _strace_cmd(output_path) + command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Own session, so stop() can signal strace and the traced command
            # together instead of orphaning the latter.
            start_new_session=True,
        )
        return StraceProcess(proc)
