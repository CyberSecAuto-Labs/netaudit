"""strace subprocess runner — spawns a command under strace and captures output."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class StraceNotFoundError(RuntimeError):
    """Raised when strace is not available on PATH."""


def _strace_cmd(output_path: Path) -> list[str]:
    return ["strace", "-e", "trace=connect", "-f", "-tt", "-o", str(output_path)]


class StraceProcess:
    """Handle to a running strace-wrapped process."""

    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self._proc = proc

    def stop(self) -> subprocess.CompletedProcess[bytes]:
        """Wait for the process to finish and return a CompletedProcess."""
        stdout, stderr = self._proc.communicate()
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
        )
        return StraceProcess(proc)
