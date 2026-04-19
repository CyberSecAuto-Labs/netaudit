"""pytest plugin — network egress auditing during test runs.

Activated by passing ``--netaudit`` to pytest, or by setting::

    [tool.netaudit]
    enabled = true
    allowlist = "netaudit.yaml"

in *pyproject.toml*.  The plugin re-executes the test process under strace,
captures all ``connect()`` syscalls, attributes violations to individual
tests, and fails the session if any are found.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Generator

import pytest

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import Reporter, Violation

_ENV_STRACE_OUT = "NETAUDIT_STRACE_OUT"
_ENV_MARKERS_OUT = "NETAUDIT_MARKERS_OUT"
_DEFAULT_ALLOWLIST = "netaudit.yaml"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_ts() -> float:
    """Seconds-since-midnight — matches the strace ``-tt`` timestamp format."""
    now = datetime.now()
    return now.hour * 3600 + now.minute * 60 + now.second + now.microsecond / 1e6


@dataclass
class _TestRange:
    nodeid: str
    start: float
    end: float


def _parse_markers(path: Path) -> list[_TestRange]:
    """Parse a markers sidecar file into test time-ranges."""
    ranges: list[_TestRange] = []
    pending: dict[str, float] = {}
    for line in path.read_text().splitlines():
        parts = line.split(" ", 2)
        if len(parts) != 3:
            continue
        kind, ts_str, nodeid = parts
        try:
            ts = float(ts_str)
        except ValueError:
            continue
        if kind == "START":
            pending[nodeid] = ts
        elif kind == "END" and nodeid in pending:
            ranges.append(_TestRange(nodeid=nodeid, start=pending.pop(nodeid), end=ts))
    return ranges


def _group_events(events: list[ConnectEvent]) -> list[Violation]:
    """Group ConnectEvents into Violations without re-running allowlist checks."""
    seen: dict[tuple[str, str | None, int | None], Violation] = {}
    for event in events:
        key = (event.family, event.addr, event.port)
        if key not in seen:
            seen[key] = Violation(
                family=event.family,
                addr=event.addr,
                port=event.port,
                first_timestamp=event.timestamp,
            )
        v = seen[key]
        v.pids.add(event.pid)
        v.count += 1
    return list(seen.values())


def _attribute_violations(
    events: list[ConnectEvent],
    allowlist: AllowList,
    test_ranges: list[_TestRange],
) -> dict[str, list[Violation]]:
    """Map each violation event to the test that caused it.

    Events that don't fall within any test's time window are grouped under
    ``"<session>"``.
    """
    violation_events = [e for e in events if not allowlist.is_allowed(e)]

    by_test: dict[str, list[ConnectEvent]] = {}
    for event in violation_events:
        attributed = False
        for tr in test_ranges:
            if tr.start <= event.timestamp <= tr.end:
                by_test.setdefault(tr.nodeid, []).append(event)
                attributed = True
                break
        if not attributed:
            by_test.setdefault("<session>", []).append(event)

    return {nodeid: _group_events(evts) for nodeid, evts in by_test.items()}


def _resolve_allowlist(config: pytest.Config) -> AllowList:
    """Resolve allowlist: CLI flag > pyproject.toml > netaudit.yaml > builtins."""
    cli_path: str | None = config.getoption("--netaudit-allowlist")
    if cli_path is not None:
        return AllowList.from_yaml(Path(cli_path))

    pyproject = Path("pyproject.toml")
    if pyproject.exists():
        try:
            import tomllib

            data = tomllib.loads(pyproject.read_text())
            tool_cfg = data.get("tool") or {}
            netaudit_cfg = tool_cfg.get("netaudit") or {} if isinstance(tool_cfg, dict) else {}
            al_path = netaudit_cfg.get("allowlist")
            if isinstance(al_path, str):
                return AllowList.from_yaml(Path(al_path))
        except Exception:
            pass

    default = Path(_DEFAULT_ALLOWLIST)
    if default.exists():
        return AllowList.from_yaml(default)

    return AllowList.empty()


def _emit_attributed(
    violations_by_test: dict[str, list[Violation]],
    session: pytest.Session,
) -> None:
    total = sum(len(vs) for vs in violations_by_test.values())
    border = "=" * 60
    print(f"\n{border}")
    noun = "violation" if total == 1 else "violations"
    print(f"  netaudit: {total} {noun} detected")
    print(border)
    for nodeid, violations in sorted(violations_by_test.items()):
        print(f"\n  [{nodeid}]")
        for v in violations:
            print(f"    {v}")
    print(f"{border}\n")
    session.exitstatus = pytest.ExitCode.TESTS_FAILED


# ---------------------------------------------------------------------------
# pytest hooks
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("netaudit", "Network egress auditing")
    group.addoption(
        "--netaudit",
        action="store_true",
        default=False,
        help="Enable network egress auditing via strace.",
    )
    group.addoption(
        "--netaudit-allowlist",
        metavar="YAML",
        default=None,
        help="Allowlist YAML file (overrides pyproject.toml and netaudit.yaml).",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Re-exec the current process under strace when --netaudit is first seen."""
    try:
        enabled: bool = bool(config.getoption("--netaudit"))
    except ValueError:
        return  # option not yet registered (e.g. nested pytester session)

    if not enabled or os.environ.get(_ENV_STRACE_OUT):
        return  # disabled or already running under strace

    if shutil.which("strace") is None:
        raise pytest.UsageError(
            "netaudit: strace is not available on PATH — install it (e.g. apt install strace)."
        )

    strace_fd, strace_path = tempfile.mkstemp(suffix=".strace", prefix="netaudit-")
    os.close(strace_fd)
    markers_fd, markers_path = tempfile.mkstemp(suffix=".markers", prefix="netaudit-")
    os.close(markers_fd)

    env = {
        **os.environ,
        _ENV_STRACE_OUT: strace_path,
        _ENV_MARKERS_OUT: markers_path,
    }
    cmd = ["strace", "-e", "trace=connect", "-f", "-tt", "-o", strace_path] + sys.argv
    os.execvpe("strace", cmd, env)
    # unreachable — execvpe replaces the current process image


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, None, None]:
    """Write START/END timestamp markers around each test for violation attribution."""
    markers_path = os.environ.get(_ENV_MARKERS_OUT)
    if markers_path:
        ts = _now_ts()
        with open(markers_path, "a") as f:
            f.write(f"START {ts:.6f} {item.nodeid}\n")

    yield

    if markers_path:
        ts = _now_ts()
        with open(markers_path, "a") as f:
            f.write(f"END {ts:.6f} {item.nodeid}\n")


def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: int | pytest.ExitCode,
) -> None:
    """Parse strace output, attribute violations to tests, and fail if any found."""
    strace_path = os.environ.get(_ENV_STRACE_OUT)
    if not strace_path:
        return

    markers_path_str = os.environ.get(_ENV_MARKERS_OUT)
    strace_file = Path(strace_path)

    try:
        if not strace_file.exists() or strace_file.stat().st_size == 0:
            return

        events = StraceParser().parse_stream(strace_file.read_text().splitlines())
        allowlist = _resolve_allowlist(session.config)

        markers_file = Path(markers_path_str) if markers_path_str else None
        if markers_file and markers_file.exists():
            test_ranges = _parse_markers(markers_file)
            violations_by_test = _attribute_violations(events, allowlist, test_ranges)
            if violations_by_test:
                _emit_attributed(violations_by_test, session)
        else:
            violations = Reporter.check(events, allowlist)
            Reporter.format(violations, stream=sys.stdout)
            if violations:
                session.exitstatus = pytest.ExitCode.TESTS_FAILED
    finally:
        strace_file.unlink(missing_ok=True)
        if markers_path_str:
            Path(markers_path_str).unlink(missing_ok=True)
