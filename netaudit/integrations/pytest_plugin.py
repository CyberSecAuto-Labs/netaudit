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
import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

import pytest

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import (
    _BOLD,
    _RED,
    Reporter,
    Violation,
    _paint,
    _ViolationKey,
    build_run_metadata,
    supports_color,
)

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
    location: str | None = None
    """``file:line`` of the test, when pytest reported a line number."""


def _item_location(item: pytest.Item) -> str:
    """``file:line`` for *item*, or the empty string when pytest has no line.

    ``item.location`` reports a 0-based line number; editors are 1-based.
    """
    try:
        path, lineno, _domain = item.location
    except (AttributeError, TypeError, ValueError):
        return ""
    if not path or lineno is None:
        return ""
    return f"{path}:{lineno + 1}"


def _parse_markers(path: Path) -> list[_TestRange]:
    """Parse a markers sidecar file into test time-ranges.

    Records are tab-separated ``kind, timestamp, location, nodeid``. Tabs rather
    than spaces because parametrized nodeids contain spaces — ``test_p[a b c]``
    — which a space-delimited fourth field could not survive.
    """
    ranges: list[_TestRange] = []
    pending: dict[str, tuple[float, str | None]] = {}
    for line in path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        kind, ts_str, location, nodeid = parts
        try:
            ts = float(ts_str)
        except ValueError:
            continue
        if kind == "START":
            pending[nodeid] = (ts, location or None)
        elif kind == "END" and nodeid in pending:
            start, loc = pending.pop(nodeid)
            ranges.append(_TestRange(nodeid=nodeid, start=start, end=ts, location=loc))
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


def _pyproject_netaudit() -> dict[str, Any]:
    """Read the ``[tool.netaudit]`` table from *pyproject.toml* in the cwd.

    Returns an empty mapping when the file is absent, unreadable, malformed,
    or carries no ``[tool.netaudit]`` table — configuration is best-effort and
    must never break collection.
    """
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        return {}
    try:
        data = tomllib.loads(pyproject.read_text())
    except Exception:
        return {}
    tool_cfg = data.get("tool")
    if not isinstance(tool_cfg, dict):
        return {}
    netaudit_cfg = tool_cfg.get("netaudit")
    return netaudit_cfg if isinstance(netaudit_cfg, dict) else {}


def _merge_by_destination(
    violations_by_test: dict[str, list[Violation]],
) -> tuple[list[Violation], dict[_ViolationKey, set[str]]]:
    """Collapse per-test violations into one row per destination.

    The same destination hit by several tests yields separate ``Violation``
    objects; the summary needs them merged, plus the inverse mapping of
    destination to the tests that reached it.
    """
    merged: dict[_ViolationKey, Violation] = {}
    tests_by_key: dict[_ViolationKey, set[str]] = {}
    for nodeid, violations in violations_by_test.items():
        for v in violations:
            existing = merged.get(v.key)
            if existing is None:
                merged[v.key] = Violation(
                    family=v.family,
                    addr=v.addr,
                    port=v.port,
                    pids=set(v.pids),
                    count=v.count,
                    first_timestamp=v.first_timestamp,
                )
            else:
                existing.pids |= v.pids
                existing.count += v.count
            tests_by_key.setdefault(v.key, set()).add(nodeid)
    return list(merged.values()), tests_by_key


def _resolve_suggest_rules(config: pytest.Config) -> bool:
    """Resolve suggest-rules: CLI flag > pyproject.toml > default (off)."""
    try:
        if bool(config.getoption("--netaudit-suggest-rules")):
            return True
    except (ValueError, pytest.UsageError):
        return False

    value = _pyproject_netaudit().get("suggest_rules")
    return value if isinstance(value, bool) else False


def _fail_session(session: pytest.Session) -> None:
    """Mark the session failed without downgrading a more severe status."""
    if not session.exitstatus:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def _resolve_report_path(config: pytest.Config) -> str | None:
    """Resolve the saved-report path: CLI flag > pyproject.toml > None."""
    try:
        cli_value = config.getoption("--netaudit-report")
    except (ValueError, pytest.UsageError):
        return None
    if cli_value:
        return str(cli_value)

    value = _pyproject_netaudit().get("report")
    return value if isinstance(value, str) else None


def _write_report(violations_by_test: dict[str, list[Violation]], path: Path) -> None:
    """Save a JSON report carrying per-test attribution.

    This is the only place test attribution survives into a durable artifact —
    the CLI has no notion of tests — so ``summary.by_destination[].tests`` is
    populated here for later consumers such as ``netaudit undeclared``.
    """
    merged, tests_by_key = _merge_by_destination(violations_by_test)
    body = Reporter.format_json(
        merged,
        tests_by_key=tests_by_key,
        run=build_run_metadata(command=["pytest", *sys.argv[1:]]),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def _resolve_color(session: pytest.Session) -> bool:
    """Colour follows pytest's own ``--color`` option (yes/no/auto)."""
    try:
        mode = session.config.getoption("color", "auto")
    except (ValueError, pytest.UsageError):
        return False
    if mode == "yes":
        return True
    if mode == "no":
        return False
    return supports_color(sys.stdout)


def _resolve_enabled(config: pytest.Config) -> bool:
    """Resolve enabled: CLI flag > pyproject.toml > default (off)."""
    try:
        if bool(config.getoption("--netaudit")):
            return True
    except (ValueError, pytest.UsageError):
        # Option not registered — the plugin is not active in this process
        # (e.g. a nested pytester session). Never auto-enable in that case.
        return False

    enabled = _pyproject_netaudit().get("enabled")
    return enabled if isinstance(enabled, bool) else False


def _resolve_verbose(config: pytest.Config) -> bool:
    """Resolve verbose: CLI flag > pyproject.toml > default (off)."""
    try:
        if bool(config.getoption("--netaudit-verbose")):
            return True
    except (ValueError, pytest.UsageError):
        pass

    verbose = _pyproject_netaudit().get("verbose")
    return verbose if isinstance(verbose, bool) else False


def _resolve_allowlist(config: pytest.Config) -> AllowList:
    """Resolve allowlist: CLI flag > pyproject.toml > netaudit.yaml > builtins."""
    cli_path: str | None = config.getoption("--netaudit-allowlist")
    if cli_path is not None:
        return AllowList.from_yaml(Path(cli_path))

    al_path = _pyproject_netaudit().get("allowlist")
    if isinstance(al_path, str):
        try:
            return AllowList.from_yaml(Path(al_path))
        except Exception:
            # Unreadable/malformed allowlist — fall through to the defaults below.
            pass

    default = Path(_DEFAULT_ALLOWLIST)
    if default.exists():
        return AllowList.from_yaml(default)

    return AllowList.empty()


def _emit_attributed_verbose(
    events: list[ConnectEvent],
    allowlist: AllowList,
    test_ranges: list[_TestRange],
    session: pytest.Session,
) -> None:
    """Emit verbose table (all events) grouped by test range.

    All events — allowed and violating — are shown, annotated with rule names.
    Exit code is set to ``TESTS_FAILED`` if any violations are present.
    """
    by_test: dict[str, list[ConnectEvent]] = {}
    for event in events:
        attributed = False
        for tr in test_ranges:
            if tr.start <= event.timestamp <= tr.end:
                by_test.setdefault(tr.nodeid, []).append(event)
                attributed = True
                break
        if not attributed:
            by_test.setdefault("<session>", []).append(event)

    has_violations = any(not allowlist.is_allowed(e) for e in events)
    color = _resolve_color(session)

    border = "=" * 60
    print(f"\n{border}")
    print("  netaudit: verbose network event report")
    print(border)
    for nodeid, test_events in sorted(by_test.items()):
        print(f"\n  [{nodeid}]")
        Reporter.format_verbose(test_events, allowlist, stream=sys.stdout, color=color)
    print(f"{border}\n")

    if has_violations:
        _fail_session(session)


def _emit_attributed(
    violations_by_test: dict[str, list[Violation]],
    session: pytest.Session,
    locations: dict[str, str] | None = None,
    suggest_rules: bool = False,
) -> None:
    total = sum(len(vs) for vs in violations_by_test.values())
    color = _resolve_color(session)
    border = "=" * 60
    print(f"\n{border}")
    noun = "violation" if total == 1 else "violations"
    print(_paint(f"  netaudit: {total} {noun} detected", _BOLD + _RED, color))
    print(border)
    for nodeid, violations in sorted(violations_by_test.items()):
        loc = (locations or {}).get(nodeid)
        # The nodeid is the pytest address; file:line is what editors can jump to.
        suffix = f"  ({loc})" if loc else ""
        print(f"\n  [{nodeid}]{suffix}")
        for v in violations:
            print("    " + _paint(str(v), _RED, color))

    merged, tests_by_key = _merge_by_destination(violations_by_test)
    print()
    Reporter.format_summary(merged, tests_by_key=tests_by_key, stream=sys.stdout, color=color)
    if suggest_rules:
        # `merged` is already one entry per destination, so the same host hit by
        # several tests yields a single rule rather than one per test.
        print()
        Reporter.format_suggestions(merged, stream=sys.stdout, color=color)
    print(f"{border}\n")
    _fail_session(session)


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
    group.addoption(
        "--netaudit-report",
        metavar="PATH",
        default=None,
        help="Write a JSON report to PATH for later analysis (e.g. netaudit undeclared).",
    )
    group.addoption(
        "--netaudit-suggest-rules",
        action="store_true",
        default=False,
        help="Print copy-paste-ready allowlist YAML for each violation.",
    )
    group.addoption(
        "--netaudit-verbose",
        action="store_true",
        default=False,
        help="Show all network events (allowed and violations) with rule names.",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Re-exec the current process under strace when auditing is enabled.

    Enabled via ``--netaudit`` or ``enabled = true`` in ``[tool.netaudit]``.
    """
    if not _resolve_enabled(config) or os.environ.get(_ENV_STRACE_OUT):
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
    # Reconstruct as `python -m pytest <args>` so the command is valid regardless
    # of whether pytest was invoked via its entry-point script or `python -m pytest`
    # (in the latter case sys.argv[0] is the non-executable __main__.py path).
    cmd = [
        "strace",
        "-e",
        "trace=connect",
        "-f",
        "-tt",
        "-o",
        strace_path,
        sys.executable,
        "-m",
        "pytest",
    ] + sys.argv[1:]
    os.execvpe("strace", cmd, env)
    # unreachable — execvpe replaces the current process image


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, None, None]:
    """Write START/END timestamp markers around each test for violation attribution."""
    markers_path = os.environ.get(_ENV_MARKERS_OUT)
    location = _item_location(item)
    if markers_path:
        ts = _now_ts()
        with open(markers_path, "a") as f:
            f.write(f"START\t{ts:.6f}\t{location}\t{item.nodeid}\n")

    yield

    if markers_path:
        ts = _now_ts()
        with open(markers_path, "a") as f:
            f.write(f"END\t{ts:.6f}\t{location}\t{item.nodeid}\n")


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
        verbose = _resolve_verbose(session.config)

        markers_file = Path(markers_path_str) if markers_path_str else None
        if markers_file and markers_file.exists():
            test_ranges = _parse_markers(markers_file)
            violations_by_test = _attribute_violations(events, allowlist, test_ranges)
            report_path = _resolve_report_path(session.config)
            if report_path:
                # Written regardless of verbosity or whether anything violated —
                # a clean report is still evidence of what the run observed.
                _write_report(violations_by_test, Path(report_path))
            if verbose:
                _emit_attributed_verbose(events, allowlist, test_ranges, session)
            else:
                if violations_by_test:
                    locations = {
                        tr.nodeid: tr.location for tr in test_ranges if tr.location is not None
                    }
                    _emit_attributed(
                        violations_by_test,
                        session,
                        locations=locations,
                        suggest_rules=_resolve_suggest_rules(session.config),
                    )
        else:
            violations = Reporter.check(events, allowlist)
            if verbose:
                Reporter.format_verbose(events, allowlist, stream=sys.stdout)
            else:
                Reporter.format(violations, stream=sys.stdout)
            if violations:
                _fail_session(session)
    finally:
        strace_file.unlink(missing_ok=True)
        if markers_path_str:
            Path(markers_path_str).unlink(missing_ok=True)
