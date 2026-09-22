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

import json
import math
import os
import secrets
import socket
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

import pytest

from netaudit import _tempfiles
from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import (
    _BOLD,
    _RED,
    Reporter,
    Violation,
    _paint,
    _printable,
    _ViolationKey,
    build_run_metadata,
    supports_color,
)
from netaudit.runner import StraceNotFoundError, _require_strace, _strace_cmd

_ENV_STRACE_OUT = "NETAUDIT_STRACE_OUT"
_ENV_MARKERS_OUT = "NETAUDIT_MARKERS_OUT"
_ENV_TRACER_PID = "NETAUDIT_TRACER_PID"
_DEFAULT_ALLOWLIST = "netaudit.yaml"

# The markers file is opened by name, after the mkstemp that created it closed
# its descriptor. Windows has neither the flag nor strace.
_NO_SYMLINK = getattr(os, "O_NOFOLLOW", 0)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_ts() -> float:
    """Seconds-since-midnight — matches the strace ``-tt`` timestamp format."""
    now = datetime.now()
    return now.hour * 3600 + now.minute * 60 + now.second + now.microsecond / 1e6


@dataclass
class _TracedRun:
    """The state and the policy of the run this process is the traced session of.

    Settled in ``pytest_configure`` and never re-read: every input behind it —
    *pyproject.toml*, the allowlist, the report destination — is named by a
    relative path, and by the time ``pytest_sessionfinish`` runs, the cwd is
    whatever the tests left it as. A test that chdirs into a directory of its
    own would otherwise choose the allowlist it is judged against.

    Settling it does not put it out of reach: tests run in this interpreter and
    can assign to these fields directly. The boundary this holds is against the
    cwd, not against code that means to defeat it.
    """

    config: pytest.Config
    """The session's own config. A nested ``pytest.main()`` runs in this
    interpreter and inherits :data:`_RUN`; its config is a different object, and
    that is what tells the two sessions apart."""
    pid: int
    """The pid that adopted the run — a ``fork()`` inherits :data:`_RUN` too."""
    trace: Path
    markers: Path | None
    canary: str
    """AF_UNIX address of the connect() emitted at startup — see :func:`_emit_canary`."""
    allowlist: AllowList
    verbose: bool
    report: Path | None
    suggest_rules: bool
    invocation: list[str]
    """The arguments pytest was handed — see :func:`_invocation`."""


_RUN: _TracedRun | None = None
"""Set once, in the traced session's ``pytest_configure``. None in every other process."""


_CANARY_FAMILY: int | None = getattr(socket, "AF_UNIX", None)


def _emit_canary(address: str) -> None:
    """Connect to a path that does not exist, purely to be traced.

    A session that reaches its end with an empty trace is either a session that
    connected to nothing or one that was never traced — an unprivileged
    container, a seccomp filter, a trace nothing survived. Those must not read
    alike, so the run plants one connect() of its own: if it is missing from the
    trace, nothing else in the trace can be trusted either.

    What this catches is a trace that never happened, was emptied, or vanished.
    It is not a check against a rewritten one: the address is in the trace file
    by construction, so anything that can write that file can keep the canary
    line and drop the rest — the tests included, since they share this
    interpreter and can read :data:`_RUN` outright. Auditing untrusted code
    means ``netaudit run --``, where the audit is a different process.
    """
    if _CANARY_FAMILY is None:
        # No AF_UNIX means no Linux, so no strace either: nothing re-execs, no
        # run is ever adopted, and the check this feeds is never reached.
        return
    sock = socket.socket(_CANARY_FAMILY, socket.SOCK_STREAM)
    try:
        sock.connect(address)
    except OSError:
        # ENOENT is the expected answer; the syscall is the point, not its result.
        pass
    finally:
        sock.close()


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


_SECONDS_IN_A_DAY = 86400.0


def _marker_timestamp(text: str) -> float | None:
    """The timestamp of a marker record, or None when *text* is not one.

    ``float`` accepts ``inf`` and ``nan``, and a range ending at infinity
    contains every event in the run. Attribution is first-match-wins, so one
    such record would report the whole run under a single benign nodeid — and
    nodeids come from the repository under audit.
    """
    try:
        ts = float(text)
    except ValueError:
        return None
    if not math.isfinite(ts) or not 0.0 <= ts < _SECONDS_IN_A_DAY:
        return None
    return ts


def _marker_field(text: str) -> str | None:
    """Decode one quoted marker field, or None when it is not one."""
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, str) else None


def _parse_markers(path: Path) -> list[_TestRange]:
    """Parse a markers sidecar file into test time-ranges.

    Records are tab-separated ``kind, timestamp, location, nodeid``. Tabs
    rather than spaces because parametrized nodeids contain spaces —
    ``test_p[a b c]`` — which a space-delimited fourth field could not survive.

    The two text fields are JSON-quoted by :func:`_append_marker`. A nodeid is
    repository-controlled, and written raw it could carry a tab (dropping the
    record) or one of the separators ``splitlines`` honours beyond ``\n`` —
    ``\x0b``, ``\x1c``, ``\x85``, ``\u2028`` — manufacturing a forged one.
    JSON escapes every one of them.
    """
    ranges: list[_TestRange] = []
    pending: dict[str, tuple[float, str | None]] = {}
    for line in path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        kind, ts_str, raw_location, raw_nodeid = parts
        ts = _marker_timestamp(ts_str)
        location = _marker_field(raw_location)
        nodeid = _marker_field(raw_nodeid)
        if ts is None or location is None or nodeid is None:
            continue
        if kind == "START":
            pending[nodeid] = (ts, location or None)
        elif kind == "END" and nodeid in pending:
            start, loc = pending.pop(nodeid)
            # A range that ends before it starts matches nothing; keeping it
            # would only add a row the reader cannot make sense of.
            if ts >= start:
                ranges.append(_TestRange(nodeid=nodeid, start=start, end=ts, location=loc))
    return ranges


def _markers_target(config: pytest.Config) -> Path | None:
    """The markers file this process may append to, or None.

    The traced session uses the path its ``pytest_configure`` settled. An xdist
    worker has no run of its own but runs this session's tests, so it takes the
    path from the environment — checked, because the worker cannot tell the
    re-exec's variable from anyone else's.
    """
    if _RUN is not None:
        return _RUN.markers
    return _from_env(_ENV_MARKERS_OUT) if _is_xdist_worker(config) else None


def _append_marker(path: Path, kind: str, location: str, nodeid: str) -> None:
    """Append one tab-separated marker record to *path*, never through a symlink.

    The text fields are JSON-quoted — see :func:`_parse_markers` for why a raw
    nodeid can forge or destroy a record.
    """
    record = f"{kind}\t{_now_ts():.6f}\t{json.dumps(location)}\t{json.dumps(nodeid)}\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | _NO_SYMLINK)
    try:
        handle = os.fdopen(fd, "a")
    except OSError:
        os.close(fd)
        raise
    with handle as f:
        f.write(record)


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


def _is_xdist_worker(config: pytest.Config) -> bool:
    """True inside a pytest-xdist worker, which runs *this* session's tests.

    A worker is a descendant of the traced session and so claims no run of its
    own, but the tests it runs are the run's own and their markers belong in
    the run's file. (Ranges from parallel workers can overlap, and attribution
    resolves that first-match — a limitation of ``-n`` itself, not of this.)
    """
    return hasattr(config, "workerinput")


def _invocation(config: pytest.Config) -> list[str]:
    """The arguments this session was asked to run, as pytest recorded them.

    ``config.invocation_params.args`` is what pytest was handed, whether that
    came from the command line or from a ``pytest.main([...])`` call. Falls
    back to ``sys.argv[1:]`` only if pytest does not record it, which no
    supported version omits.
    """
    params = getattr(config, "invocation_params", None)
    args = getattr(params, "args", None)
    return list(args) if args is not None else sys.argv[1:]


def _rootdir(config: pytest.Config) -> Path:
    """pytest's rootdir — the directory the run's configuration belongs to."""
    return Path(config.rootpath)


def _anchored(value: str, root: Path) -> Path:
    """Resolve a configured path against *root* while the cwd is still the run's own."""
    return (root / value).resolve()


def _pyproject_netaudit(root: Path, strict: bool = False) -> dict[str, Any]:
    """Read the ``[tool.netaudit]`` table from *pyproject.toml* under *root*.

    *root* is pytest's rootdir rather than the cwd: the cwd is whatever the
    tests last left it as, and the run's own configuration cannot come from
    a directory the run under audit chose.

    Returns an empty mapping when the file is absent, unreadable, malformed,
    or carries no ``[tool.netaudit]`` table. That tolerance is for the question
    "is auditing on?", which every pytest process on the machine asks — the
    plugin loads via the ``pytest11`` entry point — and where the safe answer
    to "cannot tell" is no.

    *strict* is for the questions asked once auditing is already on, where a
    file that cannot be read would silently drop the policy it declares: there
    the read failure is reported instead.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return {}
    try:
        data = tomllib.loads(pyproject.read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        if strict:
            raise pytest.UsageError(f"netaudit: could not read {pyproject}: {exc}") from None
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

    value = _pyproject_netaudit(_rootdir(config)).get("suggest_rules")
    return value if isinstance(value, bool) else False


def _fail_session(session: pytest.Session) -> None:
    """Mark the session failed without downgrading a more severe status."""
    if not session.exitstatus:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def _resolve_report_path(config: pytest.Config) -> Path | None:
    """Resolve the saved-report path: CLI flag > pyproject.toml > None."""
    root = _rootdir(config)
    try:
        cli_value = config.getoption("--netaudit-report")
    except (ValueError, pytest.UsageError):
        return None
    if cli_value:
        return _anchored(str(cli_value), Path.cwd())

    value = _pyproject_netaudit(root).get("report")
    return _anchored(value, root) if isinstance(value, str) else None


def _write_report(
    violations_by_test: dict[str, list[Violation]], path: Path, invocation: list[str]
) -> None:
    """Save a JSON report carrying per-test attribution.

    This is the only place test attribution survives into a durable artifact —
    the CLI has no notion of tests — so ``summary.by_destination[].tests`` is
    populated here for later consumers such as ``netaudit triage``.
    """
    merged, tests_by_key = _merge_by_destination(violations_by_test)
    body = Reporter.format_json(
        merged,
        tests_by_key=tests_by_key,
        run=build_run_metadata(command=["pytest", *invocation]),
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

    enabled = _pyproject_netaudit(_rootdir(config)).get("enabled")
    return enabled if isinstance(enabled, bool) else False


def _resolve_verbose(config: pytest.Config) -> bool:
    """Resolve verbose: CLI flag > pyproject.toml > default (off)."""
    try:
        if bool(config.getoption("--netaudit-verbose")):
            return True
    except (ValueError, pytest.UsageError):
        pass

    verbose = _pyproject_netaudit(_rootdir(config)).get("verbose")
    return verbose if isinstance(verbose, bool) else False


def _load_allowlist(path: Path) -> AllowList:
    """Load the allowlist at *path*, or abort the session saying why.

    ``from_yaml`` reports every way a file can be unusable as ``ValueError``,
    so this re-labels one error type rather than blanketing the call: the
    causes are all things a user wrote — a path that moved, a version bump, a
    malformed entry — and each needs naming, not a stack.
    """
    try:
        return AllowList.from_yaml(path)
    except ValueError as exc:
        raise pytest.UsageError(f"netaudit: {exc}") from None


def _resolve_allowlist(config: pytest.Config) -> AllowList:
    """Resolve allowlist: CLI flag > pyproject.toml > netaudit.yaml > builtins.

    An allowlist that is named but cannot be loaded ends the session. Falling
    back to the built-ins would not be falling back to nothing: they permit
    every AF_UNIX path, all of ``127.0.0.0/8``, ``::1`` and all of AF_NETLINK,
    so a policy that turned them off with ``includes_builtins: false`` would be
    replaced by a *more* permissive one the moment its file was renamed or
    mis-edited — silently, and on every run after. ``netaudit run`` treats the
    same condition as a hard error; this is that verdict in pytest's idiom.
    """
    root = _rootdir(config)
    cli_path: str | None = config.getoption("--netaudit-allowlist")
    if cli_path is not None:
        return _load_allowlist(_anchored(cli_path, Path.cwd()))

    al_path = _pyproject_netaudit(root, strict=True).get("allowlist")
    if al_path is not None:
        if not isinstance(al_path, str):
            # Ignoring it would be the same silent widening as a file that moved.
            raise pytest.UsageError(
                f"netaudit: [tool.netaudit] allowlist must be a path, not {al_path!r}"
            )
        return _load_allowlist(_anchored(al_path, root))

    default = _anchored(_DEFAULT_ALLOWLIST, root)
    if default.exists():
        return _load_allowlist(default)

    return AllowList.empty()


def _from_env(name: str) -> Path | None:
    """The path *name* holds, when it is one *this* run could have made.

    The re-exec passes the trace and markers paths in the environment, and this
    process goes on to append to one and unlink both. Anything else that sets
    the variable — the plugin loads in every pytest run on the machine, via the
    ``pytest11`` entry point — would otherwise be choosing a file for netaudit
    to delete.

    Two things have to hold. The path must have the shape ``_tempfiles``
    gives its own files: a regular, unshared file of this uid inside a private
    run directory. And the pid stamped into that directory must be the tracer's
    — ``execvpe`` keeps the pid, so the process that created the directory is
    the one that became strace, and ``NETAUDIT_TRACER_PID`` records it. A path
    left over from some other run therefore does not qualify.
    """
    value = os.environ.get(name)
    if value is None:
        return None
    path = Path(value)
    if not _tempfiles.is_own_name(path):
        return None
    tracer_pid = os.environ.get(_ENV_TRACER_PID)
    return path if tracer_pid is None or _tempfiles.owner_of(path.parent) == tracer_pid else None


def _adopt_the_traced_run(trace: Path, config: pytest.Config) -> _TracedRun:
    """Take ownership of this run's files and settle the policy it is judged by."""
    markers = _from_env(_ENV_MARKERS_OUT)
    _tempfiles.remove_on_cancel(*(p for p in (trace, markers) if p is not None))
    return _TracedRun(
        config=config,
        pid=os.getpid(),
        trace=trace,
        markers=markers,
        canary=f"/nonexistent/netaudit-canary-{secrets.token_hex(8)}",
        allowlist=_resolve_allowlist(config),
        verbose=_resolve_verbose(config),
        report=_resolve_report_path(config),
        suggest_rules=_resolve_suggest_rules(config),
        invocation=_invocation(config),
    )


def _keep_the_trace(path: Path, contents: str) -> bool:
    """Keep the trace and say where it is, when there is anything in it to keep.

    A trace netaudit could not judge is the only record of what the run did;
    reporting that and then deleting it would leave nothing to act on. An empty
    one holds nothing, so it goes — ``netaudit run`` makes the same distinction.

    Returns whether it was kept, for the caller's cleanup to honour.
    """
    if not contents:
        return False
    _tempfiles.keep(path)
    print(f"  The trace is kept at {path}")
    print(f"  Re-run the analysis with: netaudit analyze {path}\n")
    return True


def _discard(path: Path | None) -> None:
    """Remove a temp file, best-effort.

    Unguarded, a cleanup failure here would replace whatever the session was
    about to report with a traceback about a file nobody asked after.
    """
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _emit_report_failure(session: pytest.Session, path: Path, exc: OSError) -> None:
    """Say the report could not be written, and fail the session for it.

    The violations, if any, have already been printed. What is lost is the
    artifact the user asked for, which is its own failure.
    """
    print(f"\n  netaudit: could not write the report to {path}: {exc}")
    print("  The block above is the whole of the result; nothing was saved.\n")
    _fail_session(session)


def _emit_not_audited(session: pytest.Session, detail: str) -> None:
    """Fail the session, with *detail* saying why its trace is not evidence."""
    border = "=" * 60
    color = _resolve_color(session)
    print(f"\n{border}")
    print(_paint("  netaudit: the session was not audited", _BOLD + _RED, color))
    print(border)
    print(f"\n{detail}")
    print(f"{border}\n")
    _fail_session(session)


def _emit_untraced(session: pytest.Session) -> None:
    """Fail the session that produced no trace of its own canary connect()."""
    _emit_not_audited(
        session,
        "  No trace was produced. strace may lack ptrace permission here, or\n"
        "  the trace was removed while the session ran; either way nothing\n"
        "  observed this run, so it cannot be reported as clean.",
    )


def _emit_unreadable(session: pytest.Session, unparsed: int) -> None:
    """Fail the session whose trace holds connect() calls netaudit cannot read."""
    noun = "line" if unparsed == 1 else "lines"
    _emit_not_audited(
        session,
        f"  {unparsed} connect() {noun} in the trace could not be parsed, so the\n"
        "  destinations they reached are unknown. Part of a run cannot be\n"
        "  reported as the whole of it.",
    )


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
        print(f"\n  [{_printable(nodeid)}]")
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
        # Both are repo-controlled text on its way to a terminal.
        suffix = f"  ({_printable(loc)})" if loc else ""
        print(f"\n  [{_printable(nodeid)}]{suffix}")
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
        help="Write a JSON report to PATH for later analysis (e.g. netaudit triage).",
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
    global _RUN

    # Popped rather than read, and the pop is what claims the run. The path to
    # the trace is what would let the code under audit empty its own evidence,
    # so it must not survive into the tests — and removing it here means no
    # descendant can see it either. Whoever finds the variable set *is* the
    # traced session: a test that shells out to pytest, or an xdist worker,
    # inherits an environment this process has already emptied of it.
    #
    # Reading it this way rather than comparing pids is what makes the check
    # hold when the strace on PATH is a wrapper script — a common CI shape for
    # granting ptrace. There the traced pytest's parent is the inner strace and
    # not the recorded tracer, and a parent comparison would silently disown
    # the run, reporting no violations and leaking the trace.
    trace = _from_env(_ENV_STRACE_OUT)
    already_traced = _ENV_STRACE_OUT in os.environ or _ENV_TRACER_PID in os.environ
    os.environ.pop(_ENV_STRACE_OUT, None)
    if already_traced:
        # The process that made these files is gone — the exec replaced it — so
        # this one owns removing them, and its sessionfinish is only reached if
        # the run is allowed to finish.
        if trace is not None:
            _RUN = _adopt_the_traced_run(trace, config)
            _emit_canary(_RUN.canary)
        return

    if not _resolve_enabled(config):
        return

    try:
        strace = _require_strace()
    except StraceNotFoundError as exc:
        raise pytest.UsageError(f"netaudit: {exc}") from None

    # A SIGKILLed run cannot clean up after itself; the next one does it for it.
    _tempfiles.sweep_stale()

    strace_path = str(_tempfiles.create(".strace"))
    markers_path = str(_tempfiles.create(".markers"))

    env = {
        **os.environ,
        _ENV_STRACE_OUT: strace_path,
        _ENV_MARKERS_OUT: markers_path,
        # Survives the exec as strace's own pid, which is what the pytest it
        # forks will see as its parent — and no deeper process will.
        _ENV_TRACER_PID: str(os.getpid()),
    }
    # Reconstruct as `python -m pytest <args>` so the command is valid regardless
    # of whether pytest was invoked via its entry-point script or `python -m pytest`
    # (in the latter case sys.argv[0] is the non-executable __main__.py path).
    #
    # The arguments come from pytest, not from sys.argv, which is only pytest's
    # when pytest owns the process. Under `pytest.main([...])` called from a
    # wrapper — `python run_tests.py --profile ci` invoking
    # `pytest.main(["tests/unit", "-q"])` — sys.argv holds the wrapper's flags
    # and the list actually passed is nowhere in it. The re-exec would then
    # trace a different set of tests than the one requested, and certify a run
    # that never happened.
    #
    # The strace flags come from the runner rather than being spelled out again:
    # a second copy would drift, and the copy that lost --kill-on-exit would go
    # back to orphaning its tracees without anything failing to say so.
    cmd = _strace_cmd(Path(strace_path)) + [sys.executable, "-m", "pytest"] + _invocation(config)
    # execve, not execvpe: the path was resolved once, and searching PATH again
    # here would let a different binary run than the one that was checked.
    os.execve(strace, cmd, env)
    # unreachable — execvpe replaces the current process image


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, None, None]:
    """Write START/END timestamp markers around each test for violation attribution."""
    markers_path = _markers_target(item.config)
    location = _item_location(item)
    if markers_path:
        _append_marker(markers_path, "START", location, item.nodeid)

    yield

    if markers_path:
        _append_marker(markers_path, "END", location, item.nodeid)


def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: int | pytest.ExitCode,
) -> None:
    """Parse strace output, attribute violations to tests, and fail if any found."""
    run = _RUN
    if run is None:
        # Not the traced session: a nested pytest, or auditing was never enabled.
        return
    if run.config is not session.config or run.pid != os.getpid():
        # A session that inherited this module's state rather than one that
        # adopted the run: `pytest.main()` called from a test runs in this
        # interpreter, and a fork carries the globals with it. Either would
        # otherwise report on — and delete — a trace that is still being
        # written by the run it came from.
        return

    strace_file = run.trace
    keep_trace = False

    try:
        trace = strace_file.read_text() if strace_file.exists() else ""
        parser = StraceParser()
        events = parser.parse_stream(trace.splitlines())
        if parser.unparsed:
            _emit_unreadable(session, parser.unparsed)
            keep_trace = _keep_the_trace(strace_file, trace)
            return
        if not any(e.addr == run.canary for e in events):
            _emit_untraced(session)
            keep_trace = _keep_the_trace(strace_file, trace)
            return
        events = [e for e in events if e.addr != run.canary]

        allowlist = run.allowlist
        verbose = run.verbose

        markers_file = run.markers
        if markers_file and markers_file.exists():
            test_ranges = _parse_markers(markers_file)
            violations_by_test = _attribute_violations(events, allowlist, test_ranges)
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
                        suggest_rules=run.suggest_rules,
                    )
            if run.report:
                # Written last, and after the verdict: a path that cannot be
                # written — a read-only filesystem, a full disk, a component
                # that is a file — must not be able to jump past the violations
                # and take the trace with it on the way out. Written regardless
                # of verbosity or of whether anything violated, because a clean
                # report is still evidence of what the run observed.
                try:
                    _write_report(violations_by_test, run.report, run.invocation)
                except OSError as exc:
                    _emit_report_failure(session, run.report, exc)
        else:
            violations = Reporter.check(events, allowlist)
            if verbose:
                Reporter.format_verbose(events, allowlist, stream=sys.stdout)
            else:
                Reporter.format(violations, stream=sys.stdout)
            if violations:
                _fail_session(session)
    except Exception:
        # The audit did not finish. Whatever the trace holds is the only record
        # of what the run did, and the block above never reported it.
        keep_trace = True
        _tempfiles.keep(strace_file)
        print(f"\n  netaudit: the audit did not finish; its trace is kept at {strace_file}")
        print(f"  Re-run the analysis with: netaudit analyze {strace_file}\n")
        raise
    finally:
        if not keep_trace:
            _discard(strace_file)
        _discard(run.markers)
