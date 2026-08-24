"""Violation grouping and human-readable reporting."""

from __future__ import annotations

import io
import ipaddress
import json
import os
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent

__all__ = [
    "Destination",
    "LoadedReport",
    "MergedDestination",
    "REPORT_VERSION",
    "Reporter",
    "Violation",
    "build_run_metadata",
    "is_external",
    "load_report",
    "merge_reports",
    "supports_color",
]

#: Schema version of the JSON report envelope. Bump on any breaking change to
#: the shape, so tools reading saved reports can reject what they cannot parse.
REPORT_VERSION = 1

# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_BOLD = "\033[1m"


def supports_color(stream: TextIO | None = None) -> bool:
    """True when ANSI colour should be written to *stream* (default: stdout).

    Honours the `NO_COLOR <https://no-color.org/>`_ convention: the variable
    disables colour when present *and non-empty*, whatever its value.
    """
    if os.environ.get("NO_COLOR"):
        return False
    target = sys.stdout if stream is None else stream
    isatty = getattr(target, "isatty", None)
    return bool(isatty()) if callable(isatty) else False


def is_external(addr: str | None) -> bool:
    """True when *addr* is a globally routable internet address.

    This is the discriminating axis for review: undeclared egress to a private
    or otherwise non-routable address is unremarkable, while undeclared egress
    to the public internet is worth a look however consistent it is. It is a
    checkable fact rather than a judgement about intent — which the tool has no
    basis to make.

    Unix socket paths and anything unparseable are not addresses at all, and
    are therefore not external.
    """
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


def build_run_metadata(
    command: list[str] | None = None,
    allowlist: str | None = None,
    source: str | None = None,
    command_exit_code: int | None = None,
) -> dict[str, Any]:
    """Describe the run that produced a report.

    A saved report is only useful as evidence if it can say where it came from:
    which command, against which allowlist, on which host, when, and with what
    version of netaudit. Callers supply what they know — ``command`` for a live
    trace, ``source`` for offline analysis of an existing log.
    """
    from netaudit import __version__

    meta: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "netaudit_version": __version__,
    }
    if command is not None:
        meta["command"] = list(command)
    if allowlist is not None:
        meta["allowlist"] = allowlist
    if source is not None:
        meta["source"] = source
    if command_exit_code is not None:
        meta["command_exit_code"] = command_exit_code
    return meta


def _paint(text: str, code: str, color: bool) -> str:
    """Wrap *text* in an ANSI *code* when *color* is on, else return it plain."""
    return f"{code}{text}{_RESET}" if color else text


# ---------------------------------------------------------------------------
# Violation
# ---------------------------------------------------------------------------

_ViolationKey = tuple[str, str | None, int | None]


@dataclass
class Violation:
    family: str
    addr: str | None
    port: int | None
    pids: set[int] = field(default_factory=set)
    count: int = 0
    first_timestamp: float = 0.0

    @property
    def key(self) -> _ViolationKey:
        return (self.family, self.addr, self.port)

    def _addr_str(self) -> str:
        if self.addr is None:
            return "<unknown>"
        if self.port is not None:
            return f"{self.addr}:{self.port}"
        return self.addr

    def __str__(self) -> str:
        pids_str = ", ".join(str(p) for p in sorted(self.pids))
        return f"{self.family} {self._addr_str()} (count={self.count}, pids=[{pids_str}])"


# ---------------------------------------------------------------------------
# Saved reports
# ---------------------------------------------------------------------------


@dataclass
class Destination:
    """One destination observed in a saved report."""

    family: str
    addr: str | None
    port: int | None
    count: int = 0
    tests: set[str] = field(default_factory=set)

    @property
    def key(self) -> _ViolationKey:
        return (self.family, self.addr, self.port)


@dataclass
class LoadedReport:
    """A saved JSON report, tagged with the name it was read from."""

    label: str
    run: dict[str, Any]
    destinations: list[Destination]


@dataclass
class MergedDestination:
    """A destination merged across several reports, with its evidence."""

    family: str
    addr: str | None
    port: int | None
    count: int = 0
    tests: set[str] = field(default_factory=set)
    reports: list[str] = field(default_factory=list)
    total_reports: int = 0

    @property
    def key(self) -> _ViolationKey:
        return (self.family, self.addr, self.port)

    @property
    def is_external(self) -> bool:
        """Whether this destination is on the public internet."""
        return is_external(self.addr)

    def as_violation(self) -> Violation:
        """Adapt to the shape the existing renderers expect."""
        return Violation(family=self.family, addr=self.addr, port=self.port, count=self.count)


def load_report(path: Path) -> LoadedReport:
    """Read a saved JSON report, rejecting anything this version cannot parse.

    A report whose schema is unknown is refused outright rather than parsed
    optimistically — silently misreading evidence is worse than failing.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read report {path.name}: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"Report {path.name} is not a JSON object")

    version = data.get("version")
    if version != REPORT_VERSION:
        raise ValueError(
            f"Report {path.name} has unsupported schema version {version!r} "
            f"(this netaudit reads version {REPORT_VERSION})"
        )

    summary = data.get("summary") or {}
    raw = summary.get("by_destination") or [] if isinstance(summary, dict) else []
    destinations = [
        Destination(
            family=str(d.get("family", "")),
            addr=d.get("addr"),
            port=d.get("port"),
            count=int(d.get("count", 0)),
            tests=set(d.get("tests") or []),
        )
        for d in raw
        if isinstance(d, dict)
    ]
    run = data.get("run") or {}
    return LoadedReport(
        label=path.name,
        run=run if isinstance(run, dict) else {},
        destinations=destinations,
    )


def merge_reports(reports: list[LoadedReport]) -> list[MergedDestination]:
    """Collapse destinations seen across *reports* into one entry each.

    Each entry records which reports saw it and how many were supplied, so a
    caller can show the reviewer how well evidenced a rule is.
    """
    merged: dict[_ViolationKey, MergedDestination] = {}
    for report in reports:
        for dest in report.destinations:
            entry = merged.get(dest.key)
            if entry is None:
                entry = MergedDestination(family=dest.family, addr=dest.addr, port=dest.port)
                merged[dest.key] = entry
            entry.count += dest.count
            entry.tests |= dest.tests
            if report.label not in entry.reports:
                entry.reports.append(report.label)

    for entry in merged.values():
        entry.total_reports = len(reports)
    # Loudest first; ties broken by address so output is stable.
    return sorted(merged.values(), key=lambda d: (-d.count, str(d.addr)))


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class Reporter:
    @staticmethod
    def check(events: list[ConnectEvent], allowlist: AllowList) -> list[Violation]:
        """Return violations — events not matched by any allowlist rule."""
        violations: dict[_ViolationKey, Violation] = {}
        for event in events:
            if allowlist.is_allowed(event):
                continue
            key: _ViolationKey = (event.family, event.addr, event.port)
            if key not in violations:
                violations[key] = Violation(
                    family=event.family,
                    addr=event.addr,
                    port=event.port,
                    first_timestamp=event.timestamp,
                )
            v = violations[key]
            v.pids.add(event.pid)
            v.count += 1
        return list(violations.values())

    @staticmethod
    def format(
        violations: list[Violation],
        stream: TextIO | None = None,
        color: bool = False,
    ) -> str:
        """Render violations as a human-readable box. Returns the string and
        optionally writes it to *stream*."""
        buf = io.StringIO()
        if not violations:
            buf.write(_paint("netaudit: no violations", _GREEN, color) + "\n")
        else:
            count = len(violations)
            noun = "violation" if count == 1 else "violations"
            border = "=" * 60
            heading = f"  netaudit: {count} {noun} detected"
            buf.write(f"\n{border}\n")
            buf.write(_paint(heading, _BOLD + _RED, color) + "\n")
            buf.write(f"{border}\n")
            for v in violations:
                buf.write("  " + _paint(str(v), _RED, color) + "\n")
            buf.write(f"{border}\n\n")

        result = buf.getvalue()
        if stream is not None:
            stream.write(result)
        return result

    @staticmethod
    def format_verbose(
        events: list[ConnectEvent],
        allowlist: AllowList,
        stream: TextIO | None = None,
        color: bool = False,
    ) -> str:
        """Render all events as a table annotated with OK/VIOLATION and rule name."""
        col_family = 12
        col_addr = 30
        col_status = 10

        def _addr_str(event: ConnectEvent) -> str:
            if event.addr is None:
                return "-"
            if event.port is not None:
                return f"{event.addr}:{event.port}"
            return event.addr

        header = f"{'FAMILY':<{col_family}} {'ADDR:PORT':<{col_addr}} {'STATUS':<{col_status}} RULE"
        sep = f"{'-' * col_family} {'-' * col_addr} {'-' * col_status} {'-' * 24}"

        buf = io.StringIO()
        buf.write(header + "\n")
        buf.write(sep + "\n")
        for event in events:
            rule = allowlist.match(event)
            status = "OK" if rule is not None else "VIOLATION"
            rule_name = rule.name if rule is not None else "-"
            addr = _addr_str(event)
            # Pad first, then paint — ANSI codes must not count toward the width.
            status_cell = _paint(
                f"{status:<{col_status}}", _GREEN if rule is not None else _RED, color
            )
            row = f"{event.family:<{col_family}} {addr:<{col_addr}} {status_cell} {rule_name}"
            buf.write(row + "\n")

        result = buf.getvalue()
        if stream is not None:
            stream.write(result)
        return result

    @staticmethod
    def format_summary(
        violations: list[Violation],
        tests_by_key: dict[_ViolationKey, set[str]] | None = None,
        stream: TextIO | None = None,
        color: bool = False,
    ) -> str:
        """Render a compact per-destination overview of *violations*.

        The third column adapts to the caller: test nodeids when *tests_by_key*
        supplies attribution (pytest), otherwise the PIDs that made the calls
        (CLI). Returns the empty string when there is nothing to summarise.
        """
        if not violations:
            return ""

        col_addr = 30
        col_count = 6
        label = "TESTS" if tests_by_key is not None else "PIDS"

        header = f"{'ADDR:PORT':<{col_addr}} {'COUNT':>{col_count}}  {label}"
        sep = f"{'-' * col_addr} {'-' * col_count}  {'-' * 24}"

        buf = io.StringIO()
        buf.write(_paint(header, _BOLD, color) + "\n")
        buf.write(sep + "\n")
        # Loudest destination first; ties broken by address for stable output.
        for v in sorted(violations, key=lambda x: (-x.count, x._addr_str())):
            if tests_by_key is not None:
                third = ", ".join(sorted(tests_by_key.get(v.key, set()))) or "-"
            else:
                third = ", ".join(str(pid) for pid in sorted(v.pids))
            addr = _paint(f"{v._addr_str():<{col_addr}}", _RED, color)
            buf.write(f"{addr} {v.count:>{col_count}}  {third}\n")

        result = buf.getvalue()
        if stream is not None:
            stream.write(result)
        return result

    @staticmethod
    def format_suggestions(
        violations: list[Violation],
        stream: TextIO | None = None,
        color: bool = False,
    ) -> str:
        """Emit allowlist YAML that would permit each violating connection.

        Output is a bare rule list, ready to paste under the ``allowlist:`` key of
        a netaudit config. Rules are scoped as narrowly as the event allows —
        exact address and, where the connection had one, exact port.
        """
        if not violations:
            return ""

        buf = io.StringIO()
        buf.write(_paint("# Suggested rules to allow these connections:", _BOLD, color) + "\n")
        for v in sorted(violations, key=lambda x: (-x.count, x._addr_str())):
            if v.family == "AF_UNIX":
                buf.write(f'  - name: "allow {v.addr}"\n')
                buf.write("    family: AF_UNIX\n")
                buf.write(f"    path_glob: {v.addr}\n")
                continue
            # Quote IPv6 literals — bare colons are not valid YAML scalars here.
            addr = f'"{v.addr}"' if v.family == "AF_INET6" else str(v.addr)
            buf.write(f'  - name: "allow {v._addr_str()}"\n')
            buf.write(f"    family: {v.family}\n")
            buf.write(f"    addr: {addr}\n")
            if v.port is not None:
                buf.write(f"    port: {v.port}\n")

        result = buf.getvalue()
        if stream is not None:
            stream.write(result)
        return result

    @staticmethod
    def format_suggestions_with_evidence(
        destinations: list[MergedDestination],
        stream: TextIO | None = None,
        color: bool = False,
    ) -> str:
        """Emit allowlist YAML annotated with the evidence behind each rule.

        A combined rule set drawn from many runs makes it easy to approve egress
        nobody looked at. Every rule therefore carries how many connections were
        seen, how many of the supplied reports saw it, which ones, and — where
        the pytest plugin preserved it — the tests responsible.

        The evidence lives in comments, so a copy-paste into an allowlist keeps
        it while the YAML still parses.
        """
        if not destinations:
            return ""

        total_reports = destinations[0].total_reports
        total_calls = sum(d.count for d in destinations)
        run_noun = "run" if total_reports == 1 else "runs"
        call_noun = "connection" if total_calls == 1 else "connections"

        buf = io.StringIO()
        header = (
            f"# Undeclared egress observed across {total_reports} {run_noun}"
            f" — {total_calls} {call_noun}.\n"
            "# These are destinations your allowlist does not permit. Each is a question,\n"
            "# not a recommendation: decide which belong before committing any of them."
        )
        buf.write(_paint(header, _BOLD, color) + "\n")

        # Volume is a default ordering, not a ranking by how justified a rule is.
        for d in sorted(destinations, key=lambda x: (-x.count, str(x.addr))):
            seen = len(d.reports)
            external = d.is_external

            # Externality is the trigger; the run pattern only describes it.
            # Flagging rarity alone would call out the benign one-off and stay
            # silent on something beaconing to the internet on every run.
            if external:
                if total_reports == 1:
                    note = "! external host — never declared"
                elif seen == total_reports:
                    note = (
                        f"! external host reached on every run"
                        f" ({seen}/{total_reports}) — never declared"
                    )
                else:
                    note = (
                        f"! external host reached in {seen} of {total_reports} runs"
                        " — never declared"
                    )
                buf.write(_paint(f"# {note}", _RED, color) + "\n")

            call_word = "call" if d.count == 1 else "calls"
            evidence = f"{d.count} {call_word} · {seen}/{total_reports} runs"
            evidence += " · external" if external else " · internal"
            evidence += " · " + ", ".join(d.reports)
            if d.tests:
                evidence += " · tests: " + ", ".join(sorted(d.tests))

            addr_str = f"{d.addr}:{d.port}" if d.port is not None else str(d.addr)
            addr = f'"{d.addr}"' if d.family == "AF_INET6" else str(d.addr)
            buf.write(f'  - name: "allow {addr_str}"\n')
            buf.write(f"    # {evidence}\n")
            buf.write(f"    family: {d.family}\n")
            if d.family == "AF_UNIX":
                buf.write(f"    path_glob: {d.addr}\n")
                continue
            buf.write(f"    addr: {addr}\n")
            if d.port is not None:
                buf.write(f"    port: {d.port}\n")

        result = buf.getvalue()
        if stream is not None:
            stream.write(result)
        return result

    @staticmethod
    def format_json(
        violations: list[Violation],
        events: list[ConnectEvent] | None = None,
        allowlist: AllowList | None = None,
        include_allowed: bool = False,
        tests_by_key: dict[_ViolationKey, set[str]] | None = None,
        suggest_rules: bool = False,
        run: dict[str, Any] | None = None,
    ) -> str:
        """Render violations (and optionally all events) as a JSON string."""
        violations_data = [
            {
                "family": v.family,
                "addr": v.addr,
                "port": v.port,
                "count": v.count,
                "pids": sorted(v.pids),
            }
            for v in violations
        ]
        by_destination: list[dict[str, Any]] = []
        for v in sorted(violations, key=lambda x: (-x.count, x._addr_str())):
            dest: dict[str, Any] = {
                "family": v.family,
                "addr": v.addr,
                "port": v.port,
                "count": v.count,
                "pids": sorted(v.pids),
            }
            if tests_by_key is not None:
                dest["tests"] = sorted(tests_by_key.get(v.key, set()))
            by_destination.append(dest)

        data: dict[str, Any] = {
            "version": REPORT_VERSION,
            "violations": violations_data,
            "summary": {"total": len(violations), "by_destination": by_destination},
        }
        if run is not None:
            data["run"] = run
        if suggest_rules:
            data["suggested_rules"] = [
                {
                    k: val
                    for k, val in (
                        ("name", f"allow {v._addr_str()}"),
                        ("family", v.family),
                        ("addr", v.addr),
                        ("port", v.port),
                    )
                    if val is not None
                }
                for v in sorted(violations, key=lambda x: (-x.count, x._addr_str()))
            ]
        if include_allowed and events is not None and allowlist is not None:
            annotated = []
            for event in events:
                rule = allowlist.match(event)
                entry: dict[str, Any] = {
                    "family": event.family,
                    "addr": event.addr,
                    "port": event.port,
                    "status": "allowed" if rule is not None else "violation",
                    "rule": rule.name if rule is not None else None,
                }
                annotated.append(entry)
            data["events"] = annotated
        return json.dumps(data, indent=2)
