"""Violation grouping and human-readable reporting."""

from __future__ import annotations

import io
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, TextIO

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent

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
    def format_json(
        violations: list[Violation],
        events: list[ConnectEvent] | None = None,
        allowlist: AllowList | None = None,
        include_allowed: bool = False,
        tests_by_key: dict[_ViolationKey, set[str]] | None = None,
        suggest_rules: bool = False,
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
            "violations": violations_data,
            "summary": {"total": len(violations), "by_destination": by_destination},
        }
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
