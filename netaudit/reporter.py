"""Violation grouping and human-readable reporting."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from typing import Any, TextIO

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent

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
    def format(violations: list[Violation], stream: TextIO | None = None) -> str:
        """Render violations as a human-readable box. Returns the string and
        optionally writes it to *stream*."""
        buf = io.StringIO()
        if not violations:
            buf.write("netaudit: no violations\n")
        else:
            count = len(violations)
            noun = "violation" if count == 1 else "violations"
            border = "=" * 60
            buf.write(f"\n{border}\n")
            buf.write(f"  netaudit: {count} {noun} detected\n")
            buf.write(f"{border}\n")
            for v in violations:
                buf.write(f"  {v}\n")
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
            row = (
                f"{event.family:<{col_family}} {addr:<{col_addr}}"
                f" {status:<{col_status}} {rule_name}"
            )
            buf.write(row + "\n")

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
        data: dict[str, Any] = {
            "violations": violations_data,
            "summary": {"total": len(violations)},
        }
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
