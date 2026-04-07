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
    def format_json(violations: list[Violation]) -> str:
        """Render violations as a JSON string."""
        data: dict[str, Any] = {
            "violations": [
                {
                    "family": v.family,
                    "addr": v.addr,
                    "port": v.port,
                    "count": v.count,
                    "pids": sorted(v.pids),
                }
                for v in violations
            ],
            "summary": {"total": len(violations)},
        }
        return json.dumps(data, indent=2)
