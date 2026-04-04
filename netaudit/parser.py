"""strace output parser — produces ConnectEvent dataclasses from raw lines."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# Matches a complete connect() line, e.g.:
#   PID TS connect(fd, {sa_family=AF_INET, sin_addr=inet_addr("1.2.3.4"),
#                        sin_port=htons(443)}, 16) = -1 EINPROGRESS (...)
#   PID TS connect(fd, {sa_family=AF_UNIX, sun_path="/run/foo.sock"}, 20) = 0
#   PID TS connect(fd, {sa_family=AF_NETLINK, ...}, 12) = 0
_HEADER = r"(?P<pid>\d+)\s+(?P<ts>\d+:\d+:\d+\.\d+)\s+"
_RESULT = r"\)\s*=\s*(?P<result>-?\d+)"

_RE_INET = re.compile(
    _HEADER
    + r"connect\(\d+,\s*\{sa_family=(?P<family>AF_INET),"
    + r'\s*sin_addr=inet_addr\("(?P<addr>[^"]+)"\),'
    + r"\s*sin_port=htons\((?P<port>\d+)\)"
    + r".*?"
    + _RESULT,
)

_RE_INET6 = re.compile(
    _HEADER
    + r"connect\(\d+,\s*\{sa_family=(?P<family>AF_INET6),"
    + r'\s*sin6_addr=inet_pton\(AF_INET6,\s*"(?P<addr>[^"]+)"\),'
    + r"\s*sin6_port=htons\((?P<port>\d+)\)"
    + r".*?"
    + _RESULT,
)

_RE_UNIX = re.compile(
    _HEADER
    + r'connect\(\d+,\s*\{sa_family=(?P<family>AF_UNIX),\s*sun_path="(?P<path>[^"]+)"'
    + r".*?"
    + _RESULT,
)

# AF_UNIX abstract namespace: sun_path=@"..."  or  sun_path="\0..."
_RE_UNIX_ABSTRACT = re.compile(
    _HEADER
    + r"connect\(\d+,\s*\{sa_family=(?P<family>AF_UNIX),\s*sun_path=@?\"(?P<path>[^\"]+)\""
    + r".*?"
    + _RESULT,
)

_RE_NETLINK = re.compile(
    _HEADER + r"connect\(\d+,\s*\{sa_family=(?P<family>AF_NETLINK)" + r".*?" + _RESULT,
)

# Resumed lines: "12345 12:34:56.789 <... connect resumed>) = 0"
_RE_RESUMED = re.compile(
    r"(?P<pid>\d+)\s+(?P<ts>\d+:\d+:\d+\.\d+)\s+<\.\.\.\s+connect\s+resumed>" + r".*?" + _RESULT,
)


def _normalise_result(result: int, raw_line: str) -> int:
    """Return 0 for EINPROGRESS (non-blocking connect in flight), else result."""
    if result == -1 and "EINPROGRESS" in raw_line:
        return 0
    return result


def _parse_ts(ts: str) -> float:
    """Convert HH:MM:SS.ffffff to seconds-since-midnight float."""
    h, m, rest = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(rest)


# ---------------------------------------------------------------------------
# Data type
# ---------------------------------------------------------------------------


@dataclass
class ConnectEvent:
    pid: int
    timestamp: float
    family: str
    addr: str | None  # IP address or socket path; None for netlink
    port: int | None  # TCP/UDP port; None for unix/netlink
    result: int  # 0 = success; negative errno value
    raw_line: str


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class StraceParser:
    """Parse strace -e trace=connect -tt -f output into ConnectEvents."""

    def parse_line(self, line: str) -> ConnectEvent | None:
        """Return a ConnectEvent for *line*, or None if unrecognised."""
        line = line.rstrip()

        # Skip unfinished lines (the resumed counterpart carries the result)
        if "<unfinished ...>" in line:
            return None

        # Resumed lines — we can extract pid/ts/result but not family/addr
        m = _RE_RESUMED.match(line)
        if m:
            return ConnectEvent(
                pid=int(m.group("pid")),
                timestamp=_parse_ts(m.group("ts")),
                family="AF_UNKNOWN",
                addr=None,
                port=None,
                result=int(m.group("result")),
                raw_line=line,
            )

        # AF_INET
        m = _RE_INET.match(line)
        if m:
            return ConnectEvent(
                pid=int(m.group("pid")),
                timestamp=_parse_ts(m.group("ts")),
                family=m.group("family"),
                addr=m.group("addr"),
                port=int(m.group("port")),
                result=_normalise_result(int(m.group("result")), line),
                raw_line=line,
            )

        # AF_INET6
        m = _RE_INET6.match(line)
        if m:
            return ConnectEvent(
                pid=int(m.group("pid")),
                timestamp=_parse_ts(m.group("ts")),
                family=m.group("family"),
                addr=m.group("addr"),
                port=int(m.group("port")),
                result=_normalise_result(int(m.group("result")), line),
                raw_line=line,
            )

        # AF_UNIX (named path)
        m = _RE_UNIX.match(line)
        if m:
            return ConnectEvent(
                pid=int(m.group("pid")),
                timestamp=_parse_ts(m.group("ts")),
                family=m.group("family"),
                addr=m.group("path"),
                port=None,
                result=int(m.group("result")),
                raw_line=line,
            )

        # AF_NETLINK
        m = _RE_NETLINK.match(line)
        if m:
            return ConnectEvent(
                pid=int(m.group("pid")),
                timestamp=_parse_ts(m.group("ts")),
                family=m.group("family"),
                addr=None,
                port=None,
                result=int(m.group("result")),
                raw_line=line,
            )

        return None

    def parse_stream(self, lines: Iterable[str]) -> list[ConnectEvent]:
        """Parse all lines, returning only recognised ConnectEvents."""
        events: list[ConnectEvent] = []
        for line in lines:
            event = self.parse_line(line)
            if event is not None:
                events.append(event)
        return events
