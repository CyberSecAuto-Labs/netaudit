"""strace output parser — produces ConnectEvent dataclasses from raw lines."""

from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable

__all__ = ["ConnectEvent", "StraceParser"]

# Lines longer than this are skipped — they can't be valid strace output and
# would trigger catastrophic regex backtracking on malformed input.
_MAX_LINE_LEN = 4096

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
    + r"connect\(\d+,\s*\{sa_family=(?P<family>AF_INET),(?P<struct>[^}]*)\}"
    + r".*?"
    + _RESULT,
)
# Field extractors for AF_INET struct — order varies across strace versions
_RE_INET_ADDR = re.compile(r'sin_addr=inet_addr\("(?P<addr>[^"]+)"\)')
_RE_INET_PORT = re.compile(r"sin_port=htons\((?P<port>\d+)\)")

_RE_INET6 = re.compile(
    _HEADER
    + r"connect\(\d+,\s*\{sa_family=(?P<family>AF_INET6),(?P<struct>[^}]*)\}"
    + r".*?"
    + _RESULT,
)
# Field extractors for AF_INET6 struct — order varies across strace versions
_RE_INET6_ADDR = re.compile(r'sin6_addr=inet_pton\(AF_INET6,\s*"(?P<addr>[^"]+)"\)')
_RE_INET6_PORT = re.compile(r"sin6_port=htons\((?P<port>\d+)\)")

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

# A line that opens a traced connect() call, whatever it goes on to say. Used
# to notice the ones no matcher below could read, rather than dropping them.
#
# The pid and timestamp are optional here even though every matcher above
# requires them: a log captured without ``-f`` or ``-tt`` yields no events at
# all, and the whole point of this regex is that such a log must not read as a
# clean run. The anchor at the start is what keeps a ``connect(`` inside a
# traced write payload from being mistaken for a syscall.
# The descriptor ``-y`` decorates with the socket it names, which netaudit does
# not ask for but an offline log may carry.
_FD = r"\d+(?:<[^>]*>)?"
_RE_CONNECT_LINE = re.compile(
    # The pid forms are alternatives, not independent options: no strace line
    # carries both a bracketed pid and a bare one.
    r"\s*(?:\[pid\s+\d+\]\s+|\d+\s+)?(?:\d+:\d+:\d+\.\d+\s+)?connect\(" + _FD + r","
)

# A first argument that reached no destination. AF_UNSPEC is how a socket is
# *dis*connected, and a NULL sockaddr never made it into the kernel; neither is
# egress, so neither is a connect netaudit failed to read.
_RE_NO_DESTINATION = re.compile(r"\s*(?:NULL|\{sa_family=AF_UNSPEC\b)")

# strace prints the bare pointer when it could not read the sockaddr, which
# only happens for a call the kernel refused for the same reason. Paired with
# the failure so that a readable-but-unrecognised struct is never let through.
_RE_UNREAD_POINTER = re.compile(r"\s*0x[0-9a-fA-F]+\b")
# Anchored at the end of the line, where strace writes the syscall's result.
# Searching the whole line would let a descriptor decorated by ``-y`` — whose
# text is the socket's name, and so arbitrary — claim the call failed.
_RE_FAILED = re.compile(r"\)\s*=\s*-\d+(?:\s+[A-Z][A-Z0-9_]*(?:\s+\([^)]*\))?)?\s*$")


def _is_unreadable_connect(line: str) -> bool:
    """Whether *line* is a connect() call whose destination went unread."""
    opening = _RE_CONNECT_LINE.match(line)
    if opening is None:
        return False
    if _RE_NO_DESTINATION.match(line, opening.end()) is not None:
        return False
    if _RE_UNREAD_POINTER.match(line, opening.end()) is not None:
        return _RE_FAILED.search(line) is None  # only a failure explains an unread pointer
    return True


# Resumed lines: "12345 12:34:56.789 <... connect resumed>) = 0"
_RE_RESUMED = re.compile(
    r"(?P<pid>\d+)\s+(?P<ts>\d+:\d+:\d+\.\d+)\s+<\.\.\.\s+connect\s+resumed>" + r".*?" + _RESULT,
)


# strace splits a syscall across two lines when it blocks and another tracee's
# event needs printing first. The destination is written on the first half and
# the result on the second.
_UNFINISHED_MARKER = "<unfinished ...>"


def _as_complete_call(line: str) -> str:
    """Rewrite an ``<unfinished ...>`` line so the ordinary matchers can read it.

    Only the trailing ``) = <result>`` is missing; everything that identifies
    the destination is already there. A result of 0 stands in for "issued, not
    yet returned" — :func:`parse_stream` overwrites it with the real value when
    the resumed half arrives.
    """
    head = line[: line.index(_UNFINISHED_MARKER)].rstrip()
    return f"{head}) = 0"


def _normalise_result(result: int, raw_line: str) -> int:
    """Return 0 for EINPROGRESS (non-blocking connect in flight), else result."""
    if result == -1 and "EINPROGRESS" in raw_line:
        return 0
    return result


# How an abstract-namespace AF_UNIX name opens *inside* the quoted sun_path:
# a NUL, which strace escapes as the two characters "\0". The "@" strace also
# uses sits outside the quotes, so it never appears here — and a pathname
# socket may legitimately be called "@name", which must still be canonicalised
# as the relative path it is.
#
# Abstract names are opaque bytes: "/", "." and ".." mean nothing in them, so
# collapsing one would rename it.
_ABSTRACT_MARKERS = ("\\0", "\0")


def _canonical_path(path: str) -> str:
    """Strip control characters from an AF_UNIX path and collapse ``.`` and ``..``.

    strace renders binary bytes as \\xNN escape sequences, so the string we
    receive is already printable ASCII.  However, strace on some kernels emits
    raw control characters for very short paths; remove them defensively so
    downstream code doesn't choke on non-printable content.

    The traversal is collapsed because the kernel resolves it before the socket
    is reached: ``/run/gvmd/../../tmp/x.sock`` *is* ``/tmp/x.sock``, and an
    allowlist rule scoped to ``/run/gvmd/`` must not be made to permit it by the
    very process it is meant to constrain. ``posixpath`` rather than
    ``os.path``: the trace describes Linux paths whatever host reads it.

    Symlinks are left alone — the trace does not record what the filesystem
    held at the time, so there is nothing to resolve them against. A rule
    scoped to a directory therefore still permits a socket reached through a
    symlink out of it.

    Abstract-namespace names are returned untouched: they are opaque bytes
    rather than paths, and collapsing a ``..`` inside one would rename it. A
    pathname socket called ``@name`` is *not* one of those — the ``@`` strace
    prints for an abstract socket is outside the quotes.
    """
    if path.startswith(_ABSTRACT_MARKERS):
        return path
    cleaned = "".join(ch for ch in path if not unicodedata.category(ch).startswith("C"))
    if not cleaned:
        return cleaned
    collapsed = posixpath.normpath(cleaned)
    # POSIX leaves a leading "//" implementation-defined and normpath keeps it;
    # Linux resolves it as "/", so a rule scoped to /run/ must still apply.
    return "/" + collapsed.lstrip("/") if collapsed.startswith("//") else collapsed


def _port_or_none(text: str) -> int | None:
    """The port *text* names, or None when no socket could carry it.

    ``htons`` is 16-bit, so a real trace never holds anything else. A forged or
    corrupted one might, and an event built from it would be written into a
    report that ``load_report`` then refuses — so it is treated as a connect
    that could not be read, and counted as such.
    """
    port = int(text)
    return port if 0 <= port <= 65535 else None


def _parse_ts(ts: str) -> float:
    """Convert HH:MM:SS.ffffff to seconds-since-midnight float."""
    h, m, rest = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(rest)


# ---------------------------------------------------------------------------
# Data type
# ---------------------------------------------------------------------------


@dataclass
class ConnectEvent:
    """One observed ``connect()`` syscall.

    This is the unit every other part of netaudit works in: the parser
    produces them, allowlist rules match against them, and the reporter
    groups them into violations.

    ``result`` is 0 on success or a negative errno. A non-blocking connect
    still in flight (``EINPROGRESS``) is normalised to 0 — it egressed.
    """

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

    def __init__(self) -> None:
        self.unparsed = 0
        """connect() lines this parser could not read.

        A destination netaudit cannot read is not a destination it can judge,
        and a trace it reads as empty is indistinguishable from a clean run.
        Callers must treat a non-zero count as a failed audit rather than
        reporting on what did parse.

        :meth:`parse_line` adds to it; :meth:`parse_stream` resets it first, so
        each stream is judged on its own.
        """

    def parse_line(self, line: str) -> ConnectEvent | None:
        """Return a ConnectEvent for *line*, or None if unrecognised.

        A line ending in ``<unfinished ...>`` yields an event for the connect it
        describes: the destination is on that half, and discarding it would lose
        the egress entirely. Use :meth:`parse_stream` to pair it with the
        ``resumed`` half and pick up the real result.

        A line that opens a ``connect(`` but yields nothing adds to
        :attr:`unparsed` — returning None alone would let a caller read it as
        "not a connect at all".
        """
        line = line.rstrip()

        # Guard against extremely long lines (e.g. from corrupted output files)
        # before running regexes that could backtrack catastrophically.
        if len(line) > _MAX_LINE_LEN:
            event = None
        elif _UNFINISHED_MARKER in line:
            event = self._parse_call(_as_complete_call(line))
            if event is not None:
                event.raw_line = line
        else:
            event = self._parse_call(line)

        if event is None and _is_unreadable_connect(line):
            self.unparsed += 1
        return event

    def _parse_call(self, line: str) -> ConnectEvent | None:
        """Match *line* against every known connect() shape."""
        # Resumed lines — we can extract pid/ts/result but not family/addr
        m = _RE_RESUMED.match(line)
        if m:
            return ConnectEvent(
                pid=int(m.group("pid")),
                timestamp=_parse_ts(m.group("ts")),
                family="AF_UNKNOWN",
                addr=None,
                port=None,
                result=_normalise_result(int(m.group("result")), line),
                raw_line=line,
            )

        # AF_INET — extract addr/port from struct body (field order varies by strace version)
        m = _RE_INET.match(line)
        if m:
            struct = m.group("struct")
            addr_m = _RE_INET_ADDR.search(struct)
            port_m = _RE_INET_PORT.search(struct)
            port = _port_or_none(port_m.group("port")) if port_m else None
            if addr_m and port is not None:
                return ConnectEvent(
                    pid=int(m.group("pid")),
                    timestamp=_parse_ts(m.group("ts")),
                    family=m.group("family"),
                    addr=addr_m.group("addr"),
                    port=port,
                    result=_normalise_result(int(m.group("result")), line),
                    raw_line=line,
                )

        # AF_INET6 — extract addr/port from struct body (field order varies by strace version)
        m = _RE_INET6.match(line)
        if m:
            struct = m.group("struct")
            addr_m6 = _RE_INET6_ADDR.search(struct)
            port_m6 = _RE_INET6_PORT.search(struct)
            port6 = _port_or_none(port_m6.group("port")) if port_m6 else None
            if addr_m6 and port6 is not None:
                return ConnectEvent(
                    pid=int(m.group("pid")),
                    timestamp=_parse_ts(m.group("ts")),
                    family=m.group("family"),
                    addr=addr_m6.group("addr"),
                    port=port6,
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
                addr=_canonical_path(m.group("path")),
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
        """Parse all lines, returning one event per connect() call.

        A syscall strace split across two lines is rejoined into a single
        event: the destination comes from the ``<unfinished ...>`` half and the
        result from the ``resumed`` half. Correlation is per-pid, since a
        thread can only have one connect in flight at a time.

        Halves without a counterpart are kept rather than dropped — a truncated
        trace is still evidence that the connect was attempted.

        Lines that open a ``connect(`` no matcher understood are counted in
        :attr:`unparsed`, which is reset on every call.
        """
        events: list[ConnectEvent] = []
        # pid -> index in *events* of a connect awaiting its result.
        pending: dict[int, int] = {}
        self.unparsed = 0

        for line in lines:
            event = self.parse_line(line)
            if event is None:
                continue

            if event.family == "AF_UNKNOWN":
                index = pending.pop(event.pid, None)
                if index is not None:
                    events[index].result = event.result
                    continue
                # No pending call: the trace started mid-syscall. Keep it.
                events.append(event)
                continue

            if _UNFINISHED_MARKER in event.raw_line:
                pending[event.pid] = len(events)
            events.append(event)

        return events
