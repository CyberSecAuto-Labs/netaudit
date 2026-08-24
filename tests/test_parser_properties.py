"""Property-based tests for the strace parser.

These complement the hand-written cases in ``test_parser.py``: rather than
pinning known lines, they assert invariants that must hold for *any* input.
The parser reads attacker-adjacent data — a corrupted or truncated trace file
must never take the tool down.
"""

from __future__ import annotations

import ipaddress

from hypothesis import assume, given
from hypothesis import strategies as st

from netaudit.parser import _MAX_LINE_LEN, ConnectEvent, StraceParser

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

pids = st.integers(min_value=0, max_value=2**22)
ports = st.integers(min_value=0, max_value=65535)
results = st.integers(min_value=-4095, max_value=0)

timestamps = st.builds(
    "{:02d}:{:02d}:{:02d}.{:06d}".format,
    st.integers(min_value=0, max_value=23),
    st.integers(min_value=0, max_value=59),
    st.integers(min_value=0, max_value=59),
    st.integers(min_value=0, max_value=999999),
)

ipv4_addrs = st.ip_addresses(v=4).map(str)
ipv6_addrs = st.ip_addresses(v=6).map(str)

# Unix paths: printable, no quote or brace, since strace escapes those.
unix_paths = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126, blacklist_characters='"{}\\'),
    min_size=1,
    max_size=80,
)


def _inet_line(pid: int, ts: str, addr: str, port: int, result: int) -> str:
    return (
        f"{pid} {ts} connect(3, {{sa_family=AF_INET, "
        f'sin_port=htons({port}), sin_addr=inet_addr("{addr}")}}, 16) = {result}'
    )


def _inet6_line(pid: int, ts: str, addr: str, port: int, result: int) -> str:
    return (
        f"{pid} {ts} connect(3, {{sa_family=AF_INET6, "
        f'sin6_port=htons({port}), sin6_addr=inet_pton(AF_INET6, "{addr}")}}, 28) = {result}'
    )


# ---------------------------------------------------------------------------
# Robustness — the parser must never raise
# ---------------------------------------------------------------------------


class TestParserNeverRaises:
    @given(st.text())
    def test_arbitrary_text_is_parsed_or_rejected(self, line: str) -> None:
        result = StraceParser().parse_line(line)
        assert result is None or isinstance(result, ConnectEvent)

    @given(st.binary(max_size=512).map(lambda b: b.decode("latin-1")))
    def test_arbitrary_bytes_decoded_as_text_do_not_crash(self, line: str) -> None:
        StraceParser().parse_line(line)

    @given(
        pid=pids,
        ts=timestamps,
        addr=ipv4_addrs,
        port=ports,
        result=results,
        junk=st.text(max_size=200),
    )
    def test_a_valid_line_with_trailing_junk_does_not_crash(
        self, pid: int, ts: str, addr: str, port: int, result: int, junk: str
    ) -> None:
        assume("\n" not in junk)
        StraceParser().parse_line(_inet_line(pid, ts, addr, port, result) + junk)

    @given(st.text(alphabet='ab{}()="\\, ', min_size=1, max_size=300))
    def test_syntax_soup_does_not_crash(self, line: str) -> None:
        StraceParser().parse_line(line)


# ---------------------------------------------------------------------------
# Round-tripping — a rendered line parses back to what produced it
# ---------------------------------------------------------------------------


class TestInetRoundTrip:
    @given(pid=pids, ts=timestamps, addr=ipv4_addrs, port=ports, result=results)
    def test_ipv4_fields_survive_the_round_trip(
        self, pid: int, ts: str, addr: str, port: int, result: int
    ) -> None:
        event = StraceParser().parse_line(_inet_line(pid, ts, addr, port, result))
        assert event is not None
        assert event.pid == pid
        assert event.family == "AF_INET"
        assert event.addr == addr
        assert event.port == port
        assert event.result == result

    @given(pid=pids, ts=timestamps, addr=ipv6_addrs, port=ports, result=results)
    def test_ipv6_fields_survive_the_round_trip(
        self, pid: int, ts: str, addr: str, port: int, result: int
    ) -> None:
        event = StraceParser().parse_line(_inet6_line(pid, ts, addr, port, result))
        assert event is not None
        assert event.family == "AF_INET6"
        assert ipaddress.IPv6Address(event.addr) == ipaddress.IPv6Address(addr)
        assert event.port == port

    @given(pid=pids, ts=timestamps, addr=ipv4_addrs, port=ports, result=results)
    def test_parsed_address_is_always_a_valid_ip(
        self, pid: int, ts: str, addr: str, port: int, result: int
    ) -> None:
        """Downstream allowlist rules feed addr straight into ipaddress."""
        event = StraceParser().parse_line(_inet_line(pid, ts, addr, port, result))
        assert event is not None and event.addr is not None
        ipaddress.ip_address(event.addr)

    @given(pid=pids, ts=timestamps, path=unix_paths)
    def test_unix_path_survives_the_round_trip(self, pid: int, ts: str, path: str) -> None:
        line = f'{pid} {ts} connect(3, {{sa_family=AF_UNIX, sun_path="{path}"}}, 20) = 0'
        event = StraceParser().parse_line(line)
        assert event is not None
        assert event.family == "AF_UNIX"
        assert event.addr == path


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


class TestParserInvariants:
    @given(pid=pids, ts=timestamps, addr=ipv4_addrs, port=ports)
    def test_timestamp_is_within_a_day(self, pid: int, ts: str, addr: str, port: int) -> None:
        event = StraceParser().parse_line(_inet_line(pid, ts, addr, port, 0))
        assert event is not None
        assert 0.0 <= event.timestamp < 86400.0

    @given(pid=pids, ts=timestamps, addr=ipv4_addrs, port=ports)
    def test_einprogress_is_reported_as_success(
        self, pid: int, ts: str, addr: str, port: int
    ) -> None:
        """A non-blocking connect in flight is not a failure — it still egresses."""
        line = _inet_line(pid, ts, addr, port, -1) + " EINPROGRESS (Operation now in progress)"
        event = StraceParser().parse_line(line)
        assert event is not None
        assert event.result == 0

    @given(
        pid=pids,
        ts=timestamps,
        addr=ipv4_addrs,
        port=ports,
        pad=st.integers(min_value=1, max_value=500),
    )
    def test_overlong_lines_are_skipped(
        self, pid: int, ts: str, addr: str, port: int, pad: int
    ) -> None:
        line = _inet_line(pid, ts, addr, port, 0)
        assume(len(line) <= _MAX_LINE_LEN)
        padded = line + " " * (_MAX_LINE_LEN - len(line)) + "x" * pad
        assert StraceParser().parse_line(padded) is None

    @given(st.lists(st.text(max_size=200), max_size=30))
    def test_stream_keeps_exactly_the_recognised_lines(self, lines: list[str]) -> None:
        parser = StraceParser()
        expected = [e for e in (parser.parse_line(ln) for ln in lines) if e is not None]
        assert parser.parse_stream(lines) == expected

    @given(
        st.lists(
            st.tuples(pids, timestamps, ipv4_addrs, ports, results).map(lambda t: _inet_line(*t)),
            max_size=20,
        )
    )
    def test_stream_preserves_order_and_count(self, lines: list[str]) -> None:
        events = StraceParser().parse_stream(lines)
        assert len(events) == len(lines)
        assert [e.raw_line for e in events] == lines
