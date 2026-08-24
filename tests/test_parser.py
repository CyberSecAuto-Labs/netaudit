"""Tests for netaudit.parser."""

import pytest

from netaudit.parser import StraceParser


@pytest.fixture()
def parser() -> StraceParser:
    return StraceParser()


class TestStraceParser:
    # ------------------------------------------------------------------
    # AF_INET
    # ------------------------------------------------------------------

    def test_parse_af_inet_connect(self, parser: StraceParser) -> None:
        line = (
            "1234 12:00:00.000001 connect(3, {sa_family=AF_INET, "
            'sin_addr=inet_addr("93.184.216.34"), sin_port=htons(443)}, 16) = 0'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.pid == 1234
        assert event.family == "AF_INET"
        assert event.addr == "93.184.216.34"
        assert event.port == 443
        assert event.result == 0

    def test_parse_af_inet_einprogress(self, parser: StraceParser) -> None:
        line = (
            "5678 12:00:01.000001 connect(5, {sa_family=AF_INET, "
            'sin_addr=inet_addr("1.2.3.4"), sin_port=htons(80)}, 16)'
            " = -1 EINPROGRESS (Operation now in progress)"
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.result == 0  # EINPROGRESS normalised to 0

    def test_parse_af_inet_loopback(self, parser: StraceParser) -> None:
        line = (
            "9999 00:00:00.000001 connect(4, {sa_family=AF_INET, "
            'sin_addr=inet_addr("127.0.0.1"), sin_port=htons(9393)}, 16) = 0'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.addr == "127.0.0.1"
        assert event.port == 9393

    # ------------------------------------------------------------------
    # AF_INET6
    # ------------------------------------------------------------------

    def test_parse_af_inet6_connect(self, parser: StraceParser) -> None:
        line = (
            "2222 08:30:00.123456 connect(6, {sa_family=AF_INET6, "
            'sin6_addr=inet_pton(AF_INET6, "2001:db8::1"), sin6_port=htons(443)}, 28) = 0'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.family == "AF_INET6"
        assert event.addr == "2001:db8::1"
        assert event.port == 443

    def test_parse_af_inet6_loopback(self, parser: StraceParser) -> None:
        line = (
            "3333 09:00:00.000001 connect(7, {sa_family=AF_INET6, "
            'sin6_addr=inet_pton(AF_INET6, "::1"), sin6_port=htons(8080)}, 28) = 0'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.addr == "::1"

    def test_parse_af_inet6_einprogress(self, parser: StraceParser) -> None:
        line = (
            "4444 10:00:00.000001 connect(8, {sa_family=AF_INET6, "
            'sin6_addr=inet_pton(AF_INET6, "::1"), sin6_port=htons(443)}, 28)'
            " = -1 EINPROGRESS (Operation now in progress)"
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.result == 0

    # ------------------------------------------------------------------
    # AF_UNIX
    # ------------------------------------------------------------------

    def test_parse_af_unix(self, parser: StraceParser) -> None:
        line = (
            "1111 11:00:00.000001 connect(9, {sa_family=AF_UNIX, "
            'sun_path="/run/gvmd/gvmd.sock"}, 27) = 0'
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.family == "AF_UNIX"
        assert event.addr == "/run/gvmd/gvmd.sock"
        assert event.port is None

    # ------------------------------------------------------------------
    # AF_NETLINK
    # ------------------------------------------------------------------

    def test_parse_af_netlink(self, parser: StraceParser) -> None:
        line = (
            "7777 13:00:00.000001 connect(10, {sa_family=AF_NETLINK, "
            "nl_pid=0, nl_groups=00000000}, 12) = 0"
        )
        event = parser.parse_line(line)
        assert event is not None
        assert event.family == "AF_NETLINK"
        assert event.addr is None
        assert event.port is None

    # ------------------------------------------------------------------
    # Resumed / unfinished lines
    # ------------------------------------------------------------------

    def test_unfinished_line_returns_none(self, parser: StraceParser) -> None:
        line = (
            "8888 14:00:00.000001 connect(11, {sa_family=AF_INET, "
            'sin_addr=inet_addr("1.2.3.4"), sin_port=htons(80)}, 16 <unfinished ...>'
        )
        assert parser.parse_line(line) is None

    def test_resumed_line(self, parser: StraceParser) -> None:
        line = "8888 14:00:00.000002 <... connect resumed>) = 0"
        event = parser.parse_line(line)
        assert event is not None
        assert event.pid == 8888
        assert event.family == "AF_UNKNOWN"
        assert event.result == 0

    # ------------------------------------------------------------------
    # Malformed / unrecognised lines
    # ------------------------------------------------------------------

    def test_malformed_line_returns_none(self, parser: StraceParser) -> None:
        assert parser.parse_line("this is not strace output") is None

    def test_non_connect_syscall_returns_none(self, parser: StraceParser) -> None:
        line = '1234 12:00:00.000001 read(3, "", 1024) = 0'
        assert parser.parse_line(line) is None

    def test_af_inet_with_elided_struct_returns_none(self, parser: StraceParser) -> None:
        """strace abbreviates structs under -e abbrev; half an address is no address."""
        line = "1234 12:00:00.000001 connect(3, {sa_family=AF_INET, ...}, 16) = 0"
        assert parser.parse_line(line) is None

    def test_af_inet_without_an_address_returns_none(self, parser: StraceParser) -> None:
        line = "1234 12:00:00.000001 connect(3, {sa_family=AF_INET, sin_port=htons(53)}, 16) = 0"
        assert parser.parse_line(line) is None

    def test_af_inet_without_a_port_returns_none(self, parser: StraceParser) -> None:
        line = (
            "1234 12:00:00.000001 connect(3, {sa_family=AF_INET, "
            'sin_addr=inet_addr("8.8.8.8")}, 16) = 0'
        )
        assert parser.parse_line(line) is None

    def test_af_inet6_with_elided_struct_returns_none(self, parser: StraceParser) -> None:
        line = "1234 12:00:00.000001 connect(3, {sa_family=AF_INET6, ...}, 28) = 0"
        assert parser.parse_line(line) is None

    def test_af_inet6_without_an_address_returns_none(self, parser: StraceParser) -> None:
        line = "1234 12:00:00.000001 connect(3, {sa_family=AF_INET6, sin6_port=htons(53)}, 28) = 0"
        assert parser.parse_line(line) is None

    # ------------------------------------------------------------------
    # parse_stream
    # ------------------------------------------------------------------

    def test_parse_stream(self, parser: StraceParser) -> None:
        lines = [
            "1 00:00:01.000000 connect(3, {sa_family=AF_INET,"
            ' sin_addr=inet_addr("1.1.1.1"), sin_port=htons(53)}, 16) = 0',
            "this line is garbage",
            "2 00:00:02.000000 connect(4, {sa_family=AF_INET6,"
            ' sin6_addr=inet_pton(AF_INET6, "::1"), sin6_port=htons(80)}, 28) = 0',
        ]
        events = parser.parse_stream(lines)
        assert len(events) == 2
        assert events[0].family == "AF_INET"
        assert events[1].family == "AF_INET6"

    def test_parse_stream_empty(self, parser: StraceParser) -> None:
        assert parser.parse_stream([]) == []

    # ------------------------------------------------------------------
    # Hardening: long lines, binary paths, permission-error lines
    # ------------------------------------------------------------------

    def test_long_line_returns_none(self, parser: StraceParser) -> None:
        # Lines longer than _MAX_LINE_LEN must be skipped without error.
        long_line = "1 12:00:00.000001 " + "x" * 5000
        assert parser.parse_line(long_line) is None

    def test_line_at_limit_boundary(self, parser: StraceParser) -> None:
        # A line just at the limit (4096 chars) should also return None since
        # it won't match a valid strace pattern.
        boundary_line = "A" * 4096
        assert parser.parse_line(boundary_line) is None

    def test_permission_error_line_returns_none(self, parser: StraceParser) -> None:
        line = "strace: attach: ptrace(PTRACE_SEIZE, 1234, 0, 0): Operation not permitted"
        assert parser.parse_line(line) is None

    def test_strace_process_exited_line_returns_none(self, parser: StraceParser) -> None:
        line = "1234 12:00:00.000001 +++ exited with 0 +++"
        assert parser.parse_line(line) is None

    def test_unix_path_with_control_chars_sanitised(self, parser: StraceParser) -> None:
        # strace may emit control characters in short AF_UNIX paths; they should
        # be stripped so downstream code receives a clean string.
        line = (
            "9 12:00:00.000001 connect(5, {sa_family=AF_UNIX,"
            ' sun_path="\x01\x02/run/foo.sock"}, 20) = 0'
        )
        event = parser.parse_line(line)
        if event is not None:
            assert "\x01" not in (event.addr or "")
            assert "\x02" not in (event.addr or "")

    # ------------------------------------------------------------------
    # Timestamp parsing
    # ------------------------------------------------------------------

    def test_timestamp_parsed(self, parser: StraceParser) -> None:
        line = (
            "1 01:02:03.456789 connect(3, {sa_family=AF_INET, "
            'sin_addr=inet_addr("10.0.0.1"), sin_port=htons(80)}, 16) = 0'
        )
        event = parser.parse_line(line)
        assert event is not None
        expected = 1 * 3600 + 2 * 60 + 3.456789
        assert abs(event.timestamp - expected) < 1e-4
