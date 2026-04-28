"""Tests for netaudit.reporter."""

import io
import json

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent
from netaudit.reporter import Reporter, Violation


def _event(
    family: str,
    addr: str | None = None,
    port: int | None = None,
    pid: int = 1,
    timestamp: float = 0.0,
) -> ConnectEvent:
    return ConnectEvent(
        pid=pid, timestamp=timestamp, family=family, addr=addr, port=port, result=0, raw_line=""
    )


class TestReporterCheck:
    def test_no_violations_when_all_allowed(self) -> None:
        events = [_event("AF_INET", "127.0.0.1", 80)]
        al = AllowList.empty()
        assert Reporter.check(events, al) == []

    def test_external_ip_is_violation(self) -> None:
        events = [_event("AF_INET", "198.51.100.1", 443)]
        al = AllowList.empty()
        violations = Reporter.check(events, al)
        assert len(violations) == 1
        v = violations[0]
        assert v.family == "AF_INET"
        assert v.addr == "198.51.100.1"
        assert v.port == 443
        assert v.count == 1

    def test_violations_grouped_by_family_addr_port(self) -> None:
        events = [
            _event("AF_INET", "8.8.8.8", 53, pid=10),
            _event("AF_INET", "8.8.8.8", 53, pid=11),
            _event("AF_INET", "8.8.8.8", 53, pid=10),
        ]
        al = AllowList.empty()
        violations = Reporter.check(events, al)
        assert len(violations) == 1
        v = violations[0]
        assert v.count == 3
        assert v.pids == {10, 11}

    def test_different_ports_are_separate_violations(self) -> None:
        events = [
            _event("AF_INET", "8.8.8.8", 53),
            _event("AF_INET", "8.8.8.8", 443),
        ]
        al = AllowList.empty()
        violations = Reporter.check(events, al)
        assert len(violations) == 2

    def test_netlink_not_a_violation(self) -> None:
        events = [_event("AF_NETLINK")]
        al = AllowList.empty()
        assert Reporter.check(events, al) == []

    def test_unix_not_a_violation(self) -> None:
        events = [_event("AF_UNIX", "/run/foo.sock")]
        al = AllowList.empty()
        assert Reporter.check(events, al) == []

    def test_first_timestamp_recorded(self) -> None:
        events = [
            _event("AF_INET", "8.8.8.8", 53, timestamp=10.0),
            _event("AF_INET", "8.8.8.8", 53, timestamp=20.0),
        ]
        al = AllowList.empty()
        violations = Reporter.check(events, al)
        assert violations[0].first_timestamp == 10.0

    def test_empty_events(self) -> None:
        assert Reporter.check([], AllowList.empty()) == []


class TestReporterFormat:
    def test_no_violations_message(self) -> None:
        result = Reporter.format([])
        assert "no violations" in result

    def test_violations_box_output(self) -> None:
        v = Violation(family="AF_INET", addr="198.51.100.1", port=443)
        v.pids.add(1234)
        v.count = 2
        result = Reporter.format([v])
        assert "1 violation" in result
        assert "198.51.100.1:443" in result
        assert "1234" in result

    def test_plural_violations(self) -> None:
        violations = [Violation(family="AF_INET", addr=f"10.0.0.{i}", port=80) for i in range(1, 3)]
        result = Reporter.format(violations)
        assert "2 violations" in result

    def test_writes_to_stream(self) -> None:
        stream = io.StringIO()
        Reporter.format([], stream=stream)
        assert stream.getvalue() != ""

    def test_returns_string(self) -> None:
        result = Reporter.format([])
        assert isinstance(result, str)

    def test_violation_str_with_port(self) -> None:
        v = Violation(family="AF_INET", addr="1.2.3.4", port=80)
        v.pids.add(42)
        v.count = 1
        assert "1.2.3.4:80" in str(v)

    def test_violation_str_no_port(self) -> None:
        v = Violation(family="AF_UNIX", addr="/run/foo.sock", port=None)
        v.pids.add(1)
        v.count = 1
        assert "/run/foo.sock" in str(v)

    def test_violation_str_no_addr(self) -> None:
        v = Violation(family="AF_UNKNOWN", addr=None, port=None)
        v.pids.add(1)
        v.count = 1
        assert "<unknown>" in str(v)


class TestReporterFormatVerbose:
    def test_header_present(self) -> None:
        al = AllowList.empty()
        result = Reporter.format_verbose([], al)
        assert "FAMILY" in result
        assert "ADDR:PORT" in result
        assert "STATUS" in result
        assert "RULE" in result

    def test_allowed_event_shows_ok_and_rule(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_INET", "127.0.0.1", 80)]
        result = Reporter.format_verbose(events, al)
        assert "OK" in result
        assert "loopback (IPv4)" in result

    def test_violation_event_shows_violation(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_INET", "198.51.100.1", 443)]
        result = Reporter.format_verbose(events, al)
        assert "VIOLATION" in result

    def test_unix_event_shows_builtin_name(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_UNIX", "/run/foo.sock")]
        result = Reporter.format_verbose(events, al)
        assert "unix (builtin)" in result

    def test_writes_to_stream(self) -> None:
        al = AllowList.empty()
        stream = io.StringIO()
        Reporter.format_verbose([], al, stream=stream)
        assert stream.getvalue() != ""

    def test_empty_events_only_header(self) -> None:
        al = AllowList.empty()
        result = Reporter.format_verbose([], al)
        lines = [ln for ln in result.splitlines() if ln.strip()]
        assert len(lines) == 2  # header + separator


class TestReporterFormatJsonVerbose:
    def test_include_allowed_adds_events_key(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_INET", "127.0.0.1", 80), _event("AF_INET", "198.51.100.1", 443)]
        violations = Reporter.check(events, al)
        data = json.loads(
            Reporter.format_json(violations, events=events, allowlist=al, include_allowed=True)
        )
        assert "events" in data
        assert len(data["events"]) == 2

    def test_allowed_entry_has_status_and_rule(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_INET", "127.0.0.1", 80)]
        violations = Reporter.check(events, al)
        data = json.loads(
            Reporter.format_json(violations, events=events, allowlist=al, include_allowed=True)
        )
        entry = data["events"][0]
        assert entry["status"] == "allowed"
        assert entry["rule"] == "loopback (IPv4)"

    def test_violation_entry_has_status_and_null_rule(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_INET", "198.51.100.1", 443)]
        violations = Reporter.check(events, al)
        data = json.loads(
            Reporter.format_json(violations, events=events, allowlist=al, include_allowed=True)
        )
        entry = data["events"][0]
        assert entry["status"] == "violation"
        assert entry["rule"] is None

    def test_no_include_allowed_omits_events_key(self) -> None:
        al = AllowList.empty()
        events = [_event("AF_INET", "127.0.0.1", 80)]
        violations = Reporter.check(events, al)
        data = json.loads(Reporter.format_json(violations))
        assert "events" not in data
