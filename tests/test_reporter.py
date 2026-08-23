"""Tests for netaudit.reporter."""

import io
import json
import re
from pathlib import Path

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent
from netaudit.reporter import Reporter, Violation, supports_color


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


# ---------------------------------------------------------------------------
# Colour support
# ---------------------------------------------------------------------------


class _FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class TestSupportsColor:
    def test_tty_stream_supports_color(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert supports_color(_FakeTTY()) is True

    def test_non_tty_stream_does_not(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert supports_color(io.StringIO()) is False

    def test_no_color_env_disables_on_tty(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("NO_COLOR", "1")
        assert supports_color(_FakeTTY()) is False

    def test_empty_no_color_env_does_not_disable(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """no-color.org: the variable must be present *and non-empty* to apply."""
        monkeypatch.setenv("NO_COLOR", "")
        assert supports_color(_FakeTTY()) is True

    def test_none_stream_falls_back_to_stdout(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr("sys.stdout", _FakeTTY())
        assert supports_color() is True


class TestFormatColor:
    def test_violation_is_red_when_color_enabled(self) -> None:
        violations = Reporter.check([_event("AF_INET", "198.51.100.1", 443)], AllowList.empty())
        out = Reporter.format(violations, color=True)
        assert "\033[31m" in out
        assert "\033[0m" in out

    def test_no_ansi_when_color_disabled(self) -> None:
        violations = Reporter.check([_event("AF_INET", "198.51.100.1", 443)], AllowList.empty())
        out = Reporter.format(violations, color=False)
        assert "\033[" not in out

    def test_color_defaults_to_off(self) -> None:
        violations = Reporter.check([_event("AF_INET", "198.51.100.1", 443)], AllowList.empty())
        assert "\033[" not in Reporter.format(violations)

    def test_clean_message_is_green_when_color_enabled(self) -> None:
        out = Reporter.format([], color=True)
        assert "\033[32m" in out
        assert "no violations" in out

    def test_colored_output_preserves_plain_content(self) -> None:
        violations = Reporter.check([_event("AF_INET", "198.51.100.1", 443)], AllowList.empty())
        colored = Reporter.format(violations, color=True)
        assert "198.51.100.1:443" in colored
        assert "1 violation detected" in colored


class TestFormatVerboseColor:
    def _mixed_events(self) -> list[ConnectEvent]:
        return [_event("AF_INET", "127.0.0.1", 80), _event("AF_INET", "198.51.100.1", 443)]

    def test_ok_green_and_violation_red(self) -> None:
        out = Reporter.format_verbose(self._mixed_events(), AllowList.empty(), color=True)
        assert "\033[32m" in out
        assert "\033[31m" in out

    def test_no_ansi_when_color_disabled(self) -> None:
        out = Reporter.format_verbose(self._mixed_events(), AllowList.empty(), color=False)
        assert "\033[" not in out

    def test_columns_stay_aligned_when_colored(self) -> None:
        """ANSI codes must not be counted in the column width."""
        plain = Reporter.format_verbose(self._mixed_events(), AllowList.empty(), color=False)
        colored = Reporter.format_verbose(self._mixed_events(), AllowList.empty(), color=True)
        strip = re.sub(r"\033\[[0-9;]*m", "", colored)
        assert strip == plain


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


class TestFormatSummary:
    def _violations(self) -> list[Violation]:
        events = [
            _event("AF_INET", "198.51.100.1", 443, pid=10),
            _event("AF_INET", "198.51.100.1", 443, pid=11),
            _event("AF_INET", "203.0.113.7", 80, pid=10),
        ]
        return Reporter.check(events, AllowList.empty())

    def test_header_and_rows_present(self) -> None:
        out = Reporter.format_summary(self._violations())
        assert "ADDR:PORT" in out
        assert "COUNT" in out
        assert "198.51.100.1:443" in out
        assert "203.0.113.7:80" in out

    def test_counts_are_aggregated_per_destination(self) -> None:
        out = Reporter.format_summary(self._violations())
        row = next(ln for ln in out.splitlines() if "198.51.100.1:443" in ln)
        assert "2" in row.split()

    def test_pids_column_when_no_attribution(self) -> None:
        out = Reporter.format_summary(self._violations())
        assert "PIDS" in out
        assert "10, 11" in out

    def test_tests_column_when_attribution_given(self) -> None:
        violations = self._violations()
        tests = {v.key: {"test_a", "test_b"} for v in violations if v.port == 443}
        out = Reporter.format_summary(violations, tests_by_key=tests)
        assert "TESTS" in out
        assert "PIDS" not in out
        assert "test_a, test_b" in out

    def test_destinations_sorted_by_count_descending(self) -> None:
        out = Reporter.format_summary(self._violations())
        body = [ln for ln in out.splitlines() if ":" in ln and "ADDR" not in ln]
        assert "198.51.100.1:443" in body[0]

    def test_empty_violations_returns_empty_string(self) -> None:
        assert Reporter.format_summary([]) == ""

    def test_no_ansi_by_default(self) -> None:
        assert "\033[" not in Reporter.format_summary(self._violations())

    def test_colored_when_requested(self) -> None:
        assert "\033[" in Reporter.format_summary(self._violations(), color=True)

    def test_writes_to_stream(self) -> None:
        buf = io.StringIO()
        out = Reporter.format_summary(self._violations(), stream=buf)
        assert buf.getvalue() == out


class TestFormatJsonSummary:
    def _violations(self) -> list[Violation]:
        events = [
            _event("AF_INET", "198.51.100.1", 443, pid=10),
            _event("AF_INET", "198.51.100.1", 443, pid=11),
        ]
        return Reporter.check(events, AllowList.empty())

    def test_by_destination_present(self) -> None:
        data = json.loads(Reporter.format_json(self._violations()))
        dests = data["summary"]["by_destination"]
        assert len(dests) == 1
        assert dests[0]["addr"] == "198.51.100.1"
        assert dests[0]["port"] == 443
        assert dests[0]["count"] == 2
        assert dests[0]["pids"] == [10, 11]

    def test_total_still_present(self) -> None:
        data = json.loads(Reporter.format_json(self._violations()))
        assert data["summary"]["total"] == 1

    def test_tests_included_when_attribution_given(self) -> None:
        violations = self._violations()
        tests = {v.key: {"test_b", "test_a"} for v in violations}
        data = json.loads(Reporter.format_json(violations, tests_by_key=tests))
        assert data["summary"]["by_destination"][0]["tests"] == ["test_a", "test_b"]

    def test_tests_key_absent_without_attribution(self) -> None:
        data = json.loads(Reporter.format_json(self._violations()))
        assert "tests" not in data["summary"]["by_destination"][0]

    def test_empty_violations_gives_empty_by_destination(self) -> None:
        data = json.loads(Reporter.format_json([]))
        assert data["summary"]["by_destination"] == []


# ---------------------------------------------------------------------------
# Rule suggestions
# ---------------------------------------------------------------------------


class TestFormatSuggestions:
    def _violations(self, *events: ConnectEvent) -> list[Violation]:
        return Reporter.check(list(events), AllowList.empty())

    def test_ipv4_suggestion_includes_addr_and_port(self) -> None:
        out = Reporter.format_suggestions(self._violations(_event("AF_INET", "198.51.100.1", 443)))
        assert "family: AF_INET" in out
        assert "addr: 198.51.100.1" in out
        assert "port: 443" in out

    def test_ipv6_suggestion_quotes_the_address(self) -> None:
        out = Reporter.format_suggestions(self._violations(_event("AF_INET6", "2001:db8::1", 8080)))
        assert "family: AF_INET6" in out
        assert 'addr: "2001:db8::1"' in out
        assert "port: 8080" in out

    def test_unix_socket_suggestion_uses_path_glob(self) -> None:
        # Built-ins allow every AF_UNIX socket, so this path is only reachable
        # for users who opted out of them.
        strict = AllowList([], includes_builtins=False)
        violations = Reporter.check([_event("AF_UNIX", "/run/x.sock")], strict)
        out = Reporter.format_suggestions(violations)
        assert "family: AF_UNIX" in out
        assert "path_glob: /run/x.sock" in out
        assert "port:" not in out

    def test_port_omitted_when_event_has_none(self) -> None:
        out = Reporter.format_suggestions(self._violations(_event("AF_INET", "198.51.100.1")))
        assert "addr: 198.51.100.1" in out
        assert "port:" not in out

    def test_each_destination_gets_one_rule(self) -> None:
        out = Reporter.format_suggestions(
            self._violations(
                _event("AF_INET", "198.51.100.1", 443),
                _event("AF_INET", "203.0.113.7", 80),
            )
        )
        assert out.count("- name:") == 2

    def test_empty_violations_returns_empty_string(self) -> None:
        assert Reporter.format_suggestions([]) == ""

    def test_output_is_valid_yaml_and_round_trips(self) -> None:
        """The whole point is copy-paste: the block must load as a real allowlist."""
        import yaml

        out = Reporter.format_suggestions(self._violations(_event("AF_INET", "198.51.100.1", 443)))
        body = "\n".join(ln for ln in out.splitlines() if not ln.lstrip().startswith("#"))
        rules = yaml.safe_load(body)
        assert isinstance(rules, list)
        assert rules[0]["family"] == "AF_INET"
        assert rules[0]["port"] == 443

    def test_suggested_rule_actually_allows_the_connection(self, tmp_path: "Path") -> None:
        """A suggestion that does not silence the violation is worthless."""

        event = _event("AF_INET", "198.51.100.1", 443)
        out = Reporter.format_suggestions(self._violations(event))
        body = "\n".join(ln for ln in out.splitlines() if not ln.lstrip().startswith("#"))
        y = tmp_path / "suggested.yaml"
        y.write_text("version: 1\nallowlist:\n" + body + "\n")
        assert AllowList.from_yaml(y).is_allowed(event) is True

    def test_suggested_rule_does_not_allow_other_ports(self, tmp_path: "Path") -> None:

        out = Reporter.format_suggestions(self._violations(_event("AF_INET", "198.51.100.1", 443)))
        body = "\n".join(ln for ln in out.splitlines() if not ln.lstrip().startswith("#"))
        y = tmp_path / "suggested.yaml"
        y.write_text("version: 1\nallowlist:\n" + body + "\n")
        other = _event("AF_INET", "198.51.100.1", 22)
        assert AllowList.from_yaml(y).is_allowed(other) is False

    def test_writes_to_stream(self) -> None:
        buf = io.StringIO()
        out = Reporter.format_suggestions(
            self._violations(_event("AF_INET", "198.51.100.1", 443)), stream=buf
        )
        assert buf.getvalue() == out
