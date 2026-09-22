"""Tests for netaudit.reporter."""

import io
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from netaudit.allowlist import AllowList, IPv4Rule
from netaudit.parser import ConnectEvent
from netaudit.reporter import (
    Destination,
    LoadedReport,
    MergedDestination,
    Reporter,
    Violation,
    build_run_metadata,
    is_external,
    load_report,
    merge_reports,
    supports_color,
)


def _rules_from(body: str) -> list[dict[str, Any]]:
    """Parse the rule list out of suggestion output, as a user pasting it would.

    The evidence lives in comments, so this is exactly what an allowlist file
    holds once those lines are copied under its ``allowlist:`` key.
    """
    parsed = yaml.safe_load("version: 1\nallowlist:\n" + body)
    rules: list[dict[str, Any]] = parsed["allowlist"] or []
    return rules


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

    def test_addressless_event_renders_a_dash(self) -> None:
        """AF_NETLINK events have no address; the column still needs a value."""
        result = Reporter.format_verbose([_event("AF_NETLINK")], AllowList.empty())
        assert "AF_NETLINK" in result
        assert " - " in result

    def test_portless_event_shows_the_bare_address(self) -> None:
        result = Reporter.format_verbose([_event("AF_UNIX", "/run/foo.sock")], AllowList.empty())
        assert "/run/foo.sock" in result
        assert "/run/foo.sock:" not in result

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

    def test_ipv6_suggestion_round_trips_into_a_working_rule(self) -> None:
        """What matters is that the rule parses back and matches, not how it is quoted."""
        out = Reporter.format_suggestions(self._violations(_event("AF_INET6", "2001:db8::1", 8080)))
        assert "family: AF_INET6" in out
        assert _rules_from(out) == [
            {
                "name": "allow 2001:db8::1:8080",
                "family": "AF_INET6",
                "addr": "2001:db8::1",
                "port": 8080,
            }
        ]

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


# ---------------------------------------------------------------------------
# Report envelope (schema version + provenance)
# ---------------------------------------------------------------------------


class TestReportVersion:
    def test_report_carries_schema_version(self) -> None:
        data = json.loads(Reporter.format_json([]))
        assert data["version"] == 1

    def test_existing_keys_unchanged(self) -> None:
        data = json.loads(Reporter.format_json([]))
        assert "violations" in data
        assert "summary" in data


class TestBuildRunMetadata:
    def test_includes_timestamp_in_iso_8601_with_timezone(self) -> None:
        from datetime import datetime

        meta = build_run_metadata()
        parsed = datetime.fromisoformat(meta["timestamp"])
        assert parsed.tzinfo is not None

    def test_includes_hostname_and_version(self) -> None:
        from netaudit import __version__

        meta = build_run_metadata()
        assert meta["netaudit_version"] == __version__
        assert isinstance(meta["hostname"], str)
        assert meta["hostname"]

    def test_command_recorded_as_list(self) -> None:
        meta = build_run_metadata(command=["pytest", "tests/"])
        assert meta["command"] == ["pytest", "tests/"]

    def test_command_absent_when_not_supplied(self) -> None:
        assert "command" not in build_run_metadata()

    def test_allowlist_path_recorded(self) -> None:
        assert build_run_metadata(allowlist="netaudit.yaml")["allowlist"] == "netaudit.yaml"

    def test_source_recorded_for_offline_analysis(self) -> None:
        """`analyze` has no traced command — it has a log it read."""
        meta = build_run_metadata(source="/tmp/trace.log")
        assert meta["source"] == "/tmp/trace.log"
        assert "command" not in meta


class TestReportProvenance:
    def test_run_block_embedded_when_supplied(self) -> None:
        meta = build_run_metadata(command=["pytest"], allowlist="netaudit.yaml")
        data = json.loads(Reporter.format_json([], run=meta))
        assert data["run"]["command"] == ["pytest"]
        assert data["run"]["allowlist"] == "netaudit.yaml"

    def test_run_block_absent_when_not_supplied(self) -> None:
        assert "run" not in json.loads(Reporter.format_json([]))

    def test_provenance_survives_a_round_trip(self) -> None:
        """A saved report must still say where it came from when read back."""
        meta = build_run_metadata(command=["pytest"])
        text = Reporter.format_json([], run=meta)
        assert json.loads(text)["run"]["command"] == ["pytest"]


# ---------------------------------------------------------------------------
# Loading and merging saved reports
# ---------------------------------------------------------------------------


class TestLoadReport:
    def _write(self, path: Path, **over: object) -> Path:
        doc: dict[str, object] = {
            "version": 1,
            "run": {"timestamp": "2026-08-23T00:00:00+00:00"},
            "violations": [],
            "summary": {
                "total": 1,
                "by_destination": [
                    {"family": "AF_INET", "addr": "1.2.3.4", "port": 80, "count": 3, "pids": [1]}
                ],
            },
        }
        doc.update(over)
        path.write_text(json.dumps(doc))
        return path

    def test_loads_destinations(self, tmp_path: Path) -> None:
        rpt = load_report(self._write(tmp_path / "r.json"))
        assert len(rpt.destinations) == 1
        assert rpt.destinations[0].addr == "1.2.3.4"
        assert rpt.destinations[0].count == 3

    def test_a_unix_path_is_canonicalised_on_the_way_in(self, tmp_path: Path) -> None:
        """A report written before the parser canonicalised holds the raw sun_path.

        `triage` turns it straight into a `path_glob`, and the rule that glob
        becomes canonicalises what it matches — so an uncanonical one never fires.
        """
        rpt = load_report(
            self._write(
                tmp_path / "r.json",
                summary={
                    "total": 1,
                    "by_destination": [
                        {
                            "family": "AF_UNIX",
                            "addr": "/run/gvmd/../x.sock",
                            "port": None,
                            "count": 1,
                        }
                    ],
                },
            )
        )
        assert rpt.destinations[0].addr == "/run/x.sock"

    def test_label_is_the_file_name(self, tmp_path: Path) -> None:
        assert load_report(self._write(tmp_path / "ci-42.json")).label == "ci-42.json"

    def test_rejects_json_that_is_not_an_object(self, tmp_path: Path) -> None:
        path = tmp_path / "r.json"
        path.write_text("[]")
        with pytest.raises(ValueError, match="not a JSON object"):
            load_report(path)

    def test_rejects_a_bare_json_scalar(self, tmp_path: Path) -> None:
        path = tmp_path / "r.json"
        path.write_text('"nope"')
        with pytest.raises(ValueError, match="not a JSON object"):
            load_report(path)

    def test_tests_attribution_preserved(self, tmp_path: Path) -> None:
        rpt = load_report(
            self._write(
                tmp_path / "r.json",
                summary={
                    "total": 1,
                    "by_destination": [
                        {
                            "family": "AF_INET",
                            "addr": "1.2.3.4",
                            "port": 80,
                            "count": 1,
                            "pids": [1],
                            "tests": ["test_a"],
                        }
                    ],
                },
            )
        )
        assert rpt.destinations[0].tests == {"test_a"}

    def test_unknown_schema_version_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="version"):
            load_report(self._write(tmp_path / "r.json", version=99))

    def test_missing_version_is_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "r.json"
        p.write_text(json.dumps({"violations": [], "summary": {"by_destination": []}}))
        with pytest.raises(ValueError, match="version"):
            load_report(p)

    def test_malformed_json_is_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "r.json"
        p.write_text("{not json")
        with pytest.raises(ValueError, match="r.json"):
            load_report(p)

    def test_clean_report_loads_with_no_destinations(self, tmp_path: Path) -> None:
        rpt = load_report(
            self._write(tmp_path / "r.json", summary={"total": 0, "by_destination": []})
        )
        assert rpt.destinations == []


class TestMergeReports:
    def _report(self, label: str, *dests: dict[str, object]) -> "LoadedReport":
        return LoadedReport(
            label=label,
            run={},
            destinations=[
                Destination(
                    family=str(d.get("family", "AF_INET")),
                    addr=str(d["addr"]),
                    port=d.get("port"),  # type: ignore[arg-type]
                    count=int(d.get("count", 1)),
                    tests=set(d.get("tests", set())),  # type: ignore[arg-type]
                )
                for d in dests
            ],
        )

    def test_same_destination_across_reports_is_one_entry(self) -> None:
        merged = merge_reports(
            [
                self._report("a.json", {"addr": "1.2.3.4", "port": 80, "count": 2}),
                self._report("b.json", {"addr": "1.2.3.4", "port": 80, "count": 3}),
            ]
        )
        assert len(merged) == 1
        assert merged[0].count == 5

    def test_source_reports_are_tracked(self) -> None:
        merged = merge_reports(
            [
                self._report("a.json", {"addr": "1.2.3.4", "port": 80}),
                self._report("b.json", {"addr": "1.2.3.4", "port": 80}),
            ]
        )
        assert merged[0].reports == ["a.json", "b.json"]

    def test_distinct_ports_stay_separate(self) -> None:
        merged = merge_reports(
            [
                self._report(
                    "a.json", {"addr": "1.2.3.4", "port": 80}, {"addr": "1.2.3.4", "port": 443}
                )
            ]
        )
        assert len(merged) == 2

    def test_tests_unioned_across_reports(self) -> None:
        merged = merge_reports(
            [
                self._report("a.json", {"addr": "1.2.3.4", "port": 80, "tests": {"test_a"}}),
                self._report("b.json", {"addr": "1.2.3.4", "port": 80, "tests": {"test_b"}}),
            ]
        )
        assert merged[0].tests == {"test_a", "test_b"}

    def test_sorted_by_count_descending(self) -> None:
        merged = merge_reports(
            [
                self._report(
                    "a.json",
                    {"addr": "1.1.1.1", "port": 80, "count": 1},
                    {"addr": "2.2.2.2", "port": 80, "count": 9},
                )
            ]
        )
        assert merged[0].addr == "2.2.2.2"

    def test_total_report_count_recorded(self) -> None:
        merged = merge_reports(
            [
                self._report("a.json", {"addr": "1.2.3.4", "port": 80}),
                self._report("b.json"),
                self._report("c.json"),
            ]
        )
        assert merged[0].total_reports == 3

    def test_empty_input(self) -> None:
        assert merge_reports([]) == []


# ---------------------------------------------------------------------------
# Evidence-annotated suggestions
# ---------------------------------------------------------------------------


def _merged(
    addr: str = "1.2.3.4",
    port: int | None = 80,
    count: int = 5,
    reports: list[str] | None = None,
    total: int = 3,
    tests: set[str] | None = None,
) -> "MergedDestination":
    return MergedDestination(
        family="AF_INET",
        addr=addr,
        port=port,
        count=count,
        tests=tests or set(),
        reports=reports if reports is not None else ["a.json", "b.json", "c.json"],
        total_reports=total,
    )


class TestFormatSuggestionsWithEvidence:
    def test_rule_annotated_with_count_and_report_ratio(self) -> None:
        out = Reporter.format_suggestions_with_evidence([_merged(count=47)])
        assert "47 calls" in out
        assert "3/3 runs" in out

    def test_rule_lists_source_reports(self) -> None:
        out = Reporter.format_suggestions_with_evidence([_merged(reports=["ci-7.json"], total=1)])
        assert "ci-7.json" in out

    def test_tests_named_when_attribution_survived(self) -> None:
        out = Reporter.format_suggestions_with_evidence(
            [_merged(tests={"test_sync", "test_fetch"})]
        )
        assert "test_fetch" in out
        assert "test_sync" in out

    def test_no_tests_clause_when_attribution_absent(self) -> None:
        assert "tests:" not in Reporter.format_suggestions_with_evidence([_merged()])

    def test_external_every_run_is_flagged(self) -> None:
        """The beacon signature: consistent, high-volume, undeclared, public."""
        out = Reporter.format_suggestions_with_evidence([_merged(addr="185.199.108.153")])
        assert "external host reached on every run (3/3)" in out
        assert "never declared" in out

    def test_external_intermittent_is_flagged(self) -> None:
        out = Reporter.format_suggestions_with_evidence(
            [_merged(addr="185.199.108.153", reports=["a.json"], total=3)]
        )
        assert "external host reached in 1 of 3 runs" in out

    def test_external_single_report_is_flagged_without_a_ratio(self) -> None:
        """With one report the run pattern carries no information; externality still does."""
        out = Reporter.format_suggestions_with_evidence(
            [_merged(addr="185.199.108.153", reports=["a.json"], total=1)]
        )
        assert "! external host — never declared" in out
        assert "every run" not in out

    def test_internal_destination_is_not_flagged(self) -> None:
        out = Reporter.format_suggestions_with_evidence([_merged(addr="10.0.0.5")])
        assert "!" not in out
        assert "never declared" not in out

    def test_scope_tagged_in_the_evidence_line(self) -> None:
        assert "internal" in Reporter.format_suggestions_with_evidence([_merged(addr="10.0.0.5")])
        assert "external" in Reporter.format_suggestions_with_evidence([_merged(addr="8.8.8.8")])

    def test_non_routable_documentation_range_counts_as_internal(self) -> None:
        """TEST-NET addresses are not globally routable, so they are not 'external'."""
        out = Reporter.format_suggestions_with_evidence([_merged(addr="198.51.100.1")])
        assert "internal" in out
        assert "never declared" not in out

    def test_ipv6_externality_is_classified(self) -> None:
        public = Reporter.format_suggestions_with_evidence(
            [
                MergedDestination(
                    family="AF_INET6",
                    addr="2606:4700::1111",
                    port=443,
                    count=1,
                    reports=["a.json"],
                    total_reports=1,
                )
            ]
        )
        assert "external" in public
        private = Reporter.format_suggestions_with_evidence(
            [
                MergedDestination(
                    family="AF_INET6",
                    addr="2001:db8::1",
                    port=443,
                    count=1,
                    reports=["a.json"],
                    total_reports=1,
                )
            ]
        )
        assert "internal" in private

    def test_unix_socket_path_is_not_treated_as_external(self) -> None:
        out = Reporter.format_suggestions_with_evidence(
            [
                MergedDestination(
                    family="AF_UNIX",
                    addr="/run/x.sock",
                    port=None,
                    count=1,
                    reports=["a.json"],
                    total_reports=1,
                )
            ]
        )
        assert "never declared" not in out

    def test_header_frames_output_as_a_question_not_a_recommendation(self) -> None:
        out = Reporter.format_suggestions_with_evidence([_merged()])
        assert "Undeclared egress observed" in out
        assert "not a recommendation" in out

    def test_header_states_run_and_connection_totals(self) -> None:
        out = Reporter.format_suggestions_with_evidence([_merged(count=47)])
        assert "3 runs" in out
        assert "47 connections" in out

    def test_sorted_loudest_first(self) -> None:
        out = Reporter.format_suggestions_with_evidence(
            [_merged(addr="1.1.1.1", count=90), _merged(addr="2.2.2.2", count=2)]
        )
        assert out.index("1.1.1.1") < out.index("2.2.2.2")

    def test_output_is_still_valid_yaml(self) -> None:
        """Evidence lives in comments so a copy-paste keeps it and the YAML still loads."""
        import yaml as _yaml

        out = Reporter.format_suggestions_with_evidence(
            [_merged(count=47, tests={"test_a"}), _merged(addr="9.9.9.9", port=53, count=1)]
        )
        rules = _yaml.safe_load(out)
        assert isinstance(rules, list)
        assert len(rules) == 2
        assert rules[0]["addr"] == "1.2.3.4"
        assert rules[0]["port"] == 80

    def test_evidence_survives_yaml_round_trip_as_comments(self) -> None:
        import yaml as _yaml

        out = Reporter.format_suggestions_with_evidence([_merged(count=47)])
        # Comments are not data — they must not leak into the parsed rule.
        rule = _yaml.safe_load(out)[0]
        assert "47 calls" not in str(rule)
        assert "47 calls" in out

    def test_empty_input_returns_empty_string(self) -> None:
        assert Reporter.format_suggestions_with_evidence([]) == ""

    def test_ipv6_address_is_quoted(self) -> None:
        import yaml as _yaml

        dest = MergedDestination(
            family="AF_INET6",
            addr="2001:db8::1",
            port=8080,
            count=1,
            reports=["a.json"],
            total_reports=1,
        )
        rules = _yaml.safe_load(Reporter.format_suggestions_with_evidence([dest]))
        assert rules[0]["addr"] == "2001:db8::1"


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


class TestIsExternal:
    def test_public_address_is_external(self) -> None:
        assert is_external("8.8.8.8")

    def test_public_ipv6_address_is_external(self) -> None:
        assert is_external("2606:4700::1111")

    def test_private_address_is_not_external(self) -> None:
        assert not is_external("10.0.0.5")

    def test_loopback_is_not_external(self) -> None:
        assert not is_external("::1")

    def test_reserved_documentation_range_is_not_external(self) -> None:
        """198.51.100.0/24 is TEST-NET-3 — not routable, despite looking public."""
        assert not is_external("198.51.100.1")

    def test_missing_address_is_not_external(self) -> None:
        """AF_NETLINK events carry no address at all."""
        assert not is_external(None)

    def test_empty_address_is_not_external(self) -> None:
        assert not is_external("")

    def test_unix_socket_path_is_not_external(self) -> None:
        assert not is_external("/run/gvmd/gvmd.sock")


class TestMergedDestinationKey:
    def test_key_identifies_the_destination(self) -> None:
        assert _merged(addr="1.2.3.4", port=80).key == ("AF_INET", "1.2.3.4", 80)

    def test_key_matches_the_unmerged_destination_it_came_from(self) -> None:
        """merge_reports groups on this key; the two must agree."""
        dest = Destination(family="AF_INET", addr="1.2.3.4", port=80, count=1)
        assert _merged(addr="1.2.3.4", port=80).key == dest.key


class TestFormatSuggestionsWithEvidenceStream:
    def test_writes_to_the_given_stream(self) -> None:
        buf = io.StringIO()
        result = Reporter.format_suggestions_with_evidence([_merged()], stream=buf)
        assert buf.getvalue() == result
        assert "1.2.3.4" in buf.getvalue()

    def test_returns_the_body_when_no_stream_is_given(self) -> None:
        assert "1.2.3.4" in Reporter.format_suggestions_with_evidence([_merged()])


# ---------------------------------------------------------------------------
# Multi-destination iteration
# ---------------------------------------------------------------------------


class TestMergeReportsMultipleDestinations:
    def test_every_destination_in_a_report_is_merged(self) -> None:
        """The per-report loop must keep going after the first destination."""
        report = LoadedReport(
            label="ci-1.json",
            run={},
            destinations=[
                Destination(family="AF_INET", addr="1.2.3.4", port=80, count=2),
                Destination(family="AF_INET", addr="5.6.7.8", port=443, count=1),
            ],
        )
        merged = merge_reports([report])
        assert {d.addr for d in merged} == {"1.2.3.4", "5.6.7.8"}
        assert all(d.reports == ["ci-1.json"] for d in merged)

    def test_a_report_is_credited_once_per_destination(self) -> None:
        report = LoadedReport(
            label="ci-1.json",
            run={},
            destinations=[
                Destination(family="AF_INET", addr="1.2.3.4", port=80, count=2),
                Destination(family="AF_INET", addr="1.2.3.4", port=80, count=3),
            ],
        )
        merged = merge_reports([report])
        assert len(merged) == 1
        assert merged[0].count == 5
        assert merged[0].reports == ["ci-1.json"], "the same report is not counted twice"


class TestFormatSuggestionsWithEvidenceMultiple:
    def test_all_destinations_are_rendered(self) -> None:
        """A ported destination must not end the loop early."""
        out = Reporter.format_suggestions_with_evidence(
            [_merged(addr="1.2.3.4", port=80, count=9), _merged(addr="5.6.7.8", port=443, count=1)]
        )
        assert "1.2.3.4" in out
        assert "5.6.7.8" in out
        assert out.count("- name:") == 2

    def test_portless_destination_does_not_end_the_loop(self) -> None:
        out = Reporter.format_suggestions_with_evidence(
            [
                _merged(addr="1.2.3.4", port=None, count=9),
                _merged(addr="5.6.7.8", port=443, count=1),
            ]
        )
        assert "addr: 1.2.3.4" in out
        assert "addr: 5.6.7.8" in out
        assert out.count("port:") == 1, "only the ported destination gets a port key"

    def test_unix_destination_after_a_ported_one_is_rendered(self) -> None:
        out = Reporter.format_suggestions_with_evidence(
            [
                _merged(addr="1.2.3.4", port=80, count=9),
                MergedDestination(
                    family="AF_UNIX",
                    addr="/run/foo.sock",
                    port=None,
                    count=1,
                    reports=["a.json"],
                    total_reports=3,
                ),
            ]
        )
        assert "path_glob: /run/foo.sock" in out
        assert "addr: 1.2.3.4" in out


class TestSuggestionsSurviveHostileInput:
    """The values come out of saved reports, which the docs say to collect from CI."""

    _INJECTION = "1.2.3.4\n  - name: everything\n    family: AF_INET\n    cidr: 0.0.0.0/0"

    def test_a_newline_in_an_address_injects_no_rule(self) -> None:
        out = Reporter.format_suggestions(
            [Violation(family="AF_INET", addr=self._INJECTION, port=80, count=1)]
        )
        rules = _rules_from(out)
        assert len(rules) == 1
        assert rules[0]["family"] == "AF_INET"
        assert "0.0.0.0/0" not in str(rules[0].get("cidr", ""))

    def test_a_newline_in_a_unix_path_injects_no_rule(self) -> None:
        out = Reporter.format_suggestions(
            [Violation(family="AF_UNIX", addr="/run/x\n  - family: AF_NETLINK", port=None, count=1)]
        )
        assert len(_rules_from(out)) == 1

    def test_a_newline_in_triage_evidence_injects_no_rule(self) -> None:
        """The evidence is a comment; a newline would end it and open YAML."""
        dest = MergedDestination(
            family="AF_INET",
            addr="1.2.3.4",
            port=80,
            count=1,
            reports=["r.json"],
            total_reports=1,
            tests={"t.py::a\n  - name: everything\n    family: AF_NETLINK"},
        )
        out = Reporter.format_suggestions_with_evidence([dest])
        rules = _rules_from("\n".join(line for line in out.splitlines() if line.startswith("  ")))
        assert len(rules) == 1
        assert rules[0]["family"] == "AF_INET"

    def test_a_newline_in_a_triage_address_injects_no_rule(self) -> None:
        dest = MergedDestination(
            family="AF_INET",
            addr=self._INJECTION,
            port=80,
            count=1,
            reports=["r.json"],
            total_reports=1,
        )
        out = Reporter.format_suggestions_with_evidence([dest])
        rules = _rules_from("\n".join(line for line in out.splitlines() if line.startswith("  ")))
        assert len(rules) == 1


class TestControlCharactersAreShownNotActed:
    """An address that erases the line it is printed on can hide a violation."""

    _ERASER = "8.8.8.8\x1b[2K\rnetaudit: no violations"

    def test_the_violation_block_escapes_them(self) -> None:
        out = Reporter.format([Violation(family="AF_INET", addr=self._ERASER, port=53, count=1)])
        assert "\x1b" not in out
        assert "\\x1b" in out

    def test_the_verbose_table_escapes_them(self) -> None:
        out = Reporter.format_verbose([_event("AF_INET", self._ERASER, 53)], AllowList.empty())
        assert "\x1b" not in out

    def test_the_summary_escapes_a_test_nodeid(self) -> None:
        v = Violation(family="AF_INET", addr="1.2.3.4", port=80, count=1)
        out = Reporter.format_summary([v], tests_by_key={v.key: {"t.py::a\x1b[2K\r"}})
        assert "\x1b" not in out

    def test_a_rule_name_is_escaped_in_the_verbose_table(self) -> None:
        allowlist = AllowList([IPv4Rule("1.2.3.4/32", name="ok\x1b[2K\r")], includes_builtins=False)
        out = Reporter.format_verbose([_event("AF_INET", "1.2.3.4", 80)], allowlist)
        assert "\x1b" not in out

    def test_suggestions_escape_them(self) -> None:
        out = Reporter.format_suggestions(
            [Violation(family="AF_INET", addr=self._ERASER, port=53, count=1)]
        )
        assert "\x1b" not in out


class TestSavedReportFieldsAreTyped:
    """A report is untrusted JSON, and a wrong type does not fail — it stops matching."""

    def _load(self, tmp_path: Path, **destination: object) -> LoadedReport:
        path = tmp_path / "r.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "summary": {"total": 1, "by_destination": [destination]},
                },
                allow_nan=True,
            )
        )
        return load_report(path)

    def test_a_string_port_is_rejected(self, tmp_path: Path) -> None:
        """`'443' != 443`, so an allowlist rule that permits it would not fire."""
        with pytest.raises(ValueError, match="'port' must be a port number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port="443", count=1)

    def test_a_boolean_port_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="'port' must be a port number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=True, count=1)

    def test_a_whole_float_port_is_accepted(self, tmp_path: Path) -> None:
        report = self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=443.0, count=1)
        assert report.destinations[0].port == 443

    def test_a_fractional_port_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="'port' must be a port number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=80.5, count=1)

    @pytest.mark.parametrize("port", [-1, 65536])
    def test_a_port_no_socket_could_carry_is_rejected(self, tmp_path: Path, port: int) -> None:
        with pytest.raises(ValueError, match="'port' must be a port number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=port, count=1)

    def test_an_integer_address_is_rejected(self, tmp_path: Path) -> None:
        """`IPv4Address(12345)` is valid and means a different address entirely."""
        with pytest.raises(ValueError, match="'addr' must be a string"):
            self._load(tmp_path, family="AF_INET", addr=12345, port=80, count=1)

    def test_a_null_address_is_accepted(self, tmp_path: Path) -> None:
        report = self._load(tmp_path, family="AF_NETLINK", addr=None, port=None, count=1)
        assert report.destinations[0].addr is None

    def test_a_non_numeric_count_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="'count' must be a whole number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=80, count="many")

    def test_a_family_that_is_not_a_string_is_rejected(self, tmp_path: Path) -> None:
        """str() would turn it into a family name nothing matches."""
        with pytest.raises(ValueError, match="'family' must be a string"):
            self._load(tmp_path, family=["AF_INET"], addr="1.2.3.4", port=80, count=1)

    @pytest.mark.parametrize("count", [1.9, -1, float("inf"), float("nan")])
    def test_a_count_that_is_not_a_whole_number_is_rejected(
        self, tmp_path: Path, count: float
    ) -> None:
        """int(inf) raises OverflowError, past every caller's except ValueError."""
        with pytest.raises(ValueError, match="'count' must be a whole number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=80, count=count)

    def test_a_boolean_count_is_rejected(self, tmp_path: Path) -> None:
        """bool is a subclass of int, so `true` would otherwise become 1."""
        with pytest.raises(ValueError, match="'count' must be a whole number"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=80, count=True)

    def test_a_whole_float_count_is_accepted(self, tmp_path: Path) -> None:
        report = self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=80, count=3.0)
        assert report.destinations[0].count == 3

    def test_a_destination_list_that_is_not_a_list_is_rejected(self, tmp_path: Path) -> None:
        """Iterating a number raises TypeError, past the caller's except ValueError."""
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": 1, "summary": {"by_destination": 1}}))
        with pytest.raises(ValueError, match="'summary.by_destination' must be a list"):
            load_report(path)

    def test_a_destination_that_is_not_an_object_is_rejected(self, tmp_path: Path) -> None:
        """Skipping it silently would drop evidence the report claims to carry."""
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": 1, "summary": {"by_destination": ["nope"]}}))
        with pytest.raises(ValueError, match="each destination must be an object"):
            load_report(path)

    def test_an_absent_destination_list_is_an_empty_one(self, tmp_path: Path) -> None:
        """A report that observed nothing is still a report."""
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": 1, "summary": {"total": 0}}))
        assert load_report(path).destinations == []

    def test_an_absent_summary_is_an_empty_one(self, tmp_path: Path) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": 1}))
        assert load_report(path).destinations == []

    @pytest.mark.parametrize("summary", [[], "", 0, False])
    def test_a_falsy_summary_that_is_not_an_object_is_still_rejected(
        self, tmp_path: Path, summary: object
    ) -> None:
        """`or {}` would have read all of these as "no summary"."""
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": 1, "summary": summary}))
        with pytest.raises(ValueError, match="'summary' must be an object"):
            load_report(path)

    def test_a_summary_that_is_not_an_object_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": 1, "summary": [1, 2]}))
        with pytest.raises(ValueError, match="'summary' must be an object"):
            load_report(path)

    def test_a_tests_field_that_is_not_strings_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="'tests' must be a list of strings"):
            self._load(tmp_path, family="AF_INET", addr="1.2.3.4", port=80, count=1, tests=[1])


class TestSecretsAreMaskedInTheRecordedCommand:
    """Reports are meant to be published as CI artifacts; argv often is not."""

    def _command(self, *args: str) -> list[str]:
        meta = build_run_metadata(command=list(args))
        recorded: list[str] = meta["command"]
        return recorded

    def test_an_attached_value_is_masked(self) -> None:
        assert self._command("curl", "--token=s3cr3t") == ["curl", "--token=***"]

    def test_a_separate_value_is_masked(self) -> None:
        assert self._command("curl", "--token", "s3cr3t") == ["curl", "--token", "***"]

    def test_the_option_name_itself_survives(self) -> None:
        """What the run did is still legible; only the value goes."""
        assert "--password" in " ".join(self._command("app", "--password", "hunter2"))

    def test_credentials_in_a_url_are_masked(self) -> None:
        assert self._command("psql", "postgres://alice:hunter2@db:5432/x") == [
            "psql",
            "postgres://alice:***@db:5432/x",
        ]

    def test_an_ordinary_argument_is_untouched(self) -> None:
        assert self._command("pytest", "-q", "tests/unit") == ["pytest", "-q", "tests/unit"]

    def test_an_option_following_a_secret_option_is_not_eaten(self) -> None:
        """`--token --verbose` would otherwise mask a flag and lose it from the record."""
        assert self._command("app", "--token", "--verbose", "x") == [
            "app",
            "--token",
            "--verbose",
            "x",
        ]

    @pytest.mark.parametrize("option", ["--tokenize", "--authors", "--keyword", "-p"])
    def test_an_option_that_only_looks_secret_is_left_alone(self, option: str) -> None:
        """The name is matched by whole segments, not as a substring."""
        assert self._command("app", option, "value") == ["app", option, "value"]

    @pytest.mark.parametrize(
        "option",
        ["--token", "--api-key", "--apikey", "--db_password", "--authorization", "--dsn"],
    )
    def test_a_separate_value_is_masked_for_names_that_always_take_one(self, option: str) -> None:
        assert self._command("app", option, "s3cr3t") == ["app", option, "***"]

    @pytest.mark.parametrize("option", ["--auth", "--key", "--cookie"])
    def test_a_separate_value_is_left_for_names_that_are_often_switches(self, option: str) -> None:
        """Masking the next argument after a boolean flag would rewrite the record."""
        assert self._command("app", option, "report.txt") == ["app", option, "report.txt"]

    @pytest.mark.parametrize("option", ["--auth", "--key", "--cookie"])
    def test_an_attached_value_is_masked_even_for_those(self, option: str) -> None:
        """The `=` proves the option takes a value."""
        assert self._command("app", f"{option}=s3cr3t") == ["app", f"{option}=***"]

    def test_a_positional_secret_is_not_caught(self) -> None:
        """Documented limit: this filters shapes, it does not understand the command."""
        assert self._command("app", "hunter2") == ["app", "hunter2"]

    def test_the_hostname_is_still_recorded(self) -> None:
        """It ties a report to the machine that made it, and is not a credential."""
        assert build_run_metadata(command=["pytest"])["hostname"]


class TestRedactionEdges:
    def _command(self, *args: str) -> list[str]:
        recorded: list[str] = build_run_metadata(command=list(args))["command"]
        return recorded

    def test_a_name_that_only_joins_into_a_secret_word_is_left_alone(self) -> None:
        """`--to-ken` is not `--token`; joining is only for the compound names."""
        assert self._command("app", "--to-ken", "report.txt") == ["app", "--to-ken", "report.txt"]

    @pytest.mark.parametrize("option", ["--api-key", "--apikey", "--access-token"])
    def test_a_compound_name_is_masked_either_way_it_is_written(self, option: str) -> None:
        assert self._command("app", option, "s3cr3t") == ["app", option, "***"]
