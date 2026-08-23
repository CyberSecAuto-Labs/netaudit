"""Tests for netaudit.reporter."""

import io
import json
import re
from pathlib import Path

import pytest

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent
from netaudit.reporter import (
    Destination,
    LoadedReport,
    MergedDestination,
    Reporter,
    Violation,
    build_run_metadata,
    load_report,
    merge_reports,
    supports_color,
)


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

    def test_label_is_the_file_name(self, tmp_path: Path) -> None:
        assert load_report(self._write(tmp_path / "ci-42.json")).label == "ci-42.json"

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
