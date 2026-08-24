"""Tests for netaudit CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from netaudit.cli import main
from netaudit.parser import ConnectEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CLEAN_EVENTS: list[ConnectEvent] = []

_VIOLATION_EVENT = ConnectEvent(
    pid=42,
    timestamp=1.0,
    family="AF_INET",
    addr="8.8.8.8",
    port=53,
    result=0,
    raw_line="42 00:00:01.000000 connect(3, {sa_family=AF_INET, ...}, 16) = 0",
)

_STRACE_LOG_CLEAN = (
    '100 00:00:01.000000 connect(3, {sa_family=AF_UNIX, sun_path="/run/foo"}, 20) = 0\n'
)

_INET_STRUCT = 'sin_addr=inet_addr("8.8.8.8"), sin_port=htons(53)'
_STRACE_LOG_VIOLATION = (
    f"42 00:00:01.000000 connect(3, {{sa_family=AF_INET, {_INET_STRUCT}}}, 16) = 0\n"
)


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------


class TestAnalyzeCommand:
    def test_clean_log_exits_0(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)

        result = CliRunner().invoke(main, ["analyze", str(log)])

        assert result.exit_code == 0
        assert "no violations" in result.output

    def test_violation_log_exits_1(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)

        result = CliRunner().invoke(main, ["analyze", str(log)])

        assert result.exit_code == 1
        assert "violation" in result.output

    def test_json_format_clean(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)

        result = CliRunner().invoke(main, ["analyze", "--format", "json", str(log)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["total"] == 0
        assert data["violations"] == []

    def test_json_format_violation(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)

        result = CliRunner().invoke(main, ["analyze", "--format", "json", str(log)])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["summary"]["total"] == 1
        assert data["violations"][0]["family"] == "AF_INET"
        assert data["violations"][0]["addr"] == "8.8.8.8"
        assert data["violations"][0]["port"] == 53

    def test_uses_allowlist_file(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)
        allowlist = tmp_path / "allow.yaml"
        allowlist.write_text("version: 1\nallowlist:\n  - family: AF_INET\n    addr: 8.8.8.8\n")

        result = CliRunner().invoke(main, ["analyze", "--allowlist", str(allowlist), str(log)])

        assert result.exit_code == 0

    def test_default_allowlist_from_cwd(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)
        (tmp_path / "netaudit.yaml").write_text(
            "version: 1\nallowlist:\n  - family: AF_INET\n    addr: 8.8.8.8\n"
        )

        import os

        old = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = CliRunner().invoke(main, ["analyze", str(log)])
        finally:
            os.chdir(old)

        assert result.exit_code == 0

    def test_missing_strace_log_exits_nonzero(self) -> None:
        result = CliRunner().invoke(main, ["analyze", "/nonexistent/trace.log"])

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------


class TestRunCommand:
    def test_strace_missing_uses_a_reserved_code(self) -> None:
        with patch("netaudit.cli.StraceRunner") as mock_cls:
            from netaudit.runner import StraceNotFoundError

            mock_cls.side_effect = StraceNotFoundError("strace not found")
            result = CliRunner().invoke(main, ["run", "--", "echo", "hi"])

        assert result.exit_code == 84
        assert "strace" in result.output.lower()

    def test_clean_run_exits_0(self, tmp_path: Path) -> None:
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(_STRACE_LOG_CLEAN)

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0)

        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            # Prevent unlink from removing our fixture
            with patch("pathlib.Path.unlink"):
                result = CliRunner().invoke(main, ["run", "--", "echo", "hi"])

        assert result.exit_code == 0
        assert "no violations" in result.output

    def test_violation_run_exits_1(self, tmp_path: Path) -> None:
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(_STRACE_LOG_VIOLATION)

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0)

        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            with patch("pathlib.Path.unlink"):
                result = CliRunner().invoke(main, ["run", "--", "curl", "8.8.8.8"])

        assert result.exit_code == 83

    def test_json_format(self, tmp_path: Path) -> None:
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(_STRACE_LOG_VIOLATION)

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0)

        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            with patch("pathlib.Path.unlink"):
                result = CliRunner().invoke(
                    main, ["run", "--format", "json", "--", "curl", "8.8.8.8"]
                )

        assert result.exit_code == 83
        data = json.loads(result.output)
        assert data["summary"]["total"] == 1


# ---------------------------------------------------------------------------
# Version / help
# ---------------------------------------------------------------------------


class TestMetaCommands:
    def test_version(self) -> None:
        result = CliRunner().invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "netaudit" in result.output

    def test_help(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "run" in result.output
        assert "analyze" in result.output


# ---------------------------------------------------------------------------
# --verbose flag
# ---------------------------------------------------------------------------


class TestVerboseFlag:
    def test_analyze_verbose_shows_table(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)

        result = CliRunner().invoke(main, ["analyze", "--verbose", str(log)])

        assert result.exit_code == 0
        assert "FAMILY" in result.output
        assert "STATUS" in result.output

    def test_analyze_verbose_allowed_event_shows_ok(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)

        result = CliRunner().invoke(main, ["analyze", "-v", str(log)])

        assert "OK" in result.output
        assert "unix (builtin)" in result.output

    def test_analyze_verbose_violation_shows_violation(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)

        result = CliRunner().invoke(main, ["analyze", "--verbose", str(log)])

        assert result.exit_code == 1
        assert "VIOLATION" in result.output

    def test_analyze_verbose_json_includes_events(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)

        result = CliRunner().invoke(main, ["analyze", "--verbose", "--format", "json", str(log)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "events" in data
        assert data["events"][0]["status"] == "allowed"

    def test_run_verbose_shows_table(self, tmp_path: Path) -> None:
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(_STRACE_LOG_CLEAN)

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0)

        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            with patch("pathlib.Path.unlink"):
                result = CliRunner().invoke(main, ["run", "--verbose", "--", "echo", "hi"])

        assert result.exit_code == 0
        assert "FAMILY" in result.output
        assert "STATUS" in result.output

    def test_run_verbose_json_includes_events(self, tmp_path: Path) -> None:
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(_STRACE_LOG_VIOLATION)

        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=0)

        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            with patch("pathlib.Path.unlink"):
                result = CliRunner().invoke(
                    main, ["run", "--verbose", "--format", "json", "--", "curl", "8.8.8.8"]
                )

        assert result.exit_code == 83
        data = json.loads(result.output)
        assert "events" in data
        assert data["events"][0]["status"] == "violation"


# ---------------------------------------------------------------------------
# --no-color
# ---------------------------------------------------------------------------


class TestNoColor:
    """Colour is emitted only on a TTY, and `--no-color` always wins."""

    def _log(self, tmp_path: Path) -> Path:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)
        return log

    def test_color_emitted_when_supported(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        with patch("netaudit.cli.supports_color", return_value=True):
            result = CliRunner().invoke(main, ["analyze", str(log)])
        assert "\033[31m" in result.output

    def test_no_color_flag_suppresses_ansi(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        with patch("netaudit.cli.supports_color", return_value=True):
            result = CliRunner().invoke(main, ["analyze", "--no-color", str(log)])
        assert "\033[" not in result.output
        assert result.exit_code == 1

    def test_no_ansi_when_not_a_tty(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        with patch("netaudit.cli.supports_color", return_value=False):
            result = CliRunner().invoke(main, ["analyze", str(log)])
        assert "\033[" not in result.output

    def test_verbose_output_is_colored(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        with patch("netaudit.cli.supports_color", return_value=True):
            result = CliRunner().invoke(main, ["analyze", "--verbose", str(log)])
        assert "\033[31m" in result.output

    def test_json_format_never_colored(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        with patch("netaudit.cli.supports_color", return_value=True):
            result = CliRunner().invoke(main, ["analyze", "--format", "json", str(log)])
        assert "\033[" not in result.output
        json.loads(result.output)

    def test_run_command_accepts_no_color(self) -> None:
        result = CliRunner().invoke(main, ["run", "--help"])
        assert "--no-color" in result.output


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


class TestSummaryTable:
    def _log(self, tmp_path: Path) -> Path:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)
        return log

    def test_summary_printed_after_verbose_table(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", "--verbose", str(self._log(tmp_path))])
        assert "ADDR:PORT" in result.output
        assert "COUNT" in result.output
        # COUNT appears only in the summary; the verbose table must come first.
        assert result.output.index("STATUS") < result.output.index("COUNT")

    def test_no_summary_in_non_verbose_mode(self, tmp_path: Path) -> None:
        """The non-verbose detail block is already one row per destination."""
        result = CliRunner().invoke(main, ["analyze", str(self._log(tmp_path))])
        assert "ADDR:PORT" not in result.output
        assert "8.8.8.8" in result.output

    def test_no_summary_when_clean(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)
        result = CliRunner().invoke(main, ["analyze", str(log)])
        assert "ADDR:PORT" not in result.output
        assert result.exit_code == 0

    def test_summary_in_json_output(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", "--format", "json", str(self._log(tmp_path))])
        data = json.loads(result.output)
        assert data["summary"]["by_destination"][0]["addr"] == "8.8.8.8"

    def test_summary_sorted_loudest_first(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", "--verbose", str(self._log(tmp_path))])
        body = [ln for ln in result.output.splitlines() if ln.startswith("8.8.8.8")]
        assert body


# ---------------------------------------------------------------------------
# --suggest-rules
# ---------------------------------------------------------------------------


class TestSuggestRules:
    def _log(self, tmp_path: Path) -> Path:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)
        return log

    def test_suggestions_printed_when_flag_set(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", "--suggest-rules", str(self._log(tmp_path))])
        assert "Suggested rules" in result.output
        assert "family: AF_INET" in result.output
        assert "addr: 8.8.8.8" in result.output

    def test_no_suggestions_without_flag(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", str(self._log(tmp_path))])
        assert "Suggested rules" not in result.output

    def test_no_suggestions_when_clean(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)
        result = CliRunner().invoke(main, ["analyze", "--suggest-rules", str(log)])
        assert "Suggested rules" not in result.output
        assert result.exit_code == 0

    def test_exit_code_unchanged_by_suggestions(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", "--suggest-rules", str(self._log(tmp_path))])
        assert result.exit_code == 1

    def test_json_output_carries_suggestions(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            main, ["analyze", "--suggest-rules", "--format", "json", str(self._log(tmp_path))]
        )
        data = json.loads(result.output)
        assert data["suggested_rules"][0]["family"] == "AF_INET"
        assert data["suggested_rules"][0]["addr"] == "8.8.8.8"

    def test_run_command_accepts_suggest_rules(self) -> None:
        result = CliRunner().invoke(main, ["run", "--help"])
        assert "--suggest-rules" in result.output


# ---------------------------------------------------------------------------
# --output / saved reports
# ---------------------------------------------------------------------------


class TestOutputFile:
    def _log(self, tmp_path: Path) -> Path:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_VIOLATION)
        return log

    def test_writes_report_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = CliRunner().invoke(
            main, ["analyze", "--format", "json", "--output", str(out), str(self._log(tmp_path))]
        )
        assert out.exists()
        assert json.loads(out.read_text())["violations"][0]["addr"] == "8.8.8.8"
        assert result.exit_code == 1

    def test_stdout_is_empty_when_output_used(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = CliRunner().invoke(
            main, ["analyze", "--format", "json", "--output", str(out), str(self._log(tmp_path))]
        )
        assert result.output.strip() == ""

    def test_saved_report_carries_provenance(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        log = self._log(tmp_path)
        CliRunner().invoke(main, ["analyze", "--format", "json", "--output", str(out), str(log)])
        run = json.loads(out.read_text())["run"]
        assert run["source"] == str(log)
        assert run["netaudit_version"]
        assert run["timestamp"]

    def test_saved_report_carries_schema_version(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        CliRunner().invoke(
            main, ["analyze", "--format", "json", "--output", str(out), str(self._log(tmp_path))]
        )
        assert json.loads(out.read_text())["version"] == 1

    def test_text_format_also_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.txt"
        CliRunner().invoke(main, ["analyze", "--output", str(out), str(self._log(tmp_path))])
        body = out.read_text()
        assert "1 violation detected" in body
        assert "8.8.8.8:53" in body

    def test_output_file_never_contains_ansi(self, tmp_path: Path) -> None:
        """A file is not a terminal, whatever stdout happens to be."""
        out = tmp_path / "report.txt"
        with patch("netaudit.cli.supports_color", return_value=True):
            CliRunner().invoke(main, ["analyze", "--output", str(out), str(self._log(tmp_path))])
        assert "\033[" not in out.read_text()

    def test_clean_run_still_writes_a_report(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)
        out = tmp_path / "report.json"
        result = CliRunner().invoke(
            main, ["analyze", "--format", "json", "--output", str(out), str(log)]
        )
        assert json.loads(out.read_text())["summary"]["total"] == 0
        assert result.exit_code == 0

    def test_run_command_accepts_output(self) -> None:
        result = CliRunner().invoke(main, ["run", "--help"])
        assert "--output" in result.output

    def test_json_to_stdout_carries_provenance(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["analyze", "--format", "json", str(self._log(tmp_path))])
        assert "run" in json.loads(result.output)

    def test_verbose_text_file_lists_every_event(self, tmp_path: Path) -> None:
        out = tmp_path / "report.txt"
        CliRunner().invoke(
            main, ["analyze", "--verbose", "--output", str(out), str(self._log(tmp_path))]
        )
        body = out.read_text()
        assert "8.8.8.8:53" in body
        assert "STATUS" in body, "verbose mode writes the per-event table"
        assert "COUNT" in body, "the per-destination summary follows the event table"

    def test_suggested_rules_reach_the_text_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.txt"
        CliRunner().invoke(
            main, ["analyze", "--suggest-rules", "--output", str(out), str(self._log(tmp_path))]
        )
        body = out.read_text()
        assert "8.8.8.8" in body
        assert "family: AF_INET" in body, "suggestions are emitted as allowlist YAML"

    def test_no_suggestions_appended_for_a_clean_run(self, tmp_path: Path) -> None:
        log = tmp_path / "trace.log"
        log.write_text(_STRACE_LOG_CLEAN)
        out = tmp_path / "report.txt"
        CliRunner().invoke(main, ["analyze", "--suggest-rules", "--output", str(out), str(log)])
        assert "family:" not in out.read_text()


# ---------------------------------------------------------------------------
# netaudit undeclared
# ---------------------------------------------------------------------------


def _report_file(path: Path, *dests: dict[str, object]) -> Path:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "run": {"timestamp": "2026-08-23T00:00:00+00:00"},
                "violations": [],
                "summary": {"total": len(dests), "by_destination": list(dests)},
            }
        )
    )
    return path


_D1: dict[str, object] = {
    "family": "AF_INET",
    "addr": "198.51.100.1",
    "port": 443,
    "count": 3,
    "pids": [1],
}
_D2: dict[str, object] = {
    "family": "AF_INET",
    "addr": "203.0.113.7",
    "port": 80,
    "count": 1,
    "pids": [2],
}


class TestSuggestCommand:
    def test_clean_message_goes_to_stderr_not_stdout(self, tmp_path: Path) -> None:
        """stdout is data — a status line must not end up in a redirected rules file."""
        r = _report_file(tmp_path / "a.json")
        result = CliRunner().invoke(main, ["undeclared", str(r)])
        assert result.stdout.strip() == ""
        assert "no undeclared egress" in result.stderr

    def test_emits_rules_from_one_report(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", str(r)])
        assert "family: AF_INET" in result.output
        assert "addr: 198.51.100.1" in result.output
        assert "port: 443" in result.output

    def test_merges_across_reports(self, tmp_path: Path) -> None:
        a = _report_file(tmp_path / "a.json", _D1)
        b = _report_file(tmp_path / "b.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", str(a), str(b)])
        assert result.output.count("addr: 198.51.100.1") == 1

    def test_distinct_destinations_each_get_a_rule(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json", _D1, _D2)
        result = CliRunner().invoke(main, ["undeclared", str(r)])
        assert result.output.count("- name:") == 2

    def test_exit_1_when_undeclared_egress_found(self, tmp_path: Path) -> None:
        """Same sense as `run` and `analyze`: non-zero means something needs attention."""
        r = _report_file(tmp_path / "a.json", _D1)
        assert CliRunner().invoke(main, ["undeclared", str(r)]).exit_code == 1

    def test_exit_0_when_nothing_undeclared(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json")
        result = CliRunner().invoke(main, ["undeclared", str(r)])
        assert result.exit_code == 0

    def test_existing_allowlist_filters_known_destinations(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json", _D1, _D2)
        al = tmp_path / "netaudit.yaml"
        al.write_text(
            "version: 1\nallowlist:\n  - family: AF_INET\n    addr: 198.51.100.1\n    port: 443\n"
        )
        result = CliRunner().invoke(main, ["undeclared", "--allowlist", str(al), str(r)])
        assert "198.51.100.1" not in result.output
        assert "203.0.113.7" in result.output

    def test_all_destinations_already_allowed_exits_clean(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json", _D1)
        al = tmp_path / "netaudit.yaml"
        al.write_text(
            "version: 1\nallowlist:\n  - family: AF_INET\n    addr: 198.51.100.1\n    port: 443\n"
        )
        result = CliRunner().invoke(main, ["undeclared", "--allowlist", str(al), str(r)])
        assert result.exit_code == 0

    def test_json_format(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", "--format", "json", str(r)])
        data = json.loads(result.output)
        assert data["suggested_rules"][0]["addr"] == "198.51.100.1"

    def test_unreadable_report_reports_the_filename(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.json"
        bad.write_text("{not json")
        result = CliRunner().invoke(main, ["undeclared", str(bad)])
        assert result.exit_code == 2
        assert "broken.json" in result.output

    def test_unknown_schema_version_is_refused(self, tmp_path: Path) -> None:
        bad = tmp_path / "future.json"
        bad.write_text(json.dumps({"version": 99, "summary": {"by_destination": []}}))
        result = CliRunner().invoke(main, ["undeclared", str(bad)])
        assert result.exit_code == 2
        assert "version" in result.output

    def test_output_flag_writes_to_file(self, tmp_path: Path) -> None:
        r = _report_file(tmp_path / "a.json", _D1)
        out = tmp_path / "rules.yaml"
        CliRunner().invoke(main, ["undeclared", "--output", str(out), str(r)])
        assert "addr: 198.51.100.1" in out.read_text()


# A genuinely globally-routable address. The TEST-NET ranges used elsewhere in
# these fixtures are *not* routable, so they classify as internal and would never
# exercise the external-egress callout.
_EXTERNAL: dict[str, object] = {
    "family": "AF_INET",
    "addr": "185.199.108.153",
    "port": 443,
    "count": 5,
    "pids": [1],
}


class TestSuggestEvidence:
    def test_yaml_output_carries_evidence(self, tmp_path: Path) -> None:
        a = _report_file(tmp_path / "a.json", _D1)
        b = _report_file(tmp_path / "b.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", str(a), str(b)])
        assert "across 2 runs" in result.output
        assert "2/2 runs" in result.output
        assert "a.json" in result.output and "b.json" in result.output

    def test_header_frames_output_as_a_question(self, tmp_path: Path) -> None:
        a = _report_file(tmp_path / "a.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", str(a)])
        assert "Undeclared egress observed" in result.output
        assert "not a recommendation" in result.output

    def test_persistent_external_egress_is_flagged(self, tmp_path: Path) -> None:
        """The case the rarity heuristic missed: consistent, high-volume, public."""
        a = _report_file(tmp_path / "a.json", _EXTERNAL)
        b = _report_file(tmp_path / "b.json", _EXTERNAL)
        result = CliRunner().invoke(main, ["undeclared", str(a), str(b)])
        assert "external host reached on every run (2/2)" in result.output
        assert "never declared" in result.output

    def test_intermittent_external_egress_is_flagged(self, tmp_path: Path) -> None:
        a = _report_file(tmp_path / "a.json", _EXTERNAL, _D1)
        b = _report_file(tmp_path / "b.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", str(a), str(b)])
        assert "external host reached in 1 of 2 runs" in result.output

    def test_internal_egress_is_not_flagged(self, tmp_path: Path) -> None:
        a = _report_file(tmp_path / "a.json", _D1, _D2)
        result = CliRunner().invoke(main, ["undeclared", str(a)])
        assert "never declared" not in result.output
        assert "internal" in result.output

    def test_tests_named_from_plugin_reports(self, tmp_path: Path) -> None:
        d = dict(_D1)
        d["tests"] = ["tests/test_api.py::test_fetch"]
        r = _report_file(tmp_path / "a.json", d)
        result = CliRunner().invoke(main, ["undeclared", str(r)])
        assert "tests/test_api.py::test_fetch" in result.output

    def test_output_still_parses_as_yaml(self, tmp_path: Path) -> None:
        import yaml as _yaml

        a = _report_file(tmp_path / "a.json", _D1, _D2)
        result = CliRunner().invoke(main, ["undeclared", str(a)])
        rules = _yaml.safe_load(result.output)
        assert len(rules) == 2
        assert {r["addr"] for r in rules} == {"198.51.100.1", "203.0.113.7"}

    def test_suggested_rules_actually_allow_the_destinations(self, tmp_path: Path) -> None:
        """The emitted block must silence exactly what it describes."""
        from netaudit.allowlist import AllowList
        from netaudit.parser import ConnectEvent

        r = _report_file(tmp_path / "a.json", _D1)
        result = CliRunner().invoke(
            main, ["undeclared", "--output", str(tmp_path / "s.yaml"), str(r)]
        )
        assert result.exit_code == 1
        al_file = tmp_path / "al.yaml"
        al_file.write_text("version: 1\nallowlist:\n" + (tmp_path / "s.yaml").read_text())
        al = AllowList.from_yaml(al_file)
        allowed = ConnectEvent(
            pid=1,
            timestamp=0,
            family="AF_INET",
            addr="198.51.100.1",
            port=443,
            result=0,
            raw_line="",
        )
        other = ConnectEvent(
            pid=1,
            timestamp=0,
            family="AF_INET",
            addr="198.51.100.1",
            port=22,
            result=0,
            raw_line="",
        )
        assert al.is_allowed(allowed) is True
        assert al.is_allowed(other) is False

    def test_json_output_carries_evidence(self, tmp_path: Path) -> None:
        a = _report_file(tmp_path / "a.json", _D1)
        b = _report_file(tmp_path / "b.json", _D1)
        result = CliRunner().invoke(main, ["undeclared", "--format", "json", str(a), str(b)])
        rule = json.loads(result.output)["suggested_rules"][0]
        assert rule["count"] == 6
        assert rule["reports"] == ["a.json", "b.json"]
        assert rule["total_reports"] == 2
        assert rule["external"] is False


# ---------------------------------------------------------------------------
# run — exit code propagation
# ---------------------------------------------------------------------------


class TestRunExitCodes:
    """`run` must not swallow the wrapped command's exit status."""

    def _invoke(self, tmp_path: Path, strace_body: str, returncode: int, *args: str) -> "object":
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(strace_body)
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=returncode)
        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            with patch("pathlib.Path.unlink"):
                return CliRunner().invoke(main, ["run", *args, "--", "pytest"])

    def test_clean_command_no_violations_exits_0(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, _STRACE_LOG_CLEAN, 0)
        assert result.exit_code == 0  # type: ignore[attr-defined]

    def test_violations_use_the_reserved_code(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, _STRACE_LOG_VIOLATION, 0)
        assert result.exit_code == 83  # type: ignore[attr-defined]

    def test_failing_command_propagates_its_code(self, tmp_path: Path) -> None:
        """The bug: a failing suite with clean egress used to exit 0."""
        result = self._invoke(tmp_path, _STRACE_LOG_CLEAN, 1)
        assert result.exit_code == 1  # type: ignore[attr-defined]

    def test_unusual_command_code_propagates(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, _STRACE_LOG_CLEAN, 137)
        assert result.exit_code == 137  # type: ignore[attr-defined]

    def test_failing_command_takes_precedence_over_violations(self, tmp_path: Path) -> None:
        """A crashed command may have produced a partial trace, so its failure leads."""
        result = self._invoke(tmp_path, _STRACE_LOG_VIOLATION, 1)
        assert result.exit_code == 1  # type: ignore[attr-defined]

    def test_violations_still_reported_when_command_fails(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, _STRACE_LOG_VIOLATION, 1)
        assert "8.8.8.8" in result.output  # type: ignore[attr-defined]

    def test_command_exit_code_is_surfaced(self, tmp_path: Path) -> None:
        """Never lose it silently — 2 and 3 are ambiguous with netaudit's own codes."""
        result = self._invoke(tmp_path, _STRACE_LOG_CLEAN, 137)
        assert "137" in result.output  # type: ignore[attr-defined]

    def test_success_is_not_announced(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, _STRACE_LOG_CLEAN, 0)
        assert "exited with" not in result.output  # type: ignore[attr-defined]

    def test_json_output_records_the_command_exit_code(self, tmp_path: Path) -> None:
        result = self._invoke(tmp_path, _STRACE_LOG_CLEAN, 5, "--format", "json")
        data = json.loads(result.stdout)  # type: ignore[attr-defined]
        assert data["run"]["command_exit_code"] == 5


class TestRunReservedCodesAreDistinct:
    """netaudit's own codes must not be reachable by the traced command."""

    def test_command_exiting_2_is_not_read_as_missing_strace(self, tmp_path: Path) -> None:
        """pytest.ExitCode.INTERRUPTED is 2 — a cancelled run must stay a 2."""
        strace_log = tmp_path / "out.strace"
        strace_log.write_text(_STRACE_LOG_CLEAN)
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(returncode=2)
        with (
            patch("netaudit.cli.StraceRunner", return_value=mock_runner),
            patch("netaudit.cli.tempfile.NamedTemporaryFile") as mock_tf,
        ):
            mock_tf.return_value.__enter__.return_value.name = str(strace_log)
            with patch("pathlib.Path.unlink"):
                result = CliRunner().invoke(main, ["run", "--", "pytest"])
        assert result.exit_code == 2
        assert "traced command exited with 2" in result.output

    def test_reserved_codes_do_not_overlap(self) -> None:
        from netaudit.cli import (
            _EXIT_CLEAN,
            _EXIT_STRACE_MISSING,
            _EXIT_TRACED_VIOLATIONS,
        )

        codes = {_EXIT_CLEAN, _EXIT_TRACED_VIOLATIONS, _EXIT_STRACE_MISSING}
        assert len(codes) == 3
        # Both netaudit-originated codes sit in the band left clear of sysexits,
        # the Linux socket errno block, shell codes and signal-derived values.
        assert 79 <= _EXIT_TRACED_VIOLATIONS <= 87
        assert 79 <= _EXIT_STRACE_MISSING <= 87
