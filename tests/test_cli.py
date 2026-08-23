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
    def test_strace_missing_exits_2(self) -> None:
        with patch("netaudit.cli.StraceRunner") as mock_cls:
            from netaudit.runner import StraceNotFoundError

            mock_cls.side_effect = StraceNotFoundError("strace not found")
            result = CliRunner().invoke(main, ["run", "--", "echo", "hi"])

        assert result.exit_code == 2
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

        assert result.exit_code == 1

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

        assert result.exit_code == 1
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

        assert result.exit_code == 1
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
