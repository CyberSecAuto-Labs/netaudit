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
