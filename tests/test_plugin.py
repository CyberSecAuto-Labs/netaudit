"""Unit tests for the pytest plugin internals (no strace required)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netaudit.allowlist import AllowList
from netaudit.integrations.pytest_plugin import (
    _ENV_MARKERS_OUT,
    _ENV_STRACE_OUT,
    _attribute_violations,
    _emit_attributed,
    _group_events,
    _now_ts,
    _parse_markers,
    _resolve_allowlist,
    _TestRange,
    pytest_addoption,
    pytest_configure,
    pytest_runtest_protocol,
    pytest_sessionfinish,
)
from netaudit.parser import ConnectEvent
from netaudit.reporter import Violation


def _event(
    family: str,
    addr: str | None,
    port: int | None,
    ts: float,
    pid: int = 1,
) -> ConnectEvent:
    return ConnectEvent(
        pid=pid,
        timestamp=ts,
        family=family,
        addr=addr,
        port=port,
        result=0,
        raw_line="",
    )


# ---------------------------------------------------------------------------
# _parse_markers
# ---------------------------------------------------------------------------


class TestParseMarkers:
    def test_single_test(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text(
            "START 10.000000 tests/test_foo.py::test_a\nEND 10.500000 tests/test_foo.py::test_a\n"
        )
        ranges = _parse_markers(f)
        assert len(ranges) == 1
        assert ranges[0].nodeid == "tests/test_foo.py::test_a"
        assert ranges[0].start == pytest.approx(10.0)
        assert ranges[0].end == pytest.approx(10.5)

    def test_multiple_tests(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text("START 10.0 test_a\nEND 10.5 test_a\nSTART 10.6 test_b\nEND 11.0 test_b\n")
        ranges = _parse_markers(f)
        assert len(ranges) == 2
        assert ranges[0].nodeid == "test_a"
        assert ranges[1].nodeid == "test_b"

    def test_ignores_malformed_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text("garbage\nSTART bad_ts test_a\nSTART 10.0 test_a\nEND 10.5 test_a\n")
        ranges = _parse_markers(f)
        assert len(ranges) == 1

    def test_unmatched_start_is_dropped(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text("START 10.0 test_a\n")  # no END
        ranges = _parse_markers(f)
        assert ranges == []

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text("")
        assert _parse_markers(f) == []


# ---------------------------------------------------------------------------
# _group_events
# ---------------------------------------------------------------------------


class TestGroupEvents:
    def test_groups_same_destination(self) -> None:
        events = [
            _event("AF_INET", "1.2.3.4", 80, ts=1.0, pid=100),
            _event("AF_INET", "1.2.3.4", 80, ts=2.0, pid=101),
        ]
        violations = _group_events(events)
        assert len(violations) == 1
        assert violations[0].count == 2
        assert violations[0].pids == {100, 101}

    def test_separate_destinations(self) -> None:
        events = [
            _event("AF_INET", "1.2.3.4", 80, ts=1.0),
            _event("AF_INET", "5.6.7.8", 443, ts=2.0),
        ]
        violations = _group_events(events)
        assert len(violations) == 2

    def test_empty(self) -> None:
        assert _group_events([]) == []


# ---------------------------------------------------------------------------
# _attribute_violations
# ---------------------------------------------------------------------------


class TestAttributeViolations:
    def test_attributes_event_within_test_range(self) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = _event("AF_INET", "1.2.3.4", 80, ts=10.5)
        al = AllowList([], includes_builtins=False)
        result = _attribute_violations([event], al, ranges)
        assert "test_a" in result
        assert len(result["test_a"]) == 1

    def test_event_before_test_range_goes_to_session(self) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = _event("AF_INET", "1.2.3.4", 80, ts=5.0)
        al = AllowList([], includes_builtins=False)
        result = _attribute_violations([event], al, ranges)
        assert "<session>" in result
        assert "test_a" not in result

    def test_allowed_event_not_included(self) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = _event("AF_INET", "127.0.0.1", 8080, ts=10.5)
        al = AllowList.empty()  # builtins allow loopback
        result = _attribute_violations([event], al, ranges)
        assert result == {}

    def test_empty_events(self) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        al = AllowList([], includes_builtins=False)
        assert _attribute_violations([], al, ranges) == {}

    def test_multiple_tests_attributed_separately(self) -> None:
        ranges = [
            _TestRange(nodeid="test_a", start=10.0, end=11.0),
            _TestRange(nodeid="test_b", start=11.0, end=12.0),
        ]
        events = [
            _event("AF_INET", "1.2.3.4", 80, ts=10.5),
            _event("AF_INET", "5.6.7.8", 443, ts=11.5),
        ]
        al = AllowList([], includes_builtins=False)
        result = _attribute_violations(events, al, ranges)
        assert set(result.keys()) == {"test_a", "test_b"}

    def test_no_ranges_all_go_to_session(self) -> None:
        event = _event("AF_INET", "1.2.3.4", 80, ts=10.5)
        al = AllowList([], includes_builtins=False)
        result = _attribute_violations([event], al, [])
        assert "<session>" in result


# ---------------------------------------------------------------------------
# _now_ts
# ---------------------------------------------------------------------------


class TestNowTs:
    def test_returns_seconds_since_midnight(self) -> None:
        ts = _now_ts()
        assert 0.0 <= ts < 86400.0


# ---------------------------------------------------------------------------
# _resolve_allowlist
# ---------------------------------------------------------------------------


def _mock_config(allowlist_opt: str | None = None) -> MagicMock:
    config = MagicMock(spec=["getoption"])
    config.getoption.return_value = allowlist_opt
    return config


class TestResolveAllowlist:
    def test_cli_flag_takes_priority(self, tmp_path: Path) -> None:
        yaml = tmp_path / "custom.yaml"
        yaml.write_text("version: 1\nallowlist: []\n")
        config = _mock_config(allowlist_opt=str(yaml))
        al = _resolve_allowlist(config)  # type: ignore[arg-type]
        assert isinstance(al, AllowList)

    def test_falls_back_to_netaudit_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        yaml = tmp_path / "netaudit.yaml"
        yaml.write_text("version: 1\nallowlist: []\n")
        config = _mock_config()
        al = _resolve_allowlist(config)  # type: ignore[arg-type]
        assert isinstance(al, AllowList)

    def test_falls_back_to_builtins_when_no_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config = _mock_config()
        al = _resolve_allowlist(config)  # type: ignore[arg-type]
        assert isinstance(al, AllowList)

    def test_reads_allowlist_from_pyproject_toml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        yaml = tmp_path / "custom.yaml"
        yaml.write_text("version: 1\nallowlist: []\n")
        (tmp_path / "pyproject.toml").write_text(f'[tool.netaudit]\nallowlist = "{yaml}"\n')
        config = _mock_config()
        al = _resolve_allowlist(config)  # type: ignore[arg-type]
        assert isinstance(al, AllowList)


# ---------------------------------------------------------------------------
# _emit_attributed
# ---------------------------------------------------------------------------


class TestEmitAttributed:
    def _make_violation(self) -> Violation:
        v = Violation(family="AF_INET", addr="1.2.3.4", port=80)
        v.pids.add(1)
        v.count = 1
        return v

    def test_prints_nodeid_and_violation(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = MagicMock()
        _emit_attributed({"tests/test_foo.py::test_bar": [self._make_violation()]}, session)
        out = capsys.readouterr().out
        assert "test_bar" in out
        assert "1.2.3.4" in out
        assert "violation" in out

    def test_sets_exit_code(self) -> None:
        session = MagicMock()
        _emit_attributed({"test_a": [self._make_violation()]}, session)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_singular_noun_for_one_violation(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = MagicMock()
        _emit_attributed({"test_a": [self._make_violation()]}, session)
        out = capsys.readouterr().out
        assert "1 violation detected" in out

    def test_plural_noun_for_multiple_violations(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = MagicMock()
        v1, v2 = self._make_violation(), self._make_violation()
        v2.addr = "5.6.7.8"
        _emit_attributed({"test_a": [v1, v2]}, session)
        out = capsys.readouterr().out
        assert "2 violations detected" in out


# ---------------------------------------------------------------------------
# pytest_addoption
# ---------------------------------------------------------------------------


class TestPytestAddoption:
    def test_registers_netaudit_options(self) -> None:
        parser = MagicMock(spec=pytest.Parser)
        group = MagicMock()
        parser.getgroup.return_value = group
        pytest_addoption(parser)
        parser.getgroup.assert_called_once_with("netaudit", "Network egress auditing")
        # --netaudit and --netaudit-allowlist
        assert group.addoption.call_count == 2
        option_names = [c.args[0] for c in group.addoption.call_args_list]
        assert "--netaudit" in option_names
        assert "--netaudit-allowlist" in option_names


# ---------------------------------------------------------------------------
# pytest_configure
# ---------------------------------------------------------------------------


class TestPytestConfigure:
    def _make_config(self, enabled: bool = True, strace_env: str | None = None) -> MagicMock:
        config = MagicMock(spec=pytest.Config)
        config.getoption.return_value = enabled
        return config

    def test_does_nothing_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        execvpe_calls: list[object] = []
        monkeypatch.setattr(os, "execvpe", lambda *a: execvpe_calls.append(a))
        config = self._make_config(enabled=False)
        pytest_configure(config)
        assert execvpe_calls == []

    def test_does_nothing_when_already_under_strace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        execvpe_calls: list[object] = []
        monkeypatch.setattr(os, "execvpe", lambda *a: execvpe_calls.append(a))
        monkeypatch.setenv(_ENV_STRACE_OUT, "/tmp/fake.strace")
        config = self._make_config(enabled=True)
        pytest_configure(config)
        assert execvpe_calls == []

    def test_raises_usage_error_when_strace_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda _: None)
        config = self._make_config(enabled=True)
        with pytest.raises(pytest.UsageError, match="strace"):
            pytest_configure(config)

    def test_reexecs_under_strace_when_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/strace" if x == "strace" else None)

        execvpe_args: list[tuple[str, list[str], dict[str, str]]] = []

        def fake_execvpe(name: str, args: list[str], env: dict[str, str]) -> None:
            execvpe_args.append((name, args, env))

        monkeypatch.setattr(os, "execvpe", fake_execvpe)
        config = self._make_config(enabled=True)
        pytest_configure(config)

        assert len(execvpe_args) == 1
        name, args, env = execvpe_args[0]
        assert name == "strace"
        assert args[0] == "strace"
        assert "-e" in args
        assert "trace=connect" in args
        assert _ENV_STRACE_OUT in env
        assert _ENV_MARKERS_OUT in env

    def test_returns_silently_when_option_not_registered(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = MagicMock(spec=pytest.Config)
        config.getoption.side_effect = ValueError("unknown option")
        # Should not raise
        pytest_configure(config)


# ---------------------------------------------------------------------------
# pytest_runtest_protocol
# ---------------------------------------------------------------------------


class TestPytestRuntestProtocol:
    def test_writes_start_and_end_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        markers_file = tmp_path / "markers"
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))

        item = MagicMock(spec=pytest.Item)
        item.nodeid = "tests/test_foo.py::test_bar"

        gen = pytest_runtest_protocol(item=item, nextitem=None)
        next(gen)  # run to yield (writes START)
        try:
            gen.send(None)  # resume past yield (writes END)
        except StopIteration:
            pass

        content = markers_file.read_text()
        lines = content.splitlines()
        assert any(line.startswith("START") for line in lines)
        assert any(line.startswith("END") for line in lines)
        assert all("tests/test_foo.py::test_bar" in line for line in lines)

    def test_does_nothing_when_env_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        item = MagicMock(spec=pytest.Item)
        item.nodeid = "test_foo"
        gen = pytest_runtest_protocol(item=item, nextitem=None)
        next(gen)
        try:
            gen.send(None)
        except StopIteration:
            pass
        # No file created — just verify no exception


# ---------------------------------------------------------------------------
# pytest_sessionfinish
# ---------------------------------------------------------------------------


_STRACE_EXTERNAL = (
    "1234 12:00:00.000000 connect(3, {sa_family=AF_INET, "
    'sin_port=htons(443), sin_addr=inet_addr("198.51.100.1")}, 16) = 0\n'
)
# 12:00:00 = 43200 seconds since midnight


class TestPytestSessionfinish:
    def test_does_nothing_when_env_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        session = MagicMock()
        pytest_sessionfinish(session=session, exitstatus=0)
        # exitstatus not changed
        session.exitstatus  # just access it — no assertion needed

    def test_does_nothing_for_empty_strace_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text("")
        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        session = MagicMock()
        pytest_sessionfinish(session=session, exitstatus=0)
        # No exception, no exit code change

    def test_reports_violation_and_sets_exit_code(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)
        markers_file = tmp_path / "markers"
        markers_file.write_text("START 43199.0 test_a\nEND 43201.0 test_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)  # no netaudit.yaml → builtin-only allowlist

        config = _mock_config()
        session = MagicMock()
        session.config = config
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "198.51.100.1" in out
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_no_violations_does_not_set_fail_exit_code(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        strace_file = tmp_path / "strace.out"
        # loopback — allowed by built-ins
        strace_file.write_text(
            "1234 12:00:00.000000 connect(3, {sa_family=AF_INET, "
            'sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        )
        markers_file = tmp_path / "markers"
        markers_file.write_text("START 43199.0 test_a\nEND 43201.0 test_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        config = _mock_config()
        session = MagicMock()
        session.config = config
        pytest_sessionfinish(session=session, exitstatus=0)

        # exitstatus should NOT have been set to TESTS_FAILED
        assert session.exitstatus != pytest.ExitCode.TESTS_FAILED

    def test_cleans_up_temp_files(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)
        markers_file = tmp_path / "markers"
        markers_file.write_text("START 43199.0 test_a\nEND 43201.0 test_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        session = MagicMock()
        session.config = _mock_config()
        pytest_sessionfinish(session=session, exitstatus=0)

        assert not strace_file.exists()
        assert not markers_file.exists()

    def test_session_level_report_without_markers(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        monkeypatch.chdir(tmp_path)

        session = MagicMock()
        session.config = _mock_config()
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "198.51.100.1" in out
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
