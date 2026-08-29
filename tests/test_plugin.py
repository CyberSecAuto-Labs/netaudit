"""Unit tests for the pytest plugin internals (no strace required)."""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netaudit import _tempfiles
from netaudit.allowlist import AllowList
from netaudit.integrations.pytest_plugin import (
    _ENV_MARKERS_OUT,
    _ENV_STRACE_OUT,
    _ENV_TRACER_PID,
    _attribute_violations,
    _emit_attributed,
    _emit_attributed_verbose,
    _fail_session,
    _group_events,
    _merge_by_destination,
    _now_ts,
    _parse_markers,
    _resolve_allowlist,
    _resolve_color,
    _resolve_enabled,
    _resolve_report_path,
    _resolve_suggest_rules,
    _resolve_verbose,
    _TestRange,
    _write_report,
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
            "START\t10.000000\t\ttests/test_foo.py::test_a\n"
            "END\t10.500000\t\ttests/test_foo.py::test_a\n"
        )
        ranges = _parse_markers(f)
        assert len(ranges) == 1
        assert ranges[0].nodeid == "tests/test_foo.py::test_a"
        assert ranges[0].start == pytest.approx(10.0)
        assert ranges[0].end == pytest.approx(10.5)

    def test_multiple_tests(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text(
            "START\t10.0\t\ttest_a\nEND\t10.5\t\ttest_a\n"
            "START\t10.6\t\ttest_b\nEND\t11.0\t\ttest_b\n"
        )
        ranges = _parse_markers(f)
        assert len(ranges) == 2
        assert ranges[0].nodeid == "test_a"
        assert ranges[1].nodeid == "test_b"

    def test_ignores_malformed_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text(
            "garbage\nSTART\tbad_ts\t\ttest_a\nSTART\t10.0\t\ttest_a\nEND\t10.5\t\ttest_a\n"
        )
        ranges = _parse_markers(f)
        assert len(ranges) == 1

    def test_unmatched_start_is_dropped(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text("START\t10.0\t\ttest_a\n")  # no END
        ranges = _parse_markers(f)
        assert ranges == []

    def test_unmatched_end_is_ignored_and_parsing_continues(self, tmp_path: Path) -> None:
        """A truncated run can leave an END whose START was never written."""
        f = tmp_path / "markers"
        f.write_text("END\t9.0\t\ttest_ghost\nSTART\t10.0\t\ttest_a\nEND\t10.5\t\ttest_a\n")
        ranges = _parse_markers(f)
        assert [r.nodeid for r in ranges] == ["test_a"]

    def test_unknown_marker_kind_is_ignored(self, tmp_path: Path) -> None:
        f = tmp_path / "markers"
        f.write_text("SETUP\t9.0\t\ttest_a\nSTART\t10.0\t\ttest_a\nEND\t10.5\t\ttest_a\n")
        assert [r.nodeid for r in _parse_markers(f)] == ["test_a"]

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
    config.getoption.side_effect = lambda name, *default: allowlist_opt
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

    def test_malformed_pyproject_allowlist_falls_back_to_builtins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken allowlist path in pyproject.toml must not break collection."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text('[tool.netaudit]\nallowlist = "missing.yaml"\n')
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
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed({"tests/test_foo.py::test_bar": [self._make_violation()]}, session)
        out = capsys.readouterr().out
        assert "test_bar" in out
        assert "1.2.3.4" in out
        assert "violation" in out

    def test_sets_exit_code(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed({"test_a": [self._make_violation()]}, session)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_singular_noun_for_one_violation(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed({"test_a": [self._make_violation()]}, session)
        out = capsys.readouterr().out
        assert "1 violation detected" in out

    def test_plural_noun_for_multiple_violations(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
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
        assert group.addoption.call_count == 5
        option_names = [c.args[0] for c in group.addoption.call_args_list]
        assert "--netaudit" in option_names
        assert "--netaudit-allowlist" in option_names
        assert "--netaudit-verbose" in option_names
        assert "--netaudit-suggest-rules" in option_names
        assert "--netaudit-report" in option_names


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
        # Command must invoke python -m pytest (not sys.argv[0] directly)
        assert sys.executable in args
        assert "-m" in args
        assert "pytest" in args
        assert _ENV_STRACE_OUT in env
        assert _ENV_MARKERS_OUT in env

    def test_sweeps_leftovers_from_a_run_that_could_not_clean_up(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A SIGKILLed run leaves both files behind; only the next run can recover them."""
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/strace")
        monkeypatch.setattr(os, "execvpe", lambda *a: None)
        swept: list[object] = []
        monkeypatch.setattr(_tempfiles, "sweep_stale", lambda: swept.append(True) or [])

        pytest_configure(self._make_config(enabled=True))

        assert swept == [True]

    def test_registers_the_temp_files_it_creates_for_cleanup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/strace")
        env: dict[str, str] = {}
        monkeypatch.setattr(os, "execvpe", lambda _n, _a, e: env.update(e))

        pytest_configure(self._make_config(enabled=True))

        try:
            assert Path(env[_ENV_STRACE_OUT]) in _tempfiles._TRACKED
            assert Path(env[_ENV_MARKERS_OUT]) in _tempfiles._TRACKED
        finally:
            _tempfiles.remove_tracked()

    def test_records_the_tracer_pid_so_descendants_can_tell_themselves_apart(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """execvpe keeps the pid, so this is the pid the traced pytest sees as its parent."""
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/strace")
        env: dict[str, str] = {}
        monkeypatch.setattr(os, "execvpe", lambda _n, _a, e: env.update(e))

        pytest_configure(self._make_config(enabled=True))
        _tempfiles.remove_tracked()

        assert env[_ENV_TRACER_PID] == str(os.getpid())

    def test_a_nested_pytest_does_not_take_over_the_outer_runs_files(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A test that shells out to pytest — or an xdist worker — inherits the
        environment, and would otherwise delete a trace that is still being written."""
        monkeypatch.setenv(_ENV_STRACE_OUT, "/tmp/netaudit-x.strace")
        monkeypatch.setenv(_ENV_MARKERS_OUT, "/tmp/netaudit-x.markers")
        monkeypatch.setenv(_ENV_TRACER_PID, str(os.getppid() + 100000))
        registered: list[tuple[Path, ...]] = []
        monkeypatch.setattr(_tempfiles, "remove_on_cancel", lambda *p: registered.append(p))

        pytest_configure(self._make_config(enabled=True))

        assert registered == []

    def test_the_traced_session_recognises_itself_by_its_parent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_STRACE_OUT, "/tmp/netaudit-x.strace")
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        monkeypatch.setenv(_ENV_TRACER_PID, str(os.getppid()))
        registered: list[tuple[Path, ...]] = []
        monkeypatch.setattr(_tempfiles, "remove_on_cancel", lambda *p: registered.append(p))

        pytest_configure(self._make_config(enabled=True))

        assert registered == [(Path("/tmp/netaudit-x.strace"),)]

    def test_the_traced_process_takes_over_cleanup_of_the_temp_files(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The process that created them is gone — execvpe replaced it."""
        monkeypatch.setenv(_ENV_STRACE_OUT, "/tmp/netaudit-x.strace")
        monkeypatch.setenv(_ENV_MARKERS_OUT, "/tmp/netaudit-x.markers")
        registered: list[tuple[Path, ...]] = []
        monkeypatch.setattr(_tempfiles, "remove_on_cancel", lambda *p: registered.append(p))

        pytest_configure(self._make_config(enabled=True))

        assert registered == [(Path("/tmp/netaudit-x.strace"), Path("/tmp/netaudit-x.markers"))]

    def test_takes_over_cleanup_of_the_trace_alone_when_there_are_no_markers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_ENV_STRACE_OUT, "/tmp/netaudit-x.strace")
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        registered: list[tuple[Path, ...]] = []
        monkeypatch.setattr(_tempfiles, "remove_on_cancel", lambda *p: registered.append(p))

        pytest_configure(self._make_config(enabled=True))

        assert registered == [(Path("/tmp/netaudit-x.strace"),)]

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

    def test_a_nested_pytest_does_not_write_into_the_outer_runs_markers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Its nodeids do not exist in the outer suite, and its ranges nest
        inside the outer test's — events would be attributed to a test the
        report's reader cannot find."""
        markers_file = tmp_path / "markers"
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.setenv(_ENV_TRACER_PID, str(os.getppid() + 100000))

        item = MagicMock(spec=pytest.Item)
        item.nodeid = "nested/test_inner.py::test_inner"

        gen = pytest_runtest_protocol(item=item, nextitem=None)
        next(gen)
        with contextlib.suppress(StopIteration):
            gen.send(None)

        assert not markers_file.exists()

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
        session.exitstatus = pytest.ExitCode.OK
        pytest_sessionfinish(session=session, exitstatus=0)
        # exitstatus not changed
        session.exitstatus  # just access it — no assertion needed

    def test_a_nested_pytest_neither_reports_nor_deletes_the_outer_runs_trace(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The outer run is still going: its trace is incomplete and not ours to read."""
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)
        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        monkeypatch.setenv(_ENV_TRACER_PID, str(os.getppid() + 100000))
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK

        pytest_sessionfinish(session=session, exitstatus=0)

        assert strace_file.exists(), "deleted a trace the outer run is still writing"
        assert capsys.readouterr().out == ""
        assert session.exitstatus == pytest.ExitCode.OK

    def test_does_nothing_for_empty_strace_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text("")
        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
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
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)  # no netaudit.yaml → builtin-only allowlist

        config = _mock_config()
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
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
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        config = _mock_config()
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
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
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
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
        session.exitstatus = pytest.ExitCode.OK
        session.config = _mock_config()
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "198.51.100.1" in out
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


# ---------------------------------------------------------------------------
# _resolve_verbose
# ---------------------------------------------------------------------------


def _mock_config_verbose(verbose: bool = False, allowlist_opt: str | None = None) -> MagicMock:
    config = MagicMock(spec=["getoption"])

    def _getoption(name: str, *default: object) -> object:
        if name == "--netaudit-verbose":
            return verbose
        if name == "color":
            return default[0] if default else "auto"
        return allowlist_opt

    config.getoption.side_effect = _getoption
    return config


class TestResolveVerbose:
    def test_cli_flag_true_returns_true(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config = _mock_config_verbose(verbose=True)
        assert _resolve_verbose(config) is True  # type: ignore[arg-type]

    def test_cli_flag_false_returns_false_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config = _mock_config_verbose(verbose=False)
        assert _resolve_verbose(config) is False  # type: ignore[arg-type]

    def test_pyproject_toml_verbose_true(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nverbose = true\n")
        config = _mock_config_verbose(verbose=False)
        assert _resolve_verbose(config) is True  # type: ignore[arg-type]

    def test_pyproject_toml_verbose_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nverbose = false\n")
        config = _mock_config_verbose(verbose=False)
        assert _resolve_verbose(config) is False  # type: ignore[arg-type]

    def test_cli_flag_overrides_pyproject(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nverbose = false\n")
        config = _mock_config_verbose(verbose=True)
        assert _resolve_verbose(config) is True  # type: ignore[arg-type]

    def test_option_not_registered_returns_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config = MagicMock(spec=["getoption"])
        config.getoption.side_effect = ValueError("unknown option")
        assert _resolve_verbose(config) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _emit_attributed_verbose
# ---------------------------------------------------------------------------


class TestEmitAttributedVerbose:
    def _make_event(self, addr: str, ts: float) -> ConnectEvent:
        return ConnectEvent(
            pid=1,
            timestamp=ts,
            family="AF_INET",
            addr=addr,
            port=80,
            result=0,
            raw_line="",
        )

    def test_table_headers_present(self, capsys: pytest.CaptureFixture[str]) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = self._make_event("1.2.3.4", ts=10.5)
        al = AllowList([], includes_builtins=False)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        out = capsys.readouterr().out
        assert "FAMILY" in out
        assert "ADDR:PORT" in out
        assert "STATUS" in out

    def test_allowed_event_shown_with_ok_status(self, capsys: pytest.CaptureFixture[str]) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = self._make_event("127.0.0.1", ts=10.5)
        al = AllowList.empty()  # builtins allow loopback
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        out = capsys.readouterr().out
        assert "OK" in out
        assert "127.0.0.1" in out

    def test_violation_sets_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = self._make_event("1.2.3.4", ts=10.5)
        al = AllowList([], includes_builtins=False)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_event_is_attributed_to_a_later_range(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Ranges are scanned in order; a miss must fall through, not drop the event."""
        ranges = [
            _TestRange(nodeid="test_a", start=10.0, end=11.0),
            _TestRange(nodeid="test_b", start=12.0, end=13.0),
        ]
        event = self._make_event("1.2.3.4", ts=12.5)
        al = AllowList([], includes_builtins=False)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        out = capsys.readouterr().out
        assert "test_b" in out
        assert "test_a" not in out
        assert "<session>" not in out, "the event belongs to a test, not the session"

    def test_no_violations_does_not_set_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = self._make_event("127.0.0.1", ts=10.5)
        al = AllowList.empty()
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        assert session.exitstatus != pytest.ExitCode.TESTS_FAILED

    def test_nodeid_in_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        ranges = [_TestRange(nodeid="tests/test_foo.py::test_bar", start=10.0, end=11.0)]
        event = self._make_event("1.2.3.4", ts=10.5)
        al = AllowList([], includes_builtins=False)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        out = capsys.readouterr().out
        assert "tests/test_foo.py::test_bar" in out

    def test_unattributed_event_goes_to_session_bucket(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ranges: list[_TestRange] = []
        event = self._make_event("1.2.3.4", ts=10.5)
        al = AllowList([], includes_builtins=False)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _emit_attributed_verbose([event], al, ranges, session)
        out = capsys.readouterr().out
        assert "<session>" in out


# ---------------------------------------------------------------------------
# pytest_sessionfinish — verbose paths
# ---------------------------------------------------------------------------


_STRACE_LOOPBACK = (
    "1234 12:00:00.000000 connect(3, {sa_family=AF_INET, "
    'sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
)


class TestPytestSessionfinishVerbose:
    def _make_session(self, verbose: bool = True) -> MagicMock:
        config = _mock_config_verbose(verbose=verbose)
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        session.config = config
        return session

    def test_verbose_with_markers_shows_table_headers(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)
        markers_file = tmp_path / "markers"
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        session = self._make_session(verbose=True)
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "FAMILY" in out
        assert "198.51.100.1" in out
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_verbose_without_markers_shows_table(
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

        session = self._make_session(verbose=True)
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "FAMILY" in out
        assert "198.51.100.1" in out
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_verbose_mode_shows_allowed_events(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_LOOPBACK)
        markers_file = tmp_path / "markers"
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        session = self._make_session(verbose=True)
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "127.0.0.1" in out
        assert "OK" in out
        assert session.exitstatus != pytest.ExitCode.TESTS_FAILED

    def test_non_verbose_mode_unchanged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)
        markers_file = tmp_path / "markers"
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

        session = self._make_session(verbose=False)
        pytest_sessionfinish(session=session, exitstatus=0)

        out = capsys.readouterr().out
        assert "FAMILY" not in out
        assert "198.51.100.1" in out
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


# ---------------------------------------------------------------------------
# _resolve_enabled
# ---------------------------------------------------------------------------


def _mock_config_enabled(cli_flag: bool = False) -> MagicMock:
    config = MagicMock(spec=["getoption"])

    def _getoption(name: str, *default: object) -> object:
        if name == "--netaudit":
            return cli_flag
        return default[0] if default else None

    config.getoption.side_effect = _getoption
    return config


class TestResolveEnabled:
    def test_cli_flag_true_returns_true(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config = _mock_config_enabled(cli_flag=True)
        assert _resolve_enabled(config) is True  # type: ignore[arg-type]

    def test_no_flag_and_no_pyproject_returns_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config = _mock_config_enabled(cli_flag=False)
        assert _resolve_enabled(config) is False  # type: ignore[arg-type]

    def test_pyproject_enabled_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = true\n")
        config = _mock_config_enabled(cli_flag=False)
        assert _resolve_enabled(config) is True  # type: ignore[arg-type]

    def test_pyproject_enabled_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = false\n")
        config = _mock_config_enabled(cli_flag=False)
        assert _resolve_enabled(config) is False  # type: ignore[arg-type]

    def test_cli_flag_overrides_pyproject_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = false\n")
        config = _mock_config_enabled(cli_flag=True)
        assert _resolve_enabled(config) is True  # type: ignore[arg-type]

    def test_pyproject_without_netaudit_section_returns_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n')
        config = _mock_config_enabled(cli_flag=False)
        assert _resolve_enabled(config) is False  # type: ignore[arg-type]

    def test_non_bool_enabled_value_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text('[tool.netaudit]\nenabled = "yes"\n')
        config = _mock_config_enabled(cli_flag=False)
        assert _resolve_enabled(config) is False  # type: ignore[arg-type]

    def test_malformed_pyproject_returns_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit\nenabled = true\n")
        config = _mock_config_enabled(cli_flag=False)
        assert _resolve_enabled(config) is False  # type: ignore[arg-type]

    def test_option_not_registered_ignores_pyproject(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A nested session without the plugin registered must never auto-enable.

        Falling through to pyproject.toml here would re-exec a pytester
        subprocess under strace just because the cwd opts in.
        """
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = true\n")
        config = MagicMock(spec=["getoption"])
        config.getoption.side_effect = ValueError("unknown option")
        assert _resolve_enabled(config) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# pytest_configure — auto-enable via pyproject.toml
# ---------------------------------------------------------------------------


class TestPytestConfigureAutoEnable:
    def _capture_execvpe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> list[tuple[str, list[str], dict[str, str]]]:
        calls: list[tuple[str, list[str], dict[str, str]]] = []
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/strace" if x == "strace" else None)
        monkeypatch.setattr(os, "execvpe", lambda n, a, e: calls.append((n, a, e)))
        return calls

    def test_reexecs_when_pyproject_enabled_without_cli_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = true\n")
        calls = self._capture_execvpe(monkeypatch)

        pytest_configure(_mock_config_enabled(cli_flag=False))  # type: ignore[arg-type]

        assert len(calls) == 1
        assert calls[0][0] == "strace"

    def test_does_not_reexec_when_pyproject_enabled_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = false\n")
        calls = self._capture_execvpe(monkeypatch)

        pytest_configure(_mock_config_enabled(cli_flag=False))  # type: ignore[arg-type]

        assert calls == []

    def test_does_not_reexec_when_no_config_at_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        calls = self._capture_execvpe(monkeypatch)

        pytest_configure(_mock_config_enabled(cli_flag=False))  # type: ignore[arg-type]

        assert calls == []

    def test_cli_flag_still_reexecs_without_pyproject(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        calls = self._capture_execvpe(monkeypatch)

        pytest_configure(_mock_config_enabled(cli_flag=True))  # type: ignore[arg-type]

        assert len(calls) == 1

    def test_auto_enabled_does_not_reexec_when_already_under_strace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = true\n")
        calls = self._capture_execvpe(monkeypatch)
        monkeypatch.setenv(_ENV_STRACE_OUT, "/tmp/fake.strace")

        pytest_configure(_mock_config_enabled(cli_flag=False))  # type: ignore[arg-type]

        assert calls == []

    def test_auto_enabled_raises_usage_error_when_strace_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nenabled = true\n")
        monkeypatch.delenv(_ENV_STRACE_OUT, raising=False)
        monkeypatch.setattr("shutil.which", lambda _: None)

        with pytest.raises(pytest.UsageError, match="strace"):
            pytest_configure(_mock_config_enabled(cli_flag=False))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _resolve_color
# ---------------------------------------------------------------------------


def _mock_session_color(mode: str) -> MagicMock:
    session = MagicMock()
    session.exitstatus = pytest.ExitCode.OK
    session.config.getoption.return_value = mode
    return session


class TestResolveColor:
    """Colour follows pytest's own --color option rather than a netaudit flag."""

    def test_color_yes_forces_on(self) -> None:
        assert _resolve_color(_mock_session_color("yes")) is True

    def test_color_no_forces_off(self) -> None:
        assert _resolve_color(_mock_session_color("no")) is False

    def test_color_auto_defers_to_stream(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        session = _mock_session_color("auto")
        with patch("netaudit.integrations.pytest_plugin.supports_color", return_value=True):
            assert _resolve_color(session) is True

    def test_color_auto_off_for_non_tty(self) -> None:
        session = _mock_session_color("auto")
        with patch("netaudit.integrations.pytest_plugin.supports_color", return_value=False):
            assert _resolve_color(session) is False

    def test_option_not_registered_returns_false(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        session.config.getoption.side_effect = ValueError("unknown option")
        assert _resolve_color(session) is False


class TestEmitAttributedColor:
    def _make_violation(self) -> Violation:
        v = Violation(family="AF_INET", addr="1.2.3.4", port=80)
        v.pids.add(1)
        v.count = 1
        return v

    def test_violations_colored_when_color_yes(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("yes")
        _emit_attributed({"test_a": [self._make_violation()]}, session)
        assert "\033[31m" in capsys.readouterr().out

    def test_no_ansi_when_color_no(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("no")
        _emit_attributed({"test_a": [self._make_violation()]}, session)
        assert "\033[" not in capsys.readouterr().out

    def test_verbose_colored_when_color_yes(self, capsys: pytest.CaptureFixture[str]) -> None:
        ranges = [_TestRange(nodeid="test_a", start=10.0, end=11.0)]
        event = _event("AF_INET", "1.2.3.4", 80, ts=10.5)
        session = _mock_session_color("yes")
        _emit_attributed_verbose([event], AllowList([], includes_builtins=False), ranges, session)
        assert "\033[31m" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _merge_by_destination
# ---------------------------------------------------------------------------


class TestMergeByDestination:
    def _v(self, addr: str, port: int, pid: int, count: int) -> Violation:
        v = Violation(family="AF_INET", addr=addr, port=port)
        v.pids.add(pid)
        v.count = count
        return v

    def test_same_destination_across_tests_is_merged(self) -> None:
        by_test = {
            "test_a": [self._v("1.2.3.4", 80, pid=1, count=2)],
            "test_b": [self._v("1.2.3.4", 80, pid=2, count=3)],
        }
        merged, tests = _merge_by_destination(by_test)
        assert len(merged) == 1
        assert merged[0].count == 5
        assert merged[0].pids == {1, 2}
        assert tests[merged[0].key] == {"test_a", "test_b"}

    def test_distinct_destinations_stay_separate(self) -> None:
        by_test = {
            "test_a": [self._v("1.2.3.4", 80, pid=1, count=1)],
            "test_b": [self._v("5.6.7.8", 443, pid=1, count=1)],
        }
        merged, tests = _merge_by_destination(by_test)
        assert len(merged) == 2

    def test_empty_input(self) -> None:
        merged, tests = _merge_by_destination({})
        assert merged == []
        assert tests == {}


class TestEmitAttributedSummary:
    def _v(self, addr: str) -> Violation:
        v = Violation(family="AF_INET", addr=addr, port=80)
        v.pids.add(1)
        v.count = 1
        return v

    def test_summary_table_emitted(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("no")
        _emit_attributed({"test_a": [self._v("1.2.3.4")]}, session)
        out = capsys.readouterr().out
        assert "ADDR:PORT" in out
        assert "TESTS" in out
        assert "test_a" in out

    def test_summary_lists_every_test_hitting_a_destination(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        session = _mock_session_color("no")
        _emit_attributed({"test_a": [self._v("1.2.3.4")], "test_b": [self._v("1.2.3.4")]}, session)
        out = capsys.readouterr().out
        row = next(ln for ln in out.splitlines() if ln.startswith("1.2.3.4:80"))
        assert "test_a, test_b" in row


# ---------------------------------------------------------------------------
# Test node linking (file:line)
# ---------------------------------------------------------------------------


class TestMarkerLocations:
    def test_location_is_parsed(self, tmp_path: Path) -> None:
        f = tmp_path / "m"
        f.write_text(
            "START\t10.0\ttests/test_api.py:42\ttests/test_api.py::test_a\n"
            "END\t10.5\ttests/test_api.py:42\ttests/test_api.py::test_a\n"
        )
        ranges = _parse_markers(f)
        assert len(ranges) == 1
        assert ranges[0].location == "tests/test_api.py:42"

    def test_empty_location_becomes_none(self, tmp_path: Path) -> None:
        f = tmp_path / "m"
        f.write_text("START\t10.0\t\ttest_a\nEND\t10.5\t\ttest_a\n")
        assert _parse_markers(f)[0].location is None

    def test_nodeid_with_spaces_survives(self, tmp_path: Path) -> None:
        """Parametrized nodeids contain spaces — tabs keep the field intact."""
        nodeid = "tests/test_api.py::test_p[a b c]"
        f = tmp_path / "m"
        f.write_text(f"START\t10.0\tf.py:1\t{nodeid}\nEND\t10.5\tf.py:1\t{nodeid}\n")
        assert _parse_markers(f)[0].nodeid == nodeid

    def test_wrong_field_count_ignored(self, tmp_path: Path) -> None:
        f = tmp_path / "m"
        f.write_text("START\t10.0\ttest_a\n")
        assert _parse_markers(f) == []


class TestEmitAttributedLocations:
    def _v(self) -> Violation:
        v = Violation(family="AF_INET", addr="1.2.3.4", port=80)
        v.pids.add(1)
        v.count = 1
        return v

    def test_location_shown_next_to_nodeid(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("no")
        _emit_attributed(
            {"tests/test_api.py::test_a": [self._v()]},
            session,
            locations={"tests/test_api.py::test_a": "tests/test_api.py:42"},
        )
        out = capsys.readouterr().out
        assert "tests/test_api.py::test_a" in out
        assert "tests/test_api.py:42" in out

    def test_nodeid_alone_when_location_unknown(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("no")
        _emit_attributed({"tests/test_api.py::test_a": [self._v()]}, session, locations={})
        out = capsys.readouterr().out
        assert "tests/test_api.py::test_a" in out
        assert ".py:" not in out.split("tests/test_api.py::test_a")[1].split("\n")[0]


class TestRuntestProtocolLocation:
    def test_writes_location_field(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        markers = tmp_path / "m"
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers))
        item = MagicMock()
        item.nodeid = "tests/test_api.py::test_a"
        item.location = ("tests/test_api.py", 41, "test_a")

        gen = pytest_runtest_protocol(item, None)
        next(gen)
        with contextlib.suppress(StopIteration):
            next(gen)

        lines = markers.read_text().splitlines()
        assert lines[0].split("\t")[2] == "tests/test_api.py:42"  # 0-based -> 1-based

    def test_missing_lineno_writes_empty_location(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        markers = tmp_path / "m"
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers))
        item = MagicMock()
        item.nodeid = "test_a"
        item.location = ("tests/test_api.py", None, "test_a")

        gen = pytest_runtest_protocol(item, None)
        next(gen)
        with contextlib.suppress(StopIteration):
            next(gen)

        assert markers.read_text().splitlines()[0].split("\t")[2] == ""


# ---------------------------------------------------------------------------
# --netaudit-suggest-rules
# ---------------------------------------------------------------------------


class TestResolveSuggestRules:
    def _cfg(self, cli_flag: bool) -> MagicMock:
        config = MagicMock(spec=["getoption"])

        def _getoption(name: str, *default: object) -> object:
            if name == "--netaudit-suggest-rules":
                return cli_flag
            return default[0] if default else None

        config.getoption.side_effect = _getoption
        return config

    def test_cli_flag_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _resolve_suggest_rules(self._cfg(True)) is True  # type: ignore[arg-type]

    def test_default_off(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _resolve_suggest_rules(self._cfg(False)) is False  # type: ignore[arg-type]

    def test_pyproject_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("[tool.netaudit]\nsuggest_rules = true\n")
        assert _resolve_suggest_rules(self._cfg(False)) is True  # type: ignore[arg-type]

    def test_option_not_registered(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config = MagicMock(spec=["getoption"])
        config.getoption.side_effect = ValueError("unknown option")
        assert _resolve_suggest_rules(config) is False  # type: ignore[arg-type]


class TestEmitAttributedSuggestions:
    def _v(self) -> Violation:
        v = Violation(family="AF_INET", addr="1.2.3.4", port=80)
        v.pids.add(1)
        v.count = 1
        return v

    def test_suggestions_emitted_when_enabled(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("no")
        _emit_attributed({"test_a": [self._v()]}, session, suggest_rules=True)
        out = capsys.readouterr().out
        assert "Suggested rules" in out
        assert "addr: 1.2.3.4" in out
        assert "port: 80" in out

    def test_absent_by_default(self, capsys: pytest.CaptureFixture[str]) -> None:
        session = _mock_session_color("no")
        _emit_attributed({"test_a": [self._v()]}, session)
        assert "Suggested rules" not in capsys.readouterr().out

    def test_suggestions_deduplicated_across_tests(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        session = _mock_session_color("no")
        _emit_attributed(
            {"test_a": [self._v()], "test_b": [self._v()]}, session, suggest_rules=True
        )
        assert capsys.readouterr().out.count("addr: 1.2.3.4") == 1


# ---------------------------------------------------------------------------
# Saved report artifact
# ---------------------------------------------------------------------------


class TestResolveReportPath:
    def _cfg(self, cli_value: str | None) -> MagicMock:
        config = MagicMock(spec=["getoption"])

        def _getoption(name: str, *default: object) -> object:
            if name == "--netaudit-report":
                return cli_value
            return default[0] if default else None

        config.getoption.side_effect = _getoption
        return config

    def test_cli_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _resolve_report_path(self._cfg("r.json")) == "r.json"  # type: ignore[arg-type]

    def test_none_by_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert _resolve_report_path(self._cfg(None)) is None  # type: ignore[arg-type]

    def test_pyproject_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text('[tool.netaudit]\nreport = "out.json"\n')
        assert _resolve_report_path(self._cfg(None)) == "out.json"  # type: ignore[arg-type]

    def test_cli_overrides_pyproject(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text('[tool.netaudit]\nreport = "out.json"\n')
        assert _resolve_report_path(self._cfg("cli.json")) == "cli.json"  # type: ignore[arg-type]

    def test_option_not_registered(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config = MagicMock(spec=["getoption"])
        config.getoption.side_effect = ValueError("unknown option")
        assert _resolve_report_path(config) is None  # type: ignore[arg-type]


class TestWriteReport:
    def _v(self, addr: str = "1.2.3.4") -> Violation:
        v = Violation(family="AF_INET", addr=addr, port=80)
        v.pids.add(1)
        v.count = 1
        return v

    def test_report_has_version_and_run_block(self, tmp_path: Path) -> None:
        out = tmp_path / "r.json"
        _write_report({"test_a": [self._v()]}, out)
        data = json.loads(out.read_text())
        assert data["version"] == 1
        assert data["run"]["netaudit_version"]
        assert data["run"]["command"][:1] == ["pytest"]

    def test_tests_attribution_survives_into_the_artifact(self, tmp_path: Path) -> None:
        """The pytest path is the only source of per-test attribution."""
        out = tmp_path / "r.json"
        _write_report({"test_a": [self._v()], "test_b": [self._v()]}, out)
        dest = json.loads(out.read_text())["summary"]["by_destination"][0]
        assert dest["tests"] == ["test_a", "test_b"]
        assert dest["count"] == 2

    def test_distinct_destinations_kept_separate(self, tmp_path: Path) -> None:
        out = tmp_path / "r.json"
        _write_report({"test_a": [self._v("1.2.3.4"), self._v("5.6.7.8")]}, out)
        assert len(json.loads(out.read_text())["summary"]["by_destination"]) == 2

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        out = tmp_path / "nested" / "dir" / "r.json"
        _write_report({"test_a": [self._v()]}, out)
        assert out.exists()

    def test_clean_session_still_writes_a_report(self, tmp_path: Path) -> None:
        out = tmp_path / "r.json"
        _write_report({}, out)
        assert json.loads(out.read_text())["summary"]["total"] == 0


class TestSessionfinishWritesReport:
    def _make_session(self, report: str | None) -> MagicMock:
        config = MagicMock(spec=["getoption"])

        def _getoption(name: str, *default: object) -> object:
            if name == "--netaudit-report":
                return report
            if name == "color":
                return "no"
            if name in ("--netaudit-verbose", "--netaudit-suggest-rules"):
                return False
            return default[0] if default else None

        config.getoption.side_effect = _getoption
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        session.config = config
        return session

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_EXTERNAL)
        markers_file = tmp_path / "markers"
        markers_file.write_text("START\t43199.0\t\ttest_a\nEND\t43201.0\t\ttest_a\n")
        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.setenv(_ENV_MARKERS_OUT, str(markers_file))
        monkeypatch.chdir(tmp_path)

    def test_report_written_when_requested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._setup(tmp_path, monkeypatch)
        out = tmp_path / "report.json"
        pytest_sessionfinish(session=self._make_session(str(out)), exitstatus=0)
        capsys.readouterr()
        data = json.loads(out.read_text())
        assert data["version"] == 1
        assert data["summary"]["by_destination"][0]["tests"] == ["test_a"]

    def test_no_report_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._setup(tmp_path, monkeypatch)
        pytest_sessionfinish(session=self._make_session(None), exitstatus=0)
        capsys.readouterr()
        assert not list(tmp_path.glob("*.json"))

    def test_report_does_not_change_exit_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._setup(tmp_path, monkeypatch)
        session = self._make_session(str(tmp_path / "report.json"))
        pytest_sessionfinish(session=session, exitstatus=0)
        capsys.readouterr()
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


# ---------------------------------------------------------------------------
# Session exit status must never be downgraded
# ---------------------------------------------------------------------------


class TestFailSession:
    """Violations add a failure; they must not mask a more severe one."""

    def test_ok_session_becomes_tests_failed(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        _fail_session(session)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_already_failed_stays_failed(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        _fail_session(session)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    def test_internal_error_is_not_downgraded(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.INTERNAL_ERROR
        _fail_session(session)
        assert session.exitstatus == pytest.ExitCode.INTERNAL_ERROR

    def test_usage_error_is_not_downgraded(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.USAGE_ERROR
        _fail_session(session)
        assert session.exitstatus == pytest.ExitCode.USAGE_ERROR

    def test_interrupted_is_not_downgraded(self) -> None:
        session = MagicMock()
        session.exitstatus = pytest.ExitCode.INTERRUPTED
        _fail_session(session)
        assert session.exitstatus == pytest.ExitCode.INTERRUPTED

    def test_integer_zero_is_treated_as_ok(self) -> None:
        session = MagicMock()
        session.exitstatus = 0
        _fail_session(session)
        assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


# ---------------------------------------------------------------------------
# pytest_sessionfinish — clean run, no markers
# ---------------------------------------------------------------------------


class TestSessionfinishCleanWithoutMarkers:
    def test_clean_session_leaves_the_exit_status_alone(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Without markers the session-level path still must not fail a clean run."""
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_LOOPBACK)

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        monkeypatch.chdir(tmp_path)

        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        session.config = _mock_config()
        pytest_sessionfinish(session=session, exitstatus=0)

        assert session.exitstatus == pytest.ExitCode.OK
        assert "no violations" in capsys.readouterr().out

    def test_trace_file_is_removed_after_a_clean_run(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        strace_file = tmp_path / "strace.out"
        strace_file.write_text(_STRACE_LOOPBACK)

        monkeypatch.setenv(_ENV_STRACE_OUT, str(strace_file))
        monkeypatch.delenv(_ENV_MARKERS_OUT, raising=False)
        monkeypatch.chdir(tmp_path)

        session = MagicMock()
        session.exitstatus = pytest.ExitCode.OK
        session.config = _mock_config()
        pytest_sessionfinish(session=session, exitstatus=0)

        assert not strace_file.exists()
