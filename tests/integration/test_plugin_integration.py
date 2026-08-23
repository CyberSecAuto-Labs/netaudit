"""Integration tests for the pytest plugin — require strace (Linux only)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def _netaudit_bin() -> str:
    """Path to the installed console script.

    `python -m netaudit.cli` is not usable: the module has no __main__ guard, so
    it would import and exit 0 having run nothing.
    """
    import shutil

    path = shutil.which("netaudit")
    if path is None:  # pragma: no cover - integration env always installs it
        pytest.skip("netaudit console script not on PATH")
    return path


class TestPluginSession:
    def test_loopback_allowed_by_default(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_loopback():
                import socket
                s = socket.socket()
                try:
                    s.connect(("127.0.0.1", 9))
                except OSError:
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit")
        result.assert_outcomes(passed=1)
        assert result.ret == 0

    def test_external_ip_produces_violation(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit")
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*netaudit*violation*"])

    def test_custom_allowlist_passes_external_ip(self, pytester: pytest.Pytester) -> None:
        allowlist = pytester.makefile(
            ".yaml",
            allowlist="""
version: 1
allowlist:
  - name: "TEST-NET-2 allowed"
    family: AF_INET
    cidr: 198.51.100.0/24
""",
        )
        pytester.makepyfile(
            """
            def test_allowed_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-allowlist", str(allowlist))
        result.assert_outcomes(passed=1)
        assert result.ret == 0

    def test_violation_attributed_to_test(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_clean():
                pass

            def test_violator():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit")
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*test_violator*"])

    def test_no_network_calls_no_violations(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile("def test_pure(): pass")
        result = pytester.runpytest_subprocess("--netaudit")
        result.assert_outcomes(passed=1)
        assert result.ret == 0


class TestPluginVerbose:
    def test_verbose_flag_shows_table_headers(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_loopback():
                import socket
                s = socket.socket()
                try:
                    s.connect(("127.0.0.1", 9))
                except OSError:
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-verbose")
        result.assert_outcomes(passed=1)
        assert result.ret == 0
        result.stdout.fnmatch_lines(["*FAMILY*ADDR*STATUS*"])

    def test_verbose_shows_allowed_events(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_loopback():
                import socket
                s = socket.socket()
                try:
                    s.connect(("127.0.0.1", 9))
                except OSError:
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-verbose")
        result.assert_outcomes(passed=1)
        assert result.ret == 0
        result.stdout.fnmatch_lines(["*OK*"])

    def test_verbose_violations_still_fail(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-verbose")
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*VIOLATION*"])

    def test_verbose_via_pyproject_toml(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_loopback():
                import socket
                s = socket.socket()
                try:
                    s.connect(("127.0.0.1", 9))
                except OSError:
                    pass
                finally:
                    s.close()
            """
        )
        pytester.makefile(
            ".toml",
            pyproject="[tool.netaudit]\nverbose = true\n",
        )
        result = pytester.runpytest_subprocess("--netaudit")
        result.assert_outcomes(passed=1)
        assert result.ret == 0
        result.stdout.fnmatch_lines(["*FAMILY*ADDR*STATUS*"])


class TestPluginAutoEnable:
    """`enabled = true` in pyproject.toml activates auditing without --netaudit."""

    def test_pyproject_enabled_traces_without_cli_flag(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        pytester.makepyprojecttoml("[tool.netaudit]\nenabled = true\n")
        result = pytester.runpytest_subprocess()
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*netaudit*violation*"])

    def test_pyproject_enabled_false_does_not_trace(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        pytester.makepyprojecttoml("[tool.netaudit]\nenabled = false\n")
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(passed=1)
        assert result.ret == 0

    def test_no_pyproject_config_does_not_trace(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            """
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(passed=1)
        assert result.ret == 0


class TestPluginNodeLinking:
    """Violations carry the test's file:line for editor click-through."""

    def test_violation_reports_file_and_line(self, pytester: pytest.Pytester) -> None:
        path = pytester.makepyfile(
            test_egress="""
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        # Derive the expected line from the file rather than hard-coding it, so the
        # assertion proves the reported location really points at the test's `def`.
        lineno = next(
            i
            for i, line in enumerate(path.read_text().splitlines(), start=1)
            if line.startswith("def test_external")
        )
        result = pytester.runpytest_subprocess("--netaudit")
        assert result.ret != 0
        result.stdout.fnmatch_lines([f"*test_egress.py::test_external*test_egress.py:{lineno}*"])

    def test_summary_lists_the_offending_test(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(
            test_egress="""
            def test_external():
                import socket
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.connect(("198.51.100.1", 443))
                except (BlockingIOError, OSError):
                    pass
                finally:
                    s.close()
            """
        )
        result = pytester.runpytest_subprocess("--netaudit")
        result.stdout.fnmatch_lines(["*ADDR:PORT*COUNT*TESTS*"])
        result.stdout.fnmatch_lines(["*198.51.100.1:443*test_egress.py::test_external*"])


class TestPluginSuggestRules:
    """Suggested rules must be valid enough to silence the violation they describe."""

    _EGRESS = """
        def test_external():
            import socket
            s = socket.socket()
            s.setblocking(False)
            try:
                s.connect(("198.51.100.1", 443))
            except (BlockingIOError, OSError):
                pass
            finally:
                s.close()
        """

    def test_suggestions_printed(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(test_egress=self._EGRESS)
        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-suggest-rules")
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*Suggested rules*"])
        result.stdout.fnmatch_lines(["*addr: 198.51.100.1*"])

    def test_absent_without_flag(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(test_egress=self._EGRESS)
        result = pytester.runpytest_subprocess("--netaudit")
        assert "Suggested rules" not in result.stdout.str()

    def test_enabled_via_pyproject(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile(test_egress=self._EGRESS)
        pytester.makepyprojecttoml("[tool.netaudit]\nenabled = true\nsuggest_rules = true\n")
        result = pytester.runpytest_subprocess()
        result.stdout.fnmatch_lines(["*Suggested rules*"])


class TestPluginSavedReport:
    """The saved report is the durable input `netaudit undeclared` will consume."""

    _EGRESS = """
        def test_external():
            import socket
            s = socket.socket()
            s.setblocking(False)
            try:
                s.connect(("198.51.100.1", 443))
            except (BlockingIOError, OSError):
                pass
            finally:
                s.close()
        """

    def test_report_written_with_test_attribution(self, pytester: pytest.Pytester) -> None:
        import json

        pytester.makepyfile(test_egress=self._EGRESS)
        report = pytester.path / "report.json"
        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-report", str(report))
        assert result.ret != 0
        data = json.loads(report.read_text())
        assert data["version"] == 1
        assert data["run"]["netaudit_version"]
        dest = data["summary"]["by_destination"][0]
        assert dest["addr"] == "198.51.100.1"
        assert dest["port"] == 443
        assert dest["tests"] == ["test_egress.py::test_external"]

    def test_report_survives_the_temp_file_cleanup(self, pytester: pytest.Pytester) -> None:
        """strace/marker temp files are unlinked in a finally — the report must not be."""
        pytester.makepyfile(test_egress=self._EGRESS)
        report = pytester.path / "report.json"
        pytester.runpytest_subprocess("--netaudit", "--netaudit-report", str(report))
        assert report.exists()

    def test_report_via_pyproject(self, pytester: pytest.Pytester) -> None:
        import json

        pytester.makepyfile(test_egress=self._EGRESS)
        pytester.makepyprojecttoml('[tool.netaudit]\nenabled = true\nreport = "out/report.json"\n')
        pytester.runpytest_subprocess()
        assert json.loads((pytester.path / "out" / "report.json").read_text())["version"] == 1


class TestSuggestFromPluginReport:
    """End-to-end: a plugin report feeds `netaudit undeclared` with test attribution."""

    _EGRESS = """
        def test_external():
            import socket
            s = socket.socket()
            s.setblocking(False)
            try:
                s.connect(("198.51.100.1", 443))
            except (BlockingIOError, OSError):
                pass
            finally:
                s.close()
        """

    def test_suggest_names_the_test_that_caused_it(self, pytester: pytest.Pytester) -> None:
        import subprocess

        pytester.makepyfile(test_egress=self._EGRESS)
        report = pytester.path / "report.json"
        pytester.runpytest_subprocess("--netaudit", "--netaudit-report", str(report))

        out = subprocess.run(
            [_netaudit_bin(), "undeclared", str(report)],
            capture_output=True,
            text=True,
        )
        # 1 = undeclared egress found, same sense as `run` and `analyze`.
        assert out.returncode == 1, out.stderr
        assert "addr: 198.51.100.1" in out.stdout
        assert "port: 443" in out.stdout
        assert "test_egress.py::test_external" in out.stdout

    def test_suggested_rules_silence_the_original_violation(
        self, pytester: pytest.Pytester
    ) -> None:
        import subprocess

        pytester.makepyfile(test_egress=self._EGRESS)
        report = pytester.path / "report.json"
        pytester.runpytest_subprocess("--netaudit", "--netaudit-report", str(report))

        rules = pytester.path / "rules.yaml"
        # Not check=True: finding undeclared egress is a non-zero exit by design.
        suggested = subprocess.run(
            [_netaudit_bin(), "undeclared", "--output", str(rules), str(report)],
            capture_output=True,
            text=True,
        )
        assert suggested.returncode == 1, suggested.stderr

        allowlist = pytester.path / "netaudit.yaml"
        allowlist.write_text("version: 1\nallowlist:\n" + rules.read_text())

        result = pytester.runpytest_subprocess("--netaudit", "--netaudit-allowlist", str(allowlist))
        result.assert_outcomes(passed=1)
        assert result.ret == 0

        # And the detector agrees: nothing undeclared remains against that allowlist.
        recheck = subprocess.run(
            [_netaudit_bin(), "undeclared", "--allowlist", str(allowlist), str(report)],
            capture_output=True,
            text=True,
        )
        assert recheck.returncode == 0, recheck.stdout
        assert recheck.stdout.strip() == ""
