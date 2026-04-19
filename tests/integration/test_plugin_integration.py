"""Integration tests for the pytest plugin — require strace (Linux only)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


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
        result = pytester.runpytest("--netaudit")
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
        result = pytester.runpytest("--netaudit")
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
        result = pytester.runpytest("--netaudit", "--netaudit-allowlist", str(allowlist))
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
        result = pytester.runpytest("--netaudit")
        assert result.ret != 0
        result.stdout.fnmatch_lines(["*test_violator*"])

    def test_no_tests_no_violations(self, pytester: pytest.Pytester) -> None:
        pytester.makepyfile("# empty test file")
        result = pytester.runpytest("--netaudit")
        assert result.ret == 0
