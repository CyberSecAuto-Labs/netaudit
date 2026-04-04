"""End-to-end integration tests — require strace on PATH (Linux only).

Run with: pytest -m integration
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from netaudit.allowlist import AllowList, IPv4Rule
from netaudit.parser import StraceParser
from netaudit.reporter import Reporter
from netaudit.runner import StraceNotFoundError, StraceRunner

_EGRESS_TARGET = Path(__file__).parent / "egress_target.py"


# ---------------------------------------------------------------------------
# Module-scoped fixtures — run strace once for all tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def runner() -> StraceRunner:
    try:
        return StraceRunner()
    except StraceNotFoundError:
        pytest.skip("strace not available on this platform")


@pytest.fixture(scope="module")
def strace_output(runner: StraceRunner, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("strace") / "out.log"
    runner.run([sys.executable, str(_EGRESS_TARGET)], out)
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_output_file_created_and_nonempty(strace_output: Path) -> None:
    assert strace_output.exists(), "strace output file not created"
    assert strace_output.stat().st_size > 0, "strace output file is empty"


@pytest.mark.integration
def test_parser_extracts_af_inet_events(strace_output: Path) -> None:
    events = StraceParser().parse_stream(strace_output.read_text().splitlines())
    families = {e.family for e in events}
    assert "AF_INET" in families, f"no AF_INET events found; families seen: {families}"


@pytest.mark.integration
def test_external_ip_produces_violation(strace_output: Path) -> None:
    events = StraceParser().parse_stream(strace_output.read_text().splitlines())
    violations = Reporter.check(events, AllowList.empty())
    addrs = {v.addr for v in violations}
    assert "198.51.100.1" in addrs, f"expected 198.51.100.1 in violations; got: {addrs}"


@pytest.mark.integration
def test_loopback_allowed_by_default(strace_output: Path) -> None:
    events = StraceParser().parse_stream(strace_output.read_text().splitlines())
    loopback = [e for e in events if e.addr == "127.0.0.1"]
    assert loopback, "no loopback events recorded — egress_target may have failed"
    violations = Reporter.check(loopback, AllowList.empty())
    loopback_violations = [v for v in violations if v.addr == "127.0.0.1"]
    assert not loopback_violations, "loopback should be allowed by default"


@pytest.mark.integration
def test_unix_socket_allowed_by_default(strace_output: Path) -> None:
    events = StraceParser().parse_stream(strace_output.read_text().splitlines())
    unix_events = [e for e in events if e.family == "AF_UNIX"]
    if not unix_events:
        pytest.skip("no AF_UNIX events captured")
    violations = Reporter.check(unix_events, AllowList.empty())
    assert not violations, f"AF_UNIX should be allowed by default; got: {violations}"


@pytest.mark.integration
def test_netlink_allowed_by_default(strace_output: Path) -> None:
    events = StraceParser().parse_stream(strace_output.read_text().splitlines())
    netlink_events = [e for e in events if e.family == "AF_NETLINK"]
    if not netlink_events:
        pytest.skip("no AF_NETLINK events captured")
    violations = Reporter.check(netlink_events, AllowList.empty())
    assert not violations, f"AF_NETLINK should be allowed by default; got: {violations}"


@pytest.mark.integration
def test_custom_allowlist_passes_external_ip(strace_output: Path) -> None:
    events = StraceParser().parse_stream(strace_output.read_text().splitlines())
    allowlist = AllowList([IPv4Rule("198.51.100.0/24")], includes_builtins=True)
    violations = Reporter.check(events, allowlist)
    assert not any(v.addr == "198.51.100.1" for v in violations), (
        "198.51.100.1 should be allowed when 198.51.100.0/24 is in the allowlist"
    )
