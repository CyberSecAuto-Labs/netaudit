"""Parser tests against output a real strace produced — require strace (Linux only).

The parser's edge cases are covered in ``tests/test_parser.py`` with
hand-written lines. Those fixtures encode an assumption about what strace
emits, and an assumption can drift from the tool. These tests generate the
awkward shapes for real and assert the parser handles what actually comes back.

Run with: pytest -m integration
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from netaudit.parser import ConnectEvent, StraceParser
from netaudit.runner import StraceNotFoundError, StraceRunner

pytestmark = pytest.mark.integration

# TEST-NET-1/2/3 (RFC 5737) are reserved and unroutable, so a connect() to one
# is traced without depending on the network.
_UNROUTABLE = "192.0.2.1"


@pytest.fixture(scope="module")
def runner() -> StraceRunner:
    try:
        return StraceRunner()
    except StraceNotFoundError:
        pytest.skip("strace not available on this platform")


def _trace(runner: StraceRunner, script: str, out: Path) -> tuple[str, list[ConnectEvent]]:
    """Run *script* under strace; return the raw trace and the parsed events."""
    target = out.parent / "target.py"
    target.write_text(textwrap.dedent(script))
    runner.run([sys.executable, str(target)], out)
    raw = out.read_text()
    return raw, StraceParser().parse_stream(raw.splitlines())


def _to(events: list[ConnectEvent], addr: str) -> list[ConnectEvent]:
    return [e for e in events if e.addr == addr]


# ---------------------------------------------------------------------------
# EINPROGRESS — a non-blocking connect still in flight
# ---------------------------------------------------------------------------


class TestRealEinprogress:
    @pytest.fixture(scope="class")
    @classmethod
    def traced(
        cls, runner: StraceRunner, tmp_path_factory: pytest.TempPathFactory
    ) -> tuple[str, list[ConnectEvent]]:
        out = tmp_path_factory.mktemp("einprogress") / "trace.log"
        return _trace(
            runner,
            f"""
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                s.connect(("{_UNROUTABLE}", 443))
            except (BlockingIOError, OSError):
                pass
            finally:
                s.close()
            """,
            out,
        )

    def test_strace_really_reports_einprogress(
        self, traced: tuple[str, list[ConnectEvent]]
    ) -> None:
        """If this fails the premise is gone, and the assertions below mean nothing."""
        raw, _ = traced
        assert "EINPROGRESS" in raw

    def test_the_connect_is_captured(self, traced: tuple[str, list[ConnectEvent]]) -> None:
        _, events = traced
        assert _to(events, _UNROUTABLE), f"no event for {_UNROUTABLE}"

    def test_in_flight_connect_is_normalised_to_success(
        self, traced: tuple[str, list[ConnectEvent]]
    ) -> None:
        """A connect in flight egressed; reporting it as a failure would hide it."""
        _, events = traced
        assert all(e.result == 0 for e in _to(events, _UNROUTABLE))

    def test_the_port_survives(self, traced: tuple[str, list[ConnectEvent]]) -> None:
        _, events = traced
        assert all(e.port == 443 for e in _to(events, _UNROUTABLE))


# ---------------------------------------------------------------------------
# -f — following forks
# ---------------------------------------------------------------------------


class TestRealForkFollowing:
    @pytest.fixture(scope="class")
    @classmethod
    def traced(
        cls, runner: StraceRunner, tmp_path_factory: pytest.TempPathFactory
    ) -> tuple[str, list[ConnectEvent]]:
        out = tmp_path_factory.mktemp("fork") / "trace.log"
        return _trace(
            runner,
            """
            import os, socket, sys

            def connect(host):
                s = socket.socket()
                s.settimeout(0.2)
                try:
                    s.connect((host, 80))
                except OSError:
                    pass
                finally:
                    s.close()

            pid = os.fork()
            if pid == 0:
                connect("192.0.2.2")
                os._exit(0)
            connect("192.0.2.3")
            os.waitpid(pid, 0)
            """,
            out,
        )

    def test_the_childs_connect_is_captured(self, traced: tuple[str, list[ConnectEvent]]) -> None:
        """Without -f the forked child's egress would be invisible."""
        _, events = traced
        assert _to(events, "192.0.2.2"), "forked child's connect was not traced"

    def test_the_parents_connect_is_captured(self, traced: tuple[str, list[ConnectEvent]]) -> None:
        _, events = traced
        assert _to(events, "192.0.2.3")

    def test_parent_and_child_are_attributed_to_different_pids(
        self, traced: tuple[str, list[ConnectEvent]]
    ) -> None:
        _, events = traced
        child = {e.pid for e in _to(events, "192.0.2.2")}
        parent = {e.pid for e in _to(events, "192.0.2.3")}
        assert child and parent
        assert child.isdisjoint(parent), "fork's egress must not be credited to the parent"


# ---------------------------------------------------------------------------
# Threads — unfinished/resumed interleaving
# ---------------------------------------------------------------------------


class TestRealThreadInterleaving:
    _THREADS = 8

    @pytest.fixture(scope="class")
    @classmethod
    def traced(
        cls, runner: StraceRunner, tmp_path_factory: pytest.TempPathFactory
    ) -> tuple[str, list[ConnectEvent]]:
        out = tmp_path_factory.mktemp("threads") / "trace.log"
        return _trace(
            runner,
            f"""
            import socket, threading

            barrier = threading.Barrier({cls._THREADS})

            def hammer(index):
                barrier.wait()
                s = socket.socket()
                s.settimeout(0.3)
                try:
                    s.connect(("192.0.2.{{}}".format(10 + index), 80))
                except OSError:
                    pass
                finally:
                    s.close()

            threads = [threading.Thread(target=hammer, args=(i,))
                       for i in range({cls._THREADS})]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            """,
            out,
        )

    def test_every_thread_s_connect_is_accounted_for(
        self, traced: tuple[str, list[ConnectEvent]]
    ) -> None:
        """Holds whether or not strace split the calls across lines.

        Concurrent connects make strace emit ``<unfinished ...>`` / ``resumed``
        pairs, but only when the timing works out — so the count is asserted
        rather than the shape.
        """
        _, events = traced
        seen = {e.addr for e in events if e.addr and e.addr.startswith("192.0.2.")}
        expected = {f"192.0.2.{10 + i}" for i in range(self._THREADS)}
        assert seen == expected

    def test_no_event_is_double_counted(self, traced: tuple[str, list[ConnectEvent]]) -> None:
        """A resumed line must not be parsed as a second connect to the same place."""
        _, events = traced
        targets = [e.addr for e in events if e.addr and e.addr.startswith("192.0.2.")]
        assert len(targets) == len(set(targets)), f"duplicate events: {targets}"

    def test_split_lines_do_not_produce_addressless_inet_events(
        self, traced: tuple[str, list[ConnectEvent]]
    ) -> None:
        """Half a syscall is not an event: an AF_INET record needs addr and port."""
        _, events = traced
        broken = [e for e in events if e.family == "AF_INET" and (not e.addr or e.port is None)]
        assert broken == []

    def test_a_resumed_line_is_never_mistaken_for_a_destination(
        self, traced: tuple[str, list[ConnectEvent]]
    ) -> None:
        raw, events = traced
        if "<... connect resumed>" not in raw:
            pytest.skip("strace did not split any connect() on this run")
        resumed = [e for e in events if e.family == "AF_UNKNOWN"]
        assert all(e.addr is None and e.port is None for e in resumed)
