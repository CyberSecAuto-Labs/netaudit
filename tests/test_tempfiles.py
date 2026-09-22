"""Tests for temp-file lifetime under interruption.

The trace and marker files are created before a run and only removed when it
finishes normally. Anything that stops the process short — CI cancellation,
``docker stop``, ``timeout`` — leaves them behind, and the trace file grows
with the run: a cancelled 8-second suite leaked 24 MB. These tests pin the two
defences: unlink on the cancellation signals, and sweep whatever an unkillable
signal left behind.

The signal handler is exercised here by calling it directly, so every branch is
measured on every platform; ``tests/integration/test_cancellation.py`` fires the
real signals at a real run.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from netaudit import _tempfiles


def _probing(
    monkeypatch: pytest.MonkeyPatch,
    alive: bool = True,
    kill: Callable[[int, int], None] | None = None,
) -> None:
    """Make the pid probe answer without touching the real process table.

    Windows is in the CI matrix and ``os.kill(pid, 0)`` *terminates* a process
    there, so these cases cannot probe for real on every platform. The
    POSIX-only test below is what keeps the answers here honest.
    """
    monkeypatch.setattr(_tempfiles, "_CAN_PROBE_PIDS", True)

    def default(pid: int, sig: int) -> None:
        if not alive:
            raise ProcessLookupError(pid)

    monkeypatch.setattr(os, "kill", kill if kill is not None else default)


def _dead_pid() -> int:
    """A pid that has certainly exited: spawn one and reap it."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give each test its own tracking state and restore signal dispositions."""
    monkeypatch.setattr(_tempfiles, "_TRACKED", set())
    monkeypatch.setattr(_tempfiles, "_PREVIOUS", {})
    saved = {sig: signal.getsignal(sig) for sig in _tempfiles.CANCEL_SIGNALS}
    # Another test may already have installed the handler for real; start from
    # the default so what this test observes is what this test caused.
    for sig in _tempfiles.CANCEL_SIGNALS:
        signal.signal(sig, signal.SIG_DFL)
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


class TestCreate:
    def test_returns_a_file_that_exists(self, tmp_path: Path) -> None:
        path = _tempfiles.create(".strace", directory=tmp_path)
        assert path.exists()

    def test_names_the_file_so_the_sweep_can_recognise_it(self, tmp_path: Path) -> None:
        path = _tempfiles.create(".strace", directory=tmp_path)
        assert path.name.startswith(_tempfiles.PREFIX)
        assert path.suffix == ".strace"

    def test_stamps_the_owning_pid_into_the_name(self, tmp_path: Path) -> None:
        """The sweep needs to know whose file it is, not just how old it is."""
        path = _tempfiles.create(".strace", directory=tmp_path)
        assert path.name.startswith(f"{_tempfiles.PREFIX}{os.getpid()}-")

    def test_tracks_the_file_for_cleanup(self, tmp_path: Path) -> None:
        path = _tempfiles.create(".markers", directory=tmp_path)
        assert path in _tempfiles._TRACKED

    def test_leaves_no_descriptor_open(self, tmp_path: Path) -> None:
        """mkstemp hands back an open fd; strace opens the path itself."""
        path = _tempfiles.create(".strace", directory=tmp_path)
        path.write_text("written by someone else")
        assert path.read_text() == "written by someone else"


class TestRemoveOnCancel:
    def test_tracks_the_paths_it_is_given(self, tmp_path: Path) -> None:
        path = tmp_path / "netaudit-x.strace"
        path.touch()
        _tempfiles.remove_on_cancel(path)
        assert path in _tempfiles._TRACKED

    def test_installs_a_handler_for_every_cancel_signal(self, tmp_path: Path) -> None:
        _tempfiles.remove_on_cancel(tmp_path / "netaudit-x.strace")
        for sig in _tempfiles.CANCEL_SIGNALS:
            assert signal.getsignal(sig) is _tempfiles._on_cancel

    def test_remembers_the_handler_it_replaced(self, tmp_path: Path) -> None:
        def previous(signum: int, frame: Any) -> None:  # pragma: no cover - never called
            pass

        sig = _tempfiles.CANCEL_SIGNALS[0]
        signal.signal(sig, previous)
        _tempfiles.remove_on_cancel(tmp_path / "netaudit-x.strace")
        assert _tempfiles._PREVIOUS[sig] is previous

    def test_registering_twice_does_not_chain_the_handler_to_itself(self, tmp_path: Path) -> None:
        """The second registration must not record us as our own predecessor.

        It would recurse forever the first time a signal arrived.
        """
        _tempfiles.remove_on_cancel(tmp_path / "a.strace")
        _tempfiles.remove_on_cancel(tmp_path / "b.strace")
        for sig in _tempfiles.CANCEL_SIGNALS:
            assert _tempfiles._PREVIOUS[sig] is not _tempfiles._on_cancel

    def test_survives_registration_from_a_worker_thread(self, tmp_path: Path) -> None:
        """signal.signal() only works on the main thread; the rest must still run."""
        path = tmp_path / "netaudit-x.strace"
        error: list[BaseException] = []

        def register() -> None:
            try:
                _tempfiles.remove_on_cancel(path)
            except BaseException as exc:  # pragma: no cover - the failure we are pinning
                error.append(exc)

        thread = threading.Thread(target=register)
        thread.start()
        thread.join()

        assert not error
        assert path in _tempfiles._TRACKED


class TestRemoveTracked:
    def test_unlinks_every_tracked_file(self, tmp_path: Path) -> None:
        first, second = tmp_path / "a.strace", tmp_path / "b.markers"
        first.touch()
        second.touch()
        _tempfiles.remove_on_cancel(first, second)

        _tempfiles.remove_tracked()

        assert not first.exists()
        assert not second.exists()

    def test_leaves_untracked_files_alone(self, tmp_path: Path) -> None:
        bystander = tmp_path / "netaudit-not-ours.strace"
        bystander.touch()
        _tempfiles.remove_tracked()
        assert bystander.exists()

    def test_tolerates_a_file_that_is_already_gone(self, tmp_path: Path) -> None:
        _tempfiles.remove_on_cancel(tmp_path / "never-created.strace")
        _tempfiles.remove_tracked()  # must not raise

    def test_tolerates_a_path_that_cannot_be_unlinked(self, tmp_path: Path) -> None:
        """Cleanup is best-effort: a failure here must not mask the real exit."""
        directory = tmp_path / "a-directory.strace"
        directory.mkdir()
        _tempfiles.remove_on_cancel(directory)
        _tempfiles.remove_tracked()  # must not raise


class TestCancelHandler:
    def test_unlinks_tracked_files_before_chaining(self, tmp_path: Path) -> None:
        path = tmp_path / "netaudit-x.strace"
        path.touch()
        seen: list[bool] = []

        def previous(signum: int, frame: Any) -> None:
            seen.append(path.exists())

        sig = _tempfiles.CANCEL_SIGNALS[0]
        signal.signal(sig, previous)
        _tempfiles.remove_on_cancel(path)

        _tempfiles._on_cancel(sig, None)

        assert seen == [False], "the previous handler ran before the file was removed"

    def test_re_raises_when_the_signal_had_no_python_handler(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no predecessor, restore the default disposition and die from it."""
        path = tmp_path / "netaudit-x.strace"
        path.touch()
        sig = _tempfiles.CANCEL_SIGNALS[0]
        signal.signal(sig, signal.SIG_DFL)
        _tempfiles.remove_on_cancel(path)

        restored: list[tuple[int, Any]] = []
        killed: list[tuple[int, int]] = []
        monkeypatch.setattr(
            signal, "signal", lambda s, h: restored.append((s, h)) or signal.SIG_DFL
        )
        monkeypatch.setattr(os, "kill", lambda pid, s: killed.append((pid, s)))

        _tempfiles._on_cancel(sig, None)

        assert not path.exists()
        assert restored == [(sig, signal.SIG_DFL)]
        assert killed == [(os.getpid(), sig)]


class TestSweepStale:
    def _aged(self, path: Path, age_seconds: float) -> Path:
        path.touch()
        stamp = time.time() - age_seconds
        os.utime(path, (stamp, stamp))
        return path

    def test_removes_a_stale_trace_file(self, tmp_path: Path) -> None:
        stale = self._aged(tmp_path / "netaudit-abc.strace", 48 * 3600)
        _tempfiles.sweep_stale(directory=tmp_path)
        assert not stale.exists()

    def test_removes_a_stale_markers_file(self, tmp_path: Path) -> None:
        stale = self._aged(tmp_path / "netaudit-abc.markers", 48 * 3600)
        _tempfiles.sweep_stale(directory=tmp_path)
        assert not stale.exists()

    def test_keeps_a_file_from_a_run_that_may_still_be_going(self, tmp_path: Path) -> None:
        fresh = self._aged(tmp_path / "netaudit-abc.strace", 60)
        _tempfiles.sweep_stale(directory=tmp_path)
        assert fresh.exists(), "a live run's trace must survive another run starting"

    def test_keeps_files_that_are_not_ours(self, tmp_path: Path) -> None:
        other = self._aged(tmp_path / "tmpXYZ.strace", 48 * 3600)
        also = self._aged(tmp_path / "netaudit-abc.log", 48 * 3600)
        _tempfiles.sweep_stale(directory=tmp_path)
        assert other.exists()
        assert also.exists()

    def test_reports_what_it_removed(self, tmp_path: Path) -> None:
        stale = self._aged(tmp_path / "netaudit-abc.strace", 48 * 3600)
        assert _tempfiles.sweep_stale(directory=tmp_path) == [stale]

    def test_honours_the_age_threshold(self, tmp_path: Path) -> None:
        recent = self._aged(tmp_path / "netaudit-abc.strace", 120)
        assert _tempfiles.sweep_stale(directory=tmp_path, max_age=60) == [recent]

    def test_removes_a_long_abandoned_file_even_if_its_pid_is_in_use(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pid gets reused; a week-old trace is not a running test suite."""
        _probing(monkeypatch, alive=True)
        forgotten = self._aged(tmp_path / f"netaudit-{os.getpid()}-abc.strace", 8 * 24 * 3600)
        assert _tempfiles.sweep_stale(directory=tmp_path) == [forgotten]

    def test_spares_a_file_whose_owner_is_still_running(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A run older than the threshold is still a run. Age alone cannot tell."""
        _probing(monkeypatch, alive=True)
        live = self._aged(tmp_path / f"netaudit-{os.getpid()}-abc.strace", 48 * 3600)
        assert _tempfiles.sweep_stale(directory=tmp_path) == []
        assert live.exists()

    def test_removes_a_file_whose_owner_is_gone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _probing(monkeypatch, alive=False)
        dead = self._aged(tmp_path / "netaudit-4242-abc.strace", 48 * 3600)
        assert _tempfiles.sweep_stale(directory=tmp_path) == [dead]

    def test_treats_an_unsignalable_owner_as_alive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pid owned by another user answers PermissionError — it exists."""

        def refuse(pid: int, sig: int) -> None:
            raise PermissionError(pid)

        _probing(monkeypatch, kill=refuse)
        theirs = self._aged(tmp_path / "netaudit-4242-abc.strace", 48 * 3600)
        assert _tempfiles.sweep_stale(directory=tmp_path) == []
        assert theirs.exists()

    @pytest.mark.skipif(os.name != "posix", reason="os.kill(pid, 0) terminates on Windows")
    def test_reads_the_real_process_table(self, tmp_path: Path) -> None:
        """The probe against real pids, so the mocked cases above stay honest."""
        live = self._aged(tmp_path / f"netaudit-{os.getpid()}-live.strace", 48 * 3600)
        dead = self._aged(tmp_path / f"netaudit-{_dead_pid()}-dead.strace", 48 * 3600)

        assert _tempfiles.sweep_stale(directory=tmp_path) == [dead]
        assert live.exists()

    def test_falls_back_to_age_where_pids_cannot_be_probed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.kill(pid, 0) terminates the process on Windows — never probe there."""
        monkeypatch.setattr(_tempfiles, "_CAN_PROBE_PIDS", False)
        killed: list[object] = []
        monkeypatch.setattr(os, "kill", lambda *a: killed.append(a))
        stale = self._aged(tmp_path / f"netaudit-{os.getpid()}-abc.strace", 48 * 3600)

        assert _tempfiles.sweep_stale(directory=tmp_path) == [stale]
        assert killed == [], "probed a pid on a platform where that is destructive"

    def test_tolerates_a_file_that_vanishes_mid_sweep(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two runs can sweep at once; losing the race is not an error."""
        stale = self._aged(tmp_path / "netaudit-abc.strace", 48 * 3600)

        def vanish(self: Path) -> None:
            raise FileNotFoundError(str(self))

        monkeypatch.setattr(Path, "unlink", vanish)
        assert _tempfiles.sweep_stale(directory=tmp_path) == []
        assert stale.exists(), "the fake unlink did not run — the test proves nothing"

    def test_tolerates_a_missing_temp_directory(self, tmp_path: Path) -> None:
        assert _tempfiles.sweep_stale(directory=tmp_path / "gone") == []

    def test_sweeps_the_system_temp_directory_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        stale = self._aged(tmp_path / "netaudit-abc.strace", 48 * 3600)
        assert _tempfiles.sweep_stale() == [stale]


class TestIsOwnName:
    """The plugin unlinks paths that arrive in the environment; this is the gate."""

    def test_accepts_a_name_create_produced(self) -> None:
        path = _tempfiles.create(".strace")
        try:
            assert _tempfiles.is_own_name(path)
        finally:
            _tempfiles.remove_tracked()

    def test_rejects_a_path_outside_the_temp_directory(self, tmp_path: Path) -> None:
        assert not _tempfiles.is_own_name(tmp_path / "netaudit-1-x.strace")

    def test_rejects_a_name_directly_in_the_temp_directory(self) -> None:
        """The layout that preceded the private directory is no longer adopted."""
        root = Path(tempfile.gettempdir())
        path = root / f"netaudit-{os.getpid()}-flat.strace"
        path.write_text("")
        try:
            assert not _tempfiles.is_own_name(path)
        finally:
            path.unlink()

    def test_rejects_an_unrelated_name_in_the_temp_directory(self) -> None:
        root = Path(tempfile.gettempdir())
        assert not _tempfiles.is_own_name(root / "important.strace")

    def test_rejects_a_name_with_no_owner_pid(self) -> None:
        root = Path(tempfile.gettempdir())
        assert not _tempfiles.is_own_name(root / "netaudit-x.strace")

    def test_rejects_a_suffix_this_module_never_creates(self) -> None:
        root = Path(tempfile.gettempdir())
        assert not _tempfiles.is_own_name(root / "netaudit-1-x.db")

    def test_rejects_a_traversal_back_out_of_the_temp_directory(self) -> None:
        root = Path(tempfile.gettempdir())
        assert not _tempfiles.is_own_name(root / ".." / "netaudit-1-x.strace")

    def test_rejects_a_name_that_does_not_exist(self) -> None:
        directory = _tempfiles.own_directory()
        assert not _tempfiles.is_own_name(directory / "netaudit-1-gone.strace")

    def test_rejects_a_symlink_wearing_the_right_name(self, tmp_path: Path) -> None:
        victim = tmp_path / "important.db"
        victim.write_text("payload")
        link = _tempfiles.own_directory() / f"netaudit-{os.getpid()}-link.strace"
        link.symlink_to(victim)
        try:
            assert not _tempfiles.is_own_name(link)
        finally:
            link.unlink()

    def test_rejects_a_hard_link_wearing_the_right_name(self, tmp_path: Path) -> None:
        """A second name for someone else's inode is not a file this module made."""
        directory = _tempfiles.own_directory()
        victim = directory / "victim"
        victim.write_text("payload")
        link = directory / f"netaudit-{os.getpid()}-hard.strace"
        os.link(victim, link)
        try:
            assert not _tempfiles.is_own_name(link)
        finally:
            link.unlink()
            victim.unlink()

    def test_rejects_a_directory_wearing_the_right_name(self) -> None:
        path = _tempfiles.own_directory() / f"netaudit-{os.getpid()}-dir.strace"
        path.mkdir()
        try:
            assert not _tempfiles.is_own_name(path)
        finally:
            path.rmdir()


class TestKeep:
    """A trace that could not be judged is evidence; nothing may take it away."""

    @pytest.fixture(autouse=True)
    def _isolated(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        """One directory per process is shared by the whole session otherwise."""
        monkeypatch.setattr(_tempfiles, "_TRACKED", set())
        monkeypatch.setattr(_tempfiles, "_OWN_DIRECTORY", None)
        yield
        _tempfiles.remove_tracked()

    def test_a_kept_file_survives_cleanup(self) -> None:
        path = _tempfiles.create(".strace")
        path.write_text("evidence")

        _tempfiles.keep(path)
        _tempfiles.remove_tracked()

        try:
            assert path.read_text() == "evidence"
        finally:
            path.unlink()
            path.parent.rmdir()

    def test_the_directory_holding_it_survives_too(self) -> None:
        """Removing the directory would take the file with it."""
        trace = _tempfiles.create(".strace")
        markers = _tempfiles.create(".markers")
        trace.write_text("evidence")

        _tempfiles.keep(trace)
        _tempfiles.remove_tracked()

        try:
            assert trace.exists() and not markers.exists()
            assert trace.parent.is_dir()
        finally:
            trace.unlink()
            trace.parent.rmdir()

    def test_keeping_a_path_that_was_never_tracked_is_not_an_error(self, tmp_path: Path) -> None:
        _tempfiles.keep(tmp_path / "nothing")


class TestIsOwnDirectory:
    def test_a_file_wearing_a_run_directory_name_is_not_one(self) -> None:
        path = Path(tempfile.gettempdir()) / f"{_tempfiles.PREFIX}{os.getpid()}-notadir"
        path.write_text("")
        try:
            assert not _tempfiles.is_own_directory(path)
        finally:
            path.unlink()


class TestOffPosix:
    """Windows reports neither mode nor owner usefully, and has no strace.

    Nothing there ever writes one of these files, so the checks that are a
    POSIX statement are skipped rather than failed.
    """

    @pytest.fixture(autouse=True)
    def _not_posix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_tempfiles, "_POSIX", False)

    def test_a_directory_is_accepted_without_a_mode_or_owner_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
        directory = tmp_path / f"{_tempfiles.PREFIX}1-abc"
        directory.mkdir(mode=0o755)

        assert _tempfiles.is_own_directory(directory)

    def test_a_file_is_accepted_without_an_owner_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
        directory = tmp_path / f"{_tempfiles.PREFIX}1-abc"
        directory.mkdir(mode=0o755)
        path = directory / f"{_tempfiles.PREFIX}1-abc.strace"
        path.write_text("")

        assert _tempfiles.is_own_name(path)


class TestOwnDirectory:
    """strace reopens the trace by name; the directory is what makes that safe."""

    @pytest.fixture(autouse=True)
    def _isolated(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
        """One directory per process is shared by the whole session otherwise."""
        monkeypatch.setattr(_tempfiles, "_TRACKED", set())
        monkeypatch.setattr(_tempfiles, "_OWN_DIRECTORY", None)
        yield
        _tempfiles.remove_tracked()

    @pytest.mark.skipif(os.name != "posix", reason="Windows has no POSIX mode bits")
    def test_is_private_to_this_user(self) -> None:
        assert stat.S_IMODE(_tempfiles.own_directory().stat().st_mode) == 0o700

    def test_the_trace_lands_inside_it(self) -> None:
        path = _tempfiles.create(".strace")
        try:
            assert path.parent == _tempfiles.own_directory()
        finally:
            _tempfiles.remove_tracked()

    def test_cleanup_takes_the_directory_with_it(self) -> None:
        path = _tempfiles.create(".strace")
        directory = path.parent

        _tempfiles.remove_tracked()

        assert not directory.exists()

    def test_a_directory_with_something_else_in_it_is_left_alone(self) -> None:
        path = _tempfiles.create(".strace")
        directory = path.parent
        stranger = directory / "not-ours"
        stranger.write_text("")
        try:
            _tempfiles.remove_tracked()
            assert directory.exists()
        finally:
            stranger.unlink()
            directory.rmdir()

    def test_a_symlink_left_at_the_remembered_name_is_not_reused(self, tmp_path: Path) -> None:
        """Replacing the directory with a link would redirect the next trace."""
        first = _tempfiles.create(".strace").parent
        _tempfiles.remove_tracked()
        first.symlink_to(tmp_path)
        try:
            assert _tempfiles.own_directory() != first
        finally:
            first.unlink()

    @pytest.mark.skipif(os.name != "posix", reason="Windows has no POSIX mode bits")
    def test_a_directory_belonging_to_someone_else_is_not_removed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """rmdir on a foreign directory would fail anyway; not trying is clearer."""
        path = _tempfiles.create(".strace")
        directory = path.parent
        directory.chmod(0o755)
        try:
            _tempfiles.remove_tracked()
            assert directory.exists()
        finally:
            directory.chmod(0o700)
            directory.rmdir()

    def test_a_removed_directory_is_made_again(self) -> None:
        """A second run in the same process still needs somewhere to write."""
        first = _tempfiles.create(".strace")
        _tempfiles.remove_tracked()

        second = _tempfiles.create(".strace")
        try:
            assert second.parent.is_dir()
            assert second.parent != first.parent
        finally:
            _tempfiles.remove_tracked()


class TestSweepRemovesRunDirectories:
    """The sweep deletes a whole tree, so what it accepts has to stay narrow."""

    _AGE = 48 * 3600

    def _run_dir(self, root: Path, *children: str) -> Path:
        directory = root / f"{_tempfiles.PREFIX}999999-abc"
        directory.mkdir(mode=0o700)
        for name in children:
            (directory / name).write_text("x")
        return directory

    def _age(self, *paths: Path) -> None:
        stale = time.time() - self._AGE
        for path in paths:
            os.utime(path, (stale, stale))

    def test_a_stale_run_directory_goes_with_its_contents(self, tmp_path: Path) -> None:
        name = f"{_tempfiles.PREFIX}999999-abc.strace"
        directory = self._run_dir(tmp_path, name)
        self._age(directory / name, directory)

        assert _tempfiles.sweep_stale(tmp_path, max_age=3600) == [directory]
        assert not directory.exists()

    def test_a_directory_whose_trace_is_still_growing_is_kept(self, tmp_path: Path) -> None:
        """The directory's own mtime stops moving; the trace inside it does not."""
        directory = self._run_dir(tmp_path, f"{_tempfiles.PREFIX}999999-abc.strace")
        self._age(directory)

        assert _tempfiles.sweep_stale(tmp_path, max_age=3600) == []
        assert directory.exists()

    def test_a_directory_holding_anything_unexpected_is_kept(self, tmp_path: Path) -> None:
        """Sharing the prefix is not evidence that the tree is netaudit's."""
        directory = self._run_dir(tmp_path, "someone-elses-work.txt")
        self._age(directory / "someone-elses-work.txt", directory)

        assert _tempfiles.sweep_stale(tmp_path, max_age=3600) == []
        assert directory.exists()

    @pytest.mark.skipif(os.name != "posix", reason="Windows has no POSIX mode bits")
    def test_a_world_readable_directory_is_kept(self, tmp_path: Path) -> None:
        """own_directory makes its own 0700; anything else was made by someone else."""
        directory = self._run_dir(tmp_path, f"{_tempfiles.PREFIX}999999-abc.strace")
        directory.chmod(0o755)
        self._age(directory)

        assert _tempfiles.sweep_stale(tmp_path, max_age=3600) == []
        assert directory.exists()

    def test_a_symlinked_child_is_not_followed(self, tmp_path: Path) -> None:
        """Its target's timestamp is not evidence about this run."""
        outside = tmp_path / "fresh.txt"
        outside.write_text("x")
        directory = self._run_dir(tmp_path)
        (directory / f"{_tempfiles.PREFIX}999999-abc.strace").symlink_to(outside)
        self._age(directory, directory / f"{_tempfiles.PREFIX}999999-abc.strace")

        # The symlink is not a regular file, so the directory is not swept at all.
        assert _tempfiles.sweep_stale(tmp_path, max_age=3600) == []
        assert outside.exists()

    def test_an_unrelated_entry_is_left_alone(self, tmp_path: Path) -> None:
        stranger = tmp_path / f"{_tempfiles.PREFIX}999999-abc.log"
        stranger.write_text("x")
        self._age(stranger)

        assert _tempfiles.sweep_stale(tmp_path, max_age=3600) == []
        assert stranger.exists()
