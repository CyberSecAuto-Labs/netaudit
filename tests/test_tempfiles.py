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
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import pytest

from netaudit import _tempfiles


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give each test its own tracking state and restore signal dispositions."""
    monkeypatch.setattr(_tempfiles, "_TRACKED", set())
    monkeypatch.setattr(_tempfiles, "_PREVIOUS", {})
    saved = {sig: signal.getsignal(sig) for sig in _tempfiles._CANCEL_SIGNALS}
    # Another test may already have installed the handler for real; start from
    # the default so what this test observes is what this test caused.
    for sig in _tempfiles._CANCEL_SIGNALS:
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
        for sig in _tempfiles._CANCEL_SIGNALS:
            assert signal.getsignal(sig) is _tempfiles._on_cancel

    def test_remembers_the_handler_it_replaced(self, tmp_path: Path) -> None:
        def previous(signum: int, frame: Any) -> None:  # pragma: no cover - never called
            pass

        sig = _tempfiles._CANCEL_SIGNALS[0]
        signal.signal(sig, previous)
        _tempfiles.remove_on_cancel(tmp_path / "netaudit-x.strace")
        assert _tempfiles._PREVIOUS[sig] is previous

    def test_registering_twice_does_not_chain_the_handler_to_itself(self, tmp_path: Path) -> None:
        """The second registration must not record us as our own predecessor.

        It would recurse forever the first time a signal arrived.
        """
        _tempfiles.remove_on_cancel(tmp_path / "a.strace")
        _tempfiles.remove_on_cancel(tmp_path / "b.strace")
        for sig in _tempfiles._CANCEL_SIGNALS:
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

        sig = _tempfiles._CANCEL_SIGNALS[0]
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
        sig = _tempfiles._CANCEL_SIGNALS[0]
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
