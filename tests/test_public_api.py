"""Tests for netaudit's declared public API surface.

Everything named in a module's ``__all__`` is a promise: removing or renaming
it is a breaking change requiring a major version bump. These tests keep that
promise explicit, so widening the surface is a deliberate act rather than a
side effect of adding a class.
"""

from __future__ import annotations

import importlib
import inspect
from types import ModuleType

import pytest

import netaudit

# The modules whose public names are part of the stable contract.
# ``netaudit.cli`` is an entry point, and ``netaudit.integrations.*`` are
# framework adapters — neither is imported by library callers.
_PUBLIC_MODULES = [
    "netaudit.allowlist",
    "netaudit.parser",
    "netaudit.reporter",
    "netaudit.runner",
]

# What ``import netaudit`` must offer: the three data types, plus the two
# things that produce and evaluate them.
_TOP_LEVEL = {
    "AllowList",
    "ConnectEvent",
    "Reporter",
    "StraceParser",
    "Violation",
    "__version__",
}


def _module(name: str) -> ModuleType:
    return importlib.import_module(name)


# ---------------------------------------------------------------------------
# Top-level re-exports
# ---------------------------------------------------------------------------


class TestTopLevelSurface:
    def test_declares_all(self) -> None:
        assert hasattr(netaudit, "__all__")

    def test_all_is_exactly_the_agreed_surface(self) -> None:
        assert set(netaudit.__all__) == _TOP_LEVEL

    def test_all_is_sorted(self) -> None:
        assert list(netaudit.__all__) == sorted(netaudit.__all__)

    @pytest.mark.parametrize("name", sorted(_TOP_LEVEL))
    def test_name_is_importable(self, name: str) -> None:
        assert getattr(netaudit, name, None) is not None

    def test_reexports_are_the_same_objects_as_the_submodules(self) -> None:
        """A re-export must alias the original, not shadow it with a copy."""
        assert netaudit.ConnectEvent is _module("netaudit.parser").ConnectEvent
        assert netaudit.StraceParser is _module("netaudit.parser").StraceParser
        assert netaudit.AllowList is _module("netaudit.allowlist").AllowList
        assert netaudit.Reporter is _module("netaudit.reporter").Reporter
        assert netaudit.Violation is _module("netaudit.reporter").Violation

    def test_version_is_a_string(self) -> None:
        assert isinstance(netaudit.__version__, str)


# ---------------------------------------------------------------------------
# Per-module __all__
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module_name", _PUBLIC_MODULES)
class TestModuleAll:
    def test_module_declares_all(self, module_name: str) -> None:
        assert hasattr(_module(module_name), "__all__")

    def test_all_is_sorted(self, module_name: str) -> None:
        names = list(_module(module_name).__all__)
        assert names == sorted(names)

    def test_every_exported_name_exists(self, module_name: str) -> None:
        module = _module(module_name)
        missing = [n for n in module.__all__ if not hasattr(module, n)]
        assert missing == []

    def test_no_private_name_is_exported(self, module_name: str) -> None:
        private = [n for n in _module(module_name).__all__ if n.startswith("_")]
        assert private == []

    def test_every_public_definition_is_exported(self, module_name: str) -> None:
        """A new public class or function must be added to __all__ deliberately.

        Failing here means something became part of the API by accident: either
        export it on purpose, or rename it with a leading underscore.
        """
        module = _module(module_name)
        defined = {
            name
            for name, obj in vars(module).items()
            if not name.startswith("_")
            and (inspect.isclass(obj) or inspect.isfunction(obj))
            and getattr(obj, "__module__", None) == module_name
        }
        assert defined <= set(module.__all__), (
            f"not exported: {sorted(defined - set(module.__all__))}"
        )
