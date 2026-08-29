"""Tests for netaudit's declared public API surface.

Everything named in a module's ``__all__`` is a promise: removing or renaming
it is a breaking change requiring a major version bump. These tests make that
promise executable, so the surface cannot widen, narrow, or shift shape without
someone deciding to let it.

The pinned literals below are the contract. Editing one is how you record a
deliberate API change; a diff there is the review signal.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

import netaudit
from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent

_REPO_ROOT = Path(__file__).resolve().parents[1]

# The modules whose public names are part of the stable contract.
# ``netaudit.cli`` is an entry point and ``netaudit.integrations.*`` are
# framework adapters — neither is library API.
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

# Exact ``__all__`` of every public module. A rename that updates both the
# class and its ``__all__`` entry is still a breaking change — this is what
# catches it.
_MODULE_ALL: dict[str, set[str]] = {
    "netaudit.parser": {"ConnectEvent", "StraceParser"},
    "netaudit.allowlist": {
        "AllowList",
        "IPv4Rule",
        "IPv6Rule",
        "NetlinkRule",
        "Rule",
        "UnixSocketRule",
    },
    "netaudit.reporter": {
        "Destination",
        "LoadedReport",
        "MergedDestination",
        "REPORT_VERSION",
        "Reporter",
        "Violation",
        "build_run_metadata",
        "is_external",
        "load_report",
        "merge_reports",
        "supports_color",
    },
    "netaudit.runner": {"StraceNotFoundError", "StraceProcess", "StraceRunner"},
}

# Public methods and properties of every exported class. Dataclass fields are
# pinned separately below.
_CLASS_MEMBERS: dict[str, set[str]] = {
    "netaudit.parser.ConnectEvent": set(),
    "netaudit.parser.StraceParser": {"parse_line", "parse_stream"},
    "netaudit.allowlist.AllowList": {"empty", "from_yaml", "is_allowed", "match"},
    "netaudit.allowlist.IPv4Rule": {"matches"},
    "netaudit.allowlist.IPv6Rule": {"matches"},
    "netaudit.allowlist.NetlinkRule": {"matches"},
    "netaudit.allowlist.Rule": {"matches"},
    "netaudit.allowlist.UnixSocketRule": {"matches"},
    "netaudit.reporter.Destination": {"key"},
    "netaudit.reporter.LoadedReport": set(),
    "netaudit.reporter.MergedDestination": {"as_violation", "is_external", "key"},
    "netaudit.reporter.Reporter": {
        "check",
        "format",
        "format_json",
        "format_suggestions",
        "format_suggestions_with_evidence",
        "format_summary",
        "format_verbose",
    },
    "netaudit.reporter.Violation": {"key"},
    "netaudit.runner.StraceNotFoundError": set(),
    "netaudit.runner.StraceProcess": {"stop"},
    "netaudit.runner.StraceRunner": {"run", "start"},
}

# Dataclass fields, in order. Order is part of the contract: these types are
# constructed positionally in user code.
_DATACLASS_FIELDS: dict[str, tuple[str, ...]] = {
    "netaudit.parser.ConnectEvent": (
        "pid",
        "timestamp",
        "family",
        "addr",
        "port",
        "result",
        "raw_line",
    ),
    "netaudit.reporter.Violation": (
        "family",
        "addr",
        "port",
        "pids",
        "count",
        "first_timestamp",
    ),
    "netaudit.reporter.Destination": ("family", "addr", "port", "count", "tests"),
    "netaudit.reporter.LoadedReport": ("label", "run", "destinations"),
    "netaudit.reporter.MergedDestination": (
        "family",
        "addr",
        "port",
        "count",
        "tests",
        "reports",
        "total_reports",
    ),
}


def _module(name: str) -> ModuleType:
    return importlib.import_module(name)


def _exported(qualname: str) -> object:
    module_name, _, attr = qualname.rpartition(".")
    return getattr(_module(module_name), attr)


def _public_members(cls: type) -> set[str]:
    """Public methods and properties of *cls*, excluding dataclass fields."""
    fields = {f.name for f in dataclasses.fields(cls)} if dataclasses.is_dataclass(cls) else set()
    members = set()
    for name in dir(cls):
        if name.startswith("_") or name in fields:
            continue
        static = inspect.getattr_static(cls, name, None)
        if isinstance(static, (property, staticmethod, classmethod)) or inspect.isfunction(static):
            members.add(name)
    return members


def _import_netaudit_and_report_modules() -> list[str]:
    """Import netaudit in a clean interpreter, report what came with it."""
    code = "import json, sys; import netaudit; print(json.dumps(sorted(sys.modules)))"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        check=True,
    )
    modules: list[str] = json.loads(proc.stdout)
    return modules


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

    def test_all_has_no_duplicates(self) -> None:
        assert len(netaudit.__all__) == len(set(netaudit.__all__))

    @pytest.mark.parametrize("name", sorted(_TOP_LEVEL))
    def test_name_is_importable(self, name: str) -> None:
        assert getattr(netaudit, name, None) is not None

    def test_star_import_yields_exactly_all(self) -> None:
        """``__all__`` is only a promise if star-import honours it."""
        namespace: dict[str, object] = {}
        exec("from netaudit import *", namespace)  # noqa: S102
        imported = {k for k in namespace if k != "__builtins__"}
        assert imported == _TOP_LEVEL

    def test_reexports_are_the_same_objects_as_the_submodules(self) -> None:
        """A re-export must alias the original, not shadow it with a copy."""
        assert netaudit.ConnectEvent is _module("netaudit.parser").ConnectEvent
        assert netaudit.StraceParser is _module("netaudit.parser").StraceParser
        assert netaudit.AllowList is _module("netaudit.allowlist").AllowList
        assert netaudit.Reporter is _module("netaudit.reporter").Reporter
        assert netaudit.Violation is _module("netaudit.reporter").Violation

    def test_entry_points_are_not_part_of_the_surface(self) -> None:
        """The CLI and the pytest plugin are entry points, not library API."""
        assert "cli" not in netaudit.__all__
        assert "integrations" not in netaudit.__all__


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_is_a_string(self) -> None:
        assert isinstance(netaudit.__version__, str)

    def test_version_is_a_dotted_release(self) -> None:
        parts = netaudit.__version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_version_matches_pyproject(self) -> None:
        """Two places record the version; a release where they disagree is broken."""
        pyproject = _REPO_ROOT / "pyproject.toml"
        if not pyproject.exists():  # pragma: no cover - running from an installed wheel
            pytest.skip("pyproject.toml not available")
        declared = tomllib.loads(pyproject.read_text())["project"]["version"]
        assert netaudit.__version__ == declared


# ---------------------------------------------------------------------------
# Per-module __all__
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module_name", _PUBLIC_MODULES)
class TestModuleAll:
    def test_module_declares_all(self, module_name: str) -> None:
        assert hasattr(_module(module_name), "__all__")

    def test_all_is_a_list_of_strings(self, module_name: str) -> None:
        names = _module(module_name).__all__
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    def test_all_is_sorted(self, module_name: str) -> None:
        names = list(_module(module_name).__all__)
        assert names == sorted(names)

    def test_all_has_no_duplicates(self, module_name: str) -> None:
        names = list(_module(module_name).__all__)
        assert len(names) == len(set(names))

    def test_all_matches_the_pinned_contract(self, module_name: str) -> None:
        """Renaming an export updates both the code and __all__ — this still catches it."""
        assert set(_module(module_name).__all__) == _MODULE_ALL[module_name]

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
        unexported = sorted(defined - set(module.__all__))
        assert unexported == [], f"public but not exported: {unexported}"


# ---------------------------------------------------------------------------
# Shape of the exported objects
# ---------------------------------------------------------------------------


class TestExportedObjectShape:
    @pytest.mark.parametrize("qualname", sorted(_CLASS_MEMBERS))
    def test_class_members_match_the_pinned_contract(self, qualname: str) -> None:
        """Adding or removing a public method changes the API — say so out loud."""
        assert _public_members(_exported(qualname)) == _CLASS_MEMBERS[qualname]  # type: ignore[arg-type]

    @pytest.mark.parametrize("qualname", sorted(_DATACLASS_FIELDS))
    def test_dataclass_fields_match_the_pinned_contract(self, qualname: str) -> None:
        """Field order matters — these types get built positionally."""
        cls = _exported(qualname)
        names = tuple(f.name for f in dataclasses.fields(cls))  # type: ignore[arg-type]
        assert names == _DATACLASS_FIELDS[qualname]

    def test_every_pinned_class_is_actually_exported(self) -> None:
        """Guard the guard: a stale pin must not silently stop testing anything."""
        for qualname in _CLASS_MEMBERS:
            module_name, _, attr = qualname.rpartition(".")
            assert attr in _MODULE_ALL[module_name]


# ---------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------


class TestExportsAreDocumented:
    @staticmethod
    def _documented(name: str, obj: object) -> bool:
        doc = inspect.getdoc(obj) or ""
        # dataclasses synthesise a signature docstring; that is not documentation.
        return bool(doc) and not doc.startswith(f"{name}(")

    @pytest.mark.parametrize("module_name", _PUBLIC_MODULES)
    def test_every_exported_class_and_function_has_a_docstring(self, module_name: str) -> None:
        """These names are what ``help()`` shows a library user."""
        module = _module(module_name)
        undocumented = sorted(
            name
            for name in module.__all__
            if (inspect.isclass(o := getattr(module, name)) or inspect.isfunction(o))
            and not self._documented(name, o)
        )
        assert undocumented == [], f"undocumented exports: {undocumented}"

    @pytest.mark.parametrize("qualname", sorted(_CLASS_MEMBERS))
    def test_every_exported_method_has_a_docstring(self, qualname: str) -> None:
        cls = _exported(qualname)
        undocumented = sorted(
            name for name in _CLASS_MEMBERS[qualname] if not (inspect.getdoc(getattr(cls, name)))
        )
        assert undocumented == [], f"undocumented methods on {qualname}: {undocumented}"


# ---------------------------------------------------------------------------
# Layering — the core must stay framework-agnostic
# ---------------------------------------------------------------------------


class TestImportLayering:
    def test_importing_netaudit_does_not_pull_in_pytest(self) -> None:
        """The core is framework-agnostic; pytest is optional and plugin-only."""
        modules = _import_netaudit_and_report_modules()
        assert "pytest" not in modules
        assert "_pytest" not in modules

    def test_importing_netaudit_does_not_pull_in_the_integrations(self) -> None:
        modules = _import_netaudit_and_report_modules()
        assert [m for m in modules if m.startswith("netaudit.integrations")] == []

    def test_importing_netaudit_does_not_pull_in_the_cli(self) -> None:
        """A library caller should not pay for click."""
        modules = _import_netaudit_and_report_modules()
        assert "netaudit.cli" not in modules

    @pytest.mark.parametrize("module_name", _PUBLIC_MODULES)
    def test_core_module_does_not_import_integrations(self, module_name: str) -> None:
        source = Path(_module(module_name).__file__ or "").read_text()
        assert "netaudit.integrations" not in source


# ---------------------------------------------------------------------------
# The Rule protocol is usable from outside
# ---------------------------------------------------------------------------


class TestRuleProtocolIsUsable:
    """The docs promise any object with ``name`` and ``matches`` can be a rule."""

    class _PortRule:
        name = "custom port rule"

        def matches(self, event: ConnectEvent) -> bool:
            return event.port == 9999

    @staticmethod
    def _event(port: int) -> ConnectEvent:
        return ConnectEvent(
            pid=1,
            timestamp=0.0,
            family="AF_INET",
            addr="198.51.100.1",
            port=port,
            result=0,
            raw_line="",
        )

    def test_a_custom_rule_allows_a_matching_event(self) -> None:
        allowlist = AllowList([self._PortRule()], includes_builtins=False)
        assert allowlist.is_allowed(self._event(9999))

    def test_a_custom_rule_does_not_allow_other_events(self) -> None:
        allowlist = AllowList([self._PortRule()], includes_builtins=False)
        assert not allowlist.is_allowed(self._event(443))

    def test_match_returns_the_custom_rule_itself(self) -> None:
        rule = self._PortRule()
        allowlist = AllowList([rule], includes_builtins=False)
        assert allowlist.match(self._event(9999)) is rule


# ---------------------------------------------------------------------------
# Typing marker
# ---------------------------------------------------------------------------


class TestTypedMarker:
    def test_py_typed_marker_is_present(self) -> None:
        """Without it, type checkers ignore netaudit's annotations entirely."""
        assert (Path(netaudit.__file__ or "").parent / "py.typed").is_file()
