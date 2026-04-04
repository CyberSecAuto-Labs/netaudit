"""Allowlist engine — loads rules from YAML and matches ConnectEvents."""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Any, Protocol

import yaml

from netaudit.parser import ConnectEvent

# ---------------------------------------------------------------------------
# Rule protocol
# ---------------------------------------------------------------------------


class Rule(Protocol):
    def matches(self, event: ConnectEvent) -> bool: ...


# ---------------------------------------------------------------------------
# Concrete rule types
# ---------------------------------------------------------------------------


class IPv4Rule:
    """Allow connections whose destination falls within a CIDR block."""

    def __init__(self, cidr: str) -> None:
        self._network = ipaddress.IPv4Network(cidr, strict=False)

    def matches(self, event: ConnectEvent) -> bool:
        if event.family != "AF_INET" or event.addr is None:
            return False
        try:
            return ipaddress.IPv4Address(event.addr) in self._network
        except ValueError:
            return False


class IPv6Rule:
    """Allow connections whose destination falls within an IPv6 CIDR block."""

    def __init__(self, cidr: str) -> None:
        self._network = ipaddress.IPv6Network(cidr, strict=False)

    def matches(self, event: ConnectEvent) -> bool:
        if event.family != "AF_INET6" or event.addr is None:
            return False
        try:
            return ipaddress.IPv6Address(event.addr) in self._network
        except ValueError:
            return False


class UnixSocketRule:
    """Allow Unix socket connections whose path matches a glob pattern."""

    def __init__(self, path_glob: str) -> None:
        self._glob = path_glob

    def matches(self, event: ConnectEvent) -> bool:
        if event.family != "AF_UNIX" or event.addr is None:
            return False
        return fnmatch.fnmatch(event.addr, self._glob)


class NetlinkRule:
    """Allow all AF_NETLINK connections (glibc resolver internals etc.)."""

    def matches(self, event: ConnectEvent) -> bool:
        return event.family == "AF_NETLINK"


# ---------------------------------------------------------------------------
# Built-in defaults
# ---------------------------------------------------------------------------

_BUILTIN_RULES: list[Rule] = [
    IPv4Rule("127.0.0.0/8"),  # IPv4 loopback
    IPv6Rule("::1/128"),  # IPv6 loopback
    UnixSocketRule("*"),  # all AF_UNIX
    NetlinkRule(),  # all AF_NETLINK
]

# ---------------------------------------------------------------------------
# AllowList
# ---------------------------------------------------------------------------


def _rule_from_dict(entry: dict[str, Any]) -> Rule:
    family = entry.get("family", "")
    if family == "AF_INET":
        cidr = entry.get("cidr") or f"{entry['addr']}/32"
        return IPv4Rule(cidr)
    if family == "AF_INET6":
        cidr = entry.get("cidr") or f"{entry['addr']}/128"
        return IPv6Rule(cidr)
    if family == "AF_UNIX":
        glob = entry.get("path_glob") or entry.get("path_prefix", "") + "*"
        return UnixSocketRule(glob)
    if family == "AF_NETLINK":
        return NetlinkRule()
    raise ValueError(f"Unknown family in allowlist entry: {family!r}")


class AllowList:
    def __init__(self, rules: list[Rule], includes_builtins: bool = True) -> None:
        self._rules: list[Rule] = list(rules)
        if includes_builtins:
            self._rules = _BUILTIN_RULES + self._rules

    @classmethod
    def from_yaml(cls, path: Path) -> "AllowList":
        raw = yaml.safe_load(path.read_text())
        includes_builtins = raw.get("includes_builtins", True)
        rules: list[Rule] = []
        for entry in raw.get("allowlist", []):
            rules.append(_rule_from_dict(entry))
        return cls(rules, includes_builtins=includes_builtins)

    @classmethod
    def empty(cls) -> "AllowList":
        """Allowlist with only built-in rules."""
        return cls([], includes_builtins=True)

    def is_allowed(self, event: ConnectEvent) -> bool:
        return any(rule.matches(event) for rule in self._rules)
