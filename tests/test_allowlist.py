"""Tests for netaudit.allowlist."""

from pathlib import Path

import pytest

from netaudit.allowlist import AllowList, IPv4Rule, IPv6Rule, NetlinkRule, UnixSocketRule
from netaudit.parser import ConnectEvent


def _event(
    family: str,
    addr: str | None = None,
    port: int | None = None,
    pid: int = 1,
    timestamp: float = 0.0,
    result: int = 0,
) -> ConnectEvent:
    return ConnectEvent(
        pid=pid,
        timestamp=timestamp,
        family=family,
        addr=addr,
        port=port,
        result=result,
        raw_line="",
    )


class TestIPv4Rule:
    def test_cidr_match(self) -> None:
        rule = IPv4Rule("10.0.0.0/8")
        assert rule.matches(_event("AF_INET", "10.1.2.3"))

    def test_cidr_no_match(self) -> None:
        rule = IPv4Rule("10.0.0.0/8")
        assert not rule.matches(_event("AF_INET", "192.168.1.1"))

    def test_wrong_family(self) -> None:
        rule = IPv4Rule("0.0.0.0/0")
        assert not rule.matches(_event("AF_INET6", "::1"))

    def test_host_cidr(self) -> None:
        rule = IPv4Rule("127.0.0.1/32")
        assert rule.matches(_event("AF_INET", "127.0.0.1"))
        assert not rule.matches(_event("AF_INET", "127.0.0.2"))


class TestIPv6Rule:
    def test_loopback(self) -> None:
        rule = IPv6Rule("::1/128")
        assert rule.matches(_event("AF_INET6", "::1"))
        assert not rule.matches(_event("AF_INET6", "::2"))

    def test_cidr_block(self) -> None:
        rule = IPv6Rule("2001:db8::/32")
        assert rule.matches(_event("AF_INET6", "2001:db8::1"))
        assert not rule.matches(_event("AF_INET6", "2001:db9::1"))

    def test_wrong_family(self) -> None:
        rule = IPv6Rule("::/0")
        assert not rule.matches(_event("AF_INET", "1.2.3.4"))


class TestUnixSocketRule:
    def test_exact_path(self) -> None:
        rule = UnixSocketRule("/run/foo.sock")
        assert rule.matches(_event("AF_UNIX", "/run/foo.sock"))

    def test_glob_prefix(self) -> None:
        rule = UnixSocketRule("/run/gvmd/*")
        assert rule.matches(_event("AF_UNIX", "/run/gvmd/gvmd.sock"))
        assert not rule.matches(_event("AF_UNIX", "/tmp/other.sock"))

    def test_wildcard_all(self) -> None:
        rule = UnixSocketRule("*")
        assert rule.matches(_event("AF_UNIX", "/any/path"))

    def test_wrong_family(self) -> None:
        rule = UnixSocketRule("*")
        assert not rule.matches(_event("AF_INET", "1.2.3.4"))


class TestNetlinkRule:
    def test_matches_netlink(self) -> None:
        rule = NetlinkRule()
        assert rule.matches(_event("AF_NETLINK"))

    def test_no_match_other(self) -> None:
        rule = NetlinkRule()
        assert not rule.matches(_event("AF_INET", "1.2.3.4"))


class TestAllowListBuiltins:
    def test_loopback_ipv4_allowed(self) -> None:
        al = AllowList.empty()
        assert al.is_allowed(_event("AF_INET", "127.0.0.1", 80))

    def test_loopback_ipv4_subnet_allowed(self) -> None:
        al = AllowList.empty()
        assert al.is_allowed(_event("AF_INET", "127.255.255.255", 80))

    def test_loopback_ipv6_allowed(self) -> None:
        al = AllowList.empty()
        assert al.is_allowed(_event("AF_INET6", "::1", 80))

    def test_unix_allowed(self) -> None:
        al = AllowList.empty()
        assert al.is_allowed(_event("AF_UNIX", "/run/any.sock"))

    def test_netlink_allowed(self) -> None:
        al = AllowList.empty()
        assert al.is_allowed(_event("AF_NETLINK"))

    def test_external_ip_blocked(self) -> None:
        al = AllowList.empty()
        assert not al.is_allowed(_event("AF_INET", "198.51.100.1", 443))

    def test_no_builtins(self) -> None:
        al = AllowList([], includes_builtins=False)
        assert not al.is_allowed(_event("AF_INET", "127.0.0.1", 80))
        assert not al.is_allowed(_event("AF_NETLINK"))


class TestAllowListFromYaml:
    def test_load_ipv4_cidr(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text("version: 1\nallowlist:\n  - family: AF_INET\n    cidr: 10.0.0.0/8\n")
        al = AllowList.from_yaml(yaml_file)
        assert al.is_allowed(_event("AF_INET", "10.1.2.3", 80))
        assert not al.is_allowed(_event("AF_INET", "8.8.8.8", 53))

    def test_load_ipv4_addr(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text("version: 1\nallowlist:\n  - family: AF_INET\n    addr: 192.168.1.1\n")
        al = AllowList.from_yaml(yaml_file)
        assert al.is_allowed(_event("AF_INET", "192.168.1.1", 9393))
        assert not al.is_allowed(_event("AF_INET", "192.168.1.2", 9393))

    def test_load_ipv6(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text(
            'version: 1\nallowlist:\n  - family: AF_INET6\n    addr: "2001:db8::1"\n'
        )
        al = AllowList.from_yaml(yaml_file)
        assert al.is_allowed(_event("AF_INET6", "2001:db8::1", 443))

    def test_load_unix_path_prefix(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text(
            "version: 1\nallowlist:\n  - family: AF_UNIX\n    path_prefix: /run/gvmd/\n"
        )
        al = AllowList.from_yaml(yaml_file)
        assert al.is_allowed(_event("AF_UNIX", "/run/gvmd/gvmd.sock"))
        assert not al.is_allowed(_event("AF_INET", "1.2.3.4", 80))

    def test_load_netlink(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text("version: 1\nallowlist:\n  - family: AF_NETLINK\n")
        al = AllowList.from_yaml(yaml_file)
        assert al.is_allowed(_event("AF_NETLINK"))

    def test_includes_builtins_false(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text(
            "version: 1\nincludes_builtins: false\n"
            "allowlist:\n  - family: AF_INET\n    cidr: 10.0.0.0/8\n"
        )
        al = AllowList.from_yaml(yaml_file)
        assert not al.is_allowed(_event("AF_INET", "127.0.0.1", 80))  # loopback not built-in
        assert al.is_allowed(_event("AF_INET", "10.0.0.1", 80))

    def test_unknown_family_raises(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text("version: 1\nallowlist:\n  - family: AF_BOGUS\n")
        with pytest.raises(ValueError, match="Unknown family"):
            AllowList.from_yaml(yaml_file)

    def test_empty_allowlist(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text("version: 1\nallowlist: []\n")
        al = AllowList.from_yaml(yaml_file)
        # Built-ins still active
        assert al.is_allowed(_event("AF_INET", "127.0.0.1", 80))
        assert not al.is_allowed(_event("AF_INET", "8.8.8.8", 53))
