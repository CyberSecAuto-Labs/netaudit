# Allowlist DSL

The allowlist is a YAML file that declares which network connections your process is allowed to make. Any connection not matched by a rule is reported as a violation.

## File structure

```yaml
version: 1
allowlist:
  - comment: "Human-readable note (optional)"
    family: AF_INET
    addr: 10.0.0.1
    port: 443
```

The top-level `version` key must be `1`. Each entry in `allowlist` is a rule.

---

## Rule types

### `AF_INET` — IPv4

Allow connections to a specific IPv4 address or CIDR range.

```yaml
# Exact address
- comment: "Internal proxy"
  family: AF_INET
  addr: 10.0.0.1
  port: 9393

# CIDR range (any port)
- comment: "RFC-1918 private range"
  family: AF_INET
  cidr: 10.0.0.0/8
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `addr` | one of `addr`/`cidr` | Exact IPv4 address |
| `cidr` | one of `addr`/`cidr` | IPv4 CIDR block |
| `port` | no | If omitted, any port is allowed |

### `AF_INET6` — IPv6

```yaml
- comment: "IPv6 public DNS"
  family: AF_INET6
  addr: "2001:4860:4860::8888"
  port: 53

# CIDR range
- family: AF_INET6
  cidr: "2001:db8::/32"
```

### `AF_UNIX` — Unix domain sockets

Allow Unix socket connections matching a glob pattern.

```yaml
- comment: "GVM management socket"
  family: AF_UNIX
  path_prefix: /run/gvmd/

# Exact path
- family: AF_UNIX
  path_glob: /tmp/my-app.sock

# All sockets under /var/run
- family: AF_UNIX
  path_glob: /var/run/*
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `path_glob` | one of `path_glob`/`path_prefix` | Full glob pattern |
| `path_prefix` | one of `path_glob`/`path_prefix` | Prefix; expands to `prefix*` |

### `AF_NETLINK` — Netlink

Allow all AF_NETLINK connections (used by glibc resolver internals).

```yaml
- comment: "glibc resolver"
  family: AF_NETLINK
```

---

## Built-in rules

These are always active and do **not** need to be listed in your allowlist:

| Rule | Permits |
|------|---------|
| IPv4 loopback | `127.0.0.0/8` (any port) |
| IPv6 loopback | `::1/128` (any port) |
| AF_UNIX | All Unix domain sockets |
| AF_NETLINK | All Netlink connections |

To disable built-in rules (uncommon):

```yaml
version: 1
includes_builtins: false
allowlist:
  - family: AF_INET
    addr: 127.0.0.1
```

---

## Complete example

```yaml title="netaudit.yaml"
version: 1
allowlist:
  - comment: "PyPI"
    family: AF_INET
    cidr: 151.101.0.0/16
    port: 443

  - comment: "Internal artifact registry"
    family: AF_INET
    addr: 10.1.2.3
    port: 8081

  - comment: "IPv6 PyPI mirror"
    family: AF_INET6
    addr: "2a04:4e42::223"
    port: 443
```
