# netaudit

**CI-native network egress auditing via strace.**

`netaudit` wraps any process or test suite under `strace`, collects all `connect()` syscalls, filters them against a declarative allowlist, and reports violations. Commit a config file declaring what's allowed, run tests normally, and get pass/fail with readable output instead of raw strace noise.

## Quick start

### Install

```bash
pip install netaudit
```

`strace` must be installed separately (Linux only):

```bash
# Debian/Ubuntu
sudo apt-get install strace

# RHEL/Fedora
sudo dnf install strace
```

### Create an allowlist

```yaml title="netaudit.yaml"
version: 1
allowlist:
  - name: "Internal API"
    family: AF_INET
    addr: 10.0.0.1
    port: 8080
```

### Run

```bash
# Trace a command and report violations
netaudit run -- pytest

# Analyze an existing strace log
netaudit analyze /tmp/trace.log

# Machine-readable output
netaudit run --format json -- pytest
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No violations |
| 1 | One or more violations detected |
| 2 | `strace` not found on PATH |

## How it works

1. `netaudit run` spawns your command under `strace -e trace=connect -f -tt`
2. The output is parsed line-by-line into `ConnectEvent` dataclasses
3. Each event is matched against the allowlist rules
4. Violations (unmatched events) are grouped and reported

Built-in rules always permit loopback (`127.0.0.0/8`, `::1`), Unix sockets, and AF_NETLINK — you only need to list external destinations.
