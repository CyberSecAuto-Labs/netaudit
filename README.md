# netaudit

[![CI](https://github.com/CyberSecAuto-Labs/netaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/CyberSecAuto-Labs/netaudit/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/netaudit)](https://pypi.org/project/netaudit/)
[![Python](https://img.shields.io/pypi/pyversions/netaudit)](https://pypi.org/project/netaudit/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

CI-native network egress auditing via strace. Wrap any process or test suite, declare what connections are allowed, get pass/fail — no raw strace noise.

## Install

```bash
pip install netaudit
```

**Requires `strace`** (Linux only):

```bash
sudo apt-get install strace   # Debian/Ubuntu
sudo dnf install strace       # RHEL/Fedora
```

## Quick start

1. Create `netaudit.yaml` in your project root:

```yaml
version: 1
allowlist:
  - name: "Internal API"
    family: AF_INET
    addr: 10.0.0.1
    port: 8080
```

2. Run:

```bash
# Trace pytest (or any command) and fail on unexpected connections
netaudit run -- pytest

# Offline analysis of an existing strace log
netaudit analyze /tmp/trace.log

# Machine-readable output for CI artifacts
netaudit run --format json -- make test
```

**Exit codes:** `0` clean · `1` violations · `2` strace not found

## Documentation

Full docs at **[netaudit.readthedocs.io](https://netaudit.readthedocs.io)**:

- [CLI Reference](docs/cli-reference.md)
- [Allowlist DSL](docs/allowlist-dsl.md)
- [Architecture](docs/architecture.md)

## How it works

`netaudit run` spawns your command under `strace -e trace=connect -f -tt`, parses every `connect()` syscall, and checks each against your allowlist. Built-in rules automatically permit loopback, Unix sockets, and AF_NETLINK — you only need to list external destinations.

## Development

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```
