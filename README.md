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

Or use the [Docker image](#docker) — strace is pre-installed.

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
# Trace any command and fail on unexpected connections
netaudit run -- pytest
netaudit run -- curl https://example.com
netaudit run -- ./my-service --port 8080

# Show all network calls annotated with the matching rule name
# Everything after -- is the wrapped command
netaudit run --verbose -- pytest tests/

# Offline analysis of an existing strace log
netaudit analyze /tmp/trace.log

# Machine-readable output for CI artifacts
netaudit run --format json -- make test

# Print ready-to-paste allowlist rules for whatever was blocked
netaudit run --suggest-rules -- pytest tests/

# Save a report for later analysis
netaudit run --format json --output report.json -- pytest
```

Save a report from each CI run, then review the egress they observed that your allowlist
does not permit:

```bash
netaudit undeclared reports/*.json
```

Each entry is annotated with how many connections were seen, which reports saw it, whether
the address is on the public internet, and which tests were responsible. These are
candidates to triage, not recommendations — netaudit cannot tell a dependency phoning home
from your own API, so which of them belong in the allowlist is your call.
See [Undeclared Egress](https://netaudit.readthedocs.io/en/latest/undeclared/).

Violations are printed in red on a terminal; pass `--no-color` or set `NO_COLOR=1` to
turn that off.

A failing command takes precedence over violations, so wrapping a test suite never hides
its failure.

**Exit codes for `run`:** `0` clean · `83` violations · `84` strace not found · `85` allowlist
rejected · any other value is the traced command's own exit code, passed through.

`analyze` and `undeclared` wrap nothing, so they use `0` clean · `1` findings · `2` bad input.

## pytest plugin

Enable automatic auditing of your test suite without changing any test code:

```toml
# pyproject.toml
[tool.netaudit]
enabled = true
allowlist = "netaudit.yaml"
```

```bash
pytest --netaudit                # fail session on violations
pytest --netaudit --netaudit-verbose  # show every connection per test
```

Violations are attributed to the individual test that triggered them.

## Docker

No local strace install needed:

```bash
docker pull ghcr.io/cybersecauto-labs/netaudit:latest

docker run --rm --cap-add SYS_PTRACE \
  -v "$(pwd)/netaudit.yaml:/netaudit.yaml" \
  ghcr.io/cybersecauto-labs/netaudit \
  run --allowlist /netaudit.yaml -- \
  python -c "import socket; socket.create_connection(('example.com', 443)).close()"
```

## Documentation

Full docs at **[netaudit.readthedocs.io](https://netaudit.readthedocs.io)**:

- [CLI Reference](https://netaudit.readthedocs.io/en/latest/cli-reference/)
- [Allowlist DSL](https://netaudit.readthedocs.io/en/latest/allowlist-dsl/)
- [pytest Plugin](https://netaudit.readthedocs.io/en/latest/pytest-plugin/)
- [Docker](https://netaudit.readthedocs.io/en/latest/docker/)
- [Architecture](https://netaudit.readthedocs.io/en/latest/architecture/)
- [Contributing](https://netaudit.readthedocs.io/en/latest/contributing/)

## How it works

`netaudit run` spawns your command under `strace -e trace=connect -f -tt`, parses every
`connect()` syscall, and checks each against your allowlist. Built-in rules automatically
permit loopback, Unix sockets, and AF_NETLINK — you only need to list external destinations.

## Development

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

See [Contributing](https://netaudit.readthedocs.io/en/latest/contributing/) for the full guide.
