# Docker

`netaudit` is available as a Docker image from the GitHub Container Registry (GHCR).
The image is built on `python:3.14-slim` with `strace` pre-installed, so no local
setup is required.

## Quick start

```bash
docker pull ghcr.io/cybersecauto-labs/netaudit:latest
```

Run a command and audit its network calls:

```bash
docker run --rm \
  --cap-add SYS_PTRACE \
  -v "$(pwd)/netaudit.yaml:/netaudit.yaml" \
  ghcr.io/cybersecauto-labs/netaudit \
  run --allowlist /netaudit.yaml -- \
  python -c "import socket; socket.create_connection(('example.com', 443)).close()"
```

!!! note "No HTTP client in the image"
    The image ships `strace` and a Python interpreter, not a general-purpose userland —
    there is no `curl` or `wget` in it. Trace your own binaries by mounting them in, or
    drive a connection with the image's own `python`, as above.

!!! note "SYS_PTRACE capability"
    `strace` requires the `SYS_PTRACE` capability.
    Add `--cap-add SYS_PTRACE` (or `--privileged` for debugging) to every `docker run` invocation.

## Image tags

| Tag | Description |
|---|---|
| `latest` | Most recent release |
| `X.Y.Z` | Exact version (e.g. `0.3.0`) |
| `X.Y` | Latest patch for a minor version (e.g. `0.3`) |

## Offline analysis

Mount a strace log produced outside of Docker and analyse it without re-running:

```bash
docker run --rm \
  -v "$(pwd)/strace.log:/strace.log" \
  -v "$(pwd)/netaudit.yaml:/netaudit.yaml" \
  ghcr.io/cybersecauto-labs/netaudit \
  analyze --allowlist /netaudit.yaml /strace.log
```

## Building locally

```bash
git clone https://github.com/CyberSecAuto-Labs/netaudit.git
cd netaudit
docker build -t netaudit .
docker run --rm --cap-add SYS_PTRACE netaudit --help
```
