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

# Suggest allowlist rules for anything that was blocked
netaudit run --suggest-rules -- pytest

# Save a report, then review undeclared egress across many saved runs
netaudit run --format json --output report.json -- pytest
netaudit triage reports/*.json
```

`triage` reports what those runs touched that your allowlist does not permit — candidates
to review, not recommendations. See [Triage](triage.md).

Exit codes for `netaudit run`:

| Code | Meaning |
|------|---------|
| 0 | Command succeeded, no violations |
| 83 | Command succeeded, violations detected |
| 84 | `strace` not found on PATH |
| *other* | The traced command's own exit code, passed through |

`run` wraps another process, so violations get a reserved code and the wrapped command's
status is never swallowed — a failing test suite still fails.

Exit codes for `netaudit analyze`:

| Code | Meaning |
|------|---------|
| 0 | No violations found in log |
| 1 | One or more violations found |

Exit codes for `netaudit triage`:

| Code | Meaning |
|------|---------|
| 0 | No undeclared egress found |
| 1 | Undeclared egress found |
| 2 | A report could not be read, or its schema version is unsupported |

`analyze` and `triage` wrap nothing, so they keep the whole exit-code space and use `1`
for findings. See the [CLI reference](cli-reference.md#exit-codes) for details.

## How it works

1. `netaudit run` spawns your command under `strace -e trace=connect -f -tt`
2. The output is parsed line-by-line into `ConnectEvent` dataclasses
3. Each event is matched against the allowlist rules
4. Violations (unmatched events) are grouped and reported

Built-in rules always permit loopback (`127.0.0.0/8`, `::1`), Unix sockets, and AF_NETLINK — you only need to list external destinations.

### What it sees, and what it does not

netaudit traces `connect()` and nothing else. That covers the ordinary way a process
reaches a destination — and so the overwhelming majority of egress — but it is not all of
it:

- **UDP sent without `connect()`.** `sendto()` and `sendmsg()` carry the destination in the
  call itself, so a datagram sent on an unconnected socket never appears.
- **TCP Fast Open.** `sendto()`/`sendmsg()` with `MSG_FASTOPEN` opens a TCP connection
  without ever calling `connect()`.
- **io_uring.** Connections submitted through an `io_uring` ring are issued by the kernel
  on the process's behalf and are not `connect()` syscalls.
- **A process netaudit never wrapped.** Only the traced command and its descendants are
  observed.

DNS usually *is* visible, because the glibc resolver connects its socket before sending —
but that depends on the resolver configuration and on which retry path it takes, so treat
it as the common case rather than a guarantee.

Nothing in these categories is reported, so a run that reaches the internet only by one of
them exits 0. If your threat model includes code that is trying not to be seen, netaudit is
not the last line of defence — a network policy is.

