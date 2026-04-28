# CLI Reference

## Global options

```
netaudit [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--version` | Print version and exit |
| `--help` | Show help and exit |

---

## `netaudit run`

Trace a command under strace and report network violations.

```bash
netaudit run [OPTIONS] -- COMMAND [ARGS]...
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--allowlist YAML` | `netaudit.yaml` in cwd | Path to allowlist file |
| `--format {text,json}` | `text` | Output format |
| `--verbose` / `-v` | off | Show all network events, not just violations |
| `--help` | | Show help |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Command exited cleanly with no violations |
| 1 | One or more network violations detected |
| 2 | `strace` binary not found on PATH |

### Examples

```bash
# Trace pytest with default netaudit.yaml
netaudit run -- pytest

# Explicit allowlist, JSON output
netaudit run --allowlist ci-allowlist.yaml --format json -- make test

# Show every network call with its matching rule
netaudit run --verbose -- curl https://example.com

# Trace a single curl call
netaudit run -- curl https://example.com
```

---

## `netaudit analyze`

Analyze an existing strace log file for network violations (no live tracing).

```bash
netaudit analyze [OPTIONS] STRACE_LOG
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--allowlist YAML` | `netaudit.yaml` in cwd | Path to allowlist file |
| `--format {text,json}` | `text` | Output format |
| `--verbose` / `-v` | off | Show all network events, not just violations |
| `--help` | | Show help |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No violations found in log |
| 1 | One or more violations found |

### Examples

```bash
# Analyze a previously captured trace
netaudit analyze /tmp/strace-output.log

# Show every event, annotated with rule names
netaudit analyze --verbose /tmp/strace-output.log

# JSON report from CI artifact
netaudit analyze --format json trace.log > report.json
```

---

## Text output format

```
============================================================
  netaudit: 2 violations detected
============================================================
  AF_INET 93.184.216.34:443 (count=1, pids=[1234])
  AF_INET6 2606:2800:220:1:248:1893:25c8:1946:80 (count=3, pids=[1234, 5678])
============================================================
```

## Verbose text output format (`--verbose`)

Shows every network event — allowed and violating alike — annotated with the matching rule name.

```
FAMILY       ADDR:PORT                      STATUS     RULE
------------ ------------------------------ ---------- ------------------------
AF_INET      127.0.0.1:80                   OK         loopback (IPv4)
AF_UNIX      /run/dbus/system_bus_socket    OK         unix (builtin)
AF_NETLINK   -                              OK         netlink (builtin)
AF_INET      93.184.216.34:443              VIOLATION  -
```

## JSON output format

```json
{
  "violations": [
    {
      "family": "AF_INET",
      "addr": "93.184.216.34",
      "port": 443,
      "count": 1,
      "pids": [1234]
    }
  ],
  "summary": {
    "total": 1
  }
}
```

## Verbose JSON output format (`--verbose --format json`)

Adds an `"events"` array containing every network event with `"status"` and `"rule"` fields.

```json
{
  "events": [
    {"family": "AF_INET", "addr": "127.0.0.1", "port": 80, "status": "allowed", "rule": "loopback (IPv4)"},
    {"family": "AF_INET", "addr": "93.184.216.34", "port": 443, "status": "violation", "rule": null}
  ],
  "violations": [
    {"family": "AF_INET", "addr": "93.184.216.34", "port": 443, "count": 1, "pids": [1234]}
  ],
  "summary": {"total": 1}
}
```
