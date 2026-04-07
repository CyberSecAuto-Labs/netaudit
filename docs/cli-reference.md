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
