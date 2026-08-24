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
| `--no-color` | off | Disable coloured output |
| `--suggest-rules` | off | Print allowlist YAML that would permit each violation |
| `--output PATH` / `-o` | stdout | Write the report to PATH instead of stdout |
| `--help` | | Show help |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Command succeeded and made no unallowed connections |
| 83 | Command succeeded, but unallowed connections were detected |
| 84 | `strace` binary not found on PATH |
| *other* | The traced command's own exit code, passed through unchanged |

`run` wraps another process, so most of the exit-code space belongs to that process.
`83` and `84` are netaudit's own; every other value is the command's, passed through.

**A failing command takes precedence over violations.** A command that died part-way may
have produced an incomplete trace, so its failure is the more reliable signal — but any
violations found are still printed.

Whenever the traced command exits non-zero, netaudit writes
`netaudit: traced command exited with N` to stderr and records `run.command_exit_code` in
the JSON report. That also resolves the one ambiguous case: a command that itself exits
`83` or `84`.

!!! tip "Scripting against the result"
    Read the JSON report rather than the exit code. It states the command's status and the
    violation count separately, so nothing depends on reading one integer two ways.

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
| `--no-color` | off | Disable coloured output |
| `--suggest-rules` | off | Print allowlist YAML that would permit each violation |
| `--output PATH` / `-o` | stdout | Write the report to PATH instead of stdout |
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

## Summary table

With `--verbose`, a compact per-destination overview follows the event table:

```
ADDR:PORT                       COUNT  PIDS
------------------------------ ------  ------------------------
198.51.100.1:443                    3  100, 101
203.0.113.7:80                      1  102
```

Destinations are sorted loudest-first, so the noisiest offender is the top row.
The non-verbose report is already one row per destination, so no summary is added there.

In `--format json` the same data is always available under `summary.by_destination`,
regardless of `--verbose`.

## `netaudit undeclared`

```
netaudit undeclared [OPTIONS] REPORT [REPORT ...]
```

Reports the egress that one or more **saved** JSON reports observed but the allowlist does
not permit, merged across them with the evidence behind each entry. Entries are candidates
to review, not recommendations — see [Undeclared Egress](undeclared.md) for the full workflow
and how to read the annotations. Distinct from `--suggest-rules`, which describes only the run that just
happened; `undeclared` answers what egress has been observed that the allowlist does not permit.

```bash
netaudit undeclared ci-reports/*.json
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--allowlist YAML` | none | Existing allowlist — destinations it already permits are omitted |
| `--format {yaml,json}` | `yaml` | Output format |
| `--no-color` | off | Disable coloured output |
| `--output PATH` / `-o` | stdout | Write the rules to PATH instead of stdout |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No undeclared egress found |
| 1 | Undeclared egress found |
| 2 | A report could not be read, or its schema version is unsupported |

Same sense as `run` and `analyze`: non-zero means something needs attention. `undeclared` can
therefore be used directly as a CI assertion, with no flag to flip its meaning:

```bash
netaudit undeclared --allowlist netaudit.yaml reports/*.json
```

Status messages go to stderr, so a redirected rules file only ever contains YAML. Reports
whose `version` this netaudit does not recognise are refused rather than parsed
optimistically — misreading evidence is worse than failing.

## Saving a report

`--output PATH` writes the report to a file instead of stdout. Combined with
`--format json` this produces a durable, self-describing artifact:

```bash
netaudit run --format json --output report.json -- pytest
```

The saved report carries a schema `version` and a `run` block recording the timestamp,
hostname, netaudit version, and either the traced command or the analysed log:

```json
{
  "version": 1,
  "run": {
    "timestamp": "2026-08-23T14:03:38.499417+00:00",
    "hostname": "ci-runner-4",
    "netaudit_version": "0.5.0",
    "command": ["pytest"],
    "allowlist": "netaudit.yaml"
  },
  "violations": [...],
  "summary": {...}
}
```

Reports written to a file are never coloured, whatever stdout happens to be. A clean run
still writes a report — an empty result is evidence too.

## Suggesting rules

`--suggest-rules` prints a ready-to-paste allowlist block for every violation:

```console
$ netaudit analyze --suggest-rules trace.log
...
# Suggested rules to allow these connections:
  - name: "allow 198.51.100.1:443"
    family: AF_INET
    addr: 198.51.100.1
    port: 443
```

Rules are scoped as narrowly as the observed connection allows — exact address, and
exact port when the connection had one. Paste them under the `allowlist:` key of your
config to turn a violation into an explicit, reviewable exception.

Suggestions never change the exit code: violations still exit `83` under `run` and `1`
under `analyze`. With `--format json` they appear under the `suggested_rules` key instead.

## Coloured output

Violations are printed in red and clean results in green when stdout is a terminal.
Colour is suppressed automatically when output is piped or redirected, so captured
logs stay free of escape codes.

To turn it off explicitly:

| Method | Scope |
|--------|-------|
| `--no-color` | The single invocation |
| `NO_COLOR=1` environment variable | Every invocation — see [no-color.org](https://no-color.org/) |

Following the convention, `NO_COLOR` applies when it is set to any non-empty value;
setting it to the empty string has no effect. `--format json` is never colourised.
