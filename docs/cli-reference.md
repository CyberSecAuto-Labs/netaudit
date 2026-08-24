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

Both of netaudit's own codes — `83` and `84` — sit together in the reserved band. Every
other value belongs to the wrapped command.

`run` wraps another process, so most of the exit-code space belongs to that process.
Violations therefore get a reserved code of their own — **83** — and a missing `strace`
gets **84**, leaving the low range free for the wrapped command.

`2` in particular had to move: `pytest.ExitCode.INTERRUPTED` is **2**, so a cancelled or
timed-out test run would otherwise be indistinguishable from "strace isn't installed".
(pytest also uses 3, 4 and 5, which is a second reason the violation code is not 3.)

**A failing command takes precedence over violations.** A command that died part-way may
have produced an incomplete trace, so its failure is the more reliable signal — but any
violations found are still printed. When the traced command exits non-zero, netaudit
writes `netaudit: traced command exited with N` to stderr and records
`run.command_exit_code` in the JSON report, so the value is never lost.

### Why 83

Exit codes are 8 bits — `0`–`255` — and values above that wrap silently, so `exit(256)`
becomes `0`. A violation code must live inside that range, and clear of everything already
spoken for:

| Range | Already used for |
|-------|------------------|
| 0–2 | Success and general errors, near-universally |
| 3–10 | Common application codes — Mocha reports its *failure count* here |
| 64–78 | BSD `sysexits.h` |
| 88–115 | The Linux socket errno block — `111` is `ECONNREFUSED`, `110` `ETIMEDOUT`, `113` `EHOSTUNREACH` |
| 100, 111 | `chpst` (runit/daemontools) — "the wrapper failed to set up" |
| 126–128 | Shell: not executable, not found, bad exit argument |
| 129–192 | Killed by signal (128 + signal number) |
| 255 | Catch-all, and what `exit(-1)` becomes |

That leaves **79–87**, within the 64–113 range conventionally recommended for
application-defined codes.

The socket errno block matters especially here: netaudit reports connection results as
negated errno values, so a report can contain `-111 ECONNREFUSED` — and a network tool
exiting `111` alongside that would be read as a connection failure rather than a policy
violation. The `chpst` clash is the same hazard from the other direction: it is a process
wrapper too, so `111` already means "the wrapper broke" to anyone from that ecosystem.

Sharing a code with something a suite emits routinely teaches people to disregard it, and
a real violation then goes unnoticed. That is why the number is chosen deliberately rather
than taken from the low range.

!!! note "If the traced command itself exits 83 or 84"
    Those two values are netaudit's own, so the meaning is ambiguous from the code alone.
    They were chosen to make that vanishingly unlikely, but nothing rules it out entirely.
    netaudit writes `netaudit: traced command exited with N` to stderr and records
    `run.command_exit_code` in the JSON report, so the two cases stay distinguishable.
    **For anything scripted, read the JSON report rather than the exit code** — it states
    the command's status and the violation count separately, and no choice of number can
    make a single integer carry two independent signals unambiguously.

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

Suggestions never change the exit code: a run with violations still exits 3.
With `--format json` they appear under the `suggested_rules` key instead.

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
