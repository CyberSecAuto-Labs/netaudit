# Architecture

## Two-layer design

`netaudit` is split into a **language-agnostic core** and **framework-specific integrations**.

```
netaudit/
├── runner.py          # Spawns strace, captures output
├── parser.py          # Parses strace lines → ConnectEvent
├── allowlist.py       # YAML-driven rule engine
├── reporter.py        # Groups violations, formats output
├── cli.py             # CLI entry point (run / analyze / triage)
└── integrations/
    └── pytest_plugin.py   # pytest integration (test attribution)
```

The core must not import anything from integrations.

---

## Data flow

```
Command
  │
  ▼
StraceRunner          ← runner.py
  │ strace output file
  ▼
StraceParser          ← parser.py
  │ list[ConnectEvent]
  ▼
Reporter.check()      ← reporter.py + allowlist.py
  │ list[Violation]
  ▼
Reporter.format()     → stdout, or a saved report via --output
```

A saved JSON report closes the loop back into the tool:

```
report.json (xN)
  │
  ▼
load_report()         ← reporter.py
  │ list[LoadedReport]
  ▼
merge_reports()       ← one MergedDestination per (family, addr, port)
  │
  ▼
format_suggestions_with_evidence()  → allowlist YAML + provenance comments
```

This is what `netaudit triage` runs. Reports carry a schema `version`, and one whose
version is unrecognised is refused rather than parsed optimistically.

---

## Core modules

### `runner.py` — `StraceRunner`

Spawns a command wrapped in `strace -e trace=connect -f -tt -o <file>`. Supports both blocking (`run()`) and non-blocking (`start()` / `stop()`) modes.

Raises `StraceNotFoundError` if `strace` is not on PATH.

### `parser.py` — `StraceParser`, `ConnectEvent`

Line-by-line regex parser. Handles:

- `AF_INET` / `AF_INET6` with varying field order across strace versions
- `AF_UNIX` named and abstract namespace paths
- `AF_NETLINK`
- `EINPROGRESS` (non-blocking connect in-flight — treated as success)
- `<unfinished ...>` / `<... connect resumed>` multi-line splits
- Thread interleavings from `strace -f`

Central data type:

```python
@dataclass
class ConnectEvent:
    pid: int
    timestamp: float
    family: str  # "AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK", ...
    addr: str | None  # IP address or socket path
    port: int | None  # TCP/UDP port; None for unix/netlink
    result: int  # 0 = success; negative errno
    raw_line: str
```

### `allowlist.py` — `AllowList`, rule types

Loads rules from YAML or programmatic construction. Rule types:

| Class | Matches |
|-------|---------|
| `IPv4Rule(cidr)` | AF_INET addresses in a CIDR block |
| `IPv6Rule(cidr)` | AF_INET6 addresses in a CIDR block |
| `UnixSocketRule(glob)` | AF_UNIX paths matching a glob |
| `NetlinkRule()` | All AF_NETLINK |

Built-in defaults (loopback + unix + netlink) are prepended to every allowlist unless `includes_builtins: false`.

### `reporter.py` — `Reporter`, `Violation`

`Reporter.check()` filters events against the allowlist and groups identical destinations into `Violation` objects (deduplication by `(family, addr, port)`).

`Reporter.format()` renders a human-readable box and `Reporter.format_json()` returns structured
JSON. Three further renderers build on the same `Violation` list:

| Function | Output |
|---|---|
| `format_verbose()` | Every event — allowed and violating — annotated with the matching rule name |
| `format_summary()` | One row per destination, loudest first; third column is test nodeids when attribution is available, PIDs otherwise |
| `format_suggestions()` | Allowlist YAML that would permit each violation, scoped to exact address and port |
| `format_suggestions_with_evidence()` | The same, for destinations merged across saved reports, annotated with counts and source reports |

### Saved reports

`build_run_metadata()` describes the run that produced a report — timestamp, hostname,
netaudit version, and either the traced command or the analysed log. `Reporter` only
embeds it; callers supply it, so the module stays free of environment introspection.

`load_report()` reads a saved report into a `LoadedReport` (labelled by filename), and
`merge_reports()` collapses destinations across several into `MergedDestination` objects
carrying the evidence — total count, which reports saw it, and the tests responsible
where the pytest plugin preserved them.

`supports_color()` decides whether ANSI escapes are emitted: a TTY check plus the
[NO_COLOR](https://no-color.org/) convention. Colour is passed explicitly into each
renderer as `color=`, keeping `Reporter` free of global state — callers decide policy
(`--no-color` for the CLI, pytest's `--color` for the plugin).

### `cli.py`

Two Click commands:

- `netaudit run -- COMMAND` — live trace + analyze
- `netaudit analyze STRACE_LOG` — offline analysis

Both accept `--allowlist` (defaults to `netaudit.yaml` in cwd) and `--format {text,json}`.

Exit codes: **0** clean, **83** violations, **84** strace missing, anything else the traced
command's own status passed through. `run` shares its exit space with the process it wraps,
so violations take a reserved code and a failing command is never masked; `analyze` and
`triage` wrap nothing and use **1** for findings.

---

## Integrations pattern

Framework integrations follow a single pattern:

1. Re-exec the test process under strace (or attach to the existing PID)
2. Emit timestamp **markers** at session/test boundaries into the strace stream
3. Correlate marker timestamps with `ConnectEvent` timestamps to attribute violations to individual test cases
4. Call the framework's fail mechanism after the session if violations exist

New integrations go in `netaudit/integrations/` and must not require changes to core modules.
