# Architecture

## Two-layer design

`netaudit` is split into a **language-agnostic core** and **framework-specific integrations**.

```
netaudit/
├── runner.py          # Spawns strace, captures output
├── parser.py          # Parses strace lines → ConnectEvent
├── allowlist.py       # YAML-driven rule engine
├── reporter.py        # Groups violations, formats output
├── cli.py             # CLI entry point (run / analyze)
└── integrations/
    └── pytest_plugin.py   # (future) pytest integration
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
Reporter.format()     → stdout (text or JSON)
```

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
    family: str       # "AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK", ...
    addr: str | None  # IP address or socket path
    port: int | None  # TCP/UDP port; None for unix/netlink
    result: int       # 0 = success; negative errno
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

`Reporter.format()` renders a human-readable box. `Reporter.format_json()` returns structured JSON.

### `cli.py`

Two Click commands:

- `netaudit run -- COMMAND` — live trace + analyze
- `netaudit analyze STRACE_LOG` — offline analysis

Both accept `--allowlist` (defaults to `netaudit.yaml` in cwd) and `--format {text,json}`.

Exit codes: **0** clean, **1** violations, **2** strace missing.

---

## Integrations pattern

Framework integrations follow a single pattern:

1. Re-exec the test process under strace (or attach to the existing PID)
2. Emit timestamp **markers** at session/test boundaries into the strace stream
3. Correlate marker timestamps with `ConnectEvent` timestamps to attribute violations to individual test cases
4. Call the framework's fail mechanism after the session if violations exist

New integrations go in `netaudit/integrations/` and must not require changes to core modules.
