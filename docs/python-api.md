# Python API

`netaudit` is a library as well as a CLI. The names below are the supported
surface: they are re-exported from the top-level package and declared in each
module's `__all__`.

## Stability

Every non-underscore name listed in a module's `__all__` is stable. Removing or
renaming one is a breaking change and requires a major version bump.

Anything reachable only by reaching into a submodule — a helper that is not in
`__all__`, or a module not listed here — carries no such promise and may change
in a patch release. `netaudit.cli` and `netaudit.integrations.*` are entry
points, not library API.

## Top-level

```python
from netaudit import AllowList, ConnectEvent, Reporter, StraceParser, Violation
```

| Name | What it is |
|---|---|
| `ConnectEvent` | One observed `connect()` call — pid, timestamp, family, addr, port, result |
| `StraceParser` | Turns strace output lines into `ConnectEvent`s |
| `AllowList` | The rule set an event is evaluated against |
| `Reporter` | Evaluates events and formats the result |
| `Violation` | A destination that no rule allowed, with its evidence |

## Checking a trace

```python
from pathlib import Path

from netaudit import AllowList, Reporter, StraceParser

with open("strace.log") as f:
    events = StraceParser().parse_stream(f)

allowlist = AllowList.from_yaml(Path("netaudit.yaml"))
violations = Reporter.check(events, allowlist)

for v in violations:
    print(v.family, v.addr, v.port, v.count)
```

`AllowList.empty()` gives you the built-in defaults (loopback, Unix sockets,
netlink) with no user rules. Pass `includes_builtins=False` to
`AllowList([...])` to opt out of them entirely.

## Producing a trace

`netaudit.runner` spawns strace itself. It is Linux-only and requires `strace`
on `PATH`.

```python
from pathlib import Path
from netaudit.runner import StraceNotFoundError, StraceRunner

try:
    runner = StraceRunner()
except StraceNotFoundError:
    ...  # strace is not installed

result = runner.run(["curl", "https://example.com"], Path("strace.log"))
print(result.returncode)
```

`StraceRunner.start()` returns a `StraceProcess` instead of blocking; call
`.stop()` on it to wait and collect the result.

## Building an allowlist in code

Rules can be constructed directly instead of loaded from YAML:

```python
from netaudit.allowlist import AllowList, IPv4Rule, UnixSocketRule

allowlist = AllowList(
    [
        IPv4Rule("10.0.0.0/8", name="internal network"),
        IPv4Rule("127.0.0.1/32", name="local proxy", port=9393),
        UnixSocketRule("/run/gvmd/*", name="GVM socket"),
    ]
)
```

Any object satisfying the `Rule` protocol — a `name` attribute and a
`matches(event) -> bool` method — can be passed in the same list.

## Reading saved reports

```python
from pathlib import Path
from netaudit.reporter import load_report, merge_reports

reports = [load_report(p) for p in Path("reports").glob("*.json")]
for dest in merge_reports(reports):
    print(dest.addr, dest.count, f"{len(dest.reports)}/{dest.total_reports} runs")
```

`load_report` refuses a report whose schema `version` it does not recognise,
raising `ValueError` rather than parsing it optimistically.

## Module contents

| Module | `__all__` |
|---|---|
| `netaudit.parser` | `ConnectEvent`, `StraceParser` |
| `netaudit.allowlist` | `AllowList`, `IPv4Rule`, `IPv6Rule`, `NetlinkRule`, `Rule`, `UnixSocketRule` |
| `netaudit.reporter` | `Destination`, `LoadedReport`, `MergedDestination`, `REPORT_VERSION`, `Reporter`, `Violation`, `build_run_metadata`, `is_external`, `load_report`, `merge_reports`, `supports_color` |
| `netaudit.runner` | `StraceNotFoundError`, `StraceProcess`, `StraceRunner` |
