# pytest Plugin

The netaudit pytest plugin automatically audits network egress during your test suite. It wraps the test process under strace, validates every `connect()` syscall against your allowlist, and attributes violations to the individual test that caused them.

## Requirements

- Linux (strace is Linux-only)
- strace: `sudo apt install strace`

## Quick start

```bash
pip install netaudit
pytest --netaudit
```

## Permanent activation

Add to `pyproject.toml` to avoid passing flags every time:

```toml
[tool.netaudit]
enabled = true
allowlist = "netaudit.yaml"
verbose = true   # optional: show all events, not just violations
```

With `enabled = true`, a plain `pytest` audits the run — no `--netaudit` flag and no
`addopts` entry needed. Setting `enabled = false` (or omitting the key) keeps the
plugin inactive; `--netaudit` still works and overrides the file.

Resolution order for `enabled`:

| Priority | Source |
|---|---|
| 1 | `--netaudit` CLI flag |
| 2 | `enabled = true` in `[tool.netaudit]` in `pyproject.toml` |
| 3 | Default: off |

The `pyproject.toml` is read from the current working directory. Because activation
re-executes the test process under strace, it is resolved before collection starts —
so `enabled` must live in `pyproject.toml`, not in a conftest or an ini option.

## Allowlist resolution

The plugin resolves the allowlist in this priority order:

| Priority | Source |
|---|---|
| 1 | `--netaudit-allowlist <file>` CLI flag |
| 2 | `allowlist = "..."` in `[tool.netaudit]` in `pyproject.toml` |
| 3 | `netaudit.yaml` in the current working directory |
| 4 | Built-in defaults only (loopback, Unix sockets, Netlink) |

## CLI options

| Option | Description |
|---|---|
| `--netaudit` | Enable network auditing for this session |
| `--netaudit-allowlist YAML` | Path to allowlist YAML file |
| `--netaudit-verbose` | Show all network events (allowed and violations) with rule names |
| `--netaudit-suggest-rules` | Print allowlist YAML that would permit each violation |
| `--netaudit-report PATH` | Write a JSON report to PATH for later analysis |

## Verbose mode

Pass `--netaudit-verbose` (or set `verbose = true` in `[tool.netaudit]`) to see every `connect()` event — not just violations. Allowed events are annotated with the matching rule name; violations are marked `VIOLATION`. The session still fails if any violations are found.

```
============================================================
  netaudit: verbose network event report
============================================================

  [tests/test_api.py::test_fetch_data]
FAMILY       ADDR:PORT                      STATUS     RULE
------------ ------------------------------ ---------- ------------------------
AF_INET      127.0.0.1:5432                OK         loopback (IPv4)
AF_INET      93.184.216.34:443             VIOLATION  -
============================================================
```

Resolution order for `verbose`:

| Priority | Source |
|---|---|
| 1 | `--netaudit-verbose` CLI flag |
| 2 | `verbose = true` in `[tool.netaudit]` in `pyproject.toml` |
| 3 | Default: off |

## Test node linking

Each violation block is headed by the standard pytest nodeid, followed by the test's
`file:line` so editors and terminals can jump straight to it:

```
  [tests/test_api.py::TestFetch::test_timeout]  (tests/test_api.py:42)
    AF_INET 198.51.100.1:443 (count=1, pids=[4242])
```

The location is omitted when pytest reports no line number for the item.

## Summary table

After the per-test violations, a summary maps each destination to the tests that
reached it — the inverse of the detail block, which answers "what did this test do?"
rather than "which tests hit this host?":

```
ADDR:PORT                       COUNT  TESTS
------------------------------ ------  ------------------------
198.51.100.1:443                    3  test_api.py::test_fetch, test_api.py::test_sync
```

## Saving a report

`--netaudit-report PATH`, or `report = "..."` in `[tool.netaudit]`, writes a JSON report
alongside the console output. Parent directories are created as needed.

```toml
[tool.netaudit]
enabled = true
report = "netaudit-report.json"
```

The plugin's report is the only one carrying **per-test attribution** — each entry in
`summary.by_destination` lists the tests that reached that destination. The CLI has no
notion of tests, so that information exists nowhere else.

The strace log and marker sidecar are deleted when the session ends; the report is not.
It is written whether or not the run had violations.

## Suggesting rules

Pass `--netaudit-suggest-rules`, or set `suggest_rules = true` in `[tool.netaudit]`,
to append copy-paste-ready allowlist YAML to the report. A destination reached by
several tests yields a single rule, not one per test.

```toml
[tool.netaudit]
enabled = true
suggest_rules = true
```

## Coloured output

Violations are printed in red when the terminal supports it. The plugin follows
pytest's own `--color` option — `--color=no` disables it, `--color=yes` forces it on
even when output is captured — and the `NO_COLOR` environment variable.

## Output

Violations are attributed to the individual test that triggered them:

```
============================================================
  netaudit: 2 violations detected
============================================================

  [tests/test_api.py::test_fetch_data]
    AF_INET 93.184.216.34:443 (count=1, pids=[12345])

  [tests/test_payment.py::test_charge]
    AF_INET 3.33.146.76:443 (count=1, pids=[12346])
============================================================
```

Violations that happen outside of any test (e.g. during session setup) are grouped under `<session>`.

## How it works

1. On first entry to `pytest_configure`, the plugin re-execs the current process under `strace -e trace=connect -f -tt -o <tmpfile>`, setting an environment variable so the second invocation knows it is already traced.
2. During the test run, `pytest_runtest_protocol` writes `START`/`END` timestamp markers around each test to a sidecar file.
3. In `pytest_sessionfinish`, the plugin reads the strace log, cross-references it with the marker file, validates each `connect()` event against the allowlist, and reports attributed violations.
4. If any violations are found, the session exit code is set to non-zero.

## Example allowlist

```yaml
version: 1
allowlist:
  - name: "Internal Postgres"
    family: AF_INET
    addr: 10.0.1.5
    port: 5432
  - name: "Redis cluster subnet"
    family: AF_INET
    cidr: 10.0.2.0/24
  - name: "IPv6 DNS"
    family: AF_INET6
    addr: "2001:4860:4860::8888"
```

See the [Allowlist DSL](allowlist-dsl.md) reference for the full rule syntax.
