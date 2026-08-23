# Reviewing undeclared egress

`netaudit undeclared` reports the egress that earlier runs observed but your allowlist does
not permit, merged into one reviewable set with the evidence behind each entry.

## What this command does and does not claim

!!! warning "These are candidates, not recommendations"
    The reports this command reads contain **violations** — traffic that was not allowed.
    Some of it is legitimate egress nobody has declared yet. Some of it is exactly what
    netaudit exists to catch: a dependency phoning home, a misconfigured endpoint, a
    compromised package.

    **The command cannot tell those apart.** A repeated `connect()` to an exfiltration
    endpoint and a repeated `connect()` to your own API are identical in the data.
    Deciding which belongs in your allowlist is your judgement to make.

## How it differs from `--suggest-rules`

| | `--suggest-rules` | `netaudit undeclared` |
|---|---|---|
| Question | *What would unblock the run I just did?* | *What undeclared egress have these runs observed?* |
| Input | The run in progress | One or more saved reports |
| When | Inline, at the moment of failure | Later, deliberately, before deciding |
| Output is | A fix | A finding to triage |

Both exist because they answer different questions. Neither replaces the other.

## The workflow

### 1. Save reports in CI

```bash
netaudit run --format json --output "reports/$CI_RUN_ID.json" -- pytest
```

Or from the pytest plugin, which also records **which tests** reached each destination:

```toml
[tool.netaudit]
enabled = true
report = "reports/pytest.json"
```

Reports are written whether or not the run had violations — a clean report is evidence
too. Upload the directory as a CI artifact.

### 2. Suggest rules across them

```bash
netaudit undeclared reports/*.json
```

```yaml
# Undeclared egress observed across 4 runs — 313 connections.
# These are destinations your allowlist does not permit. Each is a question,
# not a recommendation: decide which belong before committing any of them.
  - name: "allow 10.0.0.5:8080"
    # 160 calls · 4/4 runs · internal · run-1.json, ... · tests: test_fetch
    family: AF_INET
    addr: 10.0.0.5
    port: 8080
# ! external host reached on every run (4/4) — never declared
  - name: "allow 185.199.108.153:443"
    # 152 calls · 4/4 runs · external · run-1.json, ... · tests: test_helper
    family: AF_INET
    addr: 185.199.108.153
    port: 443
```

### 3. Review, then commit

Paste the rules under the `allowlist:` key of your config. The evidence lives in
comments, so it survives the copy-paste and the YAML still parses.

## Reading the evidence

Approving a merged set in bulk is how egress nobody reviewed ends up allowed, so every
entry states its case:

| Annotation | Meaning |
|---|---|
| `160 calls` | Total connections observed across all reports |
| `4/4 runs` | How many of the supplied reports saw this destination |
| `internal` / `external` | Whether the address is globally routable |
| `run-1.json, ...` | Which reports, by name |
| `tests: ...` | Tests that reached it, when the report came from the pytest plugin |

### Why externality, and not rarity

An obvious heuristic is to flag destinations seen in only a few runs — a one-off looks
more like an accident than a dependency. That heuristic is backwards for the case that
matters most. **Persistent unwanted egress has the opposite signature:** something
beaconing on every run scores `402 calls · 12/12 runs`, sorts to the top, and reads as the
best-justified entry in the set.

High evidence means well-*attested*, not well-*justified*. So the callout keys on whether
the address is **globally routable** — a checkable fact rather than a guess at intent:

| Destination | Callout |
|---|---|
| Not globally routable, any pattern | none — tagged `internal` |
| Globally routable, every run | `! external host reached on every run (N/N) — never declared` |
| Globally routable, some runs | `! external host reached in n of N runs — never declared` |
| Globally routable, one report supplied | `! external host — never declared` |

Both callouts say *look at this*. Neither says *this one is fine*.

Entries are sorted by connection count descending. That is a default ordering by volume —
**not** a ranking by how justified an entry is.

## Narrowing to what is new

Pass your current allowlist and only the delta is emitted — the destinations you have not
already decided about:

```bash
netaudit undeclared --allowlist netaudit.yaml reports/*.json
```

Filtering uses the real rule engine, so CIDR blocks and port scoping are honoured.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No undeclared egress found |
| 1 | Undeclared egress found |
| 2 | A report could not be read, or its schema version is unsupported |

This is the same sense as `run` and `analyze` — non-zero means something needs attention —
so `undeclared` works as a CI gate with no extra flag:

```yaml
- name: Assert no new undeclared egress
  run: netaudit undeclared --allowlist netaudit.yaml reports/*.json
```

Status messages go to stderr, so `netaudit undeclared ... > rules.yaml` only ever writes YAML.

Reports whose schema version this netaudit does not recognise are refused rather than
parsed optimistically — misreading evidence is worse than failing.

## Machine-readable output

`--format json` emits the same evidence as structured data, including `count`, `reports`,
`total_reports`, `external` and `tests` per rule.

```bash
netaudit undeclared --format json reports/*.json
```
