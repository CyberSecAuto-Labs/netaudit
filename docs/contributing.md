# Contributing

Contributions are welcome — bug reports, feature requests, and pull requests all help.

## Development setup

```bash
git clone https://github.com/CyberSecAuto-Labs/netaudit.git
cd netaudit
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev,docs]"
```

Run the full check suite before opening a PR:

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy netaudit/
.venv/bin/pytest -m 'not integration' --cov=netaudit --cov-fail-under=80
```

Integration tests require `strace` (Linux only):

```bash
sudo apt-get install strace
.venv/bin/pytest -m integration -v
```

Or with Make:

```bash
make lint
make test
```

## Coding conventions

- **Type annotations**: all public functions require type annotations; `mypy --strict` must pass.
- **Formatting**: `ruff format` (line-length 100); `ruff check` with E, F, W, I rules.
- **Tests**: every new behaviour should have a unit test. Aim to keep coverage above 80%.
- **No runtime dependencies**: the only allowed runtime deps are `click` and `pyyaml`.
  `pytest` is an optional dev dependency for the plugin — never import it in core modules.

## Architecture

The codebase has a strict two-layer separation:

- **Core** (`netaudit/`): framework-agnostic; no pytest imports.
- **Integrations** (`netaudit/integrations/`): framework-specific wrappers;
  may import from core but core must never import from integrations.

See [Architecture](architecture.md) for a detailed overview.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add --dry-run flag to run command
fix: handle truncated strace output on SIGKILL
docs: document Docker usage
```

## Opening a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes with tests.
3. Run `make lint && make test` — both must pass.
4. Open a PR against `main` with a clear description of the change.

For significant features, open an issue first to discuss the design.
