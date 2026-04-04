.PHONY: venv lint test clean

venv:
	python3.11 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
	.venv/bin/mypy netaudit/

test:
	.venv/bin/pytest --cov=netaudit

clean:
	rm -rf .venv __pycache__ .mypy_cache .ruff_cache .pytest_cache dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
