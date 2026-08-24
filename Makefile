.PHONY: venv lint test integration integration-docker docs docs-serve clean

venv:
	python3.11 -m venv .venv
	.venv/bin/pip install -e ".[dev,docs]"

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
	.venv/bin/mypy netaudit/
	.venv/bin/mkdocs build --strict

test:
	.venv/bin/pytest --cov=netaudit --cov-fail-under=98

integration:
	COVERAGE_PROCESS_START=$(PWD)/pyproject.toml .venv/bin/pytest -m integration -v

# Runs the integration suite the way CI does: Linux, real strace, same image.
# Use this on macOS/Windows, where strace does not exist.
integration-docker:
	docker build -f Dockerfile.test -t netaudit:test .
	docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
		netaudit:test -m integration -v

docs:
	.venv/bin/mkdocs build --strict

docs-serve:
	.venv/bin/mkdocs serve

clean:
	rm -rf .venv __pycache__ .mypy_cache .ruff_cache .pytest_cache dist site *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
