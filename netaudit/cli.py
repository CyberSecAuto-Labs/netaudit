"""CLI entry point for netaudit."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import click

from netaudit import __version__
from netaudit.allowlist import AllowList
from netaudit.parser import StraceParser
from netaudit.reporter import Reporter, Violation
from netaudit.runner import StraceNotFoundError, StraceRunner

_DEFAULT_ALLOWLIST = "netaudit.yaml"

# Exit codes
_EXIT_CLEAN = 0
_EXIT_VIOLATIONS = 1
_EXIT_STRACE_MISSING = 2


def _load_allowlist(allowlist: str | None) -> AllowList:
    if allowlist is not None:
        return AllowList.from_yaml(Path(allowlist))
    default = Path(_DEFAULT_ALLOWLIST)
    if default.exists():
        return AllowList.from_yaml(default)
    return AllowList.empty()


def _emit(violations: list[Violation], fmt: str) -> None:

    if fmt == "json":
        click.echo(Reporter.format_json(violations))
    else:
        Reporter.format(violations, stream=sys.stdout)


@click.group()
@click.version_option(version=__version__, prog_name="netaudit")
def main() -> None:
    """netaudit — CI-native network egress auditing via strace."""


@main.command("run")
@click.option(
    "--allowlist",
    default=None,
    metavar="YAML",
    help=f"Allowlist file (default: {_DEFAULT_ALLOWLIST} in cwd if present).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.argument("command", nargs=-1, required=True)
def run_cmd(allowlist: str | None, fmt: str, command: tuple[str, ...]) -> None:
    """Trace COMMAND under strace and report network violations."""
    try:
        runner = StraceRunner()
    except StraceNotFoundError as exc:
        click.echo(f"netaudit: {exc}", err=True)
        sys.exit(_EXIT_STRACE_MISSING)

    al = _load_allowlist(allowlist)

    with tempfile.NamedTemporaryFile(suffix=".strace", delete=False) as tf:
        strace_out = Path(tf.name)

    try:
        runner.run(list(command), strace_out)
        events = StraceParser().parse_stream(strace_out.read_text().splitlines())
        violations = Reporter.check(events, al)
        _emit(violations, fmt)
        sys.exit(_EXIT_VIOLATIONS if violations else _EXIT_CLEAN)
    finally:
        strace_out.unlink(missing_ok=True)


@main.command("analyze")
@click.option(
    "--allowlist",
    default=None,
    metavar="YAML",
    help=f"Allowlist file (default: {_DEFAULT_ALLOWLIST} in cwd if present).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.argument("strace_log", type=click.Path(exists=True, dir_okay=False))
def analyze_cmd(allowlist: str | None, fmt: str, strace_log: str) -> None:
    """Analyze an existing strace log file for network violations."""
    al = _load_allowlist(allowlist)
    events = StraceParser().parse_stream(Path(strace_log).read_text().splitlines())
    violations = Reporter.check(events, al)
    _emit(violations, fmt)
    sys.exit(_EXIT_VIOLATIONS if violations else _EXIT_CLEAN)
