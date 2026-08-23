"""CLI entry point for netaudit."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import click

from netaudit import __version__
from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import Reporter, Violation, supports_color
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


def _resolve_color(no_color: bool) -> bool:
    """Colour is on only for a capable TTY, and ``--no-color`` always wins."""
    return False if no_color else supports_color(sys.stdout)


def _emit(
    violations: list[Violation],
    fmt: str,
    verbose: bool = False,
    events: list[ConnectEvent] | None = None,
    allowlist: AllowList | None = None,
    color: bool = False,
) -> None:
    if fmt == "json":
        # JSON is machine-readable — never colourised.
        click.echo(
            Reporter.format_json(
                violations,
                events=events if verbose else None,
                allowlist=allowlist if verbose else None,
                include_allowed=verbose,
            )
        )
    elif verbose and events is not None and allowlist is not None:
        Reporter.format_verbose(events, allowlist, stream=sys.stdout, color=color)
    else:
        Reporter.format(violations, stream=sys.stdout, color=color)


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
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show all network events.")
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable coloured output (also honours the NO_COLOR environment variable).",
)
@click.argument("command", nargs=-1, required=True)
def run_cmd(
    allowlist: str | None,
    fmt: str,
    verbose: bool,
    no_color: bool,
    command: tuple[str, ...],
) -> None:
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
        _emit(
            violations,
            fmt,
            verbose=verbose,
            events=events,
            allowlist=al,
            color=_resolve_color(no_color),
        )
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
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show all network events.")
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable coloured output (also honours the NO_COLOR environment variable).",
)
@click.argument("strace_log", type=click.Path(exists=True, dir_okay=False))
def analyze_cmd(
    allowlist: str | None, fmt: str, verbose: bool, no_color: bool, strace_log: str
) -> None:
    """Analyze an existing strace log file for network violations."""
    al = _load_allowlist(allowlist)
    events = StraceParser().parse_stream(Path(strace_log).read_text().splitlines())
    violations = Reporter.check(events, al)
    _emit(
        violations,
        fmt,
        verbose=verbose,
        events=events,
        allowlist=al,
        color=_resolve_color(no_color),
    )
    sys.exit(_EXIT_VIOLATIONS if violations else _EXIT_CLEAN)
