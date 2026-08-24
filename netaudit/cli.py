"""CLI entry point for netaudit."""

from __future__ import annotations

import io
import json
import sys
import tempfile
from pathlib import Path

import click

from netaudit import __version__
from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import (
    REPORT_VERSION,
    MergedDestination,
    Reporter,
    Violation,
    build_run_metadata,
    load_report,
    merge_reports,
    supports_color,
)
from netaudit.runner import StraceNotFoundError, StraceRunner

_DEFAULT_ALLOWLIST = "netaudit.yaml"

# Exit codes for `analyze` and `undeclared`, which wrap no child process.
_EXIT_CLEAN = 0
_EXIT_VIOLATIONS = 1
_EXIT_BAD_REPORT = 2

# Reserved for `run`. Every other value belongs to the traced command and is
# passed through, so these sit clear of the ranges a wrapped process may use.
_EXIT_TRACED_VIOLATIONS = 83
_EXIT_STRACE_MISSING = 84


def _load_allowlist(allowlist: str | None) -> AllowList:
    if allowlist is not None:
        return AllowList.from_yaml(Path(allowlist))
    default = Path(_DEFAULT_ALLOWLIST)
    if default.exists():
        return AllowList.from_yaml(default)
    return AllowList.empty()


def _write_report(
    violations: list[Violation],
    fmt: str,
    verbose: bool,
    events: list[ConnectEvent] | None,
    allowlist: AllowList | None,
    suggest_rules: bool,
    run: dict[str, object] | None,
    path: Path,
) -> None:
    """Render the report into *path* instead of stdout."""
    if fmt == "json":
        body = Reporter.format_json(
            violations,
            events=events if verbose else None,
            allowlist=allowlist if verbose else None,
            include_allowed=verbose,
            suggest_rules=suggest_rules,
            run=run,
        )
    else:
        buf = io.StringIO()
        if verbose and events is not None and allowlist is not None:
            Reporter.format_verbose(events, allowlist, stream=buf)
            buf.write("\n")
            Reporter.format_summary(violations, stream=buf)
        else:
            Reporter.format(violations, stream=buf)
        if suggest_rules and violations:
            buf.write("\n")
            Reporter.format_suggestions(violations, stream=buf)
        body = buf.getvalue()
    path.write_text(body)


def _as_event(dest: MergedDestination) -> ConnectEvent:
    """Adapt a merged destination back to an event so allowlist rules can match it."""
    return ConnectEvent(
        pid=0,
        timestamp=0.0,
        family=dest.family,
        addr=dest.addr,
        port=dest.port,
        result=0,
        raw_line="",
    )


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
    suggest_rules: bool = False,
    run: dict[str, object] | None = None,
    output: str | None = None,
) -> None:
    if output is not None:
        # A file is not a terminal: never colourise a saved report, whatever
        # stdout happens to be.
        _write_report(violations, fmt, verbose, events, allowlist, suggest_rules, run, Path(output))
        return
    if fmt == "json":
        # JSON is machine-readable — never colourised.
        click.echo(
            Reporter.format_json(
                violations,
                events=events if verbose else None,
                allowlist=allowlist if verbose else None,
                include_allowed=verbose,
                suggest_rules=suggest_rules,
                run=run,
            )
        )
    elif verbose and events is not None and allowlist is not None:
        Reporter.format_verbose(events, allowlist, stream=sys.stdout, color=color)
        # The verbose table is per-event; the summary aggregates it per destination.
        # In non-verbose mode the detail block is already one row per destination,
        # so a summary there would repeat it verbatim.
        print()
        Reporter.format_summary(violations, stream=sys.stdout, color=color)
    else:
        Reporter.format(violations, stream=sys.stdout, color=color)

    if fmt != "json" and suggest_rules and violations:
        print()
        Reporter.format_suggestions(violations, stream=sys.stdout, color=color)


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
@click.option(
    "--suggest-rules",
    is_flag=True,
    default=False,
    help="Print copy-paste-ready allowlist YAML for each violation.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    metavar="PATH",
    type=click.Path(dir_okay=False, writable=True),
    help="Write the report to PATH instead of stdout (never coloured).",
)
@click.argument("command", nargs=-1, required=True)
def run_cmd(
    allowlist: str | None,
    fmt: str,
    verbose: bool,
    no_color: bool,
    suggest_rules: bool,
    output: str | None,
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
        completed = runner.run(list(command), strace_out)
        command_code = completed.returncode
        events = StraceParser().parse_stream(strace_out.read_text().splitlines())
        violations = Reporter.check(events, al)
        _emit(
            violations,
            fmt,
            verbose=verbose,
            events=events,
            allowlist=al,
            color=_resolve_color(no_color),
            suggest_rules=suggest_rules,
            run=build_run_metadata(
                command=list(command),
                allowlist=allowlist,
                command_exit_code=command_code,
            ),
            output=output,
        )
        if command_code != 0:
            # Surface it: codes 2 and 3 are netaudit's own, so a propagated
            # value could otherwise be misread as netaudit's verdict.
            click.echo(
                f"netaudit: traced command exited with {command_code}",
                err=True,
            )
            # The command's failure leads. It may have died part-way, which makes
            # the trace — and therefore the violation set — incomplete.
            sys.exit(command_code)
        sys.exit(_EXIT_TRACED_VIOLATIONS if violations else _EXIT_CLEAN)
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
@click.option(
    "--suggest-rules",
    is_flag=True,
    default=False,
    help="Print copy-paste-ready allowlist YAML for each violation.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    metavar="PATH",
    type=click.Path(dir_okay=False, writable=True),
    help="Write the report to PATH instead of stdout (never coloured).",
)
@click.argument("strace_log", type=click.Path(exists=True, dir_okay=False))
def analyze_cmd(
    allowlist: str | None,
    fmt: str,
    verbose: bool,
    no_color: bool,
    suggest_rules: bool,
    output: str | None,
    strace_log: str,
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
        suggest_rules=suggest_rules,
        run=build_run_metadata(source=strace_log, allowlist=allowlist),
        output=output,
    )
    sys.exit(_EXIT_VIOLATIONS if violations else _EXIT_CLEAN)


@main.command("undeclared")
@click.option(
    "--allowlist",
    default=None,
    metavar="YAML",
    help="Existing allowlist — destinations it already permits are omitted.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable coloured output (also honours the NO_COLOR environment variable).",
)
@click.option(
    "--output",
    "-o",
    default=None,
    metavar="PATH",
    type=click.Path(dir_okay=False, writable=True),
    help="Write the rules to PATH instead of stdout (never coloured).",
)
@click.argument("reports", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
def undeclared_cmd(
    allowlist: str | None,
    fmt: str,
    no_color: bool,
    output: str | None,
    reports: tuple[str, ...],
) -> None:
    """Report egress observed across saved JSON REPORTS that is not allowed.

    Merges the destinations those runs reached but the allowlist does not permit,
    and renders them as candidate rules annotated with the evidence behind each.

    These are candidates to review, not recommendations: the reports contain
    violations, and netaudit cannot distinguish egress nobody has declared yet
    from egress that should never have happened. Which of them belong in the
    allowlist is the reviewer's decision.

    Exits 1 when undeclared egress is found and 0 when there is none, matching
    `run` and `analyze`, so it works directly as a CI assertion.
    """
    try:
        loaded = [load_report(Path(r)) for r in reports]
    except ValueError as exc:
        click.echo(f"netaudit: {exc}", err=True)
        sys.exit(_EXIT_BAD_REPORT)

    merged = merge_reports(loaded)

    if allowlist is not None:
        al = AllowList.from_yaml(Path(allowlist))
        merged = [d for d in merged if not al.is_allowed(_as_event(d))]

    if not merged:
        # Status goes to stderr: stdout is data, and a redirected rules file
        # must not pick up a human-readable line.
        click.echo("netaudit: no undeclared egress found", err=True)
        sys.exit(_EXIT_CLEAN)

    color = False if output is not None else _resolve_color(no_color)
    if fmt == "json":
        body = json.dumps(
            {
                "version": REPORT_VERSION,
                "run": build_run_metadata(source=", ".join(r.label for r in loaded)),
                "suggested_rules": [
                    {
                        "name": f"allow {d.as_violation()._addr_str()}",
                        "family": d.family,
                        "addr": d.addr,
                        **({"port": d.port} if d.port is not None else {}),
                        "count": d.count,
                        "reports": d.reports,
                        "total_reports": d.total_reports,
                        "external": d.is_external,
                        **({"tests": sorted(d.tests)} if d.tests else {}),
                    }
                    for d in merged
                ],
            },
            indent=2,
        )
    else:
        body = Reporter.format_suggestions_with_evidence(merged, color=color)

    if output is not None:
        Path(output).write_text(body)
    else:
        click.echo(body, nl=False)
    # Same sense as `run` and `analyze`: non-zero means something needs attention.
    sys.exit(_EXIT_VIOLATIONS)
