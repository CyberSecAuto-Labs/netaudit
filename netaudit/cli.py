"""CLI entry point for netaudit."""

import click

from netaudit import __version__


@click.group()
@click.version_option(version=__version__, prog_name="netaudit")
def main() -> None:
    """netaudit — CI-native network egress auditing via strace."""
