"""netaudit — CI-native network egress auditing via strace.

The names re-exported here are the supported library API: the three data
types, plus the parser that produces events and the reporter that evaluates
them against an allowlist.

    from pathlib import Path

    from netaudit import AllowList, Reporter, StraceParser

    allowlist = AllowList.from_yaml(Path("netaudit.yaml"))
    with open("strace.log") as log:
        events = StraceParser().parse_stream(log)
    violations = Reporter.check(events, allowlist)

Anything reachable only through a submodule is not covered by this promise.
Removing or renaming a name below requires a major version bump.
"""

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import Reporter, Violation

__version__ = "0.6.0"

__all__ = [
    "AllowList",
    "ConnectEvent",
    "Reporter",
    "StraceParser",
    "Violation",
    "__version__",
]
