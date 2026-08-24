"""netaudit — CI-native network egress auditing via strace.

The names re-exported here are the supported library API: the three data
types, plus the parser that produces events and the reporter that evaluates
them against an allowlist.

    from netaudit import AllowList, Reporter, StraceParser

    events = StraceParser().parse_stream(open("strace.log"))
    violations = Reporter.check(events, AllowList.from_yaml("netaudit.yaml"))

Anything reachable only through a submodule is not covered by this promise.
Removing or renaming a name below requires a major version bump.
"""

from netaudit.allowlist import AllowList
from netaudit.parser import ConnectEvent, StraceParser
from netaudit.reporter import Reporter, Violation

__version__ = "0.5.0"

__all__ = [
    "AllowList",
    "ConnectEvent",
    "Reporter",
    "StraceParser",
    "Violation",
    "__version__",
]
