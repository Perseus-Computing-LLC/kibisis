"""Checks shared by the commands only a person should run: ``kibisis.review`` and ``kibisis admit``.

Both commands record a person's verdict, so both refuse to run without a terminal on stdin, and both
record the operating-system account they run as. The account comes from the process's user id, not
from ``USER`` or ``LOGNAME``: whoever starts a process sets those, so trusting them would let one
account sign as many names as it liked, and the verification quorum would count names, not people.

Neither check is an authentication boundary. Anything that can run commands as an account, with a
pseudo-terminal, can run these commands as that account; the check stops pipes, cron jobs and agent
shell tools that run without one.
"""

from __future__ import annotations

import os
import sys

from .config import login_name


class NotInteractive(RuntimeError):
    """A person-only command was invoked without a terminal on stdin."""


def require_terminal(command: str) -> None:
    """Raise :class:`NotInteractive` unless stdin is a terminal.

    There is no environment-variable escape: an agent can set a variable as easily as a person can,
    so one would turn the check into a convention. Tests drive these commands through a
    pseudo-terminal instead.
    """
    isatty = getattr(sys.stdin, "isatty", None)
    if sys.stdin is None or isatty is None or not isatty():
        raise NotInteractive(
            f"{command} requires an interactive terminal (stdin is not a TTY); run it yourself in a shell"
        )


def account_identity() -> str:
    """The operating-system account this process runs as, read from its user id.

    The passwd name for the uid, or ``uid-<n>`` when the uid has no passwd entry (as under
    ``docker run --user``), the same strings :func:`kibisis.config.login_name` gives when ``USER``
    and ``LOGNAME`` are not set, so reviews recorded before this check count as the same account.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is None:  # pragma: no cover - Windows, which CI does not run
        return login_name()
    uid = getuid()
    try:
        import pwd
    except ImportError:  # pragma: no cover - every POSIX Python has pwd
        return f"uid-{uid}"
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid-{uid}"
