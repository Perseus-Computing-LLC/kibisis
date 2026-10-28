"""``python -m kibisis`` — operator commands that need a person at the keyboard."""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from .vault import ORIGINS, AdmissionRefused, SQLiteMemoryVault

DEFAULT_DB_PATH = os.environ.get("KIBISIS_DB_PATH", os.path.expanduser("~/.hermes/kibisis/vault.sqlite"))


class NotInteractive(RuntimeError):
    """``admit`` was invoked without a terminal on stdin."""


def _require_tty() -> None:
    """``admit --by user`` asserts a person is present; refuse when stdin is not a terminal.

    An agent driving a shell tool, a cron job or a pipe has no TTY, so this check keeps the
    human path from being replayed by automation. There is no environment-variable escape: an
    agent can set a variable as easily as a person can, so one would turn the gate into a
    convention. The test suite drives this through a pseudo-terminal instead.
    """
    if not sys.stdin.isatty():
        raise NotInteractive("admit requires an interactive terminal (stdin is not a TTY); run it yourself in a shell")


def _admit(args: argparse.Namespace) -> int:
    try:
        _require_tty()
    except NotInteractive as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    vault = SQLiteMemoryVault(args.db)
    try:
        entity = vault.admit(
            args.category,
            args.key,
            reviewer=args.reviewer,
            reviewer_origin=args.by,
            note=args.note,
            scope=args.scope,
        )
    except AdmissionRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        vault.close()
    state = entity.epistemic_state.value if hasattr(entity.epistemic_state, "value") else entity.epistemic_state
    print(f"{args.category}:{args.key} [scope={args.scope}] is now {state} (origin={entity.origin}, reviewed by {args.reviewer}/{args.by})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kibisis")
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("admit", help="promote a candidate entry to verified (a person's action)")
    a.add_argument("--db", default=DEFAULT_DB_PATH, help="vault path (default: $KIBISIS_DB_PATH)")
    a.add_argument("--category", required=True)
    a.add_argument("--key", required=True)
    a.add_argument("--scope", default="default")
    a.add_argument("--by", required=True, choices=ORIGINS, help="who is reviewing; only 'user' can admit")
    a.add_argument("--reviewer", default=getpass.getuser(), help="reviewer name recorded in the journal")
    a.add_argument("--note", default=None)
    a.set_defaults(func=_admit)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
