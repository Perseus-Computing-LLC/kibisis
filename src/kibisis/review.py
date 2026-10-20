"""Review candidate memory: ``python -m kibisis.review``.

Entries written through the MCP server are stored as candidates by ``mcp-agent``. A person lists
them here and approves, disputes or rejects them:

    python -m kibisis.review list [--category C]
    python -m kibisis.review approve CATEGORY KEY [--notes TEXT]
    python -m kibisis.review dispute CATEGORY KEY [--notes TEXT]
    python -m kibisis.review reject  CATEGORY KEY [--notes TEXT]

Approving stores the entry as verified and applies any supersession it proposed. Rejecting deletes
the entry and records a tombstone, so the same value cannot be written, restored or imported again
in that scope. The reviewer is recorded as the operating-system user name unless ``--reviewer`` is
given.

The vault, key and scope come from the same environment variables as the MCP server:
``KIBISIS_DB_PATH``, ``KIBISIS_PASSPHRASE_FILE`` or ``KIBISIS_PASSPHRASE``, and ``KIBISIS_SCOPE``.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import List, Optional

from .config import ConfigError, open_vault, resolve_scope
from .models import EpistemicState
from .protocols import EncryptionRequiredError

_VERDICTS = {
    "approve": EpistemicState.VERIFIED.value,
    "dispute": EpistemicState.DISPUTED.value,
    "reject": EpistemicState.REVOKED.value,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m kibisis.review", description="Review candidate memory.")
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list", help="list candidates waiting for review")
    listing.add_argument("--category")
    for name in _VERDICTS:
        cmd = sub.add_parser(name, help=f"{name} one entry")
        cmd.add_argument("category")
        cmd.add_argument("key")
        cmd.add_argument("--notes")
        cmd.add_argument("--reviewer", help="name to record (default: your user name)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        scope = resolve_scope()
        vault = open_vault()
    except (ConfigError, EncryptionRequiredError) as exc:
        print(f"kibisis-review: {exc}", file=sys.stderr)
        return 2

    if args.command == "list":
        entries = vault.list_entities(
            category=args.category, scope=scope, epistemic_state=EpistemicState.CANDIDATE.value
        )
        if not entries:
            print(f"No candidates in scope {scope!r}.")
            return 0
        for entity in entries:
            author = (entity.metadata or {}).get("author_id", "unknown")
            print(f"{entity.category}:{entity.key}  (author {author}, version {entity.version})")
            for line in (entity.content or "").splitlines() or [""]:
                print(f"    {line}")
        return 0

    reviewer = args.reviewer or getpass.getuser()
    try:
        entity = vault.review_entity(
            category=args.category,
            key=args.key,
            verdict=_VERDICTS[args.command],
            scope=scope,
            reviewer_id=reviewer,
            notes=args.notes,
        )
    except KeyError as exc:
        print(f"kibisis-review: {exc.args[0] if exc.args else exc}", file=sys.stderr)
        return 1
    if args.command == "reject":
        vault.scrub()
        print(f"Rejected {args.category}:{args.key}: deleted, and its value is tombstoned in scope {scope!r}.")
    else:
        print(f"{args.category}:{args.key} is now {entity.epistemic_state.value if hasattr(entity.epistemic_state, 'value') else entity.epistemic_state} (reviewer {reviewer}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
