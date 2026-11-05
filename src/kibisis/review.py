"""Review candidate memory: ``python -m kibisis.review``.

Entries written through the MCP server are stored as candidates by ``mcp-agent``. A person lists
them here and approves, disputes or rejects them:

    python -m kibisis.review list [--category C]
    python -m kibisis.review approve CATEGORY KEY [--notes TEXT]
    python -m kibisis.review dispute CATEGORY KEY [--notes TEXT]
    python -m kibisis.review reject  CATEGORY KEY [--notes TEXT]

``approve``, ``dispute`` and ``reject`` need a terminal on stdin, as ``kibisis admit`` does, and record
the operating-system account they run as, read from the process's user id. ``--reviewer`` adds a label
beside the account; it does not change who reviewed.

Approving records one account's approval. The entry becomes verified once ``KIBISIS_VERIFICATION_QUORUM``
distinct accounts have approved it (two unless set; a person who wrote the entry as verified counts as
one), and any supersession it proposed is applied then. Until then it stays a candidate, and a second
approval from the same account changes nothing. Rejecting deletes the entry and records a tombstone, so
the same value cannot be written, restored or imported again in that scope.

``list`` also shows the agent's requests to forget an entry a person reviewed. The MCP server refuses
those and journals the request; a person carries one out by rejecting the entry, and reviewing the entry
again (approve or dispute) settles the request without deleting anything.

The vault, key and scope come from the same environment variables as the MCP server:
``KIBISIS_DB_PATH``, ``KIBISIS_PASSPHRASE_FILE`` or ``KIBISIS_PASSPHRASE``, and ``KIBISIS_SCOPE``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import Any, List, Optional

from ._operator import NotInteractive, account_identity, require_terminal
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
    listing = sub.add_parser("list", help="list candidates and forget requests waiting for review")
    listing.add_argument("--category")
    for name in _VERDICTS:
        cmd = sub.add_parser(name, help=f"{name} one entry (needs a terminal)")
        cmd.add_argument("category")
        cmd.add_argument("key")
        cmd.add_argument("--notes")
        cmd.add_argument(
            "--reviewer",
            help="label to record beside your account; the quorum counts accounts, not labels",
        )
    return parser


def _state(entity: Any) -> str:
    state = entity.epistemic_state
    return state.value if hasattr(state, "value") else str(state)


def _list(vault: Any, scope: str, category: Optional[str]) -> int:
    entries = vault.list_entities(category=category, scope=scope, epistemic_state=EpistemicState.CANDIDATE.value)
    requests = [r for r in vault.forget_requests(scope) if category is None or r["category"] == category]
    if not entries and not requests:
        print(f"No candidates or forget requests in scope {scope!r}.")
        return 0
    if not entries:
        print(f"No candidates in scope {scope!r}.")
    for entity in entries:
        meta = entity.metadata or {}
        author = meta.get("author_id", "unknown")
        pending = meta.get("verification_pending")
        approvals = f", approvals {pending['have']} of {pending['need']}" if pending else ""
        print(f"{entity.category}:{entity.key}  (author {author}, version {entity.version}{approvals})")
        for line in (entity.content or "").splitlines() or [""]:
            print(f"    {line}")
    if requests:
        print()
        print("Requests to forget reviewed entries (carry one out with `reject CATEGORY KEY`):")
        for request in requests:
            when = datetime.fromtimestamp(request["requested_at"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            why = f": {request['reason']}" if request["reason"] else ""
            who = request["author_id"] or "unknown"
            print(f"{request['category']}:{request['key']}  (requested by {who} at {when}{why})")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "list":
        # A verdict is a person's act: refuse before the vault is opened, as `kibisis admit` does.
        try:
            require_terminal(f"kibisis-review {args.command}")
        except NotInteractive as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 3
    try:
        scope = resolve_scope()
        vault = open_vault()
    except (ConfigError, EncryptionRequiredError) as exc:
        print(f"kibisis-review: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "list":
            return _list(vault, scope, args.category)

        reviewer = account_identity()
        try:
            entity = vault.review_entity(
                category=args.category,
                key=args.key,
                verdict=_VERDICTS[args.command],
                scope=scope,
                reviewer_id=reviewer,
                notes=args.notes,
                reviewer_label=args.reviewer,
            )
        except KeyError as exc:
            print(f"kibisis-review: {exc.args[0] if exc.args else exc}", file=sys.stderr)
            return 1
        label = f" as {args.reviewer!r}" if args.reviewer and args.reviewer != reviewer else ""
        if args.command == "reject":
            vault.scrub()
            print(f"Rejected {args.category}:{args.key}: deleted, and its value is tombstoned in scope {scope!r}.")
            return 0
        pending = (entity.metadata or {}).get("verification_pending")
        if args.command == "approve" and pending:
            print(
                f"{args.category}:{args.key} has {pending['have']} of {pending['need']} approvals (account "
                f"{reviewer}{label}); it stays a candidate until another account approves it."
            )
        else:
            print(f"{args.category}:{args.key} is now {_state(entity)} (account {reviewer}{label}).")
        return 0
    finally:
        vault.close()


if __name__ == "__main__":
    raise SystemExit(main())
