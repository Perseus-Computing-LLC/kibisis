"""Review candidate memory: ``python -m kibisis.review``.

Entries written through the MCP server are stored as candidates by ``mcp-agent``. A person lists
them here and approves, disputes or rejects them:

    python -m kibisis.review list [--category C]
    python -m kibisis.review approve CATEGORY KEY [--notes TEXT]
    python -m kibisis.review dispute CATEGORY KEY [--notes TEXT]
    python -m kibisis.review reject  CATEGORY KEY [--notes TEXT]
    python -m kibisis.review lift    CATEGORY KEY [--digest HEXPREFIX]

``approve``, ``dispute``, ``reject`` and ``lift`` need a terminal on stdin, as ``kibisis admit`` does,
and record the operating-system account they run as, read from the process's user id. ``--reviewer``
adds a label beside the account; it does not change who reviewed. The terminal check stops pipes and
cron jobs; a process that can allocate a pseudo-terminal passes it, so it is a guard against accident,
not against an agent that has a shell.

Every run prints the vault path and the scope it resolved, and a verdict on an entry that is not in
that scope lists the scopes that do hold the entry, so the person can set ``KIBISIS_SCOPE``.

``lift`` removes the tombstones recorded under ``CATEGORY KEY`` (``--digest`` narrows it to one value)
and journals each as ``tombstone_lifted``; the value may be written again afterwards. It is the only
way past a principal-class tombstone (one a person made, or one made before tombstones had classes).
A tombstone the agent made through ``kibisis_forget`` is model-class: a person's later write of the
value lifts it on its own.

Approving a candidate that proposed to supersede a verified entry retires that entry; ``list`` says so
beside the candidate and ``approve`` repeats it.

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
from .config import ConfigError, default_db_path, open_vault, resolve_scope
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
    lift = sub.add_parser("lift", help="remove the tombstones under CATEGORY KEY so the value may be written again (needs a terminal)")
    lift.add_argument("category")
    lift.add_argument("key")
    lift.add_argument("--digest", help="hex digest (or prefix) of the one tombstoned value to lift")
    return parser


def _supersession_notice(vault: Any, entity: Any, scope: str) -> Optional[str]:
    """What approving ``entity`` does to the entry it proposed to supersede, or ``None``."""
    proposal = (entity.metadata or {}).get("proposed_supersedes")
    if not isinstance(proposal, dict):
        return None
    category, key = proposal.get("category"), proposal.get("key")
    if not category or not key:
        return None
    target = vault.get(category, key, scope=scope)
    state = _state(target) if target is not None else "missing"
    return f"approving retires {category}:{key} ({state})"


def _scopes_holding(vault: Any, category: str, key: str) -> List[str]:
    """Scopes that hold an entry ``category:key`` (any state, archived or not)."""
    cursor = vault._conn.cursor()
    cursor.execute(
        "SELECT DISTINCT scope FROM entities WHERE category = ? AND key = ? ORDER BY scope", (category, key)
    )
    return [row[0] for row in cursor.fetchall()]


def _not_found(vault: Any, category: str, key: str, scope: str, stream: Any = None, prog: str = "kibisis-review") -> None:
    """Explain a missing entry: the scope it was looked up in and the scopes that do hold it."""
    stream = stream or sys.stderr
    print(f"{prog}: {category}:{key} is not in scope {scope!r}.", file=stream)
    held = _scopes_holding(vault, category, key)
    if held:
        print(
            f"{prog}: it exists in scope(s) {', '.join(repr(s) for s in held)}; "
            f"set KIBISIS_SCOPE to one of them (or run from that checkout) and retry.",
            file=stream,
        )


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
        notice = _supersession_notice(vault, entity, scope)
        if notice:
            print(f"    ! {notice}")
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
        db_path = default_db_path()
        vault = open_vault(db_path)
    except (ConfigError, EncryptionRequiredError) as exc:
        print(f"kibisis-review: {exc}", file=sys.stderr)
        return 2
    print(f"vault {db_path}  scope {scope!r}", file=sys.stderr)

    try:
        if args.command == "list":
            return _list(vault, scope, args.category)

        reviewer = account_identity()
        if args.command == "lift":
            lifted = vault.lift_tombstone(
                args.category, args.key, scope=scope, digest=args.digest, author_id=reviewer, origin="user"
            )
            if not lifted:
                print(f"kibisis-review: no tombstone under {args.category}:{args.key} in scope {scope!r}.", file=sys.stderr)
                return 1
            print(f"Lifted {lifted} tombstone(s) under {args.category}:{args.key} in scope {scope!r} (account {reviewer}).")
            return 0

        before = vault.get(args.category, args.key, scope=scope)
        if before is None:
            _not_found(vault, args.category, args.key, scope)
            return 1
        notice = _supersession_notice(vault, before, scope) if args.command == "approve" else None
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
            if notice:
                print(f"    ! {notice} once the quorum is met")
        else:
            print(f"{args.category}:{args.key} is now {_state(entity)} (account {reviewer}{label}).")
            if notice:
                print(f"    ! {notice.replace('approving retires', 'this approval retired')}")
        return 0
    finally:
        vault.close()


if __name__ == "__main__":
    raise SystemExit(main())
