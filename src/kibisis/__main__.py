"""``python -m kibisis`` — operator commands.

``admit`` needs a person at the keyboard. ``okf-export`` and ``okf-check`` (P13.1) project the
vault into an OKF v0.2 bundle and check one; ``okf-export`` opens the vault read-only (no
conversion, upgrade or index build) and never changes the vault file's bytes, though SQLite may leave
an empty ``-wal`` and a ``-shm`` beside a WAL-mode vault; ``okf-check`` opens no vault. ``okf-import``
(P13.2) diffs a bundle into the vault as model-origin candidates; ``--dry-run`` opens it read-only and
writes nothing.
Every subcommand resolves the vault the same way: ``--db``, else ``KIBISIS_DB_PATH``, else the
per-user data directory (``kibisis.config.default_db_path``).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Tuple

from .config import ConfigError, default_db_path, open_vault, resolve_scope, validate_scope
from ._operator import NotInteractive, account_identity, require_terminal
from .protocols import EncryptionRequiredError
from .vault import ORIGINS, AdmissionRefused, SQLiteMemoryVault

_DB_HELP = "vault path (default: $KIBISIS_DB_PATH, else the per-user vault the MCP server and kibisis-review use)"


def __getattr__(name: str) -> str:
    # ``DEFAULT_DB_PATH`` used to be computed once at import from a path nothing else used. It is now
    # the same vault every subcommand opens, read when asked so a later env change is honoured.
    if name == "DEFAULT_DB_PATH":
        return default_db_path()
    raise AttributeError(name)

__all__ = ["NotInteractive", "main"]


def _require_tty() -> None:
    """``admit --by user`` asserts a person is present; refuse when stdin is not a terminal.

    An agent driving a shell tool, a cron job or a pipe has no TTY, so this check keeps the
    human path from being replayed by automation. There is no environment-variable escape: an
    agent can set a variable as easily as a person can, so one would turn the gate into a
    convention. The test suite drives this through a pseudo-terminal instead.
    """
    require_terminal("admit")


def _admit(args: argparse.Namespace) -> int:
    try:
        _require_tty()
    except NotInteractive as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    # The same vault, key and scope the MCP server and the review CLI use, so a person admits the
    # entry the agent wrote, not a namesake in another file or scope.
    try:
        scope = validate_scope(args.scope) if args.scope is not None else resolve_scope()
        vault = open_vault(args.db, pin_quorum=True)  # a person at a terminal: the one open that may pin the quorum
    except (ConfigError, EncryptionRequiredError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"vault {vault.db_path}  scope {scope!r}", file=sys.stderr)
    if vault.verification_quorum == 1:
        print("quorum 1 — one account verifies", file=sys.stderr)
    reviewer = account_identity()
    try:
        entity = vault.admit(
            args.category,
            args.key,
            reviewer=reviewer,
            reviewer_origin=args.by,
            note=args.note,
            scope=scope,
            reviewer_label=args.reviewer,
        )
    except AdmissionRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except KeyError:
        from .review import _not_found

        _not_found(vault, args.category, args.key, scope, prog="error")
        return 1
    finally:
        vault.close()
    state = entity.epistemic_state.value if hasattr(entity.epistemic_state, "value") else entity.epistemic_state
    pending = (entity.metadata or {}).get("verification_pending")
    waiting = f"; {pending['have']} of {pending['need']} approvals" if pending else ""
    label = f" as {args.reviewer!r}" if args.reviewer and args.reviewer != reviewer else ""
    print(
        f"{args.category}:{args.key} [scope={scope}] in {vault.db_path} is now {state}{waiting} "
        f"(origin={entity.origin}, reviewed by account {reviewer}{label}, --by {args.by})"
    )
    return 0


def _open_okf_vault(db: Optional[str], *, read_only: bool) -> Tuple[Optional[SQLiteMemoryVault], int]:
    """Open the vault an OKF command works on: the same path and key rules as every other subcommand
    (``--db``, else KIBISIS_DB_PATH, else the XDG data dir; KIBISIS_ALLOW_PLAINTEXT). Never creates one."""
    path = db or default_db_path()
    if not os.path.isfile(path):
        print(f"error: no vault at {path}", file=sys.stderr)
        return None, 1
    try:
        return open_vault(path, read_only=read_only), 0
    except ConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return None, 2
    except Exception as exc:  # wrong or missing passphrase, not a vault, unreadable
        print(f"error: cannot open the vault at {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None, 1


def _okf_export(args: argparse.Namespace) -> int:
    from .okf.export import ExportError, GateRefused, command_gate, export_bundle
    from .okf.profile import ProfileError, load_profile

    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    try:
        gate = command_gate(args.gate_cmd, verbose=args.gate_verbose) if args.gate_cmd is not None else None
    except (ExportError, ValueError) as exc:
        print(f"refused: --gate-cmd: {exc}", file=sys.stderr)
        return 2
    vault, rc = _open_okf_vault(args.db, read_only=True)  # an export reads the vault and never changes it
    if vault is None:
        return rc
    try:
        report = export_bundle(vault, profile, args.out, at=args.at, ungated=args.ungated, bundle_gate=gate)
    except GateRefused as exc:
        print(f"refused: {exc}; nothing was written to {args.out}", file=sys.stderr)
        return 4
    except ExportError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    finally:
        vault.close()
    print(json.dumps(report.summary(), sort_keys=True))
    return 0


def _okf_check(args: argparse.Namespace) -> int:
    from .okf.check import check_bundle

    result = check_bundle(args.bundle)
    if args.json:
        print(json.dumps(result.as_dict(), sort_keys=True, indent=2))
    else:
        for f in result.errors:
            print(f"error: {f.path}: [{f.code}] {f.message}")
        for f in result.notes:
            print(f"note: {f.path}: [{f.code}] {f.message}")
        print(f"okf-check: {result.files_checked} files, {len(result.errors)} errors, {len(result.notes)} notes")
    return 0 if result.ok else 1


def _okf_import(args: argparse.Namespace) -> int:
    from .okf.importer import BundleImportError, import_bundle
    from .okf.profile import ProfileError, default_profile, load_profile

    try:
        profile = load_profile(args.profile) if args.profile is not None else default_profile()
    except ProfileError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if os.path.islink(args.bundle) or not os.path.isdir(args.bundle):
        print(f"refused: no bundle directory at {args.bundle}", file=sys.stderr)
        return 2
    # --dry-run reads the vault and never changes it; a real import never creates a vault either.
    vault, rc = _open_okf_vault(args.db, read_only=args.dry_run)
    if vault is None:
        return rc
    try:
        report = import_bundle(vault, args.bundle, profile=profile, dry_run=args.dry_run)
    except BundleImportError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    finally:
        vault.close()
    print(json.dumps(report.summary(), sort_keys=True))
    return 0


def _aml_key_sha256(args: argparse.Namespace) -> str | None:
    """SHA-256 of the Memory System Key: given as a digest, or hashed from a key file or the environment."""
    from .aml_adapter import key_digest
    from .keys import _read_keyfile

    digest = args.key_sha256 or os.environ.get("KIBISIS_AML_KEY_SHA256")
    if digest:
        return digest
    path = os.environ.get("KIBISIS_AML_KEY_FILE")
    key = _read_keyfile(path) if path else os.environ.get("KIBISIS_AML_KEY")
    return key_digest(key) if key else None


def _aml_serve(args: argparse.Namespace) -> int:
    import logging

    from .aml_adapter import AMLConfig, run_server
    from .keys import resolve_passphrase

    # Evaluation traffic is not mirrored into an operator's Argus ledger unless ARGUS_LEDGER_PATH says so.
    os.environ.setdefault("ARGUS_LEDGER_PATH", "")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    digest = _aml_key_sha256(args)
    if not digest:
        print("aml-serve: no Memory System Key: set KIBISIS_AML_KEY_SHA256 (hex SHA-256 of the key), "
              "KIBISIS_AML_KEY_FILE (a mode-600 file holding the key) or KIBISIS_AML_KEY", file=sys.stderr)
        return 2
    passphrase = None
    if not args.plaintext:
        passphrase = resolve_passphrase()
        if not passphrase:
            print("aml-serve: no vault key: set KIBISIS_PASSPHRASE_FILE or KIBISIS_PASSPHRASE, "
                  "or pass --plaintext to store evaluation data unencrypted", file=sys.stderr)
            return 2
    try:
        config = AMLConfig(data_dir=args.data_dir, key_sha256=digest, passphrase=passphrase,
                           candidates=args.candidates, context_before=args.context_before,
                           max_inflight=args.max_inflight, max_open_vaults=args.max_open_vaults,
                           retention_days=args.retention_days, socket_timeout=args.socket_timeout,
                           max_connections=args.max_connections)
    except ValueError as exc:
        print(f"aml-serve: {exc}", file=sys.stderr)
        return 2
    try:
        run_server(config, host=args.host, port=args.port)
    except EncryptionRequiredError as exc:  # a vault key without sqlcipher3 and without the plaintext opt-in
        print(f"aml-serve: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kibisis")
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("admit", help="promote a candidate entry to verified (a person's action)")
    a.add_argument(
        "--db", default=None, help=_DB_HELP,
    )
    a.add_argument("--category", required=True)
    a.add_argument("--key", required=True)
    a.add_argument(
        "--scope", default=None,
        help="scope (default: as for the MCP server: $KIBISIS_SCOPE, else the git project, else 'default')",
    )
    a.add_argument("--by", required=True, choices=ORIGINS, help="who is reviewing; only 'user' can admit")
    a.add_argument(
        "--reviewer", default=None,
        help="label recorded with the review; the quorum counts the operating-system account, not this",
    )
    a.add_argument("--note", default=None)
    a.set_defaults(func=_admit)

    e = sub.add_parser("okf-export", help="write allowlisted vault rows as an OKF v0.2 bundle (reads the vault only)")
    e.add_argument("--profile", required=True, help="export profile (JSON, kibisis.okf_export_profile/1)")
    e.add_argument("--out", required=True, help="bundle directory: absent, empty, or a bundle okf-export wrote")
    e.add_argument("--db", default=None, help=_DB_HELP)
    e.add_argument("--at", default=None, help="ISO date or datetime for the log entry (default: today, UTC)")
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--gate-cmd", default=None,
                   help="command run over the staged files (paths appended); non-zero aborts the bundle. Its "
                        "stdout is summarised (line count, exit status); --gate-verbose copies it to stderr")
    e.add_argument("--gate-verbose", action="store_true",
                   help="copy the gate command's stdout to stderr (it may quote vault content)")
    g.add_argument("--ungated", action="store_true", help="write without a content gate (synthetic fixtures only)")
    e.set_defaults(func=_okf_export)

    c = sub.add_parser("okf-check", help="check a bundle against the OKF v0.2 producer MUSTs")
    c.add_argument("bundle", help="bundle directory")
    c.add_argument("--json", action="store_true", help="print the result as JSON")
    c.set_defaults(func=_okf_check)

    i = sub.add_parser("okf-import", help="diff an OKF v0.2 bundle into the vault as model-origin candidates")
    i.add_argument("--bundle", required=True, help="bundle directory to read")
    i.add_argument("--db", default=None, help=_DB_HELP)
    i.add_argument("--profile", default=None,
                   help="allowlist (export profile JSON); default: scope default, the four P13 categories")
    i.add_argument("--dry-run", action="store_true", help="report what would change and write nothing")
    i.set_defaults(func=_okf_import)

    s = sub.add_parser("aml-serve", help="run the Agent Memory Leaderboard (AML) Add/Search HTTP adapter",
                       description="Serve the AML Add/Search contract over per-user Kibisis vaults. The Memory "
                                   "System Key comes from KIBISIS_AML_KEY_SHA256, KIBISIS_AML_KEY_FILE or "
                                   "KIBISIS_AML_KEY; the vault key from KIBISIS_PASSPHRASE_FILE or KIBISIS_PASSPHRASE.")
    s.add_argument("--host", default="127.0.0.1",
                   help="bind host (default: 127.0.0.1, this machine only; pass 0.0.0.0 to listen on every interface)")
    s.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    s.add_argument("--data-dir", default=os.environ.get("KIBISIS_AML_DATA_DIR", "aml-data"),
                   help="directory for the per-user vaults (default: $KIBISIS_AML_DATA_DIR or ./aml-data)")
    s.add_argument("--key-sha256", default=None, help="hex SHA-256 of the Memory System Key (not the key itself)")
    s.add_argument("--plaintext", action="store_true", help="store vaults unencrypted (no vault key needed)")
    s.add_argument("--candidates", type=int, default=200, help="BM25 hits fetched per search (default: 200)")
    s.add_argument("--context-before", type=int, default=1,
                   help="earlier messages of the same Add request shown before each hit (default: 1)")
    s.add_argument("--max-inflight", type=int, default=32,
                   help="requests processed at once (body read plus Add/Search); more get 429 (default: 32). "
                        "Connections are bounded by --max-connections and --socket-timeout, not by this")
    s.add_argument("--max-open-vaults", type=int, default=64, help="per-user vaults kept open (default: 64)")
    s.add_argument("--max-connections", type=int, default=256,
                   help="connections (handler threads) accepted at once; more get 503 and are closed (default: 256)")
    s.add_argument("--socket-timeout", type=float, default=30.0,
                   help="seconds an idle or stalled connection is kept before it is closed (default: 30)")
    s.add_argument("--retention-days", type=float, default=28.0,
                   help="delete vaults not used (no Add or Search) for this many days; 0 keeps them (default: 28)")
    s.set_defaults(func=_aml_serve)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
