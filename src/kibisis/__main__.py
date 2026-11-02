"""``python -m kibisis`` — operator commands.

``admit`` needs a person at the keyboard. ``okf-export`` and ``okf-check`` (P13.1) project the
vault into an OKF v0.2 bundle and check one; they read the vault and never change it. ``okf-import``
(P13.2) diffs a bundle into the vault as model-origin candidates; ``--dry-run`` writes nothing.
"""
from __future__ import annotations

import argparse
import getpass
import json
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


def _okf_export(args: argparse.Namespace) -> int:
    from .okf.export import ExportError, GateRefused, command_gate, export_bundle
    from .okf.profile import ProfileError, load_profile

    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    try:
        gate = command_gate(args.gate_cmd) if args.gate_cmd is not None else None
    except (ExportError, ValueError) as exc:
        print(f"refused: --gate-cmd: {exc}", file=sys.stderr)
        return 2
    # SQLiteMemoryVault creates a missing file; an export never creates a vault.
    if not os.path.isfile(args.db):
        print(f"error: no vault at {args.db}", file=sys.stderr)
        return 1
    try:
        vault = SQLiteMemoryVault(args.db)
    except Exception as exc:  # wrong or missing passphrase, not a vault, unreadable
        print(f"error: cannot open the vault at {args.db}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
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
    # SQLiteMemoryVault creates a missing file; an import never creates a vault.
    if not os.path.isfile(args.db):
        print(f"error: no vault at {args.db}", file=sys.stderr)
        return 1
    try:
        vault = SQLiteMemoryVault(args.db)
    except Exception as exc:  # wrong or missing passphrase, not a vault, unreadable
        print(f"error: cannot open the vault at {args.db}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    try:
        report = import_bundle(vault, args.bundle, profile=profile, dry_run=args.dry_run)
    except BundleImportError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    finally:
        vault.close()
    print(json.dumps(report.summary(), sort_keys=True))
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

    e = sub.add_parser("okf-export", help="write allowlisted vault rows as an OKF v0.2 bundle (reads the vault only)")
    e.add_argument("--profile", required=True, help="export profile (JSON, kibisis.okf_export_profile/1)")
    e.add_argument("--out", required=True, help="bundle directory: absent, empty, or a bundle okf-export wrote")
    e.add_argument("--db", default=DEFAULT_DB_PATH, help="vault path (default: $KIBISIS_DB_PATH)")
    e.add_argument("--at", default=None, help="ISO date or datetime for the log entry (default: today, UTC)")
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--gate-cmd", default=None,
                   help="command run over the staged files (paths appended); non-zero aborts the bundle")
    g.add_argument("--ungated", action="store_true", help="write without a content gate (synthetic fixtures only)")
    e.set_defaults(func=_okf_export)

    c = sub.add_parser("okf-check", help="check a bundle against the OKF v0.2 producer MUSTs")
    c.add_argument("bundle", help="bundle directory")
    c.add_argument("--json", action="store_true", help="print the result as JSON")
    c.set_defaults(func=_okf_check)

    i = sub.add_parser("okf-import", help="diff an OKF v0.2 bundle into the vault as model-origin candidates")
    i.add_argument("--bundle", required=True, help="bundle directory to read")
    i.add_argument("--db", default=DEFAULT_DB_PATH, help="vault path (default: $KIBISIS_DB_PATH)")
    i.add_argument("--profile", default=None,
                   help="allowlist (export profile JSON); default: scope default, the four P13 categories")
    i.add_argument("--dry-run", action="store_true", help="report what would change and write nothing")
    i.set_defaults(func=_okf_import)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
