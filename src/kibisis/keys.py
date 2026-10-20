"""Passphrase resolution for Kibisis. Keys are read from a file or the environment, never from source."""

from __future__ import annotations

import os
import secrets
import stat
from typing import Mapping, Optional

MIN_PASSPHRASE_LENGTH = 12
ENV_FILE = "KIBISIS_PASSPHRASE_FILE"
ENV_VALUE = "KIBISIS_PASSPHRASE"


def _read_keyfile(path: str) -> str:
    mode = os.stat(path).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"Key file {path} is readable by group or others (mode {stat.S_IMODE(mode):o}); chmod 600 it.")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def resolve_passphrase(explicit: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Return the passphrase from, in order: the argument, KIBISIS_PASSPHRASE_FILE, KIBISIS_PASSPHRASE."""
    if explicit:
        return explicit
    env = os.environ if env is None else env
    path = env.get(ENV_FILE)
    if path:
        return _read_keyfile(path) or None
    return env.get(ENV_VALUE) or None


def generate_keyfile(path: str) -> None:
    """Create a new 256-bit random key file with mode 0600. Refuses to overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secrets.token_urlsafe(32) + "\n")


def main(argv: Optional[list] = None) -> int:
    """``python -m kibisis.keys PATH`` creates a new key file (mode 0600) and never prints the key."""
    import sys

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] in ("-h", "--help"):
        print("usage: python -m kibisis.keys PATH   (creates a new key file; refuses to overwrite)", file=sys.stderr)
        return 2
    path = os.path.abspath(os.path.expanduser(args[0]))
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    try:
        generate_keyfile(path)
    except FileExistsError:
        print(f"{path} already exists; not overwriting it.", file=sys.stderr)
        return 1
    print(f"Created {path}. Set KIBISIS_PASSPHRASE_FILE={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
