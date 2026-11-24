"""Passphrase resolution for Kibisis. Keys are read from a file or the environment, never from source."""

from __future__ import annotations

import errno
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
    """Return the passphrase from, in order: the argument, KIBISIS_PASSPHRASE_FILE, KIBISIS_PASSPHRASE.

    A key file that is named but empty is an error (``ValueError``), not "no passphrase": a key file
    that lost its contents must never open a vault as if no key had been configured."""
    if explicit:
        return explicit
    env = os.environ if env is None else env
    path = env.get(ENV_FILE)
    if path:
        key = _read_keyfile(path)
        if not key:
            raise ValueError(f"Key file {path} is empty; restore the key (or unset {ENV_FILE}).")
        return key
    return env.get(ENV_VALUE) or None


_TEMP_MARK = ".tmp-"


def _temp_prefix(path: str) -> str:
    return "." + os.path.basename(path) + _TEMP_MARK


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _sweep_stale_temps(path: str) -> None:
    """Remove temp files a killed :func:`generate_keyfile` for ``path`` left beside it (its pid is gone).
    They hold a key that was never installed, so nothing can depend on them."""
    directory = os.path.dirname(path) or "."
    prefix = _temp_prefix(path)
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        if not name.startswith(prefix):
            continue
        pid_text = name[len(prefix):].split("-", 1)[0]
        if not pid_text.isdigit() or _pid_alive(int(pid_text)):
            continue
        full = os.path.join(directory, name)
        try:
            if stat.S_ISREG(os.lstat(full).st_mode):
                os.unlink(full)
        except OSError:
            pass


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def generate_keyfile(path: str) -> None:
    """Create a new 256-bit random key file with mode 0600. Refuses to overwrite.

    The key is written and fsynced under a temporary name beside ``path`` and then linked into place
    in one step that fails when ``path`` exists, so ``path`` never exists without its whole key, and
    a process killed part way leaves at most a temporary file (removed by the next run)."""
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, "File exists", path)
    key = secrets.token_urlsafe(32) + "\n"
    directory = os.path.dirname(path) or "."
    _sweep_stale_temps(path)
    temp = os.path.join(directory, f"{_temp_prefix(path)}{os.getpid()}-{secrets.token_hex(4)}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temp, path)  # atomic, and never replaces an existing file
        except FileExistsError:
            raise
        except OSError:
            # A filesystem without hard links: an atomic rename instead, after a last check for a file
            # at ``path`` (only a concurrent creator in the instant between the two could be replaced).
            if os.path.lexists(path):
                raise FileExistsError(errno.EEXIST, "File exists", path) from None
            os.replace(temp, path)
        _fsync_dir(directory)
    finally:
        try:
            os.unlink(temp)
        except OSError:
            pass


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
        try:
            empty = os.path.isfile(path) and os.path.getsize(path) == 0
        except OSError:
            empty = False
        hint = " It is empty (left by an interrupted earlier version?): remove it and run again." if empty else ""
        print(f"{path} already exists; not overwriting it.{hint}", file=sys.stderr)
        return 1
    print(f"Created {path}. Set KIBISIS_PASSPHRASE_FILE={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
