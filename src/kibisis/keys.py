"""Passphrase resolution for Kibisis. Keys are read from a file or the environment, never from source."""

from __future__ import annotations

import errno
import os
import re
import secrets
import stat
from typing import Mapping, Optional

from . import _atomic

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
#: What follows ``.<key file name>.tmp-`` in a temp name: ``<pid>-<hex>`` and nothing else. A sweep
#: matches it whole, so the temp of another key file whose name starts with this one's is never taken
#: for its own.
_TEMP_TOKEN = re.compile(r"[0-9]+-[0-9a-f]+\Z")


def _temp_prefix(path: str) -> str:
    return "." + os.path.basename(path) + _TEMP_MARK


def _sweep_stale_temps(path: str) -> None:
    """Remove the temp files a killed :func:`generate_keyfile` for ``path`` left beside it.

    A temp is removed only once its lock has been taken here, so never while the run that made it is
    alive (that run holds the lock until the temp is gone), whatever pid either run has. A leftover is
    either a key that was never installed or, when its run was killed between the link and the
    unlink, a second name of the installed key: neither may outlive the run that made it."""
    directory = os.path.dirname(path) or "."
    prefix = _temp_prefix(path)
    try:
        names = os.listdir(directory)
    except OSError:
        return
    removed = False
    for name in names:
        if not name.startswith(prefix) or not _TEMP_TOKEN.match(name[len(prefix):]):
            continue
        full = os.path.join(directory, name)
        fd = _atomic.claim(full)
        if fd is None:
            continue
        try:
            os.unlink(full)
            removed = True
        except OSError:
            pass
        finally:
            os.close(fd)
    if removed:
        _fsync_dir(directory)


def _fsync_dir(directory: str) -> None:
    _atomic.fsync_dir(directory)


def generate_keyfile(path: str) -> None:
    """Create a new 256-bit random key file with mode 0600. Refuses to overwrite.

    The key is written and fsynced under a temporary name beside ``path`` and then linked into place
    in one step that fails when ``path`` exists, so ``path`` never exists without its whole key. The
    run holds a lock on the temp until it has removed it. A run killed part way leaves at most that
    temp, and the next run for ``path`` removes it first, before it checks for (and refuses) an
    existing key, so a temp that is a second name of the installed key does not survive either."""
    directory = os.path.dirname(path) or "."
    _sweep_stale_temps(path)
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, "File exists", path)
    key = (secrets.token_urlsafe(32) + "\n").encode("utf-8")
    temp, fd = _atomic.create_unique(
        lambda: os.path.join(directory, f"{_temp_prefix(path)}{os.getpid()}-{secrets.token_hex(4)}")
    )
    try:
        try:
            view = memoryview(key)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
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
            _fsync_dir(directory)  # the key's own name is durable before its temp name goes
        finally:
            try:
                os.unlink(temp)  # still under the lock, so no sweep takes the temp before this
            except OSError:
                pass
        _fsync_dir(directory)
    finally:
        os.close(fd)


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
