"""Crash-safe temporaries beside an output: exact names, liveness by lock, and fsync ordering.

Every Kibisis writer that publishes a file or directory by building it under a temporary name beside
the output and renaming it into place (the key file, ``export_snapshot(path=...)``, the OKF bundle)
follows the same three rules, so that whatever a kill leaves behind is recognised and removed by a
later run, and nothing a live writer still needs is ever touched:

* **Exact names.** A temporary's name is derived from the exact name of the output it belongs to,
  plus a random token. A sweep matches a whole name against the pattern for its own output
  (``fullmatch``), never a prefix or a suffix, so two outputs whose names share a suffix
  (``bundle`` and ``shared.bundle``) never claim each other's leftovers.
* **Liveness by lock, not by pid.** The writer holds an exclusive ``flock`` on the temporary for as
  long as it can still need it. A later run removes a leftover only after taking that lock itself
  (:func:`claim`). The pid in a name is informational only: a container entrypoint is pid 1 on every
  run and pids are reused, so a pid can neither prove a writer alive nor dead. The kernel drops the
  lock when the writer dies, however it dies.
* **Durability.** Data is fsynced before it is renamed into place, the directory after the rename
  (:func:`fsync_dir`), and anything the rename supersedes is deleted only after that.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from typing import Callable, Optional, Tuple, Union

try:
    import fcntl
except ImportError:  # pragma: no cover - not POSIX
    fcntl = None  # type: ignore[assignment]

PathLike = Union[str, "os.PathLike[str]"]

#: Where no lock can be taken (no ``flock`` on the platform or the filesystem), a leftover is treated
#: as abandoned only once it is this old.
UNLOCKED_STALE_SECONDS = 3600.0

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_HELD = frozenset({errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES})
_UNSUPPORTED = frozenset(
    e for e in (errno.ENOLCK, errno.EINVAL, errno.ENOSYS, getattr(errno, "ENOTSUP", None), getattr(errno, "EOPNOTSUPP", None)) if e
)


def pid_alive(pid: int) -> bool:
    """Whether a process with ``pid`` exists (only for names written before locks were used)."""
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # PermissionError: alive, another user's
        return True
    return True


def fsync_dir(directory: PathLike) -> None:
    """Make the entries of ``directory`` (a rename, link or unlink in it) durable. Best effort where a
    directory cannot be opened or synced (some platforms and filesystems)."""
    try:
        fd = os.open(os.fspath(directory) or ".", os.O_RDONLY | _DIRECTORY | _CLOEXEC)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _lock(fd: int) -> Optional[bool]:
    """Take an exclusive lock on ``fd`` without waiting: True when taken, False when another open file
    holds it, None when locks are not available here."""
    if fcntl is None:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in _HELD:
            return False
        if exc.errno in _UNSUPPORTED:
            return None
        raise
    return True


def _same_entry(fd: int, path: PathLike) -> bool:
    """Whether ``path`` still names the file or directory open at ``fd``."""
    try:
        held, named = os.fstat(fd), os.lstat(path)
    except OSError:
        return False
    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


def create_locked(path: PathLike, *, directory: bool = False, mode: int = 0o600) -> Optional[int]:
    """Create ``path``, which must not exist, and take its lock. Returns the descriptor that holds the
    lock (a file is open for writing), or None when a sweep took the new entry before its lock was
    taken (the caller tries another name). ``FileExistsError`` when the name is taken."""
    if directory:
        os.mkdir(path, mode)
        try:
            fd = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
        except FileNotFoundError:
            return None
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC, mode)
    try:
        if _lock(fd) is False or not _same_entry(fd, path):
            os.close(fd)
            return None
    except BaseException:
        os.close(fd)
        raise
    return fd


def create_unique(
    make_path: Callable[[], PathLike], *, directory: bool = False, mode: int = 0o600, attempts: int = 16
) -> Tuple[str, int]:
    """Create a locked temporary under a fresh name from ``make_path`` (which adds a random token);
    returns its path and the descriptor holding its lock. The caller keeps the descriptor open until
    the temporary is renamed into place or removed."""
    path = ""
    for _ in range(max(1, attempts)):
        path = os.fspath(make_path())
        try:
            fd = create_locked(path, directory=directory, mode=mode)
        except FileExistsError:
            continue
        if fd is not None:
            return path, fd
    raise FileExistsError(errno.EEXIST, "could not create a unique temporary name", path)


def _take(path: PathLike, directory: bool, unlocked_ok: bool) -> Optional[int]:
    if directory:
        expected = stat.S_ISDIR
        flags = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
    else:
        expected = stat.S_ISREG
        flags = os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NONBLOCK  # a FIFO planted at the name never blocks
    try:
        if not expected(os.lstat(path).st_mode):
            return None  # never a symbolic link, a device or a socket
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not expected(st.st_mode) or not _same_entry(fd, path):
            os.close(fd)
            return None
        got = _lock(fd)
        if got is False or (got is None and not unlocked_ok and time.time() - st.st_mtime < UNLOCKED_STALE_SECONDS):
            os.close(fd)
            return None
        if not _same_entry(fd, path):  # renamed or replaced while the lock was being taken
            os.close(fd)
            return None
    except BaseException:
        os.close(fd)
        raise
    return fd


def claim(path: PathLike, *, directory: bool = False) -> Optional[int]:
    """Take a leftover at ``path`` to remove or restore it. Returns the descriptor holding its lock, or
    None when it is not abandoned: a live writer holds the lock, it is not a regular file (or, with
    ``directory``, a directory; a symbolic link is never followed), or it changed meanwhile. Without
    locks on this platform or filesystem, only a leftover older than :data:`UNLOCKED_STALE_SECONDS`
    is taken. The caller closes the descriptor once done."""
    return _take(path, directory, unlocked_ok=False)


def hold(path: PathLike, *, directory: bool = False) -> Optional[int]:
    """Lock an existing ``path`` the caller is about to move aside, so a sweep in another process
    reads it as live work for as long as the descriptor is open. None when another holds its lock.
    Without locks on this platform or filesystem the descriptor is returned unlocked."""
    return _take(path, directory, unlocked_ok=True)
