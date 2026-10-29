"""Settings shared by the MCP server and the ``kibisis`` command: database path, scope and passphrase.

Environment variables:

- ``KIBISIS_DB_PATH``: vault file. Default: a per-user data directory (see :func:`default_data_dir`).
- ``KIBISIS_SCOPE``: the one scope a server or command works in. Default: ``default``.
- ``KIBISIS_PASSPHRASE_FILE`` or ``KIBISIS_PASSPHRASE``: the key. Required unless
  ``KIBISIS_ALLOW_PLAINTEXT=1`` is set on purpose.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Optional

from .keys import resolve_passphrase
from .vault import SQLiteMemoryVault

ENV_DB_PATH = "KIBISIS_DB_PATH"
ENV_SCOPE = "KIBISIS_SCOPE"
ENV_ALLOW_PLAINTEXT = "KIBISIS_ALLOW_PLAINTEXT"
DEFAULT_SCOPE = "default"

# Letters, digits and . _ : @ - only. Rules out '*', empty and whitespace.
_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


class ConfigError(RuntimeError):
    """Raised when the environment does not describe a usable vault."""


def default_data_dir(env: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> Path:
    """Per-user data directory: XDG on Linux, Application Support on macOS, LOCALAPPDATA on Windows."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    if platform == "darwin":
        return home / "Library" / "Application Support" / "kibisis"
    if platform.startswith("win"):
        base = env.get("LOCALAPPDATA") or env.get("APPDATA")
        return (Path(base) if base else home / "AppData" / "Local") / "kibisis"
    xdg = env.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg and os.path.isabs(xdg) else home / ".local" / "share") / "kibisis"


def default_db_path(env: Optional[Mapping[str, str]] = None, platform: Optional[str] = None) -> str:
    """``KIBISIS_DB_PATH`` if set, else ``vault.sqlite`` in :func:`default_data_dir`."""
    env = os.environ if env is None else env
    explicit = env.get(ENV_DB_PATH)
    if explicit:
        return explicit
    return str(default_data_dir(env, platform) / "vault.sqlite")


def validate_scope(scope: str) -> str:
    """Return ``scope`` if it names exactly one scope; raise :class:`ConfigError` otherwise."""
    if not isinstance(scope, str) or not _SCOPE_RE.match(scope):
        raise ConfigError(
            f"Scope {scope!r} is not allowed: use 1-128 letters, digits or . _ : @ - "
            "(no wildcard, no empty scope)."
        )
    return scope


GLOBAL_SCOPE = "global"
_SCOPE_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def git_root(cwd: Optional[str] = None) -> Optional[str]:
    """Absolute path of the git checkout containing ``cwd``, or None when there is none."""
    start = os.path.abspath(cwd or os.getcwd())
    if not os.path.isdir(start):
        return None
    try:
        out = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    root = out.stdout.strip()
    return os.path.realpath(root) if root else None


def project_scope_for(root: str) -> str:
    """The scope a checkout at ``root`` gets: ``project:<name>-<8 hex of the root path>``.

    The name is the directory's basename reduced to scope-safe characters; the digest keeps two
    checkouts with the same name at different paths apart and makes every subdirectory agree."""
    real = os.path.realpath(root)
    name = _SCOPE_SAFE.sub("-", os.path.basename(real)).strip("-") or "repo"
    digest = hashlib.sha256(real.encode("utf-8")).hexdigest()[:8]
    return validate_scope(f"project:{name[:64]}-{digest}")


def resolve_scope(env: Optional[Mapping[str, str]] = None, cwd: Optional[str] = None) -> str:
    """The scope a process works in (K-J).

    ``KIBISIS_SCOPE`` wins when set (``global`` is only ever reached this way). Otherwise, inside a git
    checkout the scope is that project's (:func:`project_scope_for` of the root), and outside one it is
    ``default``. Wildcards and empty values are refused.
    """
    env = os.environ if env is None else env
    explicit = env.get(ENV_SCOPE)
    if explicit is not None:
        return validate_scope(explicit)
    root = git_root(cwd)
    if root is not None:
        return project_scope_for(root)
    return DEFAULT_SCOPE


def plaintext_allowed(env: Optional[Mapping[str, str]] = None) -> bool:
    """True only when ``KIBISIS_ALLOW_PLAINTEXT`` is set to 1, true or yes."""
    env = os.environ if env is None else env
    return env.get(ENV_ALLOW_PLAINTEXT, "").strip().lower() in ("1", "true", "yes")


def open_vault(db_path: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> SQLiteMemoryVault:
    """Open the vault the environment describes. Refuses to run without a key unless plaintext is allowed."""
    env = os.environ if env is None else env
    path = db_path or default_db_path(env)
    passphrase = resolve_passphrase(env=env)
    allow_plaintext = plaintext_allowed(env)
    if not passphrase and not allow_plaintext:
        raise ConfigError(
            "No key: set KIBISIS_PASSPHRASE_FILE to a key file (create one with `python -m kibisis.keys PATH`) "
            "or set KIBISIS_PASSPHRASE. To store memory unencrypted on purpose, set KIBISIS_ALLOW_PLAINTEXT=1."
        )
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    return SQLiteMemoryVault(path, passphrase=passphrase, allow_plaintext=allow_plaintext and not passphrase)
