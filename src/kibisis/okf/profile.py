"""OKF export profile: which vault rows one ``okf-export`` run may project (P13.4).

A profile is a JSON file with schema ``kibisis.okf_export_profile/1``::

    {
      "schema": "kibisis.okf_export_profile/1",
      "audience": "owner",
      "allow": {"scopes": ["default"],
                "categories": ["architecture", "convention", "decision", "project_state"]},
      "named": [],
      "exclude": {"keys": [], "categories": []}
    }

It is default-deny. A row is exportable only when its scope is in ``allow.scopes``, its category
is in ``allow.categories`` or ``named``, and neither its category nor its key is excluded.
``allow.categories`` may hold only categories in :data:`DEFAULT_CATEGORIES`; any other category
(``user_profile``, ``diagnosis``, ...) is exported only when the profile names it in ``named``.
Every list is explicit: a wildcard, an unknown key or a missing allow list is refused.

``producer`` is not a file key. It is ``kibisis/<version>``, set from the library at load, so a
new library version that would project the same file differently also gets a new digest.

The digest is the sha256 of the canonical JSON (sorted keys, separators ``,`` and ``:``, UTF-8,
lists sorted). It goes into the bundle-root ``index.md`` as ``telarch_export_profile_sha256``.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

SCHEMA = "kibisis.okf_export_profile/1"

#: The categories a profile may allow without naming them (owner decision 3, P13).
DEFAULT_CATEGORIES: Tuple[str, ...] = ("architecture", "convention", "decision", "project_state")

_TOP_KEYS = frozenset({"schema", "audience", "allow", "named", "exclude"})
_ALLOW_KEYS = frozenset({"scopes", "categories"})
_EXCLUDE_KEYS = frozenset({"keys", "categories"})
#: Scope and category names are literal identifiers: no glob, regex or SQL wildcard characters.
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*\Z")
#: Excluded keys are free-form vault keys, but still literal.
_WILDCARD_CHARS = frozenset("*?[]{}%")


class ProfileError(ValueError):
    """The profile is malformed, or it would widen an export beyond an explicit allowlist."""


def producer() -> str:
    """``kibisis/<version>`` of the library that loads (and so projects through) a profile."""
    import kibisis

    return "kibisis/" + str(kibisis.__version__)


@dataclass(frozen=True)
class ExportProfile:
    """A loaded, validated profile. Every tuple is sorted, so equal profiles compare and digest equal."""

    audience: str
    scopes: Tuple[str, ...]
    allow_categories: Tuple[str, ...]
    named: Tuple[str, ...]
    exclude_keys: Tuple[str, ...]
    exclude_categories: Tuple[str, ...]
    producer: str

    @property
    def categories(self) -> Tuple[str, ...]:
        """Every category the profile opts in: the allowed default categories plus the named ones."""
        return tuple(sorted(set(self.allow_categories) | set(self.named)))

    def allows(self, scope: str, category: str) -> bool:
        """True when a row in ``scope``/``category`` passes the allowlist and the category exclusions."""
        return scope in self.scopes and category in self.categories and category not in self.exclude_categories

    def excludes_key(self, key: str) -> bool:
        return key in self.exclude_keys

    def canonical(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "audience": self.audience,
            "allow": {"scopes": list(self.scopes), "categories": list(self.allow_categories)},
            "named": list(self.named),
            "exclude": {"keys": list(self.exclude_keys), "categories": list(self.exclude_categories)},
            "producer": self.producer,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def _no_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ProfileError(f"duplicate key {k!r} in the profile; a later value would silently replace an earlier one")
        out[k] = v
    return out


def _only(obj: Dict[str, Any], allowed: frozenset, where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise ProfileError(f"unknown key(s) {unknown} in {where}; allowed: {sorted(allowed)}")


def _string_list(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        raise ProfileError(f"{field} must be a list of strings, got {type(value).__name__}")
    for item in value:
        if not isinstance(item, str):
            raise ProfileError(f"{field} holds a non-string entry {item!r}")
    if len(set(value)) != len(value):
        raise ProfileError(f"{field} lists an entry more than once")
    return value


def _names(value: Any, field: str, *, required: bool) -> Tuple[str, ...]:
    items = _string_list(value, field)
    if required and not items:
        raise ProfileError(f"{field} is empty; default-deny: name each one to export")
    for item in items:
        if not _NAME.match(item):
            raise ProfileError(f"{field} entry {item!r} is not a literal name (wildcards and odd characters are refused)")
    return tuple(sorted(items))


def _keys(value: Any, field: str) -> Tuple[str, ...]:
    items = _string_list(value, field)
    for item in items:
        if not item or any(ch in _WILDCARD_CHARS or ord(ch) < 32 or ord(ch) == 127 for ch in item):
            raise ProfileError(f"{field} entry {item!r} is not a literal key (wildcards and control characters are refused)")
    return tuple(sorted(items))


def parse_profile(text: str) -> ExportProfile:
    """Validate profile JSON text; raise :class:`ProfileError` on anything but an explicit allowlist."""
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except ProfileError:
        raise
    except ValueError as exc:
        raise ProfileError(f"the profile is not valid JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise ProfileError("the profile must be a JSON object")
    unknown = sorted(set(obj) - _TOP_KEYS)
    if unknown:
        hint = " (producer is set from the library at load, not read from the file)" if "producer" in unknown else ""
        raise ProfileError(f"unknown profile key(s) {unknown}{hint}")
    if obj.get("schema") != SCHEMA:
        raise ProfileError(f"schema must be {SCHEMA!r}, got {obj.get('schema')!r}")
    audience = obj.get("audience")
    if not isinstance(audience, str) or not audience.strip():
        raise ProfileError("audience must be a non-empty string")

    if "allow" not in obj:
        raise ProfileError("the profile has no allow list (default-deny: name the scopes and categories to export)")
    allow = obj["allow"]
    if not isinstance(allow, dict):
        raise ProfileError("allow must be an object with scopes and categories")
    _only(allow, _ALLOW_KEYS, "allow")
    for field in ("scopes", "categories"):
        if field not in allow:
            raise ProfileError(f"allow.{field} is missing; default-deny: name each one to export")
    scopes = _names(allow["scopes"], "allow.scopes", required=True)
    allow_categories = _names(allow["categories"], "allow.categories", required=True)
    outside = [c for c in allow_categories if c not in DEFAULT_CATEGORIES]
    if outside:
        raise ProfileError(
            f"allow.categories {outside} are outside the default allowlist {list(DEFAULT_CATEGORIES)}; "
            "a profile opts such a category in by listing it in named"
        )

    named = _names(obj.get("named", []), "named", required=False)
    inside = [c for c in named if c in DEFAULT_CATEGORIES]
    if inside:
        raise ProfileError(f"named lists only categories outside the default allowlist; {inside} are in it (use allow.categories)")

    exclude = obj.get("exclude", {})
    if not isinstance(exclude, dict):
        raise ProfileError("exclude must be an object with keys and categories")
    _only(exclude, _EXCLUDE_KEYS, "exclude")
    exclude_keys = _keys(exclude.get("keys", []), "exclude.keys")
    exclude_categories = _names(exclude.get("categories", []), "exclude.categories", required=False)

    return ExportProfile(
        audience=audience,
        scopes=scopes,
        allow_categories=allow_categories,
        named=named,
        exclude_keys=exclude_keys,
        exclude_categories=exclude_categories,
        producer=producer(),
    )


def load_profile(path: Union[str, Path]) -> ExportProfile:
    """Read and validate a profile file (UTF-8 JSON)."""
    try:
        text = Path(path).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProfileError(f"cannot read profile {str(path)!r}: {exc}") from None
    return parse_profile(text)
