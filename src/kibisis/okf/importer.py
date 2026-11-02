"""okf-import: diff an OKF v0.2 bundle into the vault as model-origin candidates (P13.2). Stdlib only.

What is read. Concept files at ``<scope>/<category>/<key>.md`` under the profile's allowlist; the
built-in profile is owner decision 3 (scope ``default``; ``architecture``, ``convention``, ``decision``,
``project_state``). ``index.md`` and ``log.md`` at the bundle root are the bundle's own files. Every other
entry is skipped and counted under the first reason that applies:

``hidden`` (a name starting with ``.``; never descended), ``symlink`` (never followed), ``not_regular``,
``not_markdown``, ``unexpected_path`` (not three levels deep), ``unsafe_name`` (scope or category is not
a portable directory name), ``scope``, ``excluded_category``, ``category``, ``excluded_key``,
``unsafe_key``, ``reserved_key``, ``too_large`` (over :data:`MAX_CONCEPT_BYTES`), ``unreadable``,
``not_utf8``, ``frontmatter`` (does not parse, or a value could not be written back), ``not_concept`` (no
frontmatter, or no ``type``), ``confidential`` / ``sensitivity`` (the file declares what the exporter's
default-deny rule withholds), and ``key_collision`` (files whose paths differ only in case; all of them).

How a concept maps onto a row. The path gives (scope, category, key); the body after the closing fence is
the content, byte for byte. Field-map keys (:data:`~kibisis.okf.export.FIELD_MAP_KEYS`) project vault state
and are not read back, with one exception: ``verified``. Its stamps (a list, a bare mapping or a bare
string) are claims. They are kept as metadata ``okf_verified_claims`` (``by`` and ``at`` as read, plus the
file's sha256) and never become trust. A stamp the exporter writes for the row itself (a person's admit)
and a claim the row already records are not new claims. Keys the vault owns
(:func:`~kibisis.okf.export.is_vault_owned_key`) are dropped and counted in ``dropped_keys``. Every other
key is kept in file order as metadata ``okf_extra`` (a JSON object in a string, so the order survives the
vault), and okf-export writes those keys back after its own, in the writer's canonical form.

Outcomes. A concept is ``unchanged`` when its body, its unknown keys and its claims match its row, and
otherwise ``new`` (no row) or ``changed``. New and changed concepts are written through the vault's
model-origin path: ``origin="model"`` (the vault caps ``act_class`` at ``inform``) with ``author_id``
:data:`IMPORTER_ID` and the admission gate off. The importer never passes ``epistemic_state``, so the
vault makes every import write a ``candidate``. With the gate on, a write that states no state is routed
by its content (an empty body lands ``revoked``, a transient one expires in 24 h), which owner decision 3
rules out and a dry run could not predict. The importer takes no origin, state or identity from its
caller or from file text. A rewrite carries the row's own metadata forward, lineage included, except
``author_id`` (so the row is attributed to the importer) and the vault's per-write annotations, which
would misdescribe the import's own write. It passes the row's ``derived_from`` back to the vault, which
recomputes the class drop along it (so an import cannot launder trust), and keeps the row's binding
(``tenant_id``, ``principal_id``), validity window, ``source_ref`` and ``confidence``.

A new or changed concept that may not be written is a conflict, left for a person. The first reason that
applies wins: ``key_collision`` (a new concept whose path differs only in case from a row's), ``archived``
(the write would revive the row), ``confidential`` / ``sensitivity`` (the row is withheld from export),
then the vault's own refusals in the order it checks them: ``superseded`` (SupersededEntryError),
``origin_class`` (OriginClassError: a model write cannot overwrite a higher-class row), ``reviewed``
(ReviewedEntryError: the row is verified or carries a person's review), ``tombstoned``
(TombstonedValueError), and last two writes the vault would accept but a person decides:
``pending_review`` (a supersession proposal waits on the row, which carries ``proposed_supersedes`` or
``pending_supersession_by``; review_entity reads both) and ``disputed`` (the review cascade or a
contradiction disputed the row, and a rewrite would land it as a plain candidate). Where the vault would
refuse, its reason is the one reported. Conflicts are predicted before any write, so a dry run reports
what a real run does. A real run never sends a predicted conflict to the vault, and it records any
refusal the vault still raises as a conflict. Writes are one row at a time: an unexpected error stops the
run, and the rows written before it stay written.

``dry_run=True`` reads the bundle and the vault and writes nothing. Live use in P13 is dry-run only.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .._vault_review import ORIGIN_CLASSES, _class_rank, origin_class_of
from ..vault import (
    RESERVED_METADATA_KEYS,
    RESERVED_METADATA_PREFIX,
    OriginClassError,
    ReviewedEntryError,
    SupersededEntryError,
    TombstonedValueError,
)
from .export import (
    FIELD_MAP_KEYS,
    OKF_VERSION,
    RESERVED_STEMS,
    _dir_segment,
    _person_admit_stamps,
    _sensitivity_reason,
    _state,
    dump_extra,
    is_vault_owned_key,
    safe_segment,
)
from .frontmatter import FrontmatterError, dump_frontmatter, parse_frontmatter, split_document
from .profile import ExportProfile, default_profile

__all__ = ["IMPORTER_ID", "MAX_CONCEPT_BYTES", "BundleImportError", "ImportReport", "import_bundle"]

#: The ``author_id`` of every import write, in the entity's metadata and in the journal.
IMPORTER_ID = "kibisis:okf-import"
#: A larger concept file is skipped as ``too_large`` unread.
MAX_CONCEPT_BYTES = 1 << 20
#: The only origin an import writes with. Not a parameter anywhere.
_ORIGIN = "model"
_BUNDLE_FILES = frozenset({"index.md", "log.md"})
#: Metadata a rewrite does not carry forward: ``author_id`` (the vault keeps a caller's over its own),
#: the vault's per-write annotations (the admission gate's verdict, a capped trust request), and the
#: importer's own keys, which it writes afresh. Lineage (``derived_from``, ``supersedes``,
#: ``supersession``, ``revived_from``, ``invalidated_by``) is the row's history and is carried forward.
_REWRITTEN_KEYS = frozenset({
    "author_id", "admission_disposition", "admission_provenance", "trust_capped_from",
    "okf_extra", "okf_verified_claims",
})
_REFUSALS = (
    (SupersededEntryError, "superseded"),
    (OriginClassError, "origin_class"),
    (ReviewedEntryError, "reviewed"),
    (TombstonedValueError, "tombstoned"),
)


class BundleImportError(ValueError):
    """The bundle cannot be read: missing, not a directory, a symlink, or another OKF version."""


@dataclass
class ImportReport:
    bundle: str
    dry_run: bool
    profile_digest: str
    examined: int = 0
    new: List[str] = field(default_factory=list)
    changed: List[str] = field(default_factory=list)
    unchanged: int = 0
    conflicts: Dict[str, str] = field(default_factory=dict)
    skipped: Dict[str, int] = field(default_factory=dict)
    claims: int = 0
    dropped_keys: Dict[str, int] = field(default_factory=dict)
    written: List[str] = field(default_factory=list)

    @property
    def would_change(self) -> int:
        return len(self.new) + len(self.changed)

    def summary(self) -> Dict[str, Any]:
        return {
            "bundle": self.bundle,
            "dry_run": self.dry_run,
            "profile_digest": self.profile_digest,
            "examined": self.examined,
            "new": len(self.new),
            "changed": len(self.changed),
            "unchanged": self.unchanged,
            "would_change": self.would_change,
            "written": len(self.written),
            "conflicts": dict(sorted(Counter(self.conflicts.values()).items())),
            "conflicts_total": len(self.conflicts),
            "skipped": dict(sorted(self.skipped.items())),
            "skipped_total": sum(self.skipped.values()),
            "claims": self.claims,
            "dropped_keys": dict(sorted(self.dropped_keys.items())),
            "files": {"new": list(self.new), "changed": list(self.changed), "conflicts": dict(self.conflicts)},
        }


@dataclass
class _Concept:
    rel: str
    scope: str
    category: str
    key: str
    body: str
    extra: List[Tuple[str, Any]]
    claims: List[Dict[str, Optional[str]]]
    dropped: List[str]
    sha256: str


# ----------------------------------------------------------------------------------- reading the bundle

def _claims(value: Any) -> List[Dict[str, Optional[str]]]:
    """``verified`` stamps as claims: ``by`` (a non-empty string) and ``at`` (a string, else None)."""
    items = value if isinstance(value, list) else [value]
    out: List[Dict[str, Optional[str]]] = []
    seen: Set[Tuple[str, Optional[str]]] = set()
    for item in items:
        if isinstance(item, str):
            by, at = item, None
        elif isinstance(item, dict):
            by, at = item.get("by"), item.get("at")
        else:
            continue
        if not isinstance(by, str) or not by.strip():
            continue
        at = at if isinstance(at, str) else None
        if (by, at) not in seen:
            seen.add((by, at))
            out.append({"by": by, "at": at})
    return out


def _path_reason(parts: Tuple[str, ...], profile: ExportProfile) -> Optional[str]:
    if not parts[-1].endswith(".md"):
        return "not_markdown"
    if len(parts) != 3:
        return "unexpected_path"
    scope, category, name = parts
    key = name[:-3]
    if not (_dir_segment(scope) and _dir_segment(category)):
        return "unsafe_name"
    if scope not in profile.scopes:
        return "scope"
    if category in profile.exclude_categories:
        return "excluded_category"
    if category not in profile.categories:
        return "category"
    if profile.excludes_key(key):
        return "excluded_key"
    if not safe_segment(key):
        return "unsafe_key"
    if key.lower() in RESERVED_STEMS:
        return "reserved_key"
    return None


def _read_capped(path: Path) -> Union[bytes, str]:
    """The file's bytes, or a skip reason. Opened without following a link, and never blocking."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return "symlink" if exc.errno == errno.ELOOP else "unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "not_regular"
        if st.st_size > MAX_CONCEPT_BYTES:
            return "too_large"
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONCEPT_BYTES:
                return "too_large"
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError:
        return "unreadable"
    finally:
        os.close(fd)


def _parse(rel: str, parts: Tuple[str, ...], data: bytes) -> Union[_Concept, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "not_utf8"
    try:
        fm, body = split_document(text)
        if fm is None:
            return "not_concept"
        meta = parse_frontmatter(fm)
    except FrontmatterError:
        return "frontmatter"
    kind = meta.get("type")
    if not isinstance(kind, str) or not kind.strip():
        return "not_concept"
    reason = _sensitivity_reason(meta)
    if reason is not None:
        return reason
    extra: List[Tuple[str, Any]] = []
    dropped: List[str] = []
    for k, v in meta.items():
        if k in FIELD_MAP_KEYS:
            continue
        if is_vault_owned_key(k):
            dropped.append(k)
        else:
            extra.append((k, v))
    if extra:
        try:
            dump_frontmatter(dict(extra))  # what okf-export will write back must be writable
            dump_extra(extra)
        except (FrontmatterError, ValueError, TypeError):
            return "frontmatter"
    scope, category, name = parts
    return _Concept(rel=rel, scope=scope, category=category, key=name[:-3], body=body, extra=extra,
                    claims=_claims(meta.get("verified")), dropped=dropped,
                    sha256=hashlib.sha256(data).hexdigest())


def _scan(root: Path, profile: ExportProfile, skipped: Counter) -> Dict[str, _Concept]:
    found: Dict[str, _Concept] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        base = here.relative_to(root).parts
        keep: List[str] = []
        for name in sorted(dirnames):
            if name.startswith("."):
                skipped["hidden"] += 1
            elif os.path.islink(here / name):
                skipped["symlink"] += 1
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            parts = base + (name,)
            rel = "/".join(parts)
            full = here / name
            if name.startswith("."):
                skipped["hidden"] += 1
                continue
            try:
                st = os.lstat(full)
            except OSError:
                skipped["unreadable"] += 1
                continue
            if stat.S_ISLNK(st.st_mode):
                skipped["symlink"] += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                skipped["not_regular"] += 1
                continue
            if len(parts) == 1 and name in _BUNDLE_FILES:
                continue
            reason = _path_reason(parts, profile)
            if reason is None and st.st_size > MAX_CONCEPT_BYTES:
                reason = "too_large"
            if reason is not None:
                skipped[reason] += 1
                continue
            data = _read_capped(full)
            parsed = _parse(rel, parts, data) if isinstance(data, bytes) else data
            if isinstance(parsed, str):
                skipped[parsed] += 1
                continue
            found[rel] = parsed
    folded = Counter(rel.lower() for rel in found)
    for rel in [r for r in found if folded[r.lower()] > 1]:
        del found[rel]
        skipped["key_collision"] += 1
    return found


def _check_version(root: Path) -> None:
    index = root / "index.md"
    if os.path.islink(index) or not index.is_file():
        return
    try:
        fm, _body = split_document(index.read_bytes().decode("utf-8"))
        meta = parse_frontmatter(fm) if fm is not None else {}
    except (UnicodeDecodeError, FrontmatterError, OSError):
        return  # okf-check reports a malformed index; the concepts are still read under the rules above
    version = meta.get("okf_version")
    if version is not None and str(version) != OKF_VERSION:
        raise BundleImportError(f"the bundle declares okf_version {version!r}; this importer reads {OKF_VERSION}")


# --------------------------------------------------------------------------------- diffing against rows

def _stored_extra(meta: Dict[str, Any]) -> Optional[str]:
    raw = meta.get("okf_extra")
    return raw if isinstance(raw, str) else None


def _stored_claims(meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = meta.get("okf_verified_claims")
    return [c for c in raw if isinstance(c, dict)] if isinstance(raw, list) else []


def _row_conflict(vault: Any, row: Any, body: str) -> Optional[str]:
    """The reason a model-origin rewrite of ``row`` must not happen, in the vault's own order, or None."""
    meta = row.metadata if isinstance(row.metadata, dict) else {}
    if row.archived:
        return "archived"
    reason = _sensitivity_reason(row.metadata)
    if reason is not None:
        return reason
    if row.superseded_by:
        return "superseded"
    stored = meta.get("origin_class")
    stored_class = stored if stored in ORIGIN_CLASSES else origin_class_of(row.origin)
    if _class_rank(origin_class_of(_ORIGIN)) < _class_rank(stored_class):
        return "origin_class"
    if _state(row) == "verified" or meta.get("human_reviews"):
        return "reviewed"
    if vault.is_tombstoned(row.category, row.key, body, scope=row.scope):
        return "tombstoned"
    if meta.get("proposed_supersedes") or meta.get("pending_supersession_by"):
        return "pending_review"
    if _state(row) == "disputed":
        return "disputed"
    return None


def _reserved(key: str) -> bool:
    return key in RESERVED_METADATA_KEYS or key.startswith(RESERVED_METADATA_PREFIX)


def _write(vault: Any, c: _Concept, row: Any, claims: List[Dict[str, Any]]) -> None:
    if row is None:
        meta: Dict[str, Any] = {}
        if c.extra:
            meta["okf_extra"] = dump_extra(c.extra)
        if claims:
            meta["okf_verified_claims"] = claims
        vault.put(c.category, c.key, c.body, metadata=meta or None, scope=c.scope, origin=_ORIGIN,
                  author_id=IMPORTER_ID, auto_gate=False)
        return
    old = row.metadata if isinstance(row.metadata, dict) else {}
    meta = {k: v for k, v in old.items() if not _reserved(k) and k not in _REWRITTEN_KEYS}
    if c.extra:
        meta["okf_extra"] = dump_extra(c.extra)
    if claims:
        meta["okf_verified_claims"] = claims
    tenant = old.get("tenant_id")
    principal = old.get("principal_id")
    lineage = old.get("derived_from")
    derived = [r for r in lineage if isinstance(r, str)] if isinstance(lineage, list) else []
    vault.put(
        row.category, row.key, c.body, metadata=meta, scope=row.scope, origin=_ORIGIN, author_id=IMPORTER_ID,
        tenant_id=tenant if isinstance(tenant, str) and tenant else None,
        principal_id=principal if isinstance(principal, str) and principal else None,
        derived_from=derived or None,
        valid_from=row.valid_from, valid_until=row.valid_until, source_ref=row.source_ref,
        confidence=row.confidence, auto_gate=False,
    )


def import_bundle(
    vault: Any,
    bundle: Union[str, "os.PathLike[str]"],
    *,
    profile: Optional[ExportProfile] = None,
    dry_run: bool = False,
) -> ImportReport:
    """Diff the OKF bundle at ``bundle`` into ``vault``; see the module docstring."""
    if profile is None:
        profile = default_profile()
    if not isinstance(profile, ExportProfile):
        raise BundleImportError("profile must be an ExportProfile from load_profile, parse_profile or default_profile")
    root = Path(os.path.abspath(os.fspath(bundle)))
    if os.path.islink(root):
        raise BundleImportError(f"the bundle {root} is a symlink; pass the directory itself")
    if not root.is_dir():
        raise BundleImportError(f"no bundle directory at {root}")
    _check_version(root)

    skipped: Counter = Counter()
    concepts = _scan(root, profile, skipped)
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    by_ref = {(r.scope, r.category, r.key): r for r in rows}
    row_folds = {("%s/%s/%s.md" % (r.scope, r.category, r.key)).lower() for r in rows}

    report = ImportReport(bundle=str(root), dry_run=bool(dry_run), profile_digest=profile.digest,
                          examined=len(concepts), skipped=dict(skipped))
    dropped: Counter = Counter()
    for rel in sorted(concepts):
        c = concepts[rel]
        dropped.update(c.dropped)
        row = by_ref.get((c.scope, c.category, c.key))
        if row is None:
            fresh = list(c.claims)
            if rel.lower() in row_folds:
                report.conflicts[rel] = "key_collision"
                continue
            if vault.is_tombstoned(c.category, c.key, c.body, scope=c.scope):
                report.conflicts[rel] = "tombstoned"
                continue
            outcome = report.new
            recorded: List[Dict[str, Any]] = []
        else:
            meta = row.metadata if isinstance(row.metadata, dict) else {}
            recorded = _stored_claims(meta)
            known = {(x.get("by"), x.get("at")) for x in recorded}
            if c.claims:
                known |= {(s["by"], s["at"]) for s in _person_admit_stamps(vault, row)}
            fresh = [x for x in c.claims if (x["by"], x["at"]) not in known]
            extra_now = dump_extra(c.extra) if c.extra else None
            if c.body == row.content and extra_now == _stored_extra(meta) and not fresh:
                report.unchanged += 1
                continue
            reason = _row_conflict(vault, row, c.body)
            if reason is not None:
                report.conflicts[rel] = reason
                continue
            outcome = report.changed
        if not dry_run:
            stamped = recorded + [dict(x, file_sha256=c.sha256) for x in fresh]
            try:
                _write(vault, c, row, stamped)
            except tuple(cls for cls, _ in _REFUSALS) as exc:
                report.conflicts[rel] = next(name for cls, name in _REFUSALS if isinstance(exc, cls))
                continue
            report.written.append(rel)
        outcome.append(rel)
        report.claims += len(fresh)
    report.dropped_keys = dict(sorted(dropped.items()))
    return report
