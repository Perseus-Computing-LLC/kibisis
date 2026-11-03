"""okf-export: project allowlisted vault rows into an OKF v0.2 bundle (P13.1). Stdlib only.

A row is kept only if it passes, in this order (the first failure is the reason it is counted under):

1. not archived (``archived``);
2. in the profile's allowlist: scope (``scope``), category not excluded (``excluded_category``),
   category allowed or named (``category``), key not excluded (``excluded_key``);
3. sensitivity absent or ``normal``. ``confidential`` (or a truthy ``confidential`` flag) is
   ``confidential``; any other value fails closed as ``sensitivity``;
4. scope and category safe as directory names (``unsafe_name``), key safe as one path segment
   (``unsafe_key``) and not an OKF reserved filename in any case (``reserved_key``), and no other
   kept row whose path differs only in case (``key_collision``, every member withheld);
5. renders (``render_error``), then the content gate: a rendered file the row gate flags is
   withheld (``content_gate``), and a file the bundle gate names is withheld and the bundle
   re-staged (``bundle_gate``). A flagged row is withheld, never redacted: a redacted concept would
   differ from its row and break P13.2's unchanged round trip.

Each kept row becomes ``<scope>/<category>/<key>.md`` under the INTEGRATION.md section 5 field map.
The bundle root gets ``index.md`` (frontmatter ``okf_version`` and ``telarch_export_profile_sha256``)
and ``log.md`` (one entry per run, counts only). ``index_profile_digest=False`` leaves the digest key
out of ``index.md`` (``okf_version`` alone) for callers whose content gate flags it; the digest is
still returned in the report, and every other file is unchanged. Concept files and ``index.md`` carry
no run time; ``at`` fixes only the log date, so the same vault, profile and ``at`` give the same bytes.

Unknown keys. A row whose metadata ``okf_extra`` (written by okf-import, P13.2) holds a JSON object gets
those keys after the field map's own, in stored order, in the frontmatter writer's canonical form. A
field-map key, or a key the vault owns (:func:`is_vault_owned_key`), is never written from it, so
``okf_extra`` cannot add a stamp, a state, an identity or a lineage mark to a concept. A malformed ``okf_extra`` (not a
JSON object, or a non-finite number) withholds the row as ``render_error``.

The bundle is written to a fresh staging directory beside ``out`` and moved into place by rename, or,
when ``out`` already holds a bundle, by one exchange call (renameat2 / renamex_np) so ``out`` never
goes missing; other platforms fall back to two renames.
``out`` must be absent, empty, or a bundle this exporter wrote; anything else is refused untouched.
The library refuses to write without a gate choice: ``row_gate``, ``bundle_gate`` or an explicit
``ungated=True`` (synthetic fixtures).
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import functools
import json
import math
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from .frontmatter import FrontmatterError, parse_frontmatter, render_document, split_document
from ..vault import RESERVED_METADATA_KEYS, RESERVED_METADATA_PREFIX
from .profile import ExportProfile

__all__ = [
    "BundleGate",
    "ExportError",
    "ExportReport",
    "FIELD_MAP_KEYS",
    "GateRefused",
    "LOG_TITLE",
    "OKF_VERSION",
    "PROFILE_DIGEST_KEY",
    "RowGate",
    "command_gate",
    "dump_extra",
    "export_bundle",
    "first_sentence",
    "is_vault_owned_key",
    "iso_utc",
    "load_extra",
    "name_tokens",
    "named_rows",
    "names_at",
    "safe_segment",
    "type_name",
]

OKF_VERSION = "0.2"
PROFILE_DIGEST_KEY = "telarch_export_profile_sha256"
LOG_TITLE = "# Export Log"
#: OKF reserved filenames (section 3.1) without the extension; compared case-insensitively.
RESERVED_STEMS = frozenset({"index", "log"})
#: Frontmatter keys the field map writes from vault state (INTEGRATION.md section 5). okf-import reads
#: none of them back except ``verified``, whose stamps it keeps as claims, never as trust.
FIELD_MAP_KEYS = frozenset({
    "type", "title", "description", "status", "stale_after", "generated", "verified", "sources",
    "kibisis_state", "kibisis_origin", "kibisis_superseded_by",
})
#: Keys the vault owns besides its reserved metadata: identity, state, sensitivity, lineage and
#: supersession marks, per-write annotations, and the importer's own.
_OWNED_KEYS = frozenset({
    "author_id", "writer_id", "writer_class", "epistemic_state", "origin", "trust_ceiling", "reviewer_id",
    "reviewer_origin", "confidential", "sensitivity",
    "derived_from", "supersedes", "superseded_by", "supersession", "supersession_approved_by",
    "proposed_supersedes", "pending_supersession_by", "revived_from", "invalidated_by",
    "admission_disposition", "admission_provenance", "trust_capped_from",
    "okf_extra", "okf_verified_claims",
})
_OWNED_LOWER = frozenset(k.lower() for k in RESERVED_METADATA_KEYS | _OWNED_KEYS)
_OWNED_PREFIXES = (RESERVED_METADATA_PREFIX.lower(), "kibisis_", "telarch_")
_ALL_EVENTS = 2 ** 62

#: ``row_gate(rel_path, rendered_text)`` returns findings; any truthy result withholds the row.
RowGate = Callable[[str, str], Any]
#: ``bundle_gate(staging_dir, file_paths)`` returns True (pass), False (refuse the bundle), or the
#: paths of concept files to withhold; the bundle is then re-staged and gated again.
BundleGate = Callable[[str, List[str]], Any]


class ExportError(RuntimeError):
    """The export was refused before anything was written to ``out``."""


class GateRefused(ExportError):
    """A gate refused the staged bundle; the staging directory was removed and ``out`` is untouched."""


@dataclass(frozen=True)
class ExportReport:
    out: str
    day: str
    profile_digest: str
    concepts: List[str] = field(default_factory=list)
    withheld: Dict[str, int] = field(default_factory=dict)

    @property
    def exported(self) -> int:
        return len(self.concepts)

    @property
    def withheld_total(self) -> int:
        return sum(self.withheld.values())

    def summary(self) -> Dict[str, Any]:
        return {
            "out": self.out,
            "at": self.day,
            "profile_sha256": self.profile_digest,
            "exported": self.exported,
            "withheld": dict(sorted(self.withheld.items())),
            "withheld_total": self.withheld_total,
        }


# --------------------------------------------------------------------------------------- field map

def iso_utc(ts: float) -> str:
    """An epoch timestamp as ISO 8601 UTC with ``Z``: whole seconds, or microseconds when it has a fraction."""
    value = float(ts)
    if not math.isfinite(value):
        raise ValueError("non-finite timestamp")
    moment = datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None)
    return moment.isoformat(timespec="microseconds" if moment.microsecond else "seconds") + "Z"


def type_name(category: str) -> str:
    """OKF ``type`` from a category: ``project_state`` -> ``Project State``."""
    words = [w for w in re.split(r"[_\s]+", category) if w]
    return " ".join(w[:1].upper() + w[1:] for w in words) or category


_SENTENCE_END = re.compile(r"[.!?](?=\s|\Z)")
_MAX_DESCRIPTION = 200


def first_sentence(content: str) -> Optional[str]:
    """The first sentence of the first paragraph, on one line (a heading line stands alone), or None."""
    para: List[str] = []
    for line in content.splitlines():
        text = line.strip()
        if not text:
            if para:
                break
            continue
        if not para and text.startswith("#"):
            para.append(text.lstrip("#").strip())
            break
        para.append(text)
    text = " ".join(" ".join(para).split())
    text = "".join(ch for ch in text if ch == " " or ch.isprintable()).strip()
    match = _SENTENCE_END.search(text)
    if match:
        text = text[:match.end()]
    if len(text) > _MAX_DESCRIPTION:
        cut = text[:_MAX_DESCRIPTION - 1]
        if " " in cut:
            cut = cut[:cut.rindex(" ")]
        text = cut.rstrip() + "\u2026"
    return text or None


# ---- Naming (telarch P14.3, roadmap 17.2 Pass 2) ----
# A turn's query names a row when the row's key appears in it (case-folded, not inside a longer word) or when
# the row's title's token sequence appears among the query's tokens. A vault row's title is its key: that is
# the title okf-export writes. One tokenizer serves titles and queries, runs of letters and digits, so "_",
# "-", "/" and every other non-word character separate tokens.
_NAME_TOKEN = re.compile(r"[^\W_]+")


def name_tokens(text: str) -> List[str]:
    """The case-folded tokens of a key, title or query: its runs of letters and digits, in order."""
    return _NAME_TOKEN.findall(str(text).casefold())


def _key_at(folded_query: str, key: str) -> Optional[int]:
    folded = str(key).casefold()
    if not folded:
        return None
    head = r"(?<!\w)" if re.match(r"\w", folded[0]) else ""
    tail = r"(?!\w)" if re.match(r"\w", folded[-1]) else ""
    match = re.search(head + re.escape(folded) + tail, folded_query)
    return match.start() if match else None


def _tokens_at(folded_query: str, title: str) -> Optional[int]:
    wanted = name_tokens(title)
    if not wanted:
        return None
    tokens = [(m.group(0), m.start()) for m in _NAME_TOKEN.finditer(folded_query)]
    width = len(wanted)
    for i in range(len(tokens) - width + 1):
        if all(tokens[i + j][0] == wanted[j] for j in range(width)):
            return tokens[i][1]
    return None


def names_at(query: str, key: str, title: Optional[str] = None) -> Optional[int]:
    """Where ``query`` first names a row, or None: the earliest offset, in the case-folded query, of the row's
    key (case-folded, not inside a longer word) or of the start of its title's token sequence among the query's
    tokens. ``title`` defaults to the key, the title okf-export writes for a row."""
    folded = str(query).casefold()
    found = [at for at in (_key_at(folded, key), _tokens_at(folded, key if title is None else title)) if at is not None]
    return min(found) if found else None


def named_rows(query: str, rows: Iterable[Union[str, Tuple[str, Optional[str]]]]) -> List[int]:
    """The indices of the rows ``query`` names, in request order: by where the query first names each row, ties
    in ``rows`` order, each row once. A row is its key or a ``(key, title)`` pair."""
    found: List[Tuple[int, int]] = []
    for index, row in enumerate(rows):
        key, title = (row, None) if isinstance(row, str) else (row[0], row[1])
        at = names_at(query, key, title)
        if at is not None:
            found.append((at, index))
    return [index for _, index in sorted(found)]


_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}\Z")
_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"} | {"com%d" % i for i in range(10)} | {"lpt%d" % i for i in range(10)}
)


def safe_segment(name: Any) -> bool:
    """True when ``name`` is one portable path segment: ASCII letters, digits, ``_ . -``, not starting with
    ``.`` or ``-``, not ending with ``.``, at most 200 characters, and not a Windows device name."""
    if not isinstance(name, str) or not _SEGMENT.match(name) or name.endswith("."):
        return False
    return name.split(".", 1)[0].lower() not in _DEVICE_NAMES


def _dir_segment(name: Any) -> bool:
    return safe_segment(name) and not str(name).lower().endswith(".md")


def _state(row: Any) -> str:
    value = row.epistemic_state
    return str(getattr(value, "value", value) or "")


def _status(state: str, row: Any) -> str:
    if state == "revoked" or row.superseded_by:
        return "deprecated"
    return "stable" if state == "verified" else "draft"


def _sensitivity_reason(metadata: Any) -> Optional[str]:
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        return "sensitivity"
    flag = metadata.get("confidential")
    if flag is not None and flag is not False:
        return "confidential"
    if "sensitivity" not in metadata:
        return None
    value = metadata["sensitivity"]
    norm = value.strip().lower() if isinstance(value, str) else None
    if norm == "normal":
        return None
    return "confidential" if norm == "confidential" else "sensitivity"


_ACTOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}\Z")


def _person_admit_stamps(vault: Any, row: Any) -> List[Dict[str, str]]:
    """``verified`` entries from person-admit journal records for a row that is verified now.

    A record counts when the journal holds a ``state_transition`` to ``verified`` with cause
    ``review`` (the vault refuses a verified review from anyone but a person) and the row's
    vault-written ``human_reviews`` holds that reviewer's ``verified`` verdict with origin ``user``.
    A later transition away from verified clears earlier stamps. Anything less writes no stamp.
    """
    if _state(row) != "verified":
        return []
    meta = row.metadata if isinstance(row.metadata, dict) else {}
    persons: Set[str] = set()
    for review in meta.get("human_reviews") or []:
        if (
            isinstance(review, dict)
            and review.get("verdict") == "verified"
            and review.get("reviewer_origin") == "user"
            and isinstance(review.get("reviewer_id"), str)
        ):
            persons.add(review["reviewer_id"])
    if not persons:
        return []
    events = vault.list_audit_events(scope=row.scope, category=row.category, key=row.key, limit=_ALL_EVENTS)
    stamps: List[Dict[str, str]] = []
    for event in sorted(events, key=lambda e: e.sequence):
        if event.action != "state_transition":
            continue
        detail = event.metadata if isinstance(event.metadata, dict) else {}
        if detail.get("to") != "verified":
            stamps = []
            continue
        reviewer = detail.get("reviewer")
        if (
            detail.get("cause") == "review"
            and isinstance(reviewer, str)
            and reviewer in persons
            and _ACTOR_ID.match(reviewer)
        ):
            stamps.append({"by": "human:" + reviewer, "at": iso_utc(event.timestamp)})
    return stamps


@dataclass
class _Concept:
    rel: str
    row: Any
    description: Optional[str]
    stamps: List[Dict[str, str]]

    @property
    def sort_key(self) -> Tuple[str, str, str]:
        return (self.row.scope, self.row.category, self.row.key)


def is_vault_owned_key(key: Any) -> bool:
    """True for a frontmatter key that names vault state rather than content, compared case-insensitively:
    the vault's reserved metadata (and the ``lineage_`` prefix), identity, state and sensitivity keys, the
    importer's own keys, any ``kibisis_`` or ``telarch_`` key, and a field-map key spelled in another case.
    The field-map keys themselves are not owned; the field map handles them."""
    if not isinstance(key, str):
        return True
    if key in FIELD_MAP_KEYS:
        return False
    low = key.lower()
    return low in FIELD_MAP_KEYS or low in _OWNED_LOWER or low.startswith(_OWNED_PREFIXES)


def dump_extra(items: Iterable[Tuple[str, Any]]) -> str:
    """Unknown frontmatter keys as the JSON object okf-import stores in metadata ``okf_extra``, in order."""
    obj: Dict[str, Any] = {}
    for key, value in items:
        if not isinstance(key, str) or key in obj:
            raise ValueError(f"okf_extra: a bad or repeated key {key!r}")
        obj[key] = value
    return json.dumps(obj, allow_nan=False, separators=(",", ":"))


def _no_repeats(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"okf_extra: repeated key {key!r}")
        out[key] = value
    return out


def _non_finite(name: str) -> Any:
    raise ValueError(f"okf_extra: non-finite number {name}")


def load_extra(raw: Any) -> List[Tuple[str, Any]]:
    """Metadata ``okf_extra`` as (key, value) pairs in stored order; ValueError unless it is a JSON object
    with no repeated keys and no non-finite numbers."""
    if not isinstance(raw, str):
        raise ValueError("okf_extra: not a string")
    try:
        obj = json.loads(raw, object_pairs_hook=_no_repeats, parse_constant=_non_finite)
    except RecursionError as exc:
        raise ValueError("okf_extra: nested too deeply") from exc
    if not isinstance(obj, dict):
        raise ValueError("okf_extra: not a JSON object")
    return list(obj.items())


def _render(concept: _Concept, producer: str, link: Optional[str]) -> str:
    row = concept.row
    state = _state(row)
    doc: Dict[str, Any] = {"type": type_name(row.category), "title": row.key}
    if concept.description:
        doc["description"] = concept.description
    doc["status"] = _status(state, row)
    if row.valid_until is not None:
        doc["stale_after"] = iso_utc(row.valid_until)
    doc["generated"] = {"by": producer, "at": iso_utc(row.updated_at)}
    stamped = state == "verified" and bool(concept.stamps)
    if stamped:
        doc["verified"] = [dict(s) for s in concept.stamps]
    if row.source_ref:
        doc["sources"] = [{"id": "source_ref", "resource": str(row.source_ref)}]
    if not stamped:
        doc["kibisis_state"] = state
    if row.origin:
        doc["kibisis_origin"] = str(row.origin)
    if link:
        doc["kibisis_superseded_by"] = link
    meta = row.metadata if isinstance(row.metadata, dict) else {}
    if meta.get("okf_extra") is not None:
        for key, value in load_extra(meta["okf_extra"]):
            if key not in doc and not is_vault_owned_key(key) and key not in FIELD_MAP_KEYS:
                doc[key] = value
    text = render_document(doc, row.content)
    text.encode("utf-8")  # a lone surrogate cannot be written; the caller withholds the row
    return text


def _render_all(kept: Dict[str, _Concept], producer: str) -> Dict[str, str]:
    """Render every kept row; a superseded row links its replacement only when that row is kept too."""
    by_ref: Dict[Tuple[str, str], str] = {}
    for rel, c in kept.items():
        by_ref[(c.row.scope, "%s:%s" % (c.row.category, c.row.key))] = rel
    docs: Dict[str, str] = {}
    for rel, c in kept.items():
        link = None
        if c.row.superseded_by:
            target = by_ref.get((c.row.scope, str(c.row.superseded_by)))
            if target is not None and target != rel:
                link = "/" + target
        docs[rel] = _render(c, producer, link)
    return docs


# ------------------------------------------------------------------------------- index and log

def _index_text(kept: Dict[str, _Concept], digest: Optional[str]) -> str:
    lines: List[str] = []
    group: Optional[Tuple[str, str]] = None
    for c in sorted(kept.values(), key=lambda x: x.sort_key):
        here = (c.row.scope, c.row.category)
        if here != group:
            if lines:
                lines.append("")
            lines.extend(["# %s/%s" % here, ""])
            group = here
        entry = "* [%s](%s)" % (c.row.key, c.rel)
        if c.description:
            entry += " - " + c.description
        lines.append(entry)
    if not lines:
        lines = ["# Concepts", "", "No rows were exported."]
    meta: Dict[str, Any] = {"okf_version": OKF_VERSION}
    if digest is not None:
        meta[PROFILE_DIGEST_KEY] = digest
    return render_document(meta, "\n".join(lines) + "\n")


_LOG_HEADING = re.compile(r"## (\d{4}-\d{2}-\d{2})[ \t]*\Z")


def _log_bullet(exported: int, withheld: Dict[str, int]) -> str:
    """Counts only: rows exported, and withheld by reason (the profile digest lives in index.md)."""
    parts = ", ".join("%s %d" % (k, withheld[k]) for k in sorted(withheld))
    detail = " (%s)" % parts if parts else ""
    return "* **Export**: exported %d; withheld %d%s." % (exported, sum(withheld.values()), detail)


def _log_text(prior: Optional[str], day: str, bullet: str) -> str:
    """Keep earlier date sections, add this run's bullet first under its date, newest date first."""
    sections: List[List[Any]] = []
    current: Optional[List[Any]] = None
    for line in (prior or "").splitlines():
        match = _LOG_HEADING.match(line)
        if match:
            current = [match.group(1), []]
            sections.append(current)
        elif current is not None:
            current[1].append(line)
    for section in sections:
        if section[0] == day:
            body = list(section[1])
            while body and not body[0].strip():
                body.pop(0)
            section[1] = ["", bullet] + body
            break
    else:
        sections.append([day, ["", bullet]])
    sections.sort(key=lambda s: s[0], reverse=True)
    out = [LOG_TITLE, ""]
    for heading, body in sections:
        body = list(body)
        while body and not body[-1].strip():
            body.pop()
        out.append("## " + heading)
        out.extend(body)
        out.append("")
    return "\n".join(out)


def _log_day(at: Optional[str]) -> str:
    if at is None:
        return datetime.now(timezone.utc).date().isoformat()
    text = str(at).strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            return date.fromisoformat(text).isoformat()
        if not re.match(r"\d{4}-\d{2}-\d{2}[T ]", text):
            raise ValueError(text)
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        moment = datetime.fromisoformat(iso)
    except ValueError:
        raise ExportError("--at must be an ISO 8601 date or datetime, got %r" % text[:40]) from None
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.date().isoformat()


# ---------------------------------------------------------------------------------- out handling

def _category_dir_ok(path: str) -> bool:
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                return False
            with os.scandir(entry.path) as inner:
                for item in inner:
                    if item.is_symlink() or not item.is_file(follow_symlinks=False) or not item.name.endswith(".md"):
                        return False
    return True


def _is_previous_bundle(out: Path, require_digest: bool = True) -> bool:
    """Empty, or exactly the shape this exporter writes with an index.md naming a profile digest.

    With ``require_digest=False`` an index without the digest key (a digest-less export) also counts.
    """
    with os.scandir(out) as it:
        top = list(it)
    if not top:
        return True
    if "index.md" not in {e.name for e in top}:
        return False
    for entry in top:
        if entry.is_symlink():
            return False
        if entry.is_dir(follow_symlinks=False):
            if not _category_dir_ok(entry.path):
                return False
        elif not (entry.is_file(follow_symlinks=False) and entry.name in ("index.md", "log.md")):
            return False
    try:
        fm_text, _ = split_document((out / "index.md").read_text(encoding="utf-8"))
        meta = parse_frontmatter(fm_text) if fm_text is not None else {}
    except (OSError, UnicodeDecodeError, FrontmatterError):
        return False
    if "okf_version" not in meta:
        return False
    if PROFILE_DIGEST_KEY not in meta:
        return not require_digest
    return isinstance(meta[PROFILE_DIGEST_KEY], str)


def _prepare_out(out: Path, require_digest: bool = True) -> Tuple[bool, Optional[str]]:
    """(out exists, previous log text); raise ExportError when ``out`` may not be replaced."""
    if out.is_symlink():
        raise ExportError("--out %s is a symbolic link; refusing" % out)
    if not out.exists():
        if not out.parent.is_dir():
            raise ExportError("the parent of --out (%s) is not a directory" % out.parent)
        return False, None
    if not out.is_dir():
        raise ExportError("--out %s exists and is not a directory" % out)
    try:
        previous = _is_previous_bundle(out, require_digest)
    except OSError as exc:
        raise ExportError("cannot inspect --out %s: %s" % (out, exc)) from None
    if not previous:
        raise ExportError("--out %s exists and is not a bundle okf-export wrote; refusing to replace it" % out)
    log = out / "log.md"
    if log.is_file() and not log.is_symlink():
        try:
            return True, log.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return True, None
    return True, None


#: Linux renameat2 RENAME_EXCHANGE and macOS renamex_np RENAME_SWAP share the value 2.
_EXCHANGE_FLAG = 2
_AT_FDCWD = -100


@functools.lru_cache(maxsize=1)
def _libc() -> Optional[Any]:
    try:
        name = ctypes.util.find_library("c")
        return ctypes.CDLL(name, use_errno=True) if name else ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None


def _exchange_dirs(a: str, b: str) -> bool:
    """Swap two existing paths in one atomic call: renameat2(RENAME_EXCHANGE) on Linux, renamex_np(RENAME_SWAP)
    on macOS. False when the platform, libc or filesystem has no such call; any other failure raises OSError."""
    libc = _libc()
    if libc is None:
        return False
    src, dst = os.fsencode(a), os.fsencode(b)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        fn = libc.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        rc = fn(_AT_FDCWD, src, _AT_FDCWD, dst, _EXCHANGE_FLAG)
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        rc = fn(src, dst, _EXCHANGE_FLAG)
    else:
        return False
    if rc == 0:
        return True
    err = ctypes.get_errno()
    if err in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
        return False
    raise OSError(err, os.strerror(err), a)


def _write_stage(parent: Path, files: Dict[str, str]) -> Path:
    stage = Path(tempfile.mkdtemp(prefix=".okf-stage-", dir=str(parent)))
    try:
        os.chmod(stage, 0o700)
        root = os.path.realpath(stage)
        made: Set[str] = set()
        for rel in sorted(files):
            parts = rel.split("/")
            target = os.path.normpath(os.path.join(root, *parts))
            if os.path.commonpath([root, target]) != root or target == root:
                raise ExportError("internal: %r escapes the staging directory" % rel)
            current = root
            for part in parts[:-1]:
                current = os.path.join(current, part)
                if current not in made:
                    os.mkdir(current, 0o700)
                    made.add(current)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(files[rel].encode("utf-8"))
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return stage


def _swap_into_place(stage: Path, out: Path, existed: bool) -> None:
    """Move the staged bundle to ``out``: one rename when ``out`` is new, one exchange call when it exists.

    Without an exchange call (other platforms or filesystems) it falls back to two renames, which
    leaves a moment with no ``out``; the previous bundle is restored if the second rename fails."""
    if not existed:
        os.rename(stage, out)
        return
    if _exchange_dirs(str(stage), str(out)):
        shutil.rmtree(stage, ignore_errors=True)  # the staging path now holds the previous bundle
        return
    old = out.parent / (".okf-old-" + secrets.token_hex(8))
    os.rename(out, old)
    try:
        os.rename(stage, out)
    except BaseException:
        os.rename(old, out)
        raise
    shutil.rmtree(old, ignore_errors=True)


def _staged_files(stage: Path) -> List[str]:
    found: List[str] = []
    for dirpath, _dirs, names in os.walk(stage):
        found.extend(os.path.join(dirpath, n) for n in names)
    return sorted(found)


def _hit_rels(stage: Path, verdict: Iterable[Any]) -> Set[str]:
    root = os.path.realpath(stage)
    rels: Set[str] = set()
    for item in verdict:
        path = os.fspath(item)
        if os.path.isabs(path):
            path = os.path.relpath(os.path.realpath(path), root)
        rels.add(Path(path).as_posix())
    return rels


# --------------------------------------------------------------------------------------- export

def _plan(vault: Any, profile: ExportProfile, withheld: Counter) -> Dict[str, _Concept]:
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    candidates: Dict[str, _Concept] = {}
    for row in sorted(rows, key=lambda r: (r.scope, r.category, r.key)):
        reason = None
        if row.archived:
            reason = "archived"
        elif row.scope not in profile.scopes:
            reason = "scope"
        elif row.category in profile.exclude_categories:
            reason = "excluded_category"
        elif row.category not in profile.categories:
            reason = "category"
        elif profile.excludes_key(row.key):
            reason = "excluded_key"
        else:
            reason = _sensitivity_reason(row.metadata)
        if reason is None:
            if not (_dir_segment(row.scope) and _dir_segment(row.category)):
                reason = "unsafe_name"
            elif not safe_segment(row.key):
                reason = "unsafe_key"
            elif row.key.lower() in RESERVED_STEMS:
                reason = "reserved_key"
        if reason is not None:
            withheld[reason] += 1
            continue
        rel = "%s/%s/%s.md" % (row.scope, row.category, row.key)
        candidates[rel] = _Concept(rel=rel, row=row, description=None, stamps=[])
    folded = Counter(rel.lower() for rel in candidates)
    for rel in [r for r in candidates if folded[r.lower()] > 1]:
        del candidates[rel]
        withheld["key_collision"] += 1
    for c in candidates.values():
        c.description = first_sentence(c.row.content)
        c.stamps = _person_admit_stamps(vault, c.row)
    return candidates


def export_bundle(
    vault: Any,
    profile: ExportProfile,
    out: Union[str, "os.PathLike[str]"],
    *,
    at: Optional[str] = None,
    ungated: bool = False,
    row_gate: Optional[RowGate] = None,
    bundle_gate: Optional[BundleGate] = None,
    index_profile_digest: bool = True,
) -> ExportReport:
    """Write the OKF bundle for ``vault`` under ``profile`` to ``out``; see the module docstring."""
    if not (ungated or row_gate is not None or bundle_gate is not None):
        raise ExportError("refusing to write without a content gate: pass row_gate or bundle_gate "
                          "(or ungated=True, for synthetic fixtures only)")
    if not isinstance(profile, ExportProfile):
        raise ExportError("profile must be an ExportProfile from load_profile or parse_profile")
    day = _log_day(at)
    out_path = Path(os.path.abspath(os.fspath(out)))
    existed, prior_log = _prepare_out(out_path, require_digest=index_profile_digest)

    withheld: Counter = Counter()
    kept = _plan(vault, profile, withheld)
    producer = profile.producer
    gate_cache: Dict[Tuple[str, str], bool] = {}

    while True:
        while True:
            docs: Dict[str, str] = {}
            failed: List[str] = []
            try:
                docs = _render_all(kept, producer)
            except (ValueError, OverflowError, OSError, UnicodeError, FrontmatterError):
                for rel in sorted(kept):
                    try:
                        _render(kept[rel], producer, None)
                    except (ValueError, OverflowError, OSError, UnicodeError, FrontmatterError):
                        failed.append(rel)
                if not failed:
                    raise
            if failed:
                for rel in failed:
                    del kept[rel]
                    withheld["render_error"] += 1
                continue
            if row_gate is None:
                break
            flagged = []
            for rel in sorted(docs):
                cache_key = (rel, docs[rel])
                if cache_key not in gate_cache:
                    gate_cache[cache_key] = bool(row_gate(rel, docs[rel]))
                if gate_cache[cache_key]:
                    flagged.append(rel)
            if not flagged:
                break
            for rel in flagged:
                del kept[rel]
                withheld["content_gate"] += 1

        counts = {k: v for k, v in withheld.items() if v}
        files = dict(docs)
        files["index.md"] = _index_text(kept, profile.digest if index_profile_digest else None)
        files["log.md"] = _log_text(prior_log, day, _log_bullet(len(kept), counts))
        stage = _write_stage(out_path.parent, files)
        try:
            if bundle_gate is not None:
                verdict = bundle_gate(str(stage), _staged_files(stage))
                if verdict is not True:
                    if verdict is False or verdict is None:
                        raise GateRefused("the bundle gate refused the staged bundle")
                    hits = _hit_rels(stage, verdict)
                    concept_hits = sorted(hits & set(kept))
                    if concept_hits:
                        for rel in concept_hits:
                            del kept[rel]
                            withheld["bundle_gate"] += 1
                        shutil.rmtree(stage, ignore_errors=True)
                        continue
                    if hits:
                        raise GateRefused("the bundle gate flagged files that are not concepts: %s"
                                          % ", ".join(sorted(hits)[:5]))
            _swap_into_place(stage, out_path, existed)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return ExportReport(
            out=str(out_path),
            day=day,
            profile_digest=profile.digest,
            concepts=sorted(kept),
            withheld=counts,
        )


def command_gate(cmd: str, timeout: float = 900.0) -> BundleGate:
    """A bundle gate that runs ``cmd`` (split like a shell, no shell) with every staged file path
    appended. Exit status 0 passes; anything else, a timeout or a launch failure refuses the bundle.
    The command's output goes to stderr (outbound_gate.py prints file:line:label, never the match)."""
    argv = shlex.split(cmd)
    if not argv:
        raise ExportError("--gate-cmd is empty")

    def gate(staging: str, paths: List[str]) -> bool:
        try:
            proc = subprocess.run(argv + list(paths), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("gate: %s\n" % exc)
            return False
        if proc.stdout:
            sys.stderr.write(proc.stdout.decode("utf-8", "replace"))
        return proc.returncode == 0

    return gate
