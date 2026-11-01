"""okf-check: a deterministic OKF v0.2 conformance checker (P13.1). Stdlib only, no network.

It checks the producer MUSTs the P13.1 prereg names and accepts what consumers must not reject:

errors (each with a code):
  ``frontmatter``       a concept (any ``.md`` file but ``index.md`` / ``log.md``) has no parseable
                        frontmatter block, or it is outside the fixed subset (11.1)
  ``type``              no non-empty ``type`` (4.1)
  ``reserved_name``     a concept named ``index.md`` or ``log.md``, that is, one with a ``type`` (3.1)
  ``index_frontmatter`` frontmatter in a non-root ``index.md`` (8)
  ``root_index_key``    a root ``index.md`` key other than ``okf_version`` and the noted extension (8)
  ``log_heading``       a ``log.md`` H2 heading that is not a real ``YYYY-MM-DD`` date (9)
  ``sources_resource``  a ``sources`` entry without ``resource`` (5.1)
  ``generated_by``      a ``generated`` block without ``by`` (5.2)
  ``human_actor``       a ``human:`` actor that is not exactly ``human:<id>`` (7)
  ``runtime``           an ``Attested Computation`` without ``runtime`` (10)
  ``bundle`` / ``unreadable``  the bundle or a file in it cannot be read

notes: ``noted_extension`` (``telarch_export_profile_sha256`` in the root index, which INTEGRATION.md
section 5 places there and OKF section 8 does not name) and ``symlink_skipped`` (links are not followed).

Accepted (section 11): unknown types and keys, broken links, a missing ``index.md``, a bare ``verified``
mapping (5.2), missing optional families, and files that are not markdown.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

from .frontmatter import FrontmatterError, parse_frontmatter, split_document

__all__ = ["CheckResult", "Finding", "check_bundle"]

RESERVED_NAMES = frozenset({"index.md", "log.md"})
ROOT_INDEX_KEYS = frozenset({"okf_version"})
NOTED_EXTENSIONS = frozenset({"telarch_export_profile_sha256"})
_ABSENT = object()
_HUMANISH = re.compile(r"\s*human\s*:", re.IGNORECASE)
_HUMAN = re.compile(r"human:\S+\Z")
_H2 = re.compile(r" {0,3}##(?:[ \t]+(.*?))?[ \t]*\Z")
_FENCE = re.compile(r" {0,3}(```|~~~)")


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"path": self.path, "code": self.code, "message": self.message}


@dataclass
class CheckResult:
    root: str
    errors: List[Finding] = field(default_factory=list)
    notes: List[Finding] = field(default_factory=list)
    files_checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> Dict[str, Any]:
        return {
            "bundle": self.root,
            "ok": self.ok,
            "files_checked": self.files_checked,
            "errors": [f.as_dict() for f in self.errors],
            "notes": [f.as_dict() for f in self.notes],
        }


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


class _Checker:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.result = CheckResult(root=str(root))

    def error(self, path: str, code: str, message: str) -> None:
        self.result.errors.append(Finding(path, code, message))

    def note(self, path: str, code: str, message: str) -> None:
        self.result.notes.append(Finding(path, code, message))

    def walk(self) -> List[Tuple[str, str]]:
        files: List[Tuple[str, str]] = []
        stack = [("", str(self.root))]
        while stack:
            prefix, directory = stack.pop()
            try:
                with os.scandir(directory) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as exc:
                self.error(prefix.rstrip("/") or ".", "unreadable", "cannot list the directory: %s" % exc.strerror)
                continue
            for entry in entries:
                rel = prefix + entry.name
                if entry.is_symlink():
                    self.note(rel, "symlink_skipped", "symbolic links are not followed")
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name != ".git":
                        stack.append((rel + "/", entry.path))
                elif entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(".md"):
                    files.append((rel, entry.path))
        return sorted(files)

    def check_file(self, rel: str, full: str) -> None:
        name = rel.rsplit("/", 1)[-1]
        try:
            with open(full, "rb") as fh:
                text = fh.read().decode("utf-8")
        except UnicodeDecodeError:
            self.error(rel, "frontmatter", "not UTF-8 text, so no parseable frontmatter (11.1)")
            return
        except OSError as exc:
            self.error(rel, "unreadable", "cannot read the file: %s" % exc.strerror)
            return
        self.result.files_checked += 1
        try:
            fm_text, body = split_document(text)
            meta = parse_frontmatter(fm_text) if fm_text is not None else None
        except FrontmatterError as exc:
            self.error(rel, "frontmatter", str(exc))
            return
        if name in RESERVED_NAMES:
            self.check_reserved(rel, name, meta, body)
        elif meta is None:
            self.error(rel, "frontmatter", "a concept document needs a YAML frontmatter block (11.1)")
        else:
            self.check_concept(rel, meta)

    def check_reserved(self, rel: str, name: str, meta: Any, body: str) -> None:
        if meta is not None and "type" in meta:
            self.error(rel, "reserved_name", "%s is a reserved filename (3.1); a concept cannot use it" % name)
            return
        if name == "log.md":
            self.check_log(rel, body)
            return
        if meta is None:
            return
        if "/" in rel:
            self.error(rel, "index_frontmatter", "only the bundle-root index.md may carry frontmatter (8)")
            return
        for key in sorted(meta):
            if key in ROOT_INDEX_KEYS:
                continue
            if key in NOTED_EXTENSIONS:
                self.note(rel, "noted_extension", "%s is an extension; OKF section 8 names only okf_version here" % key)
            else:
                self.error(rel, "root_index_key", "the root index.md may carry only okf_version (8), not %r" % key[:60])

    def check_log(self, rel: str, body: str) -> None:
        fenced = False
        for lineno, line in enumerate(body.splitlines(), 1):
            if _FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            match = _H2.match(line)
            if not match:
                continue
            heading = re.sub(r"[ \t]+#+\Z", "", (match.group(1) or "").strip())
            valid = False
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", heading):
                try:
                    date.fromisoformat(heading)
                    valid = True
                except ValueError:
                    valid = False
            if not valid:
                self.error(rel, "log_heading", "body line %d: log date headings use YYYY-MM-DD (9)" % lineno)

    def check_actor(self, rel: str, where: str, value: Any) -> None:
        if isinstance(value, str) and _HUMANISH.match(value) and not _HUMAN.match(value):
            self.error(rel, "human_actor", "%s must be human:<id>, lower-case prefix, no spaces (7)" % where)

    def check_concept(self, rel: str, meta: Dict[str, Any]) -> None:
        kind = meta.get("type")
        if not _nonempty(kind):
            self.error(rel, "type", "the frontmatter needs a non-empty type (4.1)")
        sources = meta.get("sources", _ABSENT)
        if sources is not _ABSENT:
            entries = sources if isinstance(sources, list) else [sources]
            for i, entry in enumerate(entries):
                if not isinstance(entry, dict) or not _nonempty(entry.get("resource")):
                    self.error(rel, "sources_resource", "sources entry %d has no resource (5.1)" % i)
        generated = meta.get("generated", _ABSENT)
        if generated is not _ABSENT:
            if not isinstance(generated, dict) or not _nonempty(generated.get("by")):
                self.error(rel, "generated_by", "generated needs by (5.2)")
            else:
                self.check_actor(rel, "generated.by", generated["by"])
        verified = meta.get("verified", _ABSENT)
        if verified is not _ABSENT:
            entries = [verified] if isinstance(verified, dict) else (verified if isinstance(verified, list) else [])
            for i, entry in enumerate(entries):
                if isinstance(entry, dict):
                    self.check_actor(rel, "verified[%d].by" % i, entry.get("by"))
        if isinstance(kind, str) and kind.strip() == "Attested Computation" and not _nonempty(meta.get("runtime")):
            self.error(rel, "runtime", "an Attested Computation needs runtime (10.2)")


def check_bundle(root: Union[str, "os.PathLike[str]"]) -> CheckResult:
    """Check the bundle at ``root``; findings are sorted, so equal trees give equal results."""
    checker = _Checker(Path(os.fspath(root)))
    path = checker.root
    if path.is_symlink() or not path.is_dir():
        checker.error(".", "bundle", "the bundle is not a directory (symbolic links are not followed)")
        return checker.result
    for rel, full in checker.walk():
        checker.check_file(rel, full)
    checker.result.errors.sort()
    checker.result.notes.sort()
    return checker.result
