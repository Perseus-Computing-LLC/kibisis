"""Synthetic fixture vaults for the OKF tests (P13). No live data: every row is made up here."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, Set, Tuple

from kibisis.vault import SQLiteMemoryVault

PASSPHRASE = "okf-fixture-passphrase-not-a-secret"

#: Keys the exporter must withhold: path separators, traversal, whitespace, a hidden file, a leading dash,
#: a Windows device name and a backslash. Classified as unsafe_key.
UNSAFE_KEYS = ("../escape", "a/b", "with space", ".hidden", "-flag", "CON", "..\\up")
#: OKF reserved filenames (section 3.1), in any case. Classified as reserved_key.
RESERVED_KEYS = ("index", "LOG")

#: (scope, category, key) of every row the default profile exports from the probe vault.
EXPORTABLE: Set[Tuple[str, str, str]] = {
    ("default", "decision", "alpha"),
    ("default", "convention", "beta"),
    ("default", "project_state", "gamma"),
    ("default", "architecture", "delta"),
    ("default", "decision", "epsilon"),
    ("default", "decision", "v1"),
    ("default", "decision", "v2"),
}

#: Withheld counts by reason for the probe vault under the default profile.
PROBE_WITHHELD: Dict[str, int] = {
    "archived": 1,
    "scope": 1,
    "category": 3,
    "confidential": 2,
    "sensitivity": 1,
    "unsafe_key": len(UNSAFE_KEYS),
    "reserved_key": len(RESERVED_KEYS),
}

DEFAULT_PROFILE_JSON = (
    '{"schema": "kibisis.okf_export_profile/1", "audience": "owner",'
    ' "allow": {"scopes": ["default"], "categories": ["architecture", "convention", "decision", "project_state"]},'
    ' "named": [], "exclude": {"keys": [], "categories": []}}'
)


def open_vault(path: Path, **kwargs) -> SQLiteMemoryVault:
    kwargs.setdefault("auto_gate", False)
    kwargs.setdefault("verification_quorum", 1)
    return SQLiteMemoryVault(str(path), passphrase=PASSPHRASE, **kwargs)


def build_probe_vault(path: Path) -> SQLiteMemoryVault:
    """Seven exportable rows and one row for every reason a row must not leave the vault."""
    v = open_vault(path)
    v.put("decision", "alpha", "Alpha is decided. More detail follows here.", origin="model", source_ref="session:s1/turn:3")
    v.put("convention", "beta", "Beta convention.\n\n---\nNot frontmatter: a rule line in the body.\n",
          metadata={"sensitivity": "normal"}, origin="model")
    v.put("project_state", "gamma", "Gamma state, verified by its author.", epistemic_state="verified", origin="user",
          valid_until=1893456000.25)
    v.put("architecture", "delta", "Delta architecture.", origin="model")
    v.admit("architecture", "delta", reviewer="owner", reviewer_origin="user")
    v.put("decision", "epsilon", "Epsilon is contested.", origin="model")
    v.review_entity("decision", "epsilon", verdict="disputed", reviewer_id="owner", reviewer_origin="user")
    v.put("decision", "v1", "Old decision.", origin="user")
    v.supersede("decision", "v1", "v2", "New decision.", origin="user")

    v.put("decision", "secret_plan", "Confidential body.", metadata={"sensitivity": "confidential"}, origin="model")
    v.put("decision", "flagged", "Flagged confidential.", metadata={"confidential": True}, origin="model")
    v.put("decision", "odd", "An unrecognised sensitivity value.", metadata={"sensitivity": "restricted"}, origin="model")
    v.put("decision", "w1", "A row in another scope.", scope="work", origin="model")
    v.put("user_profile", "u1", "A profile row.", origin="model")
    v.put("diagnosis", "d1", "A diagnosis row.", origin="model")
    v.put("architecture_blueprint", "b1", "A blueprint row.", origin="model")
    v.put("decision", "old", "An archived row.", origin="model")
    v.archive("decision", "old")
    for key in UNSAFE_KEYS + RESERVED_KEYS:
        v.put("decision", key, "A row whose key is not a safe file name.", origin="model")
    return v


def write_profile(tmp_path: Path, text: str = DEFAULT_PROFILE_JSON, name: str = "profile.json") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def tree_bytes(root: Path) -> Dict[str, bytes]:
    """Every regular file under ``root``, keyed by its POSIX path relative to ``root``."""
    out: Dict[str, bytes] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = Path(dirpath) / name
            out[full.relative_to(root).as_posix()] = full.read_bytes()
    return out


def all_paths(root: Path) -> Set[str]:
    out: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            out.add((Path(dirpath) / name).relative_to(root).as_posix())
    return out


def concept_paths(keys: Iterable[Tuple[str, str, str]]) -> Set[str]:
    return {f"{s}/{c}/{k}.md" for s, c, k in keys}
