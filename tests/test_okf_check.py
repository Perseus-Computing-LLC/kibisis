"""P13.1: kibisis/okf/check.py, a deterministic OKF v0.2 conformance checker (stdlib, no network).

It checks the spec's producer MUSTs and accepts what consumers must not reject (section 11).
"""
from pathlib import Path

import pytest

from kibisis.okf.check import check_bundle

ROOT_INDEX = '---\nokf_version: "0.2"\n---\n# Concepts\n\n* [alpha](default/decision/alpha.md) - Alpha.\n'
LOG = "# Export Log\n\n## 2026-11-01\n\n* **Export**: exported 1.\n"
CONCEPT = '---\ntype: "Decision"\ngenerated: {by: "kibisis/0.1.0", at: "2026-10-31T00:00:00Z"}\n---\nAlpha.\n'


def _bundle(tmp_path: Path, files: dict, base: bool = True) -> Path:
    root = tmp_path / "bundle"
    merged = {"index.md": ROOT_INDEX, "log.md": LOG, "default/decision/alpha.md": CONCEPT} if base else {}
    merged.update(files)
    for rel, text in merged.items():
        if text is None:
            continue
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    root.mkdir(exist_ok=True)
    return root


def _codes(result):
    return sorted({f.code for f in result.errors})


def test_a_minimal_bundle_passes_clean(tmp_path):
    result = check_bundle(_bundle(tmp_path, {}))
    assert result.errors == [] and result.notes == [] and result.ok


def test_the_profile_digest_in_the_root_index_is_a_noted_extension(tmp_path):
    index = '---\nokf_version: "0.2"\ntelarch_export_profile_sha256: "ab"\n---\n# Concepts\n'
    result = check_bundle(_bundle(tmp_path, {"index.md": index}))
    assert result.errors == []
    assert [(n.path, n.code) for n in result.notes] == [("index.md", "noted_extension")]


BROKEN = {
    # one fixture per checked MUST: (files to add or replace, expected error code)
    "frontmatter (11.1)": ({"default/decision/beta.md": "# no frontmatter\n"}, "frontmatter"),
    "frontmatter outside the subset": ({"default/decision/beta.md": "---\ntype: &a X\n---\n"}, "frontmatter"),
    "type present (4.1)": ({"default/decision/beta.md": '---\ntitle: "no type"\n---\nx\n'}, "type"),
    "type non-empty (4.1)": ({"default/decision/beta.md": '---\ntype: ""\n---\nx\n'}, "type"),
    "no concept named log.md (3.1)": ({"default/decision/log.md": '---\ntype: "Decision"\n---\nx\n'}, "reserved_name"),
    "no frontmatter in a non-root index.md (8)": ({"default/index.md": '---\nokf_version: "0.2"\n---\n# D\n'},
                                                   "index_frontmatter"),
    "root index.md holds only okf_version (8)": ({"index.md": '---\nokf_version: "0.2"\ntitle: "x"\n---\n# C\n'},
                                                  "root_index_key"),
    "ISO log headings (9)": ({"log.md": "# Log\n\n## Nov 1, 2026\n\n* x\n"}, "log_heading"),
    "ISO log headings, real dates (9)": ({"default/log.md": "# Log\n\n## 2026-13-01\n\n* x\n"}, "log_heading"),
    "resource in every sources entry (5.1)": (
        {"default/decision/beta.md": '---\ntype: "Decision"\nsources:\n  - {id: "s1", title: "no resource"}\n---\nx\n'},
        "sources_resource"),
    "by in every generated block (5.2)": (
        {"default/decision/beta.md": '---\ntype: "Decision"\ngenerated: {at: "2026-10-31T00:00:00Z"}\n---\nx\n'},
        "generated_by"),
    "well-formed human: actor, empty id (7)": (
        {"default/decision/beta.md": '---\ntype: "Decision"\nverified: [{by: "human:", at: "2026-10-31"}]\n---\nx\n'},
        "human_actor"),
    "well-formed human: actor, case and space (7)": (
        {"default/decision/beta.md": '---\ntype: "Decision"\ngenerated: {by: "Human: owner"}\n---\nx\n'},
        "human_actor"),
    "runtime on an Attested Computation (10)": (
        {"default/decision/beta.md": '---\ntype: "Attested Computation"\n---\n# Computation\n'}, "runtime"),
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_each_checked_must_has_a_failing_fixture(tmp_path, name):
    files, code = BROKEN[name]
    result = check_bundle(_bundle(tmp_path, files))
    assert not result.ok
    assert _codes(result) == [code], [(f.path, f.code, f.message) for f in result.errors]


TOLERATED = {
    "unknown type": {"default/decision/beta.md": '---\ntype: "Some Type Nobody Registered"\n---\nx\n'},
    "unknown keys": {"default/decision/beta.md": '---\ntype: "Decision"\nx_custom: {a: [1, 2]}\nzz: "z"\n---\nx\n'},
    "broken link": {"default/decision/beta.md": '---\ntype: "Decision"\n---\nSee [gone](/nowhere/missing.md).\n'},
    "missing index.md": {"index.md": None},
    "bare verified mapping": {
        "default/decision/beta.md": '---\ntype: "Decision"\nverified: {by: "human:owner", at: "2026-10-31T00:00:00Z"}\n---\nx\n'},
    "machine verifier": {
        "default/decision/beta.md": '---\ntype: "Decision"\nverified: [{by: "process:nightly", at: "2026-10-31"}]\n---\nx\n'},
    "non-markdown files": {"references/data.csv": "a,b\n1,2\n"},
}


@pytest.mark.parametrize("name", sorted(TOLERATED))
def test_consumer_tolerance_fixtures_pass(tmp_path, name):
    files = dict(TOLERATED[name])
    base = True
    if files.get("index.md", "") is None:
        files = {"log.md": LOG, "default/decision/alpha.md": CONCEPT}
        base = False
    result = check_bundle(_bundle(tmp_path, files, base=base))
    assert result.errors == [], [(f.path, f.code, f.message) for f in result.errors]


def test_a_symlink_is_not_followed(tmp_path):
    root = _bundle(tmp_path, {})
    outside = tmp_path / "outside.md"
    outside.write_text("# not frontmatter\n", encoding="utf-8")
    (root / "default" / "decision" / "link.md").symlink_to(outside)
    result = check_bundle(root)
    assert result.errors == []
    assert [(n.path, n.code) for n in result.notes] == [("default/decision/link.md", "symlink_skipped")]


def test_a_missing_bundle_directory_is_an_error(tmp_path):
    result = check_bundle(tmp_path / "absent")
    assert _codes(result) == ["bundle"]
