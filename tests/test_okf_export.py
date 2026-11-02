"""P13.1 / P13.4: okf-export projects allowlisted vault rows into an OKF v0.2 bundle.

Synthetic fixture vaults only (tmp_path); no live data in any committed test.
"""
import json
import os
import re
import sys
from pathlib import Path

import pytest

import kibisis
from kibisis.__main__ import main
from kibisis.okf.check import check_bundle
from kibisis.okf.export import ExportError, GateRefused, export_bundle, iso_utc
from kibisis.okf.frontmatter import parse_frontmatter, split_document
from kibisis.okf.profile import load_profile, parse_profile

# --import-mode=importlib (pyproject) does not put tests/ on sys.path; append it for the shared fixtures.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.append(str(Path(__file__).resolve().parent))

from _okf_fixtures import (  # noqa: E402
    DEFAULT_PROFILE_JSON,
    EXPORTABLE,
    PASSPHRASE,
    PROBE_WITHHELD,
    all_paths,
    build_probe_vault,
    concept_paths,
    open_vault,
    tree_bytes,
    write_profile,
)

AT = "2026-11-01"


@pytest.fixture()
def probe(tmp_path):
    vault = build_probe_vault(tmp_path / "vault.sqlite")
    yield vault
    vault.close()


def _profile():
    return parse_profile(DEFAULT_PROFILE_JSON)


def _read(out: Path, rel: str):
    fm, body = split_document((out / rel).read_text(encoding="utf-8"))
    assert fm is not None, f"{rel} has no frontmatter block"
    return parse_frontmatter(fm), body


# ---------------------------------------------------------------- bar (a): what must not leave the vault


def test_the_probe_vault_exports_only_allowlisted_safe_rows(tmp_path, probe):
    out = tmp_path / "bundle"
    report = export_bundle(probe, _profile(), out, at=AT, ungated=True)
    expected = concept_paths(EXPORTABLE)
    assert set(report.concepts) == expected
    assert report.exported == len(EXPORTABLE)
    assert report.withheld == PROBE_WITHHELD
    files = set(tree_bytes(out))
    assert files == expected | {"index.md", "log.md"}
    joined = b"".join(tree_bytes(out).values())
    for marker in (b"Confidential body", b"Flagged confidential", b"unrecognised sensitivity", b"another scope",
                   b"profile row", b"diagnosis row", b"blueprint row", b"archived row", b"not a safe file name"):
        assert marker not in joined, marker


def test_a_path_traversal_key_writes_nothing_outside_out(tmp_path, probe):
    out = tmp_path / "nested" / "bundle"
    out.parent.mkdir()

    def snapshot():
        return {p for p in all_paths(tmp_path) if not p.startswith("vault.sqlite")}

    before = snapshot()
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    after = snapshot()
    assert after - before == {"nested/bundle"} | {"nested/bundle/" + p for p in all_paths(out)}
    assert not any("escape" in p or p.endswith("up.md") for p in after)


def test_named_opts_a_category_in_and_exclude_wins(tmp_path, probe):
    obj = json.loads(DEFAULT_PROFILE_JSON)
    obj["named"] = ["user_profile"]
    obj["exclude"] = {"keys": ["alpha"], "categories": ["convention"]}
    report = export_bundle(probe, parse_profile(json.dumps(obj)), tmp_path / "b", at=AT, ungated=True)
    assert "default/user_profile/u1.md" in report.concepts
    assert "default/decision/alpha.md" not in report.concepts
    assert "default/convention/beta.md" not in report.concepts
    assert report.withheld["excluded_key"] == 1


def test_keys_that_collide_case_insensitively_are_both_withheld(tmp_path):
    vault = open_vault(tmp_path / "v.sqlite")
    try:
        vault.put("decision", "Same", "Upper.", origin="model")
        vault.put("decision", "same", "Lower.", origin="model")
        vault.put("decision", "other", "Other.", origin="model")
        report = export_bundle(vault, _profile(), tmp_path / "b", at=AT, ungated=True)
    finally:
        vault.close()
    assert report.concepts == ["default/decision/other.md"]
    assert report.withheld == {"key_collision": 2}


# ---------------------------------------------------------------- field map (INTEGRATION.md section 5)


def test_field_map_for_a_candidate_with_a_source(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    fm, body = _read(out, "default/decision/alpha.md")
    row = probe.get("decision", "alpha")
    assert body == row.content
    assert fm["type"] == "Decision"
    assert fm["title"] == "alpha"
    assert fm["description"] == "Alpha is decided."
    assert fm["status"] == "draft"
    assert fm["kibisis_state"] == "candidate"
    assert fm["kibisis_origin"] == "model"
    assert fm["generated"] == {"by": "kibisis/" + kibisis.__version__, "at": iso_utc(row.updated_at)}
    assert fm["sources"] == [{"id": "source_ref", "resource": "session:s1/turn:3"}]
    assert "verified" not in fm and "stale_after" not in fm


def test_only_a_person_admit_journal_record_writes_a_human_verifier(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    delta, _ = _read(out, "default/architecture/delta.md")
    events = [e for e in probe.list_audit_events(category="architecture", key="delta", limit=10**6)
              if e.action == "state_transition"]
    assert delta["verified"] == [{"by": "human:owner", "at": iso_utc(events[-1].timestamp)}]
    assert delta["status"] == "stable"
    assert "kibisis_state" not in delta
    # verified by its author's own write (no review record): no verified key, the honest tier is unverified.
    gamma, _ = _read(out, "default/project_state/gamma.md")
    assert "verified" not in gamma
    assert gamma["kibisis_state"] == "verified"
    assert gamma["type"] == "Project State"
    assert gamma["stale_after"] == "2030-01-01T00:00:00.250000Z"
    assert gamma["kibisis_origin"] == "user"
    # disputed by a person: a review record, but not an admit.
    epsilon, _ = _read(out, "default/decision/epsilon.md")
    assert "verified" not in epsilon
    assert (epsilon["status"], epsilon["kibisis_state"]) == ("draft", "disputed")
    for rel in concept_paths(EXPORTABLE):
        fm, _ = _read(out, rel)
        assert not fm["generated"]["by"].startswith("human:"), rel


def test_a_superseded_row_is_deprecated_and_links_its_replacement(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    v1, body = _read(out, "default/decision/v1.md")
    assert v1["status"] == "deprecated"
    assert v1["kibisis_state"] == "revoked"
    assert v1["kibisis_superseded_by"] == "/default/decision/v2.md"
    assert body == "Old decision."
    v2, _ = _read(out, "default/decision/v2.md")
    assert v2["status"] == "stable"


def test_no_link_to_a_replacement_that_is_not_exported(tmp_path, probe):
    obj = json.loads(DEFAULT_PROFILE_JSON)
    obj["exclude"] = {"keys": ["v2"], "categories": []}
    out = tmp_path / "b"
    export_bundle(probe, parse_profile(json.dumps(obj)), out, at=AT, ungated=True)
    v1, _ = _read(out, "default/decision/v1.md")
    assert v1["status"] == "deprecated"
    assert "kibisis_superseded_by" not in v1
    assert b"v2" not in (out / "default/decision/v1.md").read_bytes()


def test_a_body_with_a_rule_line_round_trips_exactly(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    _, body = _read(out, "default/convention/beta.md")
    assert body == probe.get("convention", "beta").content


def test_index_and_log_at_the_bundle_root(tmp_path, probe):
    out = tmp_path / "b"
    report = export_bundle(probe, _profile(), out, at=AT, ungated=True)
    index_fm, index_body = _read(out, "index.md")
    assert index_fm == {"okf_version": "0.2", "telarch_export_profile_sha256": _profile().digest}
    assert report.profile_digest == _profile().digest
    assert "* [alpha](default/decision/alpha.md) - Alpha is decided." in index_body
    log = (out / "log.md").read_text(encoding="utf-8")
    assert split_document(log)[0] is None
    assert "\n## 2026-11-01\n" in log
    assert re.search(r"exported 7; withheld 17 \(", log)
    # counts only: no key or content from any row appears in the log.
    for word in ("alpha", "secret_plan", "escape", "Confidential"):
        assert word not in log


def test_the_index_can_leave_out_the_profile_digest(tmp_path, probe):
    # For callers whose content gate flags the digest line (a 64-hex value under a long key): the
    # digest stays in the report, the index carries okf_version alone, every other file is unchanged.
    with_digest, without = tmp_path / "a", tmp_path / "b"
    export_bundle(probe, _profile(), with_digest, at=AT, ungated=True)
    report = export_bundle(probe, _profile(), without, at=AT, ungated=True, index_profile_digest=False)
    index_fm, index_body = _read(without, "index.md")
    assert index_fm == {"okf_version": "0.2"}
    assert "telarch_export_profile_sha256" not in (without / "index.md").read_text(encoding="utf-8")
    assert report.profile_digest == _profile().digest
    assert index_body == _read(with_digest, "index.md")[1]
    ta, tb = tree_bytes(with_digest), tree_bytes(without)
    assert ta.keys() == tb.keys()
    assert [k for k in ta if ta[k] != tb[k]] == ["index.md"]
    result = check_bundle(without)
    assert result.ok, result.as_dict()
    assert not any("telarch_export_profile_sha256" in str(n) for n in result.notes)


def test_re_export_without_the_digest_replaces_its_own_bundle(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at="2026-10-31", ungated=True, index_profile_digest=False)
    export_bundle(probe, _profile(), out, at=AT, ungated=True, index_profile_digest=False)
    log = (out / "log.md").read_text(encoding="utf-8")
    assert log.index("## 2026-11-01") < log.index("## 2026-10-31")
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    # A digest-less export also replaces a bundle that carries the digest (both are this exporter's shape).
    other = tmp_path / "c"
    export_bundle(probe, _profile(), other, at="2026-10-31", ungated=True)
    export_bundle(probe, _profile(), other, at=AT, ungated=True, index_profile_digest=False)
    assert _read(other, "index.md")[0] == {"okf_version": "0.2"}


def test_a_default_export_still_refuses_a_digest_less_index(tmp_path, probe):
    # The default keeps its rule: replace only an index that names a profile digest.
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at="2026-10-31", ungated=True, index_profile_digest=False)
    before = tree_bytes(out)
    with pytest.raises(ExportError, match="not a bundle okf-export wrote"):
        export_bundle(probe, _profile(), out, at=AT, ungated=True)
    assert tree_bytes(out) == before


def test_concept_files_and_the_index_carry_no_run_time(tmp_path, probe):
    a, b = tmp_path / "a", tmp_path / "b"
    export_bundle(probe, _profile(), a, at="2026-11-01", ungated=True)
    export_bundle(probe, _profile(), b, at="2030-02-03T04:05:06Z", ungated=True)
    ta, tb = tree_bytes(a), tree_bytes(b)
    assert ta.keys() == tb.keys()
    assert [k for k in ta if ta[k] != tb[k]] == ["log.md"]
    assert "## 2030-02-03" in tb["log.md"].decode()


# ---------------------------------------------------------------- bar (b): byte-identical re-export (P13.4 (b))


def test_two_fresh_exports_are_byte_identical(tmp_path, probe):
    a, b = tmp_path / "a", tmp_path / "b"
    export_bundle(probe, _profile(), a, at=AT, ungated=True)
    export_bundle(probe, _profile(), b, at=AT, ungated=True)
    assert tree_bytes(a) == tree_bytes(b)


def test_re_export_into_a_previous_bundle_keeps_its_log(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at="2026-10-31", ungated=True)
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    log = (out / "log.md").read_text(encoding="utf-8")
    assert log.index("## 2026-11-01") < log.index("## 2026-10-31")
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    leftovers = [p for p in os.listdir(tmp_path) if "okf-" in p]
    assert leftovers == []


_COUNTS_ONLY = re.compile(r"\* \*\*Export\*\*: exported \d+; withheld \d+(?: \([a-z_]+ \d+(?:, [a-z_]+ \d+)*\))?\.")


def test_the_log_carries_counts_only(tmp_path, probe):
    # P13.1: "a log.md entry per run (counts only: exported, and withheld by reason)". The profile digest
    # belongs to index.md alone.
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    export_bundle(probe, _profile(), out, at="2026-11-02", ungated=True)
    log = (out / "log.md").read_text(encoding="utf-8")
    bullets = [line for line in log.splitlines() if line.startswith("* ")]
    assert len(bullets) == 2
    assert all(_COUNTS_ONLY.fullmatch(line) for line in bullets), bullets
    assert _profile().digest not in log
    assert not re.search(r"[0-9a-fA-F]{32,}", log)


_EXCHANGE_PLATFORM = sys.platform.startswith("linux") or sys.platform == "darwin"


@pytest.mark.skipif(not _EXCHANGE_PLATFORM, reason="one-call directory exchange is Linux/macOS only")
def test_exchange_swaps_two_directories(tmp_path):
    from kibisis.okf.export import _exchange_dirs

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "x").write_text("a")
    (b / "y").write_text("b")
    assert _exchange_dirs(str(a), str(b)) is True
    assert os.listdir(a) == ["y"]
    assert os.listdir(b) == ["x"]


@pytest.mark.skipif(not _EXCHANGE_PLATFORM, reason="one-call directory exchange is Linux/macOS only")
def test_re_export_replaces_the_bundle_in_one_exchange(tmp_path, probe, monkeypatch):
    # P13.1: the bundle is replaced "by an atomic directory swap", so --out never goes missing mid-replace.
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at="2026-10-31", ungated=True)
    real_rename = os.rename

    def guarded(src, dst, *args, **kwargs):
        if os.path.abspath(os.fspath(src)) == str(out):
            raise AssertionError("--out was renamed away: the replace was not one exchange")
        return real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", guarded)
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    assert "## 2026-11-01" in (out / "log.md").read_text(encoding="utf-8")
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    assert [p for p in os.listdir(tmp_path) if "okf-" in p] == []


# ---------------------------------------------------------------- content gate: withheld, never redacted


def test_a_row_the_content_gate_flags_is_withheld_not_redacted(tmp_path, probe):
    def row_gate(rel, text):
        return ["finding"] if "Epsilon" in text else []

    out = tmp_path / "b"
    report = export_bundle(probe, _profile(), out, at=AT, row_gate=row_gate)
    assert "default/decision/epsilon.md" not in report.concepts
    assert report.withheld["content_gate"] == 1
    assert not (out / "default/decision/epsilon.md").exists()
    assert b"Epsilon" not in b"".join(tree_bytes(out).values())


def test_a_bundle_gate_refusal_leaves_no_bundle(tmp_path, probe):
    out = tmp_path / "b"
    with pytest.raises(GateRefused):
        export_bundle(probe, _profile(), out, at=AT, bundle_gate=lambda staging, paths: False)
    assert not out.exists()
    assert [p for p in os.listdir(tmp_path) if p != "vault.sqlite" and not p.startswith("vault.sqlite")] == []


def test_the_library_refuses_to_write_without_a_gate(tmp_path, probe):
    with pytest.raises(ExportError):
        export_bundle(probe, _profile(), tmp_path / "b", at=AT)
    assert not (tmp_path / "b").exists()


def test_out_that_is_not_a_bundle_is_refused_untouched(tmp_path, probe):
    out = tmp_path / "home"
    out.mkdir()
    (out / "notes.txt").write_text("keep me", encoding="utf-8")
    with pytest.raises(ExportError):
        export_bundle(probe, _profile(), out, at=AT, ungated=True)
    assert tree_bytes(out) == {"notes.txt": b"keep me"}


# ---------------------------------------------------------------- the exported bundle passes the checker


def test_the_exported_bundle_is_conformant(tmp_path, probe):
    out = tmp_path / "b"
    export_bundle(probe, _profile(), out, at=AT, ungated=True)
    result = check_bundle(out)
    assert result.errors == []
    assert [(n.path, n.code) for n in result.notes] == [("index.md", "noted_extension")]


# ---------------------------------------------------------------- CLI: bars P13.1 (d) and P13.4 (c)


@pytest.fixture()
def cli_env(tmp_path, monkeypatch):
    db = tmp_path / "vault.sqlite"
    build_probe_vault(db).close()
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    return db


def _entries(tmp_path):
    return sorted(p for p in os.listdir(tmp_path) if not p.startswith("vault.sqlite") and not p.endswith(".json")
                  and not p.endswith(".py"))


def test_cli_exports_with_ungated(tmp_path, cli_env, capsys):
    out = tmp_path / "bundle"
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(out), "--db", str(cli_env),
               "--at", AT, "--ungated"])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["exported"] == len(EXPORTABLE)
    assert summary["withheld"] == PROBE_WITHHELD
    assert set(tree_bytes(out)) == concept_paths(EXPORTABLE) | {"index.md", "log.md"}


def test_cli_without_a_gate_choice_exits_non_zero_and_writes_nothing(tmp_path, cli_env):
    out = tmp_path / "bundle"
    with pytest.raises(SystemExit) as exc:
        main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(out), "--db", str(cli_env)])
    assert exc.value.code != 0
    assert _entries(tmp_path) == []


def _gate_script(tmp_path, needle):
    script = tmp_path / "gate.py"
    script.write_text(
        "import sys\n"
        "hits = [p for p in sys.argv[1:] if %r in open(p, encoding='utf-8').read()]\n"
        "sys.exit(1 if hits else 0)\n" % needle,
        encoding="utf-8",
    )
    return f"{sys.executable} {script}"


def test_cli_gate_cmd_that_reports_a_hit_leaves_no_bundle(tmp_path, cli_env):
    out = tmp_path / "bundle"
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(out), "--db", str(cli_env),
               "--at", AT, "--gate-cmd", _gate_script(tmp_path, "Alpha is decided")])
    assert rc != 0
    assert _entries(tmp_path) == []


def test_cli_gate_cmd_that_passes_writes_the_bundle(tmp_path, cli_env):
    out = tmp_path / "bundle"
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(out), "--db", str(cli_env),
               "--at", AT, "--gate-cmd", _gate_script(tmp_path, "NOT-PRESENT-ANYWHERE")])
    assert rc == 0
    assert (out / "index.md").is_file()


@pytest.mark.parametrize(
    "profile_text",
    [
        DEFAULT_PROFILE_JSON[:-1] + ', "extra": 1}',
        DEFAULT_PROFILE_JSON.replace('"scopes": ["default"]', '"scopes": ["*"]'),
        DEFAULT_PROFILE_JSON.replace('"decision", ', '"*", '),
        '{"schema": "kibisis.okf_export_profile/1", "audience": "owner", "named": []}',
    ],
    ids=["unknown-key", "wildcard-scope", "wildcard-category", "no-allow-list"],
)
def test_cli_refuses_a_bad_profile_before_writing(tmp_path, cli_env, profile_text):
    out = tmp_path / "bundle"
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path, profile_text)), "--out", str(out),
               "--db", str(cli_env), "--at", AT, "--ungated"])
    assert rc != 0
    assert _entries(tmp_path) == []


def test_cli_refuses_a_missing_vault_without_creating_one(tmp_path, monkeypatch):
    monkeypatch.setenv("KIBISIS_PASSPHRASE", PASSPHRASE)
    rc = main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(tmp_path / "bundle"),
               "--db", str(tmp_path / "absent.sqlite"), "--at", AT, "--ungated"])
    assert rc != 0
    assert sorted(os.listdir(tmp_path)) == ["profile.json"]


def test_cli_check_reports_a_conformant_bundle(tmp_path, cli_env, capsys):
    out = tmp_path / "bundle"
    assert main(["okf-export", "--profile", str(write_profile(tmp_path)), "--out", str(out), "--db", str(cli_env),
                 "--at", AT, "--ungated"]) == 0
    capsys.readouterr()
    assert main(["okf-check", str(out)]) == 0
    (out / "default" / "decision" / "broken.md").write_text("no frontmatter\n", encoding="utf-8")
    assert main(["okf-check", str(out)]) == 1


def test_load_profile_digest_matches_the_report(tmp_path, probe):
    prof = load_profile(write_profile(tmp_path))
    report = export_bundle(probe, prof, tmp_path / "b", at=AT, ungated=True)
    assert report.profile_digest == prof.digest
