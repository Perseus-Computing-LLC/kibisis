"""Review 3, area A+B seams: tombstone rows / classes / MAC / journal reconciliation after the merge
(R2-A1, R2-A4, R2-A5, R2-A6, R2-B3; R3-AB1, R3-AB5 fixed on fix/round3-ab). ``test_control_*`` = secure
behaviour; ``test_attack_*`` = the round-3 defect scenario, asserting the FIXED behaviour.
"""

import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis._vault_crypto import canonicalize_text

PASS = "review3-ab tombstone passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _open(path, **kw):
    return SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False, **kw)


def _conn(path):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    return c


def _events(v, action):
    return [e for e in v.list_audit_events(limit=1000) if e.action == action]


# --- R2-A1: class never goes down --------------------------------------------------------------------


@pytest.mark.parametrize("lower", ["tool", "model"])
def test_control_r2a1_lower_class_retombstone_keeps_principal_row_and_mac(tmp_path, lower):
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k", "deploy on fridays", origin="model")
    v.tombstone("decision", "k", reason="no", author_id="alice", origin="user")
    v.tombstone("decision", "k", content="deploy on fridays", reason="agent says so", origin=lower)
    rows = v.list_tombstones(category="decision")
    assert [r["origin_class"] for r in rows] == ["principal"]
    assert _events(v, "tombstone_reaffirmed")[-1].metadata["origin_class"] == "principal"
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k", "deploy on fridays", origin="model")
    v.close()
    v = _open(p)  # MAC still verifies, reconciliation holds
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k", "deploy on fridays", origin="model")
    v.close()


def test_control_r2a1_snapshot_import_of_lower_class_row_does_not_downgrade(tmp_path):
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k", "deploy on fridays", origin="model")
    v.tombstone("decision", "k", reason="no", author_id="alice", origin="user")
    snap = v.export_snapshot()
    for t in snap["tombstones"]:
        t["origin_class"] = "agent"
    snap.pop("manifest_sha256")
    v.import_snapshot(snap)
    assert [r["origin_class"] for r in v.list_tombstones(category="decision")] == ["principal"]
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "k", "deploy on fridays", origin="model")
    v.close()
    _open(p).close()


def test_attack_file_writer_replays_an_older_agent_class_row_over_a_persons_raised_row(tmp_path):
    """R3-AB5 fixed. A row's class is under its MAC, but a file writer holding a copy of the row as it
    stood before a person raised its class (external class + its then-valid MAC) puts that copy back.
    ``_check_tombstones`` now carries the latest ``tombstone`` event's ``origin_class`` per identity and
    refuses a row whose class is lower, writable and read-only."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k", "deploy on fridays", origin="tool")
    v.tombstone("decision", "k", reason="tool forgot", origin="tool")  # external-class row
    v.close()
    c = _conn(p)
    old = dict(c.execute("SELECT origin_class, tombstone_mac FROM rejected_value_tombstones").fetchone())
    c.close()
    assert old["origin_class"] == "external"
    v = _open(p)
    v.tombstone("decision", "k", content="deploy on fridays", reason="person rejects", author_id="alice",
                origin="user")  # class rises to principal, re-signed, journaled 'tombstone'
    assert [r["origin_class"] for r in v.list_tombstones(category="decision")] == ["principal"]
    assert _events(v, "tombstone")[-1].metadata["origin_class"] == "principal"
    v.close()
    _open(p).close()  # control half: the raised row reconciles with its journal
    c = _conn(p)
    c.execute("UPDATE rejected_value_tombstones SET origin_class = ?, tombstone_mac = ?",
              (old["origin_class"], old["tombstone_mac"]))
    c.commit()
    c.close()
    for read_only in (False, True):
        with pytest.raises(vault_module.VaultIntegrityError, match="journal records it as principal"):
            _open(p, read_only=read_only)


def test_control_r3ab5_reaffirmed_and_lifted_rows_reconcile_by_class(tmp_path):
    """The class check follows the latest ``tombstone`` event: a lower-class re-request (journaled
    ``tombstone_reaffirmed``) leaves the expectation at principal, and a lift clears it."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k", "deploy on fridays", origin="model")
    v.tombstone("decision", "k", reason="no", author_id="alice", origin="user")
    v.tombstone("decision", "k", content="deploy on fridays", reason="agent too", origin="model")
    v.close()
    _open(p).close()
    v = _open(p)
    assert v.lift_tombstone("decision", "k", origin="user") == 1
    v.close()
    _open(p).close()
    _open(p, read_only=True).close()


# --- R3-AB1: the lifted event names the row, not the writer's entry ---------------------------------


def test_attack_lift_by_a_write_under_another_key_wedges_the_next_open(tmp_path):
    """R3-AB1 fixed. An agent's forget of ``c:k1`` (value V) followed by a person's ordinary write of V
    under ``c:k2`` lifts the row; ``_lift_lower_class_tombstones`` now journals ``tombstone_lifted``
    under the ROW's identity (the writer's entry goes in the metadata), so the next open, writable or
    read-only, reconciles and the chain verifies."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k1", "deploy on fridays", origin="model")
    v.tombstone("decision", "k1", reason="agent forgot", origin="model")  # what MCP kibisis_forget does
    v.remember("decision", "k2", "deploy on fridays", origin="user", author_id="alice")  # lifts it
    assert v.list_tombstones(category="decision") == []
    ev = _events(v, "tombstone_lifted")[-1]
    assert (ev.category, ev.key, ev.scope) == ("decision", "k1", "default")
    assert ev.metadata["tombstone"] == "decision:k1" and ev.metadata["entry"] == "decision:k2"
    assert ev.metadata["lifted_by"] == "principal-class write"
    assert v.verify_audit_chain() is True
    v.close()
    for read_only in (False, True):
        v = _open(p, read_only=read_only)
        assert v.verify_audit_chain() is True
        assert v.list_tombstones(category="decision") == []
        v.close()
    v = _open(p)
    assert v.get("decision", "k2").content == "deploy on fridays"
    v.close()


def test_attack_lift_by_a_write_in_another_scope_wedges_the_next_open(tmp_path):
    """R3-AB1 fixed, through a non-default scope and a different key."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k", "deploy on fridays", origin="model", scope="team")
    v.tombstone("decision", "k", reason="agent forgot", origin="model", scope="team")
    v.remember("decision", "k", "deploy on fridays", origin="user", author_id="alice", scope="team")
    assert v.list_tombstones(category="decision") == []
    v.close()
    _open(p).close()  # same key and scope: reconciles (control half)
    v = _open(p)
    v.remember("notes", "n", "deploy on tuesdays", origin="model", scope="team")
    v.tombstone("notes", "n", reason="agent forgot", origin="model", scope="team")
    v.remember("notes", "m", "deploy on tuesdays", origin="user", author_id="alice", scope="team")
    ev = _events(v, "tombstone_lifted")[-1]
    assert (ev.category, ev.key, ev.scope) == ("notes", "n", "team") and ev.metadata["entry_scope"] == "team"
    v.close()
    for read_only in (False, True):
        v = _open(p, read_only=read_only)
        assert v.verify_audit_chain() is True
        v.close()


def test_control_r3ab1_vault_holding_a_pre_fix_lifted_event_still_opens(tmp_path):
    """A vault whose journal already holds a ``tombstone_lifted`` under the writer's identity (written
    before the fix, row named only in ``metadata.tombstone``/``tombstone_scope``) opens: the
    reconciliation matches the row through the metadata."""
    p = tmp_path / "v.sqlite"
    v = _open(p)
    v.remember("decision", "k1", "deploy on fridays", origin="model")
    v.tombstone("decision", "k1", reason="agent forgot", origin="model")
    v.close()
    # Rewrite the lift the way the pre-fix code journaled it: event under the writer's entry.
    v = _open(p)
    real = v._record_audit_event

    def pre_fix(cursor, action, category, key, scope, value_sha256, author_id=None, metadata=None, **kw):
        if action == "tombstone_lifted":
            category, key, scope = "decision", "k2", metadata["entry_scope"]
            metadata = {k: val for k, val in metadata.items() if k not in ("entry", "entry_scope")}
        return real(cursor=cursor, action=action, category=category, key=key, scope=scope,
                    value_sha256=value_sha256, author_id=author_id, metadata=metadata, **kw)

    v._record_audit_event = pre_fix
    v.remember("decision", "k2", "deploy on fridays", origin="user", author_id="alice")
    ev = _events(v, "tombstone_lifted")[-1]
    assert (ev.category, ev.key) == ("decision", "k2") and ev.metadata["tombstone"] == "decision:k1"
    assert "entry" not in ev.metadata
    v.close()
    for read_only in (False, True):
        v = _open(p, read_only=read_only)
        assert v.verify_audit_chain() is True
        v.close()


# --- R2-A6: lift gating ----------------------------------------------------------------------------


@pytest.mark.parametrize("origin", ["model", "tool", "unknown"])
def test_control_r2a6_non_principal_lift_is_refused_and_journaled(tmp_path, origin):
    v = _open(tmp_path / "v.sqlite")
    v.remember("decision", "k", "deploy on fridays", origin="model")
    v.tombstone("decision", "k", reason="agent forgot", origin="model")
    with pytest.raises(PermissionError):
        v.lift_tombstone("decision", "k", origin=origin)
    assert len(v.list_tombstones(category="decision")) == 1
    assert _events(v, "refuse")[-1].metadata.get("path") == "lift_tombstone"
    v.close()


# --- R2-A4 / R2-A5: the fold -----------------------------------------------------------------------


@pytest.mark.parametrize("filler", ["\u115f", "\u1160", "\u3164", "\uffa0"])
def test_control_r2a5_hangul_filler_folds_to_a_space(filler):
    assert canonicalize_text(f"deploys{filler}go{filler}out") == "deploys go out"


def test_control_r2a4_spacing_vowel_signs_distinguish_words():
    assert len({canonicalize_text(w) for w in ("कल", "काल", "कील")}) == 3


def test_control_fold_still_catches_the_round_1_evasions():
    base = canonicalize_text("deploy on fridays")
    for variant in ("deploy\u200b on fridays", "deploy on fr\u0131days", "dерloy on fridays",
                    "ｄｅｐｌｏｙ ｏｎ ｆｒｉｄａｙｓ", "deploy\u2800on\u2800fridays", "deploy_on-fridays",
                    "DEPLOY ON FRIDAYS", "deploy\u00ad on fridays", "deploy\ufe0f on fridays"):
        assert canonicalize_text(variant) == base, variant


def test_attack_fold_misses_small_capitals_and_latin_alpha():
    """Documented limit (README 'Limits', docstring: 'a homoglyph outside the table'): Unicode small
    capitals (U+1D00 block, category Ll, no NFKC mapping) and Latin alpha U+0251 read as the rejected
    sentence and fold to a different digest. Recorded for the docs list, not as a defect."""
    base = canonicalize_text("deploy on fridays")
    assert canonicalize_text("ᴅᴇᴘʟᴏʏ ᴏɴ ғʀɪᴅᴀʏs") != base
    assert canonicalize_text("deploy on fridɑys") != base
