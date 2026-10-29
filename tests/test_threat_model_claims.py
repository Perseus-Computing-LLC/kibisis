"""Pins the claims SECURITY.md's threat model makes about a local file writer on a vault opened without
SQLCipher. Each test asserts the behavior the document describes, caught or not caught, so that a change in
either direction shows up here and the document is updated with it."""

import json
import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import EntryIntegrityError, SQLiteMemoryVault

PASS = "threat model passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    """The file writer's position: a plain SQLite file, sealed entries, no whole-file encryption."""
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)


def _seeded(path):
    vault = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    vault.remember("decision", "agent_fact", "Agent says deploy on Friday", origin="model")
    vault.remember("decision", "person_fact", "Deploy window is Tuesday", origin="user", epistemic_state="verified")
    vault.close()
    return path


def _edit(path, sql, params=()):
    conn = sqlite3.connect(str(path))
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def test_sealed_text_and_terms_are_not_on_disk_but_labels_are(tmp_path):
    path = _seeded(tmp_path / "v.sqlite")
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT content, epistemic_state, origin, metadata_json FROM entities WHERE key = 'agent_fact'").fetchone()
    assert row["content"] == ""  # sealed: the plaintext column is empty
    assert row["epistemic_state"] == "candidate" and row["origin"] == "model"  # labels readable
    fts = conn.execute("SELECT category, key, content FROM entities_fts WHERE key = 'agent_fact'").fetchone()
    assert fts["content"] == "" and fts["key"] == "agent_fact"  # no entry terms, but category/key terms
    conn.close()


def test_content_edit_is_caught(tmp_path):
    path = _seeded(tmp_path / "v.sqlite")
    _edit(path, "UPDATE entities SET content = 'Deploy on Monday', is_encrypted = 0 WHERE key = 'agent_fact'")
    vault = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    with pytest.raises(EntryIntegrityError):
        vault.get("decision", "agent_fact")
    assert "agent_fact" not in [r.entity.key for r in vault.search("deploy", match="any", include_unverified=True)]
    vault.close()


def test_journal_tail_delete_is_caught(tmp_path):
    path = _seeded(tmp_path / "v.sqlite")
    _edit(path, "DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
    vault = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    assert vault.verify_audit_chain() is False
    vault.close()


def test_trust_flip_is_not_caught_without_sqlcipher(tmp_path):
    """SECURITY.md, 'Flipping trust': the entry signature covers scope, category, key and content only."""
    path = _seeded(tmp_path / "v.sqlite")
    forged = json.dumps({"human_reviews": [{"reviewer_id": "forged", "verdict": "verified", "reviewer_origin": "user"}]})
    _edit(
        path,
        "UPDATE entities SET epistemic_state = 'verified', origin = 'user', metadata_json = ? WHERE key = 'agent_fact'",
        (forged,),
    )
    vault = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    entity = vault.get("decision", "agent_fact")
    assert entity is not None
    assert entity.epistemic_state.value == "verified"
    assert entity.origin == "user"
    assert entity.metadata["human_reviews"][0]["reviewer_id"] == "forged"
    assert "agent_fact" in [r.entity.key for r in vault.search("deploy friday", match="any")]  # default recall
    assert vault.verify_audit_chain() is True  # the journal checks only itself
    vault.close()


def test_deleting_journal_and_head_together_is_not_caught(tmp_path):
    """SECURITY.md, 'Deleting the whole journal together with its head'."""
    path = _seeded(tmp_path / "v.sqlite")
    _edit(path, "DELETE FROM audit_journal")
    _edit(path, "DELETE FROM audit_head")
    vault = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    assert vault.verify_audit_chain() is True
    assert vault.get("decision", "person_fact") is not None  # entries stay readable
    vault.close()
