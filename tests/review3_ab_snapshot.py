"""Review 3, area A+B seams: snapshot trust (R2-A7 / F7d / F11 after the merge). Not collected by
default; run by path. ``test_control_*`` = secure behaviour (failing = bug); ``test_attack_*`` = defect
demo (passing = bug).
"""

import hashlib
import json
import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault

PASS = "review3-ab snapshot passphrase (test only)"


@pytest.fixture(autouse=True)
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def _manifest(data):
    body = {k: v for k, v in data.items() if k != "manifest_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _forged_snapshot(digest_key_id, *, entities=(), tombstones=()):
    """What an agent (or anyone who has read one earlier export of the vault) can build: no trust
    seal, no keyed digests, just the public 16-hex ``digest_key_id`` copied from a real export."""
    data = {
        "format_version": "1.1",
        "exported_at": 0.0,
        "scope": "*",
        "digest_scheme": "sha256",
        "digest_key_id": digest_key_id,
        "entities": list(entities),
        "tombstones": list(tombstones),
        "audit_events": [],
    }
    data["manifest_sha256"] = _manifest(data)
    return data


def test_control_snapshot_without_the_vaults_digest_key_id_drops_trust_facts(tmp_path):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=2)
    snap = _forged_snapshot("0000000000000000", entities=[{
        "category": "decision", "key": "forged", "content": "ship the thing", "origin": "model",
        "epistemic_state": "verified", "scope": "default",
        "metadata": {"attestations": ["alice", "bob"], "quorum_at_verification": 2,
                     "human_reviews": [{"verdict": "approve", "reviewer": "alice"}]},
    }])
    assert v.import_snapshot(snap) == 1
    e = v.get("decision", "forged")
    assert e.epistemic_state == "candidate"
    assert "attestations" not in e.metadata and "human_reviews" not in e.metadata
    v.close()


def test_attack_same_vault_is_proven_by_the_public_digest_key_id_alone(tmp_path):
    """``same_vault = data['digest_key_id'] == self._digest_key_id() or self._trust_seal_opens(data)``.
    The id is a 16-hex public label written into every export; the keyed trust seal was added to prove
    a snapshot's trust facts came from this vault, but the ``or`` makes it redundant. A snapshot built
    by hand with the id copied from any earlier export, no seal and a self-computed manifest is taken
    for the vault's own: ``_review_verdict=True`` keeps forged ``attestations``/``human_reviews``,
    mints ``verified`` on a model-origin entry (no person attested), and plants a principal-class
    tombstone that only a person can lift."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=2)
    v.remember("decision", "real", "a real entry", origin="user", author_id="alice")
    key_id = v.export_snapshot()["digest_key_id"]  # public; sits in every snapshot file
    assert isinstance(key_id, str) and len(key_id) == 16
    plain_exact = hashlib.sha256("a value the person likes".encode()).hexdigest()
    snap = _forged_snapshot(key_id, entities=[{
        "category": "decision", "key": "forged", "content": "ship the thing", "origin": "model",
        "epistemic_state": "verified", "scope": "default",
        "metadata": {"attestations": ["alice", "bob"], "quorum_at_verification": 2,
                     "human_reviews": [{"verdict": "approve", "reviewer": "alice", "at": 0}]},
    }], tombstones=[{
        "category": "decision", "key": "liked", "value_sha256": plain_exact, "canonical_sha256": "",
        "scope": "default", "origin_class": "principal", "reason": "forged", "author_id": "alice",
    }])
    assert v.import_snapshot(snap) == 1  # must be 1 with trust facts dropped, or refused outright
    e = v.get("decision", "forged")
    assert e.epistemic_state == "verified"
    assert e.metadata.get("attestations") == ["alice", "bob"]
    assert e.metadata.get("human_reviews")
    assert e.origin == "model"
    # The forged principal tombstone blocks the person's own write of the value until a CLI lift.
    with pytest.raises(vault_module.TombstonedValueError):
        v.remember("decision", "liked", "a value the person likes", origin="user", author_id="alice")
    rows = v.list_tombstones()
    assert any(t["origin_class"] == "principal" and t["key"] == "liked" for t in rows)
    v.close()


def test_control_own_snapshot_restore_keeps_person_verified_model_entry(tmp_path):
    """R2-A7 closed: a model entry a person verified round-trips verified through its own snapshot,
    with and without clear_existing."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=1)
    v.remember("decision", "d", "agent fact", origin="model")
    v.review_entity("decision", "d", verdict="verified", reviewer_id="alice", reviewer_origin="user")
    assert v.get("decision", "d").epistemic_state == "verified"
    snap = v.export_snapshot()
    assert v.import_snapshot(snap) == 1  # over the live reviewed row: no ReviewedEntryError
    e = v.get("decision", "d")
    assert e.epistemic_state == "verified" and e.origin == "model"
    assert v.import_snapshot(snap, clear_existing=True) == 1
    e = v.get("decision", "d")
    assert e.epistemic_state == "verified" and e.origin == "model" and e.metadata.get("human_reviews")
    v.close()


def test_control_older_own_snapshot_cannot_resurrect_a_rejected_value(tmp_path):
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=1)
    v.remember("decision", "d", "agent fact", origin="model")
    old = v.export_snapshot()
    v.review_entity("decision", "d", verdict="revoked", reviewer_id="alice", reviewer_origin="user")
    assert v.get("decision", "d") is None
    assert v.import_snapshot(old, clear_existing=True) == 0
    assert v.get("decision", "d") is None
    v.close()


def test_attack_older_own_snapshot_reverts_a_persons_dispute_to_verified(tmp_path):
    """Replay of the vault's own earlier snapshot over the live vault (no clear_existing): a person's
    later ``dispute`` verdict is overwritten by the older ``verified`` row, journaled as a routine
    restore. Documented restore semantics (library caller is trusted) - recorded as 'suspected /
    by design', the test only pins the behaviour."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=1)
    v.remember("decision", "d", "agent fact", origin="model")
    v.review_entity("decision", "d", verdict="verified", reviewer_id="alice", reviewer_origin="user")
    old = v.export_snapshot()
    v.review_entity("decision", "d", verdict="disputed", reviewer_id="alice", reviewer_origin="user")
    assert v.get("decision", "d").epistemic_state == "disputed"
    assert v.import_snapshot(old) == 1
    assert v.get("decision", "d").epistemic_state == "verified"
    v.close()
