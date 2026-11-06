"""Review 3, area A+B seams: snapshot trust (R2-A7 / F7d / F11 after the merge; R3-AB3, R3-AB6).
``test_control_*`` = secure behaviour; ``test_attack_*`` = the round-3 scenario, asserting the FIXED
(or, for R3-AB6, the documented) behaviour.
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
    """R3-AB3 fixed. ``same_vault`` used to be ``digest_key_id == own or seal opens``; the id is a
    16-hex public label in every export, so a hand-built snapshot (id copied, no seal, self-computed
    manifest) was taken for the vault's own. Now only the trust seal proves it: the forged trust facts
    are dropped, the model entry arrives candidate, and the forged principal tombstone is capped at the
    importer's class (here ``origin="model"`` → agent), so the person's own write of the value lifts it."""
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
    assert v.import_snapshot(snap, origin="model") == 1
    e = v.get("decision", "forged")
    assert e.epistemic_state == "candidate" and e.metadata.get("trust_capped_from") == "verified"
    assert "attestations" not in e.metadata and "human_reviews" not in e.metadata
    rows = v.list_tombstones()
    assert [(t["key"], t["origin_class"]) for t in rows] == [("liked", "agent")]
    refusals = [ev for ev in v.list_audit_events(limit=100) if ev.action == "refuse"]
    assert any("tombstone classes capped" in ev.metadata.get("reason", "") for ev in refusals)
    # An agent-class tombstone yields to the person's own write; a planted principal one would not.
    v.remember("decision", "liked", "a value the person likes", origin="user", author_id="alice")
    assert v.list_tombstones() == []
    v.close()
    _open_again = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)  # journal reconciles
    assert _open_again.verify_audit_chain() is True
    _open_again.close()


def test_control_r3ab3_vouching_importer_caps_a_forged_tombstone_at_its_own_class(tmp_path):
    """With no ``origin`` the caller vouches for a person (as on ``tombstone``): a forged principal
    tombstone is then the importer's own principal rejection, which is what the import asked for."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    key_id = v.export_snapshot()["digest_key_id"]
    plain_exact = hashlib.sha256("x".encode()).hexdigest()
    snap = _forged_snapshot(key_id, tombstones=[{
        "category": "c", "key": "k", "value_sha256": plain_exact, "canonical_sha256": "",
        "scope": "default", "origin_class": "principal", "reason": "forged",
    }])
    assert v.import_snapshot(snap) == 0
    assert [t["origin_class"] for t in v.list_tombstones()] == ["principal"]
    v.close()


def test_control_r3ab3_seal_lifted_from_a_genuine_export_does_not_cover_added_tombstones(tmp_path):
    """The seal names the entities AND the tombstones of the export. A file built from a genuine
    export (seal and entities kept, a principal tombstone appended, manifest recomputed) fails the
    seal: trust facts drop and the tombstone is capped."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=1)
    v.remember("decision", "d", "agent fact", origin="model")
    v.review_entity("decision", "d", verdict="verified", reviewer_id="alice", reviewer_origin="user")
    snap = v.export_snapshot()
    assert snap["trust_seal"]
    snap["tombstones"].append({
        "category": "decision", "key": "liked", "value_sha256": hashlib.sha256(b"liked").hexdigest(),
        "canonical_sha256": "", "scope": "default", "origin_class": "principal", "reason": "forged",
        "sealed_digests": None,
    })
    snap.pop("manifest_sha256")
    snap["manifest_sha256"] = _manifest(snap)
    assert v.import_snapshot(snap, clear_existing=True, origin="model") == 1
    e = v.get("decision", "d")
    assert e.epistemic_state == "candidate" and "human_reviews" not in e.metadata
    assert [t["origin_class"] for t in v.list_tombstones()] == ["agent"]
    v.close()


def test_control_r3ab3_entities_only_seal_keeps_trust_facts_but_caps_tombstones(tmp_path):
    """A seal written before tombstones were covered (plaintext = entities digest) still vouches for
    the entities' trust facts; tombstone classes from such a file are capped."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, verification_quorum=1)
    v.remember("decision", "d", "agent fact", origin="model")
    v.review_entity("decision", "d", verdict="verified", reviewer_id="alice", reviewer_origin="user")
    snap = v.export_snapshot()
    snap["tombstones"] = [{
        "category": "decision", "key": "liked", "value_sha256": hashlib.sha256(b"liked").hexdigest(),
        "canonical_sha256": "", "scope": "default", "origin_class": "principal", "reason": "old export",
        "sealed_digests": None,
    }]
    legacy_plain = v._entities_digest(snap["entities"]).encode("ascii")
    from kibisis._vault_snapshot import _TRUST_SEAL_AAD
    snap["trust_seal"] = v.crypto_provider.encrypt(legacy_plain, PASS, aad=_TRUST_SEAL_AAD).model_dump_json()
    snap.pop("manifest_sha256")
    snap["manifest_sha256"] = _manifest(snap)
    assert v._trust_seal_level(snap) == "entities"
    assert v.import_snapshot(snap, clear_existing=True, origin="model") == 1
    e = v.get("decision", "d")
    assert e.epistemic_state == "verified" and e.metadata.get("human_reviews")
    assert [t["origin_class"] for t in v.list_tombstones()] == ["agent"]
    v.close()


def test_control_r3ab3_same_passphrase_vault_keeps_trust_facts_and_tombstone_classes(tmp_path):
    """The seal is the proof: another file under the same passphrase (different salt, different
    digest_key_id) opens it and keeps verdicts and principal tombstones."""
    a = SQLiteMemoryVault(str(tmp_path / "a.sqlite"), passphrase=PASS, auto_gate=False, verification_quorum=1)
    a.remember("decision", "d", "agent fact", origin="model")
    a.review_entity("decision", "d", verdict="verified", reviewer_id="alice", reviewer_origin="user")
    a.remember("decision", "bad", "deploy on fridays", origin="user", author_id="alice")
    a.tombstone("decision", "bad", reason="no", author_id="alice", origin="user")
    snap = a.export_snapshot()
    a.close()
    b = SQLiteMemoryVault(str(tmp_path / "b.sqlite"), passphrase=PASS, auto_gate=False, verification_quorum=1)
    assert snap["digest_key_id"] != b.export_snapshot()["digest_key_id"]
    assert b.import_snapshot(snap, origin="model") == 1
    e = b.get("decision", "d")
    assert e.epistemic_state == "verified" and e.metadata.get("human_reviews")
    assert [t["origin_class"] for t in b.list_tombstones()] == ["principal"]
    b.close()


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
    """R3-AB6 (by design, documented): replay of the vault's own earlier snapshot over the live vault
    (no clear_existing) is a point-in-time replay of the reviews too: a person's later ``dispute``
    verdict is overwritten by the older ``verified`` row. The test pins the documented behaviour; a
    later rejection still wins (previous test)."""
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
