"""Regression tests for the 2026-10-28 review findings (K-01, K-02, K-05, K-06, K-07, K-09).

Each test reproduces the probe that found the bug, so a regression shows up as the original failure
rather than as a tautology about the new code.
"""
import os
import stat
import threading
import time

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.models import EpistemicState

# An explicit passphrase keeps these tests independent of KIBISIS_PASSPHRASE(_FILE) in the environment.
PASSPHRASE = "review-2026-10-28-test-passphrase"


# K-01: the tombstone gate must run under the write lock.


def test_tombstone_cannot_land_between_check_and_insert(tmp_path):
    """Connection B tombstones a value while connection A is paused between its tombstone check and
    its INSERT. A takes BEGIN IMMEDIATE before the check, so B blocks until A commits and B's purge
    then removes A's copy: the forbidden value is never readable afterwards."""
    path = str(tmp_path / "race.sqlite")
    a = SQLiteMemoryVault(path, passphrase=PASSPHRASE)
    b = SQLiteMemoryVault(path, passphrase=PASSPHRASE)
    try:
        # Seed one tombstone so the gate calls _find_tombstone on every write.
        b.put("c", "seed", "unrelated seed")
        b.tombstone("c", "seed", reason="seed")
        b.put("c", "victim", "forbidden value")

        checked = threading.Event()
        resume = threading.Event()
        original = SQLiteMemoryVault._find_tombstone

        def paused_find(cursor, scope, val_hash, can_hash):
            result = original(cursor, scope, val_hash, can_hash)
            checked.set()
            resume.wait(10)
            return result

        errors = {}

        def writer():
            try:
                a.put("c", "copy", "forbidden value")
            except Exception as exc:  # noqa: BLE001 - recorded for the assertion below
                errors["a"] = exc

        def tombstoner():
            try:
                b.tombstone("c", "victim", reason="forget it")
            except Exception as exc:  # noqa: BLE001
                errors["b"] = exc

        SQLiteMemoryVault._find_tombstone = staticmethod(paused_find)
        try:
            t_a = threading.Thread(target=writer)
            t_a.start()
            assert checked.wait(10), "writer never reached the tombstone check"
            t_b = threading.Thread(target=tombstoner)
            t_b.start()
            # B is now waiting on A's write lock (or, if the fix were absent, has already committed).
            time.sleep(0.5)
            resume.set()
            t_a.join(30)
            t_b.join(30)
        finally:
            SQLiteMemoryVault._find_tombstone = staticmethod(original)

        assert not t_a.is_alive() and not t_b.is_alive()
        assert "b" not in errors, errors
        assert b.is_tombstoned("c", "copy", "forbidden value")
        # The invariant under test: a rejected value never stays readable.
        assert a.get("c", "copy") is None
        assert b.get("c", "copy") is None
        assert b.get("c", "victim") is None
    finally:
        a.close()
        b.close()


def test_write_tx_rolls_back_on_error_and_nests():
    v = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    with pytest.raises(RuntimeError):
        with v._write_tx() as cursor:
            cursor.execute("INSERT INTO vault_meta (key, value) VALUES ('probe', X'00')")
            raise RuntimeError("abort")
    assert v._conn.execute("SELECT COUNT(*) FROM vault_meta WHERE key = 'probe'").fetchone()[0] == 0
    assert not v._conn.in_transaction
    with v._write_tx() as outer:
        assert v._conn.in_transaction
        with v._write_tx() as inner:  # nested: no second BEGIN, no early commit
            inner.execute("INSERT INTO vault_meta (key, value) VALUES ('probe', X'00')")
        assert v._conn.in_transaction
        outer.execute("INSERT INTO vault_meta (key, value) VALUES ('probe2', X'00')")
    assert not v._conn.in_transaction
    assert v._conn.execute("SELECT COUNT(*) FROM vault_meta WHERE key LIKE 'probe%'").fetchone()[0] == 2


def test_tombstone_still_refuses_sequentially():
    v = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    v.put("c", "k", "a rejected value")
    v.tombstone("c", "k", reason="retracted")
    with pytest.raises(ValueError):
        v.put("c", "other", "a rejected value")
    assert v.list_audit_events(limit=100)[-1].action == "refuse"
    assert v.verify_audit_chain()


# K-02: provenance must survive every read path, not only get().


def _provenance(entity):
    return (entity.origin, entity.source_ref, entity.confidence)


@pytest.mark.parametrize("passphrase", [None, PASSPHRASE])
def test_search_list_and_put_report_the_same_provenance_as_get(tmp_path, passphrase):
    if passphrase is None:
        v = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    else:
        v = SQLiteMemoryVault(str(tmp_path / "prov.sqlite"), passphrase=passphrase)
    written = v.put(
        "c", "k", "tabs for indentation", origin="user", source_ref="ticket-7", confidence=0.9,
        epistemic_state="verified",
    )
    got = v.get("c", "k")
    assert _provenance(got) == ("user", "ticket-7", 0.9)
    assert _provenance(written) == _provenance(got)
    hits = v.search("indentation")
    assert hits and hits[0].entity.origin == got.origin
    assert _provenance(hits[0].entity) == _provenance(got)
    listed = v.list_entities()
    assert len(listed) == 1 and _provenance(listed[0]) == _provenance(got)
    # A re-write that gives no provenance keeps the stored one on every path.
    rewritten = v.put("c", "k", "tabs for indentation, always", epistemic_state="verified")
    assert _provenance(rewritten) == ("user", "ticket-7", 0.9)
    assert _provenance(v.search("indentation")[0].entity) == ("user", "ticket-7", 0.9)
    assert _provenance(v.list_entities()[0]) == ("user", "ticket-7", 0.9)
    v.close()


# K-05: a snapshot holds decrypted content and must be owner-only on disk.


def test_export_snapshot_file_is_owner_only_and_cleans_up(tmp_path, monkeypatch):
    v = SQLiteMemoryVault(str(tmp_path / "enc.sqlite"), passphrase=PASSPHRASE)
    v.put("c", "k", "secret-ish content", epistemic_state="verified")
    old = os.umask(0o000)  # the mode must come from the create call, not from the process umask
    try:
        out = tmp_path / "snap.json"
        v.export_snapshot(out)
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        assert "secret-ish content" in out.read_text(encoding="utf-8")
        assert not list(tmp_path.glob("snap.tmp.*"))

        # A failure while serialising leaves no temp file behind and no partial snapshot.
        broken = tmp_path / "broken.json"
        monkeypatch.setattr("kibisis.vault.json.dump", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        with pytest.raises(RuntimeError):
            v.export_snapshot(broken)
        assert not broken.exists()
        assert not list(tmp_path.glob("broken.tmp.*"))
    finally:
        os.umask(old)
        v.close()


# K-06: a caller cannot write the metadata the vault uses as evidence of a person's review.


def test_caller_supplied_human_reviews_does_not_count_as_reviewed(caplog):
    from kibisis.vault import RESERVED_METADATA_KEYS, _is_reviewed

    v = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    forged = {
        "human_reviews": [{"reviewer_id": "nobody", "verdict": "verified"}],
        "tenant_id": "forged-tenant",
        "principal_id": "forged-principal",
        "lineage_root": "forged",
        "note": "kept",
    }
    stored = v.put("c", "forged", "some fact", metadata=forged, epistemic_state="candidate", origin="tool")
    assert set(stored.metadata) == {"note"}
    assert set(v.get("c", "forged").metadata) == {"note"}
    assert "dropped reserved metadata keys" in caplog.text
    row = v._conn.execute("SELECT epistemic_state, metadata_json FROM entities WHERE key = 'forged'").fetchone()
    assert not _is_reviewed(row)
    # The forgery has no effect: a model write may still replace the candidate.
    v.put("c", "forged", "model rewrite", origin="model")
    assert v.get("c", "forged").content == "model rewrite"

    # The vault's own review path still records the review, and it then does protect the entry.
    reviewed = v.review_entity("c", "forged", "verified", reviewer_id="alice")
    assert reviewed.metadata["human_reviews"][-1]["reviewer_id"] == "alice"
    from kibisis.vault import ReviewedEntryError

    with pytest.raises(ReviewedEntryError):
        v.put("c", "forged", "model rewrite again", origin="model")
    assert "human_reviews" in RESERVED_METADATA_KEYS


def test_snapshot_round_trip_keeps_review_history_and_tenant(tmp_path):
    src = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    src.put("c", "k", "a fact", tenant_id="acme", epistemic_state="candidate")
    src.review_entity("c", "k", "verified", reviewer_id="alice")
    snap = src.export_snapshot()
    dst = SQLiteMemoryVault(":memory:", allow_plaintext=True)
    dst.import_snapshot(snap)
    got = dst.get("c", "k")
    assert got.metadata["tenant_id"] == "acme"
    assert got.metadata["human_reviews"][-1]["reviewer_id"] == "alice"
