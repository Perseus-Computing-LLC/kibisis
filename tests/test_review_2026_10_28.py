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


# K-09: a stored iteration count is unauthenticated; bound it before paying for PBKDF2.


def test_envelope_iteration_count_is_bounded(monkeypatch):
    import pydantic

    from kibisis.crypto import AESGCMCryptoEnvelopeProvider
    from kibisis.models import EncryptedEnvelope

    provider = AESGCMCryptoEnvelopeProvider()
    envelope = provider.encrypt(b"x", PASSPHRASE)
    assert provider.decrypt(envelope, PASSPHRASE) == b"x"

    with pytest.raises(pydantic.ValidationError):
        EncryptedEnvelope.model_validate({**envelope.model_dump(), "iterations": 5_000_001})

    calls = []
    monkeypatch.setattr(provider, "_derive_key", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError))
    too_many = envelope.model_copy(update={"iterations": provider.MAX_ITERATIONS + 1})
    with pytest.raises(ValueError, match="iteration count"):
        provider.decrypt(too_many, PASSPHRASE)
    assert calls == []  # rejected before any key derivation

    # The default and twice the default are still accepted (older and future envelopes).
    assert provider.MAX_ITERATIONS == provider.ITERATIONS * 2
    assert EncryptedEnvelope.model_validate({**envelope.model_dump(), "iterations": provider.MAX_ITERATIONS}).iterations == provider.MAX_ITERATIONS


# K-07: lease TTLs are bounded and the holder gets a monotonic deadline of its own.


def test_lease_ttl_is_bounded_and_lease_carries_monotonic_deadline():
    from kibisis.lease import MAX_TTL_SECONDS, SQLiteLeaseCoordinator

    coord = SQLiteLeaseCoordinator(":memory:")
    for bad in (0, -1, MAX_TTL_SECONDS + 1):
        with pytest.raises(ValueError):
            coord.acquire("r", "holder", ttl_seconds=bad)
    lease = coord.acquire("r", "holder", ttl_seconds=MAX_TTL_SECONDS)
    assert lease.local_deadline is not None
    assert lease.local_deadline > time.monotonic()
    assert not lease.is_locally_expired and not lease.is_expired
    for bad in (0, MAX_TTL_SECONDS + 1):
        with pytest.raises(ValueError):
            coord.renew(lease, ttl_seconds=bad)
    before = lease.local_deadline
    assert coord.renew(lease, ttl_seconds=0.05)
    assert lease.local_deadline < before  # renew re-arms the holder's own deadline to the new TTL
    time.sleep(0.1)
    assert lease.is_locally_expired
    # A lease read back from the table was not acquired here, so it has no local deadline.
    assert coord.get_lease("r").local_deadline is None
    coord.close()


# K-03 / K-04: the journal hash covers metadata and field boundaries; the signed head anchors the tail.


def _journal_vault(tmp_path):
    v = SQLiteMemoryVault(str(tmp_path / "audit.sqlite"), passphrase=PASSPHRASE)
    for i in range(5):
        v.put("c", f"k{i}", f"value {i}", epistemic_state="verified")
    v.review_entity("c", "k1", "disputed", reviewer_id="alice")
    assert v.verify_audit_chain()
    return v


def test_event_hash_has_unambiguous_field_boundaries_and_covers_metadata():
    from kibisis.vault import JOURNAL_FORMAT, _event_hash

    assert JOURNAL_FORMAT == 3
    zero = "0" * 64
    assert _event_hash(1, 1.0, "put", "a:b", "c", "s", "", zero, None) != _event_hash(1, 1.0, "put", "a", "b:c", "s", "", zero, None)
    assert _event_hash(1, 1.0, "put", "a", "b", "s", "", zero, None, {"reviewer": "alice"}) != _event_hash(
        1, 1.0, "put", "a", "b", "s", "", zero, None, {"reviewer": "mallory"}
    )
    # The legacy layout is still reproducible for rows written under it.
    legacy = _event_hash(1, 1.0, "put", "a:b", "c", "s", "", zero, None, fmt=2)
    assert legacy == _event_hash(1, 1.0, "put", "a", "b:c", "s", "", zero, None, fmt=2)


def test_metadata_rewrite_fails_verification(tmp_path):
    v = _journal_vault(tmp_path)
    with v._conn:
        v._conn.execute(
            "UPDATE audit_journal SET metadata_json = ? WHERE action = 'state_transition'",
            ('{"reviewer":"mallory","forged":true}',),
        )
    assert not v.verify_audit_chain()
    v.close()


def test_tail_truncation_fails_verification(tmp_path):
    v = _journal_vault(tmp_path)
    with v._conn:
        v._conn.execute("DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
    assert not v.verify_audit_chain()
    v.close()


def test_removing_or_forging_the_head_fails_verification(tmp_path):
    v = _journal_vault(tmp_path)
    head = v._conn.execute("SELECT sequence, event_hash, mac FROM audit_head").fetchone()
    assert head is not None
    with v._conn:
        v._conn.execute("DELETE FROM audit_head")
    assert not v.verify_audit_chain()  # a format 3 journal must be anchored
    # Re-pointing the head at an earlier row without the signing key does not verify either.
    with v._conn:
        v._conn.execute("DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
        last = v._conn.execute("SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1").fetchone()
        v._conn.execute(
            "INSERT INTO audit_head (id, sequence, event_hash, mac) VALUES (1, ?, ?, ?)",
            (last["sequence"], last["event_hash"], "00" * 32),
        )
    assert not v.verify_audit_chain()
    v.close()


def test_legacy_format_rows_still_verify_and_new_rows_anchor(tmp_path):
    """A journal written by an older version has format 2 rows and no head; it verifies on its links,
    and the first new append anchors it."""
    from kibisis.vault import _event_hash

    v = _journal_vault(tmp_path)
    rows = v._conn.execute(
        "SELECT sequence, timestamp, action, category, key, scope, value_sha256, author_id FROM audit_journal ORDER BY sequence"
    ).fetchall()
    with v._conn:
        prev = "0" * 64
        for r in rows:  # rewrite the journal as an older version would have written it
            h = _event_hash(r["sequence"], r["timestamp"], r["action"], r["category"], r["key"], r["scope"],
                            r["value_sha256"], prev, r["author_id"], fmt=2)
            v._conn.execute(
                "UPDATE audit_journal SET prev_hash = ?, event_hash = ?, format = 2 WHERE sequence = ?",
                (prev, h, r["sequence"]),
            )
            prev = h
        v._conn.execute("DELETE FROM audit_head")
    assert v.verify_audit_chain()
    assert all(e.format == 2 for e in v.list_audit_events(limit=100))
    v.put("c", "new", "appended by the current version")
    events = v.list_audit_events(limit=100)
    assert events[-1].format == 3 and events[-2].format == 2
    assert v.verify_audit_chain()
    head = v._conn.execute("SELECT sequence, event_hash FROM audit_head").fetchone()
    assert (head["sequence"], head["event_hash"]) == (events[-1].sequence, events[-1].event_hash)
    # Tail truncation of the mixed journal is now detected too.
    with v._conn:
        v._conn.execute("DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
    assert not v.verify_audit_chain()
    v.close()
