"""K-R3, K-R4, K-R5: the recall layer.

``recall()`` sits on top of ``search()`` and is what model-facing callers use. It returns what was
recalled and an explicit receipt of what was not and why:

- K-R3 conflict isolation: two verified entries that conflict (an explicit ``conflicts_with`` edge or
  the same ``slot`` with different content) are both withheld as ``conflict_unresolved`` with their
  source ids; a person's review of either one resolves it.
- K-R4 store-size-aware gate: a hit is returned only if its matched-term coverage clears an absolute
  floor and, when there are enough matches to tell, its BM25 z-score among the matched set clears a
  threshold. The receipt carries ``n_store``, ``n_matched`` and each hit's z-score and coverage, so the
  gate's behaviour can be checked at any store size. Per-class ``ttl_seconds`` with
  ``last_verified_at`` withholds stale entries as ``stale``.
- K-R5 every recall observable: one Argus ``kibisis.memory_recall`` event per call, naming the
  channel, counts, and the ids withheld; a contradiction check at write time journals a
  ``contradiction`` event before anything else happens to the write.
"""

import json
import os
import random
import time

import pytest

from kibisis import EpistemicState, SQLiteMemoryVault
from kibisis.vault import RecallResult


@pytest.fixture(autouse=True)
def _no_live_ledger(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


def _verified(vault, cat, key, content, **kw):
    return vault.put(cat, key, content, origin="user", author_id="a", epistemic_state="verified", **kw)


# --- K-R3 conflict isolation -------------------------------------------------------------------


def test_recall_returns_a_recall_result_with_receipt(vault):
    _verified(vault, "fact", "k", "the gateway listens on port nine")
    out = vault.recall("gateway port", match="any")
    assert isinstance(out, RecallResult)
    assert [r.entity.key for r in out.results] == ["k"]
    assert out.withheld == []
    assert out.receipt["n_store"] == 1
    assert out.receipt["n_matched"] == 1
    assert out.receipt["n_returned"] == 1
    assert out.receipt["channel"] == "library"


def test_two_verified_entries_with_an_explicit_conflict_edge_are_both_withheld(vault):
    _verified(vault, "fact", "a", "the office is in austin texas")
    _verified(vault, "fact", "b", "the office is in dallas texas", conflicts_with=["fact:a"])
    out = vault.recall("office texas", match="any")
    assert out.results == []
    kinds = {(w.ref, w.reason) for w in out.withheld}
    assert kinds == {("fact:a", "conflict_unresolved"), ("fact:b", "conflict_unresolved")}
    by_ref = {w.ref: w for w in out.withheld}
    assert by_ref["fact:a"].sources == ["fact:b"]
    assert by_ref["fact:b"].sources == ["fact:a"]
    assert out.receipt["n_withheld_conflict"] == 2


def test_conflict_edge_is_symmetric_in_metadata(vault):
    _verified(vault, "fact", "a", "x")
    _verified(vault, "fact", "b", "y", conflicts_with=["fact:a"])
    assert vault.get("fact", "a").metadata["conflicts_with"] == ["fact:b"]
    assert vault.get("fact", "b").metadata["conflicts_with"] == ["fact:a"]


def test_a_candidate_conflicting_with_a_verified_entry_does_not_suppress_it(vault):
    # Only two VERIFIED entries in conflict are withheld. A model cannot suppress a person's verified
    # entry by writing a conflicting candidate; the candidate itself is still returned, labeled.
    _verified(vault, "fact", "a", "the office is in austin texas")
    vault.put("fact", "b", "the office is in dallas texas", origin="model", conflicts_with=["fact:a"])
    out = vault.recall("office texas", match="any")
    assert {r.entity.key for r in out.results} == {"a", "b"}
    assert out.withheld == []


def test_same_slot_different_content_is_a_conflict(vault):
    _verified(vault, "profile", "p1", "prefers dark mode", metadata={"slot": "theme"})
    _verified(vault, "profile", "p2", "prefers light mode", metadata={"slot": "theme"})
    out = vault.recall("prefers mode", match="any")
    assert out.results == []
    assert {w.reason for w in out.withheld} == {"conflict_unresolved"}


def test_review_of_one_side_resolves_the_conflict(vault):
    _verified(vault, "fact", "a", "the office is in austin texas")
    _verified(vault, "fact", "b", "the office is in dallas texas", conflicts_with=["fact:a"])
    vault.review_entity("fact", "b", verdict="revoked", reviewer_id="r")
    out = vault.recall("office texas", match="any")
    assert [r.entity.key for r in out.results] == ["a"]
    assert out.withheld == []


def test_conflicting_pair_is_not_leaked_through_the_withheld_list(vault):
    _verified(vault, "fact", "a", "secret office location austin")
    _verified(vault, "fact", "b", "secret office location dallas", conflicts_with=["fact:a"])
    out = vault.recall("secret office", match="any")
    for w in out.withheld:
        assert "austin" not in json.dumps(w.model_dump()) and "dallas" not in json.dumps(w.model_dump())


# --- K-R5 contradiction check at write ---------------------------------------------------------


def test_contradiction_is_journaled_at_write_before_anything_else(vault):
    _verified(vault, "fact", "a", "x")
    _verified(vault, "fact", "b", "y", conflicts_with=["fact:a"])
    events = vault.list_audit_events()
    actions = [ev.action for ev in events]
    i_contra = actions.index("contradiction")
    i_put_b = max(i for i, ev in enumerate(events) if ev.action == "put" and ev.key == "b")
    assert i_contra < i_put_b
    assert events[i_contra].metadata["with"] == ["fact:a"]


def test_conflict_edge_to_a_missing_entry_is_refused(vault):
    with pytest.raises(ValueError):
        vault.put("fact", "b", "y", origin="user", conflicts_with=["fact:nope"])


# --- K-R4 store-size-aware gate -----------------------------------------------------------------


_WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa "
          "quebec romeo sierra tango uniform victor whiskey xray yankee zulu").split()


def _fill(vault, n, seed=7):
    rng = random.Random(seed)
    for i in range(n):
        # Every filler entry shares the word "alpha" with the probe queries and nothing else of theirs.
        words = "alpha " + " ".join(rng.choice(_WORDS[1:]) for _ in range(7))
        vault.put("noise", f"n{i}", words, origin="user", author_id="a", epistemic_state="verified")


@pytest.mark.parametrize("n", [8, 64, 512])
def test_false_accepts_stay_flat_across_store_size(vault, n):
    # The query shares one common word with many entries and nothing else: nothing should be returned,
    # at any N. A fixed absolute threshold lets false accepts climb with N; the gate must not.
    _fill(vault, n)
    out = vault.recall("alpha mainframe reactor", match="any", limit=10)
    assert out.receipt["n_store"] == n
    assert out.results == [], [r.entity.content for r in out.results]
    assert out.receipt["n_withheld_gate"] == out.receipt["n_matched"]


@pytest.mark.parametrize("n", [8, 64, 512])
def test_the_one_real_answer_is_returned_at_any_store_size(vault, n):
    _fill(vault, n)
    _verified(vault, "fact", "real", "the mainframe reactor coolant valve is alpha seven")
    out = vault.recall("mainframe reactor coolant", match="any", limit=10)
    assert [r.entity.key for r in out.results] == ["real"]
    hit = next(h for h in out.receipt["hits"] if h["ref"] == "fact:real")
    assert hit["coverage_bp"] == 10000
    assert hit["kept"] is True


def test_receipt_carries_z_scores_and_n_as_integers(vault):
    _fill(vault, 32)
    _verified(vault, "fact", "real", "the mainframe reactor coolant valve")
    out = vault.recall("mainframe reactor coolant", match="any")
    r = out.receipt
    assert isinstance(r["n_store"], int) and isinstance(r["n_matched"], int)
    for h in r["hits"]:
        assert isinstance(h["coverage_bp"], int)
        assert h["z_bp"] is None or isinstance(h["z_bp"], int)
        assert set(h) >= {"ref", "coverage_bp", "z_bp", "kept"}
    assert r["gate"] == {"min_coverage_bp": r["gate"]["min_coverage_bp"], "z_max_bp": r["gate"]["z_max_bp"]}


def test_gate_can_be_tuned_per_call(vault):
    _fill(vault, 16)
    out = vault.recall("alpha", match="any", min_coverage_bp=0, z_max_bp=100000)
    assert out.results  # gate off: the common word matches
    out = vault.recall("alpha", match="any")
    assert out.results == []  # default gate: a one-word query that matches a crowd is not an answer


def test_ttl_by_origin_class_withholds_stale_entries(vault):
    old = time.time() - 10 * 86400
    vault.put("fact", "fresh", "reactor coolant valve note", origin="model")
    vault.put("fact", "stale", "reactor coolant valve older note", origin="model",
              metadata={"last_verified_at": old})
    out = vault.recall("reactor coolant valve", match="any", ttl_seconds={"agent": 7 * 86400})
    assert {r.entity.key for r in out.results} == {"fresh"}
    stale = [w for w in out.withheld if w.reason == "stale"]
    assert [w.ref for w in stale] == ["fact:stale"]
    assert out.receipt["n_withheld_stale"] == 1


def test_ttl_does_not_apply_to_classes_not_named(vault):
    old = time.time() - 10 * 86400
    vault.put("fact", "p", "reactor coolant valve person note", origin="user", metadata={"last_verified_at": old})
    out = vault.recall("reactor coolant valve", match="any", ttl_seconds={"agent": 7 * 86400})
    assert [r.entity.key for r in out.results] == ["p"]


def test_a_review_refreshes_last_verified_at(vault):
    vault.put("fact", "k", "reactor coolant valve note", origin="model")
    before = time.time()
    e = vault.review_entity("fact", "k", verdict="verified", reviewer_id="r")
    assert e.metadata["last_verified_at"] >= before


# --- K-R5 every recall observable -------------------------------------------------------------


def test_every_recall_emits_one_argus_event(vault, monkeypatch, tmp_path):
    ledger = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(ledger))
    pytest.importorskip("argus_ledger")
    _verified(vault, "fact", "a", "the office is in austin texas")
    _verified(vault, "fact", "b", "the office is in dallas texas", conflicts_with=["fact:a"])
    vault.recall("office texas", match="any", channel="mcp")
    vault.recall("nothing here matches", match="any", channel="prefetch")
    lines = [json.loads(l) for l in ledger.read_text().splitlines()]
    recalls = [l for l in lines if l["event_type"] == "kibisis.memory_recall"]
    assert len(recalls) == 2
    p = recalls[0]["payload"]
    assert p["channel"] == "mcp"
    assert p["n_store"] == 2 and p["n_matched"] == 2 and p["n_returned"] == 0
    assert p["n_withheld_conflict"] == 2
    assert sorted(p["withheld"]) == ["fact:a", "fact:b"]
    assert "query_sha256_12" in p and len(p["query_sha256_12"]) == 12
    assert "office" not in json.dumps(p)  # the query text itself is not in the ledger
    for v in p.values():  # Argus payloads: ints and strings only
        assert isinstance(v, (int, str)) or (isinstance(v, list) and all(isinstance(x, str) for x in v))
    assert recalls[1]["payload"]["channel"] == "prefetch"
    assert recalls[1]["payload"]["n_returned"] == 0


def test_recall_without_argus_is_still_observable_in_process(vault):
    _verified(vault, "fact", "a", "the office is in austin texas")
    vault.recall("office", match="any")
    recent = vault.recent_recalls()
    assert len(recent) == 1
    assert recent[0]["channel"] == "library"
    assert recent[0]["n_returned"] == 1


def test_recall_does_not_write_to_the_vault_journal(vault):
    # A read must not take the write lock (a prefetch under another connection's BEGIN IMMEDIATE
    # has to return) and must not move the audit head that write-invalidated caches follow.
    _verified(vault, "fact", "a", "the office is in austin texas")
    before = [ev.sequence for ev in vault.list_audit_events()]
    vault.recall("office", match="any")
    after = [ev.sequence for ev in vault.list_audit_events()]
    assert after == before


def test_recall_returns_while_another_connection_holds_the_write_lock(tmp_path):
    db = str(tmp_path / "v.sqlite")
    a = SQLiteMemoryVault(db, auto_gate=False, verification_quorum=1)
    _verified(a, "fact", "k", "the office is in austin texas")
    b = SQLiteMemoryVault(db, auto_gate=False)
    b._conn.execute("BEGIN IMMEDIATE")
    try:
        t0 = time.time()
        out = a.recall("office texas", match="any")
        assert time.time() - t0 < 1.0
        assert [r.entity.key for r in out.results] == ["k"]
    finally:
        b._conn.execute("ROLLBACK")
        b.close()
        a.close()


# --- K-R5 contrast edges for confusables ---------------------------------------------------------


def test_contrast_edge_is_symmetric_and_both_sides_are_returned_with_the_edge(vault):
    _verified(vault, "fact", "k11", "the k11 is the desktop dac on the desk")
    _verified(vault, "fact", "btr17", "the btr17 is the portable dac in the bag", contrasts_with=["fact:k11"])
    assert vault.get("fact", "k11").metadata["contrasts_with"] == ["fact:btr17"]
    out = vault.recall("dac", match="any")
    assert {r.entity.key for r in out.results} == {"k11", "btr17"}
    hits = {h["ref"]: h for h in out.receipt["hits"]}
    assert hits["fact:k11"]["contrasts_with"] == ["fact:btr17"]
    assert hits["fact:btr17"]["contrasts_with"] == ["fact:k11"]


def test_contrast_edge_to_a_missing_entry_is_refused(vault):
    with pytest.raises(ValueError):
        vault.put("fact", "b", "y", origin="user", contrasts_with=["fact:nope"])
