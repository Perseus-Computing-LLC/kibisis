"""Journal format 3 vectors: the file tests/fixtures/journal_format3_vectors.json is shared with the Rust
suite (tests/journal_vectors.rs). Here every vector is re-derived with the Python reference functions, and
the chain vector is used to show that a truncated tail, a mid-chain edit or a missing head fails."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

import pytest

from kibisis.vault import JOURNAL_FORMAT, SQLiteMemoryVault, _event_hash, _head_mac

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "journal_format3_vectors.json")
GENERATOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "make_journal_vectors.py")


@pytest.fixture(scope="module")
def vectors() -> Dict[str, Any]:
    with open(VECTORS, encoding="utf-8") as f:
        return json.load(f)


def _ids(path: str) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return [e["name"] for e in json.load(f)["events"]]


def test_vector_file_header(vectors):
    assert vectors["journal_format"] == JOURNAL_FORMAT == 3
    assert vectors["head_mac_domain"] == "kibisis audit head v1:"
    assert len(vectors["events"]) >= 12
    names = [e["name"] for e in vectors["events"]]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("name", _ids(VECTORS))
def test_event_hash_and_head_mac_rederive(vectors, name):
    v = next(e for e in vectors["events"] if e["name"] == name)
    key = bytes.fromhex(v["signing_key_hex"])
    got = _event_hash(
        v["sequence"], v["timestamp"], v["action"], v["category"], v["key"], v["scope"], v["value_sha256"],
        v["prev_hash"], v["author_id"], v["metadata"], fmt=JOURNAL_FORMAT,
    )
    assert got == v["event_hash"]
    assert _head_mac(key, v["sequence"], got) == v["head_mac"]
    # The recorded intermediates are the canonical forms the Rust side must reproduce byte for byte.
    canonical = json.dumps(v["metadata"] or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert canonical == v["metadata_canonical"]
    assert hashlib.sha256(v["payload"].encode("utf-8")).hexdigest() == v["event_hash"]
    assert json.loads(v["payload"])[9] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    mac_payload = b"kibisis audit head v1:" + json.dumps([v["sequence"], got], separators=(",", ":")).encode()
    assert hmac.new(key, mac_payload, hashlib.sha256).hexdigest() == v["head_mac"]


def test_colon_join_ambiguity_is_resolved(vectors):
    by_name = {e["name"]: e for e in vectors["events"]}
    a = by_name["colon_fields_are_unambiguous"]
    b = by_name["colon_fields_are_unambiguous_shifted"]
    assert ":".join([a["category"], a["key"]]) == ":".join([b["category"], b["key"]])
    assert a["event_hash"] != b["event_hash"]


# --- the chain vector: links, head, tail cut, mid-chain edit ----------------------------------------------


def _verify_chain(events: List[Dict[str, Any]], head: Optional[Dict[str, Any]], key: bytes) -> bool:
    """The verification rule of SQLiteMemoryVault.verify_audit_chain, applied to plain rows.

    Mirrors kibisis::journal::verify_chain in the crate: every link and hash, then a signed head that
    must name the last row. A format 3 journal without a head does not verify.
    """
    expected_prev = "0" * 64
    for ev in events:
        if ev["prev_hash"] != expected_prev:
            return False
        recomputed = _event_hash(
            ev["sequence"], ev["timestamp"], ev["action"], ev["category"], ev["key"], ev["scope"],
            ev["value_sha256"], ev["prev_hash"], ev["author_id"], ev["metadata"], fmt=ev["format"],
        )
        if not hmac.compare_digest(recomputed, ev["event_hash"]):
            return False
        expected_prev = ev["event_hash"]
    anchored = any(ev["format"] >= 3 for ev in events)
    if head is None:
        return not anchored
    if not hmac.compare_digest(_head_mac(key, head["sequence"], head["event_hash"]), head["mac"]):
        return False
    if not events:
        return False
    return head["sequence"] == events[-1]["sequence"] and head["event_hash"] == events[-1]["event_hash"]


def test_chain_vector_verifies(vectors):
    c = vectors["chain"]
    key = bytes.fromhex(c["signing_key_hex"])
    assert len(c["events"]) == 5
    assert all(e["format"] == 3 for e in c["events"])
    assert _verify_chain(c["events"], c["head"], key)
    assert c["head"]["mac"] == _head_mac(key, c["head"]["sequence"], c["head"]["event_hash"])


def test_chain_vector_tail_cut_fails(vectors):
    c = vectors["chain"]
    key = bytes.fromhex(c["signing_key_hex"])
    assert not _verify_chain(c["events"][:-1], c["head"], key)  # one row removed from the tail
    assert not _verify_chain(c["events"][:-2], c["head"], key)
    assert not _verify_chain([], c["head"], key)  # every row removed, head left behind
    assert not _verify_chain(c["events"], None, key)  # head removed
    # Re-pointing the head at the new last row needs the signing key.
    cut = c["events"][:-1]
    forged = {"sequence": cut[-1]["sequence"], "event_hash": cut[-1]["event_hash"], "mac": "00" * 32}
    assert not _verify_chain(cut, forged, key)
    assert not _verify_chain(cut, forged, b"not the key")
    resigned = dict(forged, mac=_head_mac(key, forged["sequence"], forged["event_hash"]))
    assert _verify_chain(cut, resigned, key)  # with the key, a shorter journal can be re-anchored


def test_chain_vector_mid_chain_edit_fails(vectors):
    c = vectors["chain"]
    key = bytes.fromhex(c["signing_key_hex"])
    for field, value in (("key", "k9"), ("author_id", "mallory"), ("metadata", {"reviewer": "mallory"}),
                         ("value_sha256", "f" * 64), ("timestamp", c["events"][2]["timestamp"] + 1)):
        edited = [dict(e) for e in c["events"]]
        edited[2][field] = value
        assert not _verify_chain(edited, c["head"], key), field


def test_vault_tail_cut_fails_on_a_live_journal(tmp_path):
    """The same tail cut against a real vault file, so the vector rule matches the shipped verifier."""
    v = SQLiteMemoryVault(str(tmp_path / "v.sqlite"), allow_plaintext=True)
    for i in range(3):
        v.put("c", f"k{i}", f"value {i}")
    assert v.verify_audit_chain()
    with v._conn:
        v._conn.execute("DELETE FROM audit_journal WHERE sequence = (SELECT MAX(sequence) FROM audit_journal)")
    assert not v.verify_audit_chain()
    v.close()


def test_generator_reproduces_committed_vectors(tmp_path):
    """The committed file is exactly what the generator writes from this source tree."""
    out = tmp_path / "regen.json"
    subprocess.run([sys.executable, GENERATOR, str(out)], check=True, capture_output=True)
    with open(VECTORS, encoding="utf-8") as a, open(out, encoding="utf-8") as b:
        assert json.load(a) == json.load(b)
