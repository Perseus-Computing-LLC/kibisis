"""Review 2, area B: Python/Rust verifier agreement (R2-B8, R2-B9), PyO3 edge inputs, fencing tokens,
strict= coverage (R2-B6, R2-B7).

Regression tests converted from the review's repro file: ``test_attack_*`` assert the fixed behaviour.
"""

import json
import sqlite3
import threading

import pytest

import kibisis.vault as vault_module
native = pytest.importorskip("kibisis_native")
from kibisis import SQLiteMemoryVault
from kibisis._vault_audit import verify_journal_rows
from kibisis.models import AuditEvent

KEY = b"\x11" * 32
PASS = "review2-b native passphrase (test only)"


def _row(seq, prev, fmt=3, action="remember"):
    meta = "{}"
    h = native.event_hash_v3(seq, float(seq), action, "cat", f"k{seq}", "default", "d" * 64, prev, None, meta)
    return {"sequence": seq, "timestamp": float(seq), "action": action, "category": "cat", "key": f"k{seq}",
            "scope": "default", "value_sha256": "d" * 64, "prev_hash": prev, "event_hash": h, "author_id": None,
            "metadata_json": meta, "format": fmt}


def _chain(n):
    rows, prev = [], "0" * 64
    for i in range(1, n + 1):
        r = _row(i, prev)
        rows.append(r)
        prev = r["event_hash"]
    head = {"sequence": n, "event_hash": prev, "mac": native.head_mac_v1(KEY, n, prev)}
    return rows, head


def _events(rows):
    return [AuditEvent(**{**r, "metadata": json.loads(r.pop("metadata_json"))}) for r in [dict(r) for r in rows]]


def test_control_python_and_rust_agree_on_sound_chain():
    rows, head = _chain(3)
    assert native.verify_chain(rows, head, KEY, True) is None
    assert verify_journal_rows(_events(rows), head, KEY, format_floor=3, head_required=True) is None


def test_attack_python_and_rust_both_refuse_a_row_labelled_format_4():
    """R2-B8: a row relabelled format 4 (the hash unchanged) is refused by the crate (UnsupportedFormat)
    and by the Python verifier alike: the format column is pinned upward as well as downward."""
    rows, head = _chain(3)
    rows[1]["format"] = 4
    rust = native.verify_chain(rows, head, KEY, True)
    assert rust is not None and "format 4" in rust
    python = verify_journal_rows(_events(rows), head, KEY, format_floor=3, head_required=True)
    assert python is not None and "format 4" in python


def test_control_rust_binding_edge_inputs_raise_python_errors_not_panics():
    rows, head = _chain(1)
    bad = dict(rows[0]); bad["format"] = 256
    with pytest.raises((OverflowError, ValueError, TypeError)):
        native.verify_chain([bad], head, KEY, True)
    bad = dict(rows[0]); bad["sequence"] = 2 ** 64
    with pytest.raises((OverflowError, ValueError, TypeError)):
        native.verify_chain([bad], head, KEY, True)
    bad = dict(rows[0]); bad["timestamp"] = float("nan")
    with pytest.raises(ValueError):
        native.verify_chain([bad], head, KEY, True)
    with pytest.raises((TypeError, KeyError)):
        native.verify_chain([{}], head, KEY, True)
    with pytest.raises((TypeError, KeyError)):
        native.verify_chain(rows, {"sequence": 1}, KEY, True)


def test_control_fencing_tokens_survive_state_deletion_and_two_coordinators(tmp_path):
    d = tmp_path / "leases"
    a = native.FileLeaseCoordinator(str(d))
    b = native.FileLeaseCoordinator(str(d))
    l1 = a.acquire("doc", "h1", 1.0)
    a.release(l1)
    l2 = b.acquire("doc", "h2", 1.0)
    assert l2.fencing_token > l1.fencing_token
    b.release(l2)
    for f in d.glob("*.lease"):
        f.unlink()
    l3 = a.acquire("doc", "h3", 1.0)
    assert l3.fencing_token > l2.fencing_token
    a.release(l3)
    # concurrent issue from many threads: all tokens distinct and increasing
    tokens, lock = [], threading.Lock()

    def worker(i):
        c = native.FileLeaseCoordinator(str(d))
        while True:
            try:
                lease = c.acquire("doc", f"t{i}", 60.0)
                break
            except native.LeaseConflict:
                continue
        with lock:
            tokens.append(lease.fencing_token)
        c.release(lease)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(set(tokens)) == 12 and min(tokens) > l3.fencing_token


def test_control_ttl_out_of_range_is_value_error():
    c = native.FileLeaseCoordinator(str(__import__("tempfile").mkdtemp()))
    for ttl in (0.0, -1.0, float("inf"), float("nan"), 1e300):
        with pytest.raises(ValueError):
            c.acquire("r", "h", ttl)


@pytest.fixture
def _no_sqlcipher(monkeypatch):
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    monkeypatch.setattr(vault_module, "_sqlcipher_available", lambda: False)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")


def test_attack_forget_requests_counts_bad_signature_rows_and_honours_strict(_no_sqlcipher, tmp_path):
    """R2-B6: ``forget_requests`` counts an entry that fails its integrity check in integrity_failures
    and raises under strict=True, like the other read paths. R2-B7: strict=True does not make the OPEN
    raise through the term index; the bad row is left queued and the first read that touches the index
    raises for it."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "a person note", origin="user", author_id="person")
    v.record_refusal(path="mcp", reason="reviewed_entry", scope="default", category="decision", key="k",
                     detail={"tool": "kibisis_forget"})  # how a refused MCP forget becomes a request
    assert len(v.forget_requests("default")) == 1
    v.close()
    c = sqlite3.connect(str(p))
    c.execute("UPDATE entities SET tenant_sig = 'bad' WHERE key='k'")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, strict=True)  # opens (term index on)
    try:
        assert v.integrity_failures["count"] == 1  # counted at open, not raised
        with pytest.raises(vault_module.EntryIntegrityError):
            v.search("person note")  # the first read through the index raises for the queued row
        with pytest.raises(vault_module.EntryIntegrityError):
            v.forget_requests("default")
    finally:
        v.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False, strict=True, term_index=False)
    try:
        with pytest.raises(vault_module.EntryIntegrityError):
            v.forget_requests("default")
        assert v.integrity_failures["count"] >= 1
    finally:
        v.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        before = v.integrity_failures["count"]
        assert v.forget_requests("default") == []  # left out, not raised
        assert v.integrity_failures["count"] == before + 1  # but counted
    finally:
        v.close()


def test_attack_verify_audit_chain_returns_false_on_malformed_metadata_json(_no_sqlcipher, tmp_path):
    """R2-B9: a file writer replaces metadata_json with non-JSON: verify_audit_chain returns False with
    last_chain_error set instead of raising JSONDecodeError."""
    p = tmp_path / "v.sqlite"
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    v.remember("decision", "k", "x", origin="user")
    v.close()
    c = sqlite3.connect(str(p))
    c.execute("UPDATE audit_journal SET metadata_json = 'not json' WHERE sequence = 1")
    c.commit(); c.close()
    v = SQLiteMemoryVault(str(p), passphrase=PASS, auto_gate=False)
    try:
        assert v.verify_audit_chain() is False
        assert "unreadable metadata_json" in (v.last_chain_error or "")
    finally:
        v.close()
