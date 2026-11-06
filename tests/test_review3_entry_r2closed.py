"""R3: entry-point re-verification of the R2-A items that touch MCP/CLI paths (A1, A2, A6, A7) and
R2-C-2 (startup refusal). Controls only: failing = regression."""
from __future__ import annotations

import pytest

from kibisis.mcp_server import KibisisMCPServer
from kibisis.models import EpistemicState
from kibisis.vault import SQLiteMemoryVault

PASS = "review3-entry-passphrase"
V = "a value a person rejected"


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(tmp_path / "argus.jsonl"))
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    v = SQLiteMemoryVault(str(tmp_path / "v.sqlite"), passphrase=PASS, auto_gate=False, verification_quorum=1)
    try:
        yield v
    finally:
        v.close()


def _call(server, name, args):
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": name, "arguments": args}})
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


def _classes(vault):
    return [t.metadata.get("tombstone_class") or t.metadata.get("origin_class") for t in vault.list_tombstones()]


def test_control_r2a1_lower_class_retombstone_cannot_downgrade_a_persons_tombstone(vault):
    vault.put("c", "k", V, scope="default", origin="user", author_id="alice")
    vault.tombstone("c", "k", reason="no", author_id="alice", scope="default", origin="user")
    for origin in ("tool", "model"):
        try:
            vault.tombstone("c", "k", content=V, reason="again", author_id="x", scope="default", origin=origin)
        except Exception:
            pass
    server = KibisisMCPServer(vault=vault, scope="default")
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": V})
    assert err and "Refused" in text, text
    assert vault.get("c", "k", scope="default") is None
    # a person's own later write does not silently lift it either (principal tombstone needs `lift`)
    with pytest.raises(Exception):
        vault.put("c", "k", V, scope="default", origin="user", author_id="alice")


def test_control_r2a2_forgetting_a_bookkeeping_word_does_not_wedge_the_agent(vault):
    server = KibisisMCPServer(vault=vault, scope="default")
    for word in ("agent", "mcp", "inform", "model", "candidate", "mcp-agent"):
        err, text = _call(server, "kibisis_remember", {"category": "c", "key": "w-" + word, "content": word})
        assert not err, text
        err, text = _call(server, "kibisis_forget", {"category": "c", "key": "w-" + word})
        assert not err, text
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "next", "content": "an unrelated fact"})
    assert not err, text
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "next2", "content": "another fact",
                                                   "metadata": {"note": "x"}})
    assert not err, text


def test_control_r2a6_lift_tombstone_refuses_non_principal_origins(vault):
    server = KibisisMCPServer(vault=vault, scope="default")
    _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": V})
    _call(server, "kibisis_forget", {"category": "c", "key": "k"})
    assert vault.list_tombstones()
    for origin in ("model", "tool", "unknown"):
        with pytest.raises(Exception):
            vault.lift_tombstone("c", "k", scope="default", author_id="mcp-agent", origin=origin)
    assert vault.list_tombstones()
    assert vault.lift_tombstone("c", "k", scope="default", author_id="alice", origin="user") >= 1


def test_control_r2a7_person_verified_agent_entry_survives_its_own_snapshot(vault, tmp_path):
    server = KibisisMCPServer(vault=vault, scope="default")
    _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "agent fact"})
    e = vault.review_entity("c", "k", EpistemicState.VERIFIED.value, scope="default", reviewer_id="alice")
    assert e.epistemic_state == EpistemicState.VERIFIED
    snap = str(tmp_path / "snap.json")
    vault.export_snapshot(snap) if hasattr(vault, "export_snapshot") else vault.snapshot(snap)
    vault.import_snapshot(snap, clear_existing=True)
    e = vault.get("c", "k", scope="default")
    assert e is not None and e.epistemic_state == EpistemicState.VERIFIED, (e.epistemic_state, e.metadata)
    assert "trust_capped_from" not in (e.metadata or {})
    vault.import_snapshot(snap)  # over the live vault: no abort
    assert vault.get("c", "k", scope="default").epistemic_state == EpistemicState.VERIFIED


def test_control_r2c2_passphrase_without_sqlcipher_and_without_opt_in_refuses_at_startup(tmp_path, monkeypatch):
    import sqlite3

    import kibisis.vault as vault_module
    from kibisis.aml_adapter import AMLConfig, key_digest, storage_mode
    from kibisis.protocols import EncryptionRequiredError

    monkeypatch.delenv("KIBISIS_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
    config = AMLConfig(data_dir=str(tmp_path / "d"), key_sha256=key_digest("k"), passphrase=PASS)
    with pytest.raises(EncryptionRequiredError):
        storage_mode(config)
    monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    assert storage_mode(config) is False
