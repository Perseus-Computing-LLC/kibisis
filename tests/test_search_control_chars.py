"""A search query with control characters inside a word (U+0000 especially) must search, not fail.

Before the fix, a query word such as "data\\x00\\x00block" reached FTS5 as a quoted phrase that the query
parser stops reading at U+0000, so sqlite raised OperationalError("unterminated string") and the AML
adapter answered Search with 500. Found by a CL-bench question carrying a binary dump.
"""
import sqlite3

import pytest

import kibisis.vault as vault_module
from kibisis import SQLiteMemoryVault
from kibisis._vault_search import _search_terms
from kibisis.aml_adapter import AMLConfig, AMLService, key_digest

PASS = "control chars passphrase (test only)"
NUL_QUERY = "Which packet header \x04\x00\x00\x00 carried the payload\x00\x00checksum value?"


def _open(kind, path, monkeypatch):
    if kind == "fallback":
        monkeypatch.setattr(vault_module, "sqlcipher3", sqlite3)
        monkeypatch.setenv("KIBISIS_ALLOW_PLAINTEXT", "1")
    elif kind == "sqlcipher" and not vault_module._sqlcipher_available():
        pytest.skip("sqlcipher3 is not installed")
    if kind == "plain":
        return SQLiteMemoryVault(str(path), allow_plaintext=True, verification_quorum=1)
    return SQLiteMemoryVault(str(path), passphrase=PASS, verification_quorum=1)


def test_control_characters_separate_query_words():
    assert _search_terms("payload\x00\x00checksum", "any") == ["payload", "checksum"]
    assert _search_terms("a\x01b\x7fc header\x1bvalue", "all") == ["a", "b", "c", "header", "value"]
    assert all("\x00" not in t for t in _search_terms(NUL_QUERY, "any"))


@pytest.mark.parametrize("kind", ["plain", "sqlcipher", "fallback"])
@pytest.mark.parametrize("match", ["any", "all"])
def test_search_with_nul_in_query_returns_matches(tmp_path, monkeypatch, kind, match):
    vault = _open(kind, tmp_path / f"{kind}.db", monkeypatch)
    vault.put("m", "k1", "The payload checksum value was 0x1f in the packet header.", epistemic_state="verified",
              origin="user")
    vault.put("m", "k2", "Lunch is tacos on Friday.", epistemic_state="verified", origin="user")
    query = NUL_QUERY if match == "any" else "payload\x00checksum"
    hits = vault.search(query, category="m", limit=10, match=match)
    assert [h.entity.key for h in hits] == ["k1"]


def test_aml_search_with_nul_query_is_not_a_server_error(tmp_path):
    svc = AMLService(AMLConfig(data_dir=str(tmp_path / "vaults"), key_sha256=key_digest("k" * 32),
                               passphrase="aml control chars (test only)"))
    try:
        svc.add({"request_id": "r0", "user_id": "u", "session_id": "s", "messages": [
            {"role": "user", "timestamp": 1_704_067_200_000, "content": "The payload checksum was 0x1f."},
            {"role": "assistant", "timestamp": 1_704_067_260_000, "content": "Noted."}]})
        data = svc.search({"query": NUL_QUERY, "user_id": "u", "top_k": 100})["data"]
        assert len(data) == 1 and "checksum" in data[0]["content"]
    finally:
        svc.pool.close_all()
