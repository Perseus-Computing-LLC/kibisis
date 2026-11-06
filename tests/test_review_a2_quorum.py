"""A2 quorum: every route by which one account could reach ``KIBISIS_VERIFICATION_QUORUM``, as fixed.

Each test asserts the SECURE behaviour: the route is closed. Controls sit beside each route. The attester
of a user-origin act is the operating-system account running the process (``kibisis._operator``), so the
tests read that account once and compare against it; ``reviewer_id`` / ``author_id`` are labels.

Run: cd <worktree> && ARGUS_LEDGER_PATH=$TMPDIR/argus_a2.jsonl PYTHONPATH=src <venv>/python -m pytest -q -p no:cacheprovider tests/test_review_a2_quorum.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from kibisis import EpistemicState, KibisisMCPServer, SQLiteMemoryVault
from kibisis._operator import account_identity
from kibisis.config import ConfigError
from kibisis.vault import ReviewedEntryError

KEY = "review-a2 test key only, not a secret"
ME = account_identity()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        monkeypatch.delenv(name)


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False)  # the DEFAULT quorum, 2; not the suite's usual quorum=1
    assert v.verification_quorum == 2
    yield v
    v.close()


def _call(server, tool, arguments):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


# --- (a) admit + review by the same account: closed -----------------------------------------------------


def test_a_same_reviewer_id_twice_is_one_attestation(vault):
    """admit then review from one process is one attestation (the account), whatever labels are typed."""
    vault.remember("c", "k", "fact", origin="model")
    vault.admit("c", "k", reviewer="acct", reviewer_origin="user")
    e = vault.review_entity("c", "k", "verified", reviewer_id="acct", reviewer_label="other label")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == [ME]
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


# --- (b) principal writes: author_id is a label; the account attests, once ---------------------------------


def test_b_two_user_writes_with_different_author_ids_are_one_attestation(vault):
    """F7 fixed: ``put(origin="user", epistemic_state="verified")`` attests as the account running the
    process, not as ``author_id``. Two writes from one process with two author strings are one attestation."""
    e1 = vault.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
    assert e1.epistemic_state == EpistemicState.CANDIDATE and e1.metadata["attestations"] == [ME]
    e2 = vault.put("c", "k", "fact", origin="user", author_id="bob", epistemic_state="verified")
    assert e2.epistemic_state == EpistemicState.CANDIDATE
    assert e2.metadata["attestations"] == [ME]
    assert e2.metadata["verification_pending"] == {"have": 1, "need": 2}
    assert e2.metadata["author_id"] == "bob"  # the label is kept; it just does not sign


def test_b_user_write_with_no_author_id_attests_as_the_account_not_the_literal_principal(vault):
    """F7 fixed: the literal ``"principal"`` is never a signer."""
    e = vault.put("c", "k", "fact", origin="user", epistemic_state="verified")
    assert e.metadata["attestations"] == [ME]
    e = vault.review_entity("c", "k", "verified", reviewer_id="acct")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == [ME]


def test_b_explicit_attester_needs_trust_caller_identity(tmp_path):
    """``attester=`` is an embedder's door: refused on a vault opened without ``trust_caller_identity=True``;
    on one opened with it, two named accounts reach the quorum, and 'principal' / '' are refused."""
    with pytest.raises(ValueError):
        SQLiteMemoryVault(":memory:", auto_gate=False).put(
            "c", "k", "fact", origin="user", epistemic_state="verified", attester="alice"
        )
    v = SQLiteMemoryVault(":memory:", auto_gate=False, trust_caller_identity=True)
    try:
        e = v.put("c", "k", "fact", origin="user", epistemic_state="verified", attester="alice")
        assert e.metadata["attestations"] == ["alice"]
        for bad in ("principal", "", "  "):
            with pytest.raises(ValueError):
                v.put("c", "k", "fact", origin="user", epistemic_state="verified", attester=bad)
        e = v.review_entity("c", "k", "verified", reviewer_id="bob", attester="bob")
        assert e.epistemic_state == EpistemicState.VERIFIED
        assert e.metadata["attestations"] == ["alice", "bob"]
        assert e.metadata["quorum_at_verification"] == 2
    finally:
        v.close()


def test_b_origin_less_rewrite_of_a_principal_row_does_not_attest_again(vault):
    """A rewrite that states no origin is not a person's act: it attests nothing, and the row keeps the
    attestation it had (the account, once) rather than becoming a verified-and-capped contradiction."""
    vault.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
    e = vault.put("c", "k", "fact", epistemic_state="verified", author_id="mallory")  # origin omitted
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == [ME]
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


def test_b_control_model_and_tool_writes_never_attest(vault):
    """Positive control: a non-principal write asking for verified is capped and signs nothing."""
    for origin in ("model", "tool", "unknown"):
        e = vault.put("c", f"k-{origin}", "fact", origin=origin, author_id="x", epistemic_state="verified")
        assert e.epistemic_state == EpistemicState.CANDIDATE
        assert "attestations" not in e.metadata
        assert e.metadata["trust_capped_from"] == "verified"


# --- (c) --reviewer labels: closed in the CLI (covered by test_atlas_limits_20261105); library label never counts


def test_c_reviewer_label_never_counts(vault):
    """``reviewer_label`` is recorded beside ``reviewer_id`` and ignored by the quorum."""
    vault.remember("c", "k", "fact", origin="model")
    vault.review_entity("c", "k", "verified", reviewer_id="acct", reviewer_label="alice")
    e = vault.review_entity("c", "k", "verified", reviewer_id="acct", reviewer_label="bob")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == [ME]
    assert [r["reviewer_label"] for r in e.metadata["human_reviews"]] == ["alice", "bob"]


# --- (d) snapshot import: attestations in a foreign file are dropped ----------------------------------------


def _snapshot_of_one_candidate(tmp_path):
    src = SQLiteMemoryVault(":memory:", auto_gate=False)
    src.remember("c", "k", "fact", origin="model")
    path = tmp_path / "snap.json"
    src.export_snapshot(str(path))
    src.close()
    return path


def test_d_snapshot_import_drops_forged_attestations_so_one_approval_does_not_mint_verified(vault, tmp_path):
    """F7 fixed: an ``attestations`` list in a snapshot that is not this vault's (no manifest here, and a
    plaintext source has no seal this vault can check) is dropped on import; the next approval is 1 of 2."""
    path = _snapshot_of_one_candidate(tmp_path)
    data = json.loads(path.read_text())
    data["entities"][0]["metadata"]["attestations"] = ["ghost"]
    data.pop("manifest_sha256", None)
    path.write_text(json.dumps(data))
    assert vault.import_snapshot(str(path)) == 1
    assert "attestations" not in vault.get("c", "k").metadata
    e = vault.review_entity("c", "k", "verified", reviewer_id="real-person")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == [ME]
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


def test_d_control_one_approval_on_an_unforged_import_stays_candidate(vault, tmp_path):
    """Positive control: the same snapshot without the forged list needs two approvals."""
    path = _snapshot_of_one_candidate(tmp_path)
    assert vault.import_snapshot(str(path)) == 1
    e = vault.review_entity("c", "k", "verified", reviewer_id="real-person")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


def test_d_snapshot_import_drops_forged_human_reviews_so_the_entry_is_not_locked_against_the_agent(vault, tmp_path):
    """F7 fixed: a forged ``human_reviews`` list does not survive import, so ``_is_reviewed`` is false, a
    model-origin rewrite of the imported candidate is allowed, and recall reports no reviewer."""
    path = _snapshot_of_one_candidate(tmp_path)
    data = json.loads(path.read_text())
    data["entities"][0]["metadata"]["human_reviews"] = [
        {"timestamp": 1.0, "reviewer_id": "ghost", "verdict": "verified", "notes": "", "previous_state": "candidate", "reviewer_origin": "user"}
    ]
    data.pop("manifest_sha256", None)
    path.write_text(json.dumps(data))
    vault.import_snapshot(str(path))
    assert "human_reviews" not in vault.get("c", "k").metadata
    vault.remember("c", "k", "a correction", origin="model")
    server = KibisisMCPServer(vault=vault, scope="default")
    _, text = _call(server, "kibisis_recall", {"query": "correction"})
    assert "ghost" not in text, text


def test_d_snapshot_round_trip_keeps_a_legitimately_verified_entry(tmp_path):
    """F11 fixed: the snapshot carries ``origin`` and ``author_id``, and a restore into the same vault (its
    digest key, manifest intact) keeps a verified principal entry verified and principal."""
    db = str(tmp_path / "v.db")
    v = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=1)
    try:
        v.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
        assert v.get("c", "k").epistemic_state == EpistemicState.VERIFIED
        path = tmp_path / "snap.json"
        v.export_snapshot(str(path))
        assert v.purge("c", "k", origin="user") is True
        v.import_snapshot(str(path))
        e = v.get("c", "k")
        assert e.epistemic_state == EpistemicState.VERIFIED
        assert e.origin == "user" and e.metadata["origin_class"] == "principal"
        assert e.metadata["author_id"] == "alice" and e.metadata["attestations"] == [ME]
        assert "trust_capped_from" not in e.metadata
    finally:
        v.close()


def test_d_snapshot_restore_into_another_vault_keeps_the_class_but_not_the_verdict(tmp_path):
    """F7 + F11: a restore into a vault with another passphrase keeps origin/author (the trust class) but
    re-derives the state without the attestations it cannot check: candidate, principal, capped."""
    src = SQLiteMemoryVault(str(tmp_path / "a.db"), passphrase=KEY, auto_gate=False, verification_quorum=1)
    src.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
    path = tmp_path / "snap.json"
    src.export_snapshot(str(path))
    src.close()
    dst = SQLiteMemoryVault(str(tmp_path / "b.db"), passphrase="another " + KEY, auto_gate=False, verification_quorum=1)
    try:
        dst.import_snapshot(str(path))
        e = dst.get("c", "k")
        assert e.epistemic_state == EpistemicState.CANDIDATE
        assert e.origin == "user" and e.metadata["origin_class"] == "principal"
        assert e.metadata["trust_capped_from"] == "verified"
        assert "attestations" not in e.metadata
    finally:
        dst.close()


# --- (e) OKF import: closed for the quorum (model origin, reserved keys dropped) -------------------------------


def test_e_okf_importer_writes_are_model_origin_and_drop_reserved_keys(vault):
    """The importer's ``_write`` calls ``put`` with ``origin="model"`` and plain ``metadata``, so
    ``attestations`` cannot ride in."""
    from kibisis.okf import importer

    assert importer._ORIGIN == "model"
    e = vault.put("c", "k", "fact", origin="model", author_id=importer.IMPORTER_ID,
                  metadata={"attestations": ["ghost1", "ghost2"], "human_reviews": [{"reviewer_id": "ghost"}], "okf_extra": {}})
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert "attestations" not in e.metadata and "human_reviews" not in e.metadata


# --- (f) KIBISIS_VERIFICATION_QUORUM: stored in the vault; a lower open is refused --------------------------------


def test_f_quorum_is_stored_and_a_lower_open_is_refused(tmp_path):
    """F7 fixed: the quorum is persisted in ``vault_meta`` on first open. A process asking for a LOWER
    quorum than stored gets ``ConfigError``; a higher one is allowed and stored; a verified entry
    records ``quorum_at_verification``."""
    db = str(tmp_path / "v.db")
    strict = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=2)
    strict.remember("c", "k", "fact", origin="model")
    strict.close()
    with pytest.raises(ConfigError):
        SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=1)
    higher = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=3)
    assert higher.verification_quorum == 3
    higher.close()
    with pytest.raises(ConfigError):
        SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=2)
    again = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=3)
    e = again.review_entity("c", "k", "verified", reviewer_id="solo")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["verification_pending"] == {"have": 1, "need": 3}
    again.close()


def test_f_quorum_one_vault_records_the_quorum_at_verification(tmp_path):
    db = str(tmp_path / "v.db")
    v = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=1)
    v.remember("c", "k", "fact", origin="model")
    e = v.review_entity("c", "k", "verified", reviewer_id="solo")
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert e.metadata["quorum_at_verification"] == 1 and e.metadata["attestations"] == [ME]
    v.close()


@pytest.mark.parametrize("value,expected", [("1", 1), (" 1 ", 1), ("3", 3)], ids=["one", "padded", "three"])
def test_f_env_quorum_values_accepted(monkeypatch, value, expected):
    """Whitespace is stripped; a plain positive decimal is the quorum."""
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", value)
    v = SQLiteMemoryVault(":memory:", auto_gate=False)
    assert v.verification_quorum == expected


@pytest.mark.parametrize("value", ["0", "-1", "abc", "2.0", "", "1_0"], ids=["zero", "negative", "text", "float", "empty", "underscore"])
def test_f_env_quorum_values_are_refused_with_a_config_error(monkeypatch, value):
    """F7 fixed: a non-positive, non-integer or digit-separated value is a ``ConfigError`` (not a
    ``ValueError`` traceback); ``1_0`` is not accepted as ten."""
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", value)
    with pytest.raises(ConfigError):
        SQLiteMemoryVault(":memory:", auto_gate=False)


def test_f_review_cli_list_refuses_cleanly_on_a_bad_quorum_value(tmp_path):
    """F7 fixed: ``kibisis.review list`` exits 2 with a one-line refusal, not a traceback."""
    env = {
        **os.environ, "PYTHONPATH": os.pathsep.join(sys.path), "ARGUS_LEDGER_PATH": "",
        "KIBISIS_DB_PATH": str(tmp_path / "v.db"), "KIBISIS_PASSPHRASE": KEY, "KIBISIS_SCOPE": "p",
        "KIBISIS_VERIFICATION_QUORUM": "abc",
    }
    r = subprocess.run([sys.executable, "-m", "kibisis.review", "list"], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "Traceback" not in r.stderr
    assert "KIBISIS_VERIFICATION_QUORUM" in r.stderr


# --- (g) reviewer_id passed directly ---------------------------------------------------------------------------


def test_g_review_entity_counts_accounts_not_strings(vault):
    """F7 fixed: the quorum counts attesting accounts; two ``reviewer_id`` strings from one process are one."""
    vault.remember("c", "k", "fact", origin="model")
    vault.review_entity("c", "k", "verified", reviewer_id="x1")
    e = vault.review_entity("c", "k", "verified", reviewer_id="x2")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == [ME]
    assert [r["reviewer_id"] for r in e.metadata["human_reviews"]] == ["x1", "x2"]


def test_g_review_entity_with_reviewer_id_none_records_nothing(vault):
    """F9 fixed: ``reviewer_id=None`` is a ``ValueError``; no review is recorded, the entry is not locked."""
    vault.remember("c", "k", "fact", origin="model")
    with pytest.raises(ValueError):
        vault.review_entity("c", "k", "verified", reviewer_id=None)
    e = vault.get("c", "k")
    assert "human_reviews" not in e.metadata and e.epistemic_state == EpistemicState.CANDIDATE
    vault.remember("c", "k", "replacement", origin="model")


@pytest.mark.parametrize("verdict", ["verified", "disputed", "revoked"])
def test_g_review_entity_refuses_every_non_principal_reviewer_origin(vault, verdict):
    """F8 fixed: any ``reviewer_origin`` other than ``user`` is a ``PermissionError`` for every verdict."""
    vault.remember("c", "k", "fact", origin="model")
    for origin in ("model", "tool", "import", "unknown"):
        with pytest.raises(PermissionError):
            vault.review_entity("c", "k", verdict, reviewer_id="x", reviewer_origin=origin)
    e = vault.get("c", "k")
    assert e.epistemic_state == EpistemicState.CANDIDATE and "human_reviews" not in e.metadata


def test_g_control_mcp_exposes_no_review_admit_or_put_with_origin_user(vault):
    """Positive control: the MCP surface is remember/recall/forget/verify_ledger/health; its
    writes are model-origin and authority arguments are refused, so an MCP-only agent has no quorum route."""
    server = KibisisMCPServer(vault=vault, scope="default")
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"kibisis_remember", "kibisis_recall", "kibisis_forget", "kibisis_verify_ledger", "kibisis_health"}
    for forged in ({"epistemic_state": "verified"}, {"author_id": "alice"}, {"reviewer_id": "alice"}, {"verdict": "verified"}):
        is_error, text = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "fact", **forged})
        assert is_error, text
    is_error, _ = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "fact",
                                                      "metadata": {"attestations": ["a", "b"], "human_reviews": [{}]}})
    assert not is_error
    e = vault.get("c", "k")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert "attestations" not in e.metadata and "human_reviews" not in e.metadata
