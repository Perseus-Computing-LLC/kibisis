"""A2 quorum: every route by which one account reaches ``KIBISIS_VERIFICATION_QUORUM`` (kibisis 1299c28).

Each docstring says whether the test asserts INSECURE behaviour (passes = the route is open at this commit)
or SECURE behaviour (passes = the route is closed). Controls sit beside each route.

Run: cd <worktree> && ARGUS_LEDGER_PATH=$TMPDIR/argus_a2.jsonl PYTHONPATH=src <venv>/python -m pytest -q -p no:cacheprovider tests/review_a2_quorum.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from kibisis import EpistemicState, KibisisMCPServer, SQLiteMemoryVault
from kibisis.vault import ReviewedEntryError

KEY = "review-a2 test key only, not a secret"


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
    """SECURE behaviour (passes = closed): admit then review with the same ``reviewer_id`` stays 1 of 2."""
    vault.remember("c", "k", "fact", origin="model")
    vault.admit("c", "k", reviewer="acct", reviewer_origin="user")
    e = vault.review_entity("c", "k", "verified", reviewer_id="acct", reviewer_label="other label")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == ["acct"]
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


# --- (b) principal writes: author_id is free text and each distinct string is one attestation ----------------


def test_b_two_user_writes_with_different_author_ids_reach_quorum(vault):
    """INSECURE behaviour (passes = route open): ``put(origin="user", epistemic_state="verified")`` signs as
    ``author_id``, a free-text argument (vault.py:946-949). Two writes from one process with two strings are
    two attestations. No account lookup is involved on this path."""
    e1 = vault.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
    assert e1.epistemic_state == EpistemicState.CANDIDATE and e1.metadata["attestations"] == ["alice"]
    e2 = vault.put("c", "k", "fact", origin="user", author_id="bob", epistemic_state="verified")
    assert e2.epistemic_state == EpistemicState.VERIFIED
    assert e2.metadata["attestations"] == ["alice", "bob"]


def test_b_user_write_with_no_author_id_signs_as_the_literal_principal(vault):
    """INSECURE behaviour (passes = route open): with neither ``author_id`` nor ``principal_id`` the signer is
    the string ``"principal"`` (vault.py:947), which then counts as a person distinct from every real account."""
    e = vault.put("c", "k", "fact", origin="user", epistemic_state="verified")
    assert e.metadata["attestations"] == ["principal"]
    e = vault.review_entity("c", "k", "verified", reviewer_id="acct")
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert e.metadata["attestations"] == ["principal", "acct"]


def test_b_origin_less_rewrite_of_a_principal_row_adds_an_attestation_and_keeps_a_cap_marker(vault):
    """INSECURE behaviour (passes = route open): a rewrite that states no origin inherits the stored principal
    class (vault.py:894-895) and so attests as its new ``author_id``, although the pre-transaction check at
    vault.py:821-823 had already stamped ``trust_capped_from="verified"`` on it. Result: a verified entry that
    also says it was capped."""
    vault.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
    e = vault.put("c", "k", "fact", epistemic_state="verified", author_id="mallory")  # origin omitted
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert e.metadata["attestations"] == ["alice", "mallory"]
    assert e.metadata.get("trust_capped_from") == "verified"


def test_b_control_model_and_tool_writes_never_attest(vault):
    """Positive control (SECURE, passes): a non-principal write asking for verified is capped and signs nothing."""
    for origin in ("model", "tool", "unknown"):
        e = vault.put("c", f"k-{origin}", "fact", origin=origin, author_id="x", epistemic_state="verified")
        assert e.epistemic_state == EpistemicState.CANDIDATE
        assert "attestations" not in e.metadata
        assert e.metadata["trust_capped_from"] == "verified"


# --- (c) --reviewer labels: closed in the CLI (covered by test_atlas_limits_20261105); library label never counts


def test_c_reviewer_label_never_counts(vault):
    """SECURE behaviour (passes = closed): ``reviewer_label`` is recorded beside ``reviewer_id`` and ignored by the quorum."""
    vault.remember("c", "k", "fact", origin="model")
    vault.review_entity("c", "k", "verified", reviewer_id="acct", reviewer_label="alice")
    e = vault.review_entity("c", "k", "verified", reviewer_id="acct", reviewer_label="bob")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["attestations"] == ["acct"]
    assert [r["reviewer_label"] for r in e.metadata["human_reviews"]] == ["alice", "bob"]


# --- (d) snapshot import: attestations in the file are trusted ----------------------------------------------


def _snapshot_of_one_candidate(tmp_path):
    src = SQLiteMemoryVault(":memory:", auto_gate=False)
    src.remember("c", "k", "fact", origin="model")
    path = tmp_path / "snap.json"
    src.export_snapshot(str(path))
    src.close()
    return path


def test_d_snapshot_import_trusts_forged_attestations_so_one_real_approval_mints_verified(vault, tmp_path):
    """INSECURE behaviour (passes = route open): ``import_snapshot`` writes with ``_trusted_metadata=True``
    (_vault_snapshot.py:290), so an ``attestations`` list in the file is stored as if principals had signed. The
    import itself leaves the entry a candidate, but the next single approval reaches the quorum of 2."""
    path = _snapshot_of_one_candidate(tmp_path)
    data = json.loads(path.read_text())
    data["entities"][0]["metadata"]["attestations"] = ["ghost"]
    data.pop("manifest_sha256", None)  # a snapshot without a manifest is accepted; with one it is recomputed by the forger
    path.write_text(json.dumps(data))
    assert vault.import_snapshot(str(path)) == 1
    assert vault.get("c", "k").metadata["attestations"] == ["ghost"]
    e = vault.review_entity("c", "k", "verified", reviewer_id="real-person")
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert e.metadata["attestations"] == ["ghost", "real-person"]


def test_d_control_one_approval_on_an_unforged_import_stays_candidate(vault, tmp_path):
    """Positive control (SECURE, passes): the same snapshot without the forged list needs two approvals."""
    path = _snapshot_of_one_candidate(tmp_path)
    assert vault.import_snapshot(str(path)) == 1
    e = vault.review_entity("c", "k", "verified", reviewer_id="real-person")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["verification_pending"] == {"have": 1, "need": 2}


def test_d_snapshot_import_trusts_forged_human_reviews_which_lock_the_entry_against_the_agent(vault, tmp_path):
    """INSECURE behaviour (passes = route open): a forged ``human_reviews`` entry makes ``_is_reviewed`` true
    (vault.py:188-196), so a model-origin rewrite of the imported candidate is refused as if a person had
    reviewed it, and the MCP recall envelope reports ``reviewed_by`` for a review nobody made."""
    path = _snapshot_of_one_candidate(tmp_path)
    data = json.loads(path.read_text())
    data["entities"][0]["metadata"]["human_reviews"] = [
        {"timestamp": 1.0, "reviewer_id": "ghost", "verdict": "verified", "notes": "", "previous_state": "candidate", "reviewer_origin": "user"}
    ]
    data.pop("manifest_sha256", None)
    path.write_text(json.dumps(data))
    vault.import_snapshot(str(path))
    with pytest.raises(ReviewedEntryError):
        vault.remember("c", "k", "a correction", origin="model")
    server = KibisisMCPServer(vault=vault, scope="default")
    _, text = _call(server, "kibisis_recall", {"query": "fact"})
    assert 'reviewed_by="ghost"' in text, text


def test_d_snapshot_round_trip_demotes_a_legitimately_verified_entry(tmp_path):
    """Functional regression (passes = present): the snapshot carries no ``origin``, so ``import_snapshot``'s
    ``put`` runs with origin ``None`` -> class ``external`` -> the requested ``verified`` is capped
    (vault.py:821-823). A restore turns a verified principal entry into a candidate with
    ``trust_capped_from`` and origin ``unknown``. tests/test_cold_start_reload_integrity.py:25 never asserts the
    state after import, so this is not caught."""
    src = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    src.put("c", "k", "fact", origin="user", author_id="alice", epistemic_state="verified")
    assert src.get("c", "k").epistemic_state == EpistemicState.VERIFIED
    path = tmp_path / "snap.json"
    src.export_snapshot(str(path))
    dst = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    dst.import_snapshot(str(path))
    e = dst.get("c", "k")
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.origin == "unknown" and e.metadata["origin_class"] == "external"
    assert e.metadata["trust_capped_from"] == "verified"


# --- (e) OKF import: closed for the quorum (model origin, reserved keys dropped) -------------------------------


def test_e_okf_importer_writes_are_model_origin_and_drop_reserved_keys(vault):
    """SECURE behaviour (passes = closed): the importer's ``_write`` (okf/importer.py:405, :418) calls ``put`` with
    ``origin="model"`` and plain ``metadata`` (no ``_trusted_metadata``), so ``attestations`` cannot ride in."""
    from kibisis.okf import importer

    assert importer._ORIGIN == "model"
    e = vault.put("c", "k", "fact", origin="model", author_id=importer.IMPORTER_ID,
                  metadata={"attestations": ["ghost1", "ghost2"], "human_reviews": [{"reviewer_id": "ghost"}], "okf_extra": {}})
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert "attestations" not in e.metadata and "human_reviews" not in e.metadata


# --- (f) KIBISIS_VERIFICATION_QUORUM: read per process at open, never stored ---------------------------------------


def test_f_quorum_is_a_per_process_setting_not_a_vault_property(tmp_path):
    """INSECURE behaviour (passes = route open): the quorum is ``int(os.environ[...])`` at ``__init__``
    (vault.py:267-271) and nowhere in the file. A process that opens the same vault with quorum 1 mints
    ``verified`` with one approval, and a quorum-2 process reads it back as verified with no trace of which
    quorum minted it."""
    db = str(tmp_path / "v.db")
    strict = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=2)
    strict.remember("c", "k", "fact", origin="model")
    strict.close()
    lax = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=1)
    e = lax.review_entity("c", "k", "verified", reviewer_id="solo")
    assert e.epistemic_state == EpistemicState.VERIFIED
    lax.close()
    strict = SQLiteMemoryVault(db, passphrase=KEY, auto_gate=False, verification_quorum=2)
    e = strict.get("c", "k")
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert "verification_pending" not in e.metadata and e.metadata["attestations"] == ["solo"]
    strict.close()


@pytest.mark.parametrize("value,expected", [("1", 1), (" 1 ", 1), ("1_0", 10)], ids=["one", "padded", "underscore"])
def test_f_env_quorum_values_that_lower_or_change_the_quorum(monkeypatch, value, expected):
    """Behaviour pin (passes): ``int()`` accepts padding and digit separators; ``1`` lowers the quorum to one."""
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", value)
    v = SQLiteMemoryVault(":memory:", auto_gate=False)
    assert v.verification_quorum == expected


@pytest.mark.parametrize("value", ["0", "-1", "abc", "2.0", ""], ids=["zero", "negative", "text", "float", "empty"])
def test_f_env_quorum_values_that_crash_every_opener(monkeypatch, value):
    """INSECURE-adjacent behaviour (passes = present): a non-positive or non-integer value raises ``ValueError``
    out of ``SQLiteMemoryVault.__init__``; the MCP server and both CLIs do not catch it (review.py:106-111 catches
    ConfigError and EncryptionRequiredError only). Whoever sets the variable in the operator's environment
    denies review until it is unset."""
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", value)
    with pytest.raises(ValueError):
        SQLiteMemoryVault(":memory:", auto_gate=False)


def test_f_review_cli_list_crashes_with_a_traceback_on_a_bad_quorum_value(tmp_path):
    """INSECURE-adjacent behaviour (passes = present): ``kibisis.review list`` needs no terminal and exits 1 with
    a traceback, not a refusal message, when the variable is not an integer."""
    env = {
        **os.environ, "PYTHONPATH": os.pathsep.join(sys.path), "ARGUS_LEDGER_PATH": "",
        "KIBISIS_DB_PATH": str(tmp_path / "v.db"), "KIBISIS_PASSPHRASE": KEY, "KIBISIS_SCOPE": "p",
        "KIBISIS_VERIFICATION_QUORUM": "abc",
    }
    r = subprocess.run([sys.executable, "-m", "kibisis.review", "list"], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 1
    assert "Traceback" in r.stderr and "invalid literal for int()" in r.stderr


# --- (g) reviewer_id passed directly ---------------------------------------------------------------------------


def test_g_review_entity_counts_any_two_strings(vault):
    """INSECURE behaviour (passes = route open): the library quorum counts ``reviewer_id`` strings
    (_vault_review.py:474-479); the caller 'vouches'. Two calls from one process with two strings verify."""
    vault.remember("c", "k", "fact", origin="model")
    vault.review_entity("c", "k", "verified", reviewer_id="x1")
    e = vault.review_entity("c", "k", "verified", reviewer_id="x2")
    assert e.epistemic_state == EpistemicState.VERIFIED
    assert e.metadata["attestations"] == ["x1", "x2"]


def test_g_review_entity_with_reviewer_id_none_records_a_review_but_no_attestation(vault):
    """Behaviour pin (passes): ``reviewer_id=None`` appends a ``human_reviews`` record (which makes ``_is_reviewed``
    true and locks the entry against model rewrites) while attesting nothing: 0 of 2."""
    vault.remember("c", "k", "fact", origin="model")
    e = vault.review_entity("c", "k", "verified", reviewer_id=None)
    assert e.epistemic_state == EpistemicState.CANDIDATE
    assert e.metadata["verification_pending"] == {"have": 0, "need": 2}
    assert e.metadata["human_reviews"][0]["reviewer_id"] is None
    with pytest.raises(ReviewedEntryError):
        vault.remember("c", "k", "replacement", origin="model")


def test_g_control_mcp_exposes_no_review_admit_or_put_with_origin_user(vault):
    """Positive control (SECURE, passes): the MCP surface is remember/recall/forget/verify_ledger/health; its
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
    assert e.metadata["agent_metadata"] == {"attestations": ["a", "b"], "human_reviews": [{}]}
