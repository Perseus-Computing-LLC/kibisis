"""Second-pass review (R2, area A) — snapshot trust facts, quorum/attesters, review doors, cascade,
metadata keys, review CLI.

Run by explicit path. ``test_control_*`` asserts the SECURE behaviour (failing = bug);
``test_attack_*`` demonstrates a defect (PASSING = bug). See review_notes/R2_A.md.
"""

import os
import sqlite3
import subprocess
import sys

import pytest

from kibisis import KibisisMCPServer, SQLiteMemoryVault
from kibisis.config import ConfigError
from kibisis.vault import OriginClassError, ReviewedEntryError, TombstonedValueError

VALUE = "Deploys go out on Tuesdays."
PY = sys.executable


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM", raising=False)
    # file-backed vaults below are plain on purpose (allow_plaintext); keep the shell's passphrase out
    monkeypatch.delenv("KIBISIS_PASSPHRASE", raising=False)
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)


def _plain(path, **kw):
    kw.setdefault("auto_gate", False)
    return SQLiteMemoryVault(path, allow_plaintext=True, **kw)


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


@pytest.fixture
def server(vault):
    return KibisisMCPServer(vault=vault, scope="default")


def _call(server, tool, arguments):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


# ----------------------------------------------------------------------------------------------
# F11 / F7(d): snapshot round trip
# ----------------------------------------------------------------------------------------------


def test_control_f11_user_verified_entry_round_trips_verified_and_principal(vault):
    vault.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    snap = vault.export_snapshot()
    vault.import_snapshot(snap, clear_existing=True)
    e = vault.get("c", "k")
    assert (e.origin, e.metadata.get("origin_class"), e.epistemic_state.value) == ("user", "principal", "verified")


def test_control_f7d_foreign_snapshot_attestations_are_dropped(tmp_path):
    a = SQLiteMemoryVault(str(tmp_path / "a.sqlite"), passphrase="passphrase-for-vault-a", auto_gate=False, verification_quorum=2)
    a.put("c", "k", VALUE, origin="user", epistemic_state="verified", metadata={})
    snap = a.export_snapshot()
    # forge: say two accounts attested
    for ent in snap["entities"]:
        ent["metadata"]["attestations"] = ["ghost", "ghost2"]
        ent["epistemic_state"] = "verified"
    snap.pop("manifest_sha256", None)
    a.close()
    b = SQLiteMemoryVault(str(tmp_path / "b.sqlite"), passphrase="passphrase-for-vault-b", auto_gate=False, verification_quorum=2)
    b.import_snapshot(snap)
    e = b.get("c", "k")
    assert e.epistemic_state.value == "candidate"
    assert "attestations" not in e.metadata
    b.close()


def test_attack_f11_person_verified_agent_entry_is_demoted_by_its_own_vaults_snapshot(vault, server):
    """R2-A7 (passing = bug). The common MCP case: an agent candidate a person approved. The
    snapshot is this vault's (same digest_key_id, manifest verifies) so trust facts are kept, but
    ``import_snapshot`` passes ``origin='model'`` and ``_put`` sets ``trust_ceiling`` for every
    model-origin write BEFORE it looks at ``_review_verdict`` (vault.py L1135, L1191): the entry comes
    back ``candidate`` with ``trust_capped_from='verified'`` while still carrying ``human_reviews`` and
    ``attestations``. F11 is closed for user-origin rows only."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.review_entity("c", "k", "verified", reviewer_id="alice")
    assert vault.get("c", "k").epistemic_state.value == "verified"
    snap = vault.export_snapshot()
    assert vault.import_snapshot(snap, clear_existing=True) == 1
    e = vault.get("c", "k")
    assert e.metadata.get("human_reviews") and e.metadata.get("attestations")  # trust facts were kept...
    assert e.epistemic_state.value == "candidate"  # ...but the state they support was not
    assert e.metadata.get("trust_capped_from") == "verified"


def test_attack_f11_restoring_own_snapshot_over_the_live_vault_aborts_on_a_person_verified_agent_entry(vault, server):
    """R2-A7 variant (passing = bug). Same cause: the capped write hits the live reviewed row and
    ``_put`` raises ``ReviewedEntryError`` (L1370), so ``import_snapshot`` without ``clear_existing``
    aborts part-way (tombstones already committed, earlier entities already written)."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.review_entity("c", "k", "verified", reviewer_id="alice")
    snap = vault.export_snapshot()
    with pytest.raises(ReviewedEntryError):
        vault.import_snapshot(snap)


# ----------------------------------------------------------------------------------------------
# F7: attesters and quorum
# ----------------------------------------------------------------------------------------------


def test_control_f7_user_writes_with_different_author_ids_are_one_attestation(tmp_path):
    v = _plain(str(tmp_path / "q.sqlite"), verification_quorum=2)
    v.put("c", "k", VALUE, origin="user", epistemic_state="verified", author_id="alice")
    v.put("c", "k", VALUE, origin="user", epistemic_state="verified", author_id="bob")
    e = v.get("c", "k")
    assert e.epistemic_state.value == "candidate"
    assert len(e.metadata.get("attestations") or []) == 1
    with pytest.raises(ValueError):
        v.put("c", "k", VALUE, origin="user", epistemic_state="verified", attester="carol")
    with pytest.raises(ValueError):
        v.review_entity("c", "k", "verified", reviewer_id="x", attester="principal")
    v.close()


def test_control_f7_quorum_cannot_be_lowered_and_is_adopted_when_unnamed(tmp_path, monkeypatch):
    p = str(tmp_path / "q.sqlite")
    v = _plain(p, verification_quorum=3)
    v.close()
    with pytest.raises(ConfigError):
        _plain(p, verification_quorum=2)
    monkeypatch.setenv("KIBISIS_VERIFICATION_QUORUM", "1")
    with pytest.raises(ConfigError):
        _plain(p)
    monkeypatch.delenv("KIBISIS_VERIFICATION_QUORUM")
    v = _plain(p)
    assert v.verification_quorum == 3
    v.close()


def test_attack_stored_quorum_is_not_under_the_vault_meta_mac(tmp_path):
    """R2-A8 (passing = bug; file-writer, plain-file vaults). ``verification_quorum`` is persisted
    in ``vault_meta`` but is not in ``VAULT_META_BOUND_KEYS``; on a vault whose file is plain SQLite
    a file writer lowers it to 1 and the next unnamed open adopts it, so one attestation mints
    ``verified``. (With SQLCipher active the file is encrypted and this needs the passphrase; the
    other trust-deciding meta values ARE bound by ``meta_mac``.)"""
    from kibisis.crypto import VAULT_META_BOUND_KEYS

    assert "verification_quorum" not in VAULT_META_BOUND_KEYS
    p = str(tmp_path / "q.sqlite")
    v = _plain(p, verification_quorum=2)
    v.close()
    con = sqlite3.connect(p)
    con.execute("UPDATE vault_meta SET value = ? WHERE key = 'verification_quorum'", (b"1",))
    con.commit()
    con.close()
    v = _plain(p)
    assert v.verification_quorum == 1
    e = v.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    assert e.epistemic_state.value == "verified"
    v.close()


def test_attack_attestations_carry_over_a_content_change(tmp_path):
    """R2-A9 (passing = bug; library, principals only). ``_put`` seeds ``attested`` from the stored
    row's ``attestations`` whatever the content: alice attested X, bob writes Y asking for verified,
    and Y is verified with ['alice','bob'] although alice never saw Y."""
    v = _plain(str(tmp_path / "q.sqlite"), verification_quorum=2, trust_caller_identity=True)
    e = v.put("c", "k", "X", origin="user", epistemic_state="verified", attester="alice")
    assert e.epistemic_state.value == "candidate" and e.metadata["attestations"] == ["alice"]
    e = v.put("c", "k", "Y, a different claim", origin="user", epistemic_state="verified", attester="bob")
    assert e.epistemic_state.value == "verified"
    assert e.metadata["attestations"] == ["alice", "bob"]
    v.close()


# ----------------------------------------------------------------------------------------------
# F8 / F9 / L2 / L3 / F6 / L1 controls
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", ["model", "tool", "unknown"])
@pytest.mark.parametrize("verdict", ["verified", "disputed", "revoked"])
def test_control_f8_non_user_reviewer_origin_raises_and_records_nothing(vault, origin, verdict):
    vault.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    with pytest.raises(PermissionError):
        vault.review_entity("c", "k", verdict, reviewer_id="x", reviewer_origin=origin)
    e = vault.get("c", "k")
    assert e.epistemic_state.value == "verified" and not e.metadata.get("human_reviews")


def test_control_f8_private_flags_are_not_reachable_through_put_or_put_batch(vault):
    for flag in ("_review_verdict", "_trusted_metadata", "_attest"):
        with pytest.raises(TypeError):
            vault.put("c", "k", VALUE, origin="tool", epistemic_state="verified", **{flag: True})
        with pytest.raises(TypeError):
            vault.put_batch([{"category": "c", "key": "k", "content": VALUE, "origin": "tool", flag: True}])
    assert vault.get("c", "k") is None


def test_control_f9_review_without_reviewer_id_raises(vault):
    vault.put("c", "k", VALUE, origin="model")
    with pytest.raises(ValueError):
        vault.review_entity("c", "k", "verified")
    assert not vault.get("c", "k").metadata.get("human_reviews")


@pytest.mark.parametrize("state", ["verified", "disputed", "revoked"])
def test_control_l2_model_states_are_capped(vault, state):
    e = vault.put("c", "k", VALUE, origin="model", epistemic_state=state)
    assert e.epistemic_state.value == "candidate" and e.metadata.get("trust_capped_from") == state


def test_control_l3_principal_metadata_keys_are_moved_for_model_writes(vault):
    e = vault.put(
        "c", "k", VALUE, origin="model",
        metadata={"last_verified_at": 1.0, "slot": "persona", "supersession": {"x": 1}, "proposed_supersedes": {"y": 1}},
    )
    for k in ("last_verified_at", "slot", "supersession", "proposed_supersedes"):
        assert k not in e.metadata and k in e.metadata["agent_metadata"]


def test_control_l3_archive_and_persona_slot_take_origin(vault):
    vault.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    with pytest.raises(ReviewedEntryError):
        vault.archive("c", "k", origin="model")
    assert vault.get("c", "k") is not None
    vault.set_persona_slot("I like tea", origin="user")
    with pytest.raises((ReviewedEntryError, OriginClassError, PermissionError)):
        vault.set_persona_slot("I like coffee", origin="model")


def test_control_f6_agent_supersession_cascade_leaves_person_verified_dependent_alone(vault):
    vault.put("n", "a", "agent note A", origin="model")
    vault.put("p", "v", "person fact from A", origin="user", epistemic_state="verified", derived_from=["n:a"])
    vault.put("n", "b", "agent note B replaces A", origin="model", supersedes_key="a", supersedes_category="n")
    e = vault.get("p", "v")
    assert e.epistemic_state.value == "verified"
    assert e.metadata.get("invalidation_notice")
    assert not e.metadata.get("invalidated_by")


def test_control_l1_model_conflicts_with_leaves_no_back_edge_on_a_person_row(vault):
    vault.put("p", "v", "person fact", origin="user", epistemic_state="verified")
    vault.put("n", "a", "agent counter-claim", origin="model", conflicts_with=["p:v"])
    assert not vault.get("p", "v").metadata.get("conflicts_with")
    assert vault.get("n", "a").metadata.get("conflicts_with") == ["p:v"]


def test_control_f1_f10_mcp_forget_of_person_candidate_is_refused_and_journaled_as_forget_request(vault, server):
    vault.put("c", "k", VALUE, origin="user")
    err, _ = _call(server, "kibisis_forget", {"category": "c", "key": "k", "reason": "x"})
    assert err
    assert vault.get("c", "k") is not None
    # forget_request is only recorded for a *reviewed* entry; a person's unreviewed candidate is
    # refused as a higher-class entry but is not queued for review.
    acts = [e.action for e in vault.list_audit_events(limit=20)]
    assert "refuse" in acts


def test_control_f18_forget_request_for_a_verified_entry_is_queued(vault, server):
    vault.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    assert _call(server, "kibisis_forget", {"category": "c", "key": "k", "reason": "x"})[0]
    reqs = vault.forget_requests("default")
    assert [(r["category"], r["key"]) for r in reqs] == [("c", "k")]


# ----------------------------------------------------------------------------------------------
# Review CLI door (short pty run): lift is terminal-gated and refuses a pipe
# ----------------------------------------------------------------------------------------------


def test_control_review_lift_refuses_without_a_tty(tmp_path):
    env = dict(os.environ, XDG_DATA_HOME=str(tmp_path), KIBISIS_ALLOW_PLAINTEXT="1", ARGUS_LEDGER_PATH="",
               PYTHONPATH=os.path.join(os.getcwd(), "src"))
    env.pop("KIBISIS_PASSPHRASE", None)
    proc = subprocess.run(
        [PY, "-m", "kibisis.review", "lift", "c", "k"], input=b"", capture_output=True, env=env, timeout=60,
    )
    assert proc.returncode == 3, proc.stderr
    assert b"requires an interactive terminal" in proc.stderr
