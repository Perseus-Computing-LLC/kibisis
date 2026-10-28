"""Provenance: where an entry came from decides what state it may hold and who may promote it."""
import json
import os
import sqlite3

import sqlcipher3
import subprocess
import sys

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.models import EpistemicState
from kibisis.vault import AdmissionRefused, ORIGINS


def _legacy_a9_vault(path, passphrase):
    """A real vault whose entities table is put back to the 0.1.0a9 shape (no provenance columns)."""
    v = SQLiteMemoryVault(path, passphrase=passphrase)
    v.put("c", "legacy", "old")
    v.close()
    conn = sqlcipher3.dbapi2.connect(path)
    conn.execute(f"PRAGMA key = '{passphrase}';")
    for col in ("origin", "source_ref", "confidence"):
        conn.execute(f"ALTER TABLE entities DROP COLUMN {col}")
    conn.commit()
    cols = {r[1] for r in conn.execute("PRAGMA table_info(entities)")}
    conn.close()
    assert not ({"origin", "source_ref", "confidence"} & cols)


def test_schema_adds_origin_source_ref_confidence(tmp_path):
    db = str(tmp_path / "a9.sqlite")
    _legacy_a9_vault(db, "test-passphrase-a9")
    vault = SQLiteMemoryVault(db, passphrase="test-passphrase-a9")
    cols = {r[1]: r for r in vault._conn.execute("PRAGMA table_info(entities)").fetchall()}
    assert {"origin", "source_ref", "confidence"} <= set(cols)
    assert cols["origin"][3] == 1  # NOT NULL
    assert cols["origin"][4].strip("'") == "unknown"
    with pytest.raises(sqlcipher3.dbapi2.IntegrityError):
        with vault._conn:
            vault._conn.execute("UPDATE entities SET origin = 'alien' WHERE key = 'legacy'")
    # legacy rows (D4): origin='unknown', readable through the normal API
    legacy = vault.get("c", "legacy")
    assert legacy is not None and legacy.origin == "unknown"
    assert legacy.source_ref is None and legacy.confidence is None
    assert ORIGINS == ("user", "model", "tool", "import", "unknown")
    vault.close()


def test_remember_stores_origin():
    vault = SQLiteMemoryVault(":memory:")
    e = vault.remember("c", "k", "fact", origin="model", source_ref="session:X/turn:3", confidence=0.6)
    assert (e.origin, e.source_ref, e.confidence) == ("model", "session:X/turn:3", 0.6)
    again = vault.get("c", "k")
    assert (again.origin, again.source_ref, again.confidence) == ("model", "session:X/turn:3", 0.6)
    with pytest.raises(ValueError):
        vault.remember("c", "k2", "fact", origin="oracle")
    with pytest.raises(ValueError):
        vault.remember("c", "k3", "fact", origin="model", confidence=1.5)
    # rows written without an origin stay 'unknown', and put() still works unchanged
    assert vault.put("c", "k4", "fact").origin == "unknown"


def test_default_state_is_candidate_for_model_origin():
    vault = SQLiteMemoryVault(":memory:")
    m = vault.remember("c", "from_model", "The sky is blue.", origin="model")
    assert m.epistemic_state == EpistemicState.CANDIDATE
    assert vault.get("c", "from_model").epistemic_state == EpistemicState.CANDIDATE
    # a model may not talk itself into verified either
    m2 = vault.remember("c", "from_model_2", "The sky is blue.", origin="model", epistemic_state="verified")
    assert m2.epistemic_state == EpistemicState.CANDIDATE
    assert m2.metadata.get("trust_capped_from") == "verified"
    u = vault.remember("c", "from_user", "The sky is blue.", origin="user", epistemic_state="verified")
    assert u.epistemic_state == EpistemicState.VERIFIED
    # model writes do not reach default recall; the user's does
    keys = {r.entity.key for r in vault.search("sky", limit=10)}
    assert "from_user" in keys and "from_model" not in keys


def test_admit_refuses_model_self_promotion():
    vault = SQLiteMemoryVault(":memory:")
    vault.remember("c", "k", "fact", origin="model")
    with pytest.raises(AdmissionRefused):
        vault.admit("c", "k", reviewer="hermes-agent", reviewer_origin="model")
    assert vault.get("c", "k").epistemic_state == EpistemicState.CANDIDATE
    with pytest.raises(ValueError):
        vault.admit("c", "k", reviewer="x", reviewer_origin="oracle")
    promoted = vault.admit("c", "k", reviewer="thomas", reviewer_origin="user", note="checked")
    assert promoted.epistemic_state == EpistemicState.VERIFIED
    assert promoted.origin == "model"  # provenance of the fact does not change on review
    assert promoted.metadata["human_reviews"][-1]["reviewer_origin"] == "user"


def test_state_transition_emits_audit_event(tmp_path, monkeypatch):
    ledger_path = tmp_path / "argus.jsonl"
    monkeypatch.setenv("ARGUS_LEDGER_PATH", str(ledger_path))
    vault = SQLiteMemoryVault(":memory:")
    vault.remember("c", "k", "fact", origin="model")  # unknown->candidate on first write: no transition
    vault.admit("c", "k", reviewer="thomas", reviewer_origin="user")  # candidate->verified
    vault.review_entity("c", "k", verdict="disputed", reviewer_id="thomas")  # verified->disputed
    rows = [
        e for e in vault.list_audit_events(category="c", key="k", limit=50)
        if e.action == "state_transition"
    ]
    assert [(r.metadata["from"], r.metadata["to"]) for r in rows] == [
        ("candidate", "verified"), ("verified", "disputed")
    ] or [(r.metadata["from"], r.metadata["to"]) for r in rows] == [
        ("verified", "disputed"), ("candidate", "verified")
    ]
    for r in rows:
        assert r.metadata["event"] == "state_transition"
        assert r.metadata["origin"] == "model"
        assert r.metadata["reviewer"] == "thomas"
    assert vault.verify_audit_chain()

    # the same transitions reached Argus through the argus_ledger library, and the chain verifies
    lines = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    kinds = [(l["payload"]["from"], l["payload"]["to"]) for l in lines if l["event_type"] == "kibisis.state_transition"]
    assert sorted(kinds) == sorted([("candidate", "verified"), ("verified", "disputed")])
    from argus_ledger import AppendOnlyLedger
    assert AppendOnlyLedger(str(ledger_path)).verify_chain()
    r = subprocess.run(["argus-verify", str(ledger_path)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def _run_admit(args, *, tty: bool):
    """Run the CLI's admit command with stdin on a pseudo-terminal (``tty=True``) or on /dev/null.

    The gate checks ``sys.stdin.isatty()``; a pty slave is the real thing, so the test exercises the
    same code path a person at a shell does, with no environment escape to keep in sync.
    """
    import pty

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    cmd = [sys.executable, "-m", "kibisis", "admit", *args]
    if not tty:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=60)
    master, slave = pty.openpty()
    try:
        return subprocess.run(cmd, stdin=slave, capture_output=True, text=True, env=env, timeout=60)
    finally:
        os.close(slave)
        os.close(master)


def test_admit_cli_sets_reviewer_origin_user(tmp_path, monkeypatch):
    db = str(tmp_path / "v.sqlite")
    monkeypatch.setenv("KIBISIS_PASSPHRASE", "test-passphrase")
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    v = SQLiteMemoryVault(db, passphrase="test-passphrase")
    v.remember("c", "k", "fact", origin="model")
    v.close()
    common = ["--db", db, "--category", "c", "--key", "k"]
    r = _run_admit([*common, "--by", "user", "--note", "looked at it"], tty=True)
    assert r.returncode == 0, r.stdout + r.stderr
    r2 = _run_admit([*common, "--by", "model"], tty=True)
    assert r2.returncode != 0
    v = SQLiteMemoryVault(db, passphrase="test-passphrase")
    assert v.get("c", "k").epistemic_state == EpistemicState.VERIFIED
    v.close()


def test_admit_cli_refuses_without_tty_even_with_env_escape(tmp_path, monkeypatch):
    """The gate has no environment escape: the variable the old test suite used must do nothing."""
    db = str(tmp_path / "v.sqlite")
    monkeypatch.setenv("KIBISIS_PASSPHRASE", "test-passphrase")
    monkeypatch.delenv("KIBISIS_PASSPHRASE_FILE", raising=False)
    monkeypatch.setenv("KIBISIS_ADMIT_ALLOW_NOTTY", "1")
    v = SQLiteMemoryVault(db, passphrase="test-passphrase")
    v.remember("c", "k", "fact", origin="model")
    v.close()
    r = _run_admit(["--db", db, "--category", "c", "--key", "k", "--by", "user"], tty=False)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "interactive terminal" in r.stderr
    v = SQLiteMemoryVault(db, passphrase="test-passphrase")
    assert v.get("c", "k").epistemic_state == EpistemicState.CANDIDATE
    v.close()


def test_admit_cli_refuses_without_tty(tmp_path, monkeypatch):
    """The human admit path must not be drivable from a pipe (agent shell tool, cron)."""
    import io
    from kibisis.__main__ import main
    monkeypatch.setattr("sys.stdin", io.StringIO(""))  # no isatty -> False
    rc = main(["admit", "--db", str(tmp_path / "v.sqlite"), "--category", "c", "--key", "k", "--by", "user"])
    assert rc == 3
    assert not (tmp_path / "v.sqlite").exists() or (tmp_path / "v.sqlite").stat().st_size == 0
