"""severity: low
finding: the recall() docstring says every call is journaled as a `recall` event; no such event is written, so the vault keeps no durable record of recalls (and no access statistics) unless an Argus ledger is configured.

Contract (src/kibisis/_vault_search.py, recall docstring, lines 230-232):
    "K-R5: every call is journaled as a ``recall`` event and mirrored to Argus as ``kibisis.memory_recall``
    (counts and withheld ids; the query appears only as a digest)."

On this head recall() appends to an in-process deque of 1000 records (`_recent_recalls`, vault.py:478) and
calls `_argus_append`, which does nothing when ARGUS_LEDGER_PATH is unset. The code comment at
_vault_search.py:354-355 ("A read never writes") and tests/test_recall_layer_kr345.py
(`test_recall_does_not_write_to_the_vault_journal`) state the opposite of the docstring, so the likely fix
is the docstring; it is recorded because a consolidation job that reads the docstring will look in the
journal for recall counts and find none.
"""
import pytest

from kibisis import SQLiteMemoryVault


@pytest.fixture(autouse=True)
def _no_live_ledger(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


def test_control_a_write_is_journaled_and_a_recall_is_seen_in_process(vault):
    # Positive control: the journal is readable and records the write; the in-process log sees the recall.
    vault.put("fact", "k", "the mainframe reactor coolant valve", origin="user", author_id="a", epistemic_state="verified")
    vault.recall("mainframe reactor", match="any")
    assert any(e.key == "k" for e in vault.list_audit_events(limit=1000))
    assert len(vault.recent_recalls()) == 1


def test_every_recall_is_journaled_as_a_recall_event(vault):
    vault.put("fact", "k", "the mainframe reactor coolant valve", origin="user", author_id="a", epistemic_state="verified")
    vault.recall("mainframe reactor", match="any")
    actions = [e.action for e in vault.list_audit_events(limit=1000)]
    assert "recall" in actions, f"journal actions after one recall: {sorted(set(actions))}"
