"""severity: high
finding: set_persona_slot checks a non-principal request in one transaction and writes in another, so a person's review committed in between is overwritten and erased

``set_persona_slot`` (src/kibisis/vault.py:2544-2567) runs the protection check for a request from
outside the principal class (``_refuse_if_protected`` inside its own ``_write_tx``, which commits at
the end of the ``with`` block) and only then calls ``self.put(...)``, which opens a second write
transaction. ``put`` re-checks a reviewed entry only for a capped write (``trust_ceiling``, implied by
``origin="model"`` alone: vault.py:1489-1493, 1738-1744), so a ``tool``-origin write is not
re-checked under the lock it writes with. A person's review that another connection commits between
the two transactions is overwritten, and the slot loses the review.

The docstring promises the opposite (vault.py:2539-2542: such a request "cannot replace a slot a
person verified or reviewed"), and ``_write_tx`` (vault.py:889-899) says every mutating method makes
check-then-write atomic against other connections.

The interleaving is made deterministic by wrapping the agent vault's ``_write_tx``: when the agent
opens its second outermost write transaction, a person's review is first committed through a second
vault object (its own connection) on the same file. Once the check and the write share one
transaction, the hook either fires before the check (the request is refused) or does not fire during
the call at all (the review is then applied afterwards and must survive); both outcomes pass.
"""

import contextlib

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.vault import ReviewedEntryError

SLOT = ("persona", "user_profile")


@pytest.fixture
def pair(tmp_path):
    path = str(tmp_path / "vault.db")
    agent = SQLiteMemoryVault(path, allow_plaintext=True)
    person = SQLiteMemoryVault(path, allow_plaintext=True)
    agent.set_persona_slot("tool's profile v1", origin="tool")
    yield agent, person
    agent.close()
    person.close()


def _person_reviews(person):
    person.review_entity(*SLOT, "verified", reviewer_id="alice")


def test_control_tool_write_over_a_reviewed_slot_is_refused_when_not_interleaved(pair):
    agent, person = pair
    _person_reviews(person)
    with pytest.raises(ReviewedEntryError):
        agent.set_persona_slot("tool's profile v2", origin="tool")
    slot = person.get(*SLOT)
    assert slot.content == "tool's profile v1"
    assert slot.metadata.get("human_reviews")


def test_review_committed_between_check_and_write_is_not_erased(pair, monkeypatch):
    agent, person = pair
    original = agent._write_tx
    seen = {"outermost": 0, "reviewed": False}

    @contextlib.contextmanager
    def interleaved():
        if not agent._conn.in_transaction:
            seen["outermost"] += 1
            if seen["outermost"] == 2 and not seen["reviewed"]:
                seen["reviewed"] = True
                _person_reviews(person)  # another connection commits a person's review here
        with original() as cursor:
            yield cursor

    monkeypatch.setattr(agent, "_write_tx", interleaved)
    refused = False
    try:
        agent.set_persona_slot("tool's profile v2", origin="tool")
    except ReviewedEntryError:
        refused = True
    monkeypatch.undo()
    if not seen["reviewed"]:
        _person_reviews(person)

    slot = person.get(*SLOT)
    reviews = slot.metadata.get("human_reviews") or []
    assert refused or reviews, (
        "a person's review committed between set_persona_slot's protection check and its write was "
        f"overwritten by a tool-origin write: the slot now holds {slot.content!r} with no human_reviews "
        f"(outermost write transactions opened by the call: {seen['outermost']})"
    )
