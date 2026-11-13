"""severity: high
finding: put_batch drops a MemoryEntity item's origin, so a model-origin entity replaces a person's reviewed entry and is stored as the person's
"""

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.models import EpistemicState, MemoryEntity
from kibisis.vault import OriginClassError, ReviewedEntryError

PASS = "review2-batch-origin-passphrase-not-secret"


@pytest.fixture()
def vault(tmp_path):
    v = SQLiteMemoryVault(str(tmp_path / "vault.sqlite"), passphrase=PASS)
    v.put("notes", "pref", "the person's own fact", origin="user")
    v.review_entity("notes", "pref", "verified", reviewer_id="person-1")
    yield v
    v.close()


def _row(vault, key):
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    return {(r.category, r.key): r for r in rows}[("notes", key)]


def _snapshot(row):
    meta = row.metadata or {}
    return (row.content, row.origin, row.version, len(meta.get("human_reviews") or []))


def test_control_put_and_dict_items_refuse_a_model_write_over_the_persons_entry(vault):
    before = _snapshot(_row(vault, "pref"))
    assert before[1] == "user" and before[3] == 1
    with pytest.raises((OriginClassError, ReviewedEntryError)):
        vault.put("notes", "pref", "model rewrite", origin="model")
    with pytest.raises((OriginClassError, ReviewedEntryError)):
        vault.put_batch([dict(category="notes", key="pref", content="model rewrite", origin="model")])
    assert _snapshot(_row(vault, "pref")) == before


def test_control_put_batch_writes_memory_entity_items(vault):
    vault.put_batch([MemoryEntity(category="notes", key="fresh", content="a new note")])
    assert _row(vault, "fresh").content == "a new note"


def test_put_batch_memory_entity_with_model_origin_cannot_replace_the_persons_entry(vault):
    before = _snapshot(_row(vault, "pref"))
    item = MemoryEntity(
        category="notes", key="pref", content="model rewrite", origin="model",
        epistemic_state=EpistemicState.VERIFIED,
    )
    try:
        vault.put_batch([item])
    except (OriginClassError, ReviewedEntryError):
        pass
    after = _row(vault, "pref")
    # On this head the write lands: the model's text replaces the person's, the person's review is
    # dropped and the row still says origin 'user' (principal class).
    assert _snapshot(after) == before, ("model-origin entity replaced the person's entry", _snapshot(after))


def test_put_batch_memory_entity_keeps_its_model_origin(vault):
    item = MemoryEntity(category="notes", key="claim", content="what the model said", origin="model")
    vault.put_batch([item])
    assert _row(vault, "claim").origin == "model"
