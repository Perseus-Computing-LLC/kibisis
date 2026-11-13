"""put_batch writes a MemoryEntity item as the put() call its fields describe.

Every put() parameter a MemoryEntity carries that the entity's caller set reaches put: the provenance
(origin, source_ref, confidence) as well as the content fields, so put's class check, trust cap and
refusal journal see what the caller stated. An entity that states no origin is written as a put that
states none, as before: a re-write keeps the entry's origin and a new key is stored as ``unknown``.
"""

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.models import MemoryEntity
from kibisis.vault import _ENTITY_PUT_FIELDS, _PUT_PARAMETERS, OriginClassError

PASS = "put-batch-provenance-passphrase-not-secret"
TEXT = "the batch item's text"
# What an entity that sets nothing else passes to put, as put_batch always has.
ENTITY_DEFAULTS = dict(metadata={}, epistemic_state="verified", valid_from=None, valid_until=None, scope="default")


def _open(path):
    return SQLiteMemoryVault(str(path), passphrase=PASS)


def _seed(vault):
    vault.put("notes", "person", "the person's own fact", origin="user", source_ref="session:1", confidence=0.9)
    vault.review_entity("notes", "person", "verified", reviewer_id="person-1")
    vault.put("notes", "agent", "what the model said", origin="model", source_ref="turn:7", confidence=0.4)
    vault.put("notes", "legacy", "an entry that never stated an origin")


def _row(vault, key):
    rows = {r.key: r for r in vault.list_entities(scope="*", include_archived=True, include_unverified=True)}
    r = rows.get(key)
    if r is None:
        return None
    meta = r.metadata or {}
    return dict(
        content=r.content, origin=r.origin, origin_class=meta.get("origin_class"), source_ref=r.source_ref,
        confidence=r.confidence, state=r.epistemic_state.value, version=r.version,
        reviews=len(meta.get("human_reviews") or []), attestations=len(meta.get("attestations") or []),
    )


def _refusals(vault):
    return [
        ((e.metadata or {}).get("reason"), e.category, e.key)
        for e in vault.list_audit_events(limit=10_000) if e.action == "refuse"
    ]


def _outcome(vault, item, key):
    try:
        vault.put_batch([item])
        raised = None
    except Exception as exc:  # noqa: BLE001 - the outcome under comparison
        raised = type(exc)
    return raised, _row(vault, key), _refusals(vault)


def test_the_put_parameters_an_entity_carries_are_the_fields_both_signatures_share():
    assert _ENTITY_PUT_FIELDS == set(MemoryEntity.model_fields) & _PUT_PARAMETERS
    assert _ENTITY_PUT_FIELDS == {
        "category", "key", "content", "metadata", "epistemic_state", "valid_from", "valid_until", "scope",
        "origin", "source_ref", "confidence",
    }


# (key, the provenance the entity states, what the batch must do): an exception class (nothing written,
# the refusal journaled as put journals it), or the row fields the write must leave.
CASES = [
    ("person", {"origin": "model"}, OriginClassError),
    ("person", {"origin": "tool"}, OriginClassError),
    ("person", {"origin": "unknown"}, OriginClassError),
    ("person", {"origin": "model", "source_ref": "turn:8", "confidence": 0.2}, OriginClassError),
    ("person", {"origin": "user", "source_ref": "session:2", "confidence": 1.0},
     {"origin": "user", "origin_class": "principal", "source_ref": "session:2", "confidence": 1.0}),
    ("person", {"source_ref": "session:3"}, {"origin": "user", "source_ref": "session:3", "confidence": 0.9}),
    ("person", {}, {"origin": "user", "origin_class": "principal", "source_ref": "session:1", "confidence": 0.9}),
    ("agent", {"origin": "tool"}, OriginClassError),
    ("agent", {"origin": "model", "source_ref": "turn:8"},
     {"origin": "model", "origin_class": "agent", "state": "candidate", "source_ref": "turn:8", "confidence": 0.4}),
    ("agent", {"confidence": 0.1}, {"origin": "model", "origin_class": "agent", "confidence": 0.1}),
    ("legacy", {"origin": "model"}, {"origin": "model", "origin_class": "agent", "state": "candidate"}),
    ("fresh", {}, {"origin": "unknown", "origin_class": "external", "source_ref": None, "confidence": None}),
    ("fresh", {"origin": "unknown"}, {"origin": "unknown", "origin_class": "external"}),
    ("fresh", {"origin": "model", "source_ref": "turn:9", "confidence": 0.5},
     {"origin": "model", "origin_class": "agent", "state": "candidate", "source_ref": "turn:9", "confidence": 0.5}),
    ("fresh", {"origin": "tool", "confidence": 0.3}, {"origin": "tool", "origin_class": "external", "confidence": 0.3}),
]


@pytest.mark.parametrize("key, stated, expected", CASES, ids=[f"{k}-{'-'.join(f'{n}={v}' for n, v in s.items()) or 'none'}" for k, s, _ in CASES])
def test_an_entity_item_is_the_put_its_stated_fields_describe(tmp_path, key, stated, expected):
    as_entity, as_dict = _open(tmp_path / "entity.sqlite"), _open(tmp_path / "dict.sqlite")
    try:
        for vault in (as_entity, as_dict):
            _seed(vault)
        before = _row(as_entity, key)
        entity = MemoryEntity(category="notes", key=key, content=TEXT, **stated)
        got = _outcome(as_entity, entity, key)
        # The same write as a dict item, which put_batch has always passed to put key for key.
        want = _outcome(as_dict, dict(category="notes", key=key, content=TEXT, **ENTITY_DEFAULTS, **stated), key)
        assert got == want
        raised, row, refusals = got
        if isinstance(expected, type):
            assert raised is expected
            assert row == before, "a refused batch item changed the row"
            assert refusals[-1] == ("origin_class_refused", "notes", key)
            assert len([r for r in refusals if r[2] == key]) == 1
        else:
            assert raised is None
            assert row["content"] == TEXT
            assert {name: row[name] for name in expected} == expected
    finally:
        as_entity.close()
        as_dict.close()


def test_an_origin_set_after_construction_is_honoured(tmp_path):
    vault = _open(tmp_path / "vault.sqlite")
    try:
        _seed(vault)
        before = _row(vault, "person")
        assigned = MemoryEntity(category="notes", key="person", content=TEXT)
        assigned.origin = "model"
        copied = MemoryEntity(category="notes", key="person", content=TEXT).model_copy(update={"origin": "model"})
        for item in (assigned, copied):
            with pytest.raises(OriginClassError):
                vault.put_batch([item])
        assert _row(vault, "person") == before
    finally:
        vault.close()


def test_entities_a_vault_returned_carry_their_stored_provenance(tmp_path):
    src, dst = _open(tmp_path / "src.sqlite"), _open(tmp_path / "dst.sqlite")
    try:
        _seed(dst)
        src.put("notes", "person", "a model's claim about the person's fact", origin="model",
                source_ref="turn:1", confidence=0.6)
        src.put("notes", "relayed", "a model's note", origin="model", source_ref="turn:2", confidence=0.7)
        relay = {e.key: e for e in src.list_entities(include_unverified=True)}
        before = _row(dst, "person")
        # Relaying a model-origin entry onto a person's reviewed entry is the model write it is.
        with pytest.raises(OriginClassError):
            dst.put_batch([relay["person"]])
        assert _row(dst, "person") == before
        dst.put_batch([relay["relayed"]])
        row = _row(dst, "relayed")
        assert (row["origin"], row["origin_class"], row["source_ref"], row["confidence"]) == ("model", "agent", "turn:2", 0.7)
        assert row["state"] == "candidate"
        # A vault's own entry written back through put_batch keeps its provenance and class.
        dst.put_batch([dst.get("notes", "agent")])
        row = _row(dst, "agent")
        assert (row["origin"], row["origin_class"], row["source_ref"], row["confidence"]) == ("model", "agent", "turn:7", 0.4)
    finally:
        src.close()
        dst.close()


def test_an_origin_put_refuses_is_refused_for_an_entity_too(tmp_path):
    vault = _open(tmp_path / "vault.sqlite")
    try:
        _seed(vault)
        with pytest.raises(ValueError):
            vault.put_batch([MemoryEntity(category="notes", key="fresh", content=TEXT, origin="robot")])
        assert _row(vault, "fresh") is None
    finally:
        vault.close()
