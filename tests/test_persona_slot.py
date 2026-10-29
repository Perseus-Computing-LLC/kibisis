"""Tests for Kibisis dedicated user persona / preference slot and ContextItem conversion."""

import pytest
from kibisis import EpistemicState, SQLiteMemoryVault


def test_persona_slot_lifecycle():
    # The persona slot is the person's own profile (origin "user"); with a quorum of one the
    # author's write verifies it (K-R1).
    vault = SQLiteMemoryVault(":memory:", allow_plaintext=True, verification_quorum=1)

    # Initially empty
    assert vault.get_persona_slot() is None
    assert vault.get_persona_context_item() is None

    # Set persona slot
    ent = vault.set_persona_slot(
        content="User prefers high-compression responses and strict type hints.",
        metadata={"user": "alice"},
    )
    assert ent.category == "persona"
    assert ent.key == "user_profile"
    assert ent.content == "User prefers high-compression responses and strict type hints."
    assert ent.epistemic_state == EpistemicState.VERIFIED
    assert ent.origin == "user"
    assert ent.metadata.get("origin_class") == "principal"
    assert ent.metadata.get("is_persona_slot") is True
    assert ent.metadata.get("user") == "alice"

    # Get persona slot
    retrieved = vault.get_persona_slot()
    assert retrieved is not None
    assert retrieved.content == ent.content

    # Get persona formatted as pinned ContextItem dict
    ctx_dict = vault.get_persona_context_item()
    assert ctx_dict is not None
    assert ctx_dict["role"] == "system"
    assert ctx_dict["priority"] == 0
    assert ctx_dict["pinned"] is True
    assert ctx_dict["content"] == ent.content
    assert ctx_dict["metadata"]["category"] == "persona"
    assert ctx_dict["metadata"]["key"] == "user_profile"
    assert ctx_dict["metadata"]["is_persona_slot"] is True

    # Update persona slot
    vault.set_persona_slot(content="Updated preferences: markdown tables only.")
    updated = vault.get_persona_slot()
    assert updated is not None
    assert updated.content == "Updated preferences: markdown tables only."
    assert updated.version == 2

    # Scoped persona slot
    vault.set_persona_slot(content="Tenant X preference", scope="tenant-x")
    slot_x = vault.get_persona_slot(scope="tenant-x")
    slot_def = vault.get_persona_slot(scope="default")
    assert slot_x is not None and slot_x.content == "Tenant X preference"
    assert slot_def is not None and slot_def.content == "Updated preferences: markdown tables only."

    vault.close()


def test_persona_slot_below_quorum_is_a_pending_candidate():
    """Under the default quorum (2) the author's write is one attestation: stored, but not verified."""
    vault = SQLiteMemoryVault(":memory:", allow_plaintext=True, verification_quorum=2)
    ent = vault.set_persona_slot(content="User prefers terse answers.", author_id="alice")
    assert ent.epistemic_state == EpistemicState.CANDIDATE
    assert ent.metadata["attestations"] == ["alice"]
    assert ent.metadata["verification_pending"] == {"have": 1, "need": 2}
    assert vault.get_persona_slot() is not None
    vault.close()


def test_memory_entity_to_context_item():
    vault = SQLiteMemoryVault(":memory:", allow_plaintext=True, verification_quorum=1)
    ent = vault.put(
        category="insights",
        key="knapsack_pruning",
        content="Knapsack pruning achieves deterministic context limits.",
        metadata={"author": "harpe"},
        epistemic_state="verified",
        origin="user",
    )

    ctx_item = ent.to_context_item(pinned=False, priority=10, role="context")
    assert ctx_item["id"] == "kibisis_insights_knapsack_pruning"
    assert ctx_item["content"] == ent.content
    assert ctx_item["role"] == "context"
    assert ctx_item["priority"] == 10
    assert ctx_item["pinned"] is False
    assert ctx_item["metadata"]["author"] == "harpe"
    assert ctx_item["metadata"]["epistemic_state"] == "verified"

    vault.close()
