"""Unit and integration tests for temporal supersession, invalidation, and write-time admission gating.

Incorporates proven patterns from the r/AIMemory analysis:
- Particles engine temporal superseding (active state vs superseded pointer).
- Write-time admission gating (quarantine speculation, transient state windows).
- Stale fact filtering in active search queries vs point-in-time bi-temporal retrieval.
- Directional semantic relationship typing (SUPERSEDES, DEPENDS_ON, CONTRADICTS, DERIVED_FROM).
"""

import time
import pytest
from kibisis.vault import SQLiteMemoryVault
from kibisis.models import EpistemicState, RelationType
from kibisis.admission import FactDisposition, MemoryAdmissionGate


def test_write_time_admission_gating_speculation_quarantine():
    """Verify that speculative statements are automatically quarantined as candidate."""
    vault = SQLiteMemoryVault(":memory:", auto_gate=True)

    # Speculation should be routed to candidate
    ent_spec = vault.put(
        category="planning",
        key="cloud-migration",
        content="We might migrate our primary database to BigQuery next quarter.",
    )
    assert ent_spec.epistemic_state == EpistemicState.CANDIDATE
    assert ent_spec.metadata.get("admission_disposition") == FactDisposition.SPECULATION.value
    assert ent_spec.metadata.get("unresolved_speculation") is True

    # Normal factual statements should be admitted as verified
    ent_fact = vault.put(
        category="convention",
        key="license",
        content="The Telarch Suite software is released under the MIT License.",
    )
    assert ent_fact.epistemic_state == EpistemicState.VERIFIED
    assert ent_fact.metadata.get("admission_disposition") == FactDisposition.ADMIT.value


def test_write_time_admission_transient_temporal_window():
    """Verify that transient situational observations receive candidate state or bounded validity."""
    vault = SQLiteMemoryVault(":memory:", auto_gate=True)

    ent_trans = vault.put(
        category="status",
        key="location-travel",
        content="I am temporarily in Chicago for a conference right now.",
    )
    assert ent_trans.epistemic_state == EpistemicState.CANDIDATE
    assert ent_trans.metadata.get("admission_disposition") == FactDisposition.TRANSIENT.value
    assert ent_trans.valid_until is not None
    assert ent_trans.valid_until > time.time()


def test_write_time_admission_correction_detection():
    """Verify that explicit corrections are admitted and flagged as corrections."""
    vault = SQLiteMemoryVault(":memory:", auto_gate=True)

    ent_corr = vault.put(
        category="architecture",
        key="cache-backend",
        content="Actually, the cache backend was switched to an in-memory ring buffer instead of disk storage.",
    )
    assert ent_corr.epistemic_state == EpistemicState.VERIFIED
    assert ent_corr.metadata.get("is_correction") is True
    assert ent_corr.metadata.get("admission_disposition") == FactDisposition.CORRECTION.value


def test_explicit_superseding_invalidation_and_audit():
    """Verify that adding a superseding fact revokes the prior entity and records pointers."""
    vault = SQLiteMemoryVault(":memory:", auto_gate=False)

    t0 = time.time() - 100.0
    # Store initial fact
    old_ent = vault.put(
        category="profile",
        key="residence_v1",
        content="User lives in Seattle, WA.",
        valid_from=t0,
    )
    assert old_ent.epistemic_state == EpistemicState.VERIFIED
    assert old_ent.superseded_by is None

    # Supersede with new location
    t1 = time.time()
    new_ent = vault.put(
        category="profile",
        key="residence_v2",
        content="User lives in Austin, TX.",
        supersedes_key="residence_v1",
    )

    assert new_ent.supersedes == "profile:residence_v1"
    assert new_ent.valid_from is not None
    assert new_ent.valid_from >= t1

    # Verify old entity is now revoked, bounded, and points to successor
    old_fetched = vault.get("profile", "residence_v1")
    assert old_fetched is not None
    assert old_fetched.epistemic_state == EpistemicState.REVOKED
    assert old_fetched.valid_until is not None
    assert old_fetched.valid_until <= time.time()
    assert old_fetched.superseded_by == "profile:residence_v2"
    assert old_fetched.metadata.get("superseded_by") == "profile:residence_v2"

    # Verify audit journal has supersede action
    cursor = vault._conn.cursor()
    cursor.execute("SELECT action, category, key, metadata_json FROM audit_journal WHERE action = 'supersede'")
    row = cursor.fetchone()
    assert row is not None
    assert row["key"] == "residence_v1"
    assert "profile:residence_v2" in row["metadata_json"]


def test_supersede_helper_method():
    """Verify the atomic supersede() convenience helper."""
    vault = SQLiteMemoryVault(":memory:", auto_gate=False)

    vault.put(category="infra", key="primary_db", content="Primary DB is Aurora MySQL 5.7")
    new_ent = vault.supersede(
        category="infra",
        old_key="primary_db",
        new_key="primary_db_v2",
        new_content="Primary DB is PostgreSQL 16 on Greg Unraid",
    )

    assert new_ent.key == "primary_db_v2"
    assert new_ent.supersedes == "infra:primary_db"
    assert new_ent.epistemic_state == EpistemicState.VERIFIED

    old_ent = vault.get("infra", "primary_db")
    assert old_ent.epistemic_state == EpistemicState.REVOKED
    assert old_ent.superseded_by == "infra:primary_db_v2"


def test_active_search_filters_superseded_and_expired_facts():
    """Verify that search() filters out superseded facts in active queries while bi-temporal point-in-time works."""
    vault = SQLiteMemoryVault(":memory:", auto_gate=False)

    past_time = time.time() - 3600.0  # 1 hour ago
    # Past residence in Seattle
    vault.put(
        category="profile",
        key="residence_seattle",
        content="Current home city is Seattle Washington.",
        valid_from=past_time - 7200.0,
    )

    # Move to Austin 1 hour ago: supersede Seattle
    vault.supersede(
        category="profile",
        old_key="residence_seattle",
        new_key="residence_austin",
        new_content="Current home city is Austin Texas.",
        valid_from=past_time,
    )

    # 1. Active search for "city" or "home" should return ONLY Austin
    active_results = vault.search("city", active_only=True)
    keys = [r.entity.key for r in active_results]
    assert "residence_austin" in keys
    assert "residence_seattle" not in keys  # Revoked/superseded fact excluded!

    # 2. Point-in-time search at (past_time - 1800) should return Seattle, NOT Austin
    pit_time = past_time - 1800.0
    # For point-in-time query, also include revoked if searching historical state
    historical_results = vault.search("city", as_of_valid_time=pit_time, include_unverified=True)
    hist_keys = [r.entity.key for r in historical_results]
    assert "residence_seattle" in hist_keys
    assert "residence_austin" not in hist_keys


def test_relation_types_and_context_item_temporal_metadata():
    """Verify RelationType enum and context item export formatting."""
    assert RelationType.SUPERSEDES == "supersedes"
    assert RelationType.DEPENDS_ON == "depends_on"
    assert RelationType.CONTRADICTS == "contradicts"
    assert RelationType.DERIVED_FROM == "derived_from"

    vault = SQLiteMemoryVault(":memory:", auto_gate=False)
    ent = vault.put(
        category="policy",
        key="security_rule",
        content="Do not leak secret keys.",
        supersedes_key="legacy_rule",
    )

    context_dict = ent.to_context_item()
    assert context_dict["id"] == "kibisis_policy_security_rule"
    assert context_dict["metadata"]["supersedes"] == "policy:legacy_rule"
    assert "created_at" in context_dict["metadata"]
    assert "epistemic_state" in context_dict["metadata"]
