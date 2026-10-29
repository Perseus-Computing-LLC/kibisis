import time
import unittest
from kibisis import EpistemicState, MemoryEntity, SQLiteMemoryVault


class TestAtlasRubricHardening(unittest.TestCase):

    def test_epistemic_lifecycle_and_unverified_filtering(self):
        # K-R1: a single person's review reaches quorum here.
        vault = SQLiteMemoryVault(verification_quorum=1)
        # 1. Candidate ingestion
        entity = vault.admit_candidate(
            category="theories",
            key="quantum_gravity",
            content="Loop Quantum Gravity formulation",
            scope="lab_alpha",
        )
        self.assertEqual(entity.epistemic_state, EpistemicState.CANDIDATE)

        # K-K: candidates are recallable by default, labeled by state; a verified-only recall
        # withholds them.
        res = vault.search(query="Quantum", scope="lab_alpha")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].entity.key, "quantum_gravity")
        self.assertEqual(res[0].entity.epistemic_state, EpistemicState.CANDIDATE)
        res_ver = vault.search(query="Quantum", scope="lab_alpha", epistemic_state=EpistemicState.VERIFIED.value)
        self.assertEqual(len(res_ver), 0)

        # Human review promotes to verified
        reviewed = vault.review_entity(
            category="theories",
            key="quantum_gravity",
            verdict=EpistemicState.VERIFIED.value,
            scope="lab_alpha",
            reviewer_id="human_peer_reviewer_42",
            notes="Empirical math checks pass.",
        )
        self.assertEqual(reviewed.epistemic_state, EpistemicState.VERIFIED)
        self.assertEqual(len(reviewed.metadata["human_reviews"]), 1)

        # Now a verified-only search finds it too
        res_verified = vault.search(query="Quantum", scope="lab_alpha", epistemic_state=EpistemicState.VERIFIED.value)
        self.assertEqual(len(res_verified), 1)
        self.assertEqual(res_verified[0].entity.epistemic_state, EpistemicState.VERIFIED)

        # Human review revokes it -> automatic tombstone & purge
        revoked = vault.review_entity(
            category="theories",
            key="quantum_gravity",
            verdict=EpistemicState.REVOKED.value,
            scope="lab_alpha",
            reviewer_id="human_lead",
            notes="Superseded by string theory experiment",
        )
        self.assertEqual(revoked.epistemic_state, EpistemicState.REVOKED)
        self.assertIsNone(vault.get("theories", "quantum_gravity", scope="lab_alpha"))
        # Revoked entries are withheld from default recall.
        self.assertEqual(vault.search(query="Quantum", scope="lab_alpha"), [])

        # Cannot re-insert tombstoned payload into same scope
        with self.assertRaises(ValueError) as cm:
            vault.put(
                category="theories",
                key="quantum_gravity",
                content="Loop Quantum Gravity formulation",
                scope="lab_alpha",
            )
        self.assertIn("matches rejected tombstone", str(cm.exception))


    def test_scope_enforcement_and_tenant_isolation(self):
        vault = SQLiteMemoryVault()
        vault.put(
            category="creds",
            key="api_token",
            content="secret_token_alpha",
            scope="tenant_alpha",
        )
        vault.put(
            category="creds",
            key="api_token",
            content="secret_token_beta",
            scope="tenant_beta",
        )

        # Retrieval isolation
        alpha_ent = vault.get(category="creds", key="api_token", scope="tenant_alpha")
        beta_ent = vault.get(category="creds", key="api_token", scope="tenant_beta")
        gamma_ent = vault.get(category="creds", key="api_token", scope="tenant_gamma")

        self.assertIsNotNone(alpha_ent)
        self.assertEqual(alpha_ent.content, "secret_token_alpha")
        self.assertIsNotNone(beta_ent)
        self.assertEqual(beta_ent.content, "secret_token_beta")
        self.assertIsNone(gamma_ent)

        # Search isolation
        search_alpha = vault.search("secret_token", scope="tenant_alpha")
        self.assertEqual(len(search_alpha), 1)
        self.assertEqual(search_alpha[0].entity.content, "secret_token_alpha")

        search_beta = vault.search("secret_token", scope="tenant_beta")
        self.assertEqual(len(search_beta), 1)
        self.assertEqual(search_beta[0].entity.content, "secret_token_beta")

        search_gamma = vault.search("secret_token", scope="tenant_gamma")
        self.assertEqual(len(search_gamma), 0)


    def test_bitemporal_validity_point_in_time(self):
        vault = SQLiteMemoryVault(verification_quorum=1)
        # Event valid from t=1000 to t=2000, verified by the person who wrote it
        vault.put(
            category="regulations",
            key="tariffs",
            content="Steel imports subjected to 25% duty",
            valid_from=1000.0,
            valid_until=2000.0,
            scope="trade_dept",
            epistemic_state="verified",
            origin="user",
        )

        # Point-in-time search at t=500 (before validity) -> 0
        res_past = vault.search("Steel", scope="trade_dept", as_of_valid_time=500.0)
        self.assertEqual(len(res_past), 0)

        # Point-in-time search at t=1500 (valid window) -> 1
        res_now = vault.search("Steel", scope="trade_dept", as_of_valid_time=1500.0)
        self.assertEqual(len(res_now), 1)
        self.assertEqual(res_now[0].entity.key, "tariffs")

        # Point-in-time search at t=2500 (after expiry) -> 0
        res_future = vault.search("Steel", scope="trade_dept", as_of_valid_time=2500.0)
        self.assertEqual(len(res_future), 0)

        # List entities also enforces bi-temporal bounds
        ents_valid = vault.list_entities(scope="trade_dept", as_of_valid_time=1500.0)
        self.assertEqual(len(ents_valid), 1)
        ents_expired = vault.list_entities(scope="trade_dept", as_of_valid_time=3000.0)
        self.assertEqual(len(ents_expired), 0)


    def test_tamper_evident_audit_log_and_chain_verification(self):
        vault = SQLiteMemoryVault()
        vault.put("audit_test", "k1", "payload alpha", scope="sec_team", author_id="agent_1")
        vault.put("audit_test", "k2", "payload beta", scope="sec_team", author_id="agent_2")
        vault.put("audit_test", "k1", "payload alpha updated", scope="sec_team", author_id="agent_1")
        vault.archive("audit_test", "k2", scope="sec_team", author_id="agent_3")

        # Chain verification
        self.assertTrue(vault.verify_audit_chain(scope="sec_team"))

        events = vault.list_audit_events(scope="sec_team")
        self.assertEqual(len(events), 4)
        self.assertEqual([e.action for e in events], ["put", "put", "update", "archive"])
        self.assertEqual(events[0].prev_hash, "0" * 64)
        self.assertEqual(events[1].prev_hash, events[0].event_hash)
        self.assertEqual(events[2].prev_hash, events[1].event_hash)
        self.assertEqual(events[3].prev_hash, events[2].event_hash)


    def test_negative_contract_assertions(self):
        vault = SQLiteMemoryVault()
        # 1. Invalid epistemic status rejected
        with self.assertRaises(ValueError):
            vault.put("cat", "k", "test", epistemic_state="non_existent_state")

        # 2. Review invalid verdict rejected
        vault.admit_candidate("cat", "k", "test")
        with self.assertRaises(ValueError) as cm:
            vault.review_entity("cat", "k", verdict="invalid_verdict")
        self.assertIn("Verdict must be one of", str(cm.exception))

        # 3. Review non-existent entity raises KeyError
        with self.assertRaises(KeyError) as cm:
            vault.review_entity("non_cat", "non_k", verdict=EpistemicState.VERIFIED.value)
        self.assertIn("Entity not found for review", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
