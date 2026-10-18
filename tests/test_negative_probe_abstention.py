"""Unit tests for Negative-Probe Discipline and Epistemic Abstention in Kibisis."""

import unittest
import time
from kibisis import EpistemicState, SQLiteMemoryVault


class TestNegativeProbeAbstention(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)

    def tearDown(self):
        self.vault.close()

    def test_negative_probes_clean_abstention(self):
        """Out-of-scope probes must return 0 results and never fabricate matches."""
        # Populate vault with specific facts
        self.vault.store(
            category="deployment",
            key="primary_region",
            content="us-east-1",
            epistemic_state=EpistemicState.VERIFIED.value,
        )
        self.vault.store(
            category="network",
            key="firewall_policy",
            content="Strict inbound deny-all on port 22",
            epistemic_state=EpistemicState.VERIFIED.value,
        )

        # Probes completely out of domain
        unknown_probes = [
            "What is the user's favorite ice cream flavor?",
            "quantum decryption algorithm credentials",
            "Mars rover telemetry coordinates",
            "unrelated company quarterly revenue 2024",
            "cryptographic private seed for external ledger",
            "personal banking account routing number",
        ]

        report = self.vault.evaluate_epistemic_abstention(unknown_probes)
        self.assertEqual(report["total_probes"], len(unknown_probes))
        self.assertEqual(report["abstained_count"], len(unknown_probes))
        self.assertEqual(report["false_positive_count"], 0)
        self.assertEqual(report["abstention_rate"], 1.0)
        self.assertTrue(report["perfect_abstention"])

    def test_epistemic_supersession_accuracy(self):
        """Updated or revoked facts must never be recalled over current verified state."""
        now = time.time()

        # Step 1: Store initial fact valid from T-100 to T-10
        self.vault.put(
            category="infrastructure",
            key="database_host",
            content="db-primary-old.internal.net",
            epistemic_state=EpistemicState.VERIFIED.value,
            valid_from=now - 100.0,
            valid_until=now - 10.0,
        )

        # Step 2: Store superseding fact valid from T-10 onwards
        self.vault.put(
            category="infrastructure",
            key="database_host_v2",
            content="db-primary-new.internal.net",
            epistemic_state=EpistemicState.VERIFIED.value,
            valid_from=now - 10.0,
            valid_until=None,
        )

        # Point-in-time query at present (as_of_valid_time=now)
        current_results = self.vault.search("db-primary", as_of_valid_time=now)
        self.assertEqual(len(current_results), 1)
        self.assertEqual(current_results[0].entity.content, "db-primary-new.internal.net")

        # Point-in-time query in the past (as_of_valid_time = now - 50.0)
        past_results = self.vault.search("db-primary", as_of_valid_time=now - 50.0)
        self.assertEqual(len(past_results), 1)
        self.assertEqual(past_results[0].entity.content, "db-primary-old.internal.net")

    def test_candidate_and_revoked_quarantine(self):
        """Candidate and revoked memories must be quarantined from normal recall."""
        self.vault.store(
            category="rumor",
            key="candidate_fact",
            content="Unverified leak regarding project deadline",
            epistemic_state=EpistemicState.CANDIDATE.value,
        )
        self.vault.store(
            category="policy",
            key="revoked_rule",
            content="Old password rotation policy every 30 days",
            epistemic_state=EpistemicState.REVOKED.value,
        )
        self.vault.store(
            category="policy",
            key="active_rule",
            content="FIDO2 passkey authentication required for all operators",
            epistemic_state=EpistemicState.VERIFIED.value,
        )

        # Normal search: candidate and revoked must be quarantined
        results = self.vault.search("policy", include_unverified=False)
        matched_keys = [r.entity.key for r in results]
        self.assertIn("active_rule", matched_keys)
        self.assertNotIn("revoked_rule", matched_keys)

        candidate_results = self.vault.search("deadline", include_unverified=False)
        self.assertEqual(len(candidate_results), 0)

        # Search with include_unverified=True reveals candidate
        unverified_results = self.vault.search("deadline", include_unverified=True)
        self.assertEqual(len(unverified_results), 1)
        self.assertEqual(unverified_results[0].entity.key, "candidate_fact")


if __name__ == "__main__":
    unittest.main()
