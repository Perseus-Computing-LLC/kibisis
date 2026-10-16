"""Unit tests for Kibisis write-time admission gate and post-retrieval governance."""

import unittest
from kibisis import (
    FactDisposition,
    MemoryAdmissionGate,
    SQLiteMemoryVault,
)


class TestAdmissionAndGovernance(unittest.TestCase):
    def setUp(self):
        self.vault = SQLiteMemoryVault(":memory:")
        self.gate = MemoryAdmissionGate()

    def tearDown(self):
        self.vault.close()

    def test_admission_gate_speculation_detection(self):
        decision = self.gate.evaluate("I might move to Seattle next spring.")
        self.assertEqual(decision.disposition, FactDisposition.SPECULATION)
        self.assertFalse(decision.is_admissible)
        self.assertTrue(decision.metadata.get("unresolved_speculation"))

        decision2 = self.gate.evaluate("Planning to migrate the database to Postgres.")
        self.assertEqual(decision2.disposition, FactDisposition.SPECULATION)

    def test_admission_gate_transient_detection(self):
        decision = self.gate.evaluate("I am really tired today right now.")
        self.assertEqual(decision.disposition, FactDisposition.TRANSIENT)
        self.assertFalse(decision.is_admissible)

    def test_admission_gate_factual_admit(self):
        decision = self.gate.evaluate("The project license is MIT.")
        self.assertEqual(decision.disposition, FactDisposition.ADMIT)
        self.assertTrue(decision.is_admissible)

    def test_post_retrieval_tenant_isolation_memleak_defense(self):
        # Tenant A stores an insight
        self.vault.put(
            category="finance",
            key="kpi_q3",
            content="Q3 recurring revenue reached 1.2M",
            tenant_id="tenant_a",
        )
        # Tenant B stores an insight
        self.vault.put(
            category="finance",
            key="kpi_q4",
            content="Q4 recurring revenue projected at 1.5M",
            tenant_id="tenant_b",
        )

        # Query without tenant filter sees both
        all_hits = self.vault.search("revenue")
        self.assertEqual(len(all_hits), 2)

        # Query with Tenant A filter sees only Tenant A (MemLeak mitigation)
        tenant_a_hits = self.vault.search("revenue", tenant_id="tenant_a")
        self.assertEqual(len(tenant_a_hits), 1)
        self.assertEqual(tenant_a_hits[0].entity.key, "kpi_q3")

        # Query with Tenant B filter sees only Tenant B
        tenant_b_hits = self.vault.search("revenue", tenant_id="tenant_b")
        self.assertEqual(len(tenant_b_hits), 1)
        self.assertEqual(tenant_b_hits[0].entity.key, "kpi_q4")

    def test_derivation_gated_lineage_amu_check(self):
        # Entity derived from sensitive columns [col_ssn, col_salary]
        self.vault.put(
            category="analytics",
            key="payroll_summary",
            content="Aggregated department payroll metric",
            derived_from=["col_dept", "col_salary"],
        )

        # Requester authorized for only col_dept cannot retrieve derived payroll metric
        hits_unauthorized = self.vault.search(
            "payroll",
            authorized_lineage_roots=["col_dept"],
        )
        self.assertEqual(len(hits_unauthorized), 0)

        # Requester authorized for both can retrieve
        hits_authorized = self.vault.search(
            "payroll",
            authorized_lineage_roots=["col_dept", "col_salary"],
        )
        self.assertEqual(len(hits_authorized), 1)
        self.assertEqual(hits_authorized[0].entity.key, "payroll_summary")


if __name__ == "__main__":
    unittest.main()
