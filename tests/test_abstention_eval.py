"""Abstention evaluation (issue #20): score answerable and unanswerable probes through the search a
caller actually runs, and never report a perfect verdict for a vault that returns nothing."""

import warnings

import pytest

from kibisis import KibisisMCPServer, Probe, SQLiteMemoryVault
from kibisis.mcp_server import recalled_refs

# Synthetic entries from the issue's repro.
ENTRIES = [
    ("decision", "log_storage_vendor", "Chose vendor B for log storage after the pricing review; renewal is due in March."),
    ("project_state", "dashboard_migration", "Dashboard migration: three issues remain open on the charts page."),
    ("insight", "benchmark_round3", "Round 3 benchmark: the latency checks passed but the accuracy gate failed."),
    ("decision", "release_freeze", "Release freeze starts Friday; open pull requests must merge before then."),
    ("project_state", "office_move", "Office move to the fourth floor is scheduled for the week of the 14th."),
    ("insight", "customer_feedback", "Customer feedback: exports are slow for large workspaces; the wrap-up survey is closed."),
    ("decision", "hiring_plan", "Hiring plan: one backend engineer in Q1, budget approved."),
    ("project_state", "docs_site", "Docs site rebuild: search works, navigation still needs a pass."),
]
ANSWERABLE = {
    "Which vendor did we pick for log storage?": "decision:log_storage_vendor",
    "When is the release freeze?": "decision:release_freeze",
    "How many backend engineers are we hiring?": "decision:hiring_plan",
}
OFF_TOPIC = [
    "What is the weather on Mars today?",
    "favorite ice cream flavor",
]
# Chat and tool output that share words with stored entries but ask about nothing stored.
NEAR_MISS = [
    "Sounds good. Open the issues, then wrap up so there are no loose ends.",
    "Background process completed normally (exit code 0). SUMMARY: 21/22 checks passed. FAILED: gate-zero-leaks",
    "What did we decide about the database backup schedule?",
]
K = 6


def seeded_vault():
    vault = SQLiteMemoryVault(":memory:", allow_plaintext=True, auto_gate=False)
    for category, key, text in ENTRIES:
        vault.remember(category, key, text, origin="user", epistemic_state="verified")
    return vault


def figures(report):
    """The comparable part of a report: every count, rate and verdict, plus each probe's outcome."""
    keys = (
        "store_size", "total_probes", "answerable_count", "unanswerable_count", "answered_count",
        "false_block_count", "wrong_entry_count", "false_reject_count", "abstained_count",
        "false_accept_count", "answerable_hit_rate", "unanswerable_abstain_rate", "verdict", "perfect",
    )
    return {k: report[k] for k in keys} | {"outcomes": [(o["probe"], o["outcome"]) for o in report["outcomes"]]}


class TestEmptyVault:
    def test_empty_vault_is_not_perfect(self):
        vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        report = vault.evaluate_abstention(answerable=ANSWERABLE, unanswerable=OFF_TOPIC)
        assert report["store_size"] == 0
        assert report["verdict"] == "empty_store"
        assert report["perfect"] is False
        # Every answerable probe is a false block, and refusing everything is still 100% abstention.
        assert report["false_reject_count"] == len(ANSWERABLE)
        assert report["false_block_count"] == len(ANSWERABLE)
        assert report["answerable_hit_rate"] == 0.0
        assert report["unanswerable_abstain_rate"] == 1.0
        assert report["false_accept_count"] == 0

    def test_empty_vault_with_only_unanswerable_probes_is_not_perfect(self):
        vault = SQLiteMemoryVault(":memory:", allow_plaintext=True)
        report = vault.evaluate_abstention(unanswerable=OFF_TOPIC + NEAR_MISS)
        assert report["abstained_count"] == len(OFF_TOPIC) + len(NEAR_MISS)
        assert report["verdict"] == "empty_store"
        assert report["perfect"] is False

    def test_retriever_that_returns_nothing_shows_no_leak_and_full_false_block(self):
        vault = seeded_vault()
        report = vault.evaluate_abstention(answerable=ANSWERABLE, unanswerable=OFF_TOPIC, search_fn=lambda q: [])
        assert report["store_size"] == len(ENTRIES)
        assert report["false_accept_count"] == 0
        assert report["unanswerable_abstain_rate"] == 1.0
        assert report["false_block_count"] == len(ANSWERABLE)
        assert report["answerable_hit_rate"] == 0.0
        assert report["verdict"] == "false_rejects"
        assert report["perfect"] is False


class TestOutcomes:
    def test_seeded_vault_scores_perfect_on_strict_probes(self):
        vault = seeded_vault()
        report = vault.evaluate_abstention(answerable=ANSWERABLE, unanswerable=OFF_TOPIC, k=K)
        assert report["store_size"] == len(ENTRIES)
        assert report["k"] == K
        assert report["answered_count"] == len(ANSWERABLE)
        assert report["abstained_count"] == len(OFF_TOPIC)
        assert report["answerable_hit_rate"] == 1.0
        assert report["unanswerable_abstain_rate"] == 1.0
        assert report["false_accept_count"] == 0
        assert report["false_reject_count"] == 0
        assert report["verdict"] == "perfect"
        assert report["perfect"] is True

    def test_no_probes_is_not_perfect(self):
        report = seeded_vault().evaluate_abstention()
        assert report["total_probes"] == 0
        assert report["verdict"] == "no_probes"
        assert report["perfect"] is False
        assert report["answerable_hit_rate"] is None
        assert report["unanswerable_abstain_rate"] is None

    def test_only_unanswerable_probes_cannot_be_perfect(self):
        # Abstention alone is what the old evaluator scored: a dead retriever passes it.
        report = seeded_vault().evaluate_abstention(unanswerable=OFF_TOPIC)
        assert report["abstained_count"] == len(OFF_TOPIC)
        assert report["verdict"] == "no_answerable_probes"
        assert report["perfect"] is False

    def test_wrong_entry_is_a_false_reject_with_matched_keys(self):
        vault = seeded_vault()
        # The right entry exists but the retriever hands back another one.
        wrong = lambda q: vault.search("office move fourth floor", match="any", limit=K)
        report = vault.evaluate_abstention(answerable={"When is the release freeze?": "decision:release_freeze"}, search_fn=wrong)
        assert report["wrong_entry_count"] == 1
        assert report["false_block_count"] == 0
        assert report["false_reject_count"] == 1
        assert report["answerable_hit_rate"] == 0.0
        assert report["false_rejects"][0]["matched"] == ["project_state:office_move"]
        assert report["false_rejects"][0]["expected"] == ["decision:release_freeze"]
        assert report["outcomes"][0]["outcome"] == "wrong_entry"
        assert report["verdict"] == "false_rejects"

    def test_answerable_probe_accepts_any_of_several_expected_refs(self):
        vault = seeded_vault()
        probes = [Probe("When is the release freeze?", expected={"decision:release_freeze", "decision:hiring_plan"})]
        report = vault.evaluate_abstention(probes, k=K)
        assert report["answered_count"] == 1

    def test_top_k_cuts_the_results_scored(self):
        vault = seeded_vault()
        # A retriever that returns the right entry last, after five others.
        others = [r for r in vault.search("issues floor survey budget navigation", match="any", limit=10)
                  if r.entity.key != "release_freeze"][:5]
        right = vault.search("release freeze", match="all", limit=1)
        assert len(others) == 5 and right
        report = vault.evaluate_abstention(
            answerable={"When is the release freeze?": "decision:release_freeze"}, search_fn=lambda q: others + right, k=5,
        )
        assert report["outcomes"][0]["outcome"] == "wrong_entry"
        report = vault.evaluate_abstention(
            answerable={"When is the release freeze?": "decision:release_freeze"}, search_fn=lambda q: others + right, k=6,
        )
        assert report["outcomes"][0]["outcome"] == "answered"

    def test_probe_validation(self):
        with pytest.raises(ValueError):
            Probe("q", expected=set())
        with pytest.raises(ValueError):
            Probe("", expected={"a:b"})
        with pytest.raises(ValueError):
            seeded_vault().evaluate_abstention(answerable={"q": "no-colon"})
        with pytest.raises(ValueError):
            seeded_vault().evaluate_abstention(k=0)


class TestDistractors:
    def test_near_miss_distractors_produce_false_accepts_under_a_loose_query(self):
        vault = seeded_vault()
        # Distractors that reuse the stored vocabulary around things that are not stored.
        vault.remember("decision", "backup_vendor", "Chose vendor C for backup storage after a short pricing call.",
                       origin="user", epistemic_state="verified")
        vault.remember("project_state", "log_dashboard", "Log dashboard: the storage graph still shows stale data.",
                       origin="user", epistemic_state="verified")
        probes = [Probe(q, expected=frozenset({ref}), tag="reworded") for q, ref in ANSWERABLE.items()]
        probes += [Probe(q, tag="near-miss") for q in NEAR_MISS]
        probes += [Probe(q, tag="off-topic") for q in OFF_TOPIC]
        # Deliberately loose: any word may match and nothing is cut off by score.
        loose = lambda q: vault.search(q, scope="default", match="any", limit=K, include_unverified=True)
        report = vault.evaluate_abstention(probes, search_fn=loose, k=K)

        assert report["store_size"] == len(ENTRIES) + 2
        assert report["false_accept_count"] >= 1
        assert report["false_accept_count"] == len(report["false_accepts"])
        assert report["abstained_count"] + report["false_accept_count"] == len(NEAR_MISS) + len(OFF_TOPIC)
        assert report["unanswerable_abstain_rate"] == pytest.approx(
            report["abstained_count"] / (len(NEAR_MISS) + len(OFF_TOPIC))
        )
        assert report["unanswerable_abstain_rate"] < 1.0
        assert report["perfect"] is False
        assert report["verdict"] in ("false_accepts", "mixed")
        for leak in report["false_accepts"]:
            assert leak["probe"] in NEAR_MISS  # the off-topic chat still abstains
            assert leak["matched"], leak
            assert all(":" in ref for ref in leak["matched"])
        # Per-tag figures count the leaks under the tag that produced them.
        assert report["by_tag"]["near-miss"]["false_accept"] == report["false_accept_count"]
        assert report["by_tag"]["off-topic"]["false_accept"] == 0
        assert report["by_tag"]["off-topic"]["abstained"] == len(OFF_TOPIC)
        assert report["by_tag"]["reworded"]["answerable"] == len(ANSWERABLE)

    def test_issue_repro_per_turn_retriever(self):
        """The issue's per-turn caller: match='any' and keep hits at least half as good as the best."""
        vault = seeded_vault()

        def per_turn(query):
            hits = vault.search(query, limit=15, match="any")
            if hits:
                best = hits[0].rank_score  # BM25: lower is better
                hits = [h for h in hits if h.rank_score <= best / 2]
            return hits[:K]

        report = vault.evaluate_abstention(
            answerable={"Which vendor did we pick for log storage?": "decision:log_storage_vendor"},
            unanswerable=NEAR_MISS, search_fn=per_turn, k=K,
        )
        by_probe = {o["probe"]: o["outcome"] for o in report["outcomes"]}
        assert by_probe["Which vendor did we pick for log storage?"] == "answered"
        for q in NEAR_MISS:
            assert by_probe[q] == "false_accept", q
        assert report["false_accept_count"] == len(NEAR_MISS)
        assert report["perfect"] is False
        # The old evaluator's default search scores the same vault and probes as spotless.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            legacy = vault.evaluate_epistemic_abstention(NEAR_MISS)
        assert legacy["abstained_count"] == len(NEAR_MISS)


class TestSearchCallers:
    def test_mcp_recall_and_library_search_agree(self):
        vault = seeded_vault()
        # An agent-written candidate: the MCP server's recall shows candidates by default.
        vault.remember("insight", "agent_note", "Agent note: the nightly export job retries twice before failing.",
                       origin="model")
        server = KibisisMCPServer(vault=vault, scope="default")
        probes = [Probe(q, expected=frozenset({ref}), tag="reworded") for q, ref in ANSWERABLE.items()]
        probes.append(Probe("How often does the nightly export retry?", expected=frozenset({"insight:agent_note"}), tag="candidate"))
        probes += [Probe(q, tag="near-miss") for q in NEAR_MISS]
        probes += [Probe(q, tag="off-topic") for q in OFF_TOPIC]

        def through_mcp(query):
            resp = server.handle_request({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "kibisis_recall", "arguments": {"query": query, "limit": K}},
            })
            assert resp["result"]["isError"] is False, resp
            return recalled_refs(resp["result"]["content"][0]["text"])

        def through_library(query):
            # The arguments kibisis_recall passes to search() with its defaults.
            return vault.search(query, category=None, limit=K, scope="default", include_unverified=True, match="any")

        via_mcp = vault.evaluate_abstention(probes, search_fn=through_mcp, k=K)
        via_lib = vault.evaluate_abstention(probes, search_fn=through_library, k=K)
        assert figures(via_mcp) == figures(via_lib)
        assert via_mcp["false_accepts"] == via_lib["false_accepts"]
        assert via_mcp["false_rejects"] == via_lib["false_rejects"]
        assert via_mcp["store_size"] == len(ENTRIES) + 1
        assert via_mcp["answered_count"] == len(ANSWERABLE) + 1  # the candidate is recalled too
        assert via_mcp["false_accept_count"] >= 1  # the near-miss chat leaks through match="any"
        assert via_mcp["perfect"] is False

    def test_default_search_fn_is_the_natural_language_search(self):
        vault = seeded_vault()
        default = vault.evaluate_abstention(answerable=ANSWERABLE, unanswerable=NEAR_MISS, k=K)
        explicit = vault.evaluate_abstention(
            answerable=ANSWERABLE, unanswerable=NEAR_MISS, k=K,
            search_fn=lambda q: vault.search(q, scope="default", limit=K, match="any"),
        )
        assert figures(default) == figures(explicit)
        # match="all" (the old evaluator's search) cannot answer the questions at all.
        strict = vault.evaluate_abstention(
            answerable=ANSWERABLE, unanswerable=NEAR_MISS, k=K,
            search_fn=lambda q: vault.search(q, scope="default", limit=K),
        )
        assert strict["false_accept_count"] == 0
        assert strict["false_block_count"] == len(ANSWERABLE)
        assert strict["perfect"] is False

    def test_recalled_refs_parses_the_envelope(self):
        vault = seeded_vault()
        vault.remember("notes", 'odd "key" <x>', "Entry with a key that needs escaping; mention vendor pricing.",
                       origin="user", epistemic_state="verified")
        server = KibisisMCPServer(vault=vault, scope="default")
        text = server._recall({"query": "vendor pricing", "limit": K})
        refs = recalled_refs(text)
        assert "decision:log_storage_vendor" in refs
        assert 'notes:odd "key" <x>' in refs
        assert recalled_refs('<kibisis-recall scope="default" count="0">\nnotice\n</kibisis-recall>') == []


class TestLegacyWrapper:
    def test_evaluate_epistemic_abstention_keeps_its_shape_and_warns(self):
        vault = seeded_vault()
        with pytest.warns(DeprecationWarning):
            report = vault.evaluate_epistemic_abstention(OFF_TOPIC)
        for key in ("total_probes", "abstained_count", "false_positive_count", "abstention_rate", "false_positives",
                    "perfect_abstention"):
            assert key in report
        assert report["total_probes"] == len(OFF_TOPIC)
        assert report["abstained_count"] == len(OFF_TOPIC)
        assert report["perfect_abstention"] is True
        # The new figures ride along so a reader can see what the old verdict leaves out.
        assert report["store_size"] == len(ENTRIES)
        assert report["verdict"] == "no_answerable_probes"
        assert report["perfect"] is False

    def test_legacy_wrapper_lists_false_positives(self):
        vault = seeded_vault()
        with pytest.warns(DeprecationWarning):
            report = vault.evaluate_epistemic_abstention(["release freeze"])
        assert report["false_positive_count"] == 1
        assert report["false_positives"][0]["matched_keys"] == ["release_freeze"]
        assert report["perfect_abstention"] is False
