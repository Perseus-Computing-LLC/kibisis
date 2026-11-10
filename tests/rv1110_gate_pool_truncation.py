"""severity: medium
finding: recall() gates and counts only the top max(limit*8, 64) matches, so `n_matched` understates the matches and the same hit passes or fails the gate depending on `limit`.

Contract (src/kibisis/_vault_search.py, recall docstring, lines 225-228):
    "K-R4: a hit is returned only if the share of query words it contains is at least ``min_coverage_bp``
    (basis points) and, with four or more matches to compare against, its BM25 z-score among the matched
    set is at most ``z_max_bp``; the receipt carries ``n_store`` and every hit's z-score and coverage."
Contract (CHANGELOG.md, line 293): "The receipt carries `n_store`, `n_matched`, the counts withheld by reason,"
Contract (README.md, line 118): "matches that contain under half of the query's words, or that do not stand
    out from four or more other matches, are only counted"

On this head the z-score is taken over the pool recall fetched (`pool = max(limit * 8, 64)`,
_vault_search.py:237), not over the matched set. The pool is the best-scoring slice, so its mean is better
than the matched set's mean, and a hit that stands out from all matches does not stand out from the pool.
`limit` therefore changes which hits pass, not only how many are returned, and matches beyond the pool are
neither gated nor counted.
"""
import os

import pytest

from kibisis import SQLiteMemoryVault

_FILL = "bravo charlie delta echo foxtrot golf hotel india juliet kilo".split()


@pytest.fixture(autouse=True)
def _no_live_ledger(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


def _graded(vault, n):
    """n entries that all hold both query words; entry i repeats them (i % 12) + 1 times, so scores are graded."""
    for i in range(n):
        reps = (i % 12) + 1
        text = " ".join(["mainframe reactor"] * reps + [_FILL[(i + j) % len(_FILL)] for j in range(30 - 2 * reps)])
        vault.put("fact", f"e{i:03d}", text, origin="user", author_id="a", epistemic_state="verified")


def _verdicts(vault, limit):
    out = vault.recall("mainframe reactor", match="any", limit=limit)
    return out.receipt, {h["ref"]: h["kept"] for h in out.receipt["hits"]}


def test_control_under_the_pool_size_limit_changes_nothing(vault):
    # Positive control: 40 matches fit in every pool, so the count is exact and the verdicts agree.
    _graded(vault, 40)
    small_receipt, small = _verdicts(vault, 2)
    large_receipt, large = _verdicts(vault, 40)
    assert small_receipt["n_matched"] == large_receipt["n_matched"] == 40
    assert small == large
    assert any(small.values()) and not all(small.values())  # the gate is doing something here


def test_n_matched_counts_every_match(vault):
    _graded(vault, 150)
    every_match = vault.search("mainframe reactor", match="any", limit=1000)
    assert len(every_match) == 150
    receipt, _ = _verdicts(vault, 5)
    assert receipt["n_matched"] == 150, f"receipt counts {receipt['n_matched']} of 150 matches"


def test_gate_verdict_for_a_hit_does_not_depend_on_limit(vault):
    _graded(vault, 150)
    _, small = _verdicts(vault, 5)    # pool 64
    _, large = _verdicts(vault, 40)   # pool 320: the whole matched set
    flipped = sorted(ref for ref in small if small[ref] != large[ref])
    assert not flipped, f"{len(flipped)} hits pass the gate at limit=40 and fail it at limit=5, e.g. {flipped[:3]}"
