"""severity: medium
finding: the gate's coverage is a raw substring test on the content alone, while matching is FTS5 over category, key, content and scope with accent folding; an entry that matched every query word is withheld as covering none of them.

Contract (README.md, line 19): "The model-facing `recall()`, which the MCP server uses, also holds back
    verified memories that conflict and matches that cover too little of the query, and says what it held back."
Contract (README.md, line 118): "matches that contain under half of the query's words, or that do not stand
    out from four or more other matches, are only counted"
Contract (src/kibisis/_vault_search.py, recall docstring, lines 225-226): "a hit is returned only if the
    share of query words it contains is at least ``min_coverage_bp``"

On this head coverage is `sum(1 for t in terms if t in text)` with `text = h.entity.content.lower()`
(_vault_search.py:299-300). The index that produced the match covers the key as well
(`fts5(category, key, content, scope, ...)`, _vault_search.py:701-702) and folds accents (unicode61). So a
note keyed `autopoiesis-loop-phase-7-closeout` whose text says "stage 7 is done" matches the query
"autopoiesis loop phase" on all three words and is withheld with coverage_bp == 0; so is a note that
spells a query word with an accent.
"""
import pytest

from kibisis import SQLiteMemoryVault


@pytest.fixture(autouse=True)
def _no_live_ledger(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


def _put(vault, key, content):
    vault.put("project_state", key, content, origin="user", author_id="a", epistemic_state="verified")


def _hit(out, ref):
    return next(h for h in out.receipt["hits"] if h["ref"] == ref)


def test_control_words_in_the_content_are_covered(vault):
    # Positive control: the same words in the content pass the gate.
    _put(vault, "note-1", "autopoiesis loop phase 7 is done; the upcoming one is organization")
    out = vault.recall("autopoiesis loop phase", match="any", limit=5)
    assert [r.entity.key for r in out.results] == ["note-1"]
    assert _hit(out, "project_state:note-1")["coverage_bp"] == 10000


def test_query_words_matched_in_the_key_count_as_covered(vault):
    _put(vault, "autopoiesis-loop-phase-7-closeout", "Stage 7 is done; the upcoming one is organization.")
    assert [r.entity.key for r in vault.search("autopoiesis loop phase", match="all")] == ["autopoiesis-loop-phase-7-closeout"]
    out = vault.recall("autopoiesis loop phase", match="any", limit=5)
    hit = _hit(out, "project_state:autopoiesis-loop-phase-7-closeout")
    assert hit["coverage_bp"] == 10000, f"matched all three words, coverage_bp={hit['coverage_bp']}, reason={hit['reason']!r}"
    assert [r.entity.key for r in out.results] == ["autopoiesis-loop-phase-7-closeout"]


def test_query_words_matched_through_accent_folding_count_as_covered(vault):
    _put(vault, "note-2", "Le résumé du café: décision reportée.")
    assert [r.entity.key for r in vault.search("resume cafe decision", match="all")] == ["note-2"]
    out = vault.recall("resume cafe decision", match="any", limit=5)
    hit = _hit(out, "project_state:note-2")
    assert hit["coverage_bp"] == 10000, f"matched all three words, coverage_bp={hit['coverage_bp']}, reason={hit['reason']!r}"
    assert [r.entity.key for r in out.results] == ["note-2"]
