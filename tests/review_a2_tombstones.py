"""A2 tombstones: can a forgotten value come back, and what the purge misses (kibisis 1299c28).

Each docstring says whether the test asserts INSECURE behaviour (passes = the gap is present) or SECURE
behaviour (passes = closed). Controls sit beside each gap.

Run: cd <worktree> && ARGUS_LEDGER_PATH=$TMPDIR/argus_a2.jsonl PYTHONPATH=src <venv>/python -m pytest -q -p no:cacheprovider tests/review_a2_tombstones.py
"""

from __future__ import annotations

import os
import unicodedata

import pytest

from kibisis import EpistemicState, KibisisMCPServer, SQLiteMemoryVault
from kibisis._vault_crypto import canonicalize_text
from kibisis.vault import ReviewedEntryError, TombstonedValueError

FORGOTTEN = "Use tabs for indentation"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")
    for name in [k for k in os.environ if k.startswith("KIBISIS_")]:
        monkeypatch.delenv(name)


@pytest.fixture
def vault():
    v = SQLiteMemoryVault(":memory:", auto_gate=False, verification_quorum=1)
    yield v
    v.close()


@pytest.fixture
def server(vault):
    return KibisisMCPServer(vault=vault, scope="default")


def _call(server, tool, arguments):
    resp = server.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    )
    return resp["result"]["isError"], resp["result"]["content"][0]["text"]


def _forget_via_person(vault, category="prefs", key="indent"):
    """The documented path: a person rejects the entry in the review CLI (review_entity + scrub)."""
    vault.review_entity(category, key, "revoked", reviewer_id="acct", notes="forget this")
    vault.scrub()
    assert vault.is_tombstoned("x", "y", FORGOTTEN)


# --- canonical-form gaps ------------------------------------------------------------------------------------

LOOKALIKES = {
    # name: (variant, unicode category of the inserted char)
    "variation-selector-16 U+FE0F": "Use tabs\ufe0f for indentation",
    "combining-grapheme-joiner U+034F": "Use t\u034fabs for indentation",
    "mongolian-fvs1 U+180B": "Use tabs\u180b for indentation",
    "hangul-filler U+3164": "Use tabs\u3164 for indentation",
    "cyrillic-a U+0430": "Use t\u0430bs for indentation",
    "dotless-i U+0131": "Use tabs for \u0131ndentation",
}
CONTROLS = {
    "case+punctuation": "USE TABS, FOR INDENTATION!",
    "zero-width-space U+200B (Cf)": "Use tabs\u200b for indentation",
    "fullwidth U+FF35": "\uff35se tabs for indentation",
    "nbsp-and-tabs": "Use\u00a0tabs\tfor   indentation",
}


@pytest.mark.parametrize("name", list(CONTROLS), ids=list(CONTROLS))
def test_control_case_punctuation_cf_and_compatibility_variants_are_refused(vault, name):
    """Positive control (SECURE, passes): the folds README.md:20 and :115 promise do hold."""
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct")
    _forget_via_person(vault)
    assert canonicalize_text(CONTROLS[name]) == canonicalize_text(FORGOTTEN)
    with pytest.raises(TombstonedValueError):
        vault.put("notes", "n", CONTROLS[name], origin="model")


@pytest.mark.parametrize("name", list(LOOKALIKES), ids=list(LOOKALIKES))
def test_invisible_nonspacing_marks_and_homoglyphs_bring_a_tombstoned_value_back(vault, name):
    """INSECURE behaviour (passes = gap present): ``canonicalize_text`` (_vault_crypto.py:45-71) strips only
    ``Cf``/``Cc`` and ``P*``/``S*``; a nonspacing mark (``Mn``: U+FE0F, U+034F, U+180B), the Hangul filler
    (``Lo``, invisible) or a script homoglyph survives NFKC+casefold, so the canonical digest differs and the
    look-alike is stored. README.md:55 and :125 say look-alikes are refused."""
    variant = LOOKALIKES[name]
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct")
    _forget_via_person(vault)
    assert canonicalize_text(variant) != canonicalize_text(FORGOTTEN)
    e = vault.put("notes", "n", variant, origin="model")
    assert e is not None and vault.get("notes", "n").content == variant
    assert not vault.is_tombstoned("notes", "n", variant)


def test_invisible_mark_variant_is_accepted_through_the_mcp_remember_tool(vault, server):
    """INSECURE behaviour (passes = gap present): the agent's own path. After a person rejects the entry, the
    agent re-stores the same sentence with one invisible U+FE0F and recall returns it; the control (the exact
    sentence) is refused."""
    _call(server, "kibisis_remember", {"category": "prefs", "key": "indent", "content": FORGOTTEN})
    _forget_via_person(vault)
    is_error, text = _call(server, "kibisis_remember", {"category": "prefs", "key": "again", "content": FORGOTTEN})
    assert is_error and "tombstone" in text
    is_error, text = _call(server, "kibisis_remember", {"category": "prefs", "key": "again", "content": "Use tabs\ufe0f for indentation"})
    assert not is_error, text
    _, text = _call(server, "kibisis_recall", {"query": "tabs indentation"})
    assert "Use tabs\ufe0f for indentation" in text
    assert unicodedata.category("\ufe0f") == "Mn"


# --- copies the purge does not see: metadata and key names ----------------------------------------------------


def test_value_kept_in_agent_metadata_survives_the_tombstone_and_can_be_rewritten_after_it(vault, server):
    """INSECURE behaviour (passes = gap present): ``_value_copies`` (_vault_tombstone.py:73-101) compares entry
    content only, and ``_put``'s check (vault.py:1066-1079) digests content only. A copy the agent placed in
    ``metadata`` (stored under ``agent_metadata``) is neither purged nor refused afterwards."""
    _call(server, "kibisis_remember", {"category": "prefs", "key": "indent", "content": FORGOTTEN})
    _call(server, "kibisis_remember", {"category": "prefs", "key": "side", "content": "see metadata", "metadata": {"note": FORGOTTEN}})
    _forget_via_person(vault)
    assert vault.get("prefs", "side").metadata["agent_metadata"] == {"note": FORGOTTEN}
    is_error, _ = _call(server, "kibisis_remember", {"category": "prefs", "key": "later", "content": "benign", "metadata": {"v": FORGOTTEN}})
    assert not is_error
    assert vault.get("prefs", "later").metadata["agent_metadata"] == {"v": FORGOTTEN}


def test_value_used_as_a_key_survives_and_is_shown_by_mcp_recall(vault, server):
    """INSECURE behaviour (passes = gap present): the key column is not digested or purged. The agent stores the
    forgotten sentence as a key before (or after) the tombstone, and ``kibisis_recall`` prints it in the
    ``key=`` attribute of the envelope."""
    _call(server, "kibisis_remember", {"category": "prefs", "key": "indent", "content": FORGOTTEN})
    _call(server, "kibisis_remember", {"category": "prefs", "key": FORGOTTEN, "content": "stored under the value as its key"})
    _forget_via_person(vault)
    assert [e.key for e in vault.list_entities(scope="default", epistemic_state="candidate")] == [FORGOTTEN]
    is_error, _ = _call(server, "kibisis_remember", {"category": "prefs", "key": FORGOTTEN + " (v2)", "content": "benign"})
    assert not is_error
    _, text = _call(server, "kibisis_recall", {"query": "stored under the value as its key"})
    assert f'key="{FORGOTTEN}"' in text, text


def test_control_copies_in_other_categories_and_archived_rows_are_purged(vault):
    """Positive control (SECURE, passes): content copies, live or archived, in any category of the scope go."""
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct")
    vault.remember("notes", "dup", FORGOTTEN.lower(), origin="model")
    vault.remember("notes", "old", FORGOTTEN, origin="model")
    vault.archive("notes", "old")
    _forget_via_person(vault)
    assert vault.get("notes", "dup") is None
    row = vault._conn.execute("SELECT COUNT(*) FROM entities WHERE key IN ('dup','old','indent')").fetchone()[0]
    assert row == 0
    purges = [e for e in vault.list_audit_events(limit=100) if e.action == "purge"]
    assert {e.key for e in purges} == {"dup", "old"}


def test_control_other_scopes_keep_the_value_unless_the_tombstone_is_global(vault):
    """Positive control (SECURE by design, passes): a scope-bound tombstone neither purges nor blocks another
    scope; a ``'*'`` tombstone does both."""
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct", scope="a")
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct", scope="b")
    vault.review_entity("prefs", "indent", "revoked", reviewer_id="acct", scope="a")
    assert vault.get("prefs", "indent", scope="b") is not None
    vault.put("notes", "n", FORGOTTEN, origin="model", scope="b")
    vault.tombstone("prefs", "indent", content=FORGOTTEN, scope="*", origin="user")
    assert vault.get("prefs", "indent", scope="b") is None and vault.get("notes", "n", scope="b") is None
    with pytest.raises(TombstonedValueError):
        vault.put("notes", "n", FORGOTTEN, origin="model", scope="c")


# --- what the library lets anyone delete, and what nobody can delete -------------------------------------------


def test_purge_has_no_origin_check_and_leaves_no_tombstone(vault):
    """INSECURE behaviour (passes = gap present): ``purge`` (_vault_tombstone.py:25-52) takes no ``origin`` and
    deletes a verified entry outright, where ``tombstone(origin="model")`` refuses. README.md:128 names
    ``archive()`` and origin-less ``tombstone()`` as unchecked, not ``purge()``. Library-only: the MCP server
    does not expose it."""
    vault.put("ops", "d", "Deploys go out on Tuesdays.", origin="user", author_id="acct", epistemic_state="verified")
    assert vault.get("ops", "d").epistemic_state == EpistemicState.VERIFIED
    with pytest.raises(ReviewedEntryError):
        vault.tombstone("ops", "d", origin="model")
    assert vault.purge("ops", "d", author_id="mcp-agent") is True
    assert vault.get("ops", "d") is None
    assert vault.list_tombstones() == []


def test_no_public_method_removes_a_tombstone_row(vault, tmp_path):
    """SECURE behaviour (passes = closed): scrub, purge of the original key, a second tombstone under the same
    key, and ``import_snapshot(clear_existing=True)`` all keep the tombstone; only raw SQL could drop it."""
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct")
    _forget_via_person(vault)
    vault.purge("prefs", "indent")
    vault.scrub()
    vault.put("prefs", "indent", "another value", origin="user", author_id="acct")
    vault.tombstone("prefs", "indent", origin="user")  # INSERT OR REPLACE keys on (category, key, value_sha256, scope)
    snap = tmp_path / "s.json"
    vault.export_snapshot(str(snap))
    vault.import_snapshot(str(snap), clear_existing=True)
    assert vault.is_tombstoned("x", "y", FORGOTTEN)
    assert vault.is_tombstoned("x", "y", "another value")
    assert len(vault.list_tombstones()) == 2


# --- import paths and the search index re-check ------------------------------------------------------------------


def test_control_snapshot_import_refuses_a_tombstoned_value_and_import_keeps_tombstones(vault, tmp_path):
    """Positive control (SECURE, passes): a snapshot entity whose content is tombstoned here is refused
    (_vault_snapshot.py:263-275), and tombstones in the file are imported first."""
    other = SQLiteMemoryVault(":memory:", auto_gate=False)
    other.remember("notes", "n", FORGOTTEN, origin="model")
    snap = tmp_path / "s.json"
    other.export_snapshot(str(snap))
    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct")
    _forget_via_person(vault)
    assert vault.import_snapshot(str(snap)) == 0
    assert vault.get("notes", "n") is None
    refusals = [e for e in vault.list_audit_events(limit=100) if e.action == "refuse"]
    assert refusals and refusals[-1].metadata["reason"] == "tombstoned value"


def test_control_okf_style_model_import_write_is_refused(vault):
    """Positive control (SECURE, passes): the OKF importer writes through ``put(origin="model")``
    (okf/importer.py:405), and that path applies the tombstone check."""
    from kibisis.okf import importer

    vault.put("prefs", "indent", FORGOTTEN, origin="user", author_id="acct")
    _forget_via_person(vault)
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k", FORGOTTEN, origin=importer._ORIGIN, author_id=importer.IMPORTER_ID, auto_gate=False)


def test_control_search_does_not_surface_a_revoked_entry_even_before_scrub(vault):
    """Positive control (SECURE, passes): the row delete drops its FTS and term-index rows through triggers, so
    search returns nothing for its tokens before ``scrub()`` runs."""
    vault.remember("notes", "n1", "the zebra crossing is painted weekly", origin="model")
    assert [r.entity.key for r in vault.search("zebra crossing painted", match="any")] == ["n1"]
    vault.review_entity("notes", "n1", "revoked", reviewer_id="acct")
    assert vault.search("zebra crossing painted", match="any") == []
    assert vault.search("zebra crossing painted", match="any", include_unverified=True) == []
    assert vault._conn.execute("SELECT COUNT(*) FROM entities WHERE key = 'n1'").fetchone()[0] == 0
