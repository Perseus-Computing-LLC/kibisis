"""Second-pass review (R2, area A) — tombstones: origin classes, lift, canonical fold, key/metadata digests.

Regression tests for review_notes/R2_A.md. ``test_control_*`` assert behaviour the first-round fixes
established; ``test_attack_*`` were the R2 repros and now assert the FIXED behaviour (each docstring
names the finding and what the fix guarantees).
"""

import pytest

from kibisis import KibisisMCPServer, SQLiteMemoryVault
from kibisis._vault_crypto import canonicalize_text
from kibisis.vault import ReviewedEntryError, TombstonedValueError

VALUE = "Deploys go out on Tuesdays."


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ARGUS_LEDGER_PATH", "")


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


def _classes(vault):
    return [t["origin_class"] for t in vault.list_tombstones()]


# ----------------------------------------------------------------------------------------------
# Controls: the F1 / F3 / F19 / F10 fixes hold on the paths the fixer tested
# ----------------------------------------------------------------------------------------------


def test_control_principal_tombstone_blocks_model_write(vault):
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user", author_id="alice")
    assert _classes(vault) == ["principal"]
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k2", VALUE, origin="model")


def test_control_model_tombstone_with_content_cannot_delete_verified_entry(vault):
    vault.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    assert vault.get("c", "k").epistemic_state.value == "verified"
    for content in (VALUE, "nothing stored anywhere"):
        with pytest.raises(ReviewedEntryError):
            vault.tombstone("c", "k", content=content, origin="model", author_id="mcp-agent")
    assert vault.get("c", "k") is not None
    assert vault.list_tombstones() == []


def test_control_model_tombstone_wildcard_scope_refused(vault):
    vault.put("c", "k", VALUE, origin="model")
    with pytest.raises(PermissionError):
        vault.tombstone("c", "k", content=VALUE, scope="*", origin="model")
    assert vault.list_tombstones() == []


def test_control_model_purge_of_verified_entry_refused(vault):
    vault.put("c", "k", VALUE, origin="user", epistemic_state="verified")
    with pytest.raises(ReviewedEntryError):
        vault.purge("c", "k", origin="model")
    assert vault.get("c", "k") is not None


def test_control_mcp_forget_is_agent_class_and_a_person_lifts_by_writing(vault, server):
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    assert not _call(server, "kibisis_forget", {"category": "c", "key": "k", "reason": "x"})[0]
    assert _classes(vault) == ["agent"]
    ent = vault.put("c", "k", VALUE, origin="user")  # person outranks the agent's tombstone
    assert ent.content == VALUE
    assert vault.list_tombstones() == []
    assert "tombstone_lifted" in [e.action for e in vault.list_audit_events(limit=50)]


# ----------------------------------------------------------------------------------------------
# R2-A1: INSERT OR REPLACE lets a lower-class request REPLACE a principal-class tombstone row
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("downgrade_origin, lifter_origin", [("tool", "model"), ("model", "user")])
def test_attack_retombstone_downgrades_principal_tombstone_class(vault, downgrade_origin, lifter_origin):
    """R2-A1 fixed. A non-principal ``tombstone(content=V)`` of a value that already has a person's
    principal-class row leaves the row (class and MAC) as it is and journals ``tombstone_reaffirmed``;
    a later write by any class below principal is still refused, and the refusal names the principal
    class. The guarantee "a principal-class tombstone blocks everyone until a person lifts it" holds."""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user", author_id="alice")  # the person's rejection
    assert _classes(vault) == ["principal"]
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k2", VALUE, origin="model")

    # the agent (relayed by a library embedder) names the same category/key and the same value
    vault.tombstone("c", "k", content=VALUE, origin=downgrade_origin, author_id="mcp-agent")
    assert _classes(vault) == ["principal"], "the principal row must not be replaced"
    acts = [e.action for e in vault.list_audit_events(limit=50)]
    assert "tombstone_reaffirmed" in acts
    reaffirmed = [e for e in vault.list_audit_events(limit=50) if e.action == "tombstone_reaffirmed"][0]
    assert reaffirmed.metadata["origin_class"] == "principal"
    assert reaffirmed.metadata["requester_class"] != "principal"

    with pytest.raises(TombstonedValueError, match="tombstone class: principal"):
        vault.put("c", "k2", VALUE, origin=lifter_origin)
    assert _classes(vault) == ["principal"]
    assert "tombstone_lifted" not in [e.action for e in vault.list_audit_events(limit=50)]


def test_attack_retombstone_downgrade_also_works_after_person_reject_via_review(vault, server):
    """R2-A1 fixed (review path): the person rejected an agent candidate in the review path
    (``review_entity(verdict='revoked')`` -> principal tombstone); the agent re-tombstones the same
    value through the library with origin='tool' and the row stays principal, so the agent's MCP
    write of the value is still refused."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.review_entity("c", "k", "revoked", reviewer_id="alice")
    assert _classes(vault) == ["principal"]
    assert _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.tombstone("c", "k", content=VALUE, origin="tool", author_id="mcp-agent")
    assert _classes(vault) == ["principal"]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})
    assert err and "tombstone class: principal" in text, text
    assert vault.get("c", "k") is None


def test_control_higher_class_retombstone_raises_the_row_class_and_resigns_it(vault):
    """The row's class is the highest class that ever asked: an agent's tombstone that a person later
    confirms (``tombstone(content=V, origin='user')``) becomes principal with a fresh MAC, journaled
    as a ``tombstone`` event; the vault reopens clean (every row verifies against its MAC)."""
    vault.put("c", "k", VALUE, origin="model")
    vault.tombstone("c", "k", origin="model", author_id="mcp-agent")
    assert _classes(vault) == ["agent"]
    vault.tombstone("c", "k", content=VALUE, origin="user", author_id="alice")
    assert _classes(vault) == ["principal"]
    events = [e for e in vault.list_audit_events(limit=50) if e.action == "tombstone"]
    assert any(e.metadata["origin_class"] == "principal" and e.metadata["stored_class"] == "agent" for e in events)
    assert len(vault.list_tombstones()) == 1
    with pytest.raises(TombstonedValueError, match="tombstone class: principal"):
        vault.put("c", "k2", VALUE, origin="user")
    vault._check_tombstones()  # every row's MAC verifies and every journaled tombstone has its row


def test_control_mcp_alone_cannot_replace_a_principal_tombstone_row(vault, server):
    """MCP has no ``content`` argument: forget on the key records a row for the *stored* value, so the
    person's row survives. The downgrade needs the library ``content=`` form."""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user", author_id="alice")
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "other"})[0]
    assert not _call(server, "kibisis_forget", {"category": "c", "key": "k", "reason": "x"})[0]
    assert sorted(_classes(vault)) == ["agent", "principal"]
    assert _call(server, "kibisis_remember", {"category": "c", "key": "k3", "content": VALUE})[0]


# ----------------------------------------------------------------------------------------------
# R2-A2: metadata-leaf digests match the vault's OWN bookkeeping strings -> write-path denial
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("word", ["agent", "mcp", "inform"])
def test_attack_tombstone_of_a_bookkeeping_word_blocks_every_agent_write_until_a_person_lifts(vault, server, word):
    """R2-A2 fixed. ``_entry_digests`` matches the content, the key and the caller's own metadata
    (``agent_metadata``, keys and values) only, never the vault's bookkeeping strings
    (``origin_class='agent'``, ``act_class='inform'``, the MCP server's ``origin='mcp'``). An MCP
    remember+forget of such a word tombstones the word; later writes of other content in the scope
    are accepted, and the word itself is still refused as content, key or agent metadata."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": word})[0]
    assert not _call(server, "kibisis_forget", {"category": "c", "key": "k", "reason": "x"})[0]
    assert _classes(vault) == ["agent"]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "an unrelated fact"})
    assert not err, text
    assert vault.get("c", "k2").content == "an unrelated fact"
    assert _call(server, "kibisis_remember", {"category": "c", "key": "k3", "content": word})[0]
    assert _call(server, "kibisis_remember", {"category": "c", "key": word, "content": "x"})[0]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k4", "content": "x", "metadata": {"n": word}})
    assert err and "key or metadata" in text, text
    assert _classes(vault) == ["agent"]


def test_attack_person_reject_of_a_bookkeeping_word_blocks_the_agent_permanently(vault, server):
    """R2-A2 fixed (principal variant): the person rejects an agent candidate whose content is 'mcp'
    (the MCP server stamps metadata.origin='mcp' on every remember). The principal-class tombstone
    refuses the word, not every later MCP write in the scope."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "MCP"})[0]
    vault.review_entity("c", "k", "revoked", reviewer_id="alice")
    assert _classes(vault) == ["principal"]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "an unrelated fact"})
    assert not err, text
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k3", "content": "mcp"})
    assert err and "tombstone class: principal" in text, text


# ----------------------------------------------------------------------------------------------
# R2-A3: F12 residual — dict KEYS in metadata are digested too
# ----------------------------------------------------------------------------------------------


def test_attack_tombstoned_value_stored_as_a_metadata_dict_key_survives(vault, server):
    """R2-A3 fixed. ``string_leaves`` yields dict keys as well as values, at any depth: a
    person-rejected value is refused as a key of ``agent_metadata``, nested or not, and a copy that
    was stored before the rejection is purged with the rest. (Control: as a dict value too.)"""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.review_entity("c", "k", "revoked", reviewer_id="alice")
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k3", "content": "x", "metadata": {"n": VALUE}})
    assert err, "control: value as a dict value must be refused"
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "x", "metadata": {VALUE: 1}})
    assert err and "key or metadata" in text, text
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "x", "metadata": {"a": {VALUE: 1}}})
    assert err and "key or metadata" in text, text
    assert vault.get("c", "k2") is None
    # a copy filed as a key before the value was rejected is purged by the rejection
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k5", "content": "copy holder", "metadata": {"x": 1}})[0]
    vault.put("c", "k6", "another holder", origin="user", metadata={"agent_metadata": {"n": {"x": "v"}}})
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k7", "content": "y", "metadata": {"copy": 1}})[0]
    vault.put("c", "k8", "x", origin="user")
    vault.tombstone("c", "k8", origin="user", author_id="alice")  # rejects the value "x"
    assert vault.get("c", "k5") is None and vault.get("c", "k6") is None
    assert vault.get("c", "k7") is not None


# ----------------------------------------------------------------------------------------------
# R2-A4: canonical fold drops spacing combining marks (Mc) -> abugida words collapse
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "a, b",
    [("कल", "काल"), ("कल", "कील"), ("கல", "கால")],  # Devanagari kal/kaal/keel; Tamil kal/kaal (Mc vowel signs)
)
def test_attack_canonical_fold_collapses_distinct_words_in_abugida_scripts(a, b):
    """R2-A4 fixed. Spacing combining marks (``Mc``, the side vowel signs) are kept by the fold, so
    different Devanagari/Tamil words keep different digests and a tombstone of one does not refuse
    the others."""
    assert a != b
    assert canonicalize_text(a) != canonicalize_text(b)


def test_control_fold_still_drops_nonspacing_marks_by_design():
    """R2-A4 scope: nonspacing marks (``Mn``: the virama, above/below vowel signs, the evasion marks
    an attacker adds to a Latin word) are still dropped, so a word that differs only in such a sign
    folds alike. The exact digest still tells them apart; only the canonical match is wider."""
    assert canonicalize_text("नमस्ते") == canonicalize_text("नमसत")
    assert canonicalize_text("a\u0334b") == canonicalize_text("ab")  # a mark NFKC cannot compose is dropped


def test_attack_tombstone_of_one_hindi_word_refuses_a_different_hindi_word(vault):
    """R2-A4 fixed: a rejection of 'कल' (tomorrow) does not refuse 'काल' (time)."""
    vault.put("c", "k", "कल", origin="user")
    vault.tombstone("c", "k", origin="user")
    assert vault.put("c", "k2", "काल", origin="user").content == "काल"  # a different word (time vs tomorrow)
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k3", "कल", origin="user")
    assert vault.is_tombstoned("c", "k", "कल") and not vault.is_tombstoned("c", "k", "काल")


def test_control_fold_keeps_latin_accents_distinct_from_their_base():
    """NFKC composes e + U+0301 to the precomposed é before the Mn drop, so Latin accents survive and
    'résumé' stays distinct from 'resume' in both spellings (the Mc/Mn drop hurts abugidas only)."""
    assert canonicalize_text("résumé") != canonicalize_text("resume")
    assert canonicalize_text("re\u0301sume\u0301") == canonicalize_text("résumé")


# ----------------------------------------------------------------------------------------------
# R2-A5: F5 residual — a Hangul filler is a VISIBLE blank but is dropped, not spaced
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["\u3164", "\u115f", "\u1160", "\uffa0"])
def test_attack_hangul_filler_in_place_of_spaces_brings_a_rejected_value_back_through_mcp(vault, server, blank):
    """R2-A5 fixed. U+3164/U+115F/U+1160/U+FFA0 render as a blank the width of a Hangul syllable,
    so 'DeploysㅤgoㅤoutㅤonㅤTuesdays.' reads as the rejected sentence; the fold turns them into a
    SPACE (``_BLANK_CODE_POINTS``), the canonical digest matches and ``kibisis_remember`` refuses it.
    (Controls: braille blank U+2800 and NBSP in place of spaces are refused.)"""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user")
    for control in ("\u2800", "\u00a0"):
        assert _call(server, "kibisis_remember", {"category": "c", "key": "c", "content": VALUE.replace(" ", control)})[0]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": VALUE.replace(" ", blank)})
    assert err and "tombstone" in text, text
    assert vault.get("c", "k2") is None
    assert canonicalize_text("a" + blank + "b") == "a b"


# ----------------------------------------------------------------------------------------------
# F5 controls — the homoglyph / mark fold holds for the cases the original review used
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    [
        VALUE.replace("T", "T\ufe0f"),
        VALUE.replace("o", "o\u034f"),
        VALUE + "\u180b",
        VALUE + "\u3164",
        VALUE.replace("a", "\u0430"),  # Cyrillic a
        VALUE.replace("i", "\u0131"),  # dotless i
    ],
)
def test_control_f5_variants_are_refused_through_mcp(vault, server, variant):
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user")
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": variant})
    assert err and "tombstone" in text


# ----------------------------------------------------------------------------------------------
# lift_tombstone is a person's act: the library method takes an origin and refuses the other classes
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", ["model", "tool", "unknown"])
def test_attack_lift_tombstone_has_no_origin_and_no_terminal_check(vault, origin):
    """R2-A6 fixed. ``SQLiteMemoryVault.lift_tombstone`` takes ``origin``; a request from outside
    the principal class is refused with ``PermissionError`` (journaled as a refusal), whatever class
    the tombstone carries, and the value stays refused. A library embedder relaying an agent passes
    the agent's origin and cannot lift."""
    vault.put("c", "k", VALUE, origin="model")
    vault.tombstone("c", "k", origin="model")  # an agent-class row: even that is not the agent's to lift
    with pytest.raises(PermissionError, match="person's act"):
        vault.lift_tombstone("c", "k", author_id="mcp-agent", origin=origin)
    assert _classes(vault) == ["agent"]
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k", VALUE, origin="model")
    assert any(e.action == "refuse" and e.metadata.get("path") == "lift_tombstone" for e in vault.list_audit_events(limit=20))


def test_control_lift_tombstone_by_a_person_or_a_vouching_caller(vault):
    """A person (``origin='user'``) or a caller that vouches for one (``origin=None``, the review
    CLI after its terminal check) lifts; the value is admitted again."""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user")
    assert vault.lift_tombstone("c", "k", author_id="alice", origin="user") == 1
    assert vault.put("c", "k", VALUE, origin="model").content == VALUE
    vault.tombstone("c", "k", origin="user")
    assert vault.lift_tombstone("c", "k", author_id="alice") == 1
    assert vault.put("c", "k", VALUE, origin="model").content == VALUE
