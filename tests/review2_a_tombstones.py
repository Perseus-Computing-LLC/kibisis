"""Second-pass review (R2, area A) — tombstones: origin classes, lift, canonical fold, key/metadata digests.

Not collected by default (no ``test_`` prefix on the file); run by explicit path. Convention:
``test_control_*`` asserts the SECURE behaviour (failing = bug); ``test_attack_*`` demonstrates a
defect (PASSING = bug). Each docstring names the finding in review_notes/R2_A.md.
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
    """R2-A1 (passing = bug). ``_tombstone_locked`` writes ``INSERT OR REPLACE`` on
    UNIQUE(category, key, value_sha256, scope). A non-principal ``tombstone(content=V)`` of the same
    category/key/value replaces the person's principal-class row with a row of its own class (fresh
    MAC, so integrity checks pass). ``tool`` -> external-class, which a *model* write then lifts;
    ``model`` -> agent-class, which the person's own next write silently lifts. The documented
    guarantee "a principal-class tombstone blocks everyone until a person runs lift" is gone."""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user", author_id="alice")  # the person's rejection
    assert _classes(vault) == ["principal"]
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k2", VALUE, origin="model")

    # the agent (relayed by a library embedder) names the same category/key and the same value
    vault.tombstone("c", "k", content=VALUE, origin=downgrade_origin, author_id="mcp-agent")
    assert _classes(vault) != ["principal"], "the principal row was not replaced"

    ent = vault.put("c", "k2", VALUE, origin=lifter_origin)  # lifted: the value is back
    assert ent.content == VALUE
    assert vault.list_tombstones() == []
    lifted = [e for e in vault.list_audit_events(limit=50) if e.action == "tombstone_lifted"]
    assert lifted and lifted[0].metadata.get("tombstone_class") != "principal"


def test_attack_retombstone_downgrade_also_works_after_person_reject_via_review(vault, server):
    """R2-A1 variant (passing = bug): the person rejected an agent candidate in the review path
    (``review_entity(verdict='revoked')`` -> principal tombstone); the agent re-tombstones the same
    value through the library with origin='tool' and then writes it back through MCP."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.review_entity("c", "k", "revoked", reviewer_id="alice")
    assert _classes(vault) == ["principal"]
    assert _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.tombstone("c", "k", content=VALUE, origin="tool", author_id="mcp-agent")
    assert _classes(vault) == ["external"]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})
    assert not err, text
    assert vault.get("c", "k").content == VALUE


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


@pytest.mark.parametrize("word", ["agent", "mcp"])
def test_attack_tombstone_of_a_bookkeeping_word_blocks_every_agent_write_until_a_person_lifts(vault, server, word):
    """R2-A2 (passing = bug). ``_entry_digests`` digests every string leaf of the final ``meta``,
    which includes the vault's own fields (``origin_class='agent'``, ``act_class='inform'``, the MCP
    server's ``origin='mcp'``). One MCP remember+forget of such a word tombstones it (agent class);
    from then on every ``kibisis_remember`` in the scope is refused. A person's write does not lift
    it (their rows carry 'principal', not 'agent'), so only ``kibisis-review lift`` recovers."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": word})[0]
    assert not _call(server, "kibisis_forget", {"category": "c", "key": "k", "reason": "x"})[0]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "an unrelated fact"})
    assert err and "key or metadata" in text, text
    vault.put("c", "p", "a person's fact", origin="user")  # does not lift it
    assert _classes(vault) == ["agent"]
    err, _ = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "an unrelated fact"})
    assert err
    assert vault.lift_tombstone("c", "k") == 1
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "an unrelated fact"})[0]


def test_attack_person_reject_of_a_bookkeeping_word_blocks_the_agent_permanently(vault, server):
    """R2-A2 variant (passing = bug): the person rejects an agent candidate whose content is 'mcp'
    (the MCP server stamps metadata.origin='mcp' on every remember). The principal-class tombstone
    then refuses every later MCP write in the scope."""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": "MCP"})[0]
    vault.review_entity("c", "k", "revoked", reviewer_id="alice")
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "an unrelated fact"})
    assert err and "tombstone class: principal" in text, text


# ----------------------------------------------------------------------------------------------
# R2-A3: F12 residual — dict KEYS in metadata are not digested
# ----------------------------------------------------------------------------------------------


def test_attack_tombstoned_value_stored_as_a_metadata_dict_key_survives(vault, server):
    """R2-A3 (passing = bug). ``string_leaves`` walks dict values only. A person-rejected value is
    accepted as a key of ``agent_metadata``, is readable through ``get()`` / ``list_entities()`` and
    is not purged by ``_value_copies``. (Control: the same value as a dict *value* is refused.)"""
    assert not _call(server, "kibisis_remember", {"category": "c", "key": "k", "content": VALUE})[0]
    vault.review_entity("c", "k", "revoked", reviewer_id="alice")
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k3", "content": "x", "metadata": {"n": VALUE}})
    assert err, "control: value as a dict value must be refused"
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": "x", "metadata": {VALUE: 1}})
    assert not err, text
    assert VALUE in vault.get("c", "k2").metadata["agent_metadata"]
    # and a later principal tombstone of the value does not purge this copy
    vault.put("c", "k4", VALUE + " (copy)", origin="user")
    assert VALUE in vault.get("c", "k2").metadata["agent_metadata"]


# ----------------------------------------------------------------------------------------------
# R2-A4: canonical fold drops spacing combining marks (Mc) -> abugida words collapse
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "a, b",
    [("कल", "काल"), ("कल", "कील"), ("नमस्ते", "नमसत"), ("கல", "கால")],  # Devanagari kal/kaal/keel, namaste; Tamil kal/kaal
)
def test_attack_canonical_fold_collapses_distinct_words_in_abugida_scripts(a, b):
    """R2-A4 (passing = bug). Dropping ``Mc`` (spacing vowel signs) after NFKC makes different
    Devanagari/Tamil words identical, so a tombstone of one refuses the others (false refusals), and
    ``is_tombstoned`` reports them as rejected."""
    assert a != b
    assert canonicalize_text(a) == canonicalize_text(b)


def test_attack_tombstone_of_one_hindi_word_refuses_a_different_hindi_word(vault):
    vault.put("c", "k", "कल", origin="user")
    vault.tombstone("c", "k", origin="user")
    with pytest.raises(TombstonedValueError):
        vault.put("c", "k2", "काल", origin="user")  # a different word (time vs tomorrow)


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
    """R2-A5 (passing = bug). U+3164/U+115F/U+1160/U+FFA0 render as a blank the width of a Hangul
    syllable, so 'DeploysㅤgoㅤoutㅤonㅤTuesdays.' reads as the rejected sentence; the fold DROPS
    them (``_IGNORABLE_CODE_POINTS``) instead of turning them into a space, the words fuse, the
    canonical digest differs and ``kibisis_remember`` accepts it. (Controls: braille
    blank U+2800 and NBSP in place of spaces are refused.)"""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user")
    for control in ("\u2800", "\u00a0"):
        assert _call(server, "kibisis_remember", {"category": "c", "key": "c", "content": VALUE.replace(" ", control)})[0]
    err, text = _call(server, "kibisis_remember", {"category": "c", "key": "k2", "content": VALUE.replace(" ", blank)})
    assert not err, text
    assert vault.get("c", "k2").content == VALUE.replace(" ", blank)


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
# lift_tombstone is a public, un-gated library method
# ----------------------------------------------------------------------------------------------


def test_attack_lift_tombstone_has_no_origin_and_no_terminal_check(vault):
    """R2-A6 (documents; passing = docs overstate). ``SQLiteMemoryVault.lift_tombstone`` takes no
    ``origin`` and runs no check; README/SECURITY say the review CLI's lift verb is 'the only way
    past a principal-class tombstone'. Any library embedder relaying an agent can call it."""
    vault.put("c", "k", VALUE, origin="user")
    vault.tombstone("c", "k", origin="user")
    assert vault.lift_tombstone("c", "k", author_id="mcp-agent") == 1
    assert vault.put("c", "k", VALUE, origin="model").content == VALUE
