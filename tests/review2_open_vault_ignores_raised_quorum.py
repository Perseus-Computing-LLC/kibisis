"""severity: high
finding: a vault object opened before a pinning open raised the file's verification quorum still mints verified under its old, lower quorum
"""

from kibisis import SQLiteMemoryVault

PASS = "review2-quorum-passphrase-not-secret"


def _open(path, **kwargs):
    return SQLiteMemoryVault(path, passphrase=PASS, trust_caller_identity=True, **kwargs)


def _approve(vault, key, *people):
    for person in people:
        vault.review_entity("notes", key, "verified", reviewer_id=person, attester=person)


def _state(vault, key):
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    row = {(r.category, r.key): r for r in rows}[("notes", key)]
    return row.epistemic_state.value, list((row.metadata or {}).get("attestations") or [])


def test_control_before_any_raise_two_approvals_verify(tmp_path):
    vault = _open(str(tmp_path / "vault.sqlite"))
    try:
        assert vault.verification_quorum == 2
        vault.put("notes", "fact", "a claim the model made", origin="model")
        _approve(vault, "fact", "alice")
        assert _state(vault, "fact")[0] == "candidate"
        _approve(vault, "fact", "bob")
        assert _state(vault, "fact") == ("verified", ["alice", "bob"])
    finally:
        vault.close()


def test_control_a_vault_opened_after_the_raise_needs_three_approvals(tmp_path):
    path = str(tmp_path / "vault.sqlite")
    raiser = _open(path, verification_quorum=3, pin_quorum=True)
    later = _open(path)
    try:
        assert raiser.verification_quorum_stored == 3
        assert later.verification_quorum == 3
        later.put("notes", "fact", "a claim the model made", origin="model")
        _approve(later, "fact", "alice", "bob")
        assert _state(later, "fact")[0] == "candidate"
        _approve(later, "fact", "carol")
        assert _state(later, "fact")[0] == "verified"
    finally:
        later.close()
        raiser.close()


def test_a_vault_opened_before_the_raise_does_not_verify_below_the_files_quorum(tmp_path):
    path = str(tmp_path / "vault.sqlite")
    early = _open(path)  # nothing stored yet: runs with the default quorum of two
    try:
        early.put("notes", "fact", "a claim the model made", origin="model")
        raiser = _open(path, verification_quorum=3, pin_quorum=True)
        try:
            assert raiser.verification_quorum_stored == 3  # the file's quorum is now three
        finally:
            raiser.close()
        _approve(early, "fact", "alice", "bob")
        state, attested = _state(early, "fact")
        # SECURITY.md: "The quorum itself is a property of the vault file, not a per-process setting".
        assert state != "verified", ("verified on two attestations; the file's quorum is three", attested)
        fresh = _open(path)
        try:
            assert fresh.verification_quorum == 3
            assert _state(fresh, "fact")[0] != "verified"
        finally:
            fresh.close()
    finally:
        early.close()
