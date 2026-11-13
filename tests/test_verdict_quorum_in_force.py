"""Every verdict that can mint ``verified`` is settled against the quorum in force when it is recorded.

The quorum is a property of the vault file and a stored quorum is a floor. A vault opened before
another connection's pinning open raised the file's quorum settles its later verdicts against the
raised value, on both paths that mint ``verified``: a person's review (``review_entity``) and the
author's attestation on a ``user``-origin write that asks for ``verified``. ``quorum_at_verification``
and ``verification_pending`` record the quorum actually applied. A process that asked for more than
the file's quorum keeps its own; nothing lowers a process's quorum; entries verified before a raise
stay as they were.
"""

import pytest

from kibisis import SQLiteMemoryVault

PASS = "verdict-quorum-passphrase-not-secret"
CLAIM = "a claim three people may vouch for"


def _open(path, **kwargs):
    return SQLiteMemoryVault(str(path), passphrase=PASS, trust_caller_identity=True, **kwargs)


def _raise_files_quorum(path, quorum):
    raiser = _open(path, verification_quorum=quorum, pin_quorum=True)
    try:
        assert raiser.verification_quorum_stored == quorum
    finally:
        raiser.close()


def _row(vault, key):
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    row = {(r.category, r.key): r for r in rows}[("notes", key)]
    meta = row.metadata or {}
    return (
        row.epistemic_state.value,
        list(meta.get("attestations") or []),
        meta.get("quorum_at_verification"),
        meta.get("verification_pending"),
    )


def _review(vault, key, person):
    vault.review_entity("notes", key, "verified", reviewer_id=person, attester=person)


def _attest(vault, key, person):
    vault.put("notes", key, CLAIM, origin="user", epistemic_state="verified", attester=person)


PATHS = {"review": _review, "author": _attest}


@pytest.fixture(params=sorted(PATHS))
def verdict(request):
    return request.param, PATHS[request.param]


def _seed(vault, name, key):
    if name == "review":
        vault.put("notes", key, CLAIM, origin="model")


def test_a_raise_after_open_governs_the_next_verdict(tmp_path, verdict):
    name, act = verdict
    path = tmp_path / "vault.sqlite"
    early = _open(path)  # nothing stored: the default quorum of two
    try:
        assert (early.verification_quorum, early.verification_quorum_stored) == (2, None)
        _seed(early, name, "fact")
        act(early, "fact", "alice")
        assert _row(early, "fact") == ("candidate", ["alice"], None, {"have": 1, "need": 2})
        _raise_files_quorum(path, 3)
        act(early, "fact", "bob")
        assert _row(early, "fact") == ("candidate", ["alice", "bob"], None, {"have": 2, "need": 3})
        assert (early.verification_quorum, early.verification_quorum_stored) == (3, 3)
        act(early, "fact", "carol")
        assert _row(early, "fact") == ("verified", ["alice", "bob", "carol"], 3, None)
    finally:
        early.close()
    fresh = _open(path)
    try:
        assert fresh.verification_quorum == 3
        assert _row(fresh, "fact")[0] == "verified"
    finally:
        fresh.close()


def test_a_process_that_asked_for_more_keeps_its_own(tmp_path, verdict):
    name, act = verdict
    path = tmp_path / "vault.sqlite"
    strict = _open(path, verification_quorum=4)  # asks for four; pins nothing
    try:
        _seed(strict, name, "fact")
        _raise_files_quorum(path, 3)
        for person in ("alice", "bob", "carol"):
            act(strict, "fact", person)
        assert _row(strict, "fact") == ("candidate", ["alice", "bob", "carol"], None, {"have": 3, "need": 4})
        assert (strict.verification_quorum, strict.verification_quorum_stored) == (4, 3)
        act(strict, "fact", "dave")
        assert _row(strict, "fact")[0::2] == ("verified", 4)
    finally:
        strict.close()


def test_a_lower_stored_quorum_never_lowers_a_process(tmp_path, verdict):
    name, act = verdict
    path = tmp_path / "vault.sqlite"
    early = _open(path)  # the default quorum of two
    try:
        _seed(early, name, "fact")
        _raise_files_quorum(path, 1)  # nothing was stored, so a pinning open that names one stores one
        act(early, "fact", "alice")
        assert _row(early, "fact") == ("candidate", ["alice"], None, {"have": 1, "need": 2})
        assert early.verification_quorum == 2
        act(early, "fact", "bob")
        assert _row(early, "fact")[0::2] == ("verified", 2)
    finally:
        early.close()


def test_entries_verified_before_a_raise_are_left_as_they_were(tmp_path, verdict):
    name, act = verdict
    path = tmp_path / "vault.sqlite"
    early = _open(path)
    try:
        _seed(early, name, "before")
        act(early, "before", "alice")
        act(early, "before", "bob")
        before = _row(early, "before")
        assert before == ("verified", ["alice", "bob"], 2, None)
        _raise_files_quorum(path, 3)
        _seed(early, name, "after")
        act(early, "after", "alice")
        act(early, "after", "bob")
        assert _row(early, "after")[0] == "candidate"
        assert _row(early, "before") == before
    finally:
        early.close()
    fresh = _open(path)
    try:
        assert _row(fresh, "before") == before
    finally:
        fresh.close()
