"""okf import judges each concept on its row inside that row's own write transaction.

A row another connection changes after the importer's scan is judged as an import started after the
change would judge it (each conflict kind, and the unchanged/changed decision, the stored claims and the
metadata the write carries forward). The judgement runs under the vault's write lock, so nothing can land
between it and the write. A refusal the vault still raises is reported under its conflict name, leaves
nothing of that row written, is journaled once (after the rollback, so it is not lost) and does not stop
the other rows.
"""

import pytest

from kibisis import SQLiteMemoryVault
from kibisis.okf import importer

PASS = "okf-judged-write-passphrase-not-secret"
BODY = "Bound body.\n"
EDITED_BODY = "Bound body, edited.\n"
EDITED = "---\ntype: Decision\n---\n" + EDITED_BODY
BOUND = ("default", "decision", "bound")
BOUND_REL = "default/decision/bound.md"
FRESH_BODY = "A fresh value.\n"
FRESH = "---\ntype: Decision\n---\n" + FRESH_BODY
FRESH_KEY = ("default", "decision", "fresh")
FRESH_REL = "default/decision/fresh.md"


def _pair(tmp_path):
    path = str(tmp_path / "vault.sqlite")
    agent = SQLiteMemoryVault(path, passphrase=PASS)
    person = SQLiteMemoryVault(path, passphrase=PASS)  # a second vault object on the same file
    person._conn.execute("PRAGMA busy_timeout = 200")
    return agent, person


def _bundle(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return root


def _rows(vault):
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    return {(r.scope, r.category, r.key): r for r in rows}


def _events(vault, key):
    events = vault.list_audit_events(scope="default", category="decision", key=key, limit=100000)
    return sorted(events, key=lambda e: e.sequence)


def _after_scan(monkeypatch, vault, change):
    """Run ``change`` once, right after the importer's scan of ``vault`` reads its rows."""
    scan = vault.list_entities
    done = []

    def scan_then_change(*args, **kwargs):
        rows = scan(*args, **kwargs)
        if not done:
            change()  # commits on the other connection: no write lock is held at the scan
            done.append(True)
        return rows

    monkeypatch.setattr(vault, "list_entities", scan_then_change)
    return done


def _seed_bound(agent, person):
    agent.put("decision", "bound", BODY, origin="model")


def _seed_src_and_dep(agent, person):
    agent.put("decision", "src", "A source.\n", origin="model")
    agent.put("decision", "bound", BODY, origin="model", derived_from=["decision:src"])


def _seed_nothing(agent, person):
    return None


# (name, seed, bundle files, the change another connection commits after the scan, expected conflicts,
#  the entry to check, what that entry must hold after the import)
CONFLICT_CASES = [
    ("archived", _seed_bound, {BOUND_REL: EDITED},
     lambda person: person.archive("decision", "bound", origin="user"),
     {BOUND_REL: "archived"}, BOUND, lambda row: row.archived and row.content == BODY),
    ("confidential", _seed_bound, {BOUND_REL: EDITED},
     lambda person: person.put("decision", "bound", BODY, metadata={"confidential": True}, origin="model"),
     {BOUND_REL: "confidential"}, BOUND, lambda row: row.content == BODY and row.metadata.get("confidential")),
    ("origin_class", _seed_bound, {BOUND_REL: EDITED},
     lambda person: person.put("decision", "bound", "A person's text.\n", origin="user"),
     {BOUND_REL: "origin_class"}, BOUND, lambda row: row.content == "A person's text.\n"),
    ("tombstoned_rewrite", _seed_bound, {BOUND_REL: EDITED},
     lambda person: person.tombstone("decision", "bound", reason="revocation", content=EDITED_BODY, origin="user"),
     {BOUND_REL: "tombstoned"}, BOUND, lambda row: row.content == BODY),
    ("disputed", _seed_src_and_dep, {BOUND_REL: EDITED},
     lambda person: person.review_entity("decision", "src", verdict="revoked", reviewer_id="owner"),
     {BOUND_REL: "disputed"}, BOUND, lambda row: row.content == BODY and row.epistemic_state == "disputed"),
    ("key_collision", _seed_nothing, {FRESH_REL: FRESH},
     lambda person: person.put("decision", "Fresh", "Another text.\n", origin="model"),
     {FRESH_REL: "key_collision"}, FRESH_KEY, lambda row: row is None),
    ("tombstoned_new", _seed_nothing, {FRESH_REL: FRESH},
     lambda person: person.tombstone("decision", "fresh", reason="revocation", content=FRESH_BODY, origin="user"),
     {FRESH_REL: "tombstoned"}, FRESH_KEY, lambda row: row is None),
    ("origin_class_new", _seed_nothing, {FRESH_REL: FRESH},
     lambda person: person.put("decision", "fresh", "A person's text.\n", origin="user"),
     {FRESH_REL: "origin_class"}, FRESH_KEY, lambda row: row is not None and row.content == "A person's text.\n"),
]


@pytest.mark.parametrize("name,seed,files,change,conflicts,entry,holds", CONFLICT_CASES,
                         ids=[case[0] for case in CONFLICT_CASES])
@pytest.mark.parametrize("when", ["before_the_import", "after_the_scan"])
def test_a_conflict_that_arises_after_the_scan_is_judged_as_one_that_was_there_before(
        tmp_path, monkeypatch, when, name, seed, files, change, conflicts, entry, holds):
    agent, person = _pair(tmp_path)
    try:
        seed(agent, person)
        bundle = _bundle(tmp_path / "bundle", files)
        if when == "before_the_import":
            change(person)
            done = [True]
        else:
            done = _after_scan(monkeypatch, agent, lambda: change(person))
        report = importer.import_bundle(agent, bundle)
        monkeypatch.undo()
        assert done == [True]
        assert report.conflicts == conflicts, (name, when)
        assert report.written == [] and report.new == [] and report.changed == []
        assert holds(_rows(agent).get(entry)), (name, when)
    finally:
        person.close()
        agent.close()


def test_a_row_changed_after_the_scan_is_rewritten_although_the_scan_saw_it_unchanged(tmp_path, monkeypatch):
    agent, person = _pair(tmp_path)
    try:
        agent.put("decision", "bound", BODY, origin="model")
        bundle = _bundle(tmp_path / "bundle", {BOUND_REL: EDITED})
        assert importer.import_bundle(agent, bundle).written == [BOUND_REL]
        done = _after_scan(monkeypatch, agent,
                           lambda: person.put("decision", "bound", "Changed by a model.\n", origin="model"))
        report = importer.import_bundle(agent, bundle)
        monkeypatch.undo()
        assert done == [True]
        assert report.unchanged == 0 and report.changed == [BOUND_REL] and report.written == [BOUND_REL]
        assert _rows(agent)[BOUND].content == EDITED_BODY
    finally:
        person.close()
        agent.close()


def test_a_row_another_import_wrote_after_the_scan_is_unchanged_and_its_claims_are_not_counted_again(
        tmp_path, monkeypatch):
    agent, person = _pair(tmp_path)
    try:
        agent.put("decision", "bound", BODY, origin="model")
        bundle = _bundle(tmp_path / "bundle",
                         {BOUND_REL: "---\ntype: Decision\nverified: human:owner\n---\n" + EDITED_BODY})
        other = []
        done = _after_scan(monkeypatch, agent, lambda: other.append(importer.import_bundle(person, bundle)))
        report = importer.import_bundle(agent, bundle)
        monkeypatch.undo()
        assert done == [True]
        assert other[0].written == [BOUND_REL] and other[0].claims == 1
        written = _rows(agent)[BOUND]
        assert report.unchanged == 1 and report.written == [] and report.changed == [] and report.claims == 0
        assert written.content == EDITED_BODY
        assert [c["by"] for c in written.metadata["okf_verified_claims"]] == ["human:owner"]
        assert written.version == _rows(person)[BOUND].version
    finally:
        person.close()
        agent.close()


def test_the_judgement_and_the_write_hold_the_write_lock(tmp_path, monkeypatch):
    agent, person = _pair(tmp_path)
    try:
        agent.put("decision", "bound", BODY, origin="model")
        judge = importer._judge
        attempts = []

        def judge_while_a_person_tries_to_archive(vault, c, row, collides):
            try:
                person.archive("decision", "bound", origin="user")
                attempts.append("committed")
            except Exception as exc:  # noqa: BLE001 - the vault's SQLite driver raises its own OperationalError
                attempts.append(f"{type(exc).__name__}: {exc}")
            return judge(vault, c, row, collides)

        monkeypatch.setattr(importer, "_judge", judge_while_a_person_tries_to_archive)
        report = importer.import_bundle(agent, _bundle(tmp_path / "bundle", {BOUND_REL: EDITED}))
        monkeypatch.undo()
        assert attempts == ["OperationalError: database is locked"]
        assert report.written == [BOUND_REL]
        row = _rows(person)[BOUND]
        assert not row.archived and row.content == EDITED_BODY
    finally:
        person.close()
        agent.close()


def test_a_refusal_in_the_write_is_its_conflict_journaled_once_and_the_other_rows_are_written(
        tmp_path, monkeypatch):
    agent, person = _pair(tmp_path)
    try:
        agent.put("decision", "held", "A person's text.\n", origin="user")
        before = _events(agent, "held")
        # The judgement misses the class conflict, so the vault's own refusal decides this row.
        monkeypatch.setattr(importer, "_row_conflict", lambda vault, row, body: None)
        report = importer.import_bundle(agent, _bundle(tmp_path / "bundle", {
            "default/decision/held.md": "---\ntype: Decision\n---\nOverwritten.\n",
            "default/decision/other.md": "---\ntype: Decision\n---\nAnother.\n",
        }))
        assert report.conflicts == {"default/decision/held.md": "origin_class"}
        assert report.written == ["default/decision/other.md"] and report.new == ["default/decision/other.md"]
        rows = _rows(agent)
        assert rows[("default", "decision", "held")].content == "A person's text.\n"
        assert rows[("default", "decision", "other")].content == "Another.\n"
        new = _events(agent, "held")[len(before):]
        assert [e.action for e in new] == ["refuse"]
        assert new[0].metadata["reason"] == "origin_class_refused"
        assert _events(person, "held")[len(before):] == new  # committed, not only seen by the importer
    finally:
        person.close()
        agent.close()
