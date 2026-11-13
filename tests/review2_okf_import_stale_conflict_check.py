"""severity: medium
finding: okf import_bundle decides a row's conflicts on a read taken before its writes, so a row a person archives in between is revived with model content
"""

from kibisis import SQLiteMemoryVault
from kibisis.okf import importer

PASS = "review2-okf-race-passphrase-not-secret"
BODY = "Bound body.\n"
EDITED = "---\ntype: Decision\n---\nBound body, edited.\n"


def _bundle(root):
    path = root / "default" / "decision" / "bound.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(EDITED.encode("utf-8"))
    return root


def _row(vault):
    rows = vault.list_entities(scope="*", include_archived=True, include_unverified=True)
    return {(r.scope, r.category, r.key): r for r in rows}[("default", "decision", "bound")]


def _pair(tmp_path):
    path = str(tmp_path / "vault.sqlite")
    agent = SQLiteMemoryVault(path, passphrase=PASS)
    agent.put("decision", "bound", BODY, origin="model")
    person = SQLiteMemoryVault(path, passphrase=PASS)  # a second vault object on the same file
    # If a fixed importer holds the write lock here, the person's archive gives up quickly instead of
    # waiting 30 s; it then never committed and the test does not ask for it to be honoured.
    person._conn.execute("PRAGMA busy_timeout = 200")
    return agent, person


def test_control_a_row_archived_before_the_import_is_a_conflict(tmp_path):
    agent, person = _pair(tmp_path)
    try:
        person.archive("decision", "bound", origin="user")
        report = importer.import_bundle(agent, _bundle(tmp_path / "bundle"))
        assert report.conflicts == {"default/decision/bound.md": "archived"}
        assert report.written == []
        row = _row(agent)
        assert row.archived and row.content == BODY
    finally:
        person.close()
        agent.close()


def test_control_without_the_archive_the_import_rewrites_the_row(tmp_path):
    agent, person = _pair(tmp_path)
    try:
        report = importer.import_bundle(agent, _bundle(tmp_path / "bundle"))
        assert report.written == ["default/decision/bound.md"]
        row = _row(agent)
        assert not row.archived and row.content == "Bound body, edited.\n"
    finally:
        person.close()
        agent.close()


def test_a_row_archived_after_the_importers_scan_is_not_revived(tmp_path, monkeypatch):
    agent, person = _pair(tmp_path)
    scan = agent.list_entities
    committed = []

    def scan_then_person_archives(*args, **kwargs):
        rows = scan(*args, **kwargs)
        if not committed:
            # A person archives the row on the other connection after the importer read it and
            # before the importer writes it.
            try:
                person.archive("decision", "bound", origin="user")
                committed.append(True)
            except Exception:  # noqa: BLE001 - the importer held the write lock: no race to honour
                committed.append(False)
        return rows

    monkeypatch.setattr(agent, "list_entities", scan_then_person_archives)
    try:
        report = importer.import_bundle(agent, _bundle(tmp_path / "bundle"))
        monkeypatch.undo()
        row = _row(agent)
        # The race is staged at the importer's scan; an importer that no longer scans, or scans under its
        # write lock (the person's archive then cannot commit in between), has nothing to honour here.
        if committed and committed[0]:
            assert row.archived, ("the import revived a row a person archived", report.written)
            assert row.content == BODY
            assert report.written == []
    finally:
        person.close()
        agent.close()
