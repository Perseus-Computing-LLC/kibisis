"""Write a vault with the released kibisis 0.1.0a5, for the integrity format 2 upgrade tests.

Run with an interpreter that has kibisis==0.1.0a5 installed:

    python tests/fixtures/make_legacy_vault.py tests/fixtures/vault-0.1.0a5-fallback.sqlite

sqlite3 stands in for sqlcipher3, as when that driver fails to load, so the file is plain SQLite with
sealed entry content. Its journal and tombstone keep plain SHA-256 digests, its signatures use a key
taken from one hash of the passphrase, and one entry has its signature removed, as entries written
before signatures existed have. The passphrase below is for this test fixture only.
"""

import os
import sqlite3
import sys

sys.modules["sqlcipher3"] = None  # the fallback: sqlcipher3 does not import

import kibisis  # noqa: E402
from kibisis import SQLiteMemoryVault, TombstonedValueError  # noqa: E402

PASSPHRASE = "legacy fixture passphrase (test only)"


def main(out: str) -> None:
    assert kibisis.__version__ == "0.1.0a5", kibisis.__version__
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(out + suffix):
            os.unlink(out + suffix)
    vault = SQLiteMemoryVault(out, passphrase=PASSPHRASE)
    vault.put("ops", "door_code", "4417", epistemic_state="verified")
    vault.put("ops", "public_note", "The lobby opens at 0700", epistemic_state="verified")
    vault.put("contacts", "alice", "Alice prefers email", scope="team", epistemic_state="verified")
    vault.put("notes", "draft", "Maybe move the standup to Tuesday", epistemic_state="candidate")
    vault.put("notes", "old", "Retired note", epistemic_state="verified")
    vault.archive("notes", "old")
    vault.put("ops", "unsigned_legacy", "Written before signatures existed", epistemic_state="verified")
    vault.put("secrets", "pin", "9031", epistemic_state="verified")
    vault.tombstone("secrets", "pin", reason="user asked")
    try:
        vault.put("secrets", "pin_again", "9031")  # refused and journaled with a digest prefix
    except TombstonedValueError:
        pass
    assert vault.verify_audit_chain()
    vault.close()

    con = sqlite3.connect(out)
    con.execute("UPDATE entities SET tenant_sig = NULL WHERE key = 'unsigned_legacy'")
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.execute("PRAGMA journal_mode = DELETE")  # one self-contained file
    con.execute("VACUUM")
    con.close()


if __name__ == "__main__":
    main(sys.argv[1])
