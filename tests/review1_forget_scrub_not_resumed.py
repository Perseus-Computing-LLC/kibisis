"""severity: medium
finding: kibisis_forget's erasure is not crash-safe: a kill after the tombstone commits and before scrub() finishes leaves the forgotten text in the file's FTS index and free pages, and no later open or write ever finishes the job

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes: an uninterrupted
forget leaves no trace of the text in the file). ``test_attack_*`` asserts the correct post-crash
behaviour (after the kill, a fresh open of the vault no longer holds the text the forget deleted)
and FAILS on this head.

Write path: ``KibisisMCPServer._forget`` (mcp_server.py:587-608) commits ``tombstone()``
(_vault_tombstone.py:308-351, its own ``_write_tx``) and only then calls ``scrub()``
(_vault_tombstone.py:627-644: FTS rebuild, commit, checkpoint, VACUUM). The pending erasure is not
recorded anywhere, so the scrub is never re-run: ``__init__``, ``close`` and later writes do not scrub.
The kill is a real SIGKILL in a child process, so no ``finally`` or ``close()`` runs.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from kibisis import SQLiteMemoryVault
from kibisis.mcp_server import KibisisMCPServer

TOKEN = "quixotrellisfjord"  # one distinctive word, nowhere else in the file
SECRET = f"my bank pin is 4321 {TOKEN} keep it safe"

CHILD = textwrap.dedent(
    """
    import os, signal, sys
    from kibisis import SQLiteMemoryVault
    from kibisis.mcp_server import KibisisMCPServer

    db, kill = sys.argv[1], sys.argv[2] == "kill"
    vault = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    if kill:
        def die():  # the tombstone has committed; the process dies before the scrub runs
            os.kill(os.getpid(), signal.SIGKILL)
        vault.scrub = die
    server = KibisisMCPServer(vault=vault, scope="default")
    out = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "kibisis_forget", "arguments": {"category": "notes", "key": "pin"}}})
    print(out)
    vault.close()
    """
)


def _seed(db):
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    v.put("notes", "pin", SECRET, origin="model", author_id="mcp-agent")
    v.put("notes", "other", "an unrelated note about the weather", origin="model", author_id="mcp-agent")
    v.close()


def _file_bytes(db):
    data = b""
    for suffix in ("", "-wal"):
        p = str(db) + suffix
        if os.path.exists(p):
            with open(p, "rb") as fh:
                data += fh.read()
    return data


def _run_child(db, mode, tmp_path):
    script = tmp_path / "child.py"
    script.write_text(CHILD)
    env = dict(os.environ)
    env.pop("KIBISIS_PASSPHRASE", None)
    env.pop("KIBISIS_PASSPHRASE_FILE", None)
    env["PYTHONPATH"] = os.pathsep.join([p for p in sys.path if p] + [env.get("PYTHONPATH", "")])
    return subprocess.run([sys.executable, str(script), str(db), mode], env=env, capture_output=True, text=True, timeout=120)


def test_control_uninterrupted_forget_erases_text(tmp_path):
    db = tmp_path / "vault.sqlite"
    _seed(db)
    assert TOKEN.encode() in _file_bytes(db)
    proc = _run_child(db, "full", tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "deleted" in proc.stdout
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        assert v.get("notes", "pin") is None
    finally:
        v.close()
    assert TOKEN.encode() not in _file_bytes(db)


def test_attack_kill_before_scrub_leaves_forgotten_text_on_disk(tmp_path):
    db = tmp_path / "vault.sqlite"
    _seed(db)
    proc = _run_child(db, "kill", tmp_path)
    assert proc.returncode == -9, (proc.returncode, proc.stderr)  # SIGKILLed at the planned point

    # Recovery: a fresh open (and a later ordinary write) as the next session would do.
    v = SQLiteMemoryVault(db, allow_plaintext=True, auto_gate=False)
    try:
        assert v.get("notes", "pin") is None  # the delete itself committed
        assert v.is_tombstoned("notes", "pin", SECRET, scope="default")  # ... and so did the tombstone
        v.put("notes", "later", "a later write in the next session", origin="model", author_id="mcp-agent")
    finally:
        v.close()
    leaked = _file_bytes(db).count(TOKEN.encode())
    assert leaked == 0, f"the forgotten text is still in the vault file ({leaked} copies) after the crash and reopen"
