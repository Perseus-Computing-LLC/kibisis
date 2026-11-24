"""severity: medium
finding: the AML adapter acknowledges an Add as durable after commit, but every vault runs WAL with synchronous=NORMAL, where a committed transaction can roll back after an OS crash or power loss

Convention: ``test_control_*`` asserts behaviour that holds on this head (passes: the Add commits and a
fresh open sees it, so process-crash durability holds). ``test_attack_*`` asserts the setting the
claim needs (``PRAGMA synchronous`` FULL or EXTRA on the connection that committed the acknowledged
write) and FAILS on this head.

Claim: aml_adapter.py:16-17, "``success`` is returned after commit, when the messages are durable".
Write path: ``AMLService.add`` (aml_adapter.py:500-525) commits through ``vault._write_tx``
(vault.py:888-913) on a connection configured by ``_configure_db`` (vault.py:961-965:
``journal_mode = WAL``, ``synchronous = NORMAL``). In WAL mode with synchronous=NORMAL, SQLite does not
fsync the WAL at COMMIT, only at checkpoint, so it documents that a committed transaction "might roll
back following a power loss or system crash". This file does not simulate a power cut (that is below
the process); it shows the setting that makes the 200 response's durability claim false. No ``fsync``
appears anywhere under src/kibisis.
"""

from __future__ import annotations

import hashlib

from kibisis import SQLiteMemoryVault
from kibisis.aml_adapter import REQUEST_CATEGORY, SCOPE, AMLConfig, AMLService, _digest

PASS = "correct horse battery staple 1"


def _add(service):
    body = {"request_id": "r-1", "user_id": "u1", "session_id": "s1",
            "messages": [{"role": "user", "content": "I moved to Lisbon in March."}]}
    assert service.add(body)["success"] is True


def _service(tmp_path):
    cfg = AMLConfig(data_dir=str(tmp_path / "vaults"), key_sha256=hashlib.sha256(b"k" * 32).hexdigest(), passphrase=PASS)
    return AMLService(cfg)


def _synchronous_of_committing_connection(service):
    with service.pool.use("u1", create=False) as vault:
        assert vault is not None
        assert vault._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        return int(vault._conn.execute("PRAGMA synchronous").fetchone()[0])


def test_control_acknowledged_add_survives_reopen(tmp_path):
    service = _service(tmp_path)
    _add(service)
    path = service.pool.path_for("u1")
    service.pool.close_all()
    assert path.exists()
    v = SQLiteMemoryVault(str(path), passphrase=PASS, auto_gate=False)
    try:
        marker = v.get(REQUEST_CATEGORY, _digest("r-1", 24), scope=SCOPE)
        assert marker is not None and marker.metadata.get("messages") == 1
    finally:
        v.close()


def test_attack_acknowledged_add_is_not_power_loss_durable(tmp_path):
    service = _service(tmp_path)
    _add(service)
    sync = _synchronous_of_committing_connection(service)
    # 0 OFF, 1 NORMAL, 2 FULL, 3 EXTRA. WAL needs FULL for a commit to survive an OS crash.
    assert sync >= 2, (
        f"the Add was acknowledged as durable, but the committing connection runs WAL with synchronous={sync} "
        "(NORMAL): the WAL is not fsynced at commit, so a power loss can roll the acknowledged request back"
    )
