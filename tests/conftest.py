"""Suite-wide: never mirror test state transitions into a real Argus ledger."""
import os

os.environ.setdefault("ARGUS_LEDGER_PATH", "")
