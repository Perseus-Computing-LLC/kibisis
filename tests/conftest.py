"""Suite-wide: never mirror test state transitions into a real Argus ledger."""
import os

os.environ.setdefault("ARGUS_LEDGER_PATH", "")

# The suite must see the same environment CI does: no vault key, no plaintext opt-in, no quorum.
# A developer shell that exports a live vault's passphrase otherwise makes keyless vaults keyed and
# two unrelated vaults "the same vault" (shared key), hiding failures that only appear in CI.
for _name in ("KIBISIS_PASSPHRASE", "KIBISIS_PASSPHRASE_FILE", "KIBISIS_ALLOW_PLAINTEXT",
              "KIBISIS_VERIFICATION_QUORUM"):
    os.environ.pop(_name, None)
