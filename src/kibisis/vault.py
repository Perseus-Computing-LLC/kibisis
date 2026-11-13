"""SQLite and FTS5 memory vault implementation for Kibisis with authenticated envelope encryption and hardened tombstones."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import inspect
import json
import logging
import os
import hmac
import urllib.parse
try:
    import sqlcipher3
except ImportError:
    import sqlite3 as sqlcipher3
import sqlite3
import string
import threading
import time
from pathlib import Path
from collections import deque
from typing import Any, Deque, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union
from .admission import AdmissionDecision, FactDisposition, MemoryAdmissionGate
from .crypto import (
    ENTRY_BINDING,
    AESGCMCryptoEnvelopeProvider,
    derive_vault_keys,
    entry_aad,
    verify_entry,
    verify_tenant_payload,
)
from .keys import MIN_PASSPHRASE_LENGTH, resolve_passphrase
from .models import (  # noqa: F401  (the search models are re-exported)
    AuditEvent,
    EncryptedEnvelope,
    EpistemicState,
    MemoryEntity,
    RecallResult,
    SearchHit,
    SearchResult,
    WithheldEntry,
)
from .protocols import CryptoEnvelopeProvider, EncryptionRequiredError, LeaseConflictError, LeaseCoordinator, MemoryVault
from ._vault_audit import (  # noqa: F401  (re-exported: every name stays importable from kibisis.vault)
    DEFAULT_ARGUS_LEDGER_PATH,
    JOURNAL_FORMAT,
    AuditJournalMixin,
    _argus_append,
    _argus_ledger_path,
    _event_hash,
    _head_mac,
)
from ._vault_crypto import (  # noqa: F401  (re-exported)
    INTEGRITY_FORMAT,
    EntryIntegrityError,
    EntryIntegrityMixin,
    VaultIntegrityError,
    _rekey_metadata,
    canonicalize_text,
    value_digests,
)
from ._vault_review import (  # noqa: F401  (re-exported)
    ORIGIN_CLASSES,
    ORIGINS,
    AdmissionRefused,
    AdmissionReviewMixin,
    Probe,
    _ORIGIN_TO_CLASS,
    _class_rank,
    _entry_ref,
    _row_origin_class,
    _validate_origin,
    origin_class_of,
    row_origin,
)
from ._vault_search import (  # noqa: F401  (re-exported)
    DEFAULT_MIN_COVERAGE_BP,
    DEFAULT_Z_MAX_BP,
    SEARCH_INDEX_FORMAT,
    TERM_INDEX_FORMAT,
    SearchRecallMixin,
    _EDGE_PUNCTUATION,
    _ENTITY_COLUMNS,
    _HIT_COLUMNS,
    _OPERATIONAL_ERRORS,
    _SEARCH_STOPWORDS,
    _WORD,
    _bounded,
    _search_terms,
    _snippet,
    _snippet_patterns,
    _within_bounds,
)
from ._vault_snapshot import SnapshotMixin
from ._vault_tombstone import TombstoneMixin

logger = logging.getLogger(__name__)


class ReadOnlyVaultError(Exception):
    """Raised by a write on a vault opened with ``read_only=True`` (area C: okf-export, okf-import --dry-run)."""


#: Metadata keys the vault writes itself and reads back as facts about trust and ownership. A caller's
#: ``metadata`` argument cannot set them: ``_put`` drops them (and logs the drop) unless the write
#: comes from an internal path whose metadata the vault produced (``review_entity``, ``import_snapshot``).
#: ``human_reviews`` is what ``_is_reviewed`` consults, so a caller-supplied value would forge a
#: person's review; ``tenant_id`` and ``principal_id`` bound recall; ``lineage_*`` is reserved.
RESERVED_METADATA_KEYS = frozenset({
    "human_reviews", "tenant_id", "principal_id",
    # K-R1 origin-bound admission: set by the vault from the write path, never from the payload.
    "origin_class", "act_class", "act_class_capped_from", "attestations", "verification_pending",
    "trust_inherited_from", "conflicts_with", "contrasts_with",
})
RESERVED_METADATA_PREFIX = "lineage_"

#: Metadata keys the vault reads back as facts a principal or the vault itself established: who wrote
#: an entry (``author_id``, shown as the author in recall), when a person last verified it
#: (``last_verified_at``, recall's TTL clock), supersession state (``supersession``,
#: ``proposed_supersedes``) and the persona ``slot``. A write from outside the principal class cannot
#: set them at the top level: ``_put`` moves them under ``agent_metadata`` and logs the move. Principal
#: writes may set them (an import of a person's notes names its author).
PRINCIPAL_METADATA_KEYS = frozenset({"author_id", "last_verified_at", "supersession", "proposed_supersedes", "slot"})

#: ``inform`` entries may be shown to a model; only ``act`` entries may drive an action (conventions,
#: standing instructions). Agent and external writers are capped at ``inform``.
ACT_CLASSES = ("inform", "act")
#: Distinct principals who must attest before an entry is ``verified`` (K-R1); ``KIBISIS_VERIFICATION_QUORUM``
#: overrides the default for a deployment.
DEFAULT_VERIFICATION_QUORUM = 2


def _reserved_metadata_keys(meta: Dict[str, Any]) -> List[str]:
    return sorted(k for k in meta if k in RESERVED_METADATA_KEYS or str(k).startswith(RESERVED_METADATA_PREFIX))
_ORIGIN_CHECK = "CHECK (origin IN ('user','model','tool','import','unknown'))"




def _sqlcipher_available() -> bool:
    """True when the real sqlcipher3 driver is loaded; the import above falls back to the standard sqlite3."""
    return sqlcipher3 is not sqlite3


def _plaintext_allowed_by_env() -> bool:
    """``KIBISIS_ALLOW_PLAINTEXT`` set to 1, true or yes (the same rule as ``kibisis.config.plaintext_allowed``,
    which cannot be imported here)."""
    return os.environ.get("KIBISIS_ALLOW_PLAINTEXT", "").strip().lower() in ("1", "true", "yes")


class TombstonedValueError(ValueError):
    """Raised when a write carries a value that a tombstone in its scope has rejected."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "",
        key: str = "",
        scope: str = "",
        digest: str = "",
        author_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.key = key
        self.scope = scope
        self.digest = digest
        self.author_id = author_id


class ReviewedEntryError(PermissionError):
    """Raised when a capped (model-originated) write targets an entry a person verified or reviewed."""


class OriginClassError(PermissionError):
    """Raised when a lower-trust writer (K-R1 ``origin_class``) tries to overwrite a higher-trust entry.

    The entry's class is fixed by the vault at write time; a model or tool cannot change it by
    re-writing the key. Write a new key with ``supersedes_key`` to propose a replacement instead.
    """

    def __init__(self, message: str, *, writer_class: str = "", stored_class: str = "") -> None:
        super().__init__(message)
        self.writer_class = writer_class
        self.stored_class = stored_class


class SupersessionRefused(ValueError):
    """Raised when a ``supersedes`` edge cannot be made: the target is missing in the scope, or it is
    already superseded (a retired edge is not re-pointed; supersede the entry that replaced it)."""


class SupersededEntryError(PermissionError):
    """Raised when a write lands on a key that an explicit ``supersedes`` edge has closed (K-R2).

    The closed interval stays closed. A principal may pass ``revive=True`` to open a new version with a
    new ``valid_from``; nothing reopens the old one.
    """


def _require_aad_support(provider: Any) -> None:
    """Fail at open, not at the first write, when a custom provider cannot bind content to its entry."""
    for name in ("encrypt", "decrypt"):
        try:
            params = inspect.signature(getattr(provider, name)).parameters
        except (TypeError, ValueError):
            continue  # not introspectable; rely on the protocol
        if "aad" not in params and not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            raise TypeError(
                f"crypto_provider.{name} must accept an 'aad' keyword argument: Kibisis binds sealed content "
                "to its entry as associated data"
            )


def _is_reviewed(row: Any) -> bool:
    """True for an entry in the verified state or one that carries a person's review."""
    if row["epistemic_state"] == EpistemicState.VERIFIED.value:
        return True
    try:
        meta = json.loads(row["metadata_json"] or "{}")
    except (TypeError, ValueError):
        return False
    return bool(meta.get("human_reviews"))


class SQLiteMemoryVault(
    AuditJournalMixin,
    EntryIntegrityMixin,
    AdmissionReviewMixin,
    SearchRecallMixin,
    TombstoneMixin,
    SnapshotMixin,
    MemoryVault,
):
    """Local SQLite memory vault featuring FTS5 full-text search, WAL mode, entity versioning,
    AES-256-GCM envelope encryption, and evasion-resistant negative memory tombstones."""

    def __init__(
        self,
        db_path: Union[str, Path] = ":memory:",
        crypto_provider: Optional[CryptoEnvelopeProvider] = None,
        passphrase: Optional[str] = None,
        *,
        allow_plaintext: bool = False,
        coordinator: Optional[LeaseCoordinator] = None,
        enforce_fencing: bool = False,
        auto_gate: bool = True,
        memory_security: bool = True,
        cache_mb: Optional[int] = None,
        verification_quorum: Optional[int] = None,
        term_index: bool = True,
        trust_caller_identity: bool = False,
        strict: bool = False,
        read_only: bool = False,
        pin_quorum: bool = False,
        adopt_keyless: bool = False,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        """Open a vault. Entry content is encrypted by default.

        ``adopt_keyless=True`` is the one way to give a passphrase to a plain file that holds content
        and no salt (a vault written without a passphrase). A keyed vault whose ``vault_meta`` and
        seals a file writer removed looks exactly like one, so without the opt-in such an open is
        refused (:class:`VaultIntegrityError`, read-only or writable), and with it every adopted entry
        is stored as a model-origin write would be stored: a ``candidate``, ``origin_class`` ``agent``,
        ``act_class`` ``inform``, with every reserved and principal-only metadata key dropped or moved
        under ``agent_metadata`` and its supersession links cleared (``_demote_adopted_row``). A
        writable open writes that into the file and a ``migrate`` event; a read-only open applies the
        same demotion to a private in-memory copy and writes nothing. :meth:`keyless_adoption` reports
        the count until a later migration. A keyless file holding a tombstone row, or a journal with no
        entries, is refused with or without the opt-in. Only the operator CLIs behind the terminal
        check pass it (``kibisis-review ... --adopt-keyless``, ``kibisis admit --adopt-keyless``); the
        servers and the OKF commands never do. A plain file with nothing in it (no rows, no tombstones,
        no journal events, no ``vault_meta`` records) needs no opt-in: it is a fresh vault.

        ``read_only=True`` opens an existing on-disk vault as it is and never writes to it: the SQLite
        connection is ``mode=ro``, so the plain-SQLite-to-SQLCipher migration, the integrity upgrade and
        the search-index build are skipped and any write fails. A plain-SQLite file that was never keyed
        is read as the plaintext vault it is even when a passphrase is set. A vault that would need a
        schema or integrity upgrade refuses to open read-only until it is opened writable once. Used by
        ``okf-export`` and ``okf-import --dry-run``.

        ``verification_quorum`` (K-R1) is how many distinct principals must attest to an entry before
        it is stored as ``verified``: the author of a ``origin="user"`` write that asked for
        ``verified`` counts as one, each person reviewing it as ``verified`` counts as one more. It
        defaults to ``KIBISIS_VERIFICATION_QUORUM`` (read from ``env``, default ``os.environ``) or
        :data:`DEFAULT_VERIFICATION_QUORUM`. The vault file remembers a quorum (``vault_meta``
        ``verification_quorum``) only once a process opened with ``pin_quorum=True`` stored it: the
        review verdicts and ``admit``, which a person runs at a terminal. Every other open (``review
        list``, the MCP and AML servers, the OKF commands, a plain library open) adopts the stored
        quorum, or runs with the process's own when none is stored, and never writes one. A stored
        quorum is a floor: an open that asks for LESS raises :class:`~kibisis.config.ConfigError`; a
        pinning open that asks for MORE stores the new value, a non-pinning one runs with it. A stored
        quorum below :data:`DEFAULT_VERIFICATION_QUORUM` is adopted only by a process whose own
        ``verification_quorum`` argument or ``KIBISIS_VERIFICATION_QUORUM`` names it; otherwise the
        open is refused with :class:`~kibisis.config.ConfigError`, so a pinned ``1`` is never taken
        up in silence. :attr:`verification_quorum_stored` is the file's value (``None`` until a
        verdict pins one).

        ``trust_caller_identity`` is for embedders only. By default the attester of a ``user``-origin
        write or review is the operating-system account running the process
        (:func:`kibisis._operator.account_identity`), whatever ``author_id`` or ``reviewer_id`` says.
        With ``trust_caller_identity=True`` an explicit ``attester=`` on :meth:`put` or
        :meth:`review_entity` is used instead: for a host that has authenticated its users itself and
        wants their identities on the attestations. Never set it for a vault an agent can reach.

        The passphrase comes from the argument, then KIBISIS_PASSPHRASE_FILE, then KIBISIS_PASSPHRASE.
        With no passphrase the vault refuses to open (EncryptionRequiredError) unless ``allow_plaintext=True``.
        An in-memory vault never touches disk, so it may run without a passphrase.

        With a passphrase but without the ``sqlcipher3`` driver, an on-disk vault is also refused
        (EncryptionRequiredError) unless ``allow_plaintext=True`` or ``KIBISIS_ALLOW_PLAINTEXT=1``: entry
        content would still be sealed, but categories, keys, scopes, metadata, the journal and the
        tombstone digests would lie in plain text in the file. :attr:`encrypted_at_rest` says whether
        the open file is actually SQLCipher-encrypted, which is not the same as a passphrase being set.

        A wrong passphrase on an existing vault raises ``ValueError`` ("Failed to authenticate ...")
        before anything is written: the stored key check is compared first, also before a plain SQLite
        file is converted to SQLCipher, so a wrong passphrase never converts, re-keys or upgrades a vault.
        A keyed vault whose integrity records are missing or do not verify (meta MAC, key check,
        tombstone MACs, journaled tombstones without rows, a journal that must verify before an upgrade)
        raises :class:`VaultIntegrityError`.

        ``strict=True`` makes every read raise :class:`EntryIntegrityError` for an entry that fails its
        integrity check instead of leaving it out; either way each such entry is logged at WARNING and
        counted in :attr:`integrity_failures`. The open itself never raises for such an entry: when the
        entry index is built or caught up at open, a failing row is logged, counted, kept out of the
        index and (under ``strict``) left queued, so the first read that touches the index raises.

        With ``enforce_fencing=True`` (which needs ``coordinator``), every call that adds, changes or
        removes entries must pass the caller's current ``fencing_token`` and ``resource``, and may
        pass ``holder_id``; a missing, stale or expired token raises ``LeaseConflictError`` and
        changes nothing. Without it, a token is checked only when one is passed.

        With SQLCipher and a passphrase, ``memory_security=True`` (the default) turns on SQLCipher's
        ``cipher_memory_security``, which wipes the memory SQLite frees, such as decrypted database pages.
        SQLCipher applies it to every connection in the process, and it costs time: ranked search over
        sealed entries runs several times slower with it. ``memory_security=False`` leaves the setting as
        it is (off unless something in the process turned it on). Either way, text that kibisis returns to
        Python stays in Python's memory until Python frees it, unwiped.

        ``cache_mb`` sets SQLite's page cache for this connection, in MiB (default: SQLite's own, a few MiB).
        Under SQLCipher a page read from outside the cache is decrypted again, so search over a vault larger
        than the cache slows down; a cache that holds the vault's pages removes that cost. The cache holds
        decrypted pages in this process's memory.

        Without SQLCipher, a vault with a passphrase keeps a keyed term index in its file so that search
        does not open every entry (:meth:`_ensure_term_index`; SECURITY.md states what the tokens show).
        ``term_index=False`` keeps no such index, removes one the file has, and searches as before: by
        opening every entry into an index in memory, at a cost that grows with the vault.
        """
        self.db_path = str(db_path)
        if cache_mb is not None and int(cache_mb) <= 0:
            raise ValueError("cache_mb must be a positive number of MiB")
        if crypto_provider is not None:
            _require_aad_support(crypto_provider)  # before anything touches the file
        self.coordinator = coordinator
        self.enforce_fencing = enforce_fencing
        self.auto_gate = auto_gate
        # A quorum named by the caller or the environment is a demand; one that is neither is the
        # default, and an existing file's stored quorum takes its place (see _persist_verification_quorum).
        # Only a pinning open (the review verdicts, admit) ever stores one.
        quorum_env = os.environ if env is None else env
        env_quorum = quorum_env.get("KIBISIS_VERIFICATION_QUORUM")
        self._quorum_requested = verification_quorum is not None or bool((env_quorum or "").strip())
        self._pin_quorum = bool(pin_quorum)
        self._adopt_keyless = bool(adopt_keyless)
        #: Set by a read-only open with the opt-in on a keyless file: the in-memory adoption it served (R6-3).
        self._keyless_adoption_view: Optional[Dict[str, Any]] = None
        #: The quorum the vault file remembers, or None until a verdict pinned one (then the default applies).
        self.verification_quorum_stored: Optional[int] = None
        #: A quorum a person had pinned that was dropped because a legacy meta MAC never covered it (R5-4);
        #: a pinning open that names no quorum will not pin below it. None once a verdict pins again.
        self.quorum_dropped_from: Optional[int] = None
        self._meta_mac_legacy = False  # True while the meta MAC verifies only over the pre-quorum key set
        if verification_quorum is None:
            from .config import parse_verification_quorum  # config imports this module

            verification_quorum = parse_verification_quorum(env_quorum, DEFAULT_VERIFICATION_QUORUM)
        if not isinstance(verification_quorum, int) or isinstance(verification_quorum, bool) or verification_quorum < 1:
            raise ValueError("verification_quorum must be a positive integer")
        self.verification_quorum = int(verification_quorum)
        self.trust_caller_identity = bool(trust_caller_identity)
        if enforce_fencing and coordinator is None:
            raise ValueError("enforce_fencing=True needs a lease coordinator: pass coordinator=")
        self._fallback_search_warned = False
        self.strict = bool(strict)
        #: Entries that reads refused and left out: ``{"count": n, "recent": [(category, key), ...]}`` (last 10).
        self.integrity_failures: Dict[str, Any] = {"count": 0, "recent": []}
        #: What the last :meth:`verify_audit_chain` found wrong, or None.
        self.last_chain_error: Optional[str] = None
        self._journal_anchored = False
        on_disk = self.db_path != ":memory:"
        passphrase = resolve_passphrase(passphrase)
        if passphrase and len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(f"passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")
        if passphrase is None and crypto_provider is None and on_disk and not allow_plaintext:
            raise EncryptionRequiredError(
                "No passphrase supplied. Set KIBISIS_PASSPHRASE_FILE (preferred) or KIBISIS_PASSPHRASE, "
                "pass passphrase=..., or open with allow_plaintext=True to store content unencrypted."
            )
        self.passphrase = passphrase
        self.crypto_provider = crypto_provider

        # --- read-only open (area C: okf-export / okf-import --dry-run) ------------------------------
        # One well-marked block, kept apart from the ordering of the writable open below. ``mode=ro``
        # makes every write fail in SQLite; _write_tx refuses first with ReadOnlyVaultError. A plain
        # SQLite file is read as plain even with a passphrase (no in-place SQLCipher conversion).
        self.read_only = bool(read_only)
        if self.read_only:
            if not on_disk or not os.path.isfile(self.db_path) or os.path.getsize(self.db_path) == 0:
                raise FileNotFoundError(f"read-only open needs an existing vault file: {self.db_path}")
            with open(self.db_path, "rb") as f:
                plain_file = f.read(16).startswith(b"SQLite format 3")
            if plain_file and passphrase and not _sqlcipher_available():
                plain_file = False  # a keyed vault kept in a plain file (no sqlcipher3): same path as below
            self._open_read_only(passphrase, crypto_provider, memory_security, cache_mb, plain_file)
            return
        # --- end read-only open ---------------------------------------------------------------------

        # Integrity keys. With a passphrase, the signing and digest keys are derived from a PBKDF2 stretch
        # of it once the vault's salt is known (below); _legacy_signing_key checks format 1 signatures
        # during the upgrade. Without a passphrase nothing is secret: signatures catch only accidental
        # damage, and value digests stay plain SHA-256.
        sig_seed = passphrase if passphrase else self.db_path
        self._legacy_signing_key = hashlib.sha256(f"kibisis-tenant-sig:{sig_seed}".encode("utf-8")).digest()
        self._signing_key = self._legacy_signing_key
        self._digest_key: Optional[bytes] = None
        self._term_key: Optional[bytes] = None
        self._keyed = False
        self._integrity_format = 1
        self._converted_to_sqlcipher = False
        self._was_keyed = False
        self._prechecked_keys: Optional[Tuple[bytes, Tuple[bytes, bytes, bytes]]] = None
        #: Counts from the integrity upgrade this open performed, or None when none was needed.
        self.integrity_upgrade: Optional[Dict[str, Any]] = None

        # Convert an existing plain SQLite file to SQLCipher when a passphrase is given. Without sqlcipher3 there
        # is nothing to convert with: the file stays plain SQLite, which is only allowed when the caller opted in.
        if on_disk and passphrase and not _sqlcipher_available():
            if not (allow_plaintext or _plaintext_allowed_by_env()):
                raise EncryptionRequiredError(
                    f"sqlcipher3 is not installed, so {self.db_path} would not be encrypted as a whole file: entry "
                    "content would be sealed, but categories, keys, scopes, metadata, the audit journal and the "
                    "tombstone digests would be stored in plain text. Install kibisis[sqlcipher], or open with "
                    "allow_plaintext=True or KIBISIS_ALLOW_PLAINTEXT=1 to accept that."
                )
            logger.warning(
                "sqlcipher3 is not installed, so %s is not encrypted as a whole file: entry content is still "
                "sealed, but categories, keys and metadata are stored in plain text",
                self.db_path,
            )
        converted_temp: Optional[str] = None  # a SQLCipher copy of a plain file, adopted only after the upgrade succeeds
        if (
            on_disk
            and passphrase
            and _sqlcipher_available()
            and os.path.isfile(self.db_path)
            and os.path.getsize(self.db_path) > 0
        ):
            with open(self.db_path, "rb") as f:
                hdr = f.read(16)
            if hdr.startswith(b"SQLite format 3"):
                # Migrate an existing plain SQLite database to SQLCipher: only after the passphrase has been
                # checked against the plain file (its key check, or for a 0.1.0a5 file one of its sealed
                # entries), so a wrong passphrase leaves it untouched. The copy is opened and upgraded
                # first; the plain file is replaced only once that has succeeded (see below).
                self._prechecked_keys = self._check_plain_file_passphrase(self.db_path, passphrase)
                converted_temp = self._migrate_file_to_sqlcipher(self.db_path, passphrase)
                self._converted_to_sqlcipher = True

        self._search_index = False  # True once a SQLCipher vault's entry index is in use
        self._term_index = False  # True once the keyed term index of a vault without SQLCipher is in use
        self._scan_cache: Optional[Tuple[Tuple[int, int], Any]] = None  # in-memory index without SQLCipher
        self._recent_recalls: Deque[Dict[str, Any]] = deque(maxlen=1000)  # K-R5 in-process recall log
        self._tokenizer: Optional[sqlite3.Connection] = None  # FTS5's tokenizer, for the term index
        self._tokenizer_lock = threading.Lock()
        self._sqlcipher_active = False
        self._cache_mb = int(cache_mb) if cache_mb is not None else None
        # A SQLite file that holds tables but none of ours is somebody else's database, not a vault to
        # initialise into (R6-1b, R6 Minor): refused by _connect like the read-only open refuses it, before
        # the journal mode is touched or _init_schema adds anything. An empty file (no tables) is a fresh vault.
        self._refuse_foreign = on_disk and os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0
        try:
            self._connect(converted_temp or self.db_path, passphrase, memory_security)
        except BaseException:
            if converted_temp is not None:
                self._discard_converted(converted_temp)
            raise
        self._a5_checked = False  # True once _refuse_unless_genuine_a5 ran on the file as it was before _init_schema
        if passphrase:
            # Everything that refuses a file must see it before _init_schema adds the tables and columns a
            # later release's schema has (audit_head, audit_journal.format, tombstone_mac) and before a salt
            # is issued, so a refused file is not written to. In order: sealed rows or keyed records with no
            # salt (the salt was removed, R5-3); plaintext rows with no salt and no adopt_keyless opt-in (a
            # keyed vault reset to look never-keyed, R5-1); and the a5 discriminator, which refuses a keyed
            # file reset to look like 0.1.0a5 and hands over a genuine a5 file's derived keys.
            try:
                self._refuse_keyed_records_without_salt()
                self._refuse_unadopted_keyless_rows()
                prechecked = self._refuse_unless_genuine_a5(passphrase)
            except BaseException:
                self._conn.close()
                if converted_temp is not None:
                    self._discard_converted(converted_temp)  # the plain file was never touched
                raise
            self._a5_checked = True
            if prechecked is not None:
                self._prechecked_keys = prechecked
        self._init_schema()
        if not passphrase:
            try:
                self._persist_verification_quorum()
            except BaseException:
                self._conn.close()
                raise
        if passphrase:
            try:
                self._was_keyed = self._has_meta_key("kdf_salt")  # written by an earlier open with a passphrase
                salt = self._vault_salt()
                if crypto_provider is None:
                    self.crypto_provider = AESGCMCryptoEnvelopeProvider(salt=salt)
                if self._prechecked_keys is not None and self._prechecked_keys[0] == salt:
                    self._signing_key, self._digest_key, self._term_key = self._prechecked_keys[1]
                else:
                    self._signing_key, self._digest_key, self._term_key = derive_vault_keys(passphrase, salt)
                self._prechecked_keys = None
                self._keyed = True
                self._upgrade_integrity()
                # After the integrity records are checked: the stored quorum is one of the values the meta
                # MAC covers, so it is adopted, compared or raised (and re-signed) only once the MAC held.
                self._persist_verification_quorum()
                if self._sqlcipher_active:
                    self._ensure_search_index()
                elif term_index:
                    self._ensure_term_index()
                elif self._has_meta_key("term_index_format"):
                    with self._write_tx() as cursor:  # opened with term_index=False: leave no tokens behind
                        for trigger in ("entities_search_ai", "entities_search_au", "entities_search_ad"):
                            cursor.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                        cursor.execute("DROP TABLE IF EXISTS entities_search_dirty")
                        self._drop_term_index(cursor)
                        self._write_meta_mac(cursor)  # term_index_format is one of the values the meta MAC covers
            except BaseException:
                self._conn.close()
                if converted_temp is not None:
                    self._discard_converted(converted_temp)  # the plain file was never touched
                raise
            if converted_temp is not None:
                # The converted copy opened, authenticated and upgraded: now it takes the plain file's place.
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.close()
                self._adopt_converted(converted_temp, self.db_path)
                self._connect(self.db_path, passphrase, memory_security)
        if on_disk:
            self._restrict_permissions()

    def _connect(self, path: str, passphrase: Optional[str], memory_security: bool) -> None:
        """Open ``path`` as this vault's connection; with a passphrase, key it (SQLCipher) and check it."""
        self._conn = sqlcipher3.connect(path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlcipher3.Row
        self._sqlcipher_active = False
        if passphrase:
            escaped_pass = passphrase.replace("'", "''")
            if memory_security:
                self._conn.execute("PRAGMA cipher_memory_security = ON;")
            self._conn.execute(f"PRAGMA key = '{escaped_pass}';")
            # Verify the key immediately by accessing sqlite_master
            try:
                self._conn.execute("SELECT count(*) FROM sqlite_master;").fetchall()
                row = self._conn.execute("PRAGMA cipher_version;").fetchone()
                if row and row[0]:
                    self._sqlcipher_active = True
            except Exception as e:
                self._conn.close()
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase") from e
            self._conn.execute("PRAGMA secure_delete = ON;")
        if getattr(self, "_refuse_foreign", False):
            # Before _configure_db switches the journal mode (a write to the file header): a SQLite file that
            # holds tables but none of ours is refused as it is (R6-1b, R6 Minor).
            try:
                self._refuse_foreign_database()
            except BaseException:
                self._conn.close()
                raise
        self._configure_db()
        if self._cache_mb is not None:
            self._conn.execute(f"PRAGMA cache_size = -{self._cache_mb * 1024}")

    @staticmethod
    def _discard_converted(temp_path: str) -> None:
        """Remove a converted copy (and its WAL files) that will not be adopted."""
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.unlink(temp_path + suffix)

    @staticmethod
    def _adopt_converted(temp_path: str, path: str) -> None:
        """Put the converted copy in the plain file's place (``os.replace``) and drop the plain file's
        WAL files. The copy's connection was checkpointed and closed before this runs."""
        for ext in ("-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.unlink(path + ext)
        os.replace(temp_path, path)
        for ext in ("-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.unlink(temp_path + ext)

    @property
    def encrypted_at_rest(self) -> bool:
        """True when the open file is SQLCipher-encrypted as a whole. A passphrase alone does not make
        it so: without the ``sqlcipher3`` driver only entry content is sealed (see ``allow_plaintext``)."""
        return bool(self._sqlcipher_active)

    @staticmethod
    def _check_plain_file_passphrase(path: str, passphrase: str) -> Optional[Tuple[bytes, Tuple[bytes, bytes, bytes]]]:
        """Check ``passphrase`` against what a plain SQLite vault file stores, before it is converted.

        The file is opened read-only with the standard sqlite3 module; nothing is written. With a key
        check, the keys are derived from the file's own ``kdf_salt`` and compared: a mismatch raises
        ``ValueError`` ("Failed to authenticate ...") and the file stays as it is. A keyed file (integrity
        format 2 or higher) without a key check raises :class:`VaultIntegrityError`. A file with a salt
        but no key check that claims format 1 (Kibisis 0.1.0a5 or earlier wrote no key check) is
        authenticated the way its migration will be: one of its sealed entries must open under the
        passphrase, or, when none is sealed, one of its format 1 signatures must verify; otherwise
        ``ValueError`` is raised and the file is untouched. This is the passphrase gate before the
        conversion only; whether such a file is a genuine 0.1.0a5 file at all (every row sealed and
        opening, no later-format table, column or meta key) is decided by its sibling
        :meth:`_refuse_unless_genuine_a5`, which runs on the connection before ``_init_schema`` in every
        writable open with a passphrase. Returns the salt and the derived keys so the
        open that follows need not derive them again, or None when the file has no vault_meta yet (a
        vault never opened with a passphrase).
        """
        uri = "file:" + Path(path).resolve().as_uri()[len("file://"):] + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            try:
                rows = conn.execute(
                    "SELECT key, value FROM vault_meta WHERE key IN ('kdf_salt', 'key_check', 'integrity_format')"
                ).fetchall()
            except sqlite3.OperationalError:
                return None  # no vault_meta table: nothing to check against
            meta = {r["key"]: r["value"] for r in rows}
            salt = meta.get("kdf_salt")
            stored = meta.get("key_check")
            if salt is None:
                return None
            salt = bytes(salt)
            keys = derive_vault_keys(passphrase, salt)
            if stored is not None:
                expected = hmac.new(keys[0], b"kibisis key check v2", hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(stored), expected):
                    raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
                return salt, keys
            if int(meta.get("integrity_format") or 0) >= 2:
                raise VaultIntegrityError(f"{path}: the vault is keyed but has no key check; refusing to open")
            if not SQLiteMemoryVault._plain_file_opens_under(conn, passphrase, salt):
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
            return salt, keys
        finally:
            conn.close()

    @staticmethod
    def _plain_file_opens_under(conn: sqlite3.Connection, passphrase: str, salt: bytes) -> bool:
        """Whether a format 1 file's entries authenticate ``passphrase``: at least one sealed entry opens
        under keys derived from ``salt`` (its binding honoured when it has one), or, when no entry is
        sealed, at least one format 1 signature verifies under the passphrase's legacy signing key. A
        file with no entries has nothing to check against and passes (its migration then decides)."""
        try:
            rows = conn.execute(
                "SELECT category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities"
            ).fetchall()
        except sqlite3.OperationalError:
            return True  # not a vault yet
        sealed = [r for r in rows if r["is_encrypted"] == 1]
        if sealed:
            provider = AESGCMCryptoEnvelopeProvider(salt=salt)
            for r in sealed:
                try:
                    envelope = EncryptedEnvelope.model_validate_json(r["encrypted_envelope_json"] or "")
                    aad = entry_aad(r["scope"], r["category"], r["key"]) if envelope.binding == ENTRY_BINDING else None
                    provider.decrypt(envelope, passphrase, aad=aad)
                    return True
                except Exception:
                    continue
            return False
        signed = [r for r in rows if r["tenant_sig"]]
        if signed:
            legacy_key = hashlib.sha256(f"kibisis-tenant-sig:{passphrase}".encode("utf-8")).digest()
            return any(
                verify_tenant_payload(legacy_key, r["scope"], f"{r['category']}:{r['key']}", r["content"] or "", r["tenant_sig"])
                for r in signed
            )
        return True

    # --- read-only open (area C) -------------------------------------------------------------------
    def _open_read_only(
        self,
        passphrase: Optional[str],
        crypto_provider: Optional[CryptoEnvelopeProvider],
        memory_security: bool,
        cache_mb: Optional[int],
        plain_file: bool,
    ) -> None:
        """The read-only half of ``__init__``: open with ``mode=ro``, derive keys from the stored salt,
        and refuse (instead of upgrading) a vault that is not at the current integrity format."""
        sig_seed = passphrase if passphrase else self.db_path
        self._legacy_signing_key = hashlib.sha256(f"kibisis-tenant-sig:{sig_seed}".encode("utf-8")).digest()
        self._signing_key = self._legacy_signing_key
        self._digest_key = None
        self._term_key = None
        self._keyed = False
        self._integrity_format = 1
        self._converted_to_sqlcipher = False
        self._was_keyed = False
        self.integrity_upgrade = None
        self._search_index = False  # search reads the entries instead of touching an index
        self._term_index = False
        self._scan_cache = None
        self._recent_recalls = deque(maxlen=1000)
        self._tokenizer = None
        self._tokenizer_lock = threading.Lock()
        self._sqlcipher_active = False
        self._cache_mb = int(cache_mb) if cache_mb is not None else None
        uri = "file:" + urllib.parse.quote(os.path.abspath(self.db_path)) + "?mode=ro"
        self._conn = sqlcipher3.connect(uri, uri=True, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlcipher3.Row
        try:
            if passphrase and not plain_file:
                escaped_pass = passphrase.replace("'", "''")
                if memory_security:
                    self._conn.execute("PRAGMA cipher_memory_security = ON;")
                self._conn.execute(f"PRAGMA key = '{escaped_pass}';")
                try:
                    self._conn.execute("SELECT count(*) FROM sqlite_master;").fetchall()
                    row = self._conn.execute("PRAGMA cipher_version;").fetchone()
                    self._sqlcipher_active = bool(row and row[0])
                except Exception as e:
                    raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase") from e
            self._conn.execute("PRAGMA foreign_keys = ON")
            if self._cache_mb is not None:
                self._conn.execute(f"PRAGMA cache_size = -{self._cache_mb * 1024}")
            if not self._conn.execute("SELECT name FROM sqlite_master WHERE name = 'entities'").fetchone():
                raise ValueError(f"{self.db_path} is not a kibisis vault (no entities table)")
            if not self._has_meta_key("kdf_salt"):
                self._refuse_keyed_records_without_salt(sealed_rows=bool(passphrase))
                if passphrase:
                    # The same door as the writable open (R5-1): a plain file with rows and no salt is served
                    # as the plaintext vault it is only when the caller opted in to adopting it.
                    self._refuse_unadopted_keyless_rows()
            if passphrase and self._has_meta_key("kdf_salt"):
                self._was_keyed = True
                salt = bytes(self._meta("kdf_salt"))
                if crypto_provider is None:
                    self.crypto_provider = AESGCMCryptoEnvelopeProvider(salt=salt)
                self._signing_key, self._digest_key, self._term_key = derive_vault_keys(passphrase, salt)
                self._keyed = True
                # Same order as the writable open (_vault_crypto.py): key check, then the edited-down
                # integrity_format test, then the upgrade refusal; so an edited record or a wrong
                # passphrase is reported as such and never as "open it writable once first".
                stored_format = self._integrity_format_record()
                stored = self._meta("key_check")
                if stored is not None and not hmac.compare_digest(str(stored), self._key_check_value()):
                    raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
                if stored_format < 2 and (stored is not None or self._meta("meta_mac") is not None):
                    raise VaultIntegrityError(
                        f"{self.db_path}: vault_meta.integrity_format says {stored_format} but the vault carries a "
                        "key check or meta MAC, which only integrity format 2 and later write; the integrity "
                        "record was edited. Refusing to open; restore the record first."
                    )
                if stored_format < INTEGRITY_FORMAT:
                    raise ValueError(f"{self.db_path} needs an integrity upgrade: open it writable once first")
                if stored is None:
                    raise VaultIntegrityError(f"{self.db_path}: the vault is keyed but has no key check; refusing to open")
                self._integrity_format = INTEGRITY_FORMAT
                # The same read-only integrity checks the writable open runs (area B): the meta MAC over the
                # integrity records, the journal anchoring flag, and every tombstone row's MAC plus the
                # journal reconciliation.
                self._verify_meta_mac()
                self._journal_anchored = bool(int(self._meta("journal_anchored") or 0))
                self._check_tombstones()
            elif passphrase:  # a plain file never opened with a passphrase: read as the plaintext vault it is
                self.passphrase = None
                self._legacy_signing_key = hashlib.sha256(f"kibisis-tenant-sig:{self.db_path}".encode("utf-8")).digest()
                self._signing_key = self._legacy_signing_key
                if plain_file and _sqlcipher_available():
                    logger.warning("kibisis: %s is a plaintext vault; read-only open leaves it as it is", self.db_path)
                if getattr(self, "_adopt_keyless", False):
                    # R6-3: the opt-in means "serve these rows as the writable adoption would store them",
                    # and a read-only open cannot write that. So the rows are demoted in a private
                    # in-memory copy of the file (the same _demote_adopted_row the writable open runs);
                    # the file is not touched and the forged state is never served as verified.
                    self._adopt_keyless_in_memory()
            # Adopt (or refuse) the stored quorum exactly as a writable open would; a read-only open never
            # stores one. After the meta MAC check, since the stored quorum is one of the values it covers.
            self._persist_verification_quorum()
        except BaseException:
            self._conn.close()
            raise

    def _adopt_keyless_in_memory(self) -> None:
        """Replace the read-only connection to a keyless file with an in-memory copy in which every row
        has been demoted as the writable adoption would demote it (:meth:`_demote_adopted_row`, R6-3).
        The file is left byte for byte as it is; :meth:`keyless_adoption` reports the in-memory adoption
        with no journal sequence, since nothing was written."""
        memory = sqlcipher3.connect(":memory:", check_same_thread=False)
        memory.row_factory = sqlcipher3.Row
        try:
            self._conn.backup(memory)
        except BaseException:
            memory.close()
            raise
        self._conn.close()
        self._conn = memory
        ids = [int(r[0]) for r in self._conn.execute("SELECT id FROM entities").fetchall()]
        cursor = self._conn.cursor()
        for entity_id in ids:
            self._demote_adopted_row(cursor, entity_id)
        # The writable adoption drops the file's policy records (R7-3); the in-memory view does the same,
        # so a planted quorum is not read as this open's stored policy either.
        self._drop_keyless_policy_records(cursor)
        self._conn.commit()
        if ids:
            self._keyless_adoption_view = {"entries": len(ids), "events": 0, "at": time.time(), "sequence": None}
    # --- end read-only open ------------------------------------------------------------------------

    def _validate_fencing(
        self,
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str] = None,
    ) -> None:
        """Validate an atomic fencing token against the attached lease coordinator."""
        if self.enforce_fencing and (fencing_token is None or resource is None):
            raise LeaseConflictError("enforce_fencing is enabled on vault, but fencing_token or resource was not provided")

        if fencing_token is None and resource is None:
            return

        if self.coordinator is None:
            raise LeaseConflictError("Fencing token validation requested but no LeaseCoordinator is configured on vault")

        if resource is None or fencing_token is None:
            raise LeaseConflictError(
                f"Both resource and fencing_token must be specified for fencing validation (got resource={resource}, token={fencing_token})"
            )

        if holder_id is not None:
            if not self.coordinator.validate_fencing_token(resource, holder_id, fencing_token):
                raise LeaseConflictError(
                    f"Stale or invalid fencing token {fencing_token} for resource '{resource}' (holder={holder_id})"
                )
        else:
            lease = self.coordinator.get_lease(resource)
            if lease is None:
                raise LeaseConflictError(f"No active lease found for resource '{resource}'")
            if lease.fencing_token != fencing_token:
                raise LeaseConflictError(
                    f"Stale fencing token {fencing_token} for resource '{resource}' (active token is {lease.fencing_token})"
                )
            if lease.expires_at <= time.time():
                raise LeaseConflictError(f"Expired lease with fencing token {fencing_token} for resource '{resource}'")

    def _fence(
        self,
        cursor: Any,
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str],
    ) -> None:
        """Check the caller's fencing token inside the write transaction, holding the write lock.

        Skipped when no token or resource is passed and ``enforce_fencing`` is off. The caller has
        already taken the write lock through :meth:`_write_tx`, so a write whose token passes is
        ordered before any write by a later lease holder, never after it. This method does not
        begin a transaction itself: taking the lock here, after the caller's reads, is what let a
        tombstone check run unlocked.
        """
        if not self._fence_applies(fencing_token, resource):
            return
        self._validate_fencing(fencing_token, resource, holder_id)

    def _fence_applies(self, fencing_token: Optional[int], resource: Optional[str]) -> bool:
        """Whether a call is fenced: it passes a token or a resource, or ``enforce_fencing`` is on."""
        return fencing_token is not None or resource is not None or bool(self.enforce_fencing)

    @contextlib.contextmanager
    def _fence_first(
        self,
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str],
    ) -> Iterator[None]:
        """Check the caller's fence before the block's origin and argument checks, when it applies.

        A fenced call runs the block inside a write transaction that checks the fence first (the
        block's writes join it), so a caller fenced out gets :class:`LeaseConflictError` before any
        refusal and changes nothing. Any other call runs the block as it is, with no transaction.
        """
        if not self._fence_applies(fencing_token, resource):
            yield
            return
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            yield

    @contextlib.contextmanager
    def _write_tx(self):
        """Run a mutation under the SQLite write lock, taken before its first read.

        Issues ``BEGIN IMMEDIATE`` when no transaction is open, commits when the block finishes and
        rolls back when it raises. Python's sqlite3 module only begins a transaction before the first
        DML statement, so a method that reads first (the tombstone gate, the reviewed-entry check,
        the audit head) and then writes used to run its reads with no lock; another connection could
        commit a tombstone or a review between the check and the insert. Every mutating method
        enters this first so check-then-write is atomic against other connections.

        Nested use inside an open transaction yields a cursor and leaves commit and rollback to the
        outermost block, so a compound operation (review, then re-write) stays one transaction.
        """
        if getattr(self, "read_only", False):  # area C: a read-only open never writes
            raise ReadOnlyVaultError(f"vault {self.db_path} was opened read-only")
        if self._conn.in_transaction:
            yield self._conn.cursor()
            return
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        try:
            yield cursor
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()

    @staticmethod
    def _migrate_file_to_sqlcipher(path: str, passphrase: str) -> str:
        """Export a plain SQLite vault file to a SQLCipher copy beside it and return the copy's path.

        The export goes to a sibling temp file (``<path>.tmp_enc``); that file is then opened with the
        key and read. A failure at any step removes the copy and leaves the plain file as it was. The
        copy does not replace the plain file here: the caller opens it, authenticates the passphrase
        against its records and upgrades it, and only then adopts it (:meth:`_adopt_converted`), so a
        passphrase that fails any check later leaves the plain file untouched. The passphrase was
        checked against the file's key check (or one of its sealed entries) before this runs
        (:meth:`_check_plain_file_passphrase`).
        """
        temp_enc = path + ".tmp_enc"
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.unlink(temp_enc + suffix)
        escaped_pass = passphrase.replace("'", "''")
        try:
            conn_raw = sqlcipher3.connect(path)
            try:
                conn_raw.execute(f"ATTACH DATABASE '{temp_enc}' AS encrypted KEY '{escaped_pass}';")
                conn_raw.execute("SELECT sqlcipher_export('encrypted');")
                conn_raw.execute("DETACH DATABASE encrypted;")
            finally:
                conn_raw.close()
            check = sqlcipher3.connect(temp_enc)
            try:
                check.execute(f"PRAGMA key = '{escaped_pass}';")
                check.execute("SELECT count(*) FROM sqlite_master").fetchone()
            finally:
                check.close()
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp_enc)
            raise
        return temp_enc

    def _restrict_permissions(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass

    def _configure_db(self) -> None:
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA foreign_keys = ON")

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    version INTEGER NOT NULL DEFAULT 1,
                    archived INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    is_encrypted INTEGER NOT NULL DEFAULT 0,
                    encrypted_envelope_json TEXT DEFAULT NULL,
                    scope TEXT NOT NULL DEFAULT 'default',
                    epistemic_state TEXT NOT NULL DEFAULT 'verified',
                    valid_from REAL DEFAULT NULL,
                    valid_until REAL DEFAULT NULL,
                    tenant_sig TEXT DEFAULT NULL,
                    supersedes TEXT DEFAULT NULL,
                    superseded_by TEXT DEFAULT NULL,
                    origin TEXT NOT NULL DEFAULT 'unknown' CHECK (origin IN ('user','model','tool','import','unknown')),
                    source_ref TEXT DEFAULT NULL,
                    confidence REAL DEFAULT NULL,
                    UNIQUE(category, key, scope)
                )
                """
            )

            # Migration for pre-existing tables lacking columns
            cursor = self._conn.cursor()
            cursor.execute("PRAGMA table_info(entities)")
            cols = {row["name"] for row in cursor.fetchall()}
            if "is_encrypted" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0")
            if "encrypted_envelope_json" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN encrypted_envelope_json TEXT DEFAULT NULL")
            if "scope" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN scope TEXT NOT NULL DEFAULT 'default'")
            if "epistemic_state" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN epistemic_state TEXT NOT NULL DEFAULT 'verified'")
            if "valid_from" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN valid_from REAL DEFAULT NULL")
            if "valid_until" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN valid_until REAL DEFAULT NULL")
            if "tenant_sig" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN tenant_sig TEXT DEFAULT NULL")
            if "supersedes" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN supersedes TEXT DEFAULT NULL")
            if "superseded_by" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN superseded_by TEXT DEFAULT NULL")
            if "origin" not in cols:
                # Rows that predate provenance read as 'unknown'; nothing claims they were a person's.
                self._conn.execute(
                    "ALTER TABLE entities ADD COLUMN origin TEXT NOT NULL DEFAULT 'unknown' " + _ORIGIN_CHECK
                )
            if "source_ref" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN source_ref TEXT DEFAULT NULL")
            if "confidence" not in cols:
                self._conn.execute("ALTER TABLE entities ADD COLUMN confidence REAL DEFAULT NULL")

            # Covering B-Tree index for bitemporal point-in-time and interval queries
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_entities_bitemporal
                ON entities (scope, category, epistemic_state, valid_from, valid_until)
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_entities_supersedes
                ON entities (scope, category, supersedes)
                """
            )

            self._conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
                    category,
                    key,
                    content,
                    scope,
                    content='entities',
                    content_rowid='id'
                )
                """
            )

            # Triggers to keep FTS5 synchronized with entities
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
                    INSERT INTO entities_fts(rowid, category, key, content, scope)
                    VALUES (new.id, new.category, new.key, new.content, new.scope);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
                    INSERT INTO entities_fts(entities_fts, rowid, category, key, content, scope)
                    VALUES ('delete', old.id, old.category, old.key, old.content, old.scope);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS entities_au AFTER UPDATE ON entities BEGIN
                    INSERT INTO entities_fts(entities_fts, rowid, category, key, content, scope)
                    VALUES ('delete', old.id, old.category, old.key, old.content, old.scope);
                    INSERT INTO entities_fts(rowid, category, key, content, scope)
                    VALUES (new.id, new.category, new.key, new.content, new.scope);
                END
                """
            )

            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rejected_value_tombstones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_sha256 TEXT NOT NULL,
                    canonical_sha256 TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL,
                    author_id TEXT,
                    created_at REAL NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'default',
                    UNIQUE(category, key, value_sha256, scope)
                )
                """
            )
            cursor.execute("PRAGMA table_info(rejected_value_tombstones)")
            tomb_cols = {row["name"] for row in cursor.fetchall()}
            if "canonical_sha256" not in tomb_cols:
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN canonical_sha256 TEXT NOT NULL DEFAULT ''")
            if "scope" not in tomb_cols:
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN scope TEXT NOT NULL DEFAULT 'default'")
            if "sealed_digests" not in tomb_cols:
                # A vault with a passphrase keeps a tombstone's plain digests sealed here, so a snapshot can
                # carry the tombstone to another vault that has the same passphrase.
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN sealed_digests TEXT DEFAULT NULL")
            if "origin_class" not in tomb_cols:
                # The K-R1 class of the request that made the tombstone. Rows from before the column
                # existed were made by callers that vouched (no origin), so they stay principal-class.
                self._conn.execute(
                    "ALTER TABLE rejected_value_tombstones ADD COLUMN origin_class TEXT NOT NULL DEFAULT 'principal'"
                )
            self._conn.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            if "tombstone_mac" not in tomb_cols:
                # HMAC over the row under the vault's signing key (integrity format 3): a lookup hit and every
                # open verify it, so a row edited or added behind the vault's back is detected.
                self._conn.execute("ALTER TABLE rejected_value_tombstones ADD COLUMN tombstone_mac TEXT DEFAULT NULL")

            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_lookup
                ON rejected_value_tombstones(category, key, value_sha256, scope)
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_canonical
                ON rejected_value_tombstones(category, canonical_sha256, scope)
                """
            )
            # A tombstone stops a value under any category or key, so writes look tombstones up
            # by digest alone.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_value ON rejected_value_tombstones(value_sha256)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rejected_tombstones_canonical_value "
                "ON rejected_value_tombstones(canonical_sha256)"
            )

            # Append-only hash-chained mutation audit journal
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_journal (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    action TEXT NOT NULL,
                    category TEXT NOT NULL,
                    key TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    value_sha256 TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    author_id TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_journal_scope
                ON audit_journal(scope, category, key)
                """
            )
            # Journal rows written before the column existed used the legacy layout (format 2 at most).
            journal_cols = {r[1] for r in self._conn.execute("PRAGMA table_info(audit_journal)").fetchall()}
            if "format" not in journal_cols:
                self._conn.execute("ALTER TABLE audit_journal ADD COLUMN format INTEGER NOT NULL DEFAULT 2")
            # One row: the sequence and hash of the newest event, signed. Updated with every append.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_head (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    sequence INTEGER NOT NULL,
                    event_hash TEXT NOT NULL,
                    mac TEXT NOT NULL
                )
                """
            )

    def _has_meta_key(self, key: str) -> bool:
        try:
            return self._meta(key) is not None
        except sqlcipher3.OperationalError:
            return False  # no vault_meta table: the vault was never opened with a passphrase

    def _refuse_foreign_database(self) -> None:
        """Refuse a SQLite file that holds tables but no ``entities`` table: another program's database,
        or a vault file whose ``entities`` table was dropped (R6-1b). The writable open used to add the
        vault schema into such a file and run, and for a salt-less file with a planted journal that chained
        the journal under the signed head; now it is refused the way the read-only open refuses it. A file
        with no tables at all is a fresh vault."""
        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        if tables and "entities" not in tables:
            raise ValueError(f"{self.db_path} is not a kibisis vault (no entities table)")

    def _meta(self, key: str) -> Any:
        row = self._conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    @staticmethod
    def _set_meta(cursor: Any, key: str, value: Any) -> None:
        cursor.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))

    def _stored_quorum(self) -> Optional[int]:
        """The quorum ``vault_meta`` holds, or None when there is none (or it is not a positive integer).

        While the meta MAC verifies only over the legacy key set (:attr:`_meta_mac_legacy`) the stored
        value was never signed, so it is not evidence of anything, whatever it is: a file writer can
        lower a quorum a person pinned above the default to the default itself (R4-2), not only below
        it (R3-AB4). It is reported as None, logged at WARNING with the value, and dropped before the
        MAC is re-signed (``_drop_untrusted_stored_quorum``); the next review verdict re-pins it.
        """
        try:
            stored_raw = self._meta("verification_quorum")
        except sqlcipher3.OperationalError:
            return None  # no vault_meta table (a read-only open of a file no passphrase ever touched)
        if stored_raw is None:
            return None
        try:
            stored = int(bytes(stored_raw).decode("ascii") if isinstance(stored_raw, (bytes, memoryview)) else stored_raw)
        except (TypeError, ValueError):
            return None
        if stored < 1:
            return None
        if self._meta_mac_legacy:
            logger.warning(
                "%s: the stored verification quorum %d is not covered by the meta MAC (it predates the bound quorum), "
                "so it is not trusted: the value is ignored and dropped at the next writable open; a review verdict "
                "run under KIBISIS_VERIFICATION_QUORUM=%d pins it again",
                self.db_path, stored, stored,
            )
            return None
        return stored

    def _dropped_quorum(self) -> Optional[int]:
        """``vault_meta.quorum_dropped_from`` as a positive integer, or None (absent or malformed)."""
        try:
            raw = self._meta("quorum_dropped_from")
        except sqlcipher3.OperationalError:
            return None
        if raw is None:
            return None
        try:
            value = int(bytes(raw).decode("ascii") if isinstance(raw, (bytes, memoryview)) else raw)
        except (TypeError, ValueError):
            return None
        return value if value >= 1 else None

    def _drop_untrusted_stored_quorum(self, cursor: Any) -> None:
        """Before a legacy (pre-quorum) meta MAC is re-signed: remove every record the MAC never covered,
        whatever its value, so the re-signed MAC never turns a value nobody signed into a signed one.
        Under the legacy key set neither ``verification_quorum`` nor ``quorum_dropped_from`` was bound
        (:data:`~kibisis.crypto.VAULT_META_BOUND_KEYS_V1`), so BOTH are untrusted and both are deleted
        (R5-4, R6-4): a stored ``quorum_dropped_from`` is never read as a floor here, since a file writer
        with a pre-quorum copy of the MAC could have planted it. A dropped ``verification_quorum`` above
        the default is then kept as ``quorum_dropped_from`` (under the full-set MAC): not as a quorum
        (nobody signed it) but as a floor for the next pinning open that names no quorum, so a person's
        pinned 3 cannot be turned into the default by their own later verdict run without
        ``KIBISIS_VERIFICATION_QUORUM``. The floor can only raise the bar that open must clear, never
        lower it, and any named quorum clears it. Called by ``_verify_meta_mac`` under
        ``_meta_mac_legacy``."""
        planted_floor = self._meta("quorum_dropped_from")
        if planted_floor is not None:
            logger.warning(
                "%s: vault_meta.quorum_dropped_from = %r is not covered by the legacy meta MAC, so it is not a floor "
                "anybody recorded: dropped before the MAC is re-signed",
                self.db_path, planted_floor,
            )
            cursor.execute("DELETE FROM vault_meta WHERE key = 'quorum_dropped_from'")
            self.quorum_dropped_from = None
        if self._stored_quorum() is None and self._meta("verification_quorum") is not None:
            raw = self._meta("verification_quorum")
            try:
                dropped = int(bytes(raw).decode("ascii") if isinstance(raw, (bytes, memoryview)) else raw)
            except (TypeError, ValueError):
                dropped = 0
            logger.warning(
                "%s: vault_meta.verification_quorum = %r is not covered by the legacy meta MAC: dropped before the "
                "MAC is re-signed%s",
                self.db_path, raw,
                f"; kept as a floor (quorum_dropped_from = {dropped}) for a pinning open that names no quorum"
                if dropped > DEFAULT_VERIFICATION_QUORUM else "",
            )
            cursor.execute("DELETE FROM vault_meta WHERE key = 'verification_quorum'")
            # Only a value above the default is worth a floor: a pinning open never pins below the default,
            # so a dropped 1 or 2 (the forged lowering R2-B4 is about) is simply gone. The floor is the
            # dropped quorum alone: the planted record above never feeds it.
            if dropped > DEFAULT_VERIFICATION_QUORUM:
                self._set_meta(cursor, "quorum_dropped_from", str(dropped))
                self.quorum_dropped_from = dropped

    def _persist_verification_quorum(self) -> None:
        """Adopt the stored quorum, compare it with the process's, and store it only from a pinning open.

        A verified entry means "``verification_quorum`` distinct accounts attested". A process opening
        the same file with a smaller quorum would mint ``verified`` on fewer attestations, so it is
        refused (:class:`~kibisis.config.ConfigError`). A larger quorum is allowed: a pinning open
        (``pin_quorum=True``: the review verdicts and ``admit``, behind the terminal check) stores it
        and it becomes the file's; any other open runs with it and writes nothing. A process that
        names no quorum (no argument, no ``KIBISIS_VERIFICATION_QUORUM``) adopts the file's, unless the
        file's is below :data:`DEFAULT_VERIFICATION_QUORUM`: a quorum of one account is taken up only by
        a process that names it itself. With nothing stored, a pinning open stores the process's
        quorum (the default, unless named) and every other open simply runs with it; but when a
        ``quorum_dropped_from`` record stands (a pinned value dropped under a legacy MAC, R5-4) a
        pinning open that names no quorum and would pin below it is refused
        (:class:`~kibisis.config.ConfigError`), and the record is cleared once a pinning open names
        its quorum or pins at least that value.
        """
        from .config import ConfigError  # config imports this module

        stored = self._stored_quorum()
        self.verification_quorum_stored = stored
        self.quorum_dropped_from = self._dropped_quorum()
        if stored is not None and not self._quorum_requested:
            if stored < DEFAULT_VERIFICATION_QUORUM:
                raise ConfigError(
                    f"{self.db_path} has its verification quorum pinned at {stored}, below the default "
                    f"{DEFAULT_VERIFICATION_QUORUM}: {'one account' if stored == 1 else f'{stored} accounts'} would "
                    f"verify an entry. Set KIBISIS_VERIFICATION_QUORUM={stored} to accept that, or raise it to "
                    f"{DEFAULT_VERIFICATION_QUORUM} or more with a review verdict run under "
                    f"KIBISIS_VERIFICATION_QUORUM={DEFAULT_VERIFICATION_QUORUM}."
                )
            self.verification_quorum = stored
            return
        if stored is not None and self.verification_quorum < stored:
            raise ConfigError(
                f"{self.db_path} was opened with verification_quorum={stored}; this process asks for "
                f"{self.verification_quorum}. A quorum may be raised but not lowered: set "
                f"KIBISIS_VERIFICATION_QUORUM to {stored} or more."
            )
        if not self._pin_quorum or getattr(self, "read_only", False):
            return  # adopt or run with the process's own; never pin
        dropped = self.quorum_dropped_from
        pins = stored is None or self.verification_quorum > stored
        if pins and dropped is not None and not self._quorum_requested and self.verification_quorum < dropped:
            raise ConfigError(
                f"{self.db_path}: a stored verification quorum of {dropped} was dropped at an earlier open because the "
                f"meta MAC did not cover it (the file read as pinned at {dropped}; nothing signed vouched for that), "
                f"and this open names no quorum, so it would pin the default {self.verification_quorum} in its "
                f"place. Run under KIBISIS_VERIFICATION_QUORUM={dropped} to pin it again (or name the quorum you mean)."
            )
        clear = dropped is not None and (
            self._quorum_requested or max(self.verification_quorum, stored or 0) >= dropped
        )
        if pins or clear:
            with self._write_tx() as cursor:
                if pins:
                    self._set_meta(cursor, "verification_quorum", str(self.verification_quorum))
                if clear:
                    cursor.execute("DELETE FROM vault_meta WHERE key = 'quorum_dropped_from'")
                    self.quorum_dropped_from = None
                self._write_meta_mac(cursor)  # the stored quorum and the dropped record are under the meta MAC
            if pins:
                self.verification_quorum_stored = self.verification_quorum

    def _resolve_attester(self, origin: Optional[str], attester: Optional[str]) -> Optional[str]:
        """The account an attestation is recorded for, or ``None`` when nothing is recorded.

        Only a ``user``-origin act attests: the identity is the operating-system account running
        the process (:func:`kibisis._operator.account_identity`), or ``attester`` when the vault was
        opened with ``trust_caller_identity=True`` and the caller named one. The literal
        ``"principal"`` and an empty name are never signers. ``import`` is principal-class but no
        person is present, so it records nothing: an import carries the attestations it was given.
        """
        if origin != "user":
            return None
        if attester is not None:
            attester = str(attester).strip()
            if not attester or attester == "principal":
                raise ValueError("attester must name an account; 'principal' and an empty name are not signers")
            if not self.trust_caller_identity:
                raise ValueError(
                    "attester= is honoured only on a vault opened with trust_caller_identity=True (embedders only); "
                    "the attester is otherwise the account running this process"
                )
            return attester
        from ._operator import account_identity

        identity = account_identity()
        if not identity or identity == "principal":
            return None
        return identity

    def _write_review(
        self,
        category: str,
        key: str,
        content: str,
        *,
        metadata: Dict[str, Any],
        epistemic_state: Union[str, EpistemicState],
        author_id: Optional[str],
        scope: str,
        origin: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        **kwargs: Any,
    ) -> MemoryEntity:
        """The write a review makes. Private: ``review_entity`` decided the state and the metadata
        it passes here, so both are taken as given (``_review_verdict``/``_trusted_metadata``).
        Nothing public reaches this path."""
        return self._put_journaled(
            category,
            key,
            content,
            metadata=metadata,
            epistemic_state=epistemic_state,
            origin=origin,
            author_id=author_id,
            scope=scope,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            _trusted_metadata=True,
            _review_verdict=True,
            **kwargs,
        )

    def _content_changed(self, existing: Any, content: str) -> bool:
        """True when ``content`` differs from what the stored row ``existing`` (a row with the
        ``_ROW_COLUMNS`` of :mod:`._vault_tombstone`) holds. A row that cannot be opened counts as
        changed: nothing attested can be shown to be the same."""
        try:
            return self._open_entry(existing) != content
        except PermissionError:
            return True

    def _put(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
        trust_ceiling: Optional[str] = None,
        origin: Optional[str] = None,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
        act_class: Optional[str] = None,
        revive: bool = False,
        conflicts_with: Optional[List[str]] = None,
        contrasts_with: Optional[List[str]] = None,
        _trusted_metadata: bool = False,
        _review_verdict: bool = False,
        attester: Optional[str] = None,
        _attest: bool = True,
    ) -> MemoryEntity:
        """Write path behind :meth:`put`, which journals the tombstone refusals this raises.

        ``_review_verdict`` is set by :meth:`_write_review` and by a same-vault ``import_snapshot``
        only: the state it passes was decided under the quorum rule in ``review_entity``, with
        ``attestations`` already in ``metadata`` (or restored from this vault's own snapshot).

        ``_trusted_metadata`` is set only by internal callers whose ``metadata`` the vault itself
        produced; a caller's reserved keys (:data:`RESERVED_METADATA_KEYS`) are dropped otherwise.

        ``attester`` names the account a ``user``-origin write that asks for ``verified`` attests as;
        it is honoured only when the vault was opened with ``trust_caller_identity=True``, else the
        attester is the account running the process (:meth:`_resolve_attester`).
        """
        if trust_ceiling is not None and trust_ceiling != EpistemicState.CANDIDATE.value:
            raise ValueError("trust_ceiling supports only 'candidate'")
        _validate_origin(origin)
        if confidence is not None and not (0.0 <= float(confidence) <= 1.0):
            raise ValueError("confidence must be within [0, 1]")
        if act_class is not None and act_class not in ACT_CLASSES:
            raise ValueError(f"act_class must be one of {ACT_CLASSES}, got {act_class!r}")
        if origin == "model" and not _review_verdict:
            # Trust comes from where the write came from, not from what it says about itself. A state
            # a person decided (review_entity, or this vault's own snapshot restoring that review) is
            # not re-capped by the origin of the entry it was decided for.
            trust_ceiling = EpistemicState.CANDIDATE.value
        now = time.time()
        meta = dict(metadata or {})
        if not _trusted_metadata:
            # Trust facts come from the vault's own paths, never from the payload: a caller that writes
            # metadata["human_reviews"] would otherwise count as a person's review in _is_reviewed.
            dropped = _reserved_metadata_keys(meta)
            for k in dropped:
                meta.pop(k)
            if dropped:
                logger.warning("put %s:%s [scope=%s] dropped reserved metadata keys %s", category, key, scope, dropped)
            if origin_class_of(origin) != "principal":
                # A non-principal write (or one that states no origin) cannot name its author, refresh
                # the TTL clock, or set supersession or persona facts at the top level. The values are
                # kept where the agent's own fields live, so nothing the agent sent is lost.
                moved = sorted(k for k in meta if k in PRINCIPAL_METADATA_KEYS)
                if moved:
                    agent_meta = meta.get("agent_metadata")
                    agent_meta = dict(agent_meta) if isinstance(agent_meta, dict) else {}
                    for k in moved:
                        agent_meta[k] = meta.pop(k)
                    meta["agent_metadata"] = agent_meta
                    logger.warning(
                        "put %s:%s [scope=%s] moved principal-only metadata keys %s under agent_metadata",
                        category, key, scope, moved,
                    )
        if author_id:
            # Keep the original author when a reviewer re-writes an entry; the review is in human_reviews.
            meta.setdefault("author_id", author_id)
        if tenant_id:
            meta["tenant_id"] = tenant_id
        if principal_id:
            meta["principal_id"] = principal_id
        if derived_from:
            meta["derived_from"] = derived_from

        # Evaluate write-time admission gate if enabled and epistemic_state not explicitly specified
        gate_enabled = self.auto_gate if auto_gate is None else auto_gate
        if gate_enabled and epistemic_state is None:
            gate = MemoryAdmissionGate()
            decision = gate.evaluate(content, category=category)
            ep_state_str = gate.route_epistemic_state(decision)
            ep_state = EpistemicState(ep_state_str)
            meta["admission_disposition"] = decision.disposition.value
            meta["admission_provenance"] = decision.provenance
            if decision.metadata:
                meta.update(decision.metadata)
            if decision.disposition == FactDisposition.TRANSIENT and valid_until is None:
                valid_until = now + 86400.0  # Default 24h validity for transient states
        else:
            # K-E: a write that states no epistemic state is a candidate. Nothing but a person's
            # review (and the quorum below) mints verified.
            ep_state = EpistemicState(epistemic_state) if epistemic_state else EpistemicState.CANDIDATE

        if trust_ceiling is not None and ep_state in (EpistemicState.VERIFIED, EpistemicState.DISPUTED):
            # A capped write cannot claim a reviewed state: verified and disputed come only from a
            # person's review, and list_entities shows them by default.
            meta["trust_capped_from"] = ep_state.value
            ep_state = EpistemicState.CANDIDATE

        # K-R1: the trust class of this write. A re-write that states no origin keeps the entry's
        # stored origin (and class); that is resolved against the stored row inside the transaction.
        writer_class: Optional[str] = origin_class_of(origin) if origin is not None else None
        if (
            epistemic_state is not None
            and not _review_verdict
            and ep_state != EpistemicState.CANDIDATE
            and origin_class_of(origin) != "principal"
        ):
            # A non-principal write is stored as a candidate whatever epistemic_state it states:
            # verified and disputed are a person's verdicts, revoked is a retirement (K-E). An
            # origin-less rewrite of a principal row is resolved below once the stored class is known.
            if writer_class is not None:
                meta["trust_capped_from"] = ep_state.value
                ep_state = EpistemicState.CANDIDATE
        requested_verified = ep_state == EpistemicState.VERIFIED and not _review_verdict
        if requested_verified:
            # An explicit "verified" from a principal is that principal's attestation, counted toward
            # the quorum; from anyone else it is a claim and the entry stays a candidate.
            if writer_class != "principal":
                meta["trust_capped_from"] = ep_state.value
                ep_state = EpistemicState.CANDIDATE
            else:
                ep_state = EpistemicState.CANDIDATE  # settled against the quorum below

        # Check explicit superseding target
        supersedes_ref: Optional[str] = None
        if supersedes_key:
            target_cat = supersedes_category or category
            supersedes_ref = f"{target_cat}:{supersedes_key}"
            meta["supersedes"] = supersedes_ref
            if valid_from is None:
                valid_from = now

        meta_str = json.dumps(meta, sort_keys=True)
        val_hash, can_hash = self._digests(content)

        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(
                "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig, "
                "epistemic_state, metadata_json, origin, superseded_by, valid_until, version "
                "FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            existing = cursor.fetchone()

            # K-R2 bitemporal non-revival: a key closed by a supersedes edge stays closed. Only a
            # principal may revive it, and only forward in time: the new version's valid_from is at or
            # after the closed interval's valid_until, so the old interval is never reopened.
            if existing is not None and existing["superseded_by"]:
                if not revive or origin_class_of(origin) != "principal":
                    raise SupersededEntryError(
                        f"'{category}:{key}' [scope={scope}] was superseded by {existing['superseded_by']}; "
                        "the closed interval is not rewritten. A principal may pass revive=True to open a new one."
                    )
                closed_at = existing["valid_until"] or now
                if valid_from is not None and valid_from < closed_at:
                    raise ValueError("revive cannot backdate valid_from into the closed interval")
                if valid_from is None:
                    valid_from = max(now, closed_at)
                meta["revived_from"] = {"version": int(existing["version"]), "superseded_by": existing["superseded_by"]}

            # K-R5: contradiction check before anything else happens to the write. An explicit
            # ``conflicts_with`` edge is recorded on both sides and journaled; recall withholds a pair of
            # verified entries that conflict until a person resolves it (K-R3).
            existing_meta: Dict[str, Any] = {}
            if existing is not None:
                try:
                    existing_meta = json.loads(existing["metadata_json"] or "{}")
                except (TypeError, ValueError):
                    existing_meta = {}
            # The class the edges are written with: a back-edge lands on a target only when the target
            # is of this class or below. The vault's own paths (trusted metadata) write both sides.
            edge_class: Optional[str] = None
            if not _trusted_metadata:
                edge_class = writer_class or (_row_origin_class(existing) if existing is not None else "external")
            conflict_refs = self._record_edges(
                cursor, "conflicts_with", conflicts_with, category, key, scope, now, existing_meta, _trusted_metadata,
                writer_class=edge_class,
            )
            if conflicts_with:
                self._record_audit_event(
                    cursor=cursor, action="contradiction", category=category, key=key, scope=scope,
                    value_sha256=val_hash, author_id=author_id, metadata={"with": list(conflicts_with)},
                )
            if conflict_refs:
                meta["conflicts_with"] = conflict_refs
            # Contrast edges name confusables: entries a reader could mistake for each other. Both are
            # returned; the receipt carries the edge so the scaffold can show the distinction.
            contrast_refs = self._record_edges(
                cursor, "contrasts_with", contrasts_with, category, key, scope, now, existing_meta, _trusted_metadata,
                writer_class=edge_class,
            )
            if contrast_refs:
                meta["contrasts_with"] = contrast_refs

            # K-R1: origin_class is immutable from below. The stored class is what a lower-trust
            # writer must not change; an equal class keeps it; a principal may raise it.
            stored_class = _row_origin_class(existing) if existing is not None else None
            if writer_class is None:
                writer_class = stored_class or origin_class_of(origin)
            if stored_class is not None and _class_rank(writer_class) < _class_rank(stored_class):
                raise OriginClassError(
                    f"'{category}:{key}' [scope={scope}] is {stored_class}-class; a {writer_class}-class write "
                    "cannot replace it. Write a new key with supersedes_key to propose a replacement.",
                    writer_class=writer_class, stored_class=stored_class,
                )
            entry_class = writer_class
            # Max-untrust along supersedes and derived_from: a non-principal entry is no more trusted
            # than what it replaces or draws on, so trust cannot be laundered through a rewrite.
            if entry_class != "principal":
                inherited: List[str] = []
                links: List[Tuple[str, str]] = []
                if supersedes_key:
                    links.append((supersedes_category or category, supersedes_key))
                for ref in derived_from or []:
                    if ":" in ref:
                        c, k = ref.split(":", 1)
                        links.append((c, k))
                for c, k in links:
                    cursor.execute(
                        "SELECT metadata_json, origin FROM entities WHERE category = ? AND key = ? AND scope = ?",
                        (c, k, scope),
                    )
                    link_row = cursor.fetchone()
                    if link_row is None:
                        continue
                    link_class = _row_origin_class(link_row)
                    if _class_rank(link_class) < _class_rank(entry_class):
                        entry_class = link_class
                        inherited.append(f"{c}:{k}")
                if inherited:
                    meta["trust_inherited_from"] = inherited
            meta["origin_class"] = entry_class
            # act_class: only a principal may mark an entry as one that drives actions.
            wanted_act = act_class or (meta.get("act_class") if _trusted_metadata else None) or "inform"
            if wanted_act == "act" and entry_class != "principal":
                meta["act_class_capped_from"] = "act"
                wanted_act = "inform"
            meta["act_class"] = wanted_act

            # Verification quorum: distinct principals who attested. The author of a principal write
            # that asked for verified is one; review_entity adds reviewers. Below quorum stays candidate.
            if not _review_verdict:
                prior_meta: Dict[str, Any] = {}
                if existing is not None:
                    try:
                        prior_meta = json.loads(existing["metadata_json"] or "{}")
                    except (TypeError, ValueError):
                        prior_meta = {}
                attested = list(prior_meta.get("attestations") or []) if existing is not None else []
                if attested and existing is not None and self._content_changed(existing, content):
                    # The stored attestations were given for the stored content. A different content
                    # is a new claim nobody has attested yet (R2-A9): the names are journaled, the
                    # quorum starts over and the state is settled against it below.
                    self._record_audit_event(
                        cursor=cursor, action="attestations_reset", category=category, key=key, scope=scope,
                        value_sha256=val_hash, author_id=author_id,
                        metadata={"reason": "content changed", "attestations": attested, "origin": origin or ""},
                    )
                    attested = []
                    meta.pop("attestations", None)
                    meta.pop("verification_pending", None)
                    meta.pop("quorum_at_verification", None)
                if requested_verified and entry_class == "principal" and _attest:
                    signer = self._resolve_attester(origin, attester)
                    if signer is not None and signer not in attested:
                        attested.append(signer)
                if attested:
                    meta["attestations"] = attested
                if requested_verified and entry_class == "principal":
                    if len(attested) >= self.verification_quorum:
                        ep_state = EpistemicState.VERIFIED
                        meta.pop("verification_pending", None)
                        meta["quorum_at_verification"] = self.verification_quorum
                    else:
                        meta["verification_pending"] = {"have": len(attested), "need": self.verification_quorum}
                        meta.pop("quorum_at_verification", None)
            if ep_state != EpistemicState.CANDIDATE and entry_class != "principal" and not _review_verdict:
                # An origin-less rewrite resolved to a non-principal class: same cap as an explicit one.
                meta["trust_capped_from"] = ep_state.value
                ep_state = EpistemicState.CANDIDATE
            meta_str = json.dumps(meta, sort_keys=True)

            if trust_ceiling is not None:
                # A capped write cannot replace an entry a person verified or reviewed.
                if existing is not None and _is_reviewed(existing):
                    raise ReviewedEntryError(
                        f"'{category}:{key}' [scope={scope}] is verified or reviewed by a person; a capped write "
                        "cannot replace it. Write a new key with supersedes_key to propose a replacement."
                    )

            # K-R2 three-way supersession. Retirement happens only through this explicit edge.
            if supersedes_key:
                target_cat = supersedes_category or category
                cursor.execute(
                    "SELECT id, metadata_json, epistemic_state, origin, superseded_by FROM entities "
                    "WHERE category = ? AND key = ? AND scope = ? AND archived = 0",
                    (target_cat, supersedes_key, scope),
                )
                target_row = cursor.fetchone()
                target_ref = f"{target_cat}:{supersedes_key}"
                if target_row is None:
                    raise SupersessionRefused(f"supersedes target '{target_ref}' [scope={scope}] does not exist")
                if target_row["superseded_by"]:
                    raise SupersessionRefused(
                        f"supersedes target '{target_ref}' [scope={scope}] is already superseded by "
                        f"{target_row['superseded_by']}; supersede that entry instead"
                    )
                target_class = _row_origin_class(target_row)
                confirmed_by = meta.get("supersession_approved_by") if _review_verdict else None
                # Applied when the writer outranks or equals the target's class and the target is not a
                # reviewed entry a non-principal may not retire; a person's approval of a proposal applies it.
                applies = bool(confirmed_by) or entry_class == "principal" or (
                    _class_rank(entry_class) >= _class_rank(target_class) and not _is_reviewed(target_row)
                )
                if not applies:
                    # needs_confirmation: store this entry as a proposal; the target stays active and
                    # carries the pending mark. review_entity applies or clears it.
                    meta.pop("supersedes", None)
                    meta["proposed_supersedes"] = {"category": target_cat, "key": supersedes_key}
                    meta["supersession"] = {"outcome": "needs_confirmation", "target": target_ref}
                    target_meta = json.loads(target_row["metadata_json"] or "{}")
                    pending = list(target_meta.get("pending_supersession_by") or [])
                    if f"{category}:{key}" not in pending:
                        pending.append(f"{category}:{key}")
                    target_meta["pending_supersession_by"] = pending
                    cursor.execute(
                        "UPDATE entities SET metadata_json = ?, updated_at = ? WHERE id = ?",
                        (json.dumps(target_meta, sort_keys=True), now, target_row["id"]),
                    )
                    self._record_audit_event(
                        cursor=cursor, action="supersession", category=target_cat, key=supersedes_key, scope=scope,
                        value_sha256="", author_id=author_id,
                        metadata={"outcome": "needs_confirmation", "proposed_by": f"{category}:{key}",
                                  "writer_class": entry_class, "target_class": target_class},
                    )
                    supersedes_ref = None
                    target_row = None
                else:
                    meta.pop("proposed_supersedes", None)
                    meta["supersession"] = {"outcome": "applied", "target": target_ref}
                    if confirmed_by:
                        meta["supersession"]["confirmed_by"] = confirmed_by
                    self._record_audit_event(
                        cursor=cursor, action="supersession", category=target_cat, key=supersedes_key, scope=scope,
                        value_sha256="", author_id=author_id,
                        metadata={"outcome": "applied", "superseded_by": f"{category}:{key}",
                                  "writer_class": entry_class, "target_class": target_class,
                                  **({"confirmed_by": confirmed_by} if confirmed_by else {})},
                    )
                meta_str = json.dumps(meta, sort_keys=True)
                if target_row is not None:
                    target_meta = json.loads(target_row["metadata_json"] or "{}")
                    target_meta["superseded_by"] = f"{category}:{key}"
                    target_meta.pop("pending_supersession_by", None)
                    cursor.execute(
                        """
                        UPDATE entities
                        SET valid_until = ?, epistemic_state = ?, metadata_json = ?, superseded_by = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            now,
                            EpistemicState.REVOKED.value,
                            json.dumps(target_meta, sort_keys=True),
                            f"{category}:{key}",
                            now,
                            target_row["id"],
                        ),
                    )
                    self._record_audit_event(
                        cursor=cursor,
                        action="supersede",
                        category=target_cat,
                        key=supersedes_key,
                        scope=scope,
                        value_sha256="",
                        author_id=author_id,
                        metadata={"superseded_by": f"{category}:{key}", "superseded_at": now},
                    )
                    if target_row["epistemic_state"] != EpistemicState.REVOKED.value:
                        self._record_state_transition(
                            cursor, target_cat, supersedes_key, scope, target_row["epistemic_state"],
                            EpistemicState.REVOKED.value, row_origin(target_row), author_id, cause="supersede",
                        )
                    self._cascade_invalidate(
                        cursor, scope, target_ref, author_id, now,
                        writer_class=None if confirmed_by else entry_class,
                    )

            # Skip canonicalization when the vault has no tombstones. Asked of the database on every
            # write: a flag cached at open misses tombstones that other processes add later.
            cursor.execute("SELECT EXISTS (SELECT 1 FROM rejected_value_tombstones)")
            if cursor.fetchone()[0]:
                # A tombstoned value is refused wherever the entry would hold it: content, key, or any
                # string in its metadata. A tombstone of a lower class than the writer is lifted by the
                # write (journaled); one of the writer's class or above refuses it.
                tombs = self._tombstones_matching(cursor, scope, self._entry_digests(key, content, meta))
                blocking = [t for t in tombs if _class_rank(t["origin_class"]) >= _class_rank(entry_class)]
                if blocking:
                    tomb = blocking[0]
                    where = "content" if tomb["value_sha256"] == val_hash else "key or metadata"
                    raise TombstonedValueError(
                        f"Write rejected by tombstone: entity '{category}:{key}' [scope={scope}] matches rejected "
                        f"tombstone in its {where} (digest: {tomb['value_sha256'][:12]}..., reason: {tomb['reason']}, "
                        f"tombstone class: {tomb['origin_class']})",
                        category=category,
                        key=key,
                        scope=scope,
                        digest=tomb["value_sha256"],
                        author_id=author_id,
                    )
                if tombs:
                    self._lift_lower_class_tombstones(cursor, tombs, entry_class, category, key, scope, author_id)

            if self.crypto_provider is not None and not self.passphrase:
                raise ValueError("Crypto provider configured but no passphrase supplied to SQLiteMemoryVault.")
            # Sealed content is bound to this entry, and its plaintext column stays empty so nothing leaks
            # into the entities table or the FTS index. The signature covers the entry either way.
            stored_content, is_encrypted, envelope_json, tenant_sig = self._seal(
                scope, category, key, content, encrypt=self.crypto_provider is not None
            )

            cursor.execute(
                "SELECT id, version, created_at, supersedes, superseded_by, epistemic_state, origin, source_ref, confidence "
                "FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            row = cursor.fetchone()
            previous_state: Optional[str] = None

            if row is None:
                action = "put"
                cursor.execute(
                    """
                    INSERT INTO entities (
                        category, key, content, metadata_json, version, archived,
                        created_at, updated_at, is_encrypted, encrypted_envelope_json,
                        scope, epistemic_state, valid_from, valid_until, tenant_sig,
                        supersedes, superseded_by, origin, source_ref, confidence
                    )
                    VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                    """,
                    (
                        category, key, stored_content, meta_str, now, now,
                        is_encrypted, envelope_json, scope, ep_state.value, valid_from, valid_until, tenant_sig,
                        supersedes_ref, origin or "unknown", source_ref, confidence
                    ),
                )
                entity_id = cursor.lastrowid
                version = 1
                stored_origin = origin or "unknown"
            else:
                action = "update"
                entity_id = row["id"]
                version = row["version"] + 1
                previous_state = row["epistemic_state"]
                # Provenance belongs to the fact: a re-write that does not state an origin keeps the original.
                stored_origin = origin or row["origin"] or "unknown"
                stored_source_ref = source_ref if source_ref is not None else row["source_ref"]
                stored_confidence = confidence if confidence is not None else row["confidence"]
                cursor.execute(
                    """
                    UPDATE entities
                    SET content = ?, metadata_json = ?, version = ?, archived = 0, updated_at = ?,
                        is_encrypted = ?, encrypted_envelope_json = ?, epistemic_state = ?,
                        valid_from = ?, valid_until = ?, tenant_sig = ?,
                        supersedes = COALESCE(?, supersedes),
                        superseded_by = CASE WHEN ? THEN NULL ELSE superseded_by END,
                        origin = ?, source_ref = ?, confidence = ?
                    WHERE id = ?
                    """,
                    (
                        stored_content, meta_str, version, now, is_encrypted, envelope_json,
                        ep_state.value, valid_from, valid_until, tenant_sig, supersedes_ref,
                        1 if "revived_from" in meta else 0,
                        stored_origin, stored_source_ref, stored_confidence, entity_id
                    ),
                )
            if self._search_index or self._term_index:
                self._index_entry(cursor, entity_id, category, key, content, scope)

            # Record hash-chained mutation audit event
            self._record_audit_event(
                cursor=cursor,
                action=action,
                category=category,
                key=key,
                scope=scope,
                value_sha256=val_hash,
                author_id=author_id,
                metadata={"version": version, "epistemic_state": ep_state.value},
            )
            if previous_state is not None and previous_state != ep_state.value:
                self._record_state_transition(
                    cursor, category, key, scope, previous_state, ep_state.value, stored_origin, author_id,
                    cause="review" if _review_verdict else "write",
                )
                if ep_state == EpistemicState.REVOKED:
                    self._cascade_invalidate(
                        cursor, scope, f"{category}:{key}", author_id, now,
                        writer_class=None if _review_verdict else entry_class,
                    )
            # Return what was stored, through the same constructor the read paths use, so the write
            # path cannot report a field differently from a later get() or search().
            cursor.execute(f"SELECT {_ENTITY_COLUMNS} FROM entities e WHERE e.id = ?", (entity_id,))
            written = cursor.fetchone()

        return self._entity(written, content)

    def put(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
        trust_ceiling: Optional[str] = None,
        origin: Optional[str] = None,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
        act_class: Optional[str] = None,
        revive: bool = False,
        conflicts_with: Optional[List[str]] = None,
        contrasts_with: Optional[List[str]] = None,
        attester: Optional[str] = None,
    ) -> MemoryEntity:
        """Insert or update an entity. See ``__init__`` for ``fencing_token``, ``resource`` and ``holder_id``.

        K-R3/K-R5: ``conflicts_with`` names existing entries this one contradicts; the edge is recorded on
        both sides and journaled as a ``contradiction`` before the write. :meth:`recall` withholds two
        verified entries that conflict until a person resolves it.

        K-R2: ``supersedes_key`` is the only way an entry retires another. The outcome is reported in
        ``metadata["supersession"]``: ``applied`` (target revoked and closed), or ``needs_confirmation``
        (this entry is a proposal; a person's ``verified`` review applies it). A missing or already
        superseded target raises :class:`SupersessionRefused`. Retiring an entry marks everything that
        ``derived_from`` it ``disputed`` (cascade). A key closed by supersession refuses writes
        (:class:`SupersededEntryError`) unless a principal passes ``revive=True``.

        K-E/K-R1: a write that states no ``epistemic_state`` is stored as ``candidate``. ``verified``
        is minted only when ``verification_quorum`` distinct principals have attested: a
        ``origin="user"``/``"import"`` write that asks for ``verified`` is its author's attestation,
        :meth:`review_entity` adds a reviewer's. The vault sets ``origin_class`` (``principal``,
        ``agent``, ``external``) from ``origin``; a lower-class writer cannot overwrite a higher-class
        entry (:class:`OriginClassError`), and a non-principal entry inherits the lowest class along
        ``supersedes_key`` and ``derived_from``. ``act_class`` (``inform``/``act``) is capped at
        ``inform`` unless the writer is a principal.

        ``origin`` records where the write came from (:data:`ORIGINS`); ``origin="model"`` implies
        ``trust_ceiling="candidate"``. A re-write that gives no origin keeps the entry's existing one.

        ``trust_ceiling="candidate"`` caps the stored state: a write that the admission gate or the
        ``epistemic_state`` argument would store as ``verified`` or ``disputed`` is stored as
        ``candidate``, and the write cannot replace or supersede an entry a person verified or
        reviewed (it raises :class:`ReviewedEntryError`, or records the supersession as a proposal
        that :meth:`review_entity` applies on approval). Write paths that carry model output (the
        MCP server) set it, so trust comes from the path, not from the payload.

        ``author_id`` is recorded in the entity's metadata and in the audit journal. A write whose
        value a tombstone rejects raises :class:`TombstonedValueError`, and the refusal is journaled.

        Reserved metadata keys (:data:`RESERVED_METADATA_KEYS`, ``lineage_*``) in ``metadata`` are
        dropped and logged; the vault sets them itself (``review_entity``, the ``tenant_id`` and
        ``principal_id`` arguments). A write from outside the principal class cannot set
        :data:`PRINCIPAL_METADATA_KEYS` at the top level; they are moved under ``agent_metadata``.
        A non-principal write is stored as ``candidate`` whatever ``epistemic_state`` says
        (``trust_capped_from`` records the claim).

        ``attester`` names the account a ``origin="user"`` write that asks for ``verified`` attests
        as. It is honoured only on a vault opened with ``trust_caller_identity=True`` (embedders that
        authenticated the person themselves); otherwise the attester is the account running the
        process and passing ``attester`` raises ``ValueError``. ``author_id`` is a label and never
        counts toward the quorum.

        The review path writes through a private method; ``put`` takes no review or trusted-metadata
        flag, so nothing public mints a reviewed state or plants trust facts.
        """
        return self._put_journaled(
            category=category,
            key=key,
            content=content,
            metadata=metadata,
            epistemic_state=epistemic_state,
            valid_from=valid_from,
            valid_until=valid_until,
            scope=scope,
            author_id=author_id,
            tenant_id=tenant_id,
            principal_id=principal_id,
            derived_from=derived_from,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=supersedes_key,
            supersedes_category=supersedes_category,
            auto_gate=auto_gate,
            trust_ceiling=trust_ceiling,
            origin=origin,
            source_ref=source_ref,
            confidence=confidence,
            act_class=act_class,
            revive=revive,
            conflicts_with=conflicts_with,
            contrasts_with=contrasts_with,
            attester=attester,
        )

    @contextlib.contextmanager
    def _journal_put_refusals(
        self,
        category: str,
        key: str,
        scope: str,
        author_id: Optional[str],
        origin: Optional[str],
        revive: bool = False,
    ) -> Iterator[None]:
        """Journal the refusals :meth:`_put` raises in the block (each in its own transaction, after the
        block's transaction has rolled back) and re-raise them. Enter it outside the outermost
        :meth:`_write_tx` of the block: a refusal journaled inside a transaction that then rolls back
        is lost."""
        try:
            yield
        except TombstonedValueError as exc:
            # The write's transaction rolled back; journal the refusal in its own transaction.
            self.record_refusal(
                path="put",
                reason="tombstoned value",
                scope=exc.scope or scope,
                category=exc.category,
                key=exc.key,
                author_id=exc.author_id,
                detail={"value_digest_prefix": exc.digest[:12]},
            )
            raise
        except OriginClassError as exc:
            # Same: the transaction rolled back, so the refusal is journaled on its own.
            self.record_refusal(
                path="put",
                reason="origin_class_refused",
                scope=scope,
                category=category,
                key=key,
                author_id=author_id,
                detail={"writer_class": exc.writer_class, "stored_class": exc.stored_class, "origin": origin or ""},
            )
            raise
        except SupersededEntryError:
            self.record_refusal(
                path="put", reason="superseded_entry", scope=scope, category=category, key=key,
                author_id=author_id,
                detail={"origin": origin or "", "revive": "yes" if revive else "no"},
            )
            raise

    def _put_journaled(
        self,
        category: str,
        key: str,
        content: str,
        *,
        scope: str = "default",
        author_id: Optional[str] = None,
        origin: Optional[str] = None,
        **kwargs: Any,
    ) -> MemoryEntity:
        """Run :meth:`_put` and journal the refusals it raises (each in its own transaction, after the
        write's rolled back). Internal paths (the review write, the snapshot import) use this with the
        private flags; :meth:`put` uses it without them."""
        with self._journal_put_refusals(category, key, scope, author_id, origin, bool(kwargs.get("revive"))):
            return self._put(
                category=category,
                key=key,
                content=content,
                scope=scope,
                author_id=author_id,
                origin=origin,
                **kwargs,
            )

    def store(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        epistemic_state: Optional[str] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        derived_from: Optional[List[str]] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        supersedes_key: Optional[str] = None,
        supersedes_category: Optional[str] = None,
        auto_gate: Optional[bool] = None,
        trust_ceiling: Optional[str] = None,
        origin: Optional[str] = None,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
    ) -> MemoryEntity:
        """Alias for put() for ergonomic convenience."""
        return self.put(
            category=category,
            key=key,
            content=content,
            metadata=metadata,
            epistemic_state=epistemic_state,
            valid_from=valid_from,
            valid_until=valid_until,
            scope=scope,
            author_id=author_id,
            tenant_id=tenant_id,
            principal_id=principal_id,
            derived_from=derived_from,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=supersedes_key,
            supersedes_category=supersedes_category,
            auto_gate=auto_gate,
            trust_ceiling=trust_ceiling,
            origin=origin,
            source_ref=source_ref,
            confidence=confidence,
        )

    def record_refusal(
        self,
        *,
        path: str,
        reason: str,
        scope: str,
        category: str = "",
        key: str = "",
        author_id: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Journal a refused request (action ``refuse``) so refusals are auditable like writes.

        Records the path (for example ``mcp``), the reason, and caller-supplied detail. Never records content.
        """
        meta: Dict[str, Any] = {"path": path, "reason": reason}
        if detail:
            meta["detail"] = detail
        with self._write_tx() as cursor:
            event = self._record_audit_event(
                cursor=cursor,
                action="refuse",
                category=category or "",
                key=key or "",
                scope=scope,
                value_sha256="",
                author_id=author_id,
                metadata=meta,
            )
            if reason == "reviewed_entry" and (detail or {}).get("tool") == "kibisis_forget":
                # A refused forget of a reviewed entry is also a request to the person. It gets its own
                # journal action so the review queue finds it by an indexed column, not by scanning the
                # last N refusals: a flood of other refusals cannot push it out of view.
                self._record_audit_event(
                    cursor=cursor,
                    action="forget_request",
                    category=category or "",
                    key=key or "",
                    scope=scope,
                    value_sha256="",
                    author_id=author_id,
                    metadata=meta,
                )
            return event

    def forget_requests(self, scope: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Refused requests to forget a reviewed entry in ``scope``, newest first, one per entry.

        The MCP server refuses ``kibisis_forget`` on an entry a person reviewed and journals the
        request; this is the review queue's view of those refusals. A request is left out once its
        entry is gone or a person has reviewed the entry since it was made. Each item has
        ``category``, ``key``, ``requested_at``, ``author_id`` and ``reason``.
        """
        cursor = self._conn.cursor()
        # Filtered in SQL on the dedicated action (see record_refusal), so the number of other
        # refusals in the journal has no bearing on whether a request is found.
        cursor.execute(
            "SELECT category, key, timestamp, author_id, metadata_json FROM audit_journal "
            "WHERE action = 'forget_request' AND scope = ? ORDER BY sequence DESC",
            (scope,),
        )
        seen = set()
        requests: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except (TypeError, ValueError):
                continue
            detail = meta.get("detail") or {}
            ref = (row["category"], row["key"])
            if ref in seen:
                continue
            seen.add(ref)
            try:
                entity = self.get(row["category"], row["key"], scope=scope)
            except EntryIntegrityError as exc:
                # Not shown anywhere, but not silently: counted, logged, and raised under strict.
                self._note_integrity_failure({"category": row["category"], "key": row["key"], "scope": scope}, exc)
                if self.strict:
                    raise
                entity = None
            except PermissionError:
                entity = None  # sealed, and this vault has no key to open it
            if entity is None:
                continue
            reviews = (entity.metadata or {}).get("human_reviews") or []
            last_review = max((float(r.get("timestamp") or 0) for r in reviews if isinstance(r, dict)), default=0.0)
            if last_review > float(row["timestamp"]):
                continue  # a person looked at the entry after the request and kept it
            requests.append({
                "category": row["category"],
                "key": row["key"],
                "requested_at": float(row["timestamp"]),
                "author_id": row["author_id"] or "",
                "reason": str(detail.get("requested_reason") or ""),
            })
            if len(requests) >= limit:
                break
        return requests

    def supersede(
        self,
        category: str,
        old_key: str,
        new_key: str,
        new_content: str,
        metadata: Optional[Dict[str, Any]] = None,
        valid_from: Optional[float] = None,
        valid_until: Optional[float] = None,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> MemoryEntity:
        """Atomically revoke old_key and record new_key as its superseding replacement.

        ``origin`` is passed through to :meth:`put`: the replacement asks for ``verified``, which
        under K-R1 is the author's attestation only when the origin is a principal (``user`` or
        ``import``) and is minted once ``verification_quorum`` is met.
        """
        return self.put(
            category=category,
            key=new_key,
            content=new_content,
            metadata=metadata,
            valid_from=valid_from,
            valid_until=valid_until,
            scope=scope,
            author_id=author_id,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=old_key,
            supersedes_category=category,
            epistemic_state=EpistemicState.VERIFIED.value,
            origin=origin,
        )

    def put_batch(
        self,
        items: Sequence[Union[Dict[str, Any], MemoryEntity]],
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> List[MemoryEntity]:
        """Insert or update several entities, in order, each in its own transaction.

        The batch stops at the first item that fails, and the items before it stay written.
        ``fencing_token``, ``resource`` and ``holder_id`` apply to every item; a dict item may set its own.
        A dict item is the keyword arguments of :meth:`put`; keys that are not ``put`` parameters
        (private flags such as ``_review_verdict`` and ``_trusted_metadata`` included) raise
        ``TypeError`` before anything is written.
        """
        fence = {"fencing_token": fencing_token, "resource": resource, "holder_id": holder_id}
        allowed = _PUT_PARAMETERS
        for item in items:
            if isinstance(item, dict):
                unknown = sorted(str(k) for k in item if k not in allowed)
                if unknown:
                    raise TypeError(f"put_batch item has arguments put() does not take: {unknown}")
        results: List[MemoryEntity] = []
        with self._conn:
            for item in items:
                if isinstance(item, MemoryEntity):
                    res = self.put(
                        category=item.category,
                        key=item.key,
                        content=item.content,
                        metadata=item.metadata,
                        epistemic_state=item.epistemic_state.value if isinstance(item.epistemic_state, EpistemicState) else str(item.epistemic_state),
                        valid_from=item.valid_from,
                        valid_until=item.valid_until,
                        scope=item.scope,
                        **fence,
                    )
                elif isinstance(item, dict):
                    res = self.put(**{**fence, **item})
                else:
                    raise TypeError(f"Expected dict or MemoryEntity, got {type(item)}")
                results.append(res)
        return results

    def get(
        self,
        category: str,
        key: str,
        scope: str = "default",
    ) -> Optional[MemoryEntity]:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT id, category, key, content, metadata_json, version, archived, created_at, updated_at,
                   is_encrypted, encrypted_envelope_json, scope, epistemic_state, valid_from, valid_until, tenant_sig,
                   supersedes, superseded_by, origin, source_ref, confidence
            FROM entities
            WHERE category = ? AND key = ? AND scope = ?
            """,
            (category, key, scope),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        content = self._open_entry(row)  # raises EntryIntegrityError for a tampered or unsigned entry
        return self._entity(row, content)

    def archive(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> bool:
        """Archive the entry at ``category:key`` (hidden from reads, kept in the file) and cascade an
        invalidation to what derived from it.

        ``origin`` names who asked, as on :meth:`tombstone`: a non-principal origin cannot archive an
        entry a person verified or reviewed, or one a higher class wrote
        (:class:`ReviewedEntryError`, nothing changed). ``None`` leaves the check to the caller.
        """
        requester = self._requester_class(origin)
        now = time.time()
        with self._journal_protected_refusal("archive", category, key, scope, author_id, origin), self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            row = self._fetch_row(cursor, category, key, scope)
            if row is None:
                return False
            self._refuse_if_protected(row, requester, origin, "archive")
            cursor.execute(
                """
                UPDATE entities
                SET archived = 1, updated_at = ?
                WHERE id = ? AND archived = 0
                """,
                (now, row["id"]),
            )
            archived = cursor.rowcount > 0
            if archived:
                self._record_audit_event(
                    cursor=cursor,
                    action="archive",
                    category=category,
                    key=key,
                    scope=scope,
                    value_sha256="",
                    author_id=author_id,
                    metadata={"origin": origin or "", "origin_class": requester},
                )
                self._cascade_invalidate(cursor, scope, f"{category}:{key}", author_id, now, writer_class=requester)
            return archived

    @staticmethod
    def _entity(r: Any, content: str) -> MemoryEntity:
        """The one row-to-entity constructor, used by every read path and by the write path's return.

        Three hand-written copies of this mapping drifted apart: search and list left out origin,
        source_ref and confidence, so every entry they returned claimed origin 'unknown'. One
        constructor means a column added to the entity is added to every path or to none.
        """
        keys = r.keys()
        return MemoryEntity(
            id=r["id"],
            category=r["category"],
            key=r["key"],
            content=content,
            metadata=json.loads(r["metadata_json"]),
            version=r["version"],
            archived=bool(r["archived"]),
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            epistemic_state=EpistemicState(r["epistemic_state"]) if "epistemic_state" in keys else EpistemicState.VERIFIED,
            valid_from=r["valid_from"] if "valid_from" in keys else None,
            valid_until=r["valid_until"] if "valid_until" in keys else None,
            scope=r["scope"] if "scope" in keys else "default",
            tenant_sig=r["tenant_sig"],
            supersedes=r["supersedes"] if "supersedes" in keys else None,
            superseded_by=r["superseded_by"] if "superseded_by" in keys else None,
            origin=(r["origin"] or "unknown") if "origin" in keys else "unknown",
            source_ref=r["source_ref"] if "source_ref" in keys else None,
            confidence=r["confidence"] if "confidence" in keys else None,
        )

    def list_entities(
        self,
        category: Optional[str] = None,
        include_archived: bool = False,
        scope: str = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
        active_only: bool = False,
    ) -> List[MemoryEntity]:
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT id, category, key, content, metadata_json, version, archived, "
            "created_at, updated_at, is_encrypted, encrypted_envelope_json, "
            "scope, epistemic_state, valid_from, valid_until, tenant_sig, "
            "supersedes, superseded_by, origin, source_ref, confidence FROM entities WHERE 1=1"
        )
        params: List[Any] = []

        if not include_archived:
            query_sql += " AND archived = 0"
        if scope != "*":
            query_sql += " AND scope = ?"
            params.append(scope)
        if category:
            query_sql += " AND category = ?"
            params.append(category)
        if epistemic_state:
            query_sql += " AND epistemic_state = ?"
            params.append(epistemic_state)
        elif not include_unverified:
            query_sql += " AND epistemic_state IN ('verified', 'disputed')"
        if as_of_valid_time is not None:
            query_sql += " AND (valid_from IS NULL OR valid_from <= ?) AND (valid_until IS NULL OR valid_until > ?)"
            params.extend([as_of_valid_time, as_of_valid_time])
        elif active_only:
            now_t = time.time()
            query_sql += " AND (valid_from IS NULL OR valid_from <= ?) AND (valid_until IS NULL OR valid_until > ?)"
            params.extend([now_t, now_t])

        query_sql += " ORDER BY category, key"
        cursor.execute(query_sql, params)

        items = []
        for r in cursor.fetchall():
            content = self._readable_content(r)
            if content is None:
                continue  # failed its integrity check: tampered, damaged, or moved from another entry
            items.append(self._entity(r, content))
        return items

    def set_persona_slot(
        self,
        content: str,
        scope: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        origin: Optional[str] = "user",
        attester: Optional[str] = None,
    ) -> MemoryEntity:
        """Store or update the dedicated user persona / preference slot.

        The slot is the person's own profile, so ``origin`` defaults to ``"user"``: the write is the
        account's attestation (see :meth:`put` for ``attester``) and the slot is ``verified`` once
        ``verification_quorum`` is met (K-R1); below quorum it is stored as a candidate with
        ``verification_pending``. A request from outside the principal class (``origin="model"``,
        say) cannot replace a slot a person verified or reviewed or that a higher class wrote
        (:class:`ReviewedEntryError`), the same check :meth:`tombstone` runs; and its write is a
        candidate whatever it claims.
        """
        requester = self._requester_class(origin)
        meta = metadata.copy() if metadata else {}
        meta["is_persona_slot"] = True
        fields: Dict[str, Any] = dict(
            category="persona",
            key="user_profile",
            content=content,
            metadata=meta,
            scope=scope,
            author_id=author_id,
            epistemic_state=EpistemicState.VERIFIED.value,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            origin=origin,
            attester=attester,
        )
        if requester == "principal":
            # Nothing to check before the write; ``put`` checks the fence first, inside its write.
            return self.put(**fields)
        # One outermost write transaction holds the fence, the protection check and the write, so a
        # review another connection commits lands before the check (refused) or after the write. The
        # write is put's own (``_put``, journaled as ``_put_journaled`` does); both journals sit outside
        # the transaction, so a refusal is journaled once, after the rollback, and a failing fence never.
        with self._journal_put_refusals("persona", "user_profile", scope, author_id, origin), \
                self._journal_protected_refusal(
                    "set_persona_slot", "persona", "user_profile", scope, author_id, origin,
                    refusals=(ReviewedEntryError,),
                ), \
                self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            row = self._fetch_row(cursor, "persona", "user_profile", scope)
            if row is not None:
                self._refuse_if_protected(row, requester, origin, "replace the persona slot of")
            return self._put(**fields)

    def get_persona_slot(
        self,
        scope: str = "default",
    ) -> Optional[MemoryEntity]:
        """Fetch the dedicated persona / preference slot for the specified scope."""
        return self.get(category="persona", key="user_profile", scope=scope)

    def get_persona_context_item(
        self,
        scope: str = "default",
        role: str = "system",
    ) -> Optional[Dict[str, Any]]:
        """Fetch persona slot formatted as a pinned Harpe ContextItem dict."""
        ent = self.get_persona_slot(scope=scope)
        if ent is None:
            return None
        return ent.to_context_item(pinned=True, priority=0, role=role)

    def validate_tenant_ownership(self, entity: MemoryEntity, expected_scope: str) -> bool:
        """Validate cryptographic HMAC ownership of an entity against expected scope (MemLeak defense)."""
        if entity.scope != expected_scope:
            return False
        if self._keyed:
            return verify_entry(
                self._signing_key, entity.scope, entity.category, entity.key, entity.content, entity.tenant_sig
            )
        if not entity.tenant_sig:
            return True  # a vault without a passphrase has no secret to sign with
        return verify_tenant_payload(
            self._signing_key,
            entity.scope,
            f"{entity.category}:{entity.key}",
            entity.content,
            entity.tenant_sig,
        )

    def close(self) -> None:
        if self._scan_cache is not None:
            self._scan_cache[1].close()
            self._scan_cache = None
        if self._tokenizer is not None:
            self._tokenizer.close()
            self._tokenizer = None
        self._conn.close()


#: The keyword arguments :meth:`SQLiteMemoryVault.put` takes; ``put_batch`` checks dict items against it.
_PUT_PARAMETERS = frozenset(
    name for name in inspect.signature(SQLiteMemoryVault.put).parameters if name != "self"
)
