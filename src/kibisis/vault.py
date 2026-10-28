"""SQLite and FTS5 memory vault implementation for Kibisis with authenticated envelope encryption and hardened tombstones."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import inspect
import json
import logging
import os
try:
    import sqlcipher3
except ImportError:
    import sqlite3 as sqlcipher3
import re
import sqlite3
import string
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from .admission import AdmissionDecision, FactDisposition, MemoryAdmissionGate
from .crypto import (
    ENTRY_BINDING,
    ENTRY_SIGNATURE_PREFIX,
    TOMBSTONE_BINDING,
    AESGCMCryptoEnvelopeProvider,
    derive_integrity_keys,
    entry_aad,
    keyed_value_digest,
    sign_entry,
    sign_tenant_payload,
    tombstone_aad,
    verify_entry,
    verify_tenant_payload,
)
from .keys import MIN_PASSPHRASE_LENGTH, resolve_passphrase
from .models import AuditEvent, EncryptedEnvelope, EpistemicState, MemoryEntity, SearchHit, SearchResult
from .protocols import CryptoEnvelopeProvider, EncryptionRequiredError, LeaseConflictError, LeaseCoordinator, MemoryVault

logger = logging.getLogger(__name__)

#: Integrity format this version writes (vault_meta 'integrity_format'). Format 2 binds sealed content
#: to its entry, signs entries with a key derived by PBKDF2, keys the value digests kept in the journal
#: and in tombstones, and refuses entries without a signature. A vault without the marker is upgraded
#: the first time it is opened with its passphrase.
INTEGRITY_FORMAT = 2

#: Journal hash layout this version writes (``audit_journal.format``). Formats 1 and 2 hashed a
#: ``':'``-joined string of eight fields and left ``metadata_json`` out, so a ``':'`` inside a category
#: or key could alias another event and a rewritten reviewer or verdict passed verification. Format 3
#: hashes a canonical JSON array (unambiguous field boundaries) that includes a digest of the metadata,
#: and every append also signs the chain head into ``audit_head`` so a deleted tail is detected.
#: Rows written under an older format keep verifying under their own layout.
JOURNAL_FORMAT = 3

#: Version of the entry index (``entities_search``) that a SQLCipher vault keeps for ranked search. A vault
#: whose index has another version, or none, gets one built from its entries when opened with its passphrase.
SEARCH_INDEX_FORMAT = 1

# sqlcipher3 raises its own OperationalError, which is not sqlite3's.
_OPERATIONAL_ERRORS = (sqlite3.OperationalError, sqlcipher3.OperationalError)
_ENTITY_COLUMNS = (
    "e.id, e.category, e.key, e.content, e.metadata_json, e.version, e.archived, e.created_at, e.updated_at, "
    "e.is_encrypted, e.encrypted_envelope_json, e.scope, e.epistemic_state, e.valid_from, e.valid_until, "
    "e.tenant_sig, e.supersedes, e.superseded_by, e.origin, e.source_ref, e.confidence"
)

# Where an entry came from. "model" writes are capped at candidate and cannot promote themselves.
ORIGINS = ("user", "model", "tool", "import", "unknown")

#: Metadata keys the vault writes itself and reads back as facts about trust and ownership. A caller's
#: ``metadata`` argument cannot set them: ``_put`` drops them (and logs the drop) unless the write
#: comes from an internal path whose metadata the vault produced (``review_entity``, ``import_snapshot``).
#: ``human_reviews`` is what ``_is_reviewed`` consults, so a caller-supplied value would forge a
#: person's review; ``tenant_id`` and ``principal_id`` bound recall; ``lineage_*`` is reserved.
RESERVED_METADATA_KEYS = frozenset({"human_reviews", "tenant_id", "principal_id"})
RESERVED_METADATA_PREFIX = "lineage_"


def _reserved_metadata_keys(meta: Dict[str, Any]) -> List[str]:
    return sorted(k for k in meta if k in RESERVED_METADATA_KEYS or str(k).startswith(RESERVED_METADATA_PREFIX))
_ORIGIN_CHECK = "CHECK (origin IN ('user','model','tool','import','unknown'))"
DEFAULT_ARGUS_LEDGER_PATH = "/opt/data/runtime/argus/audit.jsonl"


def _validate_origin(origin: Optional[str], what: str = "origin") -> Optional[str]:
    if origin is None:
        return None
    if origin not in ORIGINS:
        raise ValueError(f"{what} must be one of {ORIGINS}, got {origin!r}")
    return origin


def _argus_ledger_path() -> Optional[str]:
    """Argus ledger that state transitions are mirrored to; ARGUS_LEDGER_PATH="" turns it off."""
    if "ARGUS_LEDGER_PATH" in os.environ:
        return os.environ["ARGUS_LEDGER_PATH"] or None
    return DEFAULT_ARGUS_LEDGER_PATH if os.path.exists(DEFAULT_ARGUS_LEDGER_PATH) else None


def _argus_append(event_type: str, actor: str, payload: Dict[str, Any]) -> None:
    """Append through the argus_ledger library only, so the hash chain stays valid. Never raises."""
    path = _argus_ledger_path()
    if not path:
        return
    try:
        from argus_ledger import AppendOnlyLedger  # optional dependency
        AppendOnlyLedger(path).append(event_type=event_type, actor=actor, payload=payload)
    except Exception as exc:  # pragma: no cover - best effort mirror
        logger.debug("argus mirror skipped (%s): %s", event_type, exc)
# What keys-only search reads: no content, no sealed content.
_HIT_COLUMNS = "e.id, e.category, e.key, e.scope, e.metadata_json"
# Words that match="any" leaves out of a query while the query has other words.
_SEARCH_STOPWORDS = frozenset(
    "a an and are as at be been being but by can could did do does doing for from had has have having he her "
    "hers him his how i if in into is it its me my no not of on or our ours she should so than that the their "
    "theirs them then there these they this those to was we were what when where which who whom whose why will "
    "with would you your yours".split()
)
_EDGE_PUNCTUATION = re.compile(r"^[\W_]+|[\W_]+$")
_WORD = re.compile(r"[^\W_]+")


def _search_terms(query: str, match: str) -> List[str]:
    """Words of a search query, without surrounding punctuation and without words that have no letter or
    digit. For ``match="any"`` also lowercased and without repeats, and without common function words and
    single characters while other words remain."""
    words = [w for w in (_EDGE_PUNCTUATION.sub("", raw) for raw in query.split()) if _WORD.search(w)]
    if match != "any":
        return words
    unique: List[str] = []
    for w in words:
        if w.lower() not in unique:
            unique.append(w.lower())
    content = [w for w in unique if w not in _SEARCH_STOPWORDS] or unique
    return [w for w in content if len(w) > 1] or content


def _bounded(
    tenant_id: Optional[str], principal_id: Optional[str], authorized_lineage_roots: Optional[List[str]]
) -> bool:
    """Whether a search names a tenant, a principal or authorized lineage roots to hold its results to."""
    return bool(tenant_id or principal_id or authorized_lineage_roots is not None)


def _within_bounds(
    r: Any, tenant_id: Optional[str], principal_id: Optional[str], authorized_lineage_roots: Optional[List[str]]
) -> bool:
    """Hard post-retrieval governance gating (MemLeak arXiv:2610.04195 & Lineage AMU arXiv:2610.07258), on a
    stored row's metadata, which is not sealed: entries outside these bounds are never opened."""
    meta = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
    meta = meta or {}
    # 1. Hard tenant boundary check
    if tenant_id and meta.get("tenant_id") and meta.get("tenant_id") != tenant_id:
        return False
    # 2. Hard principal/user boundary check if specified
    if principal_id and meta.get("principal_id") and meta.get("principal_id") != principal_id:
        return False
    # 3. Derivation-gated lineage check (AMU)
    if authorized_lineage_roots is not None:
        if any(root not in authorized_lineage_roots for root in meta.get("derived_from", [])):
            return False
    return True


def _snippet_patterns(terms: Sequence[str]) -> Optional[Tuple[Any, Any]]:
    """Patterns for :func:`_snippet`, built once per search: where a query term begins a word (as FTS5
    prefix queries match), and the whole whitespace-separated word around such a place."""
    prefixes = sorted({w.lower() for term in terms for w in _WORD.findall(term)}, key=len, reverse=True)
    if not prefixes:
        return None
    alternatives = "|".join(map(re.escape, prefixes))
    start = re.compile(r"(?<![^\W_])(?:" + alternatives + ")", re.IGNORECASE)
    word = re.compile(r"\S*?(?<![^\W_])(?:" + alternatives + r")\S*", re.IGNORECASE)
    return start, word


def _snippet(text: str, patterns: Optional[Tuple[Any, Any]], width: int = 16) -> str:
    """Up to ``width`` words of ``text`` from around the first word that a query term begins, each matching
    word in <b>...</b>: the shape that FTS5's snippet() gives for entries stored in plaintext."""
    words = text.split()
    first = 0
    m = patterns[0].search(text) if patterns is not None else None
    if m is not None:
        before = text[: m.start()]
        first = len(before.split()) - (1 if before and not before[-1].isspace() else 0)
    start = max(0, min(first - width // 4, len(words) - width))
    body = " ".join(words[start : start + width])
    if patterns is not None:
        body = patterns[1].sub(lambda w: f"<b>{w.group(0)}</b>", body)
    return ("..." if start > 0 else "") + body + ("..." if start + width < len(words) else "")


def _sqlcipher_available() -> bool:
    """True when the real sqlcipher3 driver is loaded; the import above falls back to the standard sqlite3."""
    return sqlcipher3 is not sqlite3


def canonicalize_text(text: str) -> str:
    """Normalize text for evasion-resistant tombstone matching.

    Transforms text by:
    1. Unicode NFKC normalization (replaces lookalikes, fullwidth chars, compatibility ligatures)
    2. Unicode case folding (.casefold())
    3. Stripping invisible Unicode format/control characters (Cf/Cc, e.g., zero-width spaces/joiners, soft hyphens)
    4. Stripping all Unicode punctuation and symbols (replacing with space separators)
    5. Collapsing all whitespace runs into single spaces and trimming
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text).casefold()
    chars: List[str] = []
    for ch in normalized:
        if ch.isspace():
            chars.append(" ")
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc"):
            # Drop invisible format/control characters (e.g. \u200b, \u200c, \u200d, \ufeff, \u00ad)
            continue
        if cat.startswith(("P", "S")):
            chars.append(" ")
        else:
            chars.append(ch)
    return " ".join("".join(chars).split())


def value_digests(content: str) -> Tuple[str, str]:
    """Return the (exact, canonical) SHA-256 digests a tombstone records for a value.

    The canonical digest is empty when the value canonicalizes to nothing (for example
    punctuation only); such values are matched by their exact digest alone.
    """
    exact = hashlib.sha256(content.encode("utf-8")).hexdigest()
    can_text = canonicalize_text(content)
    canonical = hashlib.sha256(can_text.encode("utf-8")).hexdigest() if can_text else ""
    return exact, canonical


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


class AdmissionRefused(PermissionError):
    """Raised when a reviewer that is not a person tries to promote an entry to ``verified``."""


class EntryIntegrityError(PermissionError):
    """Raised when a stored entry fails its integrity check: it has no signature, its signature does
    not verify, or its sealed content does not belong to it. ``get`` raises it; ``search`` and
    ``list_entities`` leave such an entry out."""


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


def _event_hash(
    sequence: int,
    timestamp: float,
    action: str,
    category: str,
    key: str,
    scope: str,
    value_sha256: str,
    prev_hash: str,
    author_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
    fmt: int = JOURNAL_FORMAT,
) -> str:
    """SHA-256 of one journal event, which links to the one before it through ``prev_hash``.

    ``fmt`` selects the layout the row was written under (see :data:`JOURNAL_FORMAT`). Formats below 3
    reproduce the legacy ``':'``-joined payload, metadata excluded, so older journals still verify.
    """
    if fmt < 3:
        payload = f"{sequence}:{timestamp:.6f}:{action}:{category}:{key}:{scope}:{value_sha256}:{prev_hash}:{author_id or ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    # A digest of the canonical metadata, not the metadata itself, keeps the payload bounded and makes
    # the hash independent of how the stored JSON happens to be spaced.
    meta_digest = hashlib.sha256(
        json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    fields = [
        int(sequence), f"{timestamp:.6f}", action, category, key, scope, value_sha256, prev_hash, author_id or "",
        meta_digest,
    ]
    payload = json.dumps(fields, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _head_mac(signing_key: bytes, sequence: int, event_hash: str) -> str:
    """HMAC over the chain head, so the last row cannot be removed or replaced without the signing key.

    Without a passphrase the signing key is not secret (it is derived from the path), so the head
    then catches accidental truncation only; with a passphrase it is derived from the passphrase.
    """
    payload = json.dumps([int(sequence), event_hash], separators=(",", ":")).encode("utf-8")
    return hmac.new(signing_key, b"kibisis audit head v1:" + payload, hashlib.sha256).hexdigest()


def _rekey_metadata(metadata: Dict[str, Any], digest_key: bytes) -> bool:
    """Key the plain digest a format 1 journal event keeps in its metadata, and drop digest prefixes."""
    changed = False
    if metadata.get("canonical_sha256"):
        metadata["canonical_sha256"] = keyed_value_digest(digest_key, str(metadata["canonical_sha256"]))
        changed = True
    detail = metadata.get("detail")
    if isinstance(detail, dict) and "value_digest_prefix" in detail:
        del detail["value_digest_prefix"]  # a prefix of a plain digest cannot be keyed, and still leaks
        changed = True
    return changed


def row_origin(row: Any) -> str:
    """Origin of a fetched row; 'unknown' for rows and cursors that predate the column."""
    try:
        return row["origin"] or "unknown"
    except (IndexError, KeyError):
        return "unknown"


def _is_reviewed(row: Any) -> bool:
    """True for an entry in the verified state or one that carries a person's review."""
    if row["epistemic_state"] == EpistemicState.VERIFIED.value:
        return True
    try:
        meta = json.loads(row["metadata_json"] or "{}")
    except (TypeError, ValueError):
        return False
    return bool(meta.get("human_reviews"))


class SQLiteMemoryVault(MemoryVault):
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
    ) -> None:
        """Open a vault. Entry content is encrypted by default.

        The passphrase comes from the argument, then KIBISIS_PASSPHRASE_FILE, then KIBISIS_PASSPHRASE.
        With no passphrase the vault refuses to open (EncryptionRequiredError) unless ``allow_plaintext=True``.
        An in-memory vault never touches disk, so it may run without a passphrase.

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
        """
        self.db_path = str(db_path)
        if cache_mb is not None and int(cache_mb) <= 0:
            raise ValueError("cache_mb must be a positive number of MiB")
        if crypto_provider is not None:
            _require_aad_support(crypto_provider)  # before anything touches the file
        self.coordinator = coordinator
        self.enforce_fencing = enforce_fencing
        self.auto_gate = auto_gate
        if enforce_fencing and coordinator is None:
            raise ValueError("enforce_fencing=True needs a lease coordinator: pass coordinator=")
        self._fallback_search_warned = False
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

        # Integrity keys. With a passphrase, the signing and digest keys are derived from a PBKDF2 stretch
        # of it once the vault's salt is known (below); _legacy_signing_key checks format 1 signatures
        # during the upgrade. Without a passphrase nothing is secret: signatures catch only accidental
        # damage, and value digests stay plain SHA-256.
        sig_seed = passphrase if passphrase else self.db_path
        self._legacy_signing_key = hashlib.sha256(f"kibisis-tenant-sig:{sig_seed}".encode("utf-8")).digest()
        self._signing_key = self._legacy_signing_key
        self._digest_key: Optional[bytes] = None
        self._keyed = False
        self._integrity_format = 1
        self._converted_to_sqlcipher = False
        self._was_keyed = False
        #: Counts from the integrity upgrade this open performed, or None when none was needed.
        self.integrity_upgrade: Optional[Dict[str, Any]] = None

        # Convert an existing plain SQLite file to SQLCipher when a passphrase is given. Without sqlcipher3 there
        # is nothing to convert with: the file stays plain SQLite and the first open that has sqlcipher3 converts it.
        if on_disk and passphrase and not _sqlcipher_available():
            logger.warning(
                "sqlcipher3 is not installed, so %s is not encrypted as a whole file: entry content is still "
                "sealed, but categories, keys and metadata are stored in plain text",
                self.db_path,
            )
        if (
            on_disk
            and passphrase
            and _sqlcipher_available()
            and os.path.exists(self.db_path)
            and os.path.getsize(self.db_path) > 0
        ):
            with open(self.db_path, "rb") as f:
                hdr = f.read(16)
            if hdr.startswith(b"SQLite format 3"):
                # Migrate existing plaintext SQLite database to encrypted SQLCipher database
                self._migrate_file_to_sqlcipher(self.db_path, passphrase)
                self._converted_to_sqlcipher = True

        self._search_index = False  # True once a SQLCipher vault's entry index is in use
        self._scan_cache: Optional[Tuple[Tuple[int, int], Any]] = None  # in-memory index without SQLCipher
        self._conn = sqlcipher3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlcipher3.Row
        self._sqlcipher_active = False
        self._cache_mb = int(cache_mb) if cache_mb is not None else None
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
        self._configure_db()
        if self._cache_mb is not None:
            self._conn.execute(f"PRAGMA cache_size = -{self._cache_mb * 1024}")
        self._init_schema()
        if passphrase:
            self._was_keyed = self._has_meta_key("kdf_salt")  # written by an earlier open with a passphrase
            salt = self._vault_salt()
            if crypto_provider is None:
                self.crypto_provider = AESGCMCryptoEnvelopeProvider(salt=salt)
            self._signing_key, self._digest_key = derive_integrity_keys(passphrase, salt)
            self._keyed = True
            try:
                self._upgrade_integrity()
                if self._sqlcipher_active:
                    self._ensure_search_index()
            except BaseException:
                self._conn.close()
                raise
        if on_disk:
            self._restrict_permissions()

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
        if fencing_token is None and resource is None and not self.enforce_fencing:
            return
        self._validate_fencing(fencing_token, resource, holder_id)

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
    def _migrate_file_to_sqlcipher(path: str, passphrase: str) -> None:
        temp_enc = path + ".tmp_enc"
        if os.path.exists(temp_enc):
            os.unlink(temp_enc)
        escaped_pass = passphrase.replace("'", "''")
        conn_raw = sqlcipher3.connect(path)
        try:
            conn_raw.execute(f"ATTACH DATABASE '{temp_enc}' AS encrypted KEY '{escaped_pass}';")
            conn_raw.execute("SELECT sqlcipher_export('encrypted');")
            conn_raw.execute("DETACH DATABASE encrypted;")
        finally:
            conn_raw.close()
        for ext in ("-wal", "-shm"):
            p = path + ext
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        os.replace(temp_enc, path)

    def _vault_salt(self) -> bytes:
        """One random KDF salt per vault, stored beside the data. A salt is not a secret."""
        # Locked before the read so two processes opening a new vault together agree on one salt.
        with self._write_tx() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            row = cursor.execute("SELECT value FROM vault_meta WHERE key = 'kdf_salt'").fetchone()
            if row is not None:
                return bytes(row[0])
            salt = os.urandom(16)
            cursor.execute("INSERT INTO vault_meta (key, value) VALUES ('kdf_salt', ?)", (salt,))
            return salt

    def _restrict_permissions(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError:
                pass

    def encryption_status(self) -> Dict[str, int]:
        """Counts of live entries by storage form. ``plaintext`` should be 0 on an encrypted vault."""
        row = self._conn.execute(
            "SELECT COALESCE(SUM(is_encrypted = 1), 0) AS enc, COALESCE(SUM(is_encrypted = 0), 0) AS plain FROM entities"
        ).fetchone()
        return {"encrypted": int(row["enc"]), "plaintext": int(row["plain"])}

    def migrate_plaintext(self) -> Dict[str, int]:
        """Encrypt every plaintext entry in place, then remove the old plaintext from the search index,
        the write-ahead log and free pages. Returns {"migrated": n, "remaining_plaintext": m}."""
        if self.crypto_provider is None or not self.passphrase:
            raise EncryptionRequiredError("migrate_plaintext needs a passphrase.")
        rows = self._conn.execute(
            "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig "
            "FROM entities WHERE is_encrypted = 0"
        ).fetchall()
        refused = 0
        with self._write_tx() as cursor:
            for r in rows:
                try:
                    content = self._open_entry(r)  # never seal content that fails its signature check
                except EntryIntegrityError:
                    refused += 1
                    continue
                self._write_sealed(cursor, r, content, encrypt=True)
        self.scrub()
        return {"migrated": len(rows) - refused, "remaining_plaintext": self.encryption_status()["plaintext"]}

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

    def _record_audit_event(
        self,
        cursor: sqlite3.Cursor,
        action: str,
        category: str,
        key: str,
        scope: str,
        value_sha256: str,
        author_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Append a tamper-evident audit record chaining from the previous event's hash."""
        now = time.time()
        meta_dict = metadata or {}

        # Read the head inside the caller's write transaction, never from a per-instance cache: other
        # processes append to the same journal, so a cached head goes stale and every later insert
        # reuses an existing sequence. BEGIN IMMEDIATE covers a caller that has not written yet.
        if not self._conn.in_transaction:
            cursor.execute("BEGIN IMMEDIATE")
        cursor.execute("SELECT sequence, event_hash FROM audit_journal ORDER BY sequence DESC LIMIT 1")
        last_row = cursor.fetchone()
        seq, prev_hash = (last_row["sequence"] + 1, last_row["event_hash"]) if last_row else (1, "0" * 64)

        event_hash = _event_hash(
            seq, now, action, category, key, scope, value_sha256, prev_hash, author_id, meta_dict, fmt=JOURNAL_FORMAT
        )
        meta_json = json.dumps(meta_dict, sort_keys=True)

        cursor.execute(
            """
            INSERT INTO audit_journal (
                sequence, timestamp, action, category, key, scope, value_sha256,
                prev_hash, event_hash, author_id, metadata_json, format
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (seq, now, action, category, key, scope, value_sha256, prev_hash, event_hash, author_id, meta_json,
             JOURNAL_FORMAT),
        )
        self._write_audit_head(cursor, seq, event_hash)
        return AuditEvent(
            sequence=seq,
            timestamp=now,
            action=action,
            category=category,
            key=key,
            scope=scope,
            value_sha256=value_sha256,
            prev_hash=prev_hash,
            event_hash=event_hash,
            author_id=author_id,
            metadata=meta_dict,
            format=JOURNAL_FORMAT,
        )

    def _write_audit_head(self, cursor: Any, sequence: int, event_hash: str) -> None:
        """Sign the chain head, in the same transaction as the append it describes."""
        cursor.execute(
            "INSERT OR REPLACE INTO audit_head (id, sequence, event_hash, mac) VALUES (1, ?, ?, ?)",
            (sequence, event_hash, _head_mac(self._signing_key, sequence, event_hash)),
        )

    # Integrity: sealing, signing and checking entries, keyed digests, and the format 2 upgrade.

    def _sign(self, scope: str, category: str, key: str, content: str) -> str:
        if self._keyed:
            return sign_entry(self._signing_key, scope, category, key, content)
        return sign_tenant_payload(self._signing_key, scope, f"{category}:{key}", content)

    def _seal(
        self, scope: str, category: str, key: str, content: str, *, encrypt: bool
    ) -> Tuple[str, int, Optional[str], str]:
        """(stored content, is_encrypted, envelope JSON, signature) for an entry. Sealed content is bound
        to the entry's scope, category and key, and its plaintext column is left empty."""
        signature = self._sign(scope, category, key, content)
        if not encrypt:
            return content, 0, None, signature
        if self.crypto_provider is None or not self.passphrase:
            raise EncryptionRequiredError("Sealing an entry needs a crypto provider and a passphrase.")
        envelope = self.crypto_provider.encrypt(
            content.encode("utf-8"), self.passphrase, aad=entry_aad(scope, category, key)
        )
        return "", 1, envelope.model_copy(update={"binding": ENTRY_BINDING}).model_dump_json(), signature

    def _write_sealed(self, cursor: Any, r: Any, content: str, *, encrypt: bool) -> None:
        """Re-seal and re-sign stored row ``r`` (with id, scope, category and key) to hold ``content``."""
        stored, is_encrypted, envelope_json, signature = self._seal(
            r["scope"], r["category"], r["key"], content, encrypt=encrypt
        )
        cursor.execute(
            "UPDATE entities SET content = ?, is_encrypted = ?, encrypted_envelope_json = ?, tenant_sig = ? WHERE id = ?",
            (stored, is_encrypted, envelope_json, signature, r["id"]),
        )
        if self._search_index:
            self._index_entry(cursor, r["id"], r["category"], r["key"], content, r["scope"])

    def _open_entry(self, r: Any) -> str:
        """Content of a stored row, after its integrity checks.

        Raises :class:`EntryIntegrityError` when the row lacks a valid signature (a vault with a
        passphrase refuses unsigned rows) or its sealed content was not sealed for this entry, and a
        plain ``PermissionError`` when the row is sealed and this vault has no key.
        """
        scope, category, key = r["scope"], r["category"], r["key"]
        where = f"'{category}:{key}' [scope={scope}]"
        if r["is_encrypted"] == 1:
            if self.crypto_provider is None or not self.passphrase:
                raise PermissionError("Entity is encrypted, but vault has no crypto provider or passphrase configured.")
            try:
                envelope = EncryptedEnvelope.model_validate_json(r["encrypted_envelope_json"] or "")
            except ValueError as exc:
                raise EntryIntegrityError(f"Integrity check failed: {where} has no readable sealed content") from exc
            if envelope.binding != ENTRY_BINDING:
                raise EntryIntegrityError(f"Integrity check failed: the sealed content of {where} is not bound to it")
            try:
                content = self.crypto_provider.decrypt(
                    envelope, self.passphrase, aad=entry_aad(scope, category, key)
                ).decode("utf-8")
            except Exception as exc:
                raise EntryIntegrityError(
                    f"Integrity check failed: the sealed content of {where} was not sealed for it, or is damaged"
                ) from exc
        else:
            content = r["content"]
        signature = r["tenant_sig"]
        if self._keyed:
            if not verify_entry(self._signing_key, scope, category, key, content, signature):
                problem = "has no signature" if not signature else "has an invalid signature"
                raise EntryIntegrityError(f"Integrity check failed: {where} {problem}")
        elif signature and not verify_tenant_payload(self._signing_key, scope, f"{category}:{key}", content, signature):
            raise EntryIntegrityError(f"Integrity check failed: {where} has an invalid signature")
        return content

    def _readable_content(self, r: Any) -> Optional[str]:
        """Content for search and listing: None when the row fails its integrity check (leave it out),
        "[ENCRYPTED]" when it is sealed and this vault has no key to open it."""
        try:
            return self._open_entry(r)
        except EntryIntegrityError:
            return None
        except PermissionError:
            return "[ENCRYPTED]"

    def _open_legacy(self, r: Any) -> str:
        """Content of a row as integrity format 1 stored it (sealed without binding). Upgrade use only."""
        if r["is_encrypted"] != 1:
            return r["content"]
        envelope = EncryptedEnvelope.model_validate_json(r["encrypted_envelope_json"] or "")
        aad = entry_aad(r["scope"], r["category"], r["key"]) if envelope.binding == ENTRY_BINDING else None
        assert self.crypto_provider is not None and self.passphrase
        return self.crypto_provider.decrypt(envelope, self.passphrase, aad=aad).decode("utf-8")

    def _digests(self, value: str) -> Tuple[str, str]:
        """(exact, canonical) digests of a value as this vault stores them: keyed when it has a passphrase."""
        return self._stored_digests(*value_digests(value))

    def _digest_key_id(self) -> Optional[str]:
        """Short public identifier of the digest key, so snapshot digests can be matched to their vault."""
        if self._digest_key is None:
            return None
        return hmac.new(self._digest_key, b"kibisis digest key id", hashlib.sha256).hexdigest()[:16]

    def stored_digest(self, sha256_hex: str) -> str:
        """The form in which this vault stores a value's SHA-256 hex digest in its journal and tombstones:
        keyed when the vault has a passphrase, unchanged otherwise."""
        return keyed_value_digest(self._digest_key, sha256_hex) if self._digest_key is not None else sha256_hex

    def _stored_digests(self, exact: str, canonical: str) -> Tuple[str, str]:
        return self.stored_digest(exact), self.stored_digest(canonical)

    def _seal_digests(self, scope: str, category: str, key: str, exact: str, canonical: str) -> Optional[str]:
        """A tombstone's plain digests, sealed and bound to the tombstone, so a snapshot can carry them to
        another vault with the same passphrase. None in a vault without a passphrase."""
        if not self._keyed or self.crypto_provider is None or not self.passphrase:
            return None
        envelope = self.crypto_provider.encrypt(
            json.dumps([exact, canonical]).encode("utf-8"), self.passphrase, aad=tombstone_aad(scope, category, key)
        )
        return envelope.model_copy(update={"binding": TOMBSTONE_BINDING}).model_dump_json()

    def _unseal_digests(self, scope: str, category: str, key: str, sealed: str) -> Optional[Tuple[str, str]]:
        """Plain digests of a sealed tombstone (this vault's, or another's with the same passphrase), or None."""
        if self.crypto_provider is None or not self.passphrase:
            return None
        try:
            envelope = EncryptedEnvelope.model_validate_json(sealed)
            plain = self.crypto_provider.decrypt(envelope, self.passphrase, aad=tombstone_aad(scope, category, key))
            exact, canonical = json.loads(plain)
            return str(exact), str(canonical)
        except Exception:
            return None

    def _has_meta_key(self, key: str) -> bool:
        try:
            return self._meta(key) is not None
        except sqlcipher3.OperationalError:
            return False  # no vault_meta table: the vault was never opened with a passphrase

    def _key_check_value(self) -> str:
        return hmac.new(self._signing_key, b"kibisis key check v2", hashlib.sha256).hexdigest()

    def _meta(self, key: str) -> Any:
        row = self._conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    @staticmethod
    def _set_meta(cursor: Any, key: str, value: Any) -> None:
        cursor.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))

    def _upgrade_integrity(self) -> None:
        """Bring an older vault up to INTEGRITY_FORMAT, then check the passphrase against the key check."""
        if int(self._meta("integrity_format") or 0) < INTEGRITY_FORMAT:
            self.integrity_upgrade = self._migrate_integrity()
        stored = self._meta("key_check")
        if stored is not None and not hmac.compare_digest(str(stored), self._key_check_value()):
            raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")
        self._integrity_format = INTEGRITY_FORMAT

    def _migrate_integrity(self) -> Optional[Dict[str, Any]]:
        """Upgrade a vault written by Kibisis 0.1.0a5 or earlier to integrity format 2, in one transaction.

        Entries: each entry whose format 1 signature verifies is re-sealed with its scope, category and
        key bound to the ciphertext and signed with the PBKDF2-derived key. An entry without a signature
        is adopted only when the file was SQLCipher-encrypted before this open, because then nothing
        without the passphrase could have removed a signature; otherwise it stays as it is and reads
        refuse it until :meth:`adopt_unsigned_entries`. Entries whose signature fails, or whose content
        does not decrypt, are left untouched and refused. Journal and tombstones: every plain SHA-256
        value digest becomes its keyed form, the journal's hashes are recomputed in order, and digest
        prefixes in refusal records are dropped. A ``migrate`` event records the counts, the old chain
        head and whether the old chain verified. Returns the counts, or None for an empty vault.
        """
        counts: Dict[str, Any] = {
            "entries_resealed": 0,
            "entries_adopted_unsigned": 0,
            "entries_left_unsigned": 0,
            "entries_failed_signature": 0,
            "entries_undecryptable": 0,
            "tombstones_rekeyed": 0,
            "journal_events_rekeyed": 0,
        }
        digest_key = self._digest_key
        assert digest_key is not None
        trust_unsigned = self._sqlcipher_active and not self._converted_to_sqlcipher
        with self._write_tx() as cursor:
            if int(self._meta("integrity_format") or 0) >= INTEGRITY_FORMAT:
                return None  # another process upgraded it first
            rows = cursor.execute(
                "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities"
            ).fetchall()
            tombstones = cursor.execute(
                "SELECT id, category, key, scope, value_sha256, canonical_sha256 FROM rejected_value_tombstones"
            ).fetchall()
            events = cursor.execute(
                "SELECT sequence, timestamp, action, category, key, scope, value_sha256, prev_hash, event_hash, "
                "author_id, metadata_json, format FROM audit_journal ORDER BY sequence ASC"
            ).fetchall()
            if not (rows or tombstones or events):
                self._set_meta(cursor, "integrity_format", INTEGRITY_FORMAT)
                self._set_meta(cursor, "key_check", self._key_check_value())
                return None

            # A vault that never had a passphrase holds only plaintext entries, signed (if at all) with a key
            # anyone can compute, so its first open with a passphrase is where trust starts: adopt them.
            # Otherwise decide every entry before changing anything, and stop under a wrong passphrase: an
            # upgrade under the wrong key would re-key the tombstones and the journal beyond repair.
            was_keyed = self._was_keyed or any(r["is_encrypted"] == 1 for r in rows)
            if not was_keyed:
                counts["entries_adopted_from_keyless_vault"] = 0
            reseal: List[Tuple[Any, str]] = []
            opened = verified = 0
            for r in rows:
                try:
                    content = self._open_legacy(r)
                except Exception:
                    counts["entries_undecryptable"] += 1
                    continue
                if not was_keyed:
                    counts["entries_adopted_from_keyless_vault"] += 1
                    reseal.append((r, content))
                    continue
                opened += int(r["is_encrypted"] == 1)
                signature = r["tenant_sig"]
                if signature:
                    entity_id = f"{r['category']}:{r['key']}"
                    if not verify_tenant_payload(self._legacy_signing_key, r["scope"], entity_id, content, signature):
                        counts["entries_failed_signature"] += 1
                        continue
                    verified += 1
                elif trust_unsigned:
                    counts["entries_adopted_unsigned"] += 1
                else:
                    counts["entries_left_unsigned"] += 1
                    continue
                reseal.append((r, content))
            sealed_rows = sum(1 for r in rows if r["is_encrypted"] == 1)
            signed_rows = sum(1 for r in rows if r["tenant_sig"])
            if was_keyed and ((sealed_rows and not opened) or (signed_rows and not verified)):
                raise ValueError("Failed to authenticate or decrypt vault database with provided passphrase")

            for r, content in reseal:
                self._write_sealed(cursor, r, content, encrypt=r["is_encrypted"] == 1)
                counts["entries_resealed"] += 1

            for t in tombstones:
                exact, canonical = t["value_sha256"], t["canonical_sha256"] or ""
                cursor.execute(
                    "UPDATE rejected_value_tombstones SET value_sha256 = ?, canonical_sha256 = ?, sealed_digests = ? "
                    "WHERE id = ?",
                    (
                        keyed_value_digest(digest_key, exact),
                        keyed_value_digest(digest_key, canonical),
                        self._seal_digests(t["scope"], t["category"], t["key"], exact, canonical),
                        t["id"],
                    ),
                )
                counts["tombstones_rekeyed"] += 1

            old_head = events[-1]["event_hash"] if events else "0" * 64
            chain_was_valid = self.verify_audit_chain()
            prev_hash = "0" * 64
            for ev in events:
                value = keyed_value_digest(digest_key, ev["value_sha256"])
                metadata = json.loads(ev["metadata_json"] or "{}")
                if _rekey_metadata(metadata, digest_key) or value != ev["value_sha256"]:
                    counts["journal_events_rekeyed"] += 1
                event_hash = _event_hash(
                    ev["sequence"], ev["timestamp"], ev["action"], ev["category"], ev["key"], ev["scope"],
                    value, prev_hash, ev["author_id"], metadata, fmt=ev["format"],
                )
                cursor.execute(
                    "UPDATE audit_journal SET value_sha256 = ?, prev_hash = ?, event_hash = ?, metadata_json = ? "
                    "WHERE sequence = ?",
                    (value, prev_hash, event_hash, json.dumps(metadata, sort_keys=True), ev["sequence"]),
                )
                prev_hash = event_hash
            if not chain_was_valid:
                logger.warning(
                    "%s: the audit journal did not verify before the integrity upgrade; the upgrade's "
                    "migrate event records this and the old chain head",
                    self.db_path,
                )
            self._record_audit_event(
                cursor=cursor,
                action="migrate",
                category="",
                key="",
                scope="*",
                value_sha256="",
                metadata={
                    "integrity_format": INTEGRITY_FORMAT,
                    "previous_head": old_head,
                    "previous_chain_valid": chain_was_valid,
                    **counts,
                },
            )
            self._set_meta(cursor, "integrity_format", INTEGRITY_FORMAT)
            if opened or verified or self._sqlcipher_active or not was_keyed:
                self._set_meta(cursor, "key_check", self._key_check_value())
        if counts["entries_left_unsigned"]:
            logger.warning(
                "%s: %d entries have no signature and the file had no whole-file encryption, so they cannot "
                "be told apart from tampered entries; reads refuse them until adopt_unsigned_entries() "
                "accepts them",
                self.db_path,
                counts["entries_left_unsigned"],
            )
        if self.db_path != ":memory:":
            self.scrub()  # drop the replaced digests and envelopes from free pages and the write-ahead log
        return counts

    def integrity_status(self) -> Dict[str, int]:
        """Counts of stored entries that reads refuse, found without decrypting anything (for a vault
        opened with its passphrase): ``unsigned`` (no signature), ``legacy_signature`` (a format 1
        signature) and ``unbound`` (sealed before format 2)."""
        rows = self._conn.execute("SELECT tenant_sig, is_encrypted, encrypted_envelope_json FROM entities").fetchall()

        def unbound(r: Any) -> bool:
            try:
                return json.loads(r["encrypted_envelope_json"] or "{}").get("binding") != ENTRY_BINDING
            except ValueError:
                return True

        return {
            "integrity_format": self._integrity_format,
            "entries": len(rows),
            "unsigned": sum(1 for r in rows if not r["tenant_sig"]),
            "legacy_signature": sum(
                1 for r in rows if r["tenant_sig"] and not str(r["tenant_sig"]).startswith(ENTRY_SIGNATURE_PREFIX)
            ),
            "unbound": sum(1 for r in rows if r["is_encrypted"] == 1 and unbound(r)),
        }

    def adopt_unsigned_entries(self, scope: Optional[str] = None, author_id: Optional[str] = None) -> int:
        """Sign, and bind to their entries, stored entries that carry no signature, after a person has
        checked them. Returns how many were adopted; each is journaled as an ``adopt`` event.

        Needed only for a vault upgraded from Kibisis 0.1.0a5 or earlier that ran without SQLCipher and
        holds entries written before signatures existed, or plaintext entries written while it had no
        passphrase. Kibisis cannot tell such an entry from one whose signature was removed or forged, so
        reads refuse it until it is adopted. Entries whose format 1 signature verifies under no key are
        damaged or tampered and are never adopted. ``scope`` limits adoption to one scope (``None`` or
        ``"*"``: every scope).
        """
        if not self._keyed:
            raise EncryptionRequiredError("adopt_unsigned_entries needs a vault opened with its passphrase.")
        keyless_key = hashlib.sha256(f"kibisis-tenant-sig:{self.db_path}".encode("utf-8")).digest()
        sql = (
            "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig "
            "FROM entities WHERE (tenant_sig IS NULL OR tenant_sig = '' OR tenant_sig NOT LIKE 'v2:%')"
        )
        params: List[Any] = []
        if scope not in (None, "*"):
            sql += " AND scope = ?"
            params.append(scope)
        adopted = 0
        with self._write_tx() as cursor:
            for r in cursor.execute(sql, params).fetchall():
                try:
                    content = self._open_legacy(r)
                except Exception:
                    continue  # does not decrypt under this passphrase: nothing to adopt
                signature, entity_id = r["tenant_sig"], f"{r['category']}:{r['key']}"
                if signature and not any(
                    verify_tenant_payload(k, r["scope"], entity_id, content, signature)
                    for k in (keyless_key, self._legacy_signing_key)
                ):
                    continue
                self._write_sealed(cursor, r, content, encrypt=r["is_encrypted"] == 1)
                self._record_audit_event(
                    cursor=cursor,
                    action="adopt",
                    category=r["category"],
                    key=r["key"],
                    scope=r["scope"],
                    value_sha256=self._digests(content)[0],
                    author_id=author_id,
                    metadata={"reason": "unsigned entry accepted by a person"},
                )
                adopted += 1
        return adopted

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
        _trusted_metadata: bool = False,
    ) -> MemoryEntity:
        """Write path behind :meth:`put`, which journals the tombstone refusals this raises.

        ``_trusted_metadata`` is set only by internal callers whose ``metadata`` the vault itself
        produced; a caller's reserved keys (:data:`RESERVED_METADATA_KEYS`) are dropped otherwise.
        """
        if trust_ceiling is not None and trust_ceiling != EpistemicState.CANDIDATE.value:
            raise ValueError("trust_ceiling supports only 'candidate'")
        _validate_origin(origin)
        if confidence is not None and not (0.0 <= float(confidence) <= 1.0):
            raise ValueError("confidence must be within [0, 1]")
        if origin == "model":
            # Trust comes from where the write came from, not from what it says about itself.
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
            ep_state = EpistemicState(epistemic_state) if epistemic_state else EpistemicState.VERIFIED

        if trust_ceiling is not None and ep_state in (EpistemicState.VERIFIED, EpistemicState.DISPUTED):
            # Default recall returns verified and disputed entries; a capped write is neither.
            meta["trust_capped_from"] = ep_state.value
            ep_state = EpistemicState.CANDIDATE

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
            if trust_ceiling is not None:
                # A capped write cannot replace an entry a person verified or reviewed.
                cursor.execute(
                    "SELECT epistemic_state, metadata_json FROM entities WHERE category = ? AND key = ? AND scope = ?",
                    (category, key, scope),
                )
                existing = cursor.fetchone()
                if existing is not None and _is_reviewed(existing):
                    raise ReviewedEntryError(
                        f"'{category}:{key}' [scope={scope}] is verified or reviewed by a person; a capped write "
                        "cannot replace it. Write a new key with supersedes_key to propose a replacement."
                    )

            # Invalidate older entity if superseding is declared
            if supersedes_key:
                target_cat = supersedes_category or category
                cursor.execute(
                    "SELECT id, metadata_json, epistemic_state, origin FROM entities WHERE category = ? AND key = ? AND scope = ? AND archived = 0",
                    (target_cat, supersedes_key, scope),
                )
                target_row = cursor.fetchone()
                if target_row is not None and trust_ceiling is not None and _is_reviewed(target_row):
                    # A capped write cannot retire a reviewed entry. Record the proposal instead;
                    # review_entity applies it when a person approves this entry.
                    meta.pop("supersedes", None)
                    meta["proposed_supersedes"] = {"category": target_cat, "key": supersedes_key}
                    meta_str = json.dumps(meta, sort_keys=True)
                    supersedes_ref = None
                    target_row = None
                if target_row is not None:
                    target_meta = json.loads(target_row["metadata_json"] or "{}")
                    target_meta["superseded_by"] = f"{category}:{key}"
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
                            EpistemicState.REVOKED.value, row_origin(target_row), author_id,
                        )

            # Skip canonicalization when the vault has no tombstones. Asked of the database on every
            # write: a flag cached at open misses tombstones that other processes add later.
            cursor.execute("SELECT EXISTS (SELECT 1 FROM rejected_value_tombstones)")
            if cursor.fetchone()[0]:
                tomb = self._find_tombstone(cursor, scope, val_hash, can_hash)
                if tomb is not None:
                    raise TombstonedValueError(
                        f"Write rejected by tombstone: entity '{category}:{key}' [scope={scope}] matches rejected tombstone "
                        f"(digest: {val_hash[:12]}..., reason: {tomb['reason']})",
                        category=category,
                        key=key,
                        scope=scope,
                        digest=val_hash,
                        author_id=author_id,
                    )

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
                        origin = ?, source_ref = ?, confidence = ?
                    WHERE id = ?
                    """,
                    (
                        stored_content, meta_str, version, now, is_encrypted, envelope_json,
                        ep_state.value, valid_from, valid_until, tenant_sig, supersedes_ref,
                        stored_origin, stored_source_ref, stored_confidence, entity_id
                    ),
                )
            if self._search_index:
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
                    cursor, category, key, scope, previous_state, ep_state.value, stored_origin, author_id
                )
            # Return what was stored, through the same constructor the read paths use, so the write
            # path cannot report a field differently from a later get() or search().
            cursor.execute(f"SELECT {_ENTITY_COLUMNS} FROM entities e WHERE e.id = ?", (entity_id,))
            written = cursor.fetchone()

        return self._entity(written, content)

    def _record_state_transition(
        self,
        cursor: sqlite3.Cursor,
        category: str,
        key: str,
        scope: str,
        previous: str,
        new: str,
        origin: str,
        reviewer: Optional[str],
    ) -> None:
        """Journal an epistemic-state change and mirror it to the Argus ledger when one is configured."""
        payload = {
            "event": "state_transition",
            "from": previous,
            "to": new,
            "origin": origin,
            "reviewer": reviewer,
        }
        self._record_audit_event(
            cursor=cursor,
            action="state_transition",
            category=category,
            key=key,
            scope=scope,
            value_sha256="",
            author_id=reviewer,
            metadata=payload,
        )
        _argus_append(
            "kibisis.state_transition",
            reviewer or "kibisis",
            {**payload, "category": category, "key": key, "scope": scope},
        )

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
        _trusted_metadata: bool = False,
    ) -> MemoryEntity:
        """Insert or update an entity. See ``__init__`` for ``fencing_token``, ``resource`` and ``holder_id``.

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
        ``principal_id`` arguments). ``_trusted_metadata`` is internal.
        """
        try:
            return self._put(
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
                _trusted_metadata=_trusted_metadata,
            )
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
            return self._record_audit_event(
                cursor=cursor,
                action="refuse",
                category=category or "",
                key=key or "",
                scope=scope,
                value_sha256="",
                author_id=author_id,
                metadata=meta,
            )

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
    ) -> MemoryEntity:
        """Atomically revoke old_key and record new_key as its superseding replacement."""
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
        """
        fence = {"fencing_token": fencing_token, "resource": resource, "holder_id": holder_id}
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
    ) -> bool:
        now = time.time()
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(
                """
                UPDATE entities
                SET archived = 1, updated_at = ?
                WHERE category = ? AND key = ? AND scope = ? AND archived = 0
                """,
                (now, category, key, scope),
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
                )
            return archived

    def purge(
        self,
        category: str,
        key: str,
        scope: str = "default",
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> bool:
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            cursor.execute(
                "DELETE FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            purged = cursor.rowcount > 0
            if purged:
                self._record_audit_event(
                    cursor=cursor,
                    action="purge",
                    category=category,
                    key=key,
                    scope=scope,
                    value_sha256="",
                    author_id=author_id,
                )
            return purged

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
        scope: Optional[str] = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
        active_only: bool = True,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        authorized_lineage_roots: Optional[List[str]] = None,
        match: str = "all",
    ) -> List[SearchResult]:
        """Entries that match ``query``, best first by BM25 (``rank_score``: lower is better).

        ``match="all"`` (the default) wants every word of the query. ``match="any"`` wants at least one and
        leaves out common words such as "what" and "the": use it for questions in natural language. A word
        also matches longer words that start with it.

        A vault with a passphrase ranks its sealed entries with the scores a plaintext vault would give
        them. With SQLCipher it searches an index of entry terms kept inside the encrypted file. Without
        SQLCipher no entry terms are written to disk: it builds an index in memory by opening every entry,
        and builds it again after the vault changes.
        """
        terms, rows = self._ranked_rows(
            query, category, limit, scope, epistemic_state, as_of_valid_time, include_unverified, active_only,
            match, _ENTITY_COLUMNS, snippets=True,
        )
        bounded = _bounded(tenant_id, principal_id, authorized_lineage_roots)
        results: List[SearchResult] = []
        patterns = _snippet_patterns(terms) if any(snip is None for _, _, snip in rows) else None
        for r, score, snip in rows:
            if bounded and not _within_bounds(r, tenant_id, principal_id, authorized_lineage_roots):
                continue  # outside the caller's tenant, principal or lineage: never opened
            content = self._readable_content(r)
            if content is None:
                continue  # failed its integrity check: tampered, damaged, or moved from another entry
            if snip is None:
                snip = _snippet(content, patterns)
            results.append(SearchResult(entity=self._entity(r, content), rank_score=float(score), snippet=str(snip)))
        return results

    def search_keys(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
        scope: Optional[str] = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        include_unverified: bool = False,
        active_only: bool = True,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        authorized_lineage_roots: Optional[List[str]] = None,
        match: str = "all",
    ) -> List[SearchHit]:
        """Keys and scores of the entries :meth:`search` returns, best first, without opening any entry.

        Takes the arguments of :meth:`search` and applies its matching, filters, ranking and tenant,
        principal and lineage boundaries, but reads no entry content: nothing is decrypted and no snippet
        is built. Use it when the caller needs only which entries match, such as a retriever that holds
        the text elsewhere or fetches a few entries with :meth:`get`.

        Because it opens no entry, it checks no entry's integrity: an entry that fails its integrity check
        is left out of :meth:`search` but listed here, and :meth:`get` refuses it.
        """
        _, rows = self._ranked_rows(
            query, category, limit, scope, epistemic_state, as_of_valid_time, include_unverified, active_only,
            match, _HIT_COLUMNS, snippets=False,
        )
        bounded = _bounded(tenant_id, principal_id, authorized_lineage_roots)
        return [
            SearchHit(id=r["id"], category=r["category"], key=r["key"], scope=r["scope"], rank_score=float(score))
            for r, score, _ in rows
            if not bounded or _within_bounds(r, tenant_id, principal_id, authorized_lineage_roots)
        ]

    def _ranked_rows(
        self,
        query: str,
        category: Optional[str],
        limit: int,
        scope: Optional[str],
        epistemic_state: Optional[str],
        as_of_valid_time: Optional[float],
        include_unverified: bool,
        active_only: bool,
        match: str,
        columns: str,
        snippets: bool,
    ) -> Tuple[List[str], List[Tuple[Any, float, Optional[str]]]]:
        """Query words and ranked ``(row, score, snippet)`` rows for search, reading ``columns`` of each row."""
        if match not in ("all", "any"):
            raise ValueError("match must be 'all' or 'any'")
        terms = _search_terms(query, match)
        if not terms:
            return terms, []
        fts_query = (" OR " if match == "any" else " ").join('"' + t.replace('"', '""') + '"*' for t in terms)
        # Normalize scope: None or empty string defaults to "default"
        target_scope = "default" if scope is None or scope == "" else scope
        filter_sql, filter_params = self._search_filters(
            target_scope, category, epistemic_state, as_of_valid_time, include_unverified, active_only
        )
        if self._search_index:
            rows = self._indexed_rows(fts_query, filter_sql, filter_params, limit, columns)
        elif self.crypto_provider is not None and self.passphrase:
            rows = self._scanned_rows(fts_query, filter_sql, filter_params, limit, columns)
        else:
            rows = self._plaintext_rows(query, fts_query, filter_sql, filter_params, limit, columns, snippets)
        return terms, rows

    @staticmethod
    def _search_filters(
        target_scope: str,
        category: Optional[str],
        epistemic_state: Optional[str],
        as_of_valid_time: Optional[float],
        include_unverified: bool,
        active_only: bool,
    ) -> Tuple[str, List[Any]]:
        """SQL conditions on entities ``e`` for a search's scope, category, epistemic state and valid time.

        Search queries join with ``CROSS JOIN`` so that the full-text index drives the join: given a plain
        join, SQLite can start from the scope index on entities and run the full-text query once per row,
        which costs hundreds of times more."""
        clauses = ["e.archived = 0"]
        params: List[Any] = []
        if target_scope != "*":
            clauses.append("e.scope = ?")
            params.append(target_scope)
        if category:
            clauses.append("e.category = ?")
            params.append(category)
        if epistemic_state:
            clauses.append("e.epistemic_state = ?")
            params.append(epistemic_state)
        elif not include_unverified:
            # Epistemic polarity: unverified candidate/revoked memories withheld from active recall unless explicitly requested
            clauses.append("e.epistemic_state IN ('verified', 'disputed')")
        # Bi-temporal point-in-time filter: valid_from <= T and (valid_until IS NULL or valid_until > T)
        at = as_of_valid_time if as_of_valid_time is not None else (time.time() if active_only else None)
        if at is not None:
            clauses.append("(e.valid_from IS NULL OR e.valid_from <= ?)")
            clauses.append("(e.valid_until IS NULL OR e.valid_until > ?)")
            params.extend([at, at])
        return " AND ".join(clauses), params

    def _plaintext_rows(
        self,
        query: str,
        fts_query: str,
        filter_sql: str,
        params: List[Any],
        limit: int,
        columns: str = _ENTITY_COLUMNS,
        snippets: bool = True,
    ) -> List[Tuple[Any, float, Optional[str]]]:
        """Ranked rows from the FTS5 index of the entities table, for entries stored in plaintext."""
        snip_sql = "snippet(entities_fts, 2, '<b>', '</b>', '...', 16)" if snippets else "''"
        try:
            rows = self._conn.execute(
                f"""
                SELECT {columns},
                       rank AS score, {snip_sql} AS snip
                FROM entities_fts
                CROSS JOIN entities e ON e.id = entities_fts.rowid
                WHERE entities_fts MATCH ? AND {filter_sql}
                ORDER BY score, e.id
                LIMIT ?
                """,
                [fts_query, *params, limit],
            ).fetchall()
            return [(r, r["score"], r["snip"]) for r in rows]
        except _OPERATIONAL_ERRORS:
            # Fallback for environments where FTS query syntax or schema differs
            pattern = f"%{query}%"
            rows = self._conn.execute(
                f"SELECT {columns} FROM entities e WHERE (e.content LIKE ? OR e.key LIKE ?) AND {filter_sql} LIMIT ?",
                [pattern, pattern, *params, limit],
            ).fetchall()
            return [(r, 0.0, "") for r in rows]

    def _indexed_rows(
        self, fts_query: str, filter_sql: str, params: List[Any], limit: int, columns: str = _ENTITY_COLUMNS
    ) -> List[Tuple[Any, float, Optional[str]]]:
        """Ranked rows from the entry index of a SQLCipher vault."""
        try:
            self._drain_search_queue()
        except _OPERATIONAL_ERRORS as exc:  # another connection holds the write lock: search what is indexed
            logger.debug("kibisis: searching before queued entries were indexed: %s", exc)
        rows = self._conn.execute(
            f"""
            SELECT {columns}, entities_search.rank AS score
            FROM entities_search
            CROSS JOIN entities e ON e.id = entities_search.rowid
            WHERE entities_search MATCH ? AND {filter_sql}
            ORDER BY score, e.id
            LIMIT ?
            """,
            [fts_query, *params, limit],
        ).fetchall()
        return [(r, r["score"], None) for r in rows]

    def _scanned_rows(
        self, fts_query: str, filter_sql: str, params: List[Any], limit: int, columns: str = _ENTITY_COLUMNS
    ) -> List[Tuple[Any, float, Optional[str]]]:
        """Ranked rows from an in-memory index of the opened entries: a vault with a passphrase, without SQLCipher."""
        index = self._scan_index()
        ranked = index.execute(
            f"""
            SELECT e.id, m.rank FROM m CROSS JOIN e ON e.id = m.rowid
            WHERE m MATCH ? AND {filter_sql}
            ORDER BY m.rank, e.id
            LIMIT ?
            """,
            [fts_query, *params, limit],
        ).fetchall()
        if not ranked:
            return []
        marks = ", ".join("?" for _ in ranked)
        stored = {
            r["id"]: r
            for r in self._conn.execute(
                f"SELECT {columns} FROM entities e WHERE e.id IN ({marks})", [row[0] for row in ranked]
            ).fetchall()
        }
        return [(stored[i], score, None) for i, score in ranked if i in stored]

    def _scan_index(self) -> Any:
        """In-memory FTS5 index of every entry this vault can open, with the columns that search filters on.

        Built again once the vault has changed: ``PRAGMA data_version`` moves when another connection
        commits, and ``total_changes`` when this one writes."""
        stamp = (self._conn.execute("PRAGMA data_version").fetchone()[0], self._conn.total_changes)
        if self._scan_cache is not None and self._scan_cache[0] == stamp:
            return self._scan_cache[1]
        index = sqlite3.connect(":memory:", check_same_thread=False)
        index.execute("CREATE VIRTUAL TABLE m USING fts5(category, key, content, scope, content='')")
        index.execute(
            "CREATE TABLE e (id INTEGER PRIMARY KEY, category TEXT, scope TEXT, archived INTEGER, "
            "epistemic_state TEXT, valid_from REAL, valid_until REAL)"
        )
        rows = self._conn.execute(
            "SELECT id, category, key, content, scope, archived, epistemic_state, valid_from, valid_until, "
            "is_encrypted, encrypted_envelope_json, tenant_sig FROM entities ORDER BY id"
        ).fetchall()
        for r in rows:
            content = self._readable_content(r)
            if content is None:
                continue  # failed its integrity check: tampered, damaged, or moved from another entry
            index.execute(
                "INSERT INTO m (rowid, category, key, content, scope) VALUES (?, ?, ?, ?, ?)",
                (r["id"], r["category"], r["key"], content, r["scope"]),
            )
            index.execute(
                "INSERT INTO e VALUES (?, ?, ?, ?, ?, ?, ?)",
                (r["id"], r["category"], r["scope"], r["archived"], r["epistemic_state"], r["valid_from"], r["valid_until"]),
            )
        if self._scan_cache is not None:
            self._scan_cache[1].close()
        self._scan_cache = (stamp, index)
        return index

    def _ensure_search_index(self) -> None:
        """Keep an index of entry terms inside the SQLCipher file, so that search ranks sealed entries.

        The index (``entities_search``, a contentless FTS5 table) holds each entry's words and their
        positions, enough to rebuild its text without case or punctuation. SQLCipher's page encryption
        protects it with the rest of the file; each entry also stays sealed on its own. Triggers queue every row whose text changes, so rows that a process running an
        older kibisis writes without feeding the index are indexed before the next search. A vault without
        the index, or with an index of another version, gets one built by opening each entry once.
        """
        current = self._meta("search_index_format")
        if current is None or int(current) != SEARCH_INDEX_FORMAT:
            try:
                with self._write_tx() as cursor:
                    for trigger in ("entities_search_ai", "entities_search_au", "entities_search_ad"):
                        cursor.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                    cursor.execute("DROP TABLE IF EXISTS entities_search")
                    cursor.execute(
                        "CREATE VIRTUAL TABLE entities_search USING fts5("
                        "category, key, content, scope, content='', contentless_delete=1)"
                    )
                    cursor.execute("CREATE TABLE IF NOT EXISTS entities_search_dirty (id INTEGER PRIMARY KEY)")
                    cursor.execute(
                        "CREATE TRIGGER entities_search_ai AFTER INSERT ON entities BEGIN "
                        "INSERT OR IGNORE INTO entities_search_dirty (id) VALUES (new.id); END"
                    )
                    cursor.execute(
                        "CREATE TRIGGER entities_search_au AFTER UPDATE OF category, key, content, scope, "
                        "is_encrypted, encrypted_envelope_json, tenant_sig ON entities BEGIN "
                        "INSERT OR IGNORE INTO entities_search_dirty (id) VALUES (new.id); END"
                    )
                    cursor.execute(
                        "CREATE TRIGGER entities_search_ad AFTER DELETE ON entities BEGIN "
                        "DELETE FROM entities_search WHERE rowid = old.id; "
                        "DELETE FROM entities_search_dirty WHERE id = old.id; END"
                    )
                    cursor.execute("INSERT OR IGNORE INTO entities_search_dirty (id) SELECT id FROM entities")
                    self._set_meta(cursor, "search_index_format", SEARCH_INDEX_FORMAT)
            except _OPERATIONAL_ERRORS as exc:
                text = str(exc).lower()
                if not any(s in text for s in ("no such module", "unrecognized option", "contentless")):
                    raise
                # SQLite before 3.43 has no contentless-delete FTS5 tables: search opens the entries instead.
                logger.warning("kibisis: sealed entries are searched without an index: %s", exc)
                return
        self._search_index = True
        self._drain_search_queue()

    def _index_entry(self, cursor: Any, entity_id: int, category: str, key: str, content: str, scope: str) -> None:
        """Put an entry's terms in the entry index, in place of any it had there."""
        cursor.execute(
            "INSERT OR REPLACE INTO entities_search (rowid, category, key, content, scope) VALUES (?, ?, ?, ?, ?)",
            (entity_id, category, key, content, scope),
        )
        cursor.execute("DELETE FROM entities_search_dirty WHERE id = ?", (entity_id,))

    def _index_queued(self, cursor: Any) -> int:
        """Index the rows the triggers queued, within the caller's write transaction. Returns how many."""
        ids = [row[0] for row in cursor.execute("SELECT id FROM entities_search_dirty ORDER BY id").fetchall()]
        for entity_id in ids:
            r = cursor.execute(
                "SELECT id, category, key, content, scope, is_encrypted, encrypted_envelope_json, tenant_sig "
                "FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()
            content = None if r is None else self._readable_content(r)
            if content is None:  # deleted, or failed its integrity check: keep it out of the index
                cursor.execute("DELETE FROM entities_search WHERE rowid = ?", (entity_id,))
                cursor.execute("DELETE FROM entities_search_dirty WHERE id = ?", (entity_id,))
            else:
                self._index_entry(cursor, entity_id, r["category"], r["key"], content, r["scope"])
        return len(ids)

    def _drain_search_queue(self) -> None:
        """Index the rows written since the last search by a process that did not feed the index."""
        if not self._search_index:
            return
        if not self._conn.execute("SELECT EXISTS (SELECT 1 FROM entities_search_dirty)").fetchone()[0]:
            return
        with self._write_tx() as cursor:
            self._index_queued(cursor)

    def _rebuild_search_index(self) -> None:
        """Build the entry index again from the entries, so that no deleted or replaced terms stay in it."""
        with self._write_tx() as cursor:
            cursor.execute("INSERT INTO entities_search (entities_search) VALUES ('delete-all')")
            cursor.execute("INSERT OR IGNORE INTO entities_search_dirty (id) SELECT id FROM entities")
            self._index_queued(cursor)
            cursor.execute("INSERT INTO entities_search (entities_search) VALUES ('optimize')")

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

    @staticmethod
    def _find_tombstone(cursor: Any, scope: str, val_hash: str, can_hash: str) -> Optional[Any]:
        """Return the first tombstone in ``scope`` (or a ``'*'`` tombstone) that rejects this value.

        Category and key play no part: a tombstone stops a value, not a key, so a rejected value
        cannot come back under a new key or category. Scopes stay separate, so one tenant's
        rejection neither blocks nor reveals another tenant's writes.
        """
        cursor.execute(
            """
            SELECT category, key, reason, author_id FROM rejected_value_tombstones
            WHERE (scope = ? OR scope = '*')
              AND (value_sha256 = ? OR (canonical_sha256 != '' AND canonical_sha256 = ?))
            LIMIT 1
            """,
            (scope, val_hash, can_hash),
        )
        return cursor.fetchone()

    def _purge_value_copies(
        self,
        cursor: Any,
        scope: str,
        val_hash: str,
        can_hash: str,
        author_id: Optional[str],
        tombstoned: str,
    ) -> int:
        """Delete every stored copy of a tombstoned value in ``scope`` (every scope for ``'*'``).

        Copies under other categories or keys, live or archived, would otherwise keep a rejected
        value retrievable. Each deletion is journaled in the caller's transaction.
        """
        if scope == "*":
            cursor.execute("SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities")
        else:
            cursor.execute(
                "SELECT id, category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities WHERE scope = ?",
                (scope,),
            )
        purged = 0
        for row in cursor.fetchall():
            try:
                content = self._open_entry(row)
            except PermissionError:
                continue  # an entry that cannot be opened cannot be compared, and is never returned
            exact, canonical = self._digests(content)
            if exact != val_hash and not (can_hash and canonical == can_hash):
                continue
            cursor.execute("DELETE FROM entities WHERE id = ?", (row["id"],))
            self._record_audit_event(
                cursor=cursor,
                action="purge",
                category=row["category"],
                key=row["key"],
                scope=row["scope"],
                value_sha256=exact,
                author_id=author_id,
                metadata={"reason": "copy of tombstoned value", "tombstone": tombstoned},
            )
            purged += 1
        return purged

    def tombstone(
        self,
        category: str,
        key: str,
        reason: str = "revocation",
        author_id: Optional[str] = None,
        content: Optional[str] = None,
        scope: str = "default",
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> str:
        """Tombstone a value by its exact and canonical SHA-256 digests within ``scope``.

        Purges the entity at ``category:key`` and every other copy of the value in the scope
        (all scopes when ``scope`` is ``'*'``). Later writes of the value, or of a look-alike that
        canonicalizes to it, are refused under any category or key in the scope. Returns the value's
        SHA-256 hex digest; a vault with a passphrase stores it keyed (see :meth:`stored_digest`).
        """
        now = time.time()
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            if content is None:
                cursor.execute(
                    "SELECT category, key, scope, content, is_encrypted, encrypted_envelope_json, tenant_sig FROM entities "
                    "WHERE category = ? AND key = ? AND scope = ?",
                    (category, key, scope),
                )
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(f"Entity not found: {category}:{key} [scope={scope}]")
                content = self._open_entry(row)

            assert content is not None
            plain_exact, plain_canonical = value_digests(content)
            val_hash, can_hash = self._stored_digests(plain_exact, plain_canonical)

            cursor.execute(
                """
                INSERT OR REPLACE INTO rejected_value_tombstones (
                    category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                    sealed_digests
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    category, key, val_hash, can_hash, reason, author_id, now, scope,
                    self._seal_digests(scope, category, key, plain_exact, plain_canonical),
                ),
            )
            # Physical purge of the entity (the FTS index follows through triggers)
            cursor.execute("DELETE FROM entities WHERE category = ? AND key = ? AND scope = ?", (category, key, scope))

            # Record hash-chained mutation audit event
            self._record_audit_event(
                cursor=cursor,
                action="tombstone",
                category=category,
                key=key,
                scope=scope,
                value_sha256=val_hash,
                author_id=author_id,
                metadata={"reason": reason, "canonical_sha256": can_hash},
            )
            self._purge_value_copies(cursor, scope, val_hash, can_hash, author_id, f"{category}:{key}")
            return plain_exact

    def is_tombstoned(
        self,
        category: str,
        key: str,
        content: str,
        scope: str = "default",
    ) -> bool:
        """Check whether ``content`` is rejected in ``scope`` (exact or canonical digest).

        ``category`` and ``key`` are accepted for compatibility but do not narrow the check: a
        tombstoned value is rejected under every category and key in its scope.
        """
        val_hash, can_hash = self._digests(content)
        return self._find_tombstone(self._conn.cursor(), scope, val_hash, can_hash) is not None

    def list_tombstones(
        self,
        category: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tombstone records containing only digests, reason, author, scope, and timestamp (never plaintext)."""
        cursor = self._conn.cursor()
        query_sql = "SELECT id, category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope FROM rejected_value_tombstones WHERE 1=1"
        params: List[Any] = []
        if category:
            query_sql += " AND category = ?"
            params.append(category)
        if scope:
            query_sql += " AND (scope = ? OR scope = '*')"
            params.append(scope)
        query_sql += " ORDER BY id"
        cursor.execute(query_sql, params)
        return [dict(r) for r in cursor.fetchall()]

    def admit_candidate(
        self,
        category: str,
        key: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
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
    ) -> MemoryEntity:
        """Stage an unverified memory candidate into the vault awaiting verification/human review."""
        return self.put(
            category=category,
            key=key,
            content=content,
            metadata=metadata,
            epistemic_state=EpistemicState.CANDIDATE.value,
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
        )

    def remember(
        self,
        category: str,
        key: str,
        content: str,
        *,
        origin: str,
        source_ref: Optional[str] = None,
        confidence: Optional[float] = None,
        **kwargs: Any,
    ) -> MemoryEntity:
        """Store a fact with its provenance. ``origin`` is required and must be one of :data:`ORIGINS`.

        A ``model`` write is stored as ``candidate`` whatever ``epistemic_state`` says, and cannot
        replace an entry a person verified (:class:`ReviewedEntryError`). Other keyword arguments
        are those of :meth:`put`.
        """
        _validate_origin(origin)
        return self.put(
            category=category, key=key, content=content, origin=origin, source_ref=source_ref,
            confidence=confidence, **kwargs,
        )

    def admit(
        self,
        category: str,
        key: str,
        *,
        reviewer: str,
        reviewer_origin: str,
        note: Optional[str] = None,
        scope: str = "default",
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Promote an entry to ``verified``. Only a person (``reviewer_origin="user"``) may do so.

        A model or tool asking to verify raises :class:`AdmissionRefused`; the entry is left as it is.
        The human path is ``python -m kibisis admit --category C --key K --by user``.
        """
        _validate_origin(reviewer_origin, "reviewer_origin")
        if reviewer_origin != "user":
            entity = self.get(category=category, key=key, scope=scope)
            raise AdmissionRefused(
                f"'{category}:{key}' [scope={scope}] cannot be promoted to verified by a {reviewer_origin} reviewer "
                f"(entry origin={entity.origin if entity else 'missing'}). A person admits it with: "
                f"python -m kibisis admit --category {category} --key {key} --scope {scope} --by user"
            )
        return self.review_entity(
            category=category,
            key=key,
            verdict=EpistemicState.VERIFIED.value,
            scope=scope,
            reviewer_id=reviewer,
            notes=note,
            reviewer_origin=reviewer_origin,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
        )

    def review_entity(
        self,
        category: str,
        key: str,
        verdict: str,
        scope: str = "default",
        reviewer_id: Optional[str] = None,
        notes: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
        reviewer_origin: str = "user",
    ) -> MemoryEntity:
        """Human review gate: update epistemic state based on review decision (verified, disputed, revoked).

        This is the person's API; callers that relay a model's request use :meth:`admit`, which refuses
        anything but ``reviewer_origin="user"``. The verdict's origin is kept in ``human_reviews``.
        """
        valid_verdicts = {EpistemicState.VERIFIED.value, EpistemicState.DISPUTED.value, EpistemicState.REVOKED.value}
        if verdict not in valid_verdicts:
            raise ValueError(f"Verdict must be one of {valid_verdicts}, got '{verdict}'")
        _validate_origin(reviewer_origin, "reviewer_origin")

        # One write transaction from the read to the re-write: the entry a reviewer looked at is the
        # entry the verdict lands on, and a concurrent write cannot slip in between the two.
        with self._write_tx():
            return self._review_locked(
                category, key, verdict, scope, reviewer_id, notes, fencing_token, resource, holder_id, reviewer_origin
            )

    def _review_locked(
        self,
        category: str,
        key: str,
        verdict: str,
        scope: str,
        reviewer_id: Optional[str],
        notes: Optional[str],
        fencing_token: Optional[int],
        resource: Optional[str],
        holder_id: Optional[str],
        reviewer_origin: str,
    ) -> MemoryEntity:
        """Body of :meth:`review_entity`; runs inside the caller's write transaction."""
        entity = self.get(category=category, key=key, scope=scope)
        if entity is None:
            raise KeyError(f"Entity not found for review: {category}:{key} [scope={scope}]")

        meta = dict(entity.metadata)
        reviews = meta.get("human_reviews", [])
        reviews.append({
            "timestamp": time.time(),
            "reviewer_id": reviewer_id,
            "verdict": verdict,
            "notes": notes or "",
            "previous_state": entity.epistemic_state.value,
            "reviewer_origin": reviewer_origin,
        })
        meta["human_reviews"] = reviews

        if verdict == EpistemicState.REVOKED.value:
            # Revocation initiates tombstone recording and purges plaintext
            self.tombstone(
                category=category,
                key=key,
                reason=f"Human review rejected: {notes or 'revoked'}",
                author_id=reviewer_id,
                scope=scope,
                fencing_token=fencing_token,
                resource=resource,
                holder_id=holder_id,
            )
            if entity.epistemic_state != EpistemicState.REVOKED:
                with self._write_tx() as cursor:
                    self._record_state_transition(
                        cursor, category, key, scope, entity.epistemic_state.value,
                        EpistemicState.REVOKED.value, entity.origin, reviewer_id,
                    )
            entity.archived = True
            entity.epistemic_state = EpistemicState.REVOKED
            entity.metadata = meta
            return entity

        # Update entity with new epistemic status and review metadata. Approving an entry that proposed
        # to supersede a reviewed entry applies the supersession now, under the reviewer's authority.
        proposal = meta.pop("proposed_supersedes", None) if verdict == EpistemicState.VERIFIED.value else None
        if proposal:
            meta["supersession_approved_by"] = reviewer_id
        return self.put(
            category=category,
            key=key,
            content=entity.content,
            metadata=meta,
            epistemic_state=verdict,
            valid_from=entity.valid_from,
            valid_until=entity.valid_until,
            scope=scope,
            author_id=reviewer_id,
            fencing_token=fencing_token,
            resource=resource,
            holder_id=holder_id,
            supersedes_key=proposal["key"] if proposal else None,
            supersedes_category=proposal["category"] if proposal else None,
            _trusted_metadata=True,  # human_reviews was appended here, inside the write transaction
        )

    def scrub(self) -> None:
        """Remove deleted or replaced content from the search indexes, the write-ahead log and free pages.

        FTS5 'delete' leaves old terms in index segments until the index is rebuilt (a SQLCipher
        vault's entry index is rebuilt from its decrypted entries), and the write-ahead log and free
        pages keep old bytes until a checkpoint and VACUUM. Run after a delete (the MCP server's
        forget does) or after migrating plaintext.
        """
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('rebuild')")
        self._conn.execute("INSERT INTO entities_fts(entities_fts) VALUES ('optimize')")
        self._conn.commit()
        if self._search_index:
            self._rebuild_search_index()
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._restrict_permissions()

    def list_audit_events(
        self,
        scope: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
        key: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Fetch chronological audit records from the tamper-evident hash chain."""
        cursor = self._conn.cursor()
        query_sql = (
            "SELECT sequence, timestamp, action, category, key, scope, value_sha256, "
            "prev_hash, event_hash, author_id, metadata_json, format FROM audit_journal WHERE 1=1"
        )
        params: List[Any] = []
        if scope:
            query_sql += " AND scope = ?"
            params.append(scope)
        if category:
            query_sql += " AND category = ?"
            params.append(category)
        if key:
            query_sql += " AND key = ?"
            params.append(key)
        query_sql += " ORDER BY sequence ASC LIMIT ?"
        params.append(limit)
        cursor.execute(query_sql, params)

        events: List[AuditEvent] = []
        for r in cursor.fetchall():
            events.append(
                AuditEvent(
                    sequence=r["sequence"],
                    timestamp=r["timestamp"],
                    action=r["action"],
                    category=r["category"],
                    key=r["key"],
                    scope=r["scope"],
                    value_sha256=r["value_sha256"],
                    prev_hash=r["prev_hash"],
                    event_hash=r["event_hash"],
                    author_id=r["author_id"],
                    metadata=json.loads(r["metadata_json"]),
                    format=r["format"],
                )
            )
        return events

    def verify_audit_chain(self, scope: Optional[str] = None) -> bool:
        """Verify the append-only mutation journal: every link, every row's hash, and the signed head.

        Each row is recomputed under the layout it was written with (``format``), so journals from
        older versions verify. Once the vault has written a format 3 row, ``audit_head`` must exist,
        carry a valid MAC and name the last row: deleting rows from the tail, or the head itself,
        then fails verification. A journal with only legacy rows and no head verifies on its links
        alone, as it did before the head existed.
        """
        # Always verify the entire hash chain (or records up to limit), because prev_hash links consecutive global events
        events = self.list_audit_events(scope=None, limit=1_000_000)

        expected_prev = "0" * 64
        for ev in events:
            if ev.prev_hash != expected_prev:
                return False
            recomputed = _event_hash(
                ev.sequence, ev.timestamp, ev.action, ev.category, ev.key, ev.scope, ev.value_sha256, ev.prev_hash,
                ev.author_id, ev.metadata, fmt=ev.format,
            )
            if not hmac.compare_digest(recomputed, ev.event_hash):
                return False
            expected_prev = ev.event_hash

        head = self._conn.execute("SELECT sequence, event_hash, mac FROM audit_head WHERE id = 1").fetchone()
        anchored = any(ev.format >= 3 for ev in events)
        if head is None:
            return not anchored
        if not hmac.compare_digest(_head_mac(self._signing_key, head["sequence"], head["event_hash"]), head["mac"]):
            return False
        if not events:
            return False  # a signed head with no rows: the whole journal was removed
        return head["sequence"] == events[-1].sequence and head["event_hash"] == events[-1].event_hash

    def set_persona_slot(
        self,
        content: str,
        scope: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
        author_id: Optional[str] = None,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> MemoryEntity:
        """Store or update the dedicated user persona / preference slot."""
        meta = metadata.copy() if metadata else {}
        meta["is_persona_slot"] = True
        return self.put(
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
        )

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

    def export_snapshot(
        self,
        path: Optional[Union[str, Path]] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Export a deterministic, portable snapshot of entities, tombstones, and audit events.

        Computes a SHA-256 integrity manifest over the exported payload.
        If path is provided, writes the serialized JSON atomically to disk.
        """
        cursor = self._conn.cursor()

        if scope and scope != "*":
            cursor.execute(
                """
                SELECT category, key, content, metadata_json, version, archived,
                       created_at, updated_at, is_encrypted, encrypted_envelope_json,
                       scope, epistemic_state, valid_from, valid_until, tenant_sig
                FROM entities
                WHERE scope = ?
                ORDER BY scope, category, key
                """,
                (scope,),
            )
        else:
            cursor.execute(
                """
                SELECT category, key, content, metadata_json, version, archived,
                       created_at, updated_at, is_encrypted, encrypted_envelope_json,
                       scope, epistemic_state, valid_from, valid_until, tenant_sig
                FROM entities
                ORDER BY scope, category, key
                """
            )

        raw_entities = cursor.fetchall()
        entities_data = []
        unreadable = 0
        for r in raw_entities:
            try:
                content = self._open_entry(r)
            except EntryIntegrityError:
                unreadable += 1  # failed its integrity check; never exported
                continue
            entities_data.append({
                "category": r["category"],
                "key": r["key"],
                "content": content,
                "metadata": json.loads(r["metadata_json"]),
                "version": r["version"],
                "archived": bool(r["archived"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "scope": r["scope"],
                "epistemic_state": r["epistemic_state"],
                "valid_from": r["valid_from"],
                "valid_until": r["valid_until"],
            })

        cursor.execute(
            """
            SELECT category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                   sealed_digests
            FROM rejected_value_tombstones
            ORDER BY category, key, scope
            """
        )
        tombstones_data = [
            {
                "category": r["category"],
                "key": r["key"],
                "value_sha256": r["value_sha256"],
                "canonical_sha256": r["canonical_sha256"],
                "reason": r["reason"],
                "author_id": r["author_id"],
                "created_at": r["created_at"],
                "scope": r["scope"],
                "sealed_digests": r["sealed_digests"],
            }
            for r in cursor.fetchall()
        ]

        audit_events = self.list_audit_events(limit=1_000_000)
        events_data = [ev.model_dump() for ev in audit_events]

        snapshot: Dict[str, Any] = {
            "format_version": "1.1",
            "exported_at": time.time(),
            "scope": scope or "*",
            # Tombstone and journal digests: plain SHA-256 in a vault without a passphrase, otherwise keyed
            # to this vault (digest_key_id). A tombstone's sealed_digests let a vault with the same
            # passphrase re-key it on import.
            "digest_scheme": "hmac-sha256" if self._digest_key is not None else "sha256",
            "digest_key_id": self._digest_key_id(),
            "unreadable_entity_count": unreadable,
            "entity_count": len(entities_data),
            "tombstone_count": len(tombstones_data),
            "audit_event_count": len(events_data),
            "entities": entities_data,
            "tombstones": tombstones_data,
            "audit_events": events_data,
        }

        canonical_bytes = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        snapshot["manifest_sha256"] = manifest_sha256

        if path is not None:
            out_p = Path(path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            tmp_p = out_p.with_suffix(f".tmp.{os.getpid()}")
            # The snapshot holds decrypted content. A plain open() inherited the umask (0644 on most
            # hosts) and undid the vault's at-rest protection; create the file owner-only, refuse a
            # pre-existing path, flush to disk, then rename so a reader sees all or nothing.
            fd = os.open(tmp_p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_p, out_p)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_p)
                raise

        return snapshot

    def import_snapshot(
        self,
        snapshot_or_path: Union[str, Path, Dict[str, Any]],
        *,
        clear_existing: bool = False,
        fencing_token: Optional[int] = None,
        resource: Optional[str] = None,
        holder_id: Optional[str] = None,
    ) -> int:
        """Import a snapshot into the vault.

        Validates manifest hash integrity. Tombstones are imported first and existing tombstones
        are never removed, so restoring a snapshot taken before a deletion cannot bring the
        deleted value back: entities whose value is tombstoned in their scope are refused and not
        counted. ``clear_existing`` purges current entities (journaled) but keeps tombstones and
        the audit journal. Archived entities are restored archived.

        Returns the number of restored entities.
        """
        if isinstance(snapshot_or_path, (str, Path)):
            with open(snapshot_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif isinstance(snapshot_or_path, dict):
            data = snapshot_or_path
        else:
            raise TypeError("Expected snapshot dict or path")

        manifest_sha = data.get("manifest_sha256")
        if manifest_sha:
            check_data = {k: v for k, v in data.items() if k != "manifest_sha256"}
            canonical_bytes = json.dumps(check_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            recomputed = hashlib.sha256(canonical_bytes).hexdigest()
            if recomputed != manifest_sha:
                raise ValueError(f"Snapshot integrity violation: manifest mismatch {recomputed} != {manifest_sha}")

        imported_count = 0
        foreign_tombstones = 0
        scheme = data.get("digest_scheme", "sha256")
        same_key = (
            scheme == "hmac-sha256" and self._digest_key is not None and data.get("digest_key_id") == self._digest_key_id()
        )
        with self._write_tx() as cursor:
            self._fence(cursor, fencing_token, resource, holder_id)
            for ts in data.get("tombstones", []):
                t_scope, t_category, t_key = ts.get("scope", "default"), ts["category"], ts["key"]
                exact, canonical = ts["value_sha256"], ts.get("canonical_sha256", "")
                sealed = ts.get("sealed_digests")
                if not same_key:
                    plain: Optional[Tuple[str, str]] = None
                    if scheme == "sha256":
                        plain = (exact, canonical)
                    elif sealed and self._keyed:
                        plain = self._unseal_digests(t_scope, t_category, t_key, sealed)
                    if plain is None:
                        foreign_tombstones += 1  # from a vault with another passphrase: it cannot match here
                        continue
                    exact, canonical = self._stored_digests(*plain)
                    sealed = self._seal_digests(t_scope, t_category, t_key, *plain)
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO rejected_value_tombstones (
                        category, key, value_sha256, canonical_sha256, reason, author_id, created_at, scope,
                        sealed_digests
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        t_category,
                        t_key,
                        exact,
                        canonical,
                        ts.get("reason", "imported"),
                        ts.get("author_id"),
                        ts.get("created_at", time.time()),
                        t_scope,
                        sealed,
                    ),
                )
            if clear_existing:
                cursor.execute("SELECT category, key, scope FROM entities")
                for row in cursor.fetchall():
                    self._record_audit_event(
                        cursor=cursor,
                        action="purge",
                        category=row["category"],
                        key=row["key"],
                        scope=row["scope"],
                        value_sha256="",
                        metadata={"reason": "import_snapshot clear_existing"},
                    )
                cursor.execute("DELETE FROM entities")
                # entities_fts is an external-content index kept in step by triggers; rebuild it
                # from the (now empty) content table rather than deleting index rows directly.
                cursor.execute("INSERT INTO entities_fts(entities_fts) VALUES('rebuild')")

        if foreign_tombstones:
            logger.warning(
                "import_snapshot: %d tombstones come from a vault with another passphrase and cannot apply here",
                foreign_tombstones,
            )
            self.record_refusal(
                path="import_snapshot",
                reason="tombstones from a vault with another passphrase",
                scope="*",
                detail={"tombstones": foreign_tombstones},
            )

        for ent_data in data.get("entities", []):
            scope = ent_data.get("scope", "default")
            val_hash, can_hash = self._digests(ent_data["content"])
            if self._find_tombstone(self._conn.cursor(), scope, val_hash, can_hash) is not None:
                self.record_refusal(
                    path="import_snapshot",
                    reason="tombstoned value",
                    scope=scope,
                    category=ent_data.get("category", ""),
                    key=ent_data.get("key", ""),
                    detail={"value_digest_prefix": val_hash[:12]},
                )
                continue
            self.put(
                category=ent_data["category"],
                key=ent_data["key"],
                content=ent_data["content"],
                metadata=ent_data.get("metadata"),
                epistemic_state=ent_data.get("epistemic_state", "verified"),
                valid_from=ent_data.get("valid_from"),
                valid_until=ent_data.get("valid_until"),
                scope=scope,
                fencing_token=fencing_token,
                resource=resource,
                holder_id=holder_id,
                # A restore keeps the exported review history and tenant bounds. The snapshot's
                # epistemic_state is already trusted here, so this grants nothing it did not have.
                _trusted_metadata=True,
            )
            if ent_data.get("archived"):
                self.archive(
                    category=ent_data["category"],
                    key=ent_data["key"],
                    scope=scope,
                    fencing_token=fencing_token,
                    resource=resource,
                    holder_id=holder_id,
                )
            imported_count += 1

        return imported_count

    def evaluate_epistemic_abstention(
        self,
        negative_probes: List[str],
        scope: str = "default",
    ) -> Dict[str, Any]:
        """Evaluate vault abstention on negative out-of-scope probes.

        Ensures the vault does not return fabricated or false positive recall results
        when probed with out-of-scope or non-existent topics.
        """
        total = len(negative_probes)
        abstained = 0
        false_positives = []

        for probe in negative_probes:
            res = self.search(probe, scope=scope)
            if len(res) == 0:
                abstained += 1
            else:
                false_positives.append({
                    "probe": probe,
                    "matched_keys": [r.entity.key for r in res],
                })

        abstention_rate = (abstained / total) if total > 0 else 1.0
        return {
            "total_probes": total,
            "abstained_count": abstained,
            "false_positive_count": len(false_positives),
            "abstention_rate": abstention_rate,
            "false_positives": false_positives,
            "perfect_abstention": (abstained == total),
        }

    def close(self) -> None:
        if self._scan_cache is not None:
            self._scan_cache[1].close()
            self._scan_cache = None
        self._conn.close()
