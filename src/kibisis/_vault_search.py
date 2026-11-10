"""Search and recall in :class:`kibisis.vault.SQLiteMemoryVault`: ranked search over the plaintext FTS5 index, the
entry index a SQLCipher vault keeps, the keyed term index a passphrase vault keeps without SQLCipher, and the
scan of opened entries; the recall gate and its receipts; the query, bounds and snippet helpers.

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and keys. Every name here is
also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import sqlite3
import time
try:
    import sqlcipher3
except ImportError:
    import sqlite3 as sqlcipher3
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ._vault_audit import _argus_append
from ._vault_crypto import EntryIntegrityError
from ._vault_review import origin_class_of
from .models import EpistemicState, MemoryEntity, RecallResult, SearchHit, SearchResult, WithheldEntry
from .protocols import EncryptionRequiredError

# The vault's logger: records keep the name callers filter on.
logger = logging.getLogger("kibisis.vault")


#: Version of the entry index (``entities_search``) that a SQLCipher vault keeps for ranked search. A vault
#: whose index has another version, or none, gets one built from its entries when opened with its passphrase.
SEARCH_INDEX_FORMAT = 1


#: Version of the keyed term index (``entities_terms``) that a vault with a passphrase keeps when its file is
#: not SQLCipher-encrypted. A vault whose term index has another version, or none, gets one built from its
#: entries when opened. Bump it when the token derivation or the table layout changes.
TERM_INDEX_FORMAT = 1


# sqlcipher3 raises its own OperationalError, which is not sqlite3's.
_OPERATIONAL_ERRORS = (sqlite3.OperationalError, sqlcipher3.OperationalError)


_ENTITY_COLUMNS = (
    "e.id, e.category, e.key, e.content, e.metadata_json, e.version, e.archived, e.created_at, e.updated_at, "
    "e.is_encrypted, e.encrypted_envelope_json, e.scope, e.epistemic_state, e.valid_from, e.valid_until, "
    "e.tenant_sig, e.supersedes, e.superseded_by, e.origin, e.source_ref, e.confidence"
)


#: K-R4 recall gate defaults: a hit must contain at least this share of the query's words (basis points)
#: and, with four or more matches, sit at or below this BM25 z-score (basis points; lower BM25 is better).
DEFAULT_MIN_COVERAGE_BP = 5000


DEFAULT_Z_MAX_BP = -5000


#: ``recall(prefer_recent=True)``: a hit that passed the gate has its score multiplied by
#: ``1 + boost * 2 ** (-age / half_life)``. The boost is in basis points (5000: an entry written now
#: scores half again as well), the half-life in days.
DEFAULT_RECENCY_BOOST_BP = 5000


DEFAULT_RECENCY_HALF_LIFE_DAYS = 30


#: How many returned refs one ``kibisis.memory_recall`` ledger event names.
ARGUS_RETURNED_REFS = 40


# What the recall gate reads of every match: nothing sealed, so no entry is opened to gate it.
_GATE_COLUMNS = (
    "e.id, e.category, e.key, e.scope, e.metadata_json, e.epistemic_state, e.updated_at, e.created_at, e.origin"
)


# ``limit`` of a ranked query that wants every match (SQLite reads a negative LIMIT as none).
_EVERY_MATCH = -1


# Ids per ``IN (...)`` list, under SQLite's limit on bound values.
_ID_CHUNK = 500


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


def _fts_query(terms: Sequence[str], match: str) -> str:
    """The FTS5 query for search terms: each a quoted prefix phrase, any of them or all of them."""
    return (" OR " if match == "any" else " ").join('"' + t.replace('"', '""') + '"*' for t in terms)


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


class SearchRecallMixin:
    """Ranked search, keys-only search, recall with its gate and receipts, and the search and term indexes."""

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
        also matches longer words that start with it, except in a vault with a passphrase whose file is not
        SQLCipher-encrypted, which matches whole words only (below).

        A vault with a passphrase ranks its sealed entries with the scores a plaintext vault would give
        them. With SQLCipher it searches an index of entry terms kept inside the encrypted file. Without
        SQLCipher no entry word is written to disk: it keeps an index of keyed tokens of the words, looks
        the query's words up there and opens only the entries it returns (``term_index=False`` at open
        searches by opening every entry instead, at a cost that grows with the vault).
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

    def recall(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
        scope: Optional[str] = "default",
        epistemic_state: Optional[str] = None,
        as_of_valid_time: Optional[float] = None,
        active_only: bool = True,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        authorized_lineage_roots: Optional[List[str]] = None,
        match: str = "all",
        channel: str = "library",
        min_coverage_bp: int = DEFAULT_MIN_COVERAGE_BP,
        z_max_bp: int = DEFAULT_Z_MAX_BP,
        ttl_seconds: Optional[Dict[str, float]] = None,
        actor: Optional[str] = None,
        prefer_recent: bool = False,
        recency_boost_bp: int = DEFAULT_RECENCY_BOOST_BP,
        recency_half_life_days: float = DEFAULT_RECENCY_HALF_LIFE_DAYS,
        withheld_digest_chars: int = 0,
    ) -> RecallResult:
        """Model-facing recall: :meth:`search` plus what was withheld and why, with a receipt (K-R3..K-R5).

        K-R3: two verified entries that conflict (``conflicts_with`` edge, or the same ``slot`` with
        different content) are both withheld as ``conflict_unresolved`` with each other's ids.

        K-R4: a hit is returned only if the share of query words it matched is at least
        ``min_coverage_bp`` (basis points) and, with four or more matches to compare against, its BM25
        z-score among the matched set is at most ``z_max_bp``. Both tests are taken over every match and
        read the index that found it: a query word is covered wherever the index matched it (category,
        key, content or scope, with the index's folding of case and accents), and ``n_matched``, the mean
        and the deviation are those of the whole matched set, so a hit's verdict does not change with
        ``limit``. ``ttl_seconds`` maps an origin class to a maximum age since ``last_verified_at`` (else
        ``updated_at``); older entries are withheld as ``stale``.

        ``prefer_recent`` re-orders the hits that passed the gate and changes nothing about which pass: a
        hit's score is multiplied by ``1 + (recency_boost_bp / 10000) * 2 ** (-age / recency_half_life_days)``,
        with the age taken from ``updated_at``, and that product is the ``rank_score`` it is returned with.
        Use it for "what is the latest state" questions; leave it off for "what is the rule".

        The receipt carries ``n_store``, ``n_matched`` and the counts withheld by reason, all over the
        whole matched set. Its ``hits`` and the ``withheld`` list name the best ``max(limit * 8, 64)``
        matches in BM25 order, plus any other entry that was returned or withheld for a conflict: each
        with its coverage, z-score, ``rank`` (position in BM25 order) and ``updated_at``, so a caller can
        pick a withheld key to read. Withheld rows carry no content. With ``withheld_digest_chars`` above
        zero, a row below the gate (never one withheld for a conflict) also carries that many leading
        characters of its content, on one line.

        Entries are gated on what the vault keeps unsealed (scores, keys, metadata, times). An entry is
        opened, and so checked for integrity, when it is returned, compared for a slot conflict or
        digested; a hit that fails the check is left out, as :meth:`search` leaves it out.

        K-R5: recall writes nothing to the vault or its journal: a read never writes. Each call is kept
        in an in-process log (:meth:`recent_recalls`) and, when ``ARGUS_LEDGER_PATH`` is set, mirrored to
        Argus as ``kibisis.memory_recall``: the counts, the refs returned (``returned``: one string,
        comma-separated, at most 40 refs) and the withheld refs the receipt names. The query appears only
        as a digest.
        """
        if scope == "*":
            raise ValueError("recall is bound to one scope; '*' is not available here")
        if recency_half_life_days <= 0 or recency_boost_bp < 0:
            raise ValueError("recency_half_life_days must be above zero and recency_boost_bp must not be negative")
        digest_chars = max(0, int(withheld_digest_chars))
        # Every match is ranked and gated, on columns that are not sealed: the verdict for a hit must not
        # depend on how many the caller asked for. Entries are opened further down, a few of them.
        fts_terms, ranked = self._ranked_rows(
            query, category, _EVERY_MATCH, scope, epistemic_state, as_of_valid_time, True, active_only, match,
            _GATE_COLUMNS, snippets=False,
        )
        if _bounded(tenant_id, principal_id, authorized_lineage_roots):
            # Outside the caller's tenant, principal or lineage: not a match, and never opened.
            ranked = [x for x in ranked if _within_bounds(x[0], tenant_id, principal_id, authorized_lineage_roots)]
        rows = [x[0] for x in ranked]
        scores = [float(x[1]) for x in ranked]
        n = len(rows)
        refs = [f"{r['category']}:{r['key']}" for r in rows]
        terms = [t.lower() for t in _search_terms(query, "any")]
        cursor = self._conn.cursor()
        if scope is None:
            cursor.execute("SELECT COUNT(*) FROM entities WHERE archived = 0 AND epistemic_state != 'revoked'")
        else:
            cursor.execute(
                "SELECT COUNT(*) FROM entities WHERE archived = 0 AND epistemic_state != 'revoked' AND scope = ?", (scope,)
            )
        n_store = int(cursor.fetchone()[0])
        now = time.time()

        mean = sum(scores) / n if n else 0.0
        var = sum((x - mean) ** 2 for x in scores) / n if n else 0.0
        std = var ** 0.5
        # With four or more matches the z-score is meaningful. A crowd of tied scores carries no
        # evidence that any one of them answers the query: every z is 0 and the default gate drops them.
        use_z = n >= 4
        # Per query word, the ids the index matches it in (None: every match holds it).
        term_ids = self._coverage_sets(terms, match, scope) if n else []

        metas: Dict[int, Dict[str, Any]] = {}

        def _meta(i: int) -> Dict[str, Any]:
            found = metas.get(i)
            if found is None:
                raw = rows[i]["metadata_json"]
                found = metas[i] = (json.loads(raw) if raw else {}) or {}
            return found

        # Opened entries: position -> (whole row, content, snippet), or None when the entry cannot be read.
        opened: Dict[int, Optional[Tuple[Any, str, Optional[str]]]] = {}

        def _open(positions: Sequence[int]) -> None:
            need = [i for i in positions if i not in opened]
            if not need:
                return
            full = self._full_rows([rows[i]["id"] for i in need], _fts_query(fts_terms, match))
            for i in need:
                got = full.get(rows[i]["id"])
                content = self._readable_content(got[0]) if got is not None else None
                # None: gone since it was ranked, or failed its integrity check (tampered, damaged, moved).
                opened[i] = None if got is None or content is None else (got[0], content, got[1])

        # K-R3: conflicts among the verified entries in the matched set and their declared partners.
        position = {ref: i for i, ref in enumerate(refs)}
        conflict_sources: Dict[str, List[str]] = {}
        verified = [i for i, r in enumerate(rows) if r["epistemic_state"] == EpistemicState.VERIFIED.value]
        for i in verified:
            for other_ref in _meta(i).get("conflicts_with") or []:
                j = position.get(other_ref)
                if j is None:
                    c, k = other_ref.split(":", 1)
                    other = self.get(c, k, scope=scope or "default") if scope is not None else None
                    live = other is not None and other.epistemic_state == EpistemicState.VERIFIED and not other.archived
                else:
                    live = rows[j]["epistemic_state"] == EpistemicState.VERIFIED.value
                if not live:
                    continue
                conflict_sources.setdefault(refs[i], []).append(other_ref)
                conflict_sources.setdefault(other_ref, []).append(refs[i])
        slots: Dict[Tuple[str, str], List[int]] = {}
        for i in verified:
            slot = _meta(i).get("slot")
            if slot:
                slots.setdefault((rows[i]["category"], str(slot)), []).append(i)
        groups = [group for group in slots.values() if len(group) > 1]
        if groups:
            _open([i for group in groups for i in group])  # a slot conflict is a difference in content
            for group in groups:
                readable = [i for i in group if opened[i] is not None]
                if len({opened[i][1] for i in readable}) > 1:  # type: ignore[index]
                    for i in readable:
                        mine = conflict_sources.setdefault(refs[i], [])
                        mine.extend(refs[o] for o in readable if o != i and refs[o] not in mine)

        # K-R4, for every match, in BM25 order.
        coverage: List[int] = []
        z_bps: List[Optional[int]] = []
        reasons: List[str] = []  # "" for a hit that passed
        passed: List[int] = []
        conflicting: List[int] = []
        n_conflict = n_gate = n_stale = 0
        for i, r in enumerate(rows):
            if terms:
                entity_id = r["id"]
                covered = sum(1 for ids in term_ids if ids is None or entity_id in ids)
                coverage_bp = int(round(10000 * covered / len(terms)))
            else:
                coverage_bp = 10000
            z_bp: Optional[int] = (int(round(10000 * (scores[i] - mean) / std)) if std > 1e-9 else 0) if use_z else None
            reason = ""
            if refs[i] in conflict_sources:
                reason = "conflict_unresolved"
                n_conflict += 1
                conflicting.append(i)
            elif coverage_bp < min_coverage_bp or (z_bp is not None and z_bp > z_max_bp):
                reason = "below_gate"
                n_gate += 1
            elif ttl_seconds:
                klass = _meta(i).get("origin_class") or origin_class_of(r["origin"] or "unknown")
                ttl = ttl_seconds.get(klass)
                if ttl is not None:
                    last = _meta(i).get("last_verified_at") or r["updated_at"] or r["created_at"]
                    if last is not None and now - float(last) > float(ttl):
                        reason = "stale"
                        n_stale += 1
            coverage.append(coverage_bp)
            z_bps.append(z_bp)
            reasons.append(reason)
            if not reason:
                passed.append(i)

        # Order of the hits that passed: BM25, or BM25 times a recency factor. Never who passed.
        boost: Dict[int, float] = {}
        order = passed
        if prefer_recent:
            for i in passed:
                at = rows[i]["updated_at"] or rows[i]["created_at"]
                age_days = max(0.0, (now - float(at)) / 86400.0) if at is not None else None
                boost[i] = 1.0 if age_days is None else (
                    1.0 + (recency_boost_bp / 10000.0) * 2.0 ** (-age_days / float(recency_half_life_days))
                )
            order = sorted(passed, key=lambda i: scores[i] * boost[i])  # stable: ties keep BM25 order

        results: List[SearchResult] = []
        returned: List[int] = []
        left_out: set = set()  # passed the gate, could not be read
        patterns: Optional[Tuple[Any, Any]] = None
        taken = 0
        while len(results) < limit and taken < len(order):
            batch = order[taken:taken + (limit - len(results))]
            taken += len(batch)
            _open(batch)
            for i in batch:
                got = opened[i]
                if got is None:
                    left_out.add(i)
                    continue
                row, content, snip = got
                if snip is None:
                    patterns = patterns or _snippet_patterns(fts_terms)
                    snip = _snippet(content, patterns)
                results.append(SearchResult(
                    entity=self._entity(row, content), rank_score=scores[i] * boost.get(i, 1.0), snippet=str(snip)
                ))
                returned.append(i)

        # What the receipt names: the best of the matched set, whatever was returned, every conflict.
        window = min(n, max(limit * 8, 64))
        listed = sorted((set(range(window)) | set(returned) | set(conflicting)) - left_out)
        if digest_chars:
            _open([i for i in listed if reasons[i] == "below_gate"])
        withheld: List[WithheldEntry] = []
        hit_receipts: List[Dict[str, Any]] = []
        for i in listed:
            ref, reason = refs[i], reasons[i]
            hit: Dict[str, Any] = {
                "ref": ref, "coverage_bp": coverage[i], "z_bp": z_bps[i], "kept": not reason, "reason": reason,
                "contrasts_with": list(_meta(i).get("contrasts_with") or []),
                "rank": i + 1, "updated_at": rows[i]["updated_at"],
            }
            if i in boost:
                hit["recency_bp"] = int(round(10000 * boost[i]))
            if reason == "conflict_unresolved":
                withheld.append(WithheldEntry(ref=ref, reason=reason, sources=sorted(set(conflict_sources[ref]))))
            elif reason == "below_gate":
                digest: Optional[str] = None
                if digest_chars and opened.get(i) is not None:
                    digest = " ".join(opened[i][1].split())[:digest_chars]  # type: ignore[index]
                    hit["digest"] = digest
                withheld.append(WithheldEntry(
                    ref=ref, reason=reason, coverage_bp=coverage[i], rank=i + 1, updated_at=rows[i]["updated_at"],
                    digest=digest,
                ))
            elif reason:
                withheld.append(WithheldEntry(ref=ref, reason=reason))
            hit_receipts.append(hit)
        if conflict_sources:
            # A partner that did not match the query is withheld too: both sides of the pair stay out.
            seen = {w.ref for w in withheld}
            for ref, sources in conflict_sources.items():
                if ref not in seen and ref not in position:
                    withheld.append(WithheldEntry(ref=ref, reason="conflict_unresolved", sources=sorted(set(sources))))
                    n_conflict += 1

        n_matched = n - len(left_out)
        receipt: Dict[str, Any] = {
            "channel": channel,
            "scope": scope or "*",
            "n_store": n_store,
            "n_matched": n_matched,
            "n_returned": len(results),
            "n_withheld_conflict": n_conflict,
            "n_withheld_gate": n_gate,
            "n_withheld_stale": n_stale,
            "gate": {"min_coverage_bp": int(min_coverage_bp), "z_max_bp": int(z_max_bp)},
            "recency": {
                "prefer_recent": bool(prefer_recent), "boost_bp": int(recency_boost_bp),
                "half_life_days": recency_half_life_days,
            },
            "hits": hit_receipts,
        }
        query_digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:12]
        journal_meta = {
            "channel": channel, "query_sha256_12": query_digest, "n_store": n_store, "n_matched": n_matched,
            "n_returned": len(results), "n_withheld_conflict": n_conflict, "n_withheld_gate": n_gate,
            "n_withheld_stale": n_stale,
            # Which entries were read, for access statistics: integers and strings only in the ledger.
            "returned": ",".join(refs[i] for i in returned[:ARGUS_RETURNED_REFS]),
            "withheld": [w.ref for w in withheld],
        }
        # A read never writes: it takes no lock a writer holds and does not move the audit head that
        # write-invalidated caches follow. The record goes to Argus and to an in-process log.
        record = {**journal_meta, "scope": scope or "*", "actor": actor or "", "at": int(now)}
        self._recent_recalls.append(record)
        _argus_append("kibisis.memory_recall", actor or "kibisis", {**journal_meta, "scope": scope or "*"})
        return RecallResult(results=results, withheld=withheld, receipt=receipt)

    def recent_recalls(self, limit: int = 100) -> List[Dict[str, Any]]:
        """The newest recall records this process made (K-R5), newest last: the counts, the refs returned
        and the withheld refs named. When ``ARGUS_LEDGER_PATH`` is set the Argus ledger is the durable copy;
        the vault's own journal holds none."""
        items = list(self._recent_recalls)
        return items[-limit:] if limit else items

    def _search_mode(self) -> str:
        """Which index ranked search reads: ``index`` (the entry index of a SQLCipher vault), ``terms`` (the
        keyed term index), ``scan`` (an in-memory index of the opened entries) or ``plain`` (plaintext FTS5)."""
        if self._search_index:
            return "index"
        if self._term_index:
            return "terms"
        if self.crypto_provider is not None and self.passphrase:
            return "scan"
        return "plain"

    def _coverage_sets(self, terms: Sequence[str], match: str, scope: Optional[str]) -> List[Optional[set]]:
        """For each query word of the recall gate, the ids of the entries the search index matches it in,
        or None when every match holds the word and nothing needs looking up.

        The gate's coverage is read from the index that produced the matches, so the two agree: a word
        found in the key or the category counts, and so does a word the index folds to the query's
        (case, accents) or completes from it (prefixes, where the index matches them). No entry is opened.
        """
        if match != "any" or len(terms) < 2:
            # match="all": a match holds every query word, and the gate's words are among them.
            # One word under match="any": the match is that word.
            return [None for _ in terms]
        target_scope = "default" if scope is None or scope == "" else scope
        mode = self._search_mode()
        sets: List[Optional[set]] = []
        for term in terms:
            fts_query = _fts_query([term], "any")
            if mode == "index":
                found = self._conn.execute(
                    "SELECT rowid FROM entities_search WHERE entities_search MATCH ?", (fts_query,)
                ).fetchall()
            elif mode == "terms":
                phrase = self._tokens(term)
                found = []
                if phrase:
                    joins = " ".join(
                        f"JOIN entities_terms t{k} ON t{k}.id = t0.id AND t{k}.pos = t0.pos + {k} AND t{k}.token = ?"
                        for k in range(1, len(phrase))
                    )
                    tokens = [self._term_token(target_scope, word) for word in phrase]
                    found = self._conn.execute(
                        f"SELECT DISTINCT t0.id FROM entities_terms t0 {joins} WHERE t0.token = ?",
                        [*tokens[1:], tokens[0]],
                    ).fetchall()
            elif mode == "scan":
                found = self._scan_index().execute("SELECT rowid FROM m WHERE m MATCH ?", (fts_query,)).fetchall()
            else:
                try:
                    found = self._conn.execute(
                        "SELECT rowid FROM entities_fts WHERE entities_fts MATCH ?", (fts_query,)
                    ).fetchall()
                except _OPERATIONAL_ERRORS:
                    # Where the FTS query cannot run, search falls back to LIKE on content and key: so does this.
                    pattern = f"%{term}%"
                    found = self._conn.execute(
                        "SELECT id FROM entities WHERE content LIKE ? OR key LIKE ?", (pattern, pattern)
                    ).fetchall()
            sets.append({row[0] for row in found})
        return sets

    def _rows_by_id(self, columns: str, ids: Sequence[int]) -> Dict[int, Any]:
        """Stored rows by id, reading ``columns``; any number of ids."""
        stored: Dict[int, Any] = {}
        for start in range(0, len(ids), _ID_CHUNK):
            chunk = list(ids[start:start + _ID_CHUNK])
            marks = ", ".join("?" for _ in chunk)
            for r in self._conn.execute(f"SELECT {columns} FROM entities e WHERE e.id IN ({marks})", chunk).fetchall():
                stored[r["id"]] = r
        return stored

    def _full_rows(self, ids: Sequence[int], fts_query: str) -> Dict[int, Tuple[Any, Optional[str]]]:
        """Whole rows by id for entries a ranked query found, each with the snippet :meth:`search` would
        give it: FTS5's in a plaintext vault, None elsewhere (the caller builds it from the opened content)."""
        if self._search_mode() != "plain":
            return {i: (r, None) for i, r in self._rows_by_id(_ENTITY_COLUMNS, ids).items()}
        out: Dict[int, Tuple[Any, Optional[str]]] = {}
        for start in range(0, len(ids), _ID_CHUNK):
            chunk = list(ids[start:start + _ID_CHUNK])
            marks = ", ".join("?" for _ in chunk)
            try:
                found = self._conn.execute(
                    f"""
                    SELECT {_ENTITY_COLUMNS}, snippet(entities_fts, 2, '<b>', '</b>', '...', 16) AS snip
                    FROM entities_fts
                    CROSS JOIN entities e ON e.id = entities_fts.rowid
                    WHERE entities_fts MATCH ? AND entities_fts.rowid IN ({marks})
                    """,
                    [fts_query, *chunk],
                ).fetchall()
                out.update((r["id"], (r, r["snip"])) for r in found)
            except _OPERATIONAL_ERRORS:
                out.update((i, (r, "")) for i, r in self._rows_by_id(_ENTITY_COLUMNS, chunk).items())
        return out

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
        fts_query = _fts_query(terms, match)
        # Normalize scope: None or empty string defaults to "default"
        target_scope = "default" if scope is None or scope == "" else scope
        filter_sql, filter_params = self._search_filters(
            target_scope, category, epistemic_state, as_of_valid_time, include_unverified, active_only
        )
        mode = self._search_mode()
        if mode == "index":
            rows = self._indexed_rows(fts_query, filter_sql, filter_params, limit, columns)
        elif mode == "terms":
            rows = self._term_rows(terms, match, target_scope, filter_sql, filter_params, limit, columns)
        elif mode == "scan":
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
        else:
            # K-K: candidates are recallable and shown labeled by state; only revoked entries are withheld
            # unless asked for by state. ``include_unverified`` is kept for callers and is now implied.
            clauses.append("e.epistemic_state IN ('verified', 'disputed', 'candidate')")
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

    def _term_rows(
        self,
        terms: List[str],
        match: str,
        target_scope: str,
        filter_sql: str,
        params: List[Any],
        limit: int,
        columns: str = _ENTITY_COLUMNS,
    ) -> List[Tuple[Any, float, Optional[str]]]:
        """Ranked rows from the keyed term index (:meth:`_ensure_term_index`): a vault with a passphrase
        whose file is not SQLCipher-encrypted.

        Each query word is a phrase of one or more tokens ("us-east-1" is three, adjacent). A row's score
        is the BM25 that FTS5's ``rank`` computes (k1 = 1.2, b = 0.75, every column weighted 1): for each
        phrase, the inverse document frequency over every indexed entry, whatever its scope and whatever
        the filters, as FTS5 counts over its whole table, times a saturating function of the phrase's
        instances in the row and of the row's length against the average. So scores equal a plaintext
        vault's for whole-word queries. Lower is better; ties fall to the lower id, as the other paths order.
        Only the rows this returns are opened, by the caller.
        """
        try:
            self._drain_search_queue()
        except _OPERATIONAL_ERRORS as exc:  # another connection holds the write lock: search what is indexed
            logger.debug("kibisis: searching before queued entries were indexed: %s", exc)
        phrases = [self._tokens(t) for t in terms]
        if not all(phrases):  # a word in which the tokenizer finds no token matches nothing
            if match == "all":
                return []
            phrases = [p for p in phrases if p]
            if not phrases:
                return []
        n_row, n_token = self._conn.execute(
            "SELECT count(*), coalesce(sum(ntok), 0) FROM entities_terms_docs"
        ).fetchone()
        if not n_row:
            return []
        scopes = [r[0] for r in self._conn.execute("SELECT DISTINCT scope FROM entities").fetchall()]
        searched = scopes if target_scope == "*" else [target_scope]
        idfs: List[float] = []
        hits: List[Dict[int, Tuple[int, int]]] = []  # per phrase: id -> (instances in the row, row length)
        for phrase in phrases:
            joins = " ".join(
                f"JOIN entities_terms t{k} ON t{k}.id = t0.id AND t{k}.pos = t0.pos + {k} AND t{k}.token = ?"
                for k in range(1, len(phrase))
            )
            n_hit = 0
            found: Dict[int, Tuple[int, int]] = {}
            for scope in scopes:
                tokens = [self._term_token(scope, word) for word in phrase]
                n_hit += self._conn.execute(
                    f"SELECT count(DISTINCT t0.id) FROM entities_terms t0 {joins} WHERE t0.token = ?",
                    [*tokens[1:], tokens[0]],
                ).fetchone()[0]
                if scope not in searched:
                    continue
                for row in self._conn.execute(
                    f"SELECT t0.id, count(*), d.ntok FROM entities_terms t0 {joins} "
                    f"JOIN entities_terms_docs d ON d.id = t0.id JOIN entities e ON e.id = t0.id "
                    f"WHERE t0.token = ? AND {filter_sql} GROUP BY t0.id",
                    [*tokens[1:], tokens[0], *params],
                ):
                    found[row[0]] = (row[1], row[2])
            idf = math.log((n_row - n_hit + 0.5) / (n_hit + 0.5))
            idfs.append(idf if idf > 0.0 else 1e-6)
            hits.append(found)
        if match == "all":
            ids = set.intersection(*(set(found) for found in hits))
        else:
            ids = set().union(*(set(found) for found in hits))
        if not ids:
            return []
        k1, b = 1.2, 0.75
        avgdl = n_token / n_row
        scored: List[Tuple[float, int]] = []
        for entity_id in ids:
            score = 0.0
            length = None
            for idf, found in zip(idfs, hits):
                if entity_id not in found:
                    continue  # this phrase adds nothing to the row's score
                freq, length = found[entity_id]
                score += idf * ((freq * (k1 + 1.0)) / (freq + k1 * (1 - b + b * length / avgdl)))
            scored.append((-1.0 * score, entity_id))
        scored.sort()
        ranked = scored if limit < 0 else scored[:limit]  # a negative limit is none, as in SQL
        stored = self._rows_by_id(columns, [entity_id for _, entity_id in ranked])
        return [(stored[entity_id], score, None) for score, entity_id in ranked if entity_id in stored]

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
        stored = self._rows_by_id(columns, [row[0] for row in ranked])
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
                    cursor.execute("DROP TABLE IF EXISTS entities_search")
                    cursor.execute(
                        "CREATE VIRTUAL TABLE entities_search USING fts5("
                        "category, key, content, scope, content='', contentless_delete=1)"
                    )
                    self._create_index_queue(cursor, "DELETE FROM entities_search WHERE rowid = old.id; ")
                    # A file converted to SQLCipher may carry the keyed term index of its plain days: the
                    # FTS5 index replaces it.
                    self._drop_term_index(cursor)
                    self._set_meta(cursor, "search_index_format", SEARCH_INDEX_FORMAT)
            except _OPERATIONAL_ERRORS as exc:
                text = str(exc).lower()
                if not any(s in text for s in ("no such module", "unrecognized option", "contentless")):
                    raise
                # SQLite before 3.43 has no contentless-delete FTS5 tables: search opens the entries instead.
                logger.warning("kibisis: sealed entries are searched without an index: %s", exc)
                return
        self._search_index = True
        self._drain_search_queue(at_open=True)

    def _ensure_term_index(self) -> None:
        """Keep a keyed term index in a file that SQLCipher does not encrypt, so that search on a vault
        with a passphrase looks up the query's words instead of opening every entry.

        ``entities_terms`` holds, for each indexed entry, one row per word of its category, key, content
        and scope: the word's position and its token, the first 16 hex characters of HMAC-SHA256 under
        the vault's term key (:func:`derive_vault_keys`) of the entry's scope, a NUL byte and the word as
        FTS5's unicode61 tokenizer folds it. ``entities_terms_docs`` holds each entry's word count. No
        word reaches the file in the clear, and without the passphrase a token cannot be tested against a
        guessed word; what the file does show is the shape of the text, see SECURITY.md. Search tags the
        query's words the same way, reads the rows of those tokens, scores them with the BM25 formula
        FTS5 uses (whole-vault statistics, so scores equal a plaintext vault's) and opens only the
        entries it returns. Whole words only: a token says nothing about the tokens of longer words, so
        a query word does not match words that start with it in this mode, as it does in the others.

        The same triggers as the SQLCipher index queue every row whose text changes, so rows that a
        process running an older kibisis writes without feeding the index are indexed before the next
        search. A vault without the index, or with one of another version, gets one built by opening
        each entry once. Sub-linear in the vault: a query costs its words' rows, not the file.
        """
        current = self._meta("term_index_format")
        if current is None or int(current) != TERM_INDEX_FORMAT:
            with self._write_tx() as cursor:
                self._drop_term_index(cursor)
                cursor.execute("CREATE TABLE entities_terms (token TEXT NOT NULL, id INTEGER NOT NULL, pos INTEGER NOT NULL)")
                cursor.execute("CREATE INDEX entities_terms_token ON entities_terms (token, id, pos)")
                cursor.execute("CREATE INDEX entities_terms_id ON entities_terms (id)")
                cursor.execute("CREATE TABLE entities_terms_docs (id INTEGER PRIMARY KEY, ntok INTEGER NOT NULL)")
                self._create_index_queue(
                    cursor,
                    "DELETE FROM entities_terms WHERE id = old.id; DELETE FROM entities_terms_docs WHERE id = old.id; ",
                )
                self._set_meta(cursor, "term_index_format", TERM_INDEX_FORMAT)
                self._write_meta_mac(cursor)  # the format is one of the values the meta MAC covers
        self._term_index = True
        self._drain_search_queue(at_open=True)

    @staticmethod
    def _create_index_queue(cursor: Any, on_delete: str) -> None:
        """(Re)create the queue of rows to index, ``entities_search_dirty``, and the triggers that feed it:
        every inserted row and every row whose text changes is queued; ``on_delete`` runs when a row is
        deleted, before its queue entry goes."""
        for trigger in ("entities_search_ai", "entities_search_au", "entities_search_ad"):
            cursor.execute(f"DROP TRIGGER IF EXISTS {trigger}")
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
            + on_delete
            + "DELETE FROM entities_search_dirty WHERE id = old.id; END"
        )
        cursor.execute("INSERT OR IGNORE INTO entities_search_dirty (id) SELECT id FROM entities")

    @staticmethod
    def _drop_term_index(cursor: Any) -> None:
        cursor.execute("DROP TABLE IF EXISTS entities_terms")
        cursor.execute("DROP TABLE IF EXISTS entities_terms_docs")
        cursor.execute("DELETE FROM vault_meta WHERE key = 'term_index_format'")

    def _tokens(self, text: str) -> List[str]:
        """The words of ``text`` in order, as FTS5's default tokenizer (unicode61) splits and folds them,
        read back through an ``fts5vocab`` table, so the term index and the FTS5 indexes agree on what a
        word is and on how many a text has."""
        with self._tokenizer_lock:
            if self._tokenizer is None:
                self._tokenizer = sqlite3.connect(":memory:", check_same_thread=False)
                self._tokenizer.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
                self._tokenizer.execute("CREATE VIRTUAL TABLE tv USING fts5vocab(t, 'instance')")
            self._tokenizer.execute("DELETE FROM t")
            self._tokenizer.execute("INSERT INTO t (rowid, x) VALUES (1, ?)", (text,))
            return [r[0] for r in self._tokenizer.execute("SELECT term FROM tv ORDER BY offset").fetchall()]

    def _term_token(self, scope: str, word: str) -> str:
        """The term index token of ``word`` (already folded by :meth:`_tokens`) in ``scope``."""
        if self._term_key is None:
            raise EncryptionRequiredError("The term index needs a vault opened with its passphrase.")
        tag = hmac.new(self._term_key, scope.encode("utf-8") + b"\x00" + word.encode("utf-8"), hashlib.sha256)
        return tag.hexdigest()[:16]

    def _index_entry(self, cursor: Any, entity_id: int, category: str, key: str, content: str, scope: str) -> None:
        """Put an entry's terms in the entry index, in place of any it had there."""
        if self._search_index:
            cursor.execute(
                "INSERT OR REPLACE INTO entities_search (rowid, category, key, content, scope) VALUES (?, ?, ?, ?, ?)",
                (entity_id, category, key, content, scope),
            )
        elif self._term_index:
            rows: List[Tuple[str, int, int]] = []
            pos = 0
            for column in (category, key, content, scope):
                for word in self._tokens(column):
                    rows.append((self._term_token(scope, word), entity_id, pos))
                    pos += 1
                pos += 1  # a gap, so no phrase spans two columns (FTS5 matches phrases within one column)
            cursor.execute("DELETE FROM entities_terms WHERE id = ?", (entity_id,))
            cursor.executemany("INSERT INTO entities_terms (token, id, pos) VALUES (?, ?, ?)", rows)
            cursor.execute("INSERT OR REPLACE INTO entities_terms_docs (id, ntok) VALUES (?, ?)", (entity_id, len(rows)))
        cursor.execute("DELETE FROM entities_search_dirty WHERE id = ?", (entity_id,))

    def _unindex_entry(self, cursor: Any, entity_id: int, *, keep_queued: bool = False) -> None:
        """Take an entry out of the entry index and (unless ``keep_queued``) the queue: deleted, or
        failed its integrity check."""
        if self._search_index:
            cursor.execute("DELETE FROM entities_search WHERE rowid = ?", (entity_id,))
        elif self._term_index:
            cursor.execute("DELETE FROM entities_terms WHERE id = ?", (entity_id,))
            cursor.execute("DELETE FROM entities_terms_docs WHERE id = ?", (entity_id,))
        if not keep_queued:
            cursor.execute("DELETE FROM entities_search_dirty WHERE id = ?", (entity_id,))

    def _index_queued(self, cursor: Any, *, at_open: bool = False) -> int:
        """Index the rows the triggers queued, within the caller's write transaction. Returns how many.

        A row that fails its integrity check is logged, counted and kept out of the index. Under
        ``strict`` it raises, except ``at_open`` (the open never raises for an entry): then it is left
        in the queue, so the first read that catches the index up raises.
        """
        ids = [row[0] for row in cursor.execute("SELECT id FROM entities_search_dirty ORDER BY id").fetchall()]
        for entity_id in ids:
            r = cursor.execute(
                "SELECT id, category, key, content, scope, is_encrypted, encrypted_envelope_json, tenant_sig "
                "FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()
            if r is None:
                self._unindex_entry(cursor, entity_id)  # deleted
                continue
            try:
                content = self._open_entry(r)
            except EntryIntegrityError as exc:
                self._note_integrity_failure(r, exc)
                if self.strict and not at_open:
                    raise
                self._unindex_entry(cursor, entity_id, keep_queued=self.strict)  # kept out of the index
                continue
            except PermissionError:
                content = "[ENCRYPTED]"
            self._index_entry(cursor, entity_id, r["category"], r["key"], content, r["scope"])
        return len(ids)

    def _drain_search_queue(self, *, at_open: bool = False) -> None:
        """Index the rows written since the last search by a process that did not feed the index."""
        if not (self._search_index or self._term_index):
            return
        if not self._conn.execute("SELECT EXISTS (SELECT 1 FROM entities_search_dirty)").fetchone()[0]:
            return
        with self._write_tx() as cursor:
            self._index_queued(cursor, at_open=at_open)

    def _rebuild_search_index(self) -> None:
        """Build the entry index again from the entries, so that no deleted or replaced terms stay in it."""
        with self._write_tx() as cursor:
            if self._search_index:
                cursor.execute("INSERT INTO entities_search (entities_search) VALUES ('delete-all')")
            else:
                cursor.execute("DELETE FROM entities_terms")
                cursor.execute("DELETE FROM entities_terms_docs")
            cursor.execute("INSERT OR IGNORE INTO entities_search_dirty (id) SELECT id FROM entities")
            self._index_queued(cursor)
            if self._search_index:
                cursor.execute("INSERT INTO entities_search (entities_search) VALUES ('optimize')")
