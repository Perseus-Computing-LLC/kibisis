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
    ) -> RecallResult:
        """Model-facing recall: :meth:`search` plus what was withheld and why, with a receipt (K-R3..K-R5).

        K-R3: two verified entries that conflict (``conflicts_with`` edge, or the same ``slot`` with
        different content) are both withheld as ``conflict_unresolved`` with each other's ids. K-R4: a hit
        is returned only if the share of query words it contains is at least ``min_coverage_bp`` (basis
        points) and, with four or more matches to compare against, its BM25 z-score among the matched set
        is at most ``z_max_bp``; the receipt carries ``n_store`` and every hit's z-score and coverage.
        ``ttl_seconds`` maps an origin class to a maximum age since ``last_verified_at`` (else
        ``updated_at``); older entries are withheld as ``stale``. K-R5: every call is journaled as a
        ``recall`` event and mirrored to Argus as ``kibisis.memory_recall`` (counts and withheld ids; the
        query appears only as a digest).
        """
        if scope == "*":
            raise ValueError("recall is bound to one scope; '*' is not available here")
        # Over-fetch so the gate has a distribution to work with and withheld entries do not starve the limit.
        pool = max(limit * 8, 64)
        hits = self.search(
            query, category=category, limit=pool, scope=scope, epistemic_state=epistemic_state,
            as_of_valid_time=as_of_valid_time, include_unverified=True, active_only=active_only,
            tenant_id=tenant_id, principal_id=principal_id, authorized_lineage_roots=authorized_lineage_roots,
            match=match,
        )
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

        scores = [h.rank_score for h in hits]
        mean = sum(scores) / len(scores) if scores else 0.0
        var = sum((x - mean) ** 2 for x in scores) / len(scores) if scores else 0.0
        std = var ** 0.5
        # With four or more matches the z-score is meaningful. A crowd of tied scores carries no
        # evidence that any one of them answers the query: every z is 0 and the default gate drops them.
        use_z = len(scores) >= 4

        def _ref(e: MemoryEntity) -> str:
            return f"{e.category}:{e.key}"

        # K-R3: conflicts among the verified entries in the matched set and their declared partners.
        by_ref = {_ref(h.entity): h for h in hits}
        conflict_sources: Dict[str, List[str]] = {}
        verified_hits = [h for h in hits if h.entity.epistemic_state == EpistemicState.VERIFIED]
        for h in verified_hits:
            for other_ref in h.entity.metadata.get("conflicts_with") or []:
                other = by_ref.get(other_ref)
                if other is None:
                    c, k = other_ref.split(":", 1)
                    other_entity = self.get(c, k, scope=scope or "default") if scope is not None else None
                else:
                    other_entity = other.entity
                if other_entity is None or other_entity.epistemic_state != EpistemicState.VERIFIED or other_entity.archived:
                    continue
                conflict_sources.setdefault(_ref(h.entity), []).append(other_ref)
                conflict_sources.setdefault(other_ref, []).append(_ref(h.entity))
        slots: Dict[Tuple[str, str], List[SearchResult]] = {}
        for h in verified_hits:
            slot = h.entity.metadata.get("slot")
            if slot:
                slots.setdefault((h.entity.category, str(slot)), []).append(h)
        for group in slots.values():
            if len({g.entity.content for g in group}) > 1:
                for g in group:
                    others = [_ref(o.entity) for o in group if o is not g]
                    conflict_sources.setdefault(_ref(g.entity), []).extend(o for o in others if o not in conflict_sources.get(_ref(g.entity), []))

        results: List[SearchResult] = []
        withheld: List[WithheldEntry] = []
        hit_receipts: List[Dict[str, Any]] = []
        n_conflict = n_gate = n_stale = 0
        for h in hits:
            ref = _ref(h.entity)
            text = h.entity.content.lower()
            covered = sum(1 for t in terms if t in text) if terms else 0
            coverage_bp = int(round(10000 * covered / len(terms))) if terms else 10000
            z_bp: Optional[int] = (int(round(10000 * (h.rank_score - mean) / std)) if std > 1e-9 else 0) if use_z else None
            kept = True
            reason = ""
            if ref in conflict_sources:
                kept, reason = False, "conflict_unresolved"
                n_conflict += 1
                withheld.append(WithheldEntry(ref=ref, reason=reason, sources=sorted(set(conflict_sources[ref]))))
            elif coverage_bp < min_coverage_bp or (z_bp is not None and z_bp > z_max_bp):
                kept, reason = False, "below_gate"
                n_gate += 1
                withheld.append(WithheldEntry(ref=ref, reason=reason))
            elif ttl_seconds:
                klass = h.entity.metadata.get("origin_class") or origin_class_of(h.entity.origin)
                ttl = ttl_seconds.get(klass)
                if ttl is not None:
                    last = h.entity.metadata.get("last_verified_at") or h.entity.updated_at or h.entity.created_at
                    if last is not None and now - float(last) > float(ttl):
                        kept, reason = False, "stale"
                        n_stale += 1
                        withheld.append(WithheldEntry(ref=ref, reason=reason))
            hit_receipts.append({
                "ref": ref, "coverage_bp": coverage_bp, "z_bp": z_bp, "kept": kept, "reason": reason,
                "contrasts_with": list(h.entity.metadata.get("contrasts_with") or []),
            })
            if kept and len(results) < limit:
                results.append(h)
        if conflict_sources:
            # A partner that did not match the query is withheld too: both sides of the pair stay out.
            seen = {w.ref for w in withheld}
            for ref, sources in conflict_sources.items():
                if ref not in seen and ref not in by_ref:
                    withheld.append(WithheldEntry(ref=ref, reason="conflict_unresolved", sources=sorted(set(sources))))
                    n_conflict += 1

        receipt: Dict[str, Any] = {
            "channel": channel,
            "scope": scope or "*",
            "n_store": n_store,
            "n_matched": len(hits),
            "n_returned": len(results),
            "n_withheld_conflict": n_conflict,
            "n_withheld_gate": n_gate,
            "n_withheld_stale": n_stale,
            "gate": {"min_coverage_bp": int(min_coverage_bp), "z_max_bp": int(z_max_bp)},
            "hits": hit_receipts,
        }
        query_digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:12]
        journal_meta = {
            "channel": channel, "query_sha256_12": query_digest, "n_store": n_store, "n_matched": len(hits),
            "n_returned": len(results), "n_withheld_conflict": n_conflict, "n_withheld_gate": n_gate,
            "n_withheld_stale": n_stale, "withheld": [w.ref for w in withheld],
        }
        # A read never writes: it takes no lock a writer holds and does not move the audit head that
        # write-invalidated caches follow. The record goes to Argus and to an in-process log.
        record = {**journal_meta, "scope": scope or "*", "actor": actor or "", "at": int(now)}
        self._recent_recalls.append(record)
        _argus_append("kibisis.memory_recall", actor or "kibisis", {**journal_meta, "scope": scope or "*"})
        return RecallResult(results=results, withheld=withheld, receipt=receipt)

    def recent_recalls(self, limit: int = 100) -> List[Dict[str, Any]]:
        """The newest recall records this process made (K-R5), newest last; the Argus ledger is the durable copy."""
        items = list(self._recent_recalls)
        return items[-limit:] if limit else items

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
        elif self._term_index:
            rows = self._term_rows(terms, match, target_scope, filter_sql, filter_params, limit, columns)
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
        ranked = scored[:limit]
        marks = ", ".join("?" for _ in ranked)
        stored = {
            r["id"]: r
            for r in self._conn.execute(
                f"SELECT {columns} FROM entities e WHERE e.id IN ({marks})", [entity_id for _, entity_id in ranked]
            ).fetchall()
        }
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
        self._drain_search_queue()

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
        self._term_index = True
        self._drain_search_queue()

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

    def _unindex_entry(self, cursor: Any, entity_id: int) -> None:
        """Take an entry out of the entry index and the queue: deleted, or failed its integrity check."""
        if self._search_index:
            cursor.execute("DELETE FROM entities_search WHERE rowid = ?", (entity_id,))
        elif self._term_index:
            cursor.execute("DELETE FROM entities_terms WHERE id = ?", (entity_id,))
            cursor.execute("DELETE FROM entities_terms_docs WHERE id = ?", (entity_id,))
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
                self._unindex_entry(cursor, entity_id)
            else:
                self._index_entry(cursor, entity_id, r["category"], r["key"], content, r["scope"])
        return len(ids)

    def _drain_search_queue(self) -> None:
        """Index the rows written since the last search by a process that did not feed the index."""
        if not (self._search_index or self._term_index):
            return
        if not self._conn.execute("SELECT EXISTS (SELECT 1 FROM entities_search_dirty)").fetchone()[0]:
            return
        with self._write_tx() as cursor:
            self._index_queued(cursor)

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
