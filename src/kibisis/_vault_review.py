"""Admission and review in :class:`kibisis.vault.SQLiteMemoryVault`: the origins and trust classes of entries,
model-facing admission (``remember``, ``admit_candidate``, ``admit``), a person's review verdicts, the state
transitions, dependency edges and cascades they cause, and the abstention evaluation (``Probe``).

The methods are mixed into ``SQLiteMemoryVault``; they run on its connection and write through its ``put``.
Every name here is also importable from ``kibisis.vault``.
"""

from __future__ import annotations

import json
import sqlite3
import time
import warnings
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Union

from ._vault_audit import _argus_append
from .models import EpistemicState, MemoryEntity


# Where an entry came from. "model" writes are capped at candidate and cannot promote themselves.
ORIGINS = ("user", "model", "tool", "import", "unknown")


#: K-R1: the trust class of a write, fixed by the vault from ``origin`` at write time. ``principal``
#: is a person or an operator-run import; ``agent`` is model output; ``external`` is a tool result or
#: an unstated origin. Higher index = more trusted.
ORIGIN_CLASSES = ("external", "agent", "principal")


_ORIGIN_TO_CLASS = {"user": "principal", "import": "principal", "model": "agent", "tool": "external", "unknown": "external"}


def origin_class_of(origin: Optional[str]) -> str:
    """Trust class for an origin; an unstated origin is ``external``."""
    return _ORIGIN_TO_CLASS.get(origin or "unknown", "external")


def _class_rank(origin_class: Optional[str]) -> int:
    return ORIGIN_CLASSES.index(origin_class) if origin_class in ORIGIN_CLASSES else 0


def _row_origin_class(row: Any) -> str:
    """Origin class of a fetched row: the stored one, else derived from the row's origin."""
    try:
        meta = json.loads(row["metadata_json"] or "{}")
    except (TypeError, ValueError, IndexError, KeyError):
        meta = {}
    stored = meta.get("origin_class")
    if stored in ORIGIN_CLASSES:
        return stored
    return origin_class_of(row_origin(row))


def _validate_origin(origin: Optional[str], what: str = "origin") -> Optional[str]:
    if origin is None:
        return None
    if origin not in ORIGINS:
        raise ValueError(f"{what} must be one of {ORIGINS}, got {origin!r}")
    return origin


def row_origin(row: Any) -> str:
    """Origin of a fetched row; 'unknown' for rows and cursors that predate the column."""
    try:
        return row["origin"] or "unknown"
    except (IndexError, KeyError):
        return "unknown"


class AdmissionRefused(PermissionError):
    """Raised when a reviewer that is not a person tries to promote an entry to ``verified``."""


@dataclass(frozen=True)
class Probe:
    """One query for :meth:`SQLiteMemoryVault.evaluate_abstention`.

    ``expected`` holds the ``category:key`` references that answer the query; any one of them in the
    results counts as answered. ``None`` means nothing stored answers it, so the right result is none.
    ``tag`` groups probes in the report (for example ``"near-miss"`` or ``"off-topic"``).
    """

    query: str
    expected: Optional[Union[str, Iterable[str]]] = None  # stored as a frozenset of "category:key"
    tag: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.query, str) or not self.query.strip():
            raise ValueError("Probe.query must be a non-empty string")
        if self.expected is not None:
            refs = frozenset(_entry_ref(r) for r in ([self.expected] if isinstance(self.expected, str) else self.expected))
            if not refs:
                raise ValueError(f"Probe {self.query!r}: expected must name at least one category:key, or be None")
            object.__setattr__(self, "expected", refs)

    @property
    def answerable(self) -> bool:
        return self.expected is not None


def _entry_ref(ref: Any) -> str:
    """``category:key`` of a search result, entity, hit, ``(category, key)`` pair or ``"category:key"`` string."""
    entity = getattr(ref, "entity", None)
    if entity is not None:
        ref = entity
    if hasattr(ref, "category") and hasattr(ref, "key"):
        return f"{ref.category}:{ref.key}"
    if isinstance(ref, tuple) and len(ref) == 2:
        return f"{ref[0]}:{ref[1]}"
    if isinstance(ref, str):
        if ":" not in ref:
            raise ValueError(f"entry reference {ref!r} must be 'category:key'")
        return ref
    raise TypeError(f"cannot read an entry reference from {type(ref).__name__}")


class AdmissionReviewMixin:
    """Admits candidates, records review verdicts and state transitions, and evaluates abstention."""

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
        cause: str = "write",
    ) -> None:
        """Journal an epistemic-state change and mirror it to the Argus ledger when one is configured.

        ``cause`` names the path that made the change: ``supersede`` (explicit edge), ``review`` (a
        person's verdict), ``cascade`` (a source it derived from was retired), ``archive``, or ``write``.
        """
        payload = {
            "event": "state_transition",
            "from": previous,
            "to": new,
            "origin": origin,
            "reviewer": reviewer,
            "cause": cause,
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

    def _record_edges(
        self,
        cursor: sqlite3.Cursor,
        field: str,
        refs: Optional[List[str]],
        category: str,
        key: str,
        scope: str,
        now: float,
        existing_meta: Dict[str, Any],
        keep_existing: bool,
    ) -> List[str]:
        """Record a symmetric ``category:key`` edge list (``conflicts_with`` / ``contrasts_with``) on this
        entry and on each target, which must exist in the scope. Returns this entry's edge list."""
        kept: List[str] = list(existing_meta.get(field) or []) if keep_existing else []
        if not refs:
            return kept
        self_ref = f"{category}:{key}"
        for ref in refs:
            if ":" not in ref:
                raise ValueError(f"{field} entries are 'category:key' refs, got {ref!r}")
            if ref == self_ref:
                raise ValueError(f"an entry cannot be in {field} with itself")
            c, k = ref.split(":", 1)
            cursor.execute("SELECT id, metadata_json FROM entities WHERE category = ? AND key = ? AND scope = ?", (c, k, scope))
            other = cursor.fetchone()
            if other is None:
                raise ValueError(f"{field} target '{ref}' [scope={scope}] does not exist")
            other_meta = json.loads(other["metadata_json"] or "{}")
            back = list(other_meta.get(field) or [])
            if self_ref not in back:
                back.append(self_ref)
                other_meta[field] = back
                cursor.execute(
                    "UPDATE entities SET metadata_json = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(other_meta, sort_keys=True), now, other["id"]),
                )
            if ref not in kept:
                kept.append(ref)
        return kept

    def _cascade_invalidate(
        self, cursor: sqlite3.Cursor, scope: str, retired_ref: str, author_id: Optional[str], now: float
    ) -> List[str]:
        """K-R2 cascading invalidation: every active entry that ``derived_from`` a retired entry becomes
        ``disputed`` with ``invalidated_by`` set, and the cascade continues through their dependents.
        Entries are marked once; cycles terminate. Returns the refs marked, in order."""
        marked: List[str] = []
        seen = {retired_ref}
        queue = [retired_ref]
        while queue:
            ref = queue.pop(0)
            cursor.execute(
                "SELECT id, category, key, metadata_json, epistemic_state, origin FROM entities "
                "WHERE scope = ? AND archived = 0 AND epistemic_state != 'revoked' AND metadata_json LIKE ?",
                (scope, f'%{json.dumps(ref)}%'),
            )
            for dep in cursor.fetchall():
                dep_ref = f"{dep['category']}:{dep['key']}"
                if dep_ref in seen:
                    continue
                dep_meta = json.loads(dep["metadata_json"] or "{}")
                if ref not in (dep_meta.get("derived_from") or []):
                    continue
                seen.add(dep_ref)
                dep_meta["invalidated_by"] = ref
                cursor.execute(
                    "UPDATE entities SET epistemic_state = ?, metadata_json = ?, updated_at = ? WHERE id = ?",
                    (EpistemicState.DISPUTED.value, json.dumps(dep_meta, sort_keys=True), now, dep["id"]),
                )
                if dep["epistemic_state"] != EpistemicState.DISPUTED.value:
                    self._record_state_transition(
                        cursor, dep["category"], dep["key"], scope, dep["epistemic_state"],
                        EpistemicState.DISPUTED.value, row_origin(dep), author_id, cause="cascade",
                    )
                marked.append(dep_ref)
                queue.append(dep_ref)
        return marked

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

    def _clear_pending_supersession(self, category: str, key: str, scope: str, proposer_ref: str) -> None:
        """Drop ``proposer_ref`` from the target's ``pending_supersession_by`` mark (K-R2 proposal rejected)."""
        with self._write_tx() as cursor:
            cursor.execute(
                "SELECT id, metadata_json FROM entities WHERE category = ? AND key = ? AND scope = ?",
                (category, key, scope),
            )
            row = cursor.fetchone()
            if row is None:
                return
            meta = json.loads(row["metadata_json"] or "{}")
            pending = [r for r in (meta.get("pending_supersession_by") or []) if r != proposer_ref]
            if pending:
                meta["pending_supersession_by"] = pending
            else:
                meta.pop("pending_supersession_by", None)
            cursor.execute(
                "UPDATE entities SET metadata_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(meta, sort_keys=True), time.time(), row["id"]),
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

        if meta.get("proposed_supersedes") and verdict != EpistemicState.VERIFIED.value:
            # K-R2: the proposal is rejected; drop it and clear the target's pending mark.
            dropped = meta.pop("proposed_supersedes")
            meta.pop("supersession", None)
            self._clear_pending_supersession(dropped["category"], dropped["key"], scope, f"{category}:{key}")

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
            with self._write_tx() as cursor:
                if entity.epistemic_state != EpistemicState.REVOKED:
                    self._record_state_transition(
                        cursor, category, key, scope, entity.epistemic_state.value,
                        EpistemicState.REVOKED.value, entity.origin, reviewer_id, cause="review",
                    )
                # K-R2: everything derived from the revoked entry is now in question.
                self._cascade_invalidate(cursor, scope, f"{category}:{key}", reviewer_id, time.time())
            entity.archived = True
            entity.epistemic_state = EpistemicState.REVOKED
            entity.metadata = meta
            return entity

        # Update entity with new epistemic status and review metadata. Approving an entry that proposed
        # to supersede a reviewed entry applies the supersession now, under the reviewer's authority.
        stored_state = verdict
        if verdict == EpistemicState.VERIFIED.value:
            meta["last_verified_at"] = time.time()  # K-R4: a person's verified review refreshes the TTL clock
            # K-R1 quorum: a person's verified review is one attestation; the entry is verified once
            # verification_quorum distinct principals have attested. Other reviewer origins never count.
            attested = list(meta.get("attestations") or [])
            if reviewer_origin == "user" and reviewer_id and reviewer_id not in attested:
                attested.append(reviewer_id)
            if attested:
                meta["attestations"] = attested
            if len(attested) >= self.verification_quorum:
                meta.pop("verification_pending", None)
            else:
                meta["verification_pending"] = {"have": len(attested), "need": self.verification_quorum}
                stored_state = EpistemicState.CANDIDATE.value
        proposal = meta.pop("proposed_supersedes", None) if stored_state == EpistemicState.VERIFIED.value else None
        if proposal:
            meta["supersession_approved_by"] = reviewer_id
        return self.put(
            category=category,
            key=key,
            content=entity.content,
            metadata=meta,
            epistemic_state=stored_state,
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
            _review_verdict=True,
        )

    def evaluate_abstention(
        self,
        probes: Optional[Iterable[Probe]] = None,
        *,
        answerable: Optional[Mapping[str, Union[str, Iterable[str]]]] = None,
        unanswerable: Optional[Iterable[str]] = None,
        search_fn: Optional[Callable[[str], Iterable[Any]]] = None,
        k: int = 6,
        scope: str = "default",
    ) -> Dict[str, Any]:
        """Score recall on probes the vault must answer and probes it must refuse.

        Probes come as :class:`Probe` objects, as ``answerable`` (query -> ``category:key`` or several)
        and ``unanswerable`` (queries nothing stored answers), or both. Each probe is scored on the
        first ``k`` results of ``search_fn(query)``; the default is this vault's natural-language
        search, ``search(query, scope=scope, limit=k, match="any")``. Pass the function a caller
        really runs (the MCP server's recall, a plugin's prefetch) so the path that is scored is the
        path in use. It may return search results, hits, entities, ``(category, key)`` pairs or
        ``"category:key"`` strings.

        Outcomes per probe: an answerable probe is ``answered`` when an expected entry is in the top
        ``k``, ``false_block`` when nothing comes back and ``wrong_entry`` when only other entries do;
        an unanswerable probe is ``abstained`` when nothing comes back and ``false_accept`` otherwise.
        ``false_reject_count`` is ``false_block_count + wrong_entry_count``. ``store_size`` is the number
        of active entries in ``scope``.

        ``verdict`` is ``"perfect"`` only when the store holds entries, at least one probe is
        answerable, every answerable probe was answered and every unanswerable probe refused.
        Otherwise it names what went wrong: ``"empty_store"``, ``"no_probes"``,
        ``"no_answerable_probes"`` (refusing everything is not evidence of anything),
        ``"false_rejects"``, ``"false_accepts"`` or ``"mixed"``. ``perfect`` is that verdict as a bool.
        """
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("k must be a positive integer")
        all_probes: List[Probe] = []
        for probe in probes or ():
            if not isinstance(probe, Probe):
                raise TypeError(f"probes must be Probe objects, got {type(probe).__name__}")
            all_probes.append(probe)
        for query, refs in (answerable or {}).items():
            all_probes.append(Probe(query, expected=frozenset([refs] if isinstance(refs, str) else refs)))
        for query in unanswerable or ():
            all_probes.append(Probe(query))
        if search_fn is None:
            search_fn = lambda q: self.search(q, scope=scope, limit=k, match="any")

        store_size = int(
            self._conn.execute(
                "SELECT COUNT(*) FROM entities WHERE scope = ? AND archived = 0", (scope,)
            ).fetchone()[0]
        )

        counts = {"answered": 0, "false_block": 0, "wrong_entry": 0, "abstained": 0, "false_accept": 0}
        by_tag: Dict[str, Dict[str, int]] = {}
        outcomes: List[Dict[str, Any]] = []
        false_accepts: List[Dict[str, Any]] = []
        false_rejects: List[Dict[str, Any]] = []
        for probe in all_probes:
            matched = [_entry_ref(r) for r in search_fn(probe.query)][:k]
            if probe.expected is None:
                outcome = "abstained" if not matched else "false_accept"
            elif not matched:
                outcome = "false_block"
            elif any(ref in probe.expected for ref in matched):
                outcome = "answered"
            else:
                outcome = "wrong_entry"
            counts[outcome] += 1
            tag = by_tag.setdefault(
                probe.tag,
                {"answerable": 0, "unanswerable": 0, "answered": 0, "false_block": 0, "wrong_entry": 0,
                 "abstained": 0, "false_accept": 0},
            )
            tag["answerable" if probe.answerable else "unanswerable"] += 1
            tag[outcome] += 1
            expected = sorted(probe.expected) if probe.expected is not None else None
            record = {"probe": probe.query, "tag": probe.tag, "outcome": outcome, "expected": expected, "matched": matched}
            outcomes.append(record)
            if outcome == "false_accept":
                false_accepts.append({"probe": probe.query, "tag": probe.tag, "matched": matched})
            elif outcome in ("false_block", "wrong_entry"):
                false_rejects.append(
                    {"probe": probe.query, "tag": probe.tag, "outcome": outcome, "expected": expected, "matched": matched}
                )

        answerable_count = sum(1 for p in all_probes if p.answerable)
        unanswerable_count = len(all_probes) - answerable_count
        false_reject_count = counts["false_block"] + counts["wrong_entry"]
        false_accept_count = counts["false_accept"]
        if not all_probes:
            verdict = "no_probes"
        elif store_size == 0:
            verdict = "empty_store"
        elif answerable_count == 0:
            verdict = "no_answerable_probes"
        elif false_reject_count and false_accept_count:
            verdict = "mixed"
        elif false_reject_count:
            verdict = "false_rejects"
        elif false_accept_count:
            verdict = "false_accepts"
        else:
            verdict = "perfect"

        return {
            "scope": scope,
            "store_size": store_size,
            "k": k,
            "total_probes": len(all_probes),
            "answerable_count": answerable_count,
            "unanswerable_count": unanswerable_count,
            "answered_count": counts["answered"],
            "false_block_count": counts["false_block"],
            "wrong_entry_count": counts["wrong_entry"],
            "false_reject_count": false_reject_count,
            "abstained_count": counts["abstained"],
            "false_accept_count": false_accept_count,
            "answerable_hit_rate": (counts["answered"] / answerable_count) if answerable_count else None,
            "unanswerable_abstain_rate": (counts["abstained"] / unanswerable_count) if unanswerable_count else None,
            "false_accepts": false_accepts,
            "false_rejects": false_rejects,
            "outcomes": outcomes,
            "by_tag": by_tag,
            "verdict": verdict,
            "perfect": verdict == "perfect",
        }

    def evaluate_epistemic_abstention(
        self,
        negative_probes: List[str],
        scope: str = "default",
    ) -> Dict[str, Any]:
        """Deprecated: use :meth:`evaluate_abstention`, which also scores probes the vault must answer.

        Scores only probes that should return nothing, through ``search(probe, scope=scope)`` with its
        default ``match="all"``, and keeps its old keys: ``perfect_abstention`` is true whenever every
        probe returned nothing, which an empty vault or a dead retriever also achieves. The new
        report's ``store_size``, ``verdict`` and ``perfect`` are included so the gap is visible.
        """
        warnings.warn(
            "evaluate_epistemic_abstention() is deprecated: use evaluate_abstention(), which scores "
            "answerable probes too and does not call an empty vault perfect",
            DeprecationWarning,
            stacklevel=2,
        )
        report = self.evaluate_abstention(
            unanswerable=negative_probes, scope=scope, k=10, search_fn=lambda q: self.search(q, scope=scope),
        )
        total = report["total_probes"]
        abstained = report["abstained_count"]
        false_positives = [
            {"probe": leak["probe"], "matched_keys": [ref.split(":", 1)[1] for ref in leak["matched"]]}
            for leak in report["false_accepts"]
        ]
        return {
            "total_probes": total,
            "abstained_count": abstained,
            "false_positive_count": len(false_positives),
            "abstention_rate": (abstained / total) if total > 0 else 1.0,
            "false_positives": false_positives,
            "perfect_abstention": (abstained == total),
            "store_size": report["store_size"],
            "verdict": report["verdict"],
            "perfect": report["perfect"],
        }
