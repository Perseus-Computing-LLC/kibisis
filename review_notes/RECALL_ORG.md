# RECALL_ORG: recall gate, organization primitives, performance (review of 0d734c3)

Restatement. Explain, reproduce and measure the recall gate that withholds most matching
memories (`below_gate`); write an exact API reference of the organization primitives a background
consolidation job would build on; measure Kibisis performance at 1k/10k/50k entries, plus a short
look at Argus append/verify cost at 100k events.

Assumptions not in the task packet are listed at the end of each section as they arise.
All measurements use synthetic vaults under
`/opt/data/cache/scratch/review-20261110/scratch-kibisis/` with a made-up passphrase; the live
vault was never opened. Nothing under `src/` was edited: every "after" number comes from a
monkeypatch inside the measurement script.


## A. The recall gate

### A.1 What the code does (head 0d734c3)

Scoring (`src/kibisis/_vault_search.py`):

- The query is split on whitespace; for `match="any"` the words are lowercased, de-duplicated, and function
  words and single characters are dropped while other words remain (`_search_terms`, lines 84-96; stop list
  lines 70-75). Each word becomes an FTS5 prefix phrase `"word"*`, joined with ` OR ` (`any`) or a space
  (`all`) (line 422).
- A SQLCipher vault (the production kind; `search_path: fts5 entities_search` in every benchmark run) ranks
  with `entities_search.rank` (`_indexed_rows`, lines 510-527). The index is
  `fts5(category, key, content, scope, content='', contentless_delete=1)` (lines 701-702), and `rank` is
  FTS5's default `bm25()` with every column weighted 1.0. The score is negative and lower is better
  (`search` docstring, line 172). Order is `ORDER BY score, e.id`.
- There is no recency, trust, origin or epistemic-state term anywhere in the ranking. `updated_at`,
  `confidence` and `origin_class` do not enter the order.

Order of operations in `recall()` (lines 203-359):

1. SQL filters, before ranking (`_search_filters`, lines 439-473): not archived, one scope, optional
   category, `epistemic_state` (if given, exactly that state; otherwise verified, disputed and candidate,
   and revoked only when asked for by name), and the validity window (`valid_from <= now < valid_until` when `active_only=True`, the default). Entries
   removed here are not counted and not reported: an expired entry is not a `stale` withheld entry, it is
   simply absent (`org_probe.py`, line "4 expired/future in withheld: []"). A caller that passes
   `epistemic_state="candidate"`, as the production query did, searches candidates only: verified and
   disputed entries are not in the pool at all.
2. The best `pool = max(limit * 8, 64)` rows by BM25 are fetched (line 237). `n_matched` is the size of this
   pool, not the number of matches.
3. Conflict isolation among the verified rows of the pool (lines 266-291) -> `conflict_unresolved`.
4. The gate (lines 299-312) -> `below_gate`. A hit is withheld if either test fails:
   - coverage: `coverage_bp = 10000 * (query words that occur as a substring of the lowercased content) /
     (query words)`; withheld if `coverage_bp < min_coverage_bp` (default `DEFAULT_MIN_COVERAGE_BP = 5000`,
     line 59);
   - z-score, only when the pool holds four or more rows: `z_bp = 10000 * (score - mean) / std` over the
     pool's scores, population standard deviation, `0` when `std <= 1e-9`; withheld if `z_bp > z_max_bp`
     (default `DEFAULT_Z_MAX_BP = -5000`, line 62). So a hit must be at least half a standard deviation
     better than the mean of the pool.
5. Staleness (lines 313-321), only if the caller passes `ttl_seconds` -> `stale`.
6. The first `limit` kept rows are returned (line 326). Kept rows beyond `limit` are neither returned nor
   listed in `withheld`; they appear only in `receipt["hits"]` with `kept: true`.

Parameters and where they can be set: `min_coverage_bp`, `z_max_bp` and `ttl_seconds` are keyword arguments
of `recall()` (lines 217-219) and nothing else. There is no constructor argument, environment variable or
`config.py` setting for them (`grep -n "z_max\|min_coverage\|gate" src/kibisis/config.py` prints nothing).
The MCP tool does not take them and calls `recall()` with the defaults
(`src/kibisis/mcp_server.py:557-565`). The pool rule (`limit * 8`, floor 64) and the "four or more" rule are
literals.

What the caller is told: `RecallResult.withheld` holds one `WithheldEntry(ref, reason, sources)` per gated
row of the pool, without content (`models.py:209-213`). The receipt (lines 336-347) holds `n_store`,
`n_matched`, `n_returned`, the three withheld counts, the gate values, and per hit `ref`, `coverage_bp`,
`z_bp`, `kept`, `reason`, `contrasts_with`. It does not say which of the two tests failed, but `coverage_bp`
and `z_bp` are both there, so it can be derived. Over MCP, gated rows are only counted
(`fence_recall`, `mcp_server.py:242-252`: "matches below the relevance gate are only counted"); the refs the
production caller saw came from the plugin, which reads `out.withheld` itself
(`/opt/data/plugins/kibisis-vault/__init__.py:1250-1253`). The plugin passes no gate arguments and says why
(lines 1221-1222): "The recall gate is the operator's: min_coverage_bp / z_max_bp / ttl_seconds are not read
from the model's arguments, so a call cannot loosen it." The operator has nowhere to set them either.

The library's receipt therefore tells which test withheld an entry: the `coverage_bp` and `z_bp` of its
`hits` row. The plugin does not pass those rows on ("The receipt carries counts; per-hit scores stay in the
library", `__init__.py:1250-1251`), so the production caller could not see it. I did not open the live
vault, so I do not know which test it was there; the two candidates are measured below.

### A.2 Reproduction (`review_notes/perf/gate_repro.py`, corpus in `gate_corpus.py`)

340 entries (seed 1110): 80 notes of one project (loop phases, releases, benchmarks, review rounds; 2 to 8
sentences, 20 to 103 words, 8 to 118 days old; keyed `autopoiesis-<aspect>-...`; each rewords some of its
vocabulary), 255 unrelated notes (12 to 62 words), and 5 planted answers (131 to 174 words, 0.6 to 1.7 days
old). Five queries with a planted answer, five with none. 10 seeds, SQLCipher vault, every entry a
model-origin candidate, `match="any"`, `limit=15`, `epistemic_state="candidate"` as the production caller.

Unpatched library, seed 1110:

| query | matched (pool / all) | returned | withheld `below_gate` | of those: coverage only / z only / both | planted answer: BM25 rank, score, coverage_bp, z_bp |
|---|---|---|---|---|---|
| Q1 autopoiesis ... phase closed next | 90 / 90 | 10 | 80 | 8 / 5 / 67 | 10, -10.76, 10000, -15990, kept |
| Q2 telarch release cut ... | 88 / 88 | 10 | 78 | 11 / 0 / 67 | 2, -17.64, 10000, -25795, kept |
| Q3 convention review notes ... | 120 / 200 | 13 | 107 | 6 / 0 / 101 | 4, -13.11, 10000, -26707, kept |
| Q4 LoCoMo head-to-head ... | 26 / 26 | 9 | 17 | 0 / 3 / 14 | 4, -16.58, 10000, -12470, kept |
| Q5 user preference final report ... | 51 / 51 | 1 | 50 | 11 / 0 / 39 | 1, -22.36, 10000, -56584, kept |

All 10 seeds (50 answerable queries):

| corpus | matched | returned mean (min-max) | queries returning <= 2 | withheld mean: coverage only / z only / both | planted answer withheld | BM25 rank of the answer: median, worst |
|---|---|---|---|---|---|---|
| P: as described | 76.0 | 8.36 (1-15) | 10 of 50 | 7.4 / 1.9 / 58.3 | 0 of 50 | 3, 16 |
| P-reworded: each query word with a synonym replaced with p=0.4 | 73 | 7.5 (1-15) | 11 of 50 | 7.7 / 1.1 / 56.7 | 4 of 50 (3 with coverage >= 50%) | 7, 37 |
| H: 79 entries, all on the query's subject, Q1 only (10 queries) | 79 | 15 (15-15) | 0 of 10 | 1.2 / 29.3 / 18.9 | 8 of 10, all with coverage 100% | 32, 74 |

What was reproduced and what was not:

- Reproduced: "matched many, returned 1, the rest `below_gate`" (Q5 in every seed: 49 to 57 matched, 1
  returned; seed 1110: score -22.36 against pool quartiles of -5.86 / -3.04 / -2.5). On this corpus the single
  survivor is single because of the coverage floor: in seed 1110 all 50 withheld rows contain fewer than
  half of the seven query words.
- Reproduced: the needed entry in the withheld list, withheld by the z-test alone (H: 8 of 10, each with
  coverage 100%; P-reworded: 3 of 50, with coverage 67 to 83% and BM25 ranks 6, 8 and 10, so the answer
  was among the ten best matches and was withheld). In H every entry contains the query's words, so
  BM25's IDF collapses: the returned scores are -0.09 to -0.08 and the answer's is -0.04. The z-test
  then separates entries on length and term repetition alone.
- Not reproduced: both at once for the same query on the mixed corpus. On corpus P the planted answer was
  returned in all 50 runs, at a poor rank (Q1, seed 1110: 8th of the 10 returned, 10th by BM25).

Two things the receipts show that the production report did not separate:

1. Most withholding is the coverage floor, not the z-score: 86% of withheld rows fail both tests and a
   further 11% fail coverage alone. A seven-word natural-language query needs four of its words, verbatim
   as substrings, in the content. A note that says "stage 7 is done, upcoming: organization" has none of
   "phase", "closed", "next".
2. Ranking, not the gate, is what keeps the answer out of the top results. With the gate switched off
   entirely the planted answer is no higher (R@1 0.2 on P with every policy that keeps BM25 order). BM25
   normalises by length, which favours a two-sentence note that repeats the query's words over a 140-word
   closeout (my reading of the ranks; I did not vary length in isolation); and nothing prefers the note written yesterday over the one from three months ago.

Two further corpora are in the script's output and change none of the conclusions: P0 (P without the four
overview entries) and A (verbatim wording, everyday words in every background note; 106 matched on
average, the answer never withheld).

The same query at other limits (seed 1110): the z-score of one hit changes with `limit` because the pool
does. Corpus H, planted answer: `z_bp = -213` at limit 1 to 8 (pool 64 of 79 matches), `-2426` at limit 10
and above. In 3 of 10 seeds on H and 2 of 10 on P-reworded the answer passes the gate at one limit and
fails at another.

### A.3 Defect or design?

The behaviour as a whole is the documented design, at a bad operating point for a vault whose entries share
a vocabulary. The contract says so in as many words:

- README.md:19: "The model-facing `recall()`, which the MCP server uses, also holds back verified memories
  that conflict and matches that cover too little of the query, and says what it held back."
- README.md:118: "matches that contain under half of the query's words, or that do not stand out from four
  or more other matches, are only counted".
- CHANGELOG.md:289-291: "A hit is returned only if it covers at least `min_coverage_bp` of the query's words
  (default 50%) and, with four or more matches, its BM25 z-score among the matched set is at most `z_max_bp`
  (default -0.5): a crowd of tied scores carries no evidence and is dropped, so false accepts stay flat as
  the store grows."

"Do not stand out from the other matches" is exactly what happens to 77 project notes that all mention the
project. Returning 1 of 78 is the gate working as written.

Three details do contradict the written contract, and have failing tests (section E):

1. The z-score and `n_matched` are taken over the fetched pool, not over "the matched set", so the verdict
   for a hit depends on `limit` (`tests/rv1110_gate_pool_truncation.py`).
2. Coverage is a raw substring test on the content only, while the match that produced the hit is FTS5 over
   category, key, content and scope with accent folding. An entry keyed `autopoiesis-loop-phase-7-closeout`
   whose text uses other words matches all three query words and is withheld with `coverage_bp = 0`
   (`tests/rv1110_gate_coverage_content_only.py`). Keys are where an agent puts the project vocabulary, so
   this bears on the production case in both directions: see the measurement in A.4.
3. The `recall()` docstring says every call is journaled as a `recall` event; none is written
   (`tests/rv1110_recall_not_journaled.py`; the likely fix is the docstring).

What the gate protects (commit 2656937, 2026-10-29, "K-R3/K-R4/K-R5: recall() with conflict isolation,
size-aware gate, receipts"; `tests/test_recall_layer_kr345.py:150-168`): a query that shares one common word
with many entries must return nothing at any store size (`test_false_accepts_stay_flat_across_store_size`,
N = 8, 64, 512), while the one real answer is still returned
(`test_the_one_real_answer_is_returned_at_any_store_size`). The comment there: "A fixed absolute threshold
lets false accepts climb with N; the gate must not." In that test the query has three words and the fillers
share one, so the coverage floor alone (33% < 50%) already rejects them. The z-test is what
rejects them for a shorter query, where one shared word reaches 50%. Measured on the same store
(`review_notes/perf/gate_cost.py`; no entry answers the query, so every result is a false accept; the
z-test is switched off with the keyword argument `z_max_bp=10**9`):

| N | query | returned, default gate | returned, z-test off | with the real answer added: default / z-test off |
|---|---|---|---|---|
| 8, 64, 512 | alpha mainframe reactor (3 words) | 0, 0, 0 | 0, 0, 0 | 1 (the answer) / 1 (the answer) |
| 8, 64, 512 | alpha mainframe (2 words) | 0, 0, 0 | 8, 10, 10 | 1 (the answer) / 9, 10, 10 (the answer first) |
| 8, 64, 512 | alpha (1 word) | 0, 0, 0 | 8, 10, 10 | 0 / 9, 10, 10 |
| 8, 64, 512 | alpha bravo (2 words, both common) | 1, 10, 10 | 8, 10, 10 | 6, 10, 10 / 9, 10, 10 |

So the z-test is what keeps a one- or two-word query from returning a full page of entries that share one
common word with it, and it does so at any store size. It does not help when both words are common (last
row). A one-word query returns nothing under the default gate even when an entry holding the word exists,
because all scores tie.

### A.4 Proposals, measured

Each policy replaces the decision rule inside a monkeypatched `recall()` that fetches the same pool; the
"current" row goes through the same patch and is asserted equal to the unpatched library on every query.
R@k: the planted answer is among the first k returned. "Unanswerable": the five queries with no answer in
the vault, 50 runs; fewer results is better. "Old answer": four queries whose right answer is a 60 to 120
day old overview entry.

Corpus P (50 answerable queries, limit 15):

| policy | R@1 | R@3 | R@5 | R@10 | returned / query | unanswerable queries with any result | results per unanswerable query | old answer R@1 / R@3 |
|---|---|---|---|---|---|---|---|---|
| current (coverage >= 50% and z <= -0.5) | 0.20 | 0.60 | 0.80 | 0.94 | 8.36 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| gate off (BM25 top 15) | 0.20 | 0.60 | 0.80 | 0.88 | 15 | 40 of 50 | 12 | 1.0 / 1.0 |
| coverage floor only (no z-test) | 0.20 | 0.60 | 0.80 | 0.94 | 9.98 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| coverage floor + score >= 50% of the best score | 0.20 | 0.60 | 0.80 | 0.94 | 7.12 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| IDF-weighted coverage + score >= 50% of best | 0.20 | 0.60 | 0.80 | 0.94 | 6.74 | 0 of 50 | 0 | 1.0 / 1.0 |
| current + guaranteed minimum of 3 | 0.20 | 0.60 | 0.80 | 0.94 | 8.36 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| coverage floor + recency re-rank (score x (1 + 0.5 x 2^(-age/30d))) | 0.40 | 0.86 | 0.94 | 1.00 | 9.98 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| coverage floor + strong recency (score x (1 + 2 x 2^(-age/14d))) | 1.00 | 1.00 | 1.00 | 1.00 | 9.98 | 8 of 50 | 0.36 | 0.38 / 0.9 |
| score >= 50% of best + recency re-rank | 0.40 | 0.86 | 0.94 | 1.00 | 7.12 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| current, query words in the key counted as covered | 0.20 | 0.60 | 0.80 | 0.88 | 10.44 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| key+content coverage floor only | 0.20 | 0.60 | 0.80 | 0.88 | 11.6 | 8 of 50 | 0.36 | 1.0 / 1.0 |
| key+content coverage floor + recency re-rank | 0.40 | 0.86 | 0.94 | 1.00 | 11.6 | 8 of 50 | 0.36 | 1.0 / 1.0 |

Corpus P-reworded (the caller does not remember the notes' words):

| policy | R@1 | R@3 | R@5 | R@10 | returned / query |
|---|---|---|---|---|---|
| current | 0.20 | 0.28 | 0.44 | 0.88 | 7.5 |
| gate off | 0.20 | 0.26 | 0.36 | 0.76 | 15 |
| coverage floor only | 0.20 | 0.28 | 0.46 | 0.94 | 8.5 |
| coverage floor + score >= 50% of best | 0.20 | 0.26 | 0.44 | 0.80 | 7.34 |
| IDF-weighted coverage + score >= 50% of best | 0.22 | 0.28 | 0.48 | 0.80 | 6.24 |
| coverage floor + recency re-rank | 0.34 | 0.66 | 0.82 | 0.98 | 8.5 |
| coverage floor + strong recency | 0.84 | 0.98 | 0.98 | 0.98 | 8.5 |
| score >= 50% of best + recency re-rank | 0.34 | 0.64 | 0.76 | 0.82 | 7.34 |
| current, query words in the key counted as covered | 0.20 | 0.26 | 0.36 | 0.80 | 8.86 |
| key+content coverage floor only | 0.20 | 0.26 | 0.36 | 0.86 | 10.06 |
| key+content coverage floor + recency re-rank | 0.34 | 0.62 | 0.78 | 0.96 | 10.06 |

Corpus H (everything is on the subject; 10 queries): every policy that keeps BM25 order has R@10 = 0, because
the answer's BM25 rank is 32 (median). Only the strong recency re-rank finds it (R@3 0.3, R@5 0.8, R@10
1.0). Returning the ten best withheld rows as one-line digests would put the answer in front of the caller
in 7 of 10 runs under the current gate (10 of 10 with strong recency).

Reading the tables:

- A guaranteed minimum of k changes nothing here. The queries that return one result do so because nothing
  else passes the coverage floor, and a minimum that ignores the floor is the "gate off" row.
- Dropping the z-test costs nothing on false accepts in this set (8 of 50 either way) and gains R@10 0.88 ->
  0.94 on reworded queries. It removes the `limit` dependence of the verdict. Cost: the protection for one- and
  two-word queries measured in A.3 (0 false accepts becomes a full page), which this set of five- to
  eight-word queries does not exercise. Keeping the z-test for queries of fewer than three content words
  and dropping it above would keep both; I did not measure that combination.
- "Relative to the best score" is no better than the z-test here, and worse on reworded queries (R@10 0.80).
- IDF-weighted coverage is the only change that removes the false accepts (8 -> 0 of 50): "autopoiesis"
  counts for more than "next". Cost: one document-frequency lookup per query word, and R@10 0.80 on reworded
  queries with the 50%-of-best rule attached; I did not measure it with the floor alone.
- Counting query words found in the key as covered (the repair for failing test 2) makes recall slightly
  worse on this corpus: R@10 0.94 -> 0.88 on P and 0.88 -> 0.80 on P-reworded, with one to two more results
  per query. The crowd's keys all carry the project's name, so more of the crowd passes the floor and the
  answer moves down. With the mild recency re-rank on top it is level with content-only coverage on P
  (R@10 1.00) and a little below on P-reworded (0.96 against 0.98). This corpus has no entry whose content
  lacks the query's words while its key holds them, which is the case the repair is for
  (`tests/rv1110_gate_coverage_content_only.py` builds one).
- A recency term is the largest gain and the only one that touches R@1 to R@5. The mild one costs nothing
  measurable on old answers; the strong one finds every recent answer and loses the old ones at rank 1
  (1.0 -> 0.38). Cost: a state note written yesterday outranks the charter it restates, so "what is the rule"
  queries degrade as "what is the latest state" queries improve. A per-call switch
  (`prefer_recent=True`) or per-category setting would let the caller say which question it is asking.

Recommendation, in order: (1) add an opt-in recency re-rank to `recall()`: it is the only measured change
that moves the right answer up, and the mild form cost nothing on the old-answer queries; (2) return a
one-line digest for the best few withheld rows in the receipt, so the caller does not have to guess keys
(the answer was within the returned rows plus ten digests in 50 of 50 runs on P, 49 of 50 on P-reworded and
7 of 10 on H under the current gate); (3) take the z-score over the whole matched set, or keep it only for
short queries, checked first against `tests/test_recall_layer_kr345.py`; (4) make coverage agree with the
index (key, tokens), knowing it admits more of a crowd whose keys share a prefix. Give the operator one
place to set the gate. None of these was run against the existing suite: they are monkeypatches in a
measurement script, and the absolute figures belong to this synthetic corpus.

Assumptions for section A: the production vault is SQLCipher (FTS5 path); the term-index path used by a
passphrase vault without SQLCipher (`_term_rows`, line 531) computes its own scores and was not examined.
The synthetic corpus is mine; its vocabulary overlap was tuned so that a project query matches about 80
entries, and the absolute recall figures depend on that tuning.

## B. Organization primitives: API reference for a consolidation job

All of this was read in the source and then run: `review_notes/perf/org_probe.py`, and two shorter probes
beside it, `org_probe_cascade.py` and `org_probe_extra.py`, whose results are quoted here.
`SQLiteMemoryVault` is one class assembled from mixins; every method below is a method of it.

### B.1 Listing with metadata

`list_entities(category=None, include_archived=False, scope="default", epistemic_state=None,
as_of_valid_time=None, include_unverified=False, active_only=False) -> List[MemoryEntity]`
(`src/kibisis/vault.py:2471`).

- Filters: category (exact), scope (exact, or `"*"` for all), one epistemic state, validity at a time.
  The default returns verified and disputed entries only; `include_unverified=True` returns every state,
  revoked included (line 2501). Order is `category, key`.
- Each `MemoryEntity` (`models.py`) carries `category, key, content, metadata, id, version, archived,
  created_at, updated_at, epistemic_state, valid_from, valid_until, scope, tenant_sig, origin, source_ref,
  confidence, supersedes, superseded_by`.
- It always returns the content: every row is decrypted and integrity-checked (lines 2515-2520). There is
  no metadata-only listing, no limit or offset, no key-prefix filter, no "changed since" filter.
- `sensitivity` is not a library concept. No source file under `src/kibisis/` contains the word
  "sensitiv" or "confidential". The plugin keeps it as a free-form metadata key and filters in Python
  after reading the content (`/opt/data/plugins/kibisis-vault/__init__.py:585, 814`). So a job cannot list
  entries without the library handing it confidential content.
- `search_keys(query, ...) -> List[SearchHit]` (`_vault_search.py:366`) returns `category, id, key,
  rank_score, scope` without content, but it needs a full-text query and returns no metadata.
- `get(category, key, scope="default") -> Optional[MemoryEntity]` (`vault.py:2367`) returns archived
  entries too (`archived=True`).

### B.2 Writing a candidate with provenance

`put(category, key, content, metadata=None, epistemic_state=None, valid_from=None, valid_until=None,
scope="default", author_id=None, tenant_id=None, principal_id=None, derived_from=None, fencing_token=None,
resource=None, holder_id=None, supersedes_key=None, supersedes_category=None, auto_gate=None,
trust_ceiling=None, origin=None, source_ref=None, confidence=None, act_class=None, revive=False,
conflicts_with=None, contrasts_with=None, attester=None) -> MemoryEntity` (`vault.py:1965`).

Observed for `origin="model"`:

- The entry is a `candidate` whatever `epistemic_state` asks for; `origin`, `source_ref` and `confidence`
  are stored as given; metadata gains `origin_class: "agent"`, `act_class: "inform"`, `author_id`.
- Free-form metadata keys are kept as written (`topic`, `sensitivity`, `summarizes`, ...). Keys in
  `RESERVED_METADATA_KEYS` (`vault.py:111`: `human_reviews, tenant_id, principal_id, origin_class,
  act_class, act_class_capped_from, attestations, verification_pending, trust_inherited_from,
  conflicts_with, contrasts_with`, and anything starting `lineage_`) are dropped from the payload. Keys in
  `PRINCIPAL_METADATA_KEYS` (`vault.py:125`: `author_id, last_verified_at, supersession,
  proposed_supersedes, slot`) are moved under `metadata["agent_metadata"]`, where nothing reads them.
- `derived_from=["category:key", ...]` is stored in metadata and has effects (B.3). `conflicts_with=[...]`
  is accepted from a model writer and stored.
- A write with unchanged content still raises `version` (2 -> 3 observed): no idempotence, no dedup.
- A put on an archived key brings it back (`archived=False`, version + 1).

### B.3 Supersession and the dependency cascade

`put(..., supersedes_key=K, supersedes_category=C)`; the code is `vault.py:1747-1843`, the outcome is
reported in `entity.metadata["supersession"] = {"outcome", "target"}`.

- Applied (`outcome: "applied"`) when the writer is principal-class, or its class is at least the target's
  and no person has reviewed the target (lines 1765-1769). The superseded row is kept: `epistemic_state`
  becomes `revoked`, `valid_until` is set to now, `superseded_by` is set, `archived` stays 0. The new row
  has `supersedes` set.
- Otherwise the new entry is stored as a proposal (`outcome: "needs_confirmation"`), the target stays
  active and gains `metadata["pending_supersession_by"]`. A model superseding a user-verified entry gets
  this.
- The superseded row is out of `recall()` and of default `search()` twice over: it is revoked and its
  validity window has closed. `search(..., epistemic_state="revoked", active_only=False)` finds it;
  `list_entities(include_unverified=True)` lists it.
- The chain is two columns, `supersedes` and `superseded_by`, each holding one `category:key`. There is no
  method that walks it; a caller follows the links with `get()`. One entry can supersede one entry: there
  is no many-to-one supersession, so a summary cannot supersede the five notes it replaces.
- Refusals: writing to a superseded key raises `SupersededEntryError` (`vault.py:196`; only a principal may
  pass `revive=True`); superseding an already superseded or missing key raises `SupersessionRefused`
  (`vault.py:191`).
- Journal actions seen: `put`, `supersession`, `supersede`, `state_transition`, `refuse`.

`derived_from` and `_cascade_invalidate` (`_vault_review.py:214`; called on supersession `vault.py:1840`,
archive `vault.py:2437`, a person's verdict `_vault_review.py:521`, and a write that revokes `vault.py:1954`; `purge()` does not
call it):

- Every active entry that lists a retired entry in `derived_from` becomes `disputed` with
  `metadata["invalidated_by"]`, and so on through its dependents.
- Observed, and this is the one that bites: a model writes a summary with `derived_from=[s1, s2, s3]`,
  then archives `s1`. The summary is now `disputed`. Rewriting the summary makes it `candidate` again;
  archiving `s3` disputes it again. `purge()` of a source did not cascade.
- A summary a person verified is not changed by a model's archive: it receives
  `metadata["invalidation_notice"] = [{"at", "by_class": "agent", "retired"}]` and stays verified.

### B.4 Validity windows and `stale`

- `valid_from` / `valid_until` are arguments of `put()`, accepted from a model writer. `search()` and
  `recall()` default to `active_only=True`; `list_entities()` defaults to `active_only=False`.
- An entry outside its window is absent from `recall()`: not returned, not counted, not listed as withheld.
- `stale` is something else: `recall(..., ttl_seconds={"agent": seconds, "external": ..., "principal": ...})`
  (`_vault_search.py:313-321`) withholds a hit whose class has a TTL and whose
  `metadata.last_verified_at`, else `updated_at`, else `created_at` is older than it. With no `ttl_seconds`
  nothing is ever stale. The MCP server and the plugin pass none, so `stale` cannot occur in production
  today. `last_verified_at` is a principal-only metadata key: a model cannot refresh it except by rewriting
  the entry, which moves `updated_at`.

### B.5 Conflicts

`conflict_unresolved` is decided inside `recall()` (`_vault_search.py:266-291`), among verified hits only:

1. a verified hit names another verified, non-archived entry in `metadata["conflicts_with"]` (set with
   `put(conflicts_with=[...])`); both are withheld, each with the other in `sources`;
2. two or more verified hits of one category have the same `metadata["slot"]` and different content.

Candidates are never in conflict: a candidate that contradicts a verified pair is returned while the pair
is withheld. Nothing compares content: the vault does not detect a contradiction, it records one that a
writer declared. A model cannot set `slot` (moved under `agent_metadata`). There is no method that lists
the conflicts in a vault; they appear only in a recall that happens to match both sides.

### B.6 Compaction, dedup, zombies

None exists. The words `compact`, `zombie`, `dedup`, `merge` and `consolidat` occur nowhere under
`src/kibisis/`. Identical content under two keys is stored twice. What does exist:

- `archive(category, key, scope="default", author_id=None, fencing_token=None, resource=None,
  holder_id=None, origin=None) -> bool` (`vault.py:2391`): sets `archived = 1`, cascades to dependents.
- `purge(category, key, scope, author_id, fencing_token, resource, holder_id, origin) -> bool`
  (`_vault_tombstone.py:133`): deletes the row.
- `tombstone(category, key, reason="revocation", author_id=None, content=None, scope="default", ...) -> str`
  (`_vault_tombstone.py:308`) and `list_tombstones(category=None, scope=None)` (`:604`): rejected values
  that must not come back.
- `scrub()` (`_vault_tombstone.py:627`): checkpoint and `VACUUM`.
- `export_snapshot(path=None, scope=None)` / `import_snapshot(snapshot_or_path, *, clear_existing=False,
  ...)` (`_vault_snapshot.py:37, 225`).
- Leases for a job that must not run twice: `FileLeaseCoordinator.acquire(resource, holder_id,
  ttl_seconds) -> Lease` (`lease.py:55, 67`); the write methods take `fencing_token, resource, holder_id`.

### B.7 Access statistics

None are kept. No column, metadata key or journal event records a recall: the search for
`last_recalled|last_access|hit_count|recall_count|access_count` under `src/kibisis/` finds nothing.

- `recent_recalls(limit=100)` (`_vault_search.py:361`) returns up to 1000 records held in memory by this
  process (`vault.py:478`): `actor, at, channel, n_matched, n_returned, n_store, n_withheld_*,
  query_sha256_12, scope, withheld`. It holds the withheld refs and not the returned ones, and it is gone
  when the process exits.
- The durable copy is the Argus event `kibisis.memory_recall`, written only when `ARGUS_LEDGER_PATH` is set.
- The vault journal has no recall events, although the `recall()` docstring says it does (failing test 3).
- `list_audit_events(scope=None, category=None, limit=100, key=None) -> List[AuditEvent]`
  (`_vault_audit.py:349`) returns the oldest `limit` events (`ORDER BY sequence ASC LIMIT ?`; observed:
  `limit=2` returns sequences 1 and 2). There is no offset or "since sequence": to read the newest events a
  job must ask for all of them. An event holds `sequence, timestamp, action, category, key, scope,
  value_sha256, prev_hash, event_hash, author_id, metadata`; a put's metadata is
  `{"epistemic_state", "version"}`.

### B.8 Origin, reviewer origin, and what a model writer is refused

- `origin` is one of `ORIGINS = ("user", "model", "tool", "import", "unknown")` (`_vault_review.py:23`),
  stored in the `origin` column. The vault derives `metadata["origin_class"]` from it
  (`origin_class_of`, `_vault_review.py:35`; classes `external < agent < principal`, line 29).
- A person's verdict is appended to `metadata["human_reviews"]` as `{timestamp, reviewer_id, verdict,
  notes, previous_state, reviewer_origin}` plus `reviewer_label` when it differs
  (`_vault_review.py:481-492`).
- Refused to a model-origin caller, as observed:

| attempt | result |
|---|---|
| `put(epistemic_state="verified")` | stored as `candidate`, no error |
| reserved or principal-only metadata keys | dropped, or moved under `agent_metadata`; logged, no error |
| overwrite a principal-class entry | `OriginClassError` |
| supersede a user-verified entry | stored as a proposal, `needs_confirmation` |
| archive or purge a user-verified or reviewed entry | `ReviewedEntryError` |
| archive its own candidate | allowed |
| `review_entity(...)` with a non-user `reviewer_origin` (`_vault_review.py:408`) | `PermissionError`, nothing recorded |
| the promote-to-verified method (`_vault_review.py:345`) with a non-user `reviewer_origin` | `AdmissionRefused` per its docstring and code (lines 365-371); not run here |

### B.9 Gaps that would bite a consolidation job

1. No way to list without content, so a job that only needs keys, states and dates still decrypts every
   entry and is handed the confidential ones. Measured cost in section C: 383 ms for 10,160 rows.
2. Linking a summary to its sources has one mechanism, `derived_from`, and it works against the job:
   archiving a source disputes the summary. The alternatives are a free-form metadata key (kept, but not
   indexed and not queryable) or never retiring the sources.
3. No many-to-one supersession. Retiring five notes in favour of one summary is five archives (each one
   disputing a `derived_from` summary) or a chain of single supersessions.
4. No access statistics, so "never recalled in 90 days" cannot be computed from the vault. The Argus
   ledger has the withheld refs per recall and not the returned ones.
5. No "changed since" listing and no journal cursor: each pass re-reads the category, and reading the
   newest journal events means reading all of them.
6. A model-origin job can only produce candidates. A summary of five verified notes is a candidate; with
   the production caller's `epistemic_state="candidate"` filter it is searched, without that filter it
   competes with the verified notes it summarises under the same gate.
7. Retiring is slow in a large vault: a plain put is 1.9 ms at any size, but each archive or superseding
   put scans every live row of the scope (section C: 152 ms at 50,000 entries), so a pass that retires
   thousands of entries takes minutes.
8. No dedup and no version history: a rewrite replaces the content, raises `version`, and the old text is
   gone (the journal keeps its hash only).
9. Conflicts cannot be enumerated, and `stale` needs a TTL nobody passes.

Assumptions for section B: "model-origin" means `origin="model"`; a `tool` or `unknown` origin is the lower
`external` class and was not probed. Tenant and principal scoping (`tenant_id`, `principal_id`,
`authorized_lineage_roots`) were left alone as security-review ground.

## C. Performance (Kibisis)

Scripts: `review_notes/perf/bench_vault.py <N> profile` (results in `bench_results_<N>.json`),
`bench_proposals.py`, `bench_retire.py`, `bench_fts_rank.py`. SQLCipher vaults of N model-origin candidates, five categories,
25 to 70 words each, a 6000-word made-up vocabulary plus a project vocabulary in a quarter of the entries.
One run per size on a shared box; treat differences under about 20% as noise.

Median / p95 in ms unless a unit is given; 60 calls each (list: 10).

| operation | 1,000 | 10,000 | 50,000 |
|---|---|---|---|
| build the vault, s | 2.1 | 20.8 | 108.4 |
| file size, MB | 2.4 | 21.5 | 107.0 |
| open, s | 0.152 | 0.156 | 0.189 |
| `recall(match="any", limit=10)` | 14.7 / 20.7 | 121.0 / 205.8 | 594.1 / 826.5 |
| - queries in the project vocabulary (median) | 16.8 | 150.2 | 684.3 |
| - queries of rare words (median) | 4.1 | 88.3 | 425.4 |
| `recall(match="all", limit=10)` | 2.3 / 2.7 | 82.5 / 87.6 | 416.4 / 431.9 |
| `search(match="any", limit=10)` | 6.6 / 10.1 | 34.7 / 112.3 | 162.6 / 399.0 |
| - rare words (median) | 3.3 | 4.5 | 13.3 |
| `search_keys(match="any", limit=10)` | 4.7 / 7.0 | 28.8 / 86.9 | 146.2 / 330.9 |
| `get` | 0.077 / 0.100 | 0.095 / 0.122 | 0.113 / 0.131 |
| `put`, new key | 1.74 / 3.31 | 1.77 / 3.75 | 1.88 / 3.23 |
| `put`, existing key | 1.79 / 2.72 | 1.83 / 2.82 | 1.95 / 2.80 |
| `archive`, or `put` with `supersedes_key` (median of 8) | not measured | not measured | 152.1, 152.4 |
| `list_entities(category=...)` (rows returned) | 5.8 / 6.3 (200) | 74.8 / 80.2 (2,000) | 403.6 / 412.9 (10,000) |
| `list_entities(scope)` all rows, s | 0.034 | 0.409 | 2.239 |
| `list_audit_events(limit=1000)` | 7.6 | 7.9 | 9.0 |
| `verify_audit_chain`, s (events) | 0.015 (1,120) | 0.135 (10,120) | 0.689 (50,120) |

`get` and plain `put` do not grow with the vault. `recall` grows linearly, and at 50,000 entries costs 0.4 s
even for a query that matches almost nothing.

Native module: `kibisis_native` is loaded and used for the journal's event hash and head MAC
(`src/kibisis/_vault_audit.py:83, 93`) and for the lease coordinator (`src/kibisis/lease.py:65`). It is not
on the search or recall path, which is FTS5 inside SQLCipher (`search_path: fts5 entities_search` in every
run). `kibisis_native.verify_chain` exists; `verify_audit_chain` (`_vault_audit.py:396`) runs its loop in
Python and calls the native hash once per row.

Hot spots (cProfile at 50,000 entries):

| operation | where | share |
|---|---|---|
| recall, 60 calls, 36.5 s | `_vault_search.py:246-251`, the `SELECT COUNT(*) ... archived = 0 AND epistemic_state != 'revoked' AND scope = ?` that fills `n_store` in the receipt | 24.3 s, 67% |
| | `_vault_search.py:518`, the FTS5 query of `_indexed_rows` | 12.1 s, 33% |
| | the gate itself (coverage, z-score, opening 80 entries: `_vault_crypto.py:482`) | under 0.3 s, under 1% |
| archive, 8 calls, 1.20 s | `_vault_review.py:239-243`, `_cascade_invalidate`: `metadata_json LIKE '%"cat:key"%'` over every live row of the scope | 1.18 s, 99% |
| put, 100 calls | `commit` 0.10 s; 14 statements per put 0.08 s; `_vault_crypto.py:99 canonicalize_text` 0.06 s | flat in N |
| list one category, 2 calls of 10,160 rows | `fetchall` 0.22 s; `vault.py:2440 _entity` 0.30 s; `_vault_crypto.py:482 _open_entry` 0.58 s cumulative | |
| verify, 50,220 rows, 0.90 s | `_vault_audit.py:396` own time 0.20 s; `kibisis_native.event_hash_v3` 0.20 s; `fetchall` 0.11 s | |

Proposals, measured on a scratch copy of the 50,000-entry vault where stated:

| # | change | measured | cost |
|---|---|---|---|
| 1 | Make the `n_store` count cheap: an index on `entities(scope, archived, epistemic_state)`, or a counter kept in `vault_meta`, or compute it only when a caller asks | Count 395 ms -> 3.8 ms with the index (the plan changes from `idx_entities_supersedes (scope=?)` plus a row read each, to a covering index). `recall` for one project query 600.5 ms -> 190.9 ms | One more index to maintain on every write (not measured); `n_store` is only reported, never used by the gate |
| 2 | Retire without a table scan: keep `derived_from` edges in their own indexed table, or skip the scan when the scope has no `derived_from` entry | Not measured. `_cascade_invalidate` is 148 of the 150 ms; a plain put is 1.6 ms | A schema migration; the edge table must be written under the same transaction as the entry |
| 3 | A listing without content: keys, state, version, times, validity, supersession links, metadata | 383 ms -> 111 ms for 10,160 rows, timing the same SELECT without content, envelope and integrity check | Skips the per-entry integrity check, so a tampered row would be listed; closes gap 1 of B.9 |
| 4 | Rank fewer rows in FTS5. A project query matches 10,106 of 50,000 entries; counting them takes 3.5 ms, ranking them to take the best 80 takes 116 ms (index alone; 153 ms joined to `entities`). Prefix matching is not the cost (123 ms with `"word"*`, 114 ms with `"word"`) | Not measured: drop query words whose document frequency is above a threshold when rarer words remain | Changes which entries match; needs the recall tests |
| 5 | One transaction for a batch of puts | Not measured; `commit` is about half of a put | A new API; a failed batch rolls back together |
| 6 | `verify_audit_chain` through `kibisis_native.verify_chain` | Not measured; 0.69 s for 50,000 events today | Low priority |

At the production size (338 entries) none of this is visible: the 1,000-entry vault recalls in 15 ms.

Assumptions for section C: synthetic content is shorter and more uniform than real notes; entries are
written once and not updated, so the FTS index has no tombstones. Timings include SQLCipher page
decryption with the library's default settings.

## D. Argus ledger (secondary)

Argus head `632b548`, `src/argus_ledger/ledger.py`. Script: `review_notes/perf/bench_argus.py 100000`
(results in `bench_argus_results.json`) and `... 100000 unsigned` (`bench_argus_unsigned_results.json`).
Events are `kibisis.memory_recall` records of about 1 KB. The Argus worktree was only read.

| measurement, 100,000 events | HMAC-signed ledger (106.5 MB) | unsigned ledger (90.2 MB) |
|---|---|---|
| append, all events | 87.9 s, 1,138 per second | built with fsync off, not timed |
| one append, first 1,000 / last 1,000 (median) | 0.838 ms / 0.823 ms | |
| one append with `os.fsync` replaced by a no-op | 0.054 ms | |
| `verify_chain()` | 1.42 s (Python verifier) | 0.32 s native; 1.14 s with `ARGUS_LEDGER_PURE_PYTHON=1` |
| `iter_events()` over all | 0.35 s | |
| `head()` / `len()` | 0.014 ms / 0.012 ms | |
| `get_event(1)` / `get_event(100000)` | 0.03 ms / 350.3 ms | |
| `iter_events(start=99901)` (the last 100) | 352.5 ms | |
| Python heap peak during verify and during iteration (tracemalloc) | 1.32 MB | |
| process RSS after append, verify, iterate | 38.3 MB, unchanged | 36.1 MB |

- Nothing is O(n) per append. `append()` (`ledger.py:249`) reads only the last record by reading backwards
  from the end of the file (`_tail_record`, `ledger.py:34-40`), and the first and last thousand appends cost
  the same. The whole file is read on append only to build the message of an error about a corrupted tail
  (`_count_records`, `ledger.py:67`).
- Append is bound by `os.fsync` (`ledger.py:337`): 0.84 ms with it, 0.054 ms without, so about 94% of an
  append is the flush. With a ledger configured, every Kibisis recall pays one.
- Verification and iteration hold one record at a time: memory does not grow with the ledger.
- `get_event(sequence)` (`ledger.py:382-386`) and `iter_events(start=...)` (`ledger.py:459-465`) parse
  every record from the start of the file: reading the newest event costs as much as reading all of them.
- The native verifier is used for unsigned and Ed25519 ledgers; an HMAC-signed ledger is verified in
  Python because the Rust crate has no HMAC scheme (`ledger.py:514-519`).

Proposals:

| # | change | expected gain | basis | cost |
|---|---|---|---|---|
| 1 | Tail reads without a full parse: a sparse in-memory offset index (one entry per 1,000 records), or read backwards when `start` is near the head | 350 ms -> a few ms for the last 100 events at 100,000 | Not measured; `_tail_record` already reads the last record in 0.014 ms | The index must be rebuilt or extended under the shared lock when the file has grown |
| 2 | `append_many(events)` with one flush per batch | From 1,138 per second towards 18,000 per second for a batch writer | Computed from the measured 0.054 ms append without the flush; not measured as an API | Events of an unflushed batch are lost together in a crash; the chain stays consistent |
| 3 | HMAC in the native verifier | About 3.5 times faster verification of signed ledgers | Ratio measured on the unsigned ledger, 1.14 s -> 0.32 s | Rust work in the other repository |

Assumption for section D: one writer process; lock contention between processes was not measured.

## E. Failing tests

Each asserts a sentence of the documented contract and fails on `0d734c3`; each file has a passing control,
so a failure is not a broken fixture. Run one at a time with
`env -u KIBISIS_PASSPHRASE -u KIBISIS_PASSPHRASE_FILE -u KIBISIS_SRC -u CI PYTHONPATH=src
/opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/rv1110_<name>.py`.

| file | severity | exit code | result | contract quoted |
|---|---|---|---|---|
| `tests/rv1110_gate_pool_truncation.py` | medium | 1 | 2 failed, 1 passed. "receipt counts 64 of 150 matches"; "36 hits pass the gate at limit=40 and fail it at limit=5" | `_vault_search.py:225-228`: "its BM25 z-score among the matched set is at most ``z_max_bp``"; CHANGELOG.md:293: "The receipt carries `n_store`, `n_matched`, the counts withheld by reason," |
| `tests/rv1110_gate_coverage_content_only.py` | medium | 1 | 2 failed, 1 passed. "matched all three words, coverage_bp=0, reason='below_gate'" (words in the key; words matched through accent folding) | README.md:118: "matches that contain under half of the query's words, or that do not stand out from four or more other matches, are only counted" |
| `tests/rv1110_recall_not_journaled.py` | low | 1 | 1 failed, 1 passed. "journal actions after one recall: ['put']" | `_vault_search.py:230-232`: "K-R5: every call is journaled as a ``recall`` event and mirrored to Argus as ``kibisis.memory_recall``" |

The third contradicts a docstring that the code comment at `_vault_search.py:354-355` and the existing test
`test_recall_does_not_write_to_the_vault_journal` contradict in turn; the docstring is the likely fix.

The existing suite was run once with these files present: 1295 passed, 5 skipped (the finding files are not
collected). Nothing under `src/` or among the existing tests was changed.

## F. Files

- `review_notes/RECALL_ORG.md` (this note)
- `review_notes/perf/gate_corpus.py`, `gate_repro.py`, `gate_repro_results.json`: section A.2 and A.4
- `review_notes/perf/gate_cost.py`: section A.3, what the z-test protects
- `review_notes/perf/org_probe.py`, `org_probe_cascade.py`, `org_probe_extra.py`: section B
- `review_notes/perf/bench_vault.py`, `bench_results_1000.json`, `bench_results_10000.json`,
  `bench_results_50000.json`, `bench_proposals.py`, `bench_retire.py`, `bench_fts_rank.py`: section C
- `review_notes/perf/bench_argus.py`, `bench_argus_results.json`, `bench_argus_unsigned_results.json`:
  section D
- `review_notes/perf/_probe.py`: a first smoke probe, superseded by the scripts above
- `tests/rv1110_gate_pool_truncation.py`, `tests/rv1110_gate_coverage_content_only.py`,
  `tests/rv1110_recall_not_journaled.py`
