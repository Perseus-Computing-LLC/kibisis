# R3 — third-pass adversarial review, AREA A+B seams (merged fixes at 98c6f99)

Worktree `/opt/data/cache/scratch/kib-review3`, detached at `98c6f99` (branch `fix/review-integration`).
Nothing under `src/` or the existing tests was changed. Repro tests: `tests/review3_ab_migration.py`,
`tests/review3_ab_snapshot.py`, `tests/review3_ab_tombstones.py` (not collected by default; run by path).
Convention: `test_control_*` asserts the secure behaviour (failing = bug); `test_attack_*` demonstrates a
defect (passing = bug).

```
cd /opt/data/cache/scratch/kib-review3 && ARGUS_LEDGER_PATH=$TMPDIR/argus_r3ab.jsonl PYTHONPATH=src \
  /opt/data/work/telarch-suite/.venv/bin/python -m pytest -q -p no:cacheprovider tests/review3_ab_*.py
31 passed in 4.99s
```
(All controls pass = the R2 fixes hold on those paths; all attacks pass = the defects below exist.)

Severity scale as in REVIEW.md: critical = agent-reachable, defeats a core guarantee, no recovery; high =
agent/file-writer reachable, defeats a documented guarantee; medium = needs a library caller / passphrase
holder / unlikely precondition, or partial defeat; low = hygiene or overstated docs. Threat model
SECURITY.md:31-38 (file writer = r/w on the plain-SQLite file without the passphrase, `allow_plaintext`).

---

## Findings (most severe first)

### R3-AB1 — A lower-class tombstone lifted by a write under another key/scope wedges the vault: every later open raises `VaultIntegrityError` — **high** (MCP agent + one ordinary person write; no recovery in the CLIs)
*Where:* `_vault_tombstone.py:552-579` (`_lift_lower_class_tombstones`) journals `tombstone_lifted` with
the **writer's** `category`, `key`, `scope` (the lifted row's identity only goes into `metadata.tombstone` /
`tombstone_scope`); `_vault_crypto.py:594-623` (`_check_tombstones`) pops the expectation by the event's
`(category, key, value_sha256, scope)`. The two were written by different people in different rounds (A's
class lifting, B's reconciliation) and only agree when the lifting write names the same entry.
*Problem:* an agent's `kibisis_forget` of `c:k1` (value V) records an agent-class row for `c:k1`. A person
later writes V under `c:k2` (any `origin="user"` put: library, `kibisis` CLI, review flow). The write finds
the row by value (`_find_tombstone` matches on scope + digest, any key), lifts it correctly, and journals
`tombstone_lifted` for `c:k2`. At the next open, writable **or read-only**, `expected[(c,k1,V,default)]`
is still set, the row is gone → `"1 journaled tombstone(s) have no row … the tombstone table was changed
outside kibisis"`. Nothing in the CLIs opens the vault after that (the review CLI opens the vault too); the
journal is chained and head-signed, the row is MAC'd, so a repair needs the passphrase and hand-written
SQL. The same happens across scopes when a row in scope S is matched from another key in S (the second test).
A legitimate flow bricks the vault, and the error text blames a file writer.
*Repro:* `review3_ab_tombstones.py::test_attack_lift_by_a_write_under_another_key_wedges_the_next_open`,
`::test_attack_lift_by_a_write_in_another_scope_wedges_the_next_open` (both pass: `verify_audit_chain()` is
True before close, then `VaultIntegrityError` on `read_only=False` and `True`).
*Fix:* journal `tombstone_lifted` with the **row's** `category`/`key`/`scope`/`value_sha256` (keep the
writer's entry in metadata), as `_lift_tombstone_locked` already does; and make `_check_tombstones` also
accept a `tombstone_lifted` whose `metadata.tombstone`/`tombstone_scope` name the row (so vaults that already
hold the mismatched events can open). Add a regression that forgets under one key and writes under another.

### R3-AB2 — R2-B1 residual: the "genuine a5" discriminator's strongest witness is gated on `is_encrypted = 1`; a file writer flips the column and re-enters the format-1 migration — **high** (file writer; same cost profile R2-B1 had)
*Where:* `_vault_crypto.py:413-418` (`_format_2_artefacts`: `WHERE is_encrypted = 1 AND
encrypted_envelope_json LIKE '%"binding":…%'`); `_migrate_integrity` `:678-704` (`opened` counts only
`is_encrypted == 1` rows; `sealed_rows`/`signed_rows` both 0 → no `Failed to authenticate`; rows without a
signature are "left unsigned", not refused).
*Problem:* the fixer's own test (`test_attack_meta_reset_with_every_artefact_scrubbed_still_fails_the_floor`)
notes that "sealed entries' bindings cannot be [removed]: they are inside the ciphertext" — but the query
does not look inside the ciphertext, it looks at a plain integer column next to it. `UPDATE entities SET
is_encrypted = 0` (envelope JSON untouched) removes the witness. With the rest of the R2-B1 reset (meta
records deleted, `tenant_sig` blanked, tombstone row + event deleted, journal re-chained as format 1 with
no head — with the floor/anchoring records deleted the migration verifies a headless format-1 chain,
which needs no key at all; the path-derived fallback key `:734-736` is also one a file writer can compute)
the open succeeds, migrates, signs a fresh head, key check
and meta MAC over the forged state, and the tombstoned value is admitted again. Cost to the attacker, as
in R2-B1: entries read as unsigned until `adopt_unsigned_entries()` (which would then sign the empty
`content` column; the sealed text is recoverable only by setting `is_encrypted` back — a file writer can
do that afterwards too). A variant with `DELETE FROM entities` also passes (loud, but the journal ends up
signed and verifying with the tombstone gone).
*Repro:* `review3_ab_migration.py::test_attack_r2b1_discriminator_is_defeated_by_flipping_is_encrypted_to_0`
(passes: open succeeds, `verify_audit_chain()` True, `is_tombstoned` False, `remember` of the rejected
value accepted, `audit_head` row and `key_check`/`meta_mac` freshly written);
`::test_attack_r2b1_discriminator_is_defeated_by_deleting_every_entry`. Control
`::test_control_r2b1_full_reset_with_sealed_entries_is_refused` (the fixer's scenario) passes.
*Fix:* make the witness independent of mutable columns: test `encrypted_envelope_json LIKE binding`
regardless of `is_encrypted` (an a5 vault never wrote the binding string at all); in `_migrate_integrity`
refuse when any row has `is_encrypted = 0` but a non-empty `encrypted_envelope_json` (inconsistent row), and
drop the path-derived-key fallback for the chain check when `kdf_salt` is present (a keyed vault's format-1
chain was signed under the passphrase key). Better still: when `kdf_salt` is present, require that the
chain verifies under the passphrase-derived legacy key only.

### R3-AB3 — `same_vault` is proven by the public `digest_key_id` alone; a hand-built snapshot carries forged verdicts, attestations and principal-class tombstones into a keyed vault — **medium** (library `import_snapshot` of an attacker-supplied file; the trust seal was meant to close exactly this)
*Where:* `_vault_snapshot.py:269` `same_vault = data.get("digest_key_id") == self._digest_key_id() or
self._trust_seal_opens(data)`; `:313-314` tombstone `origin_class` taken from the snapshot; `:420`
`_review_verdict=keep_trust_facts`.
*Problem:* `digest_key_id` is a 16-hex label written in clear into every export (`:137`); anyone who has
read one snapshot file (the agent, via its shell tool, when the person keeps exports around — the export is
plaintext JSON of all content) can copy it. `manifest_sha256` is a plain SHA-256 the forger computes. With
the id in place the seal is never consulted (`or`), `keep_trust_facts` is True and the R2-A7 fix sets
`_review_verdict=True`: a model-origin entity arrives `verified` with `attestations: ["alice","bob"]` and
`human_reviews` nobody wrote (no quorum, no attester), and a tombstone with `origin_class: "principal"` and
`digest_scheme: "sha256"` is re-keyed, MAC'd and journaled as a person's rejection (the person's own write
of that value is then refused until `kibisis-review lift`). With SQLCipher active a file writer cannot
touch the database, so the snapshot file is the softer target; SECURITY.md:220-221 says a forged snapshot
"can carry any content and any candidate" — it carries any verdict.
*Repro:* `review3_ab_snapshot.py::test_attack_same_vault_is_proven_by_the_public_digest_key_id_alone`
(passes). Control `::test_control_snapshot_without_the_vaults_digest_key_id_drops_trust_facts` passes
(wrong id → candidate, facts dropped).
*Fix:* require the seal: `same_vault = self._trust_seal_opens(data)` (a vault without a passphrase has no
seal and should never keep trust facts from a file); keep `digest_key_id` as a routing hint only. Cap an
imported tombstone's class at the importer's class unless the seal opened. Say in SECURITY.md that a
snapshot can carry any verdict until that is done.

### R3-AB4 — R2-B4 residual: a legacy (V1) meta MAC is a permanent token that re-signs an attacker-set `verification_quorum` — **medium** (file writer holding any pre-R2-B4 copy of `meta_mac`)
*Where:* `_vault_crypto.py:490-510` (`_verify_meta_mac`: V1 set accepted, then `_write_meta_mac` over the
full set **as stored**); `vault.py:1109-1110` (unnamed quorum adopts the stored value after the MAC held).
*Problem:* the V1 MAC never covered `verification_quorum`, so any copy of a file's `meta_mac` from before the
upgrade (a backup, an earlier read of the plain file; the other six bound values do not change in normal
use) lets a file writer set `verification_quorum = 1` and restore the V1 MAC. The next writable open logs
"re-signing the meta MAC to cover the verification quorum" and signs the attacker's value; the process
(naming no quorum) adopts 1 and one attestation mints `verified`. The downgrade is then permanent and
verifies under the full set.
*Repro:* `review3_ab_migration.py::test_attack_r2b4_legacy_v1_meta_mac_re_signs_an_attacker_quorum`
(passes; `v._signing_key` stands in for the backup copy of the old MAC). Control
`::test_control_r2b4_quorum_edit_under_a_full_set_mac_is_refused` passes.
*Fix:* when only the V1 MAC verifies, do not trust the stored quorum: ignore it (use the process/default
quorum, refuse to adopt a stored value lower than the default) and only then re-sign; or refuse to re-sign
unless the stored quorum is absent. Log at WARNING, not INFO.

### R3-AB5 — Row/journal reconciliation checks presence only: a file writer replays an older lower-class copy of a tombstone row over a person's raised row — **low–medium** (file writer with a prior copy of the row)
*Where:* `_check_tombstones` (`_vault_crypto.py:605-623`) compares identities, never `origin_class`
against the latest `tombstone` event's `metadata.origin_class`; `_tombstone_locked` re-signs the row on a
class rise (`:437-447`) so the earlier `(origin_class, tombstone_mac)` pair stays valid forever.
*Problem:* tool tombstones V (external row); a person re-tombstones V (`origin="user"`) → row becomes
principal, journaled. A file writer puts the earlier `origin_class`/`tombstone_mac` back: MAC verifies,
presence holds, open succeeds; the agent's next `put(origin="model")` lifts it as "agent-class write". The
journal says principal, the row said external, nobody compared them.
*Repro:* `review3_ab_tombstones.py::test_attack_file_writer_replays_an_older_agent_class_row_over_a_persons_raised_row`.
*Fix:* in `_check_tombstones`, carry the latest `tombstone` event's `origin_class` per identity and refuse a
row whose class is lower.

### R3-AB6 — Restoring the vault's own older snapshot over the live vault reverts a person's later `disputed` verdict to `verified` — **low (by design, record only)**
`import_snapshot` (own snapshot, no `clear_existing`) now writes with `_review_verdict=True`, so the older
row replaces the live reviewed one. Tombstones from a later rejection still win
(`::test_control_older_own_snapshot_cannot_resurrect_a_rejected_value`). Pinned by
`review3_ab_snapshot.py::test_attack_older_own_snapshot_reverts_a_persons_dispute_to_verified`; the
docstring says "this vault's own snapshot restores over it", so this is documented restore semantics for a
trusted caller. Worth a sentence in the docs that a restore is a point-in-time replay of reviews too.

---

## Verified closed (evidence)

| R2 | Status | Evidence |
|---|---|---|
| R2-A1 lower-class re-tombstone replaced a principal row | closed | `_tombstone_locked` `:409-449` INSERT / class-raise UPDATE / no-op + `tombstone_reaffirmed`; `review3_ab_tombstones.py::test_control_r2a1_lower_class_retombstone_keeps_principal_row_and_mac[tool|model]` (row stays principal, MAC verifies at re-open, agent write refused). Snapshot path: `::test_control_r2a1_snapshot_import_of_lower_class_row_does_not_downgrade` (`INSERT OR IGNORE`, `:290`). Residual: R3-AB5 (file-writer replay of an older copy). |
| R2-A2 bookkeeping strings digested | closed | fixer `test_review2_a_tombstones.py` (`agent`/`mcp` words no longer refuse later writes); `_entry_digests` `:219-234` walks `agent_metadata` only. Code reading + fixer test; not re-tested here. |
| R2-A3 value as metadata dict key | closed | `string_leaves` `:61-76` yields keys; fixer test asserts refusal and purge. Code reading. |
| R2-A4 `Mc` dropped | closed | `canonicalize_text` keeps `Mc`; `::test_control_r2a4_spacing_vowel_signs_distinguish_words` (कल/काल/कील → 3 digests). `Mn` still dropped, now documented (docstring + README). |
| R2-A5 Hangul fillers dropped | closed | `_BLANK_CODE_POINTS` → space; `::test_control_r2a5_hangul_filler_folds_to_a_space[4]`; round-1 evasions still caught (`::test_control_fold_still_catches_the_round_1_evasions`). |
| R2-A6 `lift_tombstone` ungated | closed | `origin` parameter, `PermissionError` + journaled `refuse` path `lift_tombstone` for model/tool/unknown: `::test_control_r2a6_non_principal_lift_is_refused_and_journaled[3]`. `None` still vouches (documented). |
| R2-A7 own snapshot demotes person-verified model entry / aborts | closed | `::test_control_own_snapshot_restore_keeps_person_verified_model_entry` (with and without `clear_existing`, origin stays `model`, reviews kept, no `ReviewedEntryError`); all-or-nothing: fixer `test_review2_a_trust.py::test_attack_f11_import_snapshot_is_all_or_nothing`. **New residual: R3-AB3** (the same-vault proof is a public label). |
| R2-A8 / R2-B4 quorum outside meta MAC | closed for full-set MACs | `::test_control_r2b4_quorum_edit_under_a_full_set_mac_is_refused`; `_persist_verification_quorum` re-signs (`vault.py:1118-1121`). **Residual: R3-AB4** (V1 MAC re-sign path). |
| R2-A9 attestations carry over content change | closed | fixer test + `test_review_2026_10_28.py` update (candidate, pending `{0,1}` after an origin-less re-write). Code reading. |
| R2-B1 full meta reset re-enters migration | closed for the fixer's scenario | `::test_control_r2b1_full_reset_with_sealed_entries_is_refused` ("sealed with its binding"); floor/anchoring now hang on `kdf_salt`. **Residual: R3-AB2** (the witness is gated on `is_encrypted`). |
| R2-B2 a5 file converted under wrong passphrase | closed | `::test_control_r2b2_a5_fixture_wrong_passphrase_leaves_plain_file_untouched` (bytes identical, no `.tmp_enc`); fixer `test_review2_b_keycheck.py::test_conversion_is_not_adopted_when_the_upgrade_fails`. |
| R2-B3 imported tombstones not journaled | closed | `_vault_snapshot.py:317-332` journals in the import's transaction; fixer `test_review2_b_tombstone.py::test_attack_snapshot_imported_tombstone_row_deletion_is_caught`. The same reconciliation now wedges on R3-AB1. |
| R2-B5 salt removed → plaintext path | closed | `::test_control_r2b5_salt_removed_is_refused_and_no_salt_written[ro|rw]` (refused both ways, no salt written). |
| R2-B6/B7/B8/B9 | closed (outside the A+B seam focus) | fixer regressions in `test_review2_b_native.py`, `test_review2_b_journal.py`, `test_review_b2_misc.py` assert the secure outcome (see weakened-tests list); not re-tested here. |

## Regressions checked
- `tests/fixtures/vault-0.1.0a5-fallback.sqlite` (the only legacy fixture): read-only open before the
  upgrade is refused by design ("needs an integrity upgrade: open it writable once first") and writes
  nothing; first writable open upgrades (`integrity_upgrade` reports re-sealed entries), second open is
  idempotent (`integrity_upgrade is None`), read-only open afterwards lists the same entries, chain verifies:
  `review3_ab_migration.py::test_control_a5_fixture_opens_read_only_before_and_after_migration`.
- In-memory vault with passphrase: tombstone + canonical match + chain:
  `::test_control_in_memory_vault_with_passphrase_round_trips_tombstones`.
- Read-only open does not call `_persist_verification_quorum`, so `v.verification_quorum` on a read-only
  handle reports the process default, not the file's (seen while building R3-AB4). Harmless (read-only
  never mints) but `kibisis-review list`-style tooling that prints the quorum would print the wrong number.

## Weakened tests (fixers' conversions, `git log -p --since='24 hours ago' -- tests/test_*.py`)

| file::test | used to assert | asserts now | verdict |
|---|---|---|---|
| `test_review2_a_tombstones.py::test_attack_retombstone_downgrades_principal_tombstone_class[*]` | row class != principal, entry written, row lifted | row stays principal, `tombstone_reaffirmed` with `origin_class=principal`, agent write raises `TombstonedValueError(… class: principal)`, no `tombstone_lifted` | secure outcome; OK |
| `test_review2_a_tombstones.py::test_attack_lift_tombstone_has_no_origin_and_no_terminal_check[*]` | documented the ungated lift | `PermissionError`, row still there, `refuse` journaled | OK |
| `test_review2_a_tombstones.py::test_attack_canonical_fold_collapses_distinct_words…` | `==` digests | `!=` digests, plus a new control that `Mn` is still dropped by design | OK (limit documented) |
| `test_review2_a_tombstones.py::test_attack_hangul_filler…[*]` | value stored | refused, `get` None | OK |
| `test_review2_a_trust.py::test_attack_f11_person_verified_agent_entry_is_demoted…` | candidate + `trust_capped_from` | verified, same reviews/attestations, origin model | OK |
| `test_review2_a_trust.py::test_attack_f11_restoring_own_snapshot_over_the_live_vault_aborts…` | `ReviewedEntryError` | import returns 2, state verified | OK |
| `test_review2_a_trust.py::test_attack_stored_quorum_is_not_under_the_vault_meta_mac` | (skipped placeholder) | **deleted** in 98c6f99, pointer to `test_review2_b_journal.py` | OK — `test_attack_verification_quorum_in_vault_meta_is_under_the_meta_mac` covers the plain edit; neither covers the V1 re-sign path (R3-AB4) |
| `test_review_2026_10_28.py` (R2-A9 edit) | re-write kept provenance and state | origin-less re-write → candidate, pending {0,1}; person's re-write → verified | OK, behaviour change is the documented one |
| `test_review2_b_journal.py::test_attack_full_meta_reset_is_refused…`, `…_without_tombstone_deletion…`, `…_integrity_format_row_deleted`, `…_every_artefact_scrubbed_still_fails_the_floor` | open succeeded, value readmitted | `VaultIntegrityError` with specific match, nothing signed | OK as far as they go; they never vary `is_encrypted` (R3-AB2) |
| `test_review2_b_journal.py::test_attack_row_relabelled_format_4…` | Python accepted | Python and Rust refuse | OK |
| `test_review2_b_keycheck.py::test_attack_legacy_a5_vault_wrong_passphrase…` | file converted | bytes identical, no artefact, right passphrase works | OK |
| `test_review2_b_tombstone.py::test_attack_snapshot_imported_tombstone_row_deletion…` | open succeeded | `VaultIntegrityError("journaled tombstone")` | OK |
| `test_review2_b_tombstone.py::test_attack_read_only_open_treats_keyed_vault_with_salt_removed…` | opened as plaintext | refused `no kdf_salt`, salt count 0 | OK |
| `test_review2_b_native.py::test_attack_forget_requests_drops_bad_signature_rows…` | `== []`, count 0 | strict raises; non-strict `== []` **and** counted | OK |
| `test_review2_b_native.py` (module) | `import kibisis_native` | `pytest.importorskip("kibisis_native")` | acceptable but note: on a host without the wheel the whole file (R2-B8, L6, L7 regressions) silently skips; the wheel is present here (`kibisis_native` imports from the venv) |
| `test_review_b2_misc.py` (R2-B7 edit) | `strict=True` open raised | open succeeds, `integrity_failures == 1`, first `search` raises | OK, matches the new documented contract |

No conversion was found that merely asserts "no exception" where the secure outcome should be asserted.

## Suspected, unconfirmed
- `_migrate_integrity` accepts a headless format-1 chain (`head_required` is off below floor 2) and also
  tries the **path-derived** key as a fallback even when `kdf_salt` is present (`_vault_crypto.py:734-736`).
  Both let a file writer's re-chained journal verify; they only matter once the discriminator is passed
  (R3-AB2), but they are the second half of that attack and should be closed with it (require the
  passphrase-derived legacy key, and a head, whenever `kdf_salt` exists).
- `_lift_tombstone_locked` (the person's lift) journals under the row's own `category`/`key` — fine — but
  lifts by `(category, key, scope)` regardless of class, including rows imported from a snapshot with
  `scope="*"`; not an attack, noted for the R3-AB1 fix (both lift paths should journal the row identity).
- Foreign-passphrase snapshots: a tombstone whose `sealed_digests` opens under this passphrase keeps
  `origin_class` from the file (`:313`). Same-passphrase-other-vault imports therefore plant principal rows;
  covered by R3-AB3's fix if class is capped unless the seal opens.
- The fold's documented limits still hold with concrete strings: Unicode small capitals (`ᴅᴇᴘʟᴏʏ …`) and
  Latin alpha `ɑ` fold to a different digest (`::test_attack_fold_misses_small_capitals_and_latin_alpha`,
  recorded for the docs list, not as a defect: README "Limits" says homoglyphs outside the table pass).
- `_check_tombstones` runs on every open (read-only too) over the whole journal; with R3-AB1 it is also the
  thing that bricks the vault, so any fix should keep it cheap and non-fatal for self-inflicted mismatches.

## Docs sentences that overstate the code
- SECURITY.md:86-89 / changes/area_b.md "the format 1 migration … runs only for a genuine 0.1.0a5 file, one
  that holds nothing integrity format 2 and later write (… no entry sealed with its scope, category and key
  bound to the ciphertext)" — the entry witness is read through `is_encrypted = 1`, a column a file writer
  flips (R3-AB2).
- SECURITY.md:78-81 "every `tombstone` event … must still have its row, so a deleted row refuses the open
  instead of readmitting the value" — true, and so does a row lifted by a person's write under another key
  (R3-AB1): the check cannot tell the two apart.
- SECURITY.md:214-221 "`import_snapshot` keeps … only when the snapshot is this vault's (its
  `digest_key_id`, or a `trust_seal` …)"; "a forged snapshot can carry any content and any candidate" — the
  id is a public label, so a forged snapshot carries any verdict, attestation set and principal tombstone
  (R3-AB3).
- SECURITY.md:82-84 / changes/area_b.md R2-B4 "`verification_quorum` … bound under one HMAC" and "a vault
  whose MAC was written over the legacy key set … opens once and is re-signed" — the re-sign signs whatever
  quorum is stored at that moment (R3-AB4); until every pre-R2-B4 file has been re-signed and every old copy
  of its `meta_mac` is gone, the stored quorum is not bound.
- `_vault_snapshot.py:234-236` docstring "this vault's own snapshot restores over it" — accurate, but the
  consequence (an older own snapshot replays older verdicts over newer ones) is not stated (R3-AB6).
