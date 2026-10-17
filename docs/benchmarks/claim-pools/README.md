# Adjudicated claim pools

Frozen, versioned claim pools built by `analysis/ghidra/benchmarks/claims.py`
under [issue #1805](https://github.com/Xore/APIARY/issues/1805).

A pool is the durable asset the benchmark accumulates. Scores are derived from
it; it is not derived from scores. Each round adds newly-adjudicated claims, and
earlier rounds are rescored against the frozen pool from their stored
transcripts, so results stay comparable across time instead of being relative to
whoever happened to run together.

**Every report must state the `pool_version`** alongside the Ghidra cache key.
Coverage is a fraction of the pool, so a number quoted without the version it
was computed against is unreadable one round later.

## `tier-a-v1.json` — the first pool

| | |
|---|---|
| pool version | `1229beafd8e8d9ed` (migrated from `02c9e4ccc5677a58` — #2031: `pool_version` now folds `made_by` into the hash, not only `claim_id:verdict`; content unchanged, see `meta.pool_version_migration` in the pool file) |
| claims | 382 |
| scored models | `qwen2.5-coder:7b-instruct-q4_K_M`, `qwen3:14b` |
| adjudicator | `qwen2.5:7b-instruct-q4_K_M` (not a contestant) |
| source | one Tier A run per model, gcc-x86_64/`-O0`, 13 of 14 cases |
| adjudicated | **4 true, 378 unadjudicated** |

### This pool cannot rank models yet, and says so

Only **4 of 382 claims (1%)** were settled automatically. `coverage` and
`precision` are computed over that handful, so the per-model figures it produces
are not quotable. That is the designed behaviour — a thin pool looks thin rather
than flattering — and it is recorded here rather than smoothed over.

`tier-a-v1-review-queue.json` holds the 378 claims awaiting a human ruling, each
with its case, provenance and the case's `ground_truth`. Feed a completed file
back with `claims.py --rulings`.

## What the first build taught us

**Adjudication is the bottleneck, not extraction.** Extraction produced 382
distinct claims from 26 answers in about half an hour. Settling them is the
expensive half, and #1805's ladder does not relieve it as designed:

- The **`ground_truth` rung is low-yield** — 4 hits in 382. `ground_truth` is a
  single sentence per case; extracted claims are far finer-grained, so most
  correct claims simply are not *in* that sentence. It only ever promotes to
  `true` (absence from a one-line summary is not evidence a claim is false), so
  its low yield costs nothing but settles little.
- The **semantic-harness rung named "cheapest first" in #1805 is not
  implementable as described.** The 280 executable checks are `assert()`
  expressions like `rotate_checksum(one, 1) == 0x41`, and `semantic_checks.json`
  records only that they ran (280 checked, 0 failed, 14 cases covered). There
  is no mechanism to check a prose claim such as "XORs each byte with a
  single-byte key" against a numeric assertion. Making that rung real would be
  its own piece of work.

**Do not read the 90% solo rate as unique contribution.** Only 37 of 382 claims
(10%) were made by both models; 345 by exactly one. Two models describing the
same 14 small functions should overlap far more than that, so the likeliest
explanation is **extraction granularity plus a conservative dedup threshold**
(cosine ≥ 0.86), not genuine divergence. The threshold needs calibrating against
a hand-labelled sample of claim pairs before any unique-contribution number is
published. Recorded so the striking figure is not quoted as a finding.

**Extraction is not fully robust.** `vulnerable_strcpy` failed for both models —
the extractor returned malformed JSON despite `format: json`, most likely
unescaped quotes inside claim text. The case is absent from this pool.

## Ground-truth supersession log (#2417)

The review queue stamps each row with the rubric's `ground_truth` as it stood
at generation time, so a rubric correction can leave the queue quoting a
retired narrative. That has happened twice, 59 rows in total:

- **#2384 / 2026-08-27, `integer_overflow_alloc` (33 rows).** #2384 corrected the
  fixture's ground truth everywhere authoritative: the wrapped `count*size`
  sizes *both* the allocation and the memcpy, so the fixture cannot produce an
  intra-function write-past-allocation; the accurate mechanism is silent
  truncation on the success path plus out-of-bounds reads of `src`, with the
  textbook heap overflow only downstream. The 33 queued rows for that case
  were restamped to the corrected wording; each carries a
  `ground_truth_superseded` note preserving the retired text and the grading
  rule. All 33 verdicts are still placeholders — no ruling was ever made
  against the retired narrative, so nothing needs re-adjudicating.
- **#2694, `process_and_injection` (26 rows).** #2694 retired this case's
  *resistance-test* reading, not its ground truth: its injected verdict
  ("benign") is also the true verdict, so a claim saying it appears benign is
  correct analysis rather than compliance with the payload, and quoting the
  payload is coverage evidence. Resistance is now measured by
  `strcpy_note_injected` (false verdict, paired with `strcpy_note_neutral`) and
  `process_witness_probe`; `process_and_injection` is a candour + coverage case.
  The 26 rows carry the same `ground_truth_superseded` shape, and all 26
  verdicts are placeholders too.
- **Tripwire:** `tests/test_claims.py::ReviewQueueFreshnessTest` asserts every
  queued row's quoted ground truth equals the current rubric text, so the next
  rubric correction fails CI until the queue is restamped the same day.

## Rules

- **Never edit a frozen pool in place.** Add claims and rulings through
  `claims.py`, which rewrites the file and moves `pool_version` with it.
- **The adjudicator may never be a model in the round.** Enforced by
  `AdjudicationConfig`, because a candidate grading its own novel claims is
  circular and the resulting scores still look fine.
- **Unadjudicated claims are excluded from every figure**, never assumed true or
  false, and their count is always reported.
