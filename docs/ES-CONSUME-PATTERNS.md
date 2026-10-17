# ES consume patterns

Every consumer of Elasticsearch in this repo eventually needs the same three
sub-problems solved: "what have I already read?", "did the read fail or was
it genuinely empty?", and "what happens if I re-read something?". For years
each consumer answered them independently, in its own language, in its own
file -- six implementations of the same ideas with independent bug surfaces
(#1971). The cost was concrete: ml-worker needed #168 to discover that a
timestamp-only checkpoint permanently drops equal-timestamp siblings, and
nothing could tell whether the Go fetchers shared that landmine because
there was no shared definition to check them against.

This note defines the **two patterns** every current and future consumer is
written against. It exists so a fourth idiom can't appear: new consumers
pick a pattern, adopt the shared modules, and inherit contract tests --
instead of inventing semantics under time pressure.

Related: [#1971](https://github.com/Xore/APIARY/issues/1971) (this note,
the shared modules, the first audit), [#1977](https://github.com/Xore/APIARY/issues/1977)
(platform-hygiene epic), [#168](https://github.com/Xore/APIARY/issues/168)
(the founding equal-timestamp incident),
[#1959](https://github.com/Xore/APIARY/issues/1959) (ml-worker pathologies).

---

## Pattern 1: incremental-checkpoint consumer

**Resume where you left off; never skip what you haven't seen.**

For consumers whose output would be wrong or expensive to recompute from
scratch when they fall behind, and which therefore persist position across
cycles. ml-worker/worker.py is the reference implementation; its mechanics
are extracted into the vendored module `analysis/es-consume/es_consume.py`
(stdlib-only, zero imports) with behavioural-parity tests.

The contract, in five parts:

1. **Total-order checkpoint tuple.** Persist `{"last_timestamp": str,
   "seen_ids": [ids processed exactly AT that timestamp]}` -- never a bare
   timestamp. `seen_ids` is *replaced*, not appended, on every advance, so
   it stays bounded by one timestamp's collision count rather than by
   history.
2. **Inclusive requery + boundary exclusion (#168).** Requery with `gte`,
   never exclusive `gt`, filtering out exactly the checkpointed `seen_ids`.
   A bare-timestamp checkpoint with `gt` silently drops any sibling sharing
   the checkpointed timestamp but absent from the batch the checkpoint was
   computed from -- those siblings become invisible forever once the
   watermark moves past them. `gte`+ID-exclusion makes "already handled"
   distinguishable from "arrived later with the same timestamp" without PIT
   machinery.
3. **Failure vs empty (#188).** Fetches return `(events, ok)`. `ok=false`
   means the read itself failed -- distinct from a successful empty poll.
   Partial data comes back as `(partial_events, false)` and IS safe to
   checkpoint against: everything already read sorts at-or-before everything
   not yet read, so advancing only as far as what's in hand cannot skip
   anything; the remainder arrives next cycle. (A checkpoint READ failure
   likewise degrades to the last known in-memory position, not to a bogus
   fresh start -- #2236.)
4. **Batch caps (#190).** Bound how much one cycle pulls into memory and
   checkpoints incrementally through a backlog. Cap truncation keeps the
   *earliest* prefix of the ascending-sorted window, which combined with
   (3) preserves the no-skip guarantee.
5. **Idempotent writes.** Output document IDs derive deterministically from
   the source event's identity (`anomaly_doc_id(source_index,
   source_event_id)`, md5-keyed). Any replay -- crash-retry, checkpoint
   reset, the inclusive requery itself overwriting `seen_ids` while stuck at
   one timestamp -- *overwrites* its previous finding instead of duplicating
   it. Rule of thumb: rare replays are absorbed, drops are forever; design
   so replays are cheap.

## Pattern 2: windowed-refetch consumer

**Recompute; hold no position.**

For consumers where recomputation each cycle is cheaper than tracking state,
or whose downstream store absorbs overlap on its own. Each cycle fetches a
fixed look-back window (`gte now - WINDOW`) and writes results keyed by IDs
determined purely by content, so replays overwrite instead of duplicate:

- Full-window refetch makes the #168 drop class structurally impossible:
  there is no persisted boundary to advance past anything, and within-cycle
  pagination must use a *total-order* sort tuple (`@timestamp asc` plus a
  unique tiebreaker such as `_shard_doc`) resumed via full-tuple
  `search_after` -- a scalar last-timestamp resume is this pattern's own way
  to reintroduce sibling loss/duplication at page seams.
- Failure-vs-empty still applies (#188 shape): a failed window read skips
  the cycle loudly rather than writing an artificially small result as if
  it were complete.
- Residual risk to understand before choosing it: events whose event-time
  lies *before* the current window but that are indexed late (backfills,
  clock-skewed sensors) are missed until some cycle's window catches them;
  pattern 1 keeps no such hole behind its checkpoint. Choose window size
  accordingly (or use an mtime/content-state variant like es-results-
  importer's, which has no event-time dependency).

## Which consumer uses what

| Consumer | Language | Pattern | Why / evidence |
|---|---|---|---|
| `ml-worker/worker.py` | Python | **1** | Scores every event independently; losing one is a lost detection. `{last_timestamp, seen_ids}` checkpoint + gte/exclude (`worker.py` `advance_checkpoint`/`fetch_new_events`, delegating to vendored `es_consume.py`); `(events, ok)` + sustained-outage counter (#188); `MAX_POLL_BATCH` earliest-prefix cap (#190); `anomaly_doc_id()` deterministic writes (#168). |
| `arcane/home/honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/worker.py` (under `arcane/home/honeypot-agent-intrusion-worker/`) | Python | **2** | Campaigns recomputed per cycle: `FETCH_WINDOW_DAYS=10` full refetch (`worker.py:51`, query `:93`), verdicts upserted under `campaign_id = sha256(sorted event_ids)[:16]` (`:177`, `:224`) -- content-derived ID makes refetch idempotent. Audited in #2377: **verified-correct** -- its scroll cursor is a server-side snapshot iterator never resumed across cycles, so the scalar-desc sort has no search_after page seam; interrupted-mid-write convergence proven in `tests/test_worker.py::TestInterruptedCycleUpsert`. |
| `arcane/home/honeypot-attacker-identity-worker/attacker-identity-worker/` | Go | **2** | Wall-clock `EVIDENCE_WINDOW` (default 6h) refetched every `RUN_INTERVAL` (`main.go:52`, `runCycle ... start.Add(-window)` at `:66`), no persisted position; merges fold set-wise into entities written by deterministic-ID upsert (`newEntityID` sha256 at `identity.go:296`, `docIndex(e.ID)` at `main.go:96`). Audited against #168 in this PR: **verified-correct**, characterization tests in `fetch_boundary_test.go`. |
| `arcane/home/honeypot-correlator-worker/correlator-worker/` | Go | **2** | Rolling `CORRELATION_WINDOW` (default 7d) recomputed per cycle via ES-native aggregations instead of raw-document consumption (`main.go:70`, `fetch.go` aggregation queries at `:208`/`:279`/`:398`) -- aggregations make the refetch affordable (measured ~6.7s live, same file). No state, nothing to skip. Audited in #2377: **verified-correct** -- all three fetchers are single-round-trip `size: 0` aggregations with an inclusive `gte` window edge and no sort/search_after seam; failure-vs-empty is pinned by `fetch_test.go`, deterministic-ID upserts (`clusterDocID`) by `main_test.go`. |
| `arcane/home/honeypot-dashboard/analysis/es-results-importer/` (`importer.py`; Python despite the dashboard-adjacent path) | Python | **2 variant** | Mirrors local JSON into ES; per-file mtime recorded in a local state file replaces the event-time window entirely (`importer.py:70`, state load/save around `:451`), and doc `_id`s are content-derived (`sha256`/job/run, `<sha256>:<kind>` for artifacts) so re-sent files overwrite their mirror. mtime-checkpointing inherits pattern 1's write discipline for the file domain without any @timestamp boundary. Audited in #2377: **verified-correct with one documented residual** -- mtime equality is the sole change signal, so a rewrite within the same clock tick is invisible until any later real write (characterized in `tests/test_importer.py::ScanSourceSameMtimeRaceTest`; deterministic doc ids make that healing an overwrite, not a duplicate). |
| `arcane/home/honeypot-payload-inventory-worker/payload-inventory-worker/` | Go | **2 variant** | Full disk rescan each cycle (`scanDirs` walking every capture dir, `scan.go:140`), merged hash-keyed: documents converge from all writers onto the same hash-named files (`#1202`, noted at `scan.go:12`). Recompute-everything means there is no consume boundary at all. Audited in #2377: **verified-correct, nothing to migrate** -- both write paths key docs by the file's content hash (`docIndex(payloadInventoryIndex, file.Hash)`, `docIndex(payloadBytesIndex, hash)`), so hash-keyed convergence remains the sole dedupe; cross-directory merge and skip-unchanged/overwrite idempotence already pinned by `scan_test.go`. |

Serving-tier note (read path, not a poller): the dashboard backend pages
events with PIT + search_after in `backend-service/src/es.rs`; it shares
pattern 2's total-order tuple requirements, including the resume-from-full-
sort-tuple rule (#1979/#2039 fixed the scalar-watermark version of that bug
there).

## Shared modules

```
analysis/es-consume/
├── es_consume.py                  # canonical, stdlib-only (zero imports)
│                                  # advance_checkpoint / build_since_query /
│                                  # fetch_events_since(pattern 1 engine)
├── fixtures/es-consume-parity.json# cross-language fixture stream:
│                                  # same pages in -> same consumed set + checkpoint out
└── tests/test_es_consume.py       # vendoring registry + parity + query-shape contracts
ml-worker/es_consume.py            # vendored copy (byte-for-byte asserted)
arcane/home/honeypot-attacker-identity-worker/attacker-identity-worker/
└── esconsume.go                  # Go reference engine, behaviourally
                                  # identical, tested against the same fixtures
```

Tests, run in CI (`.github/workflows/quality.yml`):

- Canonical suite: parity fixtures + query-shape + registry walk
  (`python3 analysis/es-consume/tests/test_es_consume.py`).
- Per-consumer copy guard: `ml-worker/tests/test_es_consume_vendoring.py`
  (byte-equality; the gpu_queue.py discipline in miniature).
- Go half: `go test ./...` in the attacker-identity module runs
  `TestParityFixtures` over the SAME fixture file (located by upward search,
  no second copy exists) plus the Go-specific engine-contract units.
- Go fetcher audit pins: `fetch_boundary_test.go`.

Expectations in the fixture file are hand-computed from this document and
the issue history, NOT generated from either implementation, so both engines
can fail against them independently. If you change pattern semantics, change
this doc, the fixture expectations, AND both engines in the same PR.

## Adopting (per-consumer, opportunistically)

1. Pick a pattern from the table above; if none fits exactly, stop and add
   a third named pattern here first (#1971's whole point).
2. Copy the canonical module verbatim (Python: `es_consume.py`; Go:
   `esconsume.go`, stdlib-only). Do not edit your copy.
3. Add your copy's path to `VENDORED_COPY_REGISTRY` in the canonical
   module, and give your test suite a byte-equality guard against the
   canonical file (see ml-worker's test).
4. Wire your ES calls through the engine seam (three-callable transport in
   Python; `consumeScrollTransport` in Go) keeping your existing log text.
5. Record the migration here: move the consumer's row to "adopted", cite
   the PR, and keep the why-column honest.

### Migration ledger

| Consumer | Status |
|---|---|
| ml-worker (Python side) | migrated (#1971): mechanics delegated to vendored `es_consume.py`, wrappers preserve signatures/log text |
| attacker-identity-worker (Go fetcher) | audited (#1971): verified-correct vs #168; Go reference engine lives in-module ready for adopters |
| correlator-worker | audited (#2377): verified-correct as pattern 2-by-aggregation -- no persisted position, no document page seams (all three fetchers `size: 0`, inclusive `gte` edge, no sort/search_after, pinned by `TestFetchersKeepThePatternTwoQueryShape` in `fetch_test.go`); remains a candidate only if it ever grows persisted position |
| payload-inventory-worker | audited (#2377): verified-correct, nothing to migrate -- full rescan holds no position; hash-keyed convergence confirmed as the sole dedupe on both write paths (`docIndex(payloadInventoryIndex, file.Hash)` / `docIndex(payloadBytesIndex, hash)`, cross-directory merge pinned by `TestScanDirsMergesSameHashAcrossDirectoriesAsCopiesAndSources` and overwrite idempotence by `TestIndexPayloadInventorySkipsUnchangedAndWritesNew`/`...PreservesExtraFieldsOnOverwrite` in `scan_test.go`); revisit only if `scanDirs` ever becomes incremental |
| agent-intrusion worker | audited (#2377): verified-correct pattern 2 exemplar -- campaign_id upsert absorbs an interrupted cycle mid-write (characterized by `TestInterruptedCycleUpsert` in `tests/test_worker.py`: KeyboardInterrupt mid-write, then a restart cycle converges to byte-identical verdicts vs an uninterrupted run, @timestamp apart; rolling-window overlap overwrites instead of duplicating) |
| es-results-importer | audited (#2377): verified-correct with one documented residual -- mtime equality is the sole change signal, so a file rewritten within the same filesystem clock tick stays invisible until the next write whose mtime actually advances (characterized by `ScanSourceSameMtimeRaceTest` in `tests/test_importer.py`); never permanent loss because deterministic content-derived doc ids make the healing pass an overwrite; state only advances after bulk() confirms success (`advance_state_after_bulk`, #764's partial-failure property), so this race is bounded by tick width and self-healing |
