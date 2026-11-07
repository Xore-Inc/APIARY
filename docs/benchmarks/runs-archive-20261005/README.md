# Benchmark run transcripts

Committed transcripts from synthetic-corpus benchmark runs, written under
[issue #1805](https://github.com/Xore/APIARY/issues/1805) by
`analysis/ghidra/benchmarks/evaluate-models.py` and
`analysis/ghidra/benchmarks/corpus/record_baseline.py`.

One directory per run, named `<date>-<run_id>`:

- `transcripts.jsonl` — one record per `(run_id, slot, case, model, workflow)`
  exchange: the exact prompt as sent, the raw unparsed response, model tag and
  digest, sampling parameters, timing, and the reproducibility keys.
- `run.json` — run metadata, record count, and the transcript file's SHA-256.

## Why these are in the repo

A score is a lossy summary of an answer. Rescoring an earlier round against a
later, enlarged claim pool requires that round's original answers, and
unique-contribution ("did this model find something no other model did") is
defined against the set of models that ran, so it changes for everyone when a
model is added later. Neither is recoverable from a number, and a re-run answers
a different question because tags, quants, sampling and prompts drift.

Comparability across rounds is worth more than the small repo cost, and there is
no secret in them: these runs use only #159's provenance-controlled corpus and
the benchmark's own fixtures — TEST-NET addresses, reserved `.test`/`.invalid`
names, and fake credentials, reviewed before commit.

## What must never land here

Transcripts from runs against **real captured honeypot data**. Those contain
real attacker IPs and payloads; they belong in an operator-only path with
bounded retention, and the issue carries only the run id, hashes, a pointer and
aggregate results. `evaluate-models.py --provenance captured` refuses to write
into the repository, and `analysis/ghidra/benchmarks/tests/test_transcripts.py`
gates that on every change.

## Rescoring a stored run against the current scorer (#2266)

`evaluate-models.py --rescore-from <run_dir>` replays a run written by
*evaluate-models.py itself* (slots `ghidra`/`sessions`/`revdeck`) through the
current `_score_session_case`/`_score_triage_case`/`_score_revdeck_case`
logic, no GPU or Ollama contact, and prints a report to stdout — this is the
"needs no GPU time" rescoring path this directory's transcripts were
committed to make possible, previously unimplemented. It never writes into
the run directory. To see what a scorer change moved, run it once on the
pre-change commit and once on the post-change commit (`git worktree add` or
`git stash`) and diff the two JSON reports — each carries its own
`scorer_git_sha`, so which side is which is never ambiguous. That field is
suffixed `-dirty` when the tree it ran from had uncommitted changes (and
`-unknown-dirty` where git can name HEAD but not answer for cleanliness), so
a report produced from a working tree can never pass itself off as one
produced from the commit it happens to sit on.

Runs written by `record_baseline.py` (`benchmark:
"honeypot-stack-issue-159-corpus-baseline"` in their first record, rather
than `"honeypot-stack-issue-158-v2"`) use a different case/rubric system
(`rev_cases_v2_rubric.json`) and are not covered by this flag — their offline
rescorer is `corpus/rescore_injection_v2.py`. `--rescore-from` reports any
case name it can't match against the current scorer's roster in
`unmatched_cases` rather than guessing or crashing, which is how a run from
the other producer (or a genuinely retired case name) shows up if pointed at
by mistake.

## Rules

- **Never edit a stored transcript.** A misconfigured run is superseded by a new
  run that names the old `run_id` in `supersedes`; later scores depend on the
  original text.
- **Store the failures too.** Timeouts, refusals, malformed JSON and
  decompilation failures are measurements. For a derestricted-model round, a
  refusal *is* the measurement.
- **JSONL, one record per line**, so a run appends as it goes and a diff between
  two runs stays readable.
- Issue bodies cap around 65 k characters. A full round across models, slots,
  cases and tiers does not fit and must not be attempted — the issue holds the
  summary and the pointers, these files hold the evidence.
