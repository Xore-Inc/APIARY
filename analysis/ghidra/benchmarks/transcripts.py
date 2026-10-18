"""Full-conversation transcript records for benchmark model calls (issue #1805).

A score is a lossy summary of an answer. The questions that actually decide
model selection here -- "what did this model say that the other missed", "does
the security fine-tune surface a behaviour the base model never mentions" --
live in the answer text and cannot be reconstructed from a number. Re-running
is not a substitute: model tags, quants, sampling and prompts all drift, so a
re-run answers a different question than the original.

Two things #1805's claim-pool scoring requires are simply impossible if
transcripts are discarded:

1. Rescoring earlier rounds against a later, enlarged claim pool -- which needs
   the earlier models' original answers.
2. Computing unique-contribution retroactively, since "did this model find
   something no other model did" is defined against the set of models that ran
   and changes when a model is added later.

So the raw text is the durable artifact and the score is derived from it, not
the other way round.

Storage is split by the provenance of the INPUT, not by convenience:

- `synthetic` -- #159's corpus binaries and `evaluate-models.py`'s fixtures
  (TEST-NET addresses, reserved names, fake credentials, reviewed before
  commit), run against a model whose answers are themselves fixtures. Committed
  to the repo under `docs/benchmarks/runs/<date>-<run_id>/` so rounds stay
  comparable across time. There is no secret in them.
- `live_model` -- synthetic input, live answers. The prompts are still this
  repository's fixtures, which is what makes the transcripts committable, but
  they were answered by a real served model rather than replayed: a pinned
  artifact digest, a `done_reason` the harness did not choose, and an answer no
  one wrote by hand. It is a separate member rather than `synthetic` because
  reading a real measurement as a fixture answer is the error that lets a
  fabricated-looking result pass unexamined, and it is silent -- nothing
  downstream reads the field. It is *not* `captured`: nothing in such a run is
  attacker-supplied, so the reason `captured` is kept out of the working tree
  does not apply and the transcripts belong in the repo with the rest.
- `captured` -- runs against real honeypot data. These contain real attacker
  IPs and payloads, so they are written outside the repository with bounded
  retention and the issue carries only aggregates and pointers. Writing them
  into the working tree is refused here rather than left to reviewer vigilance.

The first two are committable and the third is not, so `PROVENANCES` orders the
committable members first and the refused one last: the tuple is also the
`--provenance` choices list, and the refusal below is the one value it has to
single out.

The committable half is a claim about the *input*, so the producers check it
rather than assert it: `assert_repository_fixture_input()` refuses a
`live_model` run whose prompt sources are not files in this tree, which is the
source-side twin of the destination-side refusal in `TranscriptWriter.__init__`.
A free argparse choice is what made the claim worthless; the enum member is
only worth having once something reads it.

This partly supersedes `docs/analysis/ghidra/benchmarks/README.md`, which tells
the operator to preserve the raw report outside the repository for everything.
That rule was written when the report was a score summary; it still governs
`captured` runs, and the other two now commit their transcripts instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "apiary-benchmark-transcript-v1"

OUTCOME_OK = "ok"
OUTCOME_ERROR = "error"
# A generation that did not finish on its own terms. Ollama answers
# done_reason="length" when generation stops at num_predict. Recording that
# as `ok` is what let 940 truncated answers in the committed runs -- 928 revdeck
# and 12 sessions -- pass every `outcome != "ok"` filter downstream and score
# as full ones.
#
# Those 940 records keep the `ok` they were stored with. classify_outcome runs
# only when a record is written, and the writer refuses to overwrite an existing
# transcript (see __init__), so this value decides the shape of future rows and
# reinterprets no committed row. History stays suspect on purpose; fixing it
# would mean rewriting scores other reports were derived from.
OUTCOME_TRUNCATED = "truncated"
# The only done_reason that means the model stopped because it was done.
# Deliberately a positive list: a done_reason this harness has not seen is a
# generation it cannot vouch for, and must not be stored as a pass. `None` is
# carved out because Ollama omits done_reason entirely on some paths -- the
# #2233 harmony signature returns empty content with no done_reason at all
# (evaluate-models.py:570-572), and 14 records in docs/benchmarks/runs/ carry
# none (11 of them errors, 3 ok). Absent is not evidence of truncation; `length`
# is. Those 3 ok records store content:"" with output_tokens 0, so they were
# empty when written and stay readable at rescore time.
CLEAN_DONE_REASONS = ("stop",)


def classify_outcome(*, error: str | None, done_reason: Any = None) -> str:
    """The one place a stored outcome is decided.

    An answer that ran into the output cap is not a completed answer, and
    every consumer filters on `outcome != "ok"` -- so the value here is what
    decides whether a partial answer counts downstream.

    `error` is checked first, so a transport failure stays `error` rather than
    being relabelled by the absence of a done_reason.
    """
    if error:
        return OUTCOME_ERROR
    if done_reason is not None and done_reason not in CLEAN_DONE_REASONS:
        return OUTCOME_TRUNCATED
    return OUTCOME_OK


def repetition_ratio(text: str, window: int = 20, step: int = 20) -> float:
    """Fraction of fixed-width windows in `text` that are not unique.

    A model stuck in a degenerate emit loop burns its whole output budget
    saying the same thing, which reads as "hit the token cap" but is a
    different failure: the answer never becomes a valid implementation at any
    budget. Raising the cap makes it worse, not better. The cap flag alone
    cannot tell those two apart, so this is measured separately and handed to
    the human grader as a rubric signal -- never as an automated score.

    0.0 means every window is distinct. 1.0 means the output is a single
    repeated chunk. The window is deliberately coarse (20 chars): it catches
    looped boilerplate and repeated blocks without flagging legitimate code,
    which naturally repeats short identifiers.
    """
    if not text or len(text) < window * 2:
        return 0.0
    windows = [text[i:i + window] for i in range(0, len(text) - window, step)]
    if not windows:
        return 0.0
    return 1.0 - (len(set(windows)) / len(windows))


DEGENERATE_REPETITION_RATIO = 0.60

# Bounds for is_looped(). The floor is below the shortest bullet a triage or
# revdeck answer is made of and above a whitespace/indentation run; the ceiling
# is past the longest block worth calling a unit of repetition, so a model
# re-emitting a whole paragraph verbatim three times is still caught.
LOOP_MIN_PERIOD_CHARS = 24
LOOP_MAX_PERIOD_CHARS = 1200
LOOP_MIN_REPEATS = 3
LOOP_TAIL_CHARS = 6000


def is_looped(
    text: str,
    *,
    min_period: int = LOOP_MIN_PERIOD_CHARS,
    min_repeats: int = LOOP_MIN_REPEATS,
    max_period: int = LOOP_MAX_PERIOD_CHARS,
    tail_chars: int = LOOP_TAIL_CHARS,
) -> bool:
    """True when the tail of `text` is one short block emitted over and over.

    The prose counterpart to is_degenerate(), and a different measure because the
    two existing ones do not survive prose at a 16k budget:

    - `repetition_ratio` scores every fixed-width window, so legitimate
      structure accumulates score. Measured: 0.42 on 120 distinct sentences,
      0.56 on 200 distinct bullets -- both at or past the 0.60 threshold within
      doubling the length. At 4096 tokens that never happened; at 16000 a
      correct long answer reaches it.
    - `injection_gate.is_degenerate` normalises digits, so a correct ATT&CK
      list -- T1037.001 .. T1037.019 -- collapses to one repeated line. It
      flags a complete, correct sessions answer as degenerate. That is measured
      on a committed record, not hypothetical.

    Both therefore over-fire on exactly the answers a raise in budget was meant
    to buy. This one asks a narrower question -- is a *block* repeated? -- which
    is what a loop actually is, and which a long distinct answer never is
    however long it gets.

    Only the tail is examined. A loop starts somewhere and then never stops, so
    the last few thousand characters are where the repetition is unambiguous.

    A repetition that runs into the output budget is still a repetition, even
    though the budget cut it mid-block, so the trailing copy is allowed to be a
    partial one -- see the loop below for why, and
    tests/test_loop_detection.py for the offsets that were previously missed.
    What keeps a recovered answer from being flagged is unchanged and is the
    honest call: the differing tail breaks the alignment.

    Measured over all 1,503 committed analysis-slot records: 15 flagged, all
    `done_reason: length`, zero flags on any answer that finished on its own
    terms. That count is unchanged by accepting a partial trailing copy -- the
    relaxation adds no false positive on the committed corpus, and
    tests/test_loop_detection.py asserts both halves against the real records.
    """
    body = text or ""
    # min_repeats is 3 by construction: two whole copies plus one character of
    # a third is the least that is evidence rather than a coincidence. Guarded
    # here rather than trusted, because the parameter is overridable.
    if min_repeats < 3:
        raise ValueError(f"min_repeats must be at least 3, got {min_repeats}")
    if len(body) < min_period * min_repeats:
        return False
    tail = body[-tail_chars:]
    # A partial trailing copy still needs min_repeats - 1 whole ones above it,
    # so this is the widest period that can be established at all.
    longest = min(max_period, len(tail) // (min_repeats - 1))
    for period in range(min_period, longest + 1):
        # `period` is a period of the tail's final region when every character
        # matches the one `period` earlier. Scanning backwards from the end is
        # both cheap and phase-independent: it stops at the first character that
        # does not line up, which for a correct answer is the very first
        # comparison for almost every candidate period, and for a real loop is
        # the character just before the loop started.
        #
        # A run of `min_repeats - 1` whole copies plus one more character is
        # what a loop cut by the budget leaves behind: the trailing copy is a
        # prefix of the block, never a whole one, so demanding whole copies all
        # the way to the final character (`block * min_repeats == tail`) missed
        # the case a truncation produces -- which is the case loops occur in.
        needed = period * (min_repeats - 2) + 1
        limit = len(tail) - period
        matched = 0
        while matched < needed and matched < limit \
                and tail[-1 - matched] == tail[-1 - period - matched]:
            matched += 1
        if matched >= needed:
            return True
    return False


def is_degenerate(text: str, threshold: float = DEGENERATE_REPETITION_RATIO) -> bool:
    """True when `text` is looped output rather than a coherent answer."""
    return repetition_ratio(text) >= threshold


def was_capped(raw: dict[str, Any]) -> bool:
    """True when generation stopped on the output cap instead of finishing, so
    `raw` holds half an answer and never got to state a verdict.

    A capped answer scores zero everywhere and is never `ok`. It is not a
    refusal either: a refusal is a deliberate decline that earns partial
    credit, whereas a cap-cut answer never reached a verdict to decline with,
    and paying it the refusal point would hand out credit for an answer the
    model did not give.

    Deliberately the *same* predicate classify_outcome() stores the record
    with, so the published score and the stored outcome cannot disagree about
    which answers completed -- an unrecognised finish reason is
    uncapped-for-scoring for exactly the reason it is not stored as a pass.
    Reusing that function rather than restating the rule is what keeps the two
    from drifting apart again.

    Lives here, beside classify_outcome(), rather than in the one scorer that
    happened to need it first: the producers that can be handed a capped
    answer are three (evaluate-models.py, corpus/record_baseline.py and this
    module's own consumers in claims.py) and `evaluate-models.py` cannot be
    `import`ed by name. A predicate two of them cannot reach is a predicate one
    of them reimplements, and the reimplementation is what let a capped corpus
    answer keep its group hits and a capped record keep its claims.

    `raw` is any mapping carrying a `done_reason` key -- a chat() result, a
    record_baseline result, or a stored record's `timing` block. `error` is not
    consulted: a transport failure is an `outcome`, and a caller scoring model
    output has already decided what to do about one.
    """
    return classify_outcome(error=None, done_reason=raw.get("done_reason")) != OUTCOME_OK


PROVENANCE_SYNTHETIC = "synthetic"
# Synthetic input, live answers. See the module docstring: the split is by the
# provenance of the *input*, and this member is the case that is neither of the
# other two -- committable like `synthetic` (its prompts are this repo's
# fixtures, so there is no attacker IP or payload in it) but not fixture
# answers, which is what `captured` would falsely claim.
PROVENANCE_LIVE_MODEL = "live_model"
PROVENANCE_CAPTURED = "captured"
# Committable members first, the repo-refused one last: the order is the
# `--provenance` choices order and it lines the enum up with the single guard
# in TranscriptWriter.__init__, which has to name `captured` on its own.
PROVENANCES = (PROVENANCE_SYNTHETIC, PROVENANCE_LIVE_MODEL, PROVENANCE_CAPTURED)

# Tier A: objdump disassembly, what record_baseline.py has always fed models.
# Tier B: real Ghidra headless JSON, what production actually sees.
# Tier C: Ghidra output refined by LLM4Decompile-Ref (x86/x86-64 only).
TIERS = ("A", "B", "C")

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SYNTHETIC_ROOT = REPO_ROOT / "docs" / "benchmarks" / "runs"

TRANSCRIPT_FILENAME = "transcripts.jsonl"
RUN_FILENAME = "run.json"


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str | None:
    """Hash a reproducibility input. Missing files record as null, not as an
    exception -- an absent corpus manifest is a fact about the run worth
    storing, and must not abort a round that does not depend on it."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def new_run_id() -> str:
    """Sortable, collision-resistant, and readable in a directory listing."""
    return f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.urandom(4).hex()}"


def default_operator() -> str:
    return os.environ.get("APIARY_OPERATOR") or os.environ.get("USER") or "unknown"


@dataclass(frozen=True)
class Reproducibility:
    """The keys that make a stored answer re-interpretable later.

    Every one of these silently changes what a model was shown. Recording them
    beside the answer is what makes a score change six months from now
    attributable rather than mysterious -- the #568 stale-assumption failure,
    one layer down.
    """

    tier: str = "A"
    corpus_manifest_sha256: str | None = None
    ghidra_cache_key: str | None = None
    rubric_version: str | None = None
    claim_pool_version: str | None = None
    prompt_contract: dict[str, Any] | None = None
    # Which engine answered, and the two flags that decide what the answer is
    # worth: whether the KV cache was pushed back to host RAM after an OOM, and
    # whether Ollama had to take the model over. A transcript line that does not
    # say this cannot be attributed, and an unattributable line cannot be
    # compared against one from the other engine -- RAM-offloaded decode runs at
    # roughly a sixth of the on-card rate, so the recorded tokens/second means two
    # different things on the two engines.
    #
    # None means "not served through the engine seam", which is what every
    # replayed and rescored record predates it. Absence is honest; a filled-in
    # guess would not be.
    engine: str | None = None
    kv_offload_disabled: bool | None = None
    fallback_engine: str | None = None
    # Where the weights physically sat when the tokens were produced, as
    # measured off llama.cpp's own load log. These are the placement the run
    # cannot be read without: a 33/33 on-card decode and an 8/33 decode that
    # spilled to host RAM differ by an order of magnitude in latency at the
    # same nominal size, so a tokens/second with no placement beside it is not
    # comparable to one that has it.
    #
    # Taken as a group dict so serving.py stays the only place that knows how
    # they are measured, and named fields here so the key set is still decided
    # in one place. Every default is None: a record that predates this, and a
    # run whose log stated nothing, both keep null. A plausible-looking number
    # invented for a missing measurement is worse than an admitted blank --
    # a benchmark record that guesses is not a benchmark record.
    residency: dict[str, Any] | None = None

    # The context window the run was budgeted against, beside the one the
    # engine actually served. They are different quantities and only one of
    # them used to be recorded: `--fit-ctx` is the *minimum* fit may set, so it
    # settles on its own value (measured 2026-10-05: asked for 24576, served
    # 98048 on a 131072-context model), and a transcript carrying only the
    # served value contradicts its own request body. A per-request `n_ctx`
    # cannot reconcile them -- llama-server accepts the field and ignores it --
    # so both are stated and the gap is readable.
    n_ctx_requested: int | None = None

    _RESIDENCY_FIELDS = (
        ("gpu_layers", int),
        ("layers_total", int),
        ("vram_mib", float),
        ("kv_cache_mib", float),
        ("n_ctx", int),
        ("ram_offloaded", bool),
    )

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"unknown tier: {self.tier}")

    @classmethod
    def placement_from(cls, provenance: dict[str, Any] | None) -> dict[str, Any] | None:
        """The placement keys lifted out of a serving record, or None.

        serving.py merges the measured placement into the provenance dict
        alongside the other engine facts, so the caller does not have to know
        that layout -- and does not get to pick the keys, which is what keeps
        `as_dict()` the one place the shape is decided.
        """
        if not provenance:
            return None
        measured = {key: provenance.get(key) for key, _type in cls._RESIDENCY_FIELDS}
        # All-None is the same claim as None, and returning None keeps an
        # unmeasured run indistinguishable from one that predates the fields.
        return measured if any(value is not None for value in measured.values()) else None

    def residency_fields(self) -> dict[str, Any]:
        """The placement keys, flattened, absent ones as None.

        One rule for every caller: a key the measurement did not produce is
        still emitted, so two rows compared side by side have the same shape.
        """
        measured = self.residency or {}
        return {key: measured.get(key) for key, _type in self._RESIDENCY_FIELDS}

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "corpus_manifest_sha256": self.corpus_manifest_sha256,
            "ghidra_cache_key": self.ghidra_cache_key,
            "rubric_version": self.rubric_version,
            "claim_pool_version": self.claim_pool_version,
            "prompt_contract": self.prompt_contract,
            "engine": self.engine,
            "kv_offload_disabled": self.kv_offload_disabled,
            "fallback_engine": self.fallback_engine,
            **self.residency_fields(),
            "n_ctx_requested": self.n_ctx_requested,
        }


@dataclass
class RunMetadata:
    benchmark: str
    provenance: str = PROVENANCE_SYNTHETIC
    operator: str = field(default_factory=default_operator)
    run_id: str = field(default_factory=new_run_id)
    started_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    # A misconfigured run is never edited away; it is superseded by a new run
    # that names it here, because later scores depend on the original text.
    supersedes: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.provenance not in PROVENANCES:
            raise ValueError(f"unknown provenance: {self.provenance}")

    @property
    def directory_name(self) -> str:
        return f"{self.started_at[:10]}-{self.run_id}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "operator": self.operator,
            "benchmark": self.benchmark,
            "provenance": self.provenance,
            "supersedes": self.supersedes,
            "notes": self.notes,
        }


def _is_inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return False
    return True


def assert_repository_fixture_input(
    provenance: str, *sources: os.PathLike[str] | str
) -> None:
    """`live_model` claims the run's INPUT is this repository's fixtures.

    That claim is the entire reason the member is committable -- the answers are
    live, but nothing attacker-supplied is in the file -- and nothing checked
    it. Both `--provenance` setters are argparse `choices=PROVENANCES`, so
    before this a caller could file real attacker data under the one label the
    captured refusal does not catch, and the enum member asserted a property no
    code ever looked at.

    So the producers name the files their prompts are read from, and this is
    the check: each one has to be a file inside this repository. That is the
    same boundary TranscriptWriter.__init__ applies to the *destination* of a
    captured run, pointed at the *source* of a live-model one. A provenance
    that does not claim repository-fixture input is none of this function's
    business and returns immediately, so this adds nothing to what `synthetic`
    and `captured` do.

    What it cannot catch, stated rather than implied: a prompt pasted from
    somewhere else into a committed fixture, or a fixture that itself holds
    real data. Both are diffs a reviewer sees and neither is a flag problem.
    What is checked is that every byte the harness sends as a prompt is read
    out of a file in this tree, which is the strongest statement available
    without a data-flow analysis of the corpus.
    """
    if provenance != PROVENANCE_LIVE_MODEL:
        return
    for source in sources:
        path = Path(source)
        if not path.is_file() or not _is_inside_repo(path):
            raise ValueError(
                f"refusing to label this run {PROVENANCE_LIVE_MODEL!r}: its prompts are read "
                f"from {path}, which is not a file inside the repository ({REPO_ROOT}). "
                f"{PROVENANCE_LIVE_MODEL!r} means this repository's fixtures in and live model "
                f"answers out; label it {PROVENANCE_SYNTHETIC!r}, or write it outside the "
                f"repository with --provenance {PROVENANCE_CAPTURED!r}."
            )


class TranscriptWriter:
    """Appends one JSONL record per model call.

    JSONL rather than one large object so a run appends as it goes and a diff
    between two runs stays readable. An interrupted round therefore still
    leaves every answer it did obtain.
    """

    def __init__(self, root: str | os.PathLike[str], run: RunMetadata) -> None:
        self.run = run
        self.directory = Path(root).expanduser() / run.directory_name
        # `captured` alone, named explicitly rather than expressed as "every
        # member that is not committable": adding `live_model` to the enum must
        # not turn this into a set membership test, or real attacker data
        # relabelled as live-model would walk straight into the working tree.
        # The other two members are committable because their *input* is this
        # repository's fixtures, and that is the only thing this guard is about.
        if run.provenance == PROVENANCE_CAPTURED and _is_inside_repo(self.directory):
            raise ValueError(
                "refusing to write captured-data transcripts inside the repository: "
                f"{self.directory}. Real session transcripts contain attacker IPs and "
                "payloads; write them to an operator-only path with bounded retention."
            )
        self.path = self.directory / TRANSCRIPT_FILENAME
        if self.path.exists():
            raise ValueError(
                f"{self.path} already exists; a stored transcript is never rewritten. "
                "Record a new run with supersedes=<old run_id> instead."
            )
        self.directory.mkdir(parents=True, exist_ok=True)
        if run.provenance == PROVENANCE_CAPTURED:
            os.chmod(self.directory, 0o700)
        self.count = 0
        self._lines: list[str] = []
        (self.directory / RUN_FILENAME).write_text(
            json.dumps(run.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _flush(self) -> None:
        """Publish the file atomically: a crash mid-run can lose records, but
        it can never leave a half-written record on disk.

        # ponytail: rewrites the whole file per record, O(n^2) in the record
        # count. Append-then-fsync is the upgrade if a run ever gets to
        # thousands of records.
        """
        tmp = self.path.with_name(self.path.name + ".partial")
        tmp.write_text("".join(self._lines), encoding="utf-8")
        os.replace(tmp, self.path)

    def record(
        self,
        *,
        slot: str,
        case: str,
        workflow: str | None,
        model: dict[str, Any],
        request_body: dict[str, Any],
        reproducibility: Reproducibility,
        response: dict[str, Any] | None = None,
        parsed: Any = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Store one (run_id, slot, case, model, workflow) exchange.

        `request_body` is the literal dict posted to Ollama, messages included,
        so the prompt is recorded as *sent* rather than reconstructed from the
        fixtures -- a prompt you have to rebuild is a prompt you cannot trust.

        A failure is a measurement, not a gap: timeouts, refusals and malformed
        JSON are stored with the same fidelity as a success. For a derestricted
        round a refusal *is* the result.
        """
        messages = request_body.get("messages", [])
        raw_content = None if response is None else response.get("content")
        record = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run.run_id,
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operator": self.run.operator,
            "benchmark": self.run.benchmark,
            "provenance": self.run.provenance,
            "slot": slot,
            "case": case,
            "workflow": workflow,
            "model": model,
            "request": {
                "system_prompt": next((m["content"] for m in messages if m.get("role") == "system"), None),
                "user_prompt": next((m["content"] for m in messages if m.get("role") == "user"), None),
                "body": request_body,
                "body_sha256": sha256_json(request_body),
            },
            "response": {
                "raw": raw_content,
                "message": (response or {}).get("message"),
                "parsed": parsed,
                "parse_ok": parsed is not None,
                "tool_turns": (response or {}).get("tool_turns", []),
            },
            "timing": {
                "wall_seconds": (response or {}).get("wall_seconds"),
                "prompt_tokens": (response or {}).get("prompt_tokens"),
                "output_tokens": (response or {}).get("output_tokens"),
                "tokens_per_second": (response or {}).get("tokens_per_second"),
                "done_reason": (response or {}).get("done_reason"),
            },
            "reproducibility": reproducibility.as_dict(),
            # Populated by #1805-f's claim extraction, so an adjudicated verdict
            # can always be traced back to the sentence that produced it.
            "claim_ids": [],
            # done_reason is the only evidence of how generation ended, and
            # it is read here rather than at each call site so no caller can
            # store a cap-truncated answer as a success by forgetting to.
            "outcome": classify_outcome(
                error=error, done_reason=(response or {}).get("done_reason")
            ),
            "error": error,
        }
        self._lines.append(json.dumps(record, sort_keys=True) + "\n")
        self._flush()
        self.count += 1
        return record

    def close(self) -> dict[str, Any]:
        self._flush()
        summary = {
            **self.run.as_dict(),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "record_count": self.count,
            "transcripts": str(self.path),
            "transcripts_sha256": sha256_file(self.path),
        }
        (self.directory / RUN_FILENAME).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return summary

    def __enter__(self) -> "TranscriptWriter":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass
class SlotRecorder:
    """The per-slot handle threaded through the scorers.

    Bundles what every call in a slot shares -- the writer, the resolved model
    artifact, and the reproducibility keys -- so the scoring functions gain one
    parameter rather than six, and so a slot cannot accidentally record a
    different model than the one it evaluated.
    """

    writer: TranscriptWriter | None
    slot: str
    model: dict[str, Any]
    reproducibility: Reproducibility

    def record(
        self,
        *,
        case: str,
        workflow: str | None,
        request_body: dict[str, Any],
        response: dict[str, Any] | None = None,
        parsed: Any = None,
        error: str | None = None,
    ) -> None:
        if self.writer is None:
            return
        self.writer.record(
            slot=self.slot,
            case=case,
            workflow=workflow,
            model=self.model,
            request_body=request_body,
            reproducibility=self.reproducibility,
            response=response,
            parsed=parsed,
            error=error,
        )
