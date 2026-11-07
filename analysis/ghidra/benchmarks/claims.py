#!/usr/bin/env python3
"""Adjudicated claim-pool scoring for the benchmark (issue #1805).

## Why the rubric score is not enough

Both existing scorers are substring matching -- `any(term in joined for term in
group)` against a fixed keyword list per case. Four consequences, all bad:

1. It rewards saying the word, not understanding it. "The loop iterates" scores
   the same as a correct account of the bounds check.
2. It cannot credit a correct insight nobody pre-listed. A model noticing that
   the XOR primitive is symmetric -- true, useful for triage, and stated in the
   case's own `ground_truth` -- earns nothing.
3. It cannot express "A found what B missed" at all, since that comparison only
   exists if it was enumerated in advance.
4. Verbosity wins: more synonyms hit more groups, and `forbidden` is empty on
   most cases, so padding is nearly free.

The irony is that `ground_truth` -- the actual semantic description -- sits in
the rubric and is not used for scoring at all.

Measured evidence that this matters, from #1805-e: Tier B beat Tier A by
+1.17 of 69 while **8 of 14 cases moved in both directions and cancelled**. The
aggregate says "+1.17"; what actually happened is that the model saw a
format-string bug it had missed and lost a file-persistence detail it had held.
A single number cannot carry that, which is what this module exists to fix.

## The scheme

1. **Decompose** each answer into atomic, individually checkable claims.
2. **Pool** across models per case, deduplicated *semantically* -- a model must
   not gain by rephrasing itself.
3. **Adjudicate each distinct claim once**, against ground truth, cheapest check
   first: the executable semantic harness where one applies, then the case's
   `ground_truth` prose, then a human ruling on the remainder.
4. **Score each model against the adjudicated pool**: coverage, precision,
   unique contribution, missed-by.
5. The pre-authored `required_groups` stays as a **floor**, not a ceiling: miss
   it and you still fail, however many novel claims you made.

Verdicts are `true`, `false`, or `unsupported` -- the last meaning plausible but
not derivable from what the model was shown. That is the hallucination signal
and is tracked separately from being wrong.

## Two rules enforced in code rather than trusted

**The adjudicator may not be a model in the round.** A candidate grading its own
novel claims is circular, and the failure is silent -- the scores still look
fine. `AdjudicationConfig` refuses to construct if the adjudicator tag appears
among the scored models.

**The pool is frozen and versioned.** Coverage is defined as a fraction of the
pool, so an unfrozen pool means a model's score moves because a *later* model
found something new. Old rounds are rescored against the frozen pool from their
stored transcripts (#1944), which is the whole reason those transcripts exist.

## What this module does not do

It does not decide verdicts by itself where the evidence is thin. Claims that no
deterministic check and no ground-truth match can settle are written to a review
queue with their provenance, and they stay `unadjudicated` -- excluded from every
score -- until a human rules. A pool that quietly guesses is worse than a small
pool, because the guess is invisible in the resulting number.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Iterable

BENCHMARKS_DIR = Path(__file__).resolve().parent
CORPUS_DIR = BENCHMARKS_DIR / "corpus"

sys.path.insert(0, str(BENCHMARKS_DIR))
from harmony_policy import refuse_harmony_model_without_adaptation  # noqa: E402
from transcripts import was_capped  # noqa: E402  (path set above so the sibling module resolves)

POOL_SCHEMA_VERSION = "apiary-claim-pool-v1"

VERDICT_TRUE = "true"
VERDICT_FALSE = "false"
VERDICT_UNSUPPORTED = "unsupported"
VERDICT_PENDING = "unadjudicated"
VERDICTS = (VERDICT_TRUE, VERDICT_FALSE, VERDICT_UNSUPPORTED, VERDICT_PENDING)

# Cosine similarity above which two claims are the same claim. Deliberately
# high: merging two genuinely different observations is worse than carrying a
# near-duplicate, because a merge silently deletes one model's finding while a
# duplicate only costs a little precision. Tuned to keep "encrypts each byte"
# and "XORs every byte" together while keeping "loops over the buffer" apart.
DEDUP_THRESHOLD = 0.86

EXTRACTION_SYSTEM = """You split reverse-engineering analyses into atomic claims.

An atomic claim is one thing that can independently be true or false: a single
behavioural assertion, one evidence citation, one risk judgement, or one
recommended next step. Split compound sentences. Drop hedging and restate each
claim as a plain assertion. Never add anything the text does not say, and never
merge two assertions into one.

Return a single JSON object and nothing else:
  {"claims": [{"text": string, "kind": string}, ...]}

kind is one of: behaviour, evidence, risk, next_step."""

# The adjudicator's own output budget, named because it is now read twice: once
# here when the request is built, and once by the harmony refusal below, which
# has to name the number this body actually carries. 1024 is for a JSON claim
# list, not a prose answer -- nothing here needs the 4096 analysis slots get.
EXTRACTION_NUM_PREDICT = 1024


class ClaimError(RuntimeError):
    pass


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical(text: str) -> str:
    """Cheap normalisation before the expensive semantic comparison.

    Only collapses things that are never a real difference in meaning -- case,
    whitespace, trailing punctuation. Anything subtler is left to the embedding,
    because a lexical rule that decides two claims are identical is exactly the
    substring matching this module replaces.
    """
    text = re.sub(r"\s+", " ", text.strip().lower())
    return text.rstrip(" .;:!")


@dataclass
class Claim:
    case: str
    text: str
    kind: str = "behaviour"
    verdict: str = VERDICT_PENDING
    verdict_source: str | None = None
    verdict_note: str | None = None
    # Which run/model first produced this claim, and everyone who has since made
    # it. Provenance is why a post-hoc addition can never be mistaken for a
    # pre-authored rubric entry.
    first_seen: dict[str, Any] = field(default_factory=dict)
    made_by: list[str] = field(default_factory=list)

    @property
    def claim_id(self) -> str:
        return _sha256(f"{self.case}|{canonical(self.text)}")[:16]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["claim_id"] = self.claim_id
        return data


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return 0.0 if not na or not nb else dot / (na * nb)


def _post_json(url: str, body: dict[str, Any], *, timeout: int, retries: int = 3) -> dict[str, Any]:
    """POST with 2-3 retries and backoff (#2032 item 1).

    A bare `urlopen` had no retry at all: one transient connection reset on a
    multi-hour local-GPU run lost every extraction since process start,
    because the pool was only ever written at the very end. Retrying the
    request is the cheap half of that fix; `main`'s incremental save is the
    other half.
    """
    data = json.dumps(body).encode()
    last_exc: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise ClaimError(f"{url} failed after {retries} attempts: {last_exc}")


def ollama_embedder(api_base: str, model: str = "nomic-embed-text:latest") -> Callable[[str], list[float]]:
    """Embeddings from the local Ollama, for semantic deduplication.

    Local by contract, like every other model call in this stack. The model is
    already deployed for `llm-search`, so this adds no new dependency.
    """
    cache: dict[str, list[float]] = {}
    base = api_base.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]

    def embed(text: str) -> list[float]:
        key = canonical(text)
        if key in cache:
            return cache[key]
        payload = _post_json(f"{base}/api/embed", {"model": model, "input": key}, timeout=120)
        vectors = payload.get("embeddings") or ([payload["embedding"]] if "embedding" in payload else [])
        if not vectors:
            raise ClaimError(f"no embedding returned for {key[:60]!r}")
        cache[key] = vectors[0]
        return cache[key]

    return embed


@dataclass
class AdjudicationConfig:
    """Who adjudicates, and the guarantee that it is not a contestant."""

    adjudicator_tag: str
    scored_models: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.adjudicator_tag in self.scored_models:
            raise ClaimError(
                f"{self.adjudicator_tag} is being scored in this round and cannot also "
                "adjudicate it -- a candidate grading its own novel claims is circular. "
                "Pick a model outside the round, or adjudicate by hand."
            )


def extract_claims(answer: str, case: str, *, chat: Callable[[str, str], str]) -> list[Claim]:
    """Decompose one answer into atomic claims via the adjudicator model."""
    raw = chat(EXTRACTION_SYSTEM, f"Case: {case}\n\nAnalysis to split:\n\n{answer}")
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end <= start:
        raise ClaimError(f"extractor returned no JSON object for {case}: {raw[:200]!r}")
    try:
        parsed = json.loads(raw[start:end + 1])
    except ValueError as exc:
        raise ClaimError(f"extractor JSON did not parse for {case}: {exc}") from exc
    claims = []
    for item in parsed.get("claims", []):
        text = (item.get("text") or "").strip()
        if text:
            claims.append(Claim(case=case, text=text, kind=item.get("kind") or "behaviour"))
    return claims


def merge_into_pool(pool: list[Claim], incoming: Iterable[Claim], embed: Callable[[str], list[float]],
                    *, model: str, run_id: str, threshold: float = DEDUP_THRESHOLD) -> dict[str, int]:
    """Add a model's claims to the pool, merging semantic duplicates.

    Deduplication is by meaning, not string: "encrypts each byte" and "XORs every
    byte" are one claim, and a model must not gain from rephrasing itself. An
    exact canonical match short-circuits the embedding call.
    """
    stats = {"new": 0, "merged": 0}
    by_case: dict[str, list[Claim]] = {}
    for claim in pool:
        by_case.setdefault(claim.case, []).append(claim)

    for claim in incoming:
        siblings = by_case.setdefault(claim.case, [])
        match = next((s for s in siblings if canonical(s.text) == canonical(claim.text)), None)
        if match is None and siblings:
            vector = embed(claim.text)
            best, score = None, 0.0
            for sibling in siblings:
                similarity = cosine(vector, embed(sibling.text))
                if similarity > score:
                    best, score = sibling, similarity
            if best is not None and score >= threshold:
                match = best
        if match is not None:
            if model not in match.made_by:
                match.made_by.append(model)
            stats["merged"] += 1
            continue
        claim.made_by = [model]
        claim.first_seen = {"model": model, "run_id": run_id,
                            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        siblings.append(claim)
        pool.append(claim)
        stats["new"] += 1
    return stats


# Ground truths are compound prose: several sentence-level facts joined into
# one paragraph (xor_decode_loop's is two sentences -- the XOR mechanism, then
# a symmetry note). An atomic claim only ever asserts one fact, so comparing
# it against the whole paragraph dilutes that one fact against every other
# sentence's vocabulary and can miss the cosine bar even for a correct
# restatement (#2030). Splitting on sentence boundaries (". ", "! ", "? ")
# recovers per-fact chunks at the same granularity as the claim.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def split_ground_truth(ground_truth: str) -> list[str]:
    """Break a compound ground_truth paragraph into sentence-level sub-facts."""
    stripped = ground_truth.strip()
    if not stripped:
        return []
    return [s.strip() for s in _SENTENCE_SPLIT_RE.split(stripped) if s.strip()]


def adjudicate_deterministic(claim: Claim, ground_truth: str, embed: Callable[[str], list[float]],
                             *, threshold: float = 0.80) -> bool:
    """Cheapest rung: does the case's own ground_truth already assert this?

    ground_truth is compound prose, so the claim is checked against each of
    its sentence-level sub-facts individually (see split_ground_truth) and the
    best match decides -- never against the whole paragraph as one string,
    which would dilute the claim's single fact against every other sentence
    and could never cross the bar even when correct.

    Only ever promotes a claim to `true`. It never rules anything false, because
    absence from a one-paragraph summary is not evidence that a claim is wrong --
    the ground_truth is a description, not an exhaustive enumeration. Everything
    it cannot settle goes to a human.
    """
    sub_facts = split_ground_truth(ground_truth)
    if not sub_facts:
        return False
    claim_vector = embed(claim.text)
    return any(cosine(claim_vector, embed(fact)) >= threshold for fact in sub_facts)


# The two readings a rubric `forbidden` term can carry inside an answer. A gate
# exists to catch the first ("this function has a buffer overflow") and must
# never fire on the second ("...thus preventing buffer overflow") -- the same
# distinction polarity.py's closed cue list approximates lexically
# (#1946/#2393). Stating the term both ways and letting the embedding pick is
# what makes the check structural rather than enumerated: "keeps the copy from
# overflowing", "cannot overflow", "rules out an overflow" and "protection
# against overflow" all simply land nearer the denial, with no cue listed
# anywhere (#2408).
FORBIDDEN_ASSERTION = "the code has {term}"
FORBIDDEN_DENIAL = "the code prevents {term}"

# How much nearer a claim must sit to one probe than to the other before the
# reading counts as settled. Both probes contain the term itself, so a claim
# that merely mentions it lands near-equidistant; under this margin the
# adjudicator abstains and says so, instead of returning a verdict that would
# be indistinguishable from a measured one in the resulting score.
POLARITY_MARGIN = 0.03


def forbidden_claim_adjudicator(embed: Callable[[str], list[float]],
                                chat: Callable[[str, str], str],
                                *, case: str = "", margin: float = POLARITY_MARGIN
                                ) -> Callable[[str, str], bool | None]:
    """Structural polarity for a rubric `forbidden` occurrence (#2408, #1805-f).

    Returns the callable `polarity.forbidden_hit` takes as `adjudicate`: given
    the clause an occurrence stands in and the forbidden term, it answers True
    when some atomic claim in that clause ASSERTS the term of the code, False
    when some claim denies or prevents it, and None when neither reading is
    settled -- in which case the caller keeps its own fast path.

    The decomposition is the pool's own (extract_claims), which restates every
    claim as a plain assertion and drops the hedging. Polarity therefore ends up
    in the claim text, where an embedding can see it, instead of in a fixed
    character window before the match. That is the whole point of folding this
    in: paraphrase tolerance stops being a hand-maintained cue list and becomes
    a property of the pool, so a phrasing nobody enumerated is not automatically
    a hit.

    One asserted claim is enough, mirroring the lexical path's rule that one
    unnegated occurrence is enough -- an answer that both denies and asserts the
    hazard has still asserted it.
    """
    def adjudicate(clause: str, term: str) -> bool | None:
        clause = (clause or "").strip()
        if not clause or not (term or "").strip():
            return None
        try:
            claims = extract_claims(clause, case, chat=chat)
        except ClaimError:
            # An extractor that returned nothing usable has settled nothing.
            # The caller's fast path is a better answer than a coin flip.
            return None
        asserted_probe = embed(FORBIDDEN_ASSERTION.format(term=term))
        denied_probe = embed(FORBIDDEN_DENIAL.format(term=term))
        verdict: bool | None = None
        for claim in claims:
            vector = embed(claim.text)
            spread = cosine(vector, asserted_probe) - cosine(vector, denied_probe)
            if spread >= margin:
                return True
            if spread <= -margin:
                verdict = False
        return verdict

    return adjudicate


def adjudicate_pool(pool: list[Claim], rubric: dict[str, Any], embed: Callable[[str], list[float]],
                    *, review_queue: Path | None = None) -> dict[str, int]:
    """Run the adjudication ladder over every pending claim."""
    counts = {VERDICT_TRUE: 0, VERDICT_FALSE: 0, VERDICT_UNSUPPORTED: 0, VERDICT_PENDING: 0}
    pending = []
    for claim in pool:
        if claim.verdict != VERDICT_PENDING:
            counts[claim.verdict] += 1
            continue
        ground_truth = (rubric.get(claim.case) or {}).get("ground_truth", "")
        if adjudicate_deterministic(claim, ground_truth, embed):
            claim.verdict = VERDICT_TRUE
            claim.verdict_source = "ground_truth-match"
            counts[VERDICT_TRUE] += 1
            continue
        counts[VERDICT_PENDING] += 1
        pending.append(claim)

    if review_queue is not None and pending:
        review_queue.parent.mkdir(parents=True, exist_ok=True)
        # #2032 item 2: a plain overwrite would clobber a human's
        # partially-completed rulings the moment extraction re-runs for any
        # reason (a new transcript merged, a rubric fix). Any row already
        # filled with a real verdict in the existing file is carried forward
        # verbatim instead of being regenerated as a placeholder.
        previously_ruled: dict[str, dict[str, Any]] = {}
        if review_queue.exists():
            try:
                for row in json.loads(review_queue.read_text()):
                    verdict = (row.get("verdict") or "").strip()
                    if verdict in (VERDICT_TRUE, VERDICT_FALSE, VERDICT_UNSUPPORTED):
                        previously_ruled[row.get("claim_id")] = row
            except (ValueError, OSError):
                pass  # a corrupt/missing existing file loses nothing new
        rows = [
            previously_ruled.get(c.claim_id) or
            {"claim_id": c.claim_id, "case": c.case, "text": c.text, "kind": c.kind,
             "first_seen": c.first_seen, "made_by": c.made_by,
             "ground_truth": (rubric.get(c.case) or {}).get("ground_truth", ""),
             "verdict": "<< true | false | unsupported >>"}
            for c in pending
        ]
        review_queue.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return counts


def apply_rulings(pool: list[Claim], rulings: Path) -> int:
    """Fold a completed human review file back into the pool.

    #2032 item 3: a ruling whose `claim_id` is not in the pool (typo, stale
    queue file from before a pool rebuild) used to vanish without a trace --
    "applied N" gave no denominator, so a mostly-stale file looked identical
    to a mostly-applied one. Unmatched ids are printed by name so a stale
    file is noticed instead of assumed complete.
    """
    rows = json.loads(rulings.read_text())
    by_id = {c.claim_id: c for c in pool}
    applied = 0
    dropped = []
    for row in rows:
        verdict = (row.get("verdict") or "").strip()
        if verdict not in (VERDICT_TRUE, VERDICT_FALSE, VERDICT_UNSUPPORTED):
            continue
        claim = by_id.get(row.get("claim_id"))
        if claim is None:
            dropped.append(row.get("claim_id"))
            continue
        claim.verdict = verdict
        claim.verdict_source = "human"
        claim.verdict_note = row.get("note")
        applied += 1
    if dropped:
        print(f"  {len(dropped)} ruling(s) skipped, claim_id not in pool: {dropped}",
              file=sys.stderr)
    return applied


def score_model(pool: list[Claim], model: str) -> dict[str, Any]:
    """Score one model against the adjudicated pool.

    - coverage: of all true claims, what fraction this model made. Recall of
      real findings.
    - precision: of this model's adjudicated claims, what fraction were true.
      The verbosity and hallucination brake -- without it, "mentions more"
      trivially wins.
    - unique: true claims no other model made. This is the number the whole
      revision is about.
    - missed: true claims others made and this one did not. The more actionable
      half when choosing a production model.

    Unadjudicated claims are excluded from every figure rather than assumed
    either way, and are reported so a thin pool is visible rather than flattering.
    """
    true_claims = [c for c in pool if c.verdict == VERDICT_TRUE]
    mine = [c for c in pool if model in c.made_by]
    mine_true = [c for c in mine if c.verdict == VERDICT_TRUE]
    mine_adjudicated = [c for c in mine if c.verdict != VERDICT_PENDING]
    unique = [c for c in mine_true if c.made_by == [model]]
    missed = [c for c in true_claims if model not in c.made_by]
    return {
        "model": model,
        "claims_made": len(mine),
        "coverage": round(len(mine_true) / len(true_claims), 3) if true_claims else None,
        "precision": round(len(mine_true) / len(mine_adjudicated), 3) if mine_adjudicated else None,
        "unique_true": len(unique),
        "unique_examples": [c.text for c in unique[:5]],
        "missed_true": len(missed),
        "missed_examples": [c.text for c in missed[:5]],
        "false": sum(1 for c in mine if c.verdict == VERDICT_FALSE),
        "unsupported": sum(1 for c in mine if c.verdict == VERDICT_UNSUPPORTED),
        "unadjudicated": sum(1 for c in mine if c.verdict == VERDICT_PENDING),
    }


def pool_version(pool: list[Claim]) -> str:
    """A content hash over adjudicated claims: the pool's identity.

    Stated in every report next to the Ghidra cache key. Coverage is a fraction
    of this set, so a report that does not name the version is unreadable a round
    later.

    `made_by` is folded in, not just `claim_id:verdict` (#2031): every per-model
    figure (`unique_true`, `missed_true`, coverage) is a function of provenance,
    not only of the verdict. A later round that only merges into existing
    claims -- no new claim ids, no verdict changes -- still moves those figures
    by appending to `made_by`, and the version must move with it or two reports
    can cite the same version while disagreeing.
    """
    payload = sorted(
        f"{c.claim_id}:{c.verdict}:{','.join(sorted(c.made_by))}" for c in pool
    )
    return _sha256("|".join(payload))[:16]


def save_pool(path: Path, pool: list[Claim], meta: dict[str, Any]) -> str:
    version = pool_version(pool)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": POOL_SCHEMA_VERSION,
        "pool_version": version,
        "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "claims": [c.as_dict() for c in pool],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return version


def load_pool(path: Path) -> tuple[list[Claim], dict[str, Any]]:
    """Load a frozen pool, rejecting a schema mismatch loudly (#2032 item 4).

    `Claim(**row)` raises a bare TypeError on an unrecognised field with no
    indication *why* -- a future schema bump would surface as a confusing
    crash deep in dataclass construction instead of a message naming both
    schema versions. A pool with no `schema_version` at all predates this
    field and is rejected the same way: too old to trust the shape of.
    """
    data = json.loads(path.read_text())
    found = data.get("schema_version")
    if found != POOL_SCHEMA_VERSION:
        raise ClaimError(
            f"{path}: schema_version {found!r} does not match this claims.py's "
            f"{POOL_SCHEMA_VERSION!r} -- migrate the pool or pin an older claims.py"
        )
    claims = []
    for row in data.get("claims", []):
        row.pop("claim_id", None)
        claims.append(Claim(**row))
    return claims, data


def load_transcripts(run_dir: Path) -> list[dict[str, Any]]:
    """Parse a run's transcripts, one JSON object per line.

    #2032 item 5: one malformed line used to crash the whole load with a bare
    JSONDecodeError naming neither the file nor the line. Each line is parsed
    individually and a bad one is reported with file+line and skipped,
    consistent with how a single failed extraction is already handled
    per-record in `main` rather than aborting the run.
    """
    path = run_dir / "transcripts.jsonl"
    records = []
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError as exc:
            print(f"  skipping malformed transcript line {path}:{lineno}: {exc}")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=Path, help="committed transcript run directories")
    parser.add_argument("--pool", type=Path, required=True, help="claim pool JSON to build or extend")
    parser.add_argument("--adjudicator", default="qwen3:14b",
                        help="model that extracts claims; must not be scored in this round")
    parser.add_argument("--api-base", default="http://127.0.0.1:11434")
    parser.add_argument("--review-queue", type=Path, help="write unadjudicated claims here for a human")
    parser.add_argument("--rulings", type=Path, help="apply a completed review file, then rescore")
    args = parser.parse_args()

    rubric = json.loads((CORPUS_DIR / "rev_cases_v2_rubric.json").read_text())["cases"]
    embed = ollama_embedder(args.api_base)

    records = []
    for run in args.runs:
        records.extend(load_transcripts(run))
    scored_models = tuple(sorted({r["model"]["tag"] for r in records}))
    AdjudicationConfig(adjudicator_tag=args.adjudicator, scored_models=scored_models)

    pool: list[Claim] = []
    meta: dict[str, Any] = {}
    if args.pool.exists():
        pool, previous = load_pool(args.pool)
        meta = previous.get("meta", {})
        print(f"loaded pool {previous.get('pool_version')} with {len(pool)} claims")

    if args.rulings:
        applied = apply_rulings(pool, args.rulings)
        print(f"applied {applied} human rulings")
    else:
        # The adjudicator is chosen here, so this is where it has to be
        # refused: a gpt-oss tag sends back the #2233 signature -- empty
        # content with the output budget spent on an analysis channel nobody
        # reads -- which extract_claims() cannot tell from a model that found
        # no claims, and which this producer has no adaptation to prevent.
        # Checked before the closure below exists, so no request can be built.
        refuse_harmony_model_without_adaptation(
            args.adjudicator, producer="claims.py", num_predict=EXTRACTION_NUM_PREDICT)

        def chat(system: str, prompt: str) -> str:
            body = {
                "model": args.adjudicator,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": prompt}],
                "stream": False, "think": False, "format": "json",
                "options": {"temperature": 0, "seed": 144, "num_ctx": 8192,
                            "num_predict": EXTRACTION_NUM_PREDICT},
            }
            payload = _post_json(f"{args.api_base.rstrip('/')}/api/chat", body, timeout=300)
            return payload.get("message", {}).get("content", "")

        # #2032 item 1: save after every record, not once at the end. A
        # multi-hour local-GPU extraction run that dies partway (Ollama
        # restart, network blip surviving the retries above) loses at most
        # one record's work instead of everything since process start -- the
        # pool file already round-trips through load_pool, so there is
        # nothing incremental-save-specific to reconcile on the next run.
        totals = {"new": 0, "merged": 0}
        for record in records:
            # #2032 item 5: a record missing a required key (malformed or
            # from an older transcript shape) is skipped with a message that
            # names what's missing, not a raw KeyError from deep inside the
            # loop.
            case = record.get("case")
            model_tag = (record.get("model") or {}).get("tag")
            run_id = record.get("run_id")
            raw = (record.get("response") or {}).get("raw")
            missing = [name for name, val in
                       (("case", case), ("model.tag", model_tag), ("run_id", run_id))
                       if not val]
            if missing:
                print(f"  skipping record missing {missing}: {json.dumps(record)[:120]!r}")
                continue
            if record.get("outcome") != "ok" or not raw:
                continue
            # The stored `outcome` cannot be the last word here. It is only
            # written by classify_outcome(), which did not exist when the 512
            # cap cut 940 records across docs/benchmarks/runs/ -- every one of
            # them is committed with `outcome: "ok"` and a `done_reason` of
            # `length`. So the cap is re-derived from the evidence the record
            # carries, through the same predicate every scorer uses.
            #
            # It has to be. A half-written answer decomposes into exactly the
            # claims it happened to complete, and once merged those are
            # indistinguishable from a finding: they are attributed to the
            # model that was cut off, they can adjudicate a true claim `true`
            # on its authority, and they lower every other model's precision
            # against the frozen pool. Failing closed here is also what keeps a
            # roster run's claim count honest about how many answers finished.
            if was_capped(record.get("timing") or {}):
                continue
            try:
                claims = extract_claims(raw, case, chat=chat)
            except ClaimError as exc:
                print(f"  extract failed {case} ({model_tag}): {exc}")
                continue
            stats = merge_into_pool(pool, claims, embed, model=model_tag, run_id=run_id)
            totals["new"] += stats["new"]
            totals["merged"] += stats["merged"]
            print(f"  {case:24s} {model_tag:34s} "
                  f"+{stats['new']} new, {stats['merged']} merged")
            save_pool(args.pool, pool, {**meta, "scored_models": list(scored_models),
                                        "adjudicator": args.adjudicator,
                                        "runs": [str(r) for r in args.runs],
                                        "extraction_in_progress": True})
        print(f"\n{totals['new']} new claims, {totals['merged']} merged into existing")

    counts = adjudicate_pool(pool, rubric, embed, review_queue=args.review_queue)
    print(f"verdicts: {counts}")

    # `meta` is loaded verbatim from the pool file on every run and `update()`
    # only ever adds keys, so a single crashed extraction would otherwise stamp
    # `extraction_in_progress` on every pool built afterwards -- including
    # complete ones. Clear it here: reaching this line means the extraction
    # loop finished, so the marker is false by construction.
    meta.pop("extraction_in_progress", None)
    meta.update({"scored_models": list(scored_models), "adjudicator": args.adjudicator,
                 "runs": [str(r) for r in args.runs]})
    version = save_pool(args.pool, pool, meta)
    print(f"pool {version} saved to {args.pool} ({len(pool)} claims)")

    print("\nper-model scores against the frozen pool:")
    for model in scored_models:
        result = score_model(pool, model)
        print(f"  {result['model']}")
        print(f"    coverage={result['coverage']} precision={result['precision']} "
              f"unique_true={result['unique_true']} missed_true={result['missed_true']} "
              f"unadjudicated={result['unadjudicated']}")
    if args.review_queue and counts[VERDICT_PENDING]:
        print(f"\n{counts[VERDICT_PENDING]} claims need a human ruling: {args.review_queue}")
        print("Scores above exclude them; they are not assumed true or false.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
