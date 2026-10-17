#!/usr/bin/env python3
"""Rescore the pre-#2393 stored baselines from their recorded answers (#2556).

Three result files in this directory were scored before #2393 (PR #2402)
widened polarity.py's prevention cues: baseline_results.json,
baseline_results_1948_remeasure.json and baseline_results_fixture_v2.json.
#2406 annotated each with the generation it was recorded under and left the
recomputation itself open, because the claim-backed adjudicator behind the
current matcher needs a local embedding model that was not reachable then.

This script closes that gap without ever touching the stored files. It reads
each source's recorded `answer` text, rescores it with the *current* scorer
(record_baseline.score, which is polarity.py post-#2393, optionally with
claims.forbidden_claim_adjudicator in front of the cue list) and writes the
result as a fresh run artifact under docs/benchmarks/runs/. The sources stay
annotated exactly as they are: a generation boundary means side-by-side
presentation, not rewritten history, and cross-generation diffing needs both
sides to survive.

If the embedding model is unreachable the script says so and exits 0. That is
the documented state, not a failure: the existing annotations remain the
source of truth until someone runs this against a host that has the model.

Two rules decide whether a stored answer earns anything here, and both are the
live scorer's rather than this file's. An answer the output cap ended scores
zero -- the `done_reason` travels into record_baseline.score(), which routes it
through transcripts.was_capped(), the one predicate every other scoring path
uses (#3172). And an answer that recorded no `done_reason` at all is not
scored either: it cannot be shown to have finished, so it is published as
unscorable instead of credited. All three sources are in that state (42 rows,
no `done_reason` anywhere -- they predate anything that recorded one), so once
these rules are reachable a regenerated artifact of them reads 0 across the
board with every case listed in `unscorable_cases`. That is the fail-closed
answer, and it is the honest one: a rescore cannot certify a completion it has
no evidence for.

See regenerate()'s comment for why they are not reachable yet: this entry point
hands rescore_source() the rubric envelope rather than its `cases`, a
pre-existing defect left alone here, so every case currently takes the
out_of_rubric carry-forward branch and score() is never reached.

Usage:
    ./regenerate_pre_2393.py --api-base http://<ollama-host>:11434
    ./regenerate_pre_2393.py --dry-run        # list what would be rescored
"""
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
BENCH_DIR = CORPUS_DIR.parent
REPO_ROOT = BENCH_DIR.parents[2]
sys.path.insert(0, str(BENCH_DIR))

from harmony_policy import refuse_harmony_model_without_adaptation  # noqa: E402  (path set above so the sibling module resolves)

# The pre-#2393 records, oldest first. Each is read, never written.
SOURCES = (
    "baseline_results.json",
    "baseline_results_1948_remeasure.json",
    "baseline_results_fixture_v2.json",
)

DEFAULT_API_BASE = "http://127.0.0.1:11434"
DEFAULT_EMBED_MODEL = "nomic-embed-text:latest"
DEFAULT_ADJUDICATOR = "qwen2.5-coder:7b-instruct-q4_K_M"
# Same request claims.py's adjudicator call sends, because that is the call
# this is re-running for the same answer. Named once so the refusal below can
# name the number the body actually carries.
ADJUDICATOR_NUM_PREDICT = 1024
UNAVAILABLE_NOTE = (
    "embedding model unavailable; existing annotations remain the source of truth"
)
# Why a row in a regenerated artifact earns nothing. Carried in the row itself
# rather than only in the artifact totals, because the number a reader is
# comparing has to be readable: a zero with no stated reason is a model that
# found nothing.
NO_DONE_REASON_NOTE = (
    "no recorded done_reason -- this stored answer cannot be shown to have "
    "finished, so it is rescored as unscorable rather than credited"
)


def stored_done_reason(stored: dict):
    """The finish reason this stored case recorded, or None if it recorded none.

    Two shapes, both read here rather than at each use: record_baseline's
    report puts `done_reason` on the case row beside the answer, and a
    transcripts record puts it in the `timing` block. A row that has neither
    carries no signal at all, which is the case rescore_source() refuses rather
    than guesses about -- not a reason to invent one.
    """
    reason = stored.get("done_reason")
    if reason is None:
        reason = (stored.get("timing") or {}).get("done_reason")
    return reason


class EmbeddingUnavailable(RuntimeError):
    """The local embedding model could not be reached or imported."""


def load_scorer():
    """Import the live scorer by path -- record_baseline.py is a script."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "record_baseline", CORPUS_DIR / "record_baseline.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_embedder(api_base: str, model: str):
    """Return claims.ollama_embedder, probed once so a dead host fails here.

    Probing is the point: without it every case would discover the missing
    model separately and half a run would already be on disk.
    """
    try:
        import claims
    except ImportError as exc:  # pragma: no cover - defensive, claims is a sibling
        raise EmbeddingUnavailable(f"claims module unimportable: {exc}") from exc
    embed = claims.ollama_embedder(api_base, model)
    try:
        embed("probe")
    except (urllib.error.URLError, OSError, ValueError, claims.ClaimError) as exc:
        raise EmbeddingUnavailable(f"{model} at {api_base}: {exc}") from exc
    return embed


def build_chat(api_base: str, model: str):
    """Ollama /api/chat in the shape claims.extract_claims expects.

    A transport failure returns empty text rather than raising: extract_claims
    turns that into a ClaimError, which forbidden_claim_adjudicator already
    reads as "settled nothing" and falls back to the deterministic cue list.

    The adjudicator is chosen here, so a harmony-served tag is refused here too:
    this body sends `think: false`, which empties the answer for the gpt-oss
    family, and forbidden_claim_adjudicator cannot tell that from an adjudicator
    that legitimately settled nothing -- every case would quietly rescore under
    the fallback cue list and the artifact would report a matcher generation
    that never ran. Refused before the closure exists, so no request is built.
    """
    refuse_harmony_model_without_adaptation(
        model, producer="corpus/regenerate_pre_2393.py",
        num_predict=ADJUDICATOR_NUM_PREDICT)
    base = api_base.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]

    def chat(system: str, prompt: str) -> str:
        body = json.dumps({
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
            "stream": False, "think": False, "format": "json",
            "options": {"temperature": 0, "seed": 144, "num_ctx": 8192,
                        "num_predict": ADJUDICATOR_NUM_PREDICT},
        }).encode()
        req = urllib.request.Request(f"{base}/api/chat", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=300) as response:
                return json.loads(response.read()).get("message", {}).get("content", "")
        except (urllib.error.URLError, OSError, ValueError):
            return ""

    return chat


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rescore_source(doc: dict, rubric: dict, scorer, adjudicator_for) -> dict:
    """Rescore every stored answer in one source document.

    Returns the per-case results plus the totals, in the same field names the
    source uses, so the two generations line up column for column.
    """
    cases = {}
    out_of_rubric = []
    total = 0
    total_max = 0
    for case_name, stored in sorted(doc.get("cases", {}).items()):
        case_rubric = rubric.get(case_name)
        if case_rubric is None:
            # The source has a case the current rubric generation does not
            # cover. Carry the stored result forward verbatim — regenerating
            # it would require a rubric that no longer exists. Flag it in the
            # output so a reader can see the gap.
            out_of_rubric.append(case_name)
            cases[case_name] = {
                "stored_score": stored.get("score"),
                "stored_group_hits": stored.get("group_hits"),
                "out_of_rubric": True,
            }
            total += stored.get("score", 0) or 0
            total_max += stored.get("max_score", 0) or 0
            continue
        answer = stored.get("answer", "")
        # The stored finish reason, read once and handed to the scorer so the
        # answer the cap ended cannot collect points offline. Nothing else in
        # this file decided that on its own: `score()` routes it through
        # transcripts.was_capped() -- the same predicate evaluate-models.py
        # routes every one of its scorers through and the claim path filters
        # on -- so an answer the cap ended scores zero here for exactly the
        # reason it scored zero live.
        done_reason = stored_done_reason(stored)
        fresh = scorer.score(answer, case_rubric, adjudicate=adjudicator_for(case_name),
                             done_reason=done_reason)
        gate_field = scorer.gate_field_for(case_rubric)
        if done_reason is None:
            # Fail closed, and separately from the cap. was_capped() reads an
            # absent done_reason as "not capped" on purpose (transcripts.py
            # carves `None` out because 14 committed records carry none, and
            # rewriting their fate from a missing field is not this script's
            # call). That carve-out is right for a stored transcript and wrong
            # here: this script re-publishes a score, and an answer with no
            # recorded finish signal is one no generation of this harness can
            # vouch for. All three pre-#2393 sources are in exactly that state
            # -- 42 rows, no done_reason anywhere -- because the cases were
            # written before anything recorded it. So they are unscorable: no
            # credit, `capped` deliberately absent (nothing says the cap ended
            # them) and the reason stated in the row.
            #
            # Zero and not a partial score, and `empty_answer` stays False for
            # the same reason record_baseline.score() keeps it False: the
            # report publishes that flag, and an unverifiable answer is not a
            # model that said nothing.
            fresh = {
                "score": 0,
                "max_score": len(case_rubric["required_groups"]) + 1,
                "group_hits": [False] * len(case_rubric["required_groups"]),
                gate_field: None,
                "empty_answer": False,
                "unscorable": NO_DONE_REASON_NOTE,
            }
        stored_gate = stored.get(gate_field, stored.get("injection_ok"))
        cases[case_name] = {
            **fresh,
            "stored_done_reason": done_reason,
            "stored_score": stored.get("score"),
            "stored_group_hits": stored.get("group_hits"),
            "stored_gate_field": gate_field,
            "stored_gate_value": stored_gate,
            "moved": (
                fresh["score"] != stored.get("score")
                or fresh["group_hits"] != stored.get("group_hits")
                or fresh[gate_field] != stored_gate
            ),
        }
        total += fresh["score"]
        total_max += fresh["max_score"]
    return {
        "cases": cases,
        "total_score": total,
        "total_max_score": total_max,
        "percent": round(100.0 * total / total_max, 1) if total_max else 0.0,
        "moved_cases": sorted(name for name, row in cases.items() if row.get("moved")),
        "out_of_rubric": sorted(out_of_rubric),
        "unscorable_cases": sorted(name for name, row in cases.items()
                                   if row.get("unscorable")),
        "done_reason_absent_cases": sum(
            1 for name, row in cases.items()
            if name not in out_of_rubric and row.get("stored_done_reason") is None),
    }


def build_artifact(source_path: Path, doc: dict, result: dict, *, api_base: str,
                   embed_model: str, adjudicator_model: str, generated_at: str) -> dict:
    return {
        "regenerated_for_issue": 2556,
        "generated_at": generated_at,
        "_scorer_generation": {
            "recorded_under": (
                "current corpus scorer -- record_baseline.score over polarity.py "
                "post-#2393 (PR #2402), with claims.forbidden_claim_adjudicator "
                "in front of the cue list"
            ),
            "regenerated_from": str(source_path.relative_to(REPO_ROOT)),
            "regenerated_from_sha256": sha256_of(source_path),
            "source_generation": (
                "pre-#2393 corpus scorer; see \"Scorer generations across stored "
                "results\" in docs/analysis/ghidra/benchmarks/corpus/README.md"
            ),
            "measurement": (
                "none -- the stored answers are rescored verbatim, no model was "
                "asked anything. Only the matcher moved."
            ),
            "adjudicator": {"api_base": api_base, "embed_model": embed_model,
                            "chat_model": adjudicator_model},
        },
        "model": doc.get("model"),
        "model_digest": doc.get("model_digest"),
        "qualification_request": doc.get("qualification_request"),
        "slice": doc.get("slice"),
        "case_count": len(result["cases"]),
        "stored_total_score": doc.get("total_score"),
        "stored_total_max_score": doc.get("total_max_score"),
        "stored_percent": doc.get("percent"),
        **{k: v for k, v in result.items() if k != "cases"},
        "cases": result["cases"],
    }


def render_readme(artifacts: list[dict]) -> str:
    lines = [
        "# Pre-#2393 baselines, rescored under the current matcher (#2556)",
        "",
        "Generated by `analysis/ghidra/benchmarks/corpus/regenerate_pre_2393.py`.",
        "No model was asked anything: every stored answer was rescored verbatim,",
        "so any delta below is the matcher moving, never measurement noise.",
        "The source files are read-only inputs and keep their own annotations --",
        "cross-generation diffing needs both sides on disk.",
        "",
        "| source | stored | rescored | moved cases |",
        "| --- | --- | --- | --- |",
    ]
    for art in artifacts:
        gen = art["_scorer_generation"]
        moved = ", ".join(art["moved_cases"]) or "none"
        lines.append(
            f"| `{gen['regenerated_from']}` | "
            f"{art['stored_total_score']}/{art['stored_total_max_score']} | "
            f"{art['total_score']}/{art['total_max_score']} | {moved} |"
        )
    lines.append("")
    return "\n".join(lines)


def regenerate(*, corpus_dir: Path, out_root: Path, api_base: str, embed_model: str,
               adjudicator_model: str, date_stamp: str, dry_run: bool = False) -> int:
    # Pre-existing, untouched by #3172 and left for the reviewer: this reads the
    # rubric ENVELOPE, where record_baseline.py reads `["cases"]`, so every
    # case_name misses the lookup below and every case takes rescore_source()'s
    # out_of_rubric branch -- which carries the stored score forward verbatim
    # and never calls score(). Verified: 0 of 14 cases resolve in each of the
    # three sources. Both rules below are therefore correct but unreachable
    # through this entry point until the envelope is unwrapped, and unwrapping it
    # is a different fix with a different blast radius: it turns on the rescore
    # proper, at which point every one of those 42 cases reads 0 and moves.
    rubric = json.loads((corpus_dir / "rev_cases_v2_rubric.json").read_text())
    sources = [corpus_dir / name for name in SOURCES]
    missing = [p.name for p in sources if not p.exists()]
    if missing:
        print(f"missing pre-#2393 source(s): {', '.join(missing)}", file=sys.stderr)
        return 1
    if dry_run:
        for path in sources:
            print(f"would rescore {path.name} ({sha256_of(path)[:12]})")
        return 0

    try:
        embed = build_embedder(api_base, embed_model)
    except EmbeddingUnavailable as exc:
        print(f"warning: {UNAVAILABLE_NOTE} ({exc})")
        return 0

    import claims
    scorer = load_scorer()
    chat = build_chat(api_base, adjudicator_model)

    def adjudicator_for(case_name: str):
        return claims.forbidden_claim_adjudicator(embed, chat, case=case_name)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_dir = out_root / f"pre-2393-regen-{date_stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    artifacts = []
    for path in sources:
        doc = json.loads(path.read_text())
        result = rescore_source(doc, rubric, scorer, adjudicator_for)
        artifact = build_artifact(path, doc, result, api_base=api_base,
                                  embed_model=embed_model,
                                  adjudicator_model=adjudicator_model,
                                  generated_at=generated_at)
        (run_dir / f"{path.stem}.rescored.json").write_text(
            json.dumps(artifact, indent=2) + "\n"
        )
        artifacts.append(artifact)
        print(f"{path.name}: {doc.get('total_score')} -> {artifact['total_score']} "
              f"of {artifact['total_max_score']} "
              f"(moved: {', '.join(artifact['moved_cases']) or 'none'})")

    (run_dir / "README.md").write_text(render_readme(artifacts))
    print(f"wrote {len(artifacts)} rescored artifact(s) to {run_dir}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api-base", default=DEFAULT_API_BASE,
                   help="Ollama base URL hosting the embedding and adjudicator models")
    p.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL)
    p.add_argument("--adjudicator-model", default=DEFAULT_ADJUDICATOR)
    p.add_argument("--corpus-dir", type=Path, default=CORPUS_DIR)
    p.add_argument("--out-root", type=Path, default=REPO_ROOT / "docs" / "benchmarks" / "runs")
    p.add_argument("--date", dest="date_stamp",
                   default=datetime.now(timezone.utc).strftime("%Y%m%d"),
                   help="YYYYMMDD stamp for the run directory name")
    p.add_argument("--dry-run", action="store_true",
                   help="list the sources and their hashes without contacting any model")
    args = p.parse_args(argv)
    return regenerate(corpus_dir=args.corpus_dir, out_root=args.out_root,
                      api_base=args.api_base, embed_model=args.embed_model,
                      adjudicator_model=args.adjudicator_model,
                      date_stamp=args.date_stamp, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
