#!/usr/bin/env python3
"""Repeat-stability probe for claims.py's LLM-as-judge adjudicator (#3077).

Not a task-accuracy benchmark, and not a test of the paper at
arXiv:2609.04198 (shared multi-tenant serving instability) -- see
docs/benchmarks/2026-09-08-judge-trust-applicability.md for why that paper's
own mechanism does not apply here (single Ollama instance, OLLAMA_NUM_PARALLEL=1,
no concurrent batch to be unstable across).

What this probes instead is a gap specific to this codebase: claims.py's
`extract_claims()` pins temperature=0/seed=144 (claims.py:623) but, unlike
evaluate-models.py and probe-gpu-capabilities.py, never brackets its calls
with unload() -- so the adjudicator runs against whatever state the shared
`ollama` instance already happens to be in. #2642/#2646 (see
docker-compose.ghidra.yml and EVIDENCE.md) already measured that a resident
(kept-warm) Ollama slot returns different text for an identical prompt at
temperature 0 with a fixed seed, while a freshly cold-loaded one reproduces
byte-identically. This probe repeats the exact same extract_claims() call
--repeats times, optionally cold-loading (`ollama stop` equivalent, via the
existing unload() helper) before each one, and reports whether the raw
response text and the extracted claim set are byte-identical / set-identical
across repeats.

## Do not run this against the live homeserver GPU right now

The round-7 cold run is live at the time this probe was written
(OLLAMA_MAX_LOADED_MODELS=1 on that host). Any call this script makes --
including a --cold run's unload() -- loads or evicts a model on whatever
Ollama instance --base-url points at. Against the shared homeserver instance
that is exactly the "one stray inference evicts the loaded model mid-protocol"
hazard the cold run must be protected from.

--dry-run makes zero network calls: it only prints the repeat plan (request
bodies, protocol, model) as JSON and exits. That is the only mode safe to run
before the cold run reports 96/96 MODEL_DONE. Once it does:

    python3 probe-judge-repeat-stability.py \\
        --base-url http://127.0.0.1:11434 \\
        --answer-file /path/to/a/sample/analysis/answer.txt \\
        --case probe_case --repeats 3 --cold

Run it twice: once with --cold (isolates the adjudicator's own determinism,
matching the protocol run_injection_pair.sh already uses for models under
test) and once without (measures the resident-state condition the live
claims.py CLI actually runs under today, since its main() never calls
unload()). A stability claim needs both, and needs repeats -- N=1 proves
nothing about drift.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claims as claims_mod  # noqa: E402  (sys.path must be set first)
from harmony_policy import refuse_harmony_model_without_adaptation  # noqa: E402


def _load_evaluate_models():
    # evaluate-models.py has a hyphen, so it can't be `import`ed by name --
    # same workaround probe-gpu-capabilities.py already uses.
    path = Path(__file__).resolve().parent / "evaluate-models.py"
    spec = importlib.util.spec_from_file_location("evaluate_models", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["evaluate_models"] = module
    spec.loader.exec_module(module)
    return module


def _chat_body(adjudicator: str, system: str, prompt: str) -> dict[str, Any]:
    # Exact shape of claims.py's closure -- same model options, so a
    # drift finding is about the adjudicator, not about a probe using
    # different generation parameters. The budget is read off claims.py rather
    # than restated: it is the same number, and a copy is how a probe ends up
    # describing a request the thing it probes no longer sends.
    return {
        "model": adjudicator,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": prompt}],
        "stream": False, "think": False, "format": "json",
        "options": {"temperature": 0, "seed": 144, "num_ctx": 8192,
                    "num_predict": claims_mod.EXTRACTION_NUM_PREDICT},
    }


def run_repeats(base_url: str, adjudicator: str, case: str, answer: str,
                repeats: int, cold: bool) -> dict[str, Any]:
    base = base_url.rstrip("/")

    def chat(system: str, prompt: str) -> str:
        payload = claims_mod._post_json(f"{base}/api/chat", _chat_body(adjudicator, system, prompt),
                                        timeout=300)
        return payload.get("message", {}).get("content", "")

    unload = _load_evaluate_models().unload

    trials = []
    for i in range(repeats):
        if cold:
            unload(base, adjudicator)
        started = time.time()
        try:
            raw_claims = claims_mod.extract_claims(answer, case, chat=chat)
        except claims_mod.ClaimError as exc:
            trials.append({"trial": i, "error": str(exc), "elapsed_seconds": round(time.time() - started, 2)})
            continue
        canonical_claims = sorted(
            (c.kind, claims_mod.canonical(c.text)) for c in raw_claims
        )
        trials.append({
            "trial": i,
            "claim_count": len(raw_claims),
            "claims_sha256": hashlib.sha256(
                json.dumps(canonical_claims, sort_keys=True).encode()
            ).hexdigest(),
            "claims": canonical_claims,
            "elapsed_seconds": round(time.time() - started, 2),
        })

    ok_trials = [t for t in trials if "error" not in t]
    hashes = {t["claims_sha256"] for t in ok_trials}
    return {
        "case": case,
        "adjudicator": adjudicator,
        "protocol": "cold" if cold else "resident",
        "repeats": repeats,
        "trials": trials,
        "claim_set_identical_across_trials": len(hashes) <= 1 and len(ok_trials) == repeats,
        "distinct_claim_sets": len(hashes),
        "errors": [t for t in trials if "error" in t],
    }


def plan(base_url: str, adjudicator: str, case: str, answer: str,
         repeats: int, cold: bool) -> dict[str, Any]:
    """What run_repeats would send, with no network call -- the --dry-run path."""
    return {
        "base_url": base_url,
        "adjudicator": adjudicator,
        "case": case,
        "protocol": "cold" if cold else "resident",
        "repeats": repeats,
        "per_trial_action": (
            ["unload(adjudicator) via /api/generate keep_alive=0", "POST /api/chat"] if cold
            else ["POST /api/chat"]
        ),
        "request_body_template": _chat_body(adjudicator, claims_mod.EXTRACTION_SYSTEM,
                                            f"Case: {case}\n\nAnalysis to split:\n\n<answer text>"),
        "note": "no network call made in --dry-run",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--adjudicator", default="qwen3:14b",
                        help="must match the model claims.py's main() would use as --adjudicator")
    parser.add_argument("--case", default="probe_case")
    parser.add_argument("--answer", help="literal answer text to decompose")
    parser.add_argument("--answer-file", type=Path, help="read answer text from this file")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--cold", action="store_true",
                        help="unload the adjudicator before every repeat (matches "
                             "run_injection_pair.sh's cold-slot protocol); omit to probe "
                             "the resident-state condition claims.py's own CLI runs under today")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the repeat plan and exit; makes no network call, "
                             "safe to run while the GPU host is busy with another protocol")
    args = parser.parse_args()

    if not args.dry_run and not args.answer and not args.answer_file:
        parser.error("--answer or --answer-file is required unless --dry-run")

    if not args.dry_run and args.repeats < 2:
        parser.error("--repeats must be >= 2 -- a stability claim from a single "
                      "trial proves nothing about drift (see module docstring)")

    # The adjudicator is chosen here, and this probe has no #2233 harmony
    # adaptation: `think: false` sends back empty content for the gpt-oss
    # family, every trial would report the same zero claim set, and the verdict
    # would read STABLE -- a stability finding about a model that answered
    # nothing. Refused rather than measured, on both paths: --dry-run's whole
    # output is the request that would go out, so printing the template for a
    # cell this probe would refuse is how the refusal gets copied past.
    refuse_harmony_model_without_adaptation(
        args.adjudicator, producer="probe-judge-repeat-stability.py",
        num_predict=claims_mod.EXTRACTION_NUM_PREDICT)

    answer = args.answer or (args.answer_file.read_text() if args.answer_file else
                             "placeholder answer text for --dry-run planning")

    if args.dry_run:
        print(json.dumps(plan(args.base_url, args.adjudicator, args.case, answer,
                              args.repeats, args.cold), indent=2, sort_keys=True))
        return 0

    result = run_repeats(args.base_url, args.adjudicator, args.case, answer,
                         args.repeats, args.cold)
    print(json.dumps(result, indent=2, sort_keys=True))
    verdict = "STABLE" if result["claim_set_identical_across_trials"] else "UNSTABLE"
    print(f"\n{verdict}: {result['distinct_claim_sets']} distinct claim set(s) across "
          f"{result['repeats']} {result['protocol']} repeats "
          f"({len(result['errors'])} error(s))", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
