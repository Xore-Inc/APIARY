#!/usr/bin/env python3
"""Score an engine against a small real-payload corpus: actual honeypot
captures, not synthetic fixtures. Scored by evidence grounding rather than
an externally-authored ground truth: does the model's free-text answer
correctly describe behavior implied by the real, mechanically-extracted
evidence it was shown (imports/strings/sections), rather than guessing at
malware family or intent. This matches #159's own stated evaluation
principle ("supported facts versus inference... evidence grounding matters
more than lexical similarity") applied to real rather than synthetic input.

This intentionally does NOT try to score "is the classification correct" --
there is no trustworthy external label for arbitrary live captures without
running a second, independent analysis (capa, sandbox detonation, etc.) and
trusting *that* as ground truth, which just moves the goalposts. Grounding
(did the model correctly cite real evidence in front of it) is the one
thing that can be checked with zero assumptions.

Usage:
    python3 run_real_corpus_eval.py llama_cpp http://127.0.0.1:8080 \\
        --evidence-dir ./evidence --rubric ./example-rubric.json

Producing the evidence directory (never commit real samples -- see README.md):
    python3 extract_evidence.py /path/to/captured.bin ./evidence/<sha256>.evidence.json
"""
import argparse
import glob
import json
import os
import sys
import urllib.request
from pathlib import Path

# Running this as a script puts engine-benchmark/ on sys.path, not its parent --
# add benchmarks/ so harmony_policy resolves, same pattern as corpus_eval.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harmony_policy import refuse_harmony_model_without_adaptation  # noqa: E402

# Production ai_triage's import budget: ghidra-worker.py slices its
# deduplicated list to GHIDRA_TRIAGE_MAX_IMPORTS (default 150) and
# docs/analysis/ghidra/AI_TRIAGE.md documents the result as "150/312
# imports". Prompt parity is this script's stated premise, and it held for
# strings while imports quietly stayed unbounded -- an import-heavy live
# capture got shown evidence production would never present (#2050). Kept
# here rather than in extract_evidence.py: extraction records every import
# so the evidence file remains a complete mechanical artifact; presentation
# decides how much of it a model sees.
TRIAGE_MAX_IMPORTS = 150


def build_prompt(evidence):
    shown_imports = evidence["imports"][:TRIAGE_MAX_IMPORTS]
    imports_block = "\n".join(f"  {imp}" for imp in shown_imports)
    interesting_strings = [s for s in evidence["strings_sample"] if len(s) < 40][:15]
    strings_block = "\n".join(f"  {s}" for s in interesting_strings) or \
        "  (no short human-readable strings found; sample dominated by high-entropy/encoded data)"
    sections = ", ".join(f"{s['name']}(entropy={s['entropy']})" for s in evidence["sections"])
    kind = "DLL" if evidence["is_dll"] else "EXE"
    # The "shown of N" header mirrors ghidra-worker.py's triage prompt block;
    # the model should be able to tell it saw a subset, not the whole truth.
    return (
        f"Q: A captured Windows PE32 {kind} was analyzed. Based on this evidence, "
        f"describe what the program does and any suspicious behavior.\n\n"
        f"IMPORTS ({len(shown_imports)} shown of {evidence['imports_count']}):\n{imports_block}\n\n"
        f"NOTABLE STRINGS:\n{strings_block}\n\n"
        f"SECTIONS: {sections}\n\n"
        f"A:"
    )


def score(text, required_groups):
    lowered = text.lower()
    hits = []
    for entry in required_groups:
        label, terms = entry["label"], entry["terms"]
        hit = any(t.lower() in lowered for t in terms)
        hits.append((label, hit))
    points = sum(1 for _, hit in hits if hit)
    return points, len(required_groups), hits


def call_ollama(base_url, model, prompt, n_predict, repeat_penalty, seed):
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0, "seed": seed, "top_k": 1, "repeat_penalty": repeat_penalty, "num_predict": n_predict},
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["response"]


def call_llama_cpp(base_url, prompt, n_predict, repeat_penalty, seed):
    body = json.dumps({
        "prompt": prompt, "n_predict": n_predict, "temperature": 0, "seed": seed,
        "repeat_penalty": repeat_penalty, "top_k": 1,
    }).encode()
    req = urllib.request.Request(f"{base_url}/completion", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["content"]


def call_vllm(base_url, model, prompt, n_predict, seed, top_k=None, repetition_penalty=None):
    # #832: see corpus_eval.py's call_vllm for why these matter -- omitted
    # by default vLLM falls back to no repeat penalty and unset top_k,
    # which is NOT equivalent to llama.cpp/Ollama's settings used here.
    payload = {"model": model, "prompt": prompt, "max_tokens": n_predict, "temperature": 0, "seed": seed}
    if top_k is not None:
        payload["top_k"] = top_k
    if repetition_penalty is not None:
        payload["repetition_penalty"] = repetition_penalty
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{base_url}/v1/completions", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["choices"][0]["text"]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("engine", choices=["ollama", "llama_cpp", "vllm"])
    p.add_argument("base_url")
    p.add_argument("--model", default="")
    p.add_argument("--evidence-dir", default=".", help="directory of *.evidence.json files produced by extract_evidence.py")
    p.add_argument("--rubric", required=True, help="JSON file: {\"required_groups\": [{\"label\": str, \"terms\": [str, ...]}, ...]}")
    p.add_argument("--n-predict", type=int, default=180)
    p.add_argument("--repeat-penalty", type=float, default=1.1)
    p.add_argument("--seed", type=int, default=66)
    p.add_argument("--vllm-top-k", type=int, default=None, help="vLLM only. See corpus_eval.py's flag of the same name.")
    p.add_argument("--vllm-repetition-penalty", type=float, default=None, help="vLLM only. See corpus_eval.py's flag of the same name.")
    args = p.parse_args()

    if args.engine in ("ollama", "vllm") and not args.model:
        raise SystemExit(f"--model is required for engine={args.engine}")

    # --model is chosen here, so it is refused here: the call_* bodies above
    # carry a num_predict and no #2233 harmony adaptation, so a gpt-oss tag
    # burns the budget on an analysis channel and returns empty content, and
    # every grounding score derived from it would be published as a zero the
    # model never earned. Refused rather than widened -- see corpus_eval.py's
    # refusal for the same argument. engine=llama_cpp takes one model per
    # server process and ignores --model, so there is no tag to read a family
    # off and nothing to refuse here.
    if args.engine in ("ollama", "vllm"):
        refuse_harmony_model_without_adaptation(
            args.model, producer="engine-benchmark/run_real_corpus_eval.py",
            num_predict=args.n_predict)

    files = sorted(glob.glob(os.path.join(args.evidence_dir, "*.evidence.json")))
    if not files:
        raise SystemExit(f"no *.evidence.json found in {args.evidence_dir} -- run extract_evidence.py first")
    required_groups = json.load(open(args.rubric))["required_groups"]

    total_score, total_max, errored_samples = 0, 0, 0
    samples_out = []
    for i, path in enumerate(files):
        evidence = json.load(open(path))
        sample_id = os.path.basename(path).split(".")[0]
        prompt = build_prompt(evidence)
        try:
            if args.engine == "ollama":
                text = call_ollama(args.base_url, args.model, prompt, args.n_predict, args.repeat_penalty, args.seed)
            elif args.engine == "llama_cpp":
                text = call_llama_cpp(args.base_url, prompt, args.n_predict, args.repeat_penalty, args.seed)
            else:
                text = call_vllm(args.base_url, args.model, prompt, args.n_predict, args.seed,
                                  top_k=args.vllm_top_k, repetition_penalty=args.vllm_repetition_penalty)
        except Exception as e:
            print(f"  [{i+1}/{len(files)}] {sample_id}: ERROR {e}", file=sys.stderr)
            # An errored sample stays in the denominator whether the engine
            # answered or not: dropping out here used to make n_samples mean
            # "files found" while the totals summed over survivors only, so
            # cross-engine pct values were computed over different, unstated
            # subsets (#2050). Errored samples differing per engine is not a
            # footnote here -- reliability differences are one of the things
            # this benchmark measures. Same shape as corpus_eval.py's
            # post-#2385 handling of its identical gap.
            mx = len(required_groups)
            samples_out.append({
                "sample": sample_id, "error": str(e),
                "score": 0, "max": mx, "hits": None,
                "output": None,
            })
            errored_samples += 1
            total_max += mx
            continue
        pts, mx, hits = score(text, required_groups)
        total_score += pts
        total_max += mx
        print(f"  [{i+1}/{len(files)}] {sample_id}  {pts}/{mx}  {hits}", file=sys.stderr)
        print(f"      output: {text[:200]!r}", file=sys.stderr)
        # Full raw completion kept per sample (mirrors corpus_eval.py): what
        # an engine actually said on real captures is the whole point of the
        # real-corpus slice; `text` is already in hand.
        samples_out.append({
            "sample": sample_id,
            "score": pts, "max": mx, "hits": [list(h) for h in hits],
            "output": text,
        })

    print(json.dumps({
        "engine": args.engine, "model": args.model, "total_score": total_score, "total_max": total_max,
        "pct": round(100 * total_score / total_max, 1) if total_max else None,
        "n_samples": len(files),
        "errored_samples": errored_samples,
        "samples": samples_out,
    }))


if __name__ == "__main__":
    main()
