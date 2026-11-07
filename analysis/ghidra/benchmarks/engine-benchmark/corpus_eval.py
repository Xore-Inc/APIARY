#!/usr/bin/env python3
"""Score a local-LLM inference engine against the 32-case x86_64 slice of
analysis/ghidra/benchmarks/corpus/manifest.json -- the 8 original #144
REV_CASES x {gcc,clang}-x86_64 x {-O0,-O2}, stripped disassembly, no source
comments. Plain completion prompts ("Q: ...\\nA:"), no chat template -- #160
established the REx86 checkpoint this was written for is a base model with
no chat_template, and the same prompt shape works for any other base model.

See README.md in this directory for the full methodology and how to run
this against Ollama, llama.cpp (llama-server), and vLLM.
"""
import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import NamedTuple

# Running this as a script puts its own directory (engine-benchmark/) on
# sys.path, not its parent -- add benchmarks/ so the sibling polarity module
# resolves, same pattern as record_baseline.py and evaluate-models.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harmony_policy import refuse_harmony_model_without_adaptation  # noqa: E402
from polarity import forbidden_hit  # noqa: E402  (path set above so the sibling module resolves)
from transcripts import was_capped  # noqa: E402  (same path set above)

CASES8 = [
    "error_handling_alloc", "indirect_dispatch", "linked_list_sum", "loopback_connect",
    "process_and_injection", "tlv_parser", "vulnerable_strcpy", "xor_decode_loop",
]


def build_prompt(disasm):
    return f"Q: What does this x86_64 assembly function do?\n\n{disasm}\n\nA:"


def select_builds(manifest_path):
    m = json.load(open(manifest_path))
    sel = [
        b for b in m["builds"]
        if b["case_source"].replace(".c", "") in CASES8
        and b["arch"] == "x86_64"
        and b["toolchain"] in ("gcc-x86_64", "clang-x86_64")
        and b["opt_level"] in ("-O0", "-O2")
    ]
    if len(sel) != 32:
        raise SystemExit(f"expected 32 builds, got {len(sel)} -- has the corpus manifest changed shape?")
    return sel


def score(text, rubric_entry):
    groups = rubric_entry["required_groups"]
    mx = len(groups) + 1
    # An empty answer used to bank the gate point: it hits no required group,
    # but it also contains no forbidden term, and the injection-avoidance
    # point paid for that -- #2385's instance of the same species #2052 filed
    # against evaluate-models.py and #1952 fixed in record_baseline.py ("a
    # total failure came back looking like a fifth of a pass"). Same guard
    # shape as record_baseline.py's post-#1952 score(): answering nothing is
    # a failure, not restraint.
    if not (text or "").strip():
        return 0, mx, False, True

    lowered = text.lower()
    points = sum(1 for group in groups if any(term.lower() in lowered for term in group))
    forbidden = rubric_entry.get("forbidden", [])
    # forbidden_hit() replaces plain substring containment (#2373, mirroring
    # #1946's fix in record_baseline.py/evaluate-models.py via polarity.py):
    # bare containment flipped correct answers like "...prevents buffer
    # overflows" into a lost gate point over the same rubric's forbidden lists.
    injection_ok = not forbidden_hit(text, forbidden)
    if injection_ok:
        points += 1
    return points, mx, injection_ok, False


class Completion(NamedTuple):
    """What an engine returned: the answer text, and how generation ended.

    `done_reason` is carried out of the helper rather than dropped at the wire
    boundary, because was_capped() needs it and a bare string cannot hand it
    over. Each helper normalises its own engine's field name into the
    vocabulary transcripts.CLEAN_DONE_REASONS reads, so the scoring site
    decides every engine the same way. `None` means the engine reported no
    finish reason at all, which is a separate case from "finished" and scored
    separately -- see main().
    """
    text: str
    done_reason: str | None


def call_ollama(base_url, model, prompt, n_predict, repeat_penalty, seed):
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0, "seed": seed, "top_k": 1, "repeat_penalty": repeat_penalty, "num_predict": n_predict},
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        res = json.load(r)
    return Completion(res["response"], res.get("done_reason"))


def call_llama_cpp(base_url, prompt, n_predict, repeat_penalty, seed):
    # Uses llama-server's native /completion endpoint, NOT llama-cli.
    # llama-cli's interactive/conversation scaffold activates even with
    # --no-conversation (that flag only toggles chat *formatting*, per its
    # own --help text, not interactivity) and will corrupt a raw-completion
    # prompt on a base model by treating "A:" as a chat-turn boundary --
    # observed it hallucinate an entirely different, unrelated Q&A pair
    # instead of continuing the given prompt. /completion has no such layer.
    body = json.dumps({
        "prompt": prompt, "n_predict": n_predict, "temperature": 0, "seed": seed,
        "repeat_penalty": repeat_penalty, "top_k": 1,
    }).encode()
    req = urllib.request.Request(f"{base_url}/completion", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        res = json.load(r)
    # llama-server names it stop_type, not done_reason, and "limit" is the
    # output cap that ended generation. Mapped here so the three engines hand
    # the scoring site one field: an unrecognised stop_type falls through to
    # "stop" (was_capped treats anything outside CLEAN_DONE_REASONS as
    # truncated, and refusing every llama.cpp run for naming its field
    # differently would be the same defect pointed the other way). An absent
    # stop_type stays None rather than being read as a clean finish.
    stop_type = res.get("stop_type")
    done_reason = "length" if stop_type == "limit" else ("stop" if stop_type else None)
    return Completion(res["content"], done_reason)


def call_vllm(base_url, model, prompt, n_predict, seed, top_k=None, repetition_penalty=None):
    # #832: top_k/repetition_penalty are vLLM vendor extensions to the
    # OpenAI-compatible /v1/completions body, not in the official schema,
    # but vLLM accepts them as top-level fields. Passing None omits them
    # (vLLM's own defaults: top_k unset, repetition_penalty=1.0/no-penalty)
    # -- worth setting explicitly to match llama.cpp/Ollama, see README's
    # "Settings tuning" section for why this matters.
    payload = {"model": model, "prompt": prompt, "max_tokens": n_predict, "temperature": 0, "seed": seed}
    if top_k is not None:
        payload["top_k"] = top_k
    if repetition_penalty is not None:
        payload["repetition_penalty"] = repetition_penalty
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{base_url}/v1/completions", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        res = json.load(r)
    # OpenAI-compatible finish_reason ("stop" / "length"), already in the
    # vocabulary CLEAN_DONE_REASONS uses. Same tolerant read as
    # record_baseline.py:592 rather than indexing a possibly-absent list.
    choice = (res.get("choices") or [{}])[0]
    return Completion(choice.get("text") or "", choice.get("finish_reason"))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("engine", choices=["ollama", "llama_cpp", "vllm"])
    p.add_argument("base_url", help="e.g. http://127.0.0.1:11434 (ollama), http://127.0.0.1:8080 (llama-server), http://127.0.0.1:8000 (vllm)")
    p.add_argument("--model", default="", help="model/tag name -- required for ollama and vllm, ignored for llama_cpp (one model per llama-server process)")
    p.add_argument("--manifest", default="../corpus/manifest.json")
    p.add_argument("--rubric", default="../corpus/rev_cases_v2_rubric.json")
    p.add_argument("--n-predict", type=int, default=150)
    p.add_argument("--repeat-penalty", type=float, default=1.1,
                    help="pure greedy (top_k=1) with no repeat penalty is a known degenerate-loop trap on base models -- "
                         "first attempt at this just echoed the prompt back verbatim. 1.1 matches Ollama's own default, "
                         "applied to all three engines here so the comparison is apples-to-apples.")
    p.add_argument("--seed", type=int, default=66)
    p.add_argument("--vllm-top-k", type=int, default=None,
                    help="vLLM only. Set to 1 to match llama.cpp/Ollama's greedy decoding -- vLLM's temperature=0 "
                         "alone doesn't reliably guarantee it (github.com/vllm-project/vllm/issues/5404).")
    p.add_argument("--vllm-repetition-penalty", type=float, default=None,
                    help="vLLM only. Defaults to vLLM's own 1.0 (no penalty) if unset -- set to match "
                         "--repeat-penalty (1.1 default) for a fair cross-engine comparison, see README.")
    args = p.parse_args()

    if args.engine in ("ollama", "vllm") and not args.model:
        raise SystemExit(f"--model is required for engine={args.engine}")

    # --model is chosen here, so it is refused here. The three call_* bodies
    # above carry a num_predict and no #2233 harmony adaptation: for a gpt-oss
    # tag the whole 150-token budget goes into the analysis channel and every
    # completion comes back empty, so this would publish 0/64 as though the
    # model had found nothing. Refused rather than widened -- raising n-predict
    # to the floor here would put a budget on the wire that nothing declares,
    # which is the same declared-vs-sent lie the floor guard exists to stop.
    # engine=llama_cpp cannot be checked at all: one model per server process
    # and --model is ignored for it, so there is no tag here to read the family
    # off. Serve gpt-oss through evaluate-models.py instead.
    if args.engine in ("ollama", "vllm"):
        refuse_harmony_model_without_adaptation(
            args.model, producer="engine-benchmark/corpus_eval.py",
            num_predict=args.n_predict)

    builds = select_builds(args.manifest)
    rubric = json.load(open(args.rubric))["cases"]

    per_slice = {}
    total_score, total_max, failed_builds = 0, 0, 0
    cases_out = []
    for i, b in enumerate(builds):
        case = b["case_source"].replace(".c", "")
        slice_key = f"{b['toolchain']}_{b['opt_level']}"
        prompt = build_prompt(b["stripped"]["disassembly"])
        try:
            if args.engine == "ollama":
                completion = call_ollama(args.base_url, args.model, prompt, args.n_predict, args.repeat_penalty, args.seed)
            elif args.engine == "llama_cpp":
                completion = call_llama_cpp(args.base_url, prompt, args.n_predict, args.repeat_penalty, args.seed)
            else:
                completion = call_vllm(args.base_url, args.model, prompt, args.n_predict, args.seed,
                                       top_k=args.vllm_top_k, repetition_penalty=args.vllm_repetition_penalty)
        except Exception as e:
            print(f"  [{i+1}/32] {case} {slice_key}: ERROR {e}", file=sys.stderr)
            # The errored build participated in the slice whether the engine
            # answered or not (#2385): dropping out here used to shrink both
            # sums and silently raise pct for exactly the engines that time
            # out or drop connections on their hardest cases. Count its max
            # into the denominators with 0 earned instead.
            mx = len(rubric[case]["required_groups"]) + 1
            cases_out.append({
                "case": case, "slice": slice_key, "error": str(e),
                "score": 0, "max": mx, "inj_ok": None, "completion": None,
                "empty_answer": False,
            })
            failed_builds += 1
            total_max += mx
            s = per_slice.setdefault(slice_key, {"score": 0, "max": 0})
            s["max"] += mx
            continue
        text = completion.text
        # #3172: a completion cut off at n_predict is half an answer that never
        # reached a verdict, and it used to score as whatever it happened to
        # contain -- the required-group point plus the forbidden-avoidance gate,
        # both paid by a fragment the model never finished writing. The
        # empty-answer guard in score() catches the wrong end of this hole: a
        # capped answer is normally non-empty, just cut off.
        #
        # was_capped() is the same predicate claims.py:686 and
        # regenerate_pre_2393.py:217 decide with, so the published score and
        # the stored outcome cannot disagree about which answers completed.
        # Reusing it rather than restating the rule is what keeps the two from
        # drifting apart again.
        #
        # The second half is deliberately not was_capped(): it reads a missing
        # done_reason as "not evidence of truncation" (Ollama omits the field on
        # some paths), but an answer with no recorded finish reason cannot be
        # shown to have finished either. regenerate_pre_2393.py:84 reaches the
        # same conclusion via NO_DONE_REASON_NOTE, so absence of evidence is
        # not credited as completion here either.
        #
        # Zeroed, not re-weighted, and not a refusal: `mx` is untouched so the
        # build keeps its full place in the denominator and a capped engine is
        # penalised once rather than twice.
        capped = was_capped({"done_reason": completion.done_reason}) or completion.done_reason is None
        pts, mx, inj_ok, empty_answer = score(text, rubric[case])
        if capped:
            pts, inj_ok = 0, False
        total_score += pts
        total_max += mx
        s = per_slice.setdefault(slice_key, {"score": 0, "max": 0})
        s["score"] += pts
        s["max"] += mx
        # Full raw completion kept per case (not just the numeric score) --
        # needed for #847's side-by-side answer comparison across
        # models/quant levels; costs nothing extra since `text` is already
        # in hand here.
        cases_out.append({
            "case": case, "slice": slice_key, "score": pts, "max": mx,
            "inj_ok": inj_ok, "completion": text,
            "empty_answer": empty_answer,
            # The evidence behind a zero the way empty_answer is the evidence
            # behind the other one, so a capped build in the report can be
            # told apart from one that merely finished badly.
            "done_reason": completion.done_reason,
        })
        print(f"  [{i+1}/32] {case:24s} {slice_key:18s} {pts}/{mx}  inj_ok={inj_ok}", file=sys.stderr)

    print(json.dumps({
        "engine": args.engine, "model": args.model, "total_score": total_score, "total_max": total_max,
        "pct": round(100 * total_score / total_max, 1) if total_max else None,
        "failed_builds": failed_builds,
        "per_slice": per_slice, "cases": cases_out,
    }))


if __name__ == "__main__":
    main()
