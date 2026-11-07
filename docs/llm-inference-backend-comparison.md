# LLM inference backend comparison: Ollama vs. llama.cpp vs. vLLM

Status: research for [issue #598](https://github.com/Xore/APIARY/issues/598), 2026-08-05.

> **Point-in-time record.** This is a dated decision record, not current
> inventory: it records what was measured on 2026-08-05, and the version pins
> quoted below have since moved (production Ollama is now 0.34.4). Read it for
> the reasoning, not as the present state of the fleet.

> **Superseded in part — read this first.** This is the CPU-only research
> pass. The *measured* three-engine comparison it asked for was run
> afterwards and is recorded in
> `analysis/ghidra/benchmarks/engine-benchmark/README.md` (2026-08-06, on the
> RTX 4000 Ada 20GB, extended by #832's settings tuning). It **overturns §6
> and §7**: real-card performance was in fact measured, and vLLM's "refuses to
> start" failure turned out to be specific to the *previous* 8GB Quadro
> RTX 4000 rather than a property of the image. It explicitly leaves §2
> standing ("no digest/registry system", `model-governance.py`'s pipeline being
> "Ollama-shaped"), and it does not re-test §1's structured-output axis or §3's
> keep-alive/swap behaviour — it runs one engine at a time by construction, so
> it says nothing about multi-model sharing. The sections below are left as
> written, as the record of what was known on 2026-08-05; where later work
> contradicts them, the later work wins.
>
> Two later findings bear on this doc and are flagged inline where they
> apply: #2646 (a warm resident slot is *not* reproducible at temperature 0
> with a fixed seed, which revises §4's premise) and `ghidra-worker.py`'s
> deliberate OpenAI-compatible `/v1` client, which revises §8's cost estimate.

This is a task-specific decision record, matching
[`local-llm-model-evaluation.md`](local-llm-model-evaluation.md)'s format for
the model-selection decision it's paired with. It evaluates the inference
*backend* Ollama sits on top of, not which model to run on it.

## Why this exists

Ollama is the only local-LLM backend used anywhere in this repo today
(`llm-worker/worker.py`'s `OllamaClient`, `analysis/ghidra/worker/ghidra-worker.py`'s
AI triage, both against the same `ghidra-ollama-1` container; and
`analysis/ghidra/models/model-governance.py`'s entire approval/drift-check
pipeline is built directly around Ollama's own `/api/tags`/`/api/version`
APIs). No comparison against llama.cpp (the inference engine Ollama itself
wraps) or vLLM (the throughput-oriented alternative) had been done. #598 asked
for one, explicitly allowing "switch, and rearchitect" as a valid outcome.

(Still true of the *deployed* stack: `arcane/manifests/home-production.json`
deploys no llama.cpp or vLLM service. Both now appear in benchmark scripts
under `analysis/ghidra/benchmarks/` — measured, not depended on. See the
status banner above.)

## Method

Every claim below was tested directly — a real container, a real (small)
GGUF model, a real request — not read off a features page. No GPU was
available for this pass (the sandboxed test environment, not the
homeserver/VPS, which the standing hold keeps off-limits); GPU-dependent
findings are marked and left as a follow-up for the real hardware. CPU-only
results still validate every *mechanism* this comparison depends on
(structured-output enforcement, determinism, provenance shape, multi-model
lifecycle, embeddings), since none of those are GPU-specific behaviors.

Test model: `Qwen/Qwen2.5-0.5B-Instruct-GGUF` (Q4_K_M, 630M params) for
generation tests; `nomic-ai/nomic-embed-text-v1.5-GGUF` (Q4_K_M) for the
embeddings test. Images: `ghcr.io/ggml-org/llama.cpp:server`/`:full`,
`ghcr.io/mostlygeek/llama-swap:cpu`, `ollama/ollama:0.32.0` (this repo's own
pinned version *at the time*; production has since moved to
`ollama/ollama:0.34.4` in `analysis/ghidra/docker-compose.ghidra.yml` and
`analysis/ghidra/models/approved-models.json`), `vllm/vllm-openai:latest`
(v0.26.0).

## 1. Structured output enforcement

`OllamaClient.analyze()` (`llm-worker/worker.py`) passes a full Pydantic JSON
schema via `format` on `/api/chat` and validates the response.

**llama.cpp**: confirmed equivalent via `/v1/chat/completions`'
`response_format: {type: json_schema, json_schema: {...}}` (OpenAI-compatible
grammar-constrained decoding). Tested against a schema with a `severity` enum
and a `mitre_attack` array — output correctly respected both the enum
constraint and array structure on the first attempt, no retry needed.

```
$ curl .../v1/chat/completions -d '{"response_format":{"type":"json_schema","json_schema":{...}}}'
{"summary":"...", "severity":"low", "mitre_attack":["exploit","system"]}
```

**vLLM**: not tested directly (the standard image cannot start without a GPU,
see §7) — vLLM's own documentation states `guided_json`/structured-outputs
support via its OpenAI-compatible server, architecturally comparable to
llama.cpp's. Treat as "documented, not verified here" pending real-hardware
testing.

**Verdict**: no loss versus Ollama for llama.cpp. vLLM's support is
documented but unverified in this pass.

## 2. Model provenance / digest pinning

`model-governance.py`'s `collect_snapshot()` reads Ollama's `/api/tags`
digest as the model's identity, and `approved-models.json` records that
digest as the audit trail.

**llama.cpp**: `/v1/models` returns an Ollama-`/api/tags`-shaped response
(same field names) but every identity field is an empty string:

```json
{"digest": "", "size": "", "details": {"quantization_level": "", "family": ""}}
```

Confirmed no registry/tags identity system exists in llama.cpp at all —
models are bare files on disk. The image's `:full` variant ships no
`llama-gguf-hash` or equivalent digest tool either; only the standard
`sha256sum` on the GGUF file itself.

**vLLM**: same shape — vLLM serves whatever HF/GGUF path it's pointed at, no
registry digest concept either.

**Verdict**: this is the biggest real migration cost, not a feature gap
llama.cpp/vLLM lose on — Ollama's digest happens to be *exactly* what
`model-governance.py` was built around, and neither alternative has an
equivalent. A migration would replace "query the running server's registry
digest" with "hash the GGUF file on disk directly" — simpler and arguably
more auditable (no trust in a registry's own digest computation), but a real
rewrite of `collect_snapshot()`/`evaluate_drift()`'s identity model,
and every recorded `approved-models.json` entry's `ollama_repo_digest`-shaped
field.

## 3. GPU-sharing / keep-alive behavior

`OLLAMA_KEEP_ALIVE`/`OLLAMA_MAX_LOADED_MODELS` and automatic model swap are
load-bearing for the documented GPU-sharing contract between `llm-worker` and
`ml-worker` (`docs/gpu-ml-worker-acceleration.md` §5).

**llama.cpp**: `llama-server` on its own loads exactly one model per running
process — no built-in swap. `llama-swap` (a separate, actively maintained
router project) replicates the missing piece. Tested directly: configured two
model slots with `ttl: 8` (seconds), confirmed (a) a request to slot 1
spawns the underlying `llama-server` process on demand, (b) after the TTL
expires with no requests, `/running` shows the process gone (auto-unloaded,
matching `OLLAMA_KEEP_ALIVE`'s behavior exactly), and (c) a request to slot 2
spawns its own process cleanly — real swap-in/swap-out, not just configured
intent.

```
$ curl :8091/running                          # {"running":[]}
$ curl :8091/v1/chat/completions -d '{"model":"qwen-small",...}'
$ curl :8091/running                          # {"running":[{"model":"qwen-small","ttl":8,...}]}
$ sleep 12
$ curl :8091/running                          # {"running":[]}  -- auto-unloaded
$ curl :8091/v1/chat/completions -d '{"model":"qwen-small-2",...}'
$ curl :8091/running                          # {"running":[{"model":"qwen-small-2",...}]}  -- swapped
```

**vLLM**: no equivalent found — vLLM's own design assumes one model per
running server process, optimized for high-throughput serving of that one
model, not swap-heavy multi-model sharing the way this stack's GPU-budget
contract needs.

**Verdict**: llama.cpp + llama-swap genuinely replicates Ollama's
keep-alive/swap contract, confirmed functionally, not just documented — but
it's an *additional* component to deploy, configure, and keep patched, not a
built-in. vLLM does not fit this stack's shared-GPU, multi-workload pattern
at all without a much larger rearchitecture (e.g. running multiple vLLM
instances with strict, static VRAM partitions instead of dynamic sharing).

## 4. Deterministic sampling

`temperature: 0, seed: 66` is relied on for reproducible output today.

> **Revised after the fact (#2646).** That reliance did not survive contact
> with the deployed configuration. `OLLAMA_KEEP_ALIVE=30m` keeps the weights
> resident between samples, and a **warm** Ollama slot returns different text
> for a byte-identical prompt at temperature 0 with a fixed seed — production
> therefore runs permanently in the drifting regime, and no setting fixes that
> without paying a reload. The fix that shipped is accounting, not determinism:
> every stored assessment now records a `slot_generation` fingerprint (read
> from Ollama's `/api/ps`) naming the resident instance that answered, so two
> results are never compared as though one instance produced both — see
> `docs/analysis/ghidra/AI_TRIAGE.md`. This is attributed to a warm **Ollama**
> slot specifically; the llama.cpp result below is not stated to have
> exercised an equivalent long-lived warm-slot regime, so it stands as
> measured. What the finding removes is this section's *premise* — that the
> deployed stack is reproducible today — not its per-engine results.

**llama.cpp**: confirmed bit-identical output across 3 repeated identical
requests (`temperature: 0, seed: 66`) against the same model. No loss.

**vLLM**: not tested (no GPU); vLLM supports `seed` and `temperature` in its
OpenAI-compatible API the same way, architecturally equivalent, unverified
here.

## 5. Quantization control

Ollama pulls pre-quantized GGUF from its own registry. llama.cpp runs
arbitrary GGUF directly and can quantize locally via `llama-quantize`
(present in the `:full` image, confirmed). vLLM primarily targets
full-precision/AWQ/GPTQ-quantized safetensors rather than GGUF, though GGUF
support exists.

**Verdict**: not a meaningful benefit either way for this stack's actual
usage — every model this stack runs today is already a specific,
pre-selected quantization tag (`docs/local-llm-model-evaluation.md`'s
candidate matrix), never re-quantized locally. Direct quantization control
is unused flexibility unless a future need for custom calibration emerges.

## 6. Performance

**Not measured on real hardware in this pass** — no GPU available in the
sandboxed test environment, and the homeserver/VPS remain off-limits under
the standing hold. `llama-bench` (llama.cpp's own official benchmarking
tool, confirmed present in the `:full` image) was run CPU-only as a
methodology proof, not a production number:

```
$ llama-bench -m qwen2.5-0.5b-instruct-q4_k_m.gguf -p 128 -n 128 -t 8
| model                   | backend | threads | test  | t/s          |
| qwen2 1B Q4_K - Medium  | CPU     |       8 | pp128 | 144.82 ± 15.09 |
| qwen2 1B Q4_K - Medium  | CPU     |       8 | tg128 |  32.62 ± 1.30  |
```

This confirms the tool works and produces standard, directly-comparable
prompt-processing (`pp`) and text-generation (`tg`) tokens/sec numbers.
**Follow-up**: run `llama-bench` against the actual currently-approved model
(`qwen3:14b`, promoted to all three slots under #568/#569 now that VRAM is
confirmed ~20GB) on the real GPU, and compare against Ollama's own measured
throughput for the same model (`docs/local-llm-model-evaluation.md` already
has some of these numbers). **Partly done, on a different model** — the later
three-engine run in `analysis/ghidra/benchmarks/engine-benchmark/README.md`
did measure decode throughput on the real 20GB card (llama.cpp ~21.4, Ollama
~21.5, vLLM ~23.1 tok/s), but against the merged REx86 f16 7B weights, not
`qwen3:14b`. The `qwen3:14b`-specific comparison is still outstanding.

## 7. Operational surface

| | Ollama 0.32.0 (as tested) | llama.cpp `:server` | llama-swap `:cpu` | vLLM 0.26.0 |
|---|---:|---:|---:|---:|
| Image size | 8.06 GB | 1.21 GB | 1.24 GB | 28.1 GB |
| Runs without a GPU present | Yes (CPU fallback) | Yes (CPU fallback) | Yes | **No — confirmed**, but hardware-specific; see below |

The vLLM finding is real and concrete, not inferred: the standard
`vllm/vllm-openai` image fails to even construct its own CLI argument parser
without a detectable GPU device —

```
RuntimeError: Failed to infer device type, please set the environment
variable `VLLM_LOGGING_LEVEL=DEBUG` to turn on verbose logging...
```

— thrown from `vllm/config/device.py` during `EngineArgs` construction, before
model loading is even attempted. This is not "vLLM performs worse on CPU," it
is "the standard distribution has no CPU path at all" (a separate CPU-only
build target exists upstream per vLLM's own docs, but is a different,
less-maintained artifact, not the mainline image this stack would pull).
Ollama and llama.cpp both degrade gracefully to CPU; vLLM does not degrade,
it refuses to start.

> **Superseded.** That failure was hardware-specific, not a property of the
> image. On the current 20GB RTX 4000 Ada Generation, `vllm/vllm-openai:latest`
> (v0.26.0) starts cleanly, loads a 7B model, completes `torch.compile`
> warmup and serves correct completions — recorded in the "Side finding"
> section of `analysis/ghidra/benchmarks/engine-benchmark/README.md`. The
> failure above was observed on the *previous* 8GB Quadro RTX 4000.
>
> Whether the mainline image has any CPU-only path at all is therefore
> **undetermined** from this repo's evidence: the two data points are one
> failure on the old card and one success on the new one, and neither isolates
> GPU *presence* from GPU *capability*. The "no CPU path at all" reading above
> overstates what was shown. Unchanged by the later run: vLLM is by far the
> largest image of the four, and §2's digest/registry finding stands.

**Embeddings** (relevant to `ml-worker`/#151's planned semantic search, both
currently spec'd around `nomic-embed-text`): llama.cpp has a native
`--embedding` server mode with an OpenAI-compatible `/v1/embeddings`
endpoint. Confirmed working end-to-end against the real
`nomic-embed-text-v1.5` GGUF:

```
$ curl :8092/v1/embeddings -d '{"input":"cowrie session: whoami then wget malware.sh"}'
{"data":[{"embedding":[-0.0120, 0.0317, -0.2030, ...]}]}   # 768 dimensions
```

One real discrepancy worth flagging: this returned **768** dimensions, not
the **384** dimensions `docs/gpu-llm-analysis-worker.md` §10 and #151's own
issue text assume — `nomic-embed-text-v1.5`'s native output is 768-dim;
384 would require Matryoshka truncation (a documented feature of that model
family) that isn't applied by default. Whichever backend is ultimately used
for embeddings, this dimension mismatch needs resolving before #151's
`dense_vector` ES mapping is written, independent of the Ollama/llama.cpp/vLLM
question.

## 8. Migration cost, enumerated

Every file that would need to change if llama.cpp (the only backend that
passes §7's "runs without a GPU crash" bar and replicates §3's sharing
contract) replaced Ollama:

- `llm-worker/worker.py` — `OllamaClient` rewritten against
  `/v1/chat/completions`'s `response_format` shape instead of `/api/chat`'s
  `format`; digest verification (`model_digest()`) rewritten to hash the
  local GGUF file instead of querying `/api/tags`.
- `analysis/ghidra/worker/ghidra-worker.py` — **no client-shape change needed**,
  as of the current code. It already speaks an OpenAI-compatible `/v1` chat
  dialect (`GHIDRA_TRIAGE_API_BASE`, default `http://127.0.0.1:11434/v1`) and
  does so deliberately: the worker records that this is what makes "llama.cpp's
  server, vLLM and LM Studio work unchanged; the requirement is that it is
  *local*, not that it is Ollama." The one Ollama-specific coupling left is the
  `/api/ps` probe behind `GHIDRA_TRIAGE_RUNTIME_BASE` that populates
  `slot_generation` (#2646); the code already handles a server that is not
  Ollama, recording `unavailable`. This line was a real cost when this doc was
  written and is no longer one.
- `analysis/ghidra/models/model-governance.py` — the largest rewrite. Its
  entire `collect_snapshot()`/drift-comparison model is built around Ollama's
  registry APIs and Docker-image-reference identity; every field in
  `approved-models.json`'s `runtime` block (`ollama_version`,
  `ollama_image`, `ollama_repo_digest`) would need a llama.cpp-shaped
  equivalent (llama.cpp binary version/commit, GGUF file hash).
- `analysis/ghidra/docker-compose.ghidra*.yml`, `llm-worker/docker-compose.*.yml`
  — swap the `ollama/ollama` service for `llama.cpp` + `llama-swap` (two
  containers replacing one).
- `docs/gpu-llm-analysis-worker.md`, `docs/gpu-ml-worker-acceleration.md`,
  `docs/ml-gpu-coordinated-roadmap.md`, `docs/local-llm-model-evaluation.md`,
  `docs/ml-worker-plan.md` (if embeddings move too) — every reference to
  Ollama's specific env vars (`OLLAMA_KEEP_ALIVE`, `OLLAMA_MAX_LOADED_MODELS`)
  and API shapes.

Not a small change, concentrated almost entirely in one file
(`model-governance.py`) plus a compose/doc update everywhere else.

## Recommendation

**Stay on Ollama for now.** Not because llama.cpp lost the comparison — on
every functional axis tested (§1, §3, §4, §7's embeddings), it matched or
exceeded Ollama, and its image is over 6x smaller. The reasons to hold:

1. **§2's migration cost is real and concentrated.** `model-governance.py`'s
   entire approval/drift-check/audit-trail design is Ollama-registry-shaped.
   Rewriting it correctly (not just making it compile) is the actual
   majority of this migration's risk, and it's exactly the kind of
   security-relevant control (#83's canary gating, #158's promotion flow)
   that shouldn't be rushed alongside a backend swap.
2. **§6 (performance) is unmeasured on real hardware.** The whole point of
   switching backends would be a concrete win (VRAM headroom, throughput,
   latency) — that hasn't been demonstrated yet, only that llama.cpp doesn't
   *lose* on the functional axes. A migration without a measured performance
   win is pure cost for no proven benefit.
3. **#568/#569 (the actual VRAM figure) is now resolved: ~20GB, not 8GB.**
   Model selection, GPU-sharing math, and any performance comparison all
   depended on this — `qwen3:14b` has since been promoted to all three
   slots (ghidra, revdeck, sessions) on that basis. This migration's
   cost/benefit analysis in §6 above was written before that resolution and
   should be re-run against `qwen3:14b` rather than the smaller candidates
   this doc originally benchmarked against.

**vLLM is not a fit for this stack today**, independent of performance —
§7's finding that the standard image refuses to start without a GPU present
makes it incompatible with this repo's own CI/local-dev conventions (every
other worker here is expected to build/import cleanly without GPU hardware,
confirmed throughout this codebase's test suites), and §3's lack of a
keep-alive/multi-model-swap story doesn't fit the shared-GPU contract
`llm-worker`/`ml-worker` already depend on. Revisit only if this stack's
usage pattern shifts toward single-model, high-throughput, dedicated-GPU
serving — not the current shared, bursty, multi-workload shape.

## Follow-ups (not implemented here, per #598's own scope)

- Run `llama-bench` against the currently-approved model (`qwen3:14b`,
  promoted under #568/#569) on the real card, side-by-side with Ollama's own
  numbers, to get the actual performance data this research couldn't gather.
  (Partly superseded: the three-engine run in
  `analysis/ghidra/benchmarks/engine-benchmark/README.md` gathered real-card
  throughput for llama.cpp/Ollama/vLLM, but on REx86 f16 7B weights. The
  `qwen3:14b` case is still open.)
- Resolve the 768-vs-384 embedding-dimension discrepancy (§7) before #151's
  `dense_vector` ES mapping work begins, regardless of backend choice.
- If a future re-evaluation is triggered (e.g. `model-governance.py` gets a
  major rework for unrelated reasons, making the §2 migration cost lower),
  llama.cpp + llama-swap remains the stronger candidate of the two
  alternatives evaluated here — this doc's §1/§3/§4/§7 evidence stays valid
  and shouldn't need re-testing from scratch.
