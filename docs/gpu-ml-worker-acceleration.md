# GPU Acceleration for the ML Worker — Implementation Guide

> **Status:** Implementation guide — not yet deployed. Originally tracked in
> [#67](https://github.com/Xore/APIARY/issues/67) (closed, not completed) —
> consolidated into [#1523](https://github.com/Xore/APIARY/issues/1523)'s
> AFTER RELEASE 0.1.0 checklist; reopen/re-file when this work is picked up.
> The ML worker itself is scaffolded (see
> [`ml-worker-plan.md`](ml-worker-plan.md), roadmap v0.1).
> **Audience:** A human operator or an AI coding agent implementing this feature.
> **Companion guide:** [`gpu-llm-analysis-worker.md`](gpu-llm-analysis-worker.md)
> — the GPU is shared between both workloads; §5 here is the coordination
> contract.
> **Setting up GPU passthrough itself?** See
> [`gpu-docker-passthrough.md`](gpu-docker-passthrough.md) — driver
> install, nvidia-container-toolkit, and the compose/`docker run` syntax
> for handing a container the GPU. This guide assumes that's already done.

---

## Table of Contents

1. [Goal & Scope](#1-goal--scope)
2. [What the GPU Buys (and What It Doesn't)](#2-what-the-gpu-buys-and-what-it-doesnt)
3. [Hardware & Compatibility Contract](#3-hardware--compatibility-contract)
4. [Implementation: CUDA-enabled ML Worker](#4-implementation-cuda-enabled-ml-worker)
5. [GPU Sharing Contract with the LLM Worker](#5-gpu-sharing-contract-with-the-llm-worker)
6. [Implementation: Embedding-based Clustering](#6-implementation-embedding-based-clustering)
7. [Acceptance Tests](#7-acceptance-tests)
8. [Rollback](#8-rollback)
9. [Guardrails](#9-guardrails)
10. [AI Implementer Checklist](#10-ai-implementer-checklist)

---

## 1. Goal & Scope

Two upgrades to the planned `ml-worker` service that use the homeserver's
NVIDIA GPU:

- **A. CUDA-accelerated models** — run the LSTM autoencoder (and any future
  PyTorch models) on the GPU instead of CPU, cutting the 6-hour retrain
  from minutes-per-epoch on CPU to seconds, and shrinking per-poll
  inference latency.
- **B. Embedding-based similarity** — add a lightweight
  `sentence-transformers` model on the GPU to embed Cowrie commands,
  usernames/passwords, and script payloads into vectors, enabling
  clustering of "same-actor / same-tool" activity and ES kNN similarity
  search.

**Out of scope:** the LLM analysis layer (separate guide), supervised
classification, and any change to the anomaly-score contract in
[`ml-worker-plan.md`](ml-worker-plan.md) — scores, indices, and the
dashboard API stay identical.

---

## 2. What the GPU Buys (and What It Doesn't)

| Component | GPU helps? | Notes |
|---|---|---|
| LSTM-AE training (6 h retrain) | **Yes — large** | 10–50× vs CPU at this model size |
| LSTM-AE inference (per-poll windows) | Yes, moderate | Small batches; mainly latency |
| IsoForest (scikit-learn) | **No** | CPU-only algorithm; leave as-is. Do not add a GPU dataframe library for this |
| HBOS (pyod) | **No** | Histogram math; CPU is already milliseconds |
| Sentence-transformers embeddings | **Yes** | New capability; impractical at volume on CPU within a 30 s poll cycle |

The honest summary: the GPU makes the **deep model cheap enough to retrain
often** and **unlocks embeddings**. It does not speed up the sklearn/pyod
parts, and it does not make the models more accurate.

---

## 3. Hardware & Compatibility Contract

**Settled by [#602](https://github.com/Xore/APIARY/issues/602)** (verbatim
host evidence: `lspci` shows a single AD104GL controller, containers
enumerate exactly one device — the earlier two-card / Turing-plus-Ada
hypothesis is refuted) and pinned as the runtime-governance authority in
`analysis/ghidra/models/approved-models.json`, which
`model-governance.py check-runtime` diffs live `nvidia-smi` against every
5 minutes:

- GPU: **NVIDIA RTX 4000 Ada Generation, 20475 MiB (~20 GB), compute
  capability 8.9.** (An earlier draft of this document, before #602,
  mis-recorded this as a Quadro RTX 4000 at compute capability 7.5/Turing —
  that card was never on this host; see #602 for the full correction.)
- Driver **595.84**, per the `approved_host.driver` field in that same
  `approved-models.json` — which is the authority this section just nominated
  two lines earlier, so quoting anything else here contradicts it directly.
  (This document previously said 580.173.02 / CUDA 13.0; that pair is not in
  the approved-host record. `docs/runtime-compatibility-record.md:39` carries the
  same stale host, including the retired Quadro RTX 4000 / 8192 MiB figures
  that #602 already corrected on the line above.)
- nvidia-container-toolkit 1.19.1 present; `docker run --rm --gpus all
  nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi -L` succeeds.
- Stack network is `honeynet`. The old `ml-worker/docker-compose.override.yml`
  targeted a network, `analysis-net`, that never existed anywhere in this
  repository; that file has been replaced by `ml-worker/docker-compose.yml`
  (its own standalone stack), which joins `honeynet` as an external network —
  resolved under #61.

**Wheel compatibility rule for Ada (sm_89), compute capability 8.9:**
PyTorch CUDA wheels (`+cu126`) ship `sm_89` kernels; they work. Re-verify
flash-attention/xformers build availability for `sm_89` specifically before
adding either — do not assume the prior Turing-era "unsupported" note still
applies, but do not assume support either without checking. **bf16 is
native on Ada** (cc 8.9 has tensor cores with bf16 support) — the earlier
blanket "no bf16, fp32/fp16-with-loss-scaling only" rule was transplanted
from the wrong (Turing, cc 7.5) architecture and forbade using hardware
capability that is actually present. Training code may use `bfloat16`
directly; fp16-with-loss-scaling remains a valid alternative but is no
longer mandatory.

---

## 4. Implementation: CUDA-enabled ML Worker

All changes are confined to `ml-worker/`.

### 4.1 `ml-worker/requirements.txt`

Replace the CPU wheel lines. (The `-` side below is the *current* content of
`ml-worker/requirements.txt` — it has moved on from the 2.13.0/3.6.2 baseline
this section was drafted against, to `torch==2.14.0+cpu` at line 84 and
`pyod==3.6.6` at line 89. Re-read the file before applying; a diff whose
context no longer matches is how a wheel pin gets silently skipped.)

```diff
 # Deep learning (CPU-only PyTorch)
-torch==2.14.0+cpu
+torch==2.13.0+cu126
 --extra-index-url https://download.pytorch.org/whl/cpu
+
+# Embeddings (§6)
+sentence-transformers==3.0.1

 # Outlier detection (HBOS)
-pyod==3.6.2
+pyod==3.6.6
```

Note the `+` side is left at the version #82 verified on this host, not bumped
to match the 2.14.0 baseline: the cu126 wheel was the one actually installed
and tensor-checked against this card. Reconciling the two is real work, not a
doc edit, and belongs with whoever runs the GPU build.

> **Verified pin (2026-08-01, #82):** `torch==2.13.0+cu124` does not exist;
> that index ends at 2.6.0. `torch==2.13.0+cu126` installed cleanly and passed
> a real tensor check on this host's card, with CUDA 12.6 and cuDNN 9.10.2.
> (#82's original note named the card "RTX 4000" and cited `sm_75` in the
> wheel's architecture list — written nine days before #602 settled the
> card's actual identity as RTX 4000 Ada Generation / cc 8.9 / `sm_89`.
> Standard PyTorch CUDA wheels bundle kernels for multiple architectures
> including both `sm_75` and `sm_89`, so the wheel's `sm_75` inclusion says
> nothing about which kernel the live card actually used; the underlying
> install-and-tensor-check result stands, only the architecture label was
> wrong.) Never silently fall back to the `+cpu` wheel; a CPU wheel in a GPU
> deployment must fail the acceptance test T2, not pass unnoticed.

### 4.2 `ml-worker/Dockerfile`

```diff
-# System deps for PyTorch (CPU-only) and scipy
+# System deps for PyTorch (CUDA wheels are self-contained; gcc for sklearn)
 RUN apt-get update && apt-get install -y --no-install-recommends \
     gcc g++ libgomp1 \
     && rm -rf /var/lib/apt/lists/*
```

No base-image change is needed: the official CUDA PyTorch wheels bundle
CUDA runtime libraries, so `python:3.12-slim` + the driver on the host is
sufficient. (The `nvidia/cuda` base image is only needed when compiling
CUDA code.)

### 4.3 Device selection in code (`ml-worker/models/`)

One helper, used by LSTM-AE and the embedder — auto-detect with CPU
fallback so the same image runs on GPU-less dev machines:

```python
import torch

def get_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda:0")
    return torch.device("cpu")
```

Rules:

- Log the selected device and GPU name at worker startup (one line,
  `loguru` INFO) — acceptance test T2 greps for it.
- Inference (per-poll scoring) runs on the selected device with
  `torch.no_grad()` and batch size ≤ 64 — bounded VRAM.
- Training (6 h retrain) uses fp32, batch size 128, and
  `torch.cuda.empty_cache()` after each retrain.

### 4.4 GPU reservation — already scaffolded; do not add it inline

This step is **already satisfied**, and doing it the way it was originally
written here would be wrong. The reservation lives in a dedicated overlay,
`ml-worker/docker-compose.ml-worker.gpu.yml`, applied as:

```bash
docker compose -f docker-compose.yml -f docker-compose.ml-worker.gpu.yml \
  up -d ml-worker
```

That file's own header is emphatic about two things this section used to
contradict: it is an "overlay, never used alone", and it is "inert scaffolding
right now, not a feature this stack turns on" — because per
`ml-gpu-coordinated-roadmap.md` §1 decision 4 only LSTM and embeddings may use
CUDA, and both are still gated behind Milestones D and H. Milestone H's own
first step requires a measured CPU baseline from #62 *before* touching CUDA.

So: do not add a `deploy.resources.reservations.devices` block to
`ml-worker/docker-compose.yml`. An inline reservation makes the GPU
unconditional on every `up`, which is precisely the gate the overlay exists to
keep shut.

One real discrepancy worth knowing: the overlay says `count: all`, while this
document's original diff proposed `count: 1`. On this host they are
equivalent — §3 establishes there is exactly one RTX 4000 Ada and that the
earlier two-card hypothesis is refuted — but `count: all` is the more
honest form if the host ever gains a second card, since the sharing contract
in §5 is written per-card. Resolving it is a decision for whoever lands
Milestone H, not a doc edit.

`ML_DEVICE: auto | cpu` belongs in the same overlay, not the base file.

---

## 5. GPU Sharing Contract with the LLM Worker

One RTX 4000 Ada Generation (20475 MiB / ~20 GB, corrected from an earlier
8192 MiB / Quadro RTX 4000 figure — see #518) is shared between `ollama`
(LLM guide) and `ml-worker`. Both guides must be deployed with these numbers
or not at all.

| Consumer | Typical VRAM | When active |
|---|---|---|
| ollama (`qwen3:14b`, promoted for all 3 slots under #568) | ~10.2 GiB at production's 8k context; up to ~14.1 GiB at the ghidra slot's 32k context (both live-measured, see `docs/local-llm-model-evaluation.md`'s #568 section) | On LLM requests; the ghidra/revdeck slots run under the shared server default `OLLAMA_KEEP_ALIVE=30m` (kept resident across a drain's queue, see `analysis/ghidra/docker-compose.ghidra.yml`) — the llm-worker slot overrides that per-request with `LLM_KEEP_ALIVE=10m` and unloads 10 min after its own last use |
| ml-worker inference (LSTM-AE + embedder) | ~0.5–1 GiB | Every poll cycle (30 s), briefly |
| ml-worker retrain | ~1–2 GiB | Every 6 h, minutes |

Rules (resolved under #569, using #568's real post-promotion numbers, not
the original 6.1 GiB `qwen3.5:9b` estimate):

- **The blanket "never overlap" rule is lifted; a scheduling gap is kept as a
  smaller safety margin instead of full separation.** Worst case — the
  ghidra slot's model loaded at its 32k context (~14.1 GiB) plus a retrain
  (~2 GiB) plus the embedder's own inference (~1 GiB) — totals ~17.1 GiB
  against the real 20475 MiB budget: about 3.3 GiB of headroom, not the
  "comfortable" double-digit margin a naive 6.1 GiB-chat-model estimate
  would suggest. That is enough to not require full separation, but not
  enough to treat as a non-issue either. This already assumes the ghidra
  slot's model is resident regardless of any keep-alive window — the 30m
  server-default residency (above) makes that the common case during a
  drain, not just a worst-case edge. Keep the `RETRAIN_SLOTS_UTC` /
  `DAILY_REPORT_HOUR` scheduling offset (retrain landing at least 1 h away
  from the LLM daily report — e.g. retrain at 01:00/07:00/13:00/19:00 UTC
  against a 06:00 report) as a cheap way to avoid the worst-case overlap in
  the common case, rather than removing it outright. `RETRAIN_INTERVAL` is
  the *old* name and shape: it was a restart-relative interval, replaced by
  fixed daily HH:MM UTC slots under #172 so GPU workloads can actually be
  separated. The live variable is `RETRAIN_SLOTS_UTC`, defaulting to
  `03:00,09:00,15:00,21:00` (`ml-worker/docker-compose.yml:54`,
  `worker.py:59`) — note the shipped default is *not* the 01:00/07:00/13:00/
  19:00 set used as the example above, so the offset is a starting point to
  adjust, not a description of what runs. The CUDA-OOM → CPU
  fallback below is what actually protects the rare case the schedule
  doesn't catch — treat it as the real safety net, the schedule as
  best-effort headroom management.
- If a future model re-evaluation (#568's process, re-run) picks something
  materially larger than `qwen3:14b` for the ghidra slot, re-check this
  margin before assuming it still holds — the 3.3 GiB headroom above was
  computed for this specific model at its current context ceiling, not as a
  permanent property of the 20 GB card.
- **On CUDA OOM, do not crash:** wrap train/infer calls, catch
  `torch.cuda.OutOfMemoryError`, log WARN, fall back to CPU for that cycle
  (`get_device()` override), and continue. Anomaly detection must degrade,
  not stop.
- Never set `PYTORCH_CUDA_ALLOC_CONF` or memory fractions in the compose
  file to "reserve" VRAM — both containers must see the whole device and
  stay within their budgets by behaviour, or the scheduling rule fails
  silently.
- `nvidia-smi dmon -s u` on the host is the ground truth when debugging
  contention.

---

## 6. Implementation: Embedding-based Clustering

New module `ml-worker/models/embedder.py`, invoked from the worker loop
after anomaly scoring (same poll cycle).

### 6.1 Model

`sentence-transformers/all-MiniLM-L6-v2` at immutable revision
`1110a243fdf4706b3f48f1d95db1a4f5529b4d41` — 384-dim, ~90 MiB, fast on GPU,
well-suited to short strings (commands, credential pairs, payload
snippets). Downloaded on first use; **prefetch at image build time** so the
runtime container needs no internet:

```dockerfile
# ml-worker/Dockerfile — after pip install
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', revision='1110a243fdf4706b3f48f1d95db1a4f5529b4d41')"
```

### 6.2 What gets embedded

| Source | Text embedded | ES field written |
|---|---|---|
| Cowrie session | joined command list (first 4k chars) | `ml-embeddings` index, `kind=session` |
| Cowrie auth | `username` + `\n` + `password` | `kind=credential` |
| Script payload | first 4k chars of text payload | `kind=payload` |

### 6.3 `ml-embeddings` index (create on startup if missing)

```json
{
  "mappings": {
    "properties": {
      "@timestamp":   { "type": "date" },
      "kind":         { "type": "keyword" },
      "source_id":    { "type": "keyword" },
      "src_ip":       { "type": "ip" },
      "text_preview": { "type": "text" },
      "embedding": {
        "type": "dense_vector",
        "dims": 384,
        "index": true,
        "similarity": "cosine"
      }
    }
  }
}
```

ES 8.13 supports indexed `dense_vector` + kNN search out of the box; no
plugins. Query example (find sessions similar to a given one):

```json
POST ml-embeddings/_search
{
  "knn": { "field": "embedding", "query_vector": [<384 floats>], "k": 10, "num_candidates": 100 },
  "filter": { "term": { "kind": "session" } }
}
```

### 6.4 Clustering use (v1 keep-simple version)

Do **not** add a clustering library in v1. The two immediately useful
queries are kNN similarity (above) and "novel text" detection: a new
session whose max cosine similarity to the last 30 days of sessions is
below 0.6 is novel → bump its `composite_score` contribution in the
explanation field. Anything beyond that (HDBSCAN, actor attribution) is a
separate design doc.

---

## 7. Acceptance Tests

```bash
# T1 GPU visible in the ml-worker container
docker exec hp-ml-worker python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
# expect: True NVIDIA RTX 4000 Ada Generation

# T2 worker actually selected CUDA
docker logs hp-ml-worker 2>&1 | grep -i "device"
# expect one line like: device=cuda:0 (NVIDIA RTX 4000 Ada Generation)

# T3 retrain completes on GPU within budget
docker exec hp-ml-worker python -c "..."  # trigger one retrain manually
nvidia-smi --query-gpu=memory.used --format=csv   # stays < 2 GiB for ml-worker

# T4 coexistence: run an ollama request during a retrain; both succeed,
#    no OOM in either container's logs
docker logs hp-ml-worker 2>&1 | grep -ci "OutOfMemory"   # expect 0

# T5 embeddings index exists with correct dims
curl -s "http://<WG_IP>:9200/ml-embeddings/_mapping" | grep -q '"dims":384'

# T6 CPU fallback: ML_DEVICE=cpu docker compose up -d ml-worker
#    → worker starts, logs device=cpu, still scores anomalies

# T7 no published ports on ml-worker (unchanged from base plan)
docker port hp-ml-worker   # expect: empty
```

---

## 8. Rollback

```bash
git checkout -- ml-worker/requirements.txt ml-worker/Dockerfile \
                ml-worker/docker-compose.yml
docker compose -f ml-worker/docker-compose.yml \
  up -d --build ml-worker
# optional: drop derived data
curl -XDELETE "http://<WG_IP>:9200/ml-embeddings"
```

The CPU-only image builds from the reverted files with no further changes
(the device helper falls back automatically).

---

## 9. Guardrails

- **G1 — Public repository.** No real IPs, domains, credentials, or
  captured payload text in code, docs, tests, or sample data. TEST-NET
  ranges and `example.com` only (same policy as the README).
- **G2 — Version verification, not assumption.** Confirm the pinned
  `+cu126` wheel exists (§4.1) and supports sm_89 (§3) before building;
  confirm the sentence-transformers pin and immutable model revision install
  offline-prefetchable
  weights. Record verified pins in this document when deploying.
- **G3 — CPU fallback always works.** The same image must run correctly
  with no GPU (dev machines, CI). Device selection is auto-detected, never
  hard-coded to `cuda`.
- **G4 — Graceful degradation.** CUDA OOM → warn + CPU fallback for that
  cycle. Missing embedder weights → skip embeddings, keep anomaly scoring.
  The core pipeline never stops because an accelerator feature failed.
- **G5 — VRAM discipline.** Respect §5: bounded batches, `empty_cache`
  after retrain, retrain schedule offset from the LLM daily report, no
  VRAM reservation env hacks.
- **G6 — Attacker data stays local and untouched.** Embeddings are derived
  annotations written to a new index; raw events are never modified, and
  nothing is sent to external model hubs at runtime (weights are prefetched
  at build time, §6.1).
- **G7 — No scope creep.** IsoForest/HBOS stay on CPU (§2). No new
  clustering frameworks, no RAPIDS, no flash-attention. Each of those is a
  separate decision with its own doc.
- **G8 — Image size awareness.** CUDA wheels add ~2.5 GiB to the image.
  That is acceptable here (local deployment, 195 GiB free disk verified),
  but do not additionally switch to a `nvidia/cuda` devel base image —
  wheels already bundle the runtime (§4.2).

---

## 10. Where the steps live

| Step | Issue |
|---|---|
| Re-verify §3 — GPU, toolkit, network name — and confirm the pinned `+cu126` wheel on the real card | [#82](https://github.com/Xore/APIARY/issues/82) |
| `analysis-net` vs `honeynet` — resolved: `ml-worker/docker-compose.yml` joins `honeynet` | [#61](https://github.com/Xore/APIARY/issues/61) (closed) |
| The §4 diffs, `get_device()`, the OOM→CPU wrapper, `models/embedder.py` and the `ml-embeddings` index, acceptance tests T1–T7 | [#67](https://github.com/Xore/APIARY/issues/67) |
| Retrain windows offset from the LLM report hour (§5) | [#84](https://github.com/Xore/APIARY/issues/84) |

The step most likely to be skipped is the second one in §4.1's guardrail:
confirm the `+cu126` wheel exists for the exact pinned version **before**
building. Pip will happily resolve to the CPU wheel, the image will build, the
worker will start, and everything will look correct except that the GPU is
idle. That failure is silent, which is why T2 greps the log line rather than
trusting the build.

Record the verified pins here when this deploys, and update the status line.
Do not restore the checklist form — see [`security-fixes.md`](security-fixes.md).
