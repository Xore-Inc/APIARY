# AI Triage

Split out of [`README.md`](README.md) (#142): this is the deep-dive on the
worker's AI-triage workflow — the local-only enforcement, the context-window
pitfall, how to read a result, and the prompt-injection posture. The README
keeps a short pointer here rather than this whole section, the same way it
links out to [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) and
[`DASHBOARD_INTEGRATION_PLAN.md`](DASHBOARD_INTEGRATION_PLAN.md) instead of
inlining them.

After collection the worker runs two workflows against the model —
`program_triage` and `suspicious_behavior` — and writes the answer to
`ai_triage` on the result.

The default, context, and explicit non-thinking request mode come from the
[task-specific live-host evaluation](../../local-llm-model-evaluation.md),
not a general model leaderboard.

The endpoint is OpenAI-compatible (`/v1/chat/completions`), the dialect that
Ollama, llama.cpp's server, vLLM and LM Studio all serve, so the backend is
swappable. What is not swappable is that it must be **local**.

## The local-only rule

The prompts carry strings, imports and function names lifted straight out of a
captured sample. Sending that to a hosted API is not a smaller version of this
feature; it is a data-exfiltration path out of the analysis environment. So the
rule is enforced in code — `endpoint_is_local()` in
[`worker/ghidra-worker.py`](../../../analysis/ghidra/worker/ghidra-worker.py) — and **there is no
override flag**:

- IP literals must be loopback, RFC1918/ULA, or link-local.
- A bare name with no dot is accepted; so is one ending `.local`, `.internal`,
  `.lan`, `.localdomain`, `.home.arpa`.
- Everything else is refused, before any request is made.

The judgement is syntactic, not a DNS lookup, because a resolver answer can be
moved by whoever controls the zone — and the failure actually being guarded
against is an operator pasting an `api.openai.com` or `openrouter.ai` URL into
config.

## Data flow

Evidence assembly, prompt construction, the model call, the truncation check
that decides whether an answer survives, and risk normalisation, tied
together — the picture prose alone left readers to reconstruct from several
separate subsections (#142):

```mermaid
flowchart TD
  functions["functions<br/>(from Ghidra)"]
  strings["strings<br/>(from Ghidra)"]
  imports["imports<br/>(from Ghidra)"]
  budget["Evidence budget<br/>GHIDRA_TRIAGE_MAX_STRINGS/_IMPORTS/_FUNCTIONS"]
  evidence["Evidence block<br/>fenced === EVIDENCE === markers"]
  prompt["System + user prompt<br/>evidence named as data, not instructions"]
  local{"endpoint_is_local()?"}
  refuse["Refused before any request is made<br/>ai_triage left null, reason logged"]
  request["POST /v1/chat/completions"]
  usage["token usage reported by the server"]
  truncated{"prompt_tokens indicates<br/>the prompt was truncated?"}
  discard["Answer discarded<br/>ai_triage left null, reason logged"]
  parse["Parse JSON answer"]
  normalise["normalise_risk()<br/>low / medium / high / critical, or empty"]
  result[("ai_triage written to the result")]

  functions --> budget
  strings --> budget
  imports --> budget
  budget --> evidence --> prompt --> local
  local -->|no| refuse
  local -->|yes| request --> usage --> truncated
  truncated -->|yes| discard
  truncated -->|no| parse --> normalise --> result
```

Triage fails soft, in every direction. No endpoint configured, an endpoint
that is refused, one that is unreachable, a model error, an answer that will
not parse — each leaves `ai_triage` null with the rest of the analysis
complete and the result written. Triage never fails an analysis.

## The context window is part of the configuration

The evidence block for a real binary is around 8000 tokens. Ollama's default
window is 4096 whatever the model can do — `qwen3:8b` advertises 40960 — and an
overlong prompt is **truncated, not refused**. There is no error, no HTTP
status, and the model answers from whichever fragment survived.

Measured here on `/usr/bin/wget`: at the default the reply described a command
line with hardcoded credentials that appears nowhere in the sample; at 16384
the same prompt returns `{"family_guess": "wget", "risk_level": "low"}`.

So the compose file sets `OLLAMA_CONTEXT_LENGTH=16384`. It has to be set on the
server, because `/v1/chat/completions` has no field for context length — only
Ollama's native API and that variable can reach it. Budget about 1.8 GB of KV
cache on top of the weights; `qwen3:8b` Q4_K_M reports 7.8 GB total on the live
host and offloads about 1 GB to system RAM. CPU/RAM offload is supported and is
not a correctness failure. On a genuinely memory-constrained host, lower the
window and the evidence budgets together rather than accept truncation.

The worker does not trust the setting. Every reply is checked against the token
count the server reports about itself, and an answer whose prompt was truncated
is discarded with the reason logged. A window that is too small therefore shows
up as **missing** triage, never as invented findings. `--selftest` probes for it
directly, so it is visible at install time rather than in a malware report.

## Reading the result

```json
"ai_triage": {
  "workflow": "program_triage+suspicious_behavior",
  "family_guess": "Mirai variant",
  "risk_level": "high",
  "behaviors": ["connects to a hardcoded C2 address", "kills competing processes"],
  "model": "qwen3:8b",
  "slot_generation": "0123456789ab/ctx32768/vram14336mib",
  "evidence_shown": "150/312 imports, 200/11482 strings (longest first, deduplicated, >=6 chars), 100/847 functions (largest first)"
}
```

- **`risk_level`** is normalised to `low` / `medium` / `high` / `critical`, or
  left empty. Models return "Highly Suspicious" and "Moderate" given the chance,
  and the dashboard's alert config matches exact strings — an un-normalised
  level would silently never alert.
- **`model`** is always recorded. The detail page and the alert text both name
  it, because "the model said" is only useful if you know which model.
- **`slot_generation`** says which *resident instance* of that model answered,
  and it is the field to check before comparing two assessments. Ollama keeps
  the weights loaded between samples (`OLLAMA_KEEP_ALIVE=30m`), and a warm slot
  returns different text for a byte-identical prompt at temperature 0 with a
  fixed seed — so two results carrying the same `model` are still not
  comparable unless this matches. Values: an instance fingerprint
  (`<digest>/ctx<n>/vram<n>mib`), `cold` when nothing was loaded at the time,
  `unavailable` when the runtime API could not be asked, or `a->b` when the
  slot changed underneath the two workflow calls. `unavailable` is
  deliberately distinct from `cold`: not knowing which instance answered must
  not read as knowing it was a fresh one.
- **`evidence_shown`** is the one to read first. A real sample overflows any
  context window, so the assessment is formed from a subset; a claim the model
  did **not** make may simply be something it was never shown.
- **`behaviors`** carry no per-claim evidence links. The workflows do not
  return that mapping, and inventing one would make a guess look like a
  citation.

`findcrypt` results are deliberately kept out of the prompt. Crypto constants
carry their own caveat — presence does not show malicious use — and feeding
them to a model invites exactly the over-reading the dashboard warns about.

Every claim is a language model's reading of decompiled code. The detail page
says so in an orange banner above the section, and the alert text carries
`UNVERIFIED`, because a webhook is read where that banner is not visible.

## Prompt injection

The evidence is attacker-authored: it is text out of a sample that may well
contain instructions aimed at whatever reads it. It is fenced in
`=== EVIDENCE ===` markers, the system prompt names it as data rather than
instructions, the answer is structurally constrained, and everything is
re-normalised on the way out. That is containment, not immunity — which is why
the banner stays.
