# Claims audit — README.md and docs/** (#3504)

> **Status:** audit only. Every row below records a claim as written and the
> disposition Pass 2 applies. Every cited file:line was read in this worktree on
> 2026-10-04, on the branch cut from `origin/main` for #3504.

The rule this audit encodes: **no marketing adjective in README or docs without
a named component and a cited behaviour.** A claim that cannot be tied to a
component that actually does it is deleted, not softened.

## 1. Method

Two passes. This file is Pass 1 (the audit); the edits are Pass 2.

Swept, case-insensitively, over `README.md` and `docs/**` for the issue's
adjective families — "AI-driven", "AI-powered", "AI-driven defense",
"next-generation", "state-of-the-art", "cutting-edge", "advanced",
"enterprise-grade", "seamless", "robust", "powerful" — plus the wider
capability-claim vocabulary the issue's rule targets ("provides", "offers",
"delivers", "enables", "unlocks", "24/7", "real-time", "zero-day", "zero
false"), so the sweep would not pass a claim just because it used a word the
issue did not list.

### 1.1 Headline result

The literal families the issue named are, with two exceptions, already absent
from `main`. Counts over `README.md` + `docs/**` (markdown):

| Family | Hits | Disposition |
|---|---|---|
| "AI-driven" | 0 | — |
| "AI-powered" | 0 | — |
| "next-generation" | 0 | — |
| "state-of-the-art" | 0 | — |
| "cutting-edge" | 0 | — |
| "enterprise-grade" | 0 | — |
| "seamless" | 0 | — |
| "powerful" | 0 | — |
| "advanced" | 5 | 4 are a GitHub CodeQL product term or a measurement statement; 1 is a superseded-tool table cell |
| "robust" | 4 | 4 are a statistical/benchmark term, not a capability claim |

The ten zero-count families are the finding: this repo has been swept for this
shape before, and the issue's premise that instances of "AI-driven defense"
remain is not borne out. **The live defects are not in the adjective list at
all** — they are the vague-but-uncited claims and the one unbacked number the
issue names by file and line (§3, §4), which is why the sweep was widened
rather than stopped at the nine families.

## 2. The rule's exclusions, verified

Two families the issue explicitly puts out of scope, confirmed here:

- **"OpenAI-compatible" is a wire-protocol term.** Occurrences name a request
  shape (`/v1/chat/completions`-style endpoints), not a quality claim. Left
  alone, including in `docs/PENTAGI.md`, where it describes the configured
  `OPEN_AI_SERVER_URL` endpoint.
- **"AI-generated" as a label on model output or attacker-controlled content
  is a safety feature.** It marks text that must not be trusted as fact. Left
  alone, and in one case (`docs/gpu-llm-analysis-worker.md:503`) confirmed
  against the UI that actually renders it (§3.2).

## 3. Findings

### 3.1 `confidence` is a model self-report, not a computed score

**The single most important fix in the issue, and it resolves as a deletion.**

- `docs/gpu-llm-analysis-worker.md:503` — "every row labelled "AI-generated"
  and showing severity/confidence".
- `docs/ml-gpu-coordinated-roadmap.md:212` — "Later UI output is escaped,
  labelled "AI-generated", and shows confidence and evidence links."
- `docs/llm-worker/README.md:255-264` — lists `confidence` in the result
  contract without saying what it is.

What `confidence` actually is, traced end to end in this worktree:

1. It is a field the model fills in for itself. `llm-worker/contracts.py:148`,
   `:170`, `:208` declare `confidence: Literal["low", "medium", "high"]` on all
   three annotation types — the model's own output schema.
2. The system prompt instructs the model when to lower it
   (`llm-worker/contracts.py:35`: "If the input is empty, truncated, or
   unintelligible, say so in the summary and set confidence to low"). That
   instruction is prose to the model, not a rule enforced by code.
3. `postprocess_annotation` (`llm-worker/contracts.py:331`) is the deterministic
   correction pass — it overwrites `iocs`, `mitre_attack`, `intent`, `severity`
   and `summary` against regex-extracted evidence. **It does not touch
   `confidence`**; a repo-wide grep for `confidence` in `llm-worker/` returns
   no assignment other than the model schema and the error-document stub
   (`worker.py:1212`, `:1252`, which write the empty string).
4. The UI renders whatever arrived: `frontend-next/src/routes/llm-analysis.tsx:158`
   prints the raw string.

So there is **no computation, no calibration, no measured quantity.** The
field is the model's own adjective about its own answer, and it is the one
field the deterministic safety pass is deliberately silent about. Per the
issue's rule — publish what it is and how it is computed, or remove the word
rather than inventing one — and per its standing preference for deletion over
softening, the docs must say so explicitly rather than leave a bare
"shows confidence" that reads as a score.

Fix: name it as a model self-report, cite the three contract lines and the
absence in `postprocess_annotation`, in all three places. Delete the roadmap's
implied promise that it is a metric.

### 3.2 `docs/PENTAGI.md` states inventory, not function

`docs/PENTAGI.md` is already precise about credentials — "the only credentials
present at all are the OpenAI-compatible key pair and the Postgres/Neo4j/session
secrets the stack generates for its own database" (`:196`), and it sets out
running/exited state, ports, volumes, networks, resource usage and observed
instability in detail.

What it never says is **what the component does end to end.** The whole
document describes *how the stack runs* and never *what it is for*. The issue
asks for that plainly. The honest statement is what the doc's own evidence
supports: it is an out-of-band autonomous-pentest stack on the homeserver,
self-hosting its model backend (the in-network `pentagi-ollama-embedding`),
reaping its own agent-execution sandboxes (`pentagi-terminal-1..3`, "created and
reaped by PentAGI itself as agent execution sandboxes", `:88`), and — per the
instability section — **not stably up**: "treat "PentAGI is up" as a sampled
observation, not a guarantee" (`:262`).

Fix: one end-to-end paragraph naming the components the doc already
enumerates, stating the sampled-not-guaranteed status inline rather than only
in the instability section.

### 3.3 "degraded or AI-generated data" — the AI half is labelled; the degraded half is not a UI mode

- `docs/ml-gpu-coordinated-roadmap.md:298` — "Dashboard output is
  authenticated, bounded, escaped, and clear about degraded or AI-generated
  data."

Two different things share the sentence. Verified separately:

- **"AI-generated": labelled as specified.** Every row of the `/llm-analysis`
  table carries an `AI-generated` badge whose tooltip is "every row on this page
  is generated by a local LLM, not a human analyst"
  (`frontend-next/src/routes/llm-analysis.tsx:150-153`), the severity column
  header is "severity (AI-guessed)" (`:157`), and the page subtitle says
  "every judgment here is AI-guessed and unverified until a human confirms it"
  (`:188`). The roadmap's claim is true as written for this half.
- **"degraded": not a UI mode.** The roadmap's own degraded-mode items
  (`:101` "health, error, and degraded-mode records"; `:176` "degraded-state
  responses") are milestone *plans* under a document that opens "**Status:**
  Proposed implementation sequence — intent, not shipped state" (`:3`).
  The nearest live thing is `ml-worker`'s checkpoint fallback: on an ES read
  timeout it continues from the last in-memory checkpoint and logs it loudly
  (`ml-worker/worker.py:308`, asserted by
  `ml-worker/tests/test_worker_fixes.py:180`, "degraded fallback must be logged
  loudly"). That degradation is visible in the worker log, **not** rendered as a
  dashboard mode — a frontend grep for a degraded badge returns nothing but
  Keycloak login copy.

Fix: split the sentence so the roadmap stops implying a dashboard degraded
label that does not exist, and says where the real degradation surfaces.

### 3.4 `README.md` "automated malware-analysis stack"

`README.md:9` — "A multi-service honeypot and automated malware-analysis stack",
and the logo alt text (`:5`) reads "Automated Payload Intelligence & Attacker
Response".

"Automate" here is backed by named components, but the README never names
them, which is precisely the shape the rule rejects. The components that do
the automating, all verified present in this worktree:

| Claim shape | Component | File |
|---|---|---|
| correlates attacker activity across sensors | `WORKER_LOOPS=correlator` (line 388), `attacker-identity` (line 368) | `arcane/home/honeypot-dashboard/backend-service/src/worker.rs` |
| detects campaigns and scores them | campaign correlator | `backend-service/src/campaign_correlator.rs` |
| detects anomalies | `ml-worker` IsolationForest/HBOS/LSTM composite | `ml-worker/worker.py:183` (`compute_composite`) |
| dedupes and YARA-scans payloads | `payload-dedupe` (line 34), `yara-scanner` (line 122) | `arcane/home/honeypot-payload-analysis/compose.yml` |
| raises alerts, with cooldown and webhook | `WORKER_LOOPS=alert-notifier` (line 348) → `dashboard-alert-state-v1` (`ALERT_INDEX`, line 33) | `backend-service/src/worker.rs` |
| schedules generated reports | `WORKER_LOOPS=reports-scheduler` | `backend-service/src/worker.rs:358` |
| reports IPs externally (dry-run by default) | reporter | `arcane/home/honeypot-utilities/reporter/` |

Fix: replace the bare "automated" claim with the detect/correlate/automate
sentence pointing at those files.

### 3.5 Keep-but-justify: the five "advanced" and four "robust" hits

Every one of these is a term of art, not a capability claim. Left in place, and
recorded here so the next sweep does not re-litigate them.

| Location | As written | Why it stays |
|---|---|---|
| `docs/CI-CD.md:73` | "CodeQL's advanced setup", "**Advanced**, not **Default**", "CodeQL analyses from advanced configurations cannot be processed" | GitHub's product term for a CodeQL configuration mode, quoted from the error string. The paragraph is a runbook telling you which setting to pick. |
| `docs/analysis/ghidra/IMPLEMENTATION_PLAN.md:503` | `strings2` \| "Advanced string extraction" | A cell in the *excluded tools* table describing what a rejected tool would have added. Not a claim about this repo. |
| `docs/llm-synthetic-canary-record.md:28` | "raw event count advanced from 769506 to 769562" | A measured counter, as a verb. |
| `docs/analysis/ghidra/benchmarks/injection-gate-protocol.md:186` | "robustness comes from more" | Benchmark-methodology meaning (variance reduction), immediately defined in the sentence. |
| `docs/benchmarks/2026-08-30-injection-gate-recalibration.md:392` | "Robustness has to come from multiple twins/payload styles" | Same methodology sense. |
| `docs/benchmarks/claim-pools/README.md:65` | "Extraction is not fully robust." | A negative finding about two specific extractions, followed by which ones failed. |
| `docs/ml-worker-evaluation.md:382` | "above robust covariance, one-class SVM and DoSE by AUROC" | "robust covariance" is an algorithm name. |

## 4. Claims deleted rather than rewritten, with reasons

Per the issue's standing preference for deletion over softening, these are the
claims Pass 2 removes rather than reword. The reasons are on the row.

| Claim as written | Where | Why deleted instead of softened |
|---|---|---|
| "shows confidence" as a product capability of the roadmap's Milestone G | `docs/ml-gpu-coordinated-roadmap.md:212` | No computation exists (§3.1). The word is replaced by the truth — a model self-report — not carried forward as a capability. |
| the roadmap's implied promise that a degraded dashboard mode exists | `docs/ml-gpu-coordinated-roadmap.md:298` | No such UI label exists (§3.3). Softening to "clear about degraded data" would still assert the mode. |
| "Advanced string extraction" as a capability cell | `docs/analysis/ghidra/IMPLEMENTATION_PLAN.md:503` | The row is in the *excluded tools* table; the capability claim belongs to a tool this repo rejected. Deleting the adjective removes an implied endorsement. |

## 5. Not in scope, recorded so it is not re-audited

- **Numbers.** Every figure already in these documents was verified in this
  worktree before appearing in any new text. No new figure was introduced by
  this issue; where a doc's numbers were already there, they were left alone.
- **Public-repo hygiene.** No real addresses, hostnames, credentials or
  captures are introduced. `docs/PENTAGI.md`'s set-vs-unset discipline is kept.
- **Maturity labels** (issue #3496 criterion 7) and the architecture diagram
  (criterion 1) are separate criteria, already landed on `main` by #3505–#3508.