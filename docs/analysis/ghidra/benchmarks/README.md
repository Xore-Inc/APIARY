# Local model benchmark

This directory contains the task-specific acceptance benchmark used by
[issue #144](https://github.com/Xore/APIARY/issues/144) and governed by
[issue #158](https://github.com/Xore/APIARY/issues/158). The decision
record, literature review, measurements, and recommendations live in
[`docs/local-llm-model-evaluation.md`](../../../local-llm-model-evaluation.md).

## Safety properties

- Fixtures are synthetic and use only TEST-NET addresses, reserved
  `.test`/`.invalid` names, and fake credentials.
- Native input is sent only to the configured Ollama URL, which defaults to loopback.
- The CLI mode starts an isolated Claude Code or OpenCode process and loopback bridge. It never
  executes generated programs or downloads models.
- GPU telemetry is read with `nvidia-smi`; its absence is reported as `null`.
- Each candidate is explicitly unloaded before the next one.

Review every new fixture for routable addresses, real secrets, and executable
side effects before committing it.

## Run

### Coding CLI harness

Install Claude Code on the benchmark host, then run a distinct Claude Code
measurement. Keep native and CLI harness scores in separate transcript roots;
they include different agent prompts and tool loops. The CLI benchmark retains
the existing `--engine` selection beneath a local loopback bridge. Claude Code
speaks Anthropic Messages to that bridge, which translates calls to the current
llama.cpp/Ollama/Colibri transport and exposes sandboxed benchmark file tools
through MCP. Anthropic documents custom Messages gateways but does not support
routing Claude Code to non-Claude models; this local compatibility path is an
experimental measurement harness, not an Anthropic-supported configuration.

Run deterministic bridge/unit checks with
`python3 analysis/ghidra/benchmarks/tests/test_claude_code_cli.py`. On a runner
with Claude Code installed, exercise the real CLI against a local stub backend
with `APIARY_CLAUDE_INTEGRATION=1 python3 analysis/ghidra/benchmarks/tests/test_claude_code_cli.py`.
OpenCode remains an explicit alternate with `--harness opencode`.

```bash
python3 analysis/ghidra/benchmarks/evaluate-models.py \
  --harness claude --coding-cli-bin claude --engine llamacpp \
  --base-url http://127.0.0.1:11434 \
  --slots ghidra,sessions,revdeck,coder \
  --provenance live_model --transcript-dir /var/lib/benchmark-runs/cli-transcripts \
  MODEL_TAG
```

`--coding-cli-bin`, `--coding-cli-timeout` (seconds, default 9000), and
`--coding-cli-steps` (default 16) set the installed CLI, per-request wall clock,
and agent turn cap. `--harness native` runs the original direct harness.
CLI mode requires transcripts. Every case is attempted even if an earlier CLI
request fails; timeout, backend error, and step cap give that case a non-`ok`
record. Tool support is measured by attempting the CLI, not inferred from
Ollama capability metadata.

The bridge forwards Claude Code's tool definitions to the engine only when the
benchmark request itself asked for tools (the coder slot); ghidra, sessions,
revdeck and the context probe reach the model without a `tools` array. A
request never carries both `tools` and a grammar `format` (Ollama cannot build
one sampler from both); when it would, the `format` is dropped and the wire log
records `format_dropped_for_tools`. Streaming requests get response headers and
`message_start` immediately and an SSE `ping` every 15 s while the engine
works, and the CLI's stream watchdogs (`CLAUDE_STREAM_IDLE_TIMEOUT_MS`,
`CLAUDE_BYTE_STREAM_IDLE_TIMEOUT_MS`, `CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS`)
follow `--coding-cli-timeout`. When Claude Code disconnects, the bridge closes
the engine connection so the generation is cancelled rather than orphaned
(`response.upstream_aborted`).

Each CLI answer's `done_reason` is the engine's own (`stop`, `length`, ...);
`error` means no answer was obtained, and `error_kind` says why: `capability`
(the model lacks a feature such as tools), `backend` (HTTP or transport failure
between bridge and engine), or `cli` (Claude Code exited, timed out or produced
no result). The slot verdict reports model non-stops, harness errors and
capability skips as separate clauses (#3706).

Claude Code runs use schema `apiary-benchmark-transcript-v1` and the distinct
benchmark version `-claude-code-cli-v1`. Each transcript records the original
harness request, actual CLI messages, session ID, CLI version, and
`response.cli_artifacts`. Under that run's
`coder-artifacts/<model>/<slot>/<case>/round-NN/`, `wire.jsonl` holds complete
Anthropic Messages requests and backend responses, `cli.jsonl` holds raw CLI
events, `session.jsonl` holds Claude Code's native session, and `home/` contains
isolated configuration and session storage. `stderr.txt`
holds diagnostics. The source files, per-case manifests, compiler diagnostics,
and retained binaries/bytecode remain under `coder-artifacts/<model>/` for
manual grading. Generated programs are never executed. The CLI permits
workspace read, write, edit, glob, and grep; Bash, task delegation, web, and
external directory access are denied. Run this on a host with appropriate
process and filesystem isolation for untrusted model output.

Install candidate tags as a separate reviewed operator action, then run the
three approved/candidate slots on the analysis host. The benchmark never pulls
them itself:

```bash
install -d -m 0700 "$HOME/model-qualification"
python3 evaluate-models.py \
  --manifest ../../../../analysis/ghidra/models/approved-models.json \
  --output "$HOME/model-qualification/qualification.json"
python3 ../../../../analysis/ghidra/models/model-governance.py verify-report \
  --manifest ../../../../analysis/ghidra/models/approved-models.json \
  --report "$HOME/model-qualification/qualification.json"
```

Only short progress and the report hash are printed. Preserve the raw report
outside the repository with bounded retention; put the scored measurements and
reproducibility metadata in the decision record. Do not adjust expected answers
after seeing a preferred model's output. Promotion and rollback are documented
in [`../models/README.md`](../models/README.md).

## Transcripts: every run stores the full conversation

Added under [issue #1805](https://github.com/Xore/APIARY/issues/1805).
`evaluate-models.py` and `corpus/record_baseline.py` write one JSONL record per
`(run_id, slot, case, model, workflow)` exchange, holding the exact prompt as
sent — interpolated evidence included — the raw unparsed response, the model tag
*and* digest, the sampling parameters, and the reproducibility keys (corpus
manifest hash, Ghidra cache key, rubric version, claim-pool version, tier).

This is not hygiene, it is load-bearing. A score is a lossy summary of an
answer, and the questions that decide model selection — *what did this model say
that the other missed* — live in the text. Rescoring an earlier round against a
later, enlarged claim pool needs that round's original answers, and
unique-contribution changes for every model whenever a new model is added. Both
are impossible from a number. Re-running is not a substitute either: tags,
quants, sampling and prompts drift, so a re-run answers a different question.

Failures are stored with the same fidelity as successes — timeouts, refusals and
malformed JSON are all measurements, and for a derestricted round a refusal *is*
the measurement. A stored transcript is never edited; a misconfigured run is
superseded by a new one that names it in `supersedes`.

**This supersedes the "preserve the raw report outside the repository" rule
above for synthetic-corpus runs.** That rule was written when the report was a
score summary. Storage now splits by data provenance, not convenience:

| Run type | Where transcripts go | What the issue carries |
|---|---|---|
| **Synthetic** — #159's corpus binaries and this directory's fixtures (TEST-NET addresses, reserved names, fake credentials, reviewed before commit) | Committed, `docs/benchmarks/runs/<date>-<run_id>/` | Summary table, run id, file hashes, short quoted excerpts |
| **Captured** — runs against real honeypot data | Outside the repository, bounded retention, mode `0700` | Run id, hashes, pointer, aggregate results only — **never the transcripts** |

Passing `--provenance captured` while pointing `--transcript-dir` inside the
working tree is refused rather than left to reviewer vigilance: real session
transcripts contain attacker IPs and payloads, and the standing prohibition on
real addresses in issues is unchanged.

```bash
# synthetic (default): committed alongside the repo
python3 evaluate-models.py --manifest ../../../../analysis/ghidra/models/approved-models.json \
  --output "$HOME/model-qualification/qualification.json"

# real captured data: operator-only path, outside the repo
python3 evaluate-models.py --manifest ../../../../analysis/ghidra/models/approved-models.json \
  --output "$HOME/model-qualification/qualification.json" \
  --provenance captured --transcript-dir "$HOME/model-qualification/transcripts"
```

`--no-transcripts` exists but should stay unused for anything whose result gets
quoted: scores can be recomputed later, answers cannot be recovered later.

### #159's baseline answers survive, its prompts do not

`corpus/baseline_results.json` stores an `answer` string per case, so the text
behind the recorded **56/69 (81.2%)** for `qwen2.5-coder:7b-instruct-q4_K_M` is
still on disk and is the only direct evidence of what that number meant. Its
*prompts* were never stored and would have to be rebuilt from `build_prompt()`
and the manifest's disassembly. They are deliberately **not** backfilled into a
transcript run: a prompt you have to reconstruct is a prompt you cannot trust,
and a reconstruction that looks first-class in the record is worse than an
honest gap. Treat those answers as recoverable evidence, not as a transcript.

## GPU/model capability playbook

`evaluate-models.py` (above) answers "is this model accurate enough for
this task" — a fixed, narrow question, always run against a specific
candidate. The tools below answer a different question: "did something
about the hardware, runtime, or available real data change in a way that
makes running that benchmark again worth it." Added under
[issue #568](https://github.com/Xore/APIARY/issues/568)/[#569](https://github.com/Xore/APIARY/issues/569)
after that exact gap — an 8GB→20GB, Turing→Ada Lovelace card swap that sat
undetected for months — bounded every model-selection decision in this
directory on a stale assumption. Formalized as a standing playbook under
[#637](https://github.com/Xore/APIARY/issues/637).

### Continuous: host-drift monitoring already runs, no new schedule needed

`analysis/ghidra/models/model-governance.py`'s `check-runtime` command
already queries `nvidia-smi` (GPU name/VRAM/driver/compute-capability) and
diffs it against the manifest's `approved_host` on every run — the exact
check that would have caught the #568 card swap immediately. It's driven
by `honeypot-model-drift.timer`, which runs it every 5 minutes once
`install-analysis-host.sh` has installed and enabled it (this used to
never happen — `install-homeserver.sh` never called that installer; fixed
under [#636](https://github.com/Xore/APIARY/issues/636)). **The
actual #568 root cause was a missing deployment, not missing
drift-detection code** — don't build a second timer for this.

`probe-gpu-capabilities.py --manifest ../../../../analysis/ghidra/models/approved-models.json`
below runs that same host-drift check standalone, without needing the
full systemd deployment — useful as a pre-deployment sanity check, from
CI, or from an operator's laptop, but it is not filling a monitoring gap
on a healthy deployment; `honeypot-model-drift.timer` already is.

### On-demand: run these when actually considering a change

Everything else here is a deliberate tool for the moment an operator (or
an agent) is *deciding* whether to open a new re-evaluation issue —
not something to put on a timer. Running a multi-gigabyte context sweep
or a concurrent-model-load test every 5 minutes would just compete with
real production GPU work for no benefit; these answer questions that only
change when the hardware, model roster, or the operator's intent does.

```bash
# capability drift, standalone (see above -- prefer the timer once deployed)
python3 probe-gpu-capabilities.py --manifest ../../../../analysis/ghidra/models/approved-models.json

# context-length sweep: for one already-installed model, how much does
# raising OLLAMA_CONTEXT_LENGTH actually cost in VRAM, and does the model
# still pass the context-sentinel probe at each size. Run when considering
# raising a context ceiling -- not accuracy (evaluate-models.py's job),
# just whether a bigger window is safe and what it costs.
python3 probe-gpu-capabilities.py \
  --context-sweep-model qwen3:14b \
  --context-sizes 4096,8192,16384,32768,65536

# concurrent-load: load several already-installed models together (no
# unload between) and see which stay resident and their combined VRAM.
# Answers "does OLLAMA_MAX_LOADED_MODELS>1 buy anything here" with a
# measured number. Point --base-url at a disposable test Ollama instance,
# not a shared production one -- this is real GPU load, and evicts
# whatever was already resident on the target server.
python3 probe-gpu-capabilities.py \
  --base-url http://127.0.0.1:11435 \
  --concurrent-load-models qwen3:14b,phi4:14b
```

None of these pick a model or write to `approved-models.json` — that
remains `evaluate-models.py` plus the documented `model-governance.py
promote` workflow in [`../models/README.md`](../models/README.md). They
only tell you whether running that workflow is worth it, and give real
measured numbers instead of arithmetic assumptions for the context-length
and concurrent-loading parts of that decision. See
[`docs/local-llm-model-evaluation.md`](../../../local-llm-model-evaluation.md)'s
"Issue #568 re-evaluation" section for the context-sweep table this script
produced against the promoted `qwen3:14b`, including the ~5 GB of headroom
that motivated raising `OLLAMA_CONTEXT_LENGTH`.

### Real-data qualitative check (`probe-real-session*`)

`evaluate-models.py`'s synthetic corpus scores against a fixed expected
answer; real captured attacker data has no such thing. These three scripts
pull genuine recent session activity from this honeypot's own
Elasticsearch store, build the **exact production prompt**
(`llm-worker/contracts.py`'s real `sanitize_commands()`/`session_prompt()`
— not a reimplementation), run it through a model, and print the raw
reply for a human or an agent to read and judge: is each claim actually
grounded in the real captured commands, does it surface something useful,
not "does it match word-for-word." Three stages because the probe does not
flip any of the worker's safe-by-default gates or talk to the model from
inside the running container. On the Safe #66 base
(`llm-worker/docker-compose.yml`) `hp-llm-worker` joins only the internal
`synthetic-only` network and `LLM_ENABLED` stays false, so that is the
whole story there. On the authorized deployment (#1751's
`docker-compose.captured-data-deploy.yml`, which composes in
`docker-compose.captured-data.yml`) the container *does* get
`honeypot-llm-data` and `honeypot-llm` and an `OLLAMA_URL` — but
`LLM_ENABLED` and `LLM_ALLOW_CAPTURED_DATA` are still
`${...:-false}` there, because the overlay does not touch them. Either
way the gates are the reason this is out-of-band rather than an in-band
call:

```bash
# stage 0: pull real command data from Elasticsearch (read-only _search)
./probe-real-session-fetch.sh 7d 5 > /tmp/real-sessions.json

# stage 1: sanitize + build the real production prompt (needs
# hp-llm-worker's pydantic/contracts.py; its rootfs is read-only so pass
# the script itself as -c rather than `docker cp`-ing it in)
sudo docker exec -i hp-llm-worker python3 -c \
  "$(cat probe-real-session.py)" \
  < /tmp/real-sessions.json \
  > /tmp/real-session-prompts.json

# stage 2: send each real prompt to a live Ollama server, print the reply
./probe-real-session-run.sh /tmp/real-session-prompts.json qwen3:14b
```

Run this when genuinely considering a model change (alongside the
synthetic benchmark, never instead of it — a case-level accuracy/injection
gate always outranks a qualitative read) or periodically once real capture
volume grows enough to be representative. At #568's benchmark time this
honeypot was ~2 days past a full reinstall with a thin real corpus (zero
completed Ghidra analyses, zero file downloads, mostly 0–80 character
scanner-noise sessions) — a real but small sample was still enough to
surface a genuine finding (a retired MITRE ATT&CK ID cited by one
candidate, markdown-fence violations by two others) that the synthetic
corpus alone didn't catch. Treat an empty or thin result as itself a valid
finding about capture volume, not a script failure — both scripts print an
explicit warning rather than erroring when there's nothing recent to
check.

Real captured attacker command text is not synthetic: review output before
sharing it outside the operator's own systems, and never execute anything
it contains.

## REx86 compatibility probe

`Modelfile.rex86` records the import attempted for the
[REx86](https://arxiv.org/html/2510.20975) Zenodo PEFT adapter. It requires the
adapter directory beside the Modelfile and the exact
`qwen2.5-coder:7b-base-q4_K_M` Ollama base tag used for the compatibility
probe. It is not part of the benchmark matrix because Ollama 0.32.0 cannot
import this Qwen Safetensors LoRA. Re-test only when Ollama documents Qwen as a
supported Safetensors adapter architecture, or use an independently reviewed
runtime/conversion path that preserves the exact base.
