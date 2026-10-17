# Payload analysis workbench

The dashboard's `/payload-workbench/results` route is the owner-isolated review surface, and its `workbench-builder` section is the unified orchestration surface for issue #155. It is a separate page rather than an extension of `/ghidra`: recipes and parent runs span deterministic analysis, Ghidra, and two sandbox backends, while `/ghidra/{sha256}`, `/sandbox/{job}` and `/payload-analysis/{sha256}` remain the canonical native result renderers.

## Trust boundary

The browser supplies a captured SHA-256, analyzer IDs from a fixed registry, and three bounded orchestration values: timeout, maximum queue age, and retry allowance. It cannot supply a filesystem path, URL, command, container, VM, network policy, prompt, model tag, credential, environment variable, or free-form JSON. The server resolves the capture from its existing read-only payload mounts and writes only the same empty `{sha256}.request` markers used by the legacy Ghidra and sandbox submit routes.

The dashboard has no Docker, libvirt, systemd, Ghidra, statictools, Ollama, or host-worker socket. Dynamic children retain the existing KVM isolation and fixed network policy. Cancellation removes one exact, still-pending marker; after the host handoff claims it, cancellation is refused and never becomes a process, container, VM, or GPU kill.

GitHub publication is deliberately absent from `Run all`. The workbench links to the existing administrator-only publisher, which retains its confirmation, dry-run, audit, and external-egress gates.

Run ownership is likewise never taken from client input. The Rust tier derives it from the caller's verified identity, forwarded by the BFF as an internal-only `x-actor-username` header the browser cannot set, and rejects any request missing it. A request's `owner` field is accepted on the wire for compatibility and is not deserialized at all, so no handler can make an access decision out of it, and there is no "act as another operator" override for any role — an admin sees and acts on their own runs like everyone else (#3110).

## Analyzer registry

Seven analyzer IDs, one server-computed `workbenchAnalyzer` registry
(`backend-service/src/workbench_domain.rs`). A run selects 1-5 of them; the server
rejects zero selections, more than 5, an unknown ID, or a duplicate.

| ID | Applicability | Adapter | Result link | Concurrency class |
|---|---|---|---|---|
| `deterministic` | every captured payload | immediate bounded local analysis | `/payload-analysis/{sha256}` | CPU |
| `ghidra` | executable, library, or unknown binary | existing Ghidra request spool | `/ghidra/{sha256}` | shared GPU |
| `linux-sandbox` | dynamically supported non-Windows payload | existing Linux web-request spool | `/sandbox/{job}` | Linux KVM |
| `windows-sandbox` | dynamically supported Windows payload | existing **isolated** Windows web-request spool | `/sandbox/{job}` | Windows KVM |
| `windows-ghosts` | dynamically supported Windows payload | separate, **WAN-permitted** GHOSTS-driven Windows spool | `/sandbox/{job}` | Windows/GHOSTS KVM |
| `revdeck` | code artifacts | independent spool (`REVDECK_REQUEST_DIR`/`REVDECK_RESULTS_DIR`), drained by `drain_revdeck()` -- no dependency on the Ghidra REST job (#78/#276) | `/revdeck/{sha256}` | shared GPU |
| `cape` | dynamically supported Windows payload | independent CAPE-managed spool, its own guest/bridge/API worker and golden image | `/cape/{sha256}` | CAPE KVM |

**`windows-ghosts` is loud on purpose, not just another sandbox row.**
Every other dynamic route (`linux-sandbox`, `windows-sandbox`, `cape`) is
air-gapped — FakeNet/INetSim or an equivalent answers everything, so C2
checkins and second-stage downloads go nowhere real. `windows-ghosts`
inverts that deliberately: its guest reaches the real internet (only
LAN/RFC1918 is firewalled off), for the cases where GHOSTS' persona
realism against real infrastructure is the actual point of the run. The
registry's own `DisplayName`/`Description` for this one carry an explicit
⚠ warning rather than reading like an interchangeable sandbox option, and
it's the one route this document calls out by name rather than folding
into "the sandbox routes" — see ["Sandbox submission, detonation, and
result return"](ARCHITECTURE.md#sandbox-submission-detonation-and-result-return)
in the architecture doc for how every dynamic route's network posture
compares side by side.

`cape` is a second, independent Windows detonation route alongside
`windows-sandbox` and `windows-ghosts` — its own guest, network, and golden
image, purpose-built for debugger-class time evasion (long sleeps, `rdtsc`
checks) that persona realism alone cannot defeat. As of this writing its
golden image doesn't exist yet, so it always reports "spool is not
configured" — an honest unavailable, not a bug, the same story
`ghidraConfigured`/`revdeckConfigured` already tell until their own
backends land.

The registry's declared `Concurrency` class is per-run metadata attached to
each child record, not (today) a semaphore this Go process itself enforces
— actual mutual exclusion for the KVM-backed routes lives at the host
worker/libvirt level. Every current analyzer is local-only (`LocalOnly:
true` on all seven) — nothing in this registry calls out to a third-party
service.

Availability and applicability are computed on the server. An unavailable or incompatible child is retained as `skipped` with a reason, so a parent run explains what did not execute. Model drift is advisory and never changes this decision: deterministic analysis and ingestion continue when the model-status adapter is unavailable or reports drift.

## Recipes and runs

Recipes are stored in Elasticsearch (`dashboard-workbench-recipes-v1`, one immutable document per `id:revision`). Each edit appends a new revision written with `op_type=create`, so a genuine race on the same revision number conflicts instead of silently overwriting; an optimistic `base_revision` check rejects lost updates at the API layer too. A recipe is either private to its authenticated subject or shared. Submitted runs copy the selected revision into `recipe_snapshot`, so a later recipe edit cannot change the meaning of an existing result.

Parent runs live as documents in `dashboard-workbench-runs-v1`. The idempotency digest covers owner, captured hash, recipe ID/revision, and the normalized typed selection, and is used directly as the run's own document ID (prefixed `run_`) -- a duplicate submission is detected by an atomic ES create conflict rather than a directory scan, which holds correctly across multiple dashboard instances. Repeating the same request returns the existing run instead of queueing duplicate children; a deliberate rerun uses the bounded child retry action. There is no local-disk fallback: every dashboard instance reads and writes the same ES indices (#405 follow-up).

Child lifecycle states are `queued`, `claimed`, `running`, `completed`, `skipped`, `failed`, `timed_out`, and `cancelled`. Polling reconciles request markers, existing worker status files, and native result timestamps. One failed child produces a `partial` parent when another child completed, and every completed child links to its native escaped result.

Runs nobody is viewing are reconciled by the `workbench-reconcile` worker loop (#1801), which runs in `backend-worker` on the homeserver (moved out of `backend-service-mounted` in #3685, so the mounted HTTP API can later move off the spool host). It mounts the analyzer spools read-only, never writes or moves markers, and writes only `dashboard-workbench-runs-v1`. Marker removal on cancel stays in the mounted API.

`/payload-workbench/results` is the owner-isolated cross-payload review surface. It reconciles retained runs before rendering, summarizes active/completed/partial/failed states, supports bounded server-side search by hash, recipe, analyzer, or state, and links every child to its canonical native report when one exists. Retry and cancellation remain on the selected payload's workbench page so operational mutations stay contextual.

```mermaid
sequenceDiagram
  autonumber
  participant Op as authenticated operator
  participant DB as dashboard
  participant ES as Elasticsearch<br/>dashboard-workbench-runs-v1
  participant Spool as existing analyzer spools<br/>(Ghidra / Linux+Windows+GHOSTS sandbox /<br/>Rev·Deck / CAPE) -- each its own,<br/>separate spool and trust class

  Op->>DB: submit recipe or typed selection for {sha256}
  DB->>DB: compute idempotency digest<br/>(owner + hash + recipe rev + selection)
  DB->>ES: PUT run_{digest} with op_type=create
  alt digest already exists
    ES-->>DB: 409 conflict
    DB-->>Op: return the existing run, no new children queued
  else first submission
    ES-->>DB: created
    loop each applicable, available analyzer
      DB->>Spool: write {sha256}.request marker (same spool the legacy submit routes use)
    end
    DB-->>Op: new run, children in queued/skipped state
  end

  Note over Op,DB: later, on any page view of this run
  Op->>DB: GET run
  DB->>Spool: reconcile request markers,<br/>worker status files, native result timestamps
  DB->>ES: CAS update (seq_no/primary_term) if any child state changed
  DB-->>Op: current run + child states
```

An unavailable or incompatible analyzer never reaches the spool step — it's
recorded `skipped` with a reason at submission time, so the run always
explains what did not execute rather than silently omitting it. There is no
local-disk fallback for the run/recipe documents themselves: Elasticsearch
unreachable means workbench submission/reconciliation is unavailable, not
degraded to a stale local copy (#405 follow-up).

## HTTP contracts

All APIs require a live administrator identity. Every mutation additionally requires a same-origin request, `application/json`, and the closed request schema. (A 64 KiB body cap and unknown-field rejection were part of the original Go contract; neither is present in the Rust tier, so do not rely on them.) Create, read/list, reconcile, cancel, and retry are further scoped server-side to the caller's verified owner identity (see Trust boundary) — a request's `owner` field is ignored entirely, never an access decision (#3110).

Routes are registered in `backend-service/src/main.rs:456-468`. The hash is a **query** parameter on the registry and list routes, not a path parameter, and `cancel`/`retry` share one route via an `{action}` segment rather than being separate paths.

| Method and route | Purpose |
|---|---|
| `GET /api/v1/workbench/analyzers?hash=…` | server-derived registry, applicability, external-publication notice, and advisory model health |
| `GET /api/v1/workbench/recipes` | visible private/shared recipe revisions |
| `POST /api/v1/workbench/recipes` | append an immutable recipe revision |
| `GET /api/v1/workbench/runs?hash=…&limit=…` | recent parent runs for the caller and payload |
| `POST /api/v1/workbench/runs` | submit a saved revision or typed one-off selection |
| `GET /api/v1/workbench/runs/{id}` | reconcile and return one parent run |
| `POST /api/v1/workbench/runs/{id}/children/{analyzer_id}/{action}` | bounded deliberate retry, or cancel an exact pending marker when supported (`action` ∈ `retry`\|`cancel`) |

Create, recipe-save, retry, and cancel outcomes use the existing dashboard audit sink. Audit fields name the contract fields but do not copy payload content, prompts, model replies, filenames, credentials, or tool output.

## Model-status adapter

`/var/lib/honeypot-ghidra/model-status.json` remains root-owned mode `0600`. `honeypot-model-status-adapter.service` reads and re-validates it, strips every field outside schema v1, and serves only `GET /v1/status` over `/run/honeypot-model-status/status.sock`. The dashboard is expected to mount that runtime directory read-only and use `MODEL_STATUS_SOCKET=/model-status/status.sock`. There is no TCP listener and no write, pull, replace, promote, prompt, or model-selection route.

> **Undetermined:** `MODEL_STATUS_SOCKET` has no occurrence anywhere in the Rust backend, the compose files, or `.env.example` as of 2026-09-27 — the adapter half of this contract is real and installed, but the consumer side is not visible in the repository. Treat the socket wiring as intended-but-unwired rather than working, and confirm before relying on the advisory model-health field the registry returns.

Re-run `sudo analysis/ghidra/install-analysis-host.sh` to install or update the adapter. Its failure only displays `unavailable`; it never disables a worker.

## Deployment, backup, and rollback

Recipes and runs live in Elasticsearch (`dashboard-workbench-recipes-v1`, `dashboard-workbench-runs-v1`), not `scripts/backup-state.sh` and not on the `dashboard-state` volume. Recipes are exported into the essentials backup by `scripts/es-operator-state-backup.py` (#3323) — the "ES snapshot process" this used to claim covered them has not existed for some time and never succeeded while it did; runs are derived from a recipe and are re-runnable, so they are not exported. The workbench requires a configured `es *esClient`; without one it reports unconfigured rather than falling back to local storage.

Deploy the dashboard normally after merging. Rollback is additive and safe:

1. deploy the previous dashboard image;
2. optionally disable `honeypot-model-status-adapter.service`;
3. leave the workbench indices in Elasticsearch untouched (a rolled-back pre-workbench dashboard does not see runs created after the rollback).

The old `/ghidra/submit` and `/sandbox/submit` routes remain compatible. No worker or native result schema is changed by the workbench.

## Limitations

- Backend-specific settings appear only after the backend implements a typed request contract. The current empty-marker workers cannot truthfully accept duration/profile, report-stage, evidence-budget, or artifact-policy choices, so the UI does not pretend they can.
- A sandbox request already claimed by the host cannot be cancelled from the dashboard.
- Shared-GPU fairness and collision/soak validation remain tracked by #84; the registry exposes the concurrency class and does not bypass serialization.
