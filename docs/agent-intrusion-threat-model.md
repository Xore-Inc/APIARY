# Agent-Speed Intrusion Chain: Threat Model & Applicability Matrix

> **Status (2026-08-27, #1662):** research record from the Go-dashboard era;
> references to `dashboard/*.go` describe code that no longer exists. The
> mechanics it proposed shipped in the Rust worker loop instead:
> `backend-service/src/agent_intrusion.rs`, `criticality_rules.rs`,
> `campaign_correlator.rs`, with the labelled corpus and Tier 1 contract
> benchmark under `arcane/home/honeypot-agent-intrusion-worker/`. Kept as
> the threat-model rationale; verify current behavior against the Rust
> modules, not the file names below.

> **Status:** Research (#154), phase 1 of 5. This document is the "map the
> published campaign to APIARY's actual trust boundaries" deliverable;
> it does not implement anything. Phases 2-5 (synthetic replay corpus,
> decode/correlate pipeline, deterministic criticality rules, preventive
> control gaps, operator evidence UI) are scoped as follow-up work — see
> [Follow-up scope](#follow-up-scope) at the end.
>
> **Source:** [huggingface.co/blog/agent-intrusion-technical-timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
> (July 2026) — an autonomous agent chaining ordinary weaknesses at machine
> speed across evaluation sandboxes, data-processing workers, Kubernetes,
> cloud identity, mesh networking, and source control. ~17,600 actions;
> isolated low-signal events were detected individually but never escalated
> with the right criticality. A corroborating source,
> [openai.com's own incident writeup](https://openai.com/index/hugging-face-model-evaluation-security-incident/),
> confirmed the initial foothold and added two checks folded in below (§1a).
>
> **Updated** since first landing (#591): §1a added (permitted cache/proxy
> trust boundaries, reference-artifact reachability); [Follow-up
> scope](#follow-up-scope) corrected to reflect that two of the four named
> follow-ups have since shipped (#592, and `llm_analysis.go`'s alert
> wiring) — checked against real repo state before starting phase 1
> (synthetic replay corpus) work, not assumed from this doc's original text.

> **Extended (#3499):** §10–§14 added — authentication events, payload
> handling, model access, sandbox escape, and secrets — as part of #3496's
> acceptance criterion 3. Sections 1–9 and §1a are unchanged; each new
> section extends the area it touches (§10 → §5, §11 → §2, §12 → §6, §13 →
> §1, §14 → §3 and §5) rather than restating it. Every mitigation cited below
> was re-verified against this tree on 2026-10-04 rather than carried over
> from the sections above, and five new rows are in the [Applicability
> matrix](#applicability-matrix).

## Method

For each of the nine areas #154 asked to cover, this maps to APIARY's
**actual** current architecture — verified against the real compose files,
the source, and docs in this tree, not assumed from what a "typical"
honeypot stack might do. Each entry records: what exists today, whether the
published campaign's technique applies here, and the evidence. (The original
pass read Go and Python source; the Go tier was deleted at #1628 on
2026-08-22, so a re-read today should be against the Rust modules named in
the status banner above.)

---

## 1. Evaluation/sandbox escape paths and reachable answer/reference artifacts

**Applies, partially — this repo's closest analogue is the malware
detonation sandbox, not an LLM eval harness.**

- `sandbox/windows/` (win11-sandbox) and the planned `cape-sandbox` (#314-322)
  are the actual "run untrusted code in a controlled environment" surfaces
  here — not an LLM code-eval sandbox, but the same escape-path shape: an
  untrusted binary/script runs inside a guest, and the question is what it
  can reach from there.
- `docs/honeypot-network-isolation.md` (§7/§11, the source #88 draws its own
  scope from) documents the isolation zones this already relies on:
  `virbr-sandbox` with no `<forward>` element (no route out), a Phase 0
  iptables DROP pair, and an `honeypot-sandbox-strict` nwfilter. **Untested
  by anything in this tree** — #88 exists precisely because no automated
  check confirms these invariants still hold after a config change.
- `docker-compose.sandbox.yml`'s INetSim/Zeek/Suricata/tcpdump containers use
  `network_mode: host` (three services, confirmed by grep) — a deliberate
  choice for full-spectrum traffic capture of the isolated sandbox network,
  but it means those specific containers are not themselves network-namespaced
  away from the host the way every honeypot sensor container is. #510 (open)
  already flags that these containers aren't reliably started/stopped per
  detonation, which is adjacent to, not the same as, this finding.
- No "reference/answer artifact" concept exists in this repo's design (unlike
  an LLM eval harness with a scored reference solution) — the nearest
  equivalent is the Ghidra/sandbox/GitHub-analysis result spools
  (`/var/lib/honeypot-ghidra/results`, etc.), which are mounted **read-only**
  into the dashboard (`arcane/home/honeypot-dashboard/compose.yml`, every `*-results` mount)
  specifically so a compromised guest or a malicious sample cannot forge a
  result by writing back into the directory the dashboard reads.

**Verdict:** the sandbox-escape shape applies; the "reachable answer
artifact" shape mostly does not (this repo has no evaluation-harness
component the campaign's original context assumed). The real open gap is
#88 (no automated proof the isolation invariants still hold) and #510 (the
network capture containers' lifecycle isn't tied to detonation lifecycle).

### 1a. Follow-up: permitted cache/registry proxies as a trust boundary

Per the corroborating primary source
([openai.com's incident writeup](https://openai.com/index/hugging-face-model-evaluation-security-incident/),
added to issue #154 after this doc's first pass): the campaign's own initial
foothold was a zero-day in a *package-registry cache proxy* — a component
everyone assumes is a passive mirror, not a trust boundary in its own right.
Two explicit checks that source asked to add here:

- **Do any package/module cache proxies exist in this repo's own build
  path, and if so, could a compromise of one become general egress?**
  Checked directly: no self-hosted package/module registry cache or proxy
  exists anywhere in this tree (grepped every Dockerfile and CI workflow for
  `GOPROXY`, a pip/npm registry-mirror config, an apt-cache-ng-style proxy,
  etc. — none found). Every build (`go build`, `npm install`, `pip install`)
  talks directly to the public upstream registry from GitHub Actions' own
  runner, not through an intermediary this repo operates. **Does not apply
  — by absence, not by a control**, the same "doesn't exist here" shape as
  item 4's cloud-metadata-service finding below. Worth stating explicitly so
  a future self-hosted proxy/mirror (e.g. for the self-hosted CI runner
  option `quality.yml` added) gets threat-modeled *as* a trust boundary from
  day one rather than assumed-safe by default.
- **Are evaluation answers/reference artifacts unreachable from the
  evaluated agent even after a sandbox or proxy compromise** (not just
  "not forgeable," which §1's own read-only-mount finding above already
  covers)? This is the sharper, distinct question: could a compromised
  sandbox guest, *during* its own detonation, read back any prior
  analysis result data that would let it detect it's being evaluated and
  adapt? Checked directly against `docs/kvm-network-traffic-analysis.md`
  and `docker-compose.sandbox.yml`: the Ghidra/sandbox/GitHub-analysis
  result spools are host-side directories, written by the analysis pipeline
  **after** a detonation completes and the guest is torn down — nothing
  mounts them into the guest's own filesystem, and the guest's isolated
  network (§1 above: no `<forward>` element, INetSim answers every
  connection attempt itself) has no route to reach the host paths even if
  it tried. A compromised guest cannot read the results of its own or any
  prior run. **Applies as a check, and the existing isolation design already
  satisfies it** — this is a confirmation, not a newly found gap.

---

## 2. Untrusted structured-data processing

**Applies directly — this is the shape of a large fraction of this repo's
own code.**

- YARA rule/corpus loading (`scripts/check-yara-corpus.sh`, now `arcane/home/honeypot-payload-analysis/analysis/yara/` since #1502)
  processes rule files against untrusted sample bytes. CI (`quality.yml`)
  already runs the corpus through the scanner's own base image on every
  change specifically because a bad rule takes the whole scanner down
  (confirmed: "yara(1) refuses to start on a corpus with one bad rule rather
  than skipping it").
- Every sensor's JSON log line is untrusted, attacker-controlled structured
  data by construction — then `dashboard/classify.go` parsed it, in the
  Rust cutover the sensor-ingest path in `backend-service` does. Escaping
  discipline here is already established: dashboard pages render event
  fields through `html/template` (auto-escaped), and `llm_analysis.go`
  (#150, just landed) explicitly re-derives this same reasoning for model
  output specifically because it is a second layer of untrusted free text on
  top of the underlying event.
- Archive/container-format processing: `arcane/home/honeypot-dashboard/analysis/es-results-importer/` and
  the Ghidra/sandbox result pipelines parse producer-written JSON, not
  archives directly — no code in this tree currently unpacks
  attacker-supplied ZIP/TAR/container images. This is a **currently-absent
  capability**, not a mitigated one; if a future sensor or the payload
  workbench ever adds archive extraction, that code needs its own bounds
  (size, depth, symlink/path-traversal) from day one — matching the pattern
  #154's own "Decoder is non-executing, bounded... records provenance"
  acceptance criterion already anticipates for phase 2.
- Template evaluation: no server-side template engine renders
  attacker-controlled strings anywhere in this tree (grepped for
  `text/template`/`html/template` `.Parse(` call sites — every one parses a
  fixed, repo-authored template string, never event data).

**Verdict:** applies broadly; the dashboard's existing escaping discipline
and #150's precedent are the right foundation for phase 2's decoder work.
Archive/container parsing is a gap only in the sense that nothing does it
yet — worth stating explicitly so it isn't added later without the same
bounding discipline.

---

## 3. Environment and `/proc/*/environ` secret exposure

**Not mitigated. Every secret-shaped env var in this tree is plain-env.**

- There is currently **no live `<NAME>_FILE` secret indirection anywhere in
  this tree.** A `<NAME>_FILE` convention was described once, for
  `AUTH_INTROSPECTION_TOKEN`, by `dashboard/authorization.go`'s
  `secretFromEnvironment()` — but that file is gone (the Go dashboard was
  retired), and `AUTH_INTROSPECTION_TOKEN` survives only as a comment in
  `docs/KEYCLOAK-CUTOVER.md:125`. Nothing implements that convention now.
- The nearest **live** precedent for file-path-delivered configuration is
  `arcane/home/honeypot-dashboard/backend-service/src/threat_intel.rs:135` —
  `std::env::var("THREAT_CIDRS_FILE")`, which reads a path from the
  environment and loads its contents from disk. It is the same shape a
  `<NAME>_FILE` secret indirection would take, but it delivers **CIDR
  threat-intel data, not a secret**, so nothing in the tree currently
  reduces a secret's `/proc/*/environ` exposure.
- Every other secret-shaped environment variable in this tree
  (`ARKIME_ADMIN_PASSWORD`, `ARKIME_PASSWORD_SECRET`, `GH_PAT` per
  `analysis/github/github.env.example`, VPS SSH keys in `deploy.yml`'s
  `secrets.VPS_SSH_KEY`) is delivered as a **plain environment variable**,
  not file-based — readable via `/proc/<pid>/environ` by anything with
  ptrace/procfs access to that container's PID namespace, and visible in
  `docker inspect`.
- GitHub Actions secrets (`deploy.yml`, `containers.yml`) are the CI-side
  equivalent: `VPS_SSH_KEY`/`VPS_HOST`/`VPS_USER`/`VPS_PORT` are consumed as
  `env:` on specific steps, GitHub's own masking prevents them appearing in
  logs, but they still exist as process environment for the step's lifetime.

**Verdict:** no `<NAME>_FILE` secret indirection is live anywhere in this
tree, so every secret-shaped env var here is plain-env. *Introducing* that
convention (modelled on `threat_intel.rs`'s `THREAT_CIDRS_FILE` path-from-env
pattern) for the other secret-shaped env vars — or at minimum documenting
which ones are plain-env by conscious choice vs. oversight — is a concrete,
scoped follow-up — see [Follow-up scope](#follow-up-scope).

---

## 4. Metadata-service and RFC 1918/link-local reachability from workloads

**Not directly applicable — this repo has no cloud metadata service in its
threat surface, but the analogous "can a compromised sensor reach
internal-only services" question is real and already has partial answers.**

- No cloud provider metadata endpoint (`169.254.169.254`, GCP/Azure
  metadata) appears anywhere in this tree's runtime code (only mentioned in
  `docs/ip-reporting-plan.md`, in an unrelated context about IP geolocation
  services). The homeserver is bare-metal/self-hosted, not cloud VM-backed —
  the metadata-service SSRF vector the original campaign used does not exist
  here by construction, not by a control.
- The RFC 1918/internal-reachability analogue that *does* apply: every
  honeypot sensor container's own private Docker network (documented
  extensively across `docker-compose.*.yml` headers — e.g. dionaea's
  `dionaea_net`, tanner's `tanner_local`) is deliberately **not** `honeynet`,
  specifically so a compromised sensor cannot pivot to Elasticsearch,
  Kibana, or any other stack service. `docs/honeypot-network-isolation.md`
  is the authoritative source for this design.
- The one exception, by explicit design: services that need cross-stack
  reach (dashboard, es-results-importer) join `honeynet` and resolve
  Elasticsearch by service-name DNS — a deliberate, narrow allowlist, not an
  oversight (see `arcane/home/honeypot-dashboard/compose.yml`'s own header comment on
  this).
- No egress-filtering control currently prevents a compromised sensor
  container from reaching the *public* internet, only from reaching other
  stack services — #538 ("docs: make outbound network policy explicit") is
  the tracked issue for defining that policy, and it remains open.

**Verdict:** the metadata-service vector itself doesn't apply (no cloud
metadata surface exists). The internal-reachability principle it represents
is already substantially addressed by per-sensor private networks; the real
gap is outbound-to-internet egress policy, tracked separately in #538.

---

## 5. Credential lifetime, workload identity, and least-privilege boundaries

**Substantially addressed for the dashboard; inconsistent elsewhere.**

- The dashboard's own Docker-socket boundary is the strongest example in
  this tree: the dashboard containers themselves never mount
  `/var/run/docker.sock` (`arcane/home/honeypot-dashboard/compose.yml`, grepped
  directly — its one socket mount belongs to `services-adapter`, below). All
  Docker-lifecycle actions (start/stop/restart) go through
  `hp-services-adapter`, a separate container that is `cap_drop: [ALL]`,
  `read_only: true`, `network_mode: none`, and reachable only via an
  AF_UNIX socket the dashboard also holds — no TCP path exists to abuse it
  remotely even if the dashboard container itself were compromised.
- `hp-autoheal` was the one other service that bind-mounted the real
  `/var/run/docker.sock` (`arcane/home/honeypot-utilities/compose.yml`) — it
  watches containers by label daemon-wide and restarts unhealthy ones. **That
  grant has since been narrowed by #592** (the strikethrough item in
  [Follow-up scope](#follow-up-scope)): it now talks to `hp-docker-socket-proxy`
  at `tcp://docker-socket-proxy:2375` with no socket bind mount of its own, and
  the proxy holds the socket `:ro` scoped to `CONTAINERS=1`, `IMAGES=1`,
  `POST=1` on a private network. What remains is that `CONTAINERS=1` is still
  daemon-wide rather than label-filtered — the label scoping is
  `AUTOHEAL_CONTAINER_LABEL` inside autoheal, not an API-side restriction.
- `tanner_docker` (`arcane/home/honeypot-tanner/compose.yml`) is `privileged: true` with
  its own `tmpfs /var/lib/docker` — explicitly isolated Docker-in-Docker on
  the private `tanner_local` network, not a bind mount of the host socket.
  This is a deliberate, already-documented exception (#88's own scope note
  says the future isolation audit "should assert it stays that shape rather
  than flag it").
- Credential *lifetime*: `AUTH_INTROSPECTION_TOKEN` is checked live on every
  privileged dashboard request (no long-lived session token cached
  server-side beyond the introspection call itself) — the closest thing this
  repo has to short-lived workload identity today.

**Verdict:** the dashboard/services-adapter split is a good existing
least-privilege pattern worth citing as the template for any new
privileged-access surface. It is also now the template autoheal was moved onto:
its raw socket grant is gone, replaced by the same narrow-proxy shape, leaving
only the daemon-wide `CONTAINERS=1` scope.

---

## 6. Encoded/chunked C2 over ordinary web services, dead drops, raw sockets

**Applies to the honeypot's own captured traffic, not to this stack's own
services (which have no legitimate reason to originate arbitrary outbound
traffic in the first place).**

- Sensors like `http-honeypot`/`tanner` are the intended **capture** surface
  for exactly this technique — an attacker probing a honeypot is expected to
  attempt encoded C2/dead-drop patterns, and that's signal, not an incident.
  then `dashboard/classify.go`'s handling of tanner's `post_data`/cookies (#578,
  landed) and Suricata's `payload_printable`/`http_body_printable` (#581,
  landed) are the current mechanisms for surfacing that content to an
  operator — neither currently *decodes* base64/gzip/chunked payloads
  automatically; an operator sees the raw captured bytes/text and would
  decode by hand today.
- The concern this campaign raises that *does* apply here: could a
  compromised **stack component** (not a honeypot sensor, which is
  supposed to be attacker-reachable) use encoded C2 over an ordinary
  outbound HTTP call to blend in? `github_analysis.go`'s
  `githubAnalysisPDFClient` (a 15s-timeout HTTP client fetching a specific,
  validated `raw.githubusercontent.com` URL) and the llm-worker's Ollama
  HTTP client are the only outbound HTTP call sites found in this tree
  outside the honeypot sensors themselves and CI. Both talk to a single,
  narrow, code-fixed destination — no general-purpose outbound HTTP client
  exists in any privileged dashboard/worker path today.
- No egress-filtering (network policy, allowlist) currently *enforces* that
  narrowness at the network layer — it is enforced only by the code not
  containing a general HTTP client. A future code change could add one
  without any control catching it. This is the same gap #538 already tracks.

**Verdict:** the honeypot's own sensors are the intended detection surface
for this exact technique (already partially wired, not decoded yet — phase 2
scope). The "could our own trusted code smuggle C2" question has no current
evidence of a problem, but also no network-layer control backing that up —
folds into #538.

---

## 7. Repeated recon, alternate egress, self-migration, machine-speed low-signal activity

**This is precisely the gap #154 opens with — "isolated low-signal events
were detected but not escalated with the right criticality" — and it
matches a real, already-partially-built mechanism in this repo.**

- `ml-worker`'s three unsupervised models (Isolation Forest, LSTM-AE, HBOS,
  delivered to the dashboard via what was then `dashboard/ml_anomalies.go`
  (#64) are
  exactly the "statistical outlier across many low-signal events" detector
  this campaign's own postmortem says was missing at Hugging Face — but
  `ml_anomalies.go`'s own doc comment is explicit that its output is
  "statistical outliers, not confirmed attacks," scored per-event, not
  correlated into a *campaign*.
- `dashboard`'s existing campaign correlation
  (`campaignRow`/`clustersData`, cited throughout `store.go`/`main_test.go`)
  already clusters activity by shared fingerprint/ASN/CIDR across sensors —
  the closest existing analogue to "correlate low-signal events into one
  ordered timeline" phase 2 asks for, but it correlates by *infrastructure*
  identity (shared IP/ASN/fingerprint), not by *behavioral phase sequence*
  (recon → dropper → exfil → persistence) the way the campaign's own
  technical timeline is structured.
- No component in this repo currently escalates severity based on a
  *combination* of otherwise-individually-low-severity events crossing a
  trust boundary (phase 2/3's core ask) — then `dashboard/alerts.go`'s alert
  manager fires on individual conditions crossing their own threshold
  (queue stalls, high-verdict samples, etc.), not on cross-signal
  combinations.

**Verdict:** the infrastructure (ml-worker anomaly scoring + dashboard
campaign clustering + `llm_analysis.go`'s new session-summary delivery,
#150) already provides three of the raw signal sources phase 2's
correlation engine would need to combine. The correlation-into-one-timeline
and combination-based severity escalation themselves do not exist yet —
this is phase 2/3's actual implementation gap, not something already
covered elsewhere.

---

## 8. Source-control/CI write paths and artifact digest/provenance verification

**Applies directly — this repo already has one deliberately narrow write
path from analysis back into source control, worth treating as the
reference implementation.**

- `analysis/github/` (#74) is the one place this repo's own automation
  writes back to a GitHub repository (publishing scanner samples/results).
  `quality.yml`'s own test step exists specifically because "the one
  property this whole feature depends on... `GITHUB_PUBLISH_ENABLED` unset
  must never reach `publish-sample.sh`" — a deterministic, CI-enforced gate
  on the one write-capable path, tested on every change regardless of
  whether `analysis/github/` itself changed.
- `GH_PAT` (the credential that write path uses) lives in
  `/etc/honeypot-github.env` on the host, read only by the root-owned host
  publisher script — the dashboard/worker side never holds it directly
  (per then-`dashboard/github_analysis.go`'s own doc comment, since
  retired with the Go dashboard: "the dashboard never writes one of these
  files, never calls git or the GitHub API, and never holds a `GH_PAT`" —
  the same non-possession property holds for the Rust cutover's
  `github_analysis_submit.rs`, which still only submits to the host
  publisher and never touches `GH_PAT` itself).
- Artifact digest/provenance: container images built by `.github/workflows/containers.yml`
  are not currently pinned by digest anywhere this research found (compose
  files reference services by `build:` context, not a pinned upstream
  digest, for this repo's own images — vendored third-party dependencies
  like `github.com/nsmfoo/dicompot` *are* pinned by module version + go.sum
  hash, a different but related form of provenance pinning already in
  place for vendored code specifically).
- CI credential probing: `dependabot-auto-merge.yml` and `deploy.yml` are
  the workflows holding real secrets (`GITHUB_TOKEN`, `VPS_SSH_KEY`,
  production environment secrets). Both are scoped with `permissions:` at
  the top of the workflow file (least-privilege GitHub Actions token grants)
  — worth an explicit audit that every workflow's `permissions:` block is
  actually minimal, not just present, as a scoped follow-up.

**Verdict:** the `analysis/github/` publish gate is a strong existing
example of exactly the deterministic, CI-tested control phase 3 asks for
("Escalate independently of an LLM when... source-control token minting,
workflow/build-script changes"). Container image digest pinning is the one
concrete gap found here.

---

## 9. Alert correlation and severity escalation across sensors, container, host, and analysis-worker evidence

**Partially built, fragmented across several independent alert sources
rather than one correlated view — matches this campaign's own core
finding.**

- Current alert sources, confirmed independent of each other (each its own
  `*Alerts` function, then in `dashboard/*.go`, all feeding the same
  `s.alerts`/`alertManager` sink but never cross-referencing each other's
  state; the same fragmentation carried into the Rust cutover's per-source
  worker functions): Suricata/sensor event alerts, `ghidraAlerts`, `githubAnalysisAlerts`,
  sandbox queue/verdict alerts, ML anomaly severity, and (as of #150) the
  new `llm-analysis` index's own severity field — which was browse-only via
  `/llm-analysis` until it was wired into the sink as `llm_flagged_alerts` in
  the Rust cutover, the "Done" item in [Follow-up scope](#follow-up-scope)
  below.
- No single "this source_ip/session/sample crossed N independent trust
  boundaries in a Y-minute window" correlation exists — each alert source
  answers its own narrow question. This is exactly the shape the campaign's
  postmortem flags: individually-reasonable-severity signals from
  Elasticsearch/session-analysis/sandbox/container evidence never combine
  into one escalated verdict.
- `dashboard`'s campaign clustering (cited in §7 above) is the nearest
  existing cross-sensor correlation, but clusters by shared infrastructure
  identity for investigation, not by trust-boundary-crossing count for
  alerting.

**Verdict:** this is the clearest concrete gap this research surfaced. Its
smallest piece — wiring `llm-analysis`'s severity into the alert sink — has
since landed (`llm_flagged_alerts` in the Rust `alert-notifier`); what remains
is a genuine cross-source trust-boundary-crossing correlation engine, which is
squarely phase 3's scope, not something to build inside this research pass.

---

## 10. Authentication events: Keycloak tokens through the BFF into the Rust tiers

**Extends §5.** §5 covers workload identity for service-to-service calls;
this section covers the *human* identity tier — the Keycloak-issued token and
the session derived from it, as it moves through
`honeypot-dashboard-backend`'s BFF into the Rust request tier. Entries 10.1–
10.4. Verified 2026-10-04 against the tree, not inferred from
`docs/KEYCLOAK-CUTOVER.md`'s contract text.

- **10.1 — Asset:** the Keycloak ID token and the BFF session it becomes.
  **Attacker:** anyone holding a browser session that has been revoked,
  expired, or forcibly logged out at the IdP while the local session is
  still live. **Path:** login exchanges the authorization code and stores
  `idToken` in the redis session document
  (`arcane/home/honeypot-dashboard/frontend-next/src/lib/oidc.server.ts`,
  `completeLogin`, which returns `idToken: tokens.id_token`);
  `session.server.ts` writes it into the `bff:session:*` record
  alongside `sub`/`username`/`role`. The id token is not validated again on
  any later request — `session.server.ts`'s `getSession` reads the stored
  document and returns it verbatim, and `sessionGate.server.ts`'s
  `resolveFunctionUser` builds the operator identity from that stored
  document alone. **Mitigation:** the session cookie is an opaque
  `__Host-apiary_bff` sid, not the token itself
  (`session.server.ts`'s `SESSION_COOKIE`, `HttpOnly; Secure; SameSite=Lax`),
  so the raw token never reaches browser script or a network hop;
  `SESSION_TTL_SECONDS` is 12 hours and redis `EX` enforces it server-side.
  **Residual risk:** there is no back-channel logout. Nothing polls Keycloak
  for session revocation, and no token-introspection call revalidates the
  stored id token on any request (grepped across the frontend tier: the only
  Keycloak calls are discovery, the code exchange, and
  `buildEndSessionUrl` on logout). A revoked, disabled, or forcibly-logged-out
  operator therefore keeps a fully working dashboard session — including the
  `admin` role derived at login — until the 12-hour `EX` expires or the user
  signs out locally. The realm's own `accessTokenLifespan` of 300s
  (`arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json`) bounds
  the *IDP-side* token, but nothing re-reads it. This is the single largest
  gap in this section.

- **10.2 — Asset:** the shared `SERVICE_TOKEN` that authenticates the
  BFF→Rust hop. **Attacker:** anything that can reach `backend-service` on
  `honeynet` and read that one secret. **Path:** `serviceFetch` sets
  `x-service-token` on every outbound call
  (`arcane/home/honeypot-dashboard/frontend-next/src/lib/backend.server.ts`),
  and `require_service_token` in
  `arcane/home/honeypot-dashboard/backend-service/src/lib.rs` compares it in
  constant time and 401s the whole `/api/v1` router layer.
  **Mitigation:** fail-closed boot gate — `resolve_service_token` refuses to
  start with `[E-SERVICE-TOKEN]` when `SERVICE_TOKEN` is unset and
  `APIARY_ALLOW_UNAUTH_DEV` is not exactly `"1"`
  (`arcane/home/honeypot-dashboard/backend-service/src/lib.rs`,
  `arcane/home/honeypot-dashboard-backend/compose.yml`'s
  `SERVICE_TOKEN=${DASHBOARD_SERVICE_TOKEN:-}`); the same refusal is mirrored
  on the BFF's proxy path (`backend.server.ts`, `SERVICE_TOKEN_GATE_CODE`) and
  on `/metrics`, which is internet-facing through Traefik and would otherwise
  leak request volumes. `scripts/check-api-auth-tier.py` probes the *running*
  service with no token and fails if any operation the OpenAPI contract
  publishes as secured answers 200 instead of 401/403.
  **Residual risk:** the token is a single shared bearer secret, so it is an
  all-or-nothing credential for the entire `/api/v1` surface rather than a
  per-caller identity. It is also carried as a plain environment variable in
  both tiers' compose files, so it is `/proc/<pid>/environ`-readable
  (§3's shape) rather than file-delivered — the `_FILE` indirection used by
  Keycloak/OIDC (§14) is not applied here. Anything else joining
  `honeynet` with the token is fully authorized.

- **10.3 — Asset:** per-operator identity for the Workbench's owner-scoped
  authorization. **Attacker:** a caller holding the shared service token who
  is not the operator they claim to be. **Path:** the BFF forwards
  `x-actor-username`/`x-actor-role` from its own verified session
  (`backend.server.ts`), and `require_actor` in
  `arcane/home/honeypot-dashboard/backend-service/src/workbench_api.rs`
  rejects a missing or blank value. **Mitigation:** identity is taken from
  the header only — the wire-level `owner` field is deliberately *not*
  deserialized anywhere in that module, so no handler can make an
  authorization decision out of request data, and there is no "act as another
  operator" override (the module doc explains that such an override would
  hand the whole decision back to anyone holding the shared token).
  **Residual risk:** the forwarded role claim is not read at all in that
  module, so all Workbench mutations are admin-gated at the BFF and the
  header is trusted purely because only the BFF can present the shared
  token. That is a sound chain today, but it means the header is
  unforgeable *only* to the degree that `SERVICE_TOKEN` is — the same
  single-secret exposure as 10.2, not an independent control.

- **10.4 — Asset:** Keycloak authentication-failure telemetry (the
  `/auth-events` dashboard page). **Attacker:** anyone who can write to the
  Elasticsearch index the worker writes, or who can present the worker's own
  service-account credentials. **Path:** `auth-events-worker` exchanges a
  client-credentials grant for an admin token each poll and writes
  `LOGIN_ERROR` docs to `auth-failure-events`
  (`auth-events-worker/worker.py`). **Mitigation:** the worker's own client
  secret is read from a mounted file, not an env var
  (`KEYCLOAK_CLIENT_SECRET_FILE` → `/run/secrets/client-secret`,
  `auth-events-worker/docker-compose.yml`), and — the substantive control —
  only an explicit six-field allowlist is persisted from Keycloak's
  `details` object (`DETAILS_ALLOWLIST` in `auth-events-worker/worker.py`:
  `auth_method`, `auth_type`, `redirect_uri`, `code_id`, `username`,
  `selected_credential_id`). The module docstring records why the allowlist is
  explicit rather than "store whatever Keycloak sends": a future Keycloak
  release adding a more sensitive detail key would otherwise start leaking
  it silently. `username` *is* persisted by design — it is an attacker-
  supplied string on a login-failure path, and it reaches Elasticsearch as a
  document field. **Residual risk:** that username is attacker-controlled
  text flowing through the same index the dashboard renders; it is safe
  today only because of §11's renderer posture. The worker's admin token is
  held in memory for the cycle's duration with no explicit expiry handling
  in-tree.

---

## 11. Payload handling: captured bytes to YARA, detonation, and the renderer

**Extends §2.** §2 covers untrusted structured-data processing generally;
this section follows one specific object — a captured payload — through the
three surfaces named in the request (YARA, the sandbox detonation path, and a
rendered dashboard cell) and settles the question §2 left open: what
currently enforces the escaping.

- **11.1 — Asset:** the dashboard renderer's escaping of attacker-controlled
  payload strings. **Attacker:** an attacker who can get a string into a
  captured payload, session field, or model output that a dashboard page
  renders. **Path:** payload bytes reach the frontend as JSON from the Rust
  tier and are rendered by React components —
  `arcane/home/honeypot-dashboard/frontend-next/src/routes/payload-analysis.$hash.tsx`
  and `payload-workbench.results.tsx` (the workbench result preview renders
  the whole row as `<pre>{JSON.stringify(row, null, 2)}</pre>`), and the
  model-derived text in `ghidra.$sha.tsx` and `llm-analysis.tsx`.
  **Mitigation — and this is the direct answer to the question §2 left
  open:** the escaping is **structural, not conventional, but the
  *audit* of it is conventional.** React escapes every interpolated child
  node; there is no `marked`/`DOMPurify`/`react-markdown` in this tier's
  `package.json` and no markdown-to-HTML path at all — `ghidra.$sha.tsx`
  deliberately renders the Rev·Deck answer as literal text with a comment
  recording that the retired `ghidra.html` used `marked.js`+`DOMPurify` and
  this port dropped it. The "AI-generated" label the request asks about is a
  real, present, per-row structural badge in `llm-analysis.tsx`, not prose in
  a subtitle. Behind the escaping there is a second, enforced control: a
  per-request CSP nonce pinning `script-src 'self' 'nonce-…'` plus
  `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'self'`
  (`arcane/home/honeypot-dashboard/frontend-next/src/lib/cspNonce.server.ts`).
  **Finding, stated plainly:** the check that pins the raw-HTML sink is
  *narrower than the codebase*. `csp.test.ts` asserts
  `dangerouslySetInnerHTML` appears only in an audited allowlist — but it
  scans exactly three files (`src/components/Sidebar.tsx`,
  `src/routes/__root.tsx`, `src/components/AppShell.tsx`). Grepping the whole
  `src/` tree today finds the sink in only `Sidebar.tsx` (an icon `path`
  attribute), so the audit's answer is currently correct — but a
  `dangerouslySetInnerHTML` added to any *other* component or route would not
  be caught by that test, because the test enumerates files rather than
  scanning the tree. That is convention enforced against a fixed list, not
  convention enforced by construction. **Residual risk:** the single-raw-HTML
  sink and the three-file allowlist should become a tree-wide scan; until
  then, the CSP nonce is the backstop that would stop a missed sink from
  executing injected script (it would not stop an HTML-injection that
  rewrites visible content).

- **11.2 — Asset:** the YARA scanner's handling of rule files and sample
  bytes. **Attacker:** an attacker who can influence either side — the rule
  set or the corpus. **Path:** rules are loaded from
  `arcane/home/honeypot-payload-analysis/analysis/yara/`; CI runs the whole
  corpus through the scanner's own image on every change
  (`scripts/check-yara-corpus.sh`, wired in `.github/workflows/quality.yml`).
  **Mitigation:** that CI gate is the control, and it exists because a single
  malformed rule prevents `yara(1)` from starting rather than being skipped
  — the repo's own recorded failure mode. **Residual risk:** the gate proves
  the corpus *parses*; it says nothing about a rule that parses and matches
  destructively, and rule provenance (who may add to that directory) is not
  constrained by anything in-tree. §2's boundary discipline for a future
  archive/container parser is unchanged and still applies.

- **11.3 — Asset:** the detonation submission path — the point where
  attacker-controlled bytes are handed to the sandbox. **Attacker:** anyone
  who can cause a payload to be submitted. **Path:** the payload is picked
  up by the inventory worker from the read-only capture mounts
  (`arcane/home/honeypot-dashboard-backend/compose.yml`'s
  `PAYLOAD_DIRS=/dionaea-lib/binaries,/cowrie-downloads`, both mounted `:ro`)
  and detonation is driven by
  `sandbox/windows/orchestrate/run_sample.py`, which destroys and re-clones
  the domain rather than using snapshot-revert (its own module comments
  record why snapshot-revert is unusable on this path). **Mitigation:** the
  capture mounts are read-only into the serving tier, and the detonation
  guest is a per-sample throwaway clone, not the golden image. **Residual
  risk:** the orchestrator is the trust boundary and nothing verifies its
  input beyond path handling; §13 covers what containment actually holds
  behind it.

- **11.4 — Asset:** model-generated text rendered as if it were an analyst
  finding — a second untrusted-text layer on top of the payload (§2's
  explicit second-layer case). **Attacker:** anyone who can influence a
  captured sample's *strings*, since those reach the model verbatim (§12).
  **Path:** `llm-analysis.tsx` and `ghidra.$sha.tsx` render model summaries,
  intents, and behaviors. **Mitigation:** React escaping (11.1), the
  per-row `AI-generated` badge, the "severity (AI-guessed)" column header,
  and the page-level note that every row is attacker-influenced text. **The
  labeling requirement is enforced by the UI's structure, and the escaping by
  React; neither is a separate CI gate on this specific page.** **Residual
  risk:** the labels are the *only* thing separating model output from
  analyst output for a reader — an export or a screenshot loses the badge
  context. Nothing in-tree measures how often operators act on these without
  verification.

---

## 12. Model access: the shared Ollama instance and the broker guard

**Applies directly, and this is the largest genuine gap in this document —
not because there is no control, but because the controls are a *network*
control plus a *log* control, and neither one constrains what the model is
asked to do.** §6 names the shared model only in passing as an outbound HTTP
destination; this section covers who reaches it, what stands in front of the
attacker-reachable consumer, and what a crafted conversation can and cannot
do. Entries 12.1–12.5.

- **12.1 — Asset:** the shared Ollama inference server and the model weights
  behind it. **Attacker:** anything on `honeypot-llm` — including a
  compromised container on it. **Path:** Ollama is published
  `127.0.0.1:11434` on the host and joined to exactly one network,
  `llm_clients` / `honeypot-llm`, declared `internal: true`
  (`analysis/ghidra/docker-compose.ghidra.yml`). **Mitigation:** three
  independent facts, all verified in the compose file rather than assumed.
  First, `internal: true` on that network means no route out — nothing on it
  can reach the internet. Second, the host port bind is loopback-only, with
  the file's own comment stating the reason: "the prompts carry strings,
  imports and function names lifted straight out of captured samples; this
  port must not be a way to read them from elsewhere on the LAN." Third,
  and the load-bearing one, **Ollama does not join `honeynet`**, so no
  sensor container — the only attacker-reachable containers in this stack —
  can resolve or reach it at all; the file states this as an invariant
  ("sensors must never be able to submit prompts or observe model traffic").
  Membership is a short, enumerable list: the Ghidra analysis stack,
  `hp-galah-llm-broker` (`arcane/home/honeypot-galah/compose.yml`),
  `llm-worker` under its captured-data overlay
  (`llm-worker/docker-compose.captured-data.yml`), `vault-worker`, and
  `backend-service` (for `/api/v1/llm-search`'s embedding call only —
  `arcane/home/honeypot-dashboard-backend/compose.yml`). `backend-service`
  additionally re-validates its own `OLLAMA_URL` at runtime, accepting only
  plain `http`, no credentials, no query, empty path, and a host that is the
  literal `ollama`/`localhost` or a loopback/private/link-local address
  (`arcane/home/honeypot-dashboard/backend-service/src/llm_search.rs`,
  `ollama_url()`), so a misconfigured URL cannot turn the embedding call
  into a general-purpose outbound request. **Residual risk:** this is a
  *network-membership* control, not an authentication control. There is no
  credential on the Ollama API itself; any container that joins `honeypot-llm`
  gets full inference, and adding a container to that network is a
  one-line change with no gate that asks whether it should be there. That is
  the same "enforced only by the code not containing a general client" shape
  §6 already flags for egress, one hop closer to the asset. The 20 GiB-class
  GPU slot is also shared, so a single abusive consumer is a denial-of-service
  against the other three legitimate consumers.

- **12.2 — Asset:** the model itself, used as an oracle by an attacker who
  controls the prompt. **Attacker:** anyone who can send text to the
  attacker-facing LLM-powered honeypot — `hp-galah`, reachable on
  `tcp:8888`. **Path:** galah's own `llm.CreateMessageContent` formats the
  attacker's raw HTTP request into the user message verbatim via
  `fmt.Sprintf(cfg.UserPrompt, strings.TrimSpace(httputil.DumpRequest(r, true)))`
  — no sanitising step between attacker and model, as both the broker's and
  `injection.go`'s own module comments state in full. **Mitigation:** the
  broker caps the body at 65 536 bytes
  (`MAX_BODY_BYTES`, `arcane/home/honeypot-galah/compose.yml`), bounds the
  upstream call with an 8→90s timeout (raised from 8s after a measured cold
  load, #1513), and forwards the body byte-for-byte unmodified. The prompt
  injection is **detected and logged, not blocked** —
  `arcane/home/honeypot-galah/galah-llm-broker/injection.go` runs five
  precedence-ordered shapes over the attacker-controlled fields only, gated
  structurally on `role == "user"` (the decoy's own system prompt is out of
  scope by construction rather than by pattern luck), and `main.go`'s handler
  states the property outright: "body is forwarded as the exact bytes galah
  sent, and neither the status nor the body this handler relays is influenced
  by what the classifier found." **This is a deliberate, documented design
  choice, not an oversight** — `logPromptInjection`'s comment says
  signalling an attacker that a detector exists is worse than the detection.
  **Residual risk — the honest answer to "can a crafted conversation drive the
  model as an oracle or a jailbreak":** **yes, and by design, and nothing in
  this tree prevents it.** The attacker reads the model's answer. The
  contained part is the *asset*, not the *behaviour*: the model is a local
  14B-class chat model with no tool access on this path, reachable only
  through the broker, whose only authority is the loopback-bound, non-`honeynet`
  Ollama. So the blast radius of a successful injection is a confident wrong
  answer inside a honeypot decoy, not data exfiltration. The detection side
  is weaker than the design deserves, for two concrete reasons worth
  recording: the five shapes are regexes, and `injection.go` states outright
  that they are "NOT … a calibration against live traffic, because there is
  none to calibrate against" with "the volume this detector will see on this
  sensor … UNMEASURED"; and the log line carries `prompt_sha256` only, never
  the matched text — a deliberate choice (`galah` persists only
  `body_sha256`, so the text is otherwise unrecoverable) that means a
  post-hoc analyst cannot read *what* was attempted, only that a matching
  shape fired. `volume=unmeasured` is in the line on purpose so nothing
  downstream reads a hit as a calibrated rate.

- **12.3 — Asset:** the non-attacker-facing consumers' prompts. **Attacker:**
  anyone who can get bytes into a captured sample's strings, imports, or
  function names. **Path:** `llm-worker` in captured-data mode reads cowrie
  download directories and dashboard-retained script payloads read-only
  (`llm-worker/docker-compose.captured-data.yml`) and embeds/summarises them.
  **Mitigation:** the safe-by-default split is unusually well made — the base
  `llm-worker/docker-compose.yml` has `ES_HOST: ''` forced empty so
  `compose_route_preflight()` refuses to start, mounts nothing, and joins an
  `internal: true` `synthetic-only` network; captured-data reach is a
  *separate* overlay file that the deployment entrypoint includes
  (`llm-worker/docker-compose.captured-data-deploy.yml`, which exists precisely
  because that authorization once lived only as a hand-applied overlay and an
  Arcane redeploy silently reverted it, #1751). Text-only scanning is
  enforced in the worker, nothing from those mounts is executed, the mounts
  are `:ro`, and every gate defaults to the safe direction
  (`LLM_ALLOW_CAPTURED_DATA: false`, `LLM_DRY_RUN: true`). **Residual risk:**
  this is a *deployment-shape* control with no runtime enforcement that the
  live deployment is actually on the overlay — the same class of gap #1751
  described, now fixed by a file rather than by a check. The worker reads
  captured attacker text into prompts by design; that is the product.

- **12.4 — Asset:** model and runtime provenance — what the shared slot is
  actually serving. **Attacker:** anyone who can alter a model tag, the
  runtime image, or the governance manifest. **Path:** all three slots
  (ghidra, sessions, revdeck) share one model under
  `OLLAMA_MAX_LOADED_MODELS: 1`; `LLM_EXPECTED_MODEL_DIGEST` and
  `LLM_EMBEDDING_EXPECTED_DIGEST` gate the worker's acceptance of what comes
  back. **Mitigation:** this is the most rigorously governed surface in the
  document and deserves saying so — the Ollama image is pinned by digest
  (`ollama/ollama:0.34.4@sha256:8262851b…`), the approved model and its
  artifact digest are recorded in
  `analysis/ghidra/models/approved-models.json` with per-slot approval
  records and report hashes, `model-governance.py check-runtime` compares the
  live container against four runtime fields and reports drift, and the file's
  `bump_policy` states that a version bump is a re-qualification event
  requiring a fresh benchmark run and a promotion, not a tag edit (#2062 —
  the record of a bump that shipped with only one line changed and left ten
  days of hosts running unrecorded against the old version).
  **Residual risk:** governance is by process and file, not by CI gate on
  this path; the enforcement depends on a maintainer following the recorded
  procedure. Also note the reproducibility caveat the compose file records
  for itself (#2646): a resident slot returns different text for an identical
  prompt at temperature 0, so two triage assessments are never directly
  comparable — the worker records which resident instance answered
  (`ai_triage.slot_generation`) for exactly that reason.

- **12.5 — Asset:** resource exhaustion of the shared GPU slot by an
  attacker-reachable consumer. **Attacker:** anyone who can send requests to
  `hp-galah`. **Path:** each request occupies the single
  `OLLAMA_NUM_PARALLEL: 1` slot for up to 90 seconds. **Mitigation:** the
  broker's body cap, timeout, and `cpus: "0.5"` / `memory: 128M` limits
  (`arcane/home/honeypot-galah/compose.yml`), and Ollama's own serialisation
  settings. **Residual risk:** there is no per-source rate limit or
  concurrency control at the broker, and `injection.go` explains why a rate
  gate was deliberately *not* added — but that reasoning is about the
  injection *detector*, not about resource control, and does not transfer.
  One attacker can therefore queue sustained 90-second generations against
  a slot three legitimate consumers depend on. `scripts/honeypot-pause.sh`
  records the operational hazard in the other direction: pausing
  `hp-galah-llm-broker` alone "makes galah's own decoy paths fail in a way
  that looks like a broken decoy rather than a stand-down," and
  `ghidra-ollama-1` is under an explicit hard prohibition while a benchmark
  holds the GPU.

---

## 13. Sandbox escape: the analysis-host → sandbox boundary

**Extends §1.** §1 established that the detonation sandbox is this repo's
closest analogue to an eval harness and that the reachable-answer-artifact
shape does *not* apply. This section answers the narrower question §1 left
open — what containment actually holds at the analysis-host → sandbox
boundary, and what is one misconfiguration away from not holding. Entries
13.1–13.5.

- **13.1 — Asset:** the analysis host itself, from a compromised detonation
  guest. **Attacker:** malware executing inside the guest. **Path:** the
  guest sits on a libvirt bridge (`sandbox/windows/setup/sandbox-network.xml`
  for the Windows detonation route; `sandbox/network.xml` for the Linux
  runner; `sandbox/ghosts/network.xml` for GHOSTS). **Mitigation — and the
  header is unusually explicit that it is the whole point:** "Isolation,
  restated because it is the whole point: the macvlan below is `internal`,
  the libvirt network has no `<forward>`, and Phase 0 adds an iptables DROP
  pair across virbr-sandbox. Three independent barriers. Removing any one of
  them because 'the container needs to pull something' puts live malware on
  the internet" (`docker-compose.sandbox.yml`). The absence of `<forward>`
  is the structural one — the file records that adding `<forward mode='nat'/>`
  would give live malware a route out. **Residual risk:** these are
  configuration properties, and §1's own verdict already records that no
  automated check in this tree confirms they still hold after a config
  change (#88). `scripts/isolation-audit.sh` is the closest thing that exists
  — it asserts the FORWARD-chain invariants and treats an explicit ACCEPT
  referencing the bridge as fatal — but it requires a live host with a
  sudoers grant, reports *unmeasured* rather than passing when it cannot read
  the chain, and does not run in `quality.yml`. Its own verdict line is
  explicit that an unmeasured check "is an unanswered question, not a pass."

- **13.2 — Asset:** the three `network_mode: host` capture containers in
  `docker-compose.sandbox.yml`. **Attacker:** anything that can execute in or
  reach those containers, and — the part worth stating plainly — **the
  containers themselves are not network-namespaced away from the host.**
  `network_mode: host` means Zeek, Suricata, and tcpdump share the host's
  network namespace: they can reach anything the host can reach, and
  anything that can reach the host's interfaces can reach them. **Mitigation:**
  the grant is deliberate and narrow in every other axis — all three carry
  `cap_drop: [ALL]` plus only the capabilities packet capture genuinely
  requires (`NET_ADMIN`, `NET_RAW`, and for Suricata the five its own
  entrypoint's `capng_change_id` requires), all carry
  `no-new-privileges:true`, none is `privileged: true`, and none is joined to
  `honeynet`. INetSim and mitmproxy, the two services on the same bridge that
  do not sniff the device, run with `cap_drop: [ALL]` and no additions —
  the file's own comment states the sniffers' privilege grant "is why only the
  two sniffers get it." The image set is digest-pinned, and
  `scripts/isolation-audit.sh` allow-lists exactly these three container
  names (plus `hp-zeek-proxy`) for `NET_ADMIN`/`NET_RAW` and flags any other
  holder as a fault — a check that fails closed on an unexpected grant.
  **Residual risk:** the host-namespace grant is permanent for the
  container's lifetime while the actual isolation between the *capture
  containers* and the *host's* networks rests on Docker's own daemon
  configuration and the host firewall, not on anything this compose file
  controls. §1 already records the adjacent lifecycle gap: these containers
  are not reliably started and stopped per detonation (#510), so a
  host-networked container with packet-capture capabilities can be up when no
  detonation is running. `docker-compose.sandbox.yml`'s `restart: "no"` is the
  mitigation for the orphan case and it does hold for an exited container —
  what it does not cover is a container left *running* across a crash of the
  orchestrator that would have stopped it.

- **13.3 — Asset:** the GHOSTS detonation host, which is deliberately *not*
  isolated the same way. **Attacker:** malware in the GHOSTS guest, which by
  design has real WAN egress. **Path:** `sandbox/ghosts/network.xml` — the
  one detonation network in this repo that *does* carry a `<forward>`, and
  the file's header is emphatic that this is intentional and must not be
  "fixed": "Do not 'fix' this network by removing the `<forward>` — that
  would break GHOSTS entirely … the containment for this network is the
  iptables policy in network-filter.sh, not the absence of a route out."
  **Mitigation:** the containment that replaces the missing route is
  `sandbox/ghosts/network-filter.sh` — a `GHOSTS-FWD` chain jumped to first
  in `FORWARD` for the bridge that admits only the enrolled client's traffic
  to the GHOSTS API backend and then DROPs every RFC1918 destination, plus
  `198.18.0.0/24` (IANA benchmarking space, which the RFC1918 rules alone
  miss), plus a `GHOSTS-IN` chain on `INPUT` for the bridge that DROPs
  everything — the latter because host-local traffic addressed to the host
  itself never traverses `FORWARD` and would otherwise be reachable. The
  filter is fail-closed on ordering: it DROPs any attempt to reach the API
  backend directly, bypassing the bridge's own gateway address, ahead of the
  `10.0.0.0/8` DROP. The script's `verify` mode asserts its own rule
  ordering, including that the enrolled-client ACCEPT precedes the
  fail-closed backend DROP. **This is stronger than §13.1's posture, not
  weaker — and it is worth saying so, because the request's framing might
  suggest otherwise.** `sandbox/ghosts/verify-network-isolation.sh` goes
  further still: it boots a throwaway guest on the network and proves the
  policy from *inside* the guest, "not just by reading the firewall rules."
  **Residual risk — the one misconfiguration away from not holding:** the
  entire network's containment is a shell script applied by
  `sandbox/ghosts/install-network.sh` and re-applied by hand. There is no
  CI gate in this tree asserting that `network-filter.sh` was run, and
  libvirt's own `net-setup` will happily (re)create the bridge with
  forwarding and no filter at all. The file says so in its own header — "Re-apply
  it after every `net-setup`" — which means the invariant is a documented
  human procedure, not an enforced property. That is the single highest-value
  finding in this section: unlike the Windows route's three barriers, this
  one is one `install-network.sh` invocation away from not holding.

- **13.4 — Asset:** the CAPE detonation path. **Attacker:** malware in the
  CAPE guest; anything reaching CAPE's database. **Path:** `sandbox/cape/`
  — MongoDB only, in Docker, deliberately isolated from this repo's own
  stacks; the CAPE application itself runs on the host, "same as
  sandbox/windows's own orchestrator," because it talks to libvirt directly.
  **Mitigation:** `sandbox/cape/network.xml` also has no `<forward>`
  (verified in the file's own header), `cape-mongo` is published
  `127.0.0.1:27017` only, and the compose file's rationale for keeping
  PostgreSQL out is explicit that the default SQLite task DB is sufficient.
  **Residual risk:** as §13.1, the network property is asserted by a file
  comment rather than a check. The compose file also records its own
  provenance gap honestly — the image digest was observed from the registry
  API, "NOT inspected off a live deployment, because no reachable host has
  ever stood this stack up," and Dependabot covers nothing under `/sandbox`,
  so mongo 7.0 patch releases will not arrive automatically.

- **13.5 — Asset:** the analysis result spools — the data a compromised
  guest might want to forge or read. **Attacker:** malware in the guest.
  **Path:** the Ghidra/sandbox/GitHub-analysis result directories, mounted
  into the dashboard. **Mitigation:** read-only mounts (§1's finding, and
  this is the same conclusion reached from the other direction — the guest
  cannot write into the directory the dashboard reads, so it cannot forge a
  result, and per §1a it cannot read a prior run's results either because
  nothing mounts them into the guest and its isolated network has no route to
  the host paths). **Residual risk:** low, and largely already closed by §1
  and §1a. The remaining item is that "the spools are written after the
  guest is torn down" is a property of the orchestrator's sequencing, not of
  any mount-level control.

---

## 14. Secrets: real, decoy, and the mechanism that keeps them apart

**Extends §3 and §5.** §3 covers secret *delivery* (env var vs. `_FILE`) and
§5 covers credential *lifetime*; neither names the decoy-credential surface.
This section draws the line between the two — which paths hold real secrets,
which hold bait, and what mechanically prevents the bait paths from being
treated as leaks or the real paths from being treated as bait. Entries
14.1–14.4. **This is the security property that most requires the explicit
exemption lists to be read as an allowlist and not a backlog**, so it is
stated first.

- **14.1 — Asset:** the decoy-credential surface — the fake files
  attackers are meant to find. **Attacker:** nobody internal; the "attacker"
  here is the CI gate, which must distinguish bait from a leak without being
  told the difference each time. **Path:** `arcane/home/honeypot-cowrie/cowrie/honeyfs/**`
  ships 54 tracked files that are *supposed* to look like a
  credential-bearing filesystem — `etc/shadow` with sha512crypt hashes,
  `etc/passwd`, `home/*/.ssh/authorized_keys`, NTFS policy scripts under
  `mnt/ad/SysVol/`. Cowrie serves these to whoever logs in; that is the
  product. **Mitigation:** `scripts/check-public-leaks.py`'s
  `ALLOWED_DOTENV` set carries exactly one honeyfs entry
  (`arcane/home/honeypot-cowrie/cowrie/honeyfs/opt/nexusai-inference/.env`),
  with a comment stating why it is there — it "is still a decoy honeyfs file
  for attackers to find, not a real credential." Everything else in that tree
  is caught by the generic rules without exemption, because the gate's
  literal-credential-assignment pattern exempts `DECOY_ONLY` as a value
  alongside `change-me` variants. Separately,
  `scripts/check-cowrie-honeyfs-realism.py` guards the *quality* of the bait
  in the opposite direction — it fails if a tracked SSH key does not parse,
  if a `$6$` shadow hash is not exactly 86 characters, if a passwd primary
  GID has no matching group entry, if an account has no shadow row, or if
  `userdb.txt` is not pure ASCII (cowrie reads it with `encoding="ascii"`,
  where one non-ASCII byte fails every login attempt). **Residual risk:** the
  exemption surface is a hardcoded path list, so it fails closed on rename
  (a moved file resurfaces the failure on the next run) but grows by hand —
  each new decoy file needing an exemption is a review decision someone has
  to notice. Note also that this repository has **no credential scanner over
  git history**; `check-public-leaks.py` is a repo-policy checker with an
  explicit allowlist and scans the working tree, not history, so a secret
  committed and later removed is outside its reach. That is #3496's own
  separate CI-gates item, recorded here because this section is where the
  allowlist shape it should reuse already lives.

- **14.2 — Asset:** real deployment secrets. **Attacker:** anything with
  procfs or `docker inspect` access to the container holding them, or anyone
  who commits one. **Path:** file-delivered where the pattern is applied —
  `OIDC_CLIENT_SECRET_FILE=/run/dashboard-secrets/oidc-client-secret` plus a
  `:ro` mount of a host directory (`arcane/home/honeypot-dashboard/compose.yml`);
  `POSTGRES_PASSWORD_FILE` and a `KC_DB_PASSWORD` export read from a mounted
  file rather than an env var (`arcane/home/honeypot-keycloak/compose.yml`);
  `KEYCLOAK_CLIENT_SECRET_FILE` → `/run/secrets/client-secret`
  (`auth-events-worker/docker-compose.yml`), where the compose comment records
  why the secrets directory is a *sibling* of the stack directory rather than
  nested inside it: anything written "into" that path would land inside the
  git checkout itself, "exactly where a secret must never live." Plain-env
  where it is not: `SERVICE_TOKEN` (§10.2), `ARKIME_PASSWORD_SECRET`, `GH_PAT`
  (§3). **Mitigation:** the file-delivered-secret pattern (§14 lists the
  three live uses) does not cover these three. `.env` files are refused
  outright by the gate: any tracked file named `.env` that is not in
  `ALLOWED_DOTENV` fails, and the pattern list separately flags private keys,
  GitHub/AWS/Slack token shapes, literal credential assignments, and
  credentials embedded in URLs. **Residual risk:** §3's finding is unchanged
  for the remaining plain-env cases, and it applies with full force to
  `SERVICE_TOKEN` specifically — the one credential an attacker would most
  want, delivered as plain env in both the BFF and Rust tiers. File-delivery
  narrows `docker inspect` and `docker inspect`-adjacent exposure; it does not
  narrow `/proc/<pid>/environ`, since the value is exported into the process
  either way — the same conclusion §3's follow-up already reached for
  `ARKIME_PASSWORD_SECRET`.

- **14.3 — Asset:** the deployed secrets directories themselves. **Attacker:**
  anything that can read the host path backing a `/run/*-secrets` bind
  mount. **Path:** `/var/dockge/stacks/honeypot-dashboard/secrets`,
  `/var/dockge/stacks/honeypot-keycloak/secrets`,
  `/var/dockge/stacks/auth-events-worker-secrets` — host directories outside
  the git checkout, mounted `:ro` into their containers. **Mitigation:**
  outside the checkout (so `git pull` cannot clobber them and `git status`
  cannot surface them), read-only into the container, and — for Keycloak —
  the compose file's own record that a *relative* path silently resolved to
  an empty auto-created directory on a fresh install, which is the exact
  failure mode that would leave a mount present and empty. **Residual risk:**
  host-side permissions are outside anything this repository can assert;
  nothing in-tree checks that these directories are not world-readable, and
  the `check-public-leaks.py` gate covers committed files only, not host
  filesystem state.

- **14.4 — Asset:** attacker-supplied strings that resemble credentials and
  get persisted. **Attacker:** anyone submitting a login to a honeypot or
  uploading a payload. **Path:** `auth-events-worker` stores `username` from
  Keycloak's `LOGIN_ERROR` details into Elasticsearch (§10.4); cowrie stores
  attacker credentials in its own logs and honeyfs. **Mitigation:** the
  worker's six-field explicit allowlist (§10.4) is the boundary — an
  attacker-supplied `username` is stored by design, and everything else in
  the event is dropped. **Residual risk:** these strings are attacker-
  controlled free text flowing into a store the dashboard renders, so they
  inherit §11's renderer posture; a credential an attacker submitted to a
  decoy SSH or HTTP sensor can end up verbatim in the operator's dashboard,
  which is correct behaviour for a honeypot and exactly the content an
  escaping regression would turn into script execution.

---

## Applicability matrix

| # | Area | Applies to this repo? | Existing mitigation | Concrete gap found |
|---|---|---|---|---|
| 1 | Sandbox escape / reference artifacts | Partial (detonation sandbox, not eval harness) | Read-only result mounts; isolation zone design (docs) | #88 (untested invariants), #510 (capture container lifecycle) |
| 2 | Untrusted structured-data processing | Yes, broadly | `html/template` auto-escaping; CI YARA corpus gate | No archive/container-format parsing exists yet — must inherit this discipline when added |
| 3 | Env/`/proc/*/environ` secret exposure | Yes | No live `<NAME>_FILE` secret indirection exists anywhere in the tree; the nearest precedent is `backend-service/src/threat_intel.rs`'s `THREAT_CIDRS_FILE` file-path delivery (CIDR data, not a secret) | Every secret-shaped env var is plain-env: `ARKIME_*`, `GH_PAT`, VPS SSH key |
| 4 | Metadata-service / RFC 1918 reachability | No cloud metadata surface exists | Per-sensor private Docker networks | Outbound-to-internet egress policy (tracked in #538) |
| 5 | Credential lifetime / workload identity | Yes | dashboard/services-adapter split (strong pattern, since carried into the backend-service/worker split); autoheal moved onto the same narrow-proxy shape by #592 | Proxy's `CONTAINERS=1` is still daemon-wide, not label-filtered |
| 6 | Encoded/chunked C2 | Yes, as honeypot capture surface | Raw payload capture (tanner/Suricata); narrow fixed-destination outbound HTTP clients | No network-layer egress enforcement (folds into #538) |
| 7 | Repeated recon / low-signal escalation | Yes — core motivating gap | ml-worker anomaly scoring; dashboard campaign clustering | No behavioral-phase correlation or combination-based severity escalation |
| 8 | Source-control/CI write paths | Yes | `analysis/github/` publish gate (CI-tested); vendored-dep hash pinning | No image digest pinning for this repo's own built images |
| 9 | Cross-source alert correlation | Yes — core motivating gap | Multiple independent alert sources feed one sink, `llm-analysis` severity included | No trust-boundary-crossing correlation engine |
| 10 | Authentication events | Yes | Fail-closed `SERVICE_TOKEN` boot gate + `scripts/check-api-auth-tier.py`; header-only per-operator identity | No back-channel logout or token revalidation — revoked sessions live up to 12h |
| 11 | Payload handling | Yes | React structural escaping; per-request CSP nonce; CI YARA corpus gate | Raw-HTML sink audit enumerates 3 files instead of scanning the tree |
| 12 | Model access | Yes — largest genuine gap | Ollama off `honeynet`, loopback-only, `internal: true` network; broker path allowlist + body cap; injection detection (log-only) | A crafted conversation *can* drive the model as an oracle — by design; no rate limit on the shared GPU slot |
| 13 | Sandbox escape | Yes | Three independent barriers on the Windows route; fail-closed iptables policy + in-guest verification on GHOSTS | GHOSTS's `network-filter.sh` is a documented manual procedure, not an enforced property |
| 14 | Secrets (real vs. decoy) | Yes | `check-public-leaks.py` `ALLOWED_DOTENV` + `check-cowrie-honeyfs-realism.py`; file-delivered secrets outside the checkout | No credential scanner over git history; `SERVICE_TOKEN` still plain-env |

---

## Follow-up scope

Per #154's own acceptance criteria ("Isolation/egress/credential audits are
implemented or linked to scoped follow-up issues"), the concrete gaps above
route to:

- **#88** (existing, open) — automated isolation-invariant checks. Item 1's
  gap is already this issue's scope; no new issue needed.
- **#538** (existing, open) — outbound network egress policy. Items 4 and 6's
  gaps are already this issue's scope; no new issue needed.
- **New, scoped follow-ups named here** (not all filed as separate issues at
  once — this research doc's job was to identify them, not to fan out five
  new issues in one round). Status as of this update, not when first
  written:
  - ~~Audit/narrow `hp-autoheal`'s standing `docker.sock` grant (item 5).~~
    **Done** — #592, merged: replaced the raw bind mount with
    docker-socket-proxy scoped to `CONTAINERS`+`IMAGES`+`POST` only,
    verified end-to-end against a real unhealthy container.
  - ~~Wire `llm-analysis` severity into the existing dashboard alert sink
    (item 9's smallest, most immediate piece).~~ **Done** —
    then-`dashboard/llm_analysis.go`'s `llmAnalysisAlerts`, retired with the
    Go dashboard; the equivalent alert-refresh wiring lives in the Rust
    cutover's worker loop today.
  - ~~Introduce a `<NAME>_FILE` secret indirection (the convention #154
    asks for, modelled on `threat_intel.rs`'s `THREAT_CIDRS_FILE`
    path-from-env pattern) for the plain-env secrets (item 3).~~
    **Assessed, closed as acceptable
    residual risk — no code change.** `ARKIME_PASSWORD_SECRET` (the one
    genuinely reachable case; see below) is consumed directly by Arkime's
    own third-party `docker.sh` entrypoint via its `ARKIME__*`
    env-var-to-config.ini convention, and `arkime/config.ini`'s own
    checked-in comment already explains why it isn't set there directly:
    "Ini files do not expand ${...} — keep secrets in .env, not here." A
    real fix (a wrapper entrypoint reading `ARKIME_PASSWORD_SECRET_FILE`
    and exporting the value just before exec'ing Arkime's real entrypoint)
    was scoped in full, then deliberately not built: it still ends up as a
    process environment variable inside the Arkime container either way —
    Arkime itself has no file-based config option for this value — so the
    `/proc/*/environ` exposure this item is actually about is completely
    unchanged by it. The only real gain would be keeping the value out of
    `docker inspect`/the rendered compose config at rest, a narrower
    benefit than the wrapper's own added complexity justifies given the
    surrounding mitigations already in place: Arkime's real access
    boundary is network isolation (WireGuard-tunnel-only bind, no public
    port) plus the isolated `oidc-arkime` Keycloak gateway (#1021 removed
    the earlier trusted-header approach after the cutover left it
    forgeable) — `passwordSecret` here signs Arkime's own session cookies,
    it is not a login credential,
    and a leak of it alone has a narrow blast radius already contained by
    that isolation. `GH_PAT` (this item's other named case) is a host-side
    `.env` file consumed by a root-owned host script, not a
    container-namespace env var at all — the `/proc/*/environ` exposure
    shape doesn't apply to it either.
  - ~~Pin this repo's own built container images by digest, not just
    `build:` context (item 8).~~ **Re-scoped and done, same PR as this update.**
    The original finding pointed at the wrong layer: this repo's own
    images pushed to `ghcr.io` by `containers.yml` are never pulled or
    deployed anywhere — confirmed directly against `deploy.yml`, which
    runs `docker compose up -d --build` against the freshly-checked-out
    git commit on every real deployment, not a pulled image at all. The
    real, present gap was every Dockerfile's own `FROM` line (~20+ of
    them), pinned by mutable tag only (`golang:1.26-alpine`,
    `python:3.12-slim`, one bare `kalilinux/kali-rolling:latest`) — a
    genuine supply-chain exposure if an upstream tag is ever repointed,
    silently picked up on the next build with no review signal at all.
    This same change pins every `FROM` line by digest (resolved for real, not
    assumed) and extends `dependabot.yml`'s `docker` ecosystem entry to
    cover the ~13 directories it was missing, so Dependabot's own
    tag-bump PRs going forward show a real digest diff to review instead
    of just a version-string change.
- **New follow-ups named by items 10-13** (added 2026-10-04 for #3499).
  Same posture as the list above: identified here, not fanned out as issues
  in this pass.
  - **Back-channel logout or per-request token revalidation (item 10.1).**
    The largest gap the new sections found: a revoked or disabled Keycloak
    session keeps a working 12-hour local dashboard session, `admin` role
    included. Named, not filed.
  - **Tree-wide raw-HTML sink audit (item 11.1).** Today's escaping is
    structural (React), and the CSP nonce is an enforced backstop — but
    `csp.test.ts`'s `dangerouslySetInnerHTML` check enumerates three files
    rather than scanning `src/`. Converting it to a directory walk is a
    small, self-contained change.
  - **Per-source rate limiting on `galah-llm-broker` (item 12.5).** Distinct
    from the injection detector's deliberate no-rate-gate decision: that
    reasoning governs detection sensitivity, not resource control.
  - **`network-filter.sh` applied-state check (item 13.3).** GHOSTS's
    containment is an iptables policy applied by hand after every
    `net-setup`, with no gate asserting it is still in force. The Windows
    route's three barriers have the same class of gap (#88) but at least two
    independent properties; this one is a single script invocation.
- **Phases 2-5 of #154 itself** (synthetic replay corpus, decode/correlate
  pipeline, deterministic criticality rules, operator evidence UI) remain
  open, larger implementation work — items 2, 7, and 9's "no correlation/
  escalation engine exists yet" findings are exactly what phases 2 and 3
  would build. This document is the prerequisite research those phases
  depend on, not a replacement for them.
