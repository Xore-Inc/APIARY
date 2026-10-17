# Agent-intrusion synthetic replay corpus, decode/correlate pipeline, criticality rules, and campaign worker (#154 phases 1-5)

A versioned, fully synthetic corpus of ordered events representing the
July 2026 agent-intrusion campaign's own phase structure, replayed in
APIARY's own sensor/event vocabulary (phase 1: "Sanitized replay corpus"),
the bounded, non-executing decoder and two correlators phase 2 asks for
("Decode and correlate before LLM analysis"), the deterministic
criticality rules phase 3 asks for ("Escalate independently of an LLM
when combinations cross trust boundaries"), and (phase 5) a worker that
wires all of the above against real Elasticsearch data plus the
`/agent-campaigns` route (`backend-service`'s Rust `src/agent_intrusion.rs`
as the writer, `stores.rs`'s generic index-store passthrough as the
reader — the Go dashboard's `dashboard/agent_campaigns.go` was the
original consumer and is retired) that renders its output — all proven
against that one corpus rather than hand-built fixtures alone. The
prerequisite research (mapping the campaign to APIARY's actual trust
boundaries) is
[`docs/agent-intrusion-threat-model.md`](../../../../../docs/agent-intrusion-threat-model.md);
phase 4's preventive-control audits (Dockerfile digest pinning, an
assessed ARKIME secret-delivery finding) are documented there, not here,
since they touch the wider repo rather than this directory. Phases 1-5
are now all done, including deployment: `agent-intrusion-worker` is
retired (#1649) in favor of `backend-service`'s Rust port, wired live as
`WORKER_LOOPS=agent-intrusion` — same index, same poll shape, confirmed
before retiring with 14 clean cycles over 5h of dual-writing. This
Python worker stays defined with `profiles: ["legacy"]` for rollback,
not as the live writer.

## What's here

- **`corpus.jsonl`** — the corpus itself. One JSON object per line, in
  strict timestamp order; `event_id` (`corpus-001`, `corpus-002`, ...)
  matches that order exactly.
- **`schema.json`** — JSON Schema for one event's shape.
- **`validate_corpus.py`** — validates the corpus against the schema plus
  safety constraints JSON Schema can't express (TEST-NET-only addressing,
  no benign/escalate contradictions, cross-reference integrity). No
  third-party dependencies — hand-rolled, matching
  `analysis/ghidra/models/*.py`'s own stated "one less supply-chain
  surface" philosophy. Run directly: `python3 validate_corpus.py`.
- **`tests/test_corpus.py`** — `unittest`-based tests (same convention as
  every other `analysis/tests/*.py` in this repo — no `pytest` dependency).
  Proves the corpus validates clean *and* that the validator actually
  catches deliberately-broken input, not just that today's corpus happens
  to pass.
- **`decode_correlate.py`** — phase 2's decoder (`bounded_decode`: bounded,
  non-executing base64/gzip/zlib decode, with a single-byte-XOR brute-force
  fallback, full provenance chain, depth/size caps) and chunk correlator
  (`ChunkCorrelator`: reassembles the campaign's own type/channel/sequence/
  checksum message protocol before a multi-part payload is even decodable).
  No third-party dependencies, same reasoning as `validate_corpus.py`.
- **`tests/test_decode_correlate.py`** — unit tests against hand-built
  fixtures (including the decoder's own bounds: depth cap, size cap,
  malformed/adversarial input never raising) *and* end-to-end tests that
  run the real corpus's encoded events through the pipeline and confirm
  the recovered plaintext actually matches what each event's own
  `expected_findings.decoded_summary` claims — cashing in the corpus's own
  "ground truth" contract for real, not just trusting the prose.
- **`campaign_correlator.py`** — phase 2's other half ("Correlate events
  across sensors into one campaign timeline using stable IDs and time
  windows"). Distinct from `decode_correlate.py`'s `ChunkCorrelator`,
  which reassembles fragments of *one message*; this correlates separate,
  already-complete *events* into one campaign, union-find style over
  shared session/source-IP/C2-channel identifiers within a time window.
  No ML, no fuzzy matching — deterministic, same posture as
  `bounded_decode`.
- **`tests/test_campaign_correlator.py`** — unit tests plus an end-to-end
  proof against the real corpus of the actual motivating case #154 opens
  with: a C2 channel ID reused across a "stage" and an "exfil" message
  bridges two events sharing *no* session or IP of their own into one
  8-event campaign. Also asserts two real, deliberate scope limits this
  identifier-only approach doesn't solve (fleet siblings on different
  hosts; an actor's IP changing across a mesh/NAT pivot) rather than
  leaving them as silent gaps.
- **`criticality_rules.py`** — phase 3's deterministic escalation rules
  (11 of them: sensitive-path reads, the campaign's own chunked-C2
  protocol shape, verified encoded-execution, encoded egress to a
  different network segment, the cloud metadata address, privileged
  container creation, broad-scope identity tokens, covert mesh
  enrollment, internal-connector enumeration, source-control writes from
  an unnamed actor, and staged-payload references), plus
  `campaign_severity()`, which scores a whole campaign by the *distinct*
  rule categories it trips (not raw match count) — 3+ distinct categories
  reaches "critical". Every rule inspects raw event structure only, never
  the corpus's own `phase`/`should_escalate` labels (see the module's own
  docstring for why getting that backwards would make it a no-op).
- **`tests/test_criticality_rules.py`** — unit tests per rule, a dedicated
  regression test for a real bug (`ipaddress.is_private()` conflates RFC
  1918 with RFC 5737 TEST-NET, which broke "internal vs. external"
  classification in both directions against a TEST-NET-only corpus before
  landing on a same-/24 check instead), the full-corpus proof that all 27
  events match their own independently-established ground truth, and the
  capstone: the merged 8-event campaign (see above) scores "critical".
- **`worker.py`** — polls the real `honeypot-v2-*`/`suricata-v2-*`
  Elasticsearch indices (the same two `ml-worker/worker.py` itself already
  polls), maps each document into the `{event_id, timestamp, raw}` shape
  the corpus already uses, and runs the exact same `correlate_campaigns` →
  `evaluate_event` → `campaign_severity` call sequence proven above —
  against real data this time, not the corpus. Writes one provenance-rich
  verdict document per `high`/`critical` campaign to a new
  `agent-intrusion-campaigns` index (`campaign_id` deterministic from the
  sorted event-ID set, so re-processing the same campaign on a later poll
  is an idempotent upsert), each matched rule carrying its own
  `trust_boundary` (`criticality_rules.TRUST_BOUNDARIES`) and — for the two
  rules that actually decode anything (`encoded-execution`,
  `encoded-egress-external`) — a `decode_chain` of the real
  `decode_correlate.DecodeStep` hashes, #154 phase 5's own
  "decoded-artifact hashes" requirement. `low`-severity campaigns (nothing
  matched) are deliberately never written — that's the isolated/benign
  case this whole pipeline exists not to separately alarm on. Bounded
  rolling re-fetch each cycle (`FETCH_WINDOW_DAYS`, default 10), not an
  incremental checkpoint like `ml-worker`'s own — a deliberate tradeoff
  (some repeated ES query cost) for a lot less state-management
  complexity, since campaign correlation needs to see the *whole* window
  at once regardless of what's new since the last poll.
- **`/agent-campaigns`** — the operator-facing half of phase 5, now served
  by `backend-service`'s Rust cutover: `src/agent_intrusion.rs` writes
  `agent-intrusion-campaigns`, and `src/stores.rs`'s generic index-store
  passthrough serves it to the route (`agent_intrusion.rs`'s own doc
  comment: "`/agent-campaigns` route reads this — see src/stores.rs's
  generic index store"). This was originally the Go dashboard's
  `dashboard/agent_campaigns.go`, since retired along with the rest of
  `dashboard/`. Every member event's matched rule, trust boundary, and
  decode-chain hashes still render the same way; no model-generated
  narrative text is rendered on this page — every field traces to a
  deterministic rule match, so there's no untrusted free-text output to
  guard against here the way `llm_analysis.go` (also retired) had to.
- **`Dockerfile`** / **`arcane/home/honeypot-agent-intrusion-worker/compose.yml`**
  (repo root) — builds and runs `worker.py` as its own Dockge stack,
  modelled directly on `ml-worker/docker-compose.yml`'s own shape (joins
  `honeynet` as an external network, same hardening: `no-new-privileges`,
  `cap_drop: [ALL]`, `read_only`). Retired (#1649) now that
  `backend-service`'s Rust port (`src/agent_intrusion.rs`) dual-wrote and
  then took over the same index — this stack's own compose header
  documents the retirement. It carries `profiles: ["legacy"]` for
  rollback and is no longer deployed by `deploy.yml`'s per-stack
  "Synchronize ..." copy step (gone since #1502's Arcane transition for
  every stack that lives under `arcane/home/`) — the whole directory now
  ships as an Arcane-managed, directory-aware git sync
  (`arcane/manifests/home-production.json`: `syncName
  honeypot-agent-intrusion-worker`), with a relative build context since
  there's no shared checkout for an absolute path to point at.
  Also built/scanned in `containers.yml` and provisioned by
  `scripts/install-homeserver.sh`'s `STACK_DEFS` for a fresh install.
- **`tests/test_worker.py`** — a hand-rolled fake Elasticsearch client (no
  network, no real ES needed), unit tests for the ES-hit-to-event mapping
  and timestamp normalization (real `@timestamp` values are full ISO 8601
  with fractional seconds/UTC offsets, unlike the corpus's own bare
  `...Z`-suffixed fixture strings), and — the actual point of this file —
  an end-to-end run of the *real corpus* through `worker.py`'s own
  correlate-then-score call sequence, proving the capstone 8-event
  campaign still reaches "critical" through the worker's own wiring, not
  just when `campaign_correlator.py`/`criticality_rules.py` are called
  directly in their own test files.

## Design

Each event carries:

| Field | Meaning |
|---|---|
| `event_id` | `corpus-NNN`, matches position in the file |
| `timestamp` | ISO 8601 UTC, strictly ascending across the whole corpus |
| `phase` | One of the 8 phases #154 required, or `benign` |
| `trust_boundary` | The boundary this event's technique crosses, in APIARY's own terms |
| `sensor` | Which real APIARY sensor/source `raw` is shaped like (cowrie, suricata, dashboard-audit, ci-workflow) |
| `encoding_layer` | What a decoder needs to peel back (`none`, `base64`, `gzip+base64`, `chunked+xor+gzip+base64`, `jinja2-template`) |
| `is_benign` | True for near-neighbor control events — same surface shape, not part of the attack chain |
| `raw` | A realistic, sensor-shaped JSON blob — what phase 2's decoder would actually receive in production |
| `expected_findings` | Ground truth: `should_escalate` (for phase 3), `decoded_summary` (for phase 2), `matched_rule` (placeholder — phase 3 doesn't define real rule IDs yet) |
| `notes` | What real campaign step this is an analog of, and why — every event is annotated, this is a reviewable artifact, not just machine input |

### Why sensor-shaped `raw`, not an abstract description

Phase 2's decoder will consume real sensor output (cowrie JSON lines,
Suricata `eve.json` alerts, etc.). A corpus that only *described* what
should happen ("attacker exfiltrates data") would be useless as a fixture
for testing an actual decoder. Every `raw` field here is built to look like
what that sensor really emits, so a future decoder can be pointed at this
file's `raw` values directly.

### The 8 required phases, and how each maps onto APIARY

Per `docs/agent-intrusion-threat-model.md`, APIARY has no real Kubernetes,
cloud IAM, or metadata service — three of the campaign's own techniques
(K8s service-account tokens, cloud metadata credential replay, forged
workload-identity tokens) have nothing to escalate into *here*. Those
events are included anyway (`cloud_k8s_identity_probe`, and the K8s-token
event under `secret_discovery`) because the corpus's job is testing
whether a correlation engine recognizes the *signature* of a technique
class — an attacker's toolkit doesn't know or care that a target lacks
Kubernetes, and a honeypot session attempting `cat
/var/run/secrets/kubernetes.io/serviceaccount/token` is real signal about
that attacker regardless of whether the path resolves to anything. Each
such event's own `notes` field says so explicitly.

`internal_network_pivot` and `source_control_ci_probe`, by contrast, map
onto real APIARY trust boundaries almost exactly: this stack has a real
WireGuard mesh (VPS↔homeserver) and a real GitHub App-adjacent write path
(`dependabot-auto-merge.yml`'s `contents:write`/`pull-requests:write`
scopes). Those phases' benign near-neighbors (corpus-004, corpus-007) are
deliberately APIARY's own *real* good-case events (an actual Dependabot
PR shape, the actual WireGuard tunnel peer address), not generic
placeholders — the sharpest possible contrast against the attack-chain
version.

### Benign near-neighbors

#154 requires them explicitly ("Include benign near-neighbors to measure
false positives"). Each one shares its attack-chain counterpart's surface
shape (same sensor, same rough technique category) but differs in the
property that should actually matter — actor identity, destination
boundary, token scope/TTL, or simply "this is the real, known-good
version of the same kind of event." `expected_findings.should_escalate`
is `false` for every benign event by construction;
`validate_corpus.py`/the tests enforce that as a hard contradiction check.

## Safety constraints (#154: "must never... expose secrets... Do not copy
live indicators, credentials, hostnames, or weaponized payloads")

- Every address is TEST-NET (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), checked by `validate_corpus.py` against every
  IP-shaped field *and* every bare dotted-quad found anywhere in an
  event's `raw` blob. A short, individually-commented allowlist exists for
  three real, non-secret constants that are meaningful specifically
  *because* they're real: APIARY's own WireGuard tunnel peer
  (`10.8.0.1`), the well-known cloud metadata link-local address
  (`169.254.169.254`, itself the point of the event it appears in), and a
  loopback SOCKS5 bind address (`127.0.0.1`).
- Every password/token value is the literal placeholder `fake-not-real`
  or an explanatory string — never a real-shaped secret.
  `test_no_obviously_real_looking_secrets` greps every event for real
  credential-prefix shapes (`AKIA`, `ghp_`, `tskey-auth-`, etc.) as a
  backstop against a future hand-edit pasting something real in.
- The encoded/C2 technique itself is expressed via the campaign's own real
  command *shapes* (`gzip.decompress(base64.b64decode(...))`, the
  message-protocol type/channel/seq/checksum fields, `--state=mem:
  --no-logs-no-support`), since that shape is what a decoder/correlator
  needs to recognize — but every payload those commands act on is an
  inert, synthetic placeholder, never a working dropper.
- No real hostnames, campaign infrastructure names, or IOCs from the
  source campaign are copied — every identifier (`corpus-example.test`,
  `corpus-fleet-01`, session IDs) is obviously fixture-shaped.

## Regenerating

`corpus.jsonl` is hand-reviewed data, not generated at build time — there
is no script in this directory that produces it. It was originally built
with a one-off Python script (events defined in final chronological order
so each event's own cross-references to other `event_id`s by name stay
correct without a renumbering pass) that was discarded after review, by
design: a corpus meant to be read and reasoned about by a person should be
edited directly, not regenerated from a generator that could silently
change reviewed content. To extend the corpus, add events directly to
`corpus.jsonl`, keep `event_id`/timestamp order consistent, and run
`validate_corpus.py` (or `tests/test_corpus.py`) before committing.

## Versioning

`corpus.jsonl` is not itself schema-versioned (no top-level `version`
field) — the file's own git history is the version record, matching how
this repo treats `analysis/yara/` and other reviewed-fixture directories.
A future breaking change to `schema.json` (a required field added/removed,
an enum value changed) should bump `schema.json`'s own `$id` and add a
note here, not silently reinterpret old corpus rows under a new meaning.

## What this directory does *not* do

`worker.py` closed the "not wired into production" gap for reading real
sensor data and writing real verdicts (now superseded by `backend-service`'s
Rust port, `src/agent_intrusion.rs`), and the `/agent-campaigns` route
closes the read side -- a real `critical` campaign is visible there, not
just via a direct Elasticsearch query. `matched_rule` in every
*corpus* event (a separate thing from the real index above) is still
either `null` or a descriptive placeholder string, not cross-referenced
back into the corpus fixture itself -- `criticality_rules.py`'s own
`RuleMatch.rule` names are the real identifiers, used directly by
`worker.py`, just not retrofitted into `corpus.jsonl`'s own ground truth.

`campaign_correlator.py` has two deliberate, tested scope limits (see
`tests/test_campaign_correlator.py`'s own "documented gap" tests): it
correlates on shared *identifiers*, not repeated-technique similarity
across different infrastructure, and it has no way to link an actor's
identity across a NAT/mesh boundary where its own address changes. Both
limits carry through to `worker.py` unchanged -- it's the same function,
called against real events instead of corpus ones.

This directory's stack was wired into production with explicit operator
go-ahead, not silently as a side effect of an earlier PR (see its own entry
in "What's here" above, including its subsequent #1649 retirement in favor
of the Rust port) -- `agent-intrusion-campaigns` gets real production
verdicts, not just whatever this repo's own tests write to a fake ES
client.

Phase 4's preventive-control audits (ARKIME secret delivery, image digest
pinning — see `docs/agent-intrusion-threat-model.md`'s own "Follow-up
scope") are unrelated, separate work this directory's own files don't
touch.
