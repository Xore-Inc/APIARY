# Testing strategy

This repo already runs a large amount of testing (`.github/workflows/quality.yml`
alone covers 20+ distinct checks — see [docs/CI-CD.md](CI-CD.md) for the full
list). What was missing was a single place describing the *shape* of testing
this project does, at which tier each kind belongs, and how to repeat the
tiers that don't run automatically. This file is that place.

## The three tiers

### Tier 1 — CI (every push, every PR, fully automated)

Fast, deterministic, no live infrastructure. Go/Python/shell unit and
component tests, frontend typecheck+build, Docker Compose config validation
for every stack, CodeQL, dependency review, and the growing set of
component-specific tests listed in
[docs/CI-CD.md](CI-CD.md#checks) (ILM rollover, GeoIP pipeline, YARA corpus
integrity, GitHub-publisher dry-run gate, and so on — each added the same
way: a real bug or gap gets a real test, not a note in a doc).

**Cadence:** automatic, on every push/PR.
**Where it lives:** `.github/workflows/quality.yml` and the per-module
`*_test.go`/`test_*.py`/`test_*.sh` files it runs.
**Pass criterion:** all green. A red check blocks merge.

### Tier 2 — Live feature smoke test (per feature, as it's built or touched)

A real submission through a real running instance of the one thing that
changed, verified against actual output — not mocked, not assumed from
reading the code. This is already this project's working convention (see
#593's ml-worker verification, #594's per-sensor ES ingestion audit, #498's
per-submission-path dashboard test, and the live-verification pattern used
throughout this repo's own commit history), just not previously written down
as a rule.

**When to do it:** any time a fix or feature touches a live-running
component (a sensor, a worker, the dashboard, an ES pipeline) and the claim
"this works" can be checked against the real thing rather than just the
diff. Prefer the homeserver/VPS directly over a from-scratch container
reproduction when the behavior depends on the real deployment's state
(portbridge joins, ES templates, real volumes) — see the account's own
standing guidance on iterating directly against `ssh homeserver`/`ssh vps`.

**Cadence:** ad hoc, tied to the change being made — not scheduled.
**Pass criterion:** the specific claim being tested is confirmed against
real output (a real log line, a real ES document, a real HTTP response),
not inferred from source reading alone.

**Worked example (#1972, serving-tier app logs):** the dashboard's own HTTP
tiers keep durable records on Elasticsearch now, and verifying a change to
them means watching a record land end-to-end rather than trusting the
writer. Signed in, hit any dashboard API route; the Rust tier appends one
JSONL line per request to `/opt/stacks/apiary/logs/dashboard-backend*/app.jsonl`
(host) and ships into `dashboard-backend-v1-*`, and it echoes its
`x-request-id` on the response so one id joins browser → BFF → Rust tier. A
failed sign-in leaves `dashboard-bff-v1-*` documents (`auth_login_failed`,
with a trimmed reason) even when nothing else recorded it. Container stdout
is still there for tailing (`docker compose logs -f backend-service`), but
it is the rotating ring buffer — Elasticsearch is where an incident is
reconstructed from after the fact.

### Tier 3 — Full clean-install end-to-end test (pre-release gate)

Everything in Tiers 1-2 verifies a change in isolation, often against a host
that has accumulated weeks of state and manual fixes. Tier 3 is the
one check that a *genuinely fresh* install of the whole stack — every
sensor, every worker, the dashboard, both hosts — comes up and works
end-to-end with no leftover state or manual intervention papering over a
gap. This is expensive and disruptive (it wipes both hosts), so it is not
a CI job — it's a deliberate, infrequent, human-triggered pass.

**When to run it:** before cutting a release (0.1.0 and every meaningful
release after it), and any time there's reason to suspect the *installation
path itself* has drifted from what a clean host actually needs (a new
service added without updating `install-homeserver.sh`, a new required
`.env` value, a new directory layout assumption).

**Never run without explicit operator go-ahead** — it wipes live
infrastructure. See #787 for the first full run of this checklist against
0.1.0; that issue is also where checklist gaps found while running it get
fixed back into this document and the install scripts themselves.

#### Procedure

1. **Confirm the backup is current, before wiping anything.** This
   doesn't need a new backup mechanism — `install-homeserver.sh` already
   restores from `BACKUP_HOST_PATH`/`BACKUP_HOST_SANDBOX_PATH` on a fresh
   box (`step_restore_env_files` for every stack's `.env`, and a separate
   phase for the sandbox golden images). The wipe is only safe once
   that backup actually reflects the current state:
   - Every stack's `.env` file — restored automatically by
     `step_restore_env_files`, but only as current as the last time it
     was pushed to `BACKUP_HOST_PATH`.
   - Windows sandbox golden images (`win11-analysis.qcow2`,
     `win11-ghosts.qcow2`) at `BACKUP_HOST_SANDBOX_PATH` — hours to
     rebuild if the backup is stale or missing.
   - The Windows 11 evaluation ISO (#49) — time-limited to obtain,
     expires at 90 days; confirm it's actually part of what gets restored,
     not assumed.
   - Anything else not reproducible from the git checkout alone (audit
     before wiping — don't assume the list above, or
     `install-homeserver.sh`'s own restore steps, are exhaustive for a
     given run; this is exactly the kind of gap this pass exists to
     catch).
2. **Wipe both hosts** — every Arcane-managed stack, container, volume, and
   piece of state on the homeserver and the VPS.
3. **Reinstall from the real path** — `scripts/install-homeserver.sh` (or
   whatever the current unattended provisioning entry point is) against a
   genuinely clean OS, not a host with leftover packages/config. Redeploy
   the VPS side the same way.
4. **Smoke test the result:**
   - Installation itself: every stack comes up healthy, in the right
     order, with no manual intervention beyond what's documented.
   - Dashboard: every page loads; every submission path (Tier 2's #498
     list) produces a real result against the fresh install.
   - Elasticsearch: every sensor's events land with the expected mapping;
     ILM/rollover behaves; no silent ingestion gaps.
   - Dashboard reads ES only: confirm no code path falls back to direct
     log-file access that happened to work during development but would
     silently break once ES is the only source of truth (see
     `docs/ARCHITECTURE.md`'s own ES-only-reads rule; #1103 tracks closing
     the remaining gaps in this).
   - Firewalling: every loopback-only/WireGuard-only service is actually
     that on the freshly-installed host — cross-check against
     `docs/honeypot-network-isolation.md`.
   - End-to-end payload analysis: one real (benign where possible) sample
     through the whole pipeline — capture, dedup, YARA, sandbox detonation
     (Linux + Windows), Ghidra static analysis, GitHub-analysis
     publishing, Rev·Deck — confirming results land where the dashboard
     reads them from.
   - No stale references: confirm every route/handler/function the
     dashboard and each worker actually call is a *current* one — no
     lingering call into a route or function that's been superseded or
     replaced but never removed (the kind of gap a working install can
     mask, since the old path may still technically respond). Cross-check
     call sites against the routes actually registered in
     [`main.rs`](../arcane/home/honeypot-dashboard/backend-service/src/main.rs)
     and the functions actually exported by each module, not just "does it
     still return 200."
   - Dead code: the reverse direction of the check above — routes,
     handlers, functions, and files that exist but are no longer called
     or registered from anywhere (a superseded implementation left behind
     after a replacement landed, an old endpoint nothing links to
     anymore). Left-behind dead code is exactly what an unofficial
     third-party dependency being swapped out (#245) or a features
     migration (#638's ES-artifact-storage series) can leave lying
     around if the old path isn't deleted in the same pass.
   - **Keycloak (#1036, mandatory — makes #787 impossible to close until
     this passes, not an optional extra check):** a fresh install must
     stage the reviewed realm and theme, provision new host-local
     secrets, and bring up healthy Keycloak/PostgreSQL/every oauth2-proxy
     gateway with no undocumented manual fix. Then, against that fresh
     install:
     - First-login password replacement and mandatory TOTP enrollment for
       a fresh administrator account and a fresh normal-user account.
     - Native dashboard OIDC: login, token refresh, account/settings
       access, admin-role enforcement, logout, a disabled/revoked
       session losing access, and fail-closed behavior when the identity
       provider is unreachable.
     - Every gateway-fronted application — the six isolated `oidc-*`
       gateways (Kibana, EveBox, Arkime, TANNER, RevDeck, the Traefik
       dashboard): authorized access reaches
       real content, wrong-role denial, logout, callback/deep-link
       behavior, and direct-upstream bypass denial (confirm the
       isolated `oidc-<app>` Docker network still has no other member).
     - The Keycloak admin console itself requires Keycloak
       authentication and MFA; frame/header exceptions stay restricted
       to the exact compatibility endpoints that need them
       (`keycloak-embedded-frames`/`security-headers-keycloak-frame` in
       `vps/traefik/dynamic.yml`), not widened generally.
     - No legacy auth runtime, route, middleware, identity-header trust,
       secret, or fallback survives the install: grep the fresh
       deployment for `AUTH_INTROSPECTION_*`, `forward-auth`,
       `strip-auth-identity`, `xore_sso`, and `X-Auth-Role` and confirm
       zero live hits (this repo's own working tree has none — verified
       2026-08-09, and re-verified 2026-09-27: the only remaining matches
       are two comments saying the thing was retired, plus the one
       allowlisted stale-path entry in `scripts/doc-path-lint-allowlist.txt`
       for the moved VPS forward-auth directory. The check here is that a
       *deployed*, fresh install has no live runtime).
     - Retain redacted evidence (pass/fail results plus browser
       traces/screenshots/logs where applicable) and link it from #787.
5. **Fix forward, and track it:** any gap found (a missing install step,
   an undocumented manual fix, a firewall hole) gets fixed in the actual
   install scripts, compose files, and docs during the same pass where it's
   small enough to — the whole point of Tier 3 is catching "works because
   I already fixed it by hand" gaps before a real first-time install hits
   them. Every gap found also gets its own GitHub issue, whether fixed
   immediately or not: a fix with no issue behind it is a fix nobody else
   can find the reasoning for later, and anything not fully resolved
   inline needs somewhere to live until it is.

**Pass criterion:** every item in step 4 confirmed against the fresh
install, with no unresolved gap left over from step 5 — including the
Keycloak checklist above, which is not optional (#1036): #787 cannot
close, and 0.1.0 cannot cut, until it passes.

## Adding a new test

- A new component-level test (Tier 1) goes in `quality.yml` next to the
  existing ones, following the same pattern: real bug or gap found → a
  real test added, not just a fix.
- A new live smoke-test convention (Tier 2) doesn't need a new file —
  it's a practice, exercised in the PR/commit that touches the live
  component, same as the existing examples.
- Tier 3's checklist (this file, `## Procedure` above) grows when a clean
  reinstall surfaces something the checklist didn't check for yet.
