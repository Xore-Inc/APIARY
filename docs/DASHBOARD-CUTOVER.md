# Dashboard modernization-port cutover

**Status: COMPLETE (2026-08-22, per Xore).** The cutover finished and its
step 9 was executed in full: the Go `dashboard` and Python
`es-results-importer` service blocks are deleted from
`honeypot-dashboard/compose.yml`, every `profiles: ["next"]` line is gone
(the new tier is the default and only tier), and
`scripts/cutover-dashboard.sh` is removed. **There is no runtime fallback
to the Go dashboard** — falling back means checking out a pre-cutover
commit (any commit before this change) and running it normally, a
deliberate decision so no profile/override machinery lingers in the live
compose files. The rest of this document is the historical runbook the
cutover followed, kept for the record.

Status at drafting: first runbook for #1628. Unlike
[`KEYCLOAK-CUTOVER.md`](KEYCLOAK-CUTOVER.md), this had not yet been executed
end-to-end — refine it against what actually happens the first time it's
run, the way that doc was.

**Pre-cutover snapshot, kept for the record — 2026-08-20, two days before
the completion banner above made this true: the `next` profile
had never been activated.** `honeypot-dashboard`'s Arcane project reported
exactly 4 running services — `dashboard`, `oidc-sessions`,
`es-results-importer`, `services-adapter`, all legacy — and zero
`hp-apiary-*` containers existed anywhere on the host. `dashboard-next`,
`backend-service`, and every Rust worker (`backend-worker`,
`backend-worker-importer`, `backend-worker-enrichment`,
`backend-service-mounted`) had never run in production. This meant:
no bake period had started for any worker, so none of #1628's
worker-retirement decisions could move to "retire" yet regardless of how
much parity testing had landed in CI — that testing proves the Rust
implementations are *correct*, not that they've *run* against real
production load. The next step at the time, once #1628's remaining ops-
blocker items were resolved, was step 3 below (`cutover-dashboard.sh
preflight`) for the very first time — not any worker's retirement.

Tracking issue for everything this cutover depends on:
[#1628](https://github.com/Xore/APIARY/issues/1628). **Do not start the
procedure below until every item in that issue's "Deployment / ops
blockers" section is checked off and the worker-retirement and
feature-parity triage sections have an explicit decision recorded, not
just this doc existing.** A runbook does not substitute for the
prerequisites it assumes.

## Fixed architecture

**Old:** one Go binary (`arcane/home/honeypot-dashboard/dashboard`),
Arcane stack `honeypot-dashboard`, service `dashboard`, published on host
port 19090, fronted by VPS Traefik's `honeypot-dashboard` router
(`vps/traefik/dynamic.yml`). Background loops (`notifyLoop`,
`reportScheduleLoop`) run inside this same binary/service.

**New:** three tiers, all originally gated behind the `next` Compose
profile so nothing bound a host port or received traffic until cutover
(the profile is gone now — see the status banner):

- `dashboard-next` — TanStack Start frontend/BFF (Arcane stack
  `honeypot-dashboard`, same stack as the old `dashboard` service, for now)
- `backend-service` — Rust request/response tier (split into its own
  Arcane stack `honeypot-dashboard-backend`, #1622)
- `backend-service-mounted`, `backend-worker`, `backend-worker-importer`,
  `backend-worker-enrichment` — Rust workers and the sandbox/Ghidra/
  GitHub-analysis submission tier (Arcane stack `honeypot-dashboard`,
  same as `dashboard-next`)

Cutover is not a config flag. It is: bring the new tiers up standalone,
verify them, repoint Traefik, move the port binding, then retire the old
service and the old standalone worker stacks. There is no beta hostname
today (#1628) — the new stack goes live at the same hostname the old one
serves, which is why the pre-flight verification step below matters more
than it would with a staged rollout.

## Rollback plan

None existed before this doc. The plan: **do not delete the old
`dashboard` service definition or the old standalone worker stacks in the
same change that cuts over.** Comment them out of active duty (stop the
containers, leave the Compose service blocks and their images in place)
for a bake period — one week is a reasonable starting point, adjust based
on what the bake period actually surfaces — before deleting anything.
Instant revert during the bake period is: re-point Traefik's
`honeypot-dashboard` service back to the old `socat-hp-dashboard:8090`
target, `docker compose up -d dashboard` (and the old standalone worker
stacks, if they were stopped), done. No data migration to reverse — both
tiers read the same Elasticsearch indices; the new tiers writing
alongside the old ones during the bake period is the point (see worker
retirement below), not a hazard.

## Cutover procedure

Each step assumes the previous one is verified, not just completed.
Steps 2-4 and 6 (and their rollback) are automated by
`scripts/cutover-dashboard.sh`, run from the `honeypot-dashboard` stack
directory on the homeserver (`honeypot-dashboard-backend` is expected as
the sibling directory `../honeypot-dashboard-backend`, matching how
Arcane's directory-aware sync materializes both) — see the script's own
header comment for exactly what it does and does not cover; it does not
touch Traefik (step 5) or make the step 7 validation/step 8-9
retirement calls for you.

1. **Confirm #1628's prerequisites are actually met**, not assumed —
   walk its checklist literally, item by item.
2. **Set real values** for every var `.env.example` documents as
   currently defaulting to empty in both `honeypot-dashboard` and
   `honeypot-dashboard-backend` — `DASHBOARD_SERVICE_TOKEN` above all;
   an empty value there means the two tiers trust every request from
   anything else on `honeynet`, not just each other. As of #2183 that
   consequence is mechanical, not prose-only: both tiers refuse to boot
   over an unset/empty token (`[E-SERVICE-TOKEN]` in the logs); the only
   sanctioned way around it is the dev-only
   `APIARY_ALLOW_UNAUTH_DEV=1` (documented in each stack's
   `.env.example` and frontend-next/README.md). The preflight check in
   step 3 below remains as the belt to this suspenders.
3. **Bring the new tiers up without touching Traefik**:
   `./scripts/cutover-dashboard.sh preflight` — brings up the `next`
   profile in both stacks (idempotent), hard-fails if
   `DASHBOARD_SERVICE_TOKEN` resolves empty in either, and health-checks
   `dashboard-next`/`backend-service`/`backend-service-mounted` directly
   over the `honeynet` bridge (no host port ever published, so this step
   alone touches nothing external — `dashboard` is still the only thing
   Traefik reaches).
4. **Verify from the homeserver directly**: preflight's own health checks
   cover `/healthz`; still manually confirm a handful of golden-path
   pages SSR correctly, `/api/live` streams, and login redirects to
   Keycloak and completes. Run `port-tests/{backend-api,frontend-ssr,
   auth-flow}.sh` against this live instance if not already fresh. (The
   whole `port-tests/` directory is gone from the tree today — this step
   is history, and the current equivalent is `.github/workflows/quality.yml`.)
5. **Re-point Traefik** — only if this cutover is ever cross-host; in
   the current single-host topology the VPS-side `socat-hp-dashboard`
   forward already points at a fixed home address
   (`10.8.0.2:19090`) regardless of which container answers there, so
   step 6's port move is what actually redirects traffic and no Traefik
   change is needed. If a future cross-host split does need this,
   change `vps/traefik/dynamic.yml`'s `honeypot-dashboard` service
   `loadBalancer` target and deploy via `.github/workflows/deploy.yml`'s
   own Traefik-config step (not something a homeserver script can drive).
6. **Move the port binding**: `./scripts/cutover-dashboard.sh cutover`
   — re-runs preflight, stops `dashboard` (frees host port `19090`;
   the container and its image are left in place for rollback — not
   yet removed), applies the port move to `dashboard-next` via a
   generated `cutover.override.yml` layered on top of the checked-in
   `compose.yml` rather than a live-only hand-edit of it, and waits for
   `dashboard-next` to report healthy on the live port. If this
   sticks, move that `ports:` mapping into `compose.yml` itself in a
   real PR afterward and delete the override file — a live-only edit
   risks a later Arcane gitops-sync silently reverting it.
   `./scripts/cutover-dashboard.sh rollback` reverses this exactly:
   stops `dashboard-next`'s override-added binding, deletes the
   override file, and restarts `dashboard` (reusing
   `deploy-dashboard-rolling.sh`'s own Health.Status poll).
7. **Full live validation**: every golden-path page, every export/
   download path, SSE, settings save, credentials/canarytokens actions,
   report generation, auth (login, TOTP, logout, session expiry),
   mobile nav if #1576's fix has landed by this point. Treat this the
   same way `KEYCLOAK-CUTOVER.md`'s validation gates treat auth — no
   step here is optional because it "probably still works."
8. **Stop, don't yet delete, the old tiers**: `docker compose stop
   dashboard` in `honeypot-dashboard`, plus whichever standalone old
   worker stacks were decided (per #1628) to retire —
   `honeypot-attacker-identity-worker`, `honeypot-agent-intrusion-worker`,
   and the plain `es-results-importer` service inside `honeypot-dashboard`
   itself. This starts the bake period.
9. **After the bake period, with no rollback needed**: delete the
   `dashboard` service block from `compose.yml`, delete the retired
   worker stacks' directories (or their Arcane manifest entries, per
   however that decision was actually recorded), drop every `profiles:
   ["next"]` line from the remaining new-tier services, and remove the
   now-dead `DASHBOARD_SERVE_MODE`/cross-host-split code paths if #1622's
   cross-host split was never actually exercised in production by this
   point — or keep them if it was.

## Hard-cutover removal list (step 9 above, spelled out)

- `dashboard` Compose service and its container, plus `scripts/
  deploy-dashboard-rolling.sh` (superseded by `scripts/
  cutover-dashboard.sh` for the cutover path — redeploying
  `dashboard-next` afterward is still the plain `docker compose build
  <service> && docker compose up -d <service>` `docs/CI-CD.md` already
  describes; that part didn't need its own wrapper)
- `arcane/home/honeypot-attacker-identity-worker/` stack, if its
  Rust replacement in `backend-worker` was confirmed at parity (#1628's
  worker-retirement decision, not automatic)
- `arcane/home/honeypot-agent-intrusion-worker/` stack, same condition
- the plain Python `es-results-importer` Compose service inside
  `honeypot-dashboard/compose.yml` (distinct from its Rust replacement,
  `backend-worker-importer`), same condition
- every `profiles: ["next"]` line across both dashboard stacks
- the old Traefik `socat-hp-dashboard` forward, once nothing references it

**Not removed by this cutover, decided separately:** whether
`DASHBOARD_SERVE_MODE`'s cross-host split (frontend and BFF on different
docker hosts, #1622's stated next step) is ever actually used. This
runbook assumes a single-host cutover throughout; a cross-host cutover
needs its own pass at step 5 in particular.

## What this runbook deliberately does not decide

- Which of the ten feature-parity gaps (#1628) block step 7's validation
  vs. ship as an accepted v1 cut. Decide before step 1, not during step 7.
- Whether `notifyLoop`/`reportScheduleLoop`'s Rust replacements have run
  long enough dual-writing to trust on their own — the old versions
  retire with the rest of `dashboard` in step 8/9, same as everything
  else in that binary. If that's premature for these two specifically,
  split them out before starting the procedure, not after.
