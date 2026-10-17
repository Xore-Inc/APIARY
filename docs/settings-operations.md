# Settings Operations Runbook

Covers the settings stores owned by the dashboard (the planning document
this page once accompanied was removed as era-stale in #1662; these are
the live stores):

| Store | Location | Contents |
| --- | --- | --- |
| config | Elasticsearch index `dashboard-config-v1`, doc id `config` | administrator dashboard configuration |
| users | Elasticsearch index `dashboard-users-v1`, doc id `users` | user projections + per-user preferences |
| audit | local file `dashboard-audit.jsonl` (`dashboard-state` volume) | settings audit log (rotates at its size cap) |
| history | local file `dashboard-config-history.jsonl` (+ `.1` rotation) | configuration revision history for rollback |

**#787:** config/users used to be local files on the shared `dashboard-state`
volume. With two dashboard replicas, each replica cached its file in memory
once at startup and never reloaded it — a setting changed via one replica's
admin UI was invisible on the other until it was restarted. Moved to
Elasticsearch, the one backend both replicas already treat as shared source
of truth (the Go dashboard's `dashboard/settings_store_es.go`, deleted with
that dashboard; the live implementation is
[`config.rs`](../arcane/home/honeypot-dashboard/backend-service/src/config.rs)).
The Rust tier carries no in-process cache at all — `load_config()` reads the
document from Elasticsearch on every request — so a change made via one
replica is visible to the other on its very next request, with no poll
interval and no restart.

audit/history were never affected by that bug (both do a fresh disk read on
every request against the same shared volume, so cross-replica visibility
already worked) and stay local files. Their paths are overridable through
`DASHBOARD_AUDIT_FILE` and `DASHBOARD_CONFIG_HISTORY_FILE`; the defaults
above apply to the compose deployment. config/users have no path override
any more — they always live in Elasticsearch at the index/doc-id pair above.

## Metrics

There are no settings-specific metrics. The `honeypot_settings_*` gauges this
page used to document belonged to the deleted Go dashboard's Prometheus
surface; nothing in the Rust backend emits them, and the fleet ships no
Prometheus stack to scrape `/metrics` today.

What `/metrics` on `backend-service` (:8081) actually exposes is the API
tier's own request instrumentation, and nothing else
([`obs.rs`](../arcane/home/honeypot-dashboard/backend-service/src/obs.rs)):

- `apiary_backend_requests_total{family,status}` — requests by route family
  and status class (`2xx`/`3xx`/`4xx`/`5xx`). `family` is the *third* path
  segment under `/api/v1/` (`store`, `live`, `workbench`, `campaigns`, …),
  or `healthz`/`metrics` for those two bare routes. A segment is only used as
  a label if it is at most 40 characters of `[A-Za-z0-9_-]`; anything else
  folds to `other`, so a raw id or a traversal attempt cannot inflate
  cardinality. That guard is why there is no allow-list of families — the
  label is derived per request, not enumerated.
- `apiary_backend_request_duration_seconds` — the same families as a
  cumulative-bucket histogram (`_bucket` / `_sum` / `_count`).

To watch the settings subsystem, watch its state instead. Note the failure
posture changed with the tier: the Go backend degraded to *compiled defaults,
read-only* when Elasticsearch was unreachable. The Rust tier does not — every
config and users read maps an Elasticsearch error to **502 Bad Gateway** rather
than serving defaults, and writes fail the same way. The only default-shaped
response is a genuinely fresh install with no document yet, which returns
`{"revision": 0, "payload": {}}`. Every accepted write lands in
`dashboard-audit.jsonl` (rotated at 8 MiB, one generation kept) with the prior
revision in `dashboard-config-history.jsonl`.

## Backup

Config and users (Elasticsearch-backed since #787) are covered by whatever
snapshot/backup policy this cluster's other Elasticsearch-owned dashboard
data already has (`arcane/home/honeypot-init/analysis/elasticsearch-setup.sh`) — not
`scripts/backup-state.sh`, which now only covers what's still on the
`dashboard-state` volume.

`scripts/backup-state.sh` archives the whole `dashboard-state` volume —
audit/history plus the sandbox payload scripts that share it:

```sh
scripts/backup-state.sh                       # default volume + backup dir
BACKUP_DIR=/mnt/backups KEEP=30 scripts/backup-state.sh
scripts/backup-state.sh <other-volume-name>   # non-default project name
```

Archives land as `dashboard-state-<utc-timestamp>.tar.gz` next to the other
host-level state backups; the newest 14 (configurable via `KEEP`) are
retained. Wire it into the same schedule as the existing host state copies
(e.g. a nightly cron entry).

## Restore

**Audit/history (local files):**

1. Stop the dashboard: `docker compose stop dashboard-next` (the service is
   `dashboard-next`, container `hp-dashboard-next`; the Go `dashboard` service
   this used to name was deleted at #1628's cutover).
2. Untar the chosen archive into the volume:
   `docker run --rm -v dashboard-state:/state -v <backup-dir>:/backup alpine:3 tar xzf /backup/dashboard-state-<ts>.tar.gz -C /state`
3. Start the dashboard: `docker compose start dashboard-next`.

**Config/users (Elasticsearch):** restore via whatever mechanism recovers the
`dashboard-config-v1`/`dashboard-users-v1` indices (snapshot repository
restore, or `keycloak/restore.sh`-style tooling if one exists for these
indices) — there is no per-dashboard-replica file to move.

Every store fails safe on a load problem: config/users serve compiled
defaults **read-only** when Elasticsearch is unreachable or the document is
corrupt (the `degraded`/`readonly` metrics flip to 1, self-healing once
Elasticsearch is reachable again); audit/history tolerate a corrupt line by
skipping it. A partial or wrong restore therefore degrades safely instead of
crashing the dashboard.

## Rollback (no restore needed)

For configuration mistakes rather than data loss, use the built-in history:
the settings modal's history pane lists retained revisions, and
`POST /api/v1/config/rollback` restores one. Rollback entries are
themselves audited and become a new revision, so rollback-of-rollback works.
Writes carry optimistic concurrency: `GET /api/v1/config` returns the
document's `revision`, every write accepts an optional `If-Match: <revision>`
and answers 409 on a mismatch (carrying `X-Current-Revision` so the client
can re-sync), and a missing header keeps last-write-wins.

## Break-glass disabling

If the settings subsystem itself misbehaves:

- **Configuration:** the store already fails open to compiled defaults,
  read-only, whenever Elasticsearch is unreachable — no manual action needed
  to force this state; if you need a deliberate outage, block network access
  from the dashboard to Elasticsearch instead of touching a file.
- **Per-user preferences:** same posture as configuration above.
- **Admin configuration API:** remove the dashboard's `admin` role from the
  `apiary-dashboard` Keycloak client (realm `apiary`; the nine clients are
  declared in
  [`arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json`](../arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json)).
  The frontend reads client roles from
  `resource_access.apiary-dashboard.roles` and treats anything without
  `admin` as `user`
  ([`arcane/home/honeypot-dashboard/frontend-next/src/lib/oidc.server.ts`](../arcane/home/honeypot-dashboard/frontend-next/src/lib/oidc.server.ts));
  the admin
  panes and endpoints are gated server-side on live introspection, so access
  ends on the next request. `Xore/auth-backend` was the pre-Keycloak home
  for those roles and is retired.
- **Orphan retention:** `DASHBOARD_USER_RETENTION_DAYS` (default 90) controls
  the sweep; it cannot fully disable live-introspection revocation, which is
  always immediate.

## Staged rollout sequence

**Design record, not live procedure.** This is the observe-only → per-user
writes → admin configuration → soak sequence the settings migration was
*planned* to follow. It ran its course: the Go dashboard is gone, so there is
nothing left to stage. Kept because the *gating discipline* it describes —
let each write class be exercised and watched before the next is enabled — is
still the right way to introduce a new settings store. Its two named metrics
(`save_failures_total`, `config_revision`) never shipped; see [Metrics](#metrics).

1. **Observe-only.** Deploy the build. Stores start, metrics appear, the
   settings UI reads. No admin writes yet; per-user preference writes are the
   only mutations and are strictly isolated per subject.
2. **Per-user writes.** Let users save preferences; watch
   `save_failures_total{kind="preferences"}` and the store health gauges.
3. **Admin configuration.** Grant admin role to operators and exercise the
   configuration pane; watch `config_revision`,
   `save_failures_total{kind="config"}`, and the audit pane.
4. **Soak.** Run 72 hours multi-user before calling the migration complete.
