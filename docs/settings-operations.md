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

Config and users (Elasticsearch-backed since #787) are exported as documents by
[`scripts/es-operator-state-backup.py`](../scripts/es-operator-state-backup.py)
into every essentials backup — `homeserver/es-operator-state/` in
`scripts/backup-essentials.sh`'s archive, and the same directory in
`analysis/backup-honeypot.sh`'s on-host copy. That is a mapping plus NDJSON
per index, kilobytes each, and it rides along in the same encrypted archive as
the secrets to three destinations off the homeserver. Full scope, including
the eight other operator-authored indices captured with these two:
[`BACKUP-ESSENTIALS.md` §Operator state](BACKUP-ESSENTIALS.md#operator-state).

**#3323:** until then this section deferred to some cluster-wide Elasticsearch
backup policy for these two stores. No such policy exists — `GET _slm/policy`
returns `{}`, the script that took an ES snapshot was removed, and it had never
succeeded once anyway
([`BACKUP-ESSENTIALS.md` §History](BACKUP-ESSENTIALS.md#history)) — so both
stores were in no backup at all. An SLM policy into `honeypot-fs` would not
have fixed that: that repository lives on the same host as `es-data` and is
excluded from this backup's own on-host copy, so a snapshot there dies with
the disk.

Neither store is covered by `scripts/backup-state.sh`, which only archives
what is still on the `dashboard-state` volume.

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

1. Stop the two writers of `dashboard-state`: `docker stop hp-apiary-backend
   hp-apiary-backend-mounted` (`backend-service` and
   `backend-service-mounted`). The dashboard UI (apiary-dashboard) holds no
   audit files; the legacy `dashboard-next` this step used to name was
   removed in #3749.
2. Untar the chosen archive into the volume:
   `docker run --rm -v dashboard-state:/state -v <backup-dir>:/backup alpine:3 tar xzf /backup/dashboard-state-<ts>.tar.gz -C /state`
3. Start them again: `docker start hp-apiary-backend hp-apiary-backend-mounted`.

**Config/users (Elasticsearch):** there is no per-dashboard-replica file to
move. The documents come back from the essentials backup with
`scripts/es-operator-state-backup.py` (it rides inside the archive, and its
copy in the checkout is the same one):

```sh
python3 scripts/es-operator-state-backup.py --restore homeserver/es-operator-state
python3 scripts/es-operator-state-backup.py --restore homeserver/es-operator-state \
  --into 'check-{index}'          # rehearse into scratch indices first
```

It recreates each index from the exported mapping and bulk-indexes the
documents, so nothing has to be assembled by hand from the NDJSON. The
`dashboard-config-v1`/`dashboard-users-v1` singletons come back under their
original doc ids (`config`, `users`), which is what the CAS writers expect.

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
  `apiary-dashboard-rewrite` Keycloak client, the production dashboard's
  (realm `apiary`; the clients are
  declared in
  [`arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json`](../arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json)).
  The dashboard (Xore-Inc/apiary-dashboard, `src/server/oidc.server.ts`)
  reads client roles from `resource_access.<OIDC_CLIENT_ID>.roles`, i.e.
  `apiary-dashboard-rewrite`, and treats anything without `admin` as a
  viewer;
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
