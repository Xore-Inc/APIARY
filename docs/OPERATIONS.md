# Operating the stack

[← back to README](../README.md)

Personas, the seeded cowrie filesystem, GeoIP enrichment, and how to actually
read the data once it's flowing.

## Persona inventory

Every sensor belongs to a stable fictional organization/site/asset identity in
[personas/personas.json](../personas/personas.json). Native sensors include these
fields in JSON; Filebeat enriches upstream logs that cannot. The dashboard makes
persona, site, and asset labels clickable so investigations can span protocols
without confusing defender-side identity with the attacker's ASN organization.
See [personas/README.md](personas/README.md) for the complete matrix and validator.

## Seeded filesystem (cowrie)

The fake shell is a believable in-use NexusAI GPU inference node, not an empty
box — realistic `/etc/passwd`, inference services, a credential-laden `.env`,
`.bash_history`, nginx/cron configs and logs (all fictional). Baked at build time; details in
[cowrie/README-fs.md](../arcane/home/honeypot-cowrie/cowrie/README-fs.md).

## GeoIP

The custom dashboard, Arkime, and Elasticsearch all share the same local
MaxMind GeoLite2 MMDB files under `analysis/geoip/`, kept current by the
`hp-geoipupdate` container (`docker compose -f compose.yml --profile
geoip-update up -d geoipupdate`, needs `MAXMIND_ACCOUNT_ID` /
`MAXMIND_LICENSE_KEY` in the honeypot-init stack's `.env`, managed by
Arcane). Dashboard lookups happen after
portbridge real-IP correlation, support IPv4/IPv6, and add country, city,
coordinates, accuracy radius, ASN, organization, and cloud/hosting/scanner
classification without sending attacker IPs to an external lookup API.

Two independent geo integrations, same source files:

- **Arkime** reads `analysis/geoip/GeoLite2-{Country,ASN}.mmdb`, mounted
  read-only into both capture and viewer at `/opt/arkime/geo` and configured
  via `geoLite2Country`/`geoLite2ASN` in
  [arkime/config.ini](../arcane/home/honeypot-elk/arkime/config.ini). Sessions
  get country + ASN. (#2713: this used to point at a separate,
  never-automated `arkime/geo/` directory populated by hand from db-ip.com —
  retired in favor of the same files everything else already uses.)
- **Elasticsearch** enriches every `suricata-*` and `honeypot-v2-*` event (and
  the portbridge, zeek, extracted-files, huginn and traefik families) through
  the `geoip-honeypot` ingest pipeline (set as `index.default_pipeline` on 8 of
  the init stack's 33 index templates), writing ECS `source.geo` / `source.as` / `destination.geo`
  with city-level lat/lon — this is what powers Kibana maps
  (`source.geo.location` is mapped as `geo_point`), from
  `GeoLite2-City.mmdb` mounted at
  `analysis/geoip/ → /usr/share/elasticsearch/config/ingest-geoip`, with
  `ingest.geoip.downloader.enabled=false` (ES's own auto-downloader needs
  egress the home server doesn't have).

The `.mmdb` files themselves are not in git; `hp-geoipupdate` refreshes them
on `GEOIPUPDATE_FREQUENCY` (hours) automatically once credentials are set —
no manual download/copy step.

> **Elasticsearch field limits:** Suricata's EVE output creates so many
> dynamic fields that the default 1000-field index cap breaks ingest — every
> event is 400-rejected and filebeat silently drops it (this bit us on
> 2026-07-19: Kibana "froze" while eve.json was fine). The `suricata-*`
> template raises the limit to 5000; stats live in their own event-type index.
> Honeypot source objects use a bounded `flattened` mapping.

## Analyse the data

The one-shot `honeypot-kibana-setup` job installs normalized honeypot,
Suricata, and dead-letter data views plus the **XORE Honeypot — enriched
investigation** dashboard. Panels cover recent attacks, OT personas,
commands/credentials, payloads, enriched IDS alerts, and ingest failures.

- **Dashboard** → `https://honeypot.<domain>`, served since 2026-10-30 by
  [Xore-Inc/apiary-dashboard](https://github.com/Xore-Inc/apiary-dashboard)
  (Arcane project `apiary-dashboard`; the in-repo `frontend-next` was removed
  in #3749). The feature notes below were written for frontend-next and
  describe the same backend views. Authenticated via its own native OIDC
  session against Keycloak directly (no gateway hop, unlike the investigation
  UIs below -- #1026). Live
  KPIs, feed-freshness states, per-sensor/protocol counts, top IPs/creds/commands,
  payload downloads, attack chains, and 7-day `/24`/`/64` campaign correlation
  scored across sensors, credentials, ports, IDS alerts, and payload hashes.
  The interface is organized as an operations console rather than a shortcut
  collection: task-based navigation separates monitoring, investigation, and the
  Elasticsearch archive. Four top-level overview tabs group live operations,
  the threat landscape, attacker behavior, and evidence/campaigns so only one
  workflow is visible at a time; the selected tab survives live refreshes.
  Every KPI and ranked value pivots directly into the relevant
  investigation, while explanatory labels make states and metrics usable
  without a separate legend. The responsive navigation becomes an accessible
  menu on narrow displays, and light, dark, and automatic themes remain
  available.
  The frontend follows the shared [**Xore/theme**](https://github.com/Xore/theme)
  design system (migration guide:
  [MIGRATE-HONEYPOT-STACK.md](https://github.com/Xore/theme/blob/main/docs/MIGRATE-HONEYPOT-STACK.md)):
  a semantic, server-rendered application shell (toolbar, sidebar, main
  canvas, command bar) styled only by the byte-identical vendored `theme.css`.
  APIARY does not carry a custom dashboard stylesheet; new selectors are
  implemented in `Xore/theme` and re-vendored. The theme and Leaflet are
  served from the dashboard binary rather than a JavaScript CDN.
  The fixed desktop sidebar becomes a compact rail and then an off-canvas
  navigation panel on narrow screens, while the 32px application toolbar keeps
  activity, health, and theme controls (dark, light, system) available across
  every investigation page.
  The command bar also routes IP addresses, payload hashes, session IDs, ASNs,
  HTTP paths, and free-text input directly to the appropriate investigation.
  Event results use server-side pagination (25 rows by default; `per_page`
  accepts 25–500).
  Every longer table and API-fed list initially displays 25 entries, then
  reveals the next 25 near the end of the page or through an accessible
  **Load 25 more** control. This also covers payloads, alerts, sandbox results,
  commands, source lists, and Elasticsearch dead letters. Payload, event, and
  attack-source rows are fetched from the server in 25-row chunks, avoiding
  large initial HTML responses even when an inventory contains thousands of
  records.
  Attacker profiles combine network enrichment, behavior aggregates, and a
  chronological progression view. `/sessions/<id>` provides an oldest-to-newest
  session replay, and both views add conservative MITRE ATT&CK Enterprise/ICS
  behavior mappings with links and explicit evidence (behavior context, never
  actor attribution). `/clusters` finds fingerprints, payloads, ASNs, and
  provider classes shared by multiple source IPs. Campaign rows now explain
  exactly which cross-sensor, credential, payload, alert, or fingerprint factors
  produced their correlation score. The navbar alert badge shows unacknowledged
  alert state, while source health uses neutral metric tiles for feeds,
  Elasticsearch, Filebeat, and dead letters.
  `/api/v1/campaigns` exposes the same correlation data. A balanced recent feed
  prevents one noisy sensor from hiding lower-volume sensors. The
  portbridge connection log is used only to recover real source IPs; it is not
  counted as a sensor or displayed as an event.
  The overview attack map uses the vendored Leaflet 1.9.4 client with a
  hardcoded OpenStreetMap raster basemap and GeoLite2 City/ASN coordinates
  from `/api/map-points`. Attack origins are geographic circles whose physical
  radius is weighted by event count, so their displayed size changes naturally
  with zoom. Hover shows IP/city/ASN/provider details and selecting a circle
  opens every event for that attacker. Live refreshes retain the Leaflet map DOM
  and update only its GeoJSON layer, preserving pan and zoom. If the map library
  or tiles fail, the current OpenStreetMap container remains visible with an
  availability message; there is no local basemap fallback.
  #2425: `HONEYPOT_MAP_TILE_URL` / `HONEYPOT_MAP_ATTRIBUTION` are gone --
  they fed the retired Go dashboard's server-side template, and the dashboard
  has no basemap env surface to set anymore.
  The hourly activity chart also exposes exact counts on hover/focus. The 24-hour
  KPI compares activity with the preceding 24 hours and labels large changes;
  source health reports dashboard process uptime and memory (RSS + virtual)
  as the runtime card on `/api/v1/source-health` — the Go heap/goroutine
  figures that card used to show have no Rust equivalent and are gone.
  Event metadata is directly pivotable: sessions, HASSH/JA3/JA4/User-Agent
  fingerprints, exact commands and credentials, HTTP paths, IDS signatures and
  categories, payload hashes, ASNs, organizations, and provider classes all
  open their related events. Source-health tail counts open normalized events;
  Elasticsearch source totals open a pre-populated historical query.
  Management-ready A4 PDF reports are available from the overview, alert
  center, campaign view, attacker profiles, sessions, and every filtered Event
  Explorer result. `/export/report.pdf` applies the same filters as Event
  Explorer, including source IP/CIDR, ASN, organization/provider, country,
  sensor, signature/category, payload, session, protocol/port, HTTP path,
  fingerprint, and time window. Reports contain an executive risk summary,
  ranked sources and indicators, operational alert state, recommendations, and
  a bounded representative-evidence appendix. Report downloads require the
  dashboard's own Keycloak-derived `admin` role because they contain hostile-source telemetry.
  The overview also ranks fingerprints, ASNs, and provider classes with the
  same one-click pivots.
  ASN/provider pivots,
  `/commands` session-aware command analysis, and `/payload-analysis/<hash>`
  with bounded hashes, entropy, hex, strings, PE/ELF and script classification,
  behavior indicators, packing likelihood, extracted URL/domain/IP indicators,
  real YARA rule matches from a networkless, read-only scanner, risk scoring, and
  Base64/hex/URL/PowerShell UTF-16 decoding. Payload inventory scans run in the
  background and refresh every two minutes, so walking large capture volumes
  cannot block `/payloads`; source filters and duplicate provenance are
  preserved. Download event rows link directly to the matching static report. `/history` adds
  Elasticsearch search/export; `/source-health` shows Filebeat/Elasticsearch
  diagnostics. Alerts have persistent cooldown/acknowledgment, live refresh uses
  SSE, and events pivot directly to Kibana, EveBox, Arkime, and VirusTotal.
  Event tables support keyboard-accessible sorting, selectable columns, and an
  expandable normalized-row JSON view; live events on investigation pages raise
  a transient notification. Browser API contracts live in apiary-dashboard
  (`src/data/contracts`), pinned against this repo's `openapi.json`.
- **Operational APIs** — `/metrics` exposes Prometheus text metrics for event,
  sensor, ingestion, Filebeat, runtime, dead-letter, and YARA health.
  `/dead-letters` investigates rejected Elasticsearch documents, and
  durable campaign/cluster snapshots in `dashboard-intelligence-archive-v1`
  are readable through the generic index-store route
  `/api/v1/store/intelligence` (there is no dedicated intelligence route
  in the Rust router).
  Alert acknowledgements and captured-malware downloads require the
  dashboard's own Keycloak-derived `admin` role.
- **Safe payload triage** — `yara-scanner` inventories all mounted Dionaea,
  Cowrie, and script captures without network access or execution. Its results
  enrich `/payloads`, static-analysis reports, risk scores, alerts, and health.
- **Backups** — run `sudo analysis/backup-honeypot.sh`; Elasticsearch uses its
  snapshot API and other named volumes are archived separately. Test and restore
  procedures are in [`docs/analysis/RECOVERY.md`](analysis/RECOVERY.md).
- **Kibana saved objects** (dashboards, visualizations, data views you build
  by hand) live only in Elasticsearch's Kibana saved-objects index — on this
  stack's Kibana 9.5.3 that is `.kibana_<n>`, not a bare `.kibana` — so an ES
  reset, migration, or upgrade loses them with no recovery path unless you've
  exported first. Run `analysis/kibana-export.sh` before any ES-affecting
  change (matching `KIBANA_URL` to how you reach Kibana — defaults to
  `http://kibana:5601`, the in-cluster address); restore with
  `analysis/kibana-import.sh`. **Export first, the same way you'd back up
  anything else you'd be upset to lose** — `backup-honeypot.sh` above
  doesn't cover these, only the raw Elasticsearch data.
- **Hard-isolated sandbox** — the optional [`sandbox/`](../sandbox/) host setup
  installs KVM/libvirt beside Docker, defines a non-forwarding network, disables
  libvirt's default NAT network, and uses disposable qcow2 overlays. It never
  mounts the Docker socket, host folders, or payloads into a running guest.
  The root-only hash resolver and serial systemd queue accept existing captures,
  deduplicate them by SHA-256, enforce guest/host deadlines, and export only
  bounded escaped JSON summaries to the dashboard's `/sandbox` investigation
  page. The view includes queue health, search, risk, timeout/duration, static
  versus dynamic evidence, ATT&CK behavior, Windows PE forensics, DNS
  query/response evidence, host and guest packet summaries, and sanitized JSON
  export. Content-based routing distinguishes PE executables, DLLs, VBS,
  JScript, batch, PowerShell, shell, Python, PHP, Node.js, ELF, documents,
  archives, and unknown data before selecting a static-only or type-specific
  detonation path. Optional headless Wine execution and allowlisted real-DNS/HTTP(S)
  forensic retrieval remain inside a freshly recreated VM and a host-enforced
  proxy boundary. Authenticated administrators can queue an existing
  captured hash with the payload **Analyze** button through a narrow host-owned
  request spool. Bounded host/guest PCAPs can be downloaded by administrators
  for Wireshark; complete traces, oversize captures, and direct queue control
  remain outside Docker. A libvirt NIC filter prevents MAC spoofing and
  unwanted L2 traffic.
- **analyze.py** — summarize the bind-mounted logs directly on the home server:
  ```bash
  python3 analysis/analyze.py /opt/stacks/apiary/logs --top 20
  ```
- **Kibana** → `https://kibana.<domain>` (Keycloak via the oauth2-proxy gateway). Data views already exist:
  `honeypot-v2-*` and `suricata-*` (time field `@timestamp`) plus
  `dead-letter-honeypot*`, alongside **Arkime
  Sessions** (`arkime_sessions3-*`, time field `lastPacket`). All suricata and
  honeypot events carry `source.geo` / `source.as` — build maps on
  `source.geo.location`. Arkime sessions have country + ASN only (GeoLite2
  Country has no coordinates).
- **Arkime** → `http://<HP_BIND>:19080` — full-packet session search over
  everything Suricata captured on the VPS.
- **TANNER dashboard** → `https://tanner.<domain>` (Keycloak via the oauth2-proxy gateway) — web-attack analysis.
- Dionaea/Conpot write their own JSON into the shared volume for jq/ELK; the
  live dashboard ingests them alongside Cowrie, multipot, HTTP, and Suricata.

## Service health contract (backend-service)

`apiary-backend` (the Rust tier behind every `/api/v1` route) answers two
different questions on two different endpoints. They used to be one endpoint
with a constant answer: `/healthz` returned `{"ok": true, "es": <bool>}`,
where `ok` was literally hardcoded to `true`, so a backend that could not
reach Elasticsearch at all still told its own healthcheck, and anything else
that probed it, that it was healthy. The `#3283` ingest outage would not have
appeared there. Split into:

| Endpoint | Question | Touches Elasticsearch | Non-200 |
|---|---|---|---|
| `/livez` | Is the process up and serving? | **No** | never |
| `/healthz` | Same handler as `/livez`, historical name | **No** | never |
| `/readyz` | Can it actually do its job? | Yes (2 probes) | 503 + `reason` |

```console
$ curl -s http://backend-service:8081/livez
{"live":true,"built":"2026-09-27T01:46:34+00:00","revision":"3dca4457f1b2c0d4e5a69788796a5b4c3d2e1f0ab"}

$ curl -s http://backend-service:8081/readyz
{"ready":true,"cluster":"green","write_blocked":[]}

$ curl -s -o /dev/null -w '%{http_code}\n' http://backend-service:8081/readyz   # during an ES outage
503
```

`/readyz` deliberately carries **no** `revision`: readiness is about whether
this process can do its job, which is a property of the running container and
not of a build, and the two questions have different answers during a rollback.
The revision belongs to the liveness body, which is the one every probe and
every ops script already reads.

**`/livez` is what the container `HEALTHCHECK` curls, and it must stay that
way.** A probe that can block on Elasticsearch converts that dependency's
outage into a restart loop of a container that was never the problem. The
image's own comment on the `HEALTHCHECK` line says this too. `/healthz` is
kept as an alias because the port-test harness
(`arcane/home/honeypot-dashboard/port-tests/lib.sh`) and the ops scripts
already use that name; it is a rename-with-a-twist, not a rename.

### What `/readyz` actually checks

1. **Reachable** — `GET /_cluster/health` answers. This is the check the old
   `es: <bool>` field gestured at; the difference is that failing it now
   produces a 503.
2. **Not red** — red means unassigned primaries, against which reads and
   writes both fail. **Yellow stays ready**: it means unassigned *replicas*,
   which is the ordinary shape of a replicated cluster during a rolling
   restart, and gating on it would mark the backend not-ready on every deploy.
3. **Writable** — no `index.blocks.write` set on any of the index families
   this tier writes to (the list is `es::WRITE_TARGET_FAMILIES` in
   `backend-service/src/es.rs`, `dashboard-*` plus the bundled worker loops'
   own families). This is what catches the flood-stage disk watermark, which
   sets the block on every index at once, and an operator's
   `PUT /<index>/_block/write`.

The response names the blocked indices rather than counting them, and the
`reason` string points at `_cat/allocation` because the endpoint **cannot
tell those two causes apart** — an honest limit, stated rather than papered
over. A *missing* index is not a block: every dashboard-owned index is created
lazily on its first write, so a fresh cluster correctly reads ready.

Both probes run concurrently under a 5s deadline
(`READINESS_TIMEOUT`), shorter than the shared client's 30s, because a probe
that blocks for 30s is indistinguishable from the outage it exists to report.

### What to point at what

- **Docker/compose healthcheck, Traefik, uptime pings** → `/livez` (or
  `/healthz`). Never `/readyz`; see above.
- **Deploy verification, diagnostics, "is ingest actually working?"** →
  `/readyz`, and treat 503 as a real answer, not a transport error. This is
  the endpoint that would have shown `#3283`.
- **"Why is the dashboard empty?"** → `/api/v1/source-health` (the
  per-sensor freshness page). `/readyz` says the backend cannot write; only
  source-health says whether events are arriving.
- **"Which commit is actually deployed?"** → `revision` on `/livez`, plus
  the image label. See below.

### Which revision is deployed (#3315)

The failure this exists for is the one `docs/ARCANE-GIT-SYNC.md` names
directly: a content-change redeploy leaves the dashboard **"green, healthy,
running the old code."** A fresh container id, a passing healthcheck and a
recent image build all say the machinery ran — none of them say this code is
what is running. So both dashboard images carry the git revision they were
built from, and `scripts/verify-deploy.sh` compares it against what you
expect.

**The contract, in one table.** Four surfaces, one value:

| Surface | Where | Read it with |
|---|---|---|
| Backend health body | `{"live":…,"built":…,"revision":…}` on `/livez` and `/healthz` | `curl -s …/healthz` |
| Backend boot log | `revision=…` on the `apiary-backend listening` line | `docker logs … \| grep listening` |
| Frontend static file | `/build.json` → `{"built":…,"revision":…,"source":…}` | `curl -s …/build.json` |
| Both images | `org.opencontainers.image.revision` (with `.source`, `.created`) | `docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' apiary-backend:latest` |

The health body and `build.json` are small enough to read unfiltered, so
there is nothing to parse here and nothing that needs `jq` — which is
deliberately absent from these hosts (`verify-deploy.sh` uses `python3` for
the same reason).

**Where the value comes from, and what `"unknown"` means.** `GIT_SHA` is a
Docker **build arg**, declared in both Dockerfiles and passed by the stacks'
compose files as `build.args.GIT_SHA: ${GIT_SHA:-}`. The backend compiles it
in (`build.rs` re-exports `GIT_SHA` as `APIARY_GIT_SHA`); the frontend writes
it into `public/build.json` before `npm run build`. Unset is normal and not
an error — you get the literal string `unknown`, never a fabricated revision,
because a plausible-looking wrong answer is worse than no answer. Both tiers
normalize to a bare lowercase hex object name (optional `sha256:` prefix
stripped, 7–64 hex chars) or `unknown`, and both are held to one shared table,
`backend-service/src/revision-corpus.json`, so the two normalizers — different
languages, different CI lanes — cannot drift.

`build.rs` also emits `cargo:rerun-if-env-changed=GIT_SHA`. That line is
load-bearing, not hygiene: cargo caches a build script's output by its inputs
and an environment variable is not one of them unless declared, so without it
the *second* build of an identical tree silently reports the *first* build's
revision — the exact failure this section exists to end, reproduced by the
stamp itself.

**Turning it on.** Nothing repo-tracked writes `GIT_SHA`; the stacks' `.env`
files are root-owned and provisioned outside this repository, and there is no
`.git` on the host to ask (`deploy.yml` rsyncs with `--exclude .git/`). So
the first run after this landed correctly reports **not stamped**. From a
clone you are deploying, one line per stack:

```console
echo "GIT_SHA=$(git rev-parse HEAD)" >> /var/dockge/stacks/honeypot-dashboard-backend/.env
echo "GIT_SHA=$(git rev-parse HEAD)" >> /var/dockge/stacks/honeypot-dashboard/.env
```

followed by the `POST /projects/{id}/build` that a content-change sync does
*not* do. CI (`.github/workflows/containers.yml`) passes `github.sha` for the
two Dockerfiles that declare the arg.

**Running the check.** `scripts/verify-deploy.sh` compares the live revision,
the image label, and an expected revision — which it takes from `origin/main`
in a real clone, or from an argument:

```console
# On a host with a clone of apiary, the full check:
scripts/verify-deploy.sh --healthz-exec \
  'docker exec hp-apiary-backend curl -sf http://127.0.0.1:8081/healthz' \
  --image apiary-backend:latest

# Without one, name the expected revision yourself:
scripts/verify-deploy.sh --behind-days 0 "$(git rev-parse origin/main)" \
  --healthz-exec 'docker exec hp-apiary-backend curl -sf http://127.0.0.1:8081/healthz'

# The frontend's form:
scripts/verify-deploy.sh --healthz-url http://host:19090/build.json
```

Exit codes are the point, and are deliberately three-valued: **0** the
deployed revision matches; **1** a finding (missing, unstamped, malformed, or
stale past `--behind-days`); **2** *could not tell* — an unreadable body or an
image that is not on this host. An unreadable answer must never read as a
stale deploy, which is why 2 is not 1. Add `--image` to check a label against
the running container, which catches the commoner variant where a
`compose up` recreated from an older image than the one whose label you just
read. The lag check measures the age of the *commit*, not of the container, so
it survives a container that has been up since before the merge it is missing
— but it needs a clone to measure against, hence `--behind-days 0` for the
clone-less form.

`diagnostics.yml` runs it in `--warn-only` mode in its own "Deployed
revision" section, against `$GITHUB_SHA`: the home runner has no clone to
measure against, so the section degrades to "is the running revision the
current tip of `main`" and says so in the report. Its exit 2 is still
reported as **could not tell**, not as a pass.

## Disk space monitoring

`hp-disk-space-monitor` (`arcane/home/honeypot-utilities/analysis/disk-space-check.sh`)
polls `df` on the bind-mounted host paths in `DISK_CHECK_PATHS` (default:
`honeypot-logs=/logs:honeypot-state=/state:dionaea-payloads=/dionaea-lib`)
plus Elasticsearch's own data volume over HTTP (`_cat/allocation`), and
writes a warning line to `/logs/diagnostics/disk-space.json` whenever a
checked filesystem's free space drops below `DISK_WARN_PERCENT_FREE`
(default 15%). Filebeat ships those lines under
`event.module:disk-space-check`.

**#2707: alerts are grouped by physical filesystem, not by bind-mounted
path.** `honeypot-logs` (`/logs`) and `honeypot-state` (`/state`) are both
bind-mounts of the same host directory tree
(`/opt/stacks/apiary` on the home server), so a low-free-space condition on
that one filesystem used to fire one near-identical WARNING line per bind
mount. The monitor now reads the backing device from `df -Pk`'s first
column, groups every checked path that shares a device into a single
alert, and names the largest of the grouped paths (by `du`) as
`top_contributor` so a real spike points straight at a directory instead
of leaving an operator to compare N identical percentages by hand. Shape:

```json
{
  "@timestamp": "2026-08-30T12:00:00Z",
  "event": {"module": "disk-space-check", "category": "host"},
  "disk": {
    "source": "/dev/sda1",
    "labels": "honeypot-logs,honeypot-state",
    "percent_free": 8,
    "available_kb": 1234567,
    "total_kb": 20000000,
    "top_contributor": {"label": "honeypot-logs", "path": "/logs", "used_kb": 15000000}
  },
  "level": "warning"
}
```

`elasticsearch-data` alerts (from `_cat/allocation`, since `es-data` is a
stack-private volume never bind-mounted cross-stack) are unaffected --
there is only ever one of them per check.

## Pausing decoys to free host CPU (#3135)

When a benchmark or training leg needs more headroom than the homeserver has,
pause the decoy stacks, run the leg, resume them afterwards. The
classification and the command list both live in
[`scripts/honeypot-pause.sh`](../scripts/honeypot-pause.sh) — this section is
the reasoning behind the table it carries, and the two measured facts that
make the procedure different from a one-liner.

```bash
scripts/honeypot-pause.sh list                          # the table, with reasons
scripts/honeypot-pause.sh pause honeypot-elasticpot     # pause (gate first)
scripts/honeypot-pause.sh status                        # what is paused, in order
scripts/honeypot-pause.sh resume                        # reverse order, verified
```

### Read this before you expect it to free RAM

**`docker pause` frees CPU, not RAM.** The issue says "free RAM/CPU"; only
the CPU half is true. Measured on 2026-09-27, cgroup v2 `memory.current` for
`hp-elasticpot` was `36,339,712` B running and `36,360,192` B while paused —
it went *up* 20 KiB. `docker pause` freezes the cgroup (the kernel stops
scheduling its tasks) but keeps the memory charged to it. For real RAM you
want `docker stop`, which is a different and more destructive operation: it
tears down the container, so in-container state and live sessions are gone
unless they are on a volume. This script does **not** substitute `stop` for
`pause` — the issue specifies `pause`, and silently substituting a more
destructive call is not a call this script gets to make on its own. If a leg
is genuinely RAM-bound, that is a separate decision with its own rollback.

So the honest summary of what a pause buys you: CPU scheduling, and the
*appearance* of a dark decoy. On a CPU-starved leg that is real. On a
RAM-starved leg it is close to nothing.

### Where `autoheal=true` actually does something (#3578)

The label restarts nothing by itself. It is read by an autoheal container
(`willfarrell/autoheal`) that polls the Docker daemon it is attached to, so it
only covers containers on that one host:

| Host | Autoheal | State |
|---|---|---|
| homeserver | `hp-autoheal`, defined in `arcane/home/honeypot-utilities/compose.yml` | Not running at the 2026-10-10 check: the container was removed, so every `autoheal=true` label on the host was inert (#3585, #3658). Recreate it only after the dionaea health check is fixed, or it will restart dionaea in a loop. |
| VPS | `autoheal` in `vps/docker-compose.yml`, behind a docker-socket-proxy (#2762) | Part of the VPS compose project. |
| precision | none | Labels on a service deployed there do nothing until an autoheal or a swarm `restart_policy` exists there (#3583). |

A new label on a host without an autoheal container gives a service that stays
`unhealthy` forever, so check `docker ps --filter name=autoheal` on that host
before relying on it. Autoheal also only reacts to the container's own health
status: a service whose check fails because a remote dependency is down will be
restarted too, so keep health checks local to the container.

The longer-term plan replaces the label with swarm `restart_policy` once the
hosts form one swarm (#3587, #3585); until then autoheal is per host.

### Why `hp-autoheal` is paused first and resumed last

This is the part that will bite you if you improvise. Every decoy on this
host carries the label `autoheal=true`, and `hp-autoheal` polls every
`AUTOHEAL_INTERVAL=30` seconds. A paused container's healthcheck exec cannot
complete, so Docker marks it `unhealthy` and autoheal `docker restart`s it —
which unpauses it. Measured on 2026-09-27, pausing `hp-elasticpot` at
`18:12:21Z` produced this in `docker logs hp-autoheal`:

```
18:12:38 Container /hp-elasticpot (4c07ab37c137) found to be unhealthy - Restarting container now with 10s timeout
```

Seventeen seconds later the decoy was running again, `docker ps` showed a
normal `Up`, and `RestartCount` was still `0` — a `docker restart` is not a
policy restart, so nothing in the container's own bookkeeping says anything
happened. **A naive pause is a ~30-second no-op that leaves the operator
believing a decoy is dark when it is not.** That is worse than an honest
outage, so `pause` shuts `hp-autoheal` down first and `resume` brings it back
last, after every decoy has been probed healthy again.

### The classification

Default-**deny**: a stack not in this table cannot be paused at all, and the
refusal prints the reason. The wrong "safe" does not fail loudly — it
silently breaks a decoy that was carrying the honeypot surface.

The test applied to each container, in order:

1. **Is it a decoy?** A sensor whose only job is to answer an attacker. A
   pipeline stage, a datastore, an orchestrator or an operator surface is not
   a decoy, however much RAM it holds.
2. **Does it hold a listener or capture path?** Pausing a listener does not
   refuse connections — the kernel keeps the socket and the SYN is queued, so
   a client *hangs* until it times out. For a decoy that is the intended
   dark. For anything in front of a capture path it is silent data loss.
3. **Does anything depend on it?** Shared state, a FUSE mount, an internal
   datastore. A partial pause hangs a live session instead of ending it
   cleanly, so these go as a whole stack.
4. **Is it a worker anything waits on, or an active test's fixture?** No.
5. **Is it a GPU, training or eval leg?** Never — those are the reason for
   pausing, not a target of it.

#### Pause-safe

| Stack | Containers | Verdict | Reason |
| --- | --- | --- | --- |
| `honeypot-elasticpot` | `hp-elasticpot` | safe | Standalone Elasticsearch decoy, no dependents, no shared state. Single container, so no in-flight session to strand. |
| `honeypot-multipot` | `hp-multipot` | safe | pop3/imap/socks/dockerv2/tls/adb/redis/elastic decoy, no dependents, no upstream. |
| `honeypot-dicompot` | `hp-dicompot` | safe | Standalone DICOM decoy, no dependents. |
| `honeypot-dnp3` | `hp-dnp3` | safe | Standalone DNP3 decoy, no dependents. |
| `honeypot-sentrypeer` | `hp-sentrypeer` | safe | Standalone SIP decoy, no dependents. |
| `honeypot-hellpot` | `hp-hellpot` | safe | Standalone SMTP/HTTP/FTP decoy, no dependents. |
| `honeypot-endlessh` | `hp-endlessh` | safe | Standalone SSH tarpit. Long-lived tarpit sessions are abandoned, which is the intended dark. |
| `honeypot-rdp-honeypot` | `hp-rdp-honeypot` | safe | Standalone RDP decoy, no dependents. |
| `honeypot-cisco-asa-honeypot` | `hp-cisco-asa-honeypot` | safe | Standalone ASA decoy, no dependents. |
| `honeypot-sonicwall-sma-honeypot` | `hp-sonicwall-sma-honeypot` | safe | Standalone SMA decoy, no dependents. |
| `honeypot-citrix-honeypot` | `hp-citrix-honeypot` | safe | Standalone Citrix decoy, no dependents. |
| `honeypot-mailoney` | `hp-mailoney` | safe | Standalone SMTP decoy, no dependents. |
| `honeypot-beelzebub` | `hp-beelzebub` | safe | Standalone adaptive SSH/HTTP/MCP decoy. It hosts an MCP endpoint; pausing it is a deliberate dark, not a defect. |

#### Pause-safe only as a whole stack

These have a real dependency on each other. Pausing half of one hangs a live
session rather than ending it cleanly, so the script refuses to pause a
partial set — it takes the named stacks whole, in dependency order.

| Stack | Containers (pause order) | Reason |
| --- | --- | --- |
| `honeypot-conpot` | `hp-conpot`, `hp-conpot-guardian`, `hp-conpot-s7-1500`, `hp-conpot-s7-1200`, `hp-conpot-iec104`, `hp-conpot-kamstrup` | Six OT decoys sharing an image and a project. `hp-conpot` is the shared modbus/s7 front and the rest are peers on it, so a partial pause leaves listeners up with no engine behind them. |
| `honeypot-cowrie` | `hp-cowrie`, `hp-honeyfs-implant` | `hp-honeyfs-implant` is the FUSE server serving cowrie's fake filesystem. Freezing the implant alone hangs every filesystem operation inside a live session. Resume implant first, cowrie second. |
| `honeypot-dionaea` | `hp-dionaea`, `hp-tftp-relay` | The largest single decoy (~369 MiB, ~14% CPU) and the one most worth pausing. `hp-tftp-relay` is stack-internal, and dionaea holds an internal MySQL plus live sessions. Never dionaea alone. |
| `honeypot-galah` | `hp-galah`, `hp-galah-llm-broker` | `hp-galah` proxies its LLM calls through the broker. Freezing the broker alone makes galah's own decoy paths fail in a way that looks like a *broken* decoy rather than a stand-down. |
| `honeypot-canarytokens` | `hp-canarytokens-http-router`, `-frontend`, `-adapter`, `-switchboard`, `-redis` | Internal chain router → adapter → switchboard → redis. A partial pause leaves the switchboard blocked on a frozen redis. |

#### Never pause

| Stack | Containers | Reason |
| --- | --- | --- |
| `honeypot-elk` | `hp-elasticsearch`, `hp-filebeat`, `hp-zeek-proxy`, `hp-arkime-capture`, `hp-arkime-viewer`, `hp-kibana`, `hp-evebox`, `hp-pcap-sync`, `hp-extracted-file-importer` | The capture pipeline. Freezing `arkime-capture`/`zeek-proxy`/`pcap-sync` stops packet capture at the point of arrival — silent data loss. Freezing `hp-elasticsearch` stalls every sensor's event write. Not a decoy; it is what makes the decoys worth running. Highest single allocation on the host (~10.6 GiB) and the least safe to interrupt. |
| `apiary-dashboard` | `hp-apiary-dashboard`, `hp-apiary-dashboard-oidc-sessions` | The operator surface (Xore-Inc/apiary-dashboard). A frozen dashboard means you cannot observe the stand-down you are performing — which defeats the point of recording it. |
| `honeypot-dashboard` | `hp-apiary-backend-mounted` | The mounted write API (analyzer submissions, Workbench). Freezing it makes every submission hang instead of failing cleanly. |
| `honeypot-backend-workers` | `hp-apiary-worker`, `-worker-enrichment`, `-worker-importer`, `-worker-payload-inventory`, `hp-services-adapter` | The ES write consumers and the service-control adapter (#3575). Freezing the workers buffers Elasticsearch bulk queues; a frozen adapter makes every service action hang. |
| `honeypot-dashboard-backend` | `hp-apiary-backend` | Auth and API surface. A frozen backend fails every dashboard and CLI call with a hang, not a clean error. |
| `honeypot-keycloak` | `hp-keycloak`, `hp-keycloak-postgres` | Identity tier. Dashboard, Arcane and the OIDC login tests all authenticate through it. |
| `honeypot-arcane` | `hp-arcane` | GitOps control plane — the container that would *re-create* a paused decoy on its next sync, so freezing it is arguably necessary. But it is also what reconciles the fleet, and a control plane held frozen across a long leg cannot report or repair drift. Reconcile first, pause decoys, do not freeze the orchestrator. |
| `honeypot-utilities` | `hp-docker-socket-proxy`, `hp-disk-space-monitor`, `hp-docker-hygiene`, `hp-log-maintenance`, `hp-reporter` | Host watchdogs. Freezing the disk and hygiene monitors during exactly the memory-hungry leg they exist to catch removes the guard against the failure you are creating. `hp-docker-socket-proxy` is also the socket autoheal drives. |
| `honeypot-tanner` | `hp-tanner`, `hp-tanner-api`, `hp-tanner-web`, `hp-tanner-redis`, `hp-tanner-docker`, `hp-tanner-phpox`, `hp-snare` | Event sink, not a decoy. cowrie and dionaea POST events here, so freezing it makes live sensors error on their own event path, and `hp-tanner-redis` holds session state in flight. Analysis of collected events is exactly what a leg must not interrupt. |
| `honeypot-payload-analysis` | `hp-yara-scanner`, `hp-payload-dedupe` | Downstream payload analysis fed from Elasticsearch. Not a decoy and holds no listener, but it is a pipeline stage and freezing it mid-file leaves partial state. |
| `honeypot-init` | `hp-geoipupdate`, `hp-threat-cidrs-refresh` | Periodic updaters. Freezing `hp-geoipupdate` mid-write can leave a truncated GeoIP database, which then fails every enrichment silently. |
| `ml-worker` | `hp-ml-worker` | Named in the cold protocol's `LIVE_WORKERS`. The cold-run mechanism governs this container via `STOP_WORKERS=1` + trap; pausing it here would create a second, unreconciled source of truth for whether it is running. |
| `auth-events-worker` | `hp-auth-events-worker` | Consumes Keycloak auth-failure events. Freezing it drops the signal that tier exists to capture. |
| `ghidra` | `ghidra-ollama-1`, `ghidra-revdeck-1`, `ghidra-statictools-1`, `ghidra-ghidra-1` | **Hard prohibition.** `ghidra-ollama-1` is the GPU slot holder, named explicitly in #3135: never pause it while a benchmark holds the GPU. `ghidra-revdeck-1` is in the cold protocol's `LIVE_WORKERS`. These are also the containers a leg runs to make room *for*. |
| `unsloth` | `hp-unsloth-studio` | The training leg itself — the reason for pausing, not a target of it. |
| `rex86-eval` | `rex86-eval` | The eval leg itself, same reasoning. |
| `technitium` | `technitium-dns` | Real recursive DNS for `192.168.42.50`, not a decoy. A frozen resolver takes the host's name resolution with it. |
| `pentagi` | `graphiti`, `neo4j`, `pentagi`, `pgvector`, `pentagi-ollama-embedding`, `pgexporter`, `scraper` | Unrelated product stack, not part of the honeypot. Out of scope. |
| `ghosts` | `ghosts-ghosts-api-1`, `ghosts-ghosts-postgres-1` | Belongs to the sandbox isolation stack that #3312 audits. Standing that down is a separate, declared act (`scripts/sandbox-standdown.sh`), not a decoy pause. |
| `dashkcnext-dashkcchaos` | `dashkcnext-{pg,kc,redis}-414734`, `dashkcchaos-{pg,kc,redis}-404812` | OIDC chaos-test fixtures — these **are** an active test. "Depended on by an active test" is an explicit not-pause-safe condition in #3135. |

The `pentagi-terminal-*` containers and the buildkit builder carry no compose
project label and are out of scope for this table; none is a decoy.

### Procedure

**Pause**

1. Confirm nothing in the cold-run protocol is running. `pause` refuses on
   its own (`pgrep` over `sweep_extra.sh`, `record_baseline.py`,
   `round7_sweep.sh`, `coldrun.sh`, `round7_coldrun.sh` — the same guard
   `coldrun.sh` uses to avoid double-booking the GPU), but the refusal is
   worth reading rather than working around.
2. `scripts/honeypot-pause.sh pause <stack> [stack...]`
3. The script pauses `hp-autoheal` first, then each stack in dependency
   order, and records every container in `APIARY_PAUSE_DIR/inventory`
   (default `/var/lib/apiary/honeypot-pause/`) plus an append-only
   what-and-when line in `record.log` next to it.
4. `scripts/honeypot-pause.sh status` — what is paused, in pause order.

**Resume**

5. `scripts/honeypot-pause.sh resume` walks the inventory in
   **strict reverse order**. For each container it unpauses, waits for the
   healthcheck to return to `healthy` *before* releasing `hp-autoheal` (so
   autoheal cannot restart it mid-verification), then makes **one real probe
   request** at the decoy's own port: a completed TCP connect, or an HTTP
   request that must come back `200` with a body.
6. Any container that does not verify keeps the inventory on disk and exits
   non-zero. Do not treat the leg as clean until they answer.

**Verify by hand** (the two things the script does, if you are checking):

```bash
docker ps --filter status=paused            # should be empty when resumed
docker ps --filter name=hp-elasticpot        # status, including (healthy)
curl -s -o /dev/null -w '%{http_code}\n' http://10.8.0.2:9201/   # expect 200
docker logs --since 5m hp-autoheal           # expect no "found to be unhealthy"
```

A paused decoy **hangs** rather than refusing: the kernel keeps the listening
socket and queues the SYN, so `curl` exits `28` (timeout), not `7`
(connection refused). Expect the timeout, and do not read it as a decoy that
is wedged differently from how you paused it.

### Dry-run evidence (2026-09-27)

Recorded here rather than only in a PR, because the next person to run this
will want to know what has actually been executed against the live host.

**Proven on the live homeserver, on the real `honeypot-elasticpot` stack** —
pause → probe stops answering → unpause → probe answers again:

| Step | Observed |
| --- | --- |
| Baseline | `Up (healthy)`, probe `HTTP 200`, 339 bytes of decoy ES (`"name": "Green Goblin"`) |
| Naive pause (no gate) | Paused, probe `HTTP 000` / `curl` exit `28`; **autoheal restored it 17s later** — see above |
| Pause with the autoheal gate | Held `Paused` through 100s (3+ `AUTOHEAL_INTERVAL`s), `State.Health=unhealthy`, autoheal silent |
| cgroup memory across the pause | `36,339,712` B running → `36,360,192` B paused — **no memory released** |
| Reverse-order resume | Unpaused, health `unhealthy` → `healthy` at t+35s |
| Probe after resume | `HTTP 200`, 339 bytes, **byte-identical to baseline** (`cmp` clean) |
| After autoheal released last | Both healthy, no restart in `docker logs hp-autoheal` |

The resume path was additionally exercised for real against throwaway
containers (never decoys, never autoheal, never the GPU leg): an inventory of
`a,b` was walked as `b,a`; a genuinely paused container was unpaused and
returned to `healthy`; and a container that could not return to `healthy`
produced `WARN`, exit `1`, and **kept its inventory for retry** rather than
reporting a clean leg.

**Not yet proven end to end:** a full script-driven `pause` → `resume` on a
live decoy. The attempt was correctly *refused* — a benchmark was holding the
GPU slot at the time (`record_baseline.py`, 8h in, 18.4 GB resident in
`ghidra-ollama-1`), and the interlock fired:

```
ABORT: cold-run protocol is active (matched 'record_baseline.py').
```

That refusal is the interlock working, not a gap in it. The consequence to be
honest about is narrower: the script's own `pause` path has not yet been run
end to end against a decoy, so the first operator to use it after the GPU slot
frees should expect to watch it once rather than treat it as battle-tested.
The measurements above were taken with the same `docker pause`/`unpause` calls
the script makes, on the same host, against the same stack.

### Scope boundary: this does not touch the cold-run protocol

Stop-workers-during-cold-run stays governed by `STOP_WORKERS=1` and the
restore trap in `analysis/ghidra/benchmarks/corpus/sweep_extra.sh`. That
mechanism is unchanged by #3135, and `honeypot-pause.sh` does not stop,
start, or otherwise manage a worker. It only refuses to run while a cold-run
pattern is live, so that ad-hoc pausing cannot become a second, competing
record of which workers are down.

### The Galah broker and a saturated Ollama (#3666)

`honeypot-galah` is already pause-safe as a unit (`hp-galah` + `hp-galah-llm-broker`
above). What the pause does not do is drain Ollama. Requests that galah already
forwarded sit in Ollama's own queue, and a client that disconnects does not
shorten it: in the incident behind #3666 Ollama logged three requests as `499` after
10h42m, 10h48m and 27m, long after galah and the broker had logged `context
canceled`. The broker's `UPSTREAM_TIMEOUT_SECONDS` cannot help for the same reason.

Two complementary limits now keep honeypot traffic from queueing behind a benchmark:

- **Broker, `MAX_INFLIGHT` (default 4, `GALAH_BROKER_MAX_INFLIGHT` in the compose
  file; 0 disables).** When every slot is taken the broker answers `503`
  immediately and logs `saturated, refusing with 503`. A cancelled client releases
  its slot and cancels the upstream call. galah turns the 503 into a
  `failedResponse`, which is indexed as an event with
  `honeypot.response_outcome: llm_failed`, so the refusals are counted, not lost.
- **Ollama, `OLLAMA_MAX_QUEUE`.** Ollama itself rejects requests beyond this queue
  depth with a 503. Set it on the Ollama service when you start a benchmark leg;
  it is not set by this repository's compose files, because Ollama is shared with
  the leg and is not changed by the pause procedure.

Procedure additions for a leg that holds the GPU:

1. Before pausing, check that nothing is already queued: `docker logs --since 10m
   hp-galah-llm-broker | grep -c saturated` and the Ollama log for pending
   requests. A queue that already exists is not emptied by pausing galah.
2. Pause `honeypot-galah` as a whole stack (`scripts/honeypot-pause.sh pause
   honeypot-galah`); the broker is in the unit. If galah is left running during a
   leg instead, rely on the two limits above and expect `llm_failed` events.
3. For the swarm form of the broker (`galah-broker`, #3591/#3639), the stack file
   needs the same `MAX_INFLIGHT` environment variable and its own
   `apiary.pause` labels; `ops/swarm/stackctl.py pause` handles it as a unit.
   `scripts/honeypot-pause.sh` needs no change for compose: its `honeypot-galah`
   row already lists both containers.

### Swarm stacks: scale to 0, not `docker pause` (#3590)

Stacks that have moved to Docker Swarm (`swarm/stacks/<name>/`, epic #3587)
are not paused by `honeypot-pause.sh`, which refuses them by name. A frozen
swarm task fails its healthcheck and swarm replaces it, the same silent
un-pause autoheal causes on compose. They are scaled to 0 through Arcane
instead:

```bash
ops/swarm/stackctl.py pause <stack> [stack...]   # gate first, then scale to 0
ops/swarm/stackctl.py pause-status               # what is recorded
ops/swarm/stackctl.py resume                     # reverse order, verified, gate last
```

The differences from the compose procedure:
- **Classification lives in the stack file.** Each service has `deploy.labels`
  `apiary.pause: safe|unit|never` plus `apiary.pause.reason`. The default is
  deny: a missing label fails the stack lint, and `pause` refuses the stack.
  The pause unit is the whole stack, ordered by an optional
  `apiary.pause.order`. `apiary.probe: tcp:PORT|http:PORT/path` is the resume probe.
- **Scaling to 0 stops the tasks, so it frees RAM as well as CPU**, unlike `docker pause`.
- **The gate is the stack's Arcane GitOps sync, not autoheal.** Every sync
  run redeploys the stack file's replica count. `pause` turns the sync's
  `autoSync` off first and `resume` restores it last. A run already in
  flight is not stopped by that, and turning `autoSync` on starts one at
  once (seen live), so `pause` keeps re-asserting 0 until the services stay
  there for 45 s. `stackctl.py deploy` refuses a paused stack.
- **Same interlock:** `pause` refuses while a cold-run pattern runs on the homeserver.

Drain is the node-level alternative: `docker node update --availability drain
NODE` moves every task off a node at once, including services classified
`never`. Use it only for node maintenance ([ops/swarm runbook](../ops/swarm/README.md#runbook-node-maintenance-drain--work--active)),
never as a way to make room for a benchmark leg.
