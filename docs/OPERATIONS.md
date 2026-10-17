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

- **Dashboard** (built in) → `https://honeypot.<domain>`, authenticated via
  its own native OIDC session against Keycloak directly (no gateway hop,
  unlike the investigation UIs below -- #1026). Live
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
  they fed the retired Go dashboard's server-side template; the Leaflet layer
  hardcodes both values outright (`frontend-next/src/components/
  OverviewPanels.tsx`), so there is no basemap env surface to set anymore.
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
  a transient notification. Browser API contracts live in
  `arcane/home/honeypot-dashboard/frontend-next`
  as strict TypeScript and compile to the committed, dependency-free production
  bundle, so Node.js is only a development tool and never part of the container.
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
