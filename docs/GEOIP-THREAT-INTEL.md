# GeoIP and network intelligence

City/ASN geolocation runs entirely inside Elasticsearch now: the
`geoip-honeypot` ingest pipeline (`arcane/home/honeypot-init/analysis/elasticsearch-setup.sh`)
enriches every document at write time from native MaxMind GeoLite2 MMDB
databases mounted from `analysis/geoip/`:

- `GeoLite2-City.mmdb` — country, city, latitude/longitude and accuracy radius
- `GeoLite2-ASN.mmdb` — ASN and organization

Both IPv4 and IPv6 are supported. The same pipeline also classifies providers
(scanner, cloud, hosting, or network) into `source.as.type` from the ASN
organization name.

### source.ip promotion (#3560)

`source.ip` is normalized once, at write time, in the first script processor of
`geoip-honeypot`, so every `source.ip`-keyed view and aggregation sees the
attacker. Candidates are tried in order and the first **non-fleet** one wins:
an existing `source.ip`, `honeypot.src_ip`, then dionaea's
`honeypot.data.connection.remote_ip`, `honeypot.data.parent.remote_ip` and
`honeypot.data.child.remote_ip`. A fleet `src_ip` therefore never shadows a
public nested address.

"Fleet" mirrors `backend-service/src/events.rs::is_fleet_address`: loopback
(`127.0.0.0/8`, `::1`), unspecified, RFC1918, link-local, IPv6 unique-local and
the deployment's own addresses (`ES_HOME_NET` at pipeline install time,
`HONEYPOT_SELF_IPS` in the backend; keep the two lists equal). Read-time
(`attacker_ip`) and write-time therefore agree.

Resulting fields:

- `source.ip` is the promoted public address, or absent when only fleet
  addresses exist (never a fleet address).
- `honeypot.fleet_peer` keeps the fleet address that was passed over, or the
  one dropped when nothing public exists (the tunnel peer, loopback, ...).
- `tags: source_ip_promoted` is added when a `honeypot.*` address was promoted.
- `source.geo` / `source.as` are computed from the promoted `source.ip`, after
  the promotion.

What it cannot do: when `honeypot.src_ip` itself is the tunnel peer and no
public address exists anywhere in the document, there is nothing to promote
(the attacker was never recorded in that document); those events need the
upstream attribution (portbridge join / zeek-proxy) instead.

Install: re-run `arcane/home/honeypot-init/analysis/elasticsearch-setup.sh`
(idempotent `PUT`). Backfill of older documents:
`scripts/backfill-source-ip.sh --dry-run` (counts), then `--run` (throttled
`_update_by_query` with `pipeline=geoip-honeypot`, progress output). Tests:
`analysis/tests/test_geoip_pipeline.sh`.

### Threat-intel enrichment (`threat-cidrs.csv`, #244, #1659)

`analysis/threat-intel/threat-cidrs.csv` is `CIDR,label` pairs. Unlike the
MMDB lookups above, this isn't matched at ES ingest time — `backend-service`'s
`threat_intel.rs` worker loop (`WORKER_LOOPS=threat-intel`) polls it, matches
recently-seen source IPs against it, and writes a match onto the *same*
`source.as.type` field the ingest pipeline populates: intel always wins over
the plain provider class when both would apply, so every existing
`source.as.type` aggregation/filter/badge in the dashboard already shows intel
labels with no separate wiring.

When more than one entry matches the same address, the highest-severity label
wins regardless of file order (`threat_intel.rs`'s `category_rank`, ported
from the old Go dashboard's `intelCategoryRank`): `blocklist:*` (a
reputation-list hit) beats `tor-exit` (a real but not inherently malicious
signal) beats everything else, including the `cloud:aws`/`cloud:gcp` ground
truth and any custom label an operator adds. Ties (equal severity) go to the
more specific prefix.

Like `country.csv` and `.mmdb` files above, `threat-cidrs.csv` is generated
content and intentionally ignored by Git -- `threat-cidrs.csv.example` is the
tracked starter. Get real coverage one of two ways:

- Populate it by hand: `cp threat-cidrs.csv.example threat-cidrs.csv` and add
  your own entries.
- Run `./refresh-threat-cidrs.sh` (or enable the `threat-intel`
  Compose profile in `arcane/home/honeypot-init/compose.yml`, which runs it on a daily
  loop) to auto-populate it from Spamhaus DROP, the Tor bulk exit list, and
  AWS/GCP's published IP ranges -- all free, no signup required. It creates
  the file from `threat-cidrs.csv.example` on first run, and leaves any
  manually-added lines above its auto-fetched block untouched on every
  later run. AbuseIPDB (needs a registered API key) is intentionally not
  included; add it by hand if wanted.

A refresh reaches previously-tagged and newly-seen documents within the
worker's own reload/run interval (`threat_intel.rs`), no restart needed.

The deployed stack already works with manually supplied MMDB files. For official
automatic MaxMind updates, set `MAXMIND_ACCOUNT_ID` and
`MAXMIND_LICENSE_KEY` in the `honeypot-init` stack's `.env` (Arcane's stack
environment; Dockge was replaced by Arcane per
[#1185](https://github.com/Xore/APIARY/issues/1185)), then enable the optional
profile. `geoipupdate` is a service of the `honeypot-init` stack, which syncs to
`/opt/stacks/honeypot-init`, not to the `/opt/stacks/apiary` checkout the `.mmdb`
files themselves land in:

```bash
cd /opt/stacks/honeypot-init
docker compose -f compose.yml --profile geoip-update up -d geoipupdate
```

As a compatibility fallback, `country.csv` may contain one IPv4 range per line:

```csv
start_ip,end_ip,country_code
1.0.0.0,1.0.0.255,AU
```

The fallback does not provide city, coordinates, ASN, organization, or IPv6.
`country.csv` and downloaded `.mmdb` files are intentionally ignored by Git;
credentials and licensed/generated databases must not be committed.

The `.mmdb` files are read by three containers, so replacing one needs all
three restarted: `hp-elasticsearch` (the `ingest-geoip` mount the
`geoip-honeypot` processors read), and both Arkime containers —
`hp-arkime-capture` and `hp-arkime-viewer` (each mounts `/opt/arkime/geo`).
A fourth container, `hp-geoipupdate` in the `honeypot-init` stack, is the
writer, not a consumer.
`threat-cidrs.csv` is mounted read-only into the dashboard's `backend-worker`
container, so hand-editing it directly needs that one restarted. A
`threat-cidrs.csv` refreshed by `refresh-threat-cidrs.sh` is the one exception:
the running worker picks that up on its own reload interval (see above), no
restart needed. Geolocation is
approximate and must not be treated as proof of an attacker's physical
location.
