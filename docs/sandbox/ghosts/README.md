# GHOSTS host stack (#324)

Part of the GHOSTS tracking issue [#331](https://github.com/Xore/APIARY/issues/331)
(path decided on [#300](https://github.com/Xore/APIARY/issues/300)).
This is step one of that chain: get `Ghosts.Api` and its database running,
isolated from everything else this repo deploys. It does not touch the
network-isolation, golden-image, VM domain, spool, or timeline work — those
are #325-#330.

## What's deployed, and what isn't

`ghosts-postgres` + `ghosts-api` only, built from CMU SEI's
[`cmu-sei/GHOSTS`](https://github.com/cmu-sei/GHOSTS) source pinned to the
`v9.0.0` tag (no published images exist upstream, so the source is *vendored*
at `sandbox/ghosts/vendor/ghosts-src/` and `compose.yml` builds from that
local context through this repo's own `Dockerfile.api-prep`). It used to be a
remote git build context pointed straight at `src/`; that stopped working when
Arcane resolved build-context git refs under `refs/heads/` only, so #1506
vendored the tree instead — see that directory's `VENDORED.md`.

**Deliberately not deployed**: Frontend, Grafana, n8n. None of the three are
required for NPC-simulation (timeline-driven browsing/document/handler
activity) — they're operational tooling for GHOSTS' own primary use case
(live cyber-range exercise management). Add any of them later via a separate
compose overlay if a concrete need shows up; don't add them speculatively.
The Frontend in particular can likely stay skipped permanently if the
timeline is authored directly as a file and machine enrollment never needs
the web UI.

**Deliberately not folded into this repo's `docker-compose.yml`** — same
reasoning as CAPE's host-stack issue (#314): a full platform with its own
database and API blurs the trust boundary the rest of this stack keeps
narrow (dashboard container never touches Docker/libvirt/WinRM directly).

## Fixed address

`ghosts-api` publishes port 5000 on the libvirt `ghosts` network's *own gateway*
address, virbr-ghosts's `10.20.30.1` — not the docker-internal `10.90.0.2` an
earlier version of this file used:

```
GHOSTS_API_ADDR=10.20.30.1:5000
```

The first attempt gave `ghosts-api` only a static address on the dedicated
`ghosts_net` bridge (`10.90.0.2`) and published no host port. That is fine
host-locally — Docker routes user-defined bridges without any `-p` — but it
never reached the WAN-permitted GHOSTS guest: recent Docker versions add a
`raw` table PREROUTING rule (`ip daddr <container> iifname != <container's own
bridge> drop`) that blocks routing straight to a container's backend IP from any
other interface, regardless of what FORWARD/DOCKER-USER say, because Docker
expects cross-network reachability to go through a published port. Binding to
virbr-ghosts's gateway also means the guest needs no FORWARD-chain exception at
all: the traffic is local to its own default gateway, covered by
`network-filter.sh`'s ordinary bridge-gateway ACCEPT. Requires the `ghosts`
libvirt network (`network.xml`) to exist before this container starts, or Docker
cannot bind the address. Same "one fixed, documented address" pattern as
RevDeck's `REVDECK_API_BASE=http://10.8.0.2:19500`: pick the address once, up
front, specifically so later issues can write a one-line exception instead of a
floating rule.

`10.90.0.2` still exists — it remains `ghosts-api`'s static address on
`ghosts_net`, which is how the throwaway `ghosts-client-test` container resolves
the API by service name on the same bridge, and why `ghosts-postgres` is pinned
to `10.90.0.3` (Docker would otherwise hand `10.90.0.2` to the database first
and the API's explicit request would fail to start).

Don't change `10.20.30.1` without updating `network.xml` and
`network-filter.sh` to match, and without updating
`/etc/default/honeypot-ghosts` on the host (written by `install-host.sh`, read
by whatever #325/#328 add later).

## Deploy

```bash
sandbox/ghosts/install-host.sh
```

On a Dockge host this deploys `compose.yml` to `/opt/stacks/ghosts` (a copy —
edit the file here and re-run, don't edit it there) so the stack shows up as
one Dockge can start/stop/tail. It generates `.env` (`POSTGRES_PASSWORD`)
there on first run and never overwrites an existing one.

The first run does a full `dotnet publish` from source and takes a while.
Subsequent runs are cheap (Docker layer cache).

After bringing the containers up, it builds the same pinned source tree's
`Ghosts.Client.Universal`, runs it once on `ghosts_net` (where the client's
own default config resolves the API via the `ghosts-api` service name, no
override needed), and polls `/api/machines/list` for that machine to appear
before tearing the test container down. That's the "confirmed with a test
machine enrollment" bar from #324 — a real client registering through the
real API against the real database, not just an HTTP 200 from a health
endpoint.

```bash
sandbox/ghosts/install-host.sh --skip-enroll-test   # containers only
```

### Postgres major upgrade (16 -> 18, #3720)

`ghosts-postgres` runs `postgres:18.6-bookworm`, the same digest as Keycloak's
database. 18's image mounts the parent `/var/lib/postgresql` and keeps
`PGDATA` at `/var/lib/postgresql/18/docker`, and 16's on-disk format cannot be
opened by 18, so the stack uses a new volume, `ghosts_ghosts-postgres18-data`.
A host that still has the old `ghosts_ghosts-postgres-data` (16) volume keeps
it untouched; to carry its data over:

```bash
# 1. dump from 16 (old volume, read-only, throwaway container)
docker run -d --name ghosts-pg16-dump -e POSTGRES_PASSWORD=x \
  -v ghosts_ghosts-postgres-data:/var/lib/postgresql/data postgres:16.15
docker exec ghosts-pg16-dump pg_dumpall -U ghosts > ghosts-pg16.sql
docker rm -f ghosts-pg16-dump
# 2. bring the 18 database up empty, then restore
docker compose --project-directory /opt/stacks/ghosts up -d --wait ghosts-postgres
docker exec -i ghosts-ghosts-postgres-1 psql -q -U ghosts -d postgres < ghosts-pg16.sql
```

Rollback: point the image back at 16 and the volume back at
`ghosts-postgres-data:/var/lib/postgresql/data`; the old volume was never
written by 18.

## Network isolation as it actually stands (#325, #2444, #2257)

#325 has landed, so this is no longer a note to a future issue — it is the
shipped state, and the address paragraph above is written against it.

- The `ghosts` libvirt network is `network.xml`; `install-network.sh` plus
  `network-filter.sh` (unit `ghosts-network-filter.service`) are what put the
  WAN-facing guest behind the host's FORWARD DROP/ACCEPT pairs. It drops
  RFC1918 and LAN destinations generally while leaving DNS real, and
  `verify-network-isolation.sh` is the guest-side check.
- `ghosts-api` is reachable from the guest only through the published
  `10.20.30.1:5000`, and `network-filter.sh` additionally source-pins tcp/5000
  on virbr-ghosts to the enrolled clients listed in its `GHOSTS_API_CLIENTS`
  (today just `10.20.30.50/32`, `win11-ghosts`), so an unpinned guest fails
  closed at the firewall even for routes that do exist. Admitting a new client
  is deliberately a two-place change: a static `<host mac=... ip=.../>` entry
  in `network.xml` **and** an address in `GHOSTS_API_CLIENTS`.
- #2444 image-preps the route surface rather than trusting the upstream
  image: `Dockerfile.api-prep` deletes the animations control plane and the
  `/api/attack` scenario tooling (upstream operator tooling #324 excluded, and
  #2444 showed an unauthenticated guest could drive them — scheduled
  server-side GETs to any caller-supplied URL, ATT&CK-table wipe-and-reload),
  and patches Swagger's middleware out. What remains is the client
  enrollment/check-in plane plus machine inventory, timelines, surveys,
  results and the SignalR hubs.
- The API still has no authentication of any kind — this is the *accepted
  residual risk* #2257 wrote down, not an oversight. `appsettings.json`'s
  `InitSettings` block reads like a credentialed surface but is bound and then
  discarded by `ApiDetails.LoadConfiguration()`, so it gates nothing. #2257
  narrowed the blast radius (the deleted routes above, no anonymous endpoint
  map, `ASPNETCORE_ENVIRONMENT=Production` so no developer exception pages),
  not the auth model. A compromised ghost can still read and rewrite NPC state
  — notably `TimelinePartial` updates, which silently steer NPC behaviour and
  poison experiments built on it. Do not put anything on this API that a
  compromised guest must not read or forge.
