# Rebuilding the stack from scratch

[← back to README](../README.md)

A runbook for a **deliberate full reset**: every Arcane-managed stack (home) and the
plain-Compose VPS stack stopped, every honeypot-owned volume and log wiped,
everything brought back up cold. Different from
[`docs/analysis/RECOVERY.md`](analysis/RECOVERY.md), which restores a backup
archive onto a *replacement* host — this is for the *same* hosts, on purpose,
usually after a schema/volume-layout change or when historical data is no
longer worth keeping.

**If `/var` itself was lost** (the filesystem under `/var/dockge/stacks`,
Docker data and Arcane state is gone, not deliberately wiped), this is the
wrong page: start at
[`HOMESERVER-VAR-RECOVERY.md`](HOMESERVER-VAR-RECOVERY.md). It restores from
the essentials archive first and uses Arcane, not the `docker compose` loops
below. The traps below still apply to it.

[`../factory-reset.sh`](../factory-reset.sh) (see [`RECOVERY.md`](RECOVERY.md))
automates the homeserver-side steps below (stop, back up via
`analysis/backup-honeypot.sh`, optionally wipe, restart) as one command. This
doc remains the source of truth for *why* each step exists and the ordering
traps hit on the first live run — read it before trusting the script blind,
and definitely before doing any of this by hand on the VPS side, which the
script doesn't touch.

Since #258 split the stack into independent Arcane-managed projects
(`honeypot-init`, `honeypot-conpot`, `honeypot-cowrie`, `honeypot-multipot`,
`honeypot-http`, `honeypot-dnp3`, `honeypot-dionaea`, `honeypot-dicompot`,
`honeypot-dns-honeypot`, `honeypot-citrix-honeypot`, `honeypot-cisco-asa-honeypot`,
`honeypot-rdp-honeypot`, `honeypot-endlessh`,
`honeypot-payload-analysis`, `honeypot-tanner`, `honeypot-elk`,
`honeypot-dashboard`, `honeypot-utilities`, plus the then-empty
`APIARY`), a full reset is no longer "stop the stack, `docker compose
down -v`, start it again" — it's an ordered sequence across projects with a
couple of real circular-dependency traps. That 19-project list was
accurate for the day; the fleet is now **33 manifest entries under
`arcane/home/`**, and the two loops below are written against the full
current set rather than that original nineteen. This doc exists because
the first live run of this sequence (2026-08-02) hit three of them.

`honeypot-keycloak` (the identity stack, `docs/KEYCLOAK-OPERATIONS.md`)
is intentionally handled separately below rather than folded into the
`honeypot-*` list above: it deploys to `/var/dockge/stacks/honeypot-keycloak`,
not `/opt/stacks/$s` like every other split stack, and its Postgres volume
holds identity data (accounts, sessions) that a routine full reset should
not touch by default.

## What survives, what doesn't

**Preserved, never touched:**
- Every stack's `.env` file
- VPS `traefik/certs/` and `traefik/dynamic.yml` (never blind-overwrite these —
  see the standing rule; certs can't be trivially reissued, `dynamic.yml`
  carries the real domain)
- `suricata-rules` (VPS) and `portbridge-blackhole` (VPS) — rule/blocklist
  state, not event data
- `state/personas/applied.json` — persona-apply is idempotent and re-verifies
  it, not something a reset needs to force
- `honeypot-keycloak`'s Postgres volume (identity data: accounts, sessions,
  realm state) — a routine full reset of the honeypot/sensor stack has no
  reason to also destroy every operator's account and force re-bootstrapping
  Keycloak from scratch. If identity data genuinely needs wiping too, that's
  a separate, deliberate decision -- follow
  `docs/KEYCLOAK-OPERATIONS.md`'s own "Upgrade and rebuild procedure" (§7)
  clean-rebuild steps instead of folding it into this reset.
- Unrelated services sharing the same hosts (other tenants' `socat-*`
  forwarders, other Compose projects entirely — a full-reset instruction
  scopes to APIARY, never to everything running on the box)

**Wiped:** every honeypot-owned Docker volume (`es-data`, `dionaea-lib`,
`dashboard-state`, `yara-results`, `evebox-config`, `arkime-pcap`,
`snare-pages`, `reporter-data`, and any orphaned pre-split leftovers still
named `APIARY_*`), every log directory under
`logs/`, `state/filebeat` (Filebeat's read-offset registry),
`state/dedupe` (payload-dedupe's hash cache), `state/init-markers` (forces
every one-shot bootstrap job in `honeypot-init` to rerun), and on the VPS,
`logs/suricata/*` and `logs/portbridge/*`.

## Order of operations

### 1. Stop the VPS side first

Do this **before** touching the homeserver's Arkime pipeline. Arkime consumes
PCAP files that arrive over an sshfs mount from the VPS's Suricata; if you
reset the VPS *after* Arkime is already back up and ingesting, it ends up
mixing pre-reset and post-reset capture files into the same session data —
confusing at best.

```bash
ssh vps
docker stop hp-suricata hp-suricata-rules-refresh hp-suricata-log-maintenance \
  hp-portbridge hp-portbridge-log-maintenance \
  hp-portbridge-blackhole-refresh hp-p0f
sudo find /opt/stacks/apiary/logs/suricata -mindepth 1 -delete
sudo find /opt/stacks/apiary/logs/portbridge -mindepth 1 -delete
```

### 2. Stop and wipe the homeserver

```bash
ssh homeserver
# Every Arcane-managed stack under arcane/home/ except honeypot-keycloak:
# 32 of the manifest's 33, derived as
# `git ls-files arcane/home | cut -d/ -f3 | sort -u` minus
# honeypot-keycloak (handled separately) and rex86-eval (never a
# deployment piece). Written out long rather than globbed, so a stack a
# future manifest entry adds does not get swept up before anyone has
# decided whether a full reset should stop it.
for s in honeypot-agent-intrusion-worker honeypot-attacker-identity-worker \
         honeypot-beelzebub honeypot-canarytokens \
         honeypot-cisco-asa-honeypot honeypot-citrix-honeypot \
         honeypot-conpot honeypot-correlator-worker honeypot-cowrie \
         honeypot-dashboard honeypot-dashboard-backend honeypot-dicompot \
         honeypot-dionaea honeypot-dnp3 honeypot-dns-honeypot \
         honeypot-elasticpot honeypot-elk honeypot-endlessh honeypot-galah \
         honeypot-hellpot honeypot-http honeypot-init honeypot-mailoney \
         honeypot-multipot honeypot-payload-analysis \
         honeypot-payload-inventory-worker honeypot-rdp-honeypot \
         honeypot-sentrypeer honeypot-sonicwall-sma honeypot-tanner \
         honeypot-utilities unsloth; do
  (cd /opt/stacks/$s && docker compose -f compose.yml down)
done
```

Do **not** include `honeypot-keycloak` in the loop above -- it lives at
`/var/dockge/stacks/honeypot-keycloak`, not `/opt/stacks/`, and unlike every
other stack here its Postgres volume holds identity data a routine reset
should preserve (see "What survives" above). Leave it running through the
whole reset; nothing else in this doc's sequence needs it stopped.

Then remove every honeypot-owned volume (list above), and wipe every log
directory under `/opt/stacks/apiary/logs/` **except** `suricata/` and
`portbridge/` (those are sshfs mounts from the VPS, already handled in step 1
and read-only from this side). Don't forget `logs/arkime-raw/` — it's the
local copy `pcap-sync` makes of the VPS's PCAP files, easy to miss since it's
not named after a sensor, and it will silently retain stale files if you wipe
everything else but leave `pcap-sync`/`arkime-capture` running during the
sweep. Stop them first if they're still up.

Recreate each sensor's log directory with the ownership `mkown` in
[`scripts/reset-logs.sh`](../scripts/reset-logs.sh) uses (2000 for
cowrie/conpot, 1000 for dionaea, 65534 for everything else) — **except
`logs/snare`, which needs `root:root`, not 65534:65534. See the pitfall below.**

Also `sudo mkdir -p logs/suricata/pcap` on the **VPS** side (not the
homeserver) before Suricata starts back up there — its own `suricata.yaml`
documents that it will not create this subdirectory itself.

### 3. Start Elasticsearch before honeypot-init

This is the real trap. `honeypot-init`'s `elasticsearch-setup` and
`arkime-init` jobs need a running, healthy Elasticsearch to bootstrap index
templates and the Arkime admin user — but Elasticsearch now lives in
`honeypot-elk`, a stack that normally deploys *after* `honeypot-init` in
steady state (because in steady state Elasticsearch is already running from
the previous deploy, so there's no real ordering dependency day to day).
On a cold start there is nothing already running, so bringing up
`honeypot-init` first makes `elasticsearch-setup`/`arkime-init` hang forever
waiting on a service that doesn't exist yet.

`honeypot-init` also expects `dionaea-lib`, `yara-results`, and `honeynet` to
already exist (`external: true` in `arcane/home/honeypot-init/compose.yml`,
formerly `arcane/home/honeypot-init/compose.yml` before #1502) — if you wiped
those volumes in step 2, create empty placeholders first:

```bash
docker volume create dionaea-lib
docker volume create yara-results
# honeynet is a network, not a volume -- confirm it survived:
docker network ls | grep honeynet   # recreate with `docker network create honeynet` if not
```

`honeypot-llm` (an `--internal` network) and `xore-zeek:local` must also exist
before honeypot-elk and honeypot-init come up on a host with no Docker state:
the elk compose runs `zeek-proxy` with `pull_policy: never` on a locally
built tag, and nothing in a project deploy builds it. Both are what
`scripts/install-homeserver.sh` does in `step_create_shared_resources` and
`step_build_zeek_image`:

```bash
docker network create honeypot-llm --internal
docker build -f vps/zeek/Containerfile -t xore-zeek:local vps/zeek   # from the apiary checkout
```

On a cold host `state/init-markers` must also be mode 0777 before
honeypot-init runs (`install -d -m 777 state/init-markers`), and
`state/honeyfs/cowrie` and `state/honeyfs/cowrie-share` must exist owned by
2000:2000. Without the first, every one-shot does its work and then exits 1
on `touch /markers/<job>.done: Permission denied`.

Then:

```bash
cd /opt/stacks/honeypot-elk && docker compose -f compose.yml up -d
# wait for hp-elasticsearch to report healthy
cd /opt/stacks/honeypot-init && docker compose -f compose.yml up -d
# elasticsearch-setup / arkime-init / honeypot-kibana-setup / log-init /
# persona-apply / snare-clone should all Exit(0) within ~30s
```

When these two stacks are deployed **through Arcane** rather than by hand,
the deploy stream reports failures that are not failures on a cold start:
the honeypot-elk redeploy ends with `container hp-pcap-sync is unhealthy`
(pcap-sync waits for the `log-init.done` marker that honeypot-init has not
written yet), and the honeypot-init redeploy ends with
`container hp-log-init exited (0)` (the known one-shot behaviour, #2714;
`scripts/arcane-deploy-honeypot-init.sh` exists for it). Judge by `docker ps
-a` and the markers, not by the final frame.

### 3b. Swarm overlays before Ollama and Galah

Since #3591, the Galah-to-Ollama broker runs as the Swarm stack
[`swarm/stacks/galah-broker`](../swarm/stacks/galah-broker/README.md), not in
Compose. Two Compose services join its encrypted overlays as
`external: true` networks:

- `ollama` in `analysis/ghidra/docker-compose.ghidra.yml` joins `galah-broker_back`.
- `galah` in `arcane/home/honeypot-galah/compose.yml` joins `galah-broker_front`.

Compose will not create a container whose external network is missing. So
neither Ollama (the Ghidra/Ollama stack) nor `honeypot-galah` can start
until the following hold:

1. The homeserver is still a Swarm manager. A full reset does not leave the
   Swarm (`docker swarm leave` is never part of this runbook), and the
   homeserver's normal availability is `pause`:
   ```bash
   docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}'   # active true
   ```
2. The `galah-broker` stack is deployed through its Arcane GitOps sync and both
   overlays exist:
   ```bash
   docker network ls --filter name=galah-broker_ --format '{{.Name}} {{.Driver}} {{.Scope}}'
   # galah-broker_back overlay swarm
   # galah-broker_front overlay swarm
   ```

Start the Ghidra/Ollama stack only after that, and `honeypot-galah` after
Ollama (in step 4). If Compose still reports `network galah-broker_* not found`
on the homeserver, follow the overlay-materialization workaround in the
broker README.

If the Swarm cannot be brought back, use the broker README's **Rollback**
section. Starting the old Compose broker with
`docker compose --profile legacy up -d galah-llm-broker` handles a failed
broker, but on its own it does not handle a missing overlay. The overlay
attachments in both Compose files have to be reverted first.

### 4. Bring up everything else

This section is for a deliberate reset, where the host's `/var`,
permissions and installer-provisioned state are intact. On a **fresh
`/var`** more than ordering matters: the installer steps listed in
[`HOMESERVER-VAR-RECOVERY.md`](HOMESERVER-VAR-RECOVERY.md) part 8 are needed
(enrichment output directories, GeoIP and threat-intel profiles, backend
ACLs, `/var/image-sbom`, `GIT_SHA` in the backend and dashboard `.env`
files). Compose profiles (`geoip-update`, `threat-intel`) are not started by
Arcane's redeploy. And the backend/dashboard order is fixed: sync
`honeypot-dashboard`, then build+redeploy `honeypot-dashboard-backend`, then
build+redeploy `honeypot-dashboard`.

Arcane syncs on the live host track `main` while
`arcane/manifests/home-production.json` says `production`; see
[`ARCANE-GIT-SYNC.md`](ARCANE-GIT-SYNC.md). Do not change this during a
rebuild.

For a reset on a healthy host, order doesn't matter much from here — every remaining stack either has no
cross-stack dependency at deploy time (the standalone honeypots, dionaea,
tanner) or tolerates being started before what it reads from (payload-analysis,
dashboard: their shared volumes are non-`external`, so whichever project
starts first just creates them empty and the real writer fills them in once
it's up).

```bash
for s in honeypot-agent-intrusion-worker honeypot-attacker-identity-worker \
         honeypot-beelzebub honeypot-canarytokens \
         honeypot-cisco-asa-honeypot honeypot-citrix-honeypot \
         honeypot-conpot honeypot-correlator-worker honeypot-cowrie \
         honeypot-dashboard honeypot-dashboard-backend honeypot-dicompot \
         honeypot-dionaea honeypot-dnp3 honeypot-dns-honeypot \
         honeypot-elasticpot honeypot-endlessh honeypot-galah \
         honeypot-hellpot honeypot-http honeypot-mailoney \
         honeypot-multipot honeypot-payload-analysis \
         honeypot-payload-inventory-worker honeypot-rdp-honeypot \
         honeypot-sentrypeer honeypot-sonicwall-sma honeypot-tanner \
         honeypot-utilities unsloth; do
  (cd /opt/stacks/$s && docker compose -f compose.yml up -d)
done
```

### 5. Bring the VPS back up

```bash
ssh vps
cd /root/vps
docker compose -f docker-compose.yml up -d suricata portbridge p0f \
  suricata-rules-refresh suricata-log-maintenance \
  portbridge-log-maintenance portbridge-blackhole-refresh
```

There is no `portbridge-log-rotate` service to start or stop. It was removed
in #1779, and its only job — pruning the renamed `portbridge.json.*` files
once they age out — is what `portbridge-log-maintenance` does now, per that
script's own header. A stop or start naming it fails on a container that does
not exist, which in a reset runbook is a step that silently does nothing.

The list also omits `portbridge-manual-blackhole-refresh` on purpose: it is
the manual counterpart to the scheduled `portbridge-blackhole-refresh` and
should not be brought up by a reset. `suricata-update` is covered separately,
just below.

`suricata` depends on `suricata-update` (`condition: service_completed_successfully`)
— if `suricata-update`'s container is still sitting there `Exited(0)` from a
previous run, Compose treats the condition as already satisfied and won't
rerun it. That's fine for a routine reset (rules don't need re-pulling); force
a fresh pull first with `docker compose rm -f suricata-update` if you want one.

### 6. Verify

```bash
# On the homeserver:
docker ps --filter health=unhealthy --format '{{.Names}}'
docker ps -a --filter status=exited --format '{{.Names}}\t{{.Status}}'
curl -s -o /dev/null -w '%{http_code}\n' http://10.8.0.2:19090/   # dashboard
docker run --rm --network honeynet curlimages/curl:latest -s \
  http://elasticsearch:9200/honeypot-v2-*/_count                  # events flowing
```

## Pitfalls hit on the first live run

**`snare` crash-loops with `Failed to access path: /opt/snare`.**
`mushorg/snare`'s own `check_privileges()` calls `os.access(path, os.W_OK)`
*before* the process drops privileges (`drop_privileges()` runs much later,
after the HTTP server has already started) — so at that check, the process is
still uid 0. The compose file gives it `cap_drop: [ALL]` with only
`SETUID`/`SETGID` added back, deliberately withholding `DAC_OVERRIDE` — so uid
0 here is *not* exempt from ordinary permission checks the way root normally
is. It needs to actually **own** `/opt/snare` to pass. `chown 65534:65534`
(the UID every other sensor in the Tanner group uses) breaks it; use
`root:root`. `scripts/reset-logs.sh`'s `mkown` call for `logs/snare` already
reflects this fix.

**Arkime says "This is a fresh Arkime install... must do init" in a
restart loop.** Expected the moment `es-data` is wiped — `arkime-init`
(honeypot-init) creates Arkime's Elasticsearch indices and admin user, and a
fresh `es-data` volume has neither. Not a bug, just confirms step 3's ordering
matters: if you see this, `honeypot-init`'s `arkime-init`/`elasticsearch-setup`
either haven't run yet or ran before Elasticsearch existed. Fix: clear their
markers and force them to rerun —

```bash
sudo rm -f state/init-markers/elasticsearch-setup.done state/init-markers/arkime-init.done
cd /opt/stacks/honeypot-init
docker compose -f compose.yml rm -f elasticsearch-setup arkime-init honeypot-kibana-setup
docker compose -f compose.yml up -d
```

**Docker's default address pools exhaust with this many stacks.** Each
split project gets at least one bridge network (its own private one, or the
implicit per-project default). On a host already running ~30 unrelated
Compose projects, `docker network create` can start failing with `all
predefined address pools have been fully subnetted`. Not something a reset
causes by itself, but a reset is exactly when you're recreating every
network at once and most likely to hit it. Fixed permanently (not per-reset)
by widening `default-address-pools` in `/etc/docker/daemon.json` and
restarting the Docker daemon — see `docs/CI-CD.md`'s `honeypot-utilities`
section for the exact config used here. A daemon restart kills any container
on the host with no `restart:` policy of its own, honeypot or not — check for
casualties afterward (`docker ps -a --filter status=exited`).

**Elasticsearch has no host-published port.** `curl http://localhost:9200`
from either host never reaches it — reach it via a throwaway container on
`honeynet` instead: `docker run --rm --network honeynet curlimages/curl:latest
curl ...`. `scripts/reset-logs.sh` does this internally now; worth remembering
for ad hoc debugging too.
