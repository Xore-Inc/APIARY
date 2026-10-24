# CGNAT deployment

The deployment is deliberately split between a public VPS and a home server
behind CGNAT.

```mermaid
flowchart TD
    Internet --> Traefik["VPS Traefik<br/>HTTPS"]
    Internet --> Portbridge["VPS portbridge<br/>TCP/UDP"]
    Traefik --> HTTPBridge["WireGuard HTTP bridge"]
    Portbridge --> Tunnel["WireGuard tunnel"]
    HTTPBridge --> Home["home server 10.8.0.2<br/>Arcane APIARY stack"]
    Tunnel --> Home
```

## Authoritative deployment paths

- Home server: **#258 split what used to be two stacks into one Arcane-managed
  project per compose file**, and **#1502 moved every one of those projects
  onto Arcane's own directory-aware Git sync** — `honeypot-init` (one-shot
  bootstrap: log paths, Elasticsearch templates, Arkime schema, persona
  validation), `honeypot-elk`, `honeypot-cowrie`, `honeypot-dionaea`,
  `honeypot-conpot`, `honeypot-dnp3`, `honeypot-http`, `honeypot-multipot`,
  `honeypot-payload-analysis`, `honeypot-tanner`, `honeypot-dashboard`,
  `honeypot-dashboard-backend`, `honeypot-utilities`, the standalone
  honeypots (cisco-asa, citrix, rdp, sonicwall-sma, dicompot, dns-honeypot,
  endlessh, beelzebub, hellpot, elasticpot, galah,
  sentrypeer, mailoney, canarytokens), `honeypot-keycloak`, and the
  workers (agent-intrusion, attacker-identity, correlator,
  payload-inventory) — 32 stacks total, one Arcane-managed directory each
  under `arcane/home/<name>/` (`honeypot-wordpot` sat here until #2381
  retired it; `ip-enrichment-worker` was in that worker list until
  f139fe24 retired the Go service, `honeypot-dashboard-backend` joined when
  #1622 split it out of `honeypot-dashboard`, and `honeypot-sonicwall-sma`
  when #3131 added it — re-counted 2026-09-27 against
  `arcane/manifests/home-production.json`, which holds 33 in-tree entries:
  these 32 plus `unsloth`). `honeypot-init` still deploys first; every
  sensor stack waits on its completion markers at its own entrypoint rather
  than a Compose-level dependency, same reasoning as before, just across
  more projects now. See `docs/STACK-REBUILD.md` for the full current list
  and the ordering traps (Elasticsearch must be healthy before
  `honeypot-init` runs, not the other way around), and
  `docs/ARCANE-GIT-SYNC.md` for how a commit actually reaches the live
  host now.
- VPS: plain Docker Compose manages `/root/vps/docker-compose.yml`.
  Unchanged by #1502 — VPS deployment stays outside Arcane entirely, as
  that issue's own scope decision.
- Each of the 33 in-tree stacks' Compose source (build context, git-tracked config,
  `compose.yml` with an explicit top-level `name:` pinned to its live
  project name) lives self-contained under `arcane/home/<name>/` in this
  repository. Arcane clones the repo and materializes the *entire
  directory* containing the selected `compose.yml`, not just that one
  file — that's what makes a build context or sidecar config file
  resolvable without a shared checkout. Runtime data (`logs/`, `state/`,
  and similarly host-owned paths) deliberately stays outside that synced
  directory, at its existing absolute host path, unchanged.
  `scripts/install-homeserver.sh`'s `step_arcane_import_stacks` creates
  these syncs on a from-scratch install, driven by the single source of
  truth at `arcane/manifests/home-production.json`. Six more home-hosted
  stacks (`auth-events-worker`, `llm-worker`, `ml-worker`,
  `analysis/ghidra`, `sandbox/ghosts`, `technitium`) are Arcane-managed too but
  were already self-contained, so they kept their existing repository-root
  path instead of moving. Three of those six (`auth-events-worker`,
  `llm-worker`, `ml-worker`) are also imported by
  `step_arcane_import_stacks` itself now (#1505 — confirmed to have no
  host-local state beyond `.env`); the other three keep their own dedicated
  installer steps for reasons specific to each (`technitium`'s non-`.env` host
  state — the step `pihole` had until #2911 swapped the two — `analysis/ghidra`'s conditional GPU compose overlay, and
  `sandbox/ghosts`'s confirmed Arcane build-context limitation, #1506) —
  see `scripts/install-homeserver.sh`'s own Phase 8 header comment for the
  full reasoning behind each. That filter reaches 35 of the manifest's 39
  entries; `unsloth` is the one the installer reaches neither way (no
  `step_unsloth_*`, and not a `honeypot-*` name), by design — see
  `docs/ARCANE-GIT-SYNC.md`'s "Manifest import".
- The public gateway source is under `vps/`.

Arcane is used only on the home server. The VPS uses `docker compose` directly.
See `docs/ARCANE-GIT-SYNC.md` for the sync model, cutover procedure, and
confirmed Arcane platform limitations (a required compose variable
in a port-binding position, remote build contexts pinned to a Git tag, the
sync file-count limit, and stale project records after a `destroy` call
all have confirmed workarounds documented there). Those were each confirmed
against `v2.8.0`–`v2.9.0`; `docker-compose.arcane.yml` now pins
`manager:v2.17.0`, and none of them has been re-confirmed against that
image — its own section header says to re-verify on upgrade.

## WireGuard addressing

The examples reserve `10.8.0.1` for the VPS and `10.8.0.2` for the home server.
`10.8.0.3` is reserved for precision, and the homeserver ↔ precision fibre
tunnel uses `10.8.1.0/30`; see [SWARM-NETWORK.md](SWARM-NETWORK.md).
Change the subnet consistently if it conflicts with an existing network.
Sensors bind `HP_BIND=10.8.0.2`, never the home LAN address. The VPS gateway is
the only internet-facing component.

## Home deployment

> **Prefer the script.** [`scripts/install-homeserver.sh`](../scripts/install-homeserver.sh)
> — or [`scripts/install.sh --profile home`](../scripts/install.sh), the single
> entry point that runs it with the answers file defaulted to
> `/etc/apiary/install-home.conf` ([#1609](https://github.com/Xore/APIARY/issues/1609)) —
> automates Docker, GPU/NVIDIA, WireGuard, Arcane, the repo checkout,
> per-stack provisioning, secret restore, and starting every stack in the
> correct order (plus the GPU/LLM/ML worker chain and, optionally, the
> KVM/libvirt sandbox VMs) against a manually-installed base Ubuntu system
> — fill in
> [`scripts/install-homeserver.conf.example`](../scripts/install-homeserver.conf.example)
> first. Run multiple times end-to-end (including a from-genuinely-fresh
> install and a full idempotent re-run) under
> [#518](https://github.com/Xore/APIARY/issues/518), with real bugs
> found and fixed each pass — it's the current source of truth for the
> real deployment order, not the numbered steps below, which describe the
> pre-#258 two-stack model and haven't been re-verified against the current
> per-stack split. File a gap against #518 if the script and reality ever
> disagree. As of #1502, per-stack provisioning means importing an Arcane
> directory-aware Git sync per `arcane/manifests/home-production.json`
> entry, not copying/symlinking a compose file — see
> `docs/ARCANE-GIT-SYNC.md`. One genuine from-scratch gap remains
> (#1504's surviving caveat): minting `ARCANE_API_TOKEN` requires a first
> human login, which is OIDC-only once Keycloak exists, so a truly-fresh
> install is inherently two-pass. (`step_dockge_install` — the pre-#1504
> "installs Dockge rather than Arcane" step this paragraph used to warn
> about — was itself the thing #1504 replaced; its mention here was
> stale.)

1. Establish WireGuard and verify that the VPS can reach `10.8.0.2`.
2. Copy this repository to `/opt/stacks/apiary/`.
3. Copy `.env.example` to `.env` in `/opt/stacks/apiary/` and generate
   every value marked `CHANGE_ME`.
4. Create `/opt/stacks/honeypot-init/`, copy `arcane/home/honeypot-init/compose.yml` from
   the repo into it as `compose.yml`, and copy the repo's
   `honeypot-init.env.example` to `.env` there (set
   `ARKIME_ADMIN_PASSWORD`/`ARKIME_PASSWORD_SECRET` — the latter must match
   the value in `APIARY`'s `.env` exactly).
5. Before first deploying `honeypot-init`:
   `install -d -m 777 /opt/stacks/apiary/state/init-markers` — its
   jobs run as several different container UIDs, and a root-owned 755
   directory 403's the non-root ones.
6. Ensure the repository `docker-compose.yml` is also present as
   `/opt/stacks/apiary/compose.yml`.
7. In Arcane, validate and deploy **`honeypot-init` first**, then
   `APIARY`. `APIARY`'s sensors wait on `honeypot-init`'s
   completion markers at their own entrypoint rather than a Compose-level
   dependency (they can't cross a Compose project boundary) — deploying
   `APIARY` first won't fail, but nothing finishes initialising
   (log paths, Elasticsearch templates, Arkime schema) until `honeypot-init`
   has run at least once. See the root `README.md`'s "Home container
   interaction map" for why these are two stacks.
8. Run `python3 analysis/verify-stack.py` (with `DASHBOARD_SERVICE_TOKEN`
   from `honeypot-dashboard/.env`) and inspect `/source-health`.

Each stack is a folder under your Arcane stacks dir (`/var/dockge/stacks`;
`/opt/stacks` is a symlink to it, #1185). **Since #1502 nothing is uploaded
by SFTP** — Arcane materializes each stack's whole directory from its Git
sync, and `honeypot-wordpot` aside the source of truth is the repository, not
a hand-copied folder. The SFTP-upload and "edit then rebuild from Arcane's
terminal" instructions this paragraph used to give are part of the pre-#258
model the callout above already flags; what replaces them is a commit plus a
sync, and a separate `POST /projects/{id}/build` for the stacks that have a
`build:` service — see `docs/ARCANE-GIT-SYNC.md`.

### Boot-safe home networking and VPS log mounts

The home stack reads Suricata and portbridge logs through read-only SSHFS
mounts over `wg0`. `_netdev` only orders an fstab mount after
`network-online.target`; it does not guarantee that the WireGuard interface is
ready. Likewise, SSHFS's `reconnect` option only reconnects a session that was
successfully established once.

On the reference homeserver, the 10 GbE interface `ens9f0` is the required
uplink. `eno1` and `eno2` are optional. Install the Netplan override first:

```bash
sudo ./setup-home-network.sh
sudo netplan try
```

The first command writes and validates
`/etc/netplan/90-honeypot-uplink.yaml`, but deliberately does not change the
live network. `netplan try` applies it with an automatic rollback unless it is
confirmed. Run this from the local console or through the required interface.
To use different interface names, set `REQUIRED_INTERFACE`,
`SECONDARY_INTERFACE`, and `UNUSED_INTERFACE` for the installer.

The override makes the required uplink use the preferred DHCP route metric,
marks the other interfaces optional, and pins
`systemd-networkd-wait-online` to the required routable interface. It does not
hard-code the DHCP address.

After confirming Netplan, install the mount ordering and recovery unit:

```bash
sudo ./setup-suricata-logs-home.sh
```

This installer requires the existing Suricata and portbridge entries in
`/etc/fstab`. It adds drop-ins that make both generated mount units require and
start after `wg-quick@wg0.service`. It also enables
`honeypot-log-mounts.service`, which retries failed mounts every 15 seconds and
restarts EveBox and Filebeat after recovery so they discover `eve.json`.

Verify the installed state:

```bash
systemctl status systemd-networkd-wait-online wg-quick@wg0 \
  honeypot-log-mounts.service
findmnt /opt/stacks/apiary/logs/suricata
findmnt /opt/stacks/apiary/logs/portbridge
docker logs --since 5m hp-evebox
```

The expected boot order is required uplink, WireGuard, SSHFS mounts, then
ingestion recovery. A temporarily unavailable VPS may delay ingestion, but the
retry service prevents the mounts from remaining failed until the next manual
intervention.

## VPS deployment

> **Prefer the script.** [`scripts/install-vps.sh`](../scripts/install-vps.sh)
> — or [`scripts/install.sh --profile vps`](../scripts/install.sh), the same
> thing with the answers file defaulted to `/etc/apiary/install-vps.conf` —
> automates Docker, WireGuard, the firewall, the NIC offload fix, the `vps/`
> checkout, secret restore, and starting the stack against a
> manually-installed base Ubuntu system — fill in
> [`scripts/install-vps.conf.example`](../scripts/install-vps.conf.example)
> first. Filed as [#1059](https://github.com/Xore/APIARY/issues/1059) after
> confirming nothing in this repo could previously bring a genuinely
> wiped/reimaged VPS back up — it's the current source of truth for the real
> deployment order, not the numbered steps below, which predate it and
> haven't been kept in lockstep since. File a gap against #1059 if the
> script and reality ever disagree.
>
> For a genuinely fresh pair of hosts, run this script BEFORE
> `install-homeserver.sh` — see its own header comment for why (its
> WireGuard peer entry for home starts as a placeholder that
> `install-homeserver.sh`'s `step_wireguard_sync_vps_peer` fills in once the
> home side exists).
>
> The VPS hub `wg0` carries every spoke in
> [`ops/swarm/hosts/hub-peers.txt`](../ops/swarm/hosts/hub-peers.txt): homeserver
> and precision (#3619). On a rebuild, restore `/etc/wireguard` from the backup
> (`vps/wireguard/`) before running the script. Otherwise the precision spoke is
> skipped with a warning and has to be re-added with
> `ops/swarm/vps-hub-peer.sh add` ([ops/swarm/README.md](../ops/swarm/README.md)).

1. Move real admin SSH to `2222` first, so cowrie can own `22` — confirm
   `2222` works before continuing. There is no script for this step; do it
   by hand and keep the old session open until the new port answers.
2. `sudo ufw allow 2222/tcp comment 'REAL admin SSH'` and, for `443/tcp`,
   allow only Cloudflare's published ranges
   (<https://www.cloudflare.com/ips-v4/> — see
   `scripts/install-vps.sh`'s `step_firewall_base` for the exact list this
   repo currently pins), not `Anywhere`: every real hostname is proxied
   through Cloudflare, and a direct-origin connection bypassing it skips
   Cloudflare's own WAF/rate-limiting. There is no `80/tcp` rule — Traefik
   has no plain-HTTP listener here. Both of these are outside
   `honeypot-firewall.sh`'s scope (below), so do them by hand too if not
   using the script above.
3. Copy `vps/.env.example` to `/root/vps/.env`.
4. Replace all example domains, the Suricata `HOME_NET`, authentication
   credentials, cookie secrets, and TOTP values.
5. Copy `vps/` contents to `/root/vps/`.
6. Validate with `docker compose -f /root/vps/docker-compose.yml config`.
7. Start with `docker compose -f /root/vps/docker-compose.yml up -d --build --remove-orphans`.
8. Apply `vps/honeypot-firewall.sh` only after reviewing the exposed ports —
   it opens every raw (non-Traefik) port `portbridge` forwards, including
   `21`/`22`/`23`/`25` (Dionaea FTP, cowrie SSH/Telnet, multipot SMTP).
   Portbridge's `22` is a separate host listener from real admin SSH — it
   only binds there because step 1 already moved admin SSH to `2222` — so
   opening it does not affect step 2's rule. Run
   `vps/check-firewall-portbridge-sync.sh` after editing either
   `honeypot-firewall.sh` or portbridge's `RULES` env var; it fails loudly if
   the two fall out of sync again (#152).
9. Run `sudo vps/disable-nic-hw-gro.sh --apply` (#342). Most VPS providers
   put the public interface on `virtio-net`, whose hardware-accelerated GRO
   (`rx-gro-hw`) is a separate feature from the standard
   `generic-receive-offload` toggle and coalesces multiple physical frames
   into one oversized packet — Suricata's AF_PACKET capture then logs the
   result as a "truncated packet" decoder-event alert (SID `2200003`/
   `2200122`), which can dominate alert volume. This installs a
   `systemd-networkd` `.link` file so the fix survives reboots.

`portbridge` binds every raw port on the public interface and forwards it
over WireGuard to `10.8.0.2`; the `socat-hp-*` services put the HTTP
honeypots on the `proxy` network for Traefik. The reusable Traefik router
template is in [`vps/traefik/dynamic.yml`](../vps/traefik/dynamic.yml):
`honeypot-http` (`decoy.<domain>`) + `honeypot-web` (catch-all) → fake nginx,
`honeypot-snare` (`www-portal.<domain>` and `snare.<domain>`) → SNARE, one
native-OIDC route for the dashboard (no gateway, since #1026), one native-OIDC
route for Arcane (no gateway, #1185), and six gateway-fronted
investigation routes sitting behind their own Keycloak-backed `oauth2-proxy`
gateway: Kibana, TANNER, EveBox, Arkime, Rev·Deck, and the Traefik dashboard
itself. Five of the six have a matching
`socat-hp-*` bridge in [`vps/docker-compose.yml`](../vps/docker-compose.yml);
the Traefik dashboard's gateway terminates on the VPS, not through one.

Traefik is an HTTP(S) reverse proxy — it adds TLS, per-subdomain routing and
auth to the web honeypots and dashboards. The other protocols (SSH, SMB,
MySQL, Modbus, …) aren't HTTP, so Traefik can't route them; `portbridge`
forwards them raw. Both paths terminate on the VPS public IP.

### Origin certificate (#3328)

Traefik serves one **Cloudflare Origin CA** certificate for every proxied
hostname (`vps/traefik/dynamic.yml`, `tls.certificates`):

| | |
|---|---|
| files | `/root/vps/traefik/certs/origin.pem` (0644) and `origin-key.pem` (0600), dir 0750, mounted at `/etc/traefik/certs/` |
| names | `<zone>` and `*.<zone>`. The wildcard covers exactly one label, which is why `install-vps.sh` refuses a `DOMAIN` that already starts with a service label |
| key | RSA 2048 |
| lifetime | chosen at issue time; the current one runs 2026-07-30 → **2028-07-29** |
| trust | only Cloudflare trusts it. It works because every hostname is proxied (orange cloud) and 443 accepts Cloudflare's ranges only. A browser hitting the origin directly would reject it |

Nothing renews it. Diagnostics' VPS job reports the days left on every run
and fails a scheduled run once fewer than 30 remain. When it expires,
Cloudflare answers every proxied hostname with **526**.

**Issuing (first install, or renewal):**

1. Cloudflare dashboard → the zone → **SSL/TLS → Origin Server → Create
   Certificate**.
   - Choose "Generate private key and CSR with Cloudflare", key type **RSA (2048)**.
   - Hostnames: exactly `<zone>` and `*.<zone>`.
   - Validity: longest offered (15 years), or 2 years to match the current cert.
   - Format: **PEM**.
2. The key is shown **once**. Copy the certificate into `origin.pem` and the
   private key into `origin-key.pem` on a trusted machine, never into the repo.
3. On the VPS:
   ```bash
   install -d -m 0750 /root/vps/traefik/certs
   install -m 0644 origin.pem     /root/vps/traefik/certs/origin.pem
   install -m 0600 origin-key.pem /root/vps/traefik/certs/origin-key.pem
   openssl x509 -in /root/vps/traefik/certs/origin.pem -noout -subject -enddate -ext subjectAltName
   cd /root/vps && docker compose restart traefik
   ```
   Restart rather than relying on the file watcher: `dynamic.yml` records a
   case where a hot reload left Traefik's per-host TLS cache stale.
4. SSL/TLS encryption mode for the zone: **Full (strict)**. An Origin CA
   certificate is valid only under Full/Full (strict), and strict is what
   makes Cloudflare check it.
5. Verify through Cloudflare. `curl -sI https://auth.<zone>/` must not
   return 526, and the next Diagnostics run should report the new expiry.
6. Get it into the backup. `scripts/backup-essentials.sh` captures
   `vps/traefik/` on its next daily run. Until then, a VPS rebuild would
   restore the *old* certificate (`install-vps.sh` `step_restore_certs`).
   Revoke the old certificate in the same Cloudflare screen once the new one
   serves.

`deploy.yml` never overwrites `traefik/certs/`. On a normal deploy it only
checks that `origin.pem` still parses.

### The gateway-fronted chain, generically

Six investigation UIs (Kibana, TANNER, EveBox, Arkime, Rev·Deck,
the Traefik dashboard) reach home through the identical chain — one pattern,
six routers in `vps/traefik/dynamic.yml`, six `oauth2-proxy` gateway
containers, five `socat-hp-*` bridges, not six different mechanisms. The
gateway *is* the router's upstream rather than a `forwardAuth` middleware:
`honeypot-kibana`'s `service:` is a loadBalancer at `http://oidc-kibana:4180`,
and that container's `OAUTH2_PROXY_UPSTREAMS` is the socat bridge
(`http://socat-hp-kibana:5601`). `grep -c forwardAuth vps/traefik/dynamic.yml`
is 0, so nothing in the config uses the forward-auth middleware form. The
sixth gateway, `oidc-traefik`, has no socat hop at all — its upstream is
Traefik's own dashboard (`http://traefik:8081`) on the VPS, which is why the
bridge count is five and not six. The honeypot dashboard and Arcane are the
two exceptions — both speak native OIDC directly, no gateway — see the note
below.

```mermaid
sequenceDiagram
  autonumber
  actor Op as operator's browser
  participant CF as Cloudflare<br/>(proxied DNS)
  participant TR as Traefik<br/>(TLS termination + routing)
  participant OA as oauth2-proxy<br/>(gateway, one per service)
  participant KC as Keycloak<br/>(honeypot-keycloak, at home)
  participant SOC as socat-hp-*<br/>(VPS container)
  participant WG as WireGuard tunnel
  participant APP as home app<br/>(HP_BIND:port)

  Op->>CF: HTTPS request, e.g. kibana.<domain>
  CF->>TR: proxied, real client IP in X-Forwarded-For
  TR->>OA: routed to the app's own gateway (oidc-kibana:4180)
  alt no valid session
    OA-->>Op: redirect to Keycloak login (auth.<domain>)
    Op->>KC: authenticate (password + mandatory TOTP)
    KC-->>OA: OIDC callback, session established
  end
  OA->>SOC: proxied request, identity headers added
  SOC->>WG: raw TCP, VPS listen port → 10.8.0.2:home-exposed-port
  WG->>APP: delivered to the app's own internal port
  APP-->>Op: response, relayed back through the same chain
```

The socat hop is a dumb TCP relay — all the routing/auth decisions happen in
Traefik and `oauth2-proxy` before it, which is why adding a new
gateway-fronted UI means one new router + one new `oauth2-proxy` container +
one new `socat-hp-*` container, never a change to this flow itself.
`vps/traefik/dynamic.yml`'s own comment table lists every current listen-port
→ home-port → app-internal-port mapping.

> **The honeypot dashboard doesn't use this chain.** Since #1026 it speaks
> OIDC to Keycloak natively (its own Go client, PKCE S256) instead of sitting
> behind an `oauth2-proxy` gateway. Traefik routes its traffic straight to
> `socat-hp-dashboard` with no forward-auth hop at all; the actual OIDC token
> exchange happens homeserver-local, directly between `honeypot-dashboard`
> and `honeypot-keycloak`, and never crosses the VPS. `Xore/auth-backend` is
> retired as a runtime service across every app now — it supplies only the
> read-only Keycloak login theme (`themes/apiary`).

> **Source IP:** the HTTP honeypots recover the real client IP from
> `X-Forwarded-For` (Traefik/Cloudflare). Some raw sensor logs initially
> contain the **VPS WireGuard IP**, but the dashboard correlates those
> connections with the portbridge connection log and attributes the real
> attacker — see "Source-IP preservation" below. The HTTPS catch-all only
> catches requests with a valid SNI/`Host`; raw-IP scanners are caught by the
> direct `:8081` tunnel instead.

## DNS

Create proxied DNS records for the HTTP services you enable, normally:

- `auth`
- `dashboard` or `honeypot`
- `decoy`
- `www-portal` or `snare`
- `kibana`
- `tanner`
- `evebox`
- `arkime`
- `rev` (optional — Rev·Deck; only if the `analysis/ghidra/` stack's
  `revdeck` profile is enabled; see `docs/analysis/ghidra/revdeck/README.md`)
- `traefik` (optional — Traefik's own dashboard/API, read-only, behind
  forward-auth same as everything else here)
- `arcane` (optional — **root-equivalent host control**: Arcane has
  `/var/run/docker.sock` mounted read-write. Unlike the routes above, it
  authenticates natively against Keycloak rather than through an
  `oauth2-proxy` gateway, but treat this subdomain as sensitive as SSH
  access to the homeserver itself)
- `*` (optional — a proxied **wildcard** record on the apex, required only
  if self-hosted Canarytokens is enabled, #1487. `canarydrop.
  generate_random_hostname()` prepends each token's own random value as a
  subdomain of `CANARY_PUBLIC_HOSTNAME` (`<token>.example.com`), so this is
  what a dashboard-created PDF/Word/Excel/image/QR/Windows-Folder token's
  embedded trigger action actually resolves to when opened anywhere on the
  internet. Deliberately the bare apex, not a dedicated `cdn`/`canary`/
  `token*` subdomain: Cloudflare's free Universal SSL certs the apex plus
  exactly one wildcard level (`example.com` + `*.example.com`), not a
  nested one (`*.cdn.example.com`) — confirmed live, TLS handshake fails
  at Cloudflare's edge for the nested form, and a flat non-wildcard record
  leaves every actual trigger URL (a random label, never known in advance)
  unresolvable regardless. vps/traefik/dynamic.yml's honeypot-canarytokens
  router matches this same wildcard at low priority, below every other
  named router's own exact `Host()` match, so a real random token label
  can't collide with `auth`/`dashboard`/etc. above it. Set
  `CANARY_PUBLIC_HOSTNAME` to the bare apex in `honeypot-canarytokens`'s
  `.env` to match)
- `hub` (optional — galah's Traefik-routed path, #1511. Its own raw
  non-standard port isn't on Cloudflare's proxied-port allowlist, so this
  is the only way it's reachable through this domain at all. Deliberately
  not named `galah`/`llm`/`ai`)

All names point to the VPS. Raw TCP/UDP sensors need no DNS record.

## Source-IP preservation

The VPS port bridge records the public source and, where supported, adds the
HAProxy PROXY protocol header. The dashboard uses bridge correlation only to
recover the real attacker IP; `portbridge` is never shown as a sensor.

## Public-repository safety

Never commit `.env`, WireGuard private keys, real VPS addresses, captured
payloads, PCAPs, GeoIP license keys, authentication databases, or sandbox
images/results. CI runs the repository leak audit for every push and pull
request.
