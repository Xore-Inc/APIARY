# Swarm phase 1: host state, rollout and runbooks (#3589)

**Status (2026-10-10, applied and verified).** The three nodes form one swarm on the WireGuard hub addresses:

| Node | Swarm role, address | Availability | WireGuard | Firewall zone `apiary-swarm` |
|---|---|---|---|---|
| homeserver (`supermicro`) | manager (Leader), `10.8.0.2` | `Pause` (tasks schedule on precision, #3583) | `wg0` hub spoke (peer VPS), `wg-fibre` `10.8.1.1`, `wg-lan` `10.8.2.1` | `ens9f1`, `wg0`, `wg-fibre`, `wg-lan`; `DOCKER-USER` hub policy (`home-wg-forward`) |
| precision | manager (Reachable), `10.8.0.3` | `Active` | `wg0` hub spoke (peer VPS), `wg-fibre` `10.8.1.2`, `wg-lan` `10.8.2.2` | `enp4s0f1`, `wg0`, `wg-fibre`, `wg-lan` |
| VPS (hostname `localhost`) | worker, `10.8.0.1` | `Active` | `wg0` hub (peers homeserver, precision) | `wg0` |

Both managers are needed for quorum: if either fails, running tasks continue but scheduling and updates stop (accepted, #3587 decision 1). Never promote the VPS. Phase 1 creates no stack or service. Compose projects, sensor binds, Arcane, runners and the registry mirror are unchanged.

The decisions, flow matrix, MTU budget and failure modes are in [docs/SWARM-NETWORK.md](../../docs/SWARM-NETWORK.md).

## What lives where

Keys, preshared keys, join tokens, the VPS public endpoint and the homeserver LAN address never enter git. Templates carry `REPLACE_WITH_*` placeholders that are rendered **on the host**, with keys read from root-only files and not passed on a command line.

| Repo file | Host path | Hosts |
|---|---|---|
| `hosts/*-wg-fibre.conf.example`, `hosts/*-wg-lan.conf.example` | `/etc/wireguard/wg-fibre.conf`, `wg-lan.conf` (0600), `wg-quick@wg-fibre`/`@wg-lan` enabled | homeserver, precision |
| `hosts/precision-wg0.conf.example` | `/etc/wireguard/wg0.conf`, `wg-quick@wg0` enabled | precision |
| `hosts/hub-peers.txt` | the VPS hub spoke list (name, hub address); `scripts/install-vps.sh` renders one `wg0.conf` `[Peer]` per line (#3619). Keys: `/etc/wireguard/<name>.pub` and `<name>.psk` (0600) | VPS |
| `vps-hub-peer.sh` | `/usr/local/libexec/apiary-vps-hub-peer`; `add` adds a spoke live and to `wg0.conf` (and keeps its keys in `/etc/wireguard/<name>.pub`/`.psk`); `render` prints the `[Peer]` blocks for `install-vps.sh` | VPS |
| `peer-route.sh`, `peer-route.service` | `/usr/local/libexec/apiary-swarm-peer-route`, `/etc/systemd/system/peer-route.service` (enabled) | homeserver, precision |
| `hosts/homeserver.env`, `hosts/precision.env` | `/etc/apiary/swarm-peer.env` | homeserver, precision |
| `../firewall/swarm-plane.sh`, `../firewall/hosts/*.env` | env rendered to `/etc/apiary/swarm-plane.env` (precision: `REPLACE_WITH_HOMESERVER_LAN_IP` filled in) | all three |
| `../firewall/home-wg-forward.{sh,service}`, `../firewall/hosts/homeserver-wg-ports.txt` | `/usr/local/libexec/apiary-home-wg-forward`, `/etc/systemd/system/home-wg-forward.service`, `/etc/apiary/homeserver-wg-ports.txt` | homeserver |
| `nm-profiles.sh`, `hosts/homeserver.nm`, `hosts/precision.nm` | NetworkManager profiles (LAN, fibre, MTU 9000, metrics, zones); placeholders from `/etc/apiary/host.env` | homeserver, precision |
| `hosts/precision-multihome.conf` | `/etc/sysctl.d/90-apiary-multihome.conf` | precision |
| `hosts/arcane-fibre-tunnel.service` | `~xore/.config/systemd/user/arcane-fibre-tunnel.service` (user unit, linger on) | precision |
| `hosts/homeserver-arcane-authorized_keys.fragment` | one line of `~xore/.ssh/authorized_keys` | homeserver |
| `hosts/precision-fstab.fragment` | `/etc/fstab` lines (XFS volume and three bind mounts) | precision |
| `hosts/precision-runners.txt` | runner units from `scripts/github-ci-runner/install-ci-runner.sh`, registry mirror from `install-registry-mirror.sh` | precision |
| `swarm-membership.sh` | runs on the admin workstation (SSH aliases `homeserver`, `precision`, `vps`) | swarm |
| `scripts/install-vps.sh` (`live-restore: false`) | `/etc/docker/daemon.json` | VPS |

homeserver's strict `rp_filter` on `ens9f0`/`eno1` comes from the distribution default (`/usr/lib/sysctl.d/50-redhat.conf`), not a site file. It is what drops spoofed fibre or hub sources arriving on the LAN. `wg-fibre`/`wg-lan` set loose mode in their `PostUp`, because the peer hub `/32` moves between them on failover and `AllowedIPs` already rejects spoofed sources.

Check for drift at any time: `nm-profiles.sh check hosts/HOST.nm`, `swarm-plane.sh status /etc/apiary/swarm-plane.env`, `swarm-membership.sh status`.

## Runbook: Compose DNS after swarm membership changes (#3621)

`docker swarm leave` can erase Docker's embedded DNS records for containers on
local user-defined bridge networks. That stopped `hp-filebeat` from resolving
`elasticsearch` and halted ingest during the #3589 re-init. `swarm-membership.sh`
now runs `container-dns.sh rejoin` on each host after a leave and again after
re-init/join; its dead-man copy includes the DNS script. The check uses the
host's network namespace tools, so containers need no diagnostic packages.

For a manual membership change outside that script, run this on each affected
host after `swarm leave` or re-init (from the admin workstation):

```bash
ssh homeserver sudo -n bash -s -- check < ops/swarm/container-dns.sh
ssh homeserver sudo -n bash -s -- rejoin < ops/swarm/container-dns.sh
ssh homeserver sudo -n bash -s -- check < ops/swarm/container-dns.sh
```

Replace `homeserver` with `precision` or `vps` as needed. `check` is read-only;
`rejoin` restarts only Compose containers whose own name fails a direct query
to `127.0.0.11` on a user-defined bridge network. It handles
`hp-elasticsearch` before consumers. A nonzero exit means DNS is still broken:
inspect the named container and network, then repeat the check. Before and
after a membership change, confirm `getent hosts elasticsearch` in
`hp-filebeat`, rising `honeypot-v2*` count with a fresh public `source.ip`,
Arcane environments online, runners online, and healthy containers.

The 2026-10-11 read-only sweep found three pre-existing misses in unrelated
containers: `pentagi-ollama-embedding`, `pgexporter`, and `technitium-dns`.
They were left running; the next rejoin will repair their records.

## Stacks under Arcane GitOps (#3590)

Copy [`swarm/template/stack.yml`](../../swarm/template/stack.yml) to
`swarm/stacks/<name>/stack.yml`. The directory name is the stack name. Put
non-secret files in that directory's `configs/`; use a versioned external
config name (`<base>_vN`) and `x-apiary-file` for each. `stackctl.py` creates
the immutable config from the exact commit being deployed. Do not use `file:`:
Arcane prunes the configs it creates after an update, leaving rollback unable
to start the previous task. Use digest-pinned images from the #3597 manifest.

Each secret is an external `<base>_vN`, created out of band from stdin. Services
read it through a `_FILE` variable pointing into `/run/secrets/`; values and
value files never enter git. Rotate by creating `_v(N+1)`, changing the stack
file to reference it, merging, and deploying. Keep the old secret through the
next version so a rollback can still start.

```bash
python3 scripts/check-swarm-stacks.py
python3 scripts/check-swarm-images.py stacks
ops/swarm/stackctl.py secret create app_token_v1 < /path/to/private/value
ops/swarm/stackctl.py ensure --dry-run
ops/swarm/stackctl.py ensure <name>  # creation deploys immediately
ops/swarm/stackctl.py list
ops/swarm/stackctl.py deploy <name>  # after a later merge
ops/swarm/stackctl.py status <name>
```

`ensure` owns one Arcane sync per stack: `targetType=swarm_stack`, branch
`main`, `composePath=swarm/stacks/<name>/stack.yml`, directory sync, manual
deployment. Merging alone does not deploy. A successful Arcane sync only means
the spec was submitted; `deploy` waits for service convergence and exits 3 on
automatic rollback. Every service has a healthcheck, `restart_policy`,
`update_config.failure_action=rollback`, and `rollback_config.failure_action=pause`.
Use `stop-first` for host-published sensor ports so two tasks never contend
for the port; the update monitor must outlast health detection.

If a rollout fails, inspect `status` and the Arcane sync, then use
`ops/swarm/stackctl.py rollback <name>` for the previous service spec. Revert
the bad Git commit and deploy the reverted stack before another sync can
reapply it. Keep current and previous config versions with
`ops/swarm/stackctl.py prune <name> --keep 2`; it reads Docker's previous service
spec through the manager and refuses to prune if that check fails. Remove an
old secret only after it is no longer a rollback target.
`ops/swarm/stackctl.py remove <name> --yes`
deletes the sync, services and stack-owned configs after a quiet window;
secrets require separate `secret rm NAME` after checking other users.

Pause uses `ops/swarm/stackctl.py pause <name>` / `resume`: the GitOps gate
closes first, tasks scale to 0, and a quiet window catches in-flight syncs
that try to restore replicas. See [the pause procedure](../../docs/OPERATIONS.md#swarm-stacks-scale-to-0-not-docker-pause-3590).
For node maintenance use [drain](#runbook-node-maintenance-drain--work--active),
then restore the node's recorded availability.

## How it was applied (and how to re-apply)

One host at a time. Before **every** network, firewall or swarm change, arm a dead-man and confirm its timer is active. Then change, prove from outside and inside, and only then disarm. Probes after each step: fresh `ssh HOST` from the workstation, `honeypot-v2*` count rising with recent public `source.ip`, Arcane environment `precision` `online`, runners online, `docker node ls` from a manager.

| Dead-man | Host | Restores |
|---|---|---|
| `network-rollback.sh backup` / `arm DIR 10min` → `swarm-net-rollback-3589` | homeserver, precision | `/etc/wireguard`, `wg-quick@*` and `peer-route` state, routes, the Arcane user unit, the `DOCKER-USER` hub policy |
| `swarm-plane.sh backup` / `ROLLBACK_UNIT=fw-rollback-3589 swarm-plane.sh arm DIR 10min` | all | `/etc/firewalld` and NM zone bindings |
| `vps-hub-peer.sh arm PUBKEY 10min` → `vps-hub-peer-rollback-3589` | VPS | removes that one hub peer and restores `wg0.conf`, **without** touching the homeserver peer (no `syncconf` or restart) |
| `swarm-membership.sh arm 10min` → user unit `swarm-membership-rollback-3589` | workstation | phase-0 membership: homeserver sole manager on `10.254.250.1` (`Pause`), precision worker |

Order used on 2026-10-10:
1. `wireguard-tools` on precision.
2. Keys generated on each host (`umask 077; wg genkey`); only public keys and the PSK are piped host to host. Templates are rendered in place.
3. precision, then homeserver: firewall (adds UDP 51821 from the fibre peer in `apiary-swarm` and UDP 51822 from the peer LAN address in `public`), `wg-fibre` and `wg-lan` up, interfaces bound to `apiary-swarm`. MTU proof with `ping -M do` (below).
4. VPS: `vps-hub-peer.sh arm`, then `add` the precision peer (`10.8.0.3/32`, PSK). precision: `wg0` up, `peer-route.service`. Prove that homeserver↔precision hub traffic does not touch the VPS: the VPS precision-peer counters stay flat while precision pings `10.8.0.2`.
5. `swarm-membership.sh managers` (homeserver re-initialised on `10.8.0.2` with the existing `10.200.0.0/16` /24 address pool, `Pause`, ingress MTU 1310; precision joins as manager on `10.8.0.3`).
6. homeserver `wg0` into `apiary-swarm` plus `home-wg-forward`. Then VPS `wg0` into `apiary-swarm` (`SWARM_SSH_PORT=2222`: VPS port 22 is the cowrie honeypot). `check-home-wg-ports.py LIVE_PORTS` must pass first. Watch the `APIARY-WG-IN` DROP counter: it must not grow with normal traffic.
7. VPS: `live-restore` off via `systemctl reload docker` (no container restart; swarm refuses live-restore), then `swarm-membership.sh join-vps` and `labels`.
8. `arcane-fibre-tunnel` switched to `xore@10.8.0.2`, after pinning `10.8.0.2` in its `known_hosts` only if its key equals the trusted `10.254.250.1` entry, and adding `10.8.0.3` to the `from=` of its `authorized_keys` line.

### Proofs to repeat after any change

- **MTU**, `ping -M do` (payload = MTU − 28): `wg-fibre` `-s 8892` passes, `-s 8893` → `Message too long`; `wg-lan` `-s 1472`/`1473`; hub `wg0` `-s 1392`/`1393`; raw fibre `-s 8972`.
- **Fibre failover:** on precision, drop all traffic on the fibre inside a dead-man:
  ```sh
  sudo systemd-run --on-active=3min --unit=fibre-cut-rollback-3589 /usr/sbin/nft delete table inet cut3589
  sudo nft -f - <<'EOF'
  table inet cut3589 {
    chain in  { type filter hook input  priority -300; iifname "enp4s0f1" drop; }
    chain out { type filter hook output priority -300; oifname "enp4s0f1" drop; }
  }
  EOF
  ```
  Expected: `ip route show exact 10.8.0.2/32` names `wg-lan` within about 3 s, both managers stay `Ready`/`Leader`/`Reachable`, Arcane `precision` stays `online`, and after `nft delete table inet cut3589` the route returns to `wg-fibre` without loss. Measured on 2026-10-10: a 2.7 s gap, and no Raft election.
- **Outside:** `nmap -Pn -sT -sU -p T:2377,7946,U:7946,4789` against the VPS public address and both LAN addresses: TCP `filtered`, UDP `open|filtered`, logged as `apiary-swarm-lan:`.

## Runbook: node maintenance (drain → work → active)

1. Record state: `docker node ls`, `docker node inspect NODE --format '{{.Spec.Availability}}'`, active CI jobs (`gh api repos/Xore-Inc/APIARY/actions/runners`), any running backfill, and the `honeypot-v2*` count.
2. Wait until no CI job or backfill would be cut off. For precision, also stop the runner units if the work restarts Docker.
3. `docker node update --availability drain NODE` (from a manager). Draining moves tasks; it does **not** remove a manager's Raft vote.
4. Do the work. **Powering off or rebooting a manager loses quorum**: running tasks continue, but nothing schedules until it is back. Keep the window short, and never take both managers down. Losing the VPS worker costs only its tasks.
5. Restore the recorded availability: precision and VPS `active`; homeserver `pause`, never `active` (#3583).
6. Verify: `docker node ls` from both managers (all `Ready`, one Leader), `wg show` handshakes on the node's tunnels, `ip route show exact 10.8.0.2/32` (or `10.8.0.3/32`) via `wg-fibre`, `peer-route.service` active, Arcane `precision` online, runners online, ingest rising with public `source.ip`.

## Runbook: restart after a precision storage migration or reboot

Lesson from #3584: Docker and the runners must never start on empty mountpoints.
1. **Before** starting Docker or runners: compare the storage UUID in `hosts/precision-fstab.fragment` and `/etc/fstab` with `blkid -s UUID -o value /dev/md126p1` (a reinstall can change it). Run `findmnt --mountpoint PATH -o TARGET,SOURCE,FSTYPE` separately for `/var/lib/precision-storage`, `/var/lib/docker`, `/var/lib/github-runners`, and `/var/lib/github-runner-data`. The first must be the XFS volume and the other three binds from `/var/lib/precision-storage/live/*`. If one is missing, **stop**: starting on the root filesystem creates divergent state.
2. Network: `nm-profiles.sh check hosts/precision.nm`; `wg show` for `wg0`, `wg-fibre` and `wg-lan`; `systemctl is-active peer-route.service`; `ip route show exact 10.8.0.2/32` via `wg-fibre`; `firewall-cmd --get-active-zones` lists `enp4s0f1 wg0 wg-fibre wg-lan` in `apiary-swarm`.
3. Docker: `docker info` (swarm `active`, NodeAddr `10.8.0.3`, manager), and `docker node ls` from both managers.
4. Arcane: `systemctl --user is-active arcane-fibre-tunnel`, `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:13552/api/health` → 200, and environment `precision` `online` in the manager.
5. Runners: every unit in `hosts/precision-runners.txt` active and online in GitHub. `ci-registry-mirror.service` active, published on `172.16.0.1:5555` only.
6. Run a GitOps sync, and confirm homeserver ingest is still rising with public `source.ip`.

## Runbook: key rotation

Run on suspected compromise or yearly, one tunnel at a time, inside the dead-man of the host whose key changes (procedure and rationale: [docs/SWARM-NETWORK.md](../../docs/SWARM-NETWORK.md#key-handling-and-rotation)).
- **`wg-fibre` / `wg-lan`** (homeserver↔precision): rotate one side while the other tunnel carries the hub route. Example: rotating `wg-fibre`, first confirm the failover proof above works. Then generate the new key on the host, pipe the new public key into the peer's config, and `wg set` both ends; `peer-route` fails over and back on its own. Record the date on the issue.
- **Hub `wg0`, precision spoke:** generate a new precision `wg0.key` and a new PSK on the VPS (`wg genpsk`). On the VPS, `vps-hub-peer.sh arm OLD.pub`, then add the new peer with `vps-hub-peer.sh add` and remove the old one with `wg set wg0 peer OLD remove` (and its `wg0.conf` block). Re-render precision `wg0.conf`, then `systemctl restart wg-quick@wg0` on precision. Precision's hub path carries only VPS↔precision swarm traffic.
- **Hub `wg0`, homeserver spoke or VPS key:** this tunnel carries live sensor forwarding. Use `scripts/install-homeserver.sh`'s `step_wireguard_sync_vps_peer` path, inside a VPS dead-man, with ingest probes, at a quiet time. A VPS key change also needs re-rendering precision `wg0.conf`.
- **Arcane tunnel SSH key:** a new key pair in `/var/lib/github-runners/precision-services/arcane/ssh/` on precision, and a matching update of the restricted line from `hosts/homeserver-arcane-authorized_keys.fragment`.

## Known consequences

- The VPS dockerd now runs without `live-restore` (swarm requirement). A dockerd restart there restarts portbridge and the edge containers; restart policies bring them back.
- `scripts/install-vps.sh` renders a `[Peer]` for every spoke in `hosts/hub-peers.txt` (#3619). It takes the keys from that spoke's block in the current `wg0.conf`, or else from `/etc/wireguard/<name>.pub`/`.psk`. On a rebuild, restore `/etc/wireguard` from the backup (`vps/wireguard/`) first. A spoke with no keys is skipped with a warning, and the installer summary lists it. Re-add it with `vps-hub-peer.sh add`. The homeserver spoke is never skipped: without a key it gets a placeholder that `install-homeserver.sh` replaces.
- Dry-run the hub render on the VPS (read-only, prints no secrets): `sudo sh ops/swarm/vps-hub-peer.sh render ops/swarm/hosts/hub-peers.txt 10.8.0.2 | grep -v '^PresharedKey'`, then compare the `PublicKey`/`AllowedIPs` pairs with `sudo wg show wg0 allowed-ips`.
- The Arcane manager stays a Compose project; phase 3 (#3590) moves stacks under Arcane GitOps.
