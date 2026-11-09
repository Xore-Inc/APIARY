# sensor-cowrie (#3593, phase 6)

The decoy `hp-cowrie` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing host ports 19022/tcp (SSH, container 2222) and 19023/tcp (Telnet, container 2223) in `mode: host`.
The image is the GHCR build of `arcane/home/honeypot-cowrie/cowrie`, pinned by digest from the
`image-digests` manifest of Containers run 42486586288 (`main` 55615661).

Privilege gate (#3593 audit, 2026-11-08): the image keeps Debian's stock
setuid/setgid tools (`su`, `passwd`, `mount`, `chfn`, ...) and has no file
capability (`getcap -r` on the exported image). The running service never
execs them: the live Compose container already runs with
`no-new-privileges`, which makes them inert, and works. The stack sets
`security_opt: [no-new-privileges:true]` per service (Arcane's stack deploy
carries it into the service spec), with `cap_drop: ALL`, `read_only` and the
image's non-root user.

`cowrie.cfg` and `userdb.txt` come from the image (byte-identical to the
repository files the Compose project mounts). The DMI identity files are
swarm configs: `configs/dmi_*` are copies of
`arcane/home/honeypot-cowrie/cowrie/fakefs/sys/class/dmi/id/*`; when those
change, update the copies and bump the `_vN` names. `hp-honeyfs-implant`
stays in the Compose project and keeps writing the shared honeyfs and marker
paths; an implant marker fails the healthcheck and swarm replaces the task,
which re-merges honeyfs on start (the job autoheal did under Compose).

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with `tcp 19022` and `tcp 19023` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Set `autoSync: false` on the Arcane sync of the Compose project, then stop
   the Compose service (keep the container as the rollback):
   `docker stop hp-cowrie` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-cowrie` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`, with `NoNewPrivs: 1` in
     `/proc/<pid>/status`;
   - an SSH and a Telnet session through the VPS (public 22/23, `portbridge` → `10.8.0.2:19022/19023`) request through the VPS appears in `honeypot-v2` (same `/logs/enriched/` path and field paths) with the prober's public `honeypot.src_ip`, attributed by the ip_enrichment tunnel join (portbridge has no PROXY header on this port; host mode keeps the source port the join reads);
   - from the LAN, `nmap -Pn` on the homeserver LAN address shows the port(s)
     `filtered`, and the guard's LOG/DROP counters increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-cowrie   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-cowrie
```

`stackctl.py remove sensor-cowrie --yes` deletes the stack and its sync once the
Compose service is serving again.
