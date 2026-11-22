# sensor-elasticpot (#3593, phase 6)

The decoy `hp-elasticpot` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing host port 9201/tcp (container 9200) in `mode: host`.
The image is the GHCR build of `arcane/home/honeypot-elasticpot/elasticpot`, pinned by digest from the
`image-digests` manifest of Containers run 42486586288 (`main` 55615661).

Privilege gate (#3593 audit, 2026-11-08): the image keeps Debian's stock
setuid/setgid tools (`su`, `passwd`, `mount`, `chfn`, ...) and has no file
capability (`getcap -r` on the exported image). The running service never
execs them: the live Compose container already runs with
`no-new-privileges`, which makes them inert, and works. The stack sets
`security_opt: [no-new-privileges:true]` per service (Arcane's stack deploy
carries it into the service spec), with `cap_drop: ALL`, `read_only` and the
image's non-root user.

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with `tcp 9201` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Set `autoSync: false` on the Arcane sync of the Compose project, then stop
   the Compose service (keep the container as the rollback):
   `docker stop hp-elasticpot` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-elasticpot` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`, with `NoNewPrivs: 1` in
     `/proc/<pid>/status`;
   - an HTTP request through the VPS (public 9201, `portbridge` → `10.8.0.2:9201`) appears in `honeypot-v2` (same path and field paths). The tunnel join does not attribute elasticpot today, under Compose either (it compares the container port 9200 with portbridge's target 9201, #3811), so the proof is the unchanged event plus the source port the join would read;
   - from the LAN, `nmap -Pn` on the homeserver LAN address shows the port(s)
     `filtered`, and the guard's LOG/DROP counters increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-elasticpot   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-elasticpot
```

`stackctl.py remove sensor-elasticpot --yes` deletes the stack and its sync once the
Compose service is serving again.
