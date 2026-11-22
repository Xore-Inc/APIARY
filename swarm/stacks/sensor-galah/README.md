# sensor-galah (#3593, phase 6)

The decoy `hp-galah` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing host ports 8888/tcp and 8890/tcp in `mode: host`.
The image is the GHCR build of `arcane/home/honeypot-galah/galah`, pinned by digest from the
`image-digests` manifest of Containers run 42486586288 (`main` 55615661).

Privilege gate (#3593 audit, 2026-11-08): the image keeps Debian's stock
setuid/setgid tools (`su`, `passwd`, `mount`, `chfn`, ...) and has no file
capability (`getcap -r` on the exported image). The running service never
execs them: the live Compose container already runs with
`no-new-privileges`, which makes them inert, and works. The stack sets
`security_opt: [no-new-privileges:true]` per service (Arcane's stack deploy
carries it into the service spec), with `cap_drop: ALL`, `read_only` and the
image's non-root user.

**Cut over only in the post-benchmark window.** Galah's replies come from
the LLM broker (`galah-broker` stack, held at 0/0 while #3706 runs), so the
LLM path from this task cannot be proven before then. Deploying this stack
starts no Ollama consumer: galah talks only to the broker. Scale the broker
back first (LOG.md resume steps), then cut over.

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with `tcp 8888` and `tcp 8890` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Set `autoSync: false` on the Arcane sync of the Compose project, then stop
   the Compose service (keep the container as the rollback):
   `docker stop hp-galah` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-galah` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`, with `NoNewPrivs: 1` in
     `/proc/<pid>/status`;
   - an HTTP request through the VPS (public 8889, `portbridge` → `10.8.0.2:8888`) gets an LLM-generated reply through the broker, and request through the VPS appears in `honeypot-v2` (same `/logs/enriched/` path and field paths) with the prober's public `honeypot.src_ip`, attributed by the ip_enrichment tunnel join (portbridge has no PROXY header on this port; host mode keeps the source port the join reads);
   - from the LAN, `nmap -Pn` on the homeserver LAN address shows the port(s)
     `filtered`, and the guard's LOG/DROP counters increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-galah   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-galah
```

`stackctl.py remove sensor-galah --yes` deletes the stack and its sync once the
Compose service is serving again.
