# sensor-hellpot (#3593, phase 6)

The HTTP tarpit `hp-hellpot` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing host ports 8080/tcp and 8090/tcp in
`mode: host`. From the VPS, portbridge forwards public 8080 to 8080 (no PROXY
header: HellPot has none, and ip-enrichment-worker joins on portbridge's
connection log via the tunnel peer's source port), and Traefik reaches the
second listener 8090 through `socat-hp-hellpot` (#1908). The image is the GHCR
build of `arcane/home/honeypot-hellpot/hellpot`, pinned by digest from the
`image-digests` manifest of Containers run 42420198997 (`main` 28edd73c).

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with `tcp 8080` and `tcp 8090` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the container as the rollback):
   `docker stop hp-hellpot` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-hellpot` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (public 8080, `portbridge` → `10.8.0.2:8080`)
     appears in `honeypot-v2` with the prober's public `honeypot.src_ip`;
   - containers on their own networks still reach `hp-keycloak:8080`,
     `hp-dashboard-next:8080` and `hp-canarytokens-adapter:8090`;
   - from the LAN, `nmap -Pn -p 8080,8090 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 8080,8090 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-hellpot   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-hellpot
```

`stackctl.py remove sensor-hellpot --yes` deletes the stack and its sync once the
Compose service is serving again.
