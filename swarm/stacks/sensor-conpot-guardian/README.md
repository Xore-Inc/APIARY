# sensor-conpot-guardian (#3593, phase 6)

The Conpot Guardian AST persona `hp-conpot-guardian` as a swarm stack pinned
to the homeserver (`node.labels.sensor == true`), publishing host port
10001/tcp in `mode: host`. From the VPS, portbridge forwards public 10001
there with a PROXY header. The image is the GHCR build of the same source as
the Compose service (`arcane/home/honeypot-conpot/conpot`), pinned by digest
from the `image-digests` manifest of Containers run 42260963789 (`main`
cba48317). The other Conpot personas stay on Compose for now.

`/usr/bin/python3.12` in the image has the file capability
`cap_net_bind_service=ep`. Xore accepted it on 2026-11-06: the task's bounding
set is `NET_BIND_SERVICE` only, so exec cannot gain more than the service is
granted.

## Cutover

1. `home-swarm-host-guard` is active with `tcp 10001` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the container as the rollback):
   `docker stop hp-conpot-guardian` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-conpot-guardian` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a Guardian AST request through the VPS (public 10001, `portbridge` →
     `10.8.0.2:10001`) appears in `honeypot-v2` with a public
     `honeypot.src_ip`;
   - from the LAN, `nmap -Pn -p 10001 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 10001 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-conpot-guardian   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-conpot-guardian
```

`stackctl.py remove sensor-conpot-guardian --yes` deletes the stack and its
sync once the Compose service is serving again.
