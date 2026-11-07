# sensor-conpot-kamstrup (#3593, phase 6)

The Conpot Kamstrup 382 smart meter persona `hp-conpot-kamstrup` as a swarm stack pinned
to the homeserver (`node.labels.sensor == true`), publishing host port(s)
1025/50100/tcp in `mode: host`. From the VPS, portbridge forwards public 1025/50100
there with a PROXY header. The image is the GHCR build of the same source as
the Compose service (`arcane/home/honeypot-conpot/conpot`), pinned by digest
from the `image-digests` manifest of Containers run 42260963789 (`main`
cba48317). The base `hp-conpot` (low/shared ports 102/161/502/44818/47808) stays on Compose (#3769).

`/usr/bin/python3.12` in the image has the file capability
`cap_net_bind_service=ep`. Xore accepted it on 2026-11-06: the task's bounding
set is `NET_BIND_SERVICE` only, so exec cannot gain more than the service is
granted.

## Cutover

1. `home-swarm-host-guard` is active with `tcp 1025 / tcp 50100` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the container as the rollback):
   `docker stop hp-conpot-kamstrup` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-conpot-kamstrup` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a Kamstrup 382 smart meter request through the VPS (public 1025/50100, `portbridge`
     `:pp`) appears in `honeypot-v2` with a public
     `honeypot.src_ip`;
   - from the LAN, `nmap -Pn -p 1025,50100 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 1025/50100 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-conpot-kamstrup   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-conpot-kamstrup
```

`stackctl.py remove sensor-conpot-kamstrup --yes` deletes the stack and its
sync once the Compose service is serving again.
