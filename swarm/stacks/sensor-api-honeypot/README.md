# sensor-api-honeypot (#3593, phase 6)

The API/cloud decoy `hp-api-honeypot` as a swarm stack pinned to the
homeserver (`node.labels.sensor == true`), publishing host port 18083/tcp
(container 8080) in `mode: host`. From the VPS, portbridge forwards public 8888
there with a PROXY header. The image is the same GHCR build as `sensor-http`
(`arcane/home/honeypot-http/http-honeypot`, digest `a44e608b…`), so both decoys
run one artifact. `http-honeypot` already runs as `sensor-http`.

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with `tcp 18083` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the container as the rollback):
   `docker stop hp-api-honeypot` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-api-honeypot` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (public 8888, `portbridge` → `10.8.0.2:18083`)
     appears in `honeypot-v2` with the prober's public `honeypot.src_ip`;
   - the sonicwall-sma task's AMC relay hop still connects to
     `10.8.0.2:18083` (from the task's network namespace);
   - from the LAN, `nmap -Pn -p 18083 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 18083 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-api-honeypot   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-api-honeypot
```

`stackctl.py remove sensor-api-honeypot --yes` deletes the stack and its sync once the
Compose service is serving again.
