# sensor-sonicwall-sma (#3593, phase 6)

The SonicWall SMA1000 decoy `hp-sonicwall-sma-honeypot` as a swarm stack
pinned to the homeserver (`node.labels.sensor == true`), publishing host port
8543/tcp (container 8443) in `mode: host`. From the VPS, portbridge forwards
public 8543 there with a PROXY header. The image is the GHCR build of the same
source as the Compose service
(`arcane/home/honeypot-sonicwall-sma/sonicwall-sma-honeypot`), pinned by
digest from the `image-digests` manifest of Containers run 41897572162
(`main` 63c9e6dd).

The decoy's AMC relay still calls api-honeypot at `10.8.0.2:18083` (Compose).
From the overlay that call leaves through `docker_gwbridge` and the published
port, the same way it left the Compose bridge.

## Cutover

1. `home-swarm-host-guard` is active with `tcp 8543` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the container as the rollback):
   `docker stop hp-sonicwall-sma-honeypot` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-sonicwall-sma` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (public 8543, `portbridge` → `10.8.0.2:8543`)
     appears in `honeypot-v2` with a public `honeypot.src_ip`;
   - a TCP connect from the overlay to `10.8.0.2:18083` still succeeds;
   - from the LAN, `nmap -Pn -p 8543 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 8543 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-sonicwall-sma   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-sonicwall-sma-honeypot
```

`stackctl.py remove sensor-sonicwall-sma --yes` deletes the stack and its sync
once the Compose service is serving again.
