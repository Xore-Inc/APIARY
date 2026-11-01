# sensor-http (#3593, phase 6)

The web decoy `hp-http` (`http-honeypot`) as a swarm stack pinned to the
homeserver (`node.labels.sensor == true`), publishing host port 19081/tcp
(container 8080) in `mode: host`. From the VPS, portbridge forwards public
8081 there with a PROXY header, and Traefik reaches it through
`socat-hp-http`. The image is the GHCR build of the same source as the
Compose service (`arcane/home/honeypot-http/http-honeypot`), pinned by digest
from the `image-digests` manifest of Containers run 41249267202 (`main`
1bbdd955). `api-honeypot` (same project, same image) stays on Compose.

## Cutover

1. `home-swarm-host-guard` is active with `tcp 19081` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the project and api-honeypot running):
   `docker stop hp-http` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-http` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (public 8081, `portbridge` → `10.8.0.2:19081`)
     appears in `honeypot-v2` with a public `honeypot.src_ip`;
   - from the LAN, `nmap -Pn -p 19081 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 19081 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-http      # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-http
```

`stackctl.py remove sensor-http --yes` deletes the stack and its sync once the
Compose service is serving again.
