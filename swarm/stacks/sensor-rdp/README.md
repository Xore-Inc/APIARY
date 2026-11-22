# sensor-rdp (#3593, phase 6)

The RDP decoy `hp-rdp-honeypot` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing host port 3389/tcp in `mode: host`.
From the VPS, portbridge forwards public 3389 there with a PROXY header. The
image is the GHCR build of `arcane/home/honeypot-rdp-honeypot/rdp-honeypot`,
pinned by digest from the `image-digests` manifest of Containers run
42420198997 (`main` 28edd73c). RDP to the libvirt guests is routed, never
DNATed, so the guard does not touch it (#3769).

## Cutover

1. `home-swarm-host-guard` (DNAT-scoped since #3769) is active with `tcp 3389` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the container as the rollback):
   `docker stop hp-rdp-honeypot` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-rdp` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - an RDP connection request through the VPS (public 3389, `portbridge` →
     `10.8.0.2:3389`) appears in `honeypot-v2` with the prober's public
     `honeypot.src_ip`;
   - from the LAN, `nmap -Pn -p 3389 <homeserver LAN address>` is
     `filtered`, and the guard's LOG/DROP counters for 3389 increase.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-rdp   # scale to 0, GitOps gate closed
# on the homeserver:
docker start hp-rdp-honeypot
```

`stackctl.py remove sensor-rdp --yes` deletes the stack and its sync once the
Compose service is serving again.
