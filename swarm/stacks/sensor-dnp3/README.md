# sensor-dnp3 (#3593, phase 6)

The DNP3 decoy `hp-dnp3` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing 20000/tcp in `mode: host`. The
image is the GHCR build of the same source as the Compose service
(`arcane/home/honeypot-dnp3/dnp3-honeypot`), pinned by digest from the
`image-digests` manifest of Containers run 41249267202 (`main` 1bbdd955).

## Cutover

1. `home-swarm-host-guard` is active with `tcp 20000` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the project):
   `docker compose -p honeypot-dnp3 stop dnp3` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-dnp3` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (`portbridge` → `10.8.0.2:20000`) appears in
     `honeypot-v2` with a public `source.ip`, not `10.8.0.1`;
   - from the LAN, `nmap -Pn -p 20000 <homeserver LAN address>` is
     `filtered`, with an `apiary-swarm-host:` line in the kernel log.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-dnp3      # scale to 0, GitOps gate closed
# on the homeserver, in the deployed honeypot-dnp3 project:
docker compose -p honeypot-dnp3 start dnp3
```

`stackctl.py remove sensor-dnp3 --yes` deletes the stack and its sync once
the Compose service is serving again.
