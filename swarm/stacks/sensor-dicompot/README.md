# sensor-dicompot (#3593, phase 6)

The DICOM decoy `hp-dicompot` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing 11112/tcp in `mode: host`. The
image is the GHCR build of the same source as the Compose service
(`arcane/home/honeypot-dicompot/dicompot`), pinned by digest from the
`image-digests` manifest of Containers run 41194988399 (`main` e338aed0).

## Cutover

1. `home-swarm-host-guard` is active with `tcp 11112` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the project):
   `docker compose -p honeypot-dicompot stop dicompot` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-dicompot` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (`portbridge` → `10.8.0.2:11112`) appears in
     `honeypot-v2` with a public `source.ip`, not `10.8.0.1`;
   - from the LAN, `nmap -Pn -p 11112 <homeserver LAN address>` is
     `filtered`, with an `apiary-swarm-host:` line in the kernel log.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-dicompot      # scale to 0, GitOps gate closed
# on the homeserver, in the deployed honeypot-dicompot project:
docker compose -p honeypot-dicompot start dicompot
```

`stackctl.py remove sensor-dicompot --yes` deletes the stack and its sync once
the Compose service is serving again.
