# sensor-endlessh (#3593, phase 6)

The endlessh SSH tarpit `hp-endlessh` as a swarm stack pinned to the
homeserver (`node.labels.sensor == true`), publishing host port 19024/tcp
(container 2222) in `mode: host`; portbridge forwards public 2022 there. The
image is the GHCR build of the same source as the Compose service
(`arcane/home/honeypot-endlessh/endlessh-honeypot`), pinned by digest from the
`image-digests` manifest of Containers run 41249267202 (`main` 1bbdd955).

## Cutover

1. `home-swarm-host-guard` is active with `tcp 19024` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. Stop the Compose service (keep the project):
   `docker compose -p honeypot-endlessh stop endlessh` on the homeserver.
3. `ops/swarm/stackctl.py ensure sensor-endlessh` (creation deploys).
4. Prove:
   - the task runs on `supermicro`, `healthy`;
   - a request through the VPS (public 2022, `portbridge` → `10.8.0.2:19024`) appears in
     `honeypot-v2` with a public `source.ip`, not `10.8.0.1`;
   - from the LAN, `nmap -Pn -p 19024 <homeserver LAN address>` is
     `filtered`, with an `apiary-swarm-host:` line in the kernel log.

## Rollback

```bash
ops/swarm/stackctl.py pause sensor-endlessh      # scale to 0, GitOps gate closed
# on the homeserver, in the deployed honeypot-endlessh project:
docker compose -p honeypot-endlessh start endlessh
```

`stackctl.py remove sensor-endlessh --yes` deletes the stack and its sync once
the Compose service is serving again.
