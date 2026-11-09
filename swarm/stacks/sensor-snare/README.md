# sensor-snare (#3593, phase 6)

The web decoy `hp-snare` as a swarm stack pinned to the homeserver
(`node.labels.sensor == true`), publishing host port 19082/tcp (container
8080) in `mode: host`. The VPS reaches it through Traefik
(`www-portal`/`snare` hosts → `socat-hp-snare:8082` → `10.8.0.2:19082`).
The image is the GHCR build of `arcane/home/honeypot-tanner/snare`, pinned by
digest from the `image-digests` manifest of Containers run 42490632043
(`main` b38894a3); it bakes `PAGE_URL`, `TANNER=tanner` and `PORT=8080`, the
same values as the Compose build args.

Privilege gate (#3593 audit, 2026-11-08): Debian's stock setuid/setgid tools,
no file capability. Snare starts as root, removes its state files, and drops
to 65534 by `setuid()`/`setgid()`; it never execs a setuid tool. The stack
sets `no-new-privileges` per service, `read_only`, `cap_drop: ALL` plus the
measured SETUID and SETGID. It adds a TCP healthcheck on 8080 (Compose had
none).

## Tanner (option 1, Xore 2026-11-08)

Snare posts every request to `http://tanner:8090/event`. Tanner and its group
stay on Compose. This stack owns the attachable overlay `sensor-snare_decoy`
(`10.200.29.0/24`); only `hp-tanner` joins it, as an external network in
`arcane/home/honeypot-tanner/compose.yml`, where Compose aliases it `tanner`.
`tanner_local` stays first in its list and keeps its default route.
`hp-tanner-docker` is untouched. Tanner never calls snare.

Snare follows the tanner group's pause policy (`NEVER` in
`scripts/honeypot-pause.sh`), so the stack is labelled `apiary.pause: never`
and `stackctl pause` refuses it.

## Cutover

1. `home-swarm-host-guard` is active with `tcp 19082` in
   `/etc/apiary/homeserver-swarm-host-ports.txt`.
2. The Arcane sync of `honeypot-tanner` has `autoSync: false`. Stop the
   Compose snare and keep it as the rollback: `docker stop hp-snare`.
3. Apply this change's `honeypot-tanner/compose.yml` diff to the live file
   (backup alongside) before the stop in step 2, so the join is ready.
4. Start `ops/swarm/stackctl.py ensure sensor-snare` and, **while it waits**,
   join tanner as soon as `sensor-snare_decoy` exists: recreate only tanner
   (`docker compose up -d --no-deps --no-build tanner` in the project dir; a
   build service needs its image under the Compose default name, e.g.
   `docker tag arcane.local/honeypot-tanner-<id>/tanner:latest
   honeypot-tanner-tanner:latest`). Snare exits at startup until
   `http://tanner:8090/version` answers, so the task cannot converge, and
   `ensure` cannot return, before tanner is on the overlay. The first cutover
   (2026-11-08) joined tanner only after `ensure` hung, and snare was down
   ~3m40s instead of ~30 s.
5. Prove: the task is `healthy` with `NoNewPrivs: 1`; a request with a unique
   path through the public host produces a tanner analysis in `honeypot-v2`
   (`/logs/enriched/tanner.json`), as before; tanner's access log shows the
   POST from snare's overlay address; LAN `nmap -Pn` 19082 `filtered`.

## Rollback

```bash
ops/swarm/stackctl.py remove sensor-snare --yes   # never-pause: remove instead
# on the homeserver:
docker start hp-snare
```

`hp-snare` reaches tanner on `tanner_local` as before. hp-tanner can stay on
the overlay; restore the compose backup and recreate tanner to detach it.
