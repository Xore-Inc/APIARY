# edge-revdeck (#3595, phase 8)

The socat between the `oidc-revdeck` gateway and revdeck on the homeserver
(`10.8.0.2:19500`, ghidra stack), as a swarm stack pinned to the VPS
(`node.labels.edge == true`). Second edge service after `edge-unsloth`, for
the same reason: no live traffic. revdeck is not deployed on the homeserver
(nothing listens on 19500), so the gateway answers after login with an
upstream error either way.

Network: the stack owns the attachable overlay `edge-revdeck_gw`
(`10.200.8.0/24`). The socat answers there as `socat-hp-revdeck`, the name
the gateway already uses (`OAUTH2_PROXY_UPSTREAMS`). `vps/docker-compose.yml`
adds that overlay to `oidc-revdeck` as an external network, so **deploy this
stack before `oidc-revdeck` starts** (also on a VPS rebuild). Egress to
`10.8.0.2` leaves through `docker_gwbridge`, masqueraded to `10.8.0.1` on
`wg0`, the same source the Compose socat had.

Traefik's direct service `honeypot-revdeck` (`http://socat-hp-revdeck:5000`)
is referenced by no router (the `rev.<domain>` router uses `oidc-revdeck`);
Traefik is not on the overlay, so that unused service no longer resolves.

## Cutover

1. `ops/swarm/stackctl.py ensure edge-revdeck` (creation deploys); wait for
   the task `healthy` on the VPS.
2. On the VPS (`/root/vps`, live file edited surgically with a backup, as in
   this commit): stop and remove the Compose `socat-hp-revdeck`, then
   `docker compose up -d --no-deps --force-recreate --wait oidc-revdeck` so
   the gateway joins the overlay.
3. Prove: on the overlay, `socat-hp-revdeck` resolves to the stack VIP;
   `https://rev.<domain>/` still redirects to the Keycloak login.

## Rollback

```bash
cd /root/vps
docker compose --profile legacy up -d socat-hp-revdeck   # Compose socat back on oidc-revdeck
ops/swarm/stackctl.py pause edge-revdeck                 # from the workstation
```

The gateway keeps both networks; with the stack at 0 the name resolves only
to the Compose socat. To remove the stack, disconnect `oidc-revdeck` from
`edge-revdeck_gw` first (see the subnet note in `ops/swarm/README.md`).
