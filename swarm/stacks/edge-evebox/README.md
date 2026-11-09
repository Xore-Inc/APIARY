# edge-evebox (#3595, phase 8)

The socat between the `oidc-evebox` gateway and EveBox on the homeserver
(`10.8.0.2:19636`, evebox `:5636`), as a swarm stack pinned to the VPS
(`node.labels.edge == true`). Third edge service after `edge-unsloth` and
`edge-revdeck`, and the first with a live upstream.

Network: the stack owns the attachable overlay `edge-evebox_gw`
(`10.200.12.0/24`). The socat answers there as `socat-hp-evebox`, the name
the gateway already uses (`OAUTH2_PROXY_UPSTREAMS`). `vps/docker-compose.yml`
adds that overlay to `oidc-evebox` as an external network, so **deploy this
stack before `oidc-evebox` starts** (also on a VPS rebuild). Egress to
`10.8.0.2` leaves through `docker_gwbridge`, masqueraded to `10.8.0.1` on
`wg0`, the same source the Compose socat had.

Traefik's direct service `honeypot-evebox` (`http://socat-hp-evebox:5636`)
is referenced by no router (the `evebox.<domain>` router uses `oidc-evebox`);
Traefik is not on the overlay, so that unused service no longer resolves.

## Cutover

1. `ops/swarm/stackctl.py ensure edge-evebox` (creation deploys); wait for
   the task `healthy` on the VPS.
2. On the VPS (`/root/vps`, live file edited surgically with a backup, as in
   this commit): stop and remove the Compose `socat-hp-evebox`, then
   `docker compose up -d --no-deps --force-recreate --wait oidc-evebox` so
   the gateway joins the overlay.
3. Prove: on the overlay, `socat-hp-evebox` resolves to the stack VIP and an
   HTTP request to `:5636` gets EveBox's `200`; `https://evebox.<domain>/`
   still redirects to the Keycloak login.

## Rollback

```bash
cd /root/vps
docker compose --profile legacy up -d socat-hp-evebox   # Compose socat back on oidc-evebox
ops/swarm/stackctl.py pause edge-evebox                 # from the workstation
```

The gateway keeps both networks; with the stack at 0 the name resolves only
to the Compose socat. To remove the stack, disconnect `oidc-evebox` from
`edge-evebox_gw` first (see the subnet note in `ops/swarm/README.md`).
