# edge-arkime (#3595, phase 8)

The socat between the `oidc-arkime` gateway and Arkime on the homeserver
(`10.8.0.2:19080`, `:8005`), as a swarm stack pinned to the VPS
(`node.labels.edge == true`). Fourth edge service, after `edge-evebox`, with a live upstream.

Network: the stack owns the attachable overlay `edge-arkime_gw`
(`10.200.13.0/24`). The socat answers there as `socat-hp-arkime`, the name
the gateway already uses (`OAUTH2_PROXY_UPSTREAMS`). `vps/docker-compose.yml`
adds that overlay to `oidc-arkime` as an external network, so **deploy this
stack before `oidc-arkime` starts** (also on a VPS rebuild). Egress to
`10.8.0.2` leaves through `docker_gwbridge`, masqueraded to `10.8.0.1` on
`wg0`, the same source the Compose socat had.

Traefik's direct service `honeypot-arkime` (`http://socat-hp-arkime:8005`)
is referenced by no router (the `arkime.<domain>` router uses `oidc-arkime`);
Traefik is not on the overlay, so that unused service no longer resolves.

## Cutover

1. `ops/swarm/stackctl.py ensure edge-arkime` (creation deploys); wait for
   the task `healthy` on the VPS.
2. On the VPS (`/root/vps`, live file edited surgically with a backup, as in
   this commit): stop and remove the Compose `socat-hp-arkime`, then
   `docker compose up -d --no-deps --force-recreate --wait oidc-arkime` so
   the gateway joins the overlay.
3. Prove: on the overlay, `socat-hp-arkime` resolves to the stack VIP and an
   HTTP request to `:8005` gets Arkime's usual answer; `https://arkime.<domain>/`
   still redirects to the Keycloak login.

## Rollback

```bash
cd /root/vps
docker compose --profile legacy up -d socat-hp-arkime   # Compose socat back on oidc-arkime
ops/swarm/stackctl.py pause edge-arkime                 # from the workstation
```

The gateway keeps both networks; with the stack at 0 the name resolves only
to the Compose socat. To remove the stack, disconnect `oidc-arkime` from
`edge-arkime_gw` first (see the subnet note in `ops/swarm/README.md`).
