# edge-tanner (#3595, phase 8)

The socat between the `oidc-tanner` gateway and Tanner on the homeserver
(`10.8.0.2:19091`, `:8091`), as a swarm stack pinned to the VPS
(`node.labels.edge == true`). Fifth edge service, after `edge-arkime`, with a live upstream.

Network: the stack owns the attachable overlay `edge-tanner_gw`
(`10.200.14.0/24`). The socat answers there as `socat-hp-tanner`, the name
the gateway already uses (`OAUTH2_PROXY_UPSTREAMS`). `vps/docker-compose.yml`
adds that overlay to `oidc-tanner` as an external network, so **deploy this
stack before `oidc-tanner` starts** (also on a VPS rebuild). Egress to
`10.8.0.2` leaves through `docker_gwbridge`, masqueraded to `10.8.0.1` on
`wg0`, the same source the Compose socat had.

Traefik's direct service `honeypot-tanner` (`http://socat-hp-tanner:8091`)
is referenced by no router (the `tanner.<domain>` router uses `oidc-tanner`);
Traefik is not on the overlay, so that unused service no longer resolves.

## Cutover

1. `ops/swarm/stackctl.py ensure edge-tanner` (creation deploys); wait for
   the task `healthy` on the VPS.
2. On the VPS (`/root/vps`, live file edited surgically with a backup, as in
   this commit): stop and remove the Compose `socat-hp-tanner`, then
   `docker compose up -d --no-deps --force-recreate --wait oidc-tanner` so
   the gateway joins the overlay.
3. Prove: on the overlay, `socat-hp-tanner` resolves to the stack VIP and an
   HTTP request to `:8091` gets Tanner's usual answer; `https://tanner.<domain>/`
   still redirects to the Keycloak login.

## Rollback

```bash
cd /root/vps
docker compose --profile legacy up -d socat-hp-tanner   # Compose socat back on oidc-tanner
ops/swarm/stackctl.py pause edge-tanner                 # from the workstation
```

The gateway keeps both networks; with the stack at 0 the name resolves only
to the Compose socat. To remove the stack, disconnect `oidc-tanner` from
`edge-tanner_gw` first (see the subnet note in `ops/swarm/README.md`).
