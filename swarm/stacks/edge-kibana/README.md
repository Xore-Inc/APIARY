# edge-kibana (#3595, phase 8)

The socat between the `oidc-kibana` gateway and Kibana on the homeserver
(`10.8.0.2:19601`, `:5601`), as a swarm stack pinned to the VPS
(`node.labels.edge == true`). Sixth edge service, after `edge-tanner`, with a live upstream.

Network: the stack owns the attachable overlay `edge-kibana_gw`
(`10.200.15.0/24`). The socat answers there as `socat-hp-kibana`, the name
the gateway already uses (`OAUTH2_PROXY_UPSTREAMS`). `vps/docker-compose.yml`
adds that overlay to `oidc-kibana` as an external network, so **deploy this
stack before `oidc-kibana` starts** (also on a VPS rebuild). Egress to
`10.8.0.2` leaves through `docker_gwbridge`, masqueraded to `10.8.0.1` on
`wg0`, the same source the Compose socat had.

Traefik's direct service `honeypot-kibana` (`http://socat-hp-kibana:5601`)
is referenced by no router (the `kibana.<domain>` router uses `oidc-kibana`);
Traefik is not on the overlay, so that unused service no longer resolves.

## Cutover

1. `ops/swarm/stackctl.py ensure edge-kibana` (creation deploys); wait for
   the task `healthy` on the VPS.
2. On the VPS (`/root/vps`, live file edited surgically with a backup, as in
   this commit): stop and remove the Compose `socat-hp-kibana`, then
   `docker compose up -d --no-deps --force-recreate --wait oidc-kibana` so
   the gateway joins the overlay.
3. Prove: on the overlay, `socat-hp-kibana` resolves to the stack VIP and an
   HTTP request to `:5601` gets Kibana's usual answer; `https://kibana.<domain>/`
   still redirects to the Keycloak login.

## Rollback

```bash
cd /root/vps
docker compose --profile legacy up -d socat-hp-kibana   # Compose socat back on oidc-kibana
ops/swarm/stackctl.py pause edge-kibana                 # from the workstation
```

The gateway keeps both networks; with the stack at 0 the name resolves only
to the Compose socat. To remove the stack, disconnect `oidc-kibana` from
`edge-kibana_gw` first (see the subnet note in `ops/swarm/README.md`).
