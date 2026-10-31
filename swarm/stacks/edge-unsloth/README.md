# edge-unsloth (#3595, phase 8)

The socat between the `oidc-unsloth` gateway and Unsloth Studio on the
homeserver (`10.8.0.2:8899`, #3689), as a swarm stack pinned to the VPS
(`node.labels.edge == true`). It is the first edge service moved because it
carries no live traffic: Studio is not deployed, so the gateway answers
after login with an upstream error either way.

Network: the stack owns the attachable overlay `edge-unsloth_gw`. The
socat answers there as `socat-hp-unsloth`, the name the gateway already
uses (`OAUTH2_PROXY_UPSTREAMS`). `vps/docker-compose.yml` adds that overlay
to `oidc-unsloth` as an external network, so **deploy this stack before
`oidc-unsloth` starts** (also on a VPS rebuild). Egress to `10.8.0.2` leaves
through `docker_gwbridge`, masqueraded to `10.8.0.1` on `wg0`, the same
source the Compose socat had.

## Cutover

1. `ops/swarm/stackctl.py ensure edge-unsloth` (creation deploys); wait for
   the task `healthy` on the VPS.
2. On the VPS (`/root/vps`, live file edited surgically with a backup, as in
   this commit): stop and remove the Compose `socat-hp-unsloth`, then
   `docker compose up -d --no-deps oidc-unsloth` so the gateway joins the
   overlay.
3. Prove: from `oidc-unsloth`, `socat-hp-unsloth` resolves to the overlay
   address; `https://unsloth.<domain>/` still redirects to the Keycloak
   login; the socat log shows the gateway's connection attempt.

## Rollback

```bash
cd /root/vps
docker compose --profile legacy up -d socat-hp-unsloth   # Compose socat back on oidc-unsloth
ops/swarm/stackctl.py pause edge-unsloth                 # from the workstation
```

The gateway keeps both networks; with the stack at 0 the name resolves only
to the Compose socat.
