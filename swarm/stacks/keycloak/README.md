# keycloak: Keycloak + PostgreSQL on the homeserver (#3596, swarm phase 9 leg B)

The identity tier as one stack, both services pinned to
`node.hostname == supermicro`, with the same image digests and the same PGDATA
volume as the Compose services in `arcane/home/honeypot-keycloak`. Those two
stay behind `profiles: [legacy]` as the rollback; their containers
`hp-keycloak` and `hp-keycloak-postgres` are kept, stopped.

## Paths

| From | To | How |
|---|---|---|
| Every OIDC client (dashboard, Arcane, the VPS `oidc-*` gateways) | Keycloak | the public issuer → VPS Traefik → `socat-hp-keycloak` → `10.8.0.2:18080` over `wg0` (unchanged) |
| `hp-auth-events-worker` | Keycloak | `http://10.8.0.2:18080` from its bridge (the guard's local-bridge exemption) |
| Keycloak | Postgres | `postgres:5432` on the internal overlay `data` (`10.200.32.0/24`), `endpoint_mode: dnsrr` |
| host tools (`backup-essentials`, `backup-honeypot.sh`, `keycloak/backup.sh`, `restore.sh`) | Postgres | `docker exec` into the task, found by `scripts/lib/task-container.sh` (`keycloak_postgres` first, `hp-keycloak-postgres` second) |

`18080` is a host-mode port, so it binds every homeserver address. It is in
`ops/firewall/hosts/homeserver-swarm-host-ports.txt`; `home-swarm-host-guard`
drops every NEW flow to it except the VPS on `wg0` and local containers to
`10.8.0.2`. From the LAN, port 18080 on the homeserver must time out.
Postgres publishes nothing, and the management port 9000 stays unpublished.

Networks: `data` (internal, both services) and `egress` (`10.200.33.0/24`,
**not** internal, Keycloak only). `egress` carries outbound SMTP/recovery and is
what lets swarm publish the host-mode port at all (phase 9 gate G1).

## Files (no secret or domain in git)

Read-only binds from `/var/dockge/stacks/honeypot-keycloak`, which stays the
source of these files (the `honeypot-keycloak` Arcane sync writes `keycloak/`):

- `secrets/` at `/run/secrets/keycloak`: `postgres-password`, and the
  **`public-domain`** file. The entrypoint reads the first line, refuses to
  start if it is missing, empty or not a bare hostname, and derives
  `KEYCLOAK_PUBLIC_DOMAIN` (realm render) and `KC_HOSTNAME=https://auth.<domain>`.
  Create it from the stack `.env`, `root:root` `0440` like the other secrets:

  ```bash
  sudo sh -c 'umask 337; . /var/dockge/stacks/honeypot-keycloak/.env;
    printf "%s\n" "$KEYCLOAK_PUBLIC_DOMAIN" > /var/dockge/stacks/honeypot-keycloak/secrets/public-domain'
  ```
- `theme/apiary/` and `keycloak/realm/`.

The volume is the Compose one, `honeypot-keycloak_keycloak-postgres`, declared
`external: true` on both sides (reused in place, never copied; a
`compose down -v` cannot delete it).

## Cutover (Compose → stack, done 2026-11-20, 30 s without Keycloak)

Never two postmasters on one PGDATA: the stack landed with `replicas: 0`.

1. Backups: `pg_dump -Fc` restore-tested into a throwaway Postgres on
   `--network none`, an offline `kc.sh export --users realm_file`, one
   `backup-essentials` run holding `homeserver/keycloak/keycloak.sql.gz`.
2. Create `secrets/public-domain`; `stackctl ensure keycloak` (both at 0).
3. `docker stop hp-keycloak`, then `docker stop hp-keycloak-postgres` (60 s
   grace). Kept, not removed. Check `docker top`/`State.Pid` is 0.
4. `docker service scale keycloak_postgres=1`, wait for healthy, then
   `docker service scale keycloak_keycloak=1`, wait for healthy.
5. Only now sync `honeypot-keycloak` (the legacy profile): Arcane redeploys a
   project after a sync even with `redeployAfterSync: false` (#3891).
6. A follow-up commit sets `replicas: 1`.

## Rollback

```bash
docker service scale keycloak_keycloak=0 keycloak_postgres=0   # wait until both tasks are gone
docker start hp-keycloak-postgres && docker start hp-keycloak
```

Not `stackctl remove` (#3884). Then revert the stack to `replicas: 0`, so the
next deploy does not start it again. Same digests on the same PGDATA mean no
conversion either way. If the data were damaged, restore the `pg_dump`
(`keycloak/restore.sh`, or `pg_restore` into the stopped-Keycloak Postgres).

## Fresh install

`scripts/install-homeserver.sh` deploys no swarm stack, so on a host without
a `keycloak_postgres` service it starts `honeypot-keycloak` with
`--profile legacy` and provisions on Compose. Moving to this stack is then the
cutover above.
