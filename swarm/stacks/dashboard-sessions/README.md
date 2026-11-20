# Dashboard session store (#3592, #3596)

The dashboard's memory-only Valkey (sessions and pending sign-ins) as a Swarm
stack, live since swarm phase 9 leg C (2026-11-20). One replica pinned to the
homeserver (`node.hostname == supermicro`), where the dashboard runs. Same
image digest and flags as the Compose Valkey it replaced: no RDB, no AOF,
`maxmemory 128mb noeviction`. No published port (6379 is a decoy port that
portbridge forwards to 10.8.0.2) and no host mount.

## How the dashboard reaches it

The dashboard (Xore-Inc/apiary-dashboard) stays on Compose, on its own bridges.
Its homeserver override `compose.honeynet.yml` adds `oidc-sessions-relay`
(`hp-apiary-dashboard-oidc-sessions-relay`), a read-only socat that:

- answers as `oidc-sessions` on the dashboard's private `oidc-session` bridge,
  so `OIDC_SESSION_REDIS_URL=redis://oidc-sessions:6379/0` is unchanged;
- forwards to `dashboard-sessions_valkey:6379` on this stack's overlay
  `dashboard-sessions_store` (10.200.34.0/24, internal, encrypted, attachable).

Only the relay joins the overlay, so the dashboard never depends on the swarm
at boot (#3837). If dockerd starts the relay before the overlay exists,
`apiary-overlay-attach` starts it afterwards (`start` line in
`ops/swarm/hosts/homeserver-overlay-attach.txt`). The dashboard's session
client reconnects by name, so neither a relay restart nor a new Valkey task
needs a dashboard restart. Valkey uses `endpoint_mode: dnsrr`: no VIP, so no
IPVS idle cutoff (900 s) on the dashboard's long-lived connection.

A new task starts empty: every redeploy that replaces the task (an image
bump, a spec change) signs every user out once. Updates are stop-first, so
the relay never splits sessions across two stores.

## Cutover (done 2026-11-20) and rollback

The stack first landed with `replicas: 0`. The cutover stopped the Compose
`hp-apiary-dashboard-oidc-sessions` (kept, profile `legacy` in the dashboard
project), ran `docker service scale dashboard-sessions_valkey=1`, then synced
the `apiary-dashboard` project, which created the relay. The dashboard
container was not recreated (its Compose config hash does not change). The
store path was down 22 s. The project has no `build:` service, so its sync
only reapplies files (compare canarytokens-redis, #3891).

Rollback, in this order (never both stores at once, both answer as
`oidc-sessions`):

```bash
docker stop hp-apiary-dashboard-oidc-sessions-relay
docker service scale dashboard-sessions_valkey=0
docker start hp-apiary-dashboard-oidc-sessions
```

Either way users sign in again once. Never `stackctl remove` this stack
(#3884); scale it to 0.

## History

From 2026-10-12 until leg C this stack ran unused on precision as BFF-split
preparation, on a non-attachable overlay `dashboard-sessions_session`
(10.200.4.0/24). Leg C re-pinned it rather than adding a second session store:
the digest and flags already matched, its Arcane sync existed, and #3870
expects the store to keep moving with the dashboard. The new overlay has a
new name because a deploy never changes an existing network; the old one was
removed by hand after the redeploy.

When the dashboard moves to its own host (#3870), the store moves with it.
