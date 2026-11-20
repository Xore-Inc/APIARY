# Canarytokens Redis (#3596)

The canarytokens platform's Redis (tokens, drops, alert history) as a Swarm
stack, live since swarm phase 9 leg C (2026-11-20). One replica pinned to the
homeserver. Same image digest and flags as the Compose Redis it replaced:
`--appendonly yes --save 60 1`, no password, protected mode off.

- **Data:** the Compose volume `honeypot-canarytokens_canarytokens-redis-data`
  (AOF in `appendonlydir/` plus `dump.rdb`), reused in place as an external
  volume. `analysis/backup-honeypot.sh` and `scripts/backup-essentials.sh` back
  it up by volume name, so nothing changes there.
- **One writer:** two Redis on one AOF directory corrupt it. The stack landed
  with `replicas: 0`, updates and rollbacks are stop-first, and the Compose
  `canarytokens-redis` sits behind `profiles: [legacy]`.
- **Network:** overlay `canarytokens-redis_store` (10.200.35.0/24, internal,
  encrypted, attachable), `endpoint_mode: dnsrr`. Never a published port: 6379
  is a decoy port that portbridge forwards to 10.8.0.2.

## How canarytokens reaches it

frontend, switchboard and http-router stay on Compose and keep
`CANARY_REDIS_HOST=canarytokens-redis` / `REDIS_ADDR=canarytokens-redis:6379`.
`canarytokens-redis-relay` (`hp-canarytokens-redis-relay`, read-only socat,
`cap_drop: ALL`) answers as `canarytokens-redis` on `canarytokens_net` and
forwards to `canarytokens-redis_redis:6379` on the overlay. Only the relay
joins the overlay, so no canarytokens service depends on the swarm at boot
(#3837); `apiary-overlay-attach` starts the relay after a dockerd restart.

A host without this stack (a fresh install) gets the Compose Redis instead:
`install-homeserver.sh` brings the project up with `--profile legacy` and
without the relay. Moving it to the stack is the cutover below.

## Cutover (done 2026-11-20)

1. Backup: `redis-cli BGSAVE`, then a tar of the volume with a checksum.
2. `stackctl deploy canarytokens-redis` (or `ensure`): the service at 0/0.
3. `redis-cli SAVE` in the Compose Redis, then `docker stop
   hp-canarytokens-redis` (kept). SIGTERM fsyncs the AOF and writes a final RDB.
4. `docker service scale canarytokens-redis_redis=1`, wait for healthy, check
   that `DBSIZE` equals the count before the stop.
5. Sync the `honeypot-canarytokens` project (only now, #3891): its compose up
   creates the relay and leaves the other services alone (their Compose
   config hashes are unchanged).
6. Check: a throwaway token, triggered, raises its alert, then is deleted.

## Rollback

```bash
docker stop hp-canarytokens-redis-relay
docker service scale canarytokens-redis_redis=0   # wait until the task is gone
docker start hp-canarytokens-redis
```

Same digest on the same volume either way, so no format change. Never
`stackctl remove` this stack (#3884); scale it to 0.
