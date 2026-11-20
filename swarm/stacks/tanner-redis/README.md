# Tanner Redis (#3596)

Tanner's Redis cache as a Swarm stack, live since swarm phase 9 leg C
(2026-11-20). One replica pinned to the homeserver, no volume: a pure LRU
cache (`save ""`, `appendonly no`, `maxmemory 64mb allkeys-lru`). A new task
starts empty, like a restart of the Compose one did.

- **Image and config:** the upstream base of the Compose build
  (`arcane/home/honeypot-tanner/tanner/redis/Dockerfile`, same digest), run as
  `redis` with that build's `redis.conf` as flags. Nothing is built for the
  swarm. `scripts/tests/test_3596_valkey_stores.py` fails if the flags and
  `redis.conf` drift apart.
- **Network:** overlay `tanner-redis_store` (10.200.36.0/24, internal,
  encrypted, attachable), `endpoint_mode: dnsrr`. Never a published port: 6379
  is a decoy port that portbridge forwards to 10.8.0.2.

## How tanner reaches it

tanner, tanner_api and tanner_web stay on Compose (the privileged nested
daemon can't move, #3837) and keep `REDIS.host: tanner_redis`
(`tanner/tanner/config.yaml`). `tanner_redis_relay` (`hp-tanner-redis-relay`,
read-only socat, `cap_drop: ALL`) answers as `tanner_redis` on `tanner_local`
and forwards to `tanner-redis_redis:6379` on the overlay. Only the relay joins
the overlay; `apiary-overlay-attach` starts it after a dockerd restart.

A host without this stack (a fresh install) gets the Compose `tanner_redis`
instead: `install-homeserver.sh` brings the project up with `--profile legacy`
and without the relay.

## Never sync this project through Arcane (#3878)

`honeypot-tanner` still defines the stopped `hp-snare` rollback copy of the
`sensor-snare` stack. An Arcane sync or redeploy can start it next to
`sensor-snare` (#3891). Change this project only through the docker:cli
bridge, and only the services you change:

```bash
# after copying the changed compose.yml into /var/dockge/stacks/honeypot-tanner (backup first)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/dockge:/var/dockge -v /opt:/opt -w /var/dockge/stacks/honeypot-tanner \
  docker:cli docker compose up -d --no-deps tanner_redis_relay
```

If `hp-snare` starts anyway, stop it at once and check `sensor-snare`.

## Cutover (done 2026-11-20)

1. `stackctl deploy tanner-redis` (or `ensure`): the service at 0/0.
2. `docker stop hp-tanner-redis` (kept, profile `legacy`).
3. `docker service scale tanner-redis_redis=1`, wait for healthy.
4. Copy `compose.yml` from main into the live project dir (backup first) and
   start only the relay through the bridge above.
5. Check: a request through `sensor-snare` lands in tanner's report, and the
   new Redis takes writes.

## Rollback

```bash
docker stop hp-tanner-redis-relay
docker service scale tanner-redis_redis=0
docker start hp-tanner-redis
```

Never `stackctl remove` this stack (#3884); scale it to 0.
