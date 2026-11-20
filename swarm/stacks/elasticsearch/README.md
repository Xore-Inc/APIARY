# Elasticsearch (#3596)

The single Elasticsearch node as a Swarm stack (swarm phase 9 leg D), pinned
to the homeserver. Same image digest, environment and limits as the Compose
service it replaces (`arcane/home/honeypot-elk`, `hp-elasticsearch`):
single-node, security off, 6g heap locked in RAM, 8 CPU / 12G.

- **Data:** the Compose volume `honeypot-elk_es-data` (~138 GB), reused in
  place as an external volume, never copied. It is external in the Compose
  file too, so a `compose down -v` can't delete it.
- **One node per data path:** ES holds `node.lock`. The stack landed with
  `replicas: 0`. Updates and rollbacks are stop-first, and the Compose
  `elasticsearch` is behind `profiles: [legacy]`, kept stopped as the rollback.
- **Memlock:** `ulimits.memlock -1`, `cap_add: [IPC_LOCK]`,
  `bootstrap.memory_lock=true`. A single-node ES starts even when the lock
  fails, so check `GET _nodes?filter_path=**.mlockall` (`true`) and `VmLck`
  (~10 GB on the java process) after every deploy.
- **Stopping:** `stop_grace_period: 120s` (#2339). Phase 9 gate G1 showed that
  Arcane carries both this and `ulimits` into the service spec.
- **Network:** only the D2 overlay `apiary-es` (10.200.101.0/24, internal,
  encrypted, attachable, created by hand, #3582), alias `elasticsearch`,
  `endpoint_mode: dnsrr`. **No published port:** portbridge forwards the public
  9200 to 10.8.0.2 for the decoy.
- **Snapshots:** the fs repository `honeypot-fs` is the bind
  `/opt/stacks/apiary/state/elasticsearch-snapshots` at `/snapshots`, as before.

## How consumers reach it

- **Swarm** (the kibana stack, later backend-api): `http://elasticsearch:9200`
  on `apiary-es`.
- **Compose** (Filebeat, Arkime, EveBox, the extracted-file importer,
  disk-space-monitor, ml-worker, auth-events-worker, the backend and its
  workers, the honeypot-init one-shots): unchanged `http://elasticsearch:9200`.
  `elasticsearch-shim` (`hp-elasticsearch-shim`, honeypot-elk) is a read-only
  socat with `cap_drop: ALL`. It answers as `elasticsearch` on `honeynet` and
  `honeypot-llm-data` and forwards to `elasticsearch_es:9200`, the service
  name and not the alias, so it can't resolve itself. Only the shim joins the
  overlay, so no consumer depends on the swarm at boot (#3837), and
  `apiary-overlay-attach` starts it after a dockerd restart
  (`start hp-elasticsearch-shim apiary-es`).

On a host without this stack (a fresh install), `install-homeserver.sh`
brings honeypot-elk up with `--profile legacy`, without the shim, so the
Compose ES runs. Moving it to the stack is the cutover below.

## Cutover (done 2026-11-20/21)

1. Backup: an incremental snapshot `p9-pre-es-<ts>` of all non-dot indices,
   the global state and the `kibana` feature, at the default throttle. Record
   the `_cat/indices` doc counts and the last-hour counts per data stream.
2. `stackctl ensure elasticsearch`: the service is at 0/0.
3. Remove the D2 `connect hp-elasticsearch apiary-es elasticsearch` line from
   `/etc/apiary/overlay-attach.txt` and run `docker network disconnect
   apiary-es hp-elasticsearch`, so that only one `elasticsearch` is ever on the
   overlay.
4. `POST _flush`, then `docker stop -t 120 hp-elasticsearch` (kept). Don't
   restart Filebeat: it rides the gap on backpressure and resumes from its
   registry.
5. `docker service scale elasticsearch_es=1` and wait for GREEN with the same
   shard count.
6. Start the shim. Either sync `honeypot-elk` *after* the stop (Arcane
   redeploys on a sync, #3891, and only creates the shim: no other service's
   config hash changes), or `docker compose up -d --no-deps
   elasticsearch-shim` through the docker:cli bridge.
7. Add `start hp-elasticsearch-shim apiary-es` to the live overlay-attach
   list, commit `replicas: 1`, then `stackctl deploy elasticsearch`, so the
   sync points at that commit.

## Rollback

```bash
docker stop hp-elasticsearch-shim
docker service scale elasticsearch_es=0   # wait until the task is gone (node.lock)
docker start hp-elasticsearch             # its saved config has honeynet + llm-data with the alias
```

Then put the D2 `connect` line back, remove the shim's `start` line, and
revert the commits (replicas 0 first). The same digest on the same data path
means no on-disk change either way. If the data path were damaged, restore
from `p9-pre-es-<ts>` in the `honeypot-fs` repository. Never `stackctl remove`
this stack (#3884); scale it to 0.
