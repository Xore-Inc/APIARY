# kibana: Kibana on the homeserver (#3596, swarm phase 9 leg A)

Kibana as one replica pinned to `node.hostname == supermicro`, with the same
image digest as the Compose `kibana` in `arcane/home/honeypot-elk`. That
Compose service stays behind `profiles: [legacy]` as the rollback; its
container `hp-kibana` is kept, stopped.

## Paths

| From | To | How |
|---|---|---|
| VPS `oidc-kibana` | Kibana | `edge-kibana_socat` → `10.8.0.2:19601` over `wg0` (unchanged) |
| `honeypot-init` `honeypot-kibana-setup` (one-shot) | Kibana | `KIBANA_URL=http://10.8.0.2:19601` from its bridge (the guard's local-bridge exemption) |
| homeserver host tools (`analysis/kibana-export.sh`, `kibana-import.sh`, `stackctl` probe) | Kibana | `http://10.8.0.2:19601` |
| Kibana | Elasticsearch | `elasticsearch:9200` on the D2 overlay `apiary-es` (Compose ES attached by `apiary-overlay-attach` until leg D) |

`19601` is a host-mode port, so it binds every homeserver address. It is in
`ops/firewall/hosts/homeserver-swarm-host-ports.txt`; `home-swarm-host-guard`
drops every flow to it except the VPS on `wg0` and local containers to
`10.8.0.2`. A `curl` from the LAN to the homeserver LAN address on 19601 must time out.

Networks: `apiary-es` (external, internal) and `front` (`10.200.31.0/24`,
**not** internal). A task whose only networks are internal gets no host-mode
port published (phase 9 gate G1), so `front` is required, not cosmetic.

## Secret

`kibana_encryption_key_v1` holds the saved-objects encryption key
(`xpack.encryptedSavedObjects.encryptionKey`). Kibana has no `_FILE` form, so
the entrypoint wrapper exports it from `/run/secrets/kibana_encryption_key`
and execs the image's `tini -- kibana-docker`. It was created from a fresh
random value, not from the Compose placeholder (#3887):

```bash
openssl rand -hex 32 | ops/swarm/stackctl.py secret create kibana_encryption_key_v1
```

At the move no saved object of an encrypted type existed (no connectors or
rules), so the new key made nothing unreadable. Rotation: create `_v2`, set
`xpack.encryptedSavedObjects.keyRotation.decryptionOnlyKeys` to the old value,
deploy, `POST /api/encrypted_saved_objects/_rotate_key`.

## Cutover (2026-11-20)

1. `stackctl ensure kibana` with `replicas: 0` (needs `apiary-es` and the secret).
2. `docker stop hp-kibana` (kept).
3. `docker service scale kibana_kibana=1`, wait for healthy.
4. A follow-up commit sets `replicas: 1`.

## Rollback

```bash
docker service scale kibana_kibana=0     # wait until the task is gone (port free)
docker start hp-kibana
```

Then revert the stack commit to `replicas: 0` (or `stackctl pause kibana`), so
the next deploy does not start it again. The same digest means no
saved-object migration either way. Encrypted objects created under the swarm
key are not readable by the Compose Kibana, which still uses the placeholder
key (#3887).
