# backend-api (#3582/#3592, BFF split #3579)

The two HTTP services of the Rust backend, moved off the homeserver to
precision (`node.labels.sensor == false`). Same image and routes as the Compose
services they replace:

| Service | Replaces | Port | Alias on `bff` |
|---|---|---|---|
| `api` | `backend-service` (`hp-apiary-backend`) | 8081 | `backend-api` |
| `mounted` | `backend-service-mounted` (`hp-apiary-backend-mounted`) | 8082 | `backend-api-mounted` |

The workers stay on the homeserver (`honeypot-backend-workers`, #3575).

## Where each dependency comes from

| Need | On precision | Decision |
|---|---|---|
| Spools, results, payload bytes, services adapter | the host gateway, `http://host-gateway:8083` on `host-gateway_host` (stack `host-gateway`) | D1 |
| Elasticsearch | `http://elasticsearch:9200` on the encrypted overlay `apiary-es` | D2 |
| Audit and config history | volume `backend-state` on precision, these two services as the only writers | D3 |
| Canarytokens API, honeyfs implant | fleet address `10.8.0.2` (19426, 19428) over WireGuard | #3576 |
| Filebeat stats | none: `FILEBEAT_URL` unset, the source-health pipeline row says disabled | #3576 |
| **Ollama (LLM search)** | **none: `OLLAMA_URL` unset, LLM search answers "disabled"** | #3582, 2026-11-06 |
| **Per-request JSONL log** | **none: `DASHBOARD_LOG_FILE` unset, no log mount** | #3582, 2026-11-06 |

The two bold rows are Xore's decision on #3582 (2026-11-06):

- **Ollama:** it gets a dedicated `ollama` overlay in the post-benchmark window.
  Until then, LLM search stays off on precision. To turn it on later, add that
  overlay as an external network and set `OLLAMA_URL: http://ollama:11434`.
- **Request log:** losing the per-request JSONL file on precision is accepted.
  The request lines still go to the container log (`docker service logs`).
  They just no longer reach Elasticsearch through Filebeat.

Not carried over:

- `EXPORT_TOKEN` is not set: it is empty on the live Compose service as well.
  The VPS blackhole export reads from its own sidecar (#3578).

## Prerequisites (in this order)

0. **Image:** `stack.yml` pins the main build of 069e5f3a, which contains
   #3790 (`HONEYPOT_SELF_IPS_FILE`). Any later re-pin must stay at or after
   it: an older build ignores the secret and ranks the fleet's own
   addresses as attackers. Rollback reference: the digest in the previous
   commit of `stack.yml`, after the same check.
1. **D1:** stack `host-gateway` deployed and proven from a precision probe (its README).
2. **D2:** the overlay `apiary-es` (`10.200.101.0/24`, encrypted, attachable)
   exists, and `hp-elasticsearch` is attached to it with alias
   `elasticsearch`. This is part of the post-benchmark window together with
   phase 9 (#3587). The stack refuses to deploy before that network exists.
3. **Secrets**, created on a manager from the live values (never printed):
   - `dashboard_service_token_v1`: the BFF's `SERVICE_TOKEN`;
   - `host_gateway_token_v1`: the same secret the gateway reads;
   - `actor_assertion_public_key_v1`: the PEM public key the backends verify with;
   - `honeypot_self_ips_v1`: the live Compose backend's `HONEYPOT_SELF_IPS`
     list (#3790), commas or one address per line. An empty secret refuses
     to boot.
4. **D3 seed** (on precision, before the first deploy):
   - Create the volume, copy `dashboard-audit.jsonl` (+`.1`) and
     `dashboard-config-history.jsonl` from the homeserver's `dashboard-state`,
     and `chown 65534:65534` them (the image runs as `nobody`).
   - Compare line counts and sha256 on both sides.
   - Keep the homeserver copy read-only for rollback.

## Deploy and switch

1. `ops/swarm/stackctl.py ensure backend-api`. The services start at zero
   traffic; nothing points at them yet.
2. Prove on precision:
   - both tasks are `healthy`;
   - the boot log shows `host paths files=gateway ... adapter=gateway`;
   - a signed read through `backend-api` matches the Compose backend, and
     the attacker overview leaves out the same fleet addresses
     (`honeypot_self_ips_v1`, #3790);
   - a `mounted` submit creates its marker in the homeserver spool, and the
     worker claims it.
3. Attach `apiary-dashboard` to `backend-api_bff`. Then switch its
   `BACKEND_URL`/`BACKEND_MOUNTED_URL` to `http://backend-api:8081` and
   `http://backend-api-mounted:8082` (surgical `.env` edit, backup alongside).
4. Stop the Compose `backend-service`/`-mounted` on the homeserver, but keep
   them for rollback.

## Rollback

Point the dashboard's `BACKEND_URL`/`BACKEND_MOUNTED_URL` back at the Compose
services and start them again. Then `ops/swarm/stackctl.py pause backend-api`.
Audit lines written on precision in the meantime are appended back to the
homeserver copy by hand (both files are append-only JSONL).
