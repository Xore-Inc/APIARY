# host-gateway (#3582, decision D1 on #3579)

The host gateway: the `honeypot-backend-service` image with `GATEWAY_MODE=1`,
pinned to the homeserver (`node.labels.sensor == true`). It gives the two HTTP
services the host paths they cannot have on precision:

- the analyzer request spools (writable) and results (read-only);
- captured payloads (Dionaea binaries, Cowrie downloads, script payloads in
  `dashboard-state`);
- the services-adapter socket.

It serves only `/healthz`, `/livez` and `/host/v1`. API, rules and settings:
[docs/BACKEND-HOST-GATEWAY.md](../../../docs/BACKEND-HOST-GATEWAY.md).

- **Network:** the encrypted, internal overlay `host-gateway_host`
  (`10.200.100.0/24`), with alias `host-gateway` on port 8083. No published
  port. The HTTP services join it as an external network.
- **Credential:** the swarm secret `host_gateway_token_v1`, read through
  `HOST_GATEWAY_TOKEN_FILE`. It must differ from `SERVICE_TOKEN` and
  `EXPORT_TOKEN`.
- **Mounts:** the same host paths and volumes `backend-service-mounted`
  (Compose) uses, plus `services-adapter-socket`. Only the six `requests/pending`
  directories and the socket directory are writable.

## Deploy

1. Create the secret on a manager (value generated there, never printed):
   `head -c 32 /dev/urandom | base64 | tr -d '=+/\n' | ops/swarm/stackctl.py secret create host_gateway_token_v1`
2. `ops/swarm/stackctl.py ensure host-gateway` (creation deploys).
3. Prove, before anything uses it:
   - the task runs on `supermicro` and is `healthy`;
   - from a probe task on precision attached to `host-gateway_host`:
     - `/healthz` answers 200, and `/host/v1/...` answers 401 without the token;
     - with the token: `GET /host/v1/fs/GHIDRA_RESULTS_DIR/list`;
     - `POST create` then `DELETE` of a probe marker in a request root;
     - `GET /host/v1/adapter/v1/services` equals the backend's
       `/api/v1/services` list.

Nothing reads from the gateway until the HTTP services on precision set
`HOST_GATEWAY_URL` (backend-api). Until then, deploying it changes no
existing path.

## Rollback

`ops/swarm/stackctl.py pause host-gateway`, or `remove --yes`. The Compose
backends on the homeserver keep their own mounts and never depend on it.
