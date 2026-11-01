# Backend host gateway (#3582, decision D1 on #3579)

The two HTTP services (`backend-service`, `backend-service-mounted`) are
moving off the sensor/Elasticsearch host (the homeserver) to precision. They
still need a few things that exist only on the homeserver:

| Need | Call sites |
|---|---|
| Analyzer request spools: create a marker, list, stat, remove | sandbox, Ghidra and GitHub-analysis submit; Workbench run create, cancel and reconcile |
| Analyzer results: list, read | Workbench reconcile and registry, sandbox golden-image status and VNC status |
| Captured payload bytes, by hash | submit routing, Workbench static analysis, the payload-bytes self-heal mirror |
| The services adapter (AF_UNIX socket) | `/api/v1/services` list, logs and actions |

Shared storage is excluded (#3592 decision 2). These paths therefore go
through the **host gateway**: the same `apiary-backend` image with
`GATEWAY_MODE=1`, pinned to the homeserver.

## How the backend reaches host paths

Every access listed above goes through one seam, `host_fs::HostFs` (and
`services_control`'s `Adapter`):

- **Local** (default; `HOST_GATEWAY_URL` and `SERVICES_ADAPTER_URL` unset):
  plain `std::fs` on the directories the `*_REQUEST_DIR` / `*_RESULTS_DIR` /
  `PAYLOAD_DIRS` / `SCRIPT_PAYLOAD_DIR` variables name, and the
  `SERVICES_ADAPTER_SOCKET` socket. This is the behaviour before #3582.
- **Remote** (`HOST_GATEWAY_URL` set): the same operations as HTTP calls to the
  gateway. `SERVICES_ADAPTER_URL` does the same for the adapter.

The workers stay on the homeserver (`honeypot-backend-workers`, #3575) and
keep using local disk.

## Gateway

| Setting | Meaning |
|---|---|
| `GATEWAY_MODE=1` | Serve only `/healthz` and `/host/v1/*`. `0`, `false` or unset: the normal backend. Any other value refuses to boot. |
| `LISTEN_ADDR` | e.g. `0.0.0.0:8083` on the gateway's own overlay. |
| `HOST_GATEWAY_TOKEN` or `_FILE` | Required. `_PREVIOUS` + `_PREVIOUS_UNTIL` (RFC 3339) give a rotation its overlap window, as in `trust.rs`. Refuses to boot if it equals `SERVICE_TOKEN` or `EXPORT_TOKEN`. |
| `*_REQUEST_DIR`, `*_RESULTS_DIR`, `PAYLOAD_DIRS`, `SCRIPT_PAYLOAD_DIR` | The same mounts `backend-service-mounted` has today. |
| `SERVICES_ADAPTER_SOCKET` | The adapter socket; unset answers 503 on the adapter routes. |

The gateway needs neither Elasticsearch nor `SERVICE_TOKEN`, and runs no worker loops.

### API (all but `/healthz` need `x-host-gateway-token`)

| Route | Does |
|---|---|
| `GET /healthz`, `GET /livez` | `{"ok":true,"mode":"host-gateway","revision":…}`, unauthenticated (`/livez` is the image HEALTHCHECK path) |
| `GET /host/v1/fs/{ROOT}` | root info `{dir, exists, is_dir, writable}`; 404 when the root is not configured |
| `GET /host/v1/fs/{ROOT}/list?prefix=&suffix=&files_only=&content_cap=` | entries `{name, size, is_dir, modified_ms, content?}`; content (base64) for files up to `content_cap`, 64 MiB per call, 20,000 entries |
| `GET /host/v1/fs/{ROOT}/stat/{name}` | one entry |
| `GET /host/v1/fs/{ROOT}/read/{name}?cap=` | bytes (at most 32 MiB), real size in `x-real-size` |
| `POST /host/v1/fs/{ROOT}/create/{name}` | O_CREAT\|O_EXCL: 201 created, 200 already there |
| `DELETE /host/v1/fs/{ROOT}/file/{name}` | 204, 404 when absent |
| `GET /host/v1/payload/{hash}` | `{size}`; 404 not found |
| `GET /host/v1/payload/{hash}/read?cap=` | bytes, real size in `x-real-size` |
| `GET /host/v1/adapter/v1/services` | forwarded to the adapter socket |
| `GET /host/v1/adapter/v1/services/{name}/logs?lines=1..1000` | forwarded |
| `POST /host/v1/adapter/v1/services/{name}/{start\|stop\|restart}` | forwarded with the adapter's fixed `{}` body |

Rules, enforced in `host_fs::local`, which is what the gateway runs:

- A directory is named by its variable (`ROOT`, e.g. `GHIDRA_REQUEST_DIR`),
  never by a path. Unknown names are 404. Only the thirteen analyzer roots
  exist (`host_fs::Root`).
- A file name is one path component: no `/`, `\`, NUL, `.` or `..` (400).
- A symlink that resolves outside its root is refused (403) and left out of
  listings.
- Only `*_REQUEST_DIR` roots take `create` and `remove` (403 elsewhere).
- Payloads are addressed by hash only, through the same resolution rules as
  `payload_paths::resolve_payload_path`.
- Adapter calls are rebuilt from validated parts: a service name of
  `[A-Za-z0-9._-]`, one of the three actions, and 1 to 1000 log lines.
  Nothing else reaches the socket.

Each authenticated request is logged with its method, path and status. A
refused token logs `[E-HOST-GATEWAY-TOKEN]`.

## Client side (the HTTP services on precision)

| Setting | Meaning |
|---|---|
| `HOST_GATEWAY_URL` | e.g. `http://host-gateway:8083`. Spools, results and payloads go to the gateway. |
| `SERVICES_ADAPTER_URL` | e.g. `http://host-gateway:8083`. Replaces `SERVICES_ADAPTER_SOCKET`; setting both refuses to boot. |
| `HOST_GATEWAY_TOKEN` or `_FILE` | Required when either URL is set; must differ from `SERVICE_TOKEN` and `EXPORT_TOKEN`. |

The boot log line `host paths` says which mode is in use, e.g.
`files=gateway http://host-gateway:8083 adapter=gateway http://host-gateway:8083`.

## Rotation and rollback

- **Rotate:** give the gateway the new token as current, the old one as
  `_PREVIOUS` with a `_PREVIOUS_UNTIL` some minutes ahead, then redeploy it.
  Then move the clients to the new token. The old token stops working at the
  deadline.
- **Revoke:** replace the gateway's token without a `_PREVIOUS`; every client
  gets 401 at once.
- **Roll back the move:** unset `HOST_GATEWAY_URL` and `SERVICES_ADAPTER_URL`
  on a backend that runs on the homeserver with its old mounts. That is
  exactly the pre-#3582 behaviour.

## Placement (stack PR, after this code)

The gateway joins a dedicated encrypted overlay together with the two HTTP
services, and only them. It is homeserver-pinned and publishes no port. See the
D1-D3 design on #3582.
