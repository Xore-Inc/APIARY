# Backend trust boundary: credentials, actor assertions, rotation (#3577)

Who may call the Rust backend (`backend-service`, `backend-service-mounted`),
whose operator identity it believes, and how its secrets are installed,
rotated, revoked and rolled back. Code: `backend-service/src/trust.rs`
(decisions) and `lib.rs::require_service_token` (the one place they are
applied).

## Transport

The dashboard reaches the backend over the encrypted Docker Swarm overlay
(`--opt encrypted`, decision on #3579), by service name. The backend
publishes no port beyond the overlay. `BACKEND_URL` stays configurable, so a
host outside the swarm can still be pointed at an HTTPS front, but the
overlay is the supported topology. Until the stacks move to the overlay
(#3592) the co-located compose stacks keep today's posture: no published
host port, listener on the `honeynet` bridge.

The credentials below are needed on top of the transport, not instead of
it: the overlay decides who can open a connection, the credentials decide
what a connection may do.

## Credentials

| Credential | Header | Reaches | Held by |
|---|---|---|---|
| `SERVICE_TOKEN` | `x-service-token` | every `/api/v1` route | the BFF (dashboard) only |
| `EXPORT_TOKEN` | `x-export-token` | `GET /api/v1/ip-block-export` only; 403 everywhere else | the VPS blocklist pull |
| actor assertion key | `x-actor-assertion` | proves the operator behind a BFF request | private half: the BFF; public half: the backend |

- No accepted credential is a 401, as before #3577.
- The export credential is refused (403) by
  `POST /api/v1/services/{name}/{action}`, every actor-sensitive route and
  every other read, whatever actor headers or assertion ride along. It must
  differ from every `SERVICE_TOKEN` value: the backend refuses to boot
  otherwise. Unset means there is no export credential.
- Each value only counts in its own header: the export token sent as
  `x-service-token` is no credential at all.
- Every secret can be given as `NAME` or `NAME_FILE` (the swarm secret
  convention from #3590: the variable names a file under `/run/secrets/`).
  Setting both refuses to boot. Values never enter git, issues or PRs.

The export credential is the backend side of the export-only decision in
Xore-Inc/apiary-dashboard#246. A VPS job that pulls the backend directly over
the overlay sends `x-export-token: $BLACKHOLE_EXPORT_TOKEN`. The dashboard's
own export route (#246) checks its own `EXPORT_TOKEN`; use a separate value
for each so either can be revoked alone. Until #3578/#246 switch the VPS
script, `vps/portbridge-manual-blackhole-refresh.sh` still sends
`DASHBOARD_SERVICE_TOKEN` and its sidecar stays disabled.

## Actor assertions

A BFF request that acts for an operator carries `x-actor-assertion`: a
compact JWS (a JWT) signed with Ed25519.

- Header: `{"alg":"EdDSA","typ":"JWT"}`. Any other `alg` (including `none`)
  is refused.
- Claims, all required:

  | Claim | Value |
  |---|---|
  | `sub` | the operator's OIDC subject |
  | `username` | the operator identity the backend records and scopes by (Workbench run ownership, audit entries) |
  | `role` | `admin` or `viewer` |
  | `aud` | `apiary-backend` |
  | `iat`, `exp` | Unix seconds; `exp - iat` between 1 and 300 |
  | `htm` | the request method, e.g. `POST` |
  | `htu` | the request path without the query, exactly as sent, e.g. `/api/v1/services/cowrie/restart` |

- The BFF mints one per call with `exp = iat + 60`. The backend allows 30
  seconds of clock skew. `htm`/`htu` bind the assertion to one request, so
  a captured one cannot be replayed against another route.
- The backend holds only the public key. A stolen bearer token, the
  backend's environment, or the export credential cannot mint an identity.
  A signature made with `SERVICE_TOKEN` would not have this property: its
  holder can sign anything.

Signing in Node (no dependency; the dashboard's BFF seam is
`src/data/api.ts` `request`/`raw`):

```ts
import { createPrivateKey, sign } from 'node:crypto'
const key = createPrivateKey(pem) // ACTOR_ASSERTION_PRIVATE_KEY(_FILE)
const b64 = (v: string | Buffer) => Buffer.from(v).toString('base64url')
const iat = Math.floor(Date.now() / 1000)
const input = `${b64('{"alg":"EdDSA","typ":"JWT"}')}.${b64(JSON.stringify({ sub, username, role, aud: 'apiary-backend', iat, exp: iat + 60, htm: method, htu: path }))}`
const assertion = `${input}.${b64(sign(null, Buffer.from(input), key))}`
```

### What the backend does with it (`ACTOR_ASSERTION_MODE`)

| Mode | Behaviour |
|---|---|
| `off` (default) | The pre-#3577 behaviour. Nothing is verified; plain `x-actor-*` headers and `actor_*` fields are believed as before. |
| `log` | Every BFF request is evaluated as `enforce` would, and each one `enforce` would refuse is logged as `[E-ACTOR-ASSERTION] log mode: enforce would refuse this request: <reason>`, with method, route and status. Nothing else changes. |
| `enforce` | Refuses what `log` reports. See below. |

Under `enforce`, for requests on the BFF credential:

- An assertion that does not verify (signature, key, `alg`, `aud`, expiry,
  lifetime, `htm`/`htu`, role) is a 401.
- A mutation (anything but GET/HEAD/OPTIONS) without an assertion is a 401.
  So is any request that claims an actor through plain `x-actor-username`
  or `x-actor-role` without one.
- A plain read with no actor claim passes on the bearer token alone
  (machine reads such as diagnostics and the source-health check).
- A verified `viewer` may perform only the mutations the dashboard grants
  viewers (`trust::VIEWER_MUTATIONS`, mirroring the dashboard's
  `ADMIN_QUERIES` in `src/server/authorize.ts`): alert ack, canarytoken
  create, config validate, own preferences, problem-report submit, report
  preview. Every other mutation, the service actions included, needs
  `admin`: 403, whatever `x-actor-role` says.
- The client's `x-actor-username`/`x-actor-role` are dropped and rewritten
  from the verified assertion, and the verified actor is attached to the
  request, so handlers never see a client-supplied identity. Service
  actions audit the verified actor, not the `actor_*` query labels.

`log` and `enforce` need `ACTOR_ASSERTION_PUBLIC_KEY`; the backend refuses to
boot without it, on an unknown mode, or on a private key.

### Rollout order

The backend and the dashboard deploy independently, so each step has to work
with whatever the other side currently runs.

1. **Ship this backend with no new configuration.** Mode `off`: identical
   behaviour, nothing for the dashboard to do.
2. **Generate the key pair** (below), give the backend the public key and
   `ACTOR_ASSERTION_MODE=log`, redeploy the backend. The current dashboard
   keeps working; the log now shows `[E-ACTOR-ASSERTION]` for every
   mutation and every actor-scoped read, which is expected while nothing
   signs.
3. **Ship the dashboard that signs** (Xore-Inc/apiary-dashboard#249), with
   the private key. Every other BFF that calls the backend with
   `SERVICE_TOKEN` must sign too or be retired first; the legacy
   `dashboard-next` in this repo does not sign.
4. **Watch the log** until `[E-ACTOR-ASSERTION]` stays silent through a
   representative period: an admin and a viewer session, every admin action
   the team uses, a Workbench run.
5. **Set `ACTOR_ASSERTION_MODE=enforce`** and redeploy the backend only.

Rollback, in this order:

- Something refused under `enforce`: set the backend back to `log` (or
  `off`) and redeploy the backend. No dashboard change is needed; a
  dashboard that signs works in every mode.
- Rolling the dashboard back to a version that does not sign: first put the
  backend in `log` or `off`, then roll back the dashboard. Doing it the other
  way round turns every mutation into a 401 in between.

## Health and metrics exposure

`/healthz`, `/livez`, `/readyz` and `/metrics` stay unauthenticated on the
listener, in every mode. Decision:

- The container and swarm healthchecks call `/healthz` from inside the
  container, and the deploy verifier and the metrics scrape run on the
  overlay. Authenticating them would put a credential into every probe for
  no gain on a network whose members are all fleet infrastructure.
- What they disclose: build time and git revision (also on the image
  label), Elasticsearch cluster colour and the names of write-blocked
  indices, and per-route-family request counts and latency. No event data,
  no identities, no secrets.
- The condition is the transport: the backend's listener must never be
  published beyond the overlay (no `ports:`). A host outside the swarm that
  reaches the backend through an HTTPS front must forward `/api/v1` only.

## Generating secrets

On the host that owns the secret, never in git or a ticket:

```bash
# bearer credentials (SERVICE_TOKEN, EXPORT_TOKEN): 256 bits, URL-safe
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > token-value

# actor assertion key pair
openssl genpkey -algorithm ed25519 -out actor-assertion.key   # the BFF only
openssl pkey -in actor-assertion.key -pubout                  # PEM for the backend
openssl pkey -in actor-assertion.key -pubout -outform DER | base64 -w0   # same, one line for .env
```

The public key is not secret, but keep it with the stack's configuration so
a rotation changes it in one place. The private key goes to the dashboard
host only.

## Install, rotate, revoke, roll back

Rotation has an overlap window: the predecessor value is set as
`<NAME>_PREVIOUS` with `<NAME>_PREVIOUS_UNTIL` (RFC 3339). It is accepted
strictly before that instant and refused from then on, even if nobody
removes it. `_PREVIOUS` without `_UNTIL` refuses to boot. This applies to
`SERVICE_TOKEN`, `EXPORT_TOKEN` and `ACTOR_ASSERTION_PUBLIC_KEY`.

Where the values go:

- **Compose stacks (today):** `honeypot-dashboard-backend` (`backend-service`,
  all variables) and `honeypot-dashboard` (`backend-service-mounted`, all but
  the export ones), through the Arcane project env. Edit the live env
  surgically; never overwrite it from `.env.example`. Variable names are in
  both stacks' `.env.example` (`DASHBOARD_SERVICE_TOKEN[_PREVIOUS[_UNTIL]]`,
  `BACKEND_EXPORT_TOKEN[...]`, `ACTOR_ASSERTION_*`).
- **Swarm stacks (#3592):** one external secret per value, versioned
  `<base>_vN` (`ops/swarm/stackctl.py secret create`), mounted under
  `/run/secrets/` and named by `SERVICE_TOKEN_FILE`,
  `SERVICE_TOKEN_PREVIOUS_FILE`, `EXPORT_TOKEN_FILE`,
  `ACTOR_ASSERTION_PUBLIC_KEY_FILE` and so on. The `_UNTIL` instants and the
  mode are plain environment. Follow `ops/swarm/README.md` for secret
  versions and keep the old secret through the next version so a rollback
  can still start.

### Service token

- **Install:** generate, set it on the backend (both instances) and on the
  dashboard, deploy the backend, then the dashboard.
- **Rotate:** on the backend set `SERVICE_TOKEN=<new>`,
  `SERVICE_TOKEN_PREVIOUS=<old>`, `SERVICE_TOKEN_PREVIOUS_UNTIL=<now + 24h>`
  and redeploy the backend: it now accepts both. Then give every BFF the new
  value and redeploy it. After the window remove the two `_PREVIOUS`
  variables at the next backend deploy (they already stopped working).
- **Revoke (suspected leak):** set the new value with no `_PREVIOUS` on the
  backend and every BFF and deploy them together. Requests in between fail
  with 401; that is the point.
- **Roll back a rotation inside the window:** swap the values
  (`SERVICE_TOKEN=<old>`, `_PREVIOUS=<new>`) on the backend and redeploy;
  BFFs on either value keep working.

### Export token

- **Install:** generate, set `BACKEND_EXPORT_TOKEN` on `backend-service`
  only, redeploy, then give the same value to the VPS job and re-enable it.
  Check: `GET /api/v1/ip-block-export` with `x-export-token` is 200, and the
  same header on any other route is 403.
- **Rotate:** as the service token, with `BACKEND_EXPORT_TOKEN_PREVIOUS` and
  `_UNTIL`; the VPS job switches inside the window.
- **Revoke:** unset `BACKEND_EXPORT_TOKEN` (and `_PREVIOUS`) and redeploy.
  The VPS job then fails closed and keeps its last good list
  (`portbridge-manual-blackhole-refresh.sh`, #3403).

### Actor assertion key

- **Install:** see the rollout order above.
- **Rotate:** generate a new pair. On the backend set
  `ACTOR_ASSERTION_PUBLIC_KEY=<new public>`,
  `ACTOR_ASSERTION_PUBLIC_KEY_PREVIOUS=<old public>`, `_PREVIOUS_UNTIL=<now + 24h>`
  and redeploy the backend. Then give the dashboard the new private key and
  redeploy it. Remove the `_PREVIOUS` variables after the window. Destroy
  the old private key.
- **Revoke (private key leaked):** new pair, no `_PREVIOUS`; deploy the
  backend and the dashboard together. Under `enforce`, mutations fail with
  401 until both are on the new pair; switch to `log` first if that window
  is not acceptable.
- **Roll back:** inside the window, swap current and previous on the
  backend.

## Not covered yet

- Actor fields carried in request **bodies** (preferences `subject`,
  credential and config-rollback `actor_*`, ML acknowledgement `actor`) are
  still taken from the body. Under `enforce` only a request with a valid
  assertion can reach those routes at all, so the remaining gap is a viewer
  naming another subject in their own preferences write. Binding those
  fields to the verified actor is tracked on #3577.
- The OpenAPI contract (`openapi.json`) still documents only
  `x-service-token`.
