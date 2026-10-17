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
Xore-Inc/apiary-dashboard#246. The VPS job sends `X-Export-Token:
$BLACKHOLE_EXPORT_TOKEN` to the rewrite dashboard's
`/export/portbridge-manual-blackhole.txt` (#3578), which checks its own
`EXPORT_TOKEN`; the dashboard no longer accepts `SERVICE_TOKEN` on that route.
A job that pulled the backend directly over the overlay would send the same
header to `/api/v1/ip-block-export` with the backend's export token. Use a
separate value for each so either can be revoked alone. The VPS never holds
`DASHBOARD_SERVICE_TOKEN`.

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
- Actor fields in request bodies and queries are bound the same way (next
  section).

### Actor fields in bodies and queries

Several routes also take an operator from their own input. Each such field
goes through one helper (`trust::ActorBinding::bind`, attached by the
middleware to every BFF request):

| Mode | A client-named actor field |
|---|---|
| `off` | taken as sent, as before #3577 |
| `log` | taken as sent; `[E-ACTOR-ASSERTION] log mode: <field> differs from the asserted actor; enforce will use the assertion's` when it differs from a verified assertion, or `... enforce would refuse this request: <field> names an actor without an actor assertion` when there is none. Field names and route only, never values. Nothing extra when the middleware already reported the request. |
| `enforce` | **overridden** with the verified actor, whatever the client sent (an empty field is filled in). A field that names an actor on a request with no verified assertion (possible only on a plain read) is a 401. An override is logged as `[E-ACTOR-ASSERTION] <field> differs from the asserted actor; the assertion's was used`. |

Override, not refusal, for every field: under `enforce` the client value can
then never matter, and a BFF that still sends a display name somewhere keeps
working while `log` points at it. Admins are bound too: nothing in the
dashboard writes another operator's preferences or attributes an action to
someone else.

| Route | Field | Bound to |
|---|---|---|
| `GET /api/v1/preferences` | `subject`, `username`, `role` (query) | `sub`, `username`, `role` |
| `PUT /api/v1/preferences`, `POST /api/v1/preferences/reset` | `subject`, `username` (body) | `sub`, `username` |
| `PUT /api/v1/config/presentation`, `PUT /api/v1/config/{section}` | `actor_subject`, `actor_username` (query) | `sub`, `username` |
| `POST /api/v1/config/rollback` | `actor_subject`, `actor_username` (body) | `sub`, `username` |
| `POST /api/v1/credentials`, `.../{id}/rotate`, `.../{id}/link-token` | `actor_subject`, `actor_username` (body; also `created_by`/`rotated_by`) | `sub`, `username` |
| `POST /api/v1/services/{name}/{action}` | `actor_subject`, `actor_username` (query) | `sub`, `username` |
| `POST /api/v1/problem-reports` | `actor_subject`, `actor_username` (query) | `sub`, `username` |
| `POST /api/v1/problem-reports` | `actor_display_name` (query) | dropped (an assertion has no display name; the record falls back to the username) |
| `POST /api/v1/github-analysis/submit` | `actor_subject`, `actor_username` (body) | `sub`, `username` |
| `POST /api/v1/ml-anomalies/ack`, `/ack-all`, `/disposition` | `actor` (body: `AckedBy`, `disposition_by`) | `username` |
| `POST /api/v1/ip-block` | `actor` (body: `BlockedBy`) | `username` |
| `POST /api/v1/canarytokens` | `created_by` (body) | `username` |

Not bound, on purpose: the Workbench's `owner` comes from `x-actor-username`
(already rewritten by the middleware) and is never read from a body; report
`branding.author` is free text printed on a PDF, not an identity; the bait
credential's `username` is the decoy's login, not the operator.

Before `enforce`, check the `log` output for these lines too. The current
dashboard sends the OIDC display name, not the username, as canarytoken
`created_by`, so every canarytoken creation logs one until the dashboard
sends the username (under `enforce` it is simply overridden).

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

## Workbench ownership migration (display names to usernames)

Until the dashboard signs (Xore-Inc/apiary-dashboard#249), `owner` in
`dashboard-workbench-runs-v1` and `dashboard-workbench-recipes-v1` is what
the BFF sent as `x-actor-username`: the operator's **display name**. The
signing dashboard sends the OIDC **username** in both the plain header and the
assertion's `username` claim (Xore's decision on #249: stable and unique,
where a display name is neither), and the backend scopes by it. A document
still owned by a display name is invisible to its operator from then on.

`scripts/workbench-owner-migration.py` rewrites `owner` in both indices. It
changes nothing else: run ids (which hash the old owner) and recipe ids stay,
so links and children keep working; a new submission of an identical payload by
the same operator makes a fresh run instead of reusing the migrated one.

**When.** After the signing dashboard is live (rollout step 3), and before the
flip to `enforce` (step 5). Not before step 3: until then the dashboard still
sends display names. The signing dashboard sends the username in the plain
header too (a different value would make `log` mode warn on every request, and
step 4 needs the log silent), so operators stop seeing their old runs and
recipes as soon as it deploys, in `off` and `log` mode alike, until the
migration has run. Run it right after that deploy.

**The mapping** is supplied, never guessed. From Keycloak, with the
already-authenticated `kcadm` of `docs/KEYCLOAK-OPERATIONS.md` (read-only; the
script itself logs in to nothing):

```bash
sudo docker exec hp-keycloak /opt/keycloak/bin/kcadm.sh get users -r apiary \
  --fields username,firstName,lastName -q max=1000 --config /tmp/kcadm.config > users.json
```

or a file of `display name<TAB>username` lines / a JSON object. Keep the file
out of git. The display name is first plus last name, as Keycloak's `name`
claim is; add a `--mapping` file for names that came from elsewhere.

**Run** from a throwaway container on the honeynet network (Elasticsearch
publishes no port):

```bash
docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" -v "$PWD/map:/m:ro" \
  python:3-alpine python /s/workbench-owner-migration.py --keycloak-users /m/users.json          # dry run
docker run ... python /s/workbench-owner-migration.py --keycloak-users /m/users.json --apply
```

The dry run is the default and prints, per index, what would move and what is
skipped. Read it before applying. Skipped, and never rewritten:

- **ambiguous**: two users share the display name;
- **collision**: the display name is also another user's username, so the
  documents may already be theirs;
- **unmapped**: an owner in the index that names nobody in the mapping.

Resolve these by hand (add a mapping line once you know whose they are) and
re-run. Re-running is safe: a second run changes nothing.

**Write path.** One `_update_by_query` per name and index with
`pipeline=_none`, because an index's `default_pipeline` re-runs on
`_update_by_query`. Neither index has one (no `index.default_pipeline` in
`elasticsearch-setup.sh`); the script checks anyway, bypasses a default
pipeline, and refuses `--apply` on an index with a `final_pipeline`, which
cannot be bypassed.

**Roll back** (the dashboard goes back to display names, or the migration was
wrong): run the same command with `--reverse` and the same mapping, which moves
usernames back to display names for the unambiguous pairs. If the dashboard is
being rolled back to a non-signing build, put the backend in `log` or `off`
first (see above), then `--reverse`. Documents created after the flip under a
username are moved too, which is what the rolled-back dashboard expects.

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
  only, redeploy, then give the same value to the VPS job (`BLACKHOLE_EXPORT_TOKEN`, if it pulls the backend directly) and re-enable it.
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

## OpenAPI

`openapi.json` documents the three headers as security schemes:
`serviceToken` (`X-Service-Token`), `exportToken` (`X-Export-Token`, listed
only on `GET /api/v1/ip-block-export`) and `actorAssertion`
(`X-Actor-Assertion`). Every BFF operation accepts `serviceToken` alone or
`serviceToken` plus `actorAssertion`: an alternative rather than a second
requirement, because the default mode does not ask for an assertion; the
scheme's description says when `enforce` does. `info.x-api-version` stays 1:
the additions are additive.
