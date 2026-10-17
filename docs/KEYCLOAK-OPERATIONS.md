# Keycloak deployment and operations

This is the canonical runbook for APIARY identity. It describes a hard cutover:
there is no legacy auth runtime, user import, dual-write period, or fallback.
All example hostnames are reserved placeholders. Keep production domains,
addresses, passwords, client secrets, cookies, and realm users out of Git.

## Resulting topology

- `honeypot-keycloak` is an Arcane-managed stack on the homeserver.
- No local image is built, and the two upstream images are pinned
  *differently on purpose*. PostgreSQL is a digest pin
  (`postgres:18.6-bookworm@sha256:…`) because its version is chosen, not
  chased. Keycloak is deliberately **unpinned** —
  `quay.io/keycloak/keycloak:latest` with `pull_policy: always` — because it
  is the identity provider for the whole stack: it was digest-pinned to
  26.7.1 when CVE-2026-18963 (unauthenticated account takeover via
  reset-credentials, CVSS 9.1) landed, and a digest pin is exactly what keeps
  a known-vulnerable build running until someone edits a file. `pull_policy`
  is load-bearing here, not decoration: without it a redeploy silently reuses
  whatever `:latest` first resolved to, which is a pin again with none of the
  honesty of one. Do not "tidy" the tag into a digest without reading the
  comment above it in the compose file first.
- PostgreSQL is reachable only on the internal `keycloak-data` network.
- Keycloak publishes HTTP only on the homeserver WireGuard address.
- VPS Traefik terminates TLS and forwards the issuer and administrator hosts
  through `socat-hp-keycloak` over WireGuard.
- The administrator host uses Keycloak realm-admin login and mandatory TOTP.
  Do not add HTTP Basic: the admin SPA needs the `Authorization` header for its
  Bearer API calls.
- Each VPS-fronted application has its own Keycloak client, oauth2-proxy
  cookie, client secret, Docker network, and upstream bridge -- six gateways
  total (§3). `apiary-dashboard` is the exception: its oauth2-proxy
  compatibility gateway was retired once every dashboard replica moved to
  native OIDC (#1026), so its secret goes straight to the dashboard binary
  instead of a VPS gateway.
- Two more confidential clients, `arcane` and `auth-events-poller`, live
  entirely on the homeserver side and never touch the VPS at all. Realm
  total: nine confidential clients across three surfaces (§3).
- `Xore/auth-backend` supplies only the read-only `themes/apiary` directory.

## Files and host paths

| Item | Repository source | Runtime location |
|---|---|---|
| Arcane Compose file | `arcane/home/honeypot-keycloak/compose.yml` | `/var/dockge/stacks/honeypot-keycloak/compose.yml` |
| Arcane environment | `arcane/home/honeypot-keycloak/.env.example` | `/var/dockge/stacks/honeypot-keycloak/.env` |
| Realm template | `arcane/home/honeypot-keycloak/keycloak/realm/apiary-realm.json` | `/var/dockge/stacks/honeypot-keycloak/keycloak/realm/` |
| Theme | `Xore/auth-backend:themes/apiary` | `/var/dockge/stacks/honeypot-keycloak/theme/apiary` |
| Keycloak secrets | none | `/var/dockge/stacks/honeypot-keycloak/secrets` |
| VPS Compose | `vps/docker-compose.yml` | existing VPS stack directory |
| VPS OIDC secrets | none | `vps/secrets/oidc/<client>/` on the VPS |

Arcane must own the homeserver stack directory. Do not create a second
standalone Compose project for Keycloak.

## 1. Prepare the homeserver stack

Synchronize the Compose file, `keycloak/` directory, and reviewed theme into
the paths above. The production home deployment workflow performs this copy.
For a manual installation, create the directories first:

```bash
sudo install -d -m 755 /var/dockge/stacks/honeypot-keycloak
sudo install -d -m 750 /var/dockge/stacks/honeypot-keycloak/secrets
sudo install -d -m 755 /var/dockge/stacks/honeypot-keycloak/theme
```

Copy `arcane/home/honeypot-keycloak/.env.example` to `.env` and set host-local values:

```dotenv
HP_BIND=<homeserver-wireguard-address>
KEYCLOAK_PORT=18080
KEYCLOAK_URL=https://auth.honeypot.example
KEYCLOAK_PUBLIC_DOMAIN=honeypot.example
KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=bootstrap-admin
KEYCLOAK_THEME_DIR=/var/dockge/stacks/honeypot-keycloak/theme/apiary
KEYCLOAK_SECRETS_DIR=/var/dockge/stacks/honeypot-keycloak/secrets
RESTIC_REPOSITORY=/mnt-2/apiary-keycloak
RESTIC_PASSWORD_FILE=/var/dockge/stacks/honeypot-keycloak/secrets/restic-password
```

Protect the environment and generate independent secrets locally:

```bash
sudo chmod 600 /var/dockge/stacks/honeypot-keycloak/.env
sudo sh -c 'umask 027; openssl rand -base64 48 > /var/dockge/stacks/honeypot-keycloak/secrets/postgres-password'
sudo sh -c 'umask 027; openssl rand -base64 48 > /var/dockge/stacks/honeypot-keycloak/secrets/bootstrap-admin-password'
sudo sh -c 'umask 027; openssl rand -base64 48 > /var/dockge/stacks/honeypot-keycloak/secrets/restic-password'
sudo chown root:root /var/dockge/stacks/honeypot-keycloak/secrets/*
sudo chmod 440 /var/dockge/stacks/honeypot-keycloak/secrets/*
```

The realm file contains only `example.invalid`. At container start it is
rendered into tmpfs using `KEYCLOAK_PUBLIC_DOMAIN`, then imported with
`--import-realm`. Client secrets are generated by Keycloak and are never stored
in the realm template.

Validate before starting:

```bash
./arcane/home/honeypot-keycloak/keycloak/realm/validate.sh
docker compose --env-file arcane/home/honeypot-keycloak/.env.example \
  -f arcane/home/honeypot-keycloak/compose.yml config --quiet
```

Start from Arcane, or from the stack directory:

```bash
cd /var/dockge/stacks/honeypot-keycloak
sudo docker compose --env-file .env -f compose.yml up -d
sudo docker compose --env-file .env -f compose.yml ps
```

Wait for both containers to become healthy. A first start performs Keycloak's
Quarkus augmentation and database migration, so it is slower than later starts.
The upstream image needs a writable disposable container layer for this step;
do not set `read_only: true` unless a separately reviewed optimized image is
built first.

## 2. Create the sole administrator

Authenticate `kcadm` with the temporary bootstrap administrator from inside the
container. Avoid putting either password in shell history:

```bash
sudo docker exec hp-keycloak bash -ec '
  /opt/keycloak/bin/kcadm.sh config credentials \
    --config /tmp/kcadm.config \
    --server http://127.0.0.1:8080 \
    --realm master \
    --user "$KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME" \
    --password "$(< /run/keycloak-secrets/bootstrap-admin-password)"
'
```

Create a named human in the `apiary` realm with a verified operator-owned email,
a temporary policy-compliant password, and required actions `UPDATE_PASSWORD`
and `CONFIGURE_TOTP`. Add the user to `/administrators` and grant the
`realm-management` client role `realm-admin`. Do not add
`recovery-authn-codes-config`: the pinned runtime does not provide that required
action factory. Recovery is an administrator-driven credential reset.

Verify the user before deleting bootstrap access:

```bash
KC=/opt/keycloak/bin/kcadm.sh
sudo docker exec hp-keycloak "$KC" get users -r apiary \
  -q username=<admin-user> --config /tmp/kcadm.config
```

Open `https://auth.honeypot.example/admin/apiary/console/`, replace the
temporary password, enroll TOTP, and confirm the administrator can read the
realm. Then remove both bootstrap artifacts and restart:

```bash
sudo rm /var/dockge/stacks/honeypot-keycloak/secrets/bootstrap-admin-password
sudo rm /var/dockge/stacks/honeypot-keycloak/secrets/admin.initial-password
cd /var/dockge/stacks/honeypot-keycloak
sudo docker compose --env-file .env -f compose.yml restart keycloak
```

The public realm has self-registration disabled. Administrators create every
human account, and TOTP is a default required action for all humans.

## 3. Provision VPS OIDC gateways

Set these host-local values in the existing VPS stack `.env`:

```dotenv
OIDC_ISSUER_URL=https://auth.honeypot.example/realms/apiary
OIDC_PUBLIC_DOMAIN=honeypot.example
OIDC_SECRETS_DIR=./secrets/oidc
```

For each client below, create its own directory and files. This is six of
the realm's nine confidential clients -- the ones with a VPS oauth2-proxy
gateway; see "Non-gateway confidential clients" below for the other three:

| Directory/client | Public consumer |
|---|---|
| `kibana` | Kibana |
| `evebox` | EveBox |
| `arkime` | Arkime |
| `tanner` | TANNER |
| `revdeck` | RevDeck |
| `traefik-dashboard` | Traefik dashboard |

`client-secret` is the value returned by Keycloak for that confidential client.
`cookie-secret` is 32 independent random bytes:

```bash
sudo install -d -m 750 ./secrets/oidc/<client>
sudo sh -c 'openssl rand 32 > ./secrets/oidc/<client>/cookie-secret'
sudo chown -R root:65532 ./secrets/oidc/<client>
sudo chmod 750 ./secrets/oidc/<client>
sudo chmod 440 ./secrets/oidc/<client>/*
```

`client-secret` is different: since `apiary-realm.json` pins no client
`secret`, Keycloak generates a fresh random one for all 9 confidential
clients on every `--import-realm` (including a clean rebuild, #787). Use
[`keycloak/sync-client-secrets.sh`](../arcane/home/honeypot-keycloak/keycloak/sync-client-secrets.sh) to
fetch and install these 6 gateway secrets in one pass instead of the manual
per-client procedure below -- run from the homeserver with SSH access to the
VPS:

```bash
KEYCLOAK_ADMIN_USERNAME=<master-realm admin> \
KEYCLOAK_ADMIN_PASSWORD=<its password> \
./keycloak/sync-client-secrets.sh
```

It writes each secret directly over SSH (never to a local file or a
command-line argument), fixes ownership/permissions to match the manual
steps above, and restarts each of the 6 gateways so the new secret takes
effect immediately. Manual fallback, retrieving a single client secret using
the already authenticated homeserver `kcadm` (what the script above does for
all 6):

```bash
KC=/opt/keycloak/bin/kcadm.sh
CLIENT=<client>
CLIENT_UUID=$(sudo docker exec hp-keycloak "$KC" get clients -r apiary \
  -q "clientId=$CLIENT" --fields id --format csv --noquotes \
  --config /tmp/kcadm.config)
sudo docker exec hp-keycloak "$KC" get \
  "clients/$CLIENT_UUID/client-secret" -r apiary \
  --config /tmp/kcadm.config
```

Transfer only the returned `value` into the matching VPS `client-secret` file
over an encrypted administrative channel. Do not print it into CI logs, store it
in `.env`, reuse it between clients, or commit it. A clean realm rebuild creates
new client secrets; rotate all six VPS files and restart all six gateways.

### Non-gateway confidential clients

The realm's other three confidential clients have no VPS oauth2-proxy
gateway, so `sync-client-secrets.sh` and the manual procedure above do not
cover them. Each is rotated by its own idempotent provisioner script, run on
the homeserver alongside (not instead of) the gateway rotation -- see §7 for
the full clean-rebuild sequence:

| Client | Surface | Provisioner |
|---|---|---|
| `apiary-dashboard` | homeserver -- native OIDC in the dashboard binary itself | [`keycloak/provision-dashboard-oidc-secret.sh`](../arcane/home/honeypot-keycloak/keycloak/provision-dashboard-oidc-secret.sh) |
| `arcane` | homeserver -- Arcane's own OIDC login | [`keycloak/provision-arcane-oidc-secret.sh`](../arcane/home/honeypot-keycloak/keycloak/provision-arcane-oidc-secret.sh) |
| `auth-events-poller` | homeserver -- service-account only, no login | [`keycloak/provision-events-poller.sh`](../arcane/home/honeypot-keycloak/keycloak/provision-events-poller.sh) |

`apiary-dashboard` used to be the seventh VPS gateway (`oidc-dashboard`)
until #1026's follow-up retired that compose service in favor of native
OIDC; its secret now goes straight to the dashboard binary's own secrets
file instead of a VPS `client-secret` file.

Deploy `vps/docker-compose.yml`, `vps/traefik/traefik.yml`, and a production-
rendered `vps/traefik/dynamic.yml` into the existing VPS stack. Do not start a
second Compose project. Confirm the existing Compose project label before a
manual deployment:

```bash
docker inspect traefik \
  --format '{{ index .Config.Labels "com.docker.compose.project" }}'
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.yml up -d
```

## 4. DNS, TLS, and Traefik behavior

Create public DNS/TLS coverage for the issuer/administrator hostname (they are
the same host, #1028) and the protected application hostnames. Traefik must
preserve the original Host and forwarded HTTPS scheme. Only the Keycloak
application port crosses WireGuard; PostgreSQL and Keycloak port 9000 remain
private.

The Keycloak administrator SPA embeds two issuer endpoints from itself for
session/cookie checks. Because they're the same origin, this only needs a
same-origin framing exception, not a cross-host CSP allowlist:

- `/realms/apiary/protocol/openid-connect/3p-cookies/`
- `/realms/apiary/protocol/openid-connect/login-status-iframe.html`

The dedicated `keycloak-embedded-frames` router sets `X-Frame-Options:
SAMEORIGIN` and `frame-ancestors 'self'` only for those paths. Every ordinary
Keycloak page retains `X-Frame-Options: DENY`. A separate
`keycloak-admin-console` router (`PathPrefix(/admin)` on the same host) exists
only to give the admin SPA's asset burst a larger rate limit than login/token
endpoints get.

Do not put Traefik BasicAuth in front of the admin path. The admin SPA calls
`/admin/serverinfo`, `/admin/realms/`, and related endpoints using
`Authorization: Bearer`; BasicAuth would consume the same header and cause an
endless browser credential prompt. Keycloak realm-admin authorization and TOTP
are the protection boundary.

The admin route permits a browser-sized burst because the SPA loads many
modules, fonts, and localization resources concurrently. A very small burst
returns `429` for assets and looks like a broken console.

## 5. Acceptance tests

Run all tests after first deployment, realm rebuild, secret rotation, or image
upgrade:

1. Both homeserver containers are healthy.
2. VPS-to-homeserver realm discovery returns `200` over WireGuard.
3. Discovery advertises exactly the public issuer.
4. Login HTML references the APIARY theme.
5. Every protected application redirects an anonymous request to the APIARY
   authorization endpoint.
6. A wrong-role user is denied.
7. The admin console loads without HTTP Basic and requires Keycloak login.
8. First login requires a password replacement and TOTP.
9. `/realms/apiary/protocol/openid-connect/login-status-iframe.html/init`
   **and** `/realms/master/...` (any realm, not just `apiary`) both return
   `204` and `X-Frame-Options: SAMEORIGIN` (not `DENY`) -- #1028 found the
   `master`-realm case broken (bootstrap-admin session) after only testing
   `apiary`.
10. Ordinary login/account pages still return X-Frame-Options `DENY`.
11. Log into the admin console fully (not just the initial page load) and
    confirm no `429` in the browser console -- specifically load a page with
    many asset chunks (e.g. Clients or a Dashboard widget) and open the
    Account Console's Device Activity tab. #1028 found both
    `/resources/<fingerprint>/admin/...` assets and `/realms/<realm>/
    account/...` API calls independently falling through to the tighter
    login/token rate limit.
12. Each oauth2-proxy container is healthy and has no configuration error.
13. Direct access to each protected upstream is unreachable from other public
    routers and Docker networks.

Useful checks:

```bash
docker compose --env-file vps/.env.example \
  -f vps/docker-compose.yml config --quiet
python3 scripts/check-public-leaks.py
python3 scripts/validate-oidc-redirects.py
./keycloak/realm/validate.sh
```

## 6. Backup and restore

This backup covers the active Keycloak PostgreSQL state, not the removed legacy
auth backend. Install Restic on the homeserver, initialize the configured
repository on the off-VPS storage mount, and keep the repository and password
file host-local:

```bash
sudo restic -r /mnt-2/apiary-keycloak \
  --password-file /var/dockge/stacks/honeypot-keycloak/secrets/restic-password \
  init
sudo /var/dockge/stacks/honeypot-keycloak/keycloak/backup.sh
```

`backup.sh` streams a PostgreSQL custom dump into Restic, applies daily/weekly
retention, prunes, and checks a configured data subset. Schedule it with a
root-owned systemd timer or equivalent. Test restores against a disposable
stack before relying on them:

```bash
sudo KEYCLOAK_RESTORE_CONFIRM=restore-keycloak-database \
  /var/dockge/stacks/honeypot-keycloak/keycloak/restore.sh latest
```

## 7. Upgrade and rebuild procedure

1. Review Keycloak and PostgreSQL release notes.
2. Update the PostgreSQL tag and digest together in
   `arcane/home/honeypot-keycloak/compose.yml`. The Keycloak service needs no
   edit — it is deliberately on `:latest` with `pull_policy: always` (see
   "Resulting topology"), so a security release arrives by redeploying, and
   accepting that trade is the decision this step is not asking you to
   revisit.
3. Re-test the theme against the pinned Keycloak parent theme.
4. Validate Compose and the realm template.
5. Deploy to a disposable stack and exercise the acceptance tests.
6. For a deliberate clean rebuild, remove the Keycloak PostgreSQL volume,
   import the realm, recreate the administrator, then rotate all nine
   confidential clients' secrets in two steps -- both required, either
   order:
   - `keycloak/sync-client-secrets.sh` (§3): the six VPS gateway secrets,
     restarting every gateway.
   - `keycloak/provision-dashboard-oidc-secret.sh`,
     `keycloak/provision-arcane-oidc-secret.sh`, and
     `keycloak/provision-events-poller.sh` (§3 "Non-gateway confidential
     clients"): the three homeserver-side clients.

   Then repeat the full acceptance suite.
7. Never reuse a stale client-secret file after a clean realm rebuild.

## Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| Admin console assets return `429` while the console shell itself loads | The admin theme's JS bundle loads from `/resources/<build-fingerprint>/admin/keycloak.v2/assets/...`, not `/admin` itself -- `/admin` is only the SPA shell. A rate-limit router scoped to `PathPrefix(/admin)` alone misses it and it falls through to the tighter login/token limit. Caught live (#1028). | `keycloak-admin-console`'s rule must also match `PathRegexp(^/resources/[^/]+/admin/)`, not just `/admin`. |
| Account Console (Device Activity, Sessions, etc.) returns `429` | `/realms/<realm>/account/...` REST calls are authenticated interactive SPA traffic, same as the admin console, but aren't covered by the admin-only rate-limit router. Caught live (#1028). | Route `PathRegexp(^/realms/[^/]+/account)` through the same looser rate limit (`keycloak-account-console` router). |
| Browser reports X-Frame-Options `DENY` (or "Timeout when waiting for 3rd party check iframe message") anywhere in Keycloak's own UI | `keycloak-embedded-frames`'s path rule is scoped to a single realm | Match `/realms/[^/]+/protocol/openid-connect/...` (any realm) via `PathRegexp`, not a hardcoded realm name -- the admin console's 3rd-party cookie check runs against whichever realm the current session is in, including `master` while still on the bootstrap-admin login (before a named realm admin exists). Caught live (#1028): the original rule only matched the `apiary` realm and never covered `master`. |
| Endless HTTP password prompts | BasicAuth conflicts with Keycloak Bearer calls | Remove BasicAuth and its htpasswd mount; use Keycloak login + MFA. |
| Password update returns internal error | Unsupported recovery-code required action was imported | Rebuild from the validated realm without that action; do not patch database state. |
| All gateways restart with secret read errors | UID 65532 cannot traverse/read host secret paths | Use `root:65532`, directory `0750`, files `0440`. |
| Gateways redirect but callback fails after rebuild | VPS client secrets belong to the old realm | Run `keycloak/sync-client-secrets.sh` to rotate all 6 gateway client-secret files and restart every gateway in one pass. |
| Dashboard, Arcane login, or the events poller fail after rebuild with the gateways otherwise fine | Their homeserver-side client secrets belong to the old realm -- `sync-client-secrets.sh` never touches them (§3) | Run `keycloak/provision-dashboard-oidc-secret.sh`, `keycloak/provision-arcane-oidc-secret.sh`, and/or `keycloak/provision-events-poller.sh` as applicable. |
| WireGuard port is absent | Keycloak is attached only to an internal Docker network | Attach Keycloak to `keycloak-data` and `keycloak-egress`; PostgreSQL uses only `keycloak-data`. |
| Keycloak fails on a read-only filesystem | Upstream image needs first-start augmentation | Allow its disposable layer to be writable or build a separately reviewed optimized image. |
| A theme file edit + `docker compose restart keycloak` doesn't reach real browsers, even though `curl` (no compression) and internal checks show the fix is live | Keycloak/Quarkus caches a gzip-compressed copy of every theme resource under `/opt/keycloak/data/tmp/kc-gzip-cache/`, which lives in the container's own writable layer -- it is not bind-mounted or a named volume, so it survives `docker restart` and is never invalidated when the source file on disk changes. Every real browser sends `Accept-Encoding: gzip` by default, so it keeps getting served the stale compiled variant indefinitely. Caught live (#108/#1027): repeated Cloudflare cache purges appeared not to fix a login theme bug because the *origin itself* was still serving the old file under gzip. | After any theme file change, before (or instead of) blaming CDN cache: `docker exec hp-keycloak rm -rf /opt/keycloak/data/tmp/kc-gzip-cache` -- no restart needed, Keycloak regenerates it lazily on the next request. Only a full container recreate (not `restart`) would otherwise clear it. Verify with `curl -H 'Accept-Encoding: gzip' --compressed ...` specifically, not a plain `curl`/`wget` that skips compression -- those two can disagree. |
