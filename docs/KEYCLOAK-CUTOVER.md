# Keycloak hard-cutover contract

Status: accepted Phase 0 decision record for #976 and epic #986.

> **Status, verified against the repository 2026-09-27: the cutover is
> implemented, not pending.** The line above is the decision that was accepted
> at Phase 0; the hard cutover it specifies has since been carried out, so read
> this file as the contract that governs the live identity tier rather than as a
> proposal. What the repository shows today:
>
> - `honeypot-keycloak` is a manifest entry
>   (`arcane/manifests/home-production.json`) and a deployed stack
>   (`arcane/home/honeypot-keycloak/compose.yml` — Keycloak plus its
>   PostgreSQL), which is the "Fixed architecture" section's `honeypot-keycloak`
>   stack.
> - The seven "Isolated gateway" rows in the matrix below correspond one-to-one to
>   seven `oauth2-proxy` services in `vps/docker-compose.yml`: `oidc-kibana`,
>   `oidc-tanner`, `oidc-evebox`, `oidc-arkime`, `oidc-revdeck`, `oidc-unsloth` and
>   `oidc-traefik` (one `quay.io/oauth2-proxy/oauth2-proxy` image definition,
>   seven services sharing its `oidc-gateway-environment` anchor). `arcane.*` and
>   the `dashboard.*`/`honeypot.*` row correctly have no gateway.
> - Every identifier on the **Hard-cutover removal list** below is gone from
>   live configuration. `auth-portal`, `strip-auth-identity`, `xore_sso`,
>   `AUTH_INTROSPECTION_URL` and `AUTH_TARGET_HOST` now appear only in
>   documentation (this file, `docs/TESTING.md` and the dated
>   `docs/research/518-smoke-test-research.md` record), never in `vps/` or
>   `arcane/`. No `forward-auth`/`forwardAuth` middleware reference remains
>   under `vps/` or `arcane/`.
> - The `Xore/auth-backend` line below is accurate as written and should not be
>   read as a live dependency: the *runtime* is retired and only the
>   presentation-only theme is still sourced from that repository, which is
>   what `docs/SENSORS.md` and `docs/KEYCLOAK-OPERATIONS.md` already say.
>
> The contract text itself is unchanged and still accurate; this note records
> only that it has shipped. Day-to-day administration lives in
> [`KEYCLOAK-OPERATIONS.md`](KEYCLOAK-OPERATIONS.md).

Implementation and operations are documented in
[`KEYCLOAK-OPERATIONS.md`](KEYCLOAK-OPERATIONS.md). `Xore/auth-backend` owns
exactly the presentation-only `themes/apiary` Keycloak theme, checked out
read-only into the APIARY deployment at build/install time -- see
[`Xore/auth-backend#96`](https://github.com/Xore/auth-backend/issues/96) (that
repo's own epic) and [`Xore/auth-backend#91`](https://github.com/Xore/auth-backend/issues/91)
(the theme build itself). APIARY owns every other row in the matrix below,
including Keycloak's own deployment, realm, and routing.

## Fixed architecture

Keycloak and PostgreSQL run in the Arcane-managed `honeypot-keycloak` stack on
the homeserver. Public TLS terminates at VPS Traefik, which reaches Keycloak and
protected applications only over WireGuard bridges. `auth.example.invalid` is
both the OIDC issuer and the administrator console (`/admin/apiary/console/`,
#1028) -- Keycloak's realm-admin login and mandatory MFA protect the console,
not a separate hostname.

The dashboard is a confidential native OIDC client. Every application without
acceptable native OIDC gets its own isolated `oauth2-proxy` instance and its
own confidential Keycloak client. Proxies do not share client secrets, cookie
secrets, cookies, or upstream networks. A proxy may inject identity headers
only when its upstream has no path reachable from the browser, another stack,
or the honeynet that bypasses that proxy.

Humans are created by administrators only. Every human must configure TOTP.
Automation uses narrowly scoped service accounts and is not treated as a human
MFA exception. Recovery is an administrator-driven credential reset because the
pinned Keycloak runtime does not provide a recovery-code required-action factory.

## Route and consumer matrix

| Route | Consumer | Integration | Keycloak client | Required role | Trust boundary and special traffic |
|---|---|---|---|---|---|
| `dashboard.*`, `honeypot.*` | APIARY dashboard, APIs, SSE, exports, embedded settings | Native authorization-code OIDC with PKCE | `apiary-dashboard` | `user`; mutations require `admin` | Dashboard validates tokens and owns its session. No proxy identity headers. PDF routes use the same dashboard session. |
| `kibana.*` | Kibana | Isolated gateway | `kibana` | `access` | Gateway is the only network peer allowed to reach Kibana; preserve WebSockets and base paths. |
| `evebox.*` | EveBox | Isolated gateway | `evebox` | `access` | Gateway is the only upstream path; preserve API, stream, and download behavior. |
| `arkime.*` | Arkime | Isolated gateway | `arkime` | `access` | Arkime trusts the gateway-injected `X-Forwarded-User` identity (`authMode=header+digest`, #979) -- safe only because the upstream is unreachable except through the gateway (verified) and oauth2-proxy strips any client-supplied copy of that header before injecting its own (`OAUTH2_PROXY_SKIP_AUTH_STRIP_HEADERS`, pinned). The pre-existing local "admin" digest account remains as a fallback. |
| `tanner.*` | TANNER UI | Isolated gateway | `tanner` | `access` | Gateway-only upstream network; preserve API and static assets. |
| `rev.*` | RevDeck/Ghidra UI | Isolated gateway | `revdeck` | `access` | Gateway-only upstream network; preserve long responses, downloads, and streams. |
| `unsloth.*` | Unsloth Studio UI (#3689; upstream not yet deployed) | Isolated gateway | `unsloth` | `access` (administrators group only) | Gateway-only upstream network; preserve WebSockets and long-lived streams. |
| `traefik.*` | Traefik read-only dashboard | Isolated gateway | `traefik-dashboard` | `admin` | Gateway fronts `api@internal`; callback is excluded from recursive auth. |
| `arcane.*` | Arcane administrator UI (#1185, Dockge's replacement -- Dockge decommissioned) | Native authorization-code OIDC | `arcane` | `admin` | No gateway: Arcane authenticates directly against Keycloak. Root-equivalent risk (`/var/run/docker.sock` mounted read-write) -- `admin` role is granted only to the `administrators` group. |
| `auth.example.invalid` | OIDC login, discovery, JWKS, account console | Direct Keycloak | n/a | public protocol endpoints; authenticated account actions | Rate-limited edge route to the Keycloak WireGuard bridge. |
| `auth.example.invalid/admin` | Keycloak administration | Direct Keycloak | n/a | Keycloak administrator + MFA | Same host as the issuer (#1028); a `PathPrefix(/admin)` router gives the SPA's bootstrap burst a larger rate limit. Keycloak owns authentication; HTTP Basic would conflict with the SPA's Bearer API calls. |
| decoy/static/API/status/file/blog hosts currently lacking `forward-auth` | Public honeypot or explicitly application-owned auth | Public / unchanged | none | none | Never attach operator SSO merely because the hostname exists. Public collection must remain independent of IdP availability. |

Role names differ per row on purpose. The realm's low-privilege client role is
`access`, and every gateway enforces exactly `<client>:access` through
`OAUTH2_PROXY_ALLOWED_ROLES` in `vps/docker-compose.yml`;
`traefik-dashboard` and `arcane` deliberately use `admin` instead
(#1014/#1185, root-equivalent). The dashboard row's `user` is
*not* a Keycloak role name: `resource_access.apiary-dashboard.roles` carries
`access` and `admin`, and the dashboard collapses them to its own
`user`/`admin` session role. Which human carries which role is a realm
provisioning decision, not a repository fact: the committed
`keycloak/realm/apiary-realm.json` defines the `users` and `administrators`
groups with empty `roleMappings`, so treat the group membership the matrix
implies as an operator-side grant to be verified in the live realm.

The deployment validator must fail when a protected router has neither native
OIDC ownership nor its named gateway. A redirect alone is not evidence: each
row must retain an authorized real-page/API check and an unauthorized denial
check before cutover.

## Claims and sessions

- Immutable identity and audit key: Keycloak `sub`.
- Display identity: `preferred_username`, with `name` as optional display text.
- Dashboard roles: client roles in `resource_access.apiary-dashboard.roles`;
  `admin` implies the normal `user` capabilities.
- Gateway roles: the matching client's role claim only. A role for one client
  never authorizes another client.
- Authorization code flow only, exact redirect URIs, S256 PKCE, state, and
  nonce. Implicit and resource-owner-password grants stay disabled.
- Sessions fail closed on invalid signature, issuer, audience/authorized party,
  expiry, not-before, missing subject, missing required role, refresh failure,
  or unavailable required identity state.
- Logout deletes local/gateway state and uses Keycloak RP-initiated logout with
  an allowlisted post-logout redirect.

## Hard-cutover removal list

The production cutover removes all of the following in one reviewed change:

- the `auth-portal` router/service and VPS dependency on the old runtime;
- the `forward-auth` and `strip-auth-identity` middleware chain;
- `/_auth/verify`, `/_auth/introspect`, and the `xore_sso` cookie;
- `AUTH_INTROSPECTION_URL`, `AUTH_INTROSPECTION_TOKEN`, `AUTH_TARGET_HOST`,
  `AUTH_SESSION_COOKIE_NAME`, and trusted `X-Auth-*` behavior;
- Arkime's old generic header-auth path and every direct protected-upstream
  route that bypasses its gateway;
- old account/settings iframe URLs and legacy recovery links.

There is no legacy user import, dual-write, fallback runtime, or rollback to
the old identity system. Recovery restores the validated Keycloak/APIARY
release and its PostgreSQL backup.

## Validation gates

For every protected row, test anonymous, authorized, wrong-role, expired,
revoked/disabled, wrong-issuer, wrong-audience, direct-backend, and forged-header
access. Also exercise its deep links, static assets, API calls, WebSockets/SSE,
downloads, refresh, and logout where applicable. Keycloak, PostgreSQL,
discovery/JWKS, gateway, DNS, TLS, and client-secret failures must deny access
without affecting public honeypot collection.
