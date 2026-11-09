# Dockge-managed Keycloak

For the complete installation and operations procedure, use
[`docs/KEYCLOAK-OPERATIONS.md`](../../../../docs/KEYCLOAK-OPERATIONS.md). This file is a
short component summary.

The `honeypot-keycloak` Arcane stack is defined by
[`compose.yml`](../compose.yml). Keycloak and
PostgreSQL run on the homeserver; VPS Traefik forwards `auth.example.invalid` over
WireGuard to `${HP_BIND}:${KEYCLOAK_PORT}`. PostgreSQL and port 9000 are never
published.

The stack pulls pinned upstream images and performs no Compose image build.
`Xore/auth-backend` supplies only the custom-theme assets mounted from
`KEYCLOAK_THEME_DIR`. Realm policy, runtime deployment, and database durability
belong here in APIARY.

## Bootstrap

Before the first Dockge start:

1. Review the stack `.env`, initially copied from `.env.example`.
   Set `KEYCLOAK_PUBLIC_DOMAIN` to the private deployment value; the container
   renders the secret-free realm template locally before its first import.
2. Create `KEYCLOAK_SECRETS_DIR`, owned by `root:root`, with mode `0750`.
3. Create `postgres-password`, `bootstrap-admin-client-secret`, and
   `restic-password` with independent random values, owned by `root:root` and
   mode `0440`. Keycloak runs as a non-root user in group 0, while PostgreSQL's
   entrypoint reads its password file before dropping privileges.
4. Confirm `KEYCLOAK_THEME_DIR` points at the stack-local theme synchronized
   from the reviewed `Xore/auth-backend` repository by the home deploy job.
5. Start in Dockge. On an empty database Keycloak creates only a temporary
   admin service-account client (#3824), no user.
6. Run `provision-admin-client.sh` (permanent `apiary-ops-admin` client,
   secret in `secrets/admin-client-secret`; deletes the temporary client and
   its secret file), then `provision-master-realm.sh` and the other
   provisioners. All of them authenticate through `lib-admin.sh` with that
   client, never with a password on a command line.
7. Create the named, MFA-enabled human administrator.

The canonical, secret-free realm baseline is
[`realm/apiary-realm.json`](realm/apiary-realm.json). Validate it with
`./keycloak/realm/validate.sh`. Client secrets and users are deliberately never
stored in the export.

The VPS route must target the WireGuard endpoint, preserve the original host,
set reviewed `X-Forwarded-*` headers, and never expose port 9000.

The administrator console shares the public issuer hostname
(`https://auth.example.invalid/admin/apiary/console/`, #1028) rather than a
separate host. VPS Traefik routes `/admin` through its own rate limit --
looser than the login/token endpoints, since the SPA loads many assets at
once -- while Keycloak requires a realm-administrator account and MFA. Do not
add HTTP Basic in front of the console: its SPA uses the `Authorization`
header for Bearer API calls.

## Backup and restore

`backup.sh` streams a PostgreSQL custom dump into the encrypted Restic
repository on `/mnt-2`, retaining seven daily and four weekly snapshots.
`RESTIC_REPOSITORY` remains configurable in Dockge's `.env`.

```bash
./keycloak/backup.sh
KEYCLOAK_RESTORE_CONFIRM=restore-keycloak-database \
  ./keycloak/restore.sh latest
```

Test restores against a disposable stack first. A failed restore leaves
Keycloak stopped, preventing operation against partial database state.
