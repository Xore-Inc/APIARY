# Backup and recovery

For a *deliberate* full reset on the same hosts (not disaster recovery), see
[`docs/STACK-REBUILD.md`](../STACK-REBUILD.md) instead — this doc is
about restoring a backup archive onto a replacement host after data loss.

Two backups cover this, with the same scope and the same exclusions:

- [`scripts/backup-essentials.sh`](../../scripts/backup-essentials.sh) runs on
  the workstation and fans an encrypted archive out to three locations. This
  is the one that survives the homeserver dying. Full restore procedure:
  [`docs/BACKUP-ESSENTIALS.md`](../BACKUP-ESSENTIALS.md).
- `sudo analysis/backup-honeypot.sh` runs on the homeserver itself, into a
  timestamped mode-0700 directory beneath `/opt/backups/honeypot`. Faster to
  reach, useless if the box is gone. Validate with
  `analysis/verify-backup.sh <directory>`.

Both capture configuration, secrets, the Keycloak identity database and small
config-bearing volumes. Neither captures Elasticsearch data, captured payloads,
PCAP or sandbox images — a restored stack comes back configured and
authenticated with an empty event history. See
[`docs/BACKUP-ESSENTIALS.md`](../BACKUP-ESSENTIALS.md) for the full in/out list
and the sizes behind it.

Recovery is intentionally not automatic because overwriting live volumes is
destructive.

**Which archive the steps below apply to**: an `analysis/backup-honeypot.sh`
directory — that script's on-host layout of `SHA256SUMS`,
`stack-config-state.tar.gz`, `keycloak.sql.gz` and `volumes/<name>.tar.gz`.
Those names resolve nowhere else, and that archive only exists if the
homeserver itself survived. A restore driven by the archive that actually
survives a dead homeserver — `scripts/backup-essentials.sh`'s
`apiary-essentials-<stamp>.tar.gz.gpg`, a different layout under
`homeserver/`, `vps/` and `repo/` — has its own procedure, and one
prerequisite the steps below do not cover: put
`homeserver/installer/*-install-homeserver.conf` back in place first, because
`scripts/install-homeserver.sh` will not run without it. See
[`docs/BACKUP-ESSENTIALS.md`](../BACKUP-ESSENTIALS.md).

On a replacement host:

1. Verify `SHA256SUMS`, unpack `stack-config-state.tar.gz` into a new empty stack
   directory, and inspect `.env` permissions and values.
2. Restore the Keycloak database from `keycloak.sql.gz` with `hp-keycloak-postgres`
   up and `hp-keycloak` still stopped — this is what preserves the OIDC client
   secrets that the VPS's own `secrets/oidc/` copies have to match.
3. Create the named volumes with `docker compose -f compose.yml create`, keep all
   services stopped, and restore each matching volume archive using a temporary
   networkless BusyBox container.
4. Start setup jobs and sensors, then run `analysis/verify-stack.py` — with
   `DASHBOARD_SERVICE_TOKEN` from the restored `honeypot-dashboard-backend`
   `.env` exported; it reads the backend's source-health directly (`docker
   exec` into `hp-apiary-backend`) and exits nonzero on any failure.

Never restore a volume archive into a running container. Captured malware must
remain encrypted at rest outside the analysis host and must not be unpacked on a
workstation.
