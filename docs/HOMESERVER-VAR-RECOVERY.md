# Homeserver `/var` recovery

[← back to README](../README.md)

Runbook for one specific failure: **the homeserver's `/var` is gone** (the
filesystem holding Docker data, `/var/dockge/stacks`, Arcane state and
`/var/lib/*` is destroyed or unreadable) while `/`, `/etc` and `/home`
survive. It is written from the real recovery of
[#3708](https://github.com/Xore-Inc/APIARY/issues/3708) (2026-10-18 to
2026-10-23) and generalized so it can be repeated. The incident record is at
the end.

Related pages, and when to use them instead:

| Situation | Page |
|---|---|
| Deliberate wipe of a working host | [`STACK-REBUILD.md`](STACK-REBUILD.md) |
| Whole host replaced or reinstalled | [`analysis/RECOVERY.md`](analysis/RECOVERY.md) and `scripts/install-homeserver.sh` |
| What the backup archive holds | [`BACKUP-ESSENTIALS.md`](BACKUP-ESSENTIALS.md) |
| Arcane sync/build/redeploy mechanics | [`ARCANE-GIT-SYNC.md`](ARCANE-GIT-SYNC.md) |
| Lost Swarm quorum only | [part 12](#12-swarm-quorum-recovery) below |

Everything here runs as root on the homeserver unless it says otherwise.
Commands that need a secret read it from a file or stdin. Never paste a
passphrase, token or API key into a command line, an issue or a log.

## What you need before you start

- The newest essentials archive (`apiary-essentials-<stamp>.tar.gz.gpg` plus
  its `.sha256`). Copies live on the backup host, the workstation USB and the
  server USB (`/mnt/usb-recovery/apiary-backups` on the homeserver). Also
  `/opt/backups/honeypot/<stamp>/` on the homeserver's root filesystem, which
  usually survives.
- The archive passphrase. It is stored on the backup host
  (`/etc/apiary-backup.pass`) and in the password manager.
- `/root/apiary-install/install-homeserver.conf` (or the `/home/<user>/install/`
  copy) from the root filesystem. The installer answers file is needed for
  the step functions in [part 8](#8-installer-steps-a-fresh-var-needs).
- An Arcane API key (kept on the backup host, `~/.config/apiary/arcane-api-key`,
  mode 0600). The restored Arcane database accepts the pre-incident key.
- A GitHub token with `read:packages` (and, for CI runners, repo admin on
  `Xore-Inc/APIARY`) available to the workstation you drive this from.
- A second machine to drive from. This runbook was executed over SSH from the
  backup host; every secret travels over SSH stdin.

Budget: #3708 ran from 2026-10-18 to 2026-10-23 for the full stack, the
workers and the verification, partly because the installer steps in part 8
were not yet written down. Arcane, Keycloak and ELK were back on day one.

## 1. Diagnose

Symptoms in #3708: after a planned restart, `/var` was an empty directory on
the root filesystem, its `fstab` line was commented out, and the partition
that had held it showed no filesystem signature.

1. Record what is mounted and what the disk looks like. Do not write to the
   device.
   ```bash
   findmnt /var; lsblk -f; blkid /dev/sdb1
   grep -n ' /var' /etc/fstab
   ```
2. Look for a surviving XFS superblock. The old `/var` was not at the start
   of the partition; it was 64 KiB in. Scan the first MiB for the `XFSB`
   magic at 4 KiB steps:
   ```bash
   for off in $(seq 0 4096 1048576); do
     [ "$(dd if=/dev/sdb1 bs=1 skip=$off count=4 2>/dev/null)" = XFSB ] && echo "XFSB at $off"
   done
   ```
3. Attach a **read-only** loop device at that offset and look at the
   filesystem without modifying it:
   ```bash
   LOOP=$(losetup -r -f --show -o 65536 /dev/sdb1)
   xfs_db -r -c 'sb 0' -c p "$LOOP" | head -40
   xfs_repair -n "$LOOP"
   ```
   `xfs_repair -n` is the no-modify check. **Never run `xfs_repair` without
   `-n` on the original device.** If you want to try a salvage mount, use a
   read-only loop with `mount -o ro,norecovery,nouuid "$LOOP" /mnt/probe`.
4. Optional, for the cause analysis: keep a copy of the first 1 GiB
   (`dd if=/dev/sdb1 of=<other-disk>/sdb1-head.img bs=1M count=1024`) before
   anything overwrites it.

**When to give up on salvage.** Stop and rebuild if any of these is true:

- the root inode block holds unrelated file data (the superblock's `rootino`
  points at garbage);
- `xfs_repair -n` reports `not enough secondary superblocks with matching
  geometry`, meaning another filesystem was laid over the old one;
- you cannot name a specific reason the data would still be there.

In #3708 both of the first two were true, so the filesystem was judged
unrecoverable. A salvage attempt on a damaged XFS costs
far more than restoring the essentials archive, and the archive holds
everything that cannot be recreated from the repository.

## 2. Re-create `/var`

Why this order: Docker, Arcane and the stack tree all live under `/var`, so
the new filesystem has to exist and carry the root filesystem's `/var`
content (with SELinux labels) before anything else starts.

1. Stop the services that write to `/var`.
   ```bash
   systemctl stop docker.socket docker containerd
   ```
2. Make the filesystem. The label and device below are the ones from #3708;
   confirm the device with `lsblk` first.
   ```bash
   mkfs.xfs -f -L var /dev/sdb1
   blkid /dev/sdb1          # note the new UUID
   mkdir -p /mnt/newvar && mount /dev/sdb1 /mnt/newvar
   ```
3. Copy the root-fs `/var` into it. `-A -X` keep ACLs and xattrs, which is
   where the SELinux contexts live. `-x` stays on the root filesystem.
   ```bash
   rsync -aHAXx --numeric-ids /var/ /mnt/newvar/
   ls -Zd /mnt/newvar/lib /mnt/newvar/lib/docker   # contexts must be present
   umount /mnt/newvar
   ```
4. Mount it at `/var` by **UUID**, never by `/dev/sdX`. Back up `fstab`
   first.
   ```bash
   cp -a /etc/fstab /etc/fstab.bak-$(date +%Y%m%d)-var
   # replace the commented or stale /var line with:
   # UUID=<new-uuid>  /var  xfs  defaults,noatime  0 0
   systemctl daemon-reload
   ```
5. Reboot. Check `findmnt /var` shows the new device, `systemctl is-active
   docker` is `active`, and `docker ps -a` and `docker volume ls` are empty.

Caveat: if `fstab` also has a bind mount whose source is under `/var` (the
`/var/tmproot` to `/tmp` line in #3708), leave it commented until you have
decided whether you want it. It was left as it was and is still an open
decision.

## 3. Restore from the essentials archive

The archive's contents and layout are in
[`BACKUP-ESSENTIALS.md`](BACKUP-ESSENTIALS.md); this part is the order that
worked.

1. Verify the archive, on the host that holds it:
   ```bash
   sha256sum -c apiary-essentials-<stamp>.tar.gz.gpg.sha256
   ```
2. Put the passphrase on the homeserver **through stdin**, into a root-only
   file. The passphrase must never appear on a command line.
   ```bash
   # from the backup host:
   sudo cat /etc/apiary-backup.pass \
     | ssh homeserver 'sudo sh -c "umask 077; cat > /root/.restore-pass"'
   ```
3. Decrypt and unpack into a root-only directory. Delete the passphrase file
   straight away.
   ```bash
   install -d -m 0700 /root/restore
   (umask 077
    gpg --batch --pinentry-mode loopback --passphrase-file /root/.restore-pass \
        -d /mnt/usb-recovery/apiary-backups/apiary-essentials-<stamp>.tar.gz.gpg \
      | tar xz -C /root/restore)
   shred -u /root/.restore-pass
   cat /root/restore/MANIFEST.txt
   ```
4. Read `MANIFEST.txt` and check what is **not** there. In #3708 the archive
   had no `homeserver/installer/` and no `homeserver/es-operator-state/`
   (stale installer on the backup host, then a transport bug, both tracked in
   [#3709](https://github.com/Xore-Inc/APIARY/issues/3709)). The installer
   answers file survived on `/` and `/home`. The dashboard operator state
   existed in no backup and was lost. If the manifest lacks
   `es-operator-state`, skip step 7 of the restore list in
   `BACKUP-ESSENTIALS.md` and record the loss.
5. The on-host copy `/opt/backups/honeypot/<stamp>/` is usually a few minutes
   newer than the USB archive. It carries `stack-config-state.tar.gz` (the
   `apiary` checkout plus `state/`). Prefer the archive for everything it
   holds. From `state/` you may take `personas` and `honeyfs`. **Do not**
   restore `state/init-markers`: the init jobs must re-run on the new data.

### 3.1 Re-clone the `apiary` checkout first

Every stack compose bind-mounts `/opt/stacks/apiary/...`, and
`/opt/stacks` is a symlink to `/var/dockge/stacks` that survives on `/`. The
archive does not hold the checkout, so recreate it the way the installer's
`step_clone_repo` does. The directory is not empty (it holds `logs/`), so
`git clone` will refuse; use init and fetch.

```bash
cd /var/dockge/stacks/apiary
git init -q
git remote add origin https://github.com/Xore-Inc/APIARY.git   # the org path; old Xore/ paths redirect
git fetch origin main
git checkout -f -B main FETCH_HEAD
git rev-parse HEAD        # note this SHA, you need it for GIT_SHA in part 7
```

### 3.2 `.env` files, secrets, volumes

1. **`.env` files.** `homeserver/env/<stack>.env` to
   `/var/dockge/stacks/<stack>/.env`, owner `root:deploy-runner`, mode
   `0600`. `homeserver/env/ghidra.env` goes to
   `apiary/analysis/ghidra/.env`, with the symlink
   `/var/dockge/stacks/ghidra -> apiary/analysis/ghidra` (the installer's
   `step_ghidra_stack_provision` layout). `honeypot-dashboard/.env` pins
   `DEPLOY_RUNNER_GID`; check it still equals `getent group deploy-runner`.
2. **Secrets: mode is not "0600 everywhere".** The consumers do not run as
   root:
   ```bash
   # Keycloak secrets: uid 1000 containers read them
   chown root:root /var/dockge/stacks/honeypot-keycloak/secrets/*
   chmod 0440 /var/dockge/stacks/honeypot-keycloak/secrets/*
   chmod 0750 /var/dockge/stacks/honeypot-keycloak/secrets
   # dashboard + apiary-dashboard OIDC client secret: dashboard-next runs as
   # `node` with group_add for the deploy-runner GID
   for s in honeypot-dashboard apiary-dashboard; do
     d=/var/dockge/stacks/$s/secrets
     chown github-deploy-runner:deploy-runner "$d"/oidc-client-secret
     chmod 0440 "$d"/oidc-client-secret
     chown root:deploy-runner "$d"; chmod 0750 "$d"
   done
   ```
   Mode `0600` here breaks Keycloak and every dashboard sign-in
   (`EACCES`, reported to the user as "identity provider did not answer").
3. **Technitium.** `homeserver/technitium/*` to
   `/var/dockge/stacks/technitium/config/`, then `chown -R 65532:65532`.
   Do not start it yet.
4. **Volumes.** Five named volumes, restored while nothing uses them. The
   archive file name is the real volume name:
   `dashboard-state`, `honeypot-arcane_arcane-data`,
   `honeypot-canarytokens_canarytokens-redis-data`,
   `honeypot-dashboard_es-importer-state`, `honeypot-elk_evebox-config`.
   ```bash
   for v in dashboard-state honeypot-arcane_arcane-data \
            honeypot-canarytokens_canarytokens-redis-data \
            honeypot-dashboard_es-importer-state honeypot-elk_evebox-config; do
     docker volume create "$v"
     docker run --rm --network none \
       -v "$v":/dst -v /root/restore/homeserver/volumes:/src:ro \
       busybox:1.36 tar -C /dst -xzf "/src/$v.tar.gz"
   done
   ```
   Compose later warns `already exists but was not created by Docker
   Compose` for these. That is harmless.
5. **WireGuard** is under `/etc`, which survived. Check `wg show` and leave it.
6. Keep `/root/restore` (0700) until the rebuild is verified, then delete it.

## 4. Arcane

Arcane is the control plane for every other stack, so it comes up first and
alone. The compose is rendered from the checkout, not synced.

```bash
sh /var/dockge/stacks/apiary/scripts/render-arcane-compose.sh \
   /var/dockge/stacks/apiary /var/dockge/stacks/honeypot-arcane/compose.yml auto
docker compose --project-directory /var/dockge/stacks/honeypot-arcane \
   -f /var/dockge/stacks/honeypot-arcane/compose.yml up -d --wait
```

Expect:

- The repo pins a newer Arcane than the one that wrote the backed-up
  database (v2.16.1 against v2.15.1 in #3708). The database migrates forward
  on first start without errors.
- Arcane logs `skipping project cleanup: this reconcile would delete most
  projects in a single pass`. That is its own guard against the empty
  `/var/dockge/stacks`. Good.
- All GitOps syncs and projects reappear with **unchanged IDs**, and every
  project except Arcane itself is `stopped`.

Check the API with the key piped from the backup host (header is
`X-API-Key`, not `Authorization`):

```bash
curl -fsS -H @/root/.arcane-hdr http://10.8.0.2:3552/api/environments/0/gitops-syncs?limit=100 | jq length
```

(`/root/.arcane-hdr` holds `X-API-Key: <key>`, mode 0600, written from stdin
and removed afterwards. List endpoints paginate at 20; pass `limit=100`.)

**Sync branch drift.** The manifest `arcane/manifests/home-production.json`
says every sync tracks `production`; the live syncs track `main`, and a few
track feature branches (swarm work). Do not "fix" this during a recovery.
Compare the restored syncs with what you had, and leave them. Background in
[`ARCANE-GIT-SYNC.md`](ARCANE-GIT-SYNC.md).

If a sync tracks an unmerged feature branch whose compose cannot start on
the current host (the Galah broker moved to Swarm in #3639 while Swarm was
`inactive` on the fresh `/var`), either leave that project stopped or point
the sync at `main` for the duration. Use a **partial** `PUT` to
`/api/environments/0/gitops-syncs/<id>` with `{"branch":"main"}`; a
full-object PUT is rejected with 422, and the partial one keeps every other
field. Put it back before you finish.

## 5. GHCR access

Org packages under `ghcr.io/xore-inc/*` are private. Two separate places need
credentials, because Arcane pulls through the Docker API and ignores root's
Docker login:

1. **Root's Docker** (for `docker pull` on the host, and `docker compose`
   run by hand). The token goes over stdin:
   ```bash
   gh auth token | ssh homeserver 'docker login ghcr.io -u <github-user> --password-stdin'
   ```
   The token needs `read:packages` only.
2. **Arcane's registry entry.** List `GET /api/container-registries`. The
   restored entry is scoped to one repository (`repositoryNames`). Update it
   with `PUT /api/container-registries/<id>`, `repositoryNames: []` (all
   `xore-inc/*`), the same URL and user, and the token. The PUT schema needs
   every field, including `token` and the `aws*` nulls. Build the body in a
   0600 temp file and shred it. Then `POST /api/container-registries/<id>/test`
   must answer "Authentication succeeded".
3. **Prove it with a private image.** Some org images are public, and a pull
   of one proves nothing. Pick one whose anonymous manifest fetch returns
   403 and pull it through Arcane
   (`POST /api/environments/0/images/pull {"imageName":...,"tag":...}`).
   Fresh layers and a digest mean the credential works.

For a release you pin by digest (apiary-dashboard), also run
`gh attestation verify oci://ghcr.io/xore-inc/apiary-dashboard:<tag> --owner Xore-Inc`.

## 6. Keycloak

1. **Login theme.** Not in the archive, and the compose bind-mounts it. Stage
   it as the installer's `step_stage_keycloak_theme` does:
   ```bash
   git clone --branch main https://github.com/Xore-Inc/auth-backend.git /var/dockge/stacks/auth-backend
   rsync -a --delete /var/dockge/stacks/auth-backend/themes/apiary/ \
         /var/dockge/stacks/honeypot-keycloak/theme/apiary/
   ```
   (Use the repo URL from `AUTH_THEME_REPO_URL` in your installer answers
   file if it differs.)
2. Sync the project: `POST /api/environments/0/gitops-syncs/<keycloak-sync>/sync`.
   The pre-placed `.env` and `secrets/` are kept; the sync does not refuse
   the existing directory.
3. Bring up Postgres alone and wait for healthy:
   ```bash
   D=/var/dockge/stacks/honeypot-keycloak
   docker compose --project-directory $D -f $D/compose.yml up -d --wait postgres
   ```
4. Load the dump. It is `--clean --if-exists`.
   ```bash
   gunzip -c /root/restore/homeserver/keycloak/keycloak.sql.gz \
     | docker exec -i hp-keycloak-postgres psql -q -U keycloak -d keycloak
   ```
   Expect rc 0 and no `ERROR` lines.
5. Start Keycloak: `docker compose ... up -d --wait keycloak`. It migrates the
   realm forward ("migrated realm apiary to ...", "Realm 'apiary' already
   exists. Import skipped").
6. Verify clients keep their identity. For each client ID, request
   `https://auth.<domain>/realms/apiary/protocol/openid-connect/auth?client_id=<id>&response_type=code&redirect_uri=https://invalid.example/cb`.
   A 400/403 means the client is known; "client not found" means it is not.
   Include a made-up ID as the control, which must say "client not found".
   In #3708 all 17 clients were recognised.

Do not rely on the bootstrap admin: in #3708 it no longer existed in the
`master` realm (the real users were different accounts), so the Keycloak
admin API was unusable. That matters for
the poller secret in [part 9](#9-workers-models-units).

## 7. Elasticsearch, init, then everything else

### 7.1 honeypot-elk

1. Build the Zeek image first. `zeek-proxy` is `pull_policy: never`, nothing
   in the elk compose builds it, and a missing tag fails the whole project:
   ```bash
   cd /var/dockge/stacks/apiary
   docker build -f vps/zeek/Containerfile -t xore-zeek:local vps/zeek
   ```
2. The sshfs log mounts from the VPS come from `fstab` (check
   `findmnt -t fuse.sshfs`; they are read-only from this side by design).
3. Sync `honeypot-elk`, then redeploy it
   (`POST /api/environments/0/projects/<id>/redeploy`, streamed with
   `curl -N -m 3600`; the stream must run to completion, a truncated stream
   aborts the operation server-side).
4. **Expect the redeploy to "fail".** The final frame is
   `failed to deploy project: container hp-pcap-sync is unhealthy`.
   `pcap-sync` waits for `log-init.done`, which honeypot-init writes later.
   This is a cold-start artefact, not an Elasticsearch problem. Judge by
   `docker ps` (ES, Kibana, Filebeat, EveBox healthy) and
   `_cluster/health` green.
5. `honeynet` and `honeypot-llm-data` are created by the elk compose.

### 7.2 Shared resources the compose files assume

Do these before honeypot-init. They are the installer's
`step_create_shared_resources`, and on a fresh `/var` nothing else creates
them:

```bash
docker network create honeypot-llm --internal
docker volume create dionaea-lib
docker volume create yara-results
install -d -m 777 /var/dockge/stacks/apiary/state/init-markers
install -d -m 755 -o 2000 -g 2000 \
  /var/dockge/stacks/apiary/state/honeyfs/cowrie \
  /var/dockge/stacks/apiary/state/honeyfs/cowrie-share
```

Without `init-markers` at 0777 every one-shot does its work and then dies on
`touch /markers/<job>.done: Permission denied`.

### 7.3 honeypot-init

Sync, then redeploy. Two false failures are normal:

- `failed to deploy project: container hp-log-init exited (0)` is the known
  Arcane behaviour with one-shots (#2714).
  `scripts/arcane-deploy-honeypot-init.sh` exists for it.
- `elasticsearch-setup` can exit 22 (a curl 500) once. Re-run the redeploy;
  in #3708 the second failure was the missing `init-markers` permission, the
  first never recurred.

Success is: the six one-shots `Exited (0)` (persona-apply, log-init,
elasticsearch-setup, arkime-init, snare-clone, honeypot-kibana-setup), the
markers present, and ES green with no unassigned shards.

### 7.4 GeoIP and threat-intel (compose profiles)

`geoipupdate` and `threat-cidrs-refresh` are services of honeypot-init behind
the `geoip-update` and `threat-intel` profiles. **Arcane's redeploy never
starts a profile**, so a recovered host silently has no GeoIP/AS data (and no
threat CIDRs). Start them by hand, as `step_start_init` does:

```bash
cd /var/dockge/stacks/honeypot-init
docker compose -f compose.yml --profile geoip-update --profile threat-intel \
  up -d geoipupdate threat-cidrs-refresh
```

`geoip-update` needs `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` in that
stack's `.env` (restored). When the `.mmdb` files have appeared, test the
pipeline; if it still answers `_geoip_database_unavailable`, restart the
Elasticsearch container so the processors re-read their databases
(`step_geoip_reload_elasticsearch`):

```bash
docker run --rm --network honeynet curlimages/curl:latest -sS -X POST \
  http://elasticsearch:9200/_ingest/pipeline/geoip-honeypot/_simulate \
  -H 'Content-Type: application/json' \
  -d '{"docs":[{"_source":{"honeypot":{"src_ip":"8.8.8.8"}}}]}'
docker restart hp-elasticsearch     # only if the simulate says unavailable
```

Good looks like an AS number and country for 8.8.8.8.

### 7.5 Technitium (secondary DNS)

As the installer's `step_technitium_provision`: copy the stack compose into
place, check the LAN route, start it.

```bash
install -m 0644 /var/dockge/stacks/apiary/technitium/compose.yml \
  /var/dockge/stacks/technitium/compose.yml
docker compose --project-directory /var/dockge/stacks/technitium \
  -f /var/dockge/stacks/technitium/compose.yml up -d --wait
```

Compare each zone's SOA serial with the primary
(`dig @<secondary> <zone> SOA` against `dig @<primary> <zone> SOA`). In
#3708 one reverse zone had a higher serial on the secondary than on the
primary; the secondary will not pull from the primary until the primary
passes it. That needs a serial bump on the primary, which this runbook does
not do.

### 7.6 The remaining stacks

For the sensor and utility stacks the order does not matter. Per stack, one
at a time:

1. `POST /api/environments/0/gitops-syncs/<sync-id>/sync`
2. `POST /api/environments/0/projects/<project-id>/build`
3. `POST /api/environments/0/projects/<project-id>/redeploy`

Run builds and redeploys sequentially with `curl -N -m 3600`; a frame
`{"done":true}` with no `"error"` frame is success. Do **not** use IDs from
old notes: projects can be re-created, so look them up by name
(`GET .../gitops-syncs?limit=100`) and re-read them from the restored
Arcane.

Two stacks need care:

- **Do not start what was not running before.** The pre-incident list is in
  the archive at `homeserver/manifest/homeserver.txt` (`## running
  containers`). In #3708 the following were deliberately left off:
  llm-worker, the four legacy `*-worker` stacks (replaced by the
  `hp-apiary-worker*` set, #1628), unsloth, ghosts, revdeck.
- **honeypot-galah** follows its sync branch (see part 4).

### 7.7 Backend and dashboard

`GIT_SHA` is a compose **build argument** and is not in the archived `.env`
files. Unset, the shipped image reports revision `unknown`. Add it to **both**
stack `.env` files, surgically, with a backup beside each:

```bash
SHA=$(git -C /var/dockge/stacks/apiary rev-parse HEAD)
for s in honeypot-dashboard honeypot-dashboard-backend; do
  f=/var/dockge/stacks/$s/.env
  cp -a "$f" "$f.bak-$(date +%Y%m%d)"
  grep -q '^GIT_SHA=' "$f" && sed -i "s/^GIT_SHA=.*/GIT_SHA=$SHA/" "$f" \
    || printf 'GIT_SHA=%s\n' "$SHA" >> "$f"
done
```

Then the order, which matters because only `honeypot-dashboard-backend`
builds `apiary-backend:latest`, and the workers that consume it
(`pull_policy: never`) pick it up only when `honeypot-dashboard` is
redeployed:

1. sync `honeypot-dashboard` (its compose carries the Rust source the backend
   build reads; syncing `-backend` alone leaves the source stale and
   silently re-exports the old image);
2. sync `honeypot-dashboard-backend`;
3. build, then redeploy, `honeypot-dashboard-backend`;
4. build, then redeploy, `honeypot-dashboard`.

Verify the image, not the stream:

```bash
docker image inspect apiary-backend:latest \
  --format '{{.Created}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
docker ps --format '{{.Names}} {{.Status}}' | grep -E 'hp-apiary|hp-dashboard'
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://10.8.0.2:19090/   # 307 to /auth/login
```

**apiary-dashboard** (the separate, versioned image): in its stack `.env`
change only `APIARY_DASHBOARD_VERSION` and `APIARY_DASHBOARD_DIGEST`
(backup first, `diff` must show those two lines), sync, redeploy. Needs the
registry access from part 5. Check `curl http://10.8.0.2:19092/` answers 307
to `/auth/login`.

## 8. Installer steps a fresh `/var` needs

`scripts/install-homeserver.sh` is a single run-everything script; it has no
"run one step" mode. The rest of this runbook paraphrases the steps that a
manual rebuild must reproduce. Missing any of them produced a failure in
#3708 that looked healthy. Read the function in the script before applying
it; the script is the source of truth and this table is the index.

| Installer step | What it provides | Symptom if skipped |
|---|---|---|
| `step_clone_repo` | `apiary` checkout at `/var/dockge/stacks/apiary` | every bind mount fails (part 3.1) |
| `step_restore_env_files` | `.env` files, owner and mode | stacks start with defaults or not at all |
| `step_stage_keycloak_theme` | Keycloak login theme | default theme, or the bind mount fails (part 6) |
| `step_provision_keycloak_secrets` | secret modes `0440`, dir `0750` | Keycloak or Postgres cannot read its secrets (part 3.2) |
| `step_create_shared_resources` | `honeypot-llm` network, `dionaea-lib`, `yara-results`, `state/init-markers` 0777, cowrie honeyfs 2000:2000 | one-shots fail on `touch`, cowrie crash-loops (part 7.2) |
| `step_build_zeek_image` | `xore-zeek:local` | elk redeploy fails on an unpullable tag (part 7.1) |
| `step_start_init` | starts the `geoip-update` and `threat-intel` profiles | no GeoIP/AS data, no threat CIDRs (part 7.4) |
| `step_geoip_reload_elasticsearch` | ES re-reads GeoIP databases | pipeline says `_geoip_database_unavailable` |
| `step_fix_snare_ownership` | `logs/snare` owned by root | snare crash-loops (see [`STACK-REBUILD.md`](STACK-REBUILD.md)) |
| `step_pin_deploy_runner_gid` | `logs/enriched` and `state/ip-enrichment-worker` at `2775 root:<deploy-runner GID>`, `DEPLOY_RUNNER_GID` pinned, services recreated | enrichment writes nothing while reporting healthy (see below) |
| `step_fix_apiary_backend_permissions` | ACLs for uid 65534 on `dashboard-state`, `dionaea-lib`, `services-adapter-socket` | the backend cannot read its own state |
| `step_provision_image_sbom` | `/var/image-sbom` `2775`, group-writable by every CI runner user | SBOM step degrades to a CI artifact |
| `step_provision_events_poller_secrets` | the auth-events poller client secret | `auth-events-worker` cannot start (part 9) |
| `step_ghidra_stack_provision`, `step_ghidra_worker_install` | ghidra layout, `/opt/honeypot-ghidra`, systemd units | analysis host units fail with `NAMESPACE` errors (part 9) |

**The enrichment directories deserve their own warning.** Docker creates
`logs/enriched` and `state/ip-enrichment-worker` as `root:root 0755` at mount
time. The enrichment worker runs as `nobody`, logs one `open output failed`
warning per source at start, and stays `(healthy)`. In #3708 this indexed
nothing for five days
([#3719](https://github.com/Xore-Inc/APIARY/issues/3719)). Fix:

```bash
GID=$(getent group deploy-runner | cut -d: -f3)
install -d -m 2775 -o root -g "$GID" \
  /var/dockge/stacks/apiary/logs/enriched \
  /var/dockge/stacks/apiary/state/ip-enrichment-worker
docker restart hp-apiary-worker-enrichment
```

`logs/enriched/*.json` fill within a minute.

Backend permissions, the install-time way:

```bash
for v in dashboard-state dionaea-lib; do
  mp=$(docker volume inspect "$v" --format '{{.Mountpoint}}')
  setfacl -R -m u:65534:rwX "$mp"; setfacl -m mask::rwx "$mp"
  setfacl -m d:u:65534:rwx "$mp"; setfacl -m d:mask::rwx "$mp"
done
```

`dionaea-lib` needs only read (`rX`) for uid 65534; read the function for the
exact modes and for `services-adapter-socket` (default ACL on the directory
plus a direct grant on `control.sock`). Use `step_fix_apiary_backend_permissions`
as the reference.

`/var/image-sbom`:

```bash
install -d -m 2775 -o github-ci-runner -g github-ci-runner /var/image-sbom
setfacl -d -m g:github-ci-runner:rwx /var/image-sbom
# add every github-ci-runner-N user to the github-ci-runner group, then prove
# each can write:
runuser -u <runner-user> -- test -w /var/image-sbom
```

## 9. Workers, models, units

1. **Analysis host (ghidra, Ollama, statictools).**
   ```bash
   cd /var/dockge/stacks/apiary/analysis/ghidra
   ./install-analysis-host.sh --stack-dir "" --skip-pull
   ```
   On a cold start this installs the units and exits 1 on its self-test
   (`TypeError` in `triage_state()` when Ollama serves no models),
   [#3717](https://github.com/Xore-Inc/APIARY/issues/3717). Pull the models
   first, then re-run the self-test. Pull only the models the production
   config names (read `approved-models.json` and the stack `.env`); #3708
   needed `qwen3:14b`, `nomic-embed-text` and `qwen2.5:7b-instruct-q4_K_M`.
   Compare the digest with `LLM_EXPECTED_MODEL_DIGEST`.
2. **`honeypot-gpu-queue-drain` fails every tick** until the
   `gpu-job-queue` index exists (#3717). Create it once from
   `/opt/honeypot-ghidra/worker`:
   ```python
   import gpu_queue; gpu_queue.ensure_index("http://elasticsearch:9200")
   ```
3. **auth-events-worker: the poller client secret is not in the archive.**
   It needs `/var/dockge/stacks/auth-events-worker-secrets/client-secret`,
   owned `root:10101`, mode `0440`, directory `0750` (the worker runs as
   uid/gid 10101). If the Keycloak bootstrap admin is gone, read the existing
   secret from the Keycloak database and write it straight into the file,
   never printing it:
   ```bash
   d=/var/dockge/stacks/auth-events-worker-secrets
   install -d -m 0750 -o root -g 10101 "$d"
   (umask 077; docker exec hp-keycloak-postgres psql -U keycloak -d keycloak -At \
     -c "select secret from client where client_id='auth-events-poller'" \
     > "$d/client-secret")
   chown root:10101 "$d/client-secret"; chmod 0440 "$d/client-secret"
   ```
   No credential is rotated this way. Then sync, build and redeploy
   `auth-events-worker`; it creates its two indices on first run.
4. **ml-worker**: sync, build, redeploy. It has no healthcheck by design;
   look for "Worker ready" in its log.
5. **`gssproxy`** can fail with `STATE_DIRECTORY ... Permission denied` on the
   fresh `/var`:
   ```bash
   install -d -m 0700 /var/lib/gssproxy/clients /var/lib/gssproxy/rcache
   restorecon -Rv /var/lib/gssproxy; systemctl start gssproxy
   ```
6. **Units that need a conscious decision** rather than a blind start:
   `hp-unsloth-studio` (no stack dir, was not running before),
   `honeypot-llm-injection-suite@weekly` (needs
   `APIARY_REPO_DIR=/var/dockge/stacks/apiary` in `/etc/default/honeypot-ghidra`,
   which the installer never overwrites; it also runs llm-worker's compose),
   `ghosts-network-filter` (iptables chain missing; ghosts was not running).
   Check `systemctl --failed` and write down each one you leave failed.

## 10. CI and deploy runners

A lost `/var` takes the runners with it (their homes are under
`/var/lib/github-runners`). The registrations on GitHub survive, showing as
offline, and after the org move they live under `Xore-Inc/APIARY`. Re-register
under the **old names and labels**.

Inventory (homeserver): `supermicro`, `supermicro-ci-2`, `supermicro-ci-3`,
`supermicro-ci-4` (labels `honeypot-ci,honeypot-homeserver,dependency-submission`)
and `supermicro-home` (label `honeypot-home`, the deploy runner).

1. Get a registration token on the workstation and pipe it over SSH into a
   root script that exports it only as `ACTIONS_RUNNER_INPUT_TOKEN`. The
   runner's `config.sh` reads that variable, so the token never reaches argv:
   ```bash
   gh api -X POST repos/Xore-Inc/APIARY/actions/runners/registration-token --jq .token \
     | ssh homeserver 'sudo bash /root/register-runners.sh'   # reads the token from stdin
   ```
   `register-runners.sh` is a throwaway root script you write for the
   occasion (it is not kept in the repo): it reads stdin into the variable,
   loops over the inventory, and runs step 2 for each instance.
2. For each instance, as root: create the home under
   `/var/lib/github-runners/<name>`, extract the `actions-runner` tarball
   (verify its published sha256), and run as the runner's own user:
   ```bash
   sudo --preserve-env=ACTIONS_RUNNER_INPUT_TOKEN -u <runner-user> ./config.sh \
     --url https://github.com/Xore-Inc/APIARY --name <name> \
     --labels <old labels> --work _work --unattended --replace
   ```
   `--replace` takes over the offline registration.
3. Let the repo installers do the rest. They skip registration once `.runner`
   exists:
   ```bash
   scripts/github-ci-runner/install-ci-runner.sh --repo Xore-Inc/APIARY --name supermicro
   scripts/github-ci-runner/install-ci-runner.sh --repo Xore-Inc/APIARY --instance 2   # and 3, 4
   scripts/github-ci-runner/install-deploy-runner.sh --repo Xore-Inc/APIARY
   ```
   The installer's default name for instance 1 is `supermicro-ci`, but the
   live name is `supermicro`, so pass `--name supermicro`. The
   `dependency-submission` label is not added by the installer; pass it to
   `config.sh`. `install-deploy-runner.sh` chowns `/opt/stacks/apiary`
   (minus `state` and `logs`) to `github-deploy-runner:deploy-runner` by
   design.
4. The new units are `actions.runner.Xore-Inc-APIARY.<name>.service`.
   Disable and `reset-failed` any leftover `actions.runner.Xore-APIARY.*`
   units. Confirm all five are `online` in the GitHub API
   (`gh api repos/Xore-Inc/APIARY/actions/runners`).

## 11. Backup timer

The backup host, not the homeserver, runs the timer. After any recovery,
refresh its installed copy from the current checkout, otherwise it keeps
running an old script (that is how the 2026-10-17 archive lacked the
operator-state export):

```bash
sudo REPO_DIR=<checkout on main> RUN_AS=<user> scripts/install-backup-essentials.sh
systemctl list-timers apiary-backup-essentials.timer
sudo systemctl start apiary-backup-essentials.service   # one manual run
```

Check `/etc/default/apiary-backup-essentials` `REPO_DIR` points at a
checkout on `main`, not a feature branch, or the staleness check compares the
wrong tree. Read the run's journal for `installer: N answers file(s)` and an
`es-operator-state` line. At the time of writing the operator-state export
still fails on a transport bug (curl writes to an unmounted temp path),
tracked in [#3709](https://github.com/Xore-Inc/APIARY/issues/3709); the run
fails loudly on it, which is intended.

## 12. Swarm quorum recovery

Docker Swarm manager state lives in `/var/lib/docker/swarm`, so losing `/var`
removes the homeserver as a manager. With two managers that is a lost quorum:
the surviving manager reports `The swarm does not have a leader`, and nothing
can be listed, scheduled or changed. Running tasks keep running. The fix works
from any surviving manager that still has its raft state. (Since 2026-10-19
the topology is three managers: precision, the VPS and the homeserver; see
[#3589](https://github.com/Xore-Inc/APIARY/issues/3589).)

**Do this from the surviving manager, with its plane address.** Use
`10.8.0.x` addresses on the WireGuard plane, never a LAN or public address.

1. **Check it is safe.** On the survivor:
   ```bash
   docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}} {{.Swarm.Error}}'
   ls -l /var/lib/docker/swarm/raft/wal-v3-encrypted/ /var/lib/docker/swarm/certificates
   ```
   You want state `active`, `ControlAvailable true`, the WAL present with a
   current mtime. Note whether autolock is on; if it is, have the unlock key.
2. **Back it up** before touching it. Live is fine:
   ```bash
   tar czf /root/swarm-backup-$(date +%Y%m%dT%H%M%S).tgz -C /var/lib/docker swarm
   chmod 0600 /root/swarm-backup-*.tgz; sha256sum /root/swarm-backup-*.tgz
   ```
   The node key inside carries the raft data key. Treat it as a secret.
3. **Force a one-node cluster**, keeping services, configs, secrets and
   labels. The command prints a join token; discard stdout.
   ```bash
   docker swarm init --force-new-cluster \
     --advertise-addr <plane-ip> --listen-addr <plane-ip>:2377 --data-path-addr <plane-ip> \
     >/dev/null
   docker node ls; docker service ls
   ```
   Other nodes reconnect on their own within about 20 seconds. The new
   leader reconciles stale tasks: expect replacement tasks (old ones
   `Failed "No such container"`). No service spec changes.
4. **Remove the dead node entry**:
   ```bash
   docker node rm --force <dead-node-id>
   ```
5. **Prepare the rejoining host's firewall** before it joins. It must accept
   2377/tcp, 7946/tcp+udp, 4789/udp and ESP from the peers, on the plane
   interfaces only. Use the repo script, not hand edits, **with the
   caveats below**.
6. **Rejoin the rebuilt homeserver** as a manager. The token travels only on
   the pipe:
   ```bash
   ssh <survivor> docker swarm join-token -q manager \
     | ssh homeserver 'docker swarm join --token "$(cat)" \
         --advertise-addr 10.8.0.2 --listen-addr 10.8.0.2:2377 \
         --data-path-addr 10.8.0.2 <survivor-plane-ip>:2377'
   ```
   `/var/lib/docker/swarm` on the homeserver must be empty (a fresh `/var`
   guarantees it). `live-restore=false` is fine; joining does not restart
   dockerd.
7. **Pause it at once and re-apply labels** (#3583): the host must not
   receive tasks until its stacks are rebuilt.
   ```bash
   docker node update --availability pause <new-node-id>
   docker node update --label-add role=manager --label-add edge=false \
     --label-add sensor=true --label-add gpu=true --label-add storage=true <new-node-id>
   ```
   Labels live in the raft store and are **not** restored by anything else.
   The other two managers' labels survive in raft.
8. **Repair container DNS** (#3621). Joining a node can break Docker's embedded
   DNS on existing Compose bridge networks.
   ```bash
   ops/swarm/container-dns.sh check      # before joining: record the baseline
   ops/swarm/container-dns.sh rejoin     # after joining
   ops/swarm/container-dns.sh check      # all names must resolve again
   ```
   Also snapshot `docker ps` IDs and start times before and after: in #3708
   74 of 74 compose containers were untouched.
9. Confirm from all managers: `docker node ls` (one Leader, the others
   Reachable), services at their previous replica counts, `docker network ls`
   shows the overlays.

### Firewall caveats (`swarm-plane.sh`)

Details in [#3712](https://github.com/Xore-Inc/APIARY/issues/3712).

- `swarm-plane.sh apply` treats **every** rule in the `apiary-swarm` zone as
  its own and removes rules it does not know. On the homeserver it deleted
  `rule family=ipv4 source 10.8.0.0/24 port 3552/tcp accept` (Arcane over the
  hub). Re-add it, runtime and permanent, and confirm Arcane answers
  (`curl http://10.8.0.2:3552/api/health` from the VPS and precision).
- Always bracket a firewall change with the dead-man timer: `swarm-plane.sh
  backup hosts/<host>.env`, then `arm <backup-dir> 10min`, then `apply`, then
  prove access both ways, then `disarm`. The scripts are
  `ops/firewall/swarm-plane.sh` and `ops/firewall/swarm-plane-rollback.sh`.
- The recovered host's `/var/lib/apiary-firewall` backups are gone with
  `/var`, and the live `public` zone may have drifted back to old LAN accepts
  for the swarm ports. Re-run `swarm-plane.sh apply` on **every** host after
  the incident, and read the semantic diff against the backup.
- `ops/firewall/hosts/vps.env` still says `SWARM_MANAGER=0` in the repo while
  the live VPS is a manager (2377 from the two peers). A re-apply from the
  repo would drop 2377 and break the VPS's raft membership. Do not apply it
  there until #3712 lands.
- `ops/swarm/swarm-membership.sh`, `ops/swarm/README.md` and
  `docs/SWARM-NETWORK.md` still say "never promote the VPS" and describe two
  managers; the 2026-10-19 decision supersedes that. The VPS `docker info`
  showing `Swarm: error` after promotion is cosmetic and clears on the next
  dockerd restart there (which restarts every VPS container, so not done
  casually). Arcane's `vps` environment reports "Swarm mode is not enabled"
  until then.
- The trade-off of a manager on the edge host (raft store, secrets and cluster
  CA on the internet-facing machine) is recorded on #3589. Autolock is off.

## 13. Verification

1. **Containers.** `docker ps` shows the expected set, none `(unhealthy)`,
   none restarting, none stuck in `created`. The only `Exited` ones are the
   honeypot-init one-shots with status 0. Compare to the pre-incident list.
2. **End-to-end gate.**
   ```bash
   DASHBOARD_SERVICE_TOKEN=<from the honeypot-dashboard .env> \
     python3 /var/dockge/stacks/apiary/analysis/verify-stack.py
   ```
   Exit 0 with `failures: []` means Elasticsearch is green, ingest and
   Filebeat are healthy, YARA has no errors, and every required sensor is
   ACTIVE. A "dashboard sensor has never logged: <list>" failure on a fresh
   cluster is how #3719 was found. Read the token from the `.env` inside a
   root shell; do not print it.
3. **Fresh documents in `honeypot-v2`, after the deploy.** Count documents
   indexed in the last 15 minutes, and per sensor through the source-health
   view that `verify-stack.py` reads. Documents that predate the deploy prove
   nothing. Sensor fields are nested under `honeypot.*` (for example
   `honeypot.src_ip`); confirm the real field path in a sample document
   before trusting an aggregation, because a wrong path can make a query look
   right when it is not:
   ```bash
   docker run --rm --network honeynet curlimages/curl:latest -s \
     'http://elasticsearch:9200/honeypot-v2-*/_count' \
     -H 'Content-Type: application/json' \
     -d '{"query":{"range":{"@timestamp":{"gte":"now-15m"}}}}'
   ```
   Cowrie, dionaea, multipot, http-honeypot and the conpot personas must all
   be logging (they are the enriched sensors, #3719). If only the unenriched
   sensors (api-honeypot, endlessh, dicompot, dnp3 in #3708) produce
   documents, the enrichment directories are wrong.
4. **GeoIP.** The `_simulate` call from part 7.4 resolves an AS and country.
   An investigate-IP query through the dashboard returns `as_organization`.
5. **Public path.** `curl -L https://<dashboard-domain>/` goes 307 to
   `/auth/login` and then to the Keycloak authorization endpoint with the
   `apiary-dashboard` client and PKCE (`S256`).
6. **Swarm.** `docker node ls` from each manager; service replicas as before;
   Arcane `/environments/<id>/swarm/info` online for each environment.
7. **Backups.** One manual `apiary-backup-essentials.service` run and an
   archive that lists `installer/` and `es-operator-state/`.
8. **Then clean up.** Remove `/root/restore`, the `.env.bak-*` files you
   created once they are no longer needed, and any temp header files.
   Record what you left failed and why.

## What this runbook cannot recover

- **Elasticsearch event history.** The essentials archive deliberately holds
  no ES data. Accepted loss in #3708.
- **Dashboard operator state** (config, users, alert acknowledgements,
  canarytokens, the IP block list, workbench recipes) when the archive has no
  `es-operator-state/`. That was the case in #3708.
- **Enriched sensor events** between the rebuild and the enrichment fix
  (about five days in #3708). The raw sensor logs remain on disk; no backfill
  procedure exists.
- Container images, Ollama models and build caches. All rebuilt or re-pulled.
- Anything that was only in `/var` and never in the archive or the on-host
  copy.

---

## Incident record: #3708

Factual record. Times are CEST unless marked UTC.

**Cause, as far as known.** After a planned homeserver restart on
2026-10-18 (benchmark stopped first, #3706), `/var` was missing. Its `fstab`
line was commented out and the partition (`sdb1`, 8.7 TB on a MegaRAID
volume, XFS label `var`, old UUID `1a6a3c88-...`) had no filesystem
signature. A read-only probe found the old superblock 64 KiB into the
partition, but the root inode block held unrelated file data, and
`xfs_repair -n` could not verify any secondary superblock. Another
filesystem had been laid over the old one. Who or what did that, and when,
was not established. The `fstab` line was found already commented out.

**Timeline.**

| When | What |
|---|---|
| 2026-10-17 22:12 UTC | Last essentials archive written (sha256 verified later). On-host copy two minutes later. |
| 2026-10-18 | Planned restart; `/var` found gone. Issue #3708 opened 17:53 UTC. |
| 2026-10-18 | Disk judged unrecoverable; new XFS created, root-fs `/var` copied in, `fstab` fixed by UUID, reboot. Docker active and empty. |
| 2026-10-18 | Leg 1: archive decrypted, `.env` files, secrets, five volumes and Technitium config restored, checkout re-cloned. Arcane up with all 42 syncs and 43 projects. Keycloak restored (17 clients). honeypot-elk and honeypot-init up. |
| 2026-10-18 20:27 to 20:44 | Leg 2: 22 sensor and utility stacks synced, built, redeployed. |
| 2026-10-18 20:38 | `apiary-backend:latest` built at main `2ddc7dbf`; backend and dashboard redeployed. |
| 2026-10-19 early (00:43) | apiary-dashboard v0.1.6 live. |
| 2026-10-19 00:48 | Swarm: precision backed up, quorum restored with `--force-new-cluster`, dead node removed. |
| 2026-10-19 about 01:00 | VPS promoted to manager on the WireGuard plane, public interface verified closed. |
| 2026-10-23 | Workers, ghidra/Ollama, runners and backup timer done. Homeserver rebooted at 17:08 (not part of the work; all came back). |
| 2026-10-23 (ending 19:10) | `verify-stack.py` first run rc 1; enrichment dirs and GeoIP fixed; second run rc 0. |
| 2026-10-23 about 18:55 | Swarm phase B: homeserver rejoined as the third manager. |

**What was lost.**

- All Elasticsearch event history. Xore accepted this loss.
- Dashboard operator state: no backup held it (#3709).
- Enriched sensor indexing from 2026-10-18 20:39 to 2026-10-23 19:10: the
  enrichment worker could not write its output and reported healthy (#3719).
  The raw logs exist; the events were not backfilled.
- Docker images, volumes other than the five archived ones, Ollama models,
  `/var/lib/benchmark-runs` and logs on `/var`, the CI runner installs and
  the `/var/lib/apiary-firewall` backups.
- The homeserver's Swarm manager state, which cost the cluster its quorum
  until 2026-10-19.

**What survived.** `/`, `/etc` (WireGuard, `/etc/apiary`, Docker config),
`/home`, `/opt/backups`, the USB backup drive, the installer answers file, and
every Arcane project ID.

**Follow-up issues.**

| Issue | Subject |
|---|---|
| [#3709](https://github.com/Xore-Inc/APIARY/issues/3709) | backup-essentials omitted the installer conf and operator state; stale libexec copy; the operator-state export transport bug (still open) |
| [#3712](https://github.com/Xore-Inc/APIARY/issues/3712) | capture the three-manager topology in IaC and docs; `swarm-plane.sh` removes rules it does not own; quorum-recovery runbook |
| [#3717](https://github.com/Xore-Inc/APIARY/issues/3717) | ghidra analysis-host self-test and gpu-queue-drain fail on a cold start |
| [#3719](https://github.com/Xore-Inc/APIARY/issues/3719) | enrichment worker healthy while unable to write output |
| [#3587](https://github.com/Xore-Inc/APIARY/issues/3587), [#3589](https://github.com/Xore-Inc/APIARY/issues/3589) | Swarm epic and topology decision (VPS as third manager) |

Also not yet ticketed at the time of writing: the reverse-zone serial that is
ahead on the secondary Technitium; the three units left failed on purpose
(`hp-unsloth-studio`, `honeypot-llm-injection-suite@weekly`,
`ghosts-network-filter`); and the open decision on the
`/var/tmproot` bind line in `fstab`.
