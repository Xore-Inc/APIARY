# Arcane Git sync

How the 39 home-hosted stacks (33 that live under `arcane/home/` plus 6
that were already self-contained and stayed at their existing path) get to
the live host, replacing the old model of copying or symlinking top-level
`docker-compose.*.yml` files into place. Everything here was confirmed live
against the pinned Arcane `v2.8.0` API during #1502's own migration, not
taken from Arcane's docs — see the risk that motivated that in "Version/API
compatibility" below. Census numbers and the live sync-store state were
re-verified 2026-08-27 against the pinned `v2.9.0` image and its own sqlite
store (#2549): 31 in-tree directories + 6 self-contained = 37, exactly the
manifest's entry count *at that date*. The manifest has since grown to 39 —
#2911 swapped the `pihole` entry for `technitium` and #3092 added `unsloth`
directly under `arcane/home/` — re-counted 2026-09-27 from
`arcane/manifests/home-production.json`: 33 in-tree + 6 self-contained = 39.

## The model

Each stack gets its own **directory-aware Git sync**: Arcane clones the
`apiary` repository, materializes the *entire directory* containing the
selected `compose.yml` (not just that one file) under
`/var/dockge/stacks/<syncName>/`, and deploys it. The manifest at
[`arcane/manifests/home-production.json`](../arcane/manifests/home-production.json)
is the single source of truth for which 39 stacks exist, what branch/path
each syncs from, and any per-stack sync limits — `scripts/install-homeserver.sh`,
CI, and this doc all read from it rather than maintaining separate lists.

- The 32 `honeypot-*` stacks live under `arcane/home/<name>/`: their build
  context and git-tracked config were moved there from repository root
  (see each compose file's own `#1502` comment for what moved and why).
  `unsloth` is the 33rd directory there — #3092 added it in-tree rather
  than at a root path, so it never went through the #1502 move.
- The 6 other stacks (`auth-events-worker`, `llm-worker`, `ml-worker`,
  `analysis/ghidra`, `sandbox/ghosts`, `technitium`) were already
  self-contained and stayed at their existing path — moving them would
  have broken real references from `scripts/install-homeserver.sh`, CI
  workflows, and `deploy.yml`'s own ghidra-worker resync step. See each
  one's own compose file header for the specifics.
- `honeypot-arcane` itself is **not** in the manifest and never will be —
  syncing the thing that has to already be running before any sync can
  happen is a bootstrap loop, not a simplification. It stays
  installer/`deploy.yml`-managed. Both render its `compose.yml` through
  `scripts/render-arcane-compose.sh` (#3340): the base
  `docker-compose.arcane.yml`, plus `docker-compose.arcane.gpu.yml` only when
  a real GPU container runs on the host (#2950). Never `cp` the base file over
  the live one by hand: on the GPU homeserver that silently drops Arcane's GPU
  monitoring. `deploy.yml` replaces the file only when the render differs,
  keeps the previous one as `compose.yml.bak-<timestamp>`, and runs as
  docker-group root inside `docker:cli`, because the stack dir, file and
  `.env` are root-owned.

## Repository authentication

`Xore/APIARY` is public, so the registered repository
(`POST /customize/git-repositories`) uses `authType: "none"` — plain HTTPS
clone, no deploy key or token. If this repository is ever made private,
switch to a read-only deploy key or narrowly scoped token and set
`sshHostKeyVerification` to strict (not `accept_new`) once the host key has
been provisioned once.

## Manifest import

`scripts/install-homeserver.sh`'s `step_arcane_import_stacks` reads the
manifest and creates one `POST /environments/0/gitops-syncs` per matching
entry (environment `0` is Arcane's single "Local Docker" environment on a
one-host deployment). Its selection filter matches all 32 `honeypot-*`
entries — and, since #1505, three of the seven non-`honeypot-*` entries
too: `auth-events-worker`, `llm-worker` and `ml-worker` are imported by
that step as well (each confirmed to have no host-local state beyond
`.env`). That is 35 of the manifest's 39 entries. The other three the
installer provisions itself keep their dedicated steps for reasons specific
to each: `technitium`'s non-`.env` host state (its `config/` directory needs
non-root ownership, #2911 — this is the step `pihole` used to have),
`analysis/ghidra`'s conditional GPU compose overlay, and `sandbox/ghosts`'
s Arcane build-context limitation (#1506) — see the script's own Phase 8
header comment for the reasoning behind each.

The 39th entry, `unsloth` (#3092), is the one the installer does not reach
at all: it matches neither arm of the filter, and the script has no
`step_unsloth_*` of its own. That is not a defect — `arcane/home/unsloth/compose.yml`'s
own header documents it as an operator-started stack ("Deployed through
Arcane like every other homeserver stack … Never `docker compose up` by
hand"), deliberately carrying no `restart:` policy so the cold-benchmark legs
in `analysis/ghidra/training/` can have the card to themselves. It is
covered where fleet-wide operations are concerned — `docs/STACK-REBUILD.md`
lists it in both reset loops — just not by the from-scratch import path.

To import (or re-import) by hand instead, `POST` the manifest's entries to
`/environments/0/gitops-syncs/import` — the bulk-import shape matches the
manifest's own field names exactly (`syncName`, `gitRepo`, `branch`,
`dockerComposePath`, `autoSync`, `syncDirectory`, `syncInterval`).

## A directory-sync create call deploys immediately

**Not obvious from the field names**: creating a sync (`autoSync: false` or
not) performs an initial materialize-and-deploy right away. `autoSync` only
governs whether *future* commits on the tracked branch trigger another sync
automatically — it does not make the first one a dry run. Plan a cutover
accordingly: creating the sync *is* the cutover for that stack.

## Directory-collision behavior is fail-closed

Confirmed by a live test during #1502's migration: pointing a sync at a
directory name that already exists under Arcane's `PROJECTS_DIRECTORY` gets
refused outright —

```text
cannot create project "<name>": a directory with that name already exists;
refusing to create a duplicate
```

Arcane does **not** overwrite or merge into an existing directory. This is
good for secret safety (a sync can never silently wipe a directory holding
real secrets), but it means cutting an already-deployed stack over requires
removing the stack's legacy directory first — after backing up anything not
tracked in Git that lives there. See "Cutover procedure" below; this is
exactly why `step_arcane_import_stacks` stages `.env` aside rather than
letting Arcane's own directory check block the whole import.

## Cutover procedure (per stack)

1. **Enumerate everything at the stack's current directory that Git does
   not track** — not just `.env` and `secrets/`. Confirmed live: `pihole`
   also keeps its DNSCrypt resolver config and its own Pi-hole database
   directly under its own top-level directory (`dnscrypt-proxy/`,
   `etc-pihole/`, `etc-dnsmasq.d/`), a shape only a handful of stacks have
   — the live one now is `technitium`, whose `config/` (zones, settings,
   blocklists) needs non-root ownership for its distroless image, which is
   exactly why the installer still provisions it by hand (#2911). Back up the *actual* bind-mount sources a stack's compose file
   declares, not an assumed `.env`/`secrets/` checklist — read the compose
   file if in doubt.
2. Back up everything found in step 1.
3. Remove the stack's current directory.
4. Create the Arcane sync (`syncDirectory: true`) — this deploys
   immediately, and will legitimately fail-closed if a required secret
   isn't present yet (expected, not a bug — see the four stacks that do
   declare `:?required` variables: `honeypot-canarytokens`, `ghosts`,
   `technitium` and `unsloth`).
5. Restore everything backed up in step 1, **preserving original ownership
   and permissions, not just content**. Confirmed live: restoring a secret
   file as `root:root` when the container expects the previous owning
   user/UID to read it reproduces the exact crash-loop #1143 already
   documented for Keycloak — Postgres's `SCRAM-based authentication, but no
   password was provided` when the container can't actually open the file.
   Check `stat -c "%U:%G %a"` on the original before removing anything, and
   match it exactly on restore.
6. If step 5 restored anything the initial deploy needed,
   `POST /environments/0/projects/{id}/up` to redeploy with it now present.
7. Verify health, and for anything with a network-facing port, verify
   actual reachability at the address real clients will use — not just that
   the container reports healthy. A container can be genuinely healthy and
   correctly resolving DNS internally while the host's own NAT path to its
   published port is still broken from a stale `docker-proxy`/iptables
   state after several rapid recreations; a full `docker compose down` +
   `up` (not just `docker restart`) was what actually cleared that,
   confirmed live during the `pihole` cutover.

## Retirement procedure (per stack)

Deleting a stack's `arcane/home/<name>/` directory from this repo only ever
removes the *source*. It does nothing to what is already deployed — Arcane
has no "this project's directory disappeared, tear it down" behavior, and a
homeserver whose last sync predates the deletion just keeps its
already-synced compose file and already-running containers on disk exactly
as they were. #2813/#2814 (wordpot's retirement in #2381) both surfaced
this the same way: the repo said the stack was gone, but a live container
was still up weeks later — on the VPS because `docker compose up -d`
without `--remove-orphans` never removes a service dropped from the compose
file (fixed for the VPS's own deploy path in #2813), and on the homeserver
because nothing ever told Arcane to tear the project down at all. Retiring
a stack means:

1. Remove the stack's `arcane/home/<name>/` directory (or its VPS
   equivalent block in `vps/docker-compose.yml`) from this repo, same as
   any other change.
2. On every host that had it deployed, actually stop and remove the live
   containers — `docker compose -f compose.yml down` in the stack's
   directory, not just deleting the repo source and waiting for the next
   sync. Another, still-tracked stack's `--remove-orphans` redeploy will
   not do this for you — that flag only cleans up orphans within its own
   compose file's project, not a sibling stack entirely.
3. For an Arcane-managed (homeserver) stack, also delete the corresponding
   `gitops-syncs` record (`DELETE /environments/0/gitops-syncs/{id}`) and
   remove the on-disk stack directory under `/var/dockge/stacks/<name>/` —
   an orphaned sync record with no matching repo directory is itself a
   confusing half-retired state.
4. Re-run the live verification a normal cutover would (`docker ps -a
   --filter name=<stack>` on every host it was ever deployed to), not just
   a repo grep — the repo can be fully clean while the live fleet still
   isn't.

## Known Arcane limitations, confirmed live

These are platform behaviors, not something fixable from a compose file
alone. Re-verify against whatever Arcane version is pinned in
`docker-compose.arcane.yml` if it's ever upgraded. **That upgrade has
happened and the re-verification has not:** every item below was confirmed
against `v2.8.0`–`v2.9.0` (including the no-`profiles:`-support finding,
which cites the upstream issue as still open at `v2.8.1`), while
`docker-compose.arcane.yml` now pins `ghcr.io/getarcaneapp/manager:v2.17.0`
by digest (2026-10-24, #3720; previously `v2.16.1` from #3697, `v2.15.1`,
before that `v2.11.1`). The edge agents on precision and the VPS run the
matching `ghcr.io/getarcaneapp/arcane-headless:v2.17.0`, digest-pinned in
their host-local compose files; the template is
`ops/arcane-agent/compose.yml`.
Nothing here is claimed to be false of `v2.17.0` — it is claimed to be
unconfirmed against it, and eight minor versions of upstream is exactly the
gap that re-verification is for.

- **`"project directory is not inside a mounted directory"` is a false
  warning against every stack with a relative bind-mount source, under
  Arcane's identity bind mount (`/var/dockge/stacks -> /var/dockge/stacks`)
  (#2712).** Traced to Arcane's own source
  (`getarcaneapp/arcane` pinned `v2.9.0`, `pkg/projects/path_mapper.go`):
  `hostWorkingDirInternal`'s `ContainerToHost` call treats
  `hostWorkingDir == containerWorkingDir` as failure —
  ```go
  if hostWorkingDir == "" || filepath.Clean(hostWorkingDir) == filepath.Clean(containerWorkingDir) {
      slog.WarnContext(ctx, "project directory is not inside a mounted directory...")
      return "", false
  }
  ```
  — even though that equality is the *correct* answer for an identity bind
  mount, not evidence of a broken one. `ProjectsDirectory` is the wrong
  knob (it governs an unrelated subsystem, `pkg/projects/fs_util.go`); there
  is no per-message log-suppression Arcane exposes, and `hp-arcane`'s
  container logs aren't ingested into this repo's ELK pipeline (it tails
  application log files, not `docker logs` streams), so there is no
  repo-side filter either. Fires for exactly the 10 stacks with at least one
  relative-source bind mount under this identity mount (`ghidra`,
  `honeypot-cowrie`, `honeypot-dionaea`, `honeypot-elk`, `honeypot-init`,
  `honeypot-keycloak`, `honeypot-payload-analysis`, `honeypot-tanner`,
  `honeypot-utilities`, `technitium`; the 10 is re-derived 2026-09-27 from
  each of the manifest's 39 entries' `volumes:` sources) — every relative
  mount on the 7 of the 9 that existed at the 2026-09-03 check and had
  running containers was confirmed to resolve to its real, existing host
  path, zero missing-on-host mounts. (`pihole` and `honeypot-keycloak` were
  the two without running containers, so their mounts were reasoned from the
  same identity-mount arithmetic rather than observed — #2853, #2764.
  `pihole` has since been replaced by `technitium` in the manifest, #2911 —
  hence the post-#2911 name above; the warning's mechanism is
  per-relative-mount and unchanged by the swap. The tenth stack, `ghidra`,
  is not new: its `./revdeck-proxyfix/*` mounts date from #1173, so the
  2026-09-03 live pass simply never reached it, and the "9" it recorded was
  a nine-name subset of the real set rather than a different count.)
  **Decision: live with it — this repo has no fix
  available, and the warning is confirmed harmless.** Re-verified live
  2026-09-03: still firing at the same 9 stacks, ~1 warning per relative
  mount per sync. Not reported upstream (`getarcaneapp/arcane`) as of this
  writing — posting to a third-party repo needs separate authorization this
  work didn't have; the code citation above is what to attach if that's
  ever decided.
- **A `:?required` compose variable used inside a port-binding host-IP
  position breaks Arcane's own compose validator.** The same `:?required`
  pattern works correctly inside an `environment:` block (Arcane surfaces
  the real "missing value" error there, confirmed against
  `honeypot-canarytokens`/`ghosts`). In a port-binding position, Arcane's
  pre-flight validation substitutes a placeholder for the unset variable
  and then fails Docker's own strict host-IP format check on that
  placeholder — the resulting error (`invalid IP address:
  /placeholder-undefined`) doesn't point at the real cause. Workaround:
  don't use `:?required` for a variable in that position; use `:-` with a
  safe, non-functional default instead (see `technitium/compose.yml`'s
  `LAN_IP` — defaults to `127.0.0.1`, deliberately not the real LAN
  address, since a real deployment-specific address in a public compose
  file would also trip `scripts/check-public-leaks.py`).
- **The build-context git-ref resolver only understands `refs/heads/`.** A
  remote build context pinned to a tag (`ghosts`'s
  `GHOSTS.git#v9.0.0:src`, before the fix below) fails with
  `couldn't find remote ref "refs/heads/v9.0.0"`, even though plain
  `docker build`/BuildKit resolves the same ref fine on its own. Pinning to
  the tag's commit SHA instead of the tag name does **not** fix it —
  Arcane prefixes `refs/heads/` onto *any* ref string given this way, tag
  or SHA. There is currently no compose-file-level workaround:
  **`ghosts-api` has to be built with plain `docker compose build`
  outside Arcane** after every sync (Arcane's own directory sync still
  correctly materializes the files, just not this one image build).
  ```bash
  cd /var/dockge/stacks/ghosts && docker compose up -d ghosts-api
  ```
- **The default sync file-count limit (500) is easy to exceed with a
  vendored dependency tree.** `honeypot-dashboard`'s manifest entry sets
  `maxSyncFiles: 2500` explicitly — headroom carried over from when its
  build context still included the Go dashboard's vendored tree
  (`dashboard/vendor/`, exactly 650 tracked files at the #1502 move,
  re-counted from git history), which exceeded the default back then. That
  tree is gone with the Go tier itself (#1659) and the synced directory is
  down to 279 tracked files (re-counted 2026-09-27,
  `git ls-files arcane/home/honeypot-dashboard`) — under the default
  again, so the bump is dormant headroom, kept because raising it is an
  Arcane-side change rather than a repo one. The failure mode itself
  remains: if a future stack's build context grows a large
  vendored/generated tree, expect the same `file count limit exceeded`
  failure and raise that stack's own `maxSyncFiles` rather than assuming
  the default is enough.
- **The directory-sync walk has no exclude/scope mechanism at all** —
  confirmed against the source (`pkg/gitutil/git.go`'s `WalkDirectory`):
  it walks everything under `filepath.Dir(composePath)` except `.git` and
  symlinks, with no glob, no `.gitopsignore`, no sub-path option. #2711:
  `ghosts`'s sync (`sandbox/ghosts/compose.yml`) always failed — either a
  ~40s-then-500 with no detail, or (once `maxSyncTotalSize` alone was
  raised) a fast `file count limit exceeded` — because
  `sandbox/ghosts/vendor/ghosts-src/` (935 tracked files, 135,601,433 bytes)
  sits in the same directory tree as the compose file, so the sync's
  whole-directory walk of `sandbox/ghosts/` (962 files, 135,748,394 bytes —
  both re-counted 2026-09-27; the 2026-08-31 live walk quoted below measured
  989/135,789,139) blows
  past *both* defaults (`maxSyncFiles: 500`, `maxSyncTotalSize: 50MB`), not
  just the one either failure message names. Fixed the same way as the
  `honeypot-dashboard` case above — both limits raised on the sync record
  and mirrored into the manifest (`arcane/manifests/home-production.json`:
  `maxSyncFiles: 1500`, `maxSyncTotalSize: 209715200`, ~1.5x headroom over
  the measured size). Verified live 2026-08-31: `Directory walk complete
  syncId=... totalFiles=989 totalSize=135789139 skippedBinaries=0`, sync
  request returned `200` with `"Successfully synced directory with 989
  files to project ghosts"`, `ghosts-api` rebuilt and redeployed from the
  synced tree, confirmed serving real data afterward. Total request time
  was **227s** — comfortably under the #2705 ~5 minute internal deploy
  timeout today, but with much less margin than any other project in this
  manifest; if the vendored tree grows further (see #2256, which questions
  whether it belongs in the repo at all — deliberately not addressed
  here), this is the first sync that will hit that deadline again.
- **A destroyed project can leave a stale path/sync binding.** Deleting a
  *sync* does not always fully clear the *project* record Arcane created
  for it — a subsequent sync attempt at the same path can fail with
  `UNIQUE constraint failed: projects.path` or
  `project <id> is already managed by a different GitOps sync` even after
  the blocking sync was deleted. Archiving the stale project
  (`POST .../projects/{id}/archive`) does **not** free the path either;
  only destroying it does
  (`DELETE /environments/0/projects/{id}/destroy`). Confirmed live that
  `destroy` does *not* touch a named Docker volume the stack's containers
  were using — `ghosts-postgres-data` survived a `destroy` cleanly and the
  recreated Postgres container found its existing database intact. It can,
  however, remove the stack's *containers* even when they were healthy and
  serving traffic at the time — check `docker ps -a` immediately after any
  `destroy` call and be ready to bring the affected service back up by
  hand (plain `docker compose up -d`, same as the ghosts-api workaround
  above) rather than assuming the next sync attempt alone will do it.
- **Arcane has no Docker Compose `profiles:` support at all** — not a
  quirk, a confirmed missing feature
  ([getarcaneapp/arcane#1193](https://github.com/getarcaneapp/arcane/issues/1193),
  open/unimplemented as of v2.8.1, the latest release at time of writing;
  still open against the pinned `v2.9.0`, re-checked 2026-08-27).
  Confirmed independently against this deployment, re-derived 2026-08-27
  against the exact digest-pinned `v2.9.0` image this host runs (image
  digest verified against `docker-compose.arcane.yml`; response schemas
  exported from that container with `./arcane openapi`; the project
  record read from Arcane's own store — no API token was on hand for a
  fresh authenticated GET, so the schema and the stored record stand in
  for it): `GET /environments/0/gitops-syncs` and `GET
  /environments/0/projects/{id}` still expose no profile-activation state
  — the only `profiles`-shaped fields anywhere in either response's schema
  are the raw compose service-config passthroughs embedded in the project
  response's optional `services[]` / `runtimeServices[].serviceConfig`
  arrays, which merely echo what a compose file declared and are omitted
  from a plain project GET. `honeypot-dashboard`'s project record reports
  `serviceCount: 8` — exactly the eight services its
  `arcane/home/honeypot-dashboard/compose.yml` defines today
  (`oidc-sessions`, `backend-service-mounted`, `backend-worker`,
  `dashboard-next`, `backend-worker-importer`,
  `backend-worker-enrichment`, `backend-worker-payload-inventory`,
  `services-adapter`), none of them profile-gated: the file contains no
  `profiles:` key at all. (The request/response `backend-service` itself
  now lives one stack over, in `honeypot-dashboard-backend` — its own
  one-service project record, same zero-profile shape.) The four-service
  snapshot this section used to quote (`dashboard`, `oidc-sessions`,
  `es-results-importer`, `services-adapter` at `serviceCount: 4` /
  `runningCount: 4` when captured during #1502) is an era record now: the
  Go `dashboard` went away with its folder (#1659), the Python
  `es-results-importer` was ported to the Rust `backend-worker-importer`
  (#1610), and the #1610/#1612 worker migration added the rest.
  `runningCount` is not a fixed record field: v2.9.0 recomputes it from
  `docker compose ps` on every project GET, so it tracks actual container
  state at query time (7/8 on 2026-08-27, with `backend-worker-enrichment`
  exited at that moment), not profile gating. This settles
  #1628's own open question: a sync brings up only a stack's base
  (non-profiled) services; activating any `profiles:`-gated service group
  — same as `geoip-update`/`threat-intel`/`revdeck`/`mitm`/`test`/
  `blackhole` elsewhere in this repo — is always a manual `docker compose
  --profile X up -d` run against the synced directory on the host
  afterward. There is no Arcane-native mechanism (env override or
  otherwise) that activates a profile instead. (`next` itself never got
  that treatment: #1608's cutover deleted the profile outright rather
  than activating it.)

## Local environment overrides

Compose's own `.env`-in-project-directory interpolation already covers
every `${VAR}` reference in these 39 stacks — none of them *need* `env_file:`
and only one declares it: `analysis/ghidra/docker-compose.ghidra.yml`'s
`revdeck`-profile service carries `env_file: [{path: .env, required: false}]`
(#110), which duplicates the interpolation it sits beside rather than
carrying anything. None needed it added. Arcane's effective environment merge
(`project.env` + `.env.git` → `.env`) feeds that same mechanism
transparently, so a local override set through Arcane's own UI for a synced
project works exactly like editing `.env` by hand always did; no stack-file
changes were needed to support it.

Two things worth knowing when setting an override:

- A stack whose `.env.example` documents a variable as `# REQUIRED` will
  fail-closed at sync/deploy time if that variable is missing — this is by
  design (see "Environment and secret handling" in the parent issue), not
  something Arcane's own UI will warn about before you deploy.
- A Git sync **never** touches host-local files that aren't tracked in
  Git — `.env`, `secrets/`, and (for the handful of stacks that keep other
  runtime state directly in their own directory, see `pihole` above) those
  directories all survive a re-sync of the tracked files around them,
  *provided the directory itself isn't removed and recreated* the way a
  full cutover does. Routine re-syncs (pulling a normal commit on the
  tracked branch) do not remove the directory; only the explicit
  remove-then-resync cutover sequence above does.

## Manual sync, deploy, rollback, and failure triage

- **Trigger a sync manually**: `POST /environments/0/gitops-syncs/{syncId}/sync`.
- **Redeploy without re-syncing** (e.g. after restoring a secret):
  `POST /environments/0/projects/{projectId}/up`.
- **Check a sync's last result**:
  `GET /environments/0/gitops-syncs/{syncId}` — look at `lastSyncStatus`
  and `lastSyncError`. A `"failed"` status with a container exit-code error
  for a one-shot job (`restart: no`, e.g. `honeypot-init`'s
  `snare-clone`/`elasticsearch-setup`) can be a **false negative**: Arcane's
  health-check-aware deploy logic treats any container exit — including a
  legitimate `exit 0` from a one-shot job — as a deploy failure. Confirmed
  live: the job had actually completed successfully (exit code 0, its
  state markers written) despite the sync reporting `"failed"`. Verify the
  real container exit code (`docker inspect <container> --format
  '{{.State.ExitCode}}'`) before treating a one-shot-job stack's failed
  sync status as a real incident.
- **Rollback**: point the sync's `branch` back at the previously-known-good
  ref (or revert the offending commit on the tracked branch) and trigger a
  manual sync. There is no dedicated "rollback" API call — a directory sync
  is idempotent against whatever the tracked ref currently resolves to, so
  moving that ref backward and re-syncing is the rollback.
- **A stalled-looking sync/build is often not actually stuck.** Several
  stacks in this migration took multiple minutes to build (uncached Rust
  and PyTorch compiles in particular) with no visible progress in Arcane's
  own API response — the HTTP call to create/trigger a sync can return
  well before the underlying `docker build`/`compose up` finishes. Check
  for an active build process (`ps aux | grep -i buildkit` on the host) and
  `docker logs hp-arcane` for recent activity before assuming a stuck
  build needs intervention; Arcane has an internal ~5 minute deploy
  timeout, past which it gives up waiting even though the underlying
  `docker build` keeps running and usually finishes on its own — if it
  does, `POST .../projects/{id}/up` once the image exists
  (`docker images | grep <stack>`) completes the deploy cleanly.

## Promotion workflow and change control

Decided in #1507: **release/tag promotion**, with `autoSync` enabled for
exactly the three stacks where a sync is the whole deploy. **The manifest
half of that policy is in effect: every one of the manifest's 39 entries
declares `branch: "production"`, and #1943 (2026-08-25) is the commit that
changed it from `main` — re-derived 2026-09-27, and unchanged since except
for the `pihole`→`technitium` and `unsloth` entries that inherited it.**
The live-store half is not. As of the last reads (2026-08-27 #2549, 2026-09-03)
every live sync still tracked `main` and nothing auto-deployed, so the
manifest and the host disagree about what a sync follows. #2577 holds the
one-time activation steps and the dangling-sync cleanup.

**The pointer the manifest names does not exist yet.** `git ls-remote
--heads origin` on 2026-09-27 returned `main` and assorted agent/dependabot/
design branches and no `refs/heads/production`; `scripts/promote-release.sh
--list` reports it as "branch does not exist yet". A sync pointed at
`production` therefore fails the same way a tag does — Arcane prefixes
`refs/heads/` onto whatever it is given (see "Arcane cannot track a tag"
below) — so this is the one place where the manifest is currently ahead of
reality in a way that bites: the documented bulk-import path,
`POST /environments/0/gitops-syncs/import`, would create 39 syncs that all
fail on their first run, on a branch that nothing creates until someone runs
`scripts/promote-release.sh <tag>`. What actually runs today is the manual
model below.

### Two facts (still true today)

**A sync does not build, but it redeploys anyway when a file changed —
`redeploy_after_sync = 0` does not prevent that.** #2706 caught this
live: the log line is explicit, `Redeploying project due to content
change from Git sync`, and it fires regardless of the stored
`redeploy_after_sync` flag. 28 of 38 projects were redeployed this way
during what was intended to be a files-only sync pass on 2026-08-30. The
live store carries `auto_sync = 0`, `pull_image_after_sync = 0` and
`redeploy_after_sync = 0` on every sync (re-verified 2026-08-27 against
the pinned `v2.9.0` image's own sqlite store) — those are Arcane's
defaults, not manifest-set values: the manifest carries neither field,
and #2455's schema check confirmed the bulk-import request has no way to
set them (only the single create-sync request does) — but none of the
three flags gate the content-change redeploy path, so do not read
`redeploy_after_sync = 0` as "this sync only materializes files." Plan
every sync as a restart of that stack. Confirmed operationally: syncing
`honeypot-dashboard` redeploys the dashboard project from whatever image
is already present — since that project has no `build:` service itself,
`apiary-backend:latest` is left exactly as it was until a separate
`POST /projects/{id}/build` (a call that belongs to the sibling
`honeypot-dashboard-backend` project since #1622 — its `backend-service`
is the one service in the pair with a `build:`). Without that call the
content-change redeploy recreates the containers from the *previous*
image — green, healthy, running the old code.

**The content-change redeploy runs with `removeOrphans=true`.** A
compose file that drops a service will delete that service's container
as a side effect of an ordinary sync — nobody has to ask for it, and
there is no separate confirmation step. Removing a service from a
compose file and pushing that change is enough to delete its container
on the next sync.

**This is also what causes the #2705 5-minute sync deadline.** A
files-only sync would finish well inside Arcane's ~5 minute internal
deploy timeout (see "stalled-looking sync" below); it is the implicit
redeploy documented here that pushes a sync of many/large stacks past
it. There is currently no known flag that suppresses the content-change
redeploy — until one is found (or upstream confirms there isn't one),
treat every sync as a per-project restart and bound the blast radius
accordingly: scope each run to one stack at a time and verify the result — rather than firing
 a fleet-wide sync pass and racing the timeout. (A purpose-built
 single-project script is a natural follow-up; ship it separately so the
 doc's claim of 'every sync is a restart' is reviewable on its own.)**34 of the 39 stacks build an image.** Five pull —
re-derived 2026-09-27 from the 39 manifest compose paths (34 carry
`build:`): `honeypot-elk`, `honeypot-keycloak`, `llm-worker`, `technitium`
and `unsloth`. `llm-worker` is in that set only because the manifest
deploys `llm-worker/docker-compose.captured-data-deploy.yml`, an overlay
with no `build:` of its own — `llm-worker/docker-compose.yml` still has
one. The #1502-era text named "35 of the 38" and the same three pullers,
before #2381 retired wordpot and f139fe24 retired the Go
ip-enrichment-worker. For any
building stack, `autoSync: true` would mean every merge produces a
deployment that looks successful and changes nothing — worse than a
manual process, because it is unattended.

### What actually runs

- **Every sync tracks `branch: "main"`** on the live host, while the
  manifest has said `branch: "production"` for all 39 entries since
  #1943 — so the rows predate #1507's decision and nothing re-pointed
  them. Every live `gitops_syncs` row is one of 39 manifest stacks plus
  #2577's dangling `honeypot-wordpot` orphan, so 40; the 2026-08-27 read
  saw 38 of them, before #2911's `technitium` and #3092's `unsloth`. The
  gap between the two is the thing to resolve before the next import, and
  the branch to resolve it against does not exist yet (see "Promotion
  workflow" above).
- **`autoSync` is 0 everywhere, including the three the manifest flags.**
  `honeypot-elk`, `honeypot-keycloak` and `technitium` carry
  `autoSync: true` in `arcane/manifests/home-production.json`, but the live
  store has `auto_sync = 0` on every row — the elk/keycloak/technitium
  auto-follow policy is silently inert: a promotion, or any push, will not
  deploy them.
- **Every deploy is manual**: sync → build → redeploy per stack. The
  order matters and is not arbitrary: `honeypot-dashboard` must sync
  before `honeypot-dashboard-backend` builds, because the Rust source
  lives in the dashboard project's directory.
- **Promotion is CI-only.** `scripts/promote-release.sh v0.1.0` exists
  and still refuses a ref that is not a tag, and a tag that is not an
  ancestor of `main` — so if a pointer ever exists, what reaches it has
  always been through CI. As of 2026-09-27 it still moves nothing: there
  is no `production` branch on `origin` to move.

### The #1507 design, for the record

- **What deploys is a tagged commit.** Releases are tagged `v*` on `main`.
- **`production` is a pointer at the current release.** Promotion moves
  the pointer; rollback is the same command naming an earlier tag.
- **`autoSync: true` for the three pullers**, which would follow a
  promotion within `syncInterval` (300s). Making that a real deploy
  rather than a file copy requires `pullImageAfterSync` and
  `redeployAfterSync` set on the Arcane side — fields the manifest
  schema has no way to carry (see the fact above), so they would be
  single-sync PATCH work.

#2577 closed (PR #2704) having done only the wordpot-orphan half of its own
scope, and #2858 (below) decided explicitly not to do the activation in this
round either. Two halves of "the #1507 activation" are worth keeping
distinct: the manifest half **was** done, in #1943 on 2026-08-25, which is
what put `branch: "production"` and the three `autoSync: true` flags into
`arcane/manifests/home-production.json`; the live-store half — re-pointing
the rows already in Arcane at that branch and setting the
`pullImageAfterSync`/`redeployAfterSync` fields the manifest cannot carry —
is what is still outstanding.

## Proving which revision is deployed (#3315)

The failure this section exists for is quoted above: a content-change
redeploy leaves the dashboard *"green, healthy, running the old code."*
Everything else about that state is a lie by omission — a fresh container
id, a passing healthcheck and a recent image build all say the machinery
ran, not that this code is what is running. So both dashboard images now
carry the git revision they were built from, in three places, and
`scripts/verify-deploy.sh` compares them.

**Where the stamp is.**

- **Backend** — compiled in. `backend-service/build.rs` reads the `GIT_SHA`
  build arg and re-exports it as `APIARY_GIT_SHA`; `/healthz` returns it as
  the `revision` field of the liveness body
  (`{"live":true,"built":"2026-09-27T01:46:34+00:00","revision":"3dca445…"}`)
  and the boot log line carries it. Note the `ok`/`es` pair that used to sit
  beside it is gone: #3317 split the endpoint into `/livez` (no Elasticsearch)
  and `/readyz` (503 + `reason`), so `revision` now rides on the
  liveness side. `build.rs` also emits
  `cargo:rerun-if-env-changed=GIT_SHA`, which is load-bearing: without it
  cargo reuses a cached build and the second build of an identical tree
  keeps the *first* revision, producing the exact failure this fixes.
- **Frontend** — a static `public/build.json` (`{"revision":…,"built":…,
  "source":…}`), written by `frontend-next/scripts/write-build-info.mjs`
  into the build stage before `npm run build` so vite copies it into the
  output. Served by Nitro from `public/`, the same mechanism the image
  healthcheck already uses for `/static/theme.css`. It is gitignored: a
  committed `build.json` would be a revision claim about nobody's build.
- **Both** — `org.opencontainers.image.revision` (plus `.source` and
  `.created`) as image labels, readable without running anything:
  `docker image inspect apiary-backend:latest --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}'`.

**Where the revision comes from.** The stacks' compose files take
`build.args.GIT_SHA: ${GIT_SHA:-}`, and `.env.example` documents the knob.
It is a variable rather than an inline `git rev-parse` because Arcane's
directory sync explicitly excludes `.git` — there is no repository on the
host for compose to ask. Unset is normal, not an error: a hand-run build
gets `unknown` and a developer never has to pass the arg to get a working
image. CI (`.github/workflows/containers.yml`) passes `github.sha` for
exactly the two Dockerfiles that declare the arg.

**Nothing on the homeserver sets it yet, and that is deliberate to state
plainly.** Arcane reads `${GIT_SHA:-}` out of the stack's own `.env`, and no
repo-tracked file, deploy step or installer writes that variable — the
`.env` files are root-owned `0600` and are provisioned outside this
repository (the same root-owned `.env` the #3312 token helper exists for).
It also cannot be computed in place: `/opt/stacks/apiary` looks like a
checkout but is a working-tree rsync with `.git/` excluded (`deploy.yml`'s
own sync step), and Arcane's synced directory has no `.git` either, so
there is no repository on the host to ask. So the first
`verify-deploy.sh` run after this lands reports **not stamped**, correctly:
the live image was built before the knob existed. Turning it on is one line
per stack, from whatever clone you are deploying —

```
echo "GIT_SHA=$(git rev-parse HEAD)" \
  >> /var/dockge/stacks/honeypot-dashboard-backend/.env
```

— followed by the `POST /projects/{id}/build` the "Two facts" section above
says a content-change sync does *not* do. The two dashboard stacks carry
the variable independently, so it goes in both. Reporting the gap honestly
beats having the image invent a revision.

Both tiers normalize the value to a bare lowercase hex object name
(optional `sha256:` prefix stripped, 7–64 hex characters) or `unknown`, and
both are held to the same table — `backend-service/src/revision-corpus.json`,
read by a cargo test and by `scripts/tests/test_3315_image_revision.py` —
because the two implementations are in different languages in different CI
lanes and the failure mode of their disagreeing is silent: the same build
stamped two ways, which the verification tool would then report as a
mismatch that is not one.

**How to check a deploy.** The tool compares the running revision, the image
label, and an expected revision — which it takes from `origin/main` in a
clone, or from an explicit argument:

```
# On a host with a real clone of apiary, the full check:
scripts/verify-deploy.sh --healthz-exec \
  'docker exec hp-apiary-backend curl -sf http://127.0.0.1:8081/healthz' \
  --image apiary-backend:latest

# Without one, name the expected revision yourself:
scripts/verify-deploy.sh --behind-days 0 "$(git rev-parse origin/main)" \
  --healthz-exec 'docker exec hp-apiary-backend curl -sf http://127.0.0.1:8081/healthz'
```

`--healthz-url http://host:19090/build.json` is the frontend form. Exit
codes are the point: **0** the deployed revision matches, **1** a finding
(missing, unstamped, malformed, or stale past `--behind-days`), **2**
"could not tell" — deliberately distinct, so an unreadable body or an image
that is not on this host can never be mistaken for a stale deploy. Add
`--image` to check a label against the running container, which catches the
commoner variant where a `compose up` recreated from an older image than
the one whose label you just read.

The lag check measures the age of the *deployed commit*, not of the
container, so it survives a container that has been up since before the
merge it is missing — but it needs a clone to measure against, which is why
`--behind-days 0` is the form that works without one. A short revision
(`git rev-parse --short HEAD`) is accepted and reported as an abbreviation
rather than as a mismatch — otherwise the tool would cry wolf on the first
thing an operator tries.

**`diagnostics.yml` runs it in `--warn-only` mode**, in its own "Deployed
revision" section: a scheduled diagnostics red X is the alert, and a stale
deploy is not on #2222's list of things that should redden a run. It passes
`$GITHUB_SHA` as the expected revision and `--behind-days 0`, for the
reason above — the home runner has no clone to measure against (`deploy.yml`
rsyncs into `/opt/stacks/apiary` with `--exclude .git/`, and diagnostics.yml
deliberately has no `actions/checkout`), so the section degrades to "is the
running revision the current tip of `main`" and says so in the report. Its
exit 2 is still reported as **could not tell** rather than as a pass.

## autoSync decision (#2858)

Re-measured 2026-09-03 against `GET /environments/0/gitops-syncs?limit=100`
(37 records, matching #2577's cleanup): **`autoSync` is still `false` on
every one**, unchanged since #1507 and #2577. Note that this is the *live
store*, and it disagrees with this repo's own manifest:
`arcane/manifests/home-production.json` declares `autoSync: true` for
`honeypot-elk`, `honeypot-keycloak` and `pihole`/`technitium` — the "`autoSync`
is 0 everywhere, including the three the manifest flags" bullet earlier in this
document. So #1507's three-puller policy is not merely unactivated; it is
**declared in the repo and inert in Arcane**, and the decision below is a
decision to leave that discrepancy standing for now, not a decision made on a
blank slate. `honeypot-tanner`, `ghidra` and
`ml-worker` are 957–979 commits (~18 days) behind `main`; every stack synced
on 2026-08-30/31 is 77–125 commits behind; even the dozen synced by hand on
2026-09-02 are already 30 commits behind by the next morning. This drift is
the shared root cause behind #2815, #2816 and #2817 — three separately
investigated "a merged PR never reached the host" issues.

**Decision: leave `autoSync: false` fleet-wide. Do not activate #1507's
three-puller policy in this round either.** Reasoning:

- Turning `autoSync` on for all 39 projects means every merge to `main`
  redeploys the fleet unattended — a real increase in blast radius, and
  exactly the kind of change that should not happen as a side effect of
  fixing a visibility gap. (This round's own brief calls this out
  explicitly as the wrong move.)
- #1507's narrower proposal — `autoSync: true` for the three pull-only
  stacks (`honeypot-elk`, `honeypot-keycloak`, `pihole`) — is not safe to
  *reconcile into the live store* today either. Two of the three are
  currently in a broken or undeployed state for reasons unrelated to sync
  policy: `pihole` has **zero containers** on the host right now (#2853, same
  "removed not stopped" shape as #2817), and `honeypot-keycloak`'s `.env` has
  a known host-permission gap that already blocks unprivileged inspection
  (#2764). Since this was measured, #2911 has replaced the `pihole` manifest
  entry with `technitium`, carrying the same `autoSync: true` flag — so the
  third slot is now a freshly-introduced stack that has never run under
  auto-sync at all, which is a reason to re-measure before activating, not a
  reason to treat the question as settled.
  Auto-syncing a stack that is not currently deployed correctly would just
  make the drift-tracking problem *less* visible — Arcane would report
  `success` on a sync that changed nothing observable, the same
  "green means nothing" shape #2854 already found for `honeypot-init`.
  Revisit #1507's activation once #2853 and #2764 are resolved and both
  stacks are confirmed healthy from a fresh deploy, not before.

  **Status as of round 6 (2026-09-04):** both blockers are now closed — #2853
  and #2764 were resolved by the #1609 rebuild, and live-checked here:
  `technitium-dns` and `hp-keycloak`/`hp-keycloak-postgres` are all `healthy`
  on the homeserver. That clears the stated precondition for revisiting
  #1507's narrower activation, but flipping `autoSync` on production stacks
  is a deploy-posture change, not a drift-visibility fix — deliberately left
  for a separate, dedicated decision rather than folded into this round's
  ops-triage pass. `autoSync` therefore remains `false` fleet-wide for now.
- #2854's one-shot-abort hazard (a `restart: no` job's clean `exit(0)`
  making Arcane report `failed` on a deploy that actually completed) is
  scoped to `honeypot-init` **and, since #3128 (2026-09-08), `honeypot-elk`.**
  It is **not** the only file in the repo
  with that shape, and a grep alone does not establish the claim — YAML
  writes it three ways, so the check has to be
  `git grep -nE "restart:[[:space:]]*[\"']?no[\"']?"`, which on `origin/main`
  returns twenty hits — thirteen real declarations across eight files (all
  eight are in the table below), plus seven prose matches: four in this
  document, two in `scripts/arcane-sync-drift-report.py`, one in
  `scripts/compose-drift-watch.py`'s header. (This bullet's own totals were
  fourteen / twelve / seven / two / one at the 2026-09-04 round-6 pass.)
  What scopes the hazard is that
  only two of the eight are services Arcane actually starts:

  | hit | why it cannot trip the hazard |
  |---|---|
  | `arcane/home/honeypot-init/compose.yml` (6×) | **this is an exposed one** |
  | `arcane/home/honeypot-elk/compose.yml:540` | **the other exposed one** — `arkime-pcap-init`, a `chown`/`chmod` one-shot added by #3128, not profile-gated, in a manifest entry Arcane syncs and starts like any other |
  | `sandbox/ghosts/compose.yml:162` | `ghosts` *is* an Arcane project, but the service is `ghosts-client-test`, gated behind `profiles: ["test"]`, so a default `up` never creates it |
  | `llm-worker/docker-compose.{production-session-canary,synthetic-canary}.yml` | canary overlays; the manifest deploys `llm-worker/docker-compose.captured-data-deploy.yml`, which has no `restart: no` |
  | `docker-compose.sandbox.yml:48` | per-detonation sandbox lifecycle, not an Arcane manifest entry |
  | `vps/docker-compose.yml:966` | the VPS stack, deployed by a different mechanism entirely |
  | `sandbox/ghosts/vendor/ghosts-src/Ghosts.Api/docker-compose.yml:85` | vendored upstream source, never deployed |

  All seven excluded files were checked against
  `arcane/manifests/home-production.json`'s 39 entries and their
  `dockerComposePath` values, not inferred from the file paths.
  `honeypot-init` is not one of #1507's three auto-sync candidates, so this
  decision doesn't change its exposure either way: it keeps deploying
  through `scripts/arcane-deploy-honeypot-init.sh --apply` (#2794),
  regardless of what happens to `autoSync` elsewhere. Round 5 recorded that
  wrapper as absent from the homeserver; that is no longer true — re-derived
  2026-09-04, it is at
  `/var/dockge/stacks/apiary/scripts/arcane-deploy-honeypot-init.sh`, mode
  0755, owned by `github-deploy-runner`, dated 2026-09-03 23:07. #2908 is
  closed.

  **`honeypot-elk` is a #1507 auto-sync candidate, so this one is not
  hypothetical the way `honeypot-init` is.** Two consequences follow, and
  neither is established here: whether the live `honeypot-elk` record
  actually reports `failed` (the #2854 shape is a strong reason to expect
  it does, but this has not been read off the live API), and, if it does,
  that `scripts/arcane-sync-drift-report.py`'s `KNOWN_STRUCTURAL_FAILURES`
  still names only `honeypot-init` — so the report would exit non-zero on a
  perfectly healthy fleet, which is the exact "permanently red and therefore
  ignored" failure mode its own comment says the exemption exists to
  prevent. Worth one `GET /environments/0/gitops-syncs` before #1507's
  activation is revisited.

**What makes Arcane gitops-sync drift visible, since nothing did before:**
`scripts/arcane-sync-drift-report.py` — read-only, on-demand (not wired into
a scheduled workflow: that would need an Arcane API key available to a CI
runner, which is a separate credential-handling decision this issue does not
make). Run it by hand:

```
ARCANE_API_KEY=... scripts/arcane-sync-drift-report.py [--behind-days N]
```

It queries the same `gitops-syncs?limit=100` endpoint, computes each
project's commits-behind-`main` via `git rev-list --count
<lastSyncCommit>..origin/main` against a real local clone (point
`--repo-root` at one you can write to — a CI runner's own checkout is
usually owned by a different user and can't be `git fetch`ed from an
interactive session), and exits non-zero if any record is stale past the
threshold (default 3 days), or reports `lastSyncStatus: failed` **and is
not named in the script's `KNOWN_STRUCTURAL_FAILURES` table**.

That exemption is load-bearing, not a softening. `honeypot-init` reports
`failed` on every deploy for a structural reason Arcane never rewrites
(#2854), so without it the script would exit non-zero on a perfectly
healthy fleet on the day it merged and every day after — the same
permanently-red-and-therefore-ignored failure mode
`scripts/isolation-audit.sh`'s own tiering comment was written against.
Exempted projects are still **printed**, with the reason, under an `EXEMPT`
heading; they are not silenced. Any project that reports `failed` without
being named there still fails the run. `KNOWN_STRUCTURAL_FAILURES` names
exactly one project, `honeypot-init`; if the `honeypot-elk` exposure
described under #2858 above turns out to be real, that table needs a second
entry for the same reason, or a healthy fleet goes permanently red.

**The baseline is hardcoded to `origin/main`.** `scripts/arcane-sync-drift-report.py`
fetches `origin main` and measures `<lastSyncCommit>..origin/main`
unconditionally — it does not read each record's own `branch`. That is
correct while every live sync tracks `main` (it still does, per the reads
above), but it becomes the wrong measure the moment #1507's live-store
activation re-points rows at `production`: a sync correctly caught up to
the promoted release would then read as N commits behind `main` for every
merge since the promotion. Same shape as the `honeypot-elk` gap above —
worth resolving in the same pass.

Exit-code behaviour was demonstrated in both directions (2026-09-03) by
driving the shipped `main()` with a synthetic record set: a fleet whose only
`failed` record is `honeypot-init` exits **0**; adding a second `failed`
project that is not exempt exits **1**; a project stale past
`--behind-days` exits **1**. It has **not** yet been run against the live
Arcane API: the homeserver is reachable again as of 2026-09-04, but the
Arcane API key on file was rotated in the #1609 rebuild and now returns
`401 invalid API key` from the host itself, so the first real run is still
owed and worth one look once a current key is to hand.

**What this report cannot see.**

*A second deployment channel.* It covers the Arcane gitops-sync channel only.
The fleet has a second one — `deploy.yml`'s rsync into `/opt/stacks/apiary`
(the same inode as `/var/dockge/stacks/apiary`) — that no sync record covers.
That channel had gone 18 days without a successful run, which is what made a
fleet reading `lastSyncCommit == main` on all 39 records still run a
weeks-old copy of every rsynced script: `diagnostics.yml`'s
isolation-invariants step executes the *deployed* `isolation-audit.sh` from
that path. Tracked and fixed as **#2908**, now closed — re-derived
2026-09-04, `/var/dockge/stacks/apiary/scripts/` was last rewritten
2026-09-04 12:15. The blind spot itself is structural and remains: a green
run of this report still says nothing about the rsync channel's freshness.
Extending it to cover that channel is separate work.

*Whether a project is actually deployed.* `lastSyncStatus` is unreliable in
both directions, so exit 0 means "no record reports a failure, a stale
timestamp or an unreadable one" — never "the fleet is deployed":

| shape | issue | what this report does |
|---|---|---|
| `failed` on a deploy that in fact succeeded — a `restart: no` one-shot's clean `exit(0)` read as an abort | #2854 | exempts it by name and prints the reason, so the exit code keeps carrying information |
| `success` when nothing was recreated — Arcane's 5-minute sync deadline elapses, the retry reports success, the container is untouched | #2910 | **cannot see it.** Nothing in the API response separates that from a real deploy; only comparing container creation time against `lastSyncAt` can, and that needs host access this report deliberately does not take |
| a project that has never synced, `lastSyncAt` present and null | #2853 | fails the run rather than printing `?`, since a never-synced project is exactly what this report exists to surface |

Judge a project by its containers before concluding it is deployed.

`scripts/arcane-verify-recreate.sh` is the host-side complement that closes
the #2910 row above: run **on** the Arcane host (needs `docker inspect` and
Arcane's own sqlite database, not the HTTP API — the API key on file for
this fleet is dead as of the 2026-09-04 rebuild, so a host-local read is
also the only path that currently works at all), it compares every
project's containers' creation time against its `last_sync_at` and fails
the specific containers that were not recreated since a `success` record.

```
sudo scripts/arcane-verify-recreate.sh honeypot-sentrypeer   # one project
sudo scripts/arcane-verify-recreate.sh --all                 # whole fleet
```

**A `FAIL` from it is a prompt, not a verdict.** "Container older than the
last successful sync" is also exactly what a legitimate no-op sync looks
like: if a project's compose config is unchanged, `docker compose up -d`
correctly recreates nothing, so its containers stay older than the sync
record. Arcane records nothing this script can read about *what* a given
sync actually changed, so the defect and the healthy case are
indistinguishable by this measure. Read a `FAIL` as "no redeploy happened
since that sync" and decide from there whether one was expected. The same
applies to run-once containers (`hp-*-init`, `hp-*-setup`), which are
created once and never again and so will `FAIL` on every sync after their
first.

That is also why it is on-demand rather than scheduled: at the fleet's
current sync cadence it would be mostly noise. Run it after a batch of
redeploys, when you know what should have moved.

This does not close the gap by itself — it is a report someone has to run,
not an alert that reaches anyone unprompted. Wiring it into a scheduled,
alerting check (the `compose-drift-watch.py`/`disk-usage-watch.py` pattern)
is future work gated on deciding how a CI runner gets the Arcane
credential; deliberately not done here, to keep this round's change to a
decision plus a manual tool, not a new secret-handling surface.

### Arcane cannot track a tag

`branch` accepts a tag name — the API stores it without complaint — and then
every sync against it fails with a bare `500 Failed to perform GitOps sync`.
Verified live on 2026-08-25 against the `pihole` sync and reverted. This is
the same `refs/heads/` assumption documented above for the build-context
resolver: Arcane prefixes `refs/heads/` onto whatever ref it is given.

That is why the #1507 design is a tag *promoted onto a branch* rather than
a tag tracked directly. The deployed commit would still always be a tagged
one; the branch is only the pointer Arcane is able to follow.

## Security implications of Arcane's Docker-socket access

Arcane's own container bind-mounts `/var/run/docker.sock` — Arcane
compromise is host compromise, the same trust level Dockge held before it
(#1185's own migration rationale). Nothing about directory-aware Git sync
changes that boundary; it just changes *how* a project's files get onto the
host, not what Arcane itself is trusted with once running. The existing
mitigations remain: Arcane is only reachable over the WireGuard tunnel (no
public exposure), native OIDC/MFA gates its own login, and the registered
Git credential (currently none needed — public repo) should stay
least-privilege and read-only if the repository is ever made private.
