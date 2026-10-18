# Essentials backup and restore

[← back to README](../README.md)

The backup that exists so the stack can be rebuilt. It captures what cannot be
recreated from this repository — secrets, keys, certificates, the Keycloak
identity database, operator-edited config, and the operator-authored
Elasticsearch documents the dashboard keeps — and deliberately nothing else.

For a *deliberate* reset of a working host see [`RECOVERY.md`](RECOVERY.md);
for restoring onto a replacement host see
[`analysis/RECOVERY.md`](analysis/RECOVERY.md).

## What is and isn't in it

**In**, roughly 23 MB uncompressed as of 2026-08-23:

| | |
|---|---|
| `homeserver/env/*.env` | one file per Arcane/Dockge stack (40 under `/var/dockge/stacks/` as of 2026-09-27) |
| `homeserver/secrets/` | secret files kept beside a stack rather than in its `.env` |
| `homeserver/wireguard/` | `wg0.conf` including the private key |
| `homeserver/installer/` | the installer's answers file(s), which exist only on the root filesystem a reinstall wipes. Collected from every place it lives (`/etc/apiary/install-home.conf`, `/root/apiary-install/`, `/home/*/install/`, and the older `/root/`, `/home/*/`), named after the full source path with `_` for `/`, mtimes kept — restore the newest |
| `homeserver/technitium/` | hand-maintained Technitium DNS config |
| `homeserver/keycloak/keycloak.sql.gz` | `pg_dump` of the identity DB — realm, clients, client secrets, users |
| `homeserver/es-operator-state/` | the dashboard's operator-authored Elasticsearch documents, as mapping + NDJSON — see [Operator state](#operator-state) |
| `homeserver/volumes/` | `dashboard-state`, `honeypot-arcane_arcane-data`, `honeypot-elk_evebox-config`, `honeypot-canarytokens_canarytokens-redis-data`, `honeypot-dashboard_es-importer-state` — the Arcane-prefixed names are the real volume names |
| `vps/env/vps.env`, `vps/secrets/`, `vps/traefik/`, `vps/wireguard/` | the VPS's entire config surface, including the Traefik origin certificates |
| `*/manifest/` | host reference notes — disks, volumes, containers, WireGuard, nftables |
| `repo/docs/`, `repo/scripts/`, `repo/analysis/` | this repository's runbooks and operational scripts |

**Out**, on purpose. These are bulk capture data, and a rebuilt stack does not
need any of them to come back up (sizes measured live 2026-08-23):

| | | |
|---|---|---|
| `es-data` | 30 GB | the Elasticsearch store — events, alerts, and every *derived* `dashboard-*` index. The exception, the operator-authored indices, is exported separately: see [Operator state](#operator-state) |
| `state/elasticsearch-snapshots` | 14 GB | the ES snapshot repository |
| `dionaea-lib` | 90 GB | captured malware samples |
| `/var/dockge/sandbox` | 105 GB | Windows sandbox golden images and ISOs |
| `ghidra_ollama_models` | 18 GB | re-pullable model weights |
| `arcane-trivy-cache` | 5.6 GB | rebuildable scanner cache |
| `reporter-data` | 2.8 GB | generated reports |
| `ghidra_ghidra_projects` | 158 MB | analysis output derived from payloads |
| Technitium query logs, stats DBs | varies | recompiled blocklist hits, DNS query log |
| sensor logs, PCAP, Filebeat registries | | |

The runbooks ride along on purpose. Without them a rebuild that starts from one
of these sticks has every secret in the fleet and no instructions — the restore
procedure, the stack start order, the disk layout and the Keycloak runbook
would all live only in git, on a host you are trying to reach from a machine
you have not rebuilt yet. It costs 3 MB.

Each destination also gets a plaintext `RESTORE-README.txt` beside the
archives. The runbooks are *inside* the archive, which is the wrong side of the
encryption if what you have forgotten is how to open it; that one file is
unencrypted, holds no secret, and carries the `gpg -d` command and the reading
order.

**A stack restored from this comes back with its own identity, its
configuration and its dashboard settings intact, and with an empty event
history.** That is the trade. If captured data ever needs preserving, give it
its own job with its own retention — do not couple it to this one. Coupling is
precisely what broke the previous arrangement (see *History* below).

## Operator state

`es-data` is out of scope here, and that is correct for the bulk of it: it is
tens of gigabytes of captured telemetry. It is *not* correct for the ten small
`dashboard-*-v1` indices an operator types into rather than captures. An admin
config change, a user's saved preferences, an alert somebody acknowledged, a
canarytoken somebody deployed, a manual IP block, a workbench recipe — none of
those exist anywhere but Elasticsearch, and nothing in the pipeline can
regenerate any of them.

They are exported as mapping + NDJSON by
[`scripts/es-operator-state-backup.py`](../scripts/es-operator-state-backup.py)
into `homeserver/es-operator-state/` (and, from the on-host copy,
`es-operator-state/` at the top of that backup directory). That script's
`--list` prints the whole split from the same ledger it walks:

| Exported | Written by | Why it is here |
|---|---|---|
| `dashboard-config-v1` | an admin save | the configuration singleton |
| `dashboard-users-v1` | a user | user projections + per-user preferences |
| `dashboard-alert-state-v1` | the alert-notifier, on an operator's ack | ack/cooldown bookkeeping, no ILM, so nothing prunes it |
| `dashboard-canarytokens-v1` | the canarytokens page | deployed decoy token definitions |
| `dashboard-credentials-v1` | the credentials page | bait credentials provisioned into honeypot filesystems, with the ids needed to manage them |
| `dashboard-ip-block-v1` | the manual block list | the list the VPS firewall puller consumes every 5 minutes |
| `dashboard-reports-definitions-v1` | the reports page | the report-definitions singleton |
| `dashboard-workbench-recipes-v1` | the workbench | one immutable document per `id:revision` |
| `dashboard-ml-anomaly-ack-v1` | an operator's ack on an anomaly | acks and notes |
| `dashboard-problem-reports-v1` | the "report a problem" button | operator-submitted, append-only, no ILM |

| Not exported | Regenerated by |
|---|---|
| `dashboard-payload-inventory-v1` | payload-inventory-worker, rescanning the payload stores |
| `dashboard-payload-bytes-v1` | the same scan |
| `dashboard-static-analysis-v1` | a pure function of a payload's bytes, content-hash keyed |
| `dashboard-generated-reports-v1` | the reporter, from a report definition |
| `dashboard-workbench-runs-v1` | re-running a recipe, which is itself backed up |
| `dashboard-bff-v1-*` | per-request auth/session telemetry |
| `dashboard-intelligence-archive-v1` | the upstream intel feeds |

Each export writes its own `MANIFEST.txt` beside the documents, one row per
ledger index with the document count and size, and `absent`/`failed` for
anything it did not capture — so a truncated or unreachable cluster is visible
in the archive rather than looking like a clean run. Sizes are kilobytes per
index; `ES_MAX_INDEX_BYTES` (32 MiB by default) caps any single index, and an
index that hits the cap is truncated *between documents* and flagged
`truncated` in the manifest. `dashboard-alert-state-v1` is the largest of the
ten — thousands of small records, a few megabytes.

**An SLM policy into `honeypot-fs` would not have been a backup.** That
repository is `state/elasticsearch-snapshots` on the same host as `es-data`,
and this script's on-host sibling excludes that path from its own archive — a
snapshot there dies with the disk. It would also have re-created the coupling
*History* below describes, where a broken snapshot took the config backup
down with it.

Run the export by hand, or rehearse a restore, with:

```bash
sudo /opt/stacks/apiary/scripts/es-operator-state-backup.py --list
sudo /opt/stacks/apiary/scripts/es-operator-state-backup.py --dest /tmp/es-state
```

## Where it goes

Three locations, all written by the workstation, which is the backup host:

| # | Location | Filesystem | Notes |
|---|---|---|---|
| 1 | `/run/media/xore/<uuid>/apiary-backups` | ext4 (Crucial X8 USB) | udisks auto-mount — only present while plugged in |
| 2 | `~/apiary-backups` | XFS (internal) | always available |
| 3 | `homeserver:/mnt/usb-recovery/apiary-backups` | ext4 (Samsung PSSD T7, label `APIARY-BACKUP`) | mounted from fstab by UUID with `nofail` |

Location 3 was a Ventoy stick formatted exfat until 2026-08-23, mounted
read-only and absent from `/etc/fstab` — so every write to it failed and it
would not have survived a reboot. It is now a single ext4 partition with a
proper `nofail` fstab entry, which also means it preserves ownership and the
archive's `0600`; exfat could express neither.

A destination that is unavailable is a warning, not a failure — one missing
copy must not stop the other two. All three missing does fail the run.

Retention is 30 archives per destination, pruned oldest-first after each
successful write.

## Encryption

Every archive is GPG symmetric AES256. It contains WireGuard private keys, TLS
private keys, OIDC client secrets and the full Keycloak user database, and two
of the three copies live on removable drives — plaintext there would mean
anyone who walks off with a stick owns the fleet.

Symmetric with a passphrase, not a keypair, so that recovery depends on one
string a human can keep in a password manager and nothing else. No key file
that itself needs backing up, no keyring, no dependency on this repo:

```bash
gpg -d apiary-essentials-<stamp>.tar.gz.gpg | tar xz
```

`scripts/install-backup-essentials.sh` generates the passphrase on first run,
stores it at `/etc/apiary-backup.pass` (0600, owned by the run user) and prints
it once. **Save it somewhere other than the machine being backed up** — a
passphrase that only exists on the dead host is not a passphrase.

`BACKUP_ENCRYPT=0` writes plaintext archives. Only reasonable if all three
destinations are trusted, which today they are not.

If the passphrase file is missing but archives from a previous passphrase
already exist on **any of the three destinations** (local disk, local USB, or
the homeserver's USB), the installer refuses to mint a new one — that would
leave those archives permanently unreadable. An unreachable homeserver counts
as "unknown, refuse" rather than "none found", since failing closed is the
point of the guard. Confirm the old passphrase is saved in the password
manager, then either write it back to `/etc/apiary-backup.pass` yourself or
re-run with `CONFIRM_NEW_PASSPHRASE=1` to accept minting a fresh one.

## Running it

### Required items and exit status

A run exits **0 only if every required item was collected and the archive
reached all three destinations** (#3709). Otherwise it exits 1 and prints an
`ERROR:` line for each problem, so the systemd unit goes red and the journal
says why. The archive is still written to whatever is reachable — a partial
backup beats none — and `MANIFEST.txt` inside it records `status INCOMPLETE`
and what was missing.

| Required item | Looked for at | Why it cannot be skipped |
|---|---|---|
| installer answers file | `homeserver/installer/` | `install-homeserver.sh` will not run without it; not reconstructible from the repo |
| operator-state export | `homeserver/es-operator-state/MANIFEST.txt` | dashboard config, users, alert acks — in no other backup |
| Keycloak dump | `homeserver/keycloak/keycloak.sql.gz` | the realm, client secrets and users |
| stack `.env` files | `homeserver/env/*.env` (at least one) | the generated secrets that exist nowhere in git |
| WireGuard keys | `homeserver/wireguard/` | the homeserver's peer record on the VPS is valid only with this key |

The checks run on the collected tree, not on the remote side's own messages, so
a collector that logs and carries on cannot produce a "successful" archive
without them. A destination that is unplugged, not mounted, not writable or
fails its checksum counts as a failed destination in the exit status; the
`mountpoint -q` guard stays, and `/run`, `/run/media`, `/media` and `/mnt`
themselves never count as a USB mount (the first is a tmpfs on every systemd
host), so an unattended run never writes into the wrong filesystem.

```bash
scripts/backup-essentials.sh              # collect and fan out
scripts/backup-essentials.sh --dry-run    # collect, print the tree and size, discard
scripts/backup-essentials.sh --list       # what each destination currently holds
scripts/backup-essentials.sh --check      # exit non-zero if the newest archive
                                           # anywhere is missing or stale (>48h,
                                           # override with MAX_AGE_HOURS), or the
                                           # installed copy is older than the checkout
```

Nothing runs `--check` on a schedule today; wire it into whatever host health
sweep exists, or a separate timer, if the timer silently disappearing (as it
did after the #1609 rebuild — see #3016) needs to be caught automatically.

Requirements on the workstation: SSH aliases `homeserver` and `vps` working
(see `~/.ssh/config`), passwordless `sudo` on the homeserver — the stack `.env`
files are root-owned and unreadable without it — and `gpg`.

The script only ever reads from the two servers.

### Automatic runs

```bash
sudo scripts/install-backup-essentials.sh
```

Installs `apiary-backup-essentials.timer` — daily, ±30 min jitter,
`Persistent=true` so a run missed while the workstation was powered off fires
at the next boot instead of being skipped.

The installer copies the script to `/usr/local/libexec/apiary-backup-essentials.sh`
and points the unit there, so **re-run the installer after every `git pull`**
that touches `scripts/backup-essentials.sh`; nothing else refreshes the copy
the timer runs. Forgetting did real damage once: the copy on the backup host
was six weeks old, predated the operator-state export, and every archive in
that time lacked the dashboard operator state (#3708/#3709).

The installer therefore also writes `/usr/local/libexec/apiary-backup-essentials.sh.src-sha256`,
the sha256 of the checkout script it copied. Every run, and `--check`, compares
that with `$REPO_DIR/scripts/backup-essentials.sh` and logs
`WARNING: installed copy ... is older than the checkout` (or `has no install
stamp`, for a copy installed before stamping existed) with the exact command to
run; `--check` exits non-zero on it. It is deliberately only a warning for the
scheduled run — a checkout sitting on a feature branch should not break the
backup — but it is repeated at the end of the run's output so it is the last
thing in the journal.

That is the opposite of `analysis/install-backup-timer.sh`, which deliberately
runs `backup-honeypot.sh` in place — but that script tars up the very checkout
it lives in, so a copied-out version would drift from what it backs up.
`backup-essentials.sh` has no such coupling; it only talks to remote hosts.

It is also forced here. The backup host runs Rocky with SELinux enforcing,
where a systemd unit cannot exec a file labelled `user_home_t`:

```
avc: denied { execute } ... scontext=system_u:system_r:init_t:s0
                            tcontext=unconfined_u:object_r:user_home_t:s0
```

Running in place from `~/Github/APIARY` fails with `203/EXEC`. Anything under
`/usr/local/libexec` gets `bin_t` and works.

It runs as the workstation user (`User=xore`), not root — the SSH identity, the
`~/.ssh/config` aliases and the udisks USB mount all belong to that user. A
system unit with `User=` does not need lingering enabled, which a `--user`
timer would (`Linger=no` on this box).

```bash
systemctl start apiary-backup-essentials.service     # run now
systemctl list-timers apiary-backup-essentials.timer # when next
journalctl -u apiary-backup-essentials.service       # what happened
```

## Restoring

The archive is a plain tar.gz behind a symmetric GPG envelope on purpose: the
restore path must not need this repository, this script, or any tool that is
not already on a rescue system.

```bash
gpg -d apiary-essentials-<stamp>.tar.gz.gpg | tar xz -C /tmp/restore
cat /tmp/restore/MANIFEST.txt
```

Then, onto a rebuilt host:

**Before any of the below**, put the newest file in `homeserver/installer/`
back at the path you intend to pass to `scripts/install-homeserver.sh --config`.
The installer will not run without it, and it is not reconstructible from the
repository — `install-homeserver.conf.example` carries only placeholders.

1. **Stack `.env` files.** Copy each `homeserver/env/<stack>.env` back to
   `/var/dockge/stacks/<stack>/.env`. Restore ownership and mode
   (`root:deploy-runner`, `0600` for most). Never overwrite a live `.env`
   wholesale without reading it first — the same rule that applies to any
   edit on these hosts.
2. **Secrets.** `homeserver/secrets/<stack>/secrets/*` back to the matching
   `/var/dockge/stacks/<stack>/secrets/`, `0600`.
3. **WireGuard.** `homeserver/wireguard/wg0.conf` to `/etc/wireguard/`, `0600`
   root. Reusing the original private key means the derived public key still
   matches the peer record on the far side, so **the VPS needs no WireGuard
   change at all** for the tunnel to come back.
4. **Keycloak.** Bring up `hp-keycloak-postgres` alone, then
   `gunzip -c keycloak/keycloak.sql.gz | docker exec -i hp-keycloak-postgres psql -U keycloak -d keycloak`.
   The dump is `--clean --if-exists`, so it drops and recreates. Start
   `hp-keycloak` only once the restore has finished. This is what saves the
   8-client OIDC secret resync that a fresh realm import otherwise forces —
   the clients come back with their original secrets, matching the ones in
   `vps/secrets/oidc/`.
5. **Volumes.** For each `homeserver/volumes/<name>.tar.gz`, with the stack
   stopped, create the volume and unpack into it through a networkless
   container. `<name>` is the **full real volume name** — the archive is
   written as `$volume.tar.gz` by `backup-essentials.sh`, so four of the
   five carry their Arcane project prefix
   (`honeypot-arcane_arcane-data.tar.gz`, and so on). Creating a
   short-named `arcane-data` volume instead would restore into a volume
   no stack is mounted against.
   ```bash
   docker volume create <name>
   docker run --rm --network none -v <name>:/dst -v "$PWD/homeserver/volumes:/src:ro" \
     busybox:1.36 tar -C /dst -xzf /src/<name>.tar.gz
   ```
   Never unpack into a running container's volume.
6. **Technitium DNS.** `homeserver/technitium/*` back into the stack's
   `config/`. Query logs and stats DBs are not in the archive by design —
   they rebuild themselves as the server runs. Re-apply the admin password
   and upstream (DoH/DoT) settings if the config dir was not captured.
7. **Dashboard operator state.** With `honeypot-elk` up and healthy (it is,
   or will be, whatever this list gets to first) and the tool from this
   archive, put the documents back:
   ```bash
   python3 repo/scripts/es-operator-state-backup.py \
     --restore homeserver/es-operator-state
   ```
   It creates each index from its exported mapping, bulk-indexes the
   documents, and refreshes. It refuses a bulk body it cannot parse rather
   than half-restoring an index, and it leaves an existing index alone
   apart from the documents named in the file — so running it against a live
   cluster is safe, but there is no reason to. Rehearse it with
   `--into 'check-{index}'` first, which writes scratch indices you can count
   and then delete. See [Operator state](#operator-state) for what is in
   there and what is deliberately not.
8. **VPS.** `vps/env/vps.env` to `/root/vps/.env`; `vps/secrets/` and
   `vps/traefik/` back to `/root/vps/`; `vps/wireguard/wg0.conf` to
   `/etc/wireguard/`. The Traefik origin certificates matter — they are valid
   until 2028 and cannot be regenerated from this repo, which is why
   `deploy.yml` refuses to overwrite `traefik/` on a normal deploy.

Then follow [`STACK-REBUILD.md`](STACK-REBUILD.md)'s start order —
`honeypot-elk` healthy before `honeypot-init`, everything else after.

Verify with `analysis/verify-stack.py` — `DASHBOARD_SERVICE_TOKEN` from the
stack's `.env`; it judges source-health through dashboard-next's `/bff`
passthrough and exits nonzero when anything is wrong.

## The on-host copy

`analysis/backup-honeypot.sh` captures the same material on the homeserver
itself, into `/opt/backups/honeypot/<stamp>/`, on the `backup-honeypot.timer`
schedule. Same scope, same exclusions. It is faster to reach and useless if the
box dies; the two are complements, not alternatives.

Validate one with `analysis/verify-backup.sh <directory>`.

## The benchmark work-area mirror

`/var/benchmarks` on the homeserver (sweep scripts, rosters, run-state
JSON, status markers — the same class of "irreplaceable, double-digit MB"
data #2985 lost once) is **not** in this backup's fan-out. It is out of
scope on purpose: everything in it either belongs in git (drivers, rosters —
enforced separately) or is small run-state that changes every few minutes
while a sweep is live, which does not suit a daily three-destination archive
cycle.

**Mirror of record**: `~/apiary-bench-snapshots/homeserver-workarea/` on
this workstation (`hermes`, `192.168.42.253`) — not `xps13` / `192.168.42.15`,
which is retired and unroutable. Kept current by
`scripts/mirror-benchmark-workarea.sh`, pulled (never pushed — homeserver has
no SSH key back to hermes) every 2 hours by the
`apiary-benchmark-mirror.timer`/`.service` pair on this workstation.

```bash
scripts/mirror-benchmark-workarea.sh              # pull now
systemctl list-timers apiary-benchmark-mirror.timer
```

Restore is a plain reverse rsync — no GPG envelope, since this mirror holds
scripts and JSON, not secrets:

```bash
rsync -a ~/apiary-bench-snapshots/homeserver-workarea/ <dest>
```

Dry-run restore verified 2026-09-08 against a scratch directory: 5,489 files,
154 MB, transferred clean; a full non-dry-run copy into the same scratch
directory came back byte-identical to the source (`diff -rq`).

## History

The Elasticsearch snapshot that `analysis/backup-honeypot.sh` used to take is
gone, for two reasons that happen to point the same way:

- It was the bulk ES data this backup is explicitly not meant to hold; the
  `honeypot-fs` repository it wrote into had reached 14 GB.
- **It had never once succeeded.** Every scheduled run since the timer was
  installed on 2026-08-16 failed with `curl: (22) ... error: 400` from the
  snapshot API. That call sat under `set -e`, so the run aborted right there —
  the volume archives never ran, retention never ran, and the service sat in
  `failed`. Seven consecutive days of "backups" held one config tarball, an
  empty `volumes/` directory and a zero-byte `elasticsearch-snapshot.json`.

Also found and worth knowing: `honeypot-keycloak/.env` carries a full set of
`RESTIC_*` variables pointing at `/mnt-2/apiary-keycloak`, but that repository
directory does not exist — and as of 2026-09-27 neither does `/mnt-2` itself,
which has been decommissioned, so the path cannot start working by accident.
Its password file (`secrets/restic-password`) does
not exist, `restic` is not installed on the homeserver and no unit references
it. It is dead configuration — no Keycloak restic backup has ever run. The
`keycloak.sql.gz` dump in both scripts here covers that gap.

All of the above is tracked in
[#1694](https://github.com/Xore/APIARY/issues/1694).

It is also why the operator-state documents were not left to a snapshot
(#3323). `docs/settings-operations.md` had claimed config and users were
"covered by whatever snapshot/backup policy this cluster's other
Elasticsearch-owned dashboard data already has". There was no such policy —
`GET _slm/policy` answered `{}` — so the claim described a backup that had
never existed, and the ten indices in [Operator state](#operator-state) were
in none. They are exported as documents now, which is both the thing that
actually works and the thing that cannot take the config backup down with it.
