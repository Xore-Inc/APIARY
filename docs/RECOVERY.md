# Recovery

[← back to README](../README.md)

What to run when the stack is in a bad state and you need to get back to
clean -- Elasticsearch data corrupted, a bad config landed in `.env`,
persistent volumes ended up inconsistent after a failed migration, or you
just want a safety-net snapshot before trying something risky.

This repo already has the individual pieces T-Pot's single documented
"Factory Reset" sequence (stop, back up `data/`, wipe it, `git reset
--hard`, reinstall) covers -- [`analysis/backup-honeypot.sh`](../analysis/backup-honeypot.sh)
for the backup, [`docs/STACK-REBUILD.md`](STACK-REBUILD.md)'s live-verified
runbook for the stop/wipe/restart sequence across the 33 independent
Arcane-managed stacks [#258](https://github.com/Xore/APIARY/issues/258)
split this into (Dockge originally, replaced by Arcane per
[#1185](https://github.com/Xore/APIARY/issues/1185); each now a
directory-aware Arcane Git sync per
[#1502](https://github.com/Xore/APIARY/issues/1502), see
[`docs/ARCANE-GIT-SYNC.md`](ARCANE-GIT-SYNC.md)) -- but nothing tied them
into one entry point. [`factory-reset.sh`](../factory-reset.sh), at the
repo root next to `setup-home-network.sh`/`setup-suricata-logs-home.sh`, is
that entry point.

Run it **on the homeserver** (`/opt/stacks/apiary`), not from a
local checkout -- it operates on the deployed Arcane-managed stack
directories (`/opt/stacks/honeypot-<name>/compose.yml`, unchanged by
#1502's migration -- Arcane materializes each stack at the same host path
Dockge's symlinks used to point at), same as every script it composes.

## What it does

Every destructive step is opt-in and requires `--apply`, matching this
repo's own git-safety conventions (never a blind `--hard`/`-f` by default).
Run with no flags and it only takes a backup -- `analysis/backup-honeypot.sh`
runs against the *live* stack with no downtime needed, so a routine "get me a
snapshot" run never has to stop anything.

Be clear about what that backup does and does not hold before relying on it
ahead of a `--wipe`: it captures configuration, secrets, the Keycloak identity
database and small config-bearing volumes, and deliberately **not**
Elasticsearch data, captured payloads, PCAP or sandbox images. A `--wipe`
followed by a restore brings the stack back configured and authenticated with
an empty event history. See [`BACKUP-ESSENTIALS.md`](BACKUP-ESSENTIALS.md).

```bash
sudo ./factory-reset.sh                          # backup only, nothing else touched
sudo ./factory-reset.sh --apply --wipe           # backup, stop, wipe, restart
sudo ./factory-reset.sh --apply --git-ref <ref>  # backup, stop, git reset --hard <ref>, restart
sudo ./factory-reset.sh --apply --wipe --no-restart   # backup, stop, wipe, leave stopped
```

| Flag | Effect |
| --- | --- |
| *(none)* | Back up via `analysis/backup-honeypot.sh` (config/secrets/identity only, not ES data). Nothing is stopped. |
| `--apply --wipe` | Also stop every stack and wipe state -- sensor logs via `scripts/reset-logs.sh all` (per-sensor ownership already worked out there, see its own header for why), Filebeat's registry, the dedupe cache, init-markers, and every named Docker volume `docs/STACK-REBUILD.md` documents as wiped (`es-data`, `dionaea-lib`, `dashboard-state`, `yara-results`, `evebox-config`, `arkime-pcap`, `snare-pages`, `reporter-data`) -- all **after** the backup step already ran. |
| `--apply --git-ref <ref>` | Also `git fetch` and `git reset --hard <ref>` against `/opt/stacks/apiary` -- never a bare `--hard` against whatever `HEAD` happens to be. |
| `--no-restart` | Leave every stack stopped instead of starting it back up at the end. |

`--wipe` and `--git-ref` both require `--apply`; the script refuses to run
either without it.

## Stack stop/start order

Same order and reasoning as [`docs/STACK-REBUILD.md`](STACK-REBUILD.md)'s
own live-verified runbook: `honeypot-elk` (Elasticsearch) must be up and
healthy before `honeypot-init` starts on a cold restart, or its
`elasticsearch-setup`/`arkime-init` jobs hang forever waiting on a service
that doesn't exist yet. Everything else starts after those two, in whatever
order -- confirmed order-independent by that runbook's own step 4.

`--wipe` removes `dionaea-lib`/`yara-results` along with everything else,
but `honeypot-init`'s compose file expects both to already exist
(`external: true`) -- the script recreates them as empty placeholders
before restarting, same as `docs/STACK-REBUILD.md` step 3 documents doing
by hand.

## What this doesn't replace

- **Restoring a backup onto a *replacement* host** after real data loss --
  see [`docs/analysis/RECOVERY.md`](analysis/RECOVERY.md) instead. This
  script's `--wipe` is for getting the *same* host back to a known-good
  state on purpose (a schema/volume-layout change, or historical data no
  longer worth keeping) -- it doesn't restore anything after wiping, only
  the backup step captures state for a *later*, separate restore if needed.
- **The full manual pitfalls list.** `docs/STACK-REBUILD.md` documents
  real issues hit on the first live full-reset run (Arkime's
  "fresh install" restart loop, `snare`'s `root:root` ownership
  requirement, Docker's default address-pool exhaustion) that this script
  doesn't detect or work around on its own -- if something looks wrong
  after a `--wipe` run, check that doc's "Pitfalls hit on the first live
  run" section before assuming the script itself is broken.
- **VPS-side state.** `factory-reset.sh` only touches the homeserver's
  stacks. `docs/STACK-REBUILD.md`'s step 1 and step 5 cover stopping and
  restarting the VPS side (Suricata, portbridge) separately.
