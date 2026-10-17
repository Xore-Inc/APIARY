# Container writable-layer and build-cache audit (#2859), 2026-09-03

`docker system df` on the homeserver showed **245.8 GB in container
writable layers**, invisible to the volume audit and the retention knob.
This document is the attribution the issue asked for.

## (1) Attribution: 245.8 GB is 99.9% one excluded container

`docker ps -as` sorted by writable-layer size:

| container | writable-layer size | note |
|---|---|---|
| `rex86-eval` | **245 GB** (virtual 252 GB) | benchmark corpus work, explicitly **excluded** from this round (`analysis/ghidra/benchmarks/model-quant-benchmark/rex86_bench.sh` and siblings) |
| `hp-keycloak` | 179 MB | live service, normal |
| `kctest-import-kc-*` | 178 MB | ephemeral CI test container |
| `technitium-dns` | 9.7 MB | live service |
| everything else (86 more containers) | ≤ a few MB each | normal |

`rex86-eval` alone accounts for essentially the entire 245.8 GB figure.
It's a `nvidia/cuda:12.4.1-devel-ubuntu22.04` container
(`docker inspect rex86-eval`), bind-mounting
`/var/dockge/stacks/rex86-eval/work` → `/work` and the repo itself
read-only at `${APIARY_REPO:-../../../../}` → `/repo:ro` — neither of which
is `/root/.cache`, so everything the benchmark tooling caches still lands in
its own rootfs. `docker exec rex86-eval du -sh /root/.cache`
confirms **227 GB of the 245 GB is `/root/.cache`** (pip/HuggingFace-shaped
model/package cache for the benchmark tooling), not mounted to a volume or
bind mount.

This is a genuine compose/run defect in the shape the issue described — a
container writing tens of GB to its own writable layer instead of a mount.

`rex86-eval` **is** in this repo's tracked compose files:
`arcane/home/rex86-eval/compose.yml`, `setup.sh` and `.env.example` are all
version-controlled (restored by #847), so it is a compose piece and not the
raw `docker run` stack this paragraph originally described. It is *not* in
`arcane/manifests/home-production.json` — deliberately, since it is
benchmark tooling rather than a deployment piece, which is also why it is
absent from the 33 `arcane/home/` manifest stacks. That makes it the one
directory on disk under `arcane/home/` with no manifest entry, alongside
nothing else.

It is explicitly excluded from this round's scope (model-benchmark work,
chained to the same corpus tooling #1947's paused sweep uses). **No fix
staged for it.** The correct fix, if/when the benchmark work is in scope, is a
bind mount for `/root/.cache` — noted here so a future session doesn't have to
re-derive the attribution.

Everything else on the host contributes single-digit megabytes each; there
is no second offender worth a compose change.

## (2) Build cache: already correctly capped, growth is expected floor behavior

The issue measured build cache regrowing 0 B → 11.54 GB reclaimable in one
hour from a single build and asked whether the ceiling, the prune cadence,
or the cap's application to this builder was wrong.

**None of the three — the cap is correctly configured and working exactly
as designed.** `scripts/install-homeserver.sh`'s `step_docker_daemon_config`
(landed by #2760, corrected by #2799 to restore the `maxUsedSpace`/
`minFreeSpace` guard) sets:

```
"builder": { "gc": { "enabled": true,
  "defaultReservedSpace": "20GB",
  "defaultMaxUsedSpace": "100GB",
  "defaultMinFreeSpace": "100GB" } }
```

Verified live, `/etc/docker/daemon.json` on the homeserver matches this
exactly. `defaultReservedSpace` is a **floor** buildkit's GC will not prune
below — it exists specifically to keep recent cache warm for back-to-back
builds. Measured live: `docker builder du` → Reclaimable 13.18 GB, Total
16.16 GB, both under the 20 GB floor. The issue's own 11.54 GB observation
was also under that floor. **This is the cap doing its job, not the cap
failing** — GC only starts reclaiming once usage exceeds the 100 GB
`maxUsedSpace`/pushes free space under the 100 GB `minFreeSpace` guard,
neither of which is close on this host. No config or timer change needed;
a standing prune timer would be redundant with `builder.gc`, which already
runs automatically as part of build activity per buildkit's own design
(the comment in `install-homeserver.sh:431-500` explains why a separate
timer isn't used).

One stray finding, not actioned: a leaked `buildx_buildkit_builder-<uuid>`
container (`docker-container` driver) has been running 45+ hours,
unregistered in `docker buildx ls`'s output — its backing volume is only
222 MB, not a disk driver, and it's a *volume*, so left alone per house
rule 6 rather than removed on a "looks disposable" judgment.

## (3) A third, previously-unattributed leak found in the same pass

Auditing `docker system df`'s "Local Volumes" line (935 total, 913
dangling, 52.39 GB reclaimable — a figure #2820/#2774/#2823's census never
broke out) led to a real, fixable bug: **four** scripts in the `quality.yml`
matrix run `docker rm -f` without `-v` in their cleanup traps, so every
container they boot from an image that declares an anonymous `VOLUME`
leaves that volume behind on every run.

| script | trap line on `origin/main` | anonymous volumes per run |
|---|---|---|
| `scripts/test-keycloak-realm-import.sh` | 36 | 1 postgres |
| `scripts/test-oauth2-proxy-gateway-resilience.sh` | 62 | 1 postgres |
| `scripts/test-dashboard-oidc-pkce-totp-login.sh` | 75 | 1 postgres + 1 redis |
| `scripts/test-dashboard-oidc-chaos.sh` | 66 | 1 postgres + 1 redis |

**Six anonymous volumes per full matrix run**, 4 postgres + 2 redis. The
declaring images are `postgres:18.4-bookworm` (`VOLUME /var/lib/postgresql`
— note the 18.x path, not the `/var/lib/postgresql/data` of earlier majors)
and `redis:7-alpine` (`VOLUME /data`), both read from the image config
rather than assumed. All four scripts are fixed in this branch.

The attribution is not "this is the one script": three independent lines of
evidence say the backlog comes from all four.

1. **Content.** A 40-volume random sample of the dangling set: 26 × 69–70 MB
   each containing an `18/` directory (postgres 18 data), 13 × 0 bytes,
   1 × 4 KB containing `dump.rdb` (redis). A 4-postgres : 2-redis producer
   mix predicts 26.7 : 13.3 in a 40-sample; observed 26 : 14.
2. **Falsification.** `test-keycloak-realm-import.sh` boots no redis at all,
   so it cannot have produced the redis-shaped volumes.
3. **Arithmetic.** Dangling-volume creation by day against
   `gh run list --workflow quality.yml`: 2026-09-02 = 51 runs / 306 volumes;
   2026-09-03 = 7 runs / 48 volumes. One volume per run cannot produce six
   times its own ceiling.

A second leak path stays open and `-v` cannot close it: `trap cleanup EXIT`
does not fire on `SIGKILL`, so a killed invocation leaves both its
containers and their volumes behind. Live example at audit time —
`kctest-import-kc-2993069` and `kctest-import-pg-2993069`, up 37 hours from
an invocation whose trap never ran. Closing that needs a pre-run reaper for
stale `kctest-*` / oidc-test containers, or `--rm` on the `docker run -d`;
filed as #2915 rather than widened into this row.

The 913 already-dangling volumes from before the fix are **not** removed
here — filed as #2904 for a human decision, since blanket-removing volumes
by pattern (even anonymous ones) is exactly what house rule 6 exists to
prevent.

## Net effect on `/var`

None yet from this row directly — `rex86-eval` is excluded, the build
cache was already correctly capped, and the 913 pre-existing dangling
volumes are deliberately left for #2904's human review. The durable
contribution is: (a) the attribution itself, closing out the "unaudited"
half of the issue title, (b) confirming the build-cache cap needs no
change, and (c) stopping a live, ongoing leak (six anonymous volumes per
full `quality.yml` run, across four scripts) even though its backlog isn't
cleared today.
