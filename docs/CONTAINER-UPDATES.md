# Checking and applying container updates

[← back to README](../README.md)

## Cadence: who checks, who bumps

Nothing here auto-updates, and until #2315 nothing checked either — the
Elastic trio's pin sat one full patch behind for weeks, found only by
accident during an unrelated audit. `.github/workflows/elastic-release-watch.yml`
(`scripts/elastic-release-watch.py`) now owns the recurring half of that:
runs monthly, resolves the current docker.elastic.co tag for
elasticsearch/kibana/filebeat, and files (or updates) one tracking issue
when the pin has fallen behind. It never bumps anything itself.

It reads the pins out of **both** `arcane/home/honeypot-elk/compose.yml`
and `arcane/home/honeypot-init/compose.yml` — elasticsearch is pinned in
both, and the honeypot-init copy is exactly the one #2315 found stale. If
those two pins ever disagree (tag *or* digest), the watch fails loudly
rather than picking one. It also fails — non-zero, naming the image —
whenever it cannot reach the registry for any of the three: a run that
checked one image must never look like a run that checked three.

The verification half stays a person's job, every time the watch files an
issue: work through this document's checklist (real release notes, the
Arkime-as-second-consumer check, running the `ES_IMAGE`-hardcoding tests
under `analysis/tests/` for real) before merging. The rest of the pinned
fleet (postgres, ollama, arkime, the base images, etc.) has no automated
watch yet — still a manual pass, same as #1402's.

Every third-party image in this repo is pinned by tag+digest
(`image: repo:tag@sha256:...`). Nothing auto-updates — a stale pin is safe by
construction, but it means checking for updates is a deliberate, periodic
exercise rather than something CI enforces. This is the process used for
the #1402 sweep (postgres/ollama/curl/busybox/traefik/alpine, the
Elasticsearch 8.13.4 → 9.5.1 major-version migration, `docker:27-dind` →
`29.7.2-dind`, `geoipupdate` v7 → v8) and the one to repeat for the next
pass.

## 1. Find every pinned image

```sh
grep -rhoE '^FROM\s+\S+' --include="Dockerfile*" . | sed -E 's/^FROM\s+//'
grep -rhoE '^\s*image:\s*\S+' --include="docker-compose*.yml" . | sed -E 's/^\s*image:\s*//'
```

Sort and dedupe the combined output. Skip anything locally built
(`honeypot-dashboard:latest`, `xore-portbridge:local`, etc.), anything
inside a honeypot's own decoy content (`cowrie/honeyfs/...` — that's fake
data shown *to* attackers, not a real dependency), and anything already
pinned to `:latest` deliberately (check the surrounding comment before
assuming that's an oversight — some are intentional, e.g. debug/diagnostic
tooling images meant to always be fresh).

Known deliberate `:latest` exceptions (each justified inline at its own
`image:` line — read the comment there before "fixing" it):
- (none for Keycloak any more: since #3824 `arcane/home/honeypot-keycloak/compose.yml`
  pins `quay.io/keycloak/keycloak:<version>@sha256:…` like every other
  image, and a security release is applied by moving that pin -- see
  docs/KEYCLOAK-OPERATIONS.md §7.)

## 2. Check the latest available version per image

No web search needed for this part — query the registry directly.

**Docker Hub** (needs an anonymous pull token first):

```sh
token=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $token" "https://registry-1.docker.io/v2/${repo}/tags/list"
```

**ghcr.io** — same shape, token endpoint is `https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`,
manifests endpoint is `https://ghcr.io/v2/${repo}/manifests/${tag}`.

**quay.io** — no token dance needed: `https://quay.io/api/v1/repository/${repo}/tag/?limit=50&onlyActiveTags=true`.

**docker.elastic.co** — its own auth realm:
`https://docker-auth.elastic.co/auth?service=token-service&scope=repository:${repo}:pull`,
then the same `/v2/${repo}/tags/list` shape as Docker Hub.

To resolve a specific tag to its digest for pinning, `curl -sI` the
manifest endpoint with `Accept:
application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json`
and read the `Docker-Content-Digest` response header — that's the
manifest-list digest (works across architectures), not a single-platform
digest.

## 3. Assess compatibility before touching anything

Depth should scale with the size of the jump:

- **Patch/minor within the same major line** (postgres 18.4→18.6,
  ollama within 0.32.x): read the real release notes for what changed
  between the two versions specifically, not just "is it newer." A search
  engine summary is a starting point, not a source — see the next section
  for why.
- **Major version jump**: read the project's own documented upgrade path
  (some, like Elasticsearch, require landing on the latest previous-major
  release first — there is no direct 8.13→9.5 path, only 8.19→9.x) and its
  breaking-changes list. Then check whether *this repo's own usage*
  actually touches any of those changes — grep for the specific API/flag/
  behavior the breaking-changes list names, don't assume from the
  changelog alone that it applies to us.
- **A component other projects depend on** (Elasticsearch has Arkime as a
  second consumer beyond our own ingest pipeline; a nested Docker daemon
  has whatever connects to it over its exposed API): check *their*
  compatibility too, not just ours. Read their actual source for the
  API/behavior in question if a doc's claim about them seems load-bearing
  for the decision — see the Arkime example below.

### Don't trust a secondary source on a compatibility-critical claim — verify it directly

While migrating Elasticsearch, web research reported that ES 9.0 fully
removes the legacy `_template` API. Arkime's own `db.pl` still calls it
unconditionally with no version gating — if that claim were true, the
migration would have broken Arkime outright. Instead of trusting the
claim, the actual vendored `db.pl` source was read (`docker run --rm
--entrypoint cat ghcr.io/arkime/arkime/arkime:v6-latest /opt/arkime/db/db.pl`),
and Arkime's real `init` command was run against a real, freshly pulled
Elasticsearch 9.5.1 container. It worked — `GET /_template/...` still
returns 200 with real content. The removal claim was wrong (most likely
describing an earlier, walked-back removal plan). Web search is a
starting point for *what to check*, never the final word on whether a
specific breaking change actually applies — confirm state-changing
compatibility claims against the real software before acting on them.

## 4. Verify empirically before committing

For anything more than a trivial patch bump, actually run the new image
against this repo's own logic before pinning it:

- **A service this repo has its own setup/integration script for**
  (Elasticsearch has `arcane/home/honeypot-init/analysis/elasticsearch-setup.sh`; Dionaea has
  `dionaea/log_rotation_patch.py`'s build-time patch) — run that script
  end-to-end against a real instance of the new version, not just
  `docker run` and check it starts.
- **Existing integration tests written against a specific pinned version**
  (`analysis/tests/test_*.sh` hardcode an `ES_IMAGE`) — point them at the
  new digest and run them for real (`sudo bash analysis/tests/test_*.sh`
  — these spin up real containers, not fakes) before changing the actual
  pin. If they still pass unmodified, that's real evidence, not a guess.
- **A daemon something else connects to** (the `docker:*-dind` bump) —
  reproduce the *exact* runtime shape the real consumer uses: same
  env vars (`DOCKER_TLS_CERTDIR=` mattered — omitting it in an early test
  pass produced a TLS-enforcement failure that didn't exist in the real
  config), same flags, then exercise it the way the real consumer would
  (a TCP client connecting from outside the container, not just `docker
  exec` into it).
- **A config-sensitive tool** (`geoipupdate`) — run it with the exact
  real env var set (even fake credentials) and confirm it reaches the
  real failure/success path cleanly, not some unrelated startup error.
  Note for `geoipupdate` specifically: v8.0.0 changed error handling so
  it halts on the *first* per-database error instead of continuing
  through the rest of the run. `arcane/home/honeypot-init/compose.yml` requests two
  editions (`GeoLite2-City`, `GeoLite2-ASN`) in a single run, so a
  transient failure on one can now silently prevent the other from
  refreshing too — worth remembering when diagnosing a stale `.mmdb`.

Always clean up test containers/networks/images afterward
(`docker rm -f`, `docker network rm`, `docker rmi` as needed) — these are
scratch resources, not meant to linger.

## 5. Pin, commit, and deploy

- Pin by digest, matching every other image in this repo — never leave a
  bare tag once a real check has been done (if an existing pin has no
  digest at all, add one as part of the same change, even if the version
  number isn't moving).
- One PR per logically-independent bump (not one giant PR for everything)
  — matches how #1402's own batch was split (a "safe batch" PR for several
  independent patch bumps together, then a separate PR per major-version
  jump, each with its own verification writeup).
- For anything touching **live production data or state** (a datastore
  upgrade, anything with no clean rollback), confirm with the operator
  before merging/deploying, even if the same class of change was already
  approved once earlier in a session. A snapshot/backup immediately
  before is the default; skipping it is the operator's call to make
  explicitly, not an assumption to make on their behalf.
- After deploying, verify live — cluster/container health, and that the
  thing the bump was *for* still actually works end to end (not just
  "the container is running"). For Elasticsearch specifically: cluster
  status green, shard count sane, a real recent document query against
  today's index, not just a health-endpoint 200.

## What NOT to do

- Don't bump a floating `:latest`-style tag to another floating tag and
  call it pinned — resolve an actual digest.
- Don't skip the "does anything else depend on this" check for a shared
  component. Elasticsearch's Arkime dependency was the whole reason the
  9.x hop needed real verification instead of a changelog skim.
- Don't treat "the container starts" as proof of compatibility for
  anything with its own integration surface (a setup script, a dependent
  service, a specific config shape) — start it *and* exercise the real
  path.
