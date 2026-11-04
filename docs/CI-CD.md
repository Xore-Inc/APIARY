# CI/CD and repository automation

The workflows in `.github/workflows` keep public contributions safe without
placing production credentials in GitHub or in this repository.

## Checks

Every push to `main` and every pull request runs:

- the public-repository leak and forbidden-artifact scanner;
- Go formatting and tests for every Go module;
- TypeScript checks and a reproducible Tailwind frontend build;
- Python and shell syntax checks plus high-severity ShellCheck findings;
- Docker Compose validation for the home and VPS stacks;
- actionlint over every workflow (warning-level ShellCheck in `run:` blocks),
  plus a zizmor security audit that fails on anything except the four rules
  #3313's hardening still owns (#3314);

A red run also leaves evidence behind: machine-readable JUnit XML from the
frontend unit, browser, and pytest suites, a retained Playwright report with
per-failure traces, and the Rust test log. See
[Test evidence retained on failure](#test-evidence-retained-on-failure-3319)
below.
- hadolint over every tracked Dockerfile, failing on warnings and errors
  (policy and exemptions in `.hadolint.yaml`, #3320);
- a digest-bound CycloneDX SBOM for the `backend-service` and
  `dashboard-next` images, uploaded as an artifact and kept on the homeserver
  at `/var/image-sbom/`, plus a `trivy sbom` scan over that same file
  (#3321, [below](#digest-bound-sboms-for-the-two-dashboard-images-3321));
- CodeQL for Go, JavaScript/TypeScript, and Python;
- dependency review on pull requests;
- fast-check properties for the dashboard-next appearance cookie
  (9 properties at 100 runs on a pinned seed, inside the ordinary
  `frontend-next` unit job — the file matches `vitest.config.ts`'s own include
  glob, so it costs no extra step, install, or second run). Pinned because a
  property suite whose cases change every run reports "green" for a defect that
  is still there; the nightly's unseeded high-run search is the lane that is
  *meant* to move (#3326, [record](frontend-mutation-pilot.md)).

### Advisory frontend testing pilot (#3326)

`frontend-testing-pilot.yml` runs nightly (`41 4 * * *`) and on
`workflow_dispatch`, and has **no `pull_request` trigger** — the property pass
that PRs depend on is already the one in `npm test` above, and the mutation run
is a measurement rather than a check.

| Job | What it does | Failure means |
|---|---|---|
| `property` | 100-run pinned pass, then a 2000-run `FC_SEED=random` search; opens an issue on a counterexample | a real defect, not a score — a counterexample is shrunk small enough to paste into a generator |
| `mutation` | Stryker over two modules, `continue-on-error: true`, no `thresholds` block | nothing; the run records killed/survived and uploads the report |

The asymmetry is deliberate and is the "no gate" requirement in the two places
it can be expressed. Nothing anywhere reads the mutation score, and there is no
threshold to breach: a number that has already started failing CI has stopped
being a measurement. A property counterexample is the opposite case — it is a
defect with a reproducer, and a scheduled run's own red X is not an alert
anyone is watching, which is why that job files an issue instead (the same
reasoning as #2222 in `diagnostics.yml`).

Both jobs derive their node major from the dashboard-next Dockerfile via
`scripts/node-runtime-major.sh` rather than writing a second copy (#3331), and
both run on GitHub-hosted runners only: a measurement has nothing to buy from
the homeserver, and keeping the pilot off that box costs it nothing.

Container images are built for pull requests. A push to `main` or a version tag
publishes the custom images to the repository's GitHub Container Registry.
Base images are watched for advisories on a weekly cron and on any Dockerfile
change (`image-security-scan.yml`); the two dashboard images additionally get
a package inventory of the built result (#3321).

### CodeQL setup guardrail

`security.yml` uses CodeQL's advanced setup. Keep GitHub's **Settings → Code
security → CodeQL** configuration on **Advanced**, not **Default**: the two
setups cannot process the same analysis, and the resulting failure is
reported as `CodeQL analyses from advanced configurations cannot be processed
when the default setup is enabled`. If that error appears, disable the
repository's default CodeQL setup before changing or rerunning this workflow.

### Trigger, runner, and trust boundary

```mermaid
flowchart TB
  prPush["Pull request<br/>(possibly fork-origin,<br/>unreviewed code)"]
  mainPush["Push to main<br/>(already merged,<br/>reviewed code)"]

  subgraph ghHosted["GitHub-hosted runners — disposable, torn down after the job"]
    direction TB
    quality["quality.yml —<br/>the only checks any PR<br/>ever depends on"]
    containerBuild["Container build<br/>(PR: build only,<br/>main/tag: build + publish to GHCR)"]
    codeql["CodeQL — go / js-ts / python"]
    pages["Branding site build"]
  end

  subgraph ciSelfHosted["honeypot-ci — self-hosted, docker-capable,<br/>not wired to pull_request by default"]
    qualityHome["quality.yml paired jobs + home-flagged<br/>scripts-and-compose rows"]
    containersHome["containers.yml — all image builds"]
    securityHome["security.yml — all CodeQL languages"]
    pagesHome["pages.yml artifact build"]
    imageScanHome["image-security-scan.yml"]
  end

  prPush --> quality
  prPush -->|"PR: build only,<br/>never published"| containerBuild
  prPush --> codeql
  prPush --> pages
  mainPush --> quality
  mainPush --> containerBuild
  mainPush --> codeql
  mainPush --> pages
  mainPush -.->|"those five workflows' ci-target jobs —<br/>only after passing the ci-router<br/>trust gate + heartbeat; pull_request needs<br/>repo variable CI_HOMESERVER_PRS,<br/>and forks can never qualify"| ciSelfHosted
```

**`honeypot-ci` does not see `pull_request` by default, by design.** A
GitHub-hosted runner is a disposable, sandboxed VM torn down after the
job; a self-hosted runner's job runs as a real process on real
home-network infrastructure. A malicious test file in an unreviewed PR
(`os.system(...)`, a crafted Go `TestMain`) would execute wherever that
runner has access — the same reasoning `production-home`'s own deployment
runner (below) already applies. Executor routing is a caller-side job named
`ci-target`, which since #2571 calls the shared
`.github/workflows/ci-router.yml`. Five of the repo's twenty workflows have
one: `quality.yml`, `containers.yml`, `security.yml`, `pages.yml` and
`image-security-scan.yml`. It trusts
push-to-main (already reviewed and merged), the `schedule` and
`workflow_dispatch` (an operator's own machinery); same-repo pull
requests need the repository variable `CI_HOMESERVER_PRS=true`, and fork
PRs are excluded regardless of that variable — defense-in-depth against a
compromised contributor account, not just fork-origin PRs.

## Base-image CVE gate (#3501)

`.github/workflows/image-security-scan.yml` is a **blocking** gate: it runs
`trivy image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed` over
every base image `scripts/list-docker-base-images.py` emits, and **fails the
build** if any image with fixable CRITICAL/HIGH findings has no written
exemption.

It was report-only from introduction until #3501, which is the decision this
section records.

### Three outcomes, deliberately not two

trivy exits non-zero both for "found CVEs" and for "could not pull this
reference at all". Those are opposite findings, so the workflow classifies
them rather than merging them, and each lands somewhere different:

| outcome | gate | why |
|---|---|---|
| fixable CRITICAL/HIGH, **no** reason | **fails** | this is the backlog |
| fixable CRITICAL/HIGH, reason in `ACCEPTED_CVES` | passes, `::notice` | an argued, reviewed exception |
| reference would not resolve | `::warning`, **does not fail** | we measured nothing, which is a coverage gap (#2763) |

The third row is the one most likely to be "fixed" into the wrong shape. An
unresolvable image is neither vulnerable nor exempt — we did not scan it — so
failing on it trains operators to ignore the gate, and exempting it silently
is the dishonest direction. It stays visible as a gap, and it is the reason
`UNSCANNABLE` in `list-docker-base-images.py` exists: an image that can never
resolve is withheld from stdout with a written reason and reported on stderr.

### What an exemption has to be

An exemption is a claim that **this repo cannot fix the finding**. If a
patched artifact exists, the fix is to bump the pin — not to write an
exemption. So `ACCEPTED_CVES` reasons state the constraint that makes an
image immovable *despite* a published fix: a build stage nothing inherits, a
pinned on-disk format, a vendor with no rebuild.

"No patched build is published" does not belong there unless a scan showed no
`FixedVersion`. trivy reporting a `FixedVersion` is upstream saying a patch
exists, and a reason that contradicts it is a fabricated exemption. An image
whose scan could not run is **UNVERIFIED** and is left failing; that is the
honest state, and guessing a count is worse than a red gate.

### Why the keys are digest-pinned

A key is a reference the script actually emits, matched exactly. Both halves
matter, and the earlier attempt at this gate broke both:

- **Bare tags cannot match.** `main()` emits digest-pinned refs for 58 of the
  67 images it walks. A key spelled `python:3.12-slim` compared against
  `python:3.12-slim@sha256:60deed…` never fires. 30 of that attempt's 40
  keys were inert like this — entries that read like exemptions somebody had
  argued for while covering no image at all.
- **Exact matching is what makes them expire.** Each reason describes the
  artifact that was measured. When a Dependabot bump moves the digest, the key
  stops matching and the gate re-applies to whatever now sits at that tag. A
  bare-tag key would survive every bump forever, carrying a stale judgement
  onto images nobody looked at.

`scripts/tests/test_3501_base_image_cve_exemptions.py` holds this: every key
must be a reference the script emits *now* (so deleting a Dockerfile cannot
leave an entry exempting nothing), and the match must not widen to a
neighbouring ref.

### Adding an entry

1. Scan it and read the actual numbers:
   `trivy image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed <ref>`
2. Try to move it. If a patched tag exists, bump the pin — that is the fix.
3. Only if it genuinely cannot move, add a key spelled exactly as
   `list-docker-base-images.py` prints it, with a reason that names the
   constraint and cites the scan.
4. `python3 scripts/tests/test_3501_base_image_cve_exemptions.py` will reject
   a dead or over-broad key.

## Testing conventions

Python and shell tests live in a sibling `tests/` directory next to the code
they test (e.g. `ml-worker/tests/`, `analysis/ghidra/worker/tests/`,
`arcane/home/honeypot-payload-analysis/analysis/yara/tests/`), not flat alongside it. When adding a new Python or
shell test, put it under the nearest `tests/` directory for its component,
creating one if none exists yet.

Go tests stay co-located with the package they test (`foo.go` +
`foo_test.go` in the same directory), following standard Go convention
rather than the `tests/`-directory pattern above. A meaningful fraction of
this repo's Go tests are white-box: they construct unexported types
directly and call unexported methods (e.g. dashboard tests routinely build
`&store{}` by hand). A `*_test.go` file only gets that access when it
declares the same package as the code under test, which requires it living
in the same directory — moving Go tests to a separate top-level directory
would force every one of them into an external `package foo_test`, losing
that access or requiring the production code to newly export internals
just for tests to reach them. `go test` never ships in a built binary, so
`_test.go`'s own suffix already keeps tests out of production artifacts
without a directory move. Go stays co-located; only Python and shell use
`tests/`.

## Dependabot

Dependabot checks GitHub Actions, Go modules, Cargo, npm, pip, and Docker base
images every week. Patch and minor Dependabot pull requests are approved and
placed into GitHub's auto-merge queue, where they wait for the `main` ruleset's
required checks (below). Major upgrades always require manual review, and so
does any minor bump of a `0.x` dependency: semver gives `0.y` no stability
promise, but `dependabot/fetch-metadata` still labels it `semver-minor`
(#3287 `rand` 0.9 → 0.10 and #3289 `sha2` 0.10 → 0.11 broke the backend
build that way, #3311).

Auto-merge only waits if something is required. With no protection on the
base branch, GitHub considers a PR mergeable at once and `gh pr merge --auto`
merges it on the spot, before CI has run. That is what happened before the
ruleset existed (#3311).

The repository setting **Allow auto-merge** and the Actions permission
**Allow GitHub Actions to create and approve pull requests** must remain
enabled for this workflow.

## `main` ruleset (#3311)

`main` is protected by the repository ruleset **main protection**:

- changes land through a pull request (no direct pushes), with no required
  approving review (single maintainer);
- no force-push and no branch deletion;
- these status checks must pass, and are the only required ones:

| context | workflow | what it aggregates |
|---|---|---|
| `Quality gate` | `quality.yml` | every Quality job pair, homeserver or GitHub-hosted twin |
| `Containers gate` | `containers.yml` | the router and every image build row |
| `Go formatting and tests` | `quality.yml` | Go fmt + tests, either executor |
| `Scripts and Compose` | `quality.yml` | the `scripts-and-compose` job matrix |

Individual jobs are never required directly: their names change with the
executor (`… (GitHub-hosted)` on fallback days), and a required context that
never reports leaves every PR pending forever. When adding a job pair to
`quality.yml`, add both twins to `quality-gate`'s `needs:` and the pair name
to its `pair` loop, or the new job is not gated. A skipped job counts as
passing for GitHub, which is why each gate checks results itself instead of
relying on skip semantics.

Required checks are strict=false (a PR does not have to be rebased onto the
latest `main` before merging). In an emergency, a repository admin can set the
ruleset's enforcement to *Disabled* (Settings → Rules) and must re-enable it
afterwards; there is deliberately no standing bypass actor, since automation
merges with the owner's token.

## Main health watch (#3324)

`main-health-watch.yml` runs after every Quality/Containers run on `main`
and hourly (`scripts/main-health-watch.py`):

- **Red:** when the newest completed run of either workflow on `main` failed,
  it opens one `main-red-alarm` issue naming the failing jobs, the first red
  and last green commit, and the commits in between. It comments again only
  when the failing head changes, and closes the issue itself once both are
  green. It never reverts or re-runs a failed run.
- **Untested:** merges made by `github-actions` (Dependabot auto-merge) start
  no push runs, because `GITHUB_TOKEN` events don't trigger workflows. That's
  how the 2026-09-25 breakage sat on `main` with no red run at all (#3311).
  When `main`'s head is over an hour old and a watched workflow never ran on
  it, the watch dispatches that workflow on `main` (`workflow_dispatch` is
  the exception `GITHUB_TOKEN` may start), and the next sweep judges it.

Replay any past moment without side effects:
`GITHUB_REPOSITORY=Xore/APIARY python3 scripts/main-health-watch.py --before 2026-09-25T10:00:00Z`.

## Test evidence retained on failure (#3319)

A red Quality run used to leave one thing behind: the log. Playwright traces,
screenshots, and machine-readable results were all discarded, and a lane that
was router-skipped or path-filtered looked identical in the checks list to one
that ran and passed. Both are now fixed.

### Artifacts

Every upload uses `actions/upload-artifact` pinned by SHA, with a 7-day
retention — long enough that the evidence is still there when a red run is
picked up the following week, short enough that a busy `main` does not
accumulate them indefinitely. The nightly mutation pilot (#3326) is the one
exception at 14 days: it runs once a day rather than once a PR, and its report
is the record a later ratchet decision is read off, so the gap between two runs
has to be coverable by a reviewer who was away for a fortnight.

| Lane | Artifact | Uploaded |
| --- | --- | --- |
| Dashboard frontend (next) | `frontend-next-unit-junit.xml` | `always()` |
| Dashboard-next browser matrix | `playwright-junit.xml` | `always()` |
| Dashboard-next browser matrix | `playwright-report/` + `test-results/` (HTML report, per-failure traces and screenshots) | `failure()` |
| Dashboard backend-service (Rust) | `cargo-test.log` | `failure()` |
| `scripts-and-compose` pytest rows | `ml-worker-junit.xml`, `auth-events-worker-junit.xml` | `always()` |
| Frontend mutation pilot (nightly) | `frontend-mutation-report` (`reports/mutation/` + `stryker.log`) | `always()`, 14-day retention |

JUnit XML is uploaded on `always()`, not only on failure, because it is the
record of *what ran* rather than of what the exit code happened to be. The
Playwright report and the Rust log are `failure()`-only: on a green run they
hold nothing worth storing.

The report files are all written under `.ci-artifacts/` at the workspace root,
which is git-ignored. `playwright-report/` and `test-results/` stay where the
Playwright config already put them inside `frontend-next/`.

The Rust lane gets a log rather than JUnit XML on purpose: `cargo` has no
built-in JUnit reporter, and its per-test result stream is only reachable
through the unstable `--format json`. Retaining the full log is honest about
that; converting it to XML here would mean a hand-rolled translation that
could itself misreport a result.

### Names and paths

The table above names *files*; the artifact each one lands in is named
`<that name>-${{ github.run_id }}-${{ github.run_attempt }}`, and no upload in
`quality.yml` sets `overwrite`. Two rules, both of them learned the hard way:

- **`overwrite: true` is not "the newest run wins".** It deletes an existing
  artifact of that name before uploading the new one, so on a name two runs
  share it means "the second uploader destroys the first's evidence", and the
  name then resolves to whichever run got there last — not the one a reader
  is looking at. A per-`(run, attempt)` name is claimed exactly once, so there
  is nothing to overwrite and no name an earlier run on the same ref could
  poison. The attempt number is part of the name because a GitHub re-run of a
  run keeps its `run_id`; `run_id` alone still collides on the second attempt
  of the same run. Nothing in the tree downloads these by name, so the suffix
  costs no consumer.
- **Paths name files, never the `.ci-artifacts/` directory.**
  `actions/upload-artifact` v4.4+ skips hidden paths unless told otherwise, and
  a directory whose own name begins with `.` is hidden — so `path:
  .ci-artifacts/` uploads *nothing*, logging "No files were found with the
  provided path" and, under `if-no-files-found: ignore`, saying so silently.
  That is exactly what the two `scripts-and-compose` pytest rows did from
  #3319 until this was fixed: a green run logged 330 ml-worker tests passed
  and pytest's own "generated xml file" line, and the upload step directly
  below it still found no files. Naming each report also bounds what can be
  in it: the contents are the reports the lane's own reporter wrote, not
  whatever happens to be sitting in a workspace-relative directory that
  anyone with repo read access can download for the next 7 days.

### The switch

Both reporters are opt-in through a single environment variable,
`CI_ARTIFACTS_DIR`, which the workflow sets and nothing else does:

- `arcane/home/honeypot-dashboard/frontend-next/vitest.config.ts` adds
  `junit` alongside the existing `default` reporter and writes
  `frontend-next-unit-junit.xml` when it is set.
- `arcane/home/honeypot-dashboard/frontend-next/playwright.config.ts` inserts
  a `junit` reporter *between* the existing `github` and `html` reporters, so
  inline PR annotations and the browsable report are unchanged.

Gating on the variable rather than on `CI` is deliberate: the same `npm test`
and `npm run test:browser` a developer runs locally, and that `deploy.yml`
runs, keep their console output and write no report file.

`trace: "retain-on-failure"` and `screenshot: "only-on-failure"` were already
set in the Playwright config (#2034). What was missing was uploading what they
produced, which is what the `failure()` step above does.

### Lane summary

Each aggregate job (**Go formatting and tests**, **Scripts and Compose**,
**Quality**) renders a table into the run's step summary via
`scripts/ci-lane-summary.py`, so a reader can see which executor ran and which
twin the router skipped without opening the log. An executor pair (the
homeserver job and its `-cloud` fallback) collapses to one row that names the
leg that ran. The script reads `${{ toJSON(needs) }}` and is a pure function
of it.

A skip is not a pass. The script exits non-zero when a lane has no passing
result behind it at all — a pair where *neither* twin reported is called out as
*neither executor reported a result*, which is the state that used to read as
green. One legitimately-skipped lane is accounted for explicitly: the
`--allow-skip` flag carries a reason, and Quality passes
`ai-attribution:pull_request only (#3329)` on non-PR events, matching the rule
the gate itself already encodes.

The script is covered by `scripts/tests/test_ci_lane_summary.py`, which runs
in the `scripts-and-compose` matrix's `scripts/tests suite` row.
## The `/api` contract and its weekly fuzz job (#3325)

`backend-service` publishes an OpenAPI 3.1 contract at
`arcane/home/honeypot-dashboard/backend-service/openapi.json`: 132 paths,
141 operations — 128 `/api` paths and 137 `/api` operations behind the
token, plus the four public probes `/healthz`, `/livez`, `/readyz` and
`/metrics`. It is generated, not hand-edited: the source of truth is the
`#[utoipa::path]` annotation on each handler plus the route table in
`arcane/home/honeypot-dashboard/backend-service/src/lib.rs`, rendered by
`src/openapi.rs` (whose `render()` reconciles the derived document with
the committed one — the six transform steps are documented in that
module) and emitted by

```sh
cd arcane/home/honeypot-dashboard/backend-service
cargo run --bin openapi > openapi.json
```

A shared parameter or request-body shape goes in
`arcane/home/honeypot-dashboard/backend-service/src/contract.rs` behind
`contract_schema!`; the annotations reference it rather than restating it.

**Three gates keep it honest, and they fail in different directions on
purpose:**

- **`cargo test`** runs two drift tests in `src/openapi.rs`.
  `contract_covers_every_router_route` reads `src/lib.rs` and fails if the
  router and the contract disagree about which `(path, method)` pairs exist
  — a route added without a contract row is the direction that rots, since
  it silently drops a fuzz target. `checked_in_contract_is_current` fails
  if the committed `openapi.json` is not what the module renders.
- **`OpenAPI contract is not stale (#3325)`** in both `quality.yml` backend
  jobs runs the same generator as a `diff -u`, because a test failure says
  "stale" while the diff says what changed.
- **`weekly-schemathesis.yml`** runs Mondays at 04:23 UTC and on
  `workflow_dispatch` (`max_examples` and `base_url` are both inputs). It
  boots the service against a single-node Elasticsearch service container —
  without a cluster every ES-backed route answers 502 and the run measures
  nothing — and makes three passes:

  - `scripts/check-api-auth-tier.py` is the **only** step that can fail the
    job. Every operation the contract secures must answer 401/403 with no
    token, and `/healthz` and `/metrics` must not. It is a script and not
    schemathesis's `ignored_auth` check because `ignored_auth` skips any
    operation the contract declares public: demoting a live route in the
    document turns the check green while the route keeps serving
    anonymous callers. Run it against any deployment with
    `python3 scripts/check-api-auth-tier.py --base-url http://host:8081`.
  - two `schemathesis run` passes, unauthenticated and with a fixture
    service token, both `continue-on-error: true` and both reporting into
    uploaded JUnit artifacts. These are **advisory**: this API validates
    aggressively and returns 400 for inputs no schema can distinguish from
    nonsense, so a hard gate would be red on its first run and train
    everyone to ignore it. The value is the standing record, so a change in
    the record is visible.

  The pass reports its finding classes by name, and the two that indict the
  *document* rather than the service — `Undocumented HTTP status code` and
  `Undocumented Content-Type` — are the number worth watching. Each of
  those was a real omission in the first version of the contract: `415` and
  `422` from axum's `Json<T>` rejection on all 25 body routes, `400` from
  its `Query<T>` rejection, four `services` routes answering JSON errors
  declared as `text/plain`, and a `text/plain` export declared as JSON.
  Fix those by editing the handler's `#[utoipa::path]` annotation (or the
  shape it names in `src/contract.rs`) and regenerating — never by
  suppressing the output.

`/api/v1/live` is excluded from the fuzz passes and skipped by the auth
script, and the contract marks it `x-endless-stream: true`. Its body never
ends, so probing it on a service with auth open would hang the run instead
of reporting the leak.

## Pull request workflow

### No AI attribution (#3329)

Commits, PR titles/bodies and issue text never credit an AI assistant. The
Quality job **No AI attribution in PR metadata** (`scripts/check-ai-attribution.py`)
fails a PR whose commits, title or body contain one of these:
- an assistant `Co-authored-by` trailer;
- an `@anthropic.com` / `@openai.com` address;
- an assistant session trailer or link (`Claude-Session:`, `claude.ai/code/session_…`);
- a "Generated with <coding assistant>" footer.

Mentions are fine: talking about an LLM, the `claude` theme palette, or
"generated by qwen3:14b" in a benchmark result. Fix a hit by rewording the
commit (`git rebase -i`, then force-push) or editing the PR text. Dependabot
PRs are exempt. It feeds `Quality gate`, so it is required.

### Stacked PRs and `Closes #N` (#2922)

GitHub only auto-closes a linked issue when the PR that carries `Closes #N`
merges into the repository's **default branch** (`main`). A stacked PR —
one whose base is another feature branch, not `main` — can carry a perfectly
correct `Closes #N` line that never fires: by the time the parent branch
merges into `main`, that `Closes` line was already consumed by the earlier
merge into the (non-default) parent branch. This is not a GitHub bug or a
malformed keyword; it is a predictable property of stacking, and it costs a
real fix a real closed issue every time it happens (#2749 and #2750, both
merged and fixed for two days before a later pass rediscovered them as if
still open, because the tracker still showed them open).

**Policy, in order of preference:**

1. **Prefer not to stack.** Rebase each independent fix onto `main` and open
   PRs sequentially instead of onto each other. This is the only option that
   needs no follow-up step.
2. **If a stack is unavoidable** (a later fix genuinely depends on an
   earlier, not-yet-merged one), put every `Closes #N` for the whole stack
   on the **root PR** — the one PR in the stack whose base is `main` — not
   on the children. List every issue the stack resolves there, even the
   ones a child PR's own commits actually fixed.
3. **If a child PR already shipped with its own `Closes #N`** (as #2798 and
   #2799 did), treat that line as decoration once the child merges into a
   non-`main` base: it will not fire. Close the issue by hand at the same
   time the child PR merges, don't wait for the parent to reach `main`.

**Mandatory check at the end of every merge batch:** for each PR merged in
the window, confirm every issue it claims to close (via any GitHub closing
keyword: close/closes/closed, fix/fixes/fixed, resolve/resolves/resolved) is
actually in the `closed` state — not just that the PR merged cleanly.
`scripts/check-merged-prs-closed-issues.py` automates this (see its
docstring for usage); run it after every merge wave, not only at the end of
a round, since the failure mode is a *quietly done* issue inflating the next
census, and the cost of catching it is one script run.

## Home deployment

Home deployment uses a dedicated self-hosted runner with these labels:

```text
self-hosted, linux, x64, honeypot-home
```

Attach the runner to the protected `production-home` environment. Its service
account needs write access to `/opt/stacks/apiary` and permission to
run Docker Compose. The workflow preserves the server's `.env` and runtime
state, synchronizes the repository into `/opt/stacks/apiary`, and validates
compose files — it no longer deploys any home stack itself. What actually
deploys is described below.

Install or repair the runner with
[`../scripts/github-ci-runner/install-deploy-runner.sh`](../scripts/github-ci-runner/install-deploy-runner.sh)
(`sudo ... --repo Xore/APIARY`) -- registers the runner and, precisely and
idempotently, chowns exactly the directories deploy.yml itself writes into,
never anything under a `state/`, `dashboard-state/`, or `logs/` subtree
anywhere in that list (#1143: a manual, broader `chown -R` swept those
container-owned paths too, crash-looping Keycloak and Filebeat until fixed
live -- this script is the precise command that should be run instead of
reasoning through the exclusion list by hand next time).

`sudo ... --helpers-only` (#3312) applies just the root-owned helper scripts
under `/opt/github-ci-runner-helpers/` and the sudoers grant for them, then
exits. Same narrow-mode idea as `install-ci-runner.sh`'s `--build-only`. Use
it when the only thing missing on the host is a grant a merged PR added
(the Diagnostics source-health helper, most recently): it changes no group
membership, chowns nothing, registers nothing, and never stops or restarts
the runner service -- so it cannot kill the job the homeserver is in the
middle of running. Group membership is deliberately not part of it, because
supplementary groups only reach the runner across a service restart.

Require a manual reviewer on `production-home`; never accept pull-request code
on this production runner.

**#2745: never pass an explicit `--name` that collides with the CI fleet's
name.** `install-deploy-runner.sh` defaults to `${HOSTNAME}-home` specifically
so its identity can never collide with `install-ci-runner.sh`'s
`${HOSTNAME}-ci` default. On 2026-08-31 the deploy runner's registration was
found silently clobbered: both `/opt/github-ci-runner/.runner` and
`/opt/github-deploy-runner/.runner` claimed the identical `agentName:
"supermicro"` (the bare hostname, not either script's own `-ci`/`-home`
suffixed default) -- meaning some prior run of the deploy-runner script was
given an explicit `--name` override matching the CI runner's plain hostname,
and GitHub keeps only one live registration per name. The deploy runner's
unit was left `disabled` as a result, and the Diagnostics workflow's `home`
job (and any other `honeypot-home`-targeted job, including `deploy.yml`
itself) queued forever with no online runner able to claim it. Fixed by
re-registering under the script's own unmodified default name
(`supermicro-home` on this host) rather than reusing a colliding name --
always let `--name` default unless there is a specific reason to override
it, and never reuse the bare `${HOSTNAME}` the live CI fleet's first runner
is currently registered under (an earlier `--name` override; the script's
own default is `${HOSTNAME}-ci`).

Run [`../safe-update.sh`](../safe-update.sh) (`STACK_DIR=/opt/stacks/apiary`)
before a manual deploy to snapshot the current git commit SHA, any
uncommitted config drift, and every `.env` file -- a lightweight, read-only
"about to deploy, keep a snapshot in case this is bad" step, distinct from
[`../factory-reset.sh`](../factory-reset.sh) (docs/RECOVERY.md), which is
for an already-broken stack and can stop/wipe state.

Each #258 split adds at least one new Docker bridge network (a project's
implicit default network, or an explicit private one like `dionaea_net`).
The homeserver's own Docker daemon exhausted its built-in default address
pools (`172.16.0.0/12` and `192.168.0.0/16`) partway through this split --
every one of the ~30 pre-existing Compose projects on that host already
claimed a chunk. Fixed once, at the host level, not per-stack: `/etc/docker/
daemon.json` now sets `"default-address-pools": [{"base": "10.96.0.0/12",
"size": 24}]` (4096 possible /24 subnets, chosen not to overlap the
existing `10.8.0.0/24` WireGuard tunnel or `10.10.10.0/24` sandbox network),
applied with `systemctl restart docker`. Not something this repository's
CI can apply -- if a fresh homeserver ever exhausts its own default pools
again, the fix is the same `daemon.json` edit plus a daemon restart, not a
per-stack workaround.

### What deploy.yml actually runs (since #1502)

> **Status.** The sections below this one were rewritten when the home
> stacks' deployment moved to Arcane-managed Git syncs (#1502). Anything
> still describing a deploy-loop "deploying" or "sequencing" sensor stacks
> would be pre-cutover fiction — this file should mirror `deploy.yml`'s own
> header comments, which state the same contract line by line. Where it and
> [ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md) disagree about deployment,
> ARCANE-GIT-SYNC.md wins; file a gap against #1502 if they diverge.

```mermaid
flowchart TB
  approve["Operator approves<br/>production-home environment"]
  runner["Self-hosted honeypot-home runner<br/>polls GitHub, pulls the job"]
  sync["rsync into /opt/stacks/apiary<br/>(--delete-delay, host-owned paths<br/>preserved -- see table below)<br/>+ compose.yml copy + root-config check"]
  ghidra["ghidra-worker re-sync<br/>(host-level systemd unit,<br/>skipped if not installed)"]
  arcaneBootstrap["honeypot-arcane bootstrap<br/>(up -d when its .env exists,<br/>sync-only otherwise)"]
  validate["Validate every manifest stack's<br/>compose file (placeholder-fill<br/>for required secrets)"]

  approve --> runner --> sync --> ghidra --> arcaneBootstrap --> validate
```

That is the complete list. What puts a changed sensor/persona/dashboard
stack on the host lives entirely in Arcane's Git-sync machinery — see
[ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md) for the full contract (its
non-obvious cornerstones: creating a sync *is* an initial deploy, a sync
materializes files without redeploying — live `redeploy_after_sync`
defaults to 0, though the manifest schema cannot express it — and deploys
are manual. #1507's tag-promotion / `production`-pointer policy was only
half activated: #1943 (2026-08-25) put `branch: "production"` and three
`autoSync: true` flags into `arcane/manifests/home-production.json`, so all
39 entries now name that branch rather than `main` — but the live store
still reads `auto_sync = 0` on every row, and `origin` has no
`refs/heads/production` for the pointer to name, so nothing follows a
promotion and deploys stay manual; ARCANE-GIT-SYNC.md's promotion
section carries the live-state evidence).
This workflow deliberately stopped touching those directories entirely:
running an rsync/build loop alongside Arcane's own sync would put two
independent writers in a race for the same on-host directory, the exact
failure class #1502's migration review flagged. What survived here is a
cheap validation gate so a broken compose file fails visibly at review
time instead of surfacing mid-sync on the host.

`honeypot-init`'s marker mechanism (`state/init-markers/*.done`, polled at
container entrypoint rather than via Compose-level `depends_on`) still
governs startup order between sensors and their bootstrap jobs — but on
today's topology that ordering plays out inside Arcane's sync/deploy flow,
not across steps of this job. See "Home container interaction map" in
`ARCHITECTURE.md` for the why; the dashboard redeploy mechanics live in
its own section below, unchanged by any of this.

### How files reach the homeserver

The home job runs **on the homeserver itself**. GitHub does not open an inbound
SSH connection to the home network:

1. The permanently installed Actions runner polls GitHub for an approved job.
2. `actions/checkout` downloads the selected repository commit into the
   runner's temporary work directory.
3. Local `rsync` copies that checkout into `/opt/stacks/apiary`.
4. The same step copies the root `docker-compose.yml` to `compose.yml`
   (the filename Arcane manages) and tightens `.env`'s mode to `0600`
   if the file exists.
5. `docker compose -f compose.yml config --quiet` validates the root
   configuration — a pure syntax gate, not a deploy: the root file has
   carried `services: {}` since the last monolith service moved out
   (#258, updated by #1502).
6. Nothing comes up here. With zero services under the root file there is
   no stack this workflow could reconcile — what actually deploys a changed
   stack is Arcane's Git-sync machinery ([ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md),
   "The model" above), plus this workflow's one remaining deployment-adjacent
   action: the conditional host-level nsenter re-sync of the ghidra worker's
   source tree described below.

The runner therefore needs outbound HTTPS access to GitHub, local filesystem
access to the Arcane-managed stack, and access to the Docker socket. It does not need a
publicly reachable SSH port.

The synchronization uses `--delete-delay`, so repository-controlled files
removed from Git are removed from the destination near the end of a successful
transfer. These host-owned paths are explicitly preserved:

This table mirrors the step's own `--exclude` list exactly (`deploy.yml`,
"Synchronize APIARY source"):

| Excluded path | Reason |
|---|---|
| `.env` | production addresses, credentials, and local settings |
| `logs/` | sensor and imported VPS logs, plus the dashboard's own serving-tier app logs (#1972: `dashboard-backend*/`, `dashboard-bff/`) |
| `state/`, `dashboard-state/` | application checkpoints and state |
| `sandbox/results/` | runtime malware-analysis output |
| `analysis/geoip/` | whole directory, not just `*.mmdb`: nothing under it is git-tracked, and geoipupdate (a root-owned container, #1258) writes a root-owned `.geoipupdate.lock` into its root-owned directory — the runner user cannot unlink that, so any narrower exclude broke every deploy with rsync exit 23 once the geoip-update profile ran (#1226) |
| `analysis/ghidra/revdeck/`, `sandbox/windows/packer/pxe/ipxe*` | hand-vendored or build-generated on the host, untracked in Git (`revdeck-proxyfix` doc comment; `prepare-pxe.sh`) — without excluding them, `--delete-delay` either fails outright (populated directory it can't recursively delete) or silently deletes a hand-built ipxe/webui tree on every deploy |
| `.git/`, `.github/` | not needed by the deployed stack |

The runner's service account, rather than the workflow YAML, determines the
effective host permissions. Register it only on the trusted homeserver and do
not give the `production-home` environment to pull-request workflows.

### honeypot-init

`arcane/home/honeypot-init/compose.yml` runs as a second, separate Arcane-managed stack at
`/opt/stacks/honeypot-init`, not as part of `APIARY`. It holds the
one-shot bootstrap jobs (log directory ownership, persona seeding,
Elasticsearch/Kibana/Arkime first-run setup) that used to live in the main
compose file; see that file's header for the full reasoning (#111). It
reaches the host through the same Arcane-managed sync machinery as every
manifest stack now: its one-shot jobs write the `state/init-markers/*.done`
files other stacks' dependents block on at container entrypoint, so its
initial deploy has to land before theirs — a rollout that got this backwards
once hung for 29 minutes waiting on markers that could not exist yet.

Its `.env` is created once by hand on the homeserver and is never touched by
this workflow — `ARKIME_ADMIN_PASSWORD` and `ARKIME_PASSWORD_SECRET` in it
must be kept identical to the same two values in `APIARY`'s `.env`,
and an automated sync has no safe way to verify that a value it did not set
is still correct.

### honeypot-conpot (#258 proof of concept)

`arcane/home/honeypot-conpot/compose.yml` runs as a third, separate Arcane-managed stack at
`/opt/stacks/honeypot-conpot`: the six Conpot personas (base S7-200,
S7-1200, S7-1500, IEC104, Guardian AST, Kamstrup) split out of
`APIARY`'s monolithic compose file, as a proof of concept for #258.
It has no hard ordering requirement against anything else:
each persona polls its own marker file rather than joining a compose
`depends_on` chain, so bringing the stack up through its Arcane-managed
sync never blocks on or gates another project either way. See `arcane/home/honeypot-conpot/compose.yml`'s own header for
what this proved about #258's open questions (no external networks/volumes
needed for a standalone honeypot persona; `autoheal`, which watches by Docker
label rather than by compose project, needs no changes at all).

Log directories (`logs/conpot*`) and the `state/init-markers` mount are
pre-existing host paths the "Synchronize APIARY source" rsync step already
preserves; this stack does not create or own them, and has no `.env` of its
own.

### honeypot-cowrie, honeypot-multipot, honeypot-http, honeypot-dnp3 (#258)

Four more standalone honeypots, split the same way as `honeypot-conpot` and
for the same reason: each has no `depends_on` on any other service and its
own fully private network, so no external network/volume treatment is
needed. `arcane/home/honeypot-http/compose.yml` covers two services (`http-honeypot` and
`api-honeypot`) in one stack -- they already share one build context and are
already treated as one logical unit elsewhere (`scripts/reset-logs.sh`'s
`http` target covers both). Synced through Arcane the same way as
`honeypot-conpot`; all four are otherwise identical in shape. Same
log-directory/`.env` posture as
`honeypot-conpot` above.

### honeypot-dashboard (#258)

`arcane/home/honeypot-dashboard/compose.yml` runs as its own Arcane-managed stack at
`/opt/stacks/honeypot-dashboard`; its own header lists the current service
inventory (the legacy Go `dashboard` it once led with is gone — #1659 —
and #1622 has since moved the original `backend-service` out to its own
stack below). What drove keeping this tier in one project originally was
that its members could not take the "own fully private network"
treatment: they resolve `elasticsearch` and `filebeat` by service name
over the shared `honeynet` network, and read/write named Docker volumes
other stacks also touch -- `dionaea-lib`/`yara-results`
(`arcane/home/honeypot-dionaea/compose.yml`'s `dionaea` and
`arcane/home/honeypot-payload-analysis/compose.yml`'s `yara-scanner` write there,
these services only read) and `dashboard-state` (shared both ways:
the payload-analysis workers read/write retained script payloads under
`/payloads/scripts`, the same subtree these services'
`SCRIPT_PAYLOAD_DIR=/state/script-payloads` writes). Those resources are
declared with an explicit shared `name:` in every compose file that
touches them, the same mechanism
`honeynet`/`es-data`/`evebox-config` already use to stay shared between
projects.

There is no Compose-enforced ordering in any of this — none of the shared
resources are `external: true`, so whichever project touches them first
just creates them — but standing the analysis plane up before this stack's
first start (its importer/worker tiers read the same Elasticsearch
instance) means real data to show immediately instead of booting against
empty indices. On today's topology that ordering lives in the operator's
cutover sequence ([ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md), "Cutover
procedure"), not in a workflow file. `services-adapter-socket` was
originally left private/unnamed to this stack (grepped every compose file
at the time to confirm nothing else referenced it); #1622 (below) added a
second consumer in a different project, so it now carries an explicit
shared `name:` too, same mechanism as the other three.

Per explicit instruction, this split did not preserve `dashboard-state`
across the cutover -- the new stack starts with a fresh volume, and any
alert/intelligence history in the old one is gone.

Everything else that was still monolithic as of the earlier revision of
this section (`dionaea`, `payload-dedupe`, `yara-scanner`, and the Tanner
group) has since split out too -- see the `honeypot-dionaea`,
`honeypot-payload-analysis` and `honeypot-tanner` sections below. Nothing
remains in `APIARY`: the root `docker-compose.yml` is `services: {}`.

#### Dashboard redeploy (single replica; #266 rolling pair retired, #1659 legacy `dashboard` removed)

The dashboard runs one replica (per Xore). The legacy Go `dashboard` service
and `scripts/deploy-dashboard-rolling.sh` that redeployed it are both gone
(#1659) -- `dashboard-next` is the only tier now, and redeploying it (like
`backend-service`, `backend-service-mounted`, and `backend-worker`) is a
plain build + recreate from each stack's own directory, no wrapper script:

```bash
cd /var/dockge/stacks/honeypot-dashboard
docker compose build dashboard-next && docker compose up -d dashboard-next
```

The brief recreate window is accepted on this single-operator deployment;
Traefik's active `/healthz` check (vps/traefik/dynamic.yml) fails fast during
it instead of hanging connections.

### honeypot-dashboard-backend (#1622)

`arcane/home/honeypot-dashboard-backend/compose.yml` runs as its own
Arcane-managed stack at `/opt/stacks/honeypot-dashboard-backend`, carrying
just the modernization-port `backend-service` (moved out of
`honeypot-dashboard` above, #1608's Rust request/response tier) so it can be
restarted/redeployed without touching `dashboard-next` or anything else in
the combined stack -- the deployment-layer counterpart to #1608's
`SERVE_MODE`/`BFF_INTERNAL_URL` cross-host application-code work.
`backend-service-mounted`, `backend-worker`, `backend-worker-importer`,
`backend-worker-enrichment`, and `dashboard-next` are unaffected and stay in
`honeypot-dashboard`'s own compose file; splitting those out is further
work, not part of #1622.

`backend-service` still resolves `dashboard-next`'s
`BACKEND_URL=http://backend-service:8081` (and vice versa) because both
stacks attach to the same explicitly-named `honeynet` bridge -- the same
cross-project DNS mechanism described above. It also still mounts
`dashboard-state`, `dionaea-lib`, and (new as of this split)
`services-adapter-socket` by explicit shared `name:`, so it reads/writes the
same underlying volumes as before the move.

The Rust crate source (`backend-service/`) was **not** moved -- only this
compose service definition -- so the new stack's `build:` context reaches
into the sibling `honeypot-dashboard` directory
(`../honeypot-dashboard/backend-service`). This is a considered choice, not
an established repo pattern (no other `arcane/home/` stack references a
build context outside its own directory): it works because Arcane's
directory-aware sync materializes every stack under the same parent
(`/var/dockge/stacks/<name>/`, see [`ARCANE-GIT-SYNC.md`](ARCANE-GIT-SYNC.md)),
so the relative path resolves correctly as long as both stacks stay synced
to the same host -- true of the current single-host topology, but it
reintroduces a build-time coupling to `honeypot-dashboard`'s own directory
that genuine cross-host deployment (the motivating case for both #1608 and
#1622) would need to resolve first, e.g. by relocating the crate source to
a path both stacks can reach independently. Flagged as a follow-up, not
resolved by this split.

`arcane/manifests/home-production.json` carries this stack's own
`honeypot-dashboard-backend` entry (`syncDirectory: true`,
`arcane/home/honeypot-dashboard-backend/compose.yml`) so both
`scripts/install-homeserver.sh`'s `step_arcane_import_stacks` and the `home`
job's manifest-driven compose-validation loop pick it up the same way as
every other stack -- see `ARCANE-GIT-SYNC.md` for what actually triggers
Arcane to sync/deploy a manifest entry (creating the sync is a manual,
operator-triggered API call; being listed in the manifest alone does not
deploy anything).

### honeypot-utilities (#258)

`arcane/home/honeypot-utilities/compose.yml` runs as its own Arcane-managed stack at
`/opt/stacks/honeypot-utilities`, bundling `log-maintenance`, `autoheal`,
and `reporter` -- the first #258 split that isn't one honeypot family. All
three watch or act across the whole host rather than belonging to a single
sensor: `log-maintenance` rotates every sensor's logs, `autoheal` restarts
any container across *any* Compose project carrying the `autoheal=true`
label (it watches Docker directly via `docker.sock` by label, daemon-wide,
so it needed no changes for this or any earlier #258 split), and `reporter`
tails every sensor's JSON log to (eventually, once explicitly authorized)
report attacker IPs to AbuseIPDB.

None of the three share a named volume or network with anything outside
this stack, so their Arcane-managed sync carries no ordering requirement
against any other stack.

### honeypot-dionaea and honeypot-payload-analysis (#258)

`arcane/home/honeypot-dionaea/compose.yml` (`dionaea` and `tftp-relay`) and
`arcane/home/honeypot-payload-analysis/compose.yml` (`payload-dedupe` and `yara-scanner`)
split into two separate Arcane-managed stacks, per explicit instruction rather than
bundled together the way `dashboard`+`services-adapter` were. `dionaea` and
`tftp-relay` stay paired -- `tftp-relay` has `depends_on: dionaea` and
actually forwards TFTP traffic to it over `dionaea_net`, the one exception
#235 carved out of "one honeypot per network."

The split resource is `dionaea-lib`: `dionaea` writes captured
binaries/bistreams there, `payload-dedupe`/`yara-scanner` in the other
stack only read. Explicit shared `name:` in both compose files, same
mechanism as everywhere else in #258. `payload-dedupe`/`yara-scanner` also
still touch `dashboard-state` and `yara-results` (shared with
`arcane/home/honeypot-dashboard/compose.yml`, unchanged by this split) and cowrie's
downloads directory (a host bind mount, unaffected by which Compose
project owns the container that writes to it).

Neither stack imposes an ordering constraint on deployment: each reaches
the host through its own Arcane-managed sync, and `dionaea-lib` is a
non-external shared-name volume Compose creates if absent — whichever
project touches it first just creates it. They have no cross-dependency;
any writer-before-reader sync order observed on the host is convention,
not mechanism.

`scripts/reset-logs.sh` treats `dionaea` as a `SPLIT_TARGETS` entry like
the other split honeypots. `payload-dedupe`/`yara-scanner` don't get their
own CLI target -- there wasn't one before this split either -- but the
script still stops/starts them (now via a dedicated
`payload_analysis_compose` helper pointed at their own stack directory)
whenever `cowrie` is targeted, same reasoning as before the split: they
hold reads/hardlinks into `cowrie/downloads` that would race a concurrent
wipe of that directory.

### honeypot-tanner (#258)

`arcane/home/honeypot-tanner/compose.yml` bundles the whole SNARE + TANNER web-app
honeypot group (`tanner_docker`, `tanner_redis`, `tanner_phpox`,
`tanner_api`, `tanner_web`, `tanner`, `snare`) into one stack at
`/opt/stacks/honeypot-tanner` -- all seven form a single `depends_on`
chain, so unlike every other group in this document they were never a
candidate for splitting further. `tanner_local`, the network carrying all
of it, was already wholly private to this group (confirmed by grepping
every compose file), so it moved with them unchanged.

The one resource this stack shares with anything outside itself is
`snare-pages`: written by `honeypot-init`'s `snare-clone` job, read only by
`snare` here, `external: true` in both the old monolithic file and this one
-- unaffected by the split. `autoheal` (`arcane/home/honeypot-utilities/compose.yml`)
still restarts `tanner_docker`/`tanner_redis` on unhealthy via the
`autoheal=true` label, same as always -- it needs no changes for this or
any #258 split.

No ordering requirement against other stacks: `snare-pages` is created by
`honeypot-init`'s `snare-clone` job as an external volume, so provided
that initial deploy landed first (the cutover sequencing in
[ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md)), this stack's sync never blocks
on or gates anything else. `scripts/reset-logs.sh` treats `tanner` as
a `SPLIT_TARGETS` entry, same as `dionaea`; only `tanner`, `tanner_api`,
`tanner_web`, and `snare` are stopped/started on a wipe (unchanged from
before the split) -- `tanner_docker`/`tanner_redis`/`tanner_phpox` hold no
open handles into the log directories this script wipes for this target.

### honeypot-elk (#258)

`arcane/home/honeypot-elk/compose.yml` bundles the ELK/analysis plane (`elasticsearch`,
`kibana`, `filebeat`, `evebox`, `pcap-sync`, `arkime-pcap-init`,
`arkime-capture`, `arkime-viewer`, `extracted-file-importer`, `zeek-proxy`)
into one stack at `/opt/stacks/honeypot-elk` -- the last group
that was still in the monolithic file. Kept together, not split further:
they share the one Elasticsearch instance, the `arkime-pcap` volume and the
host's `logs/` bind-mount tree, so splitting them apart would turn every one
of those relationships into a cross-stack shared resource for services that
only ever make sense running together.

The shared-network story is narrower than it looks, and the count above is
not "ten on `honeynet`". Seven of the ten declare `honeynet` explicitly
(`elasticsearch`, `kibana`, `filebeat`, `evebox`, `arkime-capture`,
`arkime-viewer`, `extracted-file-importer`); `elasticsearch` is additionally
on `llm-data`. `pcap-sync` and `arkime-pcap-init` declare no `networks:` at
all and so ride the project's implicit default network -- `pcap-sync` moves
rotated pcaps through host bind-mounts and a marker file, and
`arkime-pcap-init` is a one-shot `chown` of the `arkime-pcap` volume, so
neither needs the shared network. `zeek-proxy` sets `network_mode: host`
outright and reaches the sensor plane through host-published ports, which is
the point of it.

`honeynet` and `llm-data` get the usual explicit shared `name:` treatment.
`es-data` does **not**, despite appearances: `honeypot-init`'s
`elasticsearch-setup`/`arkime-init`/`honeypot-kibana-setup` jobs all talk
to Elasticsearch purely over HTTP (`http://elasticsearch:9200` via
`honeynet`), never touching the `es-data` volume directly (confirmed by
grep -- no `es-data` reference anywhere in `arcane/home/honeypot-init/compose.yml`).
`honeynet` is the actual shared resource; `es-data`, `evebox-config`, and
`arkime-pcap` all stay private/unnamed. Per explicit instruction (same as
`dashboard-state` in the dashboard split), this means a fresh, empty
`es-data` volume on cutover -- every honeypot's indexed Elasticsearch
history is not preserved across the split.

(#1502 closed out both loose ends this split left behind. First, the
ordering bug it surfaced -- every split stack building from absolute paths
under `/opt/stacks/apiary`, fed by an rsync step that had itself run
*after* those builds for years, quietly one deploy stale (#1103, dating
back to the original #336 proof-of-concept) -- died with the
build-from-checkout model entirely: #1502 relocated every build context
into its own stack directory under `arcane/home/<name>/`, so nothing
builds from the rsync destination any more. Second, `up -d --build`
against the now-permanently-zero-service root file failed outright with
`no service selected` (confirmed locally at the time) rather than being a
harmless no-op; that call no longer exists because nothing here brings
anything up any more.)

What remains after all of that: the root `docker-compose.yml` carries
`services: {}` permanently -- see its header for what that means -- and
the `deploy.yml` rsync step survives with exactly one direct consumer, the
ghidra worker's host-level re-sync described earlier. Everything else
that used to read or build from `/opt/stacks/apiary` reads its own
Arcane-synced directory instead ([ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md)).

## GitHub CI runner

A second, separate self-hosted runner from the deployment one above --
different labels, different systemd service, different host access. It is
the PRIMARY executor for every workflow's compute jobs (#2565): all of
Quality (including the docker-bound rows, the frontend build and the
browser matrix), all of containers.yml, all CodeQL, and the pages build,
whenever it is online. Warm toolchain caches in its persistent HOME plus
warm Rust/Go build directories make it cheaper per run than spinning an
ephemeral GitHub-hosted VM -- and unlike raw CPU, that warmth is most of
the actual speed win.

```text
self-hosted, linux, x64, honeypot-ci
```

### Build-only executors on other hosts (#3379)

The `honeypot-ci` pool is not limited to the homeserver. `precision`
(Dell Precision 5820, i9-10900X 10C/20T, 62 GB RAM, Rocky 10) is a second,
compute-only executor host registered into the same pool, so a queued
Quality/Containers/CodeQL job goes to whichever instance on either box is
idle. The router's trust gate is unchanged: the same code that may run on
the homeserver may run there, and nothing else.

Three scheduled watches measure **the homeserver itself** rather than the
checked-out code, and must never land elsewhere:

| Workflow | What it reads on the executing host |
|---|---|
| `compose-drift-watch.yml` | `/var/dockge/stacks` via the `compose-drift-ro` sudo helper |
| `backup-staleness-watch.yml` | `/mnt/usb-recovery` via the `backup-staleness-ro` sudo helper |
| `disk-usage-watch.yml` | `df` on its own `/var` |

They therefore require an extra label, `honeypot-homeserver`, which only
the homeserver's own `honeypot-ci` instances carry:

```text
self-hosted, linux, x64, honeypot-ci, honeypot-homeserver
```

`install-ci-runner.sh` adds that label by default (the homeserver role).
On any other box, pass `--build-only`: it registers with plain
`honeypot-ci` and skips the homeserver-only sudo helpers entirely.

```bash
# on precision, once per instance
sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY --build-only --instance N
```

The installer never re-registers an existing runner, so the label is not
applied to instances registered before #3379 by re-running it. Add it once
through the API instead (repo admin):

```bash
id=$(gh api repos/Xore/APIARY/actions/runners --paginate \
  --jq '.runners[] | select(.name=="supermicro-ci-2") | .id')
gh api -X POST "repos/Xore/APIARY/actions/runners/$id/labels" -f 'labels[]=honeypot-homeserver'
```

Precision-specific layout: its root LV is 70 GB, the same size that filled
up on the homeserver, and `/home` is a separate 373 GB XFS volume (XFS
cannot be shrunk to grow root). `/var/lib/docker`, `/var/lib/github-runners`
and `/var/lib/github-runner-data` are bind mounts from `/home/ci/` (fstab),
with `semanage fcontext -e` equivalence rules so a relabel of `/home` gives
the files the same SELinux types as the `/var/lib` paths the installer
labels. `/etc/docker/daemon.json` carries the homeserver's address-pool,
log and buildkit-GC policy (minus the NVIDIA runtime; precision's GPU is
not usable).

### Executor routing (homeserver first, GitHub-hosted fallback)

Actions has no "runs-on A else B" syntax, so each workflow decides in two
steps. Every workflow's `ci-target` job calls the shared reusable
`.github/workflows/ci-router.yml` (#2571 retired quality.yml's own inline
copy), which asks whether this run's source may reach the homeserver at
all (trust gate below), then whether a `honeypot-ci`-labelled runner is
currently registered AND reporting online -- measured, not read, by
dispatching the `ci-heartbeat.yml` canary (the runners-listing API
answers 403 to `GITHUB_TOKEN`, so the registry cannot be asked).

**The canary is shared, not per-router (#2849).** Before dispatching, a
router looks for one that already answers the question: a canary that
*succeeded* within `HEARTBEAT_FRESH_SECONDS` (300s default) is reused
outright, and one already *in flight* within that window is adopted and
waited on. Only if neither exists does it dispatch its own. The ref a
canary ran on is deliberately ignored — `ci-heartbeat.yml` is a no-op job
whose sole output is "a `honeypot-ci` runner picked this up", which is a
fact about the box rather than about a branch.

This is not an optimisation, it is a correctness fix. Each router used to
dispatch its own canary, and those canaries queue on the same executors as
the jobs they gate — so a fan-out deep enough to fill the queue made every
router time out and declare a healthy box *offline*, and the busier the
box got the more certainly it was mis-declared dead. Measured on run
33553809659: five runners online and executing, every canary in the
surrounding hour `success`, and the router still concluded
`online=false`. A 20-PR fan-out across ~4 routing workflows dispatched
roughly 80 canaries to measure one machine; it now converges on ~1.

Reuse trades a bounded staleness for that: a box dying immediately after a
successful canary keeps being vouched for until the window expires. Only a
*success* ever vouches — a failed or absent canary is never reused — so
the fail-safe direction is preserved. Quality
ships each eligible check as a PAIR of conditional jobs fed by that
single answer -- exactly one twin runs, the other reports skipped.
containers/security/pages instead give their one executor-agnostic job a
conditional `runs-on`. When the box is off, paused, unregistered, or the
runners API itself errors, everything falls back to its `(GitHub-hosted)`
twin/suffix and the workflow looks exactly like a conventional run:
degraded speed is the worst failure mode routing can produce. The
`force_github_hosted` workflow_dispatch input on Quality (passed through
to the shared router) forces the fallback direction manually (e.g. while
servicing the machine); repository variable `CI_HOMESERVER_PRS=true` is
what opts
same-repo pull requests into homeserver execution -- it IS set
deliberately (the operator's stated intent is that the homeserver carry
all CI), and undoing it is the auditable way to push PR runs back to the
cloud.

The old supplement `quality-homeserver.yml` (its own duplicate Go +
shellcheck pass over pushes to main) was removed once these pairs
superseded it: running both meant paying for the priciest checks twice on
every merge.

### Why this stays off pull_request by default

A public repository's pull requests can come from forks -- attacker-
controlled input a maintainer has not reviewed yet. A GitHub-hosted runner
is a disposable, sandboxed VM torn down after the job; a self-hosted
runner's job runs as a real process on real home-network infrastructure.
Routing untrusted `pull_request` code to it would mean a malicious test
file (`os.system(...)`, a crafted Go `TestMain`, anything) gets to
execute wherever that runner happens to have access -- exactly the
scenario GitHub's own self-hosted-runner security guidance warns against,
and the same reasoning the deployment runner above already applies
("never accept pull-request code" on `production-home`).

The router's trust gate allows push-to-main (reviewed on its own PR
before merging) and `workflow_dispatch` (an operator's own choice).
Same-repo pull_request branches are excluded even though they can only be
pushed with write access -- defense in depth against a compromised
contributor account, which no amount of repo-variable bookkeeping
detects. The `CI_HOMESERVER_PRS` escape hatch exists for a deliberate,
auditable decision to trade that margin away; fork PRs are excluded even
from that.

### Docker-group membership is an accepted trade-off, not an isolation gap (#2780)

Earlier prose in this section (and in `install-ci-runner.sh`'s own header)
described `github-ci-runner` as having "no production-directory/sensor-state
access" and "no access to `/var/lib/honeypot-*`, `/opt/stacks`, or any
sensor state." **That overstated the isolation.** #2780 measured, live on
the homeserver:

```
$ id github-ci-runner
uid=995(github-ci-runner) gid=981(github-ci-runner) groups=981(github-ci-runner),983(docker)
$ sudo -u github-ci-runner test -r /opt/stacks/apiary/scripts/isolation-audit.sh && echo READABLE
READABLE
$ sudo -u github-ci-runner test -r /opt/stacks/honeypot-dashboard/.env && echo READABLE
READABLE
```

Two separate findings, both real:

1. **Docker-group membership is host-root-equivalent.** A member can
   `docker run -v /:/host ...` and read, write, or chroot into anything on
   the host, including other stacks' volumes and host binaries -- this is
   the same grant `github-deploy-runner` (the *production* runner) carries,
   for the same reason (#2565 added it here so `containers.yml`, the
   frontend lockfile check, and the Keycloak/OIDC suites could run on this
   pool at all).
2. **`/opt/stacks/apiary` is plain world-readable throughout**, so
   `github-ci-runner` can already read e.g. `honeypot-dashboard`'s live
   `.env` directly, with no Docker involved.

**Decision: this is an accepted trade-off, not a gap to close.** Reasoning:

- The alternative considered was a scoped Docker socket proxy for exactly
  the checks that need it (`containers.yml`'s build/push, the lockfile
  check's `npm ci` inside a container, the Keycloak/OIDC suites' compose-up)
  plus tightened permissions on `/opt/stacks/apiary`. That is real,
  bounded engineering work across three separate workflow surfaces, each
  with a different Docker access shape (build-and-push vs. compose-up vs.
  read-only inspection) -- not a one-line permission change, and a partial
  version (proxying one job, leaving the group membership on the others) is
  strictly worse than doing nothing: it leaves the same actual capability in
  place while adding a second mechanism to reason about and maintain.
- The property that actually bounds this runner's blast radius was never
  "it can't reach much" -- it's **which code gets to run on it at all**.
  The ci-target router's trust gate (previous subsection) keeps
  attacker-controlled fork-PR code off this pool entirely; only
  push-to-main (already reviewed), `workflow_dispatch` (an operator's own
  choice), and `CI_HOMESERVER_PRS`-opted same-repo PRs (a deliberate,
  auditable trade against a compromised-contributor scenario) ever execute
  here. That gate is real containment. Docker-group membership was never
  a second, independent containment layer behind it -- treating it as one
  in the header comments was the actual bug.
- Net effect: **`github-ci-runner`'s practical host capability is not
  meaningfully smaller than `github-deploy-runner`'s** (the production
  runner). The two pools differ in *what triggers execute on them* and in
  `github-deploy-runner`'s additional `deploy-runner` group and its role in
  `deploy.yml`'s actual production-write jobs -- not in what a compromised
  process on either one could reach on the host. Anyone reasoning about
  compromise of one pool should reason about the other the same way.

This is a decision, not a patch: no code changed as a result of it beyond
correcting the header comments in `install-ci-runner.sh` and this doc to
stop asserting an isolation boundary that measurement shows doesn't exist.
If the trade-off is revisited later (e.g. because the socket-proxy work
above becomes worth doing), do all three routed surfaces in one pass, not
one at a time, per the reasoning above.

### Install

```bash
sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY
```

Registers a dedicated `github-ci-runner` system user (sudo-less, with a
docker-group membership and a preinstalled host provision for the routed
checks -- redis-server, node 22, shellcheck, and playwright's chromium
library set). This user carries no group grant scoped specifically to
`/var/lib/honeypot-*`, `/opt/stacks`, or sensor state -- but see
"Docker-group membership is an accepted trade-off" below: that phrasing
used to appear here as "no access to `/opt/stacks`", which #2780 found is
not true (the checkout there is world-readable) and has been corrected.
Downloads and
checksum-verifies the pinned `actions/runner` release, registers it with
the given repository using a registration token (fetched automatically via
`gh api` if `--token` is not passed and `gh auth login` has already been
done for an account with admin on the repo), and installs it as a systemd
service via the runner's own `svc.sh`.

Re-running the script is safe: it skips the download if already extracted
and skips re-registration if `$RUNNER_HOME/.runner` already exists (remove
that file first to re-register, e.g. after moving the runner to a new
host).

#### Root-owned leftovers in `_work` (#3021)

The install also drops two things next to the unit:

- `/opt/github-ci-runner-helpers/fix-work-ownership.sh` (installed from
  `scripts/github-ci-runner/fix-work-ownership.sh`, root-owned, 0755), and
- `/etc/systemd/system/actions.runner.<repo>.<name>.service.d/fix-work-ownership.conf`,
  a drop-in carrying
  `ExecStartPre=+/opt/github-ci-runner-helpers/fix-work-ownership.sh <runner-user> <runner-home>/_work`.

The leading `+` runs that line as root even though the unit's own `User=`
is the unprivileged runner account, so no new sudoers grant was needed
(unlike `scripts/compose-project-state.py`, the narrow root helper for
`compose-drift-watch.py`, this runs as part of the unit's own privileged
startup rather than from inside a workflow step).

**Why it exists.** A root process that writes into a runner's `_work`
checkout leaves files the runner user can never delete, and
`actions/checkout`'s clean step then fails permanently on that runner:

```
File was unable to be removed
Error: EACCES: permission denied, unlink '.../__pycache__/polarity.cpython-313.pyc'
```

Every later job scheduled onto that runner dies at checkout in 6-10
seconds, so the symptom -- dozens of unrelated suites red at once with no
test output -- looks nothing like its cause. Two causes are confirmed, both
on 2026-09-05:

1. **The repo's own CI**, fixed at source by #3024: `quality.yml`'s #159
   corpus job ran `docker run --rm -v "$PWD:/w" ... debian:trixie-slim` as
   root, so its `python3` calls wrote root-owned bytecode into the
   bind-mounted workspace. `PYTHONDONTWRITEBYTECODE=1` now goes into that
   container and is exported by `analysis/ghidra/benchmarks/corpus/ci_verify.sh`
   itself. A root container needs no `sudo`, which is why grepping the repo
   for `sudo` finds nothing here.
2. **A manual #1947 benchmark sweep run as root** directly against a runner
   checkout, outside any repo-tracked workflow. Operator process, not
   reachable from code.

#3024 closes the first at source; this helper is the backstop for the second
and for whatever the next one turns out to be. It reclaims ownership only
under the one `_work` directory it is given, only back to that runner's own
user, refuses any path outside `/var/lib/github-runners/*/_work`, and uses
`chown -h` so a root-owned symlink dropped into `_work` cannot be used to
hand ownership of its target away.

If it finds a path it **cannot** reclaim -- an immutable file (`chattr +i`
on `__pycache__` was seen doing exactly this) or a mount that refuses
`chown` -- it lists the paths and exits non-zero, which stops the unit.
That is deliberate: the runner goes offline in GitHub and its jobs queue,
instead of accepting them and failing every one at checkout. Recover with:

```bash
ssh homeserver 'sudo lsattr -R /var/lib/github-runners/<user>/_work 2>/dev/null | grep -- "-i-"'
# clear whatever it reports, then
ssh homeserver 'sudo systemctl start actions.runner.Xore-APIARY.<name>.service'
```

The drop-in only runs on a unit (re)start, not before every job, so a root
process that touches a checkout between restarts still blocks the *next*
checkout until the service restarts. `ACTIONS_RUNNER_HOOK_JOB_STARTED`
would close that window but runs as the unprivileged runner user, so it
could not fix root-owned files at all.

### Scaling past one instance (#2572)

`--instance N` registers an independent SECOND (or third, fourth, ...)
runner instance on the same box instead of touching the primary one:

```bash
sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY --instance 2
```

Each instance gets its own system user (`github-ci-runner-N`), its own
`_work` dir and `.runner` registration (`/opt/github-ci-runner-N`), and its
own systemd unit -- but registers under the SAME `honeypot-ci` label as the
primary instance, so GitHub schedules a queued job onto whichever instance
is idle rather than piling everything behind one executor. `--instance 1`
(the default, omitting the flag) is the original unsuffixed layout and
needs no migration.

This is a real fix for #2572 (one instance serializing the whole
homeserver-first matrix), not just a mitigation: `quality.yml`'s matrix
rows are already independent per #2389/#2565, so adding instances turns
that existing independence into actual wall-clock parallelism. The
`test_honeypot_ilm_rollover`/`geoip_pipeline`/`dionaea_incidents_index`/
`conpot_persona_pipeline` rows each pick a random host port in `19000-19899`
for their throwaway Elasticsearch container specifically so two instances
running one concurrently don't collide on a fixed port; `containers.yml`'s
buildx cache is `type=local` under `/var/buildx-cache/<image>` when the
build lands on this box (#2822, below), which is a path on shared local
disk rather than per-instance state, so a second instance is not cold
there either -- no extra work needed for that tier.

`actions/setup-go`/`actions/setup-node` cache their toolchain downloads in
the runner's own persistent tool cache -- unlike an ephemeral GitHub-hosted
runner, that cache survives between job runs on this same machine, so the
second and every later run skips the download entirely. This is most of
where the actual speed win comes from, not raw CPU.

#### How many instances, and why it is 2 during a benchmark window

The box ran **seven** `honeypot-ci` instances (`supermicro`,
`supermicro-ci-2` .. `-7`) plus the separate `honeypot-home` deploy runner.
Reduced to **two** (`supermicro` + `supermicro-ci-2`) on 2026-09-05.

This is a shared box, not a CI box. The homeserver is also the GPU host for
the #1947 model benchmark, and CI is that benchmark's largest source of
measurement noise: identical work on the same model spread **62%** (78.2 vs
126.7 min/run) purely from runner contention, and load average sat at
**15-27** with seven instances live. #1947's whole premise is that scores
separated by less than the error bar are not results, so a benchmark run
taken against an unknown, CI-driven load is not a measurement -- see
`docs/benchmarks/plans/2026-09-05-1947-resume-plan.md` step P5, which cannot
be answered at all without this.

Seven was never a measured optimum; it was the ceiling #2572 allowed once
one instance stopped serialising the matrix. The CPU swap (Xeon Silver 4110
8c/16t -> Xeon Gold 5220R 24c/48t) also means two instances today have more
cores behind them than four did before.

To restore the extra instances once the benchmark window closes:

```bash
ssh homeserver 'for n in 3 4 5 6 7; do
  sudo systemctl enable --now actions.runner.Xore-APIARY.supermicro-ci-$n.service
done'
```

They were only `systemctl disable --now`, not deregistered, so the local
`.runner` file, `_work` dir and tool cache survive. **GitHub, however, removes
a self-hosted runner that stays offline for more than 14 days.** As of
2026-09-26, instances 5-7 are no longer registered (the runners API lists only
`supermicro`, `-ci-2..4` and `supermicro-home`), so re-enabling their units is
not enough. Remove their stale registration and re-run the installer with a
token:

```bash
ssh homeserver 'cd /opt/stacks/apiary && for n in 5 6 7; do
  sudo rm -f /opt/github-ci-runner-$n/.runner /opt/github-ci-runner-$n/.credentials*
  sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY --instance $n
done'
```

Their `/var/lib/github-runners/github-ci-runner-{5,6,7}/_work` trees (~11 GB)
are leftovers until then and can be deleted if the instances won't return.

**State on 2026-09-26:** four `honeypot-ci` instances are active
(`supermicro`, `-ci-2`, `-ci-3`, `-ci-4`), not the two this section prescribes
for a benchmark window. At the same time the GPU was serving a benchmark model,
and the load average sat at 27-40, which is the contention described above.
Whether to drop back to two is an owner decision; record it here when made.

#### Draining a runner before maintenance

**Stopping a busy instance fails its in-flight job** (the 2026-09-05 reduction
cancelled a run and cost 16 jobs a re-run). Drain first:

1. Stop new work from landing on the instance. The runner has no "pause", so
   either disable the unit's restart and let the current job finish, or (for
   host-wide maintenance) wait until the queue is empty:
   `gh run list --status in_progress` and `--status queued` both empty, or only
   jobs you are willing to lose.
2. Check the instance is idle: `gh api repos/Xore/APIARY/actions/runners
   --jq '.runners[] | {name, busy}'` shows `busy: false`, and on the host
   `pgrep -u <runner-user> -f Runner.Worker` returns nothing.
3. `sudo systemctl stop actions.runner.Xore-APIARY.<name>.service`, then do
   the maintenance.
4. Afterwards, look for what a killed job can leave behind. That means
   the throwaway Elasticsearch test containers from `analysis/tests/`
   (named `<test>-test-<pid>`, published on `127.0.0.1:19000-19899`, where live
   services use `10.8.0.2`):
   `docker ps -a --format '{{.Names}}' | grep -E -- '-test-[0-9]+$'`.
   Also check for root-owned `_work` leftovers (see #3021 above).
5. `sudo systemctl start ...`, and confirm `status: online` in the runners API
   within a minute.

Keep any instance's downtime under 14 days, or GitHub deregisters it (above).

#### Resource limits

None. Every runner unit runs with `MemoryMax=infinity` and no CPU quota
(checked 2026-09-26) on a 48-core / 92 GB host that also runs every sensor,
Elasticsearch and the GPU workloads. Contention is managed only by instance
count, as above. A systemd slice with a `CPUWeight`/`MemoryHigh` budget for
all runner units would bound it structurally, but it would also slow CI when
the box is idle. That's an owner decision, not something to add quietly.

### Buildx layer cache: `type=local` on the homeserver (#2822)

`containers.yml` used to export every image's layer cache to `type=gha`,
the GitHub Actions cache backend. That backend counts against a single
repository-wide 10 GB quota shared with every other cache entry in the
repo, and #2822 measured it over that ceiling -- so container layers were
being LRU-evicted while still in use and the builds they were meant to
accelerate ran cold anyway. #2771's per-image `type=gha` scopes stopped
the images evicting *each other*, but did nothing about the quota itself.

The `Pick cache backend` step therefore chooses per executor:

- **Homeserver runner** -- `type=local,dest=/var/buildx-cache/<image>`.
  Local disk on `/var` (see `docs/HOMESERVER-DISK-LAYOUT.md`), outside
  the GitHub quota entirely, and it survives between runs on this box.
- **GitHub-hosted fallback** -- `type=gha,scope=<image>`, unchanged. An
  ephemeral runner has no local disk worth caching to.

**The directory must be provisioned before the runner can use it.**
`/var` is `root:root 0755`, so the workflow cannot create
`/var/buildx-cache` itself: `mkdir` as `github-ci-runner` fails with
`Permission denied`. `scripts/install-homeserver.sh`'s
`provision-buildx-cache` step creates it `2775 github-ci-runner:github-ci-runner`
(setgid so per-image subdirectories stay group-owned) and then verifies
the runner can actually write it, so a rebuild replay (#1609) recreates it
rather than leaving a hand-made directory nobody records. If the step has
not run on a given box, `Pick cache backend` emits a workflow warning and
falls back to `type=gha` -- a slow build, not nineteen failed matrix rows.

**Bounding it.** `type=local` has *no* eviction: every export leaves
unreferenced blobs behind in `blobs/sha256/` forever.
`scripts/prune-buildx-cache.sh <dir>` runs after each export and deletes
blobs untouched for `PRUNE_DAYS` (14), then, if the directory is still
over `MAX_BYTES` (2 GiB per image), clears it outright. The reset is
deliberate: BuildKit skips the *entire* import when one referenced blob is
missing (it warns and builds on, exit 0), so a partially trimmed directory
is worth nothing while still occupying the disk that `/var/benchmarks`
shares.

**Reclaiming the existing `type=gha` backlog.** `.github/workflows/cache-cleanup.yml`
deletes a PR's cache entries when the PR closes. Actions scopes cache
*reads* by ref but charges every ref against the one repository quota, so
a closed PR's entries are unreadable and still billed until the 7-day GC
gets to them. Deleting on close reclaims that quota immediately.

### Rust `target/` reuse on the homeserver runner (#3405)

`quality.yml`'s `backend-service` job (the self-hosted twin of the Rust gate)
was measured at **159s** in run 36317857731 -- the second-longest job in the
repo -- and it recompiled all 287 packages in `Cargo.lock` on *every* run.

The job's own comment explained why no cache existed: `~/.cargo` and `target/`
"simply stay warm on disk between runs". That was half right, and the half
that was wrong was the expensive half.

- `~/.cargo/registry` and `~/.cargo/git` really do persist. They live in the
  runner user's `$HOME`, outside the checkout, and have always been warm. They
  need nothing from us.
- `target/` never persisted at all. It lives *inside* the workspace, and
  `actions/checkout` defaults to `clean: true` -- i.e. `git clean -ffdx`. The
  `-x` is the whole story: it deletes **ignored** files, and `target/` is
  ignored (`.gitignore` line 7). So the checkout destroyed the previous run's
  build before the build step could touch it.

The fix is therefore not more caching machinery. It is moving the one
directory that is being wiped to a path that is not: a `Reuse a persistent,
ref-scoped target/` step exports `CARGO_TARGET_DIR` at
`<root>/<ref-slug>-<ref-digest>-<toolchain-digest>`, which is outside the
workspace and so survives `git clean -ffdx`.

**No `actions/cache`, deliberately.** The cloud twin's `actions/cache` block
over `target/` is correct and unchanged -- an `ubuntu-latest` runner is a fresh
VM, so the cache service is the only disk that outlives the job. This runner
is the mirror image: it has persistent disk, and the cache service is the
wrong tool. See the `go-fmt` job's comment for what using it here cost
before: Go writes module directories mode 0555, so the restore's `tar -x`
cannot overwrite them, and the resulting re-uploads put six same-key 465 MB
copies over the repository's 10 GB Actions quota.

**One directory per ref, never shared.** The `honeypot-ci` label is served by
several runner instances which between them run every open branch, so a single
shared `target/` would be written concurrently by unrelated checkouts. The key
is `GITHUB_REF` (`refs/heads/main` on push, `refs/pull/<n>/merge` on
`pull_request`) hashed to 8 hex digits, which makes collision impossible even
though `GITHUB_REF_NAME` mangles distinct refs onto the same slug -- `a/b` and
`a-b` both slug to `a-b`, and get different digests. The toolchain channel is
in the key as well, so a pin bump starts clean instead of relying on cargo
noticing the compiler changed underneath a long-lived directory.

**Keyed per ref, not per commit.** Cargo fingerprints every unit against its
own inputs, so reusing a branch's directory across that branch's commits is
exactly what it is built for -- and it is the case that pays. A commit-keyed
directory would be cold on every push, because a push *is* a new commit: that
would be a slower spelling of the 159s job.

**A cold cache is a valid outcome, and cannot turn a red crate green.** Root
resolution is best-effort -- `CI_CARGO_TARGET_ROOT`, then
`/var/cargo-target-cache`, then `$HOME/.cache/cargo-target` -- and if none is
writable the step warns and leaves `CARGO_TARGET_DIR` unset, so cargo builds
into the in-tree `target/` and the run costs what it always cost. The step
never fails the job. `~/.cargo` may also need repopulating if
`$HOME/.rustup`/`$HOME/.cargo` are ever cleared; that is a one-off cost, not
a per-run one.

**`/var/cargo-target-cache` needs provisioning to be used.** `/var` is
`root:root 0755`, so as `github-ci-runner` the workflow cannot create it --
the same constraint the buildx cache above runs into, and why the
`$HOME/.cache/cargo-target` fallback exists and is enough on its own:

```sh
sudo install -d -m 2775 -o github-ci-runner -g github-ci-runner \
  /var/cargo-target-cache
```

Setgid plus the unit's existing `UMask=0002` (see `provision-buildx-cache`'s
sibling in `scripts/github-ci-runner/install-ci-runner.sh`) keeps it
group-writable across every instance's user, so any instance can serve the
cache rather than only whichever one picked up the previous run of that ref.

**Bounding it.** Directories idle for `CI_CARGO_TARGET_PRUNE_DAYS` (7) are
removed after each run. Eviction reads a `.ci-target-heartbeat` file the job
touches on entry, *not* the directory's mtime: a warm rebuild writes into
`target/debug/` and need not touch the `target/` directory entry itself, so an
mtime rule could delete a directory a running job is using. A 90-minute job
timeout against a 7-day floor cannot be mistaken for an abandoned directory.

**Reading the result.** The `Build` step tees cargo's own output, and
`Report target/ reuse outcome` counts its `Compiling` lines: ~287 on a cold
run, near 0 when every unit was still fresh. That count -- not a cache-hit
log line -- is the evidence the cache is doing anything.

### Digest-bound SBOMs for the two dashboard images (#3321)

There used to be no inventory of what is inside `apiary-backend`
(`honeypot-backend-service`) or `dashboard-next`. Every other image in the
fleet was at least covered at its base — `image-security-scan.yml` walks the
tree's Dockerfiles and compose files and Trivy-scans every base image they
pull — but a built dashboard image is its base plus everything `COPY`ed in
after it, and nothing recorded that difference. Answering "are we affected?"
when a CVE landed meant rebuilding the image or `exec`-ing into the running
container.

`containers.yml` now produces a CycloneDX SBOM for those two images at build
time, keyed by the pushed manifest digest.

**Only those two rows, and only where there is a digest to key to.** The
matrix gained an `sbom: true` opt-in on `backend-service` and
`dashboard-next`; every step below is gated on it, so the other sixteen rows
build exactly as before and pay no syft run and no advisory-DB download. The
steps are also limited to events that push. A `pull_request` row builds with
`push: false` and `load: false`, so it produces no image and therefore no
digest — a tag-keyed inventory would describe whatever that tag pointed at
when syft ran, which is not the thing a CVE question is about. Those rows
emit a `::notice` saying so instead of leaving the gap unexplained.

**The digest is stamped into the document, not just the filename.** syft's
CycloneDX output records the image's name and tag and no digest at all
(verified against syft 1.52.0), so `scripts/generate-image-sbom.sh` adds
CycloneDX properties to `metadata.component` afterwards:
`apiary:image-digest`, `apiary:image-reference`, and `apiary:image-name`,
plus `component.version` set to the digest for viewers that show only
name/version. The script then re-reads the file and fails if the property is
not there — the binding is the feature, so it is verified on disk rather than
assumed from the exit code of the process that wrote it. It also refuses an
unpinned reference up front.

**Three copies, one generator.** `scripts/generate-image-sbom.sh` is the only
thing that writes an SBOM, so the CI path and the homeserver path cannot
disagree about what a file in `/var/image-sbom` claims to be:

| where | what | lifetime |
|---|---|---|
| CI artifact `sbom-<image>-<hex-digest>` | the SBOM plus the Trivy JSON report | 90 days |
| `/var/image-sbom/<image>/<hex-digest>.sbom.json` | the record, content-addressed | 10 builds per image |
| `/var/image-sbom/<image>/latest.sbom.json` | the pointer a person or Arcane reads | re-pointed at the newest survivor |

The artifact name is digest-keyed so an operator can paste it straight into
`trivy sbom`; it uses the hex form because a colon is not a legal
artifact-name character.

`/var/image-sbom` is published **only when the row ran on the homeserver**.
The GitHub-hosted fallback has an ephemeral `/var` that dies with the job, so
publishing there would only write a file nobody reads. Like
`/var/buildx-cache`, the directory has to be provisioned first —
`/var` is `root:root 0755`, so the workflow's own `mkdir` gets `EACCES`.
`scripts/install-homeserver.sh`'s `provision-image-sbom` step creates it
`2775 github-ci-runner:github-ci-runner` with a default ACL, joins every
extra runner instance to the group, repairs what is there, and then proves
each runner user can write it. Without that step the publish step degrades to
a `::warning` and the CI artifact still has the SBOM — a missing homeserver
copy must not cost a build.

**What Arcane builds.** The generator takes an image reference and a digest,
not a tag, so it is not tied to the CI path: an image built on the box rather
than by a workflow is inventoried by running the same script by hand against
that image's digest, and the file it writes is the same one CI would have
written. `scripts/generate-image-sbom.sh --help` documents the interface.
What the workflow itself does is narrower and worth stating plainly: it
writes the homeserver copy on the builds that land on this box, and it
refuses to invent a digest for anything else.

`scripts/prune-image-sbom.sh` keeps the newest 10 records per image and
re-points `latest.sbom.json` afterwards, because a pointer naming a pruned
digest is worse than no pointer: it looks authoritative and is wrong. Records
are pruned by count, never by age — a digest-keyed inventory's whole value is
that it names one exact image, so dropping a month-old one because a newer
one exists would make that older image unanswerable.

**The scan reads the SBOM, not the image.**
`scripts/scan-image-sbom.sh` runs `trivy sbom` over the same file the
inventory is in, with `image-security-scan.yml`'s flags verbatim
(`--scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1`).
Scanning the SBOM is what makes the two agree: the scan and the inventory are
derived from one artefact, so "the scan says clean" and "the inventory has no
such package" cannot drift apart. Both now install Trivy through
`scripts/install-trivy.sh`, because a version + asset + sha256 triple copied
into two YAML files is exactly how the same CVE ends up graded two different
ways with no visible cause; a test asserts the pin appears in that script and
nowhere else.

Like the base-image scan it mirrors, the scan is **report-only** and it
refuses to conflate two opposite findings: Trivy exits non-zero both for
"found CRITICAL/HIGH" and for "could not read this", and the second is a
coverage gap, not a vulnerability. The script tells them apart from Trivy's
own `Detected SBOM format` log line and annotates accordingly. Generating the
SBOM, by contrast, is a hard failure — the required `Containers gate`
aggregates the `build` job, and a silently absent inventory is the gap this
section exists to close.

Honest limitations:

- **Pull requests get no SBOM.** See above. The inventory that matters is the
  one for the digest that was actually deployed.
- **Trivy warns** `Third-party SBOM may lead to inaccurate vulnerability
  detection` on a Syft-generated CycloneDX file, and recommends Trivy
  generate SBOMs itself. The issue specifies `trivy sbom` over a CycloneDX
  inventory, so that is what this does; the warning is Trivy's, not a
  finding.
- **Provenance attestation is out of scope.** Cosign or
  `buildx --provenance` is tracked as a follow-up. An SBOM is an inventory,
  not a signature: nothing here proves the SBOM was produced by the build it
  describes.
- **CVE findings do not fail the build.** Same posture, and same re-arm note,
  as `image-security-scan.yml`'s base-image backlog.

### Docker Hub authentication and the pull-through cache (#2819)

`containers.yml` used to hold no Docker Hub credentials at all. Its single
`docker/login-action` targets `ghcr.io` and is gated
`if: github.event_name != 'pull_request'`, so on a PR every base-image pull
went out anonymous -- and Docker Hub meters anonymous pulls **per source
IP**, at roughly 100 per 6h. With `CI_HOMESERVER_PRS=true` all 19 matrix
rows leave this box through one address, and the tree carries **75
non-`scratch` `FROM` lines** across 56 tracked Dockerfiles, 68 of them
resolving to Docker Hub (the other 7 are `mcr.microsoft.com`). One cold run
spends most of the budget;
the run after it fails with `toomanyrequests` on whichever rows happen to
ask last. #2771's per-image `type=gha` scopes do not help: that cache holds
*our* layers, never the base image, so every run re-resolves every `FROM`
against the registry.

Two halves, both required.

**Authentication.** Repo secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`
(a "Public repo read-only" personal access token), consumed by a
`docker/login-action` step that deliberately runs on `pull_request` too --
that is the event where the gap bites. The step is guarded on the secret
being non-empty so a fork `pull_request`, which by design cannot read
secrets, keeps building anonymously instead of failing on empty
credentials. Authenticated pulls meter against the account rather than the
shared IP.

**Pull-through cache.** The durable half, and the one that actually cuts
traffic rather than raising the ceiling:

```bash
sudo scripts/github-ci-runner/install-registry-mirror.sh \
    --username <hub-user> --token <hub-read-only-PAT>
gh variable set CI_REGISTRY_MIRROR --repo Xore/APIARY --body '172.16.0.1:5555'
```

A `registry:3` proxy in front of Docker Hub, run under
`ci-registry-mirror.service`, storing to `/var/ci-registry-mirror` (not
`/var`, which is the docker data root and sits near full) with a 168h
upstream TTL. Eighteen rows times N bases collapse to one upstream fetch,
and it keeps them across runs.

Run it on **every** executor that should have one, not just the first. The
variable is global and the mirror is not, which is the whole of the next
point.

Three things about it are easy to get wrong:

- **The address is a per-host fact, and it is verified per-run (#3380).**
  `CI_REGISTRY_MIRROR` is a repository *variable*, but "this executor runs a
  mirror at this address" is a property of the *box*, and since #3379 the
  `honeypot-ci` pool is not one box — `precision` is registered into the same
  pool as a build-only executor, so `ci-target` routing to the homeserver can
  land on either. One global value is therefore right on one host and dead on
  the other, where the same `172.16.0.1` is that host's own docker0 gateway
  with nothing listening on it. `containers.yml` therefore probes
  `http://$CI_REGISTRY_MIRROR/v2/` **on the executor that is about to use
  it** and writes the mirror into `buildkitd.toml` only on a `200`. That is
  the same check `install-registry-mirror.sh` gates its own install on, so
  the two cannot drift. Any other answer — connection refused, or some other
  service holding the port (on the homeserver `5555` is also the multipot
  honeypot's, on the WireGuard address) — means the honest empty config is
  written instead, and the run says so in a `::warning::` annotation and its
  job summary. This is not optional belt-and-braces: #3380 was filed from
  exactly the state it prevents, with the variable set to `172.16.0.1:5555`
  and no executor in the pool having ever run the installer. Buildkit falls
  back to `docker.io` on an unreachable mirror, so the run stayed **green**
  while the cache was never in effect, every base image was pulled from Hub
  directly, and all 74 non-`scratch` `FROM` lines first paid a
  connect-refused round trip. Note the failure is a *degradation*, not a
  failure: the cache is an accelerator, and the authenticated login above is
  what actually protects against `toomanyrequests`, so a missing mirror must
  never turn a passing row red — the same fail-safe
  [ci-router.yml](https://github.com/Xore/APIARY/blob/main/.github/workflows/ci-router.yml)
  documents ("routing can degrade CI's speed, never its pass/fail
  correctness").
- **It is configured on buildkit, not on the host daemon.** buildx's
  `docker-container` driver runs its own containerd and never reads
  `/etc/docker/daemon.json`, so a `registry-mirrors` entry there is
  silently ignored by every build in this repo. `containers.yml` composes a
  `buildkitd.toml` from `CI_REGISTRY_MIRROR` and passes it to
  `setup-buildx-action` as `buildkitd-config`. Installing the service
  without setting the variable changes nothing.
- **It is applied only on the self-hosted executor.** The address is bound
  to the docker0 gateway (`172.16.0.1:5555`), reachable from any container
  on the box but not from the LAN -- an unauthenticated proxy pulling with
  our Hub credentials should not be an open relay. A GitHub-hosted fallback
  runner cannot dial it, and a mirror it cannot dial turns every `FROM`
  into a timeout, so the workflow gates the config on
  `needs.ci-target.outputs.homeserver == 'true'`.

The installer authenticates the host daemon with the same credentials
before pulling `registry:3`, because the bootstrap otherwise 429s on
exactly the limit it is being installed to fix.

## VPS deployment

Create a protected `production-vps` environment with a required reviewer and
these environment secrets:

| Secret | Purpose |
|---|---|
| `VPS_SSH_KEY` | dedicated deployment private key |
| `VPS_HOST` | VPS hostname or address |
| `VPS_USER` | deployment user, normally `root` |
| `VPS_PORT` | SSH port, normally `2222` |
| `DOMAIN` | the real production domain (e.g. `example.com`), substituted into `traefik/dynamic.yml`'s committed `*.honeypot.example` placeholders at deploy time -- see below |

Run [`../safe-update.sh`](../safe-update.sh) with `STACK_DIR=/root/vps` before
a manual VPS deploy, same reasoning as the home-side snapshot above.

The workflow preserves `/root/vps/.env`, synchronizes `vps/`, validates
`docker-compose.yml`, and recreates changed services with plain Docker Compose.
Use a dedicated key restricted to the deployment host and rotate it if workflow
logs or repository access are ever compromised.

### Backup, sync, validate, start, and config substitution

```mermaid
flowchart TB
  approve["Operator approves<br/>production-vps environment"]
  ghRunner["Short-lived GitHub-hosted runner"]
  checkout["actions/checkout"]
  key["VPS_SSH_KEY written to a<br/>temp file, mode 0600"]
  backup[("Snapshot: /root/vps-backups/<br/>pre-deploy-&lt;timestamp&gt;.tar.gz,<br/>10 most recent kept")]
  rsync["rsync vps/ -> /root/vps/<br/>over SSH, excluding .env,<br/>traefik/certs/, traefik/dynamic.yml,<br/>secrets/ (VPS-owned, see table below)"]
  validate["SSH: docker compose config<br/>validates /root/vps/docker-compose.yml"]
  up["SSH: docker compose up -d --build<br/>--remove-orphans (#2813)"]
  dynGen["Separate step: substitute DOMAIN<br/>into the committed *.honeypot.example<br/>placeholders, validate as YAML,<br/>no leftover placeholders --<br/>all BEFORE touching the VPS"]
  dynWrite["Copy to a temp path on the VPS,<br/>then write in place with cat --<br/>never copy-then-rename (see below:<br/>Traefik's bind mount tracks the<br/>inode, not the path)"]
  verify["Verify step: fail the job if certs<br/>or dynamic.yml are missing, empty,<br/>unparseable, or still placeholder"]
  destroy["GitHub destroys the runner<br/>+ its temp key file"]

  approve --> ghRunner --> checkout --> key --> backup --> rsync --> validate --> up
  up --> dynGen --> dynWrite --> verify --> destroy
```

The certificates were lost once, in a single `target: both` run before the
`traefik/certs/` exclusion existed: Traefik fell back to self-signed and
every router silently stopped matching. See below for why `dynamic.yml`'s
own deploy step specifically avoids a copy-then-rename.

### How files reach the VPS

The VPS job runs on a short-lived GitHub-hosted Ubuntu runner:

1. `actions/checkout` downloads the selected repository commit.
2. The protected `VPS_SSH_KEY` secret is written to a temporary file with mode
   `0600`.
3. The job constructs SSH options from `VPS_HOST`, `VPS_USER`, and `VPS_PORT`.
   The user defaults to `root` and the port defaults to `2222`.
4. The job snapshots the environment-specific files on the VPS into
   `/root/vps-backups/pre-deploy-<timestamp>.tar.gz`, keeping the ten most
   recent archives.
5. `rsync` sends only the repository's `vps/` directory over SSH to
   `/root/vps/`, **excluding** the four VPS-owned paths in the table below
   (`.env`, `traefik/certs/`, `traefik/dynamic.yml`, `secrets/`).
6. A second SSH command runs on the VPS, validates
   `/root/vps/docker-compose.yml`, and executes
   `docker compose up -d --build --remove-orphans`. The flag matters: a
   service removed from `docker-compose.yml` otherwise leaves its container
   running forever, which is how #2813 found `socat-hp-wordpot` still up a
   week after #2469 retired wordpot and dropped its forwarder rule.
7. A dedicated step generates the deployable `traefik/dynamic.yml` --
   substitutes `DOMAIN` for every `*.honeypot.example` placeholder in the
   committed template -- and validates the result (parses as YAML, no
   leftover placeholders) *before* it ever touches the VPS. Only then is it
   copied to a temporary path on the VPS and written into the live file
   in place with `cat` (see below for why not a plain copy/rename).
8. A verification step fails the job if the certificates or `dynamic.yml` are
   missing, empty, unparseable, or still carry placeholder domains.
9. GitHub destroys the hosted runner, including its temporary key file, after
   the job.

### Files the VPS owns, not the repository

`--delete-delay` removes destination files that no longer exist under the
repository's `vps/` directory, and overwrites the ones that do. Four paths are
therefore excluded from the main `rsync` because the VPS copy is authoritative
(or, for `dynamic.yml`, because it needs different handling entirely):

| Path | Why it is excluded from the main sync |
|---|---|
| `.env` | Secrets and host-specific values. |
| `traefik/certs/` | Issued TLS certificates. They do not exist in the repository, so an unexcluded `--delete-delay` deletes them, and the workflow cannot reissue them. |
| `traefik/dynamic.yml` | Carries the deployment's real domain. The committed copy is a `*.honeypot.example` placeholder -- Traefik's file provider has no `${VAR}`-style substitution the way docker-compose already gives every other host-specific value in this repo, so this file can't just be templated in place the normal way. Deployed by its own dedicated step instead (step 7 above), which substitutes `DOMAIN` and writes the result separately. |
| `secrets/` | Per-gateway OIDC cookie-secret/client-secret files (`OIDC_SECRETS_DIR=./secrets/oidc` in `vps/.env.example`). Git-ignored, so they are never present in the checkout at all -- and `--delete-delay` reads "absent from the source" as "delete it". That happened once for real and took down every oauth2-proxy gateway at the time, which is why the exclude exists. A client-secret is never regenerated: it has to match what is already registered with Keycloak, so recovering it means `kcadm get clients/<id>/client-secret`, and losing it means re-registering the client. |

The pre-deploy backup step ahead of the bulk `rsync` archives the same four
paths (`.env`, `traefik/certs`, `traefik/dynamic.yml`, `secrets/`) that
actually exist, keeping the last ten under `/root/vps-backups/`.

The certificates were lost once, in a single `target: both` run before that
exclusion existed: Traefik fell back to self-signed and every router silently
stopped matching. Persistent VPS data must live in named volumes, bind mounts
outside `/root/vps`, or one of the excluded paths above.

**`dynamic.yml` deploys with a plain in-place `cat`, never a copy-then-rename
(`scp`'s default, `rsync`, or `mv`).** Traefik's compose service bind-mounts
this file at a single path
(`traefik/dynamic.yml:/etc/traefik/dynamic.yml:ro`), which Docker binds to the
*specific inode* present when the container started, not the path. A
rename-based replacement repoints the host path at a new inode while the
already-running container keeps reading the orphaned old one -- silently, with
no error of any kind, and every host-side check (`cat`, `diff`) shows the new
content as correct anyway. This broke production once already, recovered only
by noticing the container's own view (`docker exec traefik cat
/etc/traefik/dynamic.yml`) disagreed with the host file. If you ever need to
edit this file by hand instead of through the workflow (a *structural* router
change, not just a domain difference -- see below), always write in place
(`cat new > /root/vps/traefik/dynamic.yml`) and never `mv`/rename a
replacement into it; `docker compose restart traefik` is the reliable recovery
if a stale-inode mismatch ever happens anyway.

Routine deploys need no manual step for this file at all now -- the workflow
regenerates and redeploys it from the committed template plus `DOMAIN` every
run. A structural change (a new router, a new middleware) still needs the
*template* (`vps/traefik/dynamic.yml` in the repository) edited, committed, and
deployed the normal way; only the domain substitution itself is automatic.
Traefik's file provider watches the live file and reloads on any change with
no restart needed, whether that change came from the workflow or a manual
edit.

The SSH key is the direct production credential in this path. Restrict it to
the intended VPS, keep it in the protected environment rather than repository
secrets where possible, and require environment approval before the job can
read it. `DOMAIN` is not itself sensitive (it is public DNS), but keep it in
the same protected environment as the other VPS secrets for consistency.

### Why these five are still repository secrets, and how to move them (#2027)

The section above describes the intended end state. The live state is not
that: as of 2026-09-03 all five values sit at **repository** scope and both
`production-vps` and `production-home` are empty environments.

```
$ gh secret list -R Xore/APIARY
DOCKERHUB_TOKEN  DOCKERHUB_USERNAME  DOMAIN  VPS_HOST  VPS_PORT  VPS_SSH_KEY  VPS_USER
$ gh secret list -R Xore/APIARY --env production-vps    # empty
$ gh secret list -R Xore/APIARY --env production-home   # empty
```

This is written down because the migration has now been re-derived from
scratch twice, reaching the same blocker both times.

**No workflow edit is needed.** Every `secrets.VPS_*` / `secrets.DOMAIN`
reference already sits inside a job that declares
`environment: production-vps` — `deploy.yml`'s `vps` job (`:231`, environment
at `:234`), `diagnostics.yml`'s `vps` job (`:292`/`:295`), and
`vps-start-blackhole.yml`'s `start-blackhole-profile` job (`:22`/`:24`). The
`home` jobs (`deploy.yml:21`, `diagnostics.yml:112`) read none of the five.
Environment secrets also shadow repository secrets of the same name, so
*writing* the environment copies is non-breaking on its own.

**What blocks it is that GitHub's secrets API is write-only.** There is no
read-back and no copy operation at either scope, so completing the move needs
a human to re-enter five plaintexts — one of which is the live VPS deployment
private key. Automation cannot do this half, and pulling key material through
a tool to "migrate" it would be worse than the drift it fixes.

**Migration order that keeps deploys green**, when someone does it by hand:

1. Write all five into `production-vps` (`gh secret set <NAME> --env
   production-vps`). Deploys keep working throughout — the environment copy
   shadows the repository one.
2. Run one deploy per target and confirm it is green. This is the acceptance
   criterion, and it must happen *before* step 3.
3. Only then delete the repository-scoped copies. Deleting first, or deleting
   against an unverified `DOMAIN`/`VPS_HOST`, silently breaks the next deploy —
   `DOMAIN` is substituted into `traefik/dynamic.yml` at deploy time, so a
   wrong or empty value reaches Traefik rather than failing loudly.

**Rotation is a separate decision.** If a value is re-entered from an unknown
source rather than the password manager, rotate it deliberately rather than
as a side effect of the move.

`DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` (added 2026-09-01) are read only by
`containers.yml:157-162`, which declares **no** `environment:` at all — so
they have to stay repository-scoped until that workflow gains one, and they
are correctly out of this migration's scope rather than merely deferred. They
are still the reason the repository-secret set grew from five to seven, which
is #2027's own argument for doing the VPS half before it grows again.

## Diagnostics

`diagnostics.yml` is the read-only counterpart to `deploy.yml`. It runs on
`workflow_dispatch` and every six hours on a schedule; only a scheduled run
turns red on a degraded finding (#2222). It mirrors the deployment topology: the home job runs
on the `[self-hosted, linux, x64, honeypot-home]` runner, and the VPS job runs
on a GitHub-hosted runner over the same SSH deployment key. Neither changes
anything — they report container state, recent logs, and disk and volume usage.

It exists because the alternative to a scoped read-only workflow is an operator
opening an interactive shell on production to answer a question, and that is
how a diagnosis turns into an accidental change. Keep it read-only. It must
never gain a step that restarts a service, prunes a volume, or writes a file —
if a finding calls for action, the action goes through `deploy.yml` and its
environment approval.

The workflow reads `HP_BIND` and deliberately never prints it: it is an
internal WireGuard address, and the job's output is visible to anyone who can
read the Actions log.

Two checks depend on host provisioning rather than on the workflow (#3312):

- **Pipeline metrics** need the dashboard service token, which lives in
  `/var/dockge/stacks/honeypot-dashboard/.env` (root-only). The home runner
  never reads it: `scripts/github-ci-runner/install-deploy-runner.sh` installs
  the root-owned, argument-less helper
  `/opt/github-ci-runner-helpers/dashboard-source-health.sh` and a NOPASSWD
  grant for exactly that path. The helper returns only the source-health JSON.
  "helper is not installed or not granted" in the summary means re-run that
  installer -- with `--helpers-only`, which applies the helper and the grant
  and stops there, so it does not interrupt whatever job the runner is
  currently executing. A merged PR that adds a grant here changes nothing on
  the host until someone runs it, so that message is the only place the
  dependency is visible.
- **Isolation invariants** run `scripts/isolation-audit.sh` as
  `github-deploy-runner`, which must be in the `libvirt` group
  (`install-homeserver.sh`'s libvirt step re-asserts it). The script pins
  `LIBVIRT_DEFAULT_URI=qemu:///system`, because a non-root `virsh` otherwise
  talks to the empty per-user session and reports every network missing.
  Group membership only takes effect across a runner restart, so unlike the
  helper grant it does need a full installer run. The audit's own host-side
  expectation — that the sandbox stack is *up* — is suspended by a dated
  declaration while it is deliberately down; see
  [honeypot-network-isolation.md](honeypot-network-isolation.md#5-declared-stand-down).

The OIDC discovery probe runs **from the VPS** over the job's SSH key.
Cloudflare answers 403 to GitHub-hosted runner address ranges, so the runner's
own result is printed for information only and never fails the job.

### Every finding is categorised (#3312)

This workflow failed 160 consecutive scheduled runs without anybody triaging
it, which means it carried no signal at all. The reason was not that the
findings were wrong — several of them were correct — but that a real host
fault, a lane that had never been able to see anything, a check asking from a
vantage point the endpoint answers differently to, and a deliberate stand-down
all produced the same thing: a red X, an `::error::` line with nothing on its
subject, and a body nobody had time to read. A run that lists five unrelated
things under one heading gets triaged by ignoring it.

So every finding now carries one of four categories. The category is the
annotation's own title, and each job ends with a ledger — one table, one row
per finding, plus the counts — so triage is reading six lines rather than
reconstructing a run from its log:

| category | Meaning | Fatal on a scheduled run |
|---|---|---|
| `fault` | A real regression: the pipeline or the host is broken | yes |
| `runner-config` | The check could not run because of how the runner or this repository's environment is configured — a helper not installed, a grant not applied, a secret unset | yes |
| `unmeasured` | The check did not run, and that is not a pass | yes |
| `expected` | A deliberate, declared absence | no |

`runner-config` being fatal is deliberate, and it is the same position
`scripts/verify-deploy.sh` already takes with its exit 2: folding "could not
tell" into a pass is the outcome that makes a check worse than not having it.
#3283 is what that costs when it is wrong — Elasticsearch at 1000/1000 shards
with every sensor's events dead-lettered for six days, in a lane whose only
question is whether the pipeline is flowing. What changes is that it is its own
category with its own title, so "this lane has never been able to measure
anything" is tellable apart from "the pipeline is broken" without opening the
log, and the fix is the operator command the finding names rather than the
symptom.

The vocabulary lives in `scripts/diagnostics-lib.sh`, which every step sources;
`alert` takes a category and refuses a non-fatal one, `note` records a finding
that must not redden the run, and `diag_ledger_report` prints the table. The
isolation audit has its own finer-grained labels and its own footer, and the
step carries that line into the ledger verbatim rather than re-deriving it — one
source of truth for the counts.

Both jobs now check the repository out (#2908). Every other step still reads
the deployed stack under `/opt/stacks/apiary`; the checkout is for the scripts,
so a check asks its question with the code that was just fixed. Running
`isolation-audit.sh` from a copy refreshed only by a `workflow_dispatch`-only
deploy is why the red X kept naming things that had already been fixed. The
deployed copy is still diffed against `origin/main` and reported when it drifts,
because drift is a real finding for everything else on the host that runs a
deployed script.

### Diagnostics vs. mutating deploy

```mermaid
flowchart LR
  operator["Operator"]

  subgraph diag["diagnostics.yml — workflow_dispatch only, read-only"]
    diagHome["home job —<br/>same runner as deploy.yml's<br/>home job"]
    diagVPS["VPS job —<br/>same SSH key as deploy.yml's<br/>VPS job"]
    diagReport["container state, recent logs,<br/>disk/volume usage --<br/>never a restart, prune, or write"]
    diagHome --> diagReport
    diagVPS --> diagReport
  end

  subgraph mutate["deploy.yml — protected environment approval required"]
    deployHome["home job"]
    deployVPS["VPS job"]
    deployChange["writes compose.yml, runs<br/>docker compose up --<br/>real, approved changes"]
    deployHome --> deployChange
    deployVPS --> deployChange
  end

  operator -->|"answer a question"| diag
  operator -->|"a finding calls for action"| mutate
```

Same runners, same credentials, same deployment topology — `diagnostics.yml`
mirrors `deploy.yml`'s shape deliberately, so an operator never needs an
interactive shell on production just to answer "is this healthy," which is
exactly how a diagnosis turns into an accidental change. The only
difference that matters is that `diagnostics.yml` has no step capable of
mutating anything; a finding that calls for real action still goes through
`deploy.yml` and its environment approval, never a follow-up edit to the
diagnostics workflow itself.

## Delivery paths at a glance

```text
Home:
GitHub -> outbound-polling self-hosted runner on homeserver
       -> local rsync /opt/stacks/apiary
       -> compose config --quiet (validation only, no `up`;
          the root file is services: {})
       -> Arcane's own Git-sync machinery materializes and
          deploys stacks (ARCANE-GIT-SYNC.md)

VPS:
GitHub-hosted runner -> rsync + SSH over VPS_PORT
                     -> /root/vps
                     -> docker compose up on VPS
```

The home path has not run a deploy in this workflow since #1502 — see
"What deploy.yml actually runs (since #1502)" above for the full list of
what it does instead. A `home` run that succeeds has still changed nothing
on the host.

Selecting `both` creates both jobs from the same workflow run. They share the
`honeypot-production` concurrency group, but the home and VPS jobs are
otherwise independent: one can fail while the other succeeds. Always inspect
both job results before calling a two-target deployment complete.

## Running a deployment

Open **Actions → Deploy → Run workflow**, select `home`, `vps`, or `both`, then
approve the relevant protected environment. Deployments are intentionally
manual; a push to a public repository never changes production by itself.

The workflow deploys the commit selected in the **Run workflow** dialog,
normally the current `main`. Merging a pull request starts checks and container
publishing, but does not invoke `Deploy`; an operator must dispatch it
separately.

For each target, verify the run after Compose finishes:

- the deployment job used the expected commit SHA;
- `docker compose ps` shows the intended services running and healthy;
- Dashboard, EveBox, Kibana, and Arkime respond where applicable;
- Filebeat and Elasticsearch report no output errors;
- source timestamps and indexed document counts continue advancing.

If the home runner is offline, the home job remains queued. If an environment
approval is missing, the job waits before gaining access to that environment's
secrets or runner. A VPS authentication failure stops before the remote Compose
command; a Compose validation failure stops before services are reconciled.
