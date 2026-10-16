# Vendored GHOSTS source (#1506)

This directory is a trimmed copy of [`cmu-sei/GHOSTS`](https://github.com/cmu-sei/GHOSTS)'s
`src/` tree, pinned at commit `335d11e5b73c278626a0a63f5bfbdec60cda7d8e` (the
`v9.0.0` tag) — the same commit `sandbox/ghosts/compose.yml` was already
building from via a remote Git build context before this change.

## Why this exists

Arcane's own image-prep step resolves a Docker build context's remote Git
ref only under `refs/heads/`, unlike plain `docker build`/BuildKit (which
resolves a tag name or a commit SHA on its own with no ref-namespace
guessing needed). Confirmed live against the pinned Arcane `v2.8.0`, in
order: a tag name failed with `couldn't find remote ref "refs/heads/v9.0.0"`,
and re-pinning to the tag's commit SHA instead failed the exact same way —
Arcane prefixes `refs/heads/` onto *any* ref string passed this way, not
just tag names. See #1506 and `docs/ARCANE-GIT-SYNC.md`'s "Known Arcane
v2.8.0 limitations" section for the full write-up.

There is no compose-file-level fix for that — Arcane's directory sync
already correctly materializes local files (it just can't resolve *remote*
git refs the way `docker build` does), so trading "no local copy of
upstream source" for "actually buildable through Arcane like every other
stack" makes `ghosts-api`/`ghosts-client-test` build the same way through
Arcane as everything else in this repo, no manual post-sync `docker compose
build` step required.

## What's here vs. upstream

Only what `Dockerfile-api` and `Dockerfile-client-universal` actually `COPY`
into their build stages, trimmed the same way upstream's own
`src/.dockerignore` already trims the Docker build context (`bin/`, `obj/`,
`_db/`, `Ghosts.Api/wwwroot/lib/fontawesome/svgs/`,
`Ghosts.Api/wwwroot/flags/` are all excluded here too — the running
container never received those either way, so excluding them changes
nothing at runtime and just avoids vendoring ~14MB nothing uses):

- `Dockerfile-api`, `Dockerfile-client-universal`, `.dockerignore`
- `certs/` (client-universal's CA bundle)
- `Ghosts.Api/`, `Ghosts.Domain/`, `Ghosts.Animator/` (ghosts-api's build —
  `Ghosts.Api.csproj`'s own `ProjectReference`s)
- `Ghosts.Client.Universal/`, `Ghosts.Domain/` (ghosts-client-test's build —
  `Ghosts.Client.Universal.csproj`'s own `ProjectReference`)
- `LICENSE.md` (MIT-style, Carnegie Mellon University — required to
  accompany copies of the software)

Not vendored: everything else in upstream's `src/` (`Ghosts.Client.Lite`,
`Ghosts.Client.Windows`, `Ghosts.Frontend`, `Ghosts.Pandora`, test projects,
`apphost`, `tools`) — none of it is reachable from either Dockerfile this
repo actually builds, matching #324's own original scope decision to skip
GHOSTS' operator-facing tooling.

## What's stripped at build time

The vendored tree itself stays upstream-verbatim — but `ghosts-api` is not
built from `Dockerfile-api` directly. `sandbox/ghosts/Dockerfile.api-prep`
(#2444) copies these same sources and deletes three controller files before
`dotnet publish` (the animations control plane, the `/animations` web UI
and `/api/attack` — all #324-excluded operator tooling; the wrapper's own
header explains each one). Nothing changes for this step when re-copying a
bumped pin: the wrapper's `rm` list is by path, so an upstream
move/rename of a listed file surfaces as a build failure to re-decide, not
as a silently skipped strip.

It also patches `Program.cs` in the build copy (#2257) to drop
`app.UseSwagger()`/`app.UseSwaggerUI()`, and ships
`ASPNETCORE_ENVIRONMENT=Production` instead of upstream's `DEVELOPMENT`, so
the image serves neither an anonymous endpoint map nor developer exception
pages -- the API authenticates nobody, so both were readable by any guest
that reached the socket. The sed is bracketed by assertions (exactly two
`app.UseSwagger*` lines before, none after), giving it the same
fail-the-build-on-upstream-drift property as the `rm` list.

## Config deviations from upstream (#2256)

Unlike the controller/`Program.cs` strips above (build-time patches over an
untouched tree), these are direct edits to the vendored config files
themselves — deliberate, and recorded here per #2256's acceptance
criterion that the vendored config diff vs. upstream consist only of
commented deviations.

**What was and was not verified.** The removals below were established
*statically*: each egress path was traced from the config value to the code
that reads it, and every deleted file was shown unreachable (Swagger-strip
plus deleted-controller reachability analysis) before deletion.
`scripts/check-ghosts-vendored-egress.sh` locks the result in and was proven
to catch a reintroduced domain. `dotnet publish -c Release` on
`Ghosts.Client.Universal` was run against the post-deletion tree under
`mcr.microsoft.com/dotnet/sdk:10.0.101` and exits 0, so nothing deleted here
is still referenced by the build.

The behavioural half is **not** done: the stack was never booted and no
tcpdump capture was taken, so "a fresh boot emits no traffic to these
domains" is a reasoned conclusion, not a measurement. Anyone booting this
stack should run that capture and record the result here.

- **`Ghosts.Api/appsettings.json`** — `AnimatorSettings.Animations.IsEnabled`
  changed `true` → `false`. Upstream's sample config ships the whole
  NPC/animator engine autostarting on boot, which is out of #324's scope
  ("NPC-simulation," not live external posting) and was generating two
  live egress paths on the ~9s animation turn loop: a plaintext HTTP POST
  from the API container to `SocialSharing.PostUrl`
  (`http://socializer.com`, a real third-party demo domain baked into
  upstream's sample config), and a `BrowserFirefox`/`isheadless:false`
  timeline pushed to enrolled guests (win11-ghosts) telling them to open a
  visible browser and browse that same domain. `IsEnabled: false` at the
  top of `Animations` gates the whole engine off before any of the four
  sub-animations (`SocialGraph`, `SocialBelief`, `SocialSharing`, `Chat`,
  `FullAutonomy`) or their `ContentEngine.Host` `localhost:11434`
  (Ollama)/`localhost:8065` (Mattermost) assumptions are ever reached — so
  those localhost assumptions, left as-is in the file, are now
  unreachable rather than a live per-cycle failure-loop-logging concern.
  Also cleared `SocialSharing.PostUrl` to `""` (was
  `http://socializer.com`) as defense-in-depth, so a future accidental
  `IsEnabled: true` flip doesn't silently resurrect the same third-party
  target — if social simulation is ever wanted, `PostUrl` must be pointed
  at a local throwaway service inside `ghosts_net`, never a public DNS
  name, never plaintext off-box.
- **`Ghosts.Client.Universal/config/timeline.json`** — deleted the `Curl`
  handler (hit real third parties: `httpbin.org`, `www.wikipedia.org`,
  `news.ycombinator.com`, alongside `example.com`) and the `Ssh` handler
  (an embedded `admin`/base64-`admin` credential pair targeting
  `10.0.0.50`, an address that exists on no APIARY network) from this
  smoke-test client's default timeline. Deletion, not substitution, for
  the same reason #2256 gives for the SSH credential specifically:
  there's no real target for either handler to reach that would make
  keeping them meaningful. The harmless local `Bash` handler (recon
  commands against the client's own filesystem, no network egress) is
  unchanged. This file is baked into the `ghosts-client-test` image
  (`Ghosts.Client.Universal.csproj`'s `CopyToOutputDirectory=Always`) and
  autostarts (`"Status": "Run"`) the moment that profile-gated smoke-test
  container boots.
- **`Ghosts.Client.Universal/config/health.json`** — `CheckUrls` emptied
  (was `["http://cmu.edu"]`, an upstream-org callback URL with no purpose
  here). `HealthRecord.Check()` iterates `CheckUrls` in a plain `foreach`,
  so an empty list is a safe no-op, not a code path change.
- **Deleted `Ghosts.Api/config/timelines/` (26 files) and
  `Ghosts.Client.Universal/config/{application,timeline}.example.yaml`** —
  confirmed unreachable by any code path this deployment actually runs
  before deleting, not merely unreferenced-looking:
  - `config/timelines/*` is loaded by exactly one place in the whole tree,
    `Ghosts.Api/Infrastructure/Examples.cs` (a Swagger
    `IExamplesProvider`) — and `Dockerfile.api-prep` (#2257) already
    strips `app.UseSwagger()`/`UseSwaggerUI()` from the build, so nothing
    ever invokes an examples provider. The only other consumer,
    `AnimationJobsController`'s dynamic by-name timeline loader, is
    already deleted by this same Dockerfile (#2444). Several of these
    files carried real third-party targets:
    `BrowserChromeBlogDrupal.json` (`netexhsv.com:8080`),
    `BrowserChromeSharepoint.json` (`portal.sitea.com`),
    `Browser upload.json` (`some_server.com`), `Browser Crawl.json`
    (`usatoday.com`/`cnn.com`/`cmu.edu`/`espn.com` via a `localhost:8080`
    recording proxy that also doesn't exist here), `trackables
    timeline.json` (`dl.dafont.com`), and `BrowserFirefox.json`
    (`cmu.edu`/`sei.cmu.edu`). Deleting the whole directory rather than
    only the files with URLs avoids leaving an arbitrary, equally-dead
    remainder for no purpose.
  - `config/*.example.yaml` are marked `CopyToOutputDirectory=Always` in
    `Ghosts.Client.Universal.csproj` (so they do ship in the built image)
    but are never read by any C# code in the tree — pure copy-and-edit
    starting templates for a from-scratch deployment, not runtime
    defaults. `timeline.example.yaml` in particular carried dozens of
    real domains (`nytimes.com`, `target.com`, `reddit.com`, etc.).
    Deleted rather than kept-as-inert, since they added real third-party
    strings to the shipped image for zero operational purpose.
  - **Not deleted, deliberately:** `Ghosts.Api/config/military_mos.json`.
    It looks equally dead by the same "grep for a reference" test, but
    `Ghosts.Animator/MilitaryRanks.cs:93` does
    `File.ReadAllText("config/military_mos.json")` — a live local-file
    read from the animator library used for persona/MOS generation. Its
    `Url` fields are Wikipedia citation-link *values* stored into
    generated profile data, never fetched by our code (no
    `HttpClient`/`WebRequest` call anywhere near this file), so it
    creates no egress — but deleting it would risk a real
    `FileNotFoundException` the first time animator persona generation
    runs, wherever that turns out to be, so it stays.
    `scripts/check-ghosts-vendored-egress.sh` allowlists it by name with
    this same reasoning rather than silently passing it.

## Updating the pin

There's no script for this yet (a genuine gap, same as every other vendored
dependency in this repo) — bump it by hand:

1. Check out `cmu-sei/GHOSTS` at the new tag/commit.
2. Re-copy the same path list above from its `src/` into this directory,
   applying the same `.dockerignore`-matching exclusions.
3. Update the commit SHA in this file and in `sandbox/ghosts/compose.yml`'s
   own header comment.
4. Rebuild locally (`docker compose -f sandbox/ghosts/compose.yml build`)
   and re-run the enrollment smoke test
   (`docker compose --profile test run ghosts-client-test`) before trusting
   the bump.

## Dockerfile-api base-image pin (#3667)

`Dockerfile-api`'s `FROM mcr.microsoft.com/dotnet/sdk:10.0` was a floating
tag the base-image CVE gate could not pin or exempt. It is now
`mcr.microsoft.com/dotnet/sdk:10.0.402@sha256:0d99ebf1…`, the same digest
`sandbox/ghosts/Dockerfile.api-prep` uses. That is the only line changed
in `Dockerfile-api`. The build that actually runs is `Dockerfile.api-prep`,
which copies these sources and does not depend on this stage.
