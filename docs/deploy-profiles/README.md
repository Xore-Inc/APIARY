# Deployment profiles

[← back to README](../../README.md)

Which of the split home stacks (#258) are active for a given deployment
shape. The authoritative roster is
`arcane/manifests/home-production.json` — since #1502 there is no per-stack
sync loop anywhere (`deploy.yml` deploys no home stack itself; see
[ARCANE-GIT-SYNC.md](../ARCANE-GIT-SYNC.md)). Declared here instead of by
hand-editing which stacks you happen to run, so an operator running a
narrower deployment (fewer sensors, no VPS) has a named, checkable choice
instead of an implicit one nobody wrote down.

Different axis from [#258](https://github.com/Xore/APIARY/issues/258)
itself, which is about *topology* (one compose file per stack vs a
monolith) -- this is about *persona declaration*: which honeypots/dashboards
run for a given deployment, independent of how the compose files are
physically organized.

## Format

Each `.txt` file here is a plain list of home stack names (the suffix after
`honeypot-`, matching the directories under `arcane/home/`) -- one per
line, `#` comments and blank lines ignored.

## Profiles

| Profile | Backbone | Sensors | Shape |
|---|---|---|---|
| [`full.txt`](../../deploy-profiles/full.txt) | keycloak, init, elk, dashboard, backend-workers, utilities, payload-analysis | the 20 classic deception sensor stacks under `arcane/home/` -- but see the gap below | the standard deployment -- everything this repo ships |
| [`ics-focused.txt`](../../deploy-profiles/ics-focused.txt) | keycloak, init, elk, dashboard, backend-workers, utilities | conpot, dnp3 | OT/ICS-only exposure -- skip the general-purpose/web/SSH/legacy-protocol sensors entirely |
| [`minimal-web.txt`](../../deploy-profiles/minimal-web.txt) | keycloak, init, elk, dashboard, backend-workers, utilities | http, tanner | web-attack-focused -- HTTP/API honeypot + SNARE/TANNER, skip ICS/SSH/legacy-protocol sensors |

**`full.txt` is not actually "everything this repo ships".** It lists 26
stacks (6 backbone + 20 sensors) and omits `honeypot-sonicwall-sma`, the
decoy sensor stack #3131 added on 2026-09-08 (`hp-sonicwall-sma-honeypot`
on `${HP_BIND:-10.8.0.2}:8543`). It is a natural fit for both `full.txt` and
`ics-focused.txt`, and is in neither. The other `arcane/home/` stacks the
profiles deliberately skip are the analysis-plane workers and
`honeypot-dashboard-backend` (not persona declarations, per below) plus
`unsloth` (the #3092 benchmark toolchain) -- and `rex86-eval`, which exists
on disk but is in no manifest entry at all.

`init` and `elk` are structural dependencies for any profile that includes at
least one sensor; `keycloak` is a structural dependency of `dashboard`, and
`elk` is too. `scripts/validate-deploy-profile.sh` enforces all three, so
these aren't just conventions to remember. `payload-analysis` and
`utilities` are strongly recommended (payload dedup/YARA scanning, log
rotation/disk monitoring/autoheal) but not structurally required, so the
validator only warns if either is missing from a non-empty profile. Note
that `dashboard` itself is *not* a required structural dependency: the
validator never demands it, it only imposes `elk` and `keycloak` on a
profile that has chosen it.

Not covered here: the VPS side (`vps/`, always deployed the same way
regardless of home profile -- see `docs/CGNAT-DEPLOYMENT.md`), the
analysis-plane workers (`ip-enrichment-worker`,
`agent-intrusion-worker`, and friends), and the `dashboard`/
`elk`/`keycloak` backbone -- none of these are persona declarations; they
are either unconditional infrastructure or governed separately from
sensor choices.

## Sizing per profile (#3328)

`scripts/deploy-profile-sizing.py` sums the `cpus:`, `mem_limit:` and
`memory:` values the compose files already declare, for exactly the stacks a
profile lists:

```bash
scripts/deploy-profile-sizing.py
```

| profile | stacks | declared cpus | declared memory |
|---|---|---|---|
| `full` | 27 | 118 | 69.2 GiB |
| `minimal-web` | 8 | 79.5 | 52.0 GiB |
| `ics-focused` | 8 | 70.5 | 46.2 GiB |

**These are ceilings, not measurements.** A `mem_limit` is the most a container
may claim, so the column is an upper bound on what the profile could ask the
host for if every stack peaked at once. It is not steady-state use: a
`minimal-web` host does not sit at 52.0 GiB with two sensors running. Nothing
here was measured under load, and the numbers are only as current as the last
`cpus:` edit. `tests/docs/test_3328_profile_sizing_matches_compose.py`
recomputes the table on every CI run and fails if it drifts.

Two things the table deliberately leaves out, because a summed number would
mislead:

- **The ES heap is not in the memory column.** Elasticsearch gets its memory
  from `ES_JAVA_OPTS=-Xms6g -Xmx6g`
  (`arcane/home/honeypot-elk/compose.yml`), not from a `mem_limit`, so the
  `elk` figure above covers Logstash/Filebeat/Beats only. The 6g heap is the
  floor that actually matters on a small host -- a profile cannot be sized
  below it, and #240 is why it is pinned rather than left to the JVM default.
- **A stack with no declared limit contributes zero.** That is the dangerous
  case, not the small one: Docker will not stop an undeclared container from
  growing. The script lists those stacks by name under each profile, so an
  undeclared limit is visible rather than silently zero.

Sizing the analysis-plane workers, the `dashboard`/`elk`/`keycloak` backbone
and the VPS is out of scope here, matching the "Not covered here" note above.

## Validating a profile

```bash
scripts/validate-deploy-profile.sh deploy-profiles/ics-focused.txt
```

Checks, against the *current* repository state (not a hardcoded snapshot):

1. **Structural dependencies** -- `init`/`elk` present if any sensor stack
   is listed; `elk` and `keycloak` present if `dashboard` is listed (the
   dashboard reads several sensors' events from Elasticsearch, not their
   log files -- see #403 for why that's a real dependency, not a
   nice-to-have; and the target auth path is native Keycloak OIDC).
2. **Real-stack existence** -- every listed name must correspond to an
   actual `arcane/home/honeypot-<name>/` directory, so a typo'd or retired
   stack name fails here instead of surfacing mid-deploy or as a silently
   absent Arcane project.

Add a new profile by adding a `.txt` file here in the same format; no code
change needed for the validator to pick it up.

> **History: the EXPECTED_SENSORS cross-check (#2359).** The validator used
> to also parse an `EXPECTED_SENSORS=` value out of
> `arcane/home/honeypot-dashboard/compose.yml` and verify the profile's
> sensor names against it. Commit 824aa33d (#1628) removed that variable
> when the dashboard cutover completed; nothing consumes it anywhere today,
> because the modern source-health view (`backend-service/src/health.rs`)
> derives sensor liveness from observed `event.sensor` values rather than a
> static expectation list. Both the check and its `--emit-expected-sensors`
> helper were deleted rather than restored to an ownerless contract -- and
> the deletion was done loudly (#2359): passing `--emit-expected-sensors`
> now prints why it is gone instead of failing wordlessly, which is more
> than the old check ever managed when the variable vanished under it.
