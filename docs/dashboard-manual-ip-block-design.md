# Operator-triggered IP block — design decision

> **Status (2026-08-27, #1662):** point-in-time design record kept because
> shipping code still cites its decisions (`vps/docker-compose.yml` and
> `vps/portbridge-manual-blackhole-refresh.sh` reference decision 4). The
> `dashboard/*.go` file references below describe the pre-cutover Go
> dashboard and are historical; the binding content is the decision logic
> that carried into the VPS scripts and their backend-service equivalents.

> **Status**: Decided and implemented, first cut. Tracking: [#914](https://github.com/Xore/APIARY/issues/914).

## Why this exists

[#914](https://github.com/Xore/APIARY/issues/914) noted that portbridge already
drops connections from addresses in `BLACKHOLE_LIST` (#268,
`vps/portbridge/blackhole.go`), and that IP-centric dashboard pages
(`/investigate/ip/{ip}`, IOC correlation then in `dashboard/ioc_correlation.go`, now
`backend-service/src/ioc_correlation.rs`) already surfaced confirmed-malicious IPs with pivot/investigate links — but
there is no "block" action anywhere in the dashboard. Unlike
[#912](https://github.com/Xore/APIARY/issues/912)/[#913](https://github.com/Xore/APIARY/issues/913),
this is not a drop-in wiring fix: `BLACKHOLE_LIST` today is wholly owned by
an external, periodically-refreshed maltrail feed, and the dashboard and
portbridge run on two different hosts. This document records the decisions
made to close that gap.

## Decision 1: scope — any IP on the per-IP attacker page

Decided explicitly, overriding an earlier draft of this document that
proposed gating the block action to only IPs the IOC correlation pipeline
(#680, then `dashboard/ioc_correlation.go`, now `backend-service/src/ioc_correlation.rs`) had marked `ConfirmedAtRuntime`. That
gate would have made the correlation pipeline's own judgment a hard
precondition for an operator's; the operator investigating a specific
attacker on `/investigate/ip/{ip}` is the actual judgment call, and the
correlation signal is one input to it, not a switch that should block the
action outright when absent (most attacker IPs a honeypot logs have no
sandbox-confirmed malware callback at all — that is not evidence they aren't
worth blocking).

`/investigate/ip/{ip}` still surfaces `ConfirmedAtRuntime` as an
informational badge (`confirmedMaliciousIPs()`/`ipIsConfirmedMalicious()` in
`ioc_correlation.go`, re-running the same per-sample correlation
`ghidraData()` already does for a single Detail row across every Ghidra
result with a sandbox run) — it just doesn't gate the form.

Not in scope for this first cut: blocking by CIDR, or surfacing the action
anywhere other than the per-IP attacker page.

## Decision 2: lifecycle — manual unblock, with an optional per-block expiry

A manual block stays active until an operator explicitly unblocks it, unless
the operator sets an expiry at block time (`expires_days` on the block form),
in which case it also lapses automatically once that many days pass. Both
paths exist side by side rather than picking one: an operator blocking known,
durable malicious infrastructure wants a permanent block with the same
"acknowledged until reopened" lifecycle `alerts.go`/`ml_anomaly_ack.go`
(#913) already establish elsewhere in this codebase; an operator blocking a
noisy-but-maybe-transient source wants it to lapse on its own rather than
becoming one more permanent entry nobody revisits.

Expiry is enforced by computing `ipBlockRecord.Active()` fresh on every read
(`Blocked && (ExpiresAt.IsZero() || now.Before(ExpiresAt))`) rather than a
background sweep that rewrites the record — the same "computed fresh on
every call" approach `ioc_correlation.go` already uses, so there is no sweep
job to fail silently and no window where a stale sweep interval keeps an
expired block enforced past its stated expiry.

## Decision 3: state and audit trail — dashboard-owned, ES-backed

`dashboard/ip_block.go` added `ipBlockManager` (ported to
`backend-service/src/ip_block.rs` in the Rust cutover; same ES-backed shape),
a direct structural copy of
`mlAnomalyAckManager` (#913): a dedicated Elasticsearch index
(`dashboard-ip-block-v1`), the same `docGet`/`docIndex`/`errESConflict`
optimistic-concurrency retry loop, keyed by the IP address itself (already a
stable, unique key — unlike an ML anomaly, no derived document ID is needed).
Every block/unblock records `BlockedBy`/`BlockedAt`, satisfying the issue's
own "explicit audit trail of who blocked what and when." No second audit
mechanism: nothing here needs `s.settings.audit` on top of the block record's
own actor/timestamp fields, since (unlike github-analysis publishing) a
refused or malformed block request has no external consequence worth a
separate audit entry.

## Decision 4: cross-host delivery — pull, not push

This is the actual new plumbing the issue called out. portbridge's blackhole
enforcement runs on the VPS; the dashboard runs at home
(`docs/CGNAT-DEPLOYMENT.md`). The only existing channel between them is a
**read-only SSHFS mount in the other direction** — home mounts the VPS's
Suricata/portbridge logs read-only over WireGuard
(`docs/ARCHITECTURE.md`); home cannot write to the VPS's filesystem this way,
and nothing about that mount should change just to carry six more bytes of
IP address.

Rather than opening a new inbound-to-VPS write channel — the VPS is
deliberately the more exposed, internet-facing box, and minimizing what can
write to it is a real security property worth keeping, not an accident of
history — the manual list is delivered exactly the way the maltrail feed
itself already is: **the VPS pulls it, on a timer, over the WireGuard tunnel
that already exists** (home is reachable at `10.8.0.2`,
`docs/CGNAT-DEPLOYMENT.md`), the same "pull, don't get pushed to" posture
`portbridge-blackhole-refresh.sh` already uses against GitHub. Concretely:

- The export is served as `GET /export/portbridge-manual-blackhole.txt`, but
  that is a **frontend** route, not a backend one:
  `frontend-next/src/routes/export.portbridge-manual-blackhole[.]txt.ts`
  proxies to the backend's `GET /api/v1/ip-block-export` (handler
  `ip_block::export` in `backend-service/src/ip_block.rs` — the Rust successor
  to the Go `dashboard/ip_block.go`'s `serveManualBlackholeExport`). Both tiers
  exist and they are not the same endpoint: the `.txt` path is the one
  `vps/portbridge-manual-blackhole-refresh.sh` fetches. The body is plain text, one
  IPv4 address per line, the exact format `blackhole.go`'s existing parser
  already reads. ~~No admin auth on the handler itself, the same posture every
  other `/export/*.csv` GET already takes (access control is the network
  boundary — WireGuard-only reachability — not a second app-layer secret)~~ —
  **corrected by #3403:** that posture assumed the frontend's unauthenticated
  passthrough, and it stopped being true. The route is now reached as
  `/api/v1/ip-block-export` behind `require_service_token` (#2183), so the
  puller authenticates with the dashboard's shared service token rather than
  relying on reachability alone. The data itself (a list of IPs an operator
  already chose to block) is still no more sensitive than the maltrail feed it
  sits alongside; what changed is that the *route* is no longer open. Reachable
  from the VPS at `10.8.0.2:19090` — the `dashboard` service's real published port
  (`arcane/home/honeypot-dashboard/compose.yml`, `${HP_BIND:-10.8.0.2}:19090:8080`), not an
  assumed default.
- A new sidecar, `vps/portbridge-manual-blackhole-refresh.sh`, is a near-
  verbatim copy of `portbridge-blackhole-refresh.sh` pointed at that URL
  instead of GitHub's maltrail mirror, writing to a second local file
  (atomic temp+rename, same as the original). ~~It has no minimum-count sanity
  floor the way the maltrail refresh does (500 lines) — an empty manual list
  is a completely normal, expected state (no IP has been manually blocked
  yet), not a sign of a broken download.~~ — **reversed by #3403:** an empty
  body is no longer written, for the reason in the note below.
- `blackhole.go` gains a second optional path, `BLACKHOLE_MANUAL_LIST`, and
  `reload()` unions both files into one blocked-set. The two sources are
  independently refreshed and independently sized, so a maltrail refresh can
  never silently wipe a manual block, and vice versa — this was the issue's
  own explicit "survive a feed refresh?" question, answered by construction
  rather than by carefully sequencing two writers against one file.

### #3403 (2026-09-27): the puller's URL was not a route, and it could not tell

The sidecar above shipped pointed at `/export/portbridge-manual-blackhole.txt`.
That path is not served. The frontend answers an unknown path with an auth
redirect, so the puller's `curl -fsSL` exited 0 on a 200 whose body was a login
page, and every 300 seconds it replaced a working `manual.txt` with nothing
while logging `updated (0 addresses)`. Operator blocks stopped reaching
portbridge and nothing said so.

Three corrections, all in `vps/portbridge-manual-blackhole-refresh.sh` and
`vps/docker-compose.yml` — the export route itself is unchanged, including its
status codes:

1. **The URL is the real one.** `/bff/api/v1/ip-block-export`: the route is the
   Rust tier's `/api/v1/ip-block-export`, reached through the BFF's `/bff/*`
   proxy — the same seam
   `scripts/github-ci-runner/dashboard-source-health.sh` already uses to call
   the Rust tier from a shell, and the only one on the dashboard's published
   port. Redirects are no longer followed, so a 307 is visible as a 307 instead
   of quietly fetching whatever it pointed at.
2. **The puller authenticates.** The route is service-token gated (#2183), so
   the request carries `X-Service-Token: $DASHBOARD_SERVICE_TOKEN` — the same
   shared secret the home stack maps to `SERVICE_TOKEN` for every tier. The VPS
   copy lives in its own git-ignored, `chmod 600` `.env` (tracked template
   `vps/.env.example`), which the deploy rsync excludes. It is handed to `curl`
   through its stdin config (`-K -`) so it is never in argv, never in the
   container's process list, and never in the log. No second auth mechanism was
   invented and no token is committed. Unset is a loud refusal, not an
   unauthenticated attempt: the unauthenticated answer is precisely the bug.
3. **An empty body is refused, not written.** This reverses the
   "no minimum-count sanity floor" decision above, and the reason is that the
   decision's premise no longer holds. The original reasoning was that an empty
   manual list is a normal steady state, not a broken download — true of the
   *dashboard's* state, but over the wire it is indistinguishable from every
   failure mode at once, and #3403 is that ambiguity made silent. A download is
   now written only after it is proven to be a blocklist: HTTP 200, non-empty
   body, `text/plain` content type, and every non-comment line an address —
   the same shapes `blackhole.go`'s `readOne` consumes, so a legitimate IPv6
   entry cannot refuse the whole export. Anything else — the 404 that always
   worked, the 307 to `/auth/login`, a 0-byte 200, an HTML page — is refused
   with a named `[E-*]` marker on every interval and the existing list is left
   untouched. A genuinely empty list is still harmless: `blackhole.go` treats a
   missing file as "no blocklist yet", and the first non-empty export replaces
   the stale one.

### #3578 (2026-10-17): the puller holds an export-only token, not the service token

Correction to point 2 above and to the "no second auth mechanism" line: the
shared service token reaches the whole backend API, including service actions
(#3577), so a VPS that holds it can do far more than read a blocklist. The
decision on apiary-dashboard#246 is a second, narrower credential:

- The rewrite dashboard's `/export/portbridge-manual-blackhole.txt` accepts
  `X-Export-Token` equal to its `EXPORT_TOKEN` (or a signed-in session) and no
  longer accepts `SERVICE_TOKEN`. The dashboard refuses to boot if the two are
  equal. Unset `EXPORT_TOKEN` turns machine access off.
- The sidecar sends `X-Export-Token: $BLACKHOLE_EXPORT_TOKEN` to that route
  (host and port from `DASHBOARD_CANDIDATE_HOST`/`_PORT`, default
  `10.8.0.2:19092`). `DASHBOARD_SERVICE_TOKEN` is gone from the VPS compose
  file, script and `.env.example`.
- The failure rules are unchanged: a 401 (wrong or missing token), a 5xx, a
  login page, an empty body or an unreachable tunnel are each refused with a
  named `[E-*]` marker and the last good list stays in place.
- Rollout: deploy the dashboard with `EXPORT_TOKEN`, put the same value in the
  VPS `.env` as `BLACKHOLE_EXPORT_TOKEN`, then enable the `blackhole` profile
  service. Verify the export answers 200 with the export token and 401 with
  the service token.

## What "first step" deliberately leaves out

- No CIDR blocking, no rate limit on how often an IP can be toggled — neither
  was asked for, and adding them here would be speculative scope past what
  #914 actually requested.
- The VPS-side sidecar is opt-in via the same `blackhole` compose profile the
  existing maltrail refresh already uses (`vps/docker-compose.yml`) — a
  deployment that doesn't run the `blackhole` profile at all is unaffected,
  exactly as before this change.
