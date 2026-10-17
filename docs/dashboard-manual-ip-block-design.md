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
  proxies to the backend's `GET /api/v1/ip-block-export`
  (`backend-service/src/main.rs:345`, handler `ip_block::export` — the Rust
  successor to the Go `dashboard/ip_block.go`'s
  `serveManualBlackholeExport`). Both tiers exist and they are not the same
  endpoint: the `.txt` path is the one
  `vps/portbridge-manual-blackhole-refresh.sh` fetches. — plain text, one
  IPv4 address per line, the exact format `blackhole.go`'s existing parser
  already reads. No admin auth on the handler itself, the same posture every
  other `/export/*.csv` GET already takes (access control is the network
  boundary — WireGuard-only reachability — not a second app-layer secret);
  the data itself (a list of IPs an operator already chose to block) is no
  more sensitive than the maltrail feed it sits alongside. Reachable from the
  VPS at `10.8.0.2:19090` — the `dashboard` service's real published port
  (`arcane/home/honeypot-dashboard/compose.yml`, `${HP_BIND:-10.8.0.2}:19090:8080`), not an
  assumed default.
- A new sidecar, `vps/portbridge-manual-blackhole-refresh.sh`, is a near-
  verbatim copy of `portbridge-blackhole-refresh.sh` pointed at that URL
  instead of GitHub's maltrail mirror, writing to a second local file
  (atomic temp+rename, same as the original). It has no minimum-count sanity
  floor the way the maltrail refresh does (500 lines) — an empty manual list
  is a completely normal, expected state (no IP has been manually blocked
  yet), not a sign of a broken download.
- `blackhole.go` gains a second optional path, `BLACKHOLE_MANUAL_LIST`, and
  `reload()` unions both files into one blocked-set. The two sources are
  independently refreshed and independently sized, so a maltrail refresh can
  never silently wipe a manual block, and vice versa — this was the issue's
  own explicit "survive a feed refresh?" question, answered by construction
  rather than by carefully sequencing two writers against one file.

## What "first step" deliberately leaves out

- No CIDR blocking, no rate limit on how often an IP can be toggled — neither
  was asked for, and adding them here would be speculative scope past what
  #914 actually requested.
- The VPS-side sidecar is opt-in via the same `blackhole` compose profile the
  existing maltrail refresh already uses (`vps/docker-compose.yml`) — a
  deployment that doesn't run the `blackhole` profile at all is unaffected,
  exactly as before this change.
