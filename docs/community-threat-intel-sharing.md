# Community threat-intel sharing — decision

[← back to README](../README.md)

**Decision: not worth building as a repo feature, on either candidate
(T-Pot's `ewsposter`/`community.sicherheitstacho.eu`, or a generic
`hpfeeds` publisher). Declined, not deferred — the reasoning below is
worth someone re-reading before re-proposing this, not just a placeholder
for "someone hasn't gotten to it yet."** TANNER already ships a disabled,
unused `hpfeeds` config block (`arcane/home/honeypot-tanner/tanner/tanner/config.yaml`) that an
operator can turn on by hand if they personally want to participate — see
§4 — but this repo doesn't recommend it by default, document a workflow
around it, or build anything to support it.

## Why this needed a decision, not a config-gap fix

T-Pot's `ewsposter` posts sanitized attack summaries to Deutsche Telekom's
community feed, with `hpfeeds` support as a generic, vendor-neutral
alternative transport. Unlike a straightforward feature gap, this is a
genuine privacy/scope tradeoff this repo hadn't made either way: whether
this stack's attack telemetry should ever leave the operator's control to
a third party at all, separate from *which* third party.

## 1. The DT-specific feed (`ewsposter`) — declined

- Single-vendor, proprietary community feed with its own terms this repo
  has no relationship with and no evaluated benefit from joining.
- No precedent elsewhere in this repo for integrating with one company's
  proprietary platform for data egress -- every other integration here is
  either self-hosted (ELK, the dashboard, Arkime) or an open protocol/API
  with multiple possible providers (AbuseIPDB/Blocklist.de for the
  existing IP reporter, both swappable, neither exclusive).
- No stated need anywhere in `docs/ROADMAP.md` or `docs/WORK-LEDGER.md` --
  this idea originated entirely from a T-Pot feature comparison
  (#233), not from an operator goal this repo is actually trying to serve.

## 2. A generic `hpfeeds` sharing component — declined

`hpfeeds` (the open Honeynet Project protocol, broker-agnostic) is the
more interesting general pattern independent of T-Pot's specific feed, and
was evaluated on its own merits, separately from §1. Still declined, for
one reason that outweighs the "it's vendor-neutral" argument in its favor:

**Attacker interaction data -- including IPs -- is personal data under
GDPR** (this repo's own `README.md` already says so explicitly, in the
containment/safety section: "Attacker IPs are personal data (GDPR) — keep
logs access-controlled and short-lived"). Publishing structured attack
data to an open community broker is a materially bigger, harder-to-reverse
commitment than this repo's existing IP-blocklist reporting:

- The existing reporter (`arcane/home/honeypot-utilities/reporter/`, #68/#69, `arcane/home/honeypot-utilities/compose.yml`)
  sends a *narrow* signal (an IP, to a blocklist, for a defensive purpose:
  getting that IP blocked elsewhere) to a small number of well-understood
  destinations (AbuseIPDB, Blocklist.de), stays dry-run by default, and
  needed its own multi-phase build (#68 for the dry-run foundation and
  safeguards, #69 for validation and metrics, #153 for reputation
  filtering and observability, still open) to get the privacy posture
  right.
- A generic `hpfeeds` publisher would share *richer* structured data
  (commands, credentials, payload hashes, session metadata -- whatever
  TANNER or another sensor chose to publish) with *whichever broker an
  operator points it at*, redistributable by anyone who consumes that
  broker. That's a bigger, less bounded exposure than "this one IP is
  reported as abusive," for a benefit (contributing to a shared research
  corpus) this repo has no stated need for -- its own mission (per
  `README.md`) is investigation/defense for the operator running it, not
  contributing to community threat intelligence.
- Building it properly (the same dry-run-by-default, explicit-authorization
  posture `docs/WORK-LEDGER.md` rule 7 requires for any production-changing,
  outbound, irreversible action -- and publishing to a broker is exactly
  that shape) would mean another multi-phase build with the same rigor
  the IP reporter needed, for a goal nobody has actually asked for.

## 3. Relationship to the existing IP reporter (#68/#69/#153)

Deliberately kept conceptually separate, per this issue's own framing:
the IP reporter is *defensive* (get an attacker's IP blocked elsewhere,
narrow scope, well-understood destinations), community threat-intel
sharing would have been *offensive/research* (contribute this stack's
observations to a shared corpus other researchers draw from, broad scope,
open redistribution). Nothing about declining §1/§2 changes the IP
reporter's own scope or posture -- see `docs/ip-reporting-plan.md` for
that work, which continues independently.

## 4. What already exists and isn't being built on

`arcane/home/honeypot-tanner/tanner/tanner/config.yaml` has a native, currently-disabled `HPFEEDS`
block (`enabled: False`, plus `HOST`/`PORT`/`IDENT`/`SECRET`/`CHANNEL`) --
TANNER's own upstream already supports publishing to an `hpfeeds` broker,
no new code required to turn it on. This is *not* a recommendation: an
operator who has personally decided they want to participate in community
sharing, understands the GDPR exposure above, and has their own broker
relationship can flip that flag and fill in real credentials themselves.
This repo does not enable it by default, does not document a broker to
point it at, and does not build tooling (validation, rate limiting,
audit logging, a dry-run mode) around it the way the IP reporter has --
that would be exactly the "build it properly" work §2 already declined,
just deferred onto whichever operator flips the switch instead of done
once, carefully, here.

## Revisiting this decision

Worth reopening only if a concrete driver appears that isn't present
today: an operator or maintainer with an actual stated need for shared
threat-intel participation, a specific broker relationship already
evaluated for its own trust/privacy terms, or upstream TANNER changing
what `hpfeeds` publishing actually contains in a way that changes the
GDPR exposure calculus above. "T-Pot has this feature" on its own is not
that driver -- it wasn't when this decision was made (#242, following the
same #233 comparison that raised it), and reopening this without a new
concrete reason would just re-litigate the same tradeoff.
