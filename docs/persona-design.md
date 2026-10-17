# Persona design: outbound policy, host naming, and placement

[← back to README](../README.md)

Two related pieces of persona design that were implicit rather than
documented decisions: whether a honeypot may reach the internet outbound,
and how to name/place a honeypot host so it doesn't look staged. T-Pot's
own README calls both out by name (`README.md` line 296 for outbound; the
"where to place a honeypot" guidance for siting). This repo already does
deep, source-verified realism work for Windows personas
([#91](https://github.com/Xore/APIARY/issues/91)/[#94](https://github.com/Xore/APIARY/issues/94)/[#96](https://github.com/Xore/APIARY/issues/96))
and has a full fictional-organization inventory
([`personas/README.md`](personas/README.md)) — this doc is the short
practical guide those didn't cover.

## 1. Outbound network policy

**Decision: outbound is allowed by default, per honeypot, unless that
honeypot has no design reason to need it.** This matches what this stack
already did before this doc existed — no *decoy's* per-stack network has ever
set `internal: true`, and it needs not: a sensor has to be reachable to be
attacked. (Scoped deliberately. Three `arcane/home/` stacks do mark a network
`internal: true` — `honeypot-keycloak`'s `keycloak-data`,
`honeypot-dashboard`'s `oidc-session`, and `honeypot-elk`'s
`honeypot-llm-data` — but all three are management-plane networks for services
that want no egress, not sensor networks. The same sentence is repeated as a
comment at `honeypot-cowrie/compose.yml:217`.) And it
mirrors T-Pot's own stated reasoning: "For some
honeypots to reach full functionality (i.e. Cowrie or Log4Pot) outgoing
connections are necessary as well, in order for them to download the
attacker's malware."

The tradeoff is real in both directions:

- **Allowed** — the honeypot captures the attacker's *actual* malware
  sample, not just the download attempt. Cowrie's fake shell really
  executes `wget`/`curl`/`tftp` when an attacker's session runs them; a
  captured sample is strictly more valuable than a logged command line.
- **Air-gapped** — the honeypot cannot become a relay for a live fetch of
  attacker-controlled content, even briefly, and cannot itself become an
  unwitting participant in whatever that fetch triggers (a second-stage
  payload reaching back out, a DDoS reflector setup, anything the sample
  itself does once it lands). Strictly safer, at the cost of never seeing
  the payload.

| Honeypot | Outbound | Why |
|---|---|---|
| Cowrie | Allowed (flag: `COWRIE_AIR_GAPPED`, default `false`) | The one sensor in this stack designed around capturing attacker-fetched malware — its whole SSH/Telnet fake-shell premise is attackers running `wget`/`curl`/`tftp` against real URLs. See `arcane/home/honeypot-cowrie/compose.yml`'s `cowrie_net`. |
| Dionaea | Allowed (flag: `DIONAEA_AIR_GAPPED`, default `false`) | Same tradeoff as Cowrie (#269/#538): captures shellcode/binaries pushed *to* it over SMB/FTP/TFTP/etc, which both ship enabled by default — this is the attacker's actual malware sample, not just the exploit attempt. See `arcane/home/honeypot-dionaea/compose.yml`'s `dionaea_net` (#541). `internal: true` still permits `tftp-relay`'s inbound forwarding on the same network — it only removes the outbound route. |
| Tanner/Snare | Allowed (flag: `TANNER_AIR_GAPPED`, default `false`) | Same tradeoff as Cowrie and Dionaea: the `template_injection` emulator fetches real RFI payloads when enabled, capturing the attacker's actual payload instead of just the RFI attempt. See `arcane/home/honeypot-tanner/compose.yml`'s `tanner_local`. Setting the flag also breaks the emulator's own `REMOTE_DOCKERFILE` self-maintenance fetch (`raw.githubusercontent.com`) — a real cost, not just a capture-vs-safety tradeoff. |
| Everything else (Conpot personas, DNP3, HTTP/API honeypot, multipot, dicompot, dns-honeypot, citrix-honeypot, cisco-asa-honeypot, rdp-honeypot) | Allowed, no design reason either way | None of these protocols involve the honeypot fetching attacker-supplied URLs — outbound access is unused in the intended interaction, just never explicitly closed off. An operator who wants maximum containment can set `internal: true` directly on that sensor's network in its compose file without losing anything these honeypots actually rely on. |
| `yara-scanner` (not a honeypot — offline payload analysis) | Blocked (`network_mode: none`) | Already air-gapped; scans captured files at rest, never needs network access at all. The one existing precedent this decision extends. |

`COWRIE_AIR_GAPPED=true` (`.env`) sets `internal: true` on `cowrie_net`,
fully removing its outbound route — Docker enforces this at the network
level, not by Cowrie's own config, so it holds even if `cowrie.cfg` changes.
`DIONAEA_AIR_GAPPED` and `TANNER_AIR_GAPPED` follow the identical pattern
(#541, #269/#538) on `dionaea_net` and `tanner_local` respectively. Add one
the same way (`internal: ${<SENSOR>_AIR_GAPPED:-false}` on that sensor's
own network) if a future sensor grows a real design reason to fetch
attacker-supplied content the way these three do.

## 2. Host naming, banners, and network placement

T-Pot's README frames *where* and *how* a honeypot should look: place it
"where you suspect intruders," and saturate a single interface rather than
scattering honeypots across random boxes. This stack's placement decision
is already made and is different in kind from T-Pot's freeform guidance,
not a gap: every sensor binds `HP_BIND` (the WireGuard tunnel interface)
and is reached exclusively through the VPS — see
[`docs/CGNAT-DEPLOYMENT.md`](CGNAT-DEPLOYMENT.md) for the full topology and
[`docs/honeypot-network-isolation.md`](honeypot-network-isolation.md) for
why the VPS/home split *is* the isolation boundary here. There is no "which
subnet" decision left to make per sensor the way there is on a single flat
LAN — every sensor already saturates the one interface an attacker can
reach (the VPS's public IP), by construction.

What's still genuinely per-sensor, and worth being deliberate about:

**Host naming and banners.** Every persona in
[`personas/personas.json`](../personas/personas.json) already carries a
fictional `organization`/`site_id`/`asset_id`/hostname — see
[`personas/README.md`](personas/README.md)'s table for the full
inventory (NexusAI Research GmbH's GPU inference node, Meridian Retail
Systems' legacy integration server, Rheinwerk Municipal Water's PLCs, and
so on). Keep new personas consistent with that pattern rather than
inventing an unrelated naming scheme:

- One fictional organization per plausible "estate" of related services,
  not one organization per honeypot — `nexusai-core`, `nexusai-edge`, and
  `nexusai-platform` are three different sensors under the same fictional
  company, matching how a real org's exposed surface looks (mail/db/cache
  next to a public doc site next to an API gateway), not three unrelated
  strangers who happen to share a subnet.
- Match the banner/version string to something a real deployment would
  actually run and *keep running slightly behind current* — real
  production systems lag patches; an OpenSSH banner one or two point
  releases behind latest reads as authentic, `HEAD`-fresh reads as staged.
  `cowrie.cfg`'s `version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13` is
  the existing example to match, not a one-off.
- Hostnames should describe a role, not the honeypot's real purpose —
  `gpu01` (Cowrie's `COWRIE_HOSTNAME`), not `cowrie-honeypot-1`.
- Never reuse a real organization's name, clone a real site, or seed real
  credentials/customer data — `docs/personas/README.md`'s own stated rule, and
  the one non-negotiable constraint on all of the above.

**Placement (protocol/persona to sensor mapping).** Match a persona's
claimed role to a protocol an attacker would actually expect that role to
expose — a "GPU inference node" persona on Cowrie's SSH/Telnet surface is
plausible; the same persona claim on a DNP3 sensor (industrial control,
not a general-purpose compute host) would read as staged the moment an
attacker cross-references what the org is supposed to do.
[`docs/SENSORS.md`](SENSORS.md) has the full sensor-to-protocol table if
you're deciding where a new persona belongs.

**Background noise.** Ambient traffic (DNS lookups, NTP syncs, low-rate
outbound chatter) makes a host look occupied rather than dead-silent —
researched and deliberately left unbuilt here
([#71](https://github.com/Xore/APIARY/issues/71); the old technique
reference doc was removed with #1662's stale-doc sweep after its tooling
never landed).
