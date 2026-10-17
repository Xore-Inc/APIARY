# APIARY Roadmap

This roadmap is the **sequencing** document: what order the work should happen
in, and why. The work itself lives in
[GitHub issues](https://github.com/Xore/APIARY/issues) — see
[`WORK-LEDGER.md`](WORK-LEDGER.md) for how issues are used.

Every deliverable below links to its issue. If something is described here with
no issue behind it, that is a gap: open one.

Last audited: 2026-08-05

> Deleted by the 2026-08-30 bulk purge and restored verbatim by #2896/#2947
> on 2026-09-04. Nothing below was updated during that window — treat
> "last audited" above as still true, not as of the restore date.

## Current baseline

- The VPS edge, WireGuard peer, Suricata, and portbridge are producing fresh
  data. CI credentials are in place: the `production-home` runner is online
  and VPS deployment secrets are set.
- The dashboard platform (render engine, CSP cutover, modal inventory,
  profile/settings/logout, regression tests) is finished — this was
  "Release 1" in the previous version of this document, and every deliverable
  in it is closed.
- `ml-worker/` is deployed and producing scored output; the ML detection
  pipeline through v1.0 (temporal/composite scoring, dashboard delivery,
  retraining/versioning/drift/rollback) is built. `llm-worker/` exists as a
  safety-gated one-shot process with a working `--selftest`, guarded GPU LLM
  analysis is built, and the Ollama canary is live. `reporter/` (IP
  reporting, Suricata/Blocklist.de validation) runs as part of
  `honeypot-utilities`. This was "Release 2" and "Release 3" — both fully
  closed.
- The Windows detonation sandbox and GHOSTS (NPC persona host) are live and
  booting; the end-to-end submit-to-report path is verified for the
  Linux/Wine sandbox and GitHub-analysis publishing. The Windows-11 golden
  image epic ([#47](https://github.com/Xore/APIARY/issues/47)) is
  still open — see the Windows sandbox section below. CAPEv2 (#314-322)
  remains unbuilt and is post-0.1.0 backlog.
- Documentation has been consolidated: every doc that used to be scattered
  next to its source now lives under `docs/`, mirroring the source tree
  ([#670](https://github.com/Xore/APIARY/issues/670), closed
  2026-08-05).
- The dashboard rewrite is done, not pending: the TanStack Start
  frontend/BFF + Rust service tier
  ([#1608](https://github.com/Xore/APIARY/issues/1608) and its
  follow-ups) cut over on 2026-08-22 under
  [#1628](https://github.com/Xore/APIARY/issues/1628), the Go dashboard is
  deleted from Compose, and `dashboard-next` runs unconditionally — no
  `next` profile, no runtime fallback. See
  [`DASHBOARD-CUTOVER.md`](DASHBOARD-CUTOVER.md).

Everything that was tracked here as "Gate 0" and "Release 1" through
"Release 3" and "Release 5" in prior versions of this document is now closed.
What remains before a 0.1.0 cut is the gate list below, tracked live in
[#671](https://github.com/Xore/APIARY/issues/671).

## Pre-0.1.0 gates

These are the items a 0.1.0 cut should not ship without. Status as of this
audit; #671 is the live source of truth if this drifts.

**Documentation**
- ✅ [#670](https://github.com/Xore/APIARY/issues/670) — consolidate
  scattered docs into `docs/`
- This rewrite — [#719](https://github.com/Xore/APIARY/issues/719)

**End-to-end / smoke tests**
- [#498](https://github.com/Xore/APIARY/issues/498) — dashboard:
  end-to-end smoke test every submission path. Linux/Wine sandbox and
  GitHub-analysis publishing verified live; GHOSTS-sandbox wiring fixed and
  the guest itself verified (network isolation, client enrollment) via
  #597. Ghidra/Rev·Deck and Payload Workbench fan-out remain.
- [#593](https://github.com/Xore/APIARY/issues/593) — verify the
  ml-worker anomaly pipeline actually runs and reaches the dashboard
- [#594](https://github.com/Xore/APIARY/issues/594) — functionally
  test every sensor sends real, well-formed events to Elasticsearch
- ✅ [#597](https://github.com/Xore/APIARY/issues/597) — end-to-end
  test: golden image creation for both win11-analysis and win11-ghosts

**In progress, not gates but relevant:** #150 (LLM analysis results to
dashboard), #154 (agent-intrusion research), #167 (ml-worker prod deploy +
CPU baseline), #239 (read-only rootfs hardening), #598 (llama.cpp/vLLM vs
Ollama research).

**Explicitly deferred, not part of the 0.1.0 pass:** #602 (GPU topology),
#603 (model benchmarking) — on hold per operator decision.

## Windows sandbox (post-0.1.0, tracked separately)

Tracked as its own issue set rather than a release, because it runs on the
analysis host and does not gate the main stack.

| Deliverable | Issue |
|---|---|
| Phase 1 golden image (epic) | [#47](https://github.com/Xore/APIARY/issues/47) |
| Golden-image lifecycle: checksum + scheduled rebuild | [#86](https://github.com/Xore/APIARY/issues/86) |
| VM-detection tells (pafish/al-khaser) | [#368](https://github.com/Xore/APIARY/issues/368) |
| windows_kimi realism gaps | [#493](https://github.com/Xore/APIARY/issues/493) |
| ProcMon CLI export hang | [#502](https://github.com/Xore/APIARY/issues/502) |
| CAPEv2 debugger-class-evasion sandbox (9 issues) | [#314-322](https://github.com/Xore/APIARY/issues/314) |

## Post-release, not hard blockers

These items run **after** 0.1.0 ships rather than gating the cut. Operator
decision in each case.

- [#662](https://github.com/Xore/APIARY/issues/662) — 72-hour
  multi-user soak of the settings/introspection subsystem (split from
  closed #81). A multi-day soak can't gate a release cut on a wait.
- [#84](https://github.com/Xore/APIARY/issues/84) — shared-GPU slot
  scheduling, collision drills, 72-hour soak. Depends on
  [#67](https://github.com/Xore/APIARY/issues/67) (CUDA selection,
  GPU-sharing budget) — moved to post-0.1.0 backlog along with it, since #67
  was only in the gate list as #84's dependency. Same soak reasoning as #662.
- [#174](https://github.com/Xore/APIARY/issues/174) — ml-worker
  severity bands/composite weights are assumed, not calibrated. Not a hard
  blocker; calibrate against live honeypot ES data once #593 lands.

## Post-0.1.0 backlog, by area

Grouped for planning, not in priority order. Full detail is in each issue.

**GPU / ML / LLM** — #67 CUDA selection + sharing budget, #84 shared-GPU
slot scheduling (see Post-release soaks above), #661 Hugging Face model
search + eval round

**GHOSTS sandbox** — #463 persona realism, #467 per-VM risk-feature
granularity

**Dashboard** — #609/#613 JA3/JA4 fingerprinting, #615/#616 Suricata
severity/MITRE + anomaly events, #618 TANNER emulator results, #620
cisco-asa WebVPN POST bodies, #624 dionaea SMB DCERPC uuid/opnum, #638
binary artifacts into ES, #646/#652 CSP inline-style violations, #647 ES
storage stats, #666 reporter metrics.json, #672 mobile/viewport testing,
#673 action-menu button sizing, #678 container/Kibana/ES log audit

**Analysis pipeline** — #528 content-defined chunking dedup, #606 dicompot
AE title capture, #619 cisco-asa IKE payload logging, #623 ip-enrichment
real attacker IP gap, #639 Kibana saved-search audit, #195 capa MIPS/ARM32
backend coverage (the visible-gap fix already shipped via #237; the real
backend is blocked on #245), #245 Ghidra/REST-backend
version tracking, #680 correlate Ghidra/floss static findings against
Windows-sandbox dynamic IOCs, #696 pafish/Session-0 validation gap

**Ops** — #537 multi-node vs single-node ES research

## Priority rule

When multiple issues are ready, select in this order:

1. production recovery or data-integrity blockers;
2. security and isolation defects;
3. shared platform work that unblocks multiple features;
4. deterministic CPU/dry-run foundations;
5. user-facing integrations;
6. GPU optimization and deception enhancements.
