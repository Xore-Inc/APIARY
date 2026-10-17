# Dionaea bistreams retention — consumer inventory and decision (#2862)

`dionaea-lib`'s `bistreams/` tree holds Dionaea's raw per-connection capture
stream: every accepted connection gets a date-named subdirectory
(`YYYY-MM-DD/`) full of raw capture files, payload or not — a superset of
the extracted-sample store (`binaries/`), which is a separate, deduplicated
stream this document does not cover.

## Consumers, and how far back each one reaches

| reader | code path | reach |
|---|---|---|
| `payload-dedupe` (`hp-payload-dedupe`) | `arcane/home/honeypot-payload-analysis/analysis/dedupe-payloads.py`: `prune_old_directories()` deletes whole date subtrees older than `BISTREAMS_RETENTION_DAYS`, then `dedupe()` runs over `PAYLOAD_ROOTS` — which **does include bistreams**. The compose file sets `PAYLOAD_ROOTS=/payloads/cowrie:/payloads/dionaea/binaries:/payloads/scripts/script-payloads:/payloads/dionaea/bistreams` (compose.yml:49), so content dedupe and hard-linking both reach into the bistreams tree; `BISTREAMS_ROOT=/payloads/dionaea/bistreams` (compose.yml:56) is the *separate* variable the pruning pass reads, not an exclusion from dedupe. Bistreams is listed **last** on purpose, and the compose comment says why: it is 82% duplicate by content in a live sample, so age-pruning runs before dedupe each pass to keep what dedupe must hash bounded (#112) | whatever the retention window currently leaves on disk — no independent age requirement |
| `yara-scanner` (`hp-yara-scanner`) | `arcane/home/honeypot-payload-analysis/compose.yml`'s `YARA_PAYLOAD_ROOTS=/payloads/dionaea:...` mounts the whole `dionaea-lib` volume read-only, so it scans bistreams as part of `/payloads/dionaea` | same — whatever's currently present |
| Elasticsearch / dashboard | none — nothing indexes bistreams content directly. `HONEYPOT_RETENTION_DAYS` (21d) governs *derived* ES indices, which is a shorter and unrelated window over structured events, not a copy of the raw stream | n/a |
| manual forensic review | ad hoc, off-repo | as far back as the window allows |

Neither automated reader has a forensic requirement for a specific window
length — both operate on "whatever is currently retained." That means the
window is a pure retention-policy choice, not something derivable from
consumer code.

**Caveat, stated rather than buried:** "no forensic requirement found" is
absence of evidence, not evidence of absence. This inventory covers the
automated readers in this repository. It cannot cover an operator who has
been relying on reaching back further by hand, because nothing records that
use. If such a use exists, it argues for a *longer* window, not a shorter
one, so it does not change the decision below — but it is the reason the
decision is framed as "do not shorten without a forensic argument" rather
than "30 is proven correct".

## Size, growth and projected steady state

Measured 2026-09-03: **163 GB across 26 date directories**, oldest
`2026-08-09`, newest `2026-09-03`, unbroken. On 2026-09-02 it was 151 GB
across 25 directories, so growth has accelerated to roughly **6–11 GB/day**
(round 4 measured ~5 GB/day).

| window | deletable today | projected steady state at 6–11 GB/day |
|---|---|---|
| 30 days (chosen) | 0 GB — nothing is 30 days old yet | **~180–330 GB** |
| 21 days | ~13.4 GB (the four oldest directories) | ~126–231 GB |

The steady-state figure for 30 days is the number the next person handling
`/var` capacity (#2823, #2820) needs: this store alone converges on roughly
a fifth of the 1.7 TB filesystem, and the acceleration means "revisit only
with a forensic argument" may be overtaken by physics inside a month. That
is a known and accepted consequence of the decision below, not an oversight.

## When this window first destroys something

**2026-09-09.** Nothing has *ever* been pruned from this store —
`prune_old_directories()` keeps a directory while
`(today − entry_date).days <= retention_days`, the oldest directory is
`2026-08-09`, and at a 30-day window it first exceeds that on 2026-09-09
(age 31). Six days after this decision was recorded.

That date matters precisely because this is the knob the decision below
calls irreversible: up to now the setting has cost nothing and destroyed
nothing, so it has never actually been exercised. From 2026-09-09 the
oldest day of raw capture is deleted every day.

## Decision (2026-09-03): keep `BISTREAMS_RETENTION_DAYS=30`

Recorded in `arcane/home/honeypot-payload-analysis/.env.example` alongside
the value.

The argument is forensic and it stands alone: this is the one fleet
retention knob that destroys captured evidence irreversibly and permanently
— there is no ES-side or any other copy of the raw stream once a date
directory is pruned — and **neither consumer has a reader-side case for a
shorter window** (see the inventory above; both read "whatever is currently
on disk"). Shortening to match `HONEYPOT_RETENTION_DAYS=21` (the
shard-count knob #2820 set) would trade ~13 GB today, and ~54–99 GB at
steady state (the difference between the two rows above), for a permanent
loss of capture that nothing asked for.

**This decision does not rest on the disk ledger, deliberately.** An earlier
draft justified it by pointing at #2859 and #2882 as the places relief would
come from instead. That turned out to be false: every lever in the same
capacity batch — #2852, #2859, #2882 and this one — ended at **zero bytes
reclaimed**, and `/var` was measured worse at the end of the batch (96% /
86 G free) than at the start (94% / 116 G free). A permanent justification
for declining to reclaim ~13 GB of captured data must not depend on rows
that delivered nothing, so it doesn't.

Options considered (see #2862 for the full text):

1. **Keep 30 (chosen).** No data lost. Disk relief comes from #2859/#2882 instead.
2. Reduce to 21. Rejected — no forensic argument found for it, only a disk one.
3. Tiered retention (full window shorter, compressed/sampled tail longer).
   Not implemented — no existing mechanism for a compressed tail in
   `dedupe-payloads.py`, and building one is new scope beyond what this
   round asked for. Worth a future issue if 30 days of full-fidelity
   capture turns out to be more than operators actually use.

Re-open this decision only with a forensic argument (an investigation that
needed data past 30 days and didn't have it, or a demonstrated case that
nobody ever looks past N days), not a disk-pressure one.
