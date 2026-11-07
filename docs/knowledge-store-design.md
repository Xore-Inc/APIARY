# Knowledge-store design record (#1634)

Decision record for #2289, gating #2290–#2292. This was the design pass
#1634 asked for, written before any ingest worker existed; no code changes
shipped with the document itself.

> **Status, re-measured 2026-09-27: authored and tracked, not deployed.** The
> ingest worker does exist in git — `vault-worker/` carries a `worker.py`, a
> `sanitize.py`, a `Dockerfile` and two compose files, the shipped output of
> #2289/#2290 — but nothing deploys it. It is absent from
> `arcane/manifests/home-production.json`; no vault-worker container has ever
> run on the homeserver, and there is no `vault-worker` stack directory among
> the deployed ones; Elasticsearch carries no `knowledge-vault*` index, so the
> `knowledge-vault-state-v1` checkpoint cited for this worker in
> [PIPELINES.md](PIPELINES.md) does not exist either (that row is planned, the
> same way); and the live APIARY worker runs
> `WORKER_LOOPS=alert-notifier,attacker-identity,agent-intrusion,correlator,dashboard-rollups,threat-intel,zeek-proxy-attribution`
> — there is no vault loop in it.
>
> So everything below is the design and implementation record of a **planned**
> subsystem, kept because #2289/#2290 shipped real code against it. Read it as
> intent that has not been switched on: none of the paths, indices or
> checkpoints it names exist on a live host, and no deployment decision is
> recorded anywhere in the repository.

## 1. Storage: plain markdown directory, carried by the existing off-host
   backup path, not git/Syncthing

Rejected: **Self-hosted LiveSync + CouchDB.** A second database and a second
sync daemon to operate, backed up, and secured, for a store whose write
volume is bounded by the analysis-index scroll rate (#2290) — not justified
against the alternative below.

Rejected: **a web-rendered publish view under the dashboard tier.** This
would mean a tenth ES index plus BFF routes plus a frontend surface just to
reproduce what a markdown file on disk already gives an operator who opens it
in Obsidian. It also collapses the distinction #1634 asked for between "an
Obsidian vault" and "another dashboard panel" (#2241 already covers dashboard
surfacing of correlation data; the vault is deliberately a different,
analyst-driven surface).

**Chosen: a plain markdown directory on the homeserver**, one file per note,
written by the #2290 worker. #1634's own recommendation was right, but its
premise about *why* it is cheap was wrong — see the correction below — so the
mechanism needs to be picked directly rather than inherited.

### Correction to #1634's premise

#1634 proposed "git-backed like `dashboard-config-v1`'s revision history" as
if that were reusing an existing mechanism. It is not. Reading
`backend-service/src/config_history.rs`: `dashboard-config-v1`'s history is a
single bounded, single-generation-rotated JSONL file
(`HISTORY_MAX_BYTES = 2 << 20`, i.e. 2 MiB, one `.1` rotation, reads walk
newest-first across both generations — `config_history.rs:14-15,50,57-88`).
There is no git repository anywhere in that path, no commit objects, no
working tree. A git-backed vault is therefore a **new mechanism** for this
stack, not a reuse of one, even though it is a trivial one to stand up
(`git init` in a directory, a commit per note-write batch). The nearest real
precedent for "git as a sync/deploy substrate" in this repo is Arcane's own
GitOps machinery (`docs/ARCANE-GIT-SYNC.md`), which already runs a
git-pull-and-apply loop against `main` and where every live row currently
carries `auto_sync = 0`, with every deploy still a manual
sync → build → redeploy (`docs/ARCANE-GIT-SYNC.md`, "Promotion workflow and
change control") — i.e.
this codebase's existing git-sync tooling defaults to *manual* triggers for
anything sensitive, which is the posture this decision adopts too (see §4).

Given that a git layer is new work either way, and the write pattern here is
"one worker upserts markdown files on an interval" rather than "operators
edit and need history," git buys idempotent-upsert bookkeeping the vault
already gets for free from #2290's sha256-keyed filenames (§2) plus normal
filesystem overwrite semantics. **v1 ships with no git layer**: a directory
of markdown files under `/opt/stacks/apiary/state/knowledge-vault/`,
optionally synced off-host by Syncthing exactly as recommended, with git
added later only if an operator workflow (e.g. "show me what changed in this
note last week") turns out to need it. Syncthing already has no data-model
opinion about the files it moves, so it costs nothing to defer.

## 2. Note shape

One note per entity, one markdown file per note, filename = `<entity-type>-<hash>.md`
where `<hash>` is a stable sha256 derived from the entity's natural key
(payload sha256 for a payload note, source IP for an attacker-identity note,
campaign ID for a campaign note — #2290 defines the exact derivation per
source index). This makes every render an **idempotent upsert keyed by
filename**: re-running the worker over the same source document overwrites
the same file byte-for-byte-equivalent rather than creating a duplicate, and
a link to `campaign-<hash>.md` never rots because the filename never changes
once the underlying entity's key is fixed.

Typed YAML frontmatter, minimum fields:

```yaml
---
entity_type: payload | attacker | campaign | ghidra-analysis | sandbox-analysis | github-analysis | cape-analysis | revdeck-analysis | llm-session
entity_id: <the hash or natural key above>
source_index: <ES index this note was rendered from>
source_doc_ids: [<ES _id values contributing to this note>]
file_hashes: [<sha256 of any payload this note concerns, if applicable>]
source_ips: [<attacker source IPs, if applicable>]
campaign_id: <campaign ID, if this entity belongs to one>
first_seen: <RFC3339>
last_seen: <RFC3339>
enrichment_status: rendered | pending | failed
rendered_at: <RFC3339, this render's timestamp>
---
```

Frontmatter carries references (IDs, hashes, timestamps); body content is
the human-readable summary, gated by §4's redaction posture.

## 3. Linking rules

v1 links are **structural only**, derived at render time from fields already
in the frontmatter above:

- shared `file_hashes` entry → link a payload note to every analysis note
  (ghidra/sandbox/cape/revdeck/github) sharing that hash;
- shared `source_ips` entry → link an attacker note to every payload/session
  note sharing that IP;
- shared `campaign_id` → link every note tagged with that campaign.

Rendered as plain markdown links (`[[campaign-<hash>]]` Obsidian wikilink
syntax, since storage is a directory Obsidian can open directly) computed
fresh on every render — no separate link-index file to keep in sync, no
possibility of a stale link pointing at a note that no longer exists, because
the worker only ever links to filenames it can derive the same way it
derived its own.

**Deferred, explicitly, per #1634 and the parent issue**: temporal-proximity
linking ("these two sessions happened within N minutes of each other, are
they related?"). That requires a similarity/clustering judgment call this
design record is not making. If it's wanted later it is additive — a second
linking pass over already-rendered notes — and does not change anything
decided here.

## 4. Redaction and access posture — the blocking decision

**The precedents pull in genuinely opposite directions, and the difference is
what the field is *for*:**

- `problem_reports.rs` bounds and regex-redacts every captured string before
  it ever reaches Elasticsearch (`redact_text`, `redact_patterns`,
  `problem_reports.rs:38-74`), because that data is arbitrary, attacker- or
  operator-supplied text riding along on a bug report — it is not itself the
  point of the feature, and redaction protects the operator submitting it
  from accidentally leaking a live credential through their own bug report.
- `credentials.rs` deliberately shows bait credentials **unredacted**,
  including in list/rotate responses (`credentials.rs:8-11` doc comment: "not
  secrets to redact from the operator — they ARE the bait content"), because
  the entire feature is operators needing to read those exact values back.

The vault is closer to `problem_reports.rs`'s situation than
`credentials.rs`'s: a vault note is a **derived summary of attacker-supplied
material**, not a record whose entire purpose is displaying a secret verbatim
to an operator who provisioned it. Attacker-supplied strings — shell input,
HTTP bodies, usernames/passwords an attacker *tried*, file contents — are
exactly the class `problem_reports.rs` exists to defend against, and they are
exactly what flows through the analysis indices #2290 will read.

**Decision: notes get the `problem_reports.rs` posture, not the
`credentials.rs` posture.**

- Any field copied into a note body is bounded and passed through
  `redact_text`-equivalent redaction (credential-shaped strings, cookies,
  bearer tokens stripped) before it is written to disk. #2290 must depend on
  or replicate this exact pattern rather than inventing a new one.
- Bulk/opaque attacker payloads (raw shell sessions, full HTTP request/response
  bodies, binary content) are **never copied into a note**. A note holds a
  bounded, redacted excerpt (matching `MAX_CAPTURED_TEXT_BYTES = 20_000` from
  `problem_reports.rs:32`) plus a reference back to the source: the ES index,
  document ID, and — where the dashboard already has a page for the entity —
  the dashboard URL. The vault is a curated index into the existing evidence,
  not a second copy of it.
- Structured, low-cardinality fields that are the point of the vault entry
  (source IP, campaign ID, technique tags, first/last seen, verdict/score from
  an analysis pipeline) are copied as-is — they're metadata, not attacker
  content, same as `credentials.rs`'s bait values being metadata about a
  provisioned artifact rather than something an attacker supplied.
- One credentials-style exception, decided deliberately rather than by
  default: a note about a captured *bait* credential (i.e. a `dashboard-credentials-v1`
  record an attacker actually used) may show that credential's value
  unredacted, because — exactly as in `credentials.rs` — the bait value is our
  own known-fake artifact, not attacker-supplied content, and hiding it from a
  note about it defeats the note's purpose. This exception does **not** extend
  to a credential an attacker *typed* into a Cowrie session, which is
  attacker-supplied and gets the redaction/bounding above.

### The consequence this decision has to reckon with, and how it's handled

A persistent, curated, cross-referenced copy of (bounded, redacted) attacker
material is qualitatively different from the raw per-event ES documents it's
derived from: it's smaller, denser, and easier for a human or a script to
sweep in one pass. Reading `analysis/backup-honeypot.sh`, its archive step
(`backup-honeypot.sh:123`) already walks `./analysis ./dashboard ./personas
./state` by directory-existence check, unconditionally including anything
found there. If the vault directory (§1: `state/knowledge-vault/`) is placed
under `$stack_dir/state/`, it is **already** inside this glob and would start
riding along in every scheduled backup the moment it exists — with no
separate decision required, and no separate exclusion currently guarding it.

That is accepted deliberately, not by omission: the vault directory is
placed under `state/knowledge-vault/` specifically so it inherits
`backup-honeypot.sh`'s existing scope, the same script that already carries
`dashboard-state` and other config-bearing material governed by the same
"config and small state, not bulk captured data" policy the script's own
header documents (`backup-honeypot.sh:14-19`). Because §4's redaction rule
above already bounds and strips what can land in a note, the vault's content
is closer in sensitivity to the config material `backup-honeypot.sh` already
carries than to the bulk payload/PCAP data it explicitly excludes — so
extending that script's existing scope to include it is the correct call,
not an oversight to patch around later. That decision is already recorded
verbatim in `analysis/backup-honeypot.sh`'s own comment block
(`backup-honeypot.sh:108-117`, which names #2289, #2290 and this document), so
a future reader sees it was deliberate rather than inferring it from a
directory glob matching by accident.

### Worker authorization gate

The vault-ingest worker (#2290) must gate non-dry-run writes the same way
`llm-worker` gates captured-data mode. Reading `llm-worker/worker.py:258-260`
and `llm-worker/worker.py:327-329`:
non-dry-run requires `LLM_ENABLED=true` **and** `LLM_ALLOW_CAPTURED_DATA=true`
together, with the error message naming both. The vault worker adopts the
same two-flag shape (its own env var names, e.g. `VAULT_ENABLED` /
`VAULT_ALLOW_CAPTURED_DATA`) rather than a single flag, and rather than
defaulting either to `true` — a vault worker that fails safe into "disabled"
on a fresh install, exactly as `llm-worker` does, until an operator makes the
opt-in explicit twice.

## Summary of decisions

| # | decision |
|---|---|
| storage | plain markdown directory, `state/knowledge-vault/` under the stack dir, no git layer in v1, off-host copy inherited via existing Syncthing/backup paths |
| note shape | one file per entity, filename keyed by stable sha256 of the entity's natural key, typed YAML frontmatter (§2), idempotent upsert-by-filename |
| linking | structural only in v1 — shared hash / shared source IP / shared campaign, computed fresh on every render; temporal-proximity deferred |
| redaction | `problem_reports.rs`-style bounded + regex redaction for attacker-supplied content; structured metadata copied as-is; bait credentials (not attacker-supplied) may stay unredacted, same exception as `credentials.rs`; bulk payloads never copied, only referenced |
| backup blast radius | accepted deliberately by placing the vault under `state/`, inside `backup-honeypot.sh`'s existing scope; record the decision in that script's comments when the directory is created |
| worker gate | two-flag opt-in (`VAULT_ENABLED` + `VAULT_ALLOW_CAPTURED_DATA`), same shape as `llm-worker`'s `LLM_ENABLED` + `LLM_ALLOW_CAPTURED_DATA`, defaults off |

#2290 implements the directory and the render worker against this record.
#2291 and #2292 depend on #2290's output shape (frontmatter fields, filename
scheme) and on this record's redaction posture holding for anything that
reaches a completion model.
