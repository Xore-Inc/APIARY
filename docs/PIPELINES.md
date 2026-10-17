# Data pipelines

[← back to README](../README.md) · [Architecture](ARCHITECTURE.md) · [Network](NETWORK.md) · [Storage](STORAGE.md)

How a byte that arrives at the VPS becomes a row an analyst clicks on.
Four pipeline families run end to end: **event ingestion**, **derived
intelligence** (the workers), **payload analysis**, and **analysis-request
spools** (the workbench's detonation/static routes). Each section below is
the live shape as of the dashboard cutover (#1628, 2026-08-22).

The one-paragraph version:

> Sensors write append-only JSON under `/opt/stacks/apiary/logs/`. The
> ingest-time enrichment worker joins tunnel-attributed events to real
> attacker IPs via the portbridge connection log; Filebeat tails the result
> into Elasticsearch, where one shared ingest pipeline normalizes and
> enriches every document. Seven worker loops then aggregate raw events into
> durable entities (attackers, clusters, campaigns, anomaly scores,
> inventory, derived overview/map/attack rollups). The dashboard reads only
> Elasticsearch for history, keeps a
> small bounded live tail for suricata/portbridge, and serves it all through
> server functions with a 15s shared cache.

```mermaid
flowchart LR
  subgraph sensors["Sensors (each its own stack + network)"]
    direction TB
    s1["cowrie · dionaea · conpot ×6"]
    s2["dnp3 · dicompot · dns · citrix<br/>cisco-asa · rdp · endlessh"]
    s3["http · api · multipot · mailoney<br/>beelzebub · hellpot · elasticpot<br/>galah · sentrypeer · tanner"]
  end

  logs[("logs/&lt;sensor&gt;/*.json")]

  subgraph vpsSide["VPS-originated evidence"]
    eve[("suricata eve.json")]
    pcap[("rotating PCAP")]
    connlog[("portbridge conn-log")]
  end

  enrich["ip-enrichment join<br/>(backend-worker-enrichment,<br/>networkless)"]
  enriched[("logs/enriched/*.json")]
  fb["Filebeat"]

  subgraph es["Elasticsearch (honeypot-elk)"]
    pipe["ingest pipeline geoip-honeypot<br/>(normalize → fingerprints → GeoIP → classify)"]
    rawIx[("honeypot-v2-*<br/>suricata-v2-*<br/>portbridge-v2-*")]
    dlq[("dead-letter-honeypot")]
  end

  subgraph workers["Worker loops (dashboard stack + own stacks)"]
    w1["attacker-identity<br/>→ attackers-v1"]
    w2["correlator<br/>→ campaigns-v1,<br/>attacker-clusters-v1"]
    w3["agent-intrusion<br/>→ agent-intrusion-campaigns"]
    w4["ml / llm scoring<br/>→ anomaly scores + acks"]
    w5["inventory + es-importer<br/>→ payload/report indices"]
  end

  dash["Dashboard tier<br/>frontend-next ⇄ backend-service"]

  s1 & s2 & s3 --> logs
  logs -->|"tunnel-blind sensors: via_port join"| enrich
  logs -->|"PROXY-attributed sensors: watched for canonical promotion only"| enrich
  connlog --> enrich
  enrich --> enriched
  logs -->|"not watched: already PROXY-attributed or adapter-written"| fb
  enriched -->|"tailed instead of raw — not shipped twice"| fb
  eve --> fb
  connlog --> fb
  fb --> pipe --> rawIx
  fb -.->|"undecodable"| dlq
  pcap --> arkime["pcap-sync → Arkime"]

  rawIx --> workers --> dash
  rawIx --> dash
```

---

## 1. Event ingestion

### 1a. Write path: sensor log → index

Every sensor writes flat JSON lines to its own directory under the host
`logs/` tree (layout in [STORAGE.md](STORAGE.md#host-tree)). Two things
consume those files, never each other:

1. **Filebeat** ships everything durable into Elasticsearch with
   restart-safe registry offsets.
2. **The enrichment worker** rewrites watched sensors' files into
   `logs/enriched/` before Filebeat sees them. That watch list began as
   the five sensor families of #37/#38 (cowrie, dionaea, the conpot
   personas, dns-honeypot, cisco-asa-honeypot) and has grown to 17 named
   sources plus every conpot persona discovered on disk (six live,
   2026-08-27) — 23 sources in all. The list is
   `discover_sources` in
   `arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment/mod.rs`;

Which sensors the worker watches, and whether their files need rewriting
at all, follows one question per sensor: **does the sensor see the
attacker's real IP?**

| Group | Sensors | Why | Fix |
|---|---|---|---|
| PROXY-aware | http, api-honeypot, multipot, tanner, dnp3, dicompot, citrix, rdp, endlessh, cisco-asa (WebVPN side), sonicwall-sma, conpot (its TCP personas — every one of the six sets `CONPOT_PROXY_PROTOCOL=1` and portbridge carries the `pp` flag on their TCP rules), galah (proxied door, XFF), hellpot (proxied door, XFF) | the VPS-side portbridge (`vps/portbridge`) speaks HAProxy PROXY v1, or Traefik sets XFF in-band | none for attribution. Six of them (multipot, tanner, http-honeypot, citrix-honeypot, rdp-honeypot, sonicwall-sma-honeypot) are watched anyway, solely so canonical-field promotion (#1217) runs on their lines |
| Tunnel-blind (joined) | cowrie, dionaea + its incident variant (#623), conpot's UDP personas only (SNMP 161, BACnet 47808, IPMI 623 — PROXY v1 has no UDP form, so those three listeners get no prefix), dns-honeypot, cisco-asa (IKE side), elasticpot, mailoney, hellpot (raw door), beelzebub, sentrypeer, galah (raw door) | raw TCP relay; the log records the WireGuard peer (`10.8.0.1`, the VPS-side tunnel address) | `via_port` join against the portbridge connection log — the generic join for flat `src_ip`/`src_port` shapes (cowrie, dionaea, the conpot personas, dns-honeypot, cisco-asa IKE, elasticpot, mailoney); bespoke join paths for the rest (dionaea-incident's nested rewrite; beelzebub and sentrypeer derive their own address field, then join; hellpot and galah's raw door is joined and adjudicated against their forwarded-header claim) |

The join runs **at ingest time, not read time** (#37/#38): the networkless
`backend-worker-enrichment` container reads both files off disk and writes
an already-correct copy to `logs/enriched/*.json`. Filebeat tails the
enriched path for every watched sensor — nothing is shipped twice. A
portbridge dial must **precede** the flow it explains for the join to fire;
where no candidate survives that ordering test, the record honestly stays
tunnel-attributed (surfaced dashboard-wide as `unattributed_24h`, #1723).
An unattributed flow is honest; a wrong attacker is not.

### 1b. Enrichment: the `geoip-honeypot` ingest pipeline

One ES ingest pipeline (`index.default_pipeline` on all three index
families) processes every document. Each processor is
`ignore_failure: true`; enrichment failure never blocks indexing.

Order (1:1 with `arcane/home/honeypot-init/analysis/elasticsearch-setup.sh`):

1. Main normalization script — promotes heterogeneous sensor fields into
   the flattened `honeypot.*` map (sensor, ips/ports, protocol, user,
   command line, url path, sha256, category, persona)
2. Fingerprint promotion (#1970) — collapses each document's correlation
   identity into one typed `fingerprint.kind` / `fingerprint.value` pair
   on all three index families: honeypot docs follow events.rs'
   `pivots_from_source` precedence exactly (canonical_fingerprint(+kind),
   hassh → HASSH, fingerprint → SSH pubkey, client → client banner,
   user_agent → User-Agent), Suricata TLS promotes JA4 over JA3.hash,
   suricata HTTP keeps the User-Agent kind alive, portbridge carries the
   p0f OS guess. Stripped/empty sources write nothing — no empty-string
   pollution — so ES-side terms aggs reproduce what the dashboard's
   read-time classification produced without the dashboard running.
3. Traefik wire-tuple `community_id` (#1765) — hashes the tuple the request
   was actually accepted on (`ClientAddr` → VPS address/entrypoint port), not
   the client Traefik resolved after forwarded-header trust, so a Traefik
   record and huginn's sidecar observation of the same TLS connection share
   a key
4. Generic `community_id` (#1742) — derives the key for any record that has a
   5-tuple but none of its own (Zeek's ~20 protocol logs carry `uid`; only
   `conn.log` carries `community_id`), seed 0 to match `suricata.yaml`
5–7. GeoIP on suricata src/dst fields (`ignore_missing` no-ops elsewhere)
8–11. GeoIP on honeypot/portbridge src fields
12. Dionaea incident hash extraction (plain scan, no regex)
13. Network-type classification from ASN org (scanner/cloud/hosting)
14. Log4Shell deobfuscation flag (bounded depth/length)

No processor makes a network call — GeoIP reads local `.mmdb` files.

### 1c. Read path: how the dashboard consumes events

| Path | Used by | Contract |
|---|---|---|
| ES query (PIT + `search_after`) | every historical view | 30s timeout, ≤10k window, `_shard_doc` tie-breaker |
| Shared serviceJSON cache | all frontend server functions | 15s TTL in-process + Redis shared layer; ConcurrencyLimiter backpressure |
| SSE `/api/v1/live` | live tail pages | resume carries the full sort tuple, so same-millisecond rows are neither dropped nor duplicated (#1979 closed by #2039) |
| Bounded local-file tail | suricata + portbridge only | the two index families without a `honeypot-v2-*` mirror (#1103 Cat. 2); every other sensor is ES-only by design |

---

## 2. Derived intelligence: the worker loops

All loops share one contract: **stateless recomputation over a rolling
window, durable output via idempotent writes** (CAS `seq_no/primary_term`
or deterministic document IDs). If ES is unavailable the loop skips a
cycle; there is no local state to corrupt.

```mermaid
flowchart TB
  raw[("honeypot-v2-* · suricata-v2-*<br/>analysis-result indices")]

  subgraph loops["Loop containers (cadence per env var)"]
    ident["attacker-identity<br/>every 15m · 10d window"]
    corr["correlator<br/>every cycle · full recompute"]
    intr["agent-intrusion<br/>every 300s · 10d window"]
    zpa["zeek-proxy-attribution<br/>every 120s · time-bounded join"]
    alert["alert-notifier<br/>webhook fan-out, cooldown-gated"]
    roll["dashboard-rollups<br/>every ROLLUP_RUN_INTERVAL_SECS (default 300s)"]
    tint["threat-intel<br/>every 15m · 24h lookback"]
  end

  subgraph out["Durable entities"]
    atk[("attackers-v1")]
    cmp[("campaigns-v1")]
    clu[("attacker-clusters-v1")]
    aic[("agent-intrusion-campaigns")]
    st[("dashboard-alert-state-v1")]
    rll[("overview-rollup-v1<br/>geo-rollup-v1<br/>attack-rollup-v1")]
  end

  raw --> ident --> atk
  raw --> corr --> cmp & clu
  raw --> intr --> aic
  raw --> zpa
  atk & cmp & aic --> alert --> st
  raw --> roll --> rll
  raw --> tint
  tint -.->|"rewrites source.as.type in place"| raw
```

| Loop | Reads | Writes | Cadence | Notes |
|---|---|---|---|---|
| attacker-identity | `honeypot-v2-*`, `*-analysis-v1` verdicts | `attackers-v1` | 15m | union of observed behavior + analysis verdicts per source IP; standalone Go worker stack |
| correlator | raw events | `campaigns-v1`, `attacker-clusters-v1` | every cycle | pure aggregations, recomputed from scratch; groups ≥2 IPs sharing fingerprint/hash/ASN/provider-class |
| agent-intrusion | raw events | `agent-intrusion-campaigns` | 300s | deterministic criticality rules escalate; LLM never gates escalation; deterministic sha256 campaign_id ⇒ upsert not duplicate |
| zeek-proxy-attribution | zeek flows + portbridge log | flow docs | 120s | attributes relayed flows to attackers; ordering rule above applies here too |
| threat-intel | raw event indices | `source.as.type` in place | 15m run, 5m CIDR reload, 24h lookback | classifies source IPs against `threat-cidrs.csv`; intel labels win over the ingest pipeline's provider class, reproducing the retired Go dashboard's `firstNonEmpty(e.Intel, e.Provider)` precedence at the data layer |
| dashboard-rollups (#2046) | raw event indices (default pattern) | `overview-rollup-v1`, `geo-rollup-v1`, `attack-rollup-v1` | `ROLLUP_RUN_INTERVAL_SECS`, default 300s | pure-ES derived overviews the dashboard's overview/map/kill-chain reads slice cheaply instead of re-aggregating raw events per request |
| ml-worker / llm-worker | payloads + events | `ml-anomalies` + `dashboard-ml-anomaly-ack-v1` | continuous | scoring semantics tracked in #1969/#1974 |
| payload-inventory | disk stores | `dashboard-payload-inventory-v1`, `dashboard-payload-bytes-v1` | periodic scan | HEAD-exists fast path (#1221) |
| es-results-importer | root-owned result spools | `*-analysis-v1` | continuous | read-only mirror, shard-partitionable |
| vault-worker (#2290) | `*-analysis-v1`, `llm-analysis` | markdown notes under the knowledge-vault directory (#2289) | `VAULT_POLL_INTERVAL_SECONDS`, default 900s | one note per payload/session entity, sha256-keyed filename ⇒ upsert not duplicate; checkpointed via `knowledge-vault-state-v1`, batch-run so a capture flood can't swamp the vault |

Operational caveat from #1980 — worker panics used to kill the whole
container on one malformed document — is fixed: every runloop carries a
`recover()` boundary now, so a poison document fails that iteration, not
the loop's uptime.

---

## 3. Payload lifecycle

Captures are content, never configuration; nothing captured is ever
executed inside the fleet.

```mermaid
flowchart LR
  up1["cowrie downloads/uploads"] --> store[("logs/cowrie/downloads")]
  up2["dionaea captures"] --> store2[("dionaea-lib volume")]
  up3["inline scripts"] --> store3[("script-payloads, SHA-256-named inert")]

  store & store2 & store3 --> dedupe["payload-dedupe<br/>SHA-256 + same-FS hard links"]
  store & store2 & store3 --> yara["YARA scanner<br/>networkless · read-only"]
  yara --> yout[("yara-results/results.json")]

  store & store2 & store3 & yout --> inv["inventory worker"] --> ix[("dashboard-payload-inventory-v1<br/>dashboard-payload-bytes-v1")]

  ix --> wb{"Analyst dispatch:<br/>payload workbench"}
  wb -->|"hash-only .request markers"| spools["analysis spools:<br/>ghidra · linux sandbox · windows sandbox<br/>GHOSTS · revdeck · CAPE"]
  spools --> results["result dirs (root-owned)"] --> importer["es-results-importer"] --> aix[("*-analysis-v1")]
  aix --> dash2["dashboard: /payloads, workbench,<br/>investigate surfaces"]
```

Key invariants:

- **Hash-only handoff.** Workbench requests are empty `<sha256>.request`
  marker files. No sample bytes, paths, or commands cross a privilege
  boundary; the receiving root-owned service resolves the hash inside its
  own approved roots and recomputes SHA-256 before use.
- **Dedupe preserves every path**, hard-linking duplicates on the same
  filesystem only — source labels survive because the inventory merge keys
  on hash but keeps every contributing store.
- **Static analysis cache is content-addressed**
  (`dashboard-static-analysis-v1`): immutable per hash, so hits never need
  invalidation.
- **Verdict discipline.** Static ≠ dynamic ≠ IDS ≠ correlation evidence;
  timeouts/failures stay visibly distinct from "clean". Scores are triage
  aids wired to nothing automatic — no firewall changes, reporting, or
  execution ever fires off a score alone.

---

## 4. Index catalog

Producer → consumer summary (verified during the #1960 review; each derived
index has exactly one writer):

| Index family | Written by | Read by |
|---|---|---|
| `honeypot-v2-*`, `suricata-v2-*`, `portbridge-v2-*` | Filebeat (+ ingest pipeline) | dashboard, all workers, Kibana, EveBox (`suricata-*`) |
| `dead-letter-honeypot` | ES (rejected docs) | dead-letters page, source-health |
| `attackers-v1` | attacker-identity-worker | backend-service (attackers, overview, graphs) |
| `campaigns-v1`, `attacker-clusters-v1` | correlator-worker | backend-service (clusters, kill-chain, investigate) |
| `agent-intrusion-campaigns` | backend-service agent_intrusion loop | agent-campaigns page |
| `ghidra-analysis-v1`, `sandbox-analysis-v1`, `github-analysis-v1`, `workbench-runs-v1`, `cape-analysis-v1`, `revdeck-analysis-v1` | es-results-importer | identity worker, investigate/payload surfaces |
| `yara-analysis-v1` | YARA join via inventory | backend-service charts + investigate |
| `dashboard-payload-inventory-v1`, `dashboard-payload-bytes-v1` | payload-inventory-worker | payloads page, charts |
| `dashboard-canarytokens-v1` | canarytokens-adapter | canarytokens page + settings pane |
| `cowrie-ttylog-v1` | Filebeat | tty-replay, recordings |
| `mailoney-mail-v1` | Filebeat | sessions/mail views |
| `reporter-metrics-v1` | reporter | settings stats pane |
| `dashboard-alert-state-v1` | alert-notifier loop | alerts page |
| `overview-rollup-v1`, `geo-rollup-v1`, `attack-rollup-v1` | dashboard-rollups loop (#2046) | overview/map/kill-chain dashboard reads |
| `ml-anomalies`, `dashboard-ml-anomaly-ack-v1` | ml/llm workers | ml-anomalies page, composite score |
| `dashboard-users-v1`, `dashboard-workbench-runs-v1`, report/problem-report indices | backend-service itself | their pages |

Retention specifics (ILM, pcap ceilings, snapshots) live in
[STORAGE.md](STORAGE.md#retention-and-lifecycle).
