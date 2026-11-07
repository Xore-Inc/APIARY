//! Thin Elasticsearch access layer. Index families and field names mirror
//! the Go dashboard's es_aggregate.go exactly (ECS: honeypot-v2-* for every
//! decoy sensor, suricata-v2-* for Suricata -- one multi-index pattern per
//! query, #1136), so both tiers agree on the data until the Go tier
//! retires at cutover.

use elasticsearch::{
    cluster::ClusterHealthParts,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    indices::IndicesGetSettingsParts,
    params::{OpType, Refresh},
    BulkOperation, BulkParts, Elasticsearch, SearchParts,
};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

/// Every index family that carries sensor events, keyed by `event.sensor`.
///
/// This is what `Es::search` targets, so it decides what the whole dashboard
/// can see: the source-health feed list, the sensor filter values, the
/// overview KPIs and the event explorer all read through it. An index absent
/// here is invisible everywhere, silently -- the page renders fine, it just
/// never mentions the sensor. #1742's sensors were missing for exactly that
/// reason, 573,463 documents of them, and portbridge had been missing since
/// long before that.
///
/// Each family here was checked for what `source.ip` actually means on it,
/// because an index whose source is our own infrastructure would re-create
/// #1677 by attributing its events to us:
///
///   portbridge-v2-*   real attacker address (zero fleet-sourced documents)
///   zeek-v1-*         real attacker address -- it sniffs the public NIC
///   traefik-v1-*      real client address
///   huginn-v1-*       often OUR VPS: it records the responder's SYN-ACK and
///                     server-uptime observations as well as the client's SYN
///   zeek-proxy-v1-*   usually the tunnel peer: it watches the relay side, so
///                     the originator is our own VPS forwarding inward
///
/// The last two are still included, because the exclusion that makes them
/// safe already exists and is applied at query level: dashboard.rs's
/// `self_addresses()` (#1677/#1779) drops the tunnel peer and everything in
/// HONEYPOT_SELF_IPS from the attacker-ranking aggregations, and charts.rs
/// inherits it. Their event counts and freshness are still worth surfacing --
/// "is this sensor alive" is the question source-health exists to answer.
pub const EVENT_INDICES: &[&str] = &[
    "honeypot-v2-*",
    "suricata-v2-*",
    "portbridge-v2-*",
    "zeek-v1-*",
    "zeek-proxy-v1-*",
    "huginn-v1-*",
    "traefik-v1-*",
];

/// Every index family THIS TIER WRITES TO, as the index expressions
/// `/readyz` asks Elasticsearch about (`Es::write_blocked`, #3317).
///
/// The complement of `EVENT_INDICES` above, not a copy of it: a read-only
/// index somebody else owns going write-blocked is that tier's outage, but
/// a write-blocked index in this list means the dashboard can no longer
/// record what it observes — which is the difference between "the process
/// is up" (what /livez says) and "the process can do its job" (what
/// /readyz has to answer).
///
/// `dashboard-*` is deliberately one wildcard rather than the twenty-odd
/// concrete `dashboard-*-v1` names behind it: every serving-tier index
/// uses that prefix, and a pattern cannot fall out of date the way a
/// hand-copied list of them can. The unprefixed families are named
/// individually because nothing about their names is predictable — each is
/// the sole write target of one bundled worker loop.
///
/// The list drifts in one direction harmlessly and in the other loudly. An
/// index missing from it goes unchecked, so readiness stays green on a
/// block nobody is watching; an entry for an index this tier only *reads*
/// reports not-ready during another component's outage, which trains
/// operators to ignore the endpoint. So when a new write target is added,
/// add it here, and when in doubt leave it out rather than widening the
/// claim.
pub const WRITE_TARGET_FAMILIES: &[&str] = &[
    // Serving tier: config, users, credentials, IP blocks, report
    // definitions/generated, workbench runs+recipes, payload inventory and
    // bytes, canary tokens, problem reports, webhook delivery, ML acks.
    "dashboard-*",
    // Bundled worker loops.
    "attackers-v1",              // attacker_identity
    "attacker-clusters-v1",      // correlator
    "campaigns-v1",              // correlator
    "cred-reuse-v1",             // correlations
    "flow-links-v1",             // correlations
    "ioc-verdicts-v1",           // attacker_identity
    "overview-rollup-v1",        // rollups
    "geo-rollup-v1",             // rollups
    "attack-rollup-v1",          // rollups
    "gpu-job-queue",             // gpu_queue, vault_rag
    "agent-intrusion-campaigns", // agent_intrusion
    // es_importer's mirrors of the external analysis workers. Its own
    // sources table keys these off env vars, so a deployment that never
    // set one simply has no such index and never gets asked about it.
    "yara-analysis-v1",
    "ghidra-analysis-v1",
    "ghidra-report-artifacts-v1",
    "sandbox-analysis-v1",
    "sandbox-export-artifacts-v1",
    "revdeck-analysis-v1",
    "cape-analysis-v1",
    "cowrie-ttylog-v1",
    "mailoney-mail-v1",
    "github-analysis-v1",
    "reporter-metrics-v1",
];

/// The "is this a login/auth attempt" query fragment (#1611 workstream C),
/// shared by every login-counting aggregation (aggregates.rs's sources
/// page, dashboard.rs's overview KPIs, reports_data.rs's report
/// summaries). The original `honeypot.event ∈ {login, auth_attempt}`
/// filter missed most real auth activity — audited against the live
/// per-sensor vocabularies (#1611's own live-cluster audit):
/// - cowrie logs cowrie.login.success/failed on `honeypot.eventid`, never
///   `honeypot.event`, and is the single largest auth source (1.26M docs
///   on the audited deployment) — entirely uncounted before this.
/// - rdp-honeypot's auth rides on a plain `connect` event with a non-empty
///   `honeypot.username` (the mstshash), no dedicated login/auth_attempt
///   kind of its own.
/// - `honeypot.canonical_user`'s existence is a sensor-agnostic catch-all:
///   ip-enrichment-worker promotes it for beelzebub/dionaea today and will
///   cover more sensors as that promotion's own coverage grows (#1611
///   workstreams D/G) — this clause benefits automatically as it does,
///   with no further change needed here.
pub fn logins_filter() -> Value {
    serde_json::json!({"bool": {"should": [
        {"terms": {"honeypot.event": ["login", "auth_attempt"]}},
        {"terms": {"honeypot.eventid": ["cowrie.login.success", "cowrie.login.failed"]}},
        {"bool": {"filter": [
            {"term": {"event.sensor": "rdp-honeypot"}},
            {"exists": {"field": "honeypot.username"}}
        ]}},
        {"exists": {"field": "honeypot.canonical_user"}}
    ], "minimum_should_match": 1}})
}

/// The ingest-time health-check probe exclusion (#1902 residue, audited in
/// #2145): the ip-enrichment worker marks every fleet/self healthcheck
/// event with `honeypot.internal_probe = true` (ip_enrichment/sensors.rs)
/// and strips its `source.ip`, but the documents still land in
/// `honeypot-v2-*` — roughly 92k/day on the audited deployment — so any
/// honeypot-v2 aggregation built without this clause silently counts
/// sensor liveness probes as attacker traffic. Every attacker-facing
/// aggregation over the index must carry this term in its `must_not`;
/// reads that exist to observe the probes themselves (source-health
/// pages, lag/activity sampling) deliberately omit it — that asymmetry is
/// the recorded #2145 decision to keep probes indexed rather than move
/// them to a separate index.
pub fn internal_probe_exclusion() -> Value {
    serde_json::json!({"term": {"honeypot.internal_probe": true}})
}

pub struct Es {
    client: Elasticsearch,
}

/// A document write that can lose an optimistic-concurrency race. Distinct
/// from `anyhow::Error` so callers doing their own create-or-reuse /
/// compare-and-swap retry logic (workbench runs/recipes) can match on
/// `Conflict` without string-sniffing an error message.
#[derive(thiserror::Error, Debug)]
pub enum WriteError {
    #[error("elasticsearch write conflict")]
    Conflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Es {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        // Transport::single_node's own default carries no request timeout at
        // all -- confirmed live during #1628's preflight: backend-worker's
        // /healthz handler used to share this same client, and a slow/stuck
        // query from any of its four bundled worker loops (correlator's
        // aggregation was hitting Elasticsearch's own
        // too_many_buckets_exception on every cycle against real data,
        // plausibly saturating the cluster's search queue for a while) could
        // therefore hang the health probe indefinitely too, since nothing ever
        // timed out client-side -- the container never crashed, /healthz just
        // never returned, and something external kept restarting it every few
        // minutes on the resulting healthcheck failure. 30s bounds the worst
        // case without punishing legitimately slower real-data queries the
        // way CI's fixture-sized indices never needed to.
        //
        // #3317: that health probe no longer exists. /livez (and its
        // /healthz alias) never touches Elasticsearch at all, and /readyz
        // runs its two probes under its own 5s READINESS_TIMEOUT rather than
        // inheriting this one, so nothing on the probe path can now block for
        // 30 seconds. The budget below is therefore sized purely for real
        // queries, which is what it was always for -- kept because those
        // worker loops are still the callers that can saturate the search
        // queue, and deleting the only bound they have would reintroduce the
        // hang for them.
        let conn_pool = SingleNodeConnectionPool::new(url.parse()?);
        let transport = TransportBuilder::new(conn_pool)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client: Elasticsearch::new(transport),
        })
    }

    /// Cluster color (green/yellow/red), "unreachable" on transport error.
    ///
    /// Deliberately lossy: this feeds the source-health card, which must
    /// render even when Elasticsearch is the thing that is broken, so it
    /// has nowhere to put an error string. `/readyz` needs the error
    /// itself and uses `cluster_health_status` below instead.
    pub async fn cluster_status(&self) -> String {
        self.cluster_health_status().await.unwrap_or_else(|_| "unreachable".into())
    }

    /// Cluster color as Elasticsearch reports it, or the failure explaining
    /// why it could not be asked. The fallible half of `cluster_status`,
    /// for callers that have to say which of the two happened (#3317).
    pub async fn cluster_health_status(&self) -> anyhow::Result<String> {
        let response = self
            .client
            .cluster()
            .health(ClusterHealthParts::None)
            .send()
            .await?;
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            anyhow::bail!("elasticsearch cluster health {}: {}", status, json);
        }
        Ok(json["status"].as_str().unwrap_or("unknown").to_string())
    }

    /// Which of `indexes` Elasticsearch currently has `index.blocks.write`
    /// set on, sorted. Empty means "a write to any of them would be
    /// accepted" (#3317).
    ///
    /// The setting is the whole answer to "is this writable", and asking
    /// for it by name means the response carries nothing else — this runs
    /// on a probe, where a full settings dump per index family would be
    /// the most expensive request this tier makes.
    ///
    /// Two things it deliberately does not report as a block. An index that
    /// does not exist is absent from the response, not blocked: every
    /// dashboard-owned index is created lazily on its first write (see
    /// `search_paginated`), so a fresh cluster correctly reads ready — and
    /// the allow_no_indices/ignore_unavailable pair above is what keeps
    /// "no such index" from arriving as a 404 error instead. The other is
    /// that a set value is compared rather than the key merely existing:
    /// Elasticsearch drops the setting entirely when a block is cleared, so
    /// `false` is not a shape this endpoint has been observed to return,
    /// but reading the block as "the key is present" would be a claim
    /// about this Elasticsearch's normalization rather than about the
    /// block.
    pub async fn write_blocked(&self, indexes: &[&str]) -> anyhow::Result<Vec<String>> {
        if indexes.is_empty() {
            return Ok(Vec::new());
        }
        let response = self
            .client
            .indices()
            .get_settings(IndicesGetSettingsParts::IndexName(indexes, &["index.blocks.write"]))
            // flat_settings is what puts the block at the literal
            // "index.blocks.write" key; without it the response nests it as
            // settings.index.blocks.write and the lookup below silently
            // matches nothing, i.e. always ready.
            .flat_settings(true)
            // A family that matches nothing (a worker loop this deployment
            // never enabled writes into an index that was never created) is
            // normal, not an error.
            .allow_no_indices(true)
            .ignore_unavailable(true)
            .send()
            .await?;
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            anyhow::bail!("elasticsearch get_settings {}: {}", status, json);
        }
        let Some(indices) = json.as_object() else {
            return Ok(Vec::new());
        };
        let mut blocked: Vec<String> = indices
            .iter()
            .filter(|(_, settings)| {
                settings["settings"]["index.blocks.write"]
                    .as_str()
                    .is_some_and(|block| block == "true" || block == "1")
            })
            .map(|(name, _)| name.clone())
            .collect();
        // Sorted so the same outage always names its indices in the same
        // order, which makes two consecutive /readyz bodies diffable.
        blocked.sort();
        Ok(blocked)
    }

    /// Cluster-wide index stats summary: (index_count, doc_count, bytes).
    pub async fn storage_summary(&self) -> anyhow::Result<(u64, u64, u64)> {
        let response = self
            .client
            .indices()
            .stats(elasticsearch::indices::IndicesStatsParts::None)
            .send()
            .await?;
        let json = response.json::<Value>().await?;
        let indices = json["indices"]
            .as_object()
            .map(|map| map.len() as u64)
            .unwrap_or(0);
        let docs = json["_all"]["total"]["docs"]["count"].as_u64().unwrap_or(0);
        let bytes = json["_all"]["total"]["store"]["size_in_bytes"]
            .as_u64()
            .unwrap_or(0);
        Ok((indices, docs, bytes))
    }

    /// Partial-document update with conflict retries — the idiomatic
    /// equivalent of the Go tier's optimistic seq_no/primary_term loop.
    pub async fn update_doc(&self, index: &str, id: &str, doc: Value) -> anyhow::Result<()> {
        let response = self
            .client
            .update(elasticsearch::UpdateParts::IndexId(index, id))
            .retry_on_conflict(3)
            .body(serde_json::json!({"doc": doc}))
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch update {}: {}", status, body);
        }
        Ok(())
    }

    /// Fetch one document's _source by id; Ok(None) on 404.
    pub async fn get_doc(&self, index: &str, id: &str) -> anyhow::Result<Option<Value>> {
        Ok(self
            .get_doc_meta(index, id)
            .await?
            .map(|(source, _, _)| source))
    }

    /// get_doc plus the seq_no/primary_term a caller needs to make a
    /// conditional overwrite (index_doc_cas) — the compare-and-swap
    /// primitive Go's docGet+docIndex(create=false, seqNo, primaryTerm)
    /// pair gives for free, needed by any read-modify-write loop (workbench
    /// run/recipe updates) beyond this crate's existing update_doc (which
    /// only ever does a partial-field merge with server-side conflict
    /// retries, not a caller-driven read-modify-write).
    pub async fn get_doc_meta(
        &self,
        index: &str,
        id: &str,
    ) -> anyhow::Result<Option<(Value, i64, i64)>> {
        let response = self
            .client
            .get(elasticsearch::GetParts::IndexId(index, id))
            .send()
            .await?;
        if response.status_code().as_u16() == 404 {
            return Ok(None);
        }
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            anyhow::bail!("elasticsearch get {}: {}", status, json);
        }
        let Some(source) = json.get("_source").cloned() else {
            return Ok(None);
        };
        let seq_no = json["_seq_no"].as_i64().unwrap_or(0);
        let primary_term = json["_primary_term"].as_i64().unwrap_or(0);
        Ok(Some((source, seq_no, primary_term)))
    }

    /// Creates a document that must not already exist (`op_type=create`),
    /// waiting for the write to become search-visible before returning —
    /// the primitive workbench run/recipe creation uses for atomic,
    /// cross-instance idempotent dedup: the document's own id IS the
    /// caller's idempotency key, so a losing race is a genuine, correct
    /// "someone already submitted this" rather than an error to retry.
    /// `WriteError::Conflict` on a 409 (id already exists); the caller
    /// fetches the existing document itself to decide what "reused" means.
    pub async fn index_doc_create(
        &self,
        index: &str,
        id: &str,
        doc: Value,
    ) -> Result<(), WriteError> {
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(index, id))
            .op_type(OpType::Create)
            .refresh(Refresh::WaitFor)
            .body(doc)
            .send()
            .await
            .map_err(|error| WriteError::Other(error.into()))?;
        let status = response.status_code();
        if status.as_u16() == 409 {
            return Err(WriteError::Conflict);
        }
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            return Err(WriteError::Other(anyhow::anyhow!(
                "elasticsearch create {}: {}",
                status,
                body
            )));
        }
        Ok(())
    }

    /// Conditional overwrite: only applies if the document's current
    /// seq_no/primary_term still match what the caller read (from
    /// get_doc_meta). `WriteError::Conflict` on a lost race (409) — the
    /// idiomatic Rust equivalent of Go's docIndex(create=false, seqNo,
    /// primaryTerm) compare-and-swap, for a caller-driven read-modify-write
    /// retry loop (workbench run updates: reconcile-on-read, child
    /// cancel/retry actions).
    pub async fn index_doc_cas(
        &self,
        index: &str,
        id: &str,
        doc: Value,
        seq_no: i64,
        primary_term: i64,
    ) -> Result<(), WriteError> {
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(index, id))
            .if_seq_no(seq_no)
            .if_primary_term(primary_term)
            .body(doc)
            .send()
            .await
            .map_err(|error| WriteError::Other(error.into()))?;
        let status = response.status_code();
        if status.as_u16() == 409 {
            return Err(WriteError::Conflict);
        }
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            return Err(WriteError::Other(anyhow::anyhow!(
                "elasticsearch index {}: {}",
                status,
                body
            )));
        }
        Ok(())
    }

    /// Index (upsert) one document by id.
    pub async fn index_doc(&self, index: &str, id: &str, doc: Value) -> anyhow::Result<()> {
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(index, id))
            .body(doc)
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch index {}: {}", status, body);
        }
        Ok(())
    }

    /// Deletes one document by id. Ok(()) even if it was already gone
    /// (404) — the same idempotent-delete posture Go's docDelete callers
    /// (pruneGenerated's best-effort retention sweep) rely on.
    pub async fn delete_doc(&self, index: &str, id: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .delete(elasticsearch::DeleteParts::IndexId(index, id))
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() && status.as_u16() != 404 {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch delete {}: {}", status, body);
        }
        Ok(())
    }

    /// Builds `delete_by_query_except`'s "everything except these ids"
    /// query as **one** `ids` clause holding every kept id in its `values`
    /// array, rather than one `must_not` clause per id (#2899).
    ///
    /// Some callers build large `keep` lists — correlations.rs's flow sweep
    /// caps at 2,000 (`FLOW_BUCKET_CAP`), its credential-reuse sweep at 800
    /// (`CRED_PAIR_CAP * 4`), correlator.rs's cluster sweep at 1,000 (four
    /// `terms` aggs of `size: 250`) — and correlator.rs's campaign sweep
    /// derives its ids from `ip_prefix` aggregations that carry no `size`
    /// key at all, so its keep list is unbounded by construction. The
    /// per-id form made the query's own bool clause count scale with
    /// `keep.len()`, independent of how many documents actually exist.
    ///
    /// What that risks, measured rather than assumed.
    /// `indices.query.bool.max_clause_count` reports **4096** as its default
    /// and is untuned on the deployed cluster (`persistent` and `transient`
    /// both empty) — but 4096 is not the number that gets enforced. The node
    /// derives the limit it actually applies from its own heap. Reproduced
    /// on Elasticsearch 9.5.1 / Lucene 10.5.0, same version the deployment
    /// runs, 2026-09-03:
    ///
    /// | node heap | setting reports | actually enforced | 5,000 clauses | 20,000 clauses |
    /// |---|---|---|---|---|
    /// | 1 GiB | 4096 | 3449 | rejected, 0.9 s | — |
    /// | 4 GiB | 4096 | 13797 | accepted, 1.4 s | rejected, 11.2 s (688 KB body) |
    ///
    /// So the wall is a property of the node, not a constant a caller can
    /// reason about, and it moves under the deployment: the same 5,000-clause
    /// probe that fails on a small node succeeded against the production
    /// cluster (HTTP 200, 2.3 s), while a 20,000-clause probe there never
    /// returned at all and coincided with that node going hard-down (#2914).
    /// Crossing it is a `query_shard_exception` — which aborts the whole
    /// resync sweep, after the node has already spent real time parsing the
    /// request. A single `ids` clause holds an arbitrary number of values
    /// without adding bool clauses, so the growth disappears regardless of
    /// how large any caller's keep list gets, and the primitive stops
    /// depending on how much heap the cluster happens to have.
    fn except_query(keep: &[String]) -> Value {
        serde_json::json!({"query": {"bool": {"must_not": [{"ids": {"values": keep}}]}}})
    }

    /// Deletes every document in `index` whose id is not in `keep` — a
    /// "delete-by-query minus explicit ids" full-resync primitive for a
    /// worker that recomputes its whole output set every cycle and is the
    /// index's sole writer (correlator-worker's campaigns-v1/attacker-
    /// clusters-v1: upsert this cycle's fresh docs, then this call removes
    /// whatever's left over from a group/cluster that no longer qualifies).
    /// `conflicts=proceed` matches the Go worker's own posture — a
    /// concurrent version conflict on a doc mid-delete is not worth
    /// aborting the sweep over. A missing index (404, first run) is not an
    /// error, same idempotent posture as `delete_doc`.
    pub async fn delete_by_query_except(&self, index: &str, keep: &[String]) -> anyhow::Result<()> {
        let body = Self::except_query(keep);
        let response = self
            .client
            .delete_by_query(elasticsearch::DeleteByQueryParts::Index(&[index]))
            .conflicts(elasticsearch::params::Conflicts::Proceed)
            .body(body)
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() && status.as_u16() != 404 {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch delete_by_query {}: {}", status, body);
        }
        Ok(())
    }

    /// `_delete_by_query` with a caller-supplied query, returning the
    /// deleted count — the general-purpose sibling of
    /// `delete_by_query_except`'s keep-list-shaped one. Ported from
    /// elastic.go's purgeDeadLetters: `conflicts=proceed`, same reasoning
    /// as above (a version conflict mid-sweep isn't worth aborting over).
    pub async fn delete_by_query(&self, index: &str, query: Value) -> anyhow::Result<u64> {
        let response = self
            .client
            .delete_by_query(elasticsearch::DeleteByQueryParts::Index(&[index]))
            .conflicts(elasticsearch::params::Conflicts::Proceed)
            .body(serde_json::json!({"query": query}))
            .send()
            .await?;
        let status = response.status_code();
        let body = response.json::<Value>().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("elasticsearch delete_by_query {}: {}", status, body);
        }
        Ok(body["deleted"].as_u64().unwrap_or(0))
    }

    /// `_update_by_query` across `indices` with a caller-supplied query and
    /// painless script (`script_params` become the script's `params`),
    /// returning the updated count. `conflicts=proceed` — same reasoning as
    /// `delete_by_query`: a version conflict racing an in-flight write
    /// isn't worth aborting the whole sweep over, the next cycle will
    /// pick it up.
    pub async fn update_by_query(
        &self,
        indices: &[&str],
        query: Value,
        script_source: &str,
        script_params: Value,
    ) -> anyhow::Result<u64> {
        let body = serde_json::json!({
            "query": query,
            "script": {"source": script_source, "lang": "painless", "params": script_params},
        });
        let response = self
            .client
            .update_by_query(elasticsearch::UpdateByQueryParts::Index(indices))
            .conflicts(elasticsearch::params::Conflicts::Proceed)
            .body(body)
            .send()
            .await?;
        let status = response.status_code();
        let body = response.json::<Value>().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("elasticsearch update_by_query {}: {}", status, body);
        }
        Ok(body["updated"].as_u64().unwrap_or(0))
    }

    /// One `_search` against the shared event indices; body is the caller's
    /// full query DSL. `ignore_unavailable` matches the Go client's posture
    /// so a not-yet-created index family never fails the whole query.
    pub async fn search(&self, body: Value) -> anyhow::Result<Value> {
        self.search_index(EVENT_INDICES, body).await
    }

    /// `_search` against arbitrary indices — the worker/store index
    /// families (campaigns-v1, attackers-v1, dashboard-*-v1, ...).
    pub async fn search_index(&self, indices: &[&str], body: Value) -> anyhow::Result<Value> {
        let response = self
            .client
            .search(SearchParts::Index(indices))
            .ignore_unavailable(true)
            .body(body)
            .send()
            .await?;
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            anyhow::bail!("elasticsearch {}: {}", status, json);
        }
        Ok(json)
    }

    /// Bulk `index` (plain upsert, not `create`) a batch of documents, each
    /// against its own (index, id) — the primitive es_importer.rs needs to
    /// mirror analysis/es-results-importer/importer.py's `bulk(es, actions,
    /// stats_only=False, raise_on_error=False)` call. Returns the `_id` of
    /// every operation the cluster reported as failed (network/transport
    /// failure fails every id in the batch); an empty set means every
    /// document in `operations` was indexed. Deliberately per-item, not a
    /// single pass/fail for the whole batch — callers need this to only
    /// advance dedup state for documents that actually made it into ES,
    /// matching the Python importer's own advance_state_after_bulk
    /// semantics on a partial batch failure.
    /// `#1978`: documents are borrowed — the caller's pending batch (which
    /// for chunked artifacts is hundreds of megabytes of base64 strings)
    /// must not be duplicated just to serialize it once.
    pub async fn bulk_index(
        &self,
        operations: Vec<(&str, &str, &Value)>,
    ) -> anyhow::Result<HashSet<String>> {
        if operations.is_empty() {
            return Ok(HashSet::new());
        }
        let all_ids: HashSet<String> = operations.iter().map(|(_, id, _)| id.to_string()).collect();
        let ops: Vec<BulkOperation<&Value>> = operations
            .into_iter()
            .map(|(index, id, doc)| BulkOperation::index(doc).index(index).id(id).into())
            .collect();
        let response = self.client.bulk(BulkParts::None).body(ops).send().await;
        let response = match response {
            Ok(r) => r,
            Err(_) => return Ok(all_ids), // transport failure: every op unconfirmed, retry next pass
        };
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            // A bulk-level rejection (e.g. auth, malformed request) fails
            // every operation in the batch, same as a transport error above.
            return Ok(all_ids);
        }
        let mut failed = HashSet::new();
        for item in json["items"].as_array().into_iter().flatten() {
            // Every op here is "index" (see BulkOperation::index above), so
            // the per-item result always nests under "index".
            let result = &item["index"];
            let ok = result["status"].as_u64().map(|s| (200..300).contains(&s)).unwrap_or(false);
            if !ok {
                if let Some(id) = result["_id"].as_str() {
                    failed.insert(id.to_string());
                }
            }
        }
        Ok(failed)
    }

    /// Point-in-time + search_after pagination, needed because
    /// Elasticsearch's *default* `index.max_result_window` is 10,000 — a
    /// single oversized `size` request hard-fails past that, not just
    /// returns less. Every other query in this crate stays under that cap
    /// by design; attacker-identity-worker's event fetch and existing-
    /// entity load can legitimately exceed it. `body_fn` receives the
    /// previous page's `search_after` value (`None` on the first call) and
    /// returns the query body for the next page — the caller owns `query`/
    /// `sort`/`_source`, this primitive only injects `size`/`pit` and walks
    /// `search_after` forward. Returns every hit object as-is (including
    /// `_source`/`sort`) across up to `max_pages` pages of `page_size` each.
    /// Ported from attacker-identity-worker's own es.go
    /// (openPointInTime/closePointInTime/docScrollAll).
    ///
    /// Holds every hit in memory at once. A caller that can fold hits as
    /// they arrive should use [`Es::search_paginated_pages`] instead (#3675).
    pub async fn search_paginated(
        &self,
        index_pattern: &str,
        body_fn: impl FnMut(Option<&Value>) -> Value,
        page_size: u64,
        max_pages: u32,
    ) -> anyhow::Result<Vec<Value>> {
        let mut out = Vec::new();
        self.search_paginated_pages(index_pattern, body_fn, page_size, max_pages, |hits| {
            out.extend(hits);
            Ok(())
        })
        .await?;
        Ok(out)
    }

    /// The same PIT + search_after walk as [`Es::search_paginated`], but
    /// hands each page to `on_page` as soon as it arrives and keeps nothing
    /// itself, so peak memory is one page rather than the whole result.
    ///
    /// #3675: attacker-identity collected a full 6h window of raw hits (up
    /// to 50 pages of 10,000 `serde_json::Value`s) before reducing them to a
    /// few thousand per-IP observations. When one source pushed ~120k events
    /// an hour into `honeypot-v2-*`, the window passed 450k hits and the
    /// worker container was OOM-killed at its 1.5 GiB limit every couple of
    /// minutes. An `Err` from `on_page` stops the walk and is returned, after
    /// the PIT is closed. Returns the number of hits delivered.
    pub async fn search_paginated_pages(
        &self,
        index_pattern: &str,
        mut body_fn: impl FnMut(Option<&Value>) -> Value,
        page_size: u64,
        max_pages: u32,
        mut on_page: impl FnMut(Vec<Value>) -> anyhow::Result<()>,
    ) -> anyhow::Result<u64> {
        // A PIT open on an index that doesn't exist yet returns 404 — the
        // expected state before a caller's very first successful write
        // (every dashboard-owned index here is created lazily on first
        // index_doc). Ported from attacker-identity-worker's own
        // docScrollAll: treating that as "zero existing documents" rather
        // than an error is what lets a caller like attacker_identity.rs's
        // load_existing_entities bootstrap past its first cycle instead of
        // looping forever on a load failure.
        let exists = self.client.indices().exists(elasticsearch::indices::IndicesExistsParts::Index(&[index_pattern])).send().await?;
        if exists.status_code().as_u16() == 404 {
            return Ok(0);
        }

        let open = self
            .client
            .open_point_in_time(elasticsearch::OpenPointInTimeParts::Index(&[index_pattern]))
            .keep_alive("2m")
            .send()
            .await?;
        let open_json = open.json::<Value>().await?;
        let pit_id = open_json["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("open_point_in_time: no id in response: {open_json}"))?
            .to_string();

        let mut delivered: u64 = 0;
        let mut search_after: Option<Value> = None;
        let result: anyhow::Result<()> = async {
            for _ in 0..max_pages {
                let mut body = body_fn(search_after.as_ref());
                body["size"] = Value::from(page_size);
                body["pit"] = serde_json::json!({"id": pit_id, "keep_alive": "2m"});
                let response = self.client.search(SearchParts::None).body(body).send().await?;
                let status = response.status_code();
                let mut json = response.json::<Value>().await?;
                if !status.is_success() {
                    anyhow::bail!("elasticsearch pit search {status}: {json}");
                }
                // Moved out, not cloned: a cloned page was a second copy of
                // up to page_size hits alive next to the response it came from.
                let hits = match json["hits"]["hits"].take() {
                    Value::Array(hits) => hits,
                    _ => Vec::new(),
                };
                drop(json);
                if hits.is_empty() {
                    break;
                }
                let got = hits.len() as u64;
                let last_sort = hits.last().and_then(|h| h.get("sort")).cloned();
                delivered += got;
                on_page(hits)?;
                if got < page_size {
                    break;
                }
                search_after = last_sort;
            }
            Ok(())
        }
        .await;

        // Best-effort close regardless of the loop's outcome above — a PIT
        // left open only holds a small amount of cluster state until its
        // own keep_alive lapses, not worth masking the real error above.
        let _ = self
            .client
            .close_point_in_time()
            .body(serde_json::json!({"id": pit_id}))
            .send()
            .await;
        result?;
        Ok(delivered)
    }
}

/// True when a `_search` response reports failed shards. ES answers 200 with
/// partial results when a shard errors (e.g. a terms agg on a field mapped
/// `text` in one index, #3570), so a 2xx alone does not mean the aggregations
/// are complete. Logs a warning naming `context` and the first failure reason.
pub fn warn_on_failed_shards(context: &str, response: &Value) -> bool {
    let failed = response["_shards"]["failed"].as_u64().unwrap_or(0);
    if failed == 0 {
        return false;
    }
    let reason = response["_shards"]["failures"][0]["reason"]["reason"].as_str().unwrap_or("unknown");
    tracing::warn!(
        context,
        failed,
        total = response["_shards"]["total"].as_u64().unwrap_or(0),
        reason,
        "elasticsearch search returned partial results; aggregations are incomplete"
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Loopback stand-in for the four Elasticsearch calls a PIT walk makes
    /// (index exists, open PIT, search, close PIT). Search answers come from
    /// `pages` in order; every request line + body is recorded. Handles
    /// several requests per connection because the client keeps them alive.
    async fn pit_stub(pages: Vec<Value>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let url = format!("http://{}", listener.local_addr().expect("stub addr"));
        let log = Arc::new(Mutex::new(Vec::new()));
        let pages = Arc::new(Mutex::new(std::collections::VecDeque::from(pages)));
        let (seen, queue) = (log.clone(), pages.clone());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (seen, queue) = (seen.clone(), queue.clone());
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                            continue;
                        };
                        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                        let body_len: usize = head
                            .to_lowercase()
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() < header_end + 4 + body_len {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                            continue;
                        }
                        let request_line = head.lines().next().unwrap_or("").to_string();
                        let body = String::from_utf8_lossy(&buf[header_end + 4..header_end + 4 + body_len]).to_string();
                        buf.drain(..header_end + 4 + body_len);
                        seen.lock().unwrap().push(format!("{request_line} {body}"));
                        let answer = if request_line.contains("/_pit") && request_line.starts_with("POST") {
                            serde_json::json!({"id": "pit-1"})
                        } else if request_line.contains("/_search") {
                            queue.lock().unwrap().pop_front().unwrap_or(serde_json::json!({"hits": {"hits": []}}))
                        } else {
                            serde_json::json!({})
                        };
                        let text = answer.to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-elastic-product: Elasticsearch\r\ncontent-length: {}\r\n\r\n{}",
                            text.len(),
                            text
                        );
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (url, log)
    }

    fn page(ids: &[u64]) -> Value {
        let hits: Vec<Value> =
            ids.iter().map(|id| serde_json::json!({"_id": id.to_string(), "sort": [id]})).collect();
        serde_json::json!({"hits": {"hits": hits}})
    }

    /// #3675: pages reach the callback one at a time, in order, and
    /// search_after advances from each page's last sort value.
    #[tokio::test]
    async fn search_paginated_pages_hands_over_each_page_as_it_arrives() {
        let (url, log) = pit_stub(vec![page(&[1, 2]), page(&[3, 4]), page(&[5])]).await;
        let es = Es::connect(&url).expect("client");
        let mut sizes = Vec::new();
        let mut ids = Vec::new();
        let delivered = es
            .search_paginated_pages(
                "idx",
                |after| {
                    let mut body = serde_json::json!({"query": {"match_all": {}}});
                    if let Some(after) = after {
                        body["search_after"] = after.clone();
                    }
                    body
                },
                2,
                10,
                |hits| {
                    sizes.push(hits.len());
                    ids.extend(hits.iter().map(|h| h["_id"].as_str().unwrap_or("").to_string()));
                    Ok(())
                },
            )
            .await
            .expect("walk");
        assert_eq!(delivered, 5);
        assert_eq!(sizes, vec![2, 2, 1]);
        assert_eq!(ids, vec!["1", "2", "3", "4", "5"]);
        let log = log.lock().unwrap().clone();
        let searches: Vec<&String> = log.iter().filter(|l| l.contains("/_search")).collect();
        assert_eq!(searches.len(), 3, "a short page ends the walk: {log:?}");
        assert!(searches[1].contains("\"search_after\":[2]"), "second page continues after the first: {log:?}");
        assert!(log.iter().any(|l| l.starts_with("DELETE") && l.contains("/_pit")), "PIT closed: {log:?}");
    }

    /// An error from the page callback stops the walk, still closes the
    /// PIT, and the wrapper that collects everything sees the same hits.
    #[tokio::test]
    async fn search_paginated_pages_stops_on_callback_error_and_wrapper_collects_all() {
        let (url, log) = pit_stub(vec![page(&[1, 2]), page(&[3, 4])]).await;
        let es = Es::connect(&url).expect("client");
        let mut calls = 0;
        let err = es
            .search_paginated_pages("idx", |_| serde_json::json!({}), 2, 10, |_| {
                calls += 1;
                anyhow::bail!("stop here")
            })
            .await
            .expect_err("callback error propagates");
        assert_eq!(calls, 1);
        assert!(err.to_string().contains("stop here"));
        let log = log.lock().unwrap().clone();
        assert_eq!(log.iter().filter(|l| l.contains("/_search")).count(), 1);
        assert!(log.iter().any(|l| l.starts_with("DELETE") && l.contains("/_pit")), "PIT closed: {log:?}");

        let (url, _) = pit_stub(vec![page(&[1, 2]), page(&[3, 4]), page(&[])]).await;
        let es = Es::connect(&url).expect("client");
        let all = es.search_paginated("idx", |_| serde_json::json!({}), 2, 10).await.expect("walk");
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn failed_shards_are_detected_and_clean_responses_are_not() {
        let partial = serde_json::json!({"_shards": {"total": 5, "successful": 4, "failed": 1,
            "failures": [{"reason": {"reason": "Text fields are not optimised"}}]}});
        assert!(warn_on_failed_shards("test", &partial));
        assert!(!warn_on_failed_shards("test", &serde_json::json!({"_shards": {"total": 5, "successful": 5, "failed": 0}})));
        // Empty placeholder (skipped search) has no _shards at all.
        assert!(!warn_on_failed_shards("test", &serde_json::json!({})));
    }

    #[test]
    fn logins_filter_has_four_should_clauses_any_one_matches() {
        let f = logins_filter();
        let should = f["bool"]["should"].as_array().expect("should array");
        assert_eq!(should.len(), 4);
        assert_eq!(f["bool"]["minimum_should_match"], 1);
        assert_eq!(should[0]["terms"]["honeypot.event"], serde_json::json!(["login", "auth_attempt"]));
        assert_eq!(should[1]["terms"]["honeypot.eventid"], serde_json::json!(["cowrie.login.success", "cowrie.login.failed"]));
        assert_eq!(should[2]["bool"]["filter"][0]["term"]["event.sensor"], "rdp-honeypot");
        assert_eq!(should[2]["bool"]["filter"][1]["exists"]["field"], "honeypot.username");
        assert_eq!(should[3]["exists"]["field"], "honeypot.canonical_user");
    }

    // -- #2899: delete_by_query_except must not scale bool clause count
    // with keep.len() --

    /// The clause ceiling this test holds the construction to. 4096 is what
    /// `indices.query.bool.max_clause_count` reports as its default on the
    /// deployed cluster, untuned -- not 1024, which is what an earlier draft
    /// of this fix asserted. It is a *reference point*, not the enforced
    /// limit: the enforced value is derived from node heap and was measured
    /// at 3449 (1 GiB heap) and 13797 (4 GiB heap) on Elasticsearch 9.5.1,
    /// so no single number is the wall. See `Es::except_query` for the
    /// measurements. What matters is the contract below -- clause count
    /// independent of `keep.len()` -- which holds at any of them.
    const REPORTED_MAX_CLAUSE_COUNT: usize = 4096;

    /// The largest keep list any *bounded* caller can produce today:
    /// correlations.rs's `FLOW_BUCKET_CAP`. correlator.rs's campaign sweep
    /// has no cap at all.
    const LARGEST_BOUNDED_CALLER_KEEP: usize = 2_000;

    fn bool_clause_count(body: &Value) -> usize {
        body["query"]["bool"]["must_not"].as_array().map(|clauses| clauses.len()).unwrap_or(0)
    }

    /// The actual contract, and the one assertion that fails against the
    /// pre-fix construction at every size: the clause count is O(1) in
    /// `keep.len()`. Stated against the largest bounded caller's keep list
    /// (correlations.rs's flow sweep, 2,000 ids) so a regression shows up
    /// at a size a real caller reaches, not only past the cluster ceiling.
    #[test]
    fn clause_count_does_not_scale_with_keep_len() {
        let keep: Vec<String> = (0..LARGEST_BOUNDED_CALLER_KEEP).map(|i| format!("id-{i}")).collect();
        let body = Es::except_query(&keep);
        assert_eq!(
            bool_clause_count(&body),
            1,
            "built {} bool clauses for {} kept ids — the query must stay one `ids` clause regardless of keep.len()",
            bool_clause_count(&body),
            keep.len()
        );
    }

    /// The regression case the correlator's real callers can actually
    /// produce (#2047/#2238): the campaign path's `ip_prefix` aggregation
    /// carries no `size` key, so its keep list is unbounded. At 8,192 ids a
    /// must_not-per-id query builds 8,192 bool clauses — past every enforced
    /// limit measured on 9.5.1 (3449 at 1 GiB heap, 13797 at 4 GiB is the
    /// only one it stays under) — and this assertion fails against that
    /// construction, which is what this test exists to catch.
    #[test]
    fn stays_under_the_clause_ceiling_past_the_wall() {
        let keep: Vec<String> = (0..(REPORTED_MAX_CLAUSE_COUNT * 2)).map(|i| format!("id-{i}")).collect();
        let body = Es::except_query(&keep);
        assert!(
            bool_clause_count(&body) <= REPORTED_MAX_CLAUSE_COUNT,
            "built {} bool clauses for {} kept ids — must_not-per-id would run past the cluster's clause ceiling",
            bool_clause_count(&body),
            keep.len()
        );
    }

    #[test]
    fn keep_list_survives_intact_in_the_single_ids_clause() {
        let keep = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let body = Es::except_query(&keep);
        assert_eq!(bool_clause_count(&body), 1, "expected exactly one must_not clause regardless of keep.len()");
        assert_eq!(body["query"]["bool"]["must_not"][0]["ids"]["values"], serde_json::json!(["a", "b", "c"]));
    }

    #[test]
    fn empty_keep_list_still_produces_a_valid_query() {
        let body = Es::except_query(&[]);
        assert_eq!(body["query"]["bool"]["must_not"][0]["ids"]["values"], serde_json::json!([]));
    }
}
