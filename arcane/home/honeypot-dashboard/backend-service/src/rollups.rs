//! Precomputed dashboard rollups (#2046): three derived indices, written by
//! the `dashboard-rollups` worker loop, so the always-on panels read a few
//! dozen tiny documents instead of re-aggregating the full event families on
//! every visitor's request.
//!
//!   overview-rollup-v1  one doc per hour bucket × slice: the `_all` fleet
//!                       slice (events/logins for the KPI strip; a #1677-
//!                       excluded `clean` flavor + per-sensor counts for the
//!                       heatmap) and the two netflow legs (zeek conn,
//!                       suricata netflow bytes/packets) the traffic charts
//!                       read. Hourly sparkline, heatmap rows and both
//!                       netflow charts become pure document reads.
//!   geo-rollup-v1       one doc per city {city,country,lat,lon,ips,events},
//!                       refreshed wholesale each cycle — what map_points
//!                       used to compute as a multi_terms+geo_centroid+
//!                       cardinality aggregation per render (≤500 docs).
//!   attack-rollup-v1    one doc per hour × technique plus per hour ×
//!                       tactic-transition/tactic-touch, so the ATT&CK
//!                       coverage grid and kill-chain sankey stop re-running
//!                       their terms/session-group aggregations per load.
//!   page-rollup-v1      one doc per slow page (#3756: sources, ja4l
//!                       fingerprints), the handler's own aggregation
//!                       answer refreshed each cycle (`page_rollup.rs`).
//!
//! House rules this follows (the correlator/identity loops set them):
//! deterministic ids, recompute-on-interval, rollups are disposable —
//! deletable and rebuildable from events within their window. Consumers
//! keep their live computation as an explicit fallback for the not-yet-
//! covered case (fresh deploy before the worker's first passes land), and
//! pick the rollup whenever coverage of the requested window is complete
//! enough — see `covered()`. Nothing else about endpoint payloads changes;
//! the frontend is untouched.
//!
//! Semantic notes each reader documents locally:
//!   * KPI 24h splits align to the hour now (they were second-exact rolling
//!     cutoffs); hourly alignment is inherent to any precomputed hourly
//!     shape and drifts at most one partial hour.
//!   * fleet `unique_ips` stays computed live in kpis: summing per-hour
//!     cardinalities over-counts, and true cross-hour uniqueness needs HLL++
//!     sketch merging which plain long-valued docs can't carry.

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use crate::AppState;

pub const OVERVIEW_INDEX: &str = "overview-rollup-v1";
pub const GEO_INDEX: &str = "geo-rollup-v1";
pub const ATTACK_INDEX: &str = "attack-rollup-v1";

/// The netflow leg families, matching charts.rs::traffic_sum's index
/// choices verbatim (zeek conn first, suricata netflow as the fallback leg).
const ZEEK_INDICES: &[&str] = &["zeek-v1-conn-*"];
const SURICATA_NETFLOW_INDICES: &[&str] = &["suricata-v2-netflow-*"];
pub(crate) const FAMILY_ALL: &str = "_all";
pub(crate) const FAMILY_ZEEK: &str = "zeek";
pub(crate) const FAMILY_SURICATA: &str = "suricata-netflow";

/// Retention horizon: 8 days covers every consumer window (traffic reads a
/// week) plus slack for the backfill sweep.
const RETENTION_HOURS: i64 = 24 * 8;

/// How many missing buckets a single cycle backfills beyond the current and
/// previous hour it always recomputes. Bounds each tick's cost; a fresh
/// deployment converges to full 8-day coverage within roughly a tick budget
/// of 169 hours ÷ 24 ≈ 8 cycles (≈40 min at the default interval).
const BACKFILL_PER_CYCLE: usize = 24;

const SENSOR_LIST_CAP: usize = 60;
const GROUP_CAP: u64 = 1000;
/// Kill-chain hourly queries cap technique/terms sizes exactly where the
/// live endpoints do (kill_chain.rs).
const TECH_TERMS_CAP: usize = 40;
const GROUP_TECH_CAP: usize = 12;

// -----------------------------------------------------------------------
// ids / labels — all deterministic, all tested
// -----------------------------------------------------------------------

pub(crate) fn hour_floor(ts: DateTime<Utc>) -> DateTime<Utc> {
    let secs = ts.timestamp();
    DateTime::from_timestamp(secs - secs.rem_euclid(3600), 0).unwrap_or(ts)
}

/// Bucket key as stored (`bucket`) and embedded in ids — fixed-width ISO so
/// lexicographic order == chronological order.
fn bucket_key(h: DateTime<Utc>) -> String {
    h.format("%Y-%m-%dT%H:00Z").to_string()
}

/// The heatmap cell label the live date_histogram produced via ES
/// `key_as_string`; the frontend renders it verbatim in cell titles, so the
/// rolled path emits the exact same format instead of making the UI absorb
/// a cosmetic change (#2046 carries no frontend diff).
pub(crate) fn bucket_label(h: DateTime<Utc>) -> String {
    h.format("%Y-%m-%dT%H:00:00.000Z").to_string()
}

fn label_to_hour(label: &str) -> Option<DateTime<Utc>> {
    // The label IS an RFC3339 timestamp (bucket_label keeps the exact shape
    // ES key_as_string used), so lean on the real RFC3339 grammar rather
    // than a custom format string — chrono rejects literal digit runs
    // (":00:00.000") right after a numeric specifier while parsing.
    chrono::DateTime::parse_from_rfc3339(label)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn overview_doc_id(family: &str, key: &str) -> String {
    format!("orv1-{family}-{key}")
}

fn attack_tech_id(technique: &str, key: &str) -> String {
    format!("arv1-t-{technique}-{key}")
}

fn attack_link_id(source: &str, target: &str, key: &str) -> String {
    format!("arv1-l-{source}>{target}-{key}")
}

fn attack_touch_id(tactic: &str, key: &str) -> String {
    format!("arv1-x-{tactic}-{key}")
}

fn geo_doc_id(country: &str, city: &str) -> String {
    // Same encoder the map pin URLs use, plus one extra rule: urlencode
    // deliberately leaves `_` alone (it's legal in URLs), so "city__extra"
    // and "X__city"/"extra" would otherwise collide across the "__"
    // separator. Escaping underscores last ("%5F" decodes back to "_",
    // and urlencode already encoded any real "%" as "%25") keeps pair ids
    // injective even for attacker-shaped strings.
    let part = |value: &str| {
        crate::services_control::urlencode(value).replace('_', "%5F")
    };
    format!("geo1-{}__{}", part(country), part(city))
}

// -----------------------------------------------------------------------
// aggregation-shaped helpers shared by readers/writers
// -----------------------------------------------------------------------

type KvList = Vec<(String, u64)>;

fn kv_list_from_buckets(value: &Value) -> KvList {
    value["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            (
                bucket["key"].as_str().unwrap_or("").to_string(),
                bucket["doc_count"].as_u64().unwrap_or(0),
            )
        })
        .filter(|(key, _)| !key.is_empty())
        .collect()
}

/// Coverage gate for switching a consumer onto its rollup: at least 90% of
/// the requested hour buckets present AND at least one document at all.
/// The second clause makes an empty-but-created index fall through to the
/// live path (it reads as "not caught up", never as "no attacks happened").
pub(crate) fn covered(docs_found: usize, hours_requested: usize) -> bool {
    docs_found > 0 && docs_found * 10 >= hours_requested * 9
}

/// One group's deduped tactic sequence → its sankey contribution: the
/// consecutive tactic-pair flows plus the touched-tactic set (kill_chain.rs
/// buildKillChainSankey semantics: each group flows one unit between
/// consecutive distinct tactics in attack-chain order).
fn tactic_pairs(tactics: &[&str]) -> (Vec<(&'static str, &'static str)>, HashSet<&'static str>) {
    use crate::kill_chain::{tactic_for, tactic_index};
    let mut ordered: Vec<&'static str> =
        tactics.iter().filter_map(|t| tactic_for(t)).collect::<Vec<_>>();
    ordered.sort_by_key(|tactic| tactic_index(tactic));
    ordered.dedup();
    let mut touched = HashSet::new();
    for tactic in &ordered {
        touched.insert(*tactic);
    }
    let pairs = ordered.windows(2).map(|pair| (pair[0], pair[1])).collect();
    (pairs, touched)
}

// -----------------------------------------------------------------------
// readers — the primitives the four endpoints consume
// -----------------------------------------------------------------------

async fn docs_since(
    state: &AppState,
    index: &str,
    since_label: &str,
    extra_clause: Option<Value>,
    size: usize,
) -> anyhow::Result<Vec<Value>> {
    let mut filter = vec![json!({"range": {"bucket": {"gte": since_label}}})];
    if let Some(clause) = extra_clause {
        filter.push(clause);
    }
    let result = state
        .es
        .search_index(
            &[index],
            json!({
                "size": size,
                "sort": [{"bucket": {"order": "asc", "unmapped_type": "keyword"}}],
                "query": {"bool": {"filter": filter}}
            }),
        )
        .await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| hit["_source"].clone())
        .collect())
}

/// One hour doc per requested family, oldest-first, over the window.
async fn overview_hours(
    state: &AppState,
    families: &[&str],
    hours: usize,
) -> anyhow::Result<Vec<(DateTime<Utc>, Value)>> {
    let since = bucket_label(hour_floor(Utc::now()) - Duration::hours(hours as i64 - 1));
    let clause = json!({"terms": {"family": families}});
    let docs =
        docs_since(state, OVERVIEW_INDEX, &since, Some(clause), hours * families.len() + 4)
            .await?;
    Ok(docs
        .into_iter()
        .filter_map(|doc| {
            let hour = label_to_hour(doc["bucket"].as_str()?)?;
            Some((hour, doc))
        })
        .collect())
}

/// The KPI/heatmap slice (`_all` fleet doc per hour), oldest-first.
pub async fn fleet_hours(
    state: &AppState,
    hours: usize,
) -> anyhow::Result<Vec<(DateTime<Utc>, Value)>> {
    overview_hours(state, &[FAMILY_ALL], hours).await
}

/// Presence signal shared by the kill-chain consumers: the `_all` fleet
/// docs are written unconditionally every cycle, so they are the honest
/// coverage probe for sibling indices whose writers legitimately emit
/// nothing on a quiet hour (#2046).
pub async fn window_covered(state: &AppState, hours: usize) -> bool {
    matches!(fleet_hours(state, hours).await, Ok(docs) if covered(docs.len(), hours))
}

/// Both netflow legs keyed by family name, oldest-first within each leg —
/// exactly what charts.rs::traffic_sum consumes per chart.
pub async fn netflow_hours(
    state: &AppState,
    hours: usize,
) -> anyhow::Result<Vec<(String, DateTime<Utc>, Value)>> {
    let mut out = Vec::new();
    for family in [FAMILY_ZEEK, FAMILY_SURICATA] {
        for (hour, doc) in overview_hours(state, &[family], hours).await? {
            out.push((family.to_string(), hour, doc));
        }
    }
    Ok(out)
}

pub async fn geo_cities(state: &AppState) -> anyhow::Result<Vec<Value>> {
    let result = state
        .es
        .search_index(
            &[GEO_INDEX],
            json!({
                "size": 500,
                "sort": [{"events": {"order": "desc"}}],
                "query": {"match_all": {}}
            }),
        )
        .await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| hit["_source"].clone())
        .collect())
}

pub async fn attack_hours(state: &AppState, hours: usize) -> anyhow::Result<Vec<Value>> {
    let since = bucket_key(hour_floor(Utc::now()) - Duration::hours(hours as i64 - 1));
    docs_since(state, ATTACK_INDEX, &since, None, TECH_TERMS_CAP + 500 * 3).await
}

// -----------------------------------------------------------------------
// writer loop
// -----------------------------------------------------------------------

fn env_duration_seconds(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse().ok())
        .unwrap_or(default)
}

/// #1677's non-attacker exclusions at write time, exactly as the dashboard
/// applies them at read time today: self-generated probes plus the fleet's
/// own addresses.
fn clean_exclusions() -> Vec<Value> {
    json!([
        {"term": {"honeypot.internal_probe": true}},
        {"terms": {"source.ip": crate::dashboard::self_addresses()}}
    ])
    .as_array()
    .cloned()
    .unwrap_or_default()
}

/// One search over `EVENT_INDICES` producing everything the `_all` slice
/// needs for one bucket: the plain events count (KPI parity) plus the
/// logins count, and the #1677-excluded events count + per-sensor counts
/// (heatmap parity).
async fn compute_fleet_slice(
    state: &AppState,
    range_gte: &str,
    range_lt: &str,
) -> anyhow::Result<Value> {
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"range": {"@timestamp": {"gte": range_gte, "lt": range_lt}}},
        "aggs": {
            "logins": {"filter": crate::es::logins_filter()},
            "clean": {
                "filter": {"bool": {"must_not": clean_exclusions()}},
                "aggs": {"sensors": {"terms": {"field": "event.sensor", "size": SENSOR_LIST_CAP}}}
            }
        }
    });
    let result = state.es.search(body).await?;
    Ok(json!({
        "events": result["hits"]["total"]["value"].as_u64().unwrap_or(0),
        "logins": result["aggregations"]["logins"]["doc_count"].as_u64().unwrap_or(0),
        "clean_events": result["aggregations"]["clean"]["doc_count"].as_u64().unwrap_or(0),
        "sensors": kv_list_to_json(kv_list_from_buckets(&result["aggregations"]["clean"]["sensors"])),
    }))
}

fn kv_list_to_json(list: KvList) -> Value {
    Value::Array(
        list.into_iter()
            .map(|(key, count)| json!({"key": key, "count": count}))
            .collect(),
    )
}

/// One netflow leg for one bucket, in a single query: hit count plus the
/// summed bytes and packets both charts read. Field lists stay exactly what
/// charts.rs passes traffic_sum today; Zeek splits volume by direction, so
/// its totals are the sum over originator+responder halves.
/// Exclusions mirror charts.rs::attacker_window verbatim (#1677: the fleet
/// can never be an attacker in its own data).
async fn compute_netflow_slice(
    state: &AppState,
    indices: &[&str],
    bytes_fields: &[&str],
    packets_fields: &[&str],
    range_gte: &str,
    range_lt: &str,
) -> anyhow::Result<(u64, f64, f64)> {
    let mut aggs: serde_json::Map<String, Value> = serde_json::Map::new();
    for (i, field) in bytes_fields.iter().chain(packets_fields.iter()).enumerate() {
        aggs.insert(format!("part{i}"), json!({"sum": {"field": field}}));
    }
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": range_gte, "lt": range_lt}}}],
            "must_not": [{"terms": {"source.ip": crate::dashboard::self_addresses()}}]
        }},
        "aggs": aggs
    });
    let result = state.es.search_index(indices, body).await?;
    let part = |name: String| result["aggregations"][name]["value"].as_f64().unwrap_or(0.0);
    // Agg names were assigned by one global counter across both field
    // lists; resume that numbering when reading them back.
    let sum = |start: usize, fields: &[&str]| -> f64 {
        (0..fields.len())
            .map(|i| part(format!("part{}", start + i)))
            .sum()
    };
    Ok((
        result["hits"]["total"]["value"].as_u64().unwrap_or(0),
        sum(0, bytes_fields),
        sum(bytes_fields.len(), packets_fields),
    ))
}

fn overview_doc(family: &str, hour: DateTime<Utc>, stats: Value) -> (String, String, Value) {
    (
        OVERVIEW_INDEX.to_string(),
        overview_doc_id(family, &bucket_key(hour)),
        json!({
            "bucket": bucket_key(hour),
            "label": bucket_label(hour),
            "family": family,
            // Finished hours are immutable in the normal cycle; only the
            // absent-doc backfill path ever rewrites one.
            "complete": hour + Duration::hours(1) <= Utc::now(),
            "updated": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        })
        .with_fields(stats),
    )
}

trait WithFields {
    /// Fold `stats`' object entries into this document shell.
    fn with_fields(self, stats: Value) -> Value;
}

impl WithFields for Value {
    fn with_fields(mut self, stats: Value) -> Value {
        if let (Some(obj), Some(stats)) = (self.as_object_mut(), stats.as_object()) {
            for (key, value) in stats {
                obj.insert(key.clone(), value.clone());
            }
        }
        self
    }
}

async fn write_overview_bucket(state: &AppState, hour: DateTime<Utc>) -> anyhow::Result<()> {
    let key = bucket_key(hour);
    let gte = hour.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let lt = (hour + Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let fleet = compute_fleet_slice(state, &gte, &lt).await?;
    let zeek = compute_netflow_slice(
        state,
        ZEEK_INDICES,
        &["source.bytes", "destination.bytes"],
        &["source.packets", "destination.packets"],
        &gte,
        &lt,
    )
    .await?;
    let suricata = compute_netflow_slice(
        state,
        SURICATA_NETFLOW_INDICES,
        &["suricata.eve.netflow.bytes"],
        &["suricata.eve.netflow.pkts"],
        &gte,
        &lt,
    )
    .await?;

    let operations = [
        overview_doc(FAMILY_ALL, hour, fleet),
        overview_doc(
            FAMILY_ZEEK,
            hour,
            json!({"events": zeek.0, "bytes": zeek.1, "packets": zeek.2}),
        ),
        overview_doc(
            FAMILY_SURICATA,
            hour,
            json!({"events": suricata.0, "bytes": suricata.1, "packets": suricata.2}),
        ),
    ];
    let failed = state
        .es
        .bulk_index(
            operations
                .iter()
                .map(|(index, id, doc)| (index.as_str(), id.as_str(), doc))
                .collect(),
        )
        .await?;
    if !failed.is_empty() {
        anyhow::bail!("overview rollup bucket {key}: {} ops failed", failed.len());
    }
    Ok(())
}

/// One bucket's kill-chain counters: hourly per-technique counts (coverage
/// grid material) plus per-group tactic transitions/touches (sankey
/// material), replicating kill_chain.rs's session-then-ip grouping units —
/// including its deliberate quirk that both groupings contribute flows.
async fn write_attack_bucket(state: &AppState, hour: DateTime<Utc>) -> anyhow::Result<()> {
    let key = bucket_key(hour);
    let gte = hour.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let lt = (hour + Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let tech_body = json!({
        "size": 0,
        // #2145: this is the hourly materialization of the kill-chain view;
        // the same probe exclusion kill_chain.rs applies at read time has
        // to hold at write time or every bucket bakes the probes in.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": gte, "lt": lt}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {"techs":
            {"terms": {"field": "honeypot.canonical_attck_techniques", "size": TECH_TERMS_CAP}}}
    });
    let techs = kv_list_from_buckets(&state.es.search(tech_body).await?["aggregations"]["techs"]);

    let group_body = json!({
        "size": 0,
        // #2145: this is the hourly materialization of the kill-chain view;
        // the same probe exclusion kill_chain.rs applies at read time has
        // to hold at write time or every bucket bakes the probes in.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": gte, "lt": lt}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "sessions": {
                "terms": {"field": "honeypot.session", "size": GROUP_CAP},
                "aggs": {"techs":
                    {"terms": {"field": "honeypot.canonical_attck_techniques", "size": GROUP_TECH_CAP}}}
            },
            "ips": {
                "terms": {"field": "source.ip", "size": GROUP_CAP},
                "aggs": {"techs":
                    {"terms": {"field": "honeypot.canonical_attck_techniques", "size": GROUP_TECH_CAP}}}
            }
        }
    });
    let grouped = state.es.search(group_body).await?;
    let mut flows: HashMap<(String, String), u64> = HashMap::new();
    let mut touches: HashMap<String, u64> = HashMap::new();
    for group_agg in ["sessions", "ips"] {
        for bucket in grouped["aggregations"][group_agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let techniques: Vec<String> = bucket["techs"]["buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|tech| tech["key"].as_str().unwrap_or("").to_string())
                .filter(|t| !t.is_empty())
                .collect();
            let borrowed: Vec<&str> = techniques.iter().map(String::as_str).collect();
            let (pairs, touched) = tactic_pairs(&borrowed);
            for (source, target) in pairs {
                *flows.entry((source.to_string(), target.to_string())).or_insert(0) += 1;
            }
            for tactic in touched {
                *touches.entry(tactic.to_string()).or_insert(0) += 1;
            }
        }
    }

    let updated = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut operations: Vec<(String, String, Value)> = techs
        .into_iter()
        .map(|(technique, count)| {
            (
                ATTACK_INDEX.to_string(),
                attack_tech_id(&technique, &key),
                json!({"kind": "tech", "bucket": key, "technique": technique,
                       "count": count, "updated": updated}),
            )
        })
        .collect();
    for ((source, target), count) in flows {
        operations.push((
            ATTACK_INDEX.to_string(),
            attack_link_id(&source, &target, &key),
            json!({"kind": "link", "bucket": key, "source": source, "target": target,
                   "count": count, "updated": updated}),
        ));
    }
    for (tactic, count) in touches {
        operations.push((
            ATTACK_INDEX.to_string(),
            attack_touch_id(&tactic, &key),
            json!({"kind": "touch", "bucket": key, "tactic": tactic,
                   "count": count, "updated": updated}),
        ));
    }
    let failed = state
        .es
        .bulk_index(
            operations
                .iter()
                .map(|(index, id, doc)| (index.as_str(), id.as_str(), doc))
                .collect(),
        )
        .await?;
    if !failed.is_empty() {
        anyhow::bail!("attack rollup bucket {key}: {} ops failed", failed.len());
    }
    Ok(())
}

/// Geo rollup: run the exact aggregation dashboard.rs serves map_points from
/// (multi_terms city/country size 500 + geo_centroid + unique-IP
/// cardinality over 24h, #1677 exclusions included), land every row as one
/// deterministic-id document stamped with this cycle's id, then drop
/// anything whose stamp is older — cities that aged out of the window leave
/// the rollup the same cycle. One bulk upsert of ≤500 tiny docs per cycle
/// replaces one multi-field aggregation per map render.
async fn write_geo_cycle(state: &AppState) -> anyhow::Result<()> {
    let tick = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let body = json!({
        "size": 0,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
            "must_not": clean_exclusions()
        }},
        "aggs": {
            "points": {
                "filter": {"exists": {"field": "source.geo.location"}},
                "aggs": {"by_place": {
                    "multi_terms": {
                        "terms": [
                            {"field": "source.geo.city_name"},
                            {"field": "source.geo.country_iso_code"}
                        ],
                        "size": 500
                    },
                    "aggs": {
                        "centroid": {"geo_centroid": {"field": "source.geo.location"}},
                        "unique_ips": {"cardinality": {"field": "source.ip"}}
                    }
                }}
            }
        }
    });
    let result = state.es.search(body).await?;
    let buckets = result["aggregations"]["points"]["by_place"]["buckets"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut operations: Vec<(String, String, Value)> = Vec::with_capacity(buckets.len());
    for bucket in &buckets {
        let keys = bucket["key"].as_array().cloned().unwrap_or_default();
        let city = keys.first().and_then(Value::as_str).unwrap_or("").to_string();
        let country = keys.get(1).and_then(Value::as_str).unwrap_or("").to_string();
        let (Some(lat), Some(lon)) = (
            bucket["centroid"]["location"]["lat"].as_f64(),
            bucket["centroid"]["location"]["lon"].as_f64(),
        ) else {
            continue; // same guard the live path applies via `.as_f64()?`
        };
        operations.push((
            GEO_INDEX.to_string(),
            geo_doc_id(&country, &city),
            json!({
                "city": city,
                "country": country,
                "lat": lat,
                "lon": lon,
                "events": bucket["doc_count"].as_u64().unwrap_or(0),
                "unique_ips": bucket["unique_ips"]["value"].as_u64().unwrap_or(0),
                "updated": tick
            }),
        ));
    }
    let failed = state
        .es
        .bulk_index(
            operations
                .iter()
                .map(|(index, id, doc)| (index.as_str(), id.as_str(), doc))
                .collect(),
        )
        .await?;
    if !failed.is_empty() {
        anyhow::bail!("geo rollup: {} ops failed", failed.len());
    }
    state.es.delete_by_query(GEO_INDEX, geo_stale_query(&tick)).await?;
    Ok(())
}

/// #2653: `EsClient::delete_by_query` wraps what it is given in `{"query":
/// …}` itself, so these builders must hand it a *bare* query. Both call
/// sites used to pass `{"query": …}` and the double wrap made every
/// request a 400 (`unknown query [query]`) -- silently, since the geo
/// refresh's delete is the second half of a write-then-swap and the prune
/// only warns. Keeping the queries as named functions is what lets the
/// tests below assert the shape the helper actually expects.
fn geo_stale_query(tick: &str) -> Value {
    json!({"range": {"updated": {"lt": tick}}})
}

fn rollup_prune_query(cutoff: &str) -> Value {
    json!({"range": {"bucket": {"lt": cutoff}}})
}

/// Drop buckets older than retention from both hourly indices; geo needs no
/// separate prune (its whole content is replaced every cycle above).
async fn prune_old_buckets(state: &AppState, now: DateTime<Utc>) {
    let cutoff = bucket_key(now - Duration::hours(RETENTION_HOURS));
    for index in [OVERVIEW_INDEX, ATTACK_INDEX] {
        match state
            .es
            .delete_by_query(index, rollup_prune_query(&cutoff))
            .await
        {
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, %index, "rollup prune failed"),
        }
    }
}

/// Which hour buckets still lack a rollup doc: expected = the retention
/// window ending at the current partial hour; existing = one cheap ids
/// query per index. Current + previous hour are always rewritten regardless
/// (late-arriving data), so they're excluded from the backfill listing.
async fn missing_buckets(state: &AppState, now: DateTime<Utc>) -> anyhow::Result<Vec<DateTime<Utc>>> {
    let current = hour_floor(now);
    let earliest = current - Duration::hours(RETENTION_HOURS - 1);
    let mut existing: HashSet<String> = HashSet::new();
    for index in [OVERVIEW_INDEX] {
        let result = state
            .es
            .search_index(
                &[index],
                json!({
                    "size": 0,
                    "track_total_hits": false,
                    "query": {"range": {"bucket": {"gte": bucket_key(earliest)}}},
                    "aggs": {"buckets": {"terms": {"field": "bucket", "size": 1000}}}
                }),
            )
            .await?;
        for bucket in result["aggregations"]["buckets"]["buckets"].as_array().into_iter().flatten() {
            existing.insert(bucket["key"].as_str().unwrap_or("").to_string());
        }
    }
    let mut missing: Vec<DateTime<Utc>> = (0..RETENTION_HOURS)
        .map(|offset| earliest + Duration::hours(offset))
        .filter(|hour| !existing.contains(&bucket_key(*hour)))
        .collect();
    missing.sort_unstable_by(|a, b| b.cmp(a)); // newest first
    Ok(missing)
}

pub async fn run_cycle(state: &AppState) -> anyhow::Result<()> {
    let now = Utc::now();
    let current = hour_floor(now);
    let always: Vec<DateTime<Utc>> = vec![current - Duration::hours(1), current];

    for hour in &always {
        if let Err(error) = write_overview_bucket(state, *hour).await {
            tracing::warn!(%error, bucket = %bucket_key(*hour), "overview rollup write failed");
        }
        if let Err(error) = write_attack_bucket(state, *hour).await {
            tracing::warn!(%error, bucket = %bucket_key(*hour), "attack rollup write failed");
        }
    }

    // Backfill what's absent, newest-first, bounded per cycle. Buckets whose
    // hour + 2h <= now are only visited when genuinely missing from the
    // index — completed-hour docs stay immutable (late events accepted as a
    // documented loss; delete + rebuild restores them because rollups are
    // disposable by design).
    match missing_buckets(state, now).await {
        Ok(missing) => {
            for hour in missing.into_iter().take(BACKFILL_PER_CYCLE) {
                if always.contains(&hour) {
                    continue;
                }
                if let Err(error) = write_overview_bucket(state, hour).await {
                    tracing::warn!(%error, bucket = %bucket_key(hour), "overview backfill failed");
                }
                if let Err(error) = write_attack_bucket(state, hour).await {
                    tracing::warn!(%error, bucket = %bucket_key(hour), "attack backfill failed");
                }
            }
        }
        Err(error) => tracing::warn!(%error, "rollup coverage scan failed"),
    }

    if let Err(error) = write_geo_cycle(state).await {
        tracing::warn!(%error, "geo rollup refresh failed");
    }
    // #3756: whole-page snapshots of the reads too slow to run per request.
    crate::page_rollup::write_cycle(state).await;
    prune_old_buckets(state, now).await;
    Ok(())
}

pub async fn dashboard_rollups_loop(state: AppState) {
    let interval_secs = env_duration_seconds("ROLLUP_RUN_INTERVAL_SECS", 300);
    loop {
        if let Err(error) = run_cycle(&state).await {
            tracing::warn!(%error, "dashboard rollup cycle failed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hour(n: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap() + Duration::hours(n)
    }

    #[test]
    fn prune_queries_are_bare_because_the_helper_adds_the_query_wrapper() {
        // #2653: EsClient::delete_by_query bodies its argument as
        // {"query": arg}. Both call sites used to pass {"query": …}
        // themselves, so every request went out as {"query":{"query":…}}
        // and Elasticsearch 400'd it -- for the whole life of the helper,
        // seen only as a warn line. A bare query here is the contract.
        for q in [geo_stale_query("2026-08-29T20:44:10.672Z"), rollup_prune_query("2026-08-29T20:00Z")] {
            assert!(
                q.get("query").is_none(),
                "query must not be pre-wrapped, delete_by_query wraps it: {q}"
            );
            assert!(q.get("range").is_some(), "expected a bare range query, got {q}");
            // What the helper actually puts on the wire.
            let body = json!({"query": q});
            assert!(body["query"]["query"].is_null(), "double-wrapped body: {body}");
        }
    }

    #[test]
    fn hour_floor_truncates_partial_hours() {
        let partial = hour(0) + Duration::minutes(59) + Duration::seconds(59);
        assert_eq!(hour_floor(partial), hour(0));
        assert_eq!(hour_floor(hour(0)), hour(0));
        assert_eq!(hour_floor(hour(3) + Duration::nanoseconds(1)), hour(3));
    }

    #[test]
    fn bucket_key_is_fixed_width_iso_and_sortable() {
        let early = DateTime::from_timestamp(0, 0).unwrap(); // 1970-01-01T00Z
        assert_eq!(bucket_key(early), "1970-01-01T00:00Z");
        assert_eq!(bucket_label(early), "1970-01-01T00:00:00.000Z");
        assert!(bucket_key(early) < bucket_key(hour(1)));
    }

    #[test]
    fn label_round_trip_recovers_the_hour() {
        assert_eq!(label_to_hour(&bucket_label(hour(7))), Some(hour(7)));
        assert_eq!(label_to_hour("garbage"), None);
    }

    #[test]
    fn ids_are_deterministic_and_family_scoped() {
        let k = bucket_key(hour(2));
        assert_eq!(overview_doc_id(FAMILY_ZEEK, &k), overview_doc_id(FAMILY_ZEEK, &k));
        assert_ne!(
            overview_doc_id(FAMILY_ZEEK, &k),
            overview_doc_id(FAMILY_SURICATA, &k)
        );
        assert_ne!(
            overview_doc_id(FAMILY_ALL, &k),
            overview_doc_id(FAMILY_ZEEK, &k)
        );
        // Cities/countries must not collide when swapped or separator-bearing.
        assert_eq!(geo_doc_id("DE", "Munich"), geo_doc_id("DE", "Munich"));
        assert_ne!(geo_doc_id("DE", "Munich"), geo_doc_id("Munich", "DE"));
        assert_ne!(geo_doc_id("A", "b"), geo_doc_id("a", "B"));
        assert_ne!(
            geo_doc_id("X", "city__extra"),
            geo_doc_id("X__city", "extra")
        );
    }

    #[test]
    fn covered_requires_most_of_the_window_and_any_document_at_all() {
        let days24 = 48;
        assert!(!covered(0, days24));
        assert!(!covered(43, days24)); // 43*10 < 48*9
        assert!(covered(44, days24)); // ≥90%
        assert!(covered(days24, days24));
    }

    #[test]
    fn tactic_pairs_order_and_deduplicate_like_the_live_sankey() {
        let (pairs, touched) = tactic_pairs(&[
            "T1105",
            "T1059",
            "T1595",
            "T1059.001",
            "unmapped-thing",
        ]);
        // Execution variants dedup to Execution; chain runs in tactic order.
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("Reconnaissance", "Execution"));
        assert_eq!(pairs[1], ("Execution", "Command and Control"));
        assert_eq!(touched.len(), 3);
        assert!(touched.contains("Command and Control"));

        // A single-tactic group contributes touch but no flow — the case
        // that keeps nodes alive without any link between tactics.
        let (pairs, touched) = tactic_pairs(&["T1110"]);
        assert!(pairs.is_empty());
        assert!(touched.contains("Credential Access"));
    }
}
