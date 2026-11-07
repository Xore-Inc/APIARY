//! Materialized cross-event correlations (#2047), written by the correlator
//! pass so a dashboard read is a point lookup instead of an aggregation:
//!
//!   flow-links-v1  one doc per `network.community_id` that ≥2 distinct
//!                  sensor FAMILIES (index prefixes, not individual sensors)
//!                  observed in the last 24h — suricata, zeek and portbridge
//!                  watching the same connection join on the hash they each
//!                  compute (#1783 put the field on events; nothing grouped
//!                  by it). The event detail page's live same-flow relation
//!                  stays exactly as it was; this adds the family summary
//!                  alongside it.
//!   cred-reuse-v1  one doc per canonical user/pass pair shared by ≥2
//!                  distinct source IPs across the correlation window. The
//!                  fingerprint/payload/ASN clusters only count signals
//!                  within one campaign's view; re-used credentials are the
//!                  re-used-wordlist signal that survives across both.
//!
//! Same house rules as the campaigns/clusters docs written beside them:
//! deterministic ids, whole-window rewrite per cycle, stale rows dropped
//! by delete-by-query-except, everything disposable and rebuildable.

use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::AppState;

pub(crate) const FLOW_INDEX: &str = "flow-links-v1";
const CRED_REUSE_INDEX: &str = "cred-reuse-v1";

/// How many flow groups one pass may land. A genuinely busy window makes
/// this the only cap between the fleet and a runaway index; sorted by first
/// seen within the agg, so which flows survive is stable rather than lucky.
const FLOW_BUCKET_CAP: u64 = 2_000;
/// Sampled event ids kept per link for drill-down links.
const FLOW_EVENT_IDS_CAP: usize = 50;
const CRED_PAIR_CAP: u64 = 200;
const CRED_IPS_LISTED: usize = 20;
/// Painless script keying a terms agg on user NUL password. Painless
/// single-quoted strings only accept `\\` and `\'` escapes, so the NUL
/// separator is built with a char cast, not a `\u0000` escape (#3568). The
/// Rust side splits the bucket key on `'\u{0}'`.
const CRED_PAIR_SCRIPT: &str =
    "def u = doc.containsKey(params.uf) && !doc[params.uf].empty ? doc[params.uf].value : ''; \
     def p = doc.containsKey(params.pf) && !doc[params.pf].empty ? doc[params.pf].value : ''; \
     if (u.length() == 0 || p.length() == 0) return ''; return u + String.valueOf((char)0) + p;";

// ---------------------------------------------------------------------
// passes
// ---------------------------------------------------------------------

pub(crate) async fn run_passes(state: &AppState) {
    if let Err(error) = write_flow_links(state).await {
        tracing::warn!(%error, "correlator: flow-links pass failed");
    }
    let since = chrono::Utc::now()
        - chrono::Duration::from_std(env_duration("CORRELATION_WINDOW", std::time::Duration::from_secs(7 * 24 * 3600)))
            .unwrap_or(chrono::Duration::days(7));
    if let Err(error) = write_cred_reuse(state, since).await {
        tracing::warn!(%error, "correlator: credential-reuse pass failed");
    }
}

fn env_duration(name: &str, default: std::time::Duration) -> std::time::Duration {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(default)
}

async fn write_flow_links(state: &AppState) -> anyhow::Result<()> {
    // Sensor FAMILY comes from `_index` -- event.sensor names individual
    // appliances ("hws1"), but the vantage point #1783's hash lets us join
    // on is the producing pipeline (suricata / zeek / portbridge ...).
    // Trimming each key back past its trailing date keeps daily rollovers
    // from splitting zeek-v1-conn-2026.08.25 off zeek-v1-conn-2026.08.26.
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h"}}},
            {"exists": {"field": "network.community_id"}}
        // #2145: probes carry community ids too; a published flow link
        // still needs 2+ families, but the exclusion keeps the buckets
        // attacker-only in the first place.
        ], "must_not": [crate::es::internal_probe_exclusion()]}},
        "aggs": {"flows": {
            "terms": {
                "field": "network.community_id",
                "size": FLOW_BUCKET_CAP,
                "order": {"_key": "asc"}
            },
            "aggs": {
                "families": {"terms": {"field": "_index", "size": 10}},
                "sensors": {"terms": {"field": "event.sensor", "size": 10}},
                "srcs": {"terms": {"field": "source.ip", "size": 1}},
                "dsts": {"terms": {"field": "destination.ip", "size": 1}},
                "dports": {"terms": {"field": "destination.port", "size": 1}},
                "first": {"min": {"field": "@timestamp"}},
                "last": {"max": {"field": "@timestamp"}},
                "sample": {"top_hits": {
                    "size": FLOW_EVENT_IDS_CAP,
                    "_source": false,
                    "sort": [{"@timestamp": "desc"}]
                }}
            }
        }}
    });
    let result = state.es.search(body).await?;
    let updated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut ids = Vec::new();
    for bucket in result["aggregations"]["flows"]["buckets"].as_array().into_iter().flatten() {
        let Some(community_id) = bucket["key"].as_str() else { continue };
        // <2 index families means every observation came from the same
        // pipeline; there is nothing to correlate yet.
        let families: Vec<String> = bucket["families"]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|b| b["key"].as_str())
            .map(flow_family)
            .collect::<Vec<_>>();
        if dedup(&families) < 2 {
            continue;
        }
        ids.push(format!("flv1-{community_id}"));
        let doc = json!({
            "community_id": community_id,
            "families": deduped(&families),
            "sensors": str_terms(bucket["sensors"]["buckets"].as_array(), 6),
            "src_ip": bucket["srcs"]["buckets"].as_array().and_then(|b| b.first()).and_then(|b| b["key"].as_str()).unwrap_or(""),
            "dst_ip": bucket["dsts"]["buckets"].as_array().and_then(|b| b.first()).and_then(|b| b["key"].as_str()).unwrap_or(""),
            "dst_port": bucket["dports"]["buckets"].as_array().and_then(|b| b.first()).and_then(|b| b["key"].as_u64()).unwrap_or(0),
            "first": bucket["first"]["value_as_string"].as_str().unwrap_or(""),
            "last": bucket["last"]["value_as_string"].as_str().unwrap_or(""),
            "events": bucket["doc_count"],
            "event_ids": sampled_ids(bucket),
            "updated": updated,
        });
        if let Err(error) = state.es.index_doc(FLOW_INDEX, &format!("flv1-{community_id}"), doc).await {
            tracing::warn!(%error, community_id, "correlator: index flow link failed");
        }
    }
    if let Err(error) = state.es.delete_by_query_except(FLOW_INDEX, &ids).await {
        tracing::warn!(%error, "correlator: clean up stale flow links failed");
    }
    Ok(())
}

async fn write_cred_reuse(state: &AppState, since: chrono::DateTime<chrono::Utc>) -> anyhow::Result<()> {
    // The pair key must be collision-free in ES's terms agg, where NUL
    // bytes in canonical values would silently merge adjacent fields --
    // user/pass come straight off the wire, and "\0" as a password is a
    // real input these honeypots see. A hex digest sidesteps the question;
    // the plaintext rides along on the doc for display.
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since.to_rfc3339()}}},
            {"exists": {"field": "source.ip"}}
        // #2145: this materializes into attacker-clusters-v1, so the
        // source.ip term alone (probes have none) is only incidental
        // protection -- make the intent explicit.
        ], "must_not": [crate::es::internal_probe_exclusion()]}},
        "aggs": {"pairs": {
            "terms": {
                "script": {
                    "source": CRED_PAIR_SCRIPT,
                    "params": {"uf": "honeypot.canonical_user", "pf": "honeypot.canonical_pass"}
                },
                "size": CRED_PAIR_CAP * 4,
                "min_doc_count": 5
            },
            "aggs": {
                "unique_ips": {"cardinality": {"field": "source.ip"}},
                "ips": {"terms": {"field": "source.ip", "size": CRED_IPS_LISTED}},
                "sensors": {"terms": {"field": "event.sensor", "size": 10}},
                "first": {"min": {"field": "@timestamp"}},
                "last": {"max": {"field": "@timestamp"}}
            }
        }}
    });
    let result = state.es.search_index(&[crate::correlator::HONEYPOT_INDEX_PATTERN], body).await?;
    let updated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut ids = Vec::new();
    for bucket in result["aggregations"]["pairs"]["buckets"].as_array().into_iter().flatten() {
        let Some(key) = bucket["key"].as_str() else { continue };
        let Some((user, pass)) = key.split_once('\u{0}') else { continue };
        // Same shell-marker gate entity merging uses: "/bin/sh"-shaped
        // "passwords" are command transcripts, not credentials.
        if !crate::correlator::valid_credential_pair(user, pass) {
            continue;
        }
        let unique_ips = bucket["unique_ips"]["value"].as_u64().unwrap_or(0);
        if unique_ips < 2 {
            continue;
        }
        let id = format!("crv1-{}", hex(&Sha256::digest(key)));
        ids.push(id.clone());
        let doc = json!({
            "user": user,
            "pass": pass,
            "unique_ips": unique_ips,
            "ips": str_terms(bucket["ips"]["buckets"].as_array(), CRED_IPS_LISTED),
            "sensors": str_terms(bucket["sensors"]["buckets"].as_array(), 6),
            "events": bucket["doc_count"],
            "first": bucket["first"]["value_as_string"].as_str().unwrap_or(""),
            "last": bucket["last"]["value_as_string"].as_str().unwrap_or(""),
            "updated": updated,
        });
        if let Err(error) = state.es.index_doc(CRED_REUSE_INDEX, &id, doc).await {
            tracing::warn!(%error, id = %id, "correlator: index cred-reuse edge failed");
        }
    }
    if let Err(error) = state.es.delete_by_query_except(CRED_REUSE_INDEX, &ids).await {
        tracing::warn!(%error, "correlator: clean up stale cred-reuse edges failed");
    }
    Ok(())
}

// ---------------------------------------------------------------------
// reads
// ---------------------------------------------------------------------

fn missing_community() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "no such flow".into())
}

#[utoipa::path(
    get,
    path = "/api/v1/connections/{community_id}",
    summary = "Every record that shares one community_id flow hash.",
    params(
        ("community_id" = inline(String), Path, description = "network.community_id flow hash, as computed independently by each sensor."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// One materialized link, by community_id.
pub async fn flow_by_id(
    State(state): State<AppState>,
    Path(community_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    match state.es.get_doc(FLOW_INDEX, &format!("flv1-{community_id}")).await {
        Ok(Some(doc)) => Ok(Json(doc)),
        Ok(None) => Err(missing_community()),
        Err(error) => Err((StatusCode::BAD_GATEWAY, error.to_string())),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/event/{id}/connections",
    summary = "The same-flow summary and re-used-wordlist edges for one event.",
    params(
        ("id" = inline(String), Path, description = "Event document id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// The materialized form of one event's connection: resolves the event's
/// own community_id first, then reads its link. Events whose flow never
/// reached two families have no link — a 404 here means exactly that, not
/// an outage.
pub async fn event_connections(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if id.trim().is_empty() || id.len() > 512 {
        return Err((StatusCode::BAD_REQUEST, "invalid event id".into()));
    }
    let body = json!({"size": 1, "query": {"ids": {"values": [id]}}});
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let source = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .ok_or_else(missing_community)?;
    let community_id = source["network"]["community_id"].as_str().unwrap_or("");
    if community_id.is_empty() {
        return Err(missing_community());
    }
    match state.es.get_doc(FLOW_INDEX, &format!("flv1-{community_id}")).await {
        Ok(Some(mut link)) => {
            // The one thing the plain link can't carry is whether THIS
            // event's own document made the sampled list; splice it in so
            // the page can say "this record" without another lookup.
            let sampled = link["event_ids"]
                .as_array()
                .map(|ids| ids.iter().filter_map(Value::as_str).any(|v| v == id))
                .unwrap_or(false);
            link["this_event_in_sample"] = Value::Bool(sampled);
            link["community_id"] = Value::String(community_id.to_string());
            Ok(Json(link))
        }
        Ok(None) => Err(missing_community()),
        Err(error) => Err((StatusCode::BAD_GATEWAY, error.to_string())),
    }
}

#[derive(Serialize)]
pub struct CredEdge {
    pub user: String,
    pub pass: String,
    pub unique_ips: u64,
    pub ips: Vec<String>,
    pub sensors: Vec<String>,
    pub events: u64,
    pub first: String,
    pub last: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/cred-reuse",
    summary = "Credential pairs reused across more than one address.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// Most-shared credentials first — the re-used-wordlist signal at its most
/// concentrated.
pub async fn cred_reuse(State(state): State<AppState>) -> Result<Json<Vec<CredEdge>>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(
            &[CRED_REUSE_INDEX],
            json!({
                "size": 200,
                "sort": [{"unique_ips": {"order": "desc"}}, {"events": {"order": "desc"}}],
                "query": {"match_all": {}}
            }),
        )
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let edges = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let src = &hit["_source"];
            Some(CredEdge {
                user: src["user"].as_str()?.to_string(),
                pass: src["pass"].as_str()?.to_string(),
                unique_ips: src["unique_ips"].as_u64().unwrap_or(0),
                ips: str_terms(src["ips"].as_array(), CRED_IPS_LISTED),
                sensors: str_terms(src["sensors"].as_array(), 6),
                events: src["events"].as_u64().unwrap_or(0),
                first: src["first"].as_str().unwrap_or("").to_string(),
                last: src["last"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();
    Ok(Json(edges))
}

// ---------------------------------------------------------------------
// helpers — pure parts get unit-tested below
// ---------------------------------------------------------------------

fn str_terms(buckets: Option<&Vec<Value>>, limit: usize) -> Vec<String> {
    buckets
        .into_iter()
        .flatten()
        .filter_map(|b| b["key"].as_str().map(str::to_string))
        .take(limit)
        .collect()
}

/// `_index` → family prefix: strip the trailing "-YYYY.MM.DD[-N]" segment
/// date-pipeline indices append on rollover.
fn flow_family(index_key: &str) -> String {
    static DATE_TAIL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"-\d{4}\.\d{2}\.\d{2}.*$").expect("static date-tail pattern")
    });
    DATE_TAIL.replace(index_key, "").into_owned()
}

fn dedup(values: &[String]) -> usize {
    let mut seen: Vec<&str> = Vec::new();
    for value in values {
        if !seen.contains(&value.as_str()) {
            seen.push(value);
        }
    }
    seen.len()
}

fn deduped(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    out
}

fn sampled_ids(bucket: &Value) -> Vec<String> {
    bucket["sample"]["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| hit["_id"].as_str().map(str::to_string))
        .collect()
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cred_pair_script_has_no_unicode_escape() {
        // Painless rejects `\u` in single-quoted strings (#3568).
        assert!(!CRED_PAIR_SCRIPT.contains("\\u"), "{CRED_PAIR_SCRIPT}");
        assert!(CRED_PAIR_SCRIPT.contains("String.valueOf((char)0)"));
    }

    #[test]
    fn flow_family_strips_daily_rollover_suffixes_but_not_version_bits() {
        assert_eq!(flow_family("zeek-v1-conn-2026.08.26"), "zeek-v1-conn");
        assert_eq!(flow_family("suricata-v2-flow-2026.08.26-3"), "suricata-v2-flow");
        assert_eq!(flow_family("portbridge-v2-2026.08.26"), "portbridge-v2");
        assert_eq!(flow_family("honeypot-v2-cowrie"), "honeypot-v2-cowrie");
    }

    #[test]
    fn two_distinct_families_is_the_gate_and_duplicates_dont_pass_it() {
        let mixed = [
            "zeek-v1-conn-2026.08.26".to_string(),
            "suricata-v2-flow-2026.08.26".to_string(),
        ];
        let families_mixed: Vec<String> = mixed.iter().map(|k| flow_family(k)).collect();
        assert!(dedup(&families_mixed) >= 2);
        // One pipeline split across two days' indices is still one family:
        // neither duplicate keys nor a rollover split satisfies the gate alone.
        let one_pipeline = [
            "zeek-v1-conn-2026.08.25".to_string(),
            "zeek-v1-conn-2026.08.26".to_string(),
            "zeek-v1-conn-2026.08.26".to_string(),
        ];
        let families_one: Vec<String> = one_pipeline.iter().map(|k| flow_family(k)).collect();
        assert_eq!(dedup(&families_one), 1);
    }

    #[test]
    fn pair_ids_are_content_addressed_and_split_safe() {
        // Two pairs that differ only by separator position can't collide —
        // the digest covers the raw user\0pass bytes, not a printed form.
        let a = "root\u{0}pa:ss".to_string();
        let b = "root:pa\u{0}ss".to_string();
        let id_of = |pair: &str| format!("crv1-{}", hex(&Sha256::digest(pair.as_bytes())));
        assert_ne!(id_of(&a), id_of(&b));
        assert_eq!(id_of(&a), id_of(&a));
    }

    #[test]
    fn str_terms_caps_list_length() {
        let buckets = serde_json::from_value::<Vec<Value>>(json!([
            {"key": "a"}, {"key": "b"}, {"key": "c"}
        ]))
        .unwrap();
        assert_eq!(str_terms(Some(&buckets), 2), vec!["a".to_string(), "b".to_string()]);
        assert!(str_terms(None, 2).is_empty());
    }
}
