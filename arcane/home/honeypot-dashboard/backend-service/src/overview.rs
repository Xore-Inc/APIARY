//! /api/v1/overview/kpis — the overview KPI strip, mirroring the fields the
//! Go dashboard's esOverview aggregation produces (es_aggregate.go): total
//! events in the 48h window, last-24h count with the vs-previous-24h delta,
//! unique source IPs. #1963 adds login attempts: the strip renders on every
//! overview tab, and reading that one integer from /overview/dashboard used
//! to force that endpoint's whole eighteen-slice aggregation on ticks that
//! needed none of it. (Captured payloads stay on the store listing the
//! frontend already reads; their count is a doc count over captured
//! artifacts, not an event aggregation.)
//!
//! #2046: everything except `unique_ips` reads the hourly fleet rollup
//! when its 48 buckets are covered — one ≤49-doc read instead of a full
//! EVENT_INDICES aggregation per visitor tick. Two deliberate divergences
//! from the live path, both inherent to a precomputed hourly shape:
//!   * the 24h splits align to the hour rather than a second-exact rolling
//!     cutoff (drift bounded by the current partial hour);
//!   * unique_ips still needs true cross-hour uniqueness — summing hourly
//!     cardinalities would over-count, and HLL++ sketches aren't carried by
//!     the plain long docs — so that single query stays computed-on-read.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    es::{internal_probe_exclusion, logins_filter},
    events::SESSION_FIELDS,
    rollups::{self},
    AppState,
};

/// Protocols shown individually on the hourly timeline; everything else
/// folds into `other`.
const TIMELINE_TOP_PROTOCOLS: usize = 5;
/// Per-hour terms bucket size. Larger than TIMELINE_TOP_PROTOCOLS so the
/// global top-5 is chosen from a wide candidate list; `other` is computed
/// as hour total minus the top-5 counts, so it never depends on this size.
const TIMELINE_TERMS_SIZE: u64 = 50;

#[derive(Serialize)]
pub struct OverviewKpis {
    pub total: u64,
    pub last24h: u64,
    pub previous24h: u64,
    /// Percent change of last24h vs previous24h, e.g. "+41%"; empty while
    /// the previous window is empty (mirrors the Go hero's guard).
    pub change24h: String,
    pub unique_ips: u64,
    /// Per-hour event counts for the last 24 hours, oldest first — the
    /// "Events in 24 hours" KPI sparkline (overview.html:65-68 /
    /// page_hero.go's hourlySpark, which summed the heatmap's columns;
    /// here the same series comes straight from a date_histogram).
    pub hourly: Vec<u64>,
    /// Login attempts in the 48h window (#1963). Same logins_filter() as
    /// /overview/dashboard's slice was; this is where the KPI strip reads
    /// it now.
    pub logins: u64,
    /// Distinct sessions with activity in the last 24h (rolling). Sum of one
    /// cardinality per session-id field (`events::SESSION_FIELDS`): an upper
    /// bound, since one session seen under two fields is counted twice.
    pub sessions_24h: u64,
    /// Same count over the 24h before that, for the trend.
    pub sessions_previous24h: u64,
    /// The last 24 hours as 24 hourly buckets, oldest first, with an ISO
    /// timestamp and per-protocol counts. Totals match `hourly`.
    pub hourly_by_protocol: Vec<HourlyByProtocol>,
    pub ready: bool,
}

/// One hour of the protocol timeline. `counts` always carries the same keys
/// (the top-5 protocols of the window, then `other`), zero-filled, so a
/// chart can use each key as a stable series.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct HourlyByProtocol {
    /// Start of the hour, UTC, ISO-8601 with millisecond precision.
    pub hour: String,
    /// Events in the hour, all protocols.
    pub total: u64,
    /// Protocol name to event count; `other` is every event in the hour not
    /// attributed to one of the named protocols (including events with no
    /// `network.protocol`).
    pub counts: std::collections::BTreeMap<String, u64>,
}

/// Live-only figures: none of them can be summed from the hourly rollup
/// (cardinalities don't add; the protocol split isn't carried by the rollup
/// doc), so they are always read from Elasticsearch.
#[derive(Debug, Default, PartialEq)]
struct LiveWindow {
    unique_ips: u64,
    sessions_24h: u64,
    sessions_previous24h: u64,
    hourly_by_protocol: Vec<HourlyByProtocol>,
}

/// KPI values pulled out of rolled `_all` hour docs: totals summed over the
/// window, 24h splits aligned to the current hour boundary, and the
/// always-length-24 oldest-first sparkline.
fn kpis_from_rollup(
    now: chrono::DateTime<chrono::Utc>,
    docs: Vec<(chrono::DateTime<chrono::Utc>, serde_json::Value)>,
) -> Option<(u64, u64, u64, Vec<u64>, u64)> {
    let current_hour = rollups::hour_floor(now);
    let day_start = current_hour - chrono::Duration::hours(23);
    let prev_end = current_hour - chrono::Duration::hours(24);
    let mut total = 0u64;
    let mut last24h = 0u64;
    let mut previous24h = 0u64;
    let mut logins = 0u64;
    let mut by_hour: std::collections::HashMap<chrono::DateTime<chrono::Utc>, u64> =
        std::collections::HashMap::new();
    for (hour, doc) in &docs {
        let events = doc["events"].as_u64().unwrap_or(0);
        total += events;
        logins += doc["logins"].as_u64().unwrap_or(0);
        if *hour >= day_start {
            last24h += events;
        } else if *hour >= prev_end {
            previous24h += events;
        }
        by_hour.insert(*hour, events);
    }
    if !rollups::covered(docs.len(), 48) {
        return None;
    }
    let hourly: Vec<u64> = (0..24)
        .map(|offset| by_hour.get(&(day_start + chrono::Duration::hours(offset))).copied().unwrap_or(0))
        .collect();
    Some((total, last24h, previous24h, hourly, logins))
}

fn change24h_str(previous24h: u64, last24h: u64) -> String {
    if previous24h > 0 {
        let delta = (last24h as i64 - previous24h as i64) * 100 / previous24h as i64;
        format!("{}{}%", if delta >= 0 { "+" } else { "" }, delta)
    } else {
        String::new()
    }
}

/// Cardinality per session-id field, under a filter that keeps the window
/// and drops the ingest-time health-check probes (es.rs
/// `internal_probe_exclusion`: every attacker-facing aggregation carries it).
fn session_aggs(window: Value) -> Value {
    let mut fields = serde_json::Map::new();
    for (index, field) in SESSION_FIELDS.iter().enumerate() {
        fields.insert(format!("session_{index}"), json!({"cardinality": {"field": field}}));
    }
    json!({
        "filter": {"bool": {"filter": [window], "must_not": [internal_probe_exclusion()]}},
        "aggs": fields,
    })
}

/// Sum of the per-field session cardinalities. A missing aggregation counts
/// as zero, so a window with no session-bearing documents reads 0.
fn sessions_from_aggs(window_aggs: &Value) -> u64 {
    (0..SESSION_FIELDS.len())
        .map(|index| window_aggs[format!("session_{index}")]["value"].as_u64().unwrap_or(0))
        .sum()
}

/// The aggregations behind `LiveWindow`, shared by the rollup path's
/// dedicated query and the live fallback's single query.
fn live_window_aggs() -> Value {
    json!({
        "unique_ips": {"cardinality": {"field": "source.ip"}},
        "sessions_last24h": session_aggs(json!({"range": {"@timestamp": {"gte": "now-24h"}}})),
        "sessions_previous24h": session_aggs(
            json!({"range": {"@timestamp": {"gte": "now-48h", "lt": "now-24h"}}})
        ),
        // Same 24 buckets as `hourly`: from the start of the hour 23 hours
        // back through the current hour, with empty hours kept as zeros.
        "timeline_last24h": {
            "filter": {"range": {"@timestamp": {"gte": "now-23h/h"}}},
            "aggs": {"hourly_by_protocol": {
                "date_histogram": {
                    "field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                    "extended_bounds": {"min": "now-23h/h", "max": "now/h"}
                },
                "aggs": {"protocols": {"terms": {
                    "field": "network.protocol", "size": TIMELINE_TERMS_SIZE
                }}}
            }}
        }
    })
}

/// Reads `LiveWindow` out of a response's `aggregations` object.
fn parse_live_window(aggregations: &Value) -> LiveWindow {
    let buckets = aggregations["timeline_last24h"]["hourly_by_protocol"]["buckets"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    LiveWindow {
        unique_ips: aggregations["unique_ips"]["value"].as_u64().unwrap_or(0),
        sessions_24h: sessions_from_aggs(&aggregations["sessions_last24h"]),
        sessions_previous24h: sessions_from_aggs(&aggregations["sessions_previous24h"]),
        hourly_by_protocol: timeline_from_buckets(buckets),
    }
}

/// Builds the protocol timeline from `date_histogram` buckets that each
/// carry a `protocols` terms sub-aggregation. Top-5 protocols are chosen by
/// their summed counts over the returned buckets; `other` is what the hour
/// total leaves once those five are subtracted.
fn timeline_from_buckets(buckets: &[Value]) -> Vec<HourlyByProtocol> {
    let mut window_totals: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
    for bucket in buckets {
        for protocol in bucket["protocols"]["buckets"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            if let Some(name) = protocol["key"].as_str() {
                *window_totals.entry(name).or_insert(0) += protocol["doc_count"].as_u64().unwrap_or(0);
            }
        }
    }
    let mut ranked: Vec<(&str, u64)> = window_totals.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    ranked.truncate(TIMELINE_TOP_PROTOCOLS);
    let top: Vec<&str> = ranked.iter().map(|(name, _)| *name).collect();

    buckets
        .iter()
        .filter_map(|bucket| {
            let key_ms = bucket["key"].as_i64()?;
            let hour = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(key_ms)?
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let total = bucket["doc_count"].as_u64().unwrap_or(0);
            let mut counts: std::collections::BTreeMap<String, u64> =
                top.iter().map(|name| ((*name).to_string(), 0)).collect();
            let mut named = 0u64;
            for protocol in bucket["protocols"]["buckets"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                let Some(name) = protocol["key"].as_str() else { continue };
                if top.contains(&name) {
                    let count = protocol["doc_count"].as_u64().unwrap_or(0);
                    counts.insert(name.to_string(), count);
                    named += count;
                }
            }
            counts.insert("other".to_string(), total.saturating_sub(named));
            Some(HourlyByProtocol { hour, total, counts })
        })
        .collect()
}

/// One live query for everything the rollup can't carry.
async fn live_window(state: &AppState) -> Result<LiveWindow, (StatusCode, String)> {
    let result = state
        .es
        .search(json!({
            "size": 0,
            "track_total_hits": false,
            "query": {"range": {"@timestamp": {"gte": "now-48h"}}},
            "aggs": live_window_aggs()
        }))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(parse_live_window(&result["aggregations"]))
}

/// KPI counters behind the overview tiles.
///
/// Event counts and their trend (`total`, `last24h`, `previous24h`,
/// `change24h`), `unique_ips` and `logins` over the 48h window, `hourly`
/// (24 hourly event counts, oldest first, no timestamps), `sessions_24h` and
/// `sessions_previous24h` (distinct session ids over the rolling 24h windows;
/// an upper bound, one cardinality per session field summed), and
/// `hourly_by_protocol` (24 hourly buckets with an ISO `hour`, `total` and
/// per-protocol `counts`: the top 5 protocols plus `other`). The rollup
/// serves the event counts when covered; the session and protocol figures
/// are always read live.
#[utoipa::path(
    get,
    path = "/api/v1/overview/kpis",
    summary = "KPI counters behind the overview tiles.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn kpis(State(state): State<AppState>) -> Result<Json<OverviewKpis>, (StatusCode, String)> {
    // #2046: the rolled fleet hours are the primary path; the aggregation
    // below runs only while the worker hasn't covered the window yet (fresh
    // deploy, disabled loop) or the rollup read itself errors. The session
    // and protocol-timeline figures are live-only on both paths.
    if let Ok(docs) = rollups::fleet_hours(&state, 48).await {
        if let Some((total, last24h, previous24h, hourly, logins)) =
            kpis_from_rollup(chrono::Utc::now(), docs)
        {
            let window = live_window(&state).await?;
            return Ok(Json(OverviewKpis {
                total,
                last24h,
                previous24h,
                change24h: change24h_str(previous24h, last24h),
                unique_ips: window.unique_ips,
                hourly,
                logins,
                sessions_24h: window.sessions_24h,
                sessions_previous24h: window.sessions_previous24h,
                hourly_by_protocol: window.hourly_by_protocol,
                ready: true,
            }));
        }
    }

    let mut aggs = live_window_aggs();
    aggs["last24h"] = json!({
        "filter": {"range": {"@timestamp": {"gte": "now-24h"}}},
        "aggs": {"hourly": {"date_histogram": {
            "field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
            "extended_bounds": {"min": "now-23h/h", "max": "now/h"}
        }}}
    });
    aggs["previous24h"] = json!({"filter": {"range": {"@timestamp": {"gte": "now-48h", "lt": "now-24h"}}}});
    aggs["logins"] = json!({"filter": logins_filter()});
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"range": {"@timestamp": {"gte": "now-48h"}}},
        "aggs": aggs
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let last24h = result["aggregations"]["last24h"]["doc_count"].as_u64().unwrap_or(0);
    let previous24h = result["aggregations"]["previous24h"]["doc_count"].as_u64().unwrap_or(0);
    let logins = result["aggregations"]["logins"]["doc_count"].as_u64().unwrap_or(0);
    let hourly: Vec<u64> = result["aggregations"]["last24h"]["hourly"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| bucket["doc_count"].as_u64().unwrap_or(0))
        .collect();
    let window = parse_live_window(&result["aggregations"]);

    let change24h = change24h_str(previous24h, last24h);

    Ok(Json(OverviewKpis {
        total,
        last24h,
        previous24h,
        change24h,
        unique_ips: window.unique_ips,
        hourly,
        logins,
        sessions_24h: window.sessions_24h,
        sessions_previous24h: window.sessions_previous24h,
        hourly_by_protocol: window.hourly_by_protocol,
        ready: true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2027-01-15T08:00:00Z, on an hour boundary.
    const HOUR_MS: i64 = 1_800_000_000_000;

    fn bucket(hour_offset: i64, total: u64, protocols: &[(&str, u64)]) -> Value {
        let protocols: Vec<Value> = protocols
            .iter()
            .map(|(key, count)| json!({"key": key, "doc_count": count}))
            .collect();
        json!({
            "key": HOUR_MS + hour_offset * 3_600_000,
            "doc_count": total,
            "protocols": {"buckets": protocols}
        })
    }

    #[test]
    fn session_clause_sums_one_cardinality_per_session_field_within_the_window() {
        let aggs = live_window_aggs();
        let last = &aggs["sessions_last24h"];
        let filters = last["filter"]["bool"]["filter"].as_array().expect("filter array");
        assert_eq!(filters[0]["range"]["@timestamp"]["gte"], "now-24h");
        assert_eq!(
            last["filter"]["bool"]["must_not"],
            json!([{"term": {"honeypot.internal_probe": true}}]),
            "session counts must drop the health-check probes like every attacker-facing aggregation"
        );
        for (index, field) in SESSION_FIELDS.iter().enumerate() {
            assert_eq!(last["aggs"][format!("session_{index}")]["cardinality"]["field"], *field);
        }
        assert_eq!(last["aggs"].as_object().map(|m| m.len()), Some(SESSION_FIELDS.len()));

        let previous = &aggs["sessions_previous24h"]["filter"]["bool"]["filter"][0]["range"]["@timestamp"];
        assert_eq!(previous["gte"], "now-48h");
        assert_eq!(previous["lt"], "now-24h");
    }

    #[test]
    fn timeline_query_is_a_24_hour_date_histogram_with_a_protocol_terms_split() {
        let timeline = &live_window_aggs()["timeline_last24h"];
        assert_eq!(timeline["filter"]["range"]["@timestamp"]["gte"], "now-23h/h");
        let histogram = &timeline["aggs"]["hourly_by_protocol"]["date_histogram"];
        assert_eq!(histogram["field"], "@timestamp");
        assert_eq!(histogram["fixed_interval"], "1h");
        assert_eq!(histogram["min_doc_count"], 0);
        assert_eq!(histogram["extended_bounds"], json!({"min": "now-23h/h", "max": "now/h"}));
        let protocols = &timeline["aggs"]["hourly_by_protocol"]["aggs"]["protocols"]["terms"];
        assert_eq!(protocols["field"], "network.protocol");
        assert_eq!(protocols["size"], TIMELINE_TERMS_SIZE);
    }

    #[test]
    fn unique_ips_stays_on_the_source_ip_cardinality() {
        assert_eq!(
            live_window_aggs()["unique_ips"],
            json!({"cardinality": {"field": "source.ip"}})
        );
    }

    #[test]
    fn sessions_from_aggs_treats_missing_aggregations_as_zero() {
        assert_eq!(sessions_from_aggs(&json!({"doc_count": 0})), 0);
        assert_eq!(sessions_from_aggs(&Value::Null), 0);
    }

    #[test]
    fn sessions_from_aggs_sums_the_per_field_values() {
        let window = json!({
            "doc_count": 10,
            "session_0": {"value": 7},
            "session_1": {"value": 2},
            "session_2": {"value": 0}
        });
        assert_eq!(sessions_from_aggs(&window), 9);
    }

    #[test]
    fn empty_histogram_yields_no_timeline_rows() {
        assert!(timeline_from_buckets(&[]).is_empty());
    }

    #[test]
    fn empty_hours_are_zero_filled_with_stable_keys_and_timestamps() {
        let rows = timeline_from_buckets(&[bucket(0, 0, &[]), bucket(1, 0, &[])]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].hour, "2027-01-15T08:00:00.000Z");
        assert_eq!(rows[1].hour, "2027-01-15T09:00:00.000Z");
        for row in &rows {
            assert_eq!(row.total, 0);
            assert_eq!(row.counts, std::collections::BTreeMap::from([("other".to_string(), 0)]));
        }
    }

    #[test]
    fn top_five_protocols_are_named_and_the_rest_fold_into_other() {
        // Window totals: a=60, b=50, c=25, d=15, e=5, f=5, g=5 (e, f, g tie;
        // the alphabetically first wins the fifth slot).
        let buckets = [
            bucket(0, 100, &[("a", 30), ("b", 25), ("c", 20), ("d", 15), ("e", 5), ("f", 5)]),
            bucket(1, 60, &[("a", 30), ("b", 25), ("c", 5)]),
            bucket(2, 10, &[("g", 5)]),
        ];
        let rows = timeline_from_buckets(&buckets);
        let keys: Vec<&str> = rows[0].counts.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["a", "b", "c", "d", "e", "other"]);
        assert_eq!(rows[0].counts["a"], 30);
        assert_eq!(rows[0].counts["e"], 5);
        // f is outside the top five; other = 100 - (30+25+20+15+5).
        assert_eq!(rows[0].counts["other"], 5);
        assert_eq!(rows[0].total, 100);
        // Hour 2 holds only g, which is outside the top five: all 10 go to other.
        assert_eq!(rows[2].counts["other"], 10);
        assert_eq!(rows[2].counts["a"], 0);
        assert_eq!(rows[2].total, 10);
    }

    #[test]
    fn events_without_a_protocol_are_counted_in_other() {
        // 12 events in the hour, only 4 carry a protocol.
        let rows = timeline_from_buckets(&[bucket(0, 12, &[("ssh", 4)])]);
        assert_eq!(rows[0].counts["ssh"], 4);
        assert_eq!(rows[0].counts["other"], 8);
    }

    #[test]
    fn live_window_parses_every_field_and_tolerates_an_empty_response() {
        let empty = parse_live_window(&json!({}));
        assert_eq!(empty, LiveWindow::default());

        let aggregations = json!({
            "unique_ips": {"value": 42},
            "sessions_last24h": {"doc_count": 9, "session_0": {"value": 3}, "session_1": {"value": 1}, "session_2": {"value": 0}},
            "sessions_previous24h": {"doc_count": 5, "session_0": {"value": 2}, "session_1": {"value": 0}, "session_2": {"value": 0}},
            "timeline_last24h": {"doc_count": 12, "hourly_by_protocol": {"buckets": [
                bucket(0, 12, &[("ssh", 4)])
            ]}}
        });
        let window = parse_live_window(&aggregations);
        assert_eq!(window.unique_ips, 42);
        assert_eq!(window.sessions_24h, 4);
        assert_eq!(window.sessions_previous24h, 2);
        assert_eq!(window.hourly_by_protocol.len(), 1);
        assert_eq!(window.hourly_by_protocol[0].counts["other"], 8);
    }

    #[test]
    fn change_is_empty_while_the_previous_window_is_empty() {
        assert_eq!(change24h_str(0, 10), "");
        assert_eq!(change24h_str(100, 141), "+41%");
    }
}
