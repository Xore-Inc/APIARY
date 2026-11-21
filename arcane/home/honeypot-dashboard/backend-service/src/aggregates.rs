//! Aggregation-backed list endpoints for the Investigate family. Query
//! shapes mirror the Go dashboard's es_aggregate.go semantics (same index
//! families, same field names); each returns page-shaped JSON the BFF
//! passes through to the routes.

// (filter_values below also lives here — small shared aggregation helpers.)
use crate::contract;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{es::logins_filter, AppState};

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
    /// `/api/v1/sources` only (#3909): comma-separated addresses to profile
    /// instead of listing the busiest. See [`parse_ips`].
    #[serde(default)]
    pub ips: Option<String>,
}

fn default_size() -> u64 {
    25
}

// ── Attack sources (/ips): top source IPs with activity window ───────────

#[derive(Serialize)]
pub struct SourceRow {
    pub ip: String,
    pub country: String,
    pub events: u64,
    pub logins: u64,
    pub sessions: u64,
    pub sensors: Vec<String>,
    pub first: String,
    pub last: String,
    /// The AS organization name ("" when unknown). Only a request with `ips=`
    /// asks for it (#3909); the listing and its snapshot carry no `org`, so
    /// the field is absent there and those answers are unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

#[derive(Serialize)]
pub struct SourcesPage {
    pub total_unique: u64,
    /// True when the terms aggregation hit its 1000-bucket request
    /// ceiling and `total_unique` counts IPs that no row shows (#2044).
    pub truncated: bool,
    pub rows: Vec<SourceRow>,
}

#[utoipa::path(
    get,
    path = "/api/v1/sources",
    summary = "Known source addresses with their event counts.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
        ("ips" = inline(Option<String>), Query, description = "Comma-separated source addresses, at most 50. Answers with exactly those addresses that have events in the window (each with its `org`), instead of the busiest ones; `offset` and `size` are then ignored, and the answer is always live. An entry that is not an address, or more than 50 entries, is a 400."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn sources(
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<SourcesPage>, (StatusCode, String)> {
    // #3909: a request for named addresses is parameterised, so it never
    // reads the snapshot (which holds the top 1000, not these addresses); one
    // search answers for all of them, where the dashboard used to profile
    // each address with its own investigate/ip.
    if let Some(raw) = q.ips.as_deref() {
        let ips = parse_ips(raw).map_err(|message| (StatusCode::BAD_REQUEST, message))?;
        let wanted = ips.len() as u64;
        let result = state.es.search(sources_body_for(wanted, Some(&ips))).await.map_err(bad_gateway)?;
        return Ok(Json(sources_page(&result, 0, wanted)));
    }
    let size = (q.offset + q.size).min(SOURCES_CAP);
    // #3756: the worker's snapshot of this same request at the cap, when a
    // recent one exists; otherwise the live aggregation.
    let result = match crate::page_rollup::read(&state, crate::page_rollup::SOURCES).await {
        Some(snapshot) => snapshot,
        None => state.es.search(sources_body(size)).await.map_err(bad_gateway)?,
    };
    Ok(Json(sources_page(&result, q.offset, size)))
}

/// The most rows `/api/v1/sources` lists; the terms aggregation asks for
/// `offset + size` buckets up to this ceiling.
pub(crate) const SOURCES_CAP: u64 = 1000;

/// The request behind `/api/v1/sources` for `size` buckets. The worker's
/// snapshot (`page_rollup`) sends it with `SOURCES_CAP`.
pub(crate) fn sources_body(size: u64) -> Value {
    sources_body_for(size, None)
}

/// The most addresses one `ips=` request names (#3909).
pub(crate) const SOURCES_IPS_MAX: usize = 50;

/// The addresses of an `ips=` value, each in its canonical spelling, repeats
/// dropped, in the order given. At most [`SOURCES_IPS_MAX`] entries; an empty
/// entry, an entry that is no IPv4 or IPv6 address, or too many entries is
/// the message of a 400. The offending value is not echoed back.
pub(crate) fn parse_ips(raw: &str) -> Result<Vec<String>, String> {
    let entries: Vec<&str> = raw.split(',').map(str::trim).collect();
    if entries.len() > SOURCES_IPS_MAX {
        return Err(format!("ips: at most {SOURCES_IPS_MAX} addresses per request, got {}", entries.len()));
    }
    let mut ips: Vec<String> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if entry.is_empty() {
            return Err(format!("ips: entry {} is empty", index + 1));
        }
        let ip: std::net::IpAddr = entry
            .parse()
            .map_err(|_| format!("ips: entry {} is not an IP address", index + 1))?;
        let ip = ip.to_string();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

/// [`sources_body`], optionally narrowed to the addresses in `ips` (#3909).
/// With `ips` the query adds a `terms` filter on `source.ip` and the buckets
/// also carry the AS organization (`org`); without it the body is exactly
/// the listing's, which the worker's snapshot (`page_rollup`) also sends.
pub(crate) fn sources_body_for(size: u64, ips: Option<&[String]>) -> Value {
    let mut filter = vec![json!({"range": {"@timestamp": {"gte": "now-10d"}}})];
    let mut per_ip = json!({
        "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
        "sensors": {"terms": {"field": "event.sensor", "size": 30}},
        "logins": {"filter": logins_filter()},
        "sessions": {"cardinality": {"field": "honeypot.session"}},
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}}
    });
    if let Some(ips) = ips {
        filter.push(json!({"terms": {"source.ip": ips}}));
        per_ip["org"] = json!({"terms": {"field": "source.as.organization_name", "size": 1}});
    }
    json!({
        "size": 0,
        // #2145: the /ips top-attacker list; probes mostly drop out via the
        // source.ip aggs, but the exclusion makes that incidental protection
        // explicit (and keeps the total-unique count probe-free).
        "query": {"bool": {
            "filter": filter,
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "unique": {"cardinality": {"field": "source.ip"}},
            "ips": {
                "terms": {"field": "source.ip", "size": size, "order": {"_count": "desc"}},
                "aggs": per_ip
            }
        }
    })
}

/// The page for `offset` out of an answer to `sources_body`. `size` is the
/// bucket count the live request asks for: a snapshot holds `SOURCES_CAP`
/// buckets, and only its first `size` are the live answer's buckets.
fn sources_page(result: &Value, offset: u64, size: u64) -> SourcesPage {
    let empty = Vec::new();
    let buckets: Vec<&Value> = result["aggregations"]["ips"]["buckets"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .take(size as usize)
        .collect();
    let total_unique = result["aggregations"]["unique"]["value"].as_u64().unwrap_or(0);
    let rows = buckets
        .iter()
        .skip(offset as usize)
        .map(|bucket| SourceRow {
            ip: text(&bucket["key"]),
            country: bucket["country"]["buckets"]
                .as_array()
                .and_then(|c| c.first())
                .map(|c| text(&c["key"]))
                .unwrap_or_default(),
            events: bucket["doc_count"].as_u64().unwrap_or(0),
            logins: bucket["logins"]["doc_count"].as_u64().unwrap_or(0),
            sessions: bucket["sessions"]["value"].as_u64().unwrap_or(0),
            sensors: bucket["sensors"]["buckets"]
                .as_array()
                .map(|s| s.iter().map(|b| text(&b["key"])).collect())
                .unwrap_or_default(),
            first: text(&bucket["first"]["value_as_string"]),
            last: text(&bucket["last"]["value_as_string"]),
            // Present only when the query asked for it (`ips=`, #3909).
            org: bucket.get("org").map(|org| {
                org["buckets"].as_array().and_then(|b| b.first()).map(|b| text(&b["key"])).unwrap_or_default()
            }),
        })
        .collect();
    // The cardinality agg counts the whole window while the terms agg
    // silently stops at its size ceiling; when they disagree, IPs exist
    // that no row shows (#2044).
    let listed = buckets.len();
    SourcesPage {
        total_unique,
        truncated: total_unique > listed as u64,
        rows,
    }
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

#[derive(serde::Serialize)]
pub struct FilterValues {
    pub sensors: Vec<String>,
    pub countries: Vec<String>,
    /// City names over the event window (#2045) — the drill-in target the
    /// overview map pins now filter events by.
    pub cities: Vec<String>,
    pub protos: Vec<String>,
    pub ports: Vec<String>,
    pub kinds: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/filter-values",
    summary = "Distinct values behind every explorer filter dropdown.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// /api/v1/filter-values — the filter bar's autocomplete vocabularies,
/// mirroring the Go tier's /api/filter-values (live terms over the event
/// window).
///
/// #3910: served from the worker's snapshot of this request (`page_rollup`)
/// while a recent one exists, so a vocabulary can trail by one cycle.
pub async fn filter_values(State(state): State<AppState>) -> Result<Json<FilterValues>, (StatusCode, String)> {
    // #3908: a vocabulary, not a count: the Modbus PDUs add no sensor,
    // port or kind the other zeek logs lack, only seconds of scanning.
    let result = match crate::page_rollup::read(&state, crate::page_rollup::FILTER_VALUES).await {
        Some(snapshot) => snapshot,
        None => state.es.search_agg(filter_values_body()).await.map_err(bad_gateway)?,
    };
    Ok(Json(filter_values_from(&result)))
}

/// The request behind `/api/v1/filter-values`, shared with its snapshot.
pub(crate) fn filter_values_body() -> Value {
    json!({
        "size": 0,
        // #2145: probe docs DO carry sensors/kinds/ports/protos values, so
        // without this clause the fleet's healthchecks leak into the
        // filter-bar vocabulary the operator browses.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": "now-48h"}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "sensors": {"terms": {"field": "event.sensor", "size": 60}},
            "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 200}},
            // Same field the map's multi_terms buckets on; a city term is
            // only useful alongside its country, so the size follows the
            // map pin cap (dashboard.rs, 500) rather than a bar-length one.
            "cities": {"terms": {"field": "source.geo.city_name", "size": 500}},
            "protos": {"terms": {"field": "network.protocol", "size": 60}},
            "ports": {"terms": {"field": "destination.port", "size": 60}},
            "kinds": {"terms": {"field": "honeypot.event", "size": 40}}
        }
    })
}

fn filter_values_from(result: &Value) -> FilterValues {
    let keys = |agg: &str| -> Vec<String> {
        result["aggregations"][agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|bucket| {
                let key = &bucket["key"];
                key.as_str().map(String::from).or_else(|| key.as_i64().map(|n| n.to_string()))
            })
            .collect()
    };
    let mut values = FilterValues {
        sensors: keys("sensors"),
        countries: keys("countries"),
        cities: keys("cities"),
        protos: keys("protos"),
        ports: keys("ports"),
        kinds: keys("kinds"),
    };
    values.countries.sort();
    values.cities.sort();
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer to `sources_body` with `n` buckets, the most active first.
    fn answer(n: u64, unique: u64) -> Value {
        let buckets: Vec<Value> = (0..n)
            .map(|i| {
                json!({
                    "key": format!("203.0.113.{i}"),
                    "doc_count": 1000 - i,
                    "country": {"buckets": [{"key": "NL", "doc_count": 1}]},
                    "sensors": {"buckets": [{"key": "cowrie", "doc_count": 1}, {"key": "zeek", "doc_count": 1}]},
                    "logins": {"doc_count": i},
                    "sessions": {"value": 2},
                    "first": {"value_as_string": "2026-10-28T00:00:00.000Z"},
                    "last": {"value_as_string": "2026-11-07T22:00:00.000Z"}
                })
            })
            .collect();
        json!({"aggregations": {"unique": {"value": unique}, "ips": {"buckets": buckets}}})
    }

    #[test]
    fn a_page_reads_its_rows_out_of_the_buckets() {
        let page = sources_page(&answer(3, 3), 1, 25);
        assert_eq!((page.total_unique, page.truncated), (3, false));
        let ips: Vec<&str> = page.rows.iter().map(|row| row.ip.as_str()).collect();
        assert_eq!(ips, ["203.0.113.1", "203.0.113.2"]);
        let row = &page.rows[0];
        assert_eq!((row.events, row.logins, row.sessions, row.country.as_str()), (999, 1, 2, "NL"));
        assert_eq!(row.sensors, ["cowrie", "zeek"]);
        assert_eq!((row.first.as_str(), row.last.as_str()), ("2026-10-28T00:00:00.000Z", "2026-11-07T22:00:00.000Z"));
    }

    /// #3756: a snapshot holds the cap's 1000 buckets. A smaller request
    /// reads only the buckets its own live query would have asked for, so
    /// rows and `truncated` (#2044) come out as they would live.
    #[test]
    fn a_snapshot_at_the_cap_answers_a_smaller_page_like_the_live_query() {
        let snapshot = answer(SOURCES_CAP, 4000);
        let live = answer(30, 4000);
        for (offset, size) in [(0, 25), (5, 25), (25, 5)] {
            let wanted = (offset + size).min(SOURCES_CAP);
            let from_snapshot = sources_page(&snapshot, offset, wanted);
            let from_live = sources_page(&live, offset, wanted);
            assert_eq!(
                serde_json::to_value(&from_snapshot).unwrap(),
                serde_json::to_value(&from_live).unwrap(),
                "offset={offset} size={size}"
            );
            assert!(from_snapshot.truncated);
        }
        let all = sources_page(&snapshot, 0, SOURCES_CAP);
        assert_eq!(all.rows.len(), 1000);
        assert!(all.truncated);
        assert!(!sources_page(&answer(SOURCES_CAP, 1000), 0, SOURCES_CAP).truncated);
    }

    #[test]
    fn the_body_asks_for_the_requested_bucket_count() {
        assert_eq!(sources_body(25)["aggs"]["ips"]["terms"]["size"], 25);
        assert_eq!(sources_body(SOURCES_CAP)["aggs"]["ips"]["terms"]["size"], 1000);
    }

    // ---- #3909: ips= ----

    fn ips(raw: &str) -> Vec<String> {
        parse_ips(raw).unwrap_or_else(|message| panic!("{raw:?}: {message}"))
    }

    #[test]
    fn ips_are_parsed_trimmed_canonical_and_deduplicated_in_order() {
        assert_eq!(ips("203.0.113.9"), ["203.0.113.9"]);
        assert_eq!(ips(" 203.0.113.9 , 198.51.100.1,203.0.113.9"), ["203.0.113.9", "198.51.100.1"]);
        assert_eq!(ips("2001:DB8:0:0:0:0:0:1,2001:db8::1"), ["2001:db8::1"]);
        assert_eq!(ips("::ffff:192.0.2.1"), ["::ffff:192.0.2.1"]);
    }

    #[test]
    fn up_to_fifty_ips_are_accepted_and_more_are_not() {
        let many = |n: usize| (0..n).map(|i| format!("203.0.113.{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(ips(&many(SOURCES_IPS_MAX)).len(), SOURCES_IPS_MAX);
        let error = parse_ips(&many(SOURCES_IPS_MAX + 1)).unwrap_err();
        assert!(error.contains("at most 50"), "{error}");
        // Repeats count as entries: the cap bounds the request, not the set.
        let repeated = vec!["203.0.113.1"; SOURCES_IPS_MAX + 1].join(",");
        assert!(parse_ips(&repeated).is_err());
    }

    #[test]
    fn a_bad_entry_is_refused_without_echoing_it() {
        for raw in ["", ",", "203.0.113.1,", ",203.0.113.1", "203.0.113.1,,198.51.100.1", " "] {
            assert!(parse_ips(raw).unwrap_err().contains("is empty"), "{raw:?}");
        }
        for raw in ["nope", "203.0.113.256", "203.0.113.0/24", "203.0.113.1,evil.example", "1.2.3", "::g"] {
            let error = parse_ips(raw).unwrap_err();
            assert!(error.contains("is not an IP address"), "{raw:?}: {error}");
            assert!(!error.contains("evil") && !error.contains("nope"), "{error}");
        }
        assert!(parse_ips("203.0.113.1,198.51.100.300").unwrap_err().contains("entry 2"));
    }

    #[test]
    fn the_listing_body_is_unchanged_by_ips() {
        let listing = sources_body(25);
        assert_eq!(listing, sources_body_for(25, None));
        assert_eq!(listing["query"]["bool"]["filter"].as_array().unwrap().len(), 1);
        assert!(listing["aggs"]["ips"]["aggs"].get("org").is_none());
        assert!(!listing.to_string().contains("\"terms\":{\"source.ip\":["));
    }

    #[test]
    fn an_ips_body_filters_on_the_addresses_and_asks_for_the_organization() {
        let wanted = ips("203.0.113.9,198.51.100.1");
        let body = sources_body_for(wanted.len() as u64, Some(&wanted));
        let filter = body["query"]["bool"]["filter"].as_array().unwrap();
        assert_eq!(filter.len(), 2);
        assert_eq!(filter[0], sources_body(1)["query"]["bool"]["filter"][0]);
        assert_eq!(filter[1], json!({"terms": {"source.ip": ["203.0.113.9", "198.51.100.1"]}}));
        assert_eq!(body["query"]["bool"]["must_not"], sources_body(1)["query"]["bool"]["must_not"]);
        assert_eq!(body["aggs"]["ips"]["terms"]["size"], 2);
        let per_ip = &body["aggs"]["ips"]["aggs"];
        assert_eq!(per_ip["org"]["terms"]["field"], "source.as.organization_name");
        // Everything the listing computes per address is still there.
        for key in ["country", "sensors", "logins", "sessions", "first", "last"] {
            assert_eq!(per_ip[key], sources_body(1)["aggs"]["ips"]["aggs"][key], "{key}");
        }
    }

    #[test]
    fn an_ips_answer_carries_every_field_a_member_profile_reads() {
        let mut result = answer(2, 2);
        for (i, bucket) in result["aggregations"]["ips"]["buckets"].as_array_mut().unwrap().iter_mut().enumerate() {
            bucket["org"] = if i == 0 { json!({"buckets": [{"key": "Example Net", "doc_count": 5}]}) } else { json!({"buckets": []}) };
        }
        let page = sources_page(&result, 0, 2);
        let rows = serde_json::to_value(&page.rows).unwrap();
        assert_eq!(rows[0]["org"], "Example Net");
        assert_eq!(rows[1]["org"], "", "an address with no organization is \"\", not absent");
        for key in ["ip", "country", "events", "sessions", "sensors", "first", "last"] {
            assert!(rows[0].get(key).is_some(), "{key}");
        }
        assert_eq!((page.total_unique, page.truncated), (2, false));
    }

    #[test]
    fn a_listing_answer_has_no_org_field() {
        let rows = serde_json::to_value(&sources_page(&answer(2, 2), 0, 2).rows).unwrap();
        assert!(rows[0].as_object().unwrap().get("org").is_none());
    }
}
