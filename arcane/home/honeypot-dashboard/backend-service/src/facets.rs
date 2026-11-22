//! /api/v1/facets/{kind} -- counted value lists for the filter pickers
//! (#3524). One aggregation request over EVENT_INDICES returns, for the
//! events explorer's filter set, every value each picker can take and how
//! many events carry it.
//!
//! The query is the explorer's own: `events::build_filters` for the filters
//! (so `since`, `ip`, `sensor`, ... mean exactly what they mean on
//! /api/v1/events) and `events::suricata_noise_exclusion` for the
//! exclusions (flow/stats noise, `honeypot.internal_probe`, a sensor's own
//! startup logging). A facet count is therefore the number the explorer
//! lists after the picker is applied. All filters apply to every facet,
//! including the facet's own field, so the lists describe the current
//! result set; clear a filter to see its siblings.
//!
//! Wire shape (snake_case, stable): every list is `[{value, count}]`,
//! highest count first, ties by value ascending.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::events::{build_filters, is_fleet_address, suricata_noise_exclusion, EventsQuery};
use crate::AppState;

/// Values returned per list.
pub const FACET_LIMIT: usize = 50;
/// Countries are a closed set of at most ~250 codes; return them all.
const COUNTRY_LIMIT: usize = 250;
/// Sources are over-fetched by this factor so dropping fleet addresses
/// still leaves `FACET_LIMIT` attackers.
const SOURCE_OVERFETCH: usize = 3;

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct FacetValue {
    /// The value to send back as the matching `/api/v1/events` filter.
    pub value: String,
    /// Events carrying this value in the filtered window.
    pub count: u64,
}

#[derive(Serialize, Debug, Default, PartialEq, Eq)]
pub struct Facets {
    /// Echo of the facet family requested (`events`).
    pub kind: String,
    /// Events matched by the filters, i.e. the explorer's `total`.
    pub total: u64,
    /// `event.sensor` -> `sensor=`.
    pub sensors: Vec<FacetValue>,
    /// `source.ip` (fleet addresses removed) -> `ip=`.
    pub sources: Vec<FacetValue>,
    /// `source.geo.country_iso_code` -> `country=`.
    pub countries: Vec<FacetValue>,
    /// `network.protocol` -> `proto=`.
    pub protocols: Vec<FacetValue>,
    /// `destination.port` -> `port=`.
    pub ports: Vec<FacetValue>,
    /// `suricata.eve.alert.signature` -> `sig=`.
    pub signatures: Vec<FacetValue>,
    /// `honeypot.event` -> `kind=`.
    pub kinds: Vec<FacetValue>,
    /// `honeypot.persona_id` -> `persona=`.
    pub personas: Vec<FacetValue>,
    /// `source.as.type` -> `provider=`.
    pub providers: Vec<FacetValue>,
    /// `source.geo.city_name` -> `city=`.
    pub cities: Vec<FacetValue>,
}

fn terms(field: &str, size: usize) -> Value {
    json!({"terms": {"field": field, "size": size, "order": [{"_count": "desc"}, {"_key": "asc"}]}})
}

/// The request body for the facet aggregation, given the explorer filters.
pub fn facet_body(filters: Vec<Value>) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}},
        "aggs": {
            "sensors": terms("event.sensor", FACET_LIMIT),
            "sources": terms("source.ip", FACET_LIMIT * SOURCE_OVERFETCH),
            "countries": terms("source.geo.country_iso_code", COUNTRY_LIMIT),
            "protocols": terms("network.protocol", FACET_LIMIT),
            "ports": terms("destination.port", FACET_LIMIT),
            // `.keyword` is the aggregatable sub-field of the text mapping.
            "signatures": terms("suricata.eve.alert.signature.keyword", FACET_LIMIT),
            "kinds": terms("honeypot.event", FACET_LIMIT),
            "personas": terms("honeypot.persona_id", FACET_LIMIT),
            "cities": terms("source.geo.city_name", FACET_LIMIT),
        }
    })
}

/// Providers are a second request on purpose. `source.as.type` is a keyword
/// field everywhere except one historical zeek-proxy index where dynamic
/// mapping made it `text`; aggregating a text field fails that shard, and a
/// failed shard silently drops its documents from the SAME response's
/// `hits.total` and every other list (observed 2026-10-09: 81k of 13M events).
/// Kept apart, that shard can only cost the providers list its own
/// documents, never the totals or the other nine lists.
pub fn provider_body(filters: Vec<Value>) -> Value {
    json!({
        "size": 0,
        "track_total_hits": false,
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}},
        "aggs": {"providers": terms("source.as.type", FACET_LIMIT)}
    })
}

/// The unfiltered explorer's query: no filter parameter, so only its
/// default window (`events::build_filters`).
fn default_query() -> EventsQuery {
    serde_json::from_value(json!({})).expect("every EventsQuery field is optional")
}

/// [`facet_body`] of the unfiltered explorer, which the worker snapshots.
pub(crate) fn default_facet_body() -> Value {
    facet_body(build_filters(&default_query()))
}

/// [`provider_body`] of the unfiltered explorer, which the worker snapshots.
pub(crate) fn default_provider_body() -> Value {
    provider_body(build_filters(&default_query()))
}

fn bucket_value(bucket: &Value) -> String {
    let key = &bucket["key"];
    match key {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn parse_list(aggs: &Value, name: &str, keep: impl Fn(&str) -> bool, limit: usize) -> Vec<FacetValue> {
    aggs[name]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let value = bucket_value(bucket);
            let count = bucket["doc_count"].as_u64().unwrap_or(0);
            (!value.trim().is_empty() && count > 0 && keep(&value)).then_some(FacetValue { value, count })
        })
        .take(limit)
        .collect()
}

/// Maps the two ES aggregation responses (`facet_body`, `provider_body`) to
/// the wire shape.
pub fn parse_facets(kind: &str, result: &Value, provider_result: &Value) -> Facets {
    let aggs = &result["aggregations"];
    let any = |_: &str| true;
    Facets {
        kind: kind.to_string(),
        total: result["hits"]["total"]["value"].as_u64().unwrap_or(0),
        sensors: parse_list(aggs, "sensors", any, FACET_LIMIT),
        sources: parse_list(aggs, "sources", |ip| !is_fleet_address(ip), FACET_LIMIT),
        countries: parse_list(aggs, "countries", any, COUNTRY_LIMIT),
        protocols: parse_list(aggs, "protocols", any, FACET_LIMIT),
        ports: parse_list(aggs, "ports", any, FACET_LIMIT),
        signatures: parse_list(aggs, "signatures", any, FACET_LIMIT),
        kinds: parse_list(aggs, "kinds", any, FACET_LIMIT),
        personas: parse_list(aggs, "personas", any, FACET_LIMIT),
        providers: parse_list(&provider_result["aggregations"], "providers", any, FACET_LIMIT),
        cities: parse_list(aggs, "cities", any, FACET_LIMIT),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/facets/{kind}",
    summary = "Counted value lists for the filter pickers.",
    description = "Top values (with event counts) for sensors, sources, countries, protocols, ports, signatures, kinds, personas, providers and cities, over the same events and filters `/api/v1/events` lists. `kind` is the facet family; only `events` exists. Accepts every `/api/v1/events` filter parameter (`since`, `ip`, `sensor`, `country`, `proto`, `port`, ...); paging parameters are ignored.",
    params(
        ("kind" = inline(String), Path, description = "Facet family. Only `events` is served."),
        ("ip" = inline(Option<String>), Query, description = "Single source address."),
        ("ips" = inline(Option<String>), Query, description = "Comma-separated source addresses."),
        ("sensor" = inline(Option<String>), Query, description = "Sensor name."),
        ("country" = inline(Option<String>), Query, description = "ISO country code."),
        ("city" = inline(Option<String>), Query, description = "City name."),
        ("port" = inline(Option<String>), Query, description = "Destination port."),
        ("proto" = inline(Option<String>), Query, description = "Transport protocol."),
        ("kind" = inline(Option<String>), Query, description = "honeypot.event kind filter."),
        ("shasum" = inline(Option<String>), Query, description = "Captured-payload hash."),
        ("community_id" = inline(Option<String>), Query, description = "One flow across every sensor."),
        ("q" = inline(Option<String>), Query, description = "Free-text query_string."),
        ("since" = inline(Option<String>), Query, description = "Go-style relative window (24h, 7d); defaults to 10d like the explorer."),
        ("persona" = inline(Option<String>), Query, description = "Decoy persona id."),
        ("site" = inline(Option<String>), Query, description = "Decoy site id."),
        ("asset" = inline(Option<String>), Query, description = "Decoy asset id."),
        ("fingerprint" = inline(Option<String>), Query, description = "Client fingerprint."),
        ("cmd" = inline(Option<String>), Query, description = "Exact command text."),
        ("cred" = inline(Option<String>), Query, description = "\"user / pass\" pair."),
        ("path" = inline(Option<String>), Query, description = "Request path."),
        ("session" = inline(Option<String>), Query, description = "Session id."),
        ("asn" = inline(Option<String>), Query, description = "Source AS number."),
        ("org" = inline(Option<String>), Query, description = "Source network organization."),
        ("provider" = inline(Option<String>), Query, description = "Provider class."),
        ("sig" = inline(Option<String>), Query, description = "IDS alert signature."),
        ("cat" = inline(Option<String>), Query, description = "Detection category."),
    ),
    responses(
        (status = 200, description = "Success: `{kind, total, sensors, sources, countries, protocols, ports, signatures, kinds, personas, providers, cities}`, each list `[{value, count}]`.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn get(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Facets>, (StatusCode, String)> {
    if kind != "events" {
        return Err((StatusCode::NOT_FOUND, format!("unknown facet kind {kind:?}; only \"events\" is served")));
    }
    let filters = build_filters(&q);
    let indices = facet_indices(&q);
    let body = facet_body(filters.clone());
    let providers_body = provider_body(filters);
    // #3910: the unfiltered explorer (its default window, no filter) is the
    // worker's snapshot of exactly these two requests (`page_rollup`) while
    // recent; any filtered request differs from them and stays live.
    let (snapshot, providers_snapshot) = tokio::join!(
        crate::page_rollup::read_matching(&state, crate::page_rollup::FACETS_EVENTS, indices, &body),
        crate::page_rollup::read_matching(&state, crate::page_rollup::FACETS_EVENTS_PROVIDERS, indices, &providers_body),
    );
    let (result, providers) = tokio::join!(
        async {
            match snapshot {
                Some(snapshot) => Ok(snapshot),
                None => state.es.search_index(indices, body).await,
            }
        },
        async {
            match providers_snapshot {
                Some(snapshot) => Ok(snapshot),
                None => state.es.search_index(indices, providers_body).await,
            }
        },
    );
    let result = result.map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    // A failed providers query degrades to an empty list, not a failed page.
    let providers = providers.unwrap_or_else(|error| {
        tracing::warn!(%error, "facets: providers query failed");
        Value::Null
    });
    Ok(Json(parse_facets(&kind, &result, &providers)))
}

/// Which indices a facet request counts over (#3908).
///
/// The unnarrowed explorer is a fleet-wide view, so its facets skip Zeek's
/// per-PDU Modbus log (`es::EVENT_INDICES_AGG`): 59 % of all events, from a
/// few dozen pollers, which made every picker list Modbus first and cost
/// 5-8 s per load. Once the explorer is narrowed to one source (`ip`,
/// `ips`), one flow (`community_id`) or a Zeek sensor, the facets read the
/// full set again: those filters are cheap, and they are exactly the views
/// where the PDUs are what the operator came to look at.
fn facet_indices(q: &EventsQuery) -> &'static [&'static str] {
    let set = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.trim().is_empty());
    let zeek_sensor = q
        .sensor
        .as_deref()
        .is_some_and(|sensors| sensors.split(',').any(|sensor| sensor.trim().starts_with("zeek")));
    if set(&q.ip) || set(&q.ips) || set(&q.community_id) || zeek_sensor {
        crate::es::EVENT_INDICES
    } else {
        crate::es::EVENT_INDICES_AGG
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(since: &str, sensor: Option<&str>) -> EventsQuery {
        serde_json::from_value(json!({"since": since, "sensor": sensor})).unwrap()
    }

    #[test]
    fn the_body_uses_the_explorers_filters_and_exclusions() {
        let body = facet_body(build_filters(&query("7d", Some("honeypot.cowrie"))));
        let filters = body["query"]["bool"]["filter"].as_array().unwrap();
        assert!(filters.contains(&json!({"range": {"@timestamp": {"gte": "now-7d"}}})));
        assert!(filters.contains(&json!({"term": {"event.sensor": "honeypot.cowrie"}})));
        let must_not = body["query"]["bool"]["must_not"].as_array().unwrap();
        assert!(must_not.contains(&json!({"term": {"honeypot.internal_probe": true}})));
        assert_eq!(body["size"], 0);
        assert_eq!(body["aggs"]["signatures"]["terms"]["field"], "suricata.eve.alert.signature.keyword");
        assert_eq!(body["aggs"]["kinds"]["terms"]["field"], "honeypot.event");
        assert_eq!(body["aggs"].as_object().unwrap().len(), 9);
        let providers = provider_body(build_filters(&query("7d", None)));
        assert_eq!(providers["aggs"]["providers"]["terms"]["field"], "source.as.type");
        assert_eq!(providers["query"]["bool"]["must_not"], body["query"]["bool"]["must_not"]);
    }

    #[test]
    fn parse_maps_buckets_and_drops_blanks_and_fleet_sources() {
        let result = json!({
            "hits": {"total": {"value": 42}},
            "aggregations": {
                "sensors": {"buckets": [{"key": "suricata", "doc_count": 30}, {"key": "honeypot.cowrie", "doc_count": 12}]},
                "sources": {"buckets": [
                    {"key": "10.8.0.1", "doc_count": 99},
                    {"key": "203.0.113.9", "doc_count": 7}
                ]},
                "ports": {"buckets": [{"key": 22, "doc_count": 5}, {"key": 23, "doc_count": 0}]},
                "countries": {"buckets": [{"key": "", "doc_count": 3}, {"key": "DE", "doc_count": 2}]}
            }
        });
        let f = parse_facets("events", &result, &json!({"aggregations": {"providers": {"buckets": [{"key": "cloud:aws", "doc_count": 4}]}}}));
        assert_eq!(f.total, 42);
        assert_eq!(f.sensors[0], FacetValue { value: "suricata".into(), count: 30 });
        assert_eq!(f.sources, vec![FacetValue { value: "203.0.113.9".into(), count: 7 }]);
        assert_eq!(f.ports, vec![FacetValue { value: "22".into(), count: 5 }]);
        assert_eq!(f.countries, vec![FacetValue { value: "DE".into(), count: 2 }]);
        assert_eq!(f.providers, vec![FacetValue { value: "cloud:aws".into(), count: 4 }]);
        assert!(f.signatures.is_empty() && f.cities.is_empty());
    }

    #[test]
    fn an_empty_response_parses_to_empty_lists() {
        let f = parse_facets("events", &json!({}), &json!({}));
        assert_eq!(f.total, 0);
        assert!(f.sensors.is_empty() && f.kinds.is_empty());
    }

    #[test]
    fn sources_are_truncated_after_the_fleet_filter() {
        let buckets: Vec<Value> = (0..200)
            .map(|i| json!({"key": format!("198.51.100.{}", i % 250), "doc_count": 200 - i}))
            .collect();
        let f = parse_facets("events", &json!({"aggregations": {"sources": {"buckets": buckets}}}), &Value::Null);
        assert_eq!(f.sources.len(), FACET_LIMIT);
    }

    #[test]
    fn fleet_facets_skip_modbus_detail_but_narrowed_ones_do_not() {
        let q = |v: Value| -> EventsQuery { serde_json::from_value(v).unwrap() };
        assert_eq!(facet_indices(&q(json!({"since": "24h"}))), crate::es::EVENT_INDICES_AGG);
        assert_eq!(facet_indices(&q(json!({"since": "24h", "sensor": "cowrie"}))), crate::es::EVENT_INDICES_AGG);
        assert_eq!(facet_indices(&q(json!({"since": "24h", "ip": ""}))), crate::es::EVENT_INDICES_AGG);
        for narrowed in [
            json!({"ip": "203.0.113.7"}),
            json!({"ips": "203.0.113.7,198.51.100.2"}),
            json!({"community_id": "1:abc="}),
            json!({"sensor": "zeek"}),
            json!({"sensor": "cowrie,zeek-proxy"}),
        ] {
            assert_eq!(facet_indices(&q(narrowed.clone())), crate::es::EVENT_INDICES, "{narrowed}");
        }
    }
}
