//! /api/v1/sensors — the per-sensor detail view (#1538), ported from
//! sensor_detail.go 1:1: mailoney SMTP conversations grouped by
//! session_id, http-honeypot and tanner raw per-request fields (the data
//! classify.go deliberately collapses into one-line summaries). Same
//! caps and 48h window as the Go loaders.

use crate::contract;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::secrets_boundary;
use crate::AppState;

const RAW_EVENT_CAP: u64 = 3000;
const MAILONEY_SESSION_CAP: usize = 150;
const REQUEST_CAP: usize = 300;
const WINDOW: &str = "now-48h";

#[derive(Serialize, Default, Clone)]
pub struct MailoneySession {
    pub session_id: String,
    pub when: String,
    pub ip: String,
    pub port: u64,
    pub logged_in: bool,
    pub user: String,
    pub pass: String,
    pub mail_from: Vec<String>,
    pub rcpt_to: Vec<String>,
    pub body_size: u64,
    pub truncated: bool,
    pub body_path: String,
    pub body_preview: String,
}

#[derive(Serialize, Default)]
pub struct HttpRequest {
    /// The document id, so the row can open its own full page (#1868).
    pub id: String,
    pub when: String,
    pub ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub user_agent: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub username: String,
    /// #3213: `password` is GONE from this response, not blanked. An
    /// always-empty `password` key is still a field a consumer can be told to
    /// read, and the issue's acceptance criteria are about what this API
    /// returns. `username` stays: an account identifier is the analytic value
    /// -- a spray is a spray of accounts -- and it is not a secret.
    ///
    /// The three axes below replace it, and each answers a different
    /// question: whether a credential was there, whether we could parse it,
    /// and whether the authentication that followed was real. They are
    /// distinct on purpose -- "there was one and we could not read it" is not
    /// "there was none", and a simulated answer is not a real one.
    pub credential_status: String,
    /// `Option<bool>`, not `bool`: `None` is `unknown` and has to survive
    /// serialization as `null`, because a defaulted `false` would report a
    /// request we could not read as one that carried no credential.
    pub credential_present: Option<bool>,
    /// This fleet's own bait values were attempted. An ATTEMPT, matched
    /// against bait we generated -- not a vendor default list, and not a
    /// verdict that anything was accessed.
    pub credential_indicator_match: bool,
    pub auth_outcome: String,
    pub auth_type: String,
    pub status: u64,
    pub category: String,
    pub tarpitted: bool,
    pub tarpit_bytes: u64,
    pub tarpit_ms: u64,
}

#[derive(Serialize, Default)]
pub struct TannerRequest {
    /// The document id, so the row can open its own full page (#1868).
    pub id: String,
    pub when: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub headers: HashMap<String, String>,
    pub username: String,
    pub password: String,
    pub tarpitted: bool,
    pub tarpit_bytes: u64,
    pub tarpit_ms: u64,
    pub post_data: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub detection_name: String,
    pub detection_payload: String,
}

#[derive(Serialize)]
pub struct SensorDetail {
    pub mailoney: Vec<MailoneySession>,
    pub http_requests: Vec<HttpRequest>,
    pub tanner: Vec<TannerRequest>,
}

fn s(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn n(value: &Value) -> u64 {
    value.as_u64().unwrap_or_else(|| value.as_f64().unwrap_or(0.0).max(0.0) as u64)
}

/// Headers object → lowercase-keyed string map (headerMap in Go).
fn header_map(value: &Value) -> HashMap<String, String> {
    value
        .as_object()
        .map(|object| object.iter().map(|(k, v)| (k.to_lowercase(), s(v))).collect())
        .unwrap_or_default()
}

/// Plain string map, key case preserved (stringMap in Go — tanner
/// post_data/cookies keys are attacker-controlled and case-significant).
fn string_map(value: &Value) -> HashMap<String, String> {
    value
        .as_object()
        .map(|object| object.iter().map(|(k, v)| (k.clone(), s(v))).collect())
        .unwrap_or_default()
}

async fn query_sensor_raw(state: &AppState, sensor: &str, desc: bool) -> anyhow::Result<Vec<Value>> {
    let body = json!({
        "size": RAW_EVENT_CAP,
        "sort": [{"@timestamp": {"order": if desc { "desc" } else { "asc" }}}],
        "query": {"bool": {"filter": [
            {"term": {"event.sensor": sensor}},
            {"range": {"@timestamp": {"gte": WINDOW}}}
        ]}}
    });
    let result = state.es.search_index(&["honeypot-v2-*"], body).await?;
    Ok(result["hits"]["hits"].as_array().cloned().unwrap_or_default())
}

fn mailoney_sessions(hits: &[Value]) -> Vec<MailoneySession> {
    let empty = Map::new();
    let mut order: Vec<String> = Vec::new();
    let mut by_session: HashMap<String, MailoneySession> = HashMap::new();
    for hit in hits {
        let source = &hit["_source"];
        let event = source["honeypot"].as_object().unwrap_or(&empty);
        let sid = s(&event.get("session_id").cloned().unwrap_or(Value::Null));
        if sid.is_empty() {
            continue;
        }
        let session = by_session.entry(sid.clone()).or_insert_with(|| {
            order.push(sid.clone());
            MailoneySession {
                session_id: sid.clone(),
                ip: s(&event.get("src_ip").cloned().unwrap_or(Value::Null)),
                port: n(&event.get("src_port").cloned().unwrap_or(Value::Null)),
                ..Default::default()
            }
        });
        session.when = s(&source["@timestamp"]);
        let get = |key: &str| event.get(key).cloned().unwrap_or(Value::Null);
        match s(&get("event")).as_str() {
            "login" => {
                session.logged_in = true;
                session.user = s(&get("username"));
                session.pass = s(&get("password"));
            }
            "envelope" => {
                let command = s(&get("command")).trim().to_string();
                let lower = command.to_lowercase();
                if lower.starts_with("mail from") {
                    session.mail_from.push(command);
                } else if lower.starts_with("rcpt to") {
                    session.rcpt_to.push(command);
                }
            }
            "mail-body" => {
                session.body_size = n(&get("size"));
                session.truncated = get("truncated").as_bool().unwrap_or(false);
                session.body_path = s(&get("body_path"));
                session.body_preview = s(&get("body_preview"));
            }
            _ => {}
        }
    }
    let mut sessions: Vec<MailoneySession> =
        order.into_iter().filter_map(|sid| by_session.remove(&sid)).collect();
    sessions.sort_by(|a, b| b.when.cmp(&a.when));
    sessions.truncate(MAILONEY_SESSION_CAP);
    sessions
}

fn http_requests(hits: &[Value]) -> Vec<HttpRequest> {
    hits.iter()
        .filter_map(|hit| {
            let source = &hit["_source"];
            // #3213: the boundary runs on the way in, so the body and query
            // below are already redacted and `password` is already gone --
            // including for documents indexed before the sensors were fixed.
            let scrubbed = secrets_boundary::scrub_event("http-honeypot", &source["honeypot"]);
            let event = scrubbed.as_ref().unwrap_or(&source["honeypot"]);
            if !event.is_object() {
                return None;
            }
            Some(HttpRequest {
                id: s(&hit["_id"]),
                when: s(&source["@timestamp"]),
                ip: s(&event["src_ip"]),
                method: s(&event["method"]),
                host: s(&event["host"]),
                path: s(&event["path"]),
                query: s(&event["query"]),
                user_agent: s(&event["user_agent"]),
                headers: header_map(&event["headers"]),
                body: s(&event["body"]),
                username: s(&event["username"]),
                credential_status: s(&event["credential_status"]),
                // `as_bool().or(...)` would flatten a missing field into
                // `false`; this keeps "the sensor never said" as `None`.
                credential_present: event["credential_present"].as_bool(),
                credential_indicator_match: event["credential_indicator_match"].as_bool().unwrap_or(false),
                auth_outcome: s(&event["auth_outcome"]),
                auth_type: s(&event["auth_type"]),
                status: n(&event["status"]),
                category: s(&event["category"]),
                tarpitted: event["tarpitted"].as_bool().unwrap_or(false),
                tarpit_bytes: n(&event["tarpit_bytes"]),
                tarpit_ms: n(&event["tarpit_ms"]),
            })
        })
        .take(REQUEST_CAP)
        .collect()
}

fn tanner_requests(hits: &[Value]) -> Vec<TannerRequest> {
    hits.iter()
        .filter_map(|hit| {
            let source = &hit["_source"];
            let event = &source["honeypot"];
            if !event.is_object() {
                return None;
            }
            // Legacy "peer" session-report shape has no per-request fields;
            // startup markers are operational noise. Same skips as Go.
            if s(&event["method"]).is_empty() && s(&event["category"]).is_empty() {
                return None;
            }
            if s(&event["category"]) == "startup" {
                return None;
            }
            let headers = header_map(&event["headers"]);
            let header = |key: &str| headers.get(key).cloned().unwrap_or_default();
            // Real client IP from CF/proxy headers when fronted by Cloudflare,
            // same preference order as classify.go.
            let ip = [
                header("cf-connecting-ip"),
                header("x-real-ip"),
                header("x-forwarded-for").split(',').next().unwrap_or("").trim().to_string(),
                s(&event["src_ip"]),
            ]
            .into_iter()
            .find(|candidate| !candidate.is_empty())
            .unwrap_or_default();
            let detection = &event["response_msg"]["response"]["message"]["detection"];
            let mut payload = s(&detection["payload"]["value"]);
            if payload.len() > 1000 {
                let mut cut = 1000;
                while !payload.is_char_boundary(cut) {
                    cut -= 1;
                }
                payload.truncate(cut);
                payload.push_str("(...)");
            }
            Some(TannerRequest {
                id: s(&hit["_id"]),
                when: s(&source["@timestamp"]),
                ip,
                method: s(&event["method"]),
                path: s(&event["path"]),
                user_agent: header("user-agent"),
                headers,
                username: s(&event["username"]),
                password: s(&event["password"]),
                tarpitted: event["tarpitted"].as_bool().unwrap_or(false),
                tarpit_bytes: n(&event["tarpit_bytes"]),
                tarpit_ms: n(&event["tarpit_ms"]),
                post_data: string_map(&event["post_data"]),
                cookies: string_map(&event["cookies"]),
                detection_name: s(&detection["name"]),
                detection_payload: payload,
            })
        })
        .take(REQUEST_CAP)
        .collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/sensors",
    summary = "Per-sensor counts, last-seen, and state.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn detail(State(state): State<AppState>) -> Result<Json<SensorDetail>, (StatusCode, String)> {
    let (mailoney, http, tanner) = tokio::try_join!(
        query_sensor_raw(&state, "mailoney", false),
        query_sensor_raw(&state, "http-honeypot", true),
        query_sensor_raw(&state, "tanner", true),
    )
    .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(SensorDetail {
        mailoney: mailoney_sessions(&mailoney),
        http_requests: http_requests(&http),
        tanner: tanner_requests(&tanner),
    }))
}

// ---------------------------------------------------------------------------
// #1856: coverage.
//
// The three loaders above are bespoke views of three sensors. Twenty-six
// sensors produce events, so twenty-three of them had no detail view at
// all -- the page named "Sensor detail" simply did not know they existed.
//
// The fix is deliberately not a fourth, fifth and sixth hand-written
// loader. A hardcoded roster silently omits whatever is deployed next,
// which is the failure mode that produced this issue. Instead: the catalog
// is an aggregation, so every sensor that produces events appears by
// construction, and the events endpoint returns the sensor's own fields
// untouched, so the client can render a protocol in its own terms without
// the backend having to know the protocol.

/// The fleet checking its own sensors are alive is not attacker traffic.
///
/// #1902: 92,496 of these a day. They are marked, so they are recognisable
/// everywhere -- they were simply not excluded everywhere. Left in, the
/// catalog presented conpot-s7-1500 as the third-busiest sensor on the
/// fleet with 65,439 of its events being the fleet knocking on its own
/// door, which is a conclusion about attacker interest in an S7 PLC that
/// the data does not support.
///
/// Several marks, because the sensors do not agree on one. A honeypot
/// sensor sets the probe flag, or sources from loopback when it does not.
/// zeek-proxy sets neither -- it observes the wire and has no notion of a
/// probe -- but it says something stronger: local_orig and local_resp
/// together mean both ends of the connection are ours, which no attacker
/// traffic can ever be. And the dashboard's own healthcheck announces
/// itself outright as a GET of /healthz.
///
/// dashboard.rs made the same choice on the honeypot side for the same
/// reason (#1677); this is the rest of it.
fn excluding_health_checks() -> Vec<Value> {
    vec![
        crate::es::internal_probe_exclusion(),
        json!({"term": {"honeypot.src_ip": "127.0.0.1"}}),
        // Both ends inside the fleet. Zeek's own judgement, from its
        // configured local networks, so it stays correct if the addressing
        // changes.
        json!({"bool": {"filter": [
            {"term": {"zeek.local_orig": true}},
            {"term": {"zeek.local_resp": true}}
        ]}}),
        json!({"term": {"zeek.uri": "/healthz"}}),
    ]
}

/// One sensor in the catalog, as the data says it exists.
#[derive(Serialize)]
pub struct SensorSummary {
    pub sensor: String,
    pub events: u64,
    pub last_seen: String,
}

#[derive(Serialize)]
pub struct SensorCatalog {
    pub window: String,
    pub sensors: Vec<SensorSummary>,
}

/// One event, with the sensor's own fields left as the sensor wrote them.
#[derive(Serialize)]
pub struct SensorEvent {
    /// The document id, so a row can link to its own full page (#1868).
    pub id: String,
    pub when: String,
    pub src_ip: String,
    pub src_port: u64,
    pub dst_port: u64,
    pub fields: Value,
}

#[derive(Serialize)]
pub struct SensorEvents {
    pub sensor: String,
    pub total: u64,
    pub rows: Vec<SensorEvent>,
}

/// How far back the catalog looks. Wider than the per-sensor WINDOW on
/// purpose: a sensor that saw nothing in the last two days is quiet, not
/// absent, and dropping it from the list is how a roster goes stale
/// without anyone noticing.
const CATALOG_WINDOW: &str = "now-14d";
const EVENT_LIMIT_DEFAULT: u64 = 200;
const EVENT_LIMIT_MAX: u64 = 1000;

#[utoipa::path(
    get,
    path = "/api/v1/sensors/catalog",
    summary = "The sensor catalog the setup pages read.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn catalog(State(state): State<AppState>) -> Result<Json<SensorCatalog>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": CATALOG_WINDOW}}}],
            "must_not": excluding_health_checks()
        }},
        "aggs": {"sensors": {
            "terms": {"field": "event.sensor", "size": 200, "order": {"_count": "desc"}},
            "aggs": {"last_seen": {"max": {"field": "@timestamp"}}}
        }}
    });
    let result = state
        .es
        .search_index(&["honeypot-v2-*"], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let sensors = result["aggregations"]["sensors"]["buckets"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|bucket| {
            let sensor = s(&bucket["key"]);
            if sensor.is_empty() {
                return None;
            }
            Some(SensorSummary {
                sensor,
                events: n(&bucket["doc_count"]),
                // `value_as_string` is the ISO form; the bare `value` is
                // epoch millis, which is not what the client formats.
                last_seen: s(&bucket["last_seen"]["value_as_string"]),
            })
        })
        .collect();
    Ok(Json(SensorCatalog { window: CATALOG_WINDOW.to_string(), sensors }))
}

#[utoipa::path(
    get,
    path = "/api/v1/sensors/{sensor}/events",
    summary = "Recent events from one sensor.",
    params(
        ("sensor" = inline(contract::SensorName), Path, description = "Sensor name; the handler rejects an empty value or one over 128 characters."),
        ("limit" = inline(Option<String>), Query, description = "How many events to return; clamped by the handler."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn events(
    State(state): State<AppState>,
    axum::extract::Path(sensor): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<SensorEvents>, (StatusCode, String)> {
    let sensor = sensor.trim().to_string();
    if sensor.is_empty() || sensor.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "invalid sensor name".into()));
    }
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(EVENT_LIMIT_DEFAULT)
        .clamp(1, EVENT_LIMIT_MAX);

    let body = json!({
        "size": limit,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {
            "filter": [
                {"term": {"event.sensor": sensor}},
                {"range": {"@timestamp": {"gte": WINDOW}}}
            ],
            "must_not": excluding_health_checks()
        }}
    });
    let result = state
        .es
        .search_index(&["honeypot-v2-*"], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
    let rows = hits
        .iter()
        .map(|hit| {
            let source = &hit["_source"];
            let event = &source["honeypot"];
            SensorEvent {
                id: s(&hit["_id"]),
                when: s(&source["@timestamp"]),
                src_ip: s(&event["src_ip"]),
                src_port: n(&event["src_port"]),
                // Sensors disagree on the name of the port they listened
                // on: dst_port for the network-shaped ones, plain port for
                // the Go ones. Both mean the same thing to a reader.
                dst_port: {
                    let dst = n(&event["dst_port"]);
                    if dst > 0 { dst } else { n(&event["port"]) }
                },
                fields: event.clone(),
            }
        })
        .collect();
    Ok(Json(SensorEvents {
        sensor,
        total: n(&result["hits"]["total"]["value"]),
        rows,
    }))
}

// ---------------------------------------------------------------------------
// #1887: what one sensor has been doing.
//
// The fleet overview counts every sensor's events the same way, which says
// nothing about what any one of them is for. A tarpit whose whole job is
// holding a connection for hours -- observed at 26 and 60 hours, single
// connections swallowing 500 MB -- is indistinguishable there from a sensor
// that answers a request and closes.
//
// So the leaderboards are the sensor's own. An HTTP sensor is asked for
// paths, an SSH sensor is given commands, a VoIP sensor is asked to call
// numbers, an ICS sensor receives function codes. Showing all of them the
// same five fields would be the fleet overview again, one level down.

/// One leaderboard: what this sensor saw most of, under its own name.
#[derive(Serialize)]
pub struct TopList {
    /// What the list is, in the sensor's terms ("paths requested").
    pub label: String,
    pub rows: Vec<SensorSummaryRow>,
}

#[derive(Serialize)]
pub struct SensorSummaryRow {
    pub key: String,
    pub count: u64,
}

/// A quantity the sensor measures that most sensors do not -- a tarpit's
/// held time and swallowed bytes, a session's duration.
#[derive(Serialize)]
pub struct SensorMeasure {
    pub label: String,
    pub total: f64,
    pub max: f64,
    /// How to render it: "duration_ms", "duration_s", "bytes" or "count".
    pub unit: String,
}

#[derive(Serialize)]
pub struct SensorOverview {
    pub sensor: String,
    pub window: String,
    pub events: u64,
    pub unique_sources: u64,
    pub first_seen: String,
    pub last_seen: String,
    /// Events per hour, oldest first, for the activity chart.
    pub hourly: Vec<u64>,
    pub top_sources: Vec<SensorSummaryRow>,
    pub top_countries: Vec<SensorSummaryRow>,
    /// The sensor's own leaderboards.
    pub top_lists: Vec<TopList>,
    /// The sensor's own units, where it has any.
    pub measures: Vec<SensorMeasure>,
}

/// Which `honeypot.*` fields make a leaderboard for this sensor, and what
/// to call each one.
///
/// Field names come from the shipped documents rather than the sensors'
/// documentation, same as lib/sensorProtocols.ts on the client -- several
/// sensors disagree with their own docs about what they emit.
fn top_fields_for(sensor: &str) -> Vec<(&'static str, &'static str)> {
    let http = vec![
        ("honeypot.path", "paths requested"),
        ("honeypot.user_agent", "user agents"),
        ("honeypot.method", "methods"),
    ];
    match sensor {
        "cowrie" => vec![
            ("honeypot.canonical_command", "commands run"),
            ("honeypot.canonical_user", "usernames tried"),
            ("honeypot.canonical_pass", "passwords tried"),
        ],
        "sentrypeer" => vec![
            ("honeypot.called_number", "numbers called"),
            ("honeypot.sip_method", "SIP methods"),
            ("honeypot.sip_user_agent", "SIP user agents"),
        ],
        "dionaea" => vec![
            ("honeypot.origin", "what happened"),
            ("honeypot.connection.protocol", "services reached"),
        ],
        "dns-honeypot" => vec![
            ("honeypot.query", "names queried"),
            ("honeypot.qtype", "record types"),
        ],
        "dnp3" => vec![
            ("honeypot.function", "function codes"),
            ("honeypot.app_function", "application functions"),
        ],
        "rdp-honeypot" => vec![
            ("honeypot.canonical_user", "usernames tried"),
            ("honeypot.canonical_pass", "passwords tried"),
            ("honeypot.requested_protocols", "protocols requested"),
        ],
        "dicompot" => vec![
            ("honeypot.calling_ae", "calling AE titles"),
            ("honeypot.called_ae", "called AE titles"),
        ],
        "canarytokens" => vec![
            ("honeypot.token_type", "token types"),
            ("honeypot.memo", "tokens fired"),
        ],
        "mailoney" => vec![("honeypot.command", "SMTP commands")],
        "multipot" => vec![
            ("honeypot.proto", "protocols"),
            ("honeypot.event", "what happened"),
        ],
        s if s.starts_with("conpot") => vec![
            ("honeypot.event_type", "what happened"),
            ("honeypot.data_type", "protocols"),
        ],
        "hellpot" | "http-honeypot" | "tanner" | "galah" | "wordpot" | "api-honeypot"
        | "citrix-honeypot" | "cisco-asa-honeypot" | "snare" | "elasticpot" => http,
        // Unrecognised: the fields nearly every sensor has, which is more
        // than nothing and is honest about being generic.
        _ => vec![
            ("honeypot.event", "what happened"),
            ("honeypot.path", "paths requested"),
        ],
    }
}

/// Quantities worth summing for this sensor, with how to render them.
fn measures_for(sensor: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    match sensor {
        // A tarpit is measured by what it wasted, not by how many events it
        // logged. This is the whole point of running one.
        "hellpot" => vec![
            ("honeypot.DURATION", "time held", "duration_s"),
            ("honeypot.BYTES", "bytes swallowed", "bytes"),
        ],
        "endlessh" => vec![
            ("honeypot.held_ms", "time held", "duration_ms"),
            ("honeypot.lines", "banner lines sent", "count"),
        ],
        "cowrie" => vec![("honeypot.duration_ms", "session time", "duration_ms")],
        "http-honeypot" | "tanner" | "api-honeypot" => vec![
            ("honeypot.tarpit_ms", "time held", "duration_ms"),
            ("honeypot.tarpit_bytes", "bytes swallowed", "bytes"),
        ],
        "mailoney" => vec![("honeypot.size", "mail body bytes", "bytes")],
        _ => vec![],
    }
}

const OVERVIEW_WINDOW: &str = "now-7d";

/// #3827: `honeypot` is mapped `flattened` in every honeypot-v2 backing
/// index, so a `stats` aggregation straight on `honeypot.<measure>` is
/// refused ("not supported for aggregation [stats]") and took the whole
/// overview down with a 502. Each measure is read instead through a
/// `double` runtime field that parses the keyed leaf's doc value (a
/// flattened leaf is stored as a keyword), inside a `filter: exists`
/// sub-aggregation so the script only runs on documents that carry the
/// field. Measured live on the cowrie 7-day window (9.4 M events, 1.66 M
/// with `duration_ms`): 0.75-1.3 s. A value that does not parse as a
/// number is skipped, not counted as zero.
///
/// Returns the runtime mappings and the `measure_{index}` aggregations;
/// the stats sit under each aggregation's `stats` key.
fn measure_aggregations(sensor: &str) -> (serde_json::Map<String, Value>, Vec<(String, Value)>) {
    const PARSE_KEYED_NUMBER: &str = "if (!doc.containsKey(params.field)) { return; } \
        def values = doc[params.field]; \
        if (values.size() > 0) { try { emit(Double.parseDouble(values.value)); } catch (NumberFormatException e) {} }";
    let mut runtime = serde_json::Map::new();
    let mut aggs = Vec::new();
    for (index, (field, _, _)) in measures_for(sensor).iter().enumerate() {
        let name = format!("measure_{index}");
        runtime.insert(
            name.clone(),
            json!({"type": "double", "script": {"source": PARSE_KEYED_NUMBER, "params": {"field": field}}}),
        );
        aggs.push((
            name.clone(),
            json!({
                "filter": {"exists": {"field": field}},
                "aggs": {"stats": {"stats": {"field": name}}}
            }),
        ));
    }
    (runtime, aggs)
}

#[utoipa::path(
    get,
    path = "/api/v1/sensors/{sensor}/overview",
    summary = "Protocols, ports and fingerprints for one sensor.",
    params(
        ("sensor" = inline(contract::SensorName), Path, description = "Sensor name; the handler rejects an empty value or one over 128 characters."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn overview(
    State(state): State<AppState>,
    axum::extract::Path(sensor): axum::extract::Path<String>,
) -> Result<Json<SensorOverview>, (StatusCode, String)> {
    let sensor = sensor.trim().to_string();
    if sensor.is_empty() || sensor.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "invalid sensor name".into()));
    }

    let mut aggs = json!({
        "unique_sources": {"cardinality": {"field": "source.ip"}},
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
        "hourly": {"date_histogram": {
            "field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
            "extended_bounds": {"min": "now-7d/h", "max": "now/h"}
        }},
        "top_sources": {"terms": {"field": "source.ip", "size": 10}},
        "top_countries": {"terms": {"field": "source.geo.country_iso_code", "size": 10}},
    });

    for (index, (field, _)) in top_fields_for(&sensor).iter().enumerate() {
        aggs[format!("top_{index}")] = json!({"terms": {"field": field, "size": 10}});
    }
    let (runtime, measure_aggs) = measure_aggregations(&sensor);
    for (name, agg) in measure_aggs {
        aggs[name] = agg;
    }

    let mut body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"bool": {
            "filter": [
                {"term": {"event.sensor": sensor}},
                {"range": {"@timestamp": {"gte": OVERVIEW_WINDOW}}}
            ],
            "must_not": excluding_health_checks()
        }},
        "aggs": aggs
    });
    if !runtime.is_empty() {
        body["runtime_mappings"] = Value::Object(runtime);
    }
    let result = state
        .es
        .search_index(&["honeypot-v2-*"], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let a = &result["aggregations"];

    let rows_of = |node: &Value| -> Vec<SensorSummaryRow> {
        node["buckets"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|bucket| {
                let key = match &bucket["key"] {
                    Value::String(text) => text.clone(),
                    other if !other.is_null() => other.to_string(),
                    _ => return None,
                };
                if key.is_empty() {
                    return None;
                }
                Some(SensorSummaryRow { key, count: n(&bucket["doc_count"]) })
            })
            .collect()
    };

    let top_lists = top_fields_for(&sensor)
        .iter()
        .enumerate()
        .filter_map(|(index, (_, label))| {
            let rows = rows_of(&a[format!("top_{index}")]);
            // A leaderboard with nothing in it is noise, not information --
            // most sensors have no value for most of these fields.
            if rows.is_empty() {
                return None;
            }
            Some(TopList { label: (*label).to_string(), rows })
        })
        .collect();

    let measures = measures_for(&sensor)
        .iter()
        .enumerate()
        .filter_map(|(index, (_, label, unit))| {
            let stats = &a[format!("measure_{index}")]["stats"];
            let total = stats["sum"].as_f64().unwrap_or(0.0);
            if total <= 0.0 {
                return None;
            }
            Some(SensorMeasure {
                label: (*label).to_string(),
                total,
                max: stats["max"].as_f64().unwrap_or(0.0),
                unit: (*unit).to_string(),
            })
        })
        .collect();

    Ok(Json(SensorOverview {
        sensor,
        window: OVERVIEW_WINDOW.to_string(),
        events: n(&result["hits"]["total"]["value"]),
        unique_sources: n(&a["unique_sources"]["value"]),
        first_seen: s(&a["first"]["value_as_string"]),
        last_seen: s(&a["last"]["value_as_string"]),
        hourly: a["hourly"]["buckets"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|bucket| n(&bucket["doc_count"]))
            .collect(),
        top_sources: rows_of(&a["top_sources"]),
        top_countries: rows_of(&a["top_countries"]),
        top_lists,
        measures,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // #3827: no measure may aggregate `stats` straight on the flattened
    // `honeypot.*` namespace; each one goes through its runtime field.
    #[test]
    fn measures_aggregate_runtime_fields_never_the_flattened_leaf() {
        for sensor in ["cowrie", "hellpot", "endlessh", "http-honeypot", "tanner", "api-honeypot", "mailoney"] {
            let (runtime, aggs) = measure_aggregations(sensor);
            assert_eq!(runtime.len(), measures_for(sensor).len(), "{sensor}");
            assert_eq!(aggs.len(), measures_for(sensor).len(), "{sensor}");
            for ((name, agg), (field, _, _)) in aggs.iter().zip(measures_for(sensor)) {
                assert_eq!(agg["filter"]["exists"]["field"], field, "{sensor}");
                assert_eq!(agg["aggs"]["stats"]["stats"]["field"], name.as_str(), "{sensor}");
                assert!(!name.starts_with("honeypot."), "{sensor}");
                let mapping = &runtime[name];
                assert_eq!(mapping["type"], "double", "{sensor}");
                assert_eq!(mapping["script"]["params"]["field"], field, "{sensor}");
            }
        }
    }

    #[test]
    fn a_sensor_without_measures_adds_no_runtime_mappings() {
        let (runtime, aggs) = measure_aggregations("dionaea");
        assert!(runtime.is_empty());
        assert!(aggs.is_empty());
    }

    // #3213: `http_requests` is what the curated sensor view renders as the
    // HTTP request table, and it used to carry a `password` column holding
    // the captured value. The canary below stands in for that value; every
    // assertion is on the SERIALIZED response, because a field check by name
    // only covers the name someone thought to check.

    const SECRET: &str = "correct-horse-battery-staple-9f2c";

    fn stored_login() -> Value {
        json!({"_id": "e2e-1", "_source": {
            "@timestamp": "2026-09-01T00:00:00Z",
            "honeypot": {
                "sensor": "http-honeypot",
                "src_ip": "203.0.113.9",
                "method": "POST",
                "host": "portal.example",
                "path": "/wp-login.php",
                "query": format!("redirect_to=/wp-admin&password={SECRET}"),
                "body": format!("log=admin&pwd={SECRET}&wp-submit=Log+In"),
                "headers": {"authorization": format!("Basic YWRtaW46{SECRET}"), "user-agent": "curl/8.4.0"},
                "username": "admin",
                "password": SECRET
            }
        }})
    }

    fn rendered() -> String {
        serde_json::to_string(&http_requests(&[stored_login()])).unwrap()
    }

    #[test]
    fn a_stored_password_never_reaches_the_http_request_response() {
        let out = rendered();
        assert!(!out.contains(SECRET), "a stored password reached the sensor response: {out}");
    }

    #[test]
    fn the_password_field_is_gone_rather_than_empty() {
        // An always-present `password: ""` is still a field a consumer can be
        // told to read, and this issue's criteria are about what the API
        // returns rather than about what it declines to fill in.
        let out = rendered();
        assert!(!out.contains("\"password\""), "the password key survived as an empty field: {out}");
    }

    #[test]
    fn the_request_stays_readable_after_the_scrub() {
        // The other failure mode: deleting the body because it held a
        // secret. Method, host, path, user agent and the account all have to
        // survive, or the table becomes a list of blanks.
        let rows = http_requests(&[stored_login()]);
        let row = &rows[0];
        assert_eq!(row.method, "POST");
        assert_eq!(row.host, "portal.example");
        assert_eq!(row.path, "/wp-login.php");
        assert_eq!(row.username, "admin");
        assert_eq!(row.headers.get("user-agent").map(String::as_str), Some("curl/8.4.0"));
        assert!(row.body.contains("wp-submit=Log+In"), "the body lost its shape: {}", row.body);
        assert!(row.body.contains(&format!("pwd={}", crate::secrets_boundary::REDACT_MARKER)), "{}", row.body);
    }

    #[test]
    fn a_historical_request_reports_no_status_rather_than_reporting_absent() {
        // No `credential_status` on a pre-fix document. Reporting "absent"
        // would be reporting the scrubber's own removal as an observation
        // about the attacker, so the field is simply left empty -- which is
        // the one thing a consumer cannot mistake for an answer.
        let rows = http_requests(&[stored_login()]);
        assert_eq!(rows[0].credential_status, "", "a pre-fix document has no status to report");
        assert_eq!(rows[0].credential_present, None, "and no presence to report either");
    }

    #[test]
    fn the_new_axes_are_reported_independently() {
        let hit = json!({"_id": "e2e-2", "_source": {
            "@timestamp": "2026-09-01T00:00:00Z",
            "honeypot": {
                "method": "POST", "path": "/api/v1/login", "username": "admin",
                "credential_status": "extracted",
                "credential_present": true,
                "credential_indicator_match": true,
                "auth_type": "form",
                "auth_outcome": "simulated",
                "status": 200
            }
        }});
        let rows = http_requests(&[hit]);
        let row = &rows[0];
        assert_eq!(row.credential_status, "extracted");
        assert_eq!(row.credential_present, Some(true));
        assert!(row.credential_indicator_match);
        assert_eq!(row.auth_type, "form");
        assert_eq!(row.auth_outcome, "simulated");
        // The status is its own field and is NOT the auth answer. A 200 on a
        // login page has to stay a 200.
        assert_eq!(row.status, 200);
        assert_ne!(row.auth_outcome, "real");
    }

    #[test]
    fn an_unknown_presence_serializes_as_null() {
        // The wire form matters: `Option<bool>` has to reach the client as
        // `null` rather than being defaulted to false on the way out.
        let hit = json!({"_id": "e2e-3", "_source": {
            "@timestamp": "2026-09-01T00:00:00Z",
            "honeypot": {
                "method": "GET", "path": "/",
                "credential_status": "unknown",
                "credential_present": Value::Null,
                "auth_outcome": "unknown"
            }
        }});
        let out = serde_json::to_string(&http_requests(&[hit])).unwrap();
        assert!(out.contains("\"credential_present\":null"), "unknown collapsed into false: {out}");
    }

    #[test]
    fn a_tanner_request_is_untouched_by_this_boundary() {
        // tanner is out of #3213's scope, and this is the test that keeps
        // the scope a decision rather than an accident. `tanner_requests`
        // has no boundary call in it at all, so a future edit that widened
        // `CREDENTIAL_SENSORS` would not change this -- and one that wrongly
        // added a scrub to the shared helper would fail it.
        let hit = json!({"_id": "t-1", "_source": {
            "@timestamp": "2026-09-01T00:00:00Z",
            "honeypot": {"sensor": "tanner", "method": "POST", "path": "/index.php", "username": "root", "password": "toor"}
        }});
        let rows = tanner_requests(&[hit]);
        assert_eq!(rows[0].password, "toor", "tanner is out of scope and must not change behaviour here");
    }
}
