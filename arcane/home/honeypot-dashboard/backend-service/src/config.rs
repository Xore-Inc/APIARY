//! Dashboard config + users stores (settings subsystem, ported from
//! settings_store_es.go's ES-backed halves):
//! - GET /api/v1/config — the dashboard-config-v1 payload (presentation
//!   + behavior), driving branding text across the frontend.
//! - PUT /api/v1/config/presentation — replace the presentation block
//!   (revision+1); the BFF enforces the admin role before calling.
//! - PUT /api/v1/config/{section} for section in {honeypot, behavior,
//!   report-presets} — same shape as put_presentation, one level deeper:
//!   each replaces its own `payload.*` block (honeypot / behavior /
//!   report_presets respectively). Still deliberately JSON `Value`-level,
//!   not settings_admin_api.go's typed behaviorPatch/honeypotPatch +
//!   pinned-field + impact-classification machinery — see put_config_section.
//! - GET /api/v1/config/history, POST /api/v1/config/rollback (#1612) —
//!   revision history and restore, working at the JSON `Value` level like
//!   everything else here rather than porting settings_admin_api.go's full
//!   typed behavior/honeypot patch + pinned-field + impact-classification
//!   machinery, which nothing in this Rust tier writes yet.
//! - Optimistic concurrency (#1653, ported from settings_store_es.go's
//!   errStaleRevision flow): GET /api/v1/config returns the document's
//!   monotonic `revision`; every write endpoint accepts an optional
//!   `If-Match: <revision>` header and answers 409 when it no longer
//!   matches the stored revision — carrying the stored `X-Current-Revision`
//!   so a stale client can re-sync directly (#2496). A missing header
//!   (or `*`) keeps the legacy last-write-wins behavior so existing
//!   callers stay working.
//! - POST /api/v1/config/validate — persist-nothing preview mirroring Go's
//!   /api/settings/config/validate, scoped to what this Value-level tier
//!   actually constrains (see validate_config_patch).
//! - GET /api/v1/users — the known-operators roster (subjects, roles,
//!   seen timestamps; per-user preference blobs stay out of the list).

use crate::contract;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::config_history::HistoryEntry;
use crate::trust::ActorBinding;
use crate::AppState;

const CONFIG_INDEX: &str = "dashboard-config-v1";
const CONFIG_ID: &str = "config";
const USERS_INDEX: &str = "dashboard-users-v1";

pub(crate) async fn load_config(state: &AppState) -> anyhow::Result<Option<Value>> {
    if let Some(doc) = state.es.get_doc(CONFIG_INDEX, CONFIG_ID).await? {
        return Ok(Some(doc));
    }
    // The store may use a different doc id — fall back to the newest doc.
    let result = state
        .es
        .search_index(
            &[CONFIG_INDEX],
            json!({"size": 1, "sort": [{"revision": {"order": "desc", "unmapped_type": "long"}}]}),
        )
        .await?;
    Ok(result["hits"]["hits"].as_array().and_then(|hits| hits.first()).map(|hit| hit["_source"].clone()))
}

#[utoipa::path(
    get,
    path = "/api/v1/config",
    summary = "The whole operator-authored dashboard configuration.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn get_config(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = load_config(&state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"revision": 0, "payload": {}}));
    Ok(Json(doc))
}

/// settings_store.go's errStaleRevision message, verbatim — the frontend
/// keys its "reloaded latest values" recovery off a 409 status, but the
/// text should stay recognizable across the two tiers.
const STALE_REVISION: &str = "settings were modified concurrently; reload and retry";

/// Optional optimistic-concurrency precondition: `If-Match: <revision>`,
/// the integer revision from a prior GET /api/v1/config (a quoted or
/// `W/`-prefixed ETag-style form is tolerated). Absent header or `*`
/// means "no check" — the legacy last-write-wins path.
fn expected_revision(headers: &HeaderMap) -> Result<Option<u64>, (StatusCode, String)> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let raw = raw.to_str().unwrap_or("").trim();
    let raw = raw.strip_prefix("W/").unwrap_or(raw).trim_matches('"').trim();
    if raw.is_empty() || raw == "*" {
        return Ok(None);
    }
    raw.parse::<u64>().map(Some).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "If-Match must be a config revision number".into(),
        )
    })
}

/// The 409 decision itself: a caller-supplied expected revision that no
/// longer matches the stored document refuses the write; no expectation
/// (legacy callers) always passes.
fn check_revision(expected: Option<u64>, doc: &Value) -> Result<(), (StatusCode, String)> {
    match expected {
        Some(revision) if revision != doc["revision"].as_u64().unwrap_or(0) => {
            Err((StatusCode::CONFLICT, STALE_REVISION.into()))
        }
        _ => Ok(()),
    }
}

/// The stale-revision 409 as an actual response (#2496): the legacy text
/// stays verbatim in the body for tier-parity recognition, and the stored
/// document's current revision rides along as `X-Current-Revision` so a
/// stale client can rebase its next If-Match without refetching the whole
/// doc first.
fn conflict_response(doc: &Value) -> Response {
    let current = doc["revision"].as_u64().unwrap_or(0);
    (
        StatusCode::CONFLICT,
        [("x-current-revision", current.to_string())],
        STALE_REVISION.to_string(),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ActorQuery {
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

/// Shared write path for put_presentation and put_config_section: load or
/// default the doc, check the caller's expected revision (409 + a
/// "conflict" audit record on mismatch), splat `value` into
/// `payload.{payload_key}`, bump revision, persist, and record history +
/// audit trail.
async fn put_config_field(
    state: &AppState,
    binding: &ActorBinding,
    actor: ActorQuery,
    expected: Option<u64>,
    payload_key: &str,
    value: Value,
) -> Result<Response, (StatusCode, String)> {
    let (actor_subject, actor_username) = binding.bind_pair(&actor.actor_subject, &actor.actor_username)?;
    let actor = ActorQuery { actor_subject, actor_username };
    let mut doc = load_config(state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"schema_version": 4, "revision": 0, "payload": {}}));
    if check_revision(expected, &doc).is_err() {
        state.audit.log(AuditEvent {
            actor_subject: actor.actor_subject,
            actor_username: actor.actor_username,
            action: "config.update".into(),
            fields: vec![payload_key.to_string()],
            revision: doc["revision"].as_i64().unwrap_or(0),
            result: "conflict".into(),
            ..Default::default()
        });
        return Ok(conflict_response(&doc));
    }
    doc["payload"][payload_key] = value;
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    state
        .es
        .index_doc(CONFIG_INDEX, CONFIG_ID, doc.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let revision = doc["revision"].as_i64().unwrap_or(0);
    let fields = vec![payload_key.to_string()];
    state.config_history.append(HistoryEntry {
        revision,
        time: String::new(),
        actor_subject: actor.actor_subject.clone(),
        actor_username: actor.actor_username.clone(),
        action: "update".into(),
        fields: fields.clone(),
        payload: doc["payload"].clone(),
    });
    state.audit.log(AuditEvent {
        actor_subject: actor.actor_subject,
        actor_username: actor.actor_username,
        action: "config.update".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(doc).into_response())
}

#[utoipa::path(
    put,
    path = "/api/v1/config/presentation",
    summary = "Replace the presentation block (branding, theme, landing copy).",
    params(
        ("actor_subject" = inline(Option<String>), Query, description = "OIDC subject recorded on the audit/history entry."),
        ("actor_username" = inline(Option<String>), Query, description = "Operator name recorded on the audit/history entry."),
        ("If-Match" = inline(Option<String>), Header, description = "Optional optimistic-concurrency revision, as a weak ETag (`W/\"7\"`). A mismatch answers 409."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `serde_json::Value`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "The stored presentation block and its new revision."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn put_presentation(
    State(state): State<AppState>,
    binding: ActorBinding,
    Query(actor): Query<ActorQuery>,
    headers: HeaderMap,
    Json(presentation): Json<Value>,
) -> Result<Response, (StatusCode, String)> {
    if !presentation.is_object() {
        return Err((StatusCode::BAD_REQUEST, "presentation object required".into()));
    }
    let expected = expected_revision(&headers)?;
    put_config_field(&state, &binding, actor, expected, "presentation", presentation).await
}

/// URL section name -> `payload.*` key. Only these three are exposed here;
/// `presentation` keeps its own dedicated route/handler above.
fn config_section_key(section: &str) -> Option<&'static str> {
    match section {
        "honeypot" => Some("honeypot"),
        "behavior" => Some("behavior"),
        "report-presets" => Some("report_presets"),
        _ => None,
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/config/{section}",
    summary = "Replace one settings section.",
    params(
        ("section" = inline(contract::ConfigSection), Path, description = "Settings section to replace."),
        ("actor_subject" = inline(Option<String>), Query, description = "OIDC subject recorded on the audit/history entry."),
        ("actor_username" = inline(Option<String>), Query, description = "Operator name recorded on the audit/history entry."),
        ("If-Match" = inline(Option<String>), Header, description = "Optional optimistic-concurrency revision, as a weak ETag (`W/\"7\"`). A mismatch answers 409."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `serde_json::Value`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "The stored section and its new revision."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// PUT /api/v1/config/{section} — identical in shape to put_presentation,
/// just parameterized over which `payload.*` block it replaces. Backs the
/// three settings.tsx admin panes that were previously entirely missing
/// server-side storage: Honeypot operations (staged thresholds, applied on
/// the consuming services' next restart — this endpoint only stores the
/// values), Dashboard behavior (live global defaults + feature toggles),
/// and Report Studio presets (per-preset name/description override map,
/// keyed by template id — an arbitrary object, same as everywhere else in
/// this file that just round-trips whatever JSON `Value` it's given).
pub async fn put_config_section(
    State(state): State<AppState>,
    binding: ActorBinding,
    Path(section): Path<String>,
    Query(actor): Query<ActorQuery>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Result<Response, (StatusCode, String)> {
    let Some(payload_key) = config_section_key(&section) else {
        return Err((StatusCode::NOT_FOUND, "unknown config section".into()));
    };
    if !value.is_object() {
        return Err((StatusCode::BAD_REQUEST, format!("{payload_key} object required")));
    }
    let expected = expected_revision(&headers)?;
    put_config_field(&state, &binding, actor, expected, payload_key, value).await
}

#[utoipa::path(
    get,
    path = "/api/v1/config/history",
    summary = "The revision history the rollback picker reads (payloads excluded).",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
/// configHistoryView-equivalent: everything needed for review and rollback
/// selection, without the retained payload snapshot itself.
pub async fn history(State(state): State<AppState>) -> Json<Value> {
    let entries: Vec<Value> = state
        .config_history
        .read(crate::config_history::HISTORY_READ_LIMIT)
        .into_iter()
        .map(|entry| {
            json!({
                "revision": entry["revision"],
                "time": entry["time"],
                "actor_subject": entry["actor_subject"],
                "actor_username": entry["actor_username"],
                "action": entry["action"],
                "fields": entry["fields"],
            })
        })
        .collect();
    Json(json!({"entries": entries}))
}

#[derive(Deserialize)]
pub struct RollbackBody {
    revision: i64,
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/config/rollback",
    summary = "Restore a past configuration revision.",
    params(
        ("If-Match" = inline(Option<String>), Header, description = "Optional optimistic-concurrency revision, as a weak ETag (`W/\"7\"`). A mismatch answers 409."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `RollbackBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "The restored configuration and its new revision."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// Restores one retained revision's full payload as a NEW revision —
/// history is append-only, rollback never rewrites the past. Accepts the
/// same optional `If-Match: <revision>` precondition as the PUT handlers.
pub async fn rollback(
    State(state): State<AppState>,
    binding: ActorBinding,
    headers: HeaderMap,
    Json(mut body): Json<RollbackBody>,
) -> Result<Response, (StatusCode, String)> {
    (body.actor_subject, body.actor_username) = binding.bind_pair(&body.actor_subject, &body.actor_username)?;
    if body.revision < 0 {
        return Err((StatusCode::BAD_REQUEST, "a non-negative revision is required".into()));
    }
    let expected = expected_revision(&headers)?;
    let Some(entry) = state.config_history.find(body.revision) else {
        return Err((StatusCode::NOT_FOUND, "revision is no longer retained".into()));
    };
    let restored_payload = entry["payload"].clone();
    let mut doc = load_config(&state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"schema_version": 4, "revision": 0, "payload": {}}));
    if check_revision(expected, &doc).is_err() {
        state.audit.log(AuditEvent {
            actor_subject: body.actor_subject,
            actor_username: body.actor_username,
            action: "config.rollback".into(),
            fields: vec!["*".to_string()],
            revision: doc["revision"].as_i64().unwrap_or(0),
            result: "conflict".into(),
            ..Default::default()
        });
        return Ok(conflict_response(&doc));
    }
    doc["payload"] = restored_payload.clone();
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    state
        .es
        .index_doc(CONFIG_INDEX, CONFIG_ID, doc.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let revision = doc["revision"].as_i64().unwrap_or(0);
    let fields = vec!["*".to_string()];
    state.config_history.append(HistoryEntry {
        revision,
        time: String::new(),
        actor_subject: body.actor_subject.clone(),
        actor_username: body.actor_username.clone(),
        action: "rollback".into(),
        fields: fields.clone(),
        payload: restored_payload,
    });
    state.audit.log(AuditEvent {
        actor_subject: body.actor_subject,
        actor_username: body.actor_username,
        action: "config.rollback".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(doc).into_response())
}

#[utoipa::path(
    get,
    path = "/api/v1/users",
    summary = "Dashboard users, as the ES-side user store reports them.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn users(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(
            &[USERS_INDEX],
            json!({"size": 1, "sort": [{"revision": {"order": "desc", "unmapped_type": "long"}}]}),
        )
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .and_then(|hit| hit["_source"]["payload"]["users"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|user| {
            json!({
                "subject": user["subject"],
                "username": user["last_username"],
                "role": user["role_snapshot"],
                "first_seen_at": user["first_seen_at"],
                "last_seen_at": user["last_seen_at"],
            })
        })
        .collect();
    Ok(Json(json!({"users": rows})))
}

#[utoipa::path(
    post,
    path = "/api/v1/config/validate",
    summary = "Check a candidate configuration without storing it.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `serde_json::Value`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/config/validate — persist-nothing preview, mirroring Go's
/// serveSettingsConfigValidate at the depth this Value-level tier can
/// honestly claim: the body is an object of config sections (the same
/// shapes the PUT endpoints accept — presentation / behavior / honeypot /
/// report_presets), and the response is `{ok, problems: [..]}`. Only
/// fields present in the patch are checked; Go's typed impact
/// classification and environment-pin machinery have no equivalent here
/// (nothing in this tier pins fields), so `changes` is not reported.
pub async fn validate(Json(patch): Json<Value>) -> Result<Json<Value>, (StatusCode, String)> {
    let is_empty = patch.as_object().map(|obj| obj.is_empty()).unwrap_or(true);
    if !patch.is_object() || is_empty {
        return Err((StatusCode::BAD_REQUEST, "invalid or empty configuration patch".into()));
    }
    let problems = validate_config_patch(&patch);
    Ok(Json(json!({"ok": problems.is_empty(), "problems": problems})))
}

/// Field bounds ported from settings_domain.go's presentationTextLimits:
/// configurable copy is plain single-purpose text, not documents.
const PRESENTATION_TEXT_LIMITS: &[(&str, usize)] = &[
    ("brand_prefix", 20),
    ("app_name", 60),
    ("product_label", 30),
    ("dashboard_title", 80),
    ("dashboard_subtitle", 200),
    ("org_name", 80),
    ("overview_intro", 500),
    ("help_link_label", 40),
    ("banner_text", 280),
    ("footer_text", 200),
    ("ai_disclaimer", 300),
    ("privacy_notice", 300),
];

const REPORT_PRESET_NAME_LIMIT: usize = 80;
const REPORT_PRESET_DESCRIPTION_LIMIT: usize = 300;

fn has_control_chars(text: &str) -> bool {
    text.chars().any(|c| (c < '\u{20}' && c != '\n') || c == '\u{7f}')
}

/// Minimal Go-duration parser (settings_domain.go validates
/// honeypot.alert_cooldown with time.ParseDuration): concatenated
/// number+unit terms over ns/us/ms/s/m/h, returned as seconds.
fn parse_go_duration_seconds(value: &str) -> Option<f64> {
    let mut rest = value.trim();
    if rest.is_empty() {
        return None;
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let number: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let (factor, unit_len) = if rest.starts_with("ns") {
            (1e-9, 2)
        } else if rest.starts_with("us") {
            (1e-6, 2)
        } else if rest.starts_with("ms") {
            (1e-3, 2)
        } else if rest.starts_with('s') {
            (1.0, 1)
        } else if rest.starts_with('m') {
            (60.0, 1)
        } else if rest.starts_with('h') {
            (3600.0, 1)
        } else {
            return None;
        };
        total += number * factor;
        rest = &rest[unit_len..];
    }
    Some(total)
}

fn check_enum(
    section: &str,
    obj: &serde_json::Map<String, Value>,
    field: &str,
    allowed: &[&str],
    problems: &mut Vec<String>,
) {
    let Some(value) = obj.get(field) else { return };
    let ok = value.as_str().is_some_and(|v| allowed.contains(&v));
    if !ok {
        problems.push(format!("{section}.{field} must be one of {}", allowed.join(", ")));
    }
}

fn check_int_range(
    section: &str,
    obj: &serde_json::Map<String, Value>,
    field: &str,
    min: i64,
    max: i64,
    problems: &mut Vec<String>,
) {
    let Some(value) = obj.get(field) else { return };
    let ok = value.as_i64().is_some_and(|n| (min..=max).contains(&n));
    if !ok {
        problems.push(format!("{section}.{field} must be an integer between {min} and {max}"));
    }
}

fn check_number_range(
    section: &str,
    obj: &serde_json::Map<String, Value>,
    field: &str,
    min: f64,
    max: f64,
    problems: &mut Vec<String>,
) {
    let Some(value) = obj.get(field) else { return };
    let ok = value.as_f64().is_some_and(|n| n >= min && n <= max);
    if !ok {
        problems.push(format!("{section}.{field} must be between {min} and {max}"));
    }
}

fn check_int_subset(
    section: &str,
    obj: &serde_json::Map<String, Value>,
    field: &str,
    allowed: &[i64],
    problems: &mut Vec<String>,
) {
    let Some(value) = obj.get(field) else { return };
    let ok = value.as_array().is_some_and(|items| {
        !items.is_empty()
            && items
                .iter()
                .all(|item| item.as_i64().is_some_and(|n| allowed.contains(&n)))
    });
    if !ok {
        let list = allowed.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
        problems.push(format!("{section}.{field} must be a non-empty subset of {list}"));
    }
}

fn validate_presentation(p: &serde_json::Map<String, Value>, problems: &mut Vec<String>) {
    for (field, limit) in PRESENTATION_TEXT_LIMITS {
        let Some(value) = p.get(*field) else { continue };
        let Some(text) = value.as_str() else {
            problems.push(format!("presentation.{field} must be a string"));
            continue;
        };
        if text.chars().count() > *limit {
            problems.push(format!("presentation.{field} must be at most {limit} characters"));
        }
        if has_control_chars(text) {
            problems.push(format!("presentation.{field} must not contain control characters"));
        }
    }
    if p.get("app_name").is_some_and(|v| v.as_str() == Some("")) {
        problems.push("presentation.app_name must not be empty".into());
    }
    if let Some(url) = p.get("help_link_url") {
        let ok = url.as_str().is_some_and(|u| u.is_empty() || u.starts_with("https://"));
        if !ok {
            problems.push("presentation.help_link_url must be empty or an https:// URL".into());
        }
    }
    if let Some(severity) = p.get("banner_severity") {
        let ok = severity
            .as_str()
            .is_some_and(|s| matches!(s, "" | "info" | "success" | "warning" | "danger"));
        if !ok {
            problems.push("presentation.banner_severity must be empty, info, success, warning or danger".into());
        }
    }
    if let Some(expires) = p.get("banner_expires") {
        let ok = expires
            .as_str()
            .is_some_and(|s| s.is_empty() || chrono::DateTime::parse_from_rfc3339(s).is_ok());
        if !ok {
            problems.push("presentation.banner_expires must be RFC 3339 or empty".into());
        }
    }
}

fn validate_behavior(b: &serde_json::Map<String, Value>, problems: &mut Vec<String>) {
    check_enum("behavior", b, "default_time_window", &["1h", "6h", "24h", "7d", "30d"], problems);
    check_int_subset("behavior", b, "rows_per_page_options", &[10, 25, 50, 100], problems);
    check_int_range("behavior", b, "max_export_rows", 100, 100_000, problems);
    check_int_subset(
        "behavior",
        b,
        "refresh_interval_seconds_options",
        &[10, 15, 30, 60, 120, 300],
        problems,
    );
    check_int_range("behavior", b, "source_stale_minutes", 2, 120, problems);
    check_enum("behavior", b, "map_provider", &["osm"], problems);
}

fn validate_honeypot(h: &serde_json::Map<String, Value>, problems: &mut Vec<String>) {
    if let Some(cooldown) = h.get("alert_cooldown") {
        let ok = cooldown
            .as_str()
            .and_then(parse_go_duration_seconds)
            .is_some_and(|seconds| (300.0..=604_800.0).contains(&seconds));
        if !ok {
            problems.push("honeypot.alert_cooldown must be a duration between 5m and 168h".into());
        }
    }
    check_number_range("honeypot", h, "alert_campaign_score", 0.0, 100.0, problems);
    check_number_range("honeypot", h, "sandbox_alert_risk_score", 0.0, 100.0, problems);
    check_number_range("honeypot", h, "ml_alert_threshold", 0.5, 0.99, problems);
    check_int_range("honeypot", h, "yara_scan_interval_seconds", 300, 86_400, problems);
    check_int_range("honeypot", h, "yara_max_bytes", 1 << 20, 1 << 30, problems);
    check_int_range("honeypot", h, "payload_dedupe_interval_seconds", 300, 86_400, problems);
}

fn validate_report_presets(overrides: &serde_json::Map<String, Value>, problems: &mut Vec<String>) {
    let known: Vec<&str> = crate::reports_store::report_template_catalog()
        .into_iter()
        .map(|t| t.id)
        .collect();
    for (id, override_value) in overrides {
        if !known.contains(&id.as_str()) {
            problems.push(format!("report_presets has an unknown template id {id:?}"));
            continue;
        }
        let Some(preset) = override_value.as_object() else {
            problems.push(format!("report_presets.{id} must be an object"));
            continue;
        };
        for (field, limit) in
            [("name", REPORT_PRESET_NAME_LIMIT), ("description", REPORT_PRESET_DESCRIPTION_LIMIT)]
        {
            let Some(value) = preset.get(field) else { continue };
            let Some(text) = value.as_str() else {
                problems.push(format!("report_presets.{id}.{field} must be a string"));
                continue;
            };
            if text.chars().count() > limit {
                problems.push(format!("report_presets.{id}.{field} must be at most {limit} characters"));
            }
            if has_control_chars(text) {
                problems.push(format!("report_presets.{id}.{field} must not contain control characters"));
            }
        }
    }
}

/// Value-level port of settings_domain.go's validateConfig, restricted to
/// fields present in the patch (a preview validates what's about to be
/// saved, not the whole stored document this tier treats as opaque).
fn validate_config_patch(patch: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(sections) = patch.as_object() else {
        return vec!["configuration patch must be an object of sections".into()];
    };
    for (name, section_value) in sections {
        let section = match section_value.as_object() {
            Some(section) => section,
            None => {
                problems.push(format!("{name} must be an object"));
                continue;
            }
        };
        match name.as_str() {
            "presentation" => validate_presentation(section, &mut problems),
            "behavior" => validate_behavior(section, &mut problems),
            "honeypot" => validate_honeypot(section, &mut problems),
            "report_presets" | "report-presets" => validate_report_presets(section, &mut problems),
            other => problems.push(format!("unknown config section {other:?}")),
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // The 409 decision, tested at the function level: the HTTP handlers
    // need a live-ES AppState and this crate has no ES test seam, so the
    // concurrency check itself is the unit under test.
    #[test]
    fn stale_revision_is_a_conflict() {
        let doc = json!({"revision": 4, "payload": {}});
        let err = check_revision(Some(3), &doc).unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(err.1, STALE_REVISION);
        assert!(check_revision(Some(4), &doc).is_ok());
        assert!(check_revision(None, &doc).is_ok());
    }

    // The 409 response itself (#2496): the stored document's revision is
    // surfaced as X-Current-Revision beside the verbatim legacy text, so a
    // stale client (expected=3 vs stored=5) learns it must rebase onto 5.
    #[tokio::test]
    async fn conflict_response_carries_the_current_revision() {
        let doc = json!({"revision": 5, "payload": {}});
        assert!(check_revision(Some(3), &doc).is_err());
        assert!(check_revision(Some(5), &doc).is_ok(), "non-conflict behavior is unchanged");

        let response = conflict_response(&doc);
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers().get("x-current-revision").and_then(|v| v.to_str().ok()),
            Some("5")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], STALE_REVISION.as_bytes());
    }

    #[test]
    fn if_match_header_parses_plain_quoted_and_wildcard_forms() {
        let mut headers = HeaderMap::new();
        assert_eq!(expected_revision(&headers).unwrap(), None);
        headers.insert("if-match", HeaderValue::from_static("7"));
        assert_eq!(expected_revision(&headers).unwrap(), Some(7));
        headers.insert("if-match", HeaderValue::from_static("\"12\""));
        assert_eq!(expected_revision(&headers).unwrap(), Some(12));
        headers.insert("if-match", HeaderValue::from_static("W/\"3\""));
        assert_eq!(expected_revision(&headers).unwrap(), Some(3));
        headers.insert("if-match", HeaderValue::from_static("*"));
        assert_eq!(expected_revision(&headers).unwrap(), None);
        headers.insert("if-match", HeaderValue::from_static("not-a-revision"));
        assert_eq!(expected_revision(&headers).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_clean_patch_validates() {
        let patch = json!({
            "presentation": {"app_name": "APIARY", "banner_severity": "info", "help_link_url": ""},
            "behavior": {"default_time_window": "24h", "rows_per_page_options": [25, 50], "max_export_rows": 5000, "source_stale_minutes": 15, "map_provider": "osm"},
            "honeypot": {"alert_cooldown": "30m", "alert_campaign_score": 70, "ml_alert_threshold": 0.85, "yara_scan_interval_seconds": 3600},
        });
        assert_eq!(validate_config_patch(&patch), Vec::<String>::new());
    }

    #[test]
    fn out_of_range_and_malformed_fields_are_reported() {
        let patch = json!({
            "presentation": {"app_name": "", "banner_severity": "loud", "help_link_url": "http://insecure.example"},
            "behavior": {"default_time_window": "2h", "rows_per_page_options": [], "max_export_rows": 5},
            "honeypot": {"alert_cooldown": "10s", "ml_alert_threshold": 1.5, "yara_max_bytes": 12},
            "mystery": {"x": 1},
        });
        let problems = validate_config_patch(&patch);
        for needle in [
            "presentation.app_name must not be empty",
            "presentation.banner_severity",
            "presentation.help_link_url",
            "behavior.default_time_window",
            "behavior.rows_per_page_options",
            "behavior.max_export_rows",
            "honeypot.alert_cooldown",
            "honeypot.ml_alert_threshold",
            "honeypot.yara_max_bytes",
            "unknown config section \"mystery\"",
        ] {
            assert!(
                problems.iter().any(|p| p.contains(needle)),
                "missing problem for {needle}: {problems:?}"
            );
        }
    }

    #[test]
    fn go_durations_parse_as_seconds() {
        assert_eq!(parse_go_duration_seconds("30m"), Some(1800.0));
        assert_eq!(parse_go_duration_seconds("1h30m"), Some(5400.0));
        assert_eq!(parse_go_duration_seconds("168h"), Some(604_800.0));
        assert_eq!(parse_go_duration_seconds("500ms"), Some(0.5));
        assert_eq!(parse_go_duration_seconds(""), None);
        assert_eq!(parse_go_duration_seconds("5"), None);
        assert_eq!(parse_go_duration_seconds("m5"), None);
    }
}
