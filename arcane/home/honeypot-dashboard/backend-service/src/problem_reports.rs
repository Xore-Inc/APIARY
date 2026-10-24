//! "Report a problem" write path — an operator-facing bug-report widget
//! present on every page when behavior.show_problem_report_button is on,
//! capturing enough technical context (click/nav trail, console errors,
//! failed requests, a DOM snapshot) to actually reproduce what went wrong.
//! Submission is open to any authenticated operator (reporting a problem
//! should never itself require the admin role that might be missing
//! *because of* the problem being reported); only the status-change PATCH
//! is admin-only, gated at the BFF like every other admin action in this
//! tier.
//!
//! Every captured string is redacted here before it's ever written to
//! Elasticsearch — the real trust boundary, not whatever a client elects
//! to trim on its own. The pattern list is deliberately conservative;
//! broadening or narrowing it needs real review, not a one-line tweak.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use rand::Rng;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

use crate::es::WriteError;
use crate::AppState;

const INDEX: &str = "dashboard-problem-reports-v1";
const MAX_DOM_SNAPSHOT_BYTES: usize = 200_000;
const MAX_CAPTURED_TEXT_BYTES: usize = 20_000;
const MAX_ACTION_TRAIL_ENTRIES: usize = 200;
const MAX_CONSOLE_ERRORS: usize = 50;
const MAX_NETWORK_FAILURES: usize = 50;
const MAX_API_CALLS: usize = 30;

fn redact_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)(Authorization:\s*Bearer\s+)(\S+)",
            r"(?i)(Cookie:\s*)(.+)",
            r#"(?i)("?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|cookie|session[_-]?id|bearer)"?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)"#,
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).expect("static redact pattern"))
        .collect()
    })
}

fn truncate_at(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Bounds a captured string to MAX_CAPTURED_TEXT_BYTES and strips anything
/// shaped like a credential — applied to every field before it's stored.
fn redact_text(input: &str) -> String {
    let bounded = if input.len() > MAX_CAPTURED_TEXT_BYTES {
        format!("{}...[truncated]", truncate_at(input, MAX_CAPTURED_TEXT_BYTES))
    } else {
        input.to_string()
    };
    redact_patterns()
        .iter()
        .fold(bounded, |text, pattern| pattern.replace_all(&text, "${1}[redacted]").into_owned())
}

/// Masks every query-string parameter VALUE in a captured API-call URL,
/// unconditionally, regardless of key name — a secret can ride along under
/// any key, not just the fixed set redact_text's own pattern recognizes.
/// Only ever called on the same-origin relative paths the client records
/// (see ProblemReportButton.tsx's `/api/` filter), so masking the query
/// string directly is enough; there's no host/scheme to parse.
fn redact_url(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let raw = truncate_at(raw, MAX_CAPTURED_TEXT_BYTES);
    let Some((path, query)) = raw.split_once('?') else {
        return redact_text(raw);
    };
    let masked = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) => format!("{key}=[redacted]"),
            None => "[redacted]".to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    redact_text(&format!("{path}?{masked}"))
}

fn new_id() -> String {
    let mut random = [0u8; 12];
    rand::rng().fill_bytes(&mut random);
    let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{hex}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"))
}

/// Drops everything but the last `max` entries — the ring buffer's own
/// client-side cap already keeps every array well under these server-side
/// limits in practice; this is the backstop for a non-standard client.
fn keep_last<T>(mut items: Vec<T>, max: usize) -> Vec<T> {
    if items.len() > max {
        items.drain(..items.len() - max);
    }
    items
}

#[derive(Deserialize, Default)]
pub struct ActionEntry {
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Deserialize, Default)]
pub struct ApiCall {
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub status: i64,
    #[serde(default)]
    pub request_body: String,
    #[serde(default)]
    pub response_body: String,
}

/// The only shape a submission is ever trusted from — no id, timestamp,
/// submitter identity, or status; the server assigns all of those.
#[derive(Deserialize, Default)]
pub struct Submission {
    #[serde(default)]
    pub page: String,
    #[serde(default)]
    pub expected: String,
    #[serde(default)]
    pub actual: String,
    #[serde(default)]
    pub action_trail: Vec<ActionEntry>,
    #[serde(default)]
    pub console_errors: Vec<String>,
    #[serde(default)]
    pub network_failures: Vec<String>,
    #[serde(default)]
    pub api_calls: Vec<ApiCall>,
    #[serde(default)]
    pub dom_snapshot: String,
    #[serde(default)]
    pub user_agent: String,
}

#[derive(Deserialize, Default)]
pub struct ActorQuery {
    #[serde(default)]
    pub actor_subject: String,
    #[serde(default)]
    pub actor_username: String,
    #[serde(default)]
    pub actor_display_name: String,
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

async fn button_enabled(state: &AppState) -> bool {
    crate::config::load_config(state)
        .await
        .ok()
        .flatten()
        .and_then(|doc| doc["payload"]["behavior"]["show_problem_report_button"].as_bool())
        .unwrap_or(false)
}

#[utoipa::path(
    post,
    path = "/api/v1/problem-reports",
    summary = "File a problem report from the dashboard UI.",
    params(
        ("actor_subject" = inline(Option<String>), Query, description = "OIDC subject recorded on the audit/history entry."),
        ("actor_username" = inline(Option<String>), Query, description = "Operator name recorded on the audit/history entry."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `Submission`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 201, description = "The stored report."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/problem-reports — any authenticated operator; the BFF
/// checks for a live session before ever calling this and passes the
/// caller's identity along as query params (this tier has no session
/// concept of its own, same posture as every other actor-attributed write
/// here). Re-checks the enabled flag server-side as defense in depth — the
/// BFF already hides the button when it's off, but a direct POST shouldn't
/// still work.
pub async fn submit(
    State(state): State<AppState>,
    binding: crate::trust::ActorBinding,
    Query(mut actor): Query<ActorQuery>,
    Json(input): Json<Submission>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
    (actor.actor_subject, actor.actor_username) = binding.bind_pair(&actor.actor_subject, &actor.actor_username)?;
    actor.actor_display_name =
        binding.bind("actor_display_name", crate::trust::ActorField::DisplayName, &actor.actor_display_name)?;
    if !button_enabled(&state).await {
        return Err((StatusCode::NOT_FOUND, "the report-a-problem feature is disabled on this dashboard".into()));
    }
    if input.expected.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "expected behavior is required".into()));
    }

    let id = new_id();
    let action_trail: Vec<Value> = keep_last(input.action_trail, MAX_ACTION_TRAIL_ENTRIES)
        .into_iter()
        .map(|entry| json!({"at": entry.at, "kind": entry.kind, "detail": redact_text(&entry.detail)}))
        .collect();
    let api_calls: Vec<Value> = keep_last(input.api_calls, MAX_API_CALLS)
        .into_iter()
        .map(|call| {
            json!({
                "at": call.at,
                "method": call.method,
                "url": redact_url(&call.url),
                "status": call.status,
                "request_body": redact_text(&call.request_body),
                "response_body": redact_text(&call.response_body),
            })
        })
        .collect();

    let doc = json!({
        "id": id,
        "submitted_at": chrono::Utc::now().to_rfc3339(),
        "submitted_by": actor.actor_subject,
        "submitted_by_name": if actor.actor_display_name.is_empty() { &actor.actor_username } else { &actor.actor_display_name },
        "page": redact_text(&input.page),
        "expected": redact_text(&input.expected),
        "actual": redact_text(&input.actual),
        "action_trail": action_trail,
        "console_errors": input.console_errors.into_iter().take(MAX_CONSOLE_ERRORS).map(|s| redact_text(&s)).collect::<Vec<_>>(),
        "network_failures": input.network_failures.into_iter().take(MAX_NETWORK_FAILURES).map(|s| redact_text(&s)).collect::<Vec<_>>(),
        "api_calls": api_calls,
        "dom_snapshot": redact_text(truncate_at(&input.dom_snapshot, MAX_DOM_SNAPSHOT_BYTES)),
        "user_agent": redact_text(&input.user_agent),
        "status": "open",
    });

    state.es.index_doc_create(INDEX, &id, doc).await.map_err(|error| match error {
        WriteError::Conflict => (StatusCode::CONFLICT, "report id collision, retry".to_string()),
        WriteError::Other(error) => bad_gateway(error),
    })?;

    Ok((StatusCode::CREATED, Json(json!({"id": id}))))
}

#[derive(Deserialize)]
pub struct StatusPatch {
    pub status: String,
}

const VALID_STATUSES: [&str; 3] = ["open", "triaged", "closed"];

#[utoipa::path(
    patch,
    path = "/api/v1/problem-reports/{id}",
    summary = "Move a problem report through open/triaged/closed.",
    params(
        ("id" = inline(String), Path, description = "Problem-report id."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `StatusPatch`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 204, description = "No content; the status was stored."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// PATCH /api/v1/problem-reports/{id} — admin-gated at the BFF. The only
/// mutation an existing report ever gets is its status; captured content
/// is never edited after submission, so this is a single-field
/// compare-and-swap rather than a general update.
pub async fn patch_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(patch): Json<StatusPatch>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !VALID_STATUSES.contains(&patch.status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, r#"status must be "open", "triaged", or "closed""#.into()));
    }
    let (mut doc, seq_no, primary_term) = state
        .es
        .get_doc_meta(INDEX, &id)
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "report not found".to_string()))?;
    doc["status"] = json!(patch.status);
    state.es.index_doc_cas(INDEX, &id, doc, seq_no, primary_term).await.map_err(|error| match error {
        WriteError::Conflict => (StatusCode::CONFLICT, "report was updated concurrently, reload and try again".to_string()),
        WriteError::Other(error) => bad_gateway(error),
    })?;
    Ok(StatusCode::NO_CONTENT)
}
