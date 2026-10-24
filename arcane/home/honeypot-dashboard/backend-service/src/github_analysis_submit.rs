//! GitHub-analysis submission, ported from github_analysis_submit.go. The
//! one place this diverges from sandbox/Ghidra submission: the consequence
//! is external and irreversible (publication to a public repository and its
//! third-party scanner pipeline), so an explicit confirm field is required
//! and every outcome — accepted or refused — is audited, mirroring
//! auditGitHubAnalysisSubmit exactly (identity is best-effort, supplied by
//! the BFF as plain body fields like every other actor-attributed write in
//! this crate — see preferences.rs/services_control.rs).

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::payload_paths::resolve_payload_path;
use crate::sandbox_submit::create_request_marker;
use crate::AppState;

pub fn github_analysis_request_dir() -> String {
    std::env::var("GITHUB_ANALYSIS_REQUEST_DIR").unwrap_or_default()
}

#[derive(Deserialize)]
pub struct SubmitBody {
    hash: String,
    #[serde(default)]
    confirm: String,
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

fn audit(state: &AppState, body: &SubmitBody, hash: &str, result: &str) {
    state.audit.log(AuditEvent {
        actor_subject: body.actor_subject.clone(),
        actor_username: body.actor_username.clone(),
        action: "github_analysis.submit".into(),
        fields: vec![hash.to_string()],
        result: result.into(),
        ..Default::default()
    });
}

#[utoipa::path(
    post,
    path = "/api/v1/github-analysis/submit",
    summary = "Queue a GitHub analysis.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `SubmitBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn submit(
    State(state): State<AppState>,
    binding: crate::trust::ActorBinding,
    Json(mut body): Json<SubmitBody>,
) -> (StatusCode, Json<Value>) {
    match binding.bind_pair(&body.actor_subject, &body.actor_username) {
        Ok(pair) => (body.actor_subject, body.actor_username) = pair,
        // Unreachable behind the trust middleware, which refuses a mutation
        // without an assertion before this runs; kept so the field can
        // never be believed without one.
        Err(refusal) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": refusal.0}))),
    }
    let hash = body.hash.to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid payload hash"})));
    }
    if body.confirm != "publish" {
        audit(&state, &body, &hash, "missing_consent");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "confirmation required: this publishes the sample externally"})),
        );
    }
    if resolve_payload_path(&hash).is_err() {
        audit(&state, &body, &hash, "not_found");
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "captured payload not found"})),
        );
    }
    let dir = github_analysis_request_dir();
    if dir.is_empty() {
        audit(&state, &body, &hash, "not_configured");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "GitHub analysis publishing is not configured on this host"})),
        );
    }
    match create_request_marker(&dir, &hash) {
        Ok(()) => {
            audit(&state, &body, &hash, "queued");
            (StatusCode::OK, Json(json!({"queued": true})))
        }
        Err(reason) => {
            audit(&state, &body, &hash, "spool_unavailable");
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": reason})))
        }
    }
}
