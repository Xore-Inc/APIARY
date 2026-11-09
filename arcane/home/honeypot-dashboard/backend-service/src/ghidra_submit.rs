//! Ghidra submission, ported from ghidra_submit.go. Same shape as
//! sandbox_submit's submit handler and the same trust boundary — the
//! dashboard/BFF only ever confirms the capture exists and writes a marker
//! file; it never talks to the Ghidra REST service. Unlike sandbox
//! submission there is no dynamic/static classification: Ghidra
//! disassembles anything with code in it, including payloads the sandbox
//! refuses to detonate.

use axum::{http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::host_fs::{host, Root};
use crate::payload_paths::resolve_payload;
use crate::sandbox_submit::create_request_marker;

#[derive(Deserialize)]
pub struct SubmitBody {
    hash: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/ghidra/submit",
    summary = "Queue a Ghidra analysis.",
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
pub async fn submit(Json(body): Json<SubmitBody>) -> (StatusCode, Json<Value>) {
    let hash = body.hash.to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid payload hash"})));
    }
    if resolve_payload(&hash).is_err() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "captured payload not found"})),
        );
    }
    if !host().configured(Root::GhidraRequests) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Ghidra analysis is not configured on this host"})),
        );
    }
    match create_request_marker(Root::GhidraRequests, &hash) {
        Ok(()) => (StatusCode::OK, Json(json!({"queued": true}))),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": reason}))),
    }
}
