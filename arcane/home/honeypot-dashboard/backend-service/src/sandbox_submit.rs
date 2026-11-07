//! Sandbox submission + golden-image staleness, ported from
//! sandbox_submit.go and sandbox.go's loadGoldenImageStatus. Adapted from
//! Go's form-POST-plus-redirect flow to plain JSON — the caller here is
//! the BFF, not a browser form, so there is no return-URL/open-redirect
//! concern to port (safeReturnPath has no equivalent needed).
//!
//! Same trust boundary as the rest of this crate: the service token is the
//! only gate. admin-role/same-origin checks stay the BFF's job.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use crate::host_fs::{host, ListFilter, Root};
use crate::payload_kind::classify_payload;
use crate::payload_paths::{read_payload_head, resolve_payload};
use crate::AppState;

fn env_dir(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// windows | linux | ghosts. Ghosts is never auto-picked by classification
/// (WAN-permitted route, opt-in only via the Workbench) — mirrors
/// determineSandboxTarget exactly.
fn determine_sandbox_target(data: &[u8]) -> Option<&'static str> {
    let classification = classify_payload(data);
    if !classification.dynamic {
        return None;
    }
    Some(if classification.platform == "Windows" {
        "windows"
    } else {
        "linux"
    })
}

/// The request spool for a sandbox target. The Linux spool keeps its
/// in-container default (`/sandbox-requests`), see `host_fs::Root`.
pub fn sandbox_request_root(target: &str) -> Root {
    match target {
        "windows" => Root::WindowsSandboxRequests,
        "ghosts" => Root::GhostsSandboxRequests,
        _ => Root::SandboxRequests,
    }
}

/// Creates {root}/{hash}.request, O_CREAT|O_EXCL, through the host seam
/// (#3582). An already-existing marker is success, not an error — the same
/// idempotence a second click on an already-queued job relies on in the Go
/// tier.
pub fn create_request_marker(root: Root, hash: &str) -> Result<(), String> {
    let fs = host();
    if !fs.configured(root) {
        return Err("spool is not configured".into());
    }
    fs.create_new(root, &format!("{hash}.request"))
        .map(|_| ())
        .map_err(|error| format!("request spool unavailable: {error}"))
}

#[derive(Deserialize)]
pub struct SubmitBody {
    hash: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/sandbox/submit",
    summary = "Queue a sandbox detonation.",
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
pub async fn submit(State(_state): State<AppState>, Json(body): Json<SubmitBody>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    fn err(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<Value>) {
        (status, Json(json!({"error": message.into()})))
    }

    let hash = body.hash.to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid payload hash"));
    }
    let payload = resolve_payload(&hash).map_err(|_| err(StatusCode::NOT_FOUND, "captured payload not found"))?;
    let head = read_payload_head(&payload).map_err(|_| err(StatusCode::NOT_FOUND, "captured payload is unreadable"))?;
    let target = determine_sandbox_target(&head).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "this payload has no dynamic detonation path — see its static analysis instead",
        )
    })?;
    let root = sandbox_request_root(target);
    if !host().configured(root) {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("the {target} sandbox is not configured on this host")));
    }
    create_request_marker(root, &hash).map_err(|reason| err(StatusCode::SERVICE_UNAVAILABLE, reason))?;
    Ok(Json(json!({"target": target, "queued": true})))
}

#[utoipa::path(
    get,
    path = "/api/v1/sandbox/golden-image-status",
    summary = "Whether the sandbox golden image is built.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
/// goldenImageStatus (#86): win11-analysis.qcow2 staleness, written by a
/// host-side timer into WINDOWS_SANDBOX_RESULTS_DIR — the same directory
/// already mounted read-only for per-job results, no new mount needed.
/// Missing/unreadable/unset is not an error: informational badge only.
pub async fn golden_image_status() -> Json<Value> {
    const CAP: u64 = 16 * 1024;
    let Ok((body, size)) = host().read(Root::WindowsSandboxResults, "golden-image-status.json", CAP + 1) else {
        return Json(json!({"configured": false}));
    };
    if size > CAP {
        return Json(json!({"configured": false}));
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
        return Json(json!({"configured": false}));
    };
    if let Value::Object(ref mut map) = value {
        map.insert("configured".into(), json!(true));
    }
    Json(value)
}

/// windowsSandboxLiveJob's regex, ported: run_pending.sh claims one
/// request at a time by renaming {sha}.request to {sha}.request.running
/// before it starts the guest, and the single-VM/flock design means at
/// most one such file can exist at a time.
fn running_sha_from(name: &str) -> Option<&str> {
    let sha = name.strip_suffix(".request.running")?;
    (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())).then_some(sha)
}

#[utoipa::path(
    get,
    path = "/api/v1/sandbox/vnc",
    summary = "The VNC port the sandbox advertises, if any.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/sandbox/vnc — read-only live-view status, ported from
/// sandbox_vnc.go's serveSandboxVNC + windowsSandboxLiveJob. This tier
/// never touches libvirt or the VNC stream itself — it only reports
/// whether a Windows-sandbox detonation is currently running and where
/// the operator-configured bridge WebSocket lives; the browser's noVNC
/// client connects to that bridge directly. Admin-gated at the BFF, same
/// posture as every other admin action here — watching a live malware
/// detonation is at least as sensitive as downloading its capture.
pub async fn vnc_status() -> Result<Json<Value>, (StatusCode, String)> {
    let bridge_ws = env_dir("SANDBOX_VNC_BRIDGE_WS");
    if bridge_ws.is_empty() {
        return Err((StatusCode::NOT_FOUND, "the VNC bridge is not configured on this host (SANDBOX_VNC_BRIDGE_WS unset)".into()));
    }
    let running_sha = host()
        .list(Root::WindowsSandboxRequests, &ListFilter { suffix: ".request.running".into(), ..Default::default() })
        .unwrap_or_default()
        .into_iter()
        .find_map(|entry| running_sha_from(&entry.name).map(str::to_string));
    let Some(sha256) = running_sha else {
        return Err((StatusCode::NOT_FOUND, "no Windows-sandbox detonation is currently running".into()));
    };
    Ok(Json(json!({"sha256": sha256, "bridge_ws": bridge_ws})))
}
