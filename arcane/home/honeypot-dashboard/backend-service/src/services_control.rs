//! Services pane API (#197), ported from settings_services_api.go /
//! services_control.go: the only path to hp-services-adapter. The real
//! allowlist and the real docker.sock access live only in the adapter
//! (services-adapter/services-adapter.py) — this module only ever forwards
//! a name and an action verb over the fixed AF_UNIX socket
//! (SERVICES_ADAPTER_SOCKET), and never gains any other path to Docker.
//!
//! The Go tier talks to the socket through Go's stdlib http.Client with a
//! custom unix dialer. There is no equivalent one-liner in this crate's
//! dependency set (reqwest has no unix-socket transport), so this is a
//! small hand-rolled HTTP/1.1 client over tokio::net::UnixStream rather
//! than pulling in a new dependency for one internal, trusted, small-JSON
//! call — every response is read to EOF after requesting `Connection:
//! close`, bounded by max_body, which sidesteps needing a real
//! Content-Length/chunked-transfer parser.

use crate::contract;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::audit::AuditEvent;
use crate::AppState;

const MAX_SERVICE_LOG_LINES: u32 = 1000;
const VALID_STATES: &[&str] =
    &["running", "exited", "restarting", "paused", "created", "removing", "dead", "not_found", "unknown"];
const VALID_ACTIONS: &[&str] = &["start", "stop", "restart"];

fn socket_path() -> Option<String> {
    std::env::var("SERVICES_ADAPTER_SOCKET").ok().filter(|s| !s.trim().is_empty())
}

async fn unix_request(
    socket: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    timeout: Duration,
    max_body: usize,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut stream = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(socket))
        .await
        .map_err(|_| anyhow::anyhow!("services adapter connect timeout"))??;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: services-adapter\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.map(|b| b.len()).unwrap_or(0)
    );
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str("\r\n");
    let mut out = request.into_bytes();
    if let Some(body) = body {
        out.extend_from_slice(body);
    }
    tokio::time::timeout(timeout, stream.write_all(&out)).await??;
    stream.shutdown().await.ok();

    let mut raw = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut raw)).await??;

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("services adapter returned a malformed response"))?;
    let header_text = std::str::from_utf8(&raw[..header_end])?;
    let status_line = header_text.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("services adapter returned a malformed status line"))?;

    let mut response_body = raw[header_end + 4..].to_vec();
    if response_body.len() > max_body {
        response_body.truncate(max_body);
    }
    Ok((status, response_body))
}

/// Fetches the current allowlisted-container inventory. Ok(None) means the
/// adapter isn't configured/reachable/valid — distinct from "zero
/// services" — so callers never render an empty pane as authoritative.
async fn load_services_status() -> Result<Vec<Value>, String> {
    let Some(socket) = socket_path() else { return Err("services adapter is not configured".into()) };
    let (status, body) = unix_request(&socket, "GET", "/v1/services", None, Duration::from_secs(8), 256 << 10)
        .await
        .map_err(|_| "services adapter is unavailable".to_string())?;
    if status != 200 {
        return Err("services adapter returned an invalid response".into());
    }
    let payload: Value =
        serde_json::from_slice(&body).map_err(|_| "services adapter returned an invalid schema".to_string())?;
    let services = payload["services"].as_array().cloned().unwrap_or_default();
    let all_valid = services.iter().all(|service| {
        let name_ok = service["name"].as_str().is_some_and(|n| !n.trim().is_empty());
        let state_ok = service["state"].as_str().is_some_and(|s| VALID_STATES.contains(&s));
        name_ok && state_ok
    });
    if !all_valid {
        return Err("services adapter returned an invalid schema".into());
    }
    Ok(services)
}

async fn perform_service_action(name: &str, action: &str) -> (bool, u16, String) {
    if name.trim().is_empty() || !VALID_ACTIONS.contains(&action) {
        return (false, 400, "unsupported action".into());
    }
    let Some(socket) = socket_path() else {
        return (false, 503, "services adapter is not configured".into());
    };
    let path = format!("/v1/services/{}/{}", urlencode(name), action);
    let Ok((status, body)) = unix_request(&socket, "POST", &path, Some(b"{}"), Duration::from_secs(15), 16 << 10).await
    else {
        return (false, 503, "services adapter is unavailable".into());
    };
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let ok = status == 200 && payload["ok"].as_bool().unwrap_or(false);
    if ok {
        return (true, 200, String::new());
    }
    let reason = payload["error"].as_str().filter(|s| !s.is_empty()).map(String::from);
    (false, status, reason.unwrap_or_else(|| format!("services adapter returned {status}")))
}

async fn fetch_service_logs(name: &str, lines: u32) -> Result<(String, u32), (u16, String)> {
    if name.trim().is_empty() {
        return Err((400, "missing service name".into()));
    }
    let lines = if lines == 0 { 200 } else { lines.min(MAX_SERVICE_LOG_LINES) };
    let Some(socket) = socket_path() else {
        return Err((503, "services adapter is not configured".into()));
    };
    let path = format!("/v1/services/{}/logs?lines={}", urlencode(name), lines);
    let (status, body) = unix_request(&socket, "GET", &path, None, Duration::from_secs(15), 4 << 20)
        .await
        .map_err(|_| (503u16, "services adapter is unavailable".to_string()))?;
    if status != 200 {
        return Err((status, format!("services adapter returned {status}")));
    }
    let payload: Value =
        serde_json::from_slice(&body).map_err(|_| (502u16, "services adapter returned an invalid schema".to_string()))?;
    let log = payload["log"].as_str().unwrap_or_default().to_string();
    Ok((log, lines))
}

pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[utoipa::path(
    get,
    path = "/api/v1/services",
    summary = "The compose services the operator can act on.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn list(State(_state): State<AppState>) -> impl axum::response::IntoResponse {
    match load_services_status().await {
        Ok(services) => (StatusCode::OK, Json(json!({"available": true, "services": services}))),
        Err(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"available": false, "reason": reason, "services": []})),
        ),
    }
}

#[derive(Deserialize)]
pub struct LogsQuery {
    lines: Option<u32>,
}

#[utoipa::path(
    get,
    path = "/api/v1/services/{name}/logs",
    summary = "Recent log lines for one service, via the services adapter.",
    params(
        ("name" = inline(String), Path, description = "compose service name."),
        ("lines" = inline(Option<contract::LogLines>), Query, description = "How many lines; the handler defaults to 200."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", content((String = "text/plain"), (inline(serde_json::Value) = "application/json"))),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn logs(
    State(_state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<LogsQuery>,
) -> impl axum::response::IntoResponse {
    match fetch_service_logs(&name, query.lines.unwrap_or(200)).await {
        Ok((log, lines)) => (StatusCode::OK, Json(json!({"name": name, "lines": lines, "log": log}))),
        Err((status, reason)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(json!({"error": reason})),
        ),
    }
}

#[derive(Deserialize)]
pub struct ActionQuery {
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/services/{name}/{action}",
    summary = "Start, stop or restart one service.",
    params(
        ("name" = inline(String), Path, description = "compose service name."),
        ("action" = inline(contract::ServiceAction), Path, description = "Lifecycle action the services adapter accepts."),
        ("actor_subject" = inline(Option<String>), Query, description = "OIDC subject recorded on the audit/history entry."),
        ("actor_username" = inline(Option<String>), Query, description = "Operator name recorded on the audit/history entry."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", content((String = "text/plain"), (inline(serde_json::Value) = "application/json"))),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
/// #3577: under `ACTOR_ASSERTION_MODE=enforce` the trust middleware has
/// already refused anyone but a verified admin, and the audit entry names
/// that verified actor; the `actor_*` query fields are only the labels for
/// the `off`/`log` modes, where nothing was verified (`log` warns when they
/// differ from the assertion).
pub async fn action(
    State(state): State<AppState>,
    binding: crate::trust::ActorBinding,
    Path((name, action)): Path<(String, String)>,
    Query(actor): Query<ActionQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (actor_subject, actor_username) = match binding.bind_pair(&actor.actor_subject, &actor.actor_username) {
        Ok(pair) => pair,
        Err(refusal) => return <(StatusCode, String)>::from(refusal).into_response(),
    };
    let (ok, status, reason) = perform_service_action(&name, &action).await;
    state.audit.log(AuditEvent {
        actor_subject,
        actor_username,
        action: format!("services.{action}"),
        fields: vec![name.clone()],
        result: if ok { "success" } else { "error" }.into(),
        ..Default::default()
    });
    let body = if ok { json!({"ok": true, "name": name, "action": action}) } else { json!({"ok": false, "error": reason}) };
    (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), Json(body)).into_response()
}
