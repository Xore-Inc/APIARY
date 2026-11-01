//! The host gateway (#3582, decision D1 on #3579): this binary with
//! `GATEWAY_MODE=1`, pinned to the sensor/Elasticsearch host. It gives the
//! HTTP services running elsewhere the few host paths they need, and nothing
//! else:
//!
//! - the analyzer spools and results (`/host/v1/fs/{ROOT}/...`), by root
//!   name only, through `host_fs::local` (one path component per file, no
//!   symlink out of a root, writes only to request roots);
//! - captured payload bytes by hash (`/host/v1/payload/{hash}`);
//! - the three services-adapter calls (`/host/v1/adapter/v1/services...`),
//!   validated and forwarded to the local AF_UNIX socket.
//!
//! It serves none of `/api/v1` and needs neither Elasticsearch nor
//! `SERVICE_TOKEN`. Its own credential, `HOST_GATEWAY_TOKEN` (or `_FILE`,
//! with `_PREVIOUS`/`_PREVIOUS_UNTIL` rotation like `trust.rs`), is refused
//! at boot if it equals the BFF or export token, so neither of those can
//! reach host files and this one cannot reach `/api/v1`.

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::{io, sync::Arc, time::Duration};

use crate::host_fs::{self, local, Dirs, ListFilter, Root};
use crate::trust::Rotating;

#[derive(Clone)]
pub struct GatewayState {
    dirs: Arc<Dirs>,
    token: Arc<Rotating<String>>,
    socket: Option<String>,
}

impl GatewayState {
    pub fn new(dirs: Dirs, token: Rotating<String>, socket: Option<String>) -> Self {
        Self { dirs: Arc::new(dirs), token: Arc::new(token), socket }
    }

    pub fn describe(&self) -> String {
        format!(
            "roots={} adapter={} token_rotation={}",
            self.dirs.describe(),
            if self.socket.is_some() { "socket" } else { "none" },
            self.token.previous.is_some()
        )
    }
}

/// `GATEWAY_MODE`: "1"/"true" on, unset/""/"0"/"false" off, anything else refused.
pub fn mode_from_env(value: Option<&str>) -> anyhow::Result<bool> {
    match value.map(str::trim) {
        None | Some("") | Some("0") | Some("false") => Ok(false),
        Some("1") | Some("true") => Ok(true),
        Some(other) => anyhow::bail!("GATEWAY_MODE={other:?}; use 1 or 0"),
    }
}

/// The gateway's configuration: its token (required), the roots and payload
/// directories from this host's environment, and the adapter socket.
pub fn from_env(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&str) -> io::Result<String>,
) -> anyhow::Result<GatewayState> {
    let current = crate::trust::secret(env, read, "HOST_GATEWAY_TOKEN")?
        .ok_or_else(|| anyhow::anyhow!("GATEWAY_MODE=1 needs HOST_GATEWAY_TOKEN (or _FILE)"))?;
    let token = crate::trust::rotating(env, read, "HOST_GATEWAY_TOKEN", Some(current))?
        .expect("a current token was given");
    for other in ["SERVICE_TOKEN", "EXPORT_TOKEN"] {
        if let Some(value) = crate::trust::secret(env, read, other)? {
            if token.current == value || token.previous.as_ref().is_some_and(|(previous, _)| *previous == value) {
                anyhow::bail!("HOST_GATEWAY_TOKEN equals {other}; the gateway credential must be its own secret");
            }
        }
    }
    let socket = env("SERVICES_ADAPTER_SOCKET").filter(|v| !v.trim().is_empty());
    Ok(GatewayState::new(Dirs::from_env(), token, socket))
}

pub fn router(state: GatewayState) -> Router {
    let host = Router::new()
        .route("/host/v1/fs/{root}", get(root_info))
        .route("/host/v1/fs/{root}/list", get(list))
        .route("/host/v1/fs/{root}/stat/{name}", get(stat))
        .route("/host/v1/fs/{root}/read/{name}", get(read))
        .route("/host/v1/fs/{root}/create/{name}", post(create))
        .route("/host/v1/fs/{root}/file/{name}", axum::routing::delete(remove))
        .route("/host/v1/payload/{hash}", get(payload_resolve))
        .route("/host/v1/payload/{hash}/read", get(payload_read))
        .route("/host/v1/adapter/v1/services", get(adapter_list))
        .route("/host/v1/adapter/v1/services/{name}/logs", get(adapter_logs))
        .route("/host/v1/adapter/v1/services/{name}/{action}", post(adapter_action))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .layer(DefaultBodyLimit::max(64 << 10));
    // /livez is what the image's HEALTHCHECK probes (Dockerfile); /healthz is
    // the name the rest of the fleet uses. Both are unauthenticated.
    Router::new().route("/healthz", get(healthz)).route("/livez", get(healthz)).merge(host).with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({"ok": true, "mode": "host-gateway", "revision": crate::git_revision()}))
}

async fn require_token(State(state): State<GatewayState>, headers: HeaderMap, request: Request, next: Next) -> Response {
    let presented = headers.get(host_fs::TOKEN_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !crate::trust::matches_any(&state.token, presented, chrono::Utc::now()) {
        tracing::warn!(path = %request.uri().path(), "[E-HOST-GATEWAY-TOKEN] refused a request without a valid gateway token");
        return (StatusCode::UNAUTHORIZED, "host gateway token required").into_response();
    }
    let (method, path) = (request.method().clone(), request.uri().path().to_string());
    let response = next.run(request).await;
    tracing::info!(%method, %path, status = response.status().as_u16(), "host gateway");
    response
}

fn status_of(error: &io::Error) -> StatusCode {
    match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        io::ErrorKind::AlreadyExists => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn io_response(error: io::Error) -> Response {
    let status = status_of(&error);
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        tracing::warn!(%error, "host gateway I/O failure");
        return (status, "host I/O failure").into_response();
    }
    (status, error.to_string()).into_response()
}

type Refusal = (StatusCode, &'static str);

fn root_of(name: &str) -> Result<Root, Refusal> {
    Root::from_env_name(name).ok_or((StatusCode::NOT_FOUND, "unknown root"))
}

/// File system work runs on the blocking pool, off the request threads.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T, Refusal> {
    tokio::task::spawn_blocking(work).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "host gateway task failed"))
}

fn bytes_response(body: Vec<u8>, size: u64) -> Response {
    (
        [(header::CONTENT_TYPE, "application/octet-stream".to_string()), (header::HeaderName::from_static("x-real-size"), size.to_string())],
        Body::from(body),
    )
        .into_response()
}

async fn root_info(State(state): State<GatewayState>, Path(root): Path<String>) -> Response {
    let root = match root_of(&root) {
        Ok(root) => root,
        Err(refusal) => return refusal.into_response(),
    };
    match blocking(move || local::root_info(&state.dirs, root)).await {
        Ok(Some(info)) => Json(info).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("{} is not configured", root.env())).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

async fn list(State(state): State<GatewayState>, Path(root): Path<String>, Query(filter): Query<ListFilter>) -> Response {
    let root = match root_of(&root) {
        Ok(root) => root,
        Err(refusal) => return refusal.into_response(),
    };
    match blocking(move || local::list(&state.dirs, root, &filter)).await {
        Ok(Ok(entries)) => Json(entries).into_response(),
        Ok(Err(error)) => io_response(error),
        Err(refusal) => refusal.into_response(),
    }
}

async fn stat(State(state): State<GatewayState>, Path((root, name)): Path<(String, String)>) -> Response {
    let root = match root_of(&root) {
        Ok(root) => root,
        Err(refusal) => return refusal.into_response(),
    };
    match blocking(move || local::stat(&state.dirs, root, &name)).await {
        Ok(Ok(entry)) => Json(entry).into_response(),
        Ok(Err(error)) => io_response(error),
        Err(refusal) => refusal.into_response(),
    }
}

#[derive(Deserialize)]
struct Cap {
    cap: Option<u64>,
}

impl Cap {
    fn bytes(&self) -> u64 {
        self.cap.unwrap_or(host_fs::MAX_READ_BYTES).min(host_fs::MAX_READ_BYTES)
    }
}

async fn read(State(state): State<GatewayState>, Path((root, name)): Path<(String, String)>, Query(cap): Query<Cap>) -> Response {
    let root = match root_of(&root) {
        Ok(root) => root,
        Err(refusal) => return refusal.into_response(),
    };
    let cap = cap.bytes();
    match blocking(move || local::read(&state.dirs, root, &name, cap)).await {
        Ok(Ok((body, size))) => bytes_response(body, size),
        Ok(Err(error)) => io_response(error),
        Err(refusal) => refusal.into_response(),
    }
}

async fn create(State(state): State<GatewayState>, Path((root, name)): Path<(String, String)>) -> Response {
    let root = match root_of(&root) {
        Ok(root) => root,
        Err(refusal) => return refusal.into_response(),
    };
    match blocking(move || local::create_new(&state.dirs, root, &name)).await {
        Ok(Ok(true)) => StatusCode::CREATED.into_response(),
        Ok(Ok(false)) => StatusCode::OK.into_response(),
        Ok(Err(error)) => io_response(error),
        Err(refusal) => refusal.into_response(),
    }
}

async fn remove(State(state): State<GatewayState>, Path((root, name)): Path<(String, String)>) -> Response {
    let root = match root_of(&root) {
        Ok(root) => root,
        Err(refusal) => return refusal.into_response(),
    };
    match blocking(move || local::remove(&state.dirs, root, &name)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => io_response(error),
        Err(refusal) => refusal.into_response(),
    }
}

async fn payload_resolve(State(state): State<GatewayState>, Path(hash): Path<String>) -> Response {
    if !crate::payload_paths::is_valid_hash(&hash) {
        return (StatusCode::BAD_REQUEST, "invalid payload id").into_response();
    }
    match blocking(move || local::resolve_payload(&state.dirs, &hash)).await {
        Ok(Ok(payload)) => Json(json!({"size": payload.size})).into_response(),
        Ok(Err(reason)) => (StatusCode::NOT_FOUND, reason).into_response(),
        Err(refusal) => refusal.into_response(),
    }
}

async fn payload_read(State(state): State<GatewayState>, Path(hash): Path<String>, Query(cap): Query<Cap>) -> Response {
    if !crate::payload_paths::is_valid_hash(&hash) {
        return (StatusCode::BAD_REQUEST, "invalid payload id").into_response();
    }
    let cap = cap.bytes();
    let work = move || {
        let payload = local::resolve_payload(&state.dirs, &hash).map_err(|reason| io::Error::new(io::ErrorKind::NotFound, reason))?;
        match &payload.location {
            host_fs::PayloadLocation::Local(path) => local::read_path(path, cap),
            host_fs::PayloadLocation::Remote => Err(io::Error::other("unreachable: the gateway resolves locally")),
        }
    };
    match blocking(work).await {
        Ok(Ok((body, size))) => bytes_response(body, size),
        Ok(Err(error)) => io_response(error),
        Err(refusal) => refusal.into_response(),
    }
}

/// A compose service name as the adapter's allowlist spells them.
fn valid_service(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

async fn forward(state: &GatewayState, method: &str, path: &str, body: Option<&[u8]>, timeout: Duration, max_body: usize) -> Response {
    let Some(socket) = state.socket.as_deref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "services adapter is not configured on this host").into_response();
    };
    match crate::services_control::unix_request(socket, method, path, body, timeout, max_body).await {
        Ok((status, body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(body),
        )
            .into_response(),
        Err(_) => (StatusCode::BAD_GATEWAY, "services adapter is unavailable").into_response(),
    }
}

async fn adapter_list(State(state): State<GatewayState>) -> Response {
    forward(&state, "GET", "/v1/services", None, Duration::from_secs(8), 256 << 10).await
}

#[derive(Deserialize)]
struct Lines {
    lines: Option<u32>,
}

async fn adapter_logs(State(state): State<GatewayState>, Path(name): Path<String>, Query(lines): Query<Lines>) -> Response {
    let lines = lines.lines.unwrap_or(200);
    if !valid_service(&name) || !(1..=1000).contains(&lines) {
        return (StatusCode::BAD_REQUEST, "invalid service or line count").into_response();
    }
    let path = format!("/v1/services/{name}/logs?lines={lines}");
    forward(&state, "GET", &path, None, Duration::from_secs(15), 4 << 20).await
}

async fn adapter_action(State(state): State<GatewayState>, Path((name, action)): Path<(String, String)>) -> Response {
    if !valid_service(&name) || !matches!(action.as_str(), "start" | "stop" | "restart") {
        return (StatusCode::BAD_REQUEST, "unsupported service or action").into_response();
    }
    let path = format!("/v1/services/{name}/{action}");
    forward(&state, "POST", &path, Some(b"{}"), Duration::from_secs(15), 16 << 10).await
}

/// Serves the gateway until the process ends.
pub async fn serve(listen: &str, state: GatewayState) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = listen.parse()?;
    tracing::info!(%addr, gateway = %state.describe(), built = %crate::build_stamp(), revision = %crate::git_revision(), "apiary-backend host gateway listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
#[path = "host_gateway_tests.rs"]
mod tests;
