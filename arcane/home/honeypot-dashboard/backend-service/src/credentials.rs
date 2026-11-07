//! Dashboard-owned record of every credential provisioned/rotated live
//! into a honeypot's filesystem via honeyfs-implant, ported from
//! dashboard/credentials_manager.go + credentials_api.go (#1487 items 3/5).
//!
//! Storage: one document per credential in dashboard-credentials-v1, doc id
//! is the credential's own id (unlike canarytokens, which keys by the
//! platform-issued token value — a credential has no natural unique key of
//! its own, so a random id is minted). Username/password/content_template
//! are not secrets to redact from the operator — they ARE the bait content,
//! visible in every response with no redaction, same posture as the Go
//! tier (credentialRecord's own doc comment).
//!
//! Item 5 (link a canarytoken to a credential) is bookkeeping only: an
//! optional soft reference into dashboard-canarytokens-v1, validated
//! against that index at write time but never enforced at the storage
//! layer — a deleted token just leaves a dangling, harmless reference.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rand::{Rng, RngExt};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::es::WriteError;
use crate::honeyfs_implant;
use crate::trust::ActorBinding;
use crate::AppState;

const INDEX: &str = "dashboard-credentials-v1";
const WRITE_RETRIES: u32 = 5;

const DEFAULT_CONTENT_TEMPLATE: &str = "username={{username}}\npassword={{password}}\n";
const PASSWORD_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*";

/// Random, opaque record id — same shape as reports_store.rs's
/// new_report_id (rand::rng() + hex-format, no `hex` crate dependency).
fn new_credential_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    format!("cred_{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn render_content(template: &str, username: &str, password: &str) -> String {
    template.replace("{{username}}", username).replace("{{password}}", password)
}

/// credentialPasswordAlphabet excludes visually-ambiguous look-alikes
/// (0/O, 1/l/I) — bait content an operator may need to read off a screen,
/// not a real secret requiring maximum entropy.
fn generate_password() -> String {
    let mut rng = rand::rng();
    (0..20).map(|_| PASSWORD_ALPHABET[rng.random_range(0..PASSWORD_ALPHABET.len())] as char).collect()
}

/// Upsert with optimistic-concurrency retry — the Rust equivalent of Go's
/// docGet+docIndex(create=!found, seqNo, primaryTerm) loop
/// (credentialsManager.save). A brand-new id (the common case: every
/// create() mints a fresh random one) always takes the create branch; an
/// update (rotate/link-token) takes the CAS branch and retries against a
/// fresh read on a lost race.
async fn save(state: &AppState, record: &Value) -> Result<(), String> {
    let id = record["id"].as_str().ok_or("credential record has no id")?;
    for _ in 0..WRITE_RETRIES {
        let existing = state.es.get_doc_meta(INDEX, id).await.map_err(|error| error.to_string())?;
        let result = match existing {
            Some((_, seq_no, primary_term)) => {
                state.es.index_doc_cas(INDEX, id, record.clone(), seq_no, primary_term).await
            }
            None => state.es.index_doc_create(INDEX, id, record.clone()).await,
        };
        match result {
            Ok(()) => return Ok(()),
            Err(WriteError::Conflict) => continue,
            Err(WriteError::Other(error)) => return Err(error.to_string()),
        }
    }
    Err("credential save conflict; retry".to_string())
}

async fn get(state: &AppState, id: &str) -> Option<Value> {
    state.es.get_doc(INDEX, id).await.ok().flatten()
}

#[utoipa::path(
    get,
    path = "/api/v1/credentials",
    summary = "HoneyFS implant credentials, including their bait passwords (not redacted).",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/credentials — list every provisioned credential, newest
/// first.
pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let result = match state.es.search_index(&[INDEX], json!({"size": 1000})).await {
        Ok(result) => result,
        Err(error) => {
            return Json(json!({"available": false, "error": error.to_string(), "credentials": []}));
        }
    };
    let mut records: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| hit["_source"].clone())
        .collect();
    records.sort_by(|a, b| {
        let a = a["created_at"].as_str().unwrap_or_default();
        let b = b["created_at"].as_str().unwrap_or_default();
        b.cmp(a)
    });
    Json(json!({"available": true, "credentials": records}))
}

#[derive(Deserialize)]
pub struct CreateBody {
    #[serde(default)]
    target: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    content_template: String,
    #[serde(default)]
    memo: String,
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/credentials",
    summary = "Provision a honeyfs-implant credential.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `CreateBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 500, description = "The handler failed in a way it does not model as a 4xx.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/credentials — provision a new credential (implants it
/// live, then records it). Cowrie-honeyfs is the only implant target this
/// pass wires up ("cowrie_honeyfs", matching the Go tier — Beelzebub's
/// passwordRegex-config rewrite is a genuinely different request shape,
/// deferred).
pub async fn create(
    State(state): State<AppState>,
    binding: ActorBinding,
    Json(mut body): Json<CreateBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    (body.actor_subject, body.actor_username) = binding.bind_pair(&body.actor_subject, &body.actor_username)?;
    if !honeyfs_implant::configured() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "credential implant is not configured on this host (HONEYFS_IMPLANT_URL unset)".into(),
        ));
    }
    let target = if body.target.is_empty() { "cowrie_honeyfs".to_string() } else { body.target };
    if target != "cowrie_honeyfs" {
        return Err((StatusCode::BAD_REQUEST, "unsupported target (only cowrie_honeyfs is implemented today)".into()));
    }
    let path = body.path.trim().to_string();
    let username = body.username.trim().to_string();
    let password = body.password;
    let memo = body.memo.trim().to_string();
    if path.is_empty() || username.is_empty() || password.is_empty() || memo.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "path, username, password, and memo are all required".into()));
    }
    // Belt-and-suspenders alongside honeyfs-implant's own containment
    // check — reject the obviously-bad shapes here too.
    if path.starts_with('/') || path.contains("..") {
        return Err((StatusCode::BAD_REQUEST, "path must be relative to the honeyfs root and must not contain \"..\"".into()));
    }
    let template = if body.content_template.trim().is_empty() { DEFAULT_CONTENT_TEMPLATE.to_string() } else { body.content_template };

    let content = render_content(&template, &username, &password);
    if let Err(error) = honeyfs_implant::implant(&path, content.as_bytes(), &memo).await {
        state.audit.log(AuditEvent {
            actor_subject: body.actor_subject,
            actor_username: body.actor_username,
            action: "credentials.create".into(),
            fields: vec![path],
            result: "error".into(),
            ..Default::default()
        });
        return Err((StatusCode::BAD_GATEWAY, format!("implant failed: {error}")));
    }

    let record = json!({
        "id": new_credential_id(),
        "target": target,
        "path": path,
        "username": username,
        "password": password,
        "content_template": template,
        "memo": memo,
        "created_by": if body.actor_username.is_empty() { body.actor_subject.clone() } else { body.actor_username.clone() },
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    if let Err(error) = save(&state, &record).await {
        tracing::warn!(%error, "credential implanted but bookkeeping save failed");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential was implanted but could not be saved to history -- check before retrying to avoid planting a duplicate".into(),
        ));
    }
    state.audit.log(AuditEvent {
        actor_subject: body.actor_subject,
        actor_username: body.actor_username,
        action: "credentials.create".into(),
        fields: vec![record["path"].as_str().unwrap_or_default().to_string()],
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(record))
}

#[derive(Deserialize, Default)]
pub struct RotateBody {
    #[serde(default)]
    password: String,
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/credentials/{id}/rotate",
    summary = "Rotate a honeyfs-implant credential's secret.",
    params(
        ("id" = inline(String), Path, description = "HoneyFS implant credential id."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `RotateBody`. The shape is left open here on purpose -- see the module doc.", extensions(("x-optional-body" = json!(true)))),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 500, description = "The handler failed in a way it does not model as a 4xx.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/credentials/{id}/rotate — rotate a credential's password
/// (re-implants at the same path with a freshly rendered body; "Rotation =
/// calling implant again with new content", no separate verb on the wire).
pub async fn rotate(
    State(state): State<AppState>,
    binding: ActorBinding,
    Path(id): Path<String>,
    body: Option<Json<RotateBody>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mut body = body.map(|Json(b)| b).unwrap_or_default();
    (body.actor_subject, body.actor_username) = binding.bind_pair(&body.actor_subject, &body.actor_username)?;
    if !honeyfs_implant::configured() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "credential rotation is not configured on this host".into()));
    }
    let Some(mut record) = get(&state, &id).await else {
        return Err((StatusCode::NOT_FOUND, "no such credential".into()));
    };
    let new_password = if body.password.trim().is_empty() { generate_password() } else { body.password.trim().to_string() };

    let template = record["content_template"].as_str().unwrap_or(DEFAULT_CONTENT_TEMPLATE);
    let username = record["username"].as_str().unwrap_or_default();
    let path = record["path"].as_str().unwrap_or_default().to_string();
    let memo = record["memo"].as_str().unwrap_or_default().to_string();
    let content = render_content(template, username, &new_password);

    if let Err(error) = honeyfs_implant::implant(&path, content.as_bytes(), &memo).await {
        state.audit.log(AuditEvent {
            actor_subject: body.actor_subject,
            actor_username: body.actor_username,
            action: "credentials.rotate".into(),
            fields: vec![path],
            result: "error".into(),
            ..Default::default()
        });
        return Err((StatusCode::BAD_GATEWAY, format!("implant failed: {error}")));
    }

    record["password"] = json!(new_password);
    record["rotated_by"] = json!(if body.actor_username.is_empty() { &body.actor_subject } else { &body.actor_username });
    record["rotated_at"] = json!(chrono::Utc::now().to_rfc3339());
    if save(&state, &record).await.is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential was rotated on the honeypot but the new value could not be saved -- check the honeyfs directly".into(),
        ));
    }
    state.audit.log(AuditEvent {
        actor_subject: body.actor_subject,
        actor_username: body.actor_username,
        action: "credentials.rotate".into(),
        fields: vec![path],
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(record))
}

#[derive(Deserialize)]
pub struct LinkTokenBody {
    #[serde(default)]
    token_id: String,
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/credentials/{id}/link-token",
    summary = "Mint a link token for a honeyfs-implant credential.",
    params(
        ("id" = inline(String), Path, description = "HoneyFS implant credential id."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `LinkTokenBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 500, description = "The handler failed in a way it does not model as a 4xx.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/credentials/{id}/link-token — associate/clear a
/// canarytoken id. Bookkeeping only, per the #1487 design comment: "a
/// dashboard-side data-model concern only ... no new backend mechanism."
pub async fn link_token(
    State(state): State<AppState>,
    binding: ActorBinding,
    Path(id): Path<String>,
    Json(mut body): Json<LinkTokenBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    (body.actor_subject, body.actor_username) = binding.bind_pair(&body.actor_subject, &body.actor_username)?;
    let Some(mut record) = get(&state, &id).await else {
        return Err((StatusCode::NOT_FOUND, "no such credential".into()));
    };
    let token_id = body.token_id.trim().to_string();
    if !token_id.is_empty() {
        let found = state.es.get_doc("dashboard-canarytokens-v1", &token_id).await.ok().flatten();
        if found.is_none() {
            return Err((StatusCode::BAD_REQUEST, "unknown canarytoken id".into()));
        }
    }
    record["linked_token_id"] = json!(token_id);
    if save(&state, &record).await.is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "failed to save the link".into()));
    }
    let action = if token_id.is_empty() { "credentials.unlink-token" } else { "credentials.link-token" };
    state.audit.log(AuditEvent {
        actor_subject: body.actor_subject,
        actor_username: body.actor_username,
        action: action.into(),
        fields: vec![record["path"].as_str().unwrap_or_default().to_string()],
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(record))
}
