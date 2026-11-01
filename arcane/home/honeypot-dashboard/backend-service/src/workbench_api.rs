//! Payload Workbench HTTP surface over workbench_orchestrator.rs's run/child
//! logic and workbench_es.rs's recipe storage.
//!
//! #3110: ownership used to be a plain BFF-supplied `owner` body/query
//! field, same precedent as preferences.rs/services_control.rs — fine for
//! those (audit logging, admin-only panes), but here it was also the
//! *authorization* check, so anyone who could reach this service (the
//! shared x-service-token, not a per-user secret) could act on any
//! operator's runs by naming them. Identity is now taken from
//! x-actor-username, a header only the BFF's serviceFetch/proxyToRust seam
//! sets (see backend.server.ts) from its own verified session — never from
//! client-controlled JSON/query. The `owner` field
//! stays on the wire so existing request bodies don't break, but nothing
//! here reads it: it isn't deserialized at all, so no handler can make an
//! access decision out of request data. There is deliberately no
//! "act as another operator" override either — every mutation is
//! admin-gated at the BFF, so a wire-level override would hand the whole
//! authorization decision back to anyone holding the shared service
//! token. An admin UI for another operator's runs gets added when it
//! exists, with its own authorization.

use crate::contract;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::workbench_domain::{self, WorkbenchRecipe, WorkbenchSelection};
use crate::workbench_es::{self, SaveRecipeError, UpdateRunError};
use crate::workbench_orchestrator::{self, CreateRunError, CreateRunRequest};
use crate::AppState;

fn error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": message.into()})))
}

/// The caller identity the BFF verified and forwarded — see the module doc
/// comment. This username is the only owner any handler below acts on; the
/// forwarded role claim is not read here, so no request can widen its own
/// reach past the operator it authenticated as.
fn require_actor(headers: &HeaderMap) -> Result<String, (StatusCode, Json<Value>)> {
    headers
        .get("x-actor-username")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "actor identity required"))
}

#[derive(Deserialize)]
pub struct AnalyzersQuery {
    hash: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/workbench/analyzers",
    summary = "Analyzers available for one payload.",
    params(
        ("hash" = inline(Option<String>), Query, description = "Payload id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", content((String = "text/plain"), (inline(serde_json::Value) = "application/json"))),
        (status = 404, description = "No such record, store, or route for the values given.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn analyzers(
    Query(query): Query<AnalyzersQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let hash = query.hash.trim().to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid payload hash"));
    }
    let payload = crate::payload_paths::resolve_payload(&hash)
        .map_err(|_| error(StatusCode::NOT_FOUND, "captured payload not found"))?;
    let head = crate::payload_paths::read_payload_head(&payload)
        .map_err(|_| error(StatusCode::NOT_FOUND, "captured payload is unreadable"))?;
    let classification = crate::payload_kind::classify_payload(&head);
    let registry = workbench_domain::registry(&classification);
    Ok(Json(
        json!({"classification": classification, "analyzers": registry}),
    ))
}

#[derive(Deserialize)]
pub struct CreateRunBody {
    payload_sha256: String,
    #[serde(default)]
    recipe_id: String,
    #[serde(default)]
    recipe_revision: i64,
    #[serde(default)]
    recipe_name: String,
    #[serde(default)]
    analyzers: Vec<WorkbenchSelection>,
}

#[utoipa::path(
    post,
    path = "/api/v1/workbench/runs",
    summary = "Start a Workbench run over one payload.",
    params(
        ("X-Actor-Username" = inline(String), Header, description = "Operator identity the BFF forwards; workbench_api.rs's require_actor rejects a missing or blank value with a JSON 401."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `CreateRunBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 401, description = "No valid service token (or, on the Workbench, no actor identity).", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn create_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRunBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let request = CreateRunRequest {
        payload_sha256: body.payload_sha256,
        owner: actor,
        recipe_id: body.recipe_id,
        recipe_revision: body.recipe_revision,
        recipe_name: body.recipe_name,
        analyzers: body.analyzers,
    };
    match workbench_orchestrator::create_run(&state, request).await {
        Ok((run, reused)) => Ok(Json(json!({"run": run, "reused": reused}))),
        Err(CreateRunError::Validation(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(CreateRunError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "captured payload not found"))
        }
        Err(CreateRunError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/workbench/runs/{id}",
    summary = "One Workbench run, with its children.",
    params(
        ("id" = inline(String), Path, description = "Workbench run id."),
        ("X-Actor-Username" = inline(String), Header, description = "Operator identity the BFF forwards; workbench_api.rs's require_actor rejects a missing or blank value with a JSON 401."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 401, description = "No valid service token (or, on the Workbench, no actor identity).", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn get_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    match workbench_orchestrator::get_run(&state, &id, &actor).await {
        Ok(run) => Ok(Json(json!({"run": run}))),
        Err(UpdateRunError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "workbench record not found"))
        }
        Err(UpdateRunError::Mutate(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(UpdateRunError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

#[derive(Deserialize)]
pub struct ListRunsQuery {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    limit: usize,
}

#[utoipa::path(
    get,
    path = "/api/v1/workbench/runs",
    summary = "Payload Workbench runs owned by the calling operator.",
    params(
        ("hash" = inline(Option<String>), Query, description = "Narrow to one payload id."),
        ("limit" = inline(Option<contract::PositiveCount>), Query, description = "How many runs to return."),
        ("X-Actor-Username" = inline(String), Header, description = "Operator identity the BFF forwards; workbench_api.rs's require_actor rejects a missing or blank value with a JSON 401."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 401, description = "No valid service token (or, on the Workbench, no actor identity).", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn list_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListRunsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let runs = workbench_es::list_runs_for_owner_and_hash(&state.es, &actor, &query.hash, query.limit)
        .await
        .map_err(|err| error(StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(json!({"runs": runs})))
}

#[utoipa::path(
    post,
    path = "/api/v1/workbench/runs/{id}/children/{analyzer_id}/{action}",
    summary = "Cancel or retry one child of a run.",
    params(
        ("id" = inline(String), Path, description = "Workbench run id."),
        ("analyzer_id" = inline(String), Path, description = "Analyzer entry on this run; the orchestrator looks the child up by it."),
        ("action" = inline(contract::ChildAction), Path, description = "Child lifecycle action."),
        ("X-Actor-Username" = inline(String), Header, description = "Operator identity the BFF forwards; workbench_api.rs's require_actor rejects a missing or blank value with a JSON 401."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 401, description = "No valid service token (or, on the Workbench, no actor identity).", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn child_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((run_id, analyzer_id, action)): Path<(String, String, String)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    match workbench_orchestrator::child_action(&state, &run_id, &analyzer_id, &action, &actor).await
    {
        Ok(run) => Ok(Json(json!({"run": run}))),
        Err(UpdateRunError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "workbench record not found"))
        }
        Err(UpdateRunError::Mutate(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(UpdateRunError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/workbench/recipes",
    summary = "Saved Workbench recipes owned by the calling operator.",
    params(
        ("X-Actor-Username" = inline(String), Header, description = "Operator identity the BFF forwards; workbench_api.rs's require_actor rejects a missing or blank value with a JSON 401."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 401, description = "No valid service token (or, on the Workbench, no actor identity).", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn list_recipes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let recipes = workbench_es::list_recipes(&state.es, &actor)
        .await
        .map_err(|err| error(StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(json!({"recipes": recipes})))
}

#[derive(Deserialize)]
pub struct SaveRecipeBody {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    scope: String,
    analyzers: Vec<WorkbenchSelection>,
    #[serde(default)]
    base_revision: i64,
}

#[utoipa::path(
    post,
    path = "/api/v1/workbench/recipes",
    summary = "Save a Workbench recipe.",
    params(
        ("X-Actor-Username" = inline(String), Header, description = "Operator identity the BFF forwards; workbench_api.rs's require_actor rejects a missing or blank value with a JSON 401."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `SaveRecipeBody`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 401, description = "No valid service token (or, on the Workbench, no actor identity).", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn save_recipe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SaveRecipeBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let input = WorkbenchRecipe {
        id: body.id,
        name: body.name,
        description: body.description,
        scope: body.scope,
        analyzers: body.analyzers,
        ..Default::default()
    };
    match workbench_es::save_recipe(&state.es, input, &actor, body.base_revision).await {
        Ok(recipe) => Ok(Json(json!({"recipe": recipe}))),
        Err(SaveRecipeError::Validation(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(SaveRecipeError::Conflict) => {
            Err(error(StatusCode::CONFLICT, "recipe revision conflict"))
        }
        Err(SaveRecipeError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "workbench record not found"))
        }
        Err(SaveRecipeError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{require_actor, CreateRunBody, SaveRecipeBody};
    use axum::http::{HeaderMap, StatusCode};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            let name: axum::http::HeaderName = name.parse().expect("valid header name");
            headers.insert(name, value.parse().expect("valid header value"));
        }
        headers
    }

    #[test]
    fn require_actor_rejects_missing_identity() {
        // No forwarded identity at all -- the BFF didn't attach one, or a
        // request reached this tier some other way. Must refuse outright,
        // never fall back to a default trusted state.
        let (status, _) = require_actor(&HeaderMap::new()).expect_err("must reject");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_actor_rejects_blank_username() {
        // Whitespace-only counts as absent, same as no header at all.
        let (status, _) =
            require_actor(&headers(&[("x-actor-username", "   ")])).expect_err("must reject");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_actor_reads_and_trims_the_username() {
        let actor = require_actor(&headers(&[("x-actor-username", "  alice  ")]))
            .expect("must accept a present username");
        assert_eq!(actor, "alice");
    }

    #[test]
    fn the_role_claim_never_widens_the_resolved_owner() {
        // An admin is still only ever themselves at this tier. The role
        // header is forwarded (the BFF gates mutations with it) but reading
        // it here would make "whose run" a wire-level decision again.
        let actor = require_actor(&headers(&[
            ("x-actor-username", "root"),
            ("x-actor-role", "admin"),
        ]))
        .expect("must accept");
        assert_eq!(actor, "root");
    }

    #[test]
    fn a_spoofed_owner_field_is_not_deserialized_at_all() {
        // The core of #3110: a create body naming another operator must not
        // be able to attribute the run to them -- not for an analyst, not
        // for an admin. It stays accepted on the wire (older BFF builds
        // still send it) and is dropped before any handler sees it, so
        // create_run has nothing but require_actor()'s username to use.
        let body: CreateRunBody = serde_json::from_value(serde_json::json!({
            "payload_sha256": "a".repeat(64),
            "owner": "operator-b",
            "analyzers": [],
        }))
        .expect("legacy bodies carrying `owner` must still parse");
        assert_eq!(body.payload_sha256, "a".repeat(64));

        let recipe: SaveRecipeBody = serde_json::from_value(serde_json::json!({
            "name": "r",
            "owner": "operator-b",
            "scope": "private",
            "analyzers": [],
        }))
        .expect("legacy recipe bodies carrying `owner` must still parse");
        assert_eq!(recipe.name, "r");
    }
}
