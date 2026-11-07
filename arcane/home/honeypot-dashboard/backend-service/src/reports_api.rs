//! Reports studio HTTP layer (#1612): template/element catalog, definitions
//! CRUD, and the on-demand generate trigger. Ported from
//! reports_api.go's serveReportTemplates/serveReportDefinitions/
//! createReportDefinition/serveReportDefinitionByID/replaceReportDefinition/
//! removeReportDefinition/generateReport/renderDefinitionToStored/
//! renderDefinitionPDFBytes — only the `default` (generic telemetry)
//! branch of renderDefinitionPDFBytes; the sandbox/payload/ghidra
//! artifact-referenced templates are validated but not yet rendered here
//! (see reports_store.rs's module doc comment for the scope decision).
//!
//! No admin-role/same-origin/If-Match machinery — this crate's trust
//! boundary is the BFF's service token, same posture as every other write
//! path here (config.rs/preferences.rs).

use crate::contract;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::reports_store::{
    self, put_definition, report_template_catalog, GeneratedReportMeta, ReportDefinition,
    ReportScope, ReportTemplateKind, REPORT_ELEMENT_CATALOG,
};
use crate::AppState;

fn bad_request(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.into())
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

#[utoipa::path(
    get,
    path = "/api/v1/reports/templates",
    summary = "The report template and element catalog.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn templates() -> Json<Value> {
    let templates: Vec<Value> = report_template_catalog()
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id, "name": t.name, "description": t.description, "title": t.title,
                "theme": t.theme, "window": t.window, "elements": t.elements,
                "sandbox": t.kind == ReportTemplateKind::Sandbox,
                "payload": t.kind == ReportTemplateKind::Payload,
                "ghidra": t.kind == ReportTemplateKind::Ghidra,
            })
        })
        .collect();
    let elements: Vec<Value> = REPORT_ELEMENT_CATALOG
        .iter()
        .map(|e| json!({"id": e.id, "label": e.label, "description": e.description}))
        .collect();
    Json(json!({"templates": templates, "elements": elements}))
}

#[utoipa::path(
    get,
    path = "/api/v1/reports/definitions",
    summary = "Saved report definitions.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn list_definitions(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let definitions = reports_store::list_definitions(&state)
        .await
        .map_err(bad_gateway)?;
    Ok(Json(json!({"definitions": definitions})))
}

#[utoipa::path(
    get,
    path = "/api/v1/reports/definitions/{id}",
    summary = "One saved report definition.",
    params(
        ("id" = inline(String), Path, description = "Saved report-definition id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn get_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let definition = reports_store::get_definition(&state, &id)
        .await
        .map_err(bad_gateway)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no such report definition".to_string(),
        ))?;
    Ok(Json(json!({"definition": definition})))
}

#[utoipa::path(
    post,
    path = "/api/v1/reports/definitions",
    summary = "Save a new report definition.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `ReportDefinition`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 201, description = "The stored definition."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn create_definition(
    State(state): State<AppState>,
    Json(mut def): Json<ReportDefinition>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
    if !def.id.is_empty() {
        return Err(bad_request(
            "id is assigned by the server; omit it when creating a definition",
        ));
    }
    def.id = String::new();
    let created = put_definition(&state, def).await.map_err(map_store_error)?;
    Ok((StatusCode::CREATED, Json(json!({"definition": created}))))
}

#[utoipa::path(
    put,
    path = "/api/v1/reports/definitions/{id}",
    summary = "Replace one saved report definition.",
    params(
        ("id" = inline(String), Path, description = "Saved report-definition id."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `ReportDefinition`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn replace_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut def): Json<ReportDefinition>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !def.id.is_empty() && def.id != id {
        return Err(bad_request(
            "id in the body must match the path or be omitted",
        ));
    }
    def.id = id;
    let updated = put_definition(&state, def).await.map_err(map_store_error)?;
    Ok(Json(json!({"definition": updated})))
}

#[utoipa::path(
    delete,
    path = "/api/v1/reports/definitions/{id}",
    summary = "Delete one saved report definition.",
    params(
        ("id" = inline(String), Path, description = "Saved report-definition id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn delete_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    reports_store::delete_definition(&state, &id)
        .await
        .map_err(map_store_error)?;
    Ok(Json(json!({"deleted": id})))
}

#[utoipa::path(
    delete,
    path = "/api/v1/reports/generated/{id}",
    summary = "Delete one generated report.",
    params(
        ("id" = inline(String), Path, description = "Generated report id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn delete_generated(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    reports_store::delete_generated(&state, &id)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(json!({"deleted": id})))
}

fn map_store_error(message: String) -> (StatusCode, String) {
    if message.contains("no report definition with this id") {
        (StatusCode::NOT_FOUND, message)
    } else if message.contains("limit reached") {
        (StatusCode::CONFLICT, message)
    } else {
        (StatusCode::UNPROCESSABLE_ENTITY, message)
    }
}

#[derive(Deserialize)]
pub struct GenerateBody {
    #[serde(default = "default_origin")]
    origin: String,
}

fn default_origin() -> String {
    "manual".into()
}

#[utoipa::path(
    post,
    path = "/api/v1/reports/definitions/{id}/generate",
    summary = "Run a saved definition now and store the result.",
    params(
        ("id" = inline(String), Path, description = "Saved report-definition id."),
    ),
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `GenerateBody`. The shape is left open here on purpose -- see the module doc.", extensions(("x-optional-body" = json!(true)))),
    responses(
        (status = 201, description = "The queued run."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 409, description = "The record changed since the revision the caller presented.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn generate(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<GenerateBody>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
    let origin = body
        .map(|b| b.origin.clone())
        .unwrap_or_else(default_origin);
    let definition = reports_store::get_definition(&state, &id)
        .await
        .map_err(bad_gateway)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no such report definition".to_string(),
        ))?;
    let meta = render_definition_to_stored(&state, &definition, &origin)
        .await
        .map_err(map_render_error)?;
    Ok((StatusCode::CREATED, Json(json!({"generated": meta}))))
}

#[utoipa::path(
    post,
    path = "/api/v1/payloads/{hash}/report",
    summary = "One-click payload PDF into the generated store.",
    params(
        ("hash" = inline(contract::PayloadHash), Path, description = "Payload id: 32 or 64 lower-case hex characters."),
    ),
    responses(
        (status = 201, description = "The queued report run."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the reference it was asked to resolve (the reports store answers this for an unresolvable scope or an unexpected storage failure).", body = String, content_type = "text/plain"),
        (status = 501, description = "The saved definition's template is not implemented by the renderer yet.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// POST /api/v1/payloads/{hash}/report — #474's one-click "Generate PDF"
/// trigger on the payload detail page, ported from reports_api.go's
/// generatePayloadReport: unlike the designer flow it never requires a
/// saved definition. An ephemeral, never-persisted payload-template
/// definition scoped to this one hash goes through the exact same
/// rendering/storage pipeline as every other Reports-studio PDF — the
/// generated record lands in dashboard-generated-reports-v1 and is
/// viewable/deletable from Reports studio like any other, it just has no
/// definition_id (nothing to look back up). The viewer then iframes
/// /api/v1/reports/{id}/pdf. Admin gating lives in the BFF, same as every
/// other write path in this crate.
pub async fn generate_payload_report(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
    let valid = (hash.len() == 64 || hash.len() == 32) && hash.chars().all(|c| c.is_ascii_hexdigit());
    if !valid {
        return Err(bad_request("invalid payload id"));
    }
    let def = ReportDefinition {
        name: format!("Payload {hash}"),
        template: "payload".into(),
        theme: "dark".into(),
        scope: ReportScope { hash: hash.clone(), ..Default::default() },
        ..Default::default()
    };
    let meta = render_definition_to_stored(&state, &def, "manual")
        .await
        .map_err(map_render_error)?;
    Ok((StatusCode::CREATED, Json(json!({"id": meta.id, "generated": meta}))))
}

#[utoipa::path(
    post,
    path = "/api/v1/reports/preview",
    summary = "What a report definition would contain, without rendering it.",
    description = "Takes the body `POST /api/v1/reports/definitions` takes (id and schedule are ignored; nothing is stored) and answers with the period, headline totals, and for every selected element its row count, pages, two column headings and the first five rows, plus the total page count of the PDF the same definition would generate. The data comes from the renderer's own query and the page counts from its own layout pass, so the preview and the PDF agree. Every scope field (`window`, `ip`, `network`, `sensor`, `port`, `signature`, `country`, `asn`, `type`, `session`, `text`) is applied exactly as in generation; each is single-valued, so a list-valued picker cannot be expressed and must be reduced to one value (or the report split) by the caller. When no events match, `empty_filter` names the first scope field that leaves nothing. Only the telemetry templates (executive, security, threat, incident, ...) can be previewed; the sandbox, payload and ghidra templates render one artifact and answer 422.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `ReportDefinition`. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "The preview: `{period: {from, to}, events, sources, sensors, sessions, sections: [{id, label, rows, pages, columns: [string, string], sample: [[string, string]]}], pages, empty_filter?: {field, message}}`.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> extractor refused the body before the handler ran, or the route's own domain check rejected the definition (invalid fields, or an artifact template that has no telemetry to preview).", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn preview(
    State(state): State<AppState>,
    Json(mut def): Json<ReportDefinition>,
) -> Result<Json<crate::reports_data::ReportPreview>, (StatusCode, String)> {
    // A draft has no identity or schedule yet; only the content is checked.
    def.id = String::new();
    def.schedule = None;
    reports_store::validate_definition_fields(&def).map_err(|message| (StatusCode::UNPROCESSABLE_ENTITY, message))?;
    let template = report_template_catalog()
        .into_iter()
        .find(|t| t.id == def.template)
        .ok_or_else(|| (StatusCode::UNPROCESSABLE_ENTITY, "unknown report template".to_string()))?;
    if template.kind != ReportTemplateKind::Generic {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "preview is only available for the telemetry templates; this template renders a single artifact".to_string(),
        ));
    }
    let title = report_title(&def, template.title);
    let preview = crate::reports_data::preview_for(&state, &def, title)
        .await
        .map_err(bad_gateway)?;
    Ok(Json(preview))
}

fn map_render_error(message: String) -> (StatusCode, String) {
    if message.contains("not yet implemented") {
        (StatusCode::NOT_IMPLEMENTED, message)
    } else if message.contains("does not resolve") {
        (StatusCode::UNPROCESSABLE_ENTITY, message)
    } else {
        (StatusCode::BAD_GATEWAY, message)
    }
}

/// Up to 20 sandbox-analysis-v1 runs matching a captured payload's hash,
/// newest first — payload_pdf.go's own `binaryAnalysis.SandboxRuns` slice,
/// assembled here from the promoted `file.hash.sha256` field every
/// es_importer.rs-mirrored source carries (same field ghidra_run/cape_run
/// query elsewhere in this crate). Raw `_source` docs, same shape
/// render_sandbox_pdf itself reads.
async fn sandbox_runs_for_hash(state: &AppState, hash: &str) -> anyhow::Result<Vec<Value>> {
    let result = state
        .es
        .search_index(
            &["sandbox-analysis-v1"],
            json!({"size": 20, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"term": {"file.hash.sha256": hash}}}),
        )
        .await?;
    Ok(result["hits"]["hits"].as_array().into_iter().flatten().map(|hit| hit["_source"].clone()).collect())
}

/// The title a definition's report carries: its branding title, else the
/// template's. Shared by the renderer and the preview.
fn report_title(def: &ReportDefinition, template_title: &str) -> String {
    let trimmed = def.branding.title.trim();
    if trimmed.is_empty() {
        template_title.to_string()
    } else {
        trimmed.to_string()
    }
}

/// renderDefinitionToStored + renderDefinitionPDFBytes, shared by the
/// manual generate endpoint and the scheduler (worker.rs). The sandbox/
/// payload/ghidra branches each resolve their scope reference to one
/// artifact and hand it to report_pdf.rs's matching renderer; `default`
/// keeps the generic telemetry path unchanged.
pub async fn render_definition_to_stored(
    state: &AppState,
    def: &ReportDefinition,
    origin: &str,
) -> Result<GeneratedReportMeta, String> {
    let template = crate::reports_store::report_template_catalog()
        .into_iter()
        .find(|t| t.id == def.template)
        .ok_or_else(|| "unknown report template".to_string())?;

    let title = report_title(def, template.title);
    let theme = crate::report_pdf::pdf_theme_named(&def.theme);
    let branding = def.branding.to_pdf_branding();
    let generated = chrono::Utc::now();

    let pdf = match template.kind {
        ReportTemplateKind::Sandbox => {
            let job = def.scope.job.trim();
            if job.is_empty() {
                return Err("scope.job does not resolve to a completed sandbox result".to_string());
            }
            let doc = crate::detail::sandbox_run(State(state.clone()), Path(job.to_string()))
                .await
                .map_err(|_| "scope.job does not resolve to a completed sandbox result".to_string())?
                .0;
            crate::report_pdf::render_sandbox_pdf(&doc, generated, theme, branding)
        }
        ReportTemplateKind::Ghidra => {
            let hash = def.scope.hash.trim();
            if hash.is_empty() {
                return Err("scope.hash does not resolve to a completed ghidra result".to_string());
            }
            let doc = crate::detail::ghidra_run(State(state.clone()), Path(hash.to_string()))
                .await
                .map_err(|_| "scope.hash does not resolve to a completed ghidra result".to_string())?
                .0;
            crate::report_pdf::render_ghidra_pdf(&doc, generated, theme, branding)
        }
        ReportTemplateKind::Payload => {
            let hash = def.scope.hash.trim();
            if hash.is_empty() {
                return Err("scope.hash does not resolve to a captured payload".to_string());
            }
            let detail = crate::payload_detail::detail(State(state.clone()), Path(hash.to_string()))
                .await
                .map_err(|_| "scope.hash does not resolve to a captured payload".to_string())?
                .0;
            let inventory = detail.inventory.unwrap_or(Value::Null);
            let analysis = detail.analysis.unwrap_or(Value::Null);
            let sandbox_runs = sandbox_runs_for_hash(state, hash).await.map_err(|e| e.to_string())?;
            let github_analysis = crate::detail::github_analysis_run(State(state.clone()), Path(hash.to_string()))
                .await
                .map(|json| json.0)
                .unwrap_or(Value::Null);
            crate::report_pdf::render_payload_pdf(
                hash,
                &inventory,
                &analysis,
                &detail.yara,
                &sandbox_runs,
                &github_analysis,
                generated,
                theme,
                branding,
            )
        }
        ReportTemplateKind::Generic => {
            let appendix_limit = if def.appendix_limit <= 0 { 120 } else { def.appendix_limit };
            let mut data = crate::reports_data::report_data_for(state, &def.scope, title.clone(), appendix_limit)
                .await
                .map_err(|e| e.to_string())?;
            data.title = title.clone();
            crate::report_pdf::render_report_pdf(&data, theme, branding, &def.elements, appendix_limit)
        }
    };

    reports_store::add_generated(
        state,
        GeneratedReportMeta {
            id: String::new(),
            definition_id: def.id.clone(),
            name: def.name.clone(),
            template: def.template.clone(),
            theme: def.theme.clone(),
            title,
            size_bytes: 0,
            created_at: String::new(),
            origin: origin.to_string(),
        },
        pdf,
    )
    .await
    .map_err(|e| e.to_string())
}
