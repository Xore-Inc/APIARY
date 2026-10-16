//! Canarytoken management (#1487), ported from canarytokens_client.go /
//! canarytokens_api.go: create against the self-hosted Canarytokens
//! platform's REST API (WireGuard-tunnel-only; CANARYTOKENS_API_URL +
//! CANARYTOKENS_API_ROOT), persist the record to
//! dashboard-canarytokens-v1, and proxy artifact downloads. The trigger
//! webhook stays the adapter (fired events flow through the existing
//! pipeline unchanged).

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

/// frontend/app.py's ROOT_API_ENDPOINT at the pinned CANARYTOKENS_REF —
/// deliberately non-guessable (upstream anti-scraping), not "/api".
const DEFAULT_API_ROOT: &str = "/d3aece8093b71007b5ccfedad91ebb11";
const MAX_UPLOAD_BYTES: usize = 8 << 20;

/// RFC 2606/6761 domains reserved for documentation. Everything this
/// repo ships as a stand-in apex (compose defaults, .env.example values)
/// sits under exactly one of these suffixes, and no real deployment
/// domain ever does (.example is a whole TLD, the rest full second-level
/// names). Endings rather than equality on purpose: a generated token's
/// hostname is always its own random label subdomained under whatever
/// domain the stack was handed.
const RESERVED_PLACEHOLDER_SUFFIXES: &[&str] =
    &[".example", ".example.com", ".example.net", ".example.org", ".invalid"];

/// #2331 belt-and-braces, create-time half of the fix: the platform bakes
/// generate()'s returned hostname into each artifact at creation, and the
/// stack serves `${CANARY_PUBLIC_HOSTNAME:-honeypot.example}` -- so an
/// operator who copied the shipped .env without overriding it plants
/// triggers that can only resolve through this repo's placeholder domain,
/// silently dead air that reads as "nobody took the bait". Refusing here
/// names the exact knob instead of issuing unresolvable bait; a
/// derive-at-deploy default for the stack env itself is tracked
/// separately in install-homeserver.sh.
fn placeholder_hostname(hostname: &str) -> bool {
    let host = hostname.to_ascii_lowercase();
    RESERVED_PLACEHOLDER_SUFFIXES
        .iter()
        .any(|suffix| host.ends_with(suffix))
}

pub struct TokenType {
    id: &'static str,
    label: &'static str,
    description: &'static str,
    download_fmt: &'static str,
    content_type: &'static str,
    filename_suffix: &'static str,
    requires_upload: bool,
    supports_snippet: bool,
}

pub const TYPES: &[TokenType] = &[
    TokenType { id: "adobe_pdf", label: "PDF document", description: "A decoy PDF that fires when opened.", download_fmt: "pdf", content_type: "application/pdf", filename_suffix: ".pdf", requires_upload: false, supports_snippet: false },
    TokenType { id: "ms_word", label: "Word document", description: "A decoy .docx that fires when opened.", download_fmt: "msword", content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename_suffix: ".docx", requires_upload: false, supports_snippet: true },
    TokenType { id: "ms_excel", label: "Excel workbook", description: "A decoy .xlsx that fires when opened.", download_fmt: "msexcel", content_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename_suffix: ".xlsx", requires_upload: false, supports_snippet: true },
    TokenType { id: "web_image", label: "Custom web image", description: "A web bug behind your own image; fires on load.", download_fmt: "", content_type: "", filename_suffix: "", requires_upload: true, supports_snippet: false },
    TokenType { id: "windows_dir", label: "Windows Folder token", description: "A desktop.ini + icon bundle that fires when the folder is opened in Explorer.", download_fmt: "zip", content_type: "application/zip", filename_suffix: ".zip", requires_upload: false, supports_snippet: false },
    TokenType { id: "qr_code", label: "QR code", description: "A PNG QR code that fires when scanned and opened.", download_fmt: "qr_code", content_type: "image/png", filename_suffix: ".png", requires_upload: false, supports_snippet: false },
];

fn base_url() -> Option<String> {
    let api = std::env::var("CANARYTOKENS_API_URL").ok()?;
    if api.is_empty() {
        return None;
    }
    let root = std::env::var("CANARYTOKENS_API_ROOT").unwrap_or_else(|_| DEFAULT_API_ROOT.into());
    Some(format!("{}{}", api.trim_end_matches('/'), root))
}

fn adapter_webhook_url(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.to_string())
}

fn type_info(token_type: &str) -> Option<&'static TokenType> {
    TYPES.iter().find(|entry| entry.id == token_type)
}

#[utoipa::path(
    get,
    path = "/api/v1/canarytokens/types",
    summary = "The canarytoken types this build can mint.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn types() -> Json<Value> {
    Json(json!(TYPES
        .iter()
        .map(|entry| json!({
            "token_type": entry.id,
            "label": entry.label,
            "description": entry.description,
            "requires_upload": entry.requires_upload,
            "supports_snippet": entry.supports_snippet,
        }))
        .collect::<Vec<_>>()))
}

#[derive(Deserialize)]
pub struct CreateBody {
    pub token_type: String,
    pub memo: String,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub include_text_snippet: bool,
    #[serde(default)]
    pub text_snippet: String,
    /// web_image upload, base64 (the BFF forwards the browser file).
    #[serde(default)]
    pub file_base64: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub file_content_type: String,
}

#[derive(Serialize)]
pub struct CreatedToken {
    pub id: String,
    pub token_type: String,
    pub memo: String,
    pub token_url: String,
    pub hostname: String,
    pub created_by: String,
    pub created_at: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/canarytokens",
    summary = "Mint a canarytoken.",
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
pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<CreatedToken>, (StatusCode, String)> {
    let base = base_url().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "canarytoken creation is not configured on this host".to_string(),
    ))?;
    let webhook = std::env::var("CANARYTOKENS_ADAPTER_WEBHOOK_URL")
        .ok()
        .and_then(|raw| adapter_webhook_url(&raw))
        .ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            "canarytoken adapter webhook is not configured on this host".to_string(),
        ))?;
    let info = type_info(&body.token_type)
        .ok_or((StatusCode::BAD_REQUEST, "unsupported token_type".to_string()))?;
    let memo = body.memo.trim().to_string();
    if memo.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "memo is required".into()));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let request = client.post(format!("{base}/generate"));
    let response = if info.requires_upload {
        // upload-required type (web_image): multipart form.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.file_base64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "a file upload is required for this token type".to_string()))?;
        if bytes.is_empty() || bytes.len() > MAX_UPLOAD_BYTES {
            return Err((StatusCode::BAD_REQUEST, "invalid upload size".into()));
        }
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(body.file_name.clone())
            .mime_str(if body.file_content_type.is_empty() { "application/octet-stream" } else { &body.file_content_type })
            .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
        let form = reqwest::multipart::Form::new()
            .text("token_type", body.token_type.clone())
            .text("memo", memo.clone())
            .text("webhook_url", webhook.clone())
            .part(body.token_type.clone(), part);
        request.multipart(form).send().await
    } else {
        let mut payload = json!({
            "token_type": body.token_type,
            "memo": memo,
            "webhook_url": webhook,
        });
        if info.supports_snippet && body.include_text_snippet {
            payload["include_text_snippet"] = json!(true);
            payload["text_snippet"] = json!(body.text_snippet.trim());
        }
        request.json(&payload).send().await
    }
    .map_err(|error| (StatusCode::BAD_GATEWAY, format!("canarytokens: {error}")))?;

    let status = response.status();
    let result: Value = response
        .json()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("canarytokens: malformed generate response: {error}")))?;
    let token = result["token"].as_str().unwrap_or("");
    let auth = result["auth_token"].as_str().unwrap_or("");
    if !status.is_success() || token.is_empty() || auth.is_empty() {
        let message = result["error_message"]
            .as_str()
            .filter(|text| !text.is_empty())
            .map(String::from)
            .unwrap_or_else(|| format!("canarytokens: generate failed with status {status}"));
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    // #2331: fail before persisting or returning -- a token generated
    // against the placeholder domain would be planted as-is by the next
    // step and could never fire for anyone outside this network.
    let baked_hostname = result["hostname"].as_str().unwrap_or("");
    if placeholder_hostname(baked_hostname) {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "canarytokens: refusing to plant a token whose trigger hostname '{baked_hostname}' is \
                 still this repo's placeholder domain -- set CANARY_PUBLIC_HOSTNAME in the \
                 honeypot-canarytokens stack .env to the deployed bare apex (see \
                 docs/CGNAT-DEPLOYMENT.md's DNS section) and redeploy that stack before creating tokens"
            ),
        ));
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let record = json!({
        "id": token,
        "token_type": body.token_type,
        "memo": memo,
        "token_url": result["token_url"].as_str().unwrap_or(""),
        "hostname": result["hostname"].as_str().unwrap_or(""),
        "filename_hint": body.file_name,
        "auth_token": auth,
        "created_by": body.created_by,
        "created_at": created_at,
    });
    state
        .es
        .index_doc("dashboard-canarytokens-v1", token, record)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    Ok(Json(CreatedToken {
        id: token.to_string(),
        token_type: body.token_type,
        memo,
        token_url: result["token_url"].as_str().unwrap_or("").to_string(),
        hostname: result["hostname"].as_str().unwrap_or("").to_string(),
        created_by: body.created_by,
        created_at,
    }))
}

/// One history record's browser-facing shape: auth_token stripped,
/// everything else passed through untouched. Extracted from list()'s map
/// so the strip has its own test -- the ES document keeps the credential
/// (create() persists it for download()'s ?auth= use), only responses
/// drop it.
fn redact_record(mut record: Value) -> Value {
    if let Some(object) = record.as_object_mut() {
        object.remove("auth_token");
    }
    record
}

#[utoipa::path(
    get,
    path = "/api/v1/canarytokens",
    summary = "Minted canarytokens, with their management token redacted.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/canarytokens — every created token's history record, newest
/// first, for the Settings pane's history table and credentials'
/// link-token id validation. auth_token is the platform's own management
/// credential for that token (equivalent to a password) and must never
/// reach a browser — see create()'s CreatedToken response for the same
/// redaction, this list applies it too rather than encoding the ES
/// document straight through.
///
/// Restored (2026-08-19) after a prior pass deleted this as "dead code" on
/// the theory that frontend-next only reads the list through the generic
/// /api/v1/store/canarytokens proxy — true for canarytokens.tsx, but
/// credentials.tsx (added in the same PR that deleted this) calls this
/// exact route by name to populate its link-token dropdown, and the
/// generic proxy returns a different shape ({total, rows}, not {tokens})
/// and does not redact auth_token. Deleting this silently broke that
/// dropdown (serviceJSON swallows the resulting 404 as null) with no
/// visible error anywhere.
pub async fn list(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&["dashboard-canarytokens-v1"], json!({"size": 1000}))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let mut records: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| redact_record(hit["_source"].clone()))
        .collect();
    records.sort_by(|a, b| {
        let a = a["created_at"].as_str().unwrap_or_default();
        let b = b["created_at"].as_str().unwrap_or_default();
        b.cmp(a)
    });
    Ok(Json(json!({"tokens": records})))
}

#[utoipa::path(
    get,
    path = "/api/v1/canarytokens/{id}/download",
    summary = "The canarytoken's landing URL, as a redirect.",
    params(
        ("id" = inline(String), Path, description = "Canarytoken id."),
    ),
    responses(
        (status = 302, description = "Redirect to the token's landing URL."),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 500, description = "The handler failed in a way it does not model as a 4xx.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 503, description = "A dependency this route needs is not configured or not reachable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/canarytokens/{id}/download — proxy the token's artifact.
/// web_image never goes through /download (fetching the trigger URL
/// server-side would itself fire the token).
pub async fn download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let base = base_url().ok_or((StatusCode::SERVICE_UNAVAILABLE, "not configured".to_string()))?;
    let record = state
        .es
        .search_index(
            &["dashboard-canarytokens-v1"],
            json!({"size": 1, "query": {"term": {"id": id}}}),
        )
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let source = record["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .ok_or((StatusCode::NOT_FOUND, "no such token".to_string()))?;
    let token_type = source["token_type"].as_str().unwrap_or("");
    let info = type_info(token_type).ok_or((StatusCode::BAD_REQUEST, "unknown token type".to_string()))?;
    if info.download_fmt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "this token type has no downloadable artifact".into()));
    }
    let auth = source["auth_token"].as_str().unwrap_or("");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let upstream = client
        .get(format!("{base}/download"))
        .query(&[("token", id.as_str()), ("auth", auth), ("fmt", info.download_fmt)])
        .send()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("canarytokens: {error}")))?;
    if !upstream.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("canarytokens: download failed with status {}", upstream.status())));
    }
    let bytes = upstream
        .bytes()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let filename = format!("canarytoken-{}{}", &id[..id.len().min(12)], info.filename_suffix);
    Ok((
        [
            (header::CONTENT_TYPE, info.content_type.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        bytes.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_webhook_accepts_host_specific_http_endpoints() {
        assert_eq!(
            adapter_webhook_url("http://canarytokens-adapter.internal:8090/"),
            Some("http://canarytokens-adapter.internal:8090/".into())
        );
        assert_eq!(
            adapter_webhook_url("https://adapter.example.test/hooks/canary"),
            Some("https://adapter.example.test/hooks/canary".into())
        );
    }

    #[test]
    fn adapter_webhook_rejects_missing_or_unsafe_endpoints() {
        for value in [
            "",
            "not-a-url",
            "file:///tmp/hook",
            "http://user:pass@adapter.example.test/",
            "https://adapter.internal/#fragment",
        ] {
            assert!(adapter_webhook_url(value).is_none(), "accepted {value}");
        }
    }

    #[test]
    fn the_compose_placeholder_itself_is_named() {
        assert!(placeholder_hostname("honeypot.example"));
    }

    #[test]
    fn a_token_hostname_subdomained_under_the_placeholder_is_caught() {
        // What generate() actually returns on an unprovisioned deploy:
        // canarydrop.generate_random_hostname()'s random label over the
        // stack's CANARY_PUBLIC_HOSTNAME. Exact-match against the bare
        // placeholder would miss every real token this way.
        assert!(placeholder_hostname("quiet-river-4211.honeypot.example"));
    }

    #[test]
    fn case_is_normalized_before_matching() {
        assert!(placeholder_hostname("Honeypot.Example"));
        assert!(placeholder_hostname("QUIET-RIVER-4211.Honeypot.Example"));
    }

    #[test]
    fn the_other_reserved_documentation_domains_are_caught_too() {
        // The stand-ins shipped across this repo's other stacks
        // (dashboard OIDC_ISSUER_URL's example.invalid etc.) -- if those
        // ever get pasted here as an "apex", same dead-air outcome.
        assert!(placeholder_hostname("x.example.com"));
        assert!(placeholder_hostname("y.example.net"));
        assert!(placeholder_hostname("z.example.org"));
        assert!(placeholder_hostname("w.invalid"));
    }

    #[test]
    fn real_deployed_apexes_pass_through() {
        assert!(!placeholder_hostname("quiet-river-4211.decoys.example-shack.net"));
        assert!(!placeholder_hostname("tokeneer.io"));
        assert!(!placeholder_hostname("label.honeynet.mydomain.dev"));
    }

    #[test]
    fn near_miss_forms_that_are_not_the_reserved_namespaces_pass() {
        // Deliberate anchors: only reserved-suffix ENDINGS count --
        // "example.evil.com" merely contains the word, and RFC 2606 says
        // nothing about subdomains two levels under ".example"
        // ("a.b.example" ends with ".example" and IS caught; these are
        // not that).
        assert!(!placeholder_hostname("example.evil.com"));
        assert!(!placeholder_hostname("a.b.co.uk"));
    }

    #[test]
    fn an_empty_or_missing_hostname_is_not_ours_to_judge() {
        // create() leaves the platform's response shape alone otherwise;
        // an absent hostname field means nothing to bake, so nothing to
        // refuse.
        assert!(!placeholder_hostname(""));
    }

    // The rest of this module pins #2457's invariant: auth_token (the
    // platform's management credential for a token, password-equivalent)
    // is persisted to dashboard-canarytokens-v1 but never serializes into
    // any browser-facing shape. See list()'s doc-comment for the incident
    // that makes this load-bearing: a generic /api/v1/store proxy route
    // once served this index with auth_token's shape exposed. These
    // assertions exist so widening a projection, adding a passthrough
    // proxy over the ES index, or forgetting the strip in a third
    // response shape fails here first.

    const FAKE_AUTH_TOKEN: &str = "tok-secret-abcdef1234567890";

    /// The ES document exactly as create()'s persisted `record` json!()
    /// block writes it -- nine fields, credential included.
    fn es_record(id: &str, created_at: &str) -> Value {
        json!({
            "id": id,
            "token_type": "ms_word",
            "memo": format!("decoy {id}"),
            "token_url": format!("https://decoys.example-shack.net/{id}"),
            "hostname": "quiet-river-4211.decoys.example-shack.net",
            "filename_hint": "quarterly-report.docx",
            "auth_token": FAKE_AUTH_TOKEN,
            "created_by": "ops",
            "created_at": created_at,
        })
    }

    fn assert_no_credential(text: &str) {
        assert!(!text.contains("auth_token"), "field name leaked: {text}");
        assert!(
            !text.contains(FAKE_AUTH_TOKEN),
            "credential value leaked past its own key (sibling-field embedding): {text}"
        );
    }

    #[test]
    fn created_token_serialization_never_carries_the_auth_token() {
        // create() builds CreatedToken field-by-field rather than
        // serializing the ES record, so the struct's field list IS the
        // redaction. A new field added there has to be added to this
        // initializer too, forcing whoever touches it through these
        // assertions. Both the key name and the value are checked: a
        // token_url-style sibling embedding the credential must not pass
        // on a technicality.
        let record = es_record("0fdec0yF", "2026-08-27T00:00:00+00:00");
        let created = CreatedToken {
            id: record["id"].as_str().unwrap().to_string(),
            token_type: record["token_type"].as_str().unwrap().to_string(),
            memo: record["memo"].as_str().unwrap().to_string(),
            token_url: record["token_url"].as_str().unwrap().to_string(),
            hostname: record["hostname"].as_str().unwrap().to_string(),
            created_by: record["created_by"].as_str().unwrap().to_string(),
            created_at: record["created_at"].as_str().unwrap().to_string(),
        };
        let wire = serde_json::to_string(&created).unwrap();
        assert_no_credential(&wire);
        assert!(serde_json::to_value(&created).unwrap().get("auth_token").is_none());
    }

    #[test]
    fn every_history_record_comes_back_without_the_auth_token() {
        // list()'s strip via redact_record(), over two documents shaped
        // like real hits.hits[] entries -- "every returned object", not
        // just the newest.
        let hits = json!({
            "hits": {"hits": [
                {"_index": "dashboard-canarytokens-v1", "_id": "old", "_source": es_record("old", "2026-08-26T10:00:00+00:00")},
                {"_index": "dashboard-canarytokens-v1", "_id": "new", "_source": es_record("new", "2026-08-27T09:30:00+00:00")},
            ]}
        });
        let tokens: Vec<Value> = hits["hits"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| redact_record(hit["_source"].clone()))
            .collect();
        assert_eq!(tokens.len(), 2);
        for token in &tokens {
            assert!(token.get("auth_token").is_none());
            assert_no_credential(&token.to_string());
            // Stripping, not truncating: everything else in the document
            // survives intact, down to filename_hint (which history keeps
            // even though CreatedToken's response omits it).
            for kept in [
                "id",
                "token_type",
                "memo",
                "token_url",
                "hostname",
                "filename_hint",
                "created_by",
                "created_at",
            ] {
                assert!(
                    token.get(kept).is_some(),
                    "redaction dropped {kept} along with the credential"
                );
            }
        }
        assert_eq!(tokens[0]["id"], "old");
        assert_eq!(tokens[1]["id"], "new");
    }
}
