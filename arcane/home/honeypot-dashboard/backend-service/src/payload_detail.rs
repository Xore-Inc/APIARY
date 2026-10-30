//! /api/v1/payloads/{hash} — one captured payload's full picture: the
//! inventory row, static analysis (dashboard-static-analysis-v1), YARA
//! results, and a bounded hex preview from dashboard-payload-bytes-v1
//! (the full artifact stays server-side; only the preview crosses the
//! wire, mirroring the legacy static-analysis page's posture).

use crate::contract;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

const PREVIEW_BYTES: usize = 512;
/// Matches Go's payloadBytesRawCap (payload_bytes_es.go) — the same
/// dashboard-payload-bytes-v1 documents this crate's payload_bytes.rs
/// mirrors, capped at the same 32MB.
const RAW_CAP_BYTES: u64 = 32 << 20;

#[derive(Serialize)]
pub struct PayloadDetail {
    pub hash: String,
    pub inventory: Option<Value>,
    pub analysis: Option<Value>,
    pub yara: Vec<Value>,
    pub size_bytes: u64,
    /// classic hexdump rows of the first bytes ("00000000  4d 5a 90 …  |MZ..|").
    pub hex_preview: Vec<String>,
}

fn hexdump(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(index, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
            let ascii: String = chunk
                .iter()
                .map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' })
                .collect();
            format!("{:08x}  {:<47}  |{}|", index * 16, hex.join(" "), ascii)
        })
        .collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/payloads/{hash}",
    summary = "One captured payload and its analysis.",
    params(
        ("hash" = inline(contract::PayloadHash), Path, description = "Payload id: 32 or 64 lower-case hex characters."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn detail(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<PayloadDetail>, (StatusCode, String)> {
    let bad_gateway = |error: anyhow::Error| (StatusCode::BAD_GATEWAY, error.to_string());
    let first_hit = |result: &Value| -> Option<Value> {
        result["hits"]["hits"].as_array().and_then(|hits| hits.first()).map(|hit| hit["_source"].clone())
    };

    let (inventory, analysis, yara, bytes) = tokio::try_join!(
        state.es.search_index(
            &["dashboard-payload-inventory-v1"],
            json!({"size": 1, "query": {"term": {"Hash": hash}}}),
        ),
        state.es.search_index(
            &["dashboard-static-analysis-v1"],
            json!({"size": 1, "query": {"term": {"Fingerprint": hash}}}),
        ),
        state.es.search_index(
            &["yara-analysis-v1"],
            json!({"size": 10, "query": {"bool": {"should": [
                {"term": {"file.hash.sha256": hash}},
                {"term": {"file.hash.md5": hash}}
            ], "minimum_should_match": 1}}}),
        ),
        state.es.search_index(
            &["dashboard-payload-bytes-v1"],
            json!({"size": 1, "query": {"term": {"hash": hash}}}),
        ),
    )
    .map_err(bad_gateway)?;

    let mut bytes_source = first_hit(&bytes);
    if bytes_source.is_none() {
        // #1612 self-heal: this replica hasn't mirrored this hash yet —
        // mirror on demand from disk rather than serving an empty preview
        // until payload-inventory-worker's next scan cycle catches it.
        crate::payload_bytes::ensure_mirrored(&state, &hash).await;
        if let Ok(result) = state
            .es
            .search_index(&["dashboard-payload-bytes-v1"], json!({"size": 1, "query": {"term": {"hash": hash}}}))
            .await
        {
            bytes_source = first_hit(&result);
        }
    }
    let (size_bytes, hex_preview) = match &bytes_source {
        Some(source) => {
            let size = source["size_bytes"].as_u64().unwrap_or(0);
            let encoded = source["data_base64"].as_str().unwrap_or("");
            // Decode only enough base64 for the preview window.
            let prefix_len = (PREVIEW_BYTES * 4 / 3 + 4).min(encoded.len());
            let mut prefix = &encoded[..prefix_len];
            while !prefix.len().is_multiple_of(4) {
                prefix = &prefix[..prefix.len() - 1];
            }
            let decoded = base64::engine::general_purpose::STANDARD.decode(prefix).unwrap_or_default();
            (size, hexdump(&decoded[..decoded.len().min(PREVIEW_BYTES)]))
        }
        None => (0, Vec::new()),
    };

    let yara_rows: Vec<Value> = yara["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect())
        .unwrap_or_default();

    let inventory = first_hit(&inventory);
    let analysis = first_hit(&analysis);
    if inventory.is_none() && analysis.is_none() && bytes_source.is_none() && yara_rows.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no such payload".into()));
    }

    Ok(Json(PayloadDetail { hash, inventory, analysis, yara: yara_rows, size_bytes, hex_preview }))
}

#[utoipa::path(
    get,
    path = "/api/v1/payloads/{hash}/raw",
    summary = "One captured payload's bytes.",
    params(
        ("hash" = inline(contract::PayloadHash), Path, description = "Payload id: 32 or 64 lower-case hex characters."),
    ),
    responses(
        (status = 200, description = "The payload bytes.", body = inline(serde_json::Value), content_type = "application/octet-stream"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 413, description = "The stored artifact is larger than this endpoint will serve.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/payloads/{hash}/raw — streams the full captured binary,
/// ported from payloads_data.go's servePayload. Admin-gating happens at
/// the BFF (apiary-dashboard checks the session role before ever calling
/// this route) — this tier has no admin check of its own, same posture as
/// every other write/download action here.
pub async fn raw(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !crate::payload_paths::is_valid_hash(&hash) {
        return Err((StatusCode::BAD_REQUEST, "invalid payload id".into()));
    }
    let bad_gateway = |error: anyhow::Error| (StatusCode::BAD_GATEWAY, error.to_string());

    let mut doc = state.es.get_doc("dashboard-payload-bytes-v1", &hash).await.map_err(bad_gateway)?;
    if doc.is_none() {
        crate::payload_bytes::ensure_mirrored(&state, &hash).await;
        doc = state.es.get_doc("dashboard-payload-bytes-v1", &hash).await.map_err(bad_gateway)?;
    }
    let Some(source) = doc else {
        return Err((StatusCode::NOT_FOUND, "no such payload".into()));
    };
    if source["too_large"].as_bool().unwrap_or(false) {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("payload exceeds the {RAW_CAP_BYTES}-byte size cap for dashboard download"),
        ));
    }
    let encoded = source["data_base64"].as_str().unwrap_or("");
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("payload decode: {error}")))?;

    // Force a download of an inert blob — never let a browser sniff/run it.
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{hash}.malware.bin\"")),
        ],
        data,
    ))
}
