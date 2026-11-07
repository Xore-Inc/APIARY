//! Manual IP blocking (#914), ported from ip_block.go: block state in
//! dashboard-ip-block-v1 keyed by the IP itself, optional per-block
//! expiry (computed fresh on read, no background sweep), and the plain
//! text export the VPS firewall puller consumes every 5 minutes
//! (portbridge-manual-blackhole-refresh.sh). An ES outage on the export
//! is a 5xx — never an empty 200 the puller would read as "operator
//! cleared every block" (#1342).

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::AppState;

const INDEX: &str = "dashboard-ip-block-v1";

/// The `ExpiresAt` a request asks for (#3525). A block must name its
/// duration: `expires_days` absent is refused, `0` is the one way to ask for
/// a permanent block (`null`). An unblock carries no expiry.
fn expiry_for(
    blocked: bool,
    expires_days: Option<u32>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, (StatusCode, String)> {
    if !blocked {
        return Ok(Value::Null);
    }
    match expires_days {
        None => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_days is required when blocked is true; 0 means permanent".into(),
        )),
        // null, not "" -- the index maps ExpiresAt as date and rejects an
        // empty string outright (confirmed live).
        Some(0) => Ok(Value::Null),
        Some(days) => Ok(json!((now + chrono::Duration::days(i64::from(days))).to_rfc3339())),
    }
}

fn active(record: &Value) -> bool {
    if !record["Blocked"].as_bool().unwrap_or(false) {
        return false;
    }
    match record["ExpiresAt"].as_str().filter(|value| !value.is_empty() && !value.starts_with("0001-")) {
        None => true,
        Some(expires) => chrono::DateTime::parse_from_rfc3339(expires)
            .map(|at| chrono::Utc::now() < at.with_timezone(&chrono::Utc))
            .unwrap_or(true),
    }
}

#[derive(Deserialize)]
pub struct BlockBody {
    pub ip: String,
    pub blocked: bool,
    /// Required when `blocked` is true (#3525): the number of days the
    /// block lasts, `0` meaning permanent. Absent on a block is a 422.
    /// Ignored on an unblock.
    #[serde(default)]
    pub expires_days: Option<u32>,
    #[serde(default)]
    pub actor: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/ip-block",
    summary = "Block or unblock an address.",
    request_body(content = inline(serde_json::Value), description = "Deserialized by the handler into `BlockBody`: `{ip, blocked, expires_days?, actor?}`. `expires_days` (days, integer >= 0) is required when `blocked` is true and `0` means a permanent block; omitting it on a block is a 422. It is ignored on an unblock. `actor` is bound to the verified actor. The shape is left open here on purpose -- see the module doc."),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 415, description = "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.", body = String, content_type = "text/plain"),
        (status = 422, description = "Well-formed but unprocessable: the Json<T> extractor refused the body before the handler ran, or `blocked` is true and `expires_days` is absent (send `0` for a permanent block).", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn set_block(
    State(state): State<AppState>,
    binding: crate::trust::ActorBinding,
    Json(mut body): Json<BlockBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    body.actor = binding.bind("actor", crate::trust::ActorField::Username, &body.actor)?;
    if body.ip.parse::<IpAddr>().is_err() {
        return Err((StatusCode::BAD_REQUEST, "invalid IP address".into()));
    }
    let now = chrono::Utc::now();
    let expires_at = expiry_for(body.blocked, body.expires_days, now)?;
    let record = json!({
        "IP": body.ip,
        "Blocked": body.blocked,
        "BlockedBy": body.actor,
        "BlockedAt": now.to_rfc3339(),
        "ExpiresAt": expires_at,
    });
    state
        .es
        .index_doc(INDEX, &body.ip, record.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(record))
}

#[utoipa::path(
    get,
    path = "/api/v1/ip-block/{ip}",
    summary = "One address's block state.",
    params(
        ("ip" = inline(String), Path, description = "Address whose block state is wanted."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn get_block(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if ip.parse::<IpAddr>().is_err() {
        return Err((StatusCode::BAD_REQUEST, "invalid IP address".into()));
    }
    let record = state
        .es
        .get_doc(INDEX, &ip)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"IP": ip, "Blocked": false}));
    let is_active = active(&record);
    let mut out = record;
    out["Active"] = json!(is_active);
    Ok(Json(out))
}

#[utoipa::path(
    get,
    path = "/api/v1/ip-block-export",
    summary = "The whole block list, for backup or review.",
    responses(
        (status = 200, description = "The blocked addresses, one per line.", body = inline(serde_json::Value), content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = []), ("exportToken" = [])),
)]
/// Plain text list of actively blocked IPs, sorted — byte-compatible
/// with the legacy /export/portbridge-manual-blackhole.txt body.
pub async fn export(State(state): State<AppState>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&[INDEX], json!({"size": 10000, "query": {"term": {"Blocked": true}}}))
        .await
        .map_err(|error| {
            (StatusCode::BAD_GATEWAY, format!("manual blackhole export unavailable: {error}"))
        })?;
    let mut ips: Vec<String> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hit| active(&hit["_source"]))
        .filter_map(|hit| hit["_source"]["IP"].as_str().map(String::from))
        .collect();
    ips.sort();
    let mut body = ips.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_without_expires_days_is_422() {
        let (status, message) = expiry_for(true, None, chrono::Utc::now()).unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(message.contains("expires_days") && message.contains("0 means permanent"));
    }

    #[test]
    fn zero_days_is_permanent() {
        assert_eq!(expiry_for(true, Some(0), chrono::Utc::now()).unwrap(), Value::Null);
    }

    #[test]
    fn seven_days_expires_in_a_week() {
        let now = chrono::Utc::now();
        let at = expiry_for(true, Some(7), now).unwrap();
        let at = chrono::DateTime::parse_from_rfc3339(at.as_str().unwrap()).unwrap();
        assert_eq!(at.with_timezone(&chrono::Utc), now + chrono::Duration::days(7));
    }

    #[test]
    fn unblock_needs_no_expires_days() {
        assert_eq!(expiry_for(false, None, chrono::Utc::now()).unwrap(), Value::Null);
        assert_eq!(expiry_for(false, Some(7), chrono::Utc::now()).unwrap(), Value::Null);
    }

    #[test]
    fn body_distinguishes_absent_from_zero() {
        let absent: BlockBody = serde_json::from_str(r#"{"ip":"192.0.2.1","blocked":true}"#).unwrap();
        let zero: BlockBody = serde_json::from_str(r#"{"ip":"192.0.2.1","blocked":true,"expires_days":0}"#).unwrap();
        assert_eq!(absent.expires_days, None);
        assert_eq!(zero.expires_days, Some(0));
    }
}
