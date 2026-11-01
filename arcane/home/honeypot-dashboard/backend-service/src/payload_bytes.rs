//! On-demand payload-bytes mirror, ported from payload_bytes_es.go's
//! mirrorOnePayloadBytes. dashboard-payload-bytes-v1 is normally kept warm
//! by payload-inventory-worker's own periodic scan; this is the self-heal
//! path for a hash this replica hasn't seen mirrored yet, so a static-
//! analysis/detail read never has to wait on that worker's next cycle.
//!
//! Simplified from the Go tier: no fingerprint (size+mtime) staleness
//! check — a document once mirrored is treated as good indefinitely, same
//! as every other read this crate serves from dashboard-payload-bytes-v1
//! today. A capture's bytes changing after the fact under the same hash
//! would be unusual (defeats the point of content-addressed storage) and
//! isn't handled here; follow-up if that turns out to matter live.

use base64::Engine;
use serde_json::{json, Value};

use crate::payload_paths::resolve_payload;
use crate::AppState;

const PAYLOAD_BYTES_INDEX: &str = "dashboard-payload-bytes-v1";
/// Matches payloadBytesRawCap: double payload_analysis.go's own
/// analysisReadCap, comfortably covering the large end of what this stack
/// captures without one outsized sample blowing out the index.
const RAW_CAP_BYTES: u64 = 32 << 20;

/// Mirrors one payload's bytes into dashboard-payload-bytes-v1 if no
/// document exists yet for it. Best-effort: any failure (not found on
/// disk, unreadable, ES unavailable) is silently a no-op — callers already
/// treat "no mirror" as a normal, handled state.
pub async fn ensure_mirrored(state: &AppState, hash: &str) {
    match state.es.get_doc(PAYLOAD_BYTES_INDEX, hash).await {
        Ok(Some(_)) => return,
        Err(_) => return,
        Ok(None) => {}
    }
    let owned_hash = hash.to_string();
    let Ok(Some(doc)) = tokio::task::spawn_blocking(move || mirror_from_disk(&owned_hash)).await else {
        return;
    };
    let _ = state.es.index_doc(PAYLOAD_BYTES_INDEX, hash, doc).await;
}

/// Reads the capture through the host seam (#3582): local disk, or the host
/// gateway when this service runs off the sensor host.
fn mirror_from_disk(hash: &str) -> Option<Value> {
    let payload = resolve_payload(hash).ok()?;
    if payload.size > RAW_CAP_BYTES {
        return Some(json!({"hash": hash, "size_bytes": payload.size, "too_large": true}));
    }
    let (data, size) = crate::host_fs::host().read_payload(&payload, RAW_CAP_BYTES).ok()?;
    if size > RAW_CAP_BYTES {
        return Some(json!({"hash": hash, "size_bytes": size, "too_large": true}));
    }
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&data);
    Some(json!({"hash": hash, "size_bytes": data.len(), "data_base64": data_base64}))
}
