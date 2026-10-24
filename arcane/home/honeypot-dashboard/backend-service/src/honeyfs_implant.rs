//! HTTP client for the honeyfs-implant service (arcane/home/honeypot-cowrie/
//! honeyfs-implant), ported from dashboard/honeyfs_implant_client.go.
//! WireGuard-tunnel-only, same reachability posture as canarytokens.rs's
//! CANARYTOKENS_API_URL — off unless HONEYFS_IMPLANT_URL is set.
//!
//! Request/response shape mirrors the Go client exactly (confirmed against
//! honeyfs-implant/main.go, not guessed):
//!
//!   POST /implant  {"path", "content_base64", "memo"} JSON
//!                  -> {"ok", "path", "bytes_written", "error"}

use base64::Engine;
use serde_json::{json, Value};

pub struct ImplantResult {
    #[allow(dead_code)]
    pub path: String,
    #[allow(dead_code)]
    pub bytes_written: i64,
}

fn base_url() -> Option<String> {
    let url = std::env::var("HONEYFS_IMPLANT_URL").ok()?;
    if url.is_empty() {
        return None;
    }
    Some(url.trim_end_matches('/').to_string())
}

/// `HONEYFS_IMPLANT_TOKEN` or `HONEYFS_IMPLANT_TOKEN_FILE` (#3680), resolved
/// by the same helper as SERVICE_TOKEN/EXPORT_TOKEN (#3577). Unset yields an
/// empty token (the service may run without auth); both set, or an unreadable
/// or empty file, is an error rather than a silent fall back to no token.
fn token_from(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&str) -> std::io::Result<String>,
) -> Result<String, String> {
    crate::trust::secret(env, read, "HONEYFS_IMPLANT_TOKEN")
        .map(Option::unwrap_or_default)
        .map_err(|refusal| format!("honeyfs-implant: {}", refusal.0))
}

fn token() -> Result<String, String> {
    token_from(&|key| std::env::var(key).ok(), &|path| std::fs::read_to_string(path))
}

/// False when the URL is unset, or when the token cannot be resolved (logged
/// loudly, so a misconfigured secret never degrades to unauthenticated calls).
pub fn configured() -> bool {
    if base_url().is_none() {
        return false;
    }
    match token() {
        Ok(_) => true,
        Err(error) => {
            tracing::error!("[E-HONEYFS-IMPLANT-TOKEN] {error}; honeyfs-implant disabled");
            false
        }
    }
}

/// POST {HONEYFS_IMPLANT_URL}/implant. path must already be validated as
/// honeyfs-root-relative by the caller — this client does not re-derive
/// containment itself, honeyfs-implant's own resolveHoneyfsPath is the
/// actual enforcement point, this is just belt-and-suspenders.
pub async fn implant(path: &str, content: &[u8], memo: &str) -> Result<ImplantResult, String> {
    let Some(base) = base_url() else {
        return Err("honeyfs-implant: not configured".to_string());
    };
    let token = token()?;
    let payload = json!({
        "path": path,
        "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
        "memo": memo,
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())?;
    let mut request = client.post(format!("{base}/implant")).json(&payload);
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    // /implant only ever answers a small JSON status object, never the
    // artifact itself — bounded read matches honeyfsImplantMaxResponseBytes.
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    if bytes.len() > 1 << 20 {
        return Err("honeyfs-implant: response too large".to_string());
    }
    let result: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("honeyfs-implant: malformed response (status {status}): {error}"))?;
    let ok = result["ok"].as_bool().unwrap_or(false);
    if !ok || !status.is_success() {
        let message = result["error"].as_str().filter(|text| !text.is_empty());
        return Err(message
            .map(String::from)
            .unwrap_or_else(|| format!("honeyfs-implant: request failed with status {status}")));
    }
    Ok(ImplantResult {
        path: result["path"].as_str().unwrap_or_default().to_string(),
        bytes_written: result["bytes_written"].as_i64().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::token_from;
    use std::collections::HashMap;

    fn resolve(vars: &[(&str, &str)]) -> Result<String, String> {
        let map: HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        token_from(&|key| map.get(key).cloned(), &|path| match path {
            "/run/secrets/implant" => Ok("from-file\n".to_string()),
            "/run/secrets/empty" => Ok("  \n".to_string()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such file")),
        })
    }

    #[test]
    fn unset_means_no_token() {
        assert_eq!(resolve(&[]), Ok(String::new()));
    }

    #[test]
    fn the_inline_variable_still_works() {
        assert_eq!(resolve(&[("HONEYFS_IMPLANT_TOKEN", "inline")]), Ok("inline".into()));
    }

    #[test]
    fn the_file_variable_works() {
        let vars = [("HONEYFS_IMPLANT_TOKEN_FILE", "/run/secrets/implant")];
        assert_eq!(resolve(&vars), Ok("from-file".into()));
    }

    #[test]
    fn both_set_is_refused() {
        let error = resolve(&[
            ("HONEYFS_IMPLANT_TOKEN", "inline"),
            ("HONEYFS_IMPLANT_TOKEN_FILE", "/run/secrets/implant"),
        ])
        .unwrap_err();
        assert!(error.contains("both"), "{error}");
    }

    #[test]
    fn an_unreadable_or_empty_file_is_refused() {
        let error = resolve(&[("HONEYFS_IMPLANT_TOKEN_FILE", "/run/secrets/missing")]).unwrap_err();
        assert!(error.contains("cannot be read"), "{error}");
        let error = resolve(&[("HONEYFS_IMPLANT_TOKEN_FILE", "/run/secrets/empty")]).unwrap_err();
        assert!(error.contains("empty"), "{error}");
    }
}
