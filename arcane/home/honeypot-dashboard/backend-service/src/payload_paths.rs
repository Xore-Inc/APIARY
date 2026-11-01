//! Captured-payload path resolution, ported from main.go's PAYLOAD_DIRS
//! wiring and payload_analysis.go's payloadPath/readPayloadHead. Shared by
//! sandbox/ghidra/github-analysis submission, the Payload Workbench
//! orchestrator, and the payload-bytes on-demand mirror — every write-path
//! feature in this tier that needs to look at a captured sample's actual
//! bytes goes through here, not through the dashboard-payload-bytes-v1 ES
//! mirror (that mirror is for the dashboard's own *serving* route only —
//! see payload_bytes.rs).

use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub use crate::host_fs::PayloadRef;

fn hash_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{32,64}$").unwrap())
}

pub fn is_valid_hash(hash: &str) -> bool {
    hash_name_re().is_match(hash)
}

/// The configured, existing payload source directories: PAYLOAD_DIRS (comma
/// list; falls back to the legacy BINARIES_DIR var if unset) plus
/// SCRIPT_PAYLOAD_DIR (default /state/script-payloads, created if missing),
/// deduplicated, each verified to actually be a directory — mirrors
/// main.go's startup wiring exactly, just re-evaluated per call instead of
/// once at boot (this crate has no long-lived store struct to cache it on).
pub fn payload_dirs() -> Vec<String> {
    let mut dirs = std::env::var("PAYLOAD_DIRS")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var("BINARIES_DIR").ok().filter(|value| !value.is_empty()))
        .unwrap_or_default();

    if let Some(script_dir) = std::env::var("SCRIPT_PAYLOAD_DIR")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| Some("/state/script-payloads".to_string()))
        .filter(|value| !value.is_empty())
    {
        if std::fs::create_dir_all(&script_dir).is_ok() {
            if !dirs.is_empty() {
                dirs.push(',');
            }
            dirs.push_str(&script_dir);
        }
    }

    let mut seen = std::collections::HashSet::new();
    dirs.split(',')
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
        .filter(|dir| seen.insert(dir.to_string()))
        .filter(|dir| Path::new(dir).is_dir())
        .map(str::to_string)
        .collect()
}

/// Case-insensitive recursive filename search, the fallback for a payload
/// dir where the exact-case join didn't hit. Best-effort: a permission
/// error prunes that subtree rather than aborting the whole resolution,
/// same fail-open posture as everywhere else file I/O happens in this
/// tier.
fn find_case_insensitive(dir: &Path, name_lower: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            if let Some(found) = find_case_insensitive(&path, name_lower) {
                return Some(found);
            }
        } else if file_type.is_file() && entry.file_name().to_string_lossy().eq_ignore_ascii_case(name_lower) {
            return Some(path);
        }
    }
    None
}

/// Resolves a hash to its on-disk capture path across every configured
/// payload dir. Unlike the Go tier, this does not fall back to a
/// SHA-256-vs-Dionaea-MD5 content scan (payloadPathBySHA256) — a hash that
/// doesn't match any filename directly (case-insensitively) is reported
/// not-found. Follow-up if that gap matters in practice.
pub fn resolve_payload_path(hash: &str) -> Result<PathBuf, &'static str> {
    resolve_in(&payload_dirs(), hash)
}

/// `resolve_payload_path` over an explicit directory list (the host gateway
/// passes its own, so it never depends on this process's environment).
pub fn resolve_in(dirs: &[String], hash: &str) -> Result<PathBuf, &'static str> {
    if !is_valid_hash(hash) {
        return Err("invalid payload id");
    }
    for dir in dirs {
        let direct = Path::new(dir).join(hash);
        if std::fs::metadata(&direct).map(|meta| meta.is_file()).unwrap_or(false) {
            return Ok(direct);
        }
        if let Some(found) = find_case_insensitive(Path::new(dir), hash) {
            return Ok(found);
        }
    }
    Err("captured payload not found")
}

/// Resolves a hash through the host seam (#3582): this host's disk, or the
/// host gateway when `HOST_GATEWAY_URL` is set. What every request handler uses.
pub fn resolve_payload(hash: &str) -> Result<PayloadRef, &'static str> {
    crate::host_fs::host().resolve_payload(hash)
}

const HEAD_BYTES: usize = 64 << 10;

/// Reads the first 64KiB of a resolved payload path — the same prefix
/// classify_payload works from, so the button that routes a submission can
/// never disagree with the row's own displayed classification.
pub fn read_payload_head(payload: &PayloadRef) -> std::io::Result<Vec<u8>> {
    crate::host_fs::host().read_payload(payload, HEAD_BYTES as u64).map(|(head, _)| head)
}
