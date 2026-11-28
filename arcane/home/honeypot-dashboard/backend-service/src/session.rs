//! /api/v1/sessions/{id} — one attacker session's full story, ported
//! from intelligence.go's sessionData + attack_sequences.go: every event
//! chronologically, per-session leaderboards, ATT&CK techniques, and the
//! curated multi-step sequence detections (Redis→SSH key injection, ADB
//! recon fingerprint).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::{events::EventRow, AppState};

#[derive(Serialize)]
pub struct Kv {
    pub key: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct Sequence {
    pub name: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Serialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub evidence: String,
    pub count: u64,
    pub url: String,
}

#[derive(Serialize)]
pub struct SessionDetail {
    pub id: String,
    pub ip: String,
    pub country: String,
    pub first: String,
    pub last: String,
    /// Every record the session has, by the search's own count. `events`
    /// holds the first 1000 of them (the search size), so a longer session
    /// is shown partially there and says so here.
    pub total: u64,
    pub sensors: Vec<Kv>,
    pub commands: Vec<Kv>,
    pub credentials: Vec<Kv>,
    pub payloads: Vec<Kv>,
    pub techniques: Vec<Technique>,
    pub sequences: Vec<Sequence>,
    pub events: Vec<EventRow>,
}

/// (name, domain, evidence) for the technique IDs
/// ip_enrichment/attck.rs's promote_attck_technique_fields actually
/// emits into canonical_attck_techniques — the ES document only ever
/// carries the bare ID (#1611 workstream D promoted it at ingest time,
/// intentionally not duplicating the derived text), so the session
/// detail pane's MITRE table (session.html's "techniques" template) needs
/// this restored here. Static, not a network lookup: this dashboard's own
/// evidence-derived annotation is a fixed set tied 1:1 to the classifier
/// rules in attck.rs, mirroring dashboard/intelligence.go's original
/// technique() call sites exactly. An ID outside this set (a future
/// classifier rule added without updating this table) falls back to the
/// bare ID as its own name rather than panicking.
pub fn technique_meta(id: &str) -> (&str, &'static str, &'static str) {
    match id {
        "T1110" => ("Brute Force", "Enterprise", "credential attempt"),
        "T1059" => ("Command and Scripting Interpreter", "Enterprise", "command captured"),
        "T1059.001" => ("PowerShell", "Enterprise", "command captured"),
        "T1059.003" => ("Windows Command Shell", "Enterprise", "command captured"),
        "T1059.004" => ("Unix Shell", "Enterprise", "command captured"),
        "T1105" => ("Ingress Tool Transfer", "Enterprise", "payload transfer or downloader"),
        "T1190" => ("Exploit Public-Facing Application", "Enterprise", "web exploit or probing evidence"),
        "T1595" => ("Active Scanning", "Enterprise", "scanner/client fingerprint"),
        "T0886" => ("Remote Services", "ICS", "industrial protocol interaction"),
        "T1692.001" => ("Unauthorized Message: Command Message", "ICS", "control command or write attempt"),
        other => (other, "Enterprise", ""),
    }
}

/// Builds one MITRE table row from a bare technique ID + observation
/// count — shared by session.rs's own techniques and investigate.rs's
/// per-IP profile (ips.html's "techniques" partial reuses the exact same
/// template session.html does).
pub fn technique_row(id: String, count: u64) -> Technique {
    let (name, domain, evidence) = technique_meta(&id);
    let (name, domain, evidence) = (name.to_string(), domain.to_string(), evidence.to_string());
    Technique { url: format!("https://attack.mitre.org/techniques/{}/", id.replace('.', "/")), id, name, domain, evidence, count }
}

fn top_n(map: HashMap<String, u64>, n: usize) -> Vec<Kv> {
    let mut rows: Vec<Kv> = map.into_iter().map(|(key, count)| Kv { key, count }).collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    rows.truncate(n);
    rows
}

fn redis_ssh_key_injection(cmds: &[String]) -> bool {
    static MATCHERS: OnceLock<Vec<Regex>> = OnceLock::new();
    let matchers = MATCHERS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)^config\s+set\s+dir\b").unwrap(),
            Regex::new(r"(?i)^config\s+set\s+dbfilename\b").unwrap(),
            Regex::new(r"(?i)ssh-(rsa|dss|ed25519|ecdsa-[a-z0-9-]+)\s").unwrap(),
            Regex::new(r"(?i)^bgsave\b").unwrap(),
        ]
    });
    let mut step = 0;
    for cmd in cmds {
        if step >= matchers.len() {
            break;
        }
        if matchers[step].is_match(cmd) {
            step += 1;
        }
    }
    step == matchers.len()
}

const ADB_RECON_INDICATORS: &[&str] = &["uname", "nproc", "meminfo", "id -u", "getprop"];

fn adb_recon_fingerprint(cmds: &[String]) -> bool {
    cmds.iter().any(|cmd| {
        let lower = cmd.to_lowercase();
        ADB_RECON_INDICATORS.iter().filter(|needle| lower.contains(**needle)).count() >= 3
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/sessions/{id}",
    summary = "One session: its events, commands and credentials.",
    params(
        ("id" = inline(String), Path, description = "Session id."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SessionDetail>, (StatusCode, String)> {
    let id = id.trim().to_string();
    if id.is_empty() || id.len() > 256 {
        return Err((StatusCode::BAD_REQUEST, "invalid session id".into()));
    }
    // The pane that hands out session ids matches the same vocabulary
    // every other reader uses (#2119).
    let body = json!({
        "size": 1000,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": crate::events::any_of(crate::events::SESSION_FIELDS, &id)
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
    if hits.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no such session".into()));
    }
    // Was the number of hits loaded (at most 1000), which reported a long
    // session as if it had only that many records.
    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(hits.len() as u64);

    let mut sensors: HashMap<String, u64> = HashMap::new();
    let mut commands: HashMap<String, u64> = HashMap::new();
    let mut credentials: HashMap<String, u64> = HashMap::new();
    let mut payloads: HashMap<String, u64> = HashMap::new();
    let mut techniques: HashMap<String, u64> = HashMap::new();
    let mut redis_cmds: Vec<String> = Vec::new();
    let mut adb_cmds: Vec<String> = Vec::new();
    let mut rows: Vec<EventRow> = Vec::new();

    let text = |value: &Value| value.as_str().unwrap_or("").to_string();
    for hit in &hits {
        let source = &hit["_source"];
        // #3213: the same boundary, on the same rule as everywhere else --
        // a session summary is an aggregate, and an aggregate that reprints
        // every secret in the session is how a five-event probe becomes a
        // credential list. `row_from_hit` below is already guarded; this is
        // the second read of `hp` in this loop, and it needs its own.
        let scrubbed = crate::secrets_boundary::scrub_event(&text(&source["event"]["sensor"]), &source["honeypot"]);
        let hp = scrubbed.as_ref().unwrap_or(&source["honeypot"]);
        let row = crate::events::row_from_hit(hit);
        *sensors.entry(row.sensor.clone()).or_insert(0) += 1;
        let command = {
            let input = text(&hp["input"]);
            if input.is_empty() { text(&hp["command"]) } else { input }
        };
        if !command.is_empty() {
            *commands.entry(command.clone()).or_insert(0) += 1;
            match text(&hp["proto"]).as_str() {
                "redis" => redis_cmds.push(command.clone()),
                "adb" => adb_cmds.push(command.clone()),
                _ => {}
            }
        }
        let user = text(&hp["username"]);
        let pass = text(&hp["password"]);
        // #3213: for the two decoys the secret is not in the document, so
        // `{user} / {pass}` would either print a dangling `admin / ` or --
        // worse, if the pass were defaulted -- claim an empty credential was
        // offered. The marker is shown only when the sensor's own
        // `credential_status` says a credential really was there, which is
        // the field that makes "we are not showing you this" distinguishable
        // from "there was nothing to show".
        let label = if !pass.is_empty() {
            format!("{user} / {pass}")
        } else {
            match text(&hp["credential_status"]).as_str() {
                "extracted" | "present_unparsed" => {
                    if user.is_empty() {
                        crate::secrets_boundary::REDACT_MARKER.to_string()
                    } else {
                        format!("{user} / {}", crate::secrets_boundary::REDACT_MARKER)
                    }
                }
                _ => user.clone(),
            }
        };
        if !label.is_empty() {
            *credentials.entry(label).or_insert(0) += 1;
        }
        let shasum = text(&hp["shasum"]);
        if !shasum.is_empty() {
            *payloads.entry(shasum).or_insert(0) += 1;
        }
        for technique in hp["canonical_attck_techniques"].as_array().into_iter().flatten() {
            if let Some(id) = technique.as_str() {
                *techniques.entry(id.to_string()).or_insert(0) += 1;
            }
        }
        rows.push(row);
    }

    let mut sequences = Vec::new();
    if redis_ssh_key_injection(&redis_cmds) {
        sequences.push(Sequence {
            name: "Unauthenticated Redis-to-SSH RCE (SSH key injection)".into(),
            severity: "critical".into(),
            summary: "CONFIG SET dir/dbfilename redirected the RDB save path into ~/.ssh, an attacker SSH public key was written as a value, then BGSAVE forced the save — the result is passwordless SSH access on any real Redis instance configured this permissively.".into(),
        });
    }
    if adb_recon_fingerprint(&adb_cmds) {
        sequences.push(Sequence {
            name: "ADB botnet-recruitment device fingerprinting".into(),
            severity: "high".into(),
            summary: "A single shell invocation chained architecture, CPU count, memory, privilege level, and device model checks — the recon pattern Mirai-family and cryptomining botnet scanners run before deciding whether a device is worth infecting.".into(),
        });
    }

    let mut technique_rows: Vec<Technique> = techniques.into_iter().map(|(id, count)| technique_row(id, count)).collect();
    technique_rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.id.cmp(&b.id)));

    let first = rows.first().map(|row| row.time.clone()).unwrap_or_default();
    let last = rows.last().map(|row| row.time.clone()).unwrap_or_default();
    let ip = rows.last().map(|row| row.src_ip.clone()).unwrap_or_default();
    let country = rows.last().map(|row| row.country.clone()).unwrap_or_default();

    Ok(Json(SessionDetail {
        id,
        ip,
        country,
        first,
        last,
        total,
        sensors: top_n(sensors, 20),
        commands: top_n(commands, 30),
        credentials: top_n(credentials, 20),
        payloads: top_n(payloads, 20),
        techniques: technique_rows,
        sequences,
        events: rows,
    }))
}
