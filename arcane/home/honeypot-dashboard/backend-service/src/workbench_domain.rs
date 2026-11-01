//! Payload Workbench types, analyzer registry, validation, and idempotency,
//! ported from dashboard/workbench_domain.go. Persistence lives in
//! workbench_es.rs; run creation/reconciliation/actions in
//! workbench_orchestrator.rs.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: i64 = 1;
pub const MAX_RUNS: usize = 500;
pub const MAX_RECIPES: usize = 100;
pub const MAX_QUEUE_DEPTH: usize = 200;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkbenchOptions {
    pub timeout_seconds: i64,
    pub max_queue_age_seconds: i64,
    pub retry_limit: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WorkbenchSelection {
    pub analyzer_id: String,
    #[serde(default)]
    pub options: WorkbenchOptions,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WorkbenchRecipe {
    #[serde(default)]
    pub schema_version: i64,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub revision: i64,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub owner: String,
    pub scope: String,
    #[serde(default)]
    pub created_at: String,
    pub analyzers: Vec<WorkbenchSelection>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WorkbenchChild {
    pub analyzer_id: String,
    pub display_name: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub result_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_hash: String,
    pub options: WorkbenchOptions,
    pub created_at: String,
    pub updated_at: String,
    pub deadline: String,
    pub queue_deadline: String,
    pub attempts: i64,
    pub retryable: bool,
    pub cancelable: bool,
    pub detonates: bool,
    #[serde(rename = "gpu_consuming")]
    pub gpu: bool,
    pub local_only: bool,
    pub stale: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WorkbenchRun {
    #[serde(default)]
    pub schema_version: i64,
    pub id: String,
    pub payload_sha256: String,
    pub payload_kind: String,
    pub owner: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recipe_id: String,
    #[serde(default)]
    pub recipe_revision: i64,
    #[serde(default)]
    pub recipe_name: String,
    #[serde(default)]
    pub recipe_snapshot: Vec<WorkbenchSelection>,
    pub idempotency_key: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub children: Vec<WorkbenchChild>,
}

#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct WorkbenchOptionSchema {
    pub timeout_min_seconds: i64,
    pub timeout_max_seconds: i64,
    pub queue_age_min_seconds: i64,
    pub queue_age_max_seconds: i64,
    pub retry_limit_max: i64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct WorkbenchAnalyzer {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub accepted_kinds: Vec<String>,
    pub availability: String,
    pub available: bool,
    pub applicable: bool,
    pub reason: String,
    pub result_link_shape: String,
    pub required_role: String,
    pub confirmation: String,
    #[serde(rename = "concurrency_class")]
    pub concurrency: String,
    pub local_only: bool,
    #[serde(rename = "externally_publishing")]
    pub externally_sends: bool,
    pub detonates: bool,
    #[serde(rename = "gpu_consuming")]
    pub gpu: bool,
    pub requires_opt_in: bool,
    pub default_options: WorkbenchOptions,
    pub option_schema: WorkbenchOptionSchema,
}

pub fn default_options(id: &str) -> WorkbenchOptions {
    match id {
        "ghidra" => WorkbenchOptions {
            timeout_seconds: 7200,
            max_queue_age_seconds: 1800,
            retry_limit: 1,
        },
        "linux-sandbox" | "windows-sandbox" => WorkbenchOptions {
            timeout_seconds: 1800,
            max_queue_age_seconds: 900,
            retry_limit: 1,
        },
        _ => WorkbenchOptions {
            timeout_seconds: 60,
            max_queue_age_seconds: 60,
            retry_limit: 0,
        },
    }
}

pub fn validate_options(id: &str, options: &mut WorkbenchOptions) -> Result<(), String> {
    if options.timeout_seconds == 0
        && options.max_queue_age_seconds == 0
        && options.retry_limit == 0
    {
        *options = default_options(id);
    }
    if !(0..=3).contains(&options.retry_limit) {
        return Err("retry_limit must be between 0 and 3".into());
    }
    let (min_timeout, max_timeout) = if id == "deterministic" {
        (5, 300)
    } else {
        (10, 86400)
    };
    if options.timeout_seconds < min_timeout || options.timeout_seconds > max_timeout {
        return Err(format!(
            "timeout_seconds must be between {min_timeout} and {max_timeout}"
        ));
    }
    if !(10..=86400).contains(&options.max_queue_age_seconds) {
        return Err("max_queue_age_seconds must be between 10 and 86400".into());
    }
    Ok(())
}

const ALLOWED_ANALYZERS: &[&str] = &[
    "deterministic",
    "ghidra",
    "linux-sandbox",
    "windows-sandbox",
    "windows-ghosts",
    "revdeck",
    "cape",
];

pub fn validate_selections(
    mut selections: Vec<WorkbenchSelection>,
) -> Result<Vec<WorkbenchSelection>, String> {
    if selections.is_empty() || selections.len() > 5 {
        return Err("select between one and five analyzers".into());
    }
    let mut seen = std::collections::HashSet::new();
    for selection in &mut selections {
        selection.analyzer_id = selection.analyzer_id.trim().to_string();
        if !ALLOWED_ANALYZERS.contains(&selection.analyzer_id.as_str())
            || !seen.insert(selection.analyzer_id.clone())
        {
            return Err(format!(
                "unknown or duplicate analyzer \"{}\"",
                selection.analyzer_id
            ));
        }
        validate_options(&selection.analyzer_id, &mut selection.options)
            .map_err(|error| format!("{}: {error}", selection.analyzer_id))?;
    }
    selections.sort_by(|a, b| a.analyzer_id.cmp(&b.analyzer_id));
    Ok(selections)
}

/// A spool directory that exists (and is writable, for a request spool), on
/// whichever host serves it (#3582).
fn directory_usable(root: crate::host_fs::Root, writable: bool) -> bool {
    crate::host_fs::host().usable(root, writable)
}

fn availability_name(configured: bool, healthy: bool) -> &'static str {
    if !configured {
        "unconfigured"
    } else if !healthy {
        "unavailable"
    } else {
        "configured"
    }
}

fn analyzer_reason(
    applicable: bool,
    configured: bool,
    healthy: bool,
    incompatible: &str,
    unconfigured: &str,
    unhealthy: &str,
) -> String {
    if !applicable {
        incompatible.to_string()
    } else if !configured {
        unconfigured.to_string()
    } else if !healthy {
        unhealthy.to_string()
    } else {
        "ready".to_string()
    }
}

/// Sync duplicate of worker.rs's read_spool_status's staleness half only
/// (that one is async/tokio::fs-based and module-private, built for the
/// alert-notifier's 60s loop) — the registry is computed synchronously
/// inline in an HTTP handler, so a second, plain version through the host
/// seam is simpler than threading async through workbenchRegistry's whole
/// call tree for one bool. Same "stale if status.json says
/// worker_state=running but updated_at is >10min old" contract as
/// loadGhidraStatus.
pub fn spool_status_stale(results: crate::host_fs::Root, request: crate::host_fs::Root) -> bool {
    use crate::host_fs::{host, ListFilter};
    let fs = host();
    if !fs.configured(results) {
        return false;
    }
    let Ok((body, _)) = fs.read(results, "status.json", 1024 * 1024) else {
        return true;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return true;
    };
    if value["worker_state"].as_str() != Some("running") {
        return false;
    }
    let Some(age) = fs.stat(results, "status.json").ok().and_then(|entry| entry.age()) else {
        return true;
    };
    if age <= std::time::Duration::from_secs(600) {
        return false;
    }
    // Re-check the live spool the same way worker.rs's read_spool_status
    // does: a stale status.json over a genuinely empty queue is a quiet
    // honeypot, not a dead worker.
    match fs.list(request, &ListFilter { suffix: ".request".into(), ..Default::default() }) {
        Ok(entries) => !entries.is_empty(),
        Err(_) => true,
    }
}

/// The analyzer catalog, scoped to one payload's classification — mirrors
/// workbenchRegistry exactly, including the "cape" entry, which is listed
/// (and can be selected/validated) but has no dispatch case in
/// submit_child: same "not implemented yet" gap the Go source itself has
/// today (its own comment: "#315's golden image doesn't exist yet").
pub fn registry(
    classification: &crate::payload_kind::PayloadClassification,
) -> Vec<WorkbenchAnalyzer> {
    let option_schema = WorkbenchOptionSchema {
        timeout_min_seconds: 10,
        timeout_max_seconds: 86400,
        queue_age_min_seconds: 10,
        queue_age_max_seconds: 86400,
        retry_limit_max: 3,
    };
    let local_schema = WorkbenchOptionSchema {
        timeout_min_seconds: 5,
        timeout_max_seconds: 300,
        ..option_schema
    };

    let code_like = classification.category == "executable"
        || classification.category == "library"
        || classification.category == "binary";

    use crate::host_fs::Root;
    let pair = |request: Root, results: Root| directory_usable(request, true) && directory_usable(results, false);

    let ghidra_configured = pair(Root::GhidraRequests, Root::GhidraResults);
    let ghidra_healthy = ghidra_configured && !spool_status_stale(Root::GhidraResults, Root::GhidraRequests);

    let revdeck_configured = pair(Root::RevdeckRequests, Root::RevdeckResults);

    let cape_configured = pair(Root::CapeRequests, Root::CapeResults);

    let linux_applicable = classification.dynamic && classification.platform != "Windows";
    let windows_applicable = classification.dynamic && classification.platform == "Windows";

    // The Linux spool keeps its /sandbox-requests and /sandbox-results defaults (host_fs::Root).
    let linux_configured = pair(Root::SandboxRequests, Root::SandboxResults);
    let windows_configured = pair(Root::WindowsSandboxRequests, Root::WindowsSandboxResults);
    let ghosts_configured = pair(Root::GhostsSandboxRequests, Root::GhostsSandboxResults);

    vec![
        WorkbenchAnalyzer {
            id: "deterministic".into(),
            display_name: "Deterministic local analysis".into(),
            description: "Hashes, type, entropy, strings, IOC extraction, YARA and bounded structural checks. The sample is never executed.".into(),
            accepted_kinds: vec!["all".into()],
            availability: "configured".into(),
            available: true,
            applicable: true,
            reason: "available for every captured payload".into(),
            result_link_shape: "/payload-analysis/{sha256}".into(),
            required_role: "admin".into(),
            confirmation: "none".into(),
            concurrency: "cpu".into(),
            local_only: true,
            default_options: default_options("deterministic"),
            option_schema: local_schema,
            ..Default::default()
        },
        WorkbenchAnalyzer {
            id: "ghidra".into(),
            display_name: "Ghidra headless".into(),
            description: "Disassembly plus deterministic statictools and the approved local advisory model slot.".into(),
            accepted_kinds: vec!["executable".into(), "library".into(), "binary".into()],
            availability: availability_name(ghidra_configured, ghidra_healthy).into(),
            available: ghidra_healthy,
            applicable: code_like,
            reason: analyzer_reason(code_like, ghidra_configured, ghidra_healthy, "payload does not contain a supported code image", "Ghidra spool is not configured", "Ghidra status is stale"),
            result_link_shape: "/ghidra/{sha256}".into(),
            required_role: "admin".into(),
            confirmation: "none".into(),
            concurrency: "shared-gpu".into(),
            local_only: true,
            gpu: true,
            default_options: default_options("ghidra"),
            option_schema,
            ..Default::default()
        },
        WorkbenchAnalyzer {
            id: "linux-sandbox".into(),
            display_name: "Linux sandbox".into(),
            description: "Dynamic detonation in the isolated Linux KVM runner with its fixed network policy.".into(),
            accepted_kinds: vec!["linux".into(), "cross-platform".into()],
            availability: availability_name(linux_configured, linux_configured).into(),
            available: linux_configured,
            applicable: linux_applicable,
            reason: analyzer_reason(linux_applicable, linux_configured, linux_configured, "payload is not compatible with the Linux detonation route", "Linux sandbox spool is not configured", "Linux sandbox is unavailable"),
            result_link_shape: "/sandbox/{job}".into(),
            required_role: "admin".into(),
            confirmation: "detonation".into(),
            concurrency: "linux-kvm".into(),
            local_only: true,
            detonates: true,
            default_options: default_options("linux-sandbox"),
            option_schema,
            ..Default::default()
        },
        WorkbenchAnalyzer {
            id: "windows-sandbox".into(),
            display_name: "Windows sandbox".into(),
            description: "Dynamic detonation in the isolated Windows KVM runner. The protected live VM cannot be selected here.".into(),
            accepted_kinds: vec!["windows".into()],
            availability: availability_name(windows_configured, windows_configured).into(),
            available: windows_configured,
            applicable: windows_applicable,
            reason: analyzer_reason(windows_applicable, windows_configured, windows_configured, "payload is not compatible with the Windows detonation route", "Windows sandbox spool is not configured", "Windows sandbox is unavailable"),
            result_link_shape: "/sandbox/{job}".into(),
            required_role: "admin".into(),
            confirmation: "detonation".into(),
            concurrency: "windows-kvm".into(),
            local_only: true,
            detonates: true,
            default_options: default_options("windows-sandbox"),
            option_schema,
            ..Default::default()
        },
        WorkbenchAnalyzer {
            id: "windows-ghosts".into(),
            display_name: "Windows sandbox (WAN-permitted, GHOSTS)".into(),
            description: "Real internet access. Dynamic detonation on a separate, WAN-permitted Windows guest with a GHOSTS-driven NPC persona.".into(),
            accepted_kinds: vec!["windows".into()],
            availability: availability_name(ghosts_configured, ghosts_configured).into(),
            available: ghosts_configured,
            applicable: windows_applicable,
            reason: analyzer_reason(windows_applicable, ghosts_configured, ghosts_configured, "payload is not compatible with the Windows detonation route", "GHOSTS sandbox spool is not configured", "GHOSTS sandbox is unavailable"),
            result_link_shape: "/sandbox/{job}".into(),
            required_role: "admin".into(),
            confirmation: "detonation".into(),
            concurrency: "windows-ghosts-kvm".into(),
            local_only: true,
            detonates: true,
            requires_opt_in: true,
            default_options: default_options("windows-sandbox"),
            option_schema,
            ..Default::default()
        },
        WorkbenchAnalyzer {
            id: "revdeck".into(),
            display_name: "Rev\u{b7}Deck / GhidrAssist".into(),
            description: "Rev\u{b7}Deck's own bounded, autonomous tool-calling loop against the Ghidra REST service, run standalone.".into(),
            accepted_kinds: vec!["executable".into(), "library".into()],
            availability: availability_name(revdeck_configured, revdeck_configured).into(),
            available: revdeck_configured,
            applicable: code_like,
            reason: analyzer_reason(code_like, revdeck_configured, revdeck_configured, "payload does not contain a supported code image", "Rev\u{b7}Deck spool is not configured", "Rev\u{b7}Deck spool is not configured"),
            result_link_shape: "/revdeck/{sha256}".into(),
            required_role: "admin".into(),
            confirmation: "none".into(),
            concurrency: "shared-gpu".into(),
            local_only: true,
            gpu: true,
            default_options: default_options("ghidra"),
            option_schema,
            ..Default::default()
        },
        WorkbenchAnalyzer {
            id: "cape".into(),
            display_name: "CAPE sandbox".into(),
            description: "Dynamic detonation in a dedicated CAPE-managed Windows guest, isolated from win11-sandbox. Purpose-built for debugger-class time evasion.".into(),
            accepted_kinds: vec!["windows".into()],
            availability: availability_name(cape_configured, cape_configured).into(),
            available: cape_configured,
            applicable: windows_applicable,
            reason: analyzer_reason(windows_applicable, cape_configured, cape_configured, "payload is not compatible with the Windows detonation route", "CAPE spool is not configured", "CAPE spool is not configured"),
            result_link_shape: "/cape/{sha256}".into(),
            required_role: "admin".into(),
            confirmation: "detonation".into(),
            concurrency: "cape-kvm".into(),
            local_only: true,
            detonates: true,
            default_options: default_options("windows-sandbox"),
            option_schema,
            ..Default::default()
        },
    ]
}

pub fn analyzer_by_id<'a>(
    items: &'a [WorkbenchAnalyzer],
    id: &str,
) -> Option<&'a WorkbenchAnalyzer> {
    items.iter().find(|item| item.id == id)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn random_id(prefix: &str) -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}_{}", to_hex(&bytes))
}

pub fn idempotency_key(
    hash: &str,
    recipe_id: &str,
    revision: i64,
    owner: &str,
    selections: &[WorkbenchSelection],
) -> String {
    let body = serde_json::to_string(selections).unwrap_or_default();
    let material = format!("{hash}\x00{recipe_id}\x00{revision}\x00{owner}\x00{body}");
    let digest = Sha256::digest(material.as_bytes());
    to_hex(&digest)
}

pub fn valid_id(id: &str, prefix: &str) -> bool {
    match id.strip_prefix(prefix) {
        Some(rest) => rest.len() == 32 && rest.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

pub fn valid_run_id(id: &str) -> bool {
    match id.strip_prefix("run_") {
        Some(rest) => rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

/// States a run or child never leaves. Public because the reconcile
/// sweeper (#1801) excludes them in the Elasticsearch query rather than
/// fetching every run and discarding most of them.
pub const TERMINAL_STATES: &[&str] = &["completed", "skipped", "failed", "timed_out", "cancelled"];

pub fn is_terminal_state(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

/// Recomputes run.state from its children's states and bumps updated_at —
/// mirrors updateWorkbenchRunState's priority order exactly (running beats
/// partial beats completed beats timed_out beats failed beats cancelled).
pub fn update_run_state(run: &mut WorkbenchRun) {
    let mut counts = std::collections::HashMap::new();
    for child in &run.children {
        *counts.entry(child.state.clone()).or_insert(0i64) += 1;
    }
    let get = |state: &str| *counts.get(state).unwrap_or(&0);
    run.state = if get("queued") + get("claimed") + get("running") > 0 {
        "running"
    } else if get("completed") > 0
        && get("failed") + get("timed_out") + get("cancelled") + get("skipped") > 0
    {
        "partial"
    } else if get("completed") > 0 {
        "completed"
    } else if get("timed_out") > 0 {
        "timed_out"
    } else if get("failed") > 0 {
        "failed"
    } else if get("cancelled") > 0 {
        "cancelled"
    } else {
        "completed"
    }
    .to_string();
    run.updated_at = chrono::Utc::now().to_rfc3339();
}
