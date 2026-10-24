//! agent-intrusion-worker port (#1610 worker migration — "campaign
//! correlator"), worker.py half: wires decode_correlate.rs,
//! campaign_correlator.rs, and criticality_rules.rs against real
//! Elasticsearch data, writing provenance-rich campaign verdicts to
//! `agent-intrusion-campaigns` (dashboard/agent_campaigns.go's own
//! `/agent-campaigns` route reads this — see src/stores.rs's generic
//! passthrough entry, fixed in the same pass as this port to sort
//! `@timestamp` instead of a nonexistent `last_seen` field).
//!
//! Every event this worker reads/correlates/scores is the raw sensor
//! sub-document (source.honeypot, or source.suricata.eve, or the bare
//! _source) — NOT this crate's usual flattened honeypot.canonical_*
//! convention every other module queries. campaign_correlator.rs and
//! criticality_rules.rs read sensor-native field names directly (session,
//! src_ip, host, actor, input, payload_printable, eventid, sensor, ...),
//! ported faithfully from the Python corpus/production fixtures — do not
//! narrow the ES `_source` filter to a canonical-field allowlist here.
//!
//! Pure ES, no host mounts, no local state — runs as the `agent-intrusion`
//! WORKER_LOOPS entry on the existing (stateless-by-design) backend-worker
//! service, alongside `alert-notifier`/`attacker-identity`.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

use crate::campaign_correlator::{self, Campaign, CorrelatorEvent};
use crate::criticality_rules::{self, RuleMatch};
use crate::AppState;

const SOURCE_INDICES: &[&str] = &["honeypot-v2-*", "suricata-v2-*"];
const CAMPAIGN_INDEX: &str = "agent-intrusion-campaigns";
const EVENT_PAGE_SIZE: u64 = 1_000;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_duration_secs(name: &str, default: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}

/// Returns the sensor-native portion of a live ECS document. Corpus
/// fixtures already use the sensor-native shape at the top level, while
/// production ingest retains it below `honeypot` or `suricata.eve`.
fn sensor_raw(source: &serde_json::Value) -> serde_json::Value {
    if let Some(honeypot) = source.get("honeypot") {
        if honeypot.is_object() {
            return honeypot.clone();
        }
    }
    if let Some(eve) = source.get("suricata").and_then(|s| s.get("eve")) {
        if eve.is_object() {
            return eve.clone();
        }
    }
    source.clone()
}

/// Scrolls the newest capped events at or after `since`, mapped into the
/// shape campaign_correlator.rs/criticality_rules.rs consume. Real ES
/// `_id`s are used directly as event_id so a dashboard page can link
/// straight back to raw evidence.
/// Each event is paired with the concrete `_index` it was read from (#3519),
/// which build_campaign_verdict stores as `source_index` so a consumer can
/// build an exact `_id` + `_index` lookup.
async fn fetch_window_events(
    state: &AppState,
    index_pattern: &str,
    since: &str,
    page_size: u64,
    max_events: u64,
) -> Vec<(CorrelatorEvent, String)> {
    // max_pages bounds total fetched at page_size*max_pages >= max_events,
    // with headroom since a page may partially exceed the cap (checked
    // per-hit below, matching the Python worker's own early-break).
    let max_pages = ((max_events / page_size) + 2) as u32;
    let hits = match state
        .es
        .search_paginated(
            index_pattern,
            |search_after| {
                let mut body = serde_json::json!({
                    // #2145: the window feed drives campaign correlation, so
                    // it must not ingest the fleet's own healthcheck stream;
                    // the term is a no-op for suricata-v2 docs (no such field).
                    "query": {"bool": {
                        "filter": [{"range": {"@timestamp": {"gte": since}}}],
                        "must_not": [crate::es::internal_probe_exclusion()]
                    }},
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": {"excludes": ["suricata.eve.packet", "suricata.eve.payload"]}
                });
                if let Some(sa) = search_after {
                    body["search_after"] = sa.clone();
                }
                body
            },
            page_size,
            max_pages,
        )
        .await
    {
        Ok(hits) => hits,
        Err(error) => {
            tracing::warn!(%error, index_pattern, "agent-intrusion: fetch error");
            return Vec::new();
        }
    };

    let mut events = Vec::new();
    for hit in hits {
        let source = &hit["_source"];
        let Some(ts) = source.get("@timestamp").and_then(|v| v.as_str()) else {
            continue;
        };
        let event_id = hit["_id"].as_str().unwrap_or_default().to_string();
        let source_index = hit["_index"].as_str().unwrap_or_default().to_string();
        events.push((
            CorrelatorEvent {
                event_id,
                timestamp: ts.to_string(),
                raw: sensor_raw(source),
            },
            source_index,
        ));
        if events.len() as u64 >= max_events {
            tracing::warn!(
                index_pattern,
                max_events,
                "agent-intrusion: fetch cap reached, processing only the newest events this cycle"
            );
            break;
        }
    }
    events
}

/// campaign_correlator.rs's parse_ts expects a bare "%Y-%m-%dT%H:%M:%SZ";
/// real Elasticsearch @timestamp values are full ISO 8601 and routinely
/// carry fractional seconds and/or a numeric UTC offset. Normalizes to
/// whole seconds, UTC, "Z"-suffixed.
fn normalize_timestamp(ts: &str) -> Option<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    Some(
        parsed
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
    )
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Runs criticality_rules against every member event, scores the whole
/// campaign, and returns a full provenance-rich verdict document — or
/// None if the campaign doesn't clear the high/critical write threshold.
/// Deterministic campaign_id (sha256 of the sorted event_id list) makes
/// re-processing the same campaign on a later poll an idempotent upsert.
fn build_campaign_verdict(
    campaign: &Campaign,
    events_by_id: &HashMap<String, CorrelatorEvent>,
    source_index_by_id: &HashMap<String, String>,
) -> Option<serde_json::Value> {
    let raw_by_id: HashMap<String, serde_json::Value> = events_by_id
        .iter()
        .map(|(id, e)| (id.clone(), e.raw.clone()))
        .collect();
    let mut matches_per_event: HashMap<String, Vec<RuleMatch>> = campaign
        .event_ids
        .iter()
        .map(|eid| {
            (
                eid.clone(),
                criticality_rules::evaluate_event(&events_by_id[eid].raw),
            )
        })
        .collect();

    // The breadcrumb-followed match needs the full per-event match set
    // already built above (it looks for a prior breadcrumb-reference
    // match), so it runs after evaluate_event, not inside it.
    if let Some((followed_eid, followed_match)) = criticality_rules::campaign_breadcrumb_followed(
        &campaign.event_ids,
        &raw_by_id,
        &matches_per_event,
    ) {
        matches_per_event
            .get_mut(&followed_eid)
            .unwrap()
            .push(followed_match);
    }

    let (severity, categories) = criticality_rules::campaign_severity(&matches_per_event);
    if severity != "high" && severity != "critical" {
        return None;
    }

    let mut sorted_event_ids = campaign.event_ids.clone();
    sorted_event_ids.sort();
    let campaign_id = &sha256_hex(sorted_event_ids.join("|").as_bytes())[..16];

    let event_docs: Vec<serde_json::Value> = campaign
        .event_ids
        .iter()
        .map(|eid| {
            let event = &events_by_id[eid];
            let matches = &matches_per_event[eid];
            serde_json::json!({
                "event_id": eid,
                // #3519: the concrete index the event was read from; empty
                // when unknown (never invented).
                "source_index": source_index_by_id.get(eid).map(String::as_str).unwrap_or_default(),
                "timestamp": event.timestamp,
                "matched_rules": matches.iter().map(|m| serde_json::json!({
                    "rule": m.rule,
                    "reason": m.reason,
                    "trust_boundary": criticality_rules::TRUST_BOUNDARIES.get(m.rule.as_str()).copied().unwrap_or(""),
                    "decode_chain": m.decode_chain.iter().map(|s| serde_json::json!({
                        "transform": s.transform,
                        "input_sha256": s.input_sha256,
                        "output_sha256": s.output_sha256,
                        "output_len": s.output_len,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut categories_sorted: Vec<&String> = categories.iter().collect();
    categories_sorted.sort();
    let mut identifiers_sorted: Vec<&String> = campaign.identifiers.iter().collect();
    identifiers_sorted.sort();

    Some(serde_json::json!({
        "@timestamp": chrono::Utc::now().to_rfc3339(),
        "campaign_id": campaign_id,
        "start": campaign.start,
        "end": campaign.end,
        "severity": severity,
        "matched_categories": categories_sorted,
        "correlation_identifiers": identifiers_sorted,
        "event_count": campaign.event_ids.len(),
        "events": event_docs,
    }))
}

async fn write_campaign_verdict(state: &AppState, verdict: &serde_json::Value) {
    let id = verdict["campaign_id"].as_str().unwrap_or_default();
    if let Err(error) = state
        .es
        .index_doc(CAMPAIGN_INDEX, id, verdict.clone())
        .await
    {
        tracing::warn!(%error, campaign_id = id, "agent-intrusion: failed to write campaign verdict (non-fatal)");
    }
}

/// One full fetch -> correlate -> score -> write pass. Returns the number
/// of campaign verdicts written. Never panics — a fetch/index error
/// degrades this cycle's output, not the loop.
async fn run_cycle(state: &AppState, fetch_window: Duration, max_events_per_source: u64) -> u64 {
    let since = (chrono::Utc::now() - chrono::Duration::from_std(fetch_window).unwrap())
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let mut fetched: Vec<(CorrelatorEvent, String)> = Vec::new();
    for index_pattern in SOURCE_INDICES {
        fetched.extend(
            fetch_window_events(
                state,
                index_pattern,
                &since,
                EVENT_PAGE_SIZE,
                max_events_per_source,
            )
            .await,
        );
    }
    if fetched.is_empty() {
        return 0;
    }
    let source_index_by_id: HashMap<String, String> = fetched
        .iter()
        .map(|(event, index)| (event.event_id.clone(), index.clone()))
        .collect();
    let events: Vec<CorrelatorEvent> = fetched.into_iter().map(|(event, _)| event).collect();

    // Normalize/sort/correlate/score is CPU-bound, synchronous work with no
    // .await points in it anywhere — run it on tokio's dedicated blocking-
    // thread-pool via spawn_blocking, not inline on this task's own async
    // worker thread. Without this, a long enough pass here (criticality_
    // rules::evaluate_event's per-event decode/hash rule chain, run once per
    // fetched event — up to 20,000 under the default fetch caps) starves
    // every other task sharing this process's tokio runtime, including
    // main.rs's probe handlers: confirmed live during #1628's preflight —
    // agent-intrusion run alone reliably made /healthz stop responding
    // entirely (a direct curl timed out at 45s with zero response) within
    // ~90s of every cycle start. The container's own cpu.max cgroup quota
    // makes this worse, not just theoretical: `available_parallelism()`
    // (which tokio's multi-threaded runtime sizes its worker-thread pool
    // from) respects cgroup CPU limits on Linux, so a 1-cpu container can
    // end up with too few worker threads for a second one to ever pick up
    // the HTTP server's work while this task hogs the only one running.
    let verdicts = tokio::task::spawn_blocking(move || {
        let mut events = events;
        for event in &mut events {
            if let Some(normalized) = normalize_timestamp(&event.timestamp) {
                event.timestamp = normalized;
            }
        }
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Correlate against the slice first, then move events into the
        // lookup map — avoids cloning every event just to satisfy both call
        // sites.
        let campaigns = campaign_correlator::correlate_campaigns(&events, chrono::Duration::hours(72));
        let events_by_id: HashMap<String, CorrelatorEvent> = events
            .into_iter()
            .map(|e| (e.event_id.clone(), e))
            .collect();

        campaigns
            .iter()
            .filter_map(|campaign| build_campaign_verdict(campaign, &events_by_id, &source_index_by_id))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();

    let mut written = 0u64;
    for verdict in &verdicts {
        write_campaign_verdict(state, verdict).await;
        written += 1;
    }
    written
}

pub async fn agent_intrusion_loop(state: AppState) {
    let poll_interval =
        env_duration_secs("AGENT_INTRUSION_POLL_INTERVAL", Duration::from_secs(300));
    let max_events_per_source = env_u64("AGENT_INTRUSION_MAX_EVENTS_PER_SOURCE", 10_000);
    let fetch_window_days = env_u64("AGENT_INTRUSION_FETCH_WINDOW_DAYS", 10);
    let fetch_window = Duration::from_secs(fetch_window_days * 24 * 3600);

    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // #2181: per-event compute was already isolated — the correlation
        // pass runs in spawn_blocking and reads its JoinHandle with
        // unwrap_or_default, so a panicked event pipeline degrades to zero
        // verdicts for that cycle instead of ending anything. This boundary
        // takes the fetch phase, which runs inline on this task, out of the
        // blast radius too; None just means isolate::cycle already logged
        // the panic and the poll cadence retries next tick.
        if let Some(written) = crate::isolate::cycle(
            "agent-intrusion",
            run_cycle(&state, fetch_window, max_events_per_source),
        )
        .await
        {
            tracing::info!(written, "agent-intrusion: cycle complete");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shared ground-truth corpus (already exercised independently by
    // campaign_correlator.rs's and criticality_rules.rs's own corpus-driven
    // tests) — included from its single source of truth rather than
    // duplicated here, so this can never silently drift from what the
    // corpus's own authors hand-labeled. Same file the old Python worker's
    // test_worker.py::TestFullPipelineAgainstRealCorpus loads.
    const CORPUS_JSONL: &str =
        include_str!("../../../honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/corpus.jsonl");

    fn load_corpus() -> Vec<(CorrelatorEvent, bool)> {
        CORPUS_JSONL
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
                let event = CorrelatorEvent {
                    event_id: parsed["event_id"].as_str().unwrap().to_string(),
                    timestamp: parsed["timestamp"].as_str().unwrap().to_string(),
                    raw: parsed["raw"].clone(),
                };
                let is_benign = parsed["is_benign"].as_bool().unwrap_or(false);
                (event, is_benign)
            })
            .collect()
    }

    /// Ports test_worker.py's TestFullPipelineAgainstRealCorpus — proves
    /// campaign_correlator.rs and criticality_rules.rs (each already
    /// verified against the corpus independently, in their own test
    /// modules) produce the same real capstone finding when driven through
    /// this module's own correlate-then-score wiring, the exact call
    /// sequence run_cycle uses — not just when called directly by their
    /// own unit tests. This is the one thing nothing in the Rust crate
    /// exercised before: the wiring itself, not either half in isolation.
    #[test]
    fn merged_campaign_still_reaches_critical_through_worker_wiring() {
        let events: Vec<CorrelatorEvent> = load_corpus().into_iter().map(|(e, _)| e).collect();
        let campaigns = campaign_correlator::correlate_campaigns(&events, chrono::Duration::hours(72));
        let events_by_id: HashMap<String, CorrelatorEvent> = events.into_iter().map(|e| (e.event_id.clone(), e)).collect();
        let critical: Vec<serde_json::Value> = campaigns
            .iter()
            .filter_map(|c| build_campaign_verdict(c, &events_by_id, &HashMap::new()))
            .filter(|v| v["severity"] == "critical")
            .collect();
        assert_eq!(critical.len(), 1);
        assert!(critical[0]["event_count"].as_u64().unwrap() >= 8);
        let member_ids: Vec<&str> = critical[0]["events"].as_array().unwrap().iter().map(|e| e["event_id"].as_str().unwrap()).collect();
        assert!(member_ids.contains(&"corpus-017"));
    }

    #[test]
    fn benign_only_events_never_produce_a_verdict() {
        let benign: Vec<CorrelatorEvent> = load_corpus().into_iter().filter(|(_, is_benign)| *is_benign).map(|(e, _)| e).collect();
        assert!(!benign.is_empty(), "corpus fixture should contain at least one benign event");
        let campaigns = campaign_correlator::correlate_campaigns(&benign, chrono::Duration::hours(72));
        let events_by_id: HashMap<String, CorrelatorEvent> = benign.into_iter().map(|e| (e.event_id.clone(), e)).collect();
        let verdicts: Vec<serde_json::Value> = campaigns.iter().filter_map(|c| build_campaign_verdict(c, &events_by_id, &HashMap::new())).collect();
        assert!(verdicts.is_empty());
    }

    // normalize_timestamp — ports TestNormalizeTimestamp, previously
    // untested on the Rust side.
    #[test]
    fn normalize_timestamp_bare_z_suffix_passes_through() {
        assert_eq!(normalize_timestamp("2026-01-01T00:00:00Z").as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn normalize_timestamp_truncates_fractional_seconds() {
        assert_eq!(normalize_timestamp("2026-01-01T00:00:00.123456Z").as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn normalize_timestamp_normalizes_a_numeric_utc_offset_to_z() {
        assert_eq!(normalize_timestamp("2026-01-01T02:00:00+02:00").as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn normalize_timestamp_rejects_an_unparseable_string() {
        assert_eq!(normalize_timestamp("not-a-timestamp"), None);
    }

    // sensor_raw — ports the ES-shape-unwrap intent of
    // TestFetchWindowEvents::test_unwraps_live_honeypot_ecs_shape, without
    // needing a FakeElasticsearch: this function is a pure mapping of one
    // already-fetched _source document, so it's directly testable.
    #[test]
    fn sensor_raw_unwraps_the_honeypot_sub_document() {
        let source = serde_json::json!({"honeypot": {"src_ip": "203.0.113.5"}, "event": {"category": "network"}});
        assert_eq!(sensor_raw(&source)["src_ip"], "203.0.113.5");
    }

    #[test]
    fn sensor_raw_unwraps_the_suricata_eve_sub_document() {
        let source = serde_json::json!({"suricata": {"eve": {"src_ip": "203.0.113.6"}}});
        assert_eq!(sensor_raw(&source)["src_ip"], "203.0.113.6");
    }

    #[test]
    fn sensor_raw_falls_back_to_the_bare_source_for_corpus_style_fixtures() {
        // Corpus fixtures already use the sensor-native shape at the top
        // level (no honeypot/suricata.eve wrapper) — this is the branch
        // load_corpus()'s own events above exercise implicitly.
        let source = serde_json::json!({"src_ip": "203.0.113.7"});
        assert_eq!(sensor_raw(&source)["src_ip"], "203.0.113.7");
    }

    // build_campaign_verdict — ports the shape of TestBuildCampaignVerdict,
    // previously untested on the Rust side (only criticality_rules.rs's
    // own campaign_severity/evaluate_event were tested, never this
    // module's wiring around them).
    fn hand_built_event(id: &str, ts: &str, raw: serde_json::Value) -> CorrelatorEvent {
        CorrelatorEvent { event_id: id.to_string(), timestamp: ts.to_string(), raw }
    }

    #[test]
    fn build_campaign_verdict_yields_none_for_a_low_severity_campaign() {
        let events = vec![hand_built_event(
            "e1",
            "2026-01-01T00:00:00Z",
            serde_json::json!({"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "203.0.113.5"}),
        )];
        let events_by_id: HashMap<String, CorrelatorEvent> = events.into_iter().map(|e| (e.event_id.clone(), e)).collect();
        let campaign = Campaign {
            event_ids: vec!["e1".to_string()],
            identifiers: ["session:s1".to_string()].into_iter().collect(),
            start: "2026-01-01T00:00:00Z".to_string(),
            end: "2026-01-01T00:00:00Z".to_string(),
        };
        assert!(build_campaign_verdict(&campaign, &events_by_id, &HashMap::new()).is_none());
    }

    #[test]
    fn build_campaign_verdict_campaign_id_is_deterministic_regardless_of_event_order() {
        // A single matched rule already reaches "high" (campaign_severity's
        // own threshold is >=1 category for high, >=3 for critical) — one
        // rule-triggering event is enough to get a real verdict back.
        let raw = serde_json::json!({"event": "container_create", "flags": ["--privileged", "-v", "/:/host"]});
        let make_events = |order: [&str; 2]| -> HashMap<String, CorrelatorEvent> {
            order
                .into_iter()
                .enumerate()
                .map(|(i, id)| (id.to_string(), hand_built_event(id, &format!("2026-01-01T00:0{i}:00Z"), raw.clone())))
                .collect()
        };
        let campaign_a = Campaign {
            event_ids: vec!["a".to_string(), "b".to_string()],
            identifiers: ["session:s1".to_string()].into_iter().collect(),
            start: "2026-01-01T00:00:00Z".to_string(),
            end: "2026-01-01T00:01:00Z".to_string(),
        };
        let campaign_b = Campaign { event_ids: vec!["b".to_string(), "a".to_string()], ..campaign_a.clone() };
        let verdict_a = build_campaign_verdict(&campaign_a, &make_events(["a", "b"]), &HashMap::new()).expect("single-rule match should reach high severity");
        let verdict_b = build_campaign_verdict(&campaign_b, &make_events(["b", "a"]), &HashMap::new()).expect("same fixture, reversed event order");
        assert_eq!(verdict_a["campaign_id"], verdict_b["campaign_id"]);
    }

    #[test]
    fn build_campaign_verdict_carries_source_index_onto_each_event() {
        let raw = serde_json::json!({"event": "container_create", "flags": ["--privileged", "-v", "/:/host"]});
        let events_by_id: HashMap<String, CorrelatorEvent> = ["a", "b"]
            .into_iter()
            .enumerate()
            .map(|(i, id)| (id.to_string(), hand_built_event(id, &format!("2026-01-01T00:0{i}:00Z"), raw.clone())))
            .collect();
        let campaign = Campaign {
            event_ids: vec!["a".to_string(), "b".to_string()],
            identifiers: ["session:s1".to_string()].into_iter().collect(),
            start: "2026-01-01T00:00:00Z".to_string(),
            end: "2026-01-01T00:01:00Z".to_string(),
        };
        // "b" is deliberately unknown: the key stays present but empty.
        let source_index_by_id: HashMap<String, String> =
            [("a".to_string(), "honeypot-v2-2026.01.01".to_string())].into_iter().collect();
        let verdict = build_campaign_verdict(&campaign, &events_by_id, &source_index_by_id).expect("verdict");
        let events = verdict["events"].as_array().unwrap();
        assert_eq!(events[0]["event_id"], "a");
        assert_eq!(events[0]["source_index"], "honeypot-v2-2026.01.01");
        assert_eq!(events[1]["event_id"], "b");
        assert_eq!(events[1]["source_index"], "");
        // Existing keys are untouched (additive change).
        assert_eq!(events[0]["timestamp"], "2026-01-01T00:00:00Z");
        assert!(events[0]["matched_rules"].is_array());
        // The stored document round-trips through JSON with the key intact.
        let reparsed: serde_json::Value = serde_json::from_str(&verdict.to_string()).unwrap();
        assert_eq!(reparsed["events"][0]["source_index"], "honeypot-v2-2026.01.01");
    }
}
