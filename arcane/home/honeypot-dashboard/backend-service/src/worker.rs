//! Background worker loops (#1610), ported from the Go dashboard's
//! embedded producers. Enabled per-role via WORKER_LOOPS (comma list;
//! empty = pure API role), so the same image serves as API replica or
//! worker on any docker host — stateless, env-configured, all state in
//! ES (per Xore's cross-host requirement).
//!
//! Currently ported: `alert-notifier` — the notifyLoop/alertManager pair
//! (store.go/alerts.go): every alert signal store.go's notifyLoop combines,
//! ES-derivable and host-local alike (#1612 finished the latter: log-stream
//! sizes, sandbox/ghidra/cape/github-analysis spool health, filebeat stats,
//! OT command detection), upserted into dashboard-alert-state-v1 with
//! cooldown + optional webhook. The host-local signals need this loop's
//! container (backend-worker) to have the same bind mounts/service URLs the
//! Go dashboard had — see compose.yml's backend-worker volumes/environment.
//! `user-retention-sweep` (#1612) — orphaned preference expiry (roadmap
//! Milestone F), ported from userStore.SweepRetention: no in-memory cache to
//! poll here, so this just re-reads the users doc on its own interval rather
//! than the Go store's 3s poll tick.
//! `threat-intel` (#1659) — Tor-exit/reputation-blocklist CIDR
//! classification, ported from geoip.go's intel matching; see
//! threat_intel.rs's own doc comment.
//! #1750 adds ingestion-lag alerting to `alert-notifier` — the one signal
//! the Go tier never had, and the one that would have caught a 45-hour
//! blackout nothing else noticed. See INGEST_FEEDS below.

use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

use crate::audit::AuditEvent;
use crate::es::WriteError;
use crate::AppState;

const ALERT_INDEX: &str = "dashboard-alert-state-v1";
const INTERVAL: Duration = Duration::from_secs(60);
const GHIDRA_INDEX: &str = "ghidra-analysis-v1";
const GITHUB_ANALYSIS_INDEX: &str = "github-analysis-v1";
const SPOOL_STALE_AFTER: Duration = Duration::from_secs(30 * 60);
const HANDOFF_STALE_AFTER: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------------------
// #1750 — ingestion-lag alerting.
//
// #1678's stall was silent for three days: `hp-filebeat` was up, the container
// has no healthcheck that tests ingestion, and other Suricata sub-types kept
// flowing, so every "is it running" check passed while `suricata-v2-alert-*`
// received nothing. The signal has to come from the data.
//
// Two signals, because neither alone is enough — measured against this fleet's
// own history rather than assumed:
//
//   * Freshness. Newest real document older than the index's threshold. This
//     catches total silence, and it is what #1750 proposed.
//
//   * Volume collapse. Last hour far below the index's own recent baseline.
//     This is the one #1750 did not ask for, and the one that matters most.
//     Between 2026-08-20 21:00 and 2026-08-22 18:00 honeypot-v2-* fell from
//     ~100k events/hour to ~9, for 45 hours, and nobody noticed. Freshness
//     would not have caught a second of it: a handful of sensors kept
//     trickling, so the longest gap in real traffic across those 45 hours was
//     1h20m — inside normal variation. Volume collapse fires on the first
//     hour, on 3 events against a 102,956/h baseline.
//
// Both signals ignore `internal_probe` traffic (#1677/#1767). That is not a
// refinement, it is what makes the check work at all: during those same 45
// hours the index kept receiving a loopback healthcheck every nine seconds, so
// anything counting raw documents saw a perfectly healthy index.
//
// Thresholds are per index because rates differ by three orders of magnitude,
// and each was read off 14 days of that index's own history (2026-08-09 to
// 2026-08-23, probes excluded) rather than guessed. Over that window, at 90
// minutes, the only index that fires on natural variation is
// suricata-v2-dns-*, and the only fire anywhere else is dionaea's real 47-hour
// outage. The two indices with longer thresholds are the two that needed them:
//
//   index                     longest natural gap    threshold
//   honeypot-v2-*                          1h20m           90m
//   dionaea-incidents-v1-*                     -           90m
//   portbridge-v2-*                            -           90m
//   suricata-v2-alert-* and peers              -           90m
//   suricata-v2-smtp-*                     1h00m          120m
//   suricata-v2-dns-*                      2h00m          180m
//
// Alerting is per feed rather than per index: the ten Suricata sub-types come
// from one eve input, and an input dying should page once naming the ten, not
// ten times. The message names which members are stalled, so #1678's shape
// (one starved index while its nine siblings flow) still reads clearly.
const INGEST_LOOKBACK: &str = "now-30d";
const INGEST_BASELINE_FROM: &str = "now-8d";
const INGEST_BASELINE_TO: &str = "now-1d";
const INGEST_BASELINE_HOURS: f64 = 7.0 * 24.0;
/// Each check aggregates a week of documents per index; running that on the
/// 60s notifier tick would be waste, and an outage caught 9 minutes later is
/// still 45 hours earlier than the last one.
const INGEST_CHECK_EVERY: Duration = Duration::from_secs(10 * 60);

struct IngestIndex {
    pattern: &'static str,
    /// Newest real document older than this counts as stalled.
    stale_after: Duration,
}

/// One independent ingestion path, and the indices it feeds.
struct IngestFeed {
    /// Alert key suffix, and how the feed is named in the message.
    name: &'static str,
    indices: &'static [IngestIndex],
}

const fn minutes(n: u64) -> Duration {
    Duration::from_secs(n * 60)
}

const INGEST_FEEDS: &[IngestFeed] = &[
    IngestFeed {
        name: "sensor",
        indices: &[IngestIndex { pattern: "honeypot-v2-*", stale_after: minutes(90) }],
    },
    IngestFeed {
        name: "dionaea",
        indices: &[IngestIndex { pattern: "dionaea-incidents-v1-*", stale_after: minutes(90) }],
    },
    IngestFeed {
        name: "portbridge",
        indices: &[IngestIndex { pattern: "portbridge-v2-*", stale_after: minutes(90) }],
    },
    // #1742's sensors. Thresholds picked from measured behaviour rather than
    // rounded up from nothing: over 24 hours the longest quiet gap was 20
    // minutes for zeek-proxy and traefik and zero for zeek and huginn, so 90
    // minutes is the same 4-to-5x headroom the feeds above already run with.
    IngestFeed {
        name: "zeek",
        indices: &[IngestIndex { pattern: "zeek-v1-conn-*", stale_after: minutes(90) }],
    },
    IngestFeed {
        name: "zeek-proxy",
        indices: &[IngestIndex { pattern: "zeek-proxy-v1-conn-*", stale_after: minutes(90) }],
    },
    IngestFeed {
        name: "huginn",
        indices: &[IngestIndex { pattern: "huginn-v1-*", stale_after: minutes(90) }],
    },
    IngestFeed {
        name: "traefik",
        indices: &[IngestIndex { pattern: "traefik-v1-*", stale_after: minutes(90) }],
    },
    IngestFeed {
        name: "extracted-files",
        // Longer, because this one is bursty by nature: it only produces when
        // a file actually crosses the wire. Measured 20/h with a 10-minute
        // worst gap, but a quiet night is a normal state here in a way it is
        // not for a flow log, so freshness gets more rope.
        indices: &[IngestIndex { pattern: "extracted-files-*", stale_after: minutes(180) }],
    },
    // #2333: flow and netflow were monitored here until #1741 removed both
    // from suricata.yaml's eve-log types (80.1% of Suricata's document
    // volume, the thinnest records it wrote; Zeek's conn.log covers the
    // same ground and more). Removing a producer never removed its
    // watcher, but the leftovers never alarmed either: a pattern matching
    // no index makes `ingest_sample` return None (Elasticsearch answers a
    // zero-index wildcard with `_shards.total: 0` and no `aggregations`
    // section at all, so `aggs["newest"]["value"].as_f64()?` short-
    // circuits) and `ingest_lag_alerts` then skips the entry without
    // counting it in `checked`. Neither ever produced a single alert --
    // what they actually cost was two futile Elasticsearch searches per
    // poll cycle. Confirmed against today's suricata.yaml (no
    // `flow`/`netflow` entries under eve-log `types:`) and against the
    // live cluster (no suricata-v2-flow-*/netflow-* index of any date
    // exists). Every other pattern in this feed was checked the same way
    // and still has a real, current producer.
    //
    // Not derived from filebeat.yml's producer registry, the alternative
    // the issue names: filebeat.yml has no per-event-type suricata entries
    // to derive from in the first place -- one dynamic line,
    // `suricata-v2-%{[suricata.eve.event_type]}-*`, matches whatever
    // event_type Suricata itself decides to emit. The real source of truth
    // for which of these indices exist is suricata.yaml's `types:` list on
    // a different host in a different language; wiring worker.rs to read
    // that file live would be new cross-host infrastructure for one list
    // of ten entries. Deleting the two dead ones is the whole fix.
    // suricata-v2-netflow-* is also read directly by charts.rs's Zeek/
    // Suricata traffic-chart fallback (#2112) and rollups.rs -- unrelated
    // in cause (that code already treats an empty index as "no fallback
    // data" rather than alarming on it) and out of scope here; left as-is.
    IngestFeed {
        name: "suricata",
        indices: &[
            IngestIndex { pattern: "suricata-v2-alert-*", stale_after: minutes(90) },
            IngestIndex { pattern: "suricata-v2-http-*", stale_after: minutes(90) },
            IngestIndex { pattern: "suricata-v2-tls-*", stale_after: minutes(90) },
            IngestIndex { pattern: "suricata-v2-ssh-*", stale_after: minutes(90) },
            IngestIndex { pattern: "suricata-v2-fileinfo-*", stale_after: minutes(90) },
            IngestIndex { pattern: "suricata-v2-anomaly-*", stale_after: minutes(90) },
            IngestIndex { pattern: "suricata-v2-smtp-*", stale_after: minutes(120) },
            IngestIndex { pattern: "suricata-v2-dns-*", stale_after: minutes(180) },
        ],
    },
    // #2300: attacker verdicts were silently frozen 4 days (last 2026-08-22
    // 23:47Z) before anyone noticed. The attacker-identity loop is wired
    // (alert-notifier,attacker-identity,... in WORKER_LOOPS), but a worker
    // crash or a deploy regression can kill the producer without paging.
    // 4h threshold: well above the worker's own tick interval and a real
    // paged-not-observed gap, while still tight enough that the next
    // multi-day freeze is impossible to miss.
    IngestFeed {
        name: "attackers",
        indices: &[IngestIndex { pattern: "attackers-v1", stale_after: minutes(240) }],
    },
];

/// What one index pattern's real (non-probe) ingestion looks like right now.
struct IngestSample {
    newest_age_seconds: i64,
    /// Real documents in the last hour.
    recent: u64,
    /// Mean real documents per hour over the reference window.
    baseline_hourly: f64,
}

/// Why this index counts as stalled, or None when it is keeping up.
///
/// Split out of the query so the thresholds above can be tested against the
/// numbers this fleet actually produced, rather than only against a live
/// cluster that happens to be healthy at the time.
fn ingest_stall(
    index: &IngestIndex,
    sample: &IngestSample,
    floor_percent: u64,
    min_baseline: f64,
) -> Option<String> {
    if sample.newest_age_seconds >= index.stale_after.as_secs() as i64 {
        return Some(format!(
            "{} has had no data for {}",
            index.pattern,
            format_go_duration(Duration::from_secs(sample.newest_age_seconds as u64))
        ));
    }
    // Below min_baseline an hour's count is too small for a percentage of it
    // to mean anything: suricata-v2-smtp-* legitimately drops to 6% of its
    // median hour, so a floor that suits honeypot-v2-* would page nightly.
    // Those indices are covered by freshness alone, which their history shows
    // is enough — none of them has ever been silent for as long as its
    // threshold.
    if sample.baseline_hourly >= min_baseline
        && (sample.recent as f64) < sample.baseline_hourly * floor_percent as f64 / 100.0
    {
        return Some(format!(
            "{} is down to {}/h against a {:.0}/h baseline",
            index.pattern, sample.recent, sample.baseline_hourly
        ));
    }
    None
}

/// How far behind the sensor's own clock delivery is allowed to fall.
///
/// #1770: a 45-hour ingestion stall showed up as a gap followed by a spike
/// rather than as lag, because `@timestamp` on honeypot documents is the
/// moment we indexed them, not the moment the sensor recorded them. The real
/// event time sits in `honeypot.timestamp`. Measured during that stall, the
/// two were twelve hours apart while every freshness check read green -- the
/// documents were arriving, just describing something half a day old.
///
/// Freshness cannot see this by construction: it asks "when did anything last
/// arrive", and something was always arriving. This asks the different
/// question, "is what arrives still current".
const DELIVERY_LAG_LIMIT: Duration = minutes(30);

/// Documents sampled per check. Newest-first, so this is the current tail of
/// the stream rather than an average over history that a long-running stall
/// would take hours to move.
const DELIVERY_LAG_SAMPLE: usize = 50;

/// Median seconds between a sensor recording an event and us indexing it.
///
/// Median rather than max: one document with a skewed clock, or a single
/// retried write, should not raise an alert. A real delivery stall moves the
/// whole tail at once, which is exactly what the median catches and an
/// outlier does not.
fn delivery_lag_seconds(pairs: &[(i64, i64)]) -> Option<i64> {
    let mut lags: Vec<i64> = pairs
        .iter()
        // Negative means the sensor clock is ahead of ours. That is a clock
        // problem, not a delivery problem, and reporting it here would send
        // someone looking at the pipeline for a thing the pipeline did not do.
        .filter_map(|(indexed, sensed)| (indexed - sensed).checked_abs().map(|_| indexed - sensed))
        .filter(|lag| *lag >= 0)
        .collect();
    if lags.is_empty() {
        return None;
    }
    lags.sort_unstable();
    Some(lags[lags.len() / 2])
}

/// Ports payloads_data.go's humanBytes: binary-prefix size, one decimal.
fn human_bytes(n: u64) -> String {
    const UNIT: u64 = 1024;
    if n < UNIT {
        return format!("{n} B");
    }
    let mut div = UNIT;
    let mut exp = 0usize;
    let mut x = n / UNIT;
    while x >= UNIT {
        div *= UNIT;
        exp += 1;
        x /= UNIT;
    }
    let suffix = b"KMGTPE"[exp] as char;
    format!("{:.1} {suffix}B", n as f64 / div as f64)
}

/// A Go-style time.Duration.String() approximation (whole seconds only —
/// good enough for a log-stream age in an alert message).
fn format_go_duration(d: Duration) -> String {
    let total = d.as_secs();
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

/// Parse "6h"/"30m"/"90s" (the ALERT_COOLDOWN contract).
fn parse_duration(text: &str) -> Duration {
    let text = text.trim();
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    match (digits.parse::<u64>(), unit) {
        (Ok(n), "h") => Duration::from_secs(n * 3600),
        (Ok(n), "m") => Duration::from_secs(n * 60),
        (Ok(n), "s") => Duration::from_secs(n),
        _ => Duration::from_secs(6 * 3600),
    }
}

pub fn spawn_enabled(state: AppState) {
    let loops = env_or("WORKER_LOOPS", "");
    for name in loops.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        match name {
            "alert-notifier" => {
                let state = state.clone();
                tokio::spawn(async move { alert_notifier_loop(state).await });
                tracing::info!("worker loop enabled: alert-notifier");
            }
            "user-retention-sweep" => {
                let state = state.clone();
                tokio::spawn(async move { retention_sweep_loop(state).await });
                tracing::info!("worker loop enabled: user-retention-sweep");
            }
            "reports-scheduler" => {
                let state = state.clone();
                tokio::spawn(async move { reports_scheduler_loop(state).await });
                tracing::info!("worker loop enabled: reports-scheduler");
            }
            "es-results-importer" => {
                let state = state.clone();
                tokio::spawn(async move { crate::es_importer::es_importer_loop(state).await });
                tracing::info!("worker loop enabled: es-results-importer");
            }
            "attacker-identity" => {
                let state = state.clone();
                tokio::spawn(async move { crate::attacker_identity::attacker_identity_loop(state).await });
                tracing::info!("worker loop enabled: attacker-identity");
            }
            "agent-intrusion" => {
                let state = state.clone();
                tokio::spawn(async move { crate::agent_intrusion::agent_intrusion_loop(state).await });
                tracing::info!("worker loop enabled: agent-intrusion");
            }
            "payload-inventory" => {
                let state = state.clone();
                tokio::spawn(async move { crate::payload_inventory::payload_inventory_loop(state).await });
                tracing::info!("worker loop enabled: payload-inventory");
            }
            "ip-enrichment" => {
                let state = state.clone();
                tokio::spawn(async move { crate::ip_enrichment::ip_enrichment_loop(state).await });
                tracing::info!("worker loop enabled: ip-enrichment");
            }
            "correlator" => {
                let state = state.clone();
                tokio::spawn(async move { crate::correlator::correlator_loop(state).await });
                tracing::info!("worker loop enabled: correlator");
            }
            "dashboard-rollups" => {
                let state = state.clone();
                tokio::spawn(async move { crate::rollups::dashboard_rollups_loop(state).await });
                tracing::info!("worker loop enabled: dashboard-rollups");
            }
            "workbench-reconcile" => {
                let state = state.clone();
                tokio::spawn(async move {
                    crate::workbench_orchestrator::workbench_reconcile_loop(state).await
                });
                tracing::info!("worker loop enabled: workbench-reconcile");
            }
            "zeek-proxy-attribution" => {
                let state = state.clone();
                tokio::spawn(async move {
                    crate::zeek_proxy_attribution::zeek_proxy_attribution_loop(state).await
                });
                tracing::info!("worker loop enabled: zeek-proxy-attribution");
            }
            "threat-intel" => {
                let state = state.clone();
                tokio::spawn(async move { crate::threat_intel::threat_intel_loop(state).await });
                tracing::info!("worker loop enabled: threat-intel");
            }
            other => tracing::warn!(loop_name = other, "unknown worker loop requested"),
        }
    }
}

struct Notifier {
    state: AppState,
    cooldown: Duration,
    webhook: String,
    client: reqwest::Client,
    messages: Vec<String>,
    /// #1750's ingestion check aggregates a week of documents per index, so
    /// it runs on INGEST_CHECK_EVERY rather than on every 60s pass.
    last_ingest_check: Option<std::time::Instant>,
}

/// Read-modify-write attempts before an alert upsert gives up (#2044).
const OBSERVE_CAS_ATTEMPTS: usize = 3;

impl Notifier {
    /// Ported alertManager.observe: upsert the alert record, deciding
    /// whether this observation should notify. Compare-and-swap on the
    /// record's seq_no/primary_term (#2044): the dashboard's ack endpoint
    /// patches Acknowledged on the same document this loop rewrites
    /// wholesale, so the old unfenced get→index could resurrect an
    /// acknowledged alert from a pre-ack read or lose a count increment.
    async fn observe(&mut self, key: &str, message: String, link: &str, mark_only: bool) {
        let now = chrono::Utc::now().to_rfc3339();
        for _ in 0..OBSERVE_CAS_ATTEMPTS {
            let current = match self.state.es.get_doc_meta(ALERT_INDEX, key).await {
                Ok(found) => found,
                // A failed read used to fall through to a fresh record and
                // silently reset Count; skipping this observation is honest.
                Err(error) => {
                    tracing::warn!(%error, key, "alert state read failed; observation skipped");
                    return;
                }
            };
            let existed = current.is_some();
            let (mut record, seq_no, primary_term) = current.unwrap_or_else(|| {
                (
                    json!({"Key": key, "FirstSeen": now, "Count": 0, "Acknowledged": false, "LastNotified": null}),
                    0,
                    0,
                )
            });
            let acknowledged = record["Acknowledged"].as_bool().unwrap_or(false);
            let last_notified = record["LastNotified"]
                .as_str()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
            let cooled_down = match last_notified {
                None => true,
                Some(at) => (chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds() as u64
                    >= self.cooldown.as_secs(),
            };
            let notify = !mark_only && !acknowledged && cooled_down;
            record["Message"] = json!(message.clone());
            record["Link"] = json!(link);
            record["LastSeen"] = json!(now);
            record["Count"] = json!(record["Count"].as_u64().unwrap_or(0) + 1);
            if notify || (mark_only && last_notified.is_none()) {
                record["LastNotified"] = json!(now);
            }
            let result = if existed {
                self.state
                    .es
                    .index_doc_cas(ALERT_INDEX, key, record, seq_no, primary_term)
                    .await
            } else {
                // op_type=create makes concurrent first sightings of one
                // key deterministic: the loser's 409 loops back into a
                // fenced update of the winner instead of clobbering it.
                self.state.es.index_doc_create(ALERT_INDEX, key, record).await
            };
            match result {
                Ok(()) => {
                    if notify {
                        self.messages.push(message);
                    }
                    return;
                }
                Err(WriteError::Conflict) => continue, // ack (or another pass) won; re-read and retry
                Err(WriteError::Other(error)) => {
                    tracing::warn!(%error, key, "alert upsert failed");
                    return;
                }
            }
        }
        tracing::warn!(key, "alert upsert kept losing races; observation dropped");
    }

    async fn search(&self, indices: &[&str], body: Value) -> Option<Value> {
        match self.state.es.search_index(indices, body).await {
            Ok(result) => Some(result),
            Err(error) => {
                tracing::warn!(%error, "notifier query failed");
                None
            }
        }
    }

    /// OT command alerts (T1692.001) — the one host-local-adjacent signal
    /// that is actually pure ES: honeypot.canonical_attck_techniques is
    /// already flattened onto every event (see kill_chain.rs's
    /// technique_counts), no mount needed. Ports store.go's otSources loop.
    async fn ot_command_alerts(&mut self, mark_only: bool) {
        let Some(result) = self
            .search(
                &["honeypot-v2-*", "suricata-v2-*"],
                json!({"size": 500, "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": "now-10m"}}},
                    {"term": {"honeypot.canonical_attck_techniques": "T1692.001"}}
                // #2145: a healthcheck exercising the OT path must not raise
                // an OT-command alert (the term is a no-op for suricata docs).
                ], "must_not": [crate::es::internal_probe_exclusion()]}}}),
            )
            .await
        else {
            return;
        };
        let mut seen = std::collections::HashSet::new();
        for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
            let source = &hit["_source"];
            let src_ip = source["source"]["ip"].as_str().unwrap_or("").to_string();
            let sensor = source["event"]["sensor"].as_str().unwrap_or("").to_string();
            if src_ip.is_empty() || !seen.insert((src_ip.clone(), sensor.clone())) {
                continue;
            }
            let label = format!("{src_ip} via {sensor}");
            let message = format!("industrial control command/write attempt: {label}");
            self.observe(&format!("ot-command:{label}"), message, &format!("/events?ip={src_ip}"), mark_only)
                .await;
        }
    }

    /// Log-stream size alerts (#1389 self-rotation regression guard). Ports
    /// log_streams.go's scanLogStreams/logStreamAlerts.
    async fn log_stream_alerts(&mut self, mark_only: bool) {
        let log_dir = env_or("LOG_DIR", "/logs");
        let max_bytes: i64 = env_or("LOG_STREAM_MAX_BYTES", "67108864").parse().unwrap_or(67108864);
        if max_bytes <= 0 {
            return;
        }
        let alert_percent: i64 = env_or("LOG_STREAM_ALERT_PERCENT", "90").parse().unwrap_or(90);
        let alert_percent = if (1..=99).contains(&alert_percent) { alert_percent } else { 90 };
        let threshold = (max_bytes * alert_percent + 99) / 100;

        let mut candidates: Vec<(String, std::path::PathBuf)> = Vec::new();
        let enriched_dir = Path::new(&log_dir).join("enriched");
        if let Ok(mut entries) = tokio::fs::read_dir(&enriched_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(rel) = path.strip_prefix(Path::new(&log_dir)) {
                        candidates.push((rel.to_string_lossy().replace('\\', "/"), path.clone()));
                    }
                }
            }
        }
        for fixed in ["dionaea/dionaea.json", "dionaea/dionaea_incident.json"] {
            candidates.push((fixed.to_string(), Path::new(&log_dir).join(fixed)));
        }

        for (name, path) in candidates {
            let Ok(meta) = tokio::fs::metadata(&path).await else { continue };
            if !meta.is_file() || (meta.len() as i64) < threshold {
                continue;
            }
            let age = meta.modified().ok().and_then(|m| m.elapsed().ok()).unwrap_or_default();
            let message = format!(
                "honeypot JSON stream approaching rotation limit: {name} size={} limit={} age={}",
                human_bytes(meta.len()),
                human_bytes(max_bytes as u64),
                format_go_duration(age)
            );
            self.observe(&format!("log-stream-size:{name}"), message, "", mark_only).await;
        }
    }

    /// Sandbox spool + worker-status health. Ports sandbox.go's
    /// loadSandboxStatus (merged across Linux/Windows/GHOSTS backends) and
    /// store.go's sandbox:handoff/sandbox:worker/sandbox:failed alerts.
    async fn sandbox_alerts(&mut self, mark_only: bool) {
        let mut results_dirs = vec![env_or("SANDBOX_RESULTS_DIR", "/sandbox-results")];
        for var in ["WINDOWS_SANDBOX_RESULTS_DIR", "GHOSTS_SANDBOX_RESULTS_DIR"] {
            let dir = env_or(var, "");
            if !dir.is_empty() && !results_dirs.contains(&dir) {
                results_dirs.push(dir);
            }
        }
        let mut request_dirs = vec![env_or("SANDBOX_REQUEST_DIR", "/sandbox-requests")];
        for var in ["WINDOWS_SANDBOX_REQUEST_DIR", "GHOSTS_SANDBOX_REQUEST_DIR"] {
            let dir = env_or(var, "");
            if !dir.is_empty() && !request_dirs.contains(&dir) {
                request_dirs.push(dir);
            }
        }

        let (mut merged_state, mut counts, mut any_ok) = (String::new(), (0i64, 0i64, 0i64, 0i64), false);
        for dir in &results_dirs {
            let Some((state, c)) = read_sandbox_queue_file(dir).await else { continue };
            if !any_ok {
                merged_state = state;
                counts = c;
                any_ok = true;
            } else {
                counts.0 += c.0;
                counts.1 += c.1;
                counts.2 += c.2;
                counts.3 += c.3;
                if sandbox_state_rank(&state) > sandbox_state_rank(&merged_state) {
                    merged_state = state;
                }
            }
        }

        let (mut handoff, mut handoff_old) = (0i64, false);
        for dir in &request_dirs {
            let (count, old) = scan_request_dir(dir).await;
            handoff += count;
            handoff_old = handoff_old || old;
        }

        if handoff_old {
            let message =
                format!("sandbox handoff stalled: {handoff} dashboard request(s) are waiting for the host watcher");
            self.observe("sandbox:handoff", message, "", mark_only).await;
        }
        if merged_state == "stale" || merged_state == "error" {
            let message =
                format!("sandbox worker unhealthy: state={merged_state} queued={} running={}", counts.0, counts.1);
            self.observe("sandbox:worker", message, "", mark_only).await;
        }
        if counts.3 > 0 {
            self.observe("sandbox:failed", format!("sandbox queue has {} failed job(s)", counts.3), "", mark_only)
                .await;
        }
    }

    /// Ghidra spool + worker-status health + flagged findings. Ports
    /// ghidra.go's loadGhidraStatus/ghidraAlerts.
    async fn ghidra_alerts(&mut self, mark_only: bool) {
        let results_dir = env_or("GHIDRA_RESULTS_DIR", "");
        let request_dir = env_or("GHIDRA_REQUEST_DIR", "");
        let status = read_spool_status(&results_dir, &request_dir).await;
        if !status.configured {
            return;
        }
        if status.stale {
            let message = format!(
                "ghidra worker not draining: queue file is stale, {} queued, {} running (check honeypot-ghidra-worker.path)",
                status.queued, status.running
            );
            self.observe("ghidra:worker", message, "", mark_only).await;
        }
        if status.failed > 0 {
            self.observe("ghidra:failed", format!("ghidra queue has {} failed request(s)", status.failed), "", mark_only)
                .await;
        }

        let alert_levels: std::collections::HashSet<String> = env_or("GHIDRA_ALERT_RISK_LEVELS", "high,critical")
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let alert_on_crypto = env_or("GHIDRA_ALERT_ON_CRYPTO", "false").eq_ignore_ascii_case("true");

        // #2179: freshest-first sort + a loud truncation warning instead of an
        // unsorted 300-doc window whose silent rotation out of alerting was
        // arbitrary (same discipline as llm_flagged_alerts below).
        const GHIDRA_ALERT_SCAN: i64 = 300;
        if let Some(result) = self
            .search(
                &[GHIDRA_INDEX],
                json!({"size": GHIDRA_ALERT_SCAN,
                       "query": {"exists": {"field": "ghidra.sha256"}},
                       "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]}),
            )
            .await
        {
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            if hits.len() as i64 >= GHIDRA_ALERT_SCAN {
                tracing::warn!(
                    cap = GHIDRA_ALERT_SCAN,
                    "ghidra alert scan hit its size cap this cycle, older samples may be skipped"
                );
            }
            for hit in hits {
                let g = &hit["_source"]["ghidra"];
                let sha = g["sha256"].as_str().unwrap_or("").to_string();
                if sha.is_empty() {
                    continue;
                }
                if g["exit_status"].as_str() == Some("error") {
                    let message =
                        format!("ghidra analysis failed: sha256={sha} reason={}", g["error"].as_str().unwrap_or(""));
                    self.observe(&format!("ghidra:error:{sha}"), message, "", mark_only).await;
                    continue;
                }
                let risk_level = g["ai_triage"]["risk_level"].as_str().unwrap_or("").to_lowercase();
                let risky = !risk_level.is_empty() && alert_levels.contains(&risk_level);
                let findcrypt_len = g["findcrypt"].as_array().map(|a| a.len()).unwrap_or(0);
                let crypto = alert_on_crypto && findcrypt_len > 0;
                if !risky && !crypto {
                    continue;
                }
                let imports_len = g["imports"].as_array().map(|a| a.len()).unwrap_or(0);
                let detail = if risky {
                    format!(
                        "AI-guessed risk={} (UNVERIFIED, {})",
                        g["ai_triage"]["risk_level"].as_str().unwrap_or(""),
                        g["ai_triage"]["model"].as_str().unwrap_or("")
                    )
                } else {
                    "crypto constants only".to_string()
                };
                let message =
                    format!("ghidra flagged sample: sha256={sha} crypto_hits={findcrypt_len} imports={imports_len} {detail}");
                self.observe(&format!("ghidra:flagged:{sha}"), message, "", mark_only).await;
            }
        }
    }

    /// CAPE spool + worker-status health only (no findings loop — #319's
    /// issue text asked specifically for worker-health surfacing). Ports
    /// cape.go's loadCapeStatus/capeAlerts.
    async fn cape_alerts(&mut self, mark_only: bool) {
        let results_dir = env_or("CAPE_RESULTS_DIR", "");
        let request_dir = env_or("CAPE_REQUEST_DIR", "");
        let status = read_spool_status(&results_dir, &request_dir).await;
        if !status.configured {
            return;
        }
        if status.stale {
            let message = format!(
                "cape worker not draining: queue file is stale, {} queued, {} running (check honeypot-cape-worker.path)",
                status.queued, status.running
            );
            self.observe("cape:worker", message, "", mark_only).await;
        }
        if status.failed > 0 {
            self.observe("cape:failed", format!("cape queue has {} failed request(s)", status.failed), "", mark_only)
                .await;
        }
    }

    /// GitHub-analysis spool + worker-status health + verdict findings.
    /// Ports github_analysis.go's loadGitHubAnalysisStatus/
    /// githubAnalysisAlerts. Unlike ghidra/cape, staleness here is a plain
    /// mtime check (no live-spool recheck) — mirrors the Go source exactly.
    async fn github_analysis_alerts(&mut self, mark_only: bool) {
        let results_dir = env_or("GITHUB_ANALYSIS_RESULTS_DIR", "");
        if results_dir.is_empty() {
            return; // not configured — no noise for an unopted-in subsystem
        }
        let request_dir = env_or("GITHUB_ANALYSIS_REQUEST_DIR", "");
        let path = Path::new(&results_dir).join("status.json");
        let (mut stale, mut queued, mut running, mut failed) = (false, 0i64, 0i64, 0i64);
        match tokio::fs::read(&path).await.ok().and_then(|body| serde_json::from_slice::<Value>(&body).ok()) {
            Some(value) => {
                queued = value["queued"].as_i64().unwrap_or(0);
                running = value["running"].as_i64().unwrap_or(0);
                failed = value["failed"].as_i64().unwrap_or(0);
                if let Ok(meta) = tokio::fs::metadata(&path).await {
                    if let Ok(modified) = meta.modified() {
                        stale = modified.elapsed().unwrap_or_default() > SPOOL_STALE_AFTER;
                    }
                }
            }
            None => stale = true,
        }

        let (handoff, handoff_old) = scan_request_dir(&request_dir).await;

        if handoff_old {
            let message = format!("github-analysis handoff stalled: {handoff} request(s) waiting for the host publisher");
            self.observe("github-analysis:handoff", message, "", mark_only).await;
        }
        if stale {
            let message = format!("github-analysis worker unhealthy: status.json stale, queued={queued} running={running}");
            self.observe("github-analysis:worker", message, "", mark_only).await;
        }
        if failed > 0 {
            self.observe(
                "github-analysis:failed",
                format!("github-analysis queue has {failed} failed request(s)"),
                "",
                mark_only,
            )
            .await;
        }

        let threshold: i64 = env_or("GITHUB_ANALYSIS_ALERT_POSITIVES", "10").parse().unwrap_or(10).max(1);
        // #2179: freshest-first sort + loud truncation warning (see
        // ghidra_alerts above for the rationale).
        const GITHUB_ALERT_SCAN: i64 = 300;
        if let Some(result) = self
            .search(
                &[GITHUB_ANALYSIS_INDEX],
                json!({"size": GITHUB_ALERT_SCAN,
                       "query": {"exists": {"field": "github_analysis.sha256"}},
                       "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]}),
            )
            .await
        {
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            if hits.len() as i64 >= GITHUB_ALERT_SCAN {
                tracing::warn!(
                    cap = GITHUB_ALERT_SCAN,
                    "github-analysis alert scan hit its size cap this cycle, older samples may be skipped"
                );
            }
            for hit in hits {
                let g = &hit["_source"]["github_analysis"];
                let sha = g["sha256"].as_str().unwrap_or("").to_string();
                let Some(malicious) = g["verdict"]["malicious"].as_i64() else { continue };
                if sha.is_empty() || malicious < threshold {
                    continue;
                }
                let total = g["verdict"]["total"].as_i64().unwrap_or(0);
                let family = g["family"].as_str().unwrap_or("");
                let message =
                    format!("github-analysis high-verdict sample: sha256={sha} malicious={malicious}/{total} family={family}");
                self.observe(&format!("github-analysis:verdict:{sha}"), message, &format!("/github-analysis/{sha}"), mark_only)
                    .await;
            }
        }
    }

    /// Filebeat ingestion health via FILEBEAT_URL. Ports elastic.go's
    /// refreshFilebeat's two alert-relevant halves (state + loss counters);
    /// the Go message also folds in a separate in-memory IngestState this
    /// Rust tier doesn't track, so this covers the filebeat half faithfully
    /// rather than inventing an ingest-staleness computation.
    async fn filebeat_alerts(&mut self, mark_only: bool) {
        // Unset or blank: Filebeat is not co-located with this backend
        // (#3576), so there is nothing to alert on. Skipping is not a
        // healthy report; source-health shows the card as "disabled".
        let url = env_or("FILEBEAT_URL", "").trim().to_string();
        if url.is_empty() {
            return;
        }
        let stats_url = format!("{}/stats", url.trim_end_matches('/'));
        let (state, failed, dropped, active) = match self.client.get(&stats_url).send().await {
            Err(_) => ("unreachable".to_string(), 0i64, 0i64, 0i64),
            Ok(response) if !response.status().is_success() => (response.status().to_string(), 0, 0, 0),
            Ok(response) => match response.json::<Value>().await {
                Ok(body) => {
                    let events = &body["libbeat"]["output"]["events"];
                    (
                        "healthy".to_string(),
                        events["failed"].as_i64().unwrap_or(0),
                        events["dropped"].as_i64().unwrap_or(0),
                        events["active"].as_i64().unwrap_or(0),
                    )
                }
                Err(_) => (String::new(), 0, 0, 0),
            },
        };
        if state != "healthy" {
            self.observe("pipeline:ingestion", format!("honeypot ingestion unhealthy: filebeat={state}"), "", mark_only)
                .await;
        }
        if failed > 0 || dropped > 0 {
            let message = format!("Filebeat reports failed={failed} dropped={dropped} active={active}");
            self.observe("pipeline:filebeat-loss", message, "", mark_only).await;
        }
    }


    /// One search per index pattern: newest real document, last hour, and the
    /// reference week. None when the query failed, or when the pattern has no
    /// real documents in the whole lookback window — a feed that was never
    /// deployed has nothing to be late about, and staying quiet is the safe
    /// direction for a check whose job is to be believed.
    /// (indexed_at, sensed_at) for the newest documents that carry both.
    ///
    /// Only honeypot-v2-* is sampled: Suricata and Zeek documents are dated
    /// from the event itself, so their delivery lag is already zero by
    /// construction and asking would measure nothing.
    async fn delivery_lag_sample(&self) -> Option<Vec<(i64, i64)>> {
        let result = self
            .search(
                &["honeypot-v2-*"],
                json!({
                    "size": DELIVERY_LAG_SAMPLE,
                    "track_total_hits": false,
                    "query": {"bool": {
                        "filter": [{"exists": {"field": "honeypot.timestamp"}}],
                        "must_not": [crate::es::internal_probe_exclusion()]
                    }},
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": ["@timestamp", "honeypot.timestamp"]
                }),
            )
            .await?;
        let pairs: Vec<(i64, i64)> = result["hits"]["hits"]
            .as_array()?
            .iter()
            .filter_map(|hit| {
                let source = &hit["_source"];
                let indexed = source["@timestamp"].as_str()?;
                let sensed = source["honeypot"]["timestamp"].as_str()?;
                let indexed = chrono::DateTime::parse_from_rfc3339(indexed).ok()?;
                // The sensor's own stamp is not always zoned; assume UTC when
                // it is not, which is what every producer here writes.
                let sensed = chrono::DateTime::parse_from_rfc3339(sensed)
                    .map(|value| value.timestamp())
                    .or_else(|_| {
                        chrono::NaiveDateTime::parse_from_str(sensed, "%Y-%m-%dT%H:%M:%S%.f")
                            .map(|value| value.and_utc().timestamp())
                    })
                    .ok()?;
                Some((indexed.timestamp(), sensed))
            })
            .collect();
        (!pairs.is_empty()).then_some(pairs)
    }

    async fn ingest_sample(&self, pattern: &str) -> Option<IngestSample> {
        let result = self
            .search(
                &[pattern],
                json!({
                    "size": 0,
                    "track_total_hits": false,
                    "query": {"bool": {
                        "filter": [{"range": {"@timestamp": {"gte": INGEST_LOOKBACK}}}],
                        "must_not": [crate::es::internal_probe_exclusion()]
                    }},
                    "aggs": {
                        "newest": {"max": {"field": "@timestamp"}},
                        "recent": {"filter": {"range": {"@timestamp": {"gte": "now-1h"}}}},
                        "baseline": {"filter": {"range": {"@timestamp": {
                            "gte": INGEST_BASELINE_FROM, "lt": INGEST_BASELINE_TO}}}}
                    }
                }),
            )
            .await?;
        let aggs = &result["aggregations"];
        // null when the pattern matched no documents at all.
        let newest_ms = aggs["newest"]["value"].as_f64()?;
        let now_ms = chrono::Utc::now().timestamp_millis() as f64;
        Some(IngestSample {
            newest_age_seconds: ((now_ms - newest_ms) / 1000.0).max(0.0) as i64,
            recent: aggs["recent"]["doc_count"].as_u64().unwrap_or(0),
            baseline_hourly: aggs["baseline"]["doc_count"].as_u64().unwrap_or(0) as f64
                / INGEST_BASELINE_HOURS,
        })
    }

    /// #1750 — one alert per ingestion path, naming the indices that stalled.
    async fn ingest_lag_alerts(&mut self, mark_only: bool) {
        let floor_percent: u64 = env_or("ALERT_INGEST_FLOOR_PERCENT", "10")
            .parse()
            .unwrap_or(10)
            .clamp(1, 90);
        let min_baseline: f64 = env_or("ALERT_INGEST_MIN_BASELINE", "1000")
            .parse()
            .unwrap_or(1000.0);

        for feed in INGEST_FEEDS {
            let mut checked = 0usize;
            let mut stalls: Vec<String> = Vec::new();
            for index in feed.indices {
                let Some(sample) = self.ingest_sample(index.pattern).await else { continue };
                checked += 1;
                if let Some(reason) = ingest_stall(index, &sample, floor_percent, min_baseline) {
                    stalls.push(reason);
                }
            }
            if stalls.is_empty() {
                continue;
            }
            let scope = if checked > 1 {
                format!(" ({} of {} indices)", stalls.len(), checked)
            } else {
                String::new()
            };
            let message = format!(
                "{} ingestion stalled: {}{}",
                feed.name,
                stalls.join("; "),
                scope
            );
            self.observe(
                &format!("pipeline:ingest-lag:{}", feed.name),
                message,
                "/source-health",
                mark_only,
            )
            .await;
        }

        // Delivery lag: is what arrives still current? Freshness cannot answer
        // that -- through #1770's 45-hour stall documents kept arriving and
        // every freshness check read green, while what arrived was half a day
        // old.
        if let Some(pairs) = self.delivery_lag_sample().await {
            if let Some(lag) = delivery_lag_seconds(&pairs) {
                if lag >= DELIVERY_LAG_LIMIT.as_secs() as i64 {
                    let message = format!(
                        "sensor events are reaching Elasticsearch {} after they were recorded \
                         (median over the newest {} documents)",
                        format_go_duration(Duration::from_secs(lag as u64)),
                        pairs.len()
                    );
                    self.observe(
                        "pipeline:delivery-lag",
                        message,
                        "/source-health",
                        mark_only,
                    )
                    .await;
                }
            }
        }
    }

    // Sections 1-6 of pass(), split out below (#2181) so all fourteen
    // checks stand behind the same per-check panic boundary the method-form
    // checks (7-14) always had.

    /// Section 1: high-scoring campaigns (campaigns-v1).
    async fn campaign_alerts(&mut self, mark_only: bool) {
        let threshold: u64 = env_or("ALERT_CAMPAIGN_SCORE", "80").parse().unwrap_or(80).clamp(1, 100);
        // #2179: sort on `last` (campaign docs carry no @timestamp; correlator
        // stamps `last`/`generated` instead) so the 200-doc window holds the
        // currently hottest campaigns, and warn loudly when the window is full.
        const CAMPAIGN_ALERT_SCAN: i64 = 200;
        if let Some(result) = self
            .search(
                &["campaigns-v1"],
                json!({"size": CAMPAIGN_ALERT_SCAN,
                       "query": {"range": {"score": {"gte": threshold}}},
                       "sort": [{"last": {"order": "desc", "unmapped_type": "date"}}]}),
            )
            .await
        {
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            if hits.len() as i64 >= CAMPAIGN_ALERT_SCAN {
                tracing::warn!(
                    cap = CAMPAIGN_ALERT_SCAN,
                    threshold,
                    "campaign alert scan hit its size cap this cycle, colder high-score campaigns may be skipped"
                );
            }
            for hit in hits {
                let source = &hit["_source"];
                let cidr = source["cidr"].as_str().unwrap_or("");
                if cidr.is_empty() {
                    continue;
                }
                let message = format!(
                    "honeypot campaign {cidr} score={} events={} sensors={:?} ports={:?}",
                    source["score"], source["events"], source["sensors"], source["ports"]
                );
                self.observe(&format!("campaign:{cidr}"), message, &format!("/events?cidr={cidr}"), mark_only)
                    .await;
            }
        }
    }

    /// Section 2: stale sensor feeds + activity spike — one aggregation.
    async fn sensor_activity_alerts(&mut self, mark_only: bool) {
        if let Some(result) = self
            .search(
                &["honeypot-v2-*", "suricata-v2-*"],
                json!({"size": 0,
                       // #2145: probe bursts would otherwise read as
                       // per-sensor activity spikes and fire false alerts.
                       "query": {"bool": {
                           "filter": [{"range": {"@timestamp": {"gte": "now-48h"}}}],
                           "must_not": [crate::es::internal_probe_exclusion()]
                       }},
                       "aggs": {
                           "sensors": {"terms": {"field": "event.sensor", "size": 50},
                                        "aggs": {"last": {"max": {"field": "@timestamp"}}}},
                           "last24h": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
                           "prev24h": {"filter": {"range": {"@timestamp": {"gte": "now-48h", "lt": "now-24h"}}}}
                       }}),
            )
            .await
        {
            let now_ms = chrono::Utc::now().timestamp_millis();
            for bucket in result["aggregations"]["sensors"]["buckets"].as_array().cloned().unwrap_or_default() {
                let name = bucket["key"].as_str().unwrap_or("").to_string();
                let last_ms = bucket["last"]["value"].as_f64().unwrap_or(0.0) as i64;
                let age_min = ((now_ms - last_ms) / 60000).max(0);
                if age_min >= 60 {
                    let message = format!("honeypot feed stale: {name} (last event {age_min}m ago)");
                    self.observe(&format!("stale:{name}"), message, "", mark_only).await;
                }
            }
            let last = result["aggregations"]["last24h"]["doc_count"].as_i64().unwrap_or(0);
            let prev = result["aggregations"]["prev24h"]["doc_count"].as_i64().unwrap_or(0);
            if prev > 0 {
                let pct = (last - prev) * 100 / prev;
                if pct >= 100 {
                    let message =
                        format!("honeypot activity spike: {last} events in 24h ({pct:+}% vs previous 24h)");
                    self.observe("activity:spike", message, "", mark_only).await;
                }
            }
        }
    }

    /// Section 3: ingest rejection dead letters.
    async fn dead_letter_alerts(&mut self, mark_only: bool) {
        if let Some(result) = self
            .search(
                &["dead-letter-honeypot"],
                json!({"size": 0, "track_total_hits": true,
                       "query": {"range": {"@timestamp": {"gte": "now-24h"}}}}),
            )
            .await
        {
            let count = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
            if count > 0 {
                let message = format!("honeypot ingest rejected {count} documents in the last 24h");
                self.observe("pipeline:dead-letters", message, "", mark_only).await;
            }
        }
    }

    /// Section 4: YARA payload matches.
    async fn yara_alerts(&mut self, mark_only: bool) {
        // #2179: this scan already sorts freshest-first; all that was missing
        // is disclosing the bound instead of rotating old matches out silently.
        const YARA_ALERT_SCAN: i64 = 200;
        if let Some(result) = self
            .search(
                &["yara-analysis-v1"],
                json!({"size": YARA_ALERT_SCAN,
                       "query": {"exists": {"field": "yara.matches"}},
                       "sort": [{"@timestamp": {"order": "desc"}}]}),
            )
            .await
        {
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            if hits.len() as i64 >= YARA_ALERT_SCAN {
                tracing::warn!(
                    cap = YARA_ALERT_SCAN,
                    "yara alert scan hit its size cap this cycle, older matches may be skipped"
                );
            }
            for hit in hits {
                let yara = &hit["_source"]["yara"];
                let matches: Vec<&str> = yara["matches"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|value| value.as_str())
                    .collect();
                let hash = yara["sha256"].as_str().unwrap_or("");
                if matches.is_empty() || hash.is_empty() {
                    continue;
                }
                let message = format!(
                    "YARA payload match: {hash} rules={} source={}",
                    matches.join(","),
                    yara["source"].as_str().unwrap_or("")
                );
                self.observe(&format!("yara:{hash}"), message, &format!("/payload-analysis/{hash}"), mark_only)
                    .await;
            }
        }
    }

    /// Section 5: sandbox high-risk detonations.
    async fn sandbox_risk_alerts(&mut self, mark_only: bool) {
        let risk_threshold: u64 = env_or("SANDBOX_ALERT_RISK_SCORE", "50").parse().unwrap_or(50).clamp(1, 100);
        // #2179: freshest-first sort + loud truncation warning (see
        // campaign_alerts above for the rationale).
        const SANDBOX_ALERT_SCAN: i64 = 100;
        if let Some(result) = self
            .search(
                &["sandbox-analysis-v1"],
                json!({"size": SANDBOX_ALERT_SCAN,
                       "query": {"range": {"risk_score": {"gte": risk_threshold}}},
                       "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]}),
            )
            .await
        {
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            if hits.len() as i64 >= SANDBOX_ALERT_SCAN {
                tracing::warn!(
                    cap = SANDBOX_ALERT_SCAN,
                    "sandbox alert scan hit its size cap this cycle, older high-risk jobs may be skipped"
                );
            }
            for hit in hits {
                let source = &hit["_source"];
                let job = source["sandbox"]["job"].as_str().or(source["job"].as_str()).unwrap_or("");
                let sha = source["file"]["hash"]["sha256"].as_str().unwrap_or("");
                if job.is_empty() {
                    continue;
                }
                let message = format!(
                    "sandbox high-risk behavior: sha256={sha} score={} level={}",
                    source["risk_score"], source["risk_level"].as_str().unwrap_or("")
                );
                self.observe(&format!("sandbox:risk:{job}"), message, &format!("/sandbox/{job}"), mark_only)
                    .await;
            }
        }
    }

    /// Section 6: LLM-flagged analyses (severity allowlist; AI-guessed, labeled).
    async fn llm_flagged_alerts(&mut self, mark_only: bool) {
        let severities: Vec<String> = env_or("LLM_ANALYSIS_ALERT_SEVERITIES", "high,critical")
            .split(',')
            .map(|level| level.trim().to_lowercase())
            .filter(|level| !level.is_empty())
            .collect();
        if let Some(result) = self
            .search(
                &["llm-analysis"],
                json!({"size": 100, "query": {"terms": {"severity": severities}},
                       "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]}),
            )
            .await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let source = &hit["_source"];
                let id = source["analysis_id"].as_str().unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                let message = format!(
                    "llm-analysis flagged {}: analysis_id={id} AI-guessed severity={} (UNVERIFIED, model={}) intent={}",
                    source["doc_type"].as_str().unwrap_or(""),
                    source["severity"].as_str().unwrap_or(""),
                    source["model"].as_str().unwrap_or(""),
                    source["intent"].as_str().unwrap_or("")
                );
                self.observe(&format!("llm-analysis:flagged:{id}"), message, "/llm-analysis", mark_only)
                    .await;
            }
        }
    }

    async fn pass(&mut self, mark_only: bool) {
        self.messages.clear();

        // #2181: every check runs behind its own panic boundary. The checks
        // share only this struct (messages vec, ES client config), never an
        // interior lock, so a panicked check costs just its own alert family
        // this pass — the sibling families keep reporting, and the webhook
        // fan-out below still sends whatever did notify. Without these,
        // one malformed document or drifted aggregation shape unwinds the
        // notifier task itself and silences every family at once.
        // 1. High-scoring campaigns (campaigns-v1).
        crate::isolate::item("alert-notifier", "campaigns", self.campaign_alerts(mark_only)).await;
        // 2. Stale sensor feeds + activity spike — one agg.
        crate::isolate::item("alert-notifier", "sensor-activity", self.sensor_activity_alerts(mark_only)).await;
        // 3. Dead letters.
        crate::isolate::item("alert-notifier", "dead-letters", self.dead_letter_alerts(mark_only)).await;
        // 4. YARA payload matches.
        crate::isolate::item("alert-notifier", "yara-matches", self.yara_alerts(mark_only)).await;
        // 5. Sandbox high-risk detonations.
        crate::isolate::item("alert-notifier", "sandbox-risk", self.sandbox_risk_alerts(mark_only)).await;
        // 6. LLM-flagged analyses.
        crate::isolate::item("alert-notifier", "llm-flagged", self.llm_flagged_alerts(mark_only)).await;
        // 7. OT command alerts (T1692.001) — ES-derived, no mount needed.
        crate::isolate::item("alert-notifier", "ot-command", self.ot_command_alerts(mark_only)).await;
        // 8. Log-stream size alerts.
        crate::isolate::item("alert-notifier", "log-stream-size", self.log_stream_alerts(mark_only)).await;
        // 9. Sandbox spool + worker-status health.
        crate::isolate::item("alert-notifier", "sandbox-spool", self.sandbox_alerts(mark_only)).await;
        // 10. Ghidra spool + worker-status health + flagged findings.
        crate::isolate::item("alert-notifier", "ghidra-spool", self.ghidra_alerts(mark_only)).await;
        // 11. CAPE spool + worker-status health.
        crate::isolate::item("alert-notifier", "cape-spool", self.cape_alerts(mark_only)).await;
        // 12. GitHub-analysis spool + worker-status health + verdict findings.
        crate::isolate::item("alert-notifier", "github-analysis", self.github_analysis_alerts(mark_only)).await;
        // 13. Filebeat ingestion health via FILEBEAT_URL.
        crate::isolate::item("alert-notifier", "filebeat", self.filebeat_alerts(mark_only)).await;
        // 14. Ingestion lag per index (#1750), on its own slower cadence.
        if self.last_ingest_check.is_none_or(|at| at.elapsed() >= INGEST_CHECK_EVERY) {
            self.last_ingest_check = Some(std::time::Instant::now());
            crate::isolate::item("alert-notifier", "ingest-lag", self.ingest_lag_alerts(mark_only)).await;
        }

        // Webhook fan-out for everything that newly notified.
        //
        // #3330: this used to discard the response and log nothing but a
        // transport error, so a webhook answering 500 — rejected token,
        // wrong path — looked exactly like a delivered alert and the only
        // trace was a container log this dashboard never reads. Each
        // message now gets a bounded retry (webhook_delivery decides what
        // is worth repeating) and its outcome recorded, which is what
        // Settings and the diagnostics page surface.
        if !mark_only && !self.webhook.is_empty() {
            let target = crate::webhook_delivery::origin_of(&self.webhook);
            for message in self.messages.clone() {
                let body = json!({"content": message, "text": message});
                let attempt =
                    crate::webhook_delivery::deliver(&self.client, &self.webhook, &body).await;
                if attempt.ok {
                    tracing::info!(
                        latency_ms = attempt.latency_ms,
                        tries = attempt.tries,
                        http_code = attempt.http_code.unwrap_or(0),
                        "alert webhook delivered"
                    );
                } else {
                    tracing::warn!(
                        latency_ms = attempt.latency_ms,
                        tries = attempt.tries,
                        error = %attempt.error.clone().unwrap_or_default(),
                        "alert webhook delivery failed"
                    );
                }
                crate::webhook_delivery::record(
                    &self.state.es,
                    crate::webhook_delivery::ALERT_ID,
                    &target,
                    &attempt,
                )
                .await;
            }
        }
    }
}

fn sandbox_state_rank(state: &str) -> u8 {
    match state {
        "idle" => 1,
        "running" => 2,
        "stale" => 3,
        _ => 0,
    }
}

/// Reads one sandbox backend's status.json (sandbox.go's
/// readSandboxQueueFile). None on missing/oversized/corrupt file — the
/// caller's merge just skips that backend, same observable effect as Go's
/// ok=false path (which never contributes to the "stale"/"error" alert
/// either way). Returns (worker_state, (queued, running, completed, failed)).
async fn read_sandbox_queue_file(dir: &str) -> Option<(String, (i64, i64, i64, i64))> {
    let path = Path::new(dir).join("status.json");
    let body = tokio::fs::read(&path).await.ok()?;
    if body.len() > 256 * 1024 {
        return None;
    }
    let value: Value = serde_json::from_slice(&body).ok()?;
    let mut state = value["worker_state"].as_str().unwrap_or("").to_string();
    let counts = (
        value["counts"]["queued"].as_i64().unwrap_or(0),
        value["counts"]["running"].as_i64().unwrap_or(0),
        value["counts"]["completed"].as_i64().unwrap_or(0),
        value["counts"]["failed"].as_i64().unwrap_or(0),
    );
    if state == "running" {
        if let Some(updated) =
            value["updated_at"].as_str().and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        {
            if (chrono::Utc::now() - updated.with_timezone(&chrono::Utc)).num_minutes() > 10 {
                state = "stale".to_string();
            }
        }
    }
    Some((state, counts))
}

/// Counts `*.request` markers in a spool dir and reports whether the oldest
/// is older than HANDOFF_STALE_AFTER. Shared by sandbox/github-analysis
/// handoff scans (sandbox.go's request-dir loop / githubAnalysisHandoffCounts).
async fn scan_request_dir(dir: &str) -> (i64, bool) {
    if dir.is_empty() {
        return (0, false);
    }
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return (0, false) };
    let (mut count, mut old) = (0i64, false);
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".request") {
            continue;
        }
        count += 1;
        if let Ok(meta) = entry.metadata().await {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or_default() > HANDOFF_STALE_AFTER {
                    old = true;
                }
            }
        }
    }
    (count, old)
}

struct SpoolStatus {
    configured: bool,
    stale: bool,
    queued: i64,
    running: i64,
    failed: i64,
}

/// Ports loadGhidraStatus/loadCapeStatus's shared shape: a flat status.json
/// written by a small host script, re-checked against the live request
/// spool when it looks stale — a systemd *path* unit only rewrites
/// status.json when a request lands, so a quiet honeypot with an empty spool
/// is healthy, not dead; only a stale file over a *non-empty* live spool is
/// a real stall.
async fn read_spool_status(results_dir: &str, request_dir: &str) -> SpoolStatus {
    if results_dir.is_empty() {
        return SpoolStatus { configured: false, stale: false, queued: 0, running: 0, failed: 0 };
    }
    let path = Path::new(results_dir).join("status.json");
    let Some(value) = tokio::fs::read(&path).await.ok().and_then(|body| serde_json::from_slice::<Value>(&body).ok())
    else {
        return SpoolStatus { configured: true, stale: true, queued: 0, running: 0, failed: 0 };
    };
    let mut queued = value["queued"].as_i64().unwrap_or(0);
    let mut running = value["running"].as_i64().unwrap_or(0);
    let failed = value["failed"].as_i64().unwrap_or(0);
    let mut stale = false;
    if let Ok(meta) = tokio::fs::metadata(&path).await {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().unwrap_or_default() > SPOOL_STALE_AFTER {
                let Ok(mut entries) = tokio::fs::read_dir(request_dir).await else {
                    return SpoolStatus { configured: true, stale: true, queued, running, failed };
                };
                let (mut live_q, mut live_r) = (0i64, 0i64);
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".request.running") {
                        live_r += 1;
                    } else if name.ends_with(".request") {
                        live_q += 1;
                    }
                }
                stale = live_q + live_r > 0;
                if stale {
                    queued = live_q;
                    running = live_r;
                }
            }
        }
    }
    SpoolStatus { configured: true, stale, queued, running, failed }
}

const USERS_INDEX: &str = "dashboard-users-v1";
const USERS_ID: &str = "users";
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

async fn retention_sweep_loop(state: AppState) {
    let mut ticker = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // #2181: the sweep reads a stored document shaped like user data
        // inline in this task; a panic below used to end the task outright.
        // The cycle is its own blast radius — nothing is written (removal
        // rewrites one doc only after partition), so a degraded pass simply
        // retriggers unchanged next hour.
        crate::isolate::cycle("user-retention-sweep", retention_sweep_once(&state)).await;
    }
}

/// Removes projections — including their stored preferences — whose
/// last_seen_at predates the retention window, and audits each removal.
/// An empty sweep never writes (matches SweepRetention's contract).
async fn retention_sweep_once(state: &AppState) {
    let retention_days: i64 = env_or("DASHBOARD_USER_RETENTION_DAYS", "90").parse().unwrap_or(90);
    if retention_days <= 0 {
        return;
    }
    let mut doc = match state.es.get_doc(USERS_INDEX, USERS_ID).await {
        Ok(Some(doc)) => doc,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, "retention sweep: users doc fetch failed");
            return;
        }
    };
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);
    let users = doc["payload"]["users"].as_array().cloned().unwrap_or_default();
    let (removed, kept): (Vec<Value>, Vec<Value>) = users.into_iter().partition(|user| {
        user["last_seen_at"]
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|at| at.with_timezone(&chrono::Utc) < cutoff)
    });
    if removed.is_empty() {
        return;
    }
    doc["payload"]["users"] = json!(kept);
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    if let Err(error) = state.es.index_doc(USERS_INDEX, USERS_ID, doc).await {
        tracing::warn!(%error, "retention sweep: users doc write failed");
        return;
    }
    let removed_count = removed.len();
    for user in removed {
        state.audit.log(AuditEvent {
            actor_subject: "system".into(),
            actor_username: "retention".into(),
            action: "users.retention".into(),
            fields: vec![
                user["subject"].as_str().unwrap_or_default().to_string(),
                user["last_username"].as_str().unwrap_or_default().to_string(),
            ],
            result: "success".into(),
            ..Default::default()
        });
    }
    tracing::info!(removed = removed_count, "user retention sweep removed orphaned projection(s)");
}

const REPORTS_SCHEDULER_INTERVAL: Duration = Duration::from_secs(30);

/// Ports reports_scheduler.go's reportScheduleLoop: every tick, render
/// every due definition through the same pipeline as the manual generate
/// endpoint (origin "schedule"), then advance its schedule.
///
/// What this comment said before #2181 was wrong. Tokio's isolation runs
/// one way only: a panicking task can't take down the process, but nothing
/// stops a panic from unwinding *this* task — renders execute inline in
/// its future, so one poisoned definition would have killed the ticker and
/// every later definition each time it came due, forever, because
/// mark_scheduled_run (which advances next_run_at out of the "due" set)
/// sits after the render and never got to run. Go needed
/// runDueReportsRecovered for exactly this reason; the port has two
/// boundaries instead:
///   * per definition — reports_scheduler_tick isolates each render behind
///     isolate::item; a panicked render still gets its mark_scheduled_run,
///     so next_run_at advances and repeated failures park the definition
///     durably (reports_store::SCHEDULE_QUARANTINE_FAILURES);
///   * per tick — isolate::cycle takes any other panic out of this task's
///     blast radius entirely.
async fn reports_scheduler_loop(state: AppState) {
    let mut ticker = tokio::time::interval(REPORTS_SCHEDULER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        crate::isolate::cycle("reports-scheduler", reports_scheduler_tick(&state)).await;
    }
}

async fn reports_scheduler_tick(state: &AppState) {
    let due = match crate::reports_store::due_definitions(state).await {
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "reports scheduler: due-definitions fetch failed");
            return;
        }
    };
    for definition in due {
        let ran_at = chrono::Utc::now();
        // One poisoned definition costs itself: siblings still render in
        // this pass, and None (panic) is counted like any other failure.
        let result = crate::isolate::item(
            "reports-scheduler",
            &definition.id,
            crate::reports_api::render_definition_to_stored(state, &definition, "schedule"),
        )
        .await;
        match &result {
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                tracing::warn!(id = %definition.id, name = %definition.name, %error, "scheduled report failed");
            }
            None => {
                tracing::warn!(id = %definition.id, name = %definition.name, "scheduled report panicked; isolated (#2181)");
            }
        }
        // Both Err and panic must still advance next_run_at — a failing
        // definition may not hot-loop — and both feed the failure streak
        // that eventually quarantines the schedule.
        let success = matches!(result, Some(Ok(_)));
        crate::reports_store::mark_scheduled_run(state, &definition.id, ran_at, success).await;
    }
}

async fn alert_notifier_loop(state: AppState) {
    let mut notifier = Notifier {
        state,
        cooldown: parse_duration(&env_or("ALERT_COOLDOWN", "6h")),
        webhook: env_or("ALERT_WEBHOOK_URL", ""),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("reqwest client"),
        messages: Vec::new(),
        last_ingest_check: None,
    };
    // Baseline pass: mark existing conditions without paging about
    // history at boot (same posture as the Go loop's current(true)).
    // #2181: even this first pass is boundary-wrapped — a boot-time panic
    // would otherwise end the task before its first tick.
    crate::isolate::cycle("alert-notifier", notifier.pass(true)).await;
    let mut ticker = tokio::time::interval(INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        crate::isolate::cycle("alert-notifier", notifier.pass(false)).await;
    }
}

#[cfg(test)]
mod delivery_lag_tests {
    use super::delivery_lag_seconds;

    #[test]
    fn reports_the_median_not_the_worst_case() {
        // One document delayed an hour among nineteen prompt ones is a retry,
        // not a stall, and must not raise an alert on its own.
        let mut pairs: Vec<(i64, i64)> = (0..19).map(|i| (1000 + i, 998 + i)).collect();
        pairs.push((9999, 6399));
        assert_eq!(delivery_lag_seconds(&pairs), Some(2));
    }

    #[test]
    fn catches_a_stall_that_moves_the_whole_tail() {
        // #1770's shape: everything arriving is twelve hours old.
        let pairs: Vec<(i64, i64)> = (0..20).map(|i| (100_000 + i, 56_800 + i)).collect();
        assert_eq!(delivery_lag_seconds(&pairs), Some(43_200));
    }

    #[test]
    fn ignores_a_sensor_clock_running_ahead() {
        // Negative lag is a clock problem. Reporting it as delivery lag would
        // send someone to inspect a pipeline that did nothing wrong.
        let pairs = vec![(100, 500), (200, 600)];
        assert_eq!(delivery_lag_seconds(&pairs), None);
    }

    #[test]
    fn no_samples_is_not_an_alert() {
        assert_eq!(delivery_lag_seconds(&[]), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(minutes_stale: u64) -> IngestIndex {
        IngestIndex { pattern: "honeypot-v2-*", stale_after: minutes(minutes_stale) }
    }

    fn sample(age_seconds: i64, recent: u64, baseline_hourly: f64) -> IngestSample {
        IngestSample { newest_age_seconds: age_seconds, recent, baseline_hourly }
    }

    #[test]
    fn a_keeping_up_index_is_silent() {
        assert!(ingest_stall(&index(90), &sample(30, 98_000, 100_000.0), 10, 1000.0).is_none());
    }

    #[test]
    fn total_silence_past_the_threshold_is_a_stall() {
        let reason = ingest_stall(&index(90), &sample(3 * 3600, 0, 100_000.0), 10, 1000.0);
        assert!(reason.unwrap().contains("no data for 3h"));
    }

    #[test]
    fn the_2026_08_20_outage_is_caught_in_its_first_hour() {
        // The 45-hour blackout freshness could not see: a trickle of sensors
        // kept the index warm, so the newest document was never more than
        // minutes old, but real volume was 3 events against ~103k/h.
        let reason = ingest_stall(&index(90), &sample(120, 3, 102_956.0), 10, 1000.0);
        assert!(reason.unwrap().contains("down to 3/h against a 102956/h baseline"));
    }

    #[test]
    fn a_quiet_but_not_collapsed_hour_is_not_a_stall() {
        // The lowest hour any high-volume index recorded across two healthy
        // weeks was 37% of its own median. The floor has to sit well under
        // that or the check pages on a quiet night.
        assert!(ingest_stall(&index(90), &sample(60, 36_398, 98_614.0), 10, 1000.0).is_none());
    }

    #[test]
    fn low_rate_indices_are_exempt_from_the_volume_floor() {
        // suricata-v2-smtp-* really does fall to 4 events in an hour against
        // a 66/h median. Freshness still covers it; a percentage does not.
        assert!(ingest_stall(&index(120), &sample(60, 4, 66.0), 10, 1000.0).is_none());
    }

    #[test]
    fn freshness_still_applies_below_the_volume_floor() {
        let reason = ingest_stall(&index(120), &sample(5 * 3600, 0, 66.0), 10, 1000.0);
        assert!(reason.unwrap().contains("no data for"));
    }

    #[test]
    fn every_feed_index_is_named_once() {
        // A duplicated pattern would double-count "n of m indices" and make
        // the message lie about how much of a feed is down.
        let mut seen: Vec<&str> = INGEST_FEEDS
            .iter()
            .flat_map(|feed| feed.indices.iter().map(|index| index.pattern))
            .collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total);
    }
}
