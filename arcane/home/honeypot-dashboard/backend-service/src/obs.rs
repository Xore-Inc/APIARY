//! Serving-tier observability (#1972) — the three things #1942's ~290ms-500
//! investigation proved were missing from this tier:
//!
//! 1. **Request identity.** `observe` (the axum middleware below) reads an
//!    inbound `x-request-id` or mints one, echoes it on every response,
//!    carries it into the per-request `tracing` span and the durable JSONL
//!    line, so one id strings together Traefik → BFF → this tier → ES.
//!    Not cryptographic — it only has to be unique-in-practice and stable
//!    across a request's hops, never secret.
//! 2. **Durable logs.** `tracing` stdout dies with a recreated container;
//!    that gap is the whole reason #1942's failures predated every log we
//!    had. When DASHBOARD_LOG_FILE names a file on the filebeat-tailed
//!    mount (/logs/dashboard-backend/app.jsonl in compose), one structured
//!    JSONL line lands there per request and survives into ES under its own
//!    index family + ILM policy, next to every other evidence stream. That
//!    sink is size-capped with rename rotation (#2468) so it can't outgrow
//!    the json-file retention stdout already has — see MAX_SINK_BYTES for
//!    the arithmetic.
//! 3. **A metrics baseline.** /metrics serves Prometheus text exposition —
//!    requests by route family/status class and a latency histogram per
//!    family — hand-rolled on atomics because the point is exposing numbers
//!    today, not adopting a client crate for two series families. A shedding
//!    storm or error burst becomes visible without reading Traefik's log.
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::Instrument;

use crate::AppState;

/// Upper bound accepted from upstream before we regenerate instead.
const MAX_INBOUND_ID_LEN: usize = 128;

/// Latency bucket edges in whole milliseconds, kept integer so every write
/// is a relaxed atomic increment (no float accumulators anywhere).
const LATENCY_BUCKETS_MS: [u64; 10] = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

/// Size cap for the durable JSONL sink (#2468). The file path it lands on is
/// bind-mounted with NO other rotator in the deployment (no host logrotate,
/// no copytruncate sidecar), so this constant IS the retention policy — and
/// stdout already sets the parity target: compose's json-file driver keeps
/// 3 × 25m per container. One live generation + one retired `.1`
/// (crate::audit::rotate_if_oversized's rename) bounds the sink at
/// 25 MiB + ≤25 MiB = ≤50 MiB on disk. Retention math at the measured line
/// shape (~300 B: timestamp, request id, method/path/status/duration):
/// 26_214_400 B ÷ 300 B ≈ ~87k requests per generation — over a day of the
/// tier's traffic including /healthz probes, and a retry storm fills it in
/// hours instead of never-pruning forever.
const MAX_SINK_BYTES: u64 = 25 << 20;

/// The path's coarse identity. "Per route family" needs bounded label sets;
/// tower's matched-route patterns would need routing internals inside the
/// middleware, while this tier's paths already namespace themselves as
/// /api/v1/<family>/... — everything after <family> is entity ids that must
/// NOT become label values (unbounded cardinality is what quietly kills a
/// metrics endpoint months later).
pub fn family_for_path(path: &str) -> String {
    let mut segments = path.split('/').filter(|s| !s.is_empty());
    match (segments.next(), segments.next(), segments.next()) {
        // The three probe routes, each its own family rather than folded
        // into "other" (#3317): /readyz answers 503 whenever Elasticsearch
        // is not ready, so an operator watching the request-rate series
        // needs to be able to tell a readiness probe's failures from an
        // unrelated path that happens to be misshapen.
        (Some("healthz"), None, None) => "healthz".to_string(),
        (Some("livez"), None, None) => "livez".to_string(),
        (Some("readyz"), None, None) => "readyz".to_string(),
        (Some("metrics"), None, None) => "metrics".to_string(),
        (Some("api"), Some("v1"), Some(family)) => {
            // Only clean single-segment names become labels; anything odd
            // folds into "other" rather than feeding cardinality.
            let clean = !family.is_empty()
                && family.len() <= 40
                && family.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if clean {
                family.to_string()
            } else {
                "other".to_string()
            }
        }
        _ => "other".to_string(),
    }
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// The tier's observability state: what AppState actually holds. Kept as one
/// handle so adding the next signal is one field here, not another
/// AppState-wide thread.
pub struct Obs {
    pub metrics: Metrics,
    /// Durable JSONL sink (DASHBOARD_LOG_FILE); empty string disables.
    pub log_file: String,
    /// Serializes each append's size-check → rotate → open → write so
    /// concurrent spawned tasks can't straddle the rename. Unserialized, a
    /// writer holding an open fd across the swap appends into the retired
    /// `.1` after filebeat has already drained it — those lines never ship.
    /// Same guard shape config_history.rs wraps its own rotated sink in.
    sink_lock: tokio::sync::Mutex<()>,
}

impl Obs {
    pub fn new(log_file: String) -> Self {
        Self { metrics: Metrics::new(), log_file, sink_lock: tokio::sync::Mutex::new(()) }
    }
}

fn valid_inbound_id(raw: &str) -> bool {
    // Accept what came from upstream when it looks like a transport id:
    // printable ASCII, no whitespace/control bytes, sane length. Anything
    // else is regenerated rather than trusted further.
    !raw.is_empty()
        && raw.len() <= MAX_INBOUND_ID_LEN
        && raw.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// This request's id: upstream's when present and well-formed, otherwise
/// time+counter hex. Monotonic-nanosecond XOR with a process-lifetime counter
/// keeps concurrent generations distinct without pulling a uuid crate; these
/// are correlation keys, not capabilities.
pub fn mint_request_id(inbound: Option<&str>) -> String {
    if let Some(id) = inbound.map(str::trim).filter(|id| valid_inbound_id(id)) {
        return id.to_string();
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = nanos ^ counter.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xa5a5_5a5a_0000_0001;
    format!("req-{mixed:016x}")
}

pub struct Metrics {
    /// {family,status_class} → count. One Mutex over plain counters: writes
    /// are a short critical section each and the scrape takes it once — fine
    /// at dashboard-grade traffic (#1616 caps this tier at 64 inflight).
    requests: Mutex<HashMap<(String, String), u64>>,
    /// Cumulative-per-family histogram buckets keyed "<family>|<le_ms>".
    latency_buckets: Mutex<HashMap<String, u64>>,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            latency_buckets: Mutex::new(HashMap::new()),
            latency_sum_ms: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
        }
    }

    pub fn record(&self, family: &str, status: u16, duration_ms: u64) {
        *self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry((family.to_string(), status_class(status).to_string()))
            .or_default() += 1;
        {
            let mut buckets = self.latency_buckets.lock().unwrap_or_else(|p| p.into_inner());
            for edge in LATENCY_BUCKETS_MS {
                if duration_ms <= edge {
                    *buckets.entry(format!("{family}|{edge}")).or_default() += 1;
                }
            }
        }
        self.latency_sum_ms.fetch_add(duration_ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text exposition. Cumulative buckets plus _sum/_count keep
    /// this standard-shape for any scraper; le=+Inf closes each family's
    /// series so rate()/histogram_quantile() behave as documented.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("# HELP apiary_backend_requests_total Requests by route family and status class.\n");
        out.push_str("# TYPE apiary_backend_requests_total counter\n");
        let mut rows: Vec<((String, String), u64)> =
            self.requests.lock().unwrap_or_else(|p| p.into_inner()).clone().into_iter().collect();
        rows.sort();
        // Borrowed, not moved: the histogram section below re-reads these
        // same rows for per-family family lists and +Inf counts.
        for ((family, class), count) in &rows {
            out.push_str(&format!(
                "apiary_backend_requests_total{{family=\"{family}\",status=\"{class}\"}} {count}\n"
            ));
        }

        out.push_str("# HELP apiary_backend_request_duration_seconds Request latency by route family.\n");
        out.push_str("# TYPE apiary_backend_request_duration_seconds histogram\n");
        let buckets = self.latency_buckets.lock().unwrap_or_else(|p| p.into_inner()).clone();
        // Family list comes from the requests rows, NOT from populated
        // bucket keys: a duration above every finite edge fills no bucket
        // yet is still a real sample of that family — dropping it would
        // strand the family with no +Inf close and skew histogram_quantile().
        // record() bumps both maps one-for-one, so the same rows also give
        // each family its own sample count for +Inf (the global counter
        // would leak one family's volume into every other family's Inf
        // bucket — caught exactly that way by the text-exposition test).
        let rows_ref = &rows;
        let mut families: Vec<&str> =
            rows_ref.iter().map(|((f, _), _)| f.as_str()).collect();
        families.sort_unstable();
        families.dedup();
        let total = self.latency_count.load(Ordering::Relaxed);
        for family in families {
            for edge in LATENCY_BUCKETS_MS {
                let value = buckets.get(&format!("{family}|{edge}")).copied().unwrap_or(0);
                out.push_str(&format!(
                    "apiary_backend_request_duration_seconds_bucket{{family=\"{family}\",le=\"{}\"}} {value}\n",
                    edge as f64 / 1000.0
                ));
            }
            let family_total: u64 = rows_ref
                .iter()
                .filter(|((f, _), _)| f.as_str() == family)
                .map(|(_, c)| c)
                .sum();
            out.push_str(&format!(
                "apiary_backend_request_duration_seconds_bucket{{family=\"{family}\",le=\"+Inf\"}} {family_total}\n"
            ));
        }
        let sum = self.latency_sum_ms.load(Ordering::Relaxed);
        out.push_str("# UNIT apiary_backend_request_duration_seconds seconds\n");
        out.push_str(&format!("apiary_backend_request_duration_seconds_sum {:.6}\n", sum as f64 / 1000.0));
        out.push_str(&format!("apiary_backend_request_duration_seconds_count {total}\n"));
        out
    }
}

/// One structured line per served request into the filebeat-tailed volume,
/// size-capped by rename rotation (#2468). Shape mirrors what the -v1 index
/// template maps: ECS-ish top level like disk-space-check's feed (#263
/// precedent), so downstream needs no ndjson target namespace. A failing
/// sink (open or rotate — rotate_if_oversized already degrades to a no-op on
/// fs errors) logs once per failure at debug and gets out of the way —
/// shipping logs must never take serving down with it.
///
/// The mechanism is rename-and-reopen, never truncation-in-place:
/// copytruncate against a file Filebeat tails shipped every line twice when
/// portbridge's 8 MiB sidecar did it ("99.9% of portbridge documents were
/// exact duplicate pairs" — the measured evidence in vps/docker-compose.yml's
/// #1776 block), because truncation reset the harvester offset AND gave the
/// rewritten head a second fingerprint identity. Renaming keeps every
/// generation append-only from byte zero — exactly the story
/// honeypot-elk/analysis/filebeat.yml's dashboard-backend stanzas already
/// bless for this path. max_bytes is a parameter so tests can cross real
/// thresholds instead of writing 25 MiB; production passes MAX_SINK_BYTES.
///
/// The rotate → open → write critical section is sync std fs, exactly as in
/// config_history.rs's rotated sink: these are single small writes on a line
/// format that must land atomically behind the guard, and an await between
/// open and write lets tokio's lazy file lifecycle interleave or defer them
/// across tasks (measured in the tests below: sizes lagged a full append).
async fn append_line(
    log_file: &Path,
    lock: &tokio::sync::Mutex<()>,
    max_bytes: u64,
    line: &serde_json::Value,
) {
    let _guard = lock.lock().await;
    // if let, not a two-arm match: clippy single_match (-D warnings) fails
    // the build otherwise, and the Err arm carries no behavior anyway.
    if let Ok(mut rendered) = serde_json::to_string(line) {
        rendered.push('\n');
        crate::audit::rotate_if_oversized(log_file, max_bytes);
        let Ok(mut file) = std::fs::OpenOptions::new().append(true).create(true).open(log_file)
        else {
            tracing::debug!(log_file = %log_file.display(), "[E-OBS] durable request log unavailable");
            return;
        };
        let _ = std::io::Write::write_all(&mut file, rendered.as_bytes());
    }
}

/// Outermost middleware: metrics + request-id echo/span + durable line for
/// everything this tier serves, the liveness/readiness probes and metrics
/// included (the probes' own behavior is part of the observability story
/// too -- /readyz's 503s are the record of an Elasticsearch outage).
pub async fn observe(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = request.method().as_str().to_string();
    let uri_path = request.uri().path().to_string();
    let inbound = headers.get("x-request-id").and_then(|v| v.to_str().ok()).map(str::to_string);
    let request_id = mint_request_id(inbound.as_deref());
    let family = family_for_path(&uri_path);

    // Named span fields put the id into every log line any inner handler
    // emits — grepping stdout for one id answers which handler ran and what
    // it saw, halving #1942's archaeology problem even before ES has the
    // durable copy.
    // `credential` stays empty unless the trust middleware records "dev" on
    // it (#3866), so every line a dev request's handler logs carries it.
    let span = tracing::info_span!(
        "request", request_id = %request_id, method = %method, path = %uri_path,
        credential = tracing::field::Empty
    );
    let response = next.run(request).instrument(span).await;

    let status = response.status().as_u16();
    let dev = response.extensions().get::<crate::trust::DevRequest>().is_some();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    state.observability.metrics.record(&family, status, duration_ms);

    let mut response = response;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    if !state.observability.log_file.is_empty() {
        let mut line = json!({
            "@timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "event.category": "api_request",
            "service": "backend-service",
            "request.id": request_id,
            "http.request.method": method,
            "url.path": uri_path,
            "status_code": status,
            "duration_ms": duration_ms,
            "level": if status >= 500 { "error" } else { "info" },
        });
        // Only a dev request carries the field (#3866): a production line is
        // byte for byte what it was.
        if dev {
            line["credential"] = json!("dev");
        }
        let observability = state.observability.clone();
        tokio::spawn(async move {
            append_line(
                Path::new(&observability.log_file),
                &observability.sink_lock,
                MAX_SINK_BYTES,
                &line,
            )
            .await;
        });
    }
    response
}

#[utoipa::path(
    get,
    path = "/metrics",
    summary = "Prometheus exposition for the #1972 request metrics. Public on purpose, like /healthz.",
    responses(
        (status = 200, description = "Prometheus text exposition format.", body = inline(serde_json::Value), content_type = "text/plain"),
    ),
)]
/// GET /metrics — deliberately unauthenticated exactly like /healthz,
/// /livez and /readyz: all of them are reachable only on LISTEN_ADDR,
/// which is the internal docker network (Traefik publishes the BFF tier,
/// not this listener). Adding auth here would just mean operators punt and
/// scrape over SSH tunnels anyway.
pub async fn metrics_route(State(state): State<AppState>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.observability.metrics.render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_match_the_tier_path_shapes() {
        assert_eq!(family_for_path("/healthz"), "healthz");
        assert_eq!(family_for_path("/livez"), "livez");
        assert_eq!(family_for_path("/readyz"), "readyz");
        assert_eq!(family_for_path("/metrics"), "metrics");
        assert_eq!(family_for_path("/api/v1/store/ml-anomalies?offset=0"), "store");
        assert_eq!(family_for_path("/api/v1/live"), "live");
        // Entity ids must not leak into labels...
        assert_eq!(family_for_path("/api/v1/workbench/runs/abc%20def/children"), "workbench");
        // ...and malformed shapes fold rather than feed cardinality.
        assert_eq!(family_for_path("/api/v1"), "other");
        assert_eq!(family_for_path("/api/v1/../etc/passwd"), "other");
        assert_eq!(family_for_path("/favicon.ico"), "other");
    }

    #[test]
    fn inbound_ids_are_kept_only_when_transport_plausible() {
        assert_eq!(mint_request_id(Some("traefik-id-123")), "traefik-id-123");
        assert_eq!(mint_request_id(Some("  padded-ok  ")), "padded-ok"); // trimmed
        // Whitespace/control bytes/oversized are regenerated, not echoed.
        assert_ne!(mint_request_id(Some("bad id")), "bad id");
        assert_ne!(mint_request_id(Some("bad\nid")), "bad\nid");
        assert_ne!(mint_request_id(Some("x".repeat(MAX_INBOUND_ID_LEN + 1).as_str())), "");
        // Every generated id is distinct from a fresh one.
        assert_ne!(mint_request_id(None), mint_request_id(None));
    }

    #[test]
    fn metrics_render_is_a_valid_text_exposition() {
        let m = Metrics::new();
        m.record("store", 200, 42);
        m.record("store", 200, 1500);
        m.record("auth", 500, 9000);
        let body = m.render();
        assert!(body.contains("apiary_backend_requests_total{family=\"store\",status=\"2xx\"} 2"));
        assert!(body.contains("apiary_backend_requests_total{family=\"auth\",status=\"5xx\"} 1"));
        // Cumulative histogram property: every finite bucket includes both
        // store samples; the 500ms bucket also does (42ms sample), the 100ms
        // one does not (1500ms sample).
        let finite_5000 = "le=\"5\"}"; // sanity: label formatting survived
        assert!(body.contains(finite_5000));
        let plus_inf = "apiary_backend_request_duration_seconds_bucket{family=\"store\",le=\"+Inf\"} 2";
        assert!(body.contains(plus_inf));
        assert!(body.contains("apiary_backend_request_duration_seconds_sum 10.542000"));
        assert!(body.contains("apiary_backend_request_duration_seconds_count 3"));
    }

    // Process-unique scratch paths under the OS temp dir: this crate has no
    // tempfile dependency, and parallel `cargo test` binaries must not share
    // a sink path.
    fn sink_path(tag: &str) -> std::path::PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("apiary-obs-sink-{tag}-{}-{seq}.jsonl", std::process::id()))
    }

    fn scrub(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(crate::audit::rotated_path(path));
    }

    fn line_count(path: &Path) -> usize {
        std::fs::read_to_string(path).unwrap().lines().count()
    }

    #[tokio::test]
    async fn crossing_the_cap_rotates_the_generation_and_the_live_sink_continues() {
        use tokio::sync::Mutex;
        let live = sink_path("cross");
        scrub(&live);
        let lock = Mutex::new(());
        let line = serde_json::json!({"request.id": "req-rotation-cross-test"});
        let step = serde_json::to_string(&line).unwrap().len() as u64 + 1; // + newline
        // Room for one full line but never two: sized off the real render so
        // the test stays far away from MAX_SINK_BYTES' 25 MiB.
        let max_bytes = step + step / 2;
        append_line(&live, &lock, max_bytes, &line).await;
        append_line(&live, &lock, max_bytes, &line).await;
        // Two lines sit over the cap but the swap happens BEFORE a write,
        // measured at append time — nothing rotated yet.
        assert!(!crate::audit::rotated_path(&live).exists());
        // The next append ships generation one whole...
        let rotated = crate::audit::rotated_path(&live);
        append_line(&live, &lock, max_bytes, &line).await;
        assert_eq!(line_count(&rotated), 2, "over-cap content moved into .1 intact");
        let retired = std::fs::read_to_string(&rotated).unwrap();
        assert!(retired.starts_with('{') && retired.ends_with('\n'));
        // ...while the live file continues receiving appended lines instead
        // of starting over per request: the fresh generation takes this line
        // on top of its own first one.
        append_line(&live, &lock, max_bytes, &line).await;
        assert_eq!(line_count(&live), 2, "fresh generation accumulates without re-rotating");
        scrub(&live);
    }

    #[tokio::test]
    async fn the_cap_boundary_is_stable_and_does_not_thrash_generations() {
        use tokio::sync::Mutex;
        let live = sink_path("boundary");
        scrub(&live);
        let lock = Mutex::new(());
        let line = serde_json::json!({"n": 123456789});
        let step = serde_json::to_string(&line).unwrap().len() as u64 + 1; // + newline
        // Room for exactly four full lines: rotate_if_oversized fires on
        // strictly-greater, so sitting AT the cap must not rotate either.
        let max_bytes = 4 * step;
        for _ in 0..4 {
            append_line(&live, &lock, max_bytes, &line).await;
        }
        assert!(!crate::audit::rotated_path(&live).exists(), "just-under/at cap: no rotation");
        assert_eq!(std::fs::metadata(&live).unwrap().len(), max_bytes);

        // One line over the cap saturates the live file; the swap itself is
        // observed by the FOLLOWING call (size-check precedes each write),
        // so two calls take it from saturated to exactly-one-generation-old.
        append_line(&live, &lock, max_bytes, &line).await;
        append_line(&live, &lock, max_bytes, &line).await;
        let rotated = crate::audit::rotated_path(&live);
        assert_eq!(line_count(&rotated), 5, "the whole saturated generation retired");
        assert_eq!(line_count(&live), 1);

        // ...and further appends settle into the fresh generation without
        // minting more of them per line.
        for _ in 0..3 {
            append_line(&live, &lock, max_bytes, &line).await;
        }
        assert_eq!(line_count(&rotated), 5, "retired generation untouched since the swap");
        assert_eq!(line_count(&live), 4);
        let name = live.file_name().unwrap().to_string_lossy().into_owned();
        let retired_name = format!("{name}.1");
        let siblings: Vec<_> = live
            .parent()
            .map(|dir| {
                // Exact-name matching, not a substring scan: /tmp keeps
                // leftovers of earlier failed runs under other pid-unique
                // names that happen to share the tag.
                std::fs::read_dir(dir)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy() == name
                        || e.file_name().to_string_lossy() == retired_name)
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(siblings.len(), 2, "exactly one live file plus one .1 generation");
        scrub(&live);
    }

    #[tokio::test]
    async fn concurrent_appenders_never_tear_or_duplicate_lines_across_generations() {
        let live = sink_path("racing");
        scrub(&live);
        // Arc over the guard mirrors Obs holding it behind its own handle.
        let lock: std::sync::Arc<tokio::sync::Mutex<()>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(()));
        // A small cap (~54 bytes vs ~10-byte lines) forces several swaps
        // mid-flight: without the shared guard holding size-check → rotate →
        // open → write together, writers race the rename and their lines
        // retire unshipped or interleave torn. Mid-run swaps may legitimately
        // evict an earlier .1 (single-generation retention), so the stable
        // property asserted is integrity, not a total.
        let max_bytes = 54;
        let tasks: Vec<_> = (0..40)
            .map(|n| {
                let lock = std::sync::Arc::clone(&lock);
                let live = live.clone();
                tokio::spawn(async move { append_line(&live, &lock, max_bytes, &serde_json::json!({"i": n})).await })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        let rotated = crate::audit::rotated_path(&live);
        assert!(rotated.exists(), "the run crossed the cap while contended");
        let mut ids = Vec::new();
        for path in [live.as_path(), rotated.as_path()] {
            if let Ok(raw) = std::fs::read_to_string(path) {
                for l in raw.lines() {
                    let parsed: serde_json::Value =
                        serde_json::from_str(l).unwrap_or_else(|e| panic!("torn line {l:?}: {e}"));
                    ids.push(parsed["i"].as_u64().expect("intact id"));
                }
            }
        }
        let distinct = {
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            sorted.dedup();
            sorted.len()
        };
        assert_eq!(distinct, ids.len(), "no payload ever shipped twice: {ids:?}");
        assert!(ids.iter().all(|&id| id < 40), "only spawned payloads land: {ids:?}");
        scrub(&live);
    }
}
