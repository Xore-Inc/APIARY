//! ip-enrichment-worker (#1610, discovered beyond #1610's originally-named
//! inventory while surveying the codebase): moves the portbridge via_port
//! -> real attacker IP join from dashboard read-time to ingest time. Unlike
//! every other worker ported under #1610, this one never touches
//! Elasticsearch at all — it tails each affected sensor's raw JSON log
//! file, rewrites any line whose src_ip is still the WireGuard tunnel peer
//! address to the real attacker IP (joined against portbridge's own
//! connection log by source port), and promotes a set of cross-sensor
//! "canonical_*" fields. The rewritten stream is written to its own file
//! under OUT_DIR, which Filebeat tails *instead of* the raw file for these
//! sensors — this module doesn't touch Filebeat's own config, it only has
//! to keep producing the same enriched-file format at the same path.
//!
//! Runs in its own compose service (`backend-worker-enrichment`,
//! `network_mode: none`) rather than on the ES-reaching `backend-worker` —
//! see compose.yml's own comment on that service for why.

mod attck;
mod canonical;
mod pending;
mod rotate;
pub(crate) mod sensors;
mod tail;
mod tftp;
mod viamap;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use pending::{EnrichFn, PendingQueue};
use rotate::OutputWriter;
use sensors::{
    enrich_beelzebub_line, enrich_dionaea_incident_line, enrich_galah_line, enrich_hellpot_line, enrich_line,
    enrich_sentrypeer_line,
};
use viamap::{ViaMap, ViaMapBuilder};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn env_duration(name: &str, default: Duration) -> Duration {
    let raw = env_or(name, "");
    if raw.is_empty() {
        return default;
    }
    parse_go_duration(&raw).unwrap_or(default)
}

/// Parses a Go-style "2s"/"5m"/"1h" duration string (the only shapes this
/// worker's own env vars ever use).
fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (digits, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = digits.parse().ok()?;
    match unit {
        "s" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_secs(n * 60)),
        "h" => Some(Duration::from_secs(n * 3600)),
        _ => None,
    }
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Debug (#1206) per-source resolution counters, logged periodically and
/// reset each interval — a snapshot of "what happened in the last N
/// seconds", the signal a live miss-rate regression would show up in.
#[derive(Default)]
struct SourceStats {
    attempted: AtomicI64,
    resolved_first: AtomicI64,
    resolved_retry: AtomicI64,
    timed_out: AtomicI64,
    /// #2181: lines whose enricher panicked — skipped rather than allowed
    /// to kill run_source's task and strand the tail offset.
    poisoned: AtomicI64,
    /// #3573: final join outcomes of the lines written, read off the
    /// `tunnel_attribution` each enricher stamps. Unlike the counters above
    /// these do not depend on which field a sensor puts its peer in.
    attributed: AtomicI64,
    ambiguous: AtomicI64,
    unmatched: AtomicI64,
}

/// #3573: counts what the written lines say about their tunnel join.
fn count_outcomes(stats: &SourceStats, written: &[Vec<u8>]) {
    for out in written {
        let text = String::from_utf8_lossy(out);
        if text.contains("\"tunnel_attribution\":\"portbridge\"") {
            stats.attributed.fetch_add(1, Ordering::Relaxed);
        } else if text.contains("\"tunnel_attribution\":\"ambiguous\"") {
            stats.ambiguous.fetch_add(1, Ordering::Relaxed);
        } else if text.contains("\"tunnel_attribution\":\"unmatched\"") {
            stats.unmatched.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Source {
    name: String,
    input: PathBuf,
    output: PathBuf,
    state_path: PathBuf,
    enrich: EnrichFn,
    stats: Arc<SourceStats>,
}

/// Finds every input file this worker is responsible for — mirrors
/// discoverSources exactly, including conpot's glob-by-persona-subdirectory
/// discovery.
fn discover_sources(logs_dir: &Path, out_dir: &Path, state_dir: &Path) -> Vec<Source> {
    let mut sources = Vec::new();
    let mut add = |name: &str, input: PathBuf, enrich: EnrichFn| {
        sources.push(Source {
            name: name.to_string(),
            input,
            output: out_dir.join(format!("{name}.json")),
            state_path: state_dir.join(format!("{name}.offset")),
            enrich,
            stats: Arc::new(SourceStats::default()),
        });
    };

    add("cowrie", logs_dir.join("cowrie").join("cowrie.json"), enrich_line);
    add("dionaea", logs_dir.join("dionaea").join("dionaea.json"), enrich_line);
    add("dns-honeypot", logs_dir.join("dns-honeypot").join("dns-honeypot.json"), enrich_line);
    add("cisco-asa-honeypot", logs_dir.join("cisco-asa-honeypot").join("cisco-asa-honeypot.json"), enrich_line);
    // #623: no top-level src_ip at all — needs its own enrich function.
    add("dionaea-incident", logs_dir.join("dionaea").join("dionaea_incident.json"), enrich_dionaea_incident_line);
    add("beelzebub", logs_dir.join("beelzebub").join("beelzebub.json"), enrich_beelzebub_line);
    add("hellpot", logs_dir.join("hellpot").join("HellPot.log"), enrich_hellpot_line);
    // elasticpot's native log shape already matches enrichLine's exactly
    // (flat top-level src_ip/src_port, stable "sensor" literal via its own
    // config) — no bespoke enrich function, no canonical.go promotion case
    // either (it captures no credentials).
    add("elasticpot", logs_dir.join("elasticpot").join("elasticpot.json"), enrich_line);
    add("galah", logs_dir.join("galah").join("event_log.json"), enrich_galah_line);
    add("sentrypeer", logs_dir.join("sentrypeer").join("sentrypeer.json"), enrich_sentrypeer_line);
    // wordpot's own source left with its retirement (#2381): its stack,
    // filebeat config and Traefik bridge no longer produce a wordpot.log.
    // mailoney's own log shape already matches enrichLine's exactly.
    add("mailoney", logs_dir.join("mailoney").join("mailoney.json"), enrich_line);

    // #1217: field-normalization-only sources — already carry the real
    // attacker IP via PROXY protocol, watched solely so canonical.go's
    // per-sensor promotion runs on their lines too.
    add("multipot", logs_dir.join("multipot").join("multipot.json"), enrich_line);
    add("tanner", logs_dir.join("tanner").join("tanner_report.json"), enrich_line);
    add("http-honeypot", logs_dir.join("http-honeypot").join("http.json"), enrich_line);
    add("citrix-honeypot", logs_dir.join("citrix-honeypot").join("citrix-honeypot.json"), enrich_line);
    add("rdp-honeypot", logs_dir.join("rdp-honeypot").join("rdp-honeypot.json"), enrich_line);
    add("sonicwall-sma-honeypot", logs_dir.join("sonicwall-sma-honeypot").join("sonicwall-sma-honeypot.json"), enrich_line);

    if let Ok(entries) = std::fs::read_dir(logs_dir) {
        let mut personas: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| {
                (name == "conpot" || name.starts_with("conpot-"))
                    && logs_dir.join(name).join("conpot.json").is_file()
            })
            .collect();
        personas.sort(); // deterministic discovery order
        for persona in personas {
            let input = logs_dir.join(&persona).join("conpot.json");
            add(&persona, input, enrich_line);
        }
    }

    sources
}

async fn run_source(
    mut source: Source,
    vm: Arc<RwLock<ViaMap>>,
    tftp_vm: Arc<RwLock<ViaMap>>,
    refresh: Duration,
    pending_timeout: Duration,
) {
    let mut writer = match OutputWriter::open(source.output.clone(), env_i64("OUTPUT_MAX_BYTES", 67_108_864) as u64) {
        Ok(w) => w,
        Err(error) => {
            tracing::warn!(source = %source.name, path = %source.output.display(), %error, "ip-enrichment: open output failed");
            return;
        }
    };

    let mut offset = tail::load_offset(&source.state_path).unwrap_or(0);
    let mut queue = PendingQueue::default();
    let mut ticker = tokio::time::interval(refresh);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let snapshot_vm = vm.read().await.clone();
        let snapshot_tftp = tftp_vm.read().await.clone();
        // #2181 backstop: the per-line boundary above is where poison is
        // expected (attacker bytes), but the tick itself stays synchronous,
        // so one std boundary keeps any other surprise from ending this
        // source's task. Holding the old offset on panic means the file
        // resummons cleanly from its last durable position next tick.
        let tick = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_source_tick(
                &mut source,
                &mut writer,
                &mut queue,
                &snapshot_vm,
                &snapshot_tftp,
                pending_timeout,
                offset,
            )
        }));
        match tick {
            Ok(new_offset) => offset = new_offset,
            Err(payload) => {
                tracing::warn!(
                    source = %source.name,
                    detail = %crate::isolate::panic_detail(payload),
                    "ip-enrichment: source tick panicked; nothing advanced -- retried next tick (#2181)"
                );
            }
        }
    }
}

/// One read/enrich/write cycle. Returns the offset to use next tick:
/// the new offset on success, or the offset passed in, unchanged, on
/// either a write or an offset-persist failure — so the same input range
/// is retried next tick instead of being silently skipped or re-written.
#[allow(clippy::too_many_arguments)]
fn process_source_tick(
    source: &mut Source,
    writer: &mut OutputWriter,
    queue: &mut PendingQueue,
    vm: &ViaMap,
    tftp_vm: &ViaMap,
    pending_timeout: Duration,
    offset: i64,
) -> i64 {
    let (lines, new_offset) = match tail::read_new_lines(&source.input, offset) {
        Ok(v) => v,
        Err(_) => return offset, // sensor container restarting, file briefly absent, etc. — retry next tick
    };

    let now = Instant::now();
    // #1876: two shapes, because sensors disagree about where they put the
    // peer. Most write src_ip; hellpot writes only REMOTE_ADDR ("ip:port")
    // and gets src_ip added *by* the enrichment, so a marker that only
    // looks for src_ip never matches a hellpot input line -- and hellpot
    // reported no join statistics at all while it was in fact resolving
    // every line. A metric that stays silent looks exactly like a metric
    // with nothing to report.
    let tunnel_peer_marker = format!("\"src_ip\":\"{}\"", crate::fleet::tunnel_peer_ip());
    let tunnel_peer_addr_marker = format!("\"REMOTE_ADDR\":\"{}:", crate::fleet::tunnel_peer_ip());
    let mut ready = Vec::new();
    // Byte position of the line being processed, for poison attribution:
    // lines were read from `offset`, so numbering within the batch pins the
    // poisoned record without a second pass to re-derive exact offsets.
    let mut line_no = 0usize;
    for line in lines {
        line_no += 1;
        let raw = String::from_utf8_lossy(&line);
        let is_tunnel_peer =
            raw.contains(&tunnel_peer_marker) || raw.contains(&tunnel_peer_addr_marker); // #1206 debug stat only
        // #2181: enrichers work on attacker-shaped bytes. A panicked line
        // used to unwind run_source's task AND strand this file — the offset
        // only advances after a successful write, so every restart tick hit
        // the same record again, forever. Isolation gives the poisoned line
        // this pipeline's native ack/skip semantics: no output row is
        // produced for it, but the offset still advances past it because the
        // healthy lines still write. Preview truncated hard; content is
        // attacker-controlled.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (source.enrich)(&line, vm, tftp_vm, &source.name)
        }));
        let (enriched, resolved) = match outcome {
            Ok(pair) => pair,
            Err(payload) => {
                source.stats.poisoned.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    source = %source.name,
                    line_no,
                    preview = %String::from_utf8_lossy(&line[..line.len().min(120)]),
                    detail = %crate::isolate::panic_detail(payload),
                    "ip-enrichment: line panicked its enricher; skipped, offset advances past it (#2181)"
                );
                continue;
            }
        };
        if resolved {
            if is_tunnel_peer {
                source.stats.resolved_first.fetch_add(1, Ordering::Relaxed);
            }
            ready.push(enriched);
        } else {
            source.stats.attempted.fetch_add(1, Ordering::Relaxed);
            queue.add(line, pending_timeout, now);
        }
    }
    let drained = queue.drain(vm, tftp_vm, now, &source.name, source.enrich);
    for out in &drained {
        if String::from_utf8_lossy(out).contains(&tunnel_peer_marker) {
            source.stats.timed_out.fetch_add(1, Ordering::Relaxed);
        } else {
            source.stats.resolved_retry.fetch_add(1, Ordering::Relaxed);
        }
    }
    ready.extend(drained);
    count_outcomes(&source.stats, &ready);

    if !writer.write_lines(&ready) {
        return offset; // don't advance/persist the offset over a batch that failed to write
    }
    if new_offset == offset {
        return offset;
    }
    if let Err(error) = tail::save_offset(&source.state_path, new_offset) {
        tracing::warn!(source = %source.name, %error, "ip-enrichment: save offset failed");
        return offset;
    }
    new_offset
}

async fn log_stats(sources: &[Arc<SourceStats>], names: &[String], interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        for (stats, name) in sources.iter().zip(names) {
            let attempted = stats.attempted.swap(0, Ordering::Relaxed);
            let first = stats.resolved_first.swap(0, Ordering::Relaxed);
            let retry = stats.resolved_retry.swap(0, Ordering::Relaxed);
            let timed_out = stats.timed_out.swap(0, Ordering::Relaxed);
            let poisoned = stats.poisoned.swap(0, Ordering::Relaxed);
            let attributed = stats.attributed.swap(0, Ordering::Relaxed);
            let ambiguous = stats.ambiguous.swap(0, Ordering::Relaxed);
            let unmatched = stats.unmatched.swap(0, Ordering::Relaxed);
            if attempted == 0 && first == 0 && poisoned == 0 && attributed + ambiguous + unmatched == 0 {
                continue; // nothing seen for this source this interval
            }
            tracing::info!(
                source = %name,
                attempted,
                resolved_first = first,
                resolved_retry = retry,
                timed_out,
                poisoned,
                attributed,
                ambiguous,
                unmatched,
                portbridge_readable = viamap::portbridge_readable(),
                "ip-enrichment: tunnel-peer join stats"
            );
        }
    }
}

pub async fn ip_enrichment_loop(_state: crate::AppState) {
    let logs_dir = PathBuf::from(env_or("LOGS_DIR", "/logs"));
    let out_dir = PathBuf::from(env_or("OUT_DIR", "/logs/enriched"));
    let state_dir = PathBuf::from(env_or("STATE_DIR", "/state/ip-enrichment-worker"));
    let refresh = env_duration("REFRESH_INTERVAL", Duration::from_secs(2));
    let pending_timeout = env_duration("PENDING_TIMEOUT", Duration::from_secs(5));

    if let Err(error) = std::fs::create_dir_all(&out_dir) {
        tracing::error!(path = %out_dir.display(), %error, "ip-enrichment: create OUT_DIR failed");
        return;
    }
    if let Err(error) = std::fs::create_dir_all(&state_dir) {
        tracing::error!(path = %state_dir.display(), %error, "ip-enrichment: create STATE_DIR failed");
        return;
    }

    let sources = discover_sources(&logs_dir, &out_dir, &state_dir);
    if sources.is_empty() {
        tracing::error!(path = %logs_dir.display(), "ip-enrichment: no input sources found under LOGS_DIR");
        return;
    }
    for source in &sources {
        tracing::info!(source = %source.name, input = %source.input.display(), output = %source.output.display(), "ip-enrichment: watching");
        // First run for this source: start at EOF rather than walking its
        // full history — an operator restarting this worker doesn't want
        // years of already-shipped raw log re-enriched and re-appended.
        if tail::load_offset(&source.state_path).is_none() {
            if let Ok(meta) = std::fs::metadata(&source.input) {
                let _ = tail::save_offset(&source.state_path, meta.len() as i64);
            }
        }
    }

    let portbridge_dir = logs_dir.join("portbridge");
    let mut via_builder = ViaMapBuilder::new(portbridge_dir);
    let vm = Arc::new(RwLock::new(via_builder.refresh()));
    let tftp_vm = Arc::new(RwLock::new(tftp::build_tftp_session_map(&logs_dir)));

    {
        let vm = vm.clone();
        let tftp_vm = tftp_vm.clone();
        let logs_dir = logs_dir.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh);
            loop {
                ticker.tick().await;
                let refreshed = via_builder.refresh();
                *vm.write().await = refreshed;
                let refreshed_tftp = tftp::build_tftp_session_map(&logs_dir);
                *tftp_vm.write().await = refreshed_tftp;
            }
        });
    }

    let stats: Vec<Arc<SourceStats>> = sources.iter().map(|s| s.stats.clone()).collect();
    let names: Vec<String> = sources.iter().map(|s| s.name.clone()).collect();
    tokio::spawn(async move { log_stats(&stats, &names, Duration::from_secs(30)).await });

    let mut handles = Vec::new();
    for source in sources {
        let vm = vm.clone();
        let tftp_vm = tftp_vm.clone();
        handles.push(tokio::spawn(async move { run_source(source, vm, tftp_vm, refresh, pending_timeout).await }));
    }
    // Runs forever; process supervision (docker restart policy) handles
    // crashes, same posture as the original.
    futures::future::join_all(handles).await;
}


#[cfg(test)]
mod tests {
    // Ported from the Go worker's main_test.go before that tree was retired
    // (#1890). mod.rs had no tests at all, and discovery is the one place
    // where being wrong is silent: a source pointed at a filename that does
    // not exist simply never produces events, and looks identical to a
    // sensor with no traffic.
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ip-enrich-discover-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovery_finds_every_conpot_persona_and_each_sensors_real_filename() {
        let logs = temp_dir("logs");
        for (dir, file) in [
            ("cowrie", "cowrie.json"),
            ("dionaea", "dionaea.json"),
            ("dns-honeypot", "dns-honeypot.json"),
            ("cisco-asa-honeypot", "cisco-asa-honeypot.json"),
            ("conpot", "conpot.json"),
            ("conpot-s7-1200", "conpot.json"),
            ("conpot-kamstrup", "conpot.json"),
        ] {
            std::fs::create_dir_all(logs.join(dir)).unwrap();
            std::fs::write(logs.join(dir).join(file), b"").unwrap();
        }

        let sources = discover_sources(&logs, &temp_dir("out"), &temp_dir("state"));
        let by_name: std::collections::HashMap<&str, &Source> =
            sources.iter().map(|s| (s.name.as_str(), s)).collect();

        for want in [
            "cowrie", "dionaea", "dionaea-incident", "dns-honeypot", "cisco-asa-honeypot",
            "conpot", "conpot-s7-1200", "conpot-kamstrup",
            "multipot", "tanner", "http-honeypot", "citrix-honeypot", "rdp-honeypot",
            "sonicwall-sma-honeypot",
            "beelzebub", "hellpot", "elasticpot", "galah", "sentrypeer", "mailoney",
        ] {
            assert!(by_name.contains_key(want), "no source named {want:?}");
        }
        assert_eq!(sources.len(), 20, "no duplicates across conpot personas");

        // Each conpot persona reads its own subdirectory, all under the
        // same literal filename.
        assert_eq!(
            by_name["conpot-s7-1200"].input,
            logs.join("conpot-s7-1200").join("conpot.json"),
        );

        // Several sensors' log files are not named after the sensor, and
        // getting one wrong costs that sensor's entire event stream with
        // no error anywhere.
        for (name, dir, file) in [
            ("multipot", "multipot", "multipot.json"),
            ("tanner", "tanner", "tanner_report.json"),
            ("http-honeypot", "http-honeypot", "http.json"),
            ("citrix-honeypot", "citrix-honeypot", "citrix-honeypot.json"),
            ("rdp-honeypot", "rdp-honeypot", "rdp-honeypot.json"),
            ("sonicwall-sma-honeypot", "sonicwall-sma-honeypot", "sonicwall-sma-honeypot.json"),
            ("hellpot", "hellpot", "HellPot.log"),
            ("galah", "galah", "event_log.json"),
        ] {
            assert_eq!(by_name[name].input, logs.join(dir).join(file), "{name} input path");
        }
    }

    #[test]
    fn a_lookalike_directory_name_is_not_mistaken_for_a_conpot_persona() {
        let logs = temp_dir("lookalike-logs");
        for dir in ["conpotato", "conpot_legacy"] {
            std::fs::create_dir_all(logs.join(dir)).unwrap();
            std::fs::write(logs.join(dir).join("conpot.json"), b"").unwrap();
        }

        let sources = discover_sources(&logs, &temp_dir("lookalike-out"), &temp_dir("lookalike-state"));

        assert!(
            !sources.iter().any(|s| s.name.starts_with("conpot")),
            "directory-name prefix match must not pick up non-persona lookalikes"
        );
    }

    #[test]
    fn a_logs_directory_with_no_conpot_personas_still_discovers_the_rest() {
        let logs = temp_dir("empty-logs");
        let sources = discover_sources(&logs, &temp_dir("empty-out"), &temp_dir("empty-state"));

        // Discovery does not require the files to exist -- only conpot is
        // glob-driven -- so the fixed list is always present.
        assert_eq!(sources.len(), 17);
        assert!(!sources.iter().any(|s| s.name.starts_with("conpot")));
    }

    /// Always "resolves", unchanged -- enough to drive the tick's
    /// read/write/offset bookkeeping without depending on the join.
    fn passthrough(line: &[u8], _vm: &ViaMap, _tftp: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
        (line.to_vec(), true)
    }

    fn test_source(input: PathBuf, output: PathBuf, state_path: PathBuf) -> Source {
        Source {
            name: "test".into(),
            input,
            output,
            state_path,
            enrich: passthrough,
            stats: Arc::new(SourceStats::default()),
        }
    }

    // ---- #1351: the offset must never run ahead of what was durably
    // ---- written. Both failure branches below produced the same visible
    // ---- symptom in production -- lines that were read once and never
    // ---- emitted -- so the control case is here too, to prove the
    // ---- failure tests are exercising the failure branch and not a
    // ---- no-op path.

    #[test]
    fn a_successful_tick_advances_and_persists_the_offset() {
        let dir = temp_dir("tick-ok");
        let input = dir.join("in.json");
        let line = b"{\"a\":1}\n";
        std::fs::write(&input, line).unwrap();

        let mut source = test_source(input, dir.join("out.json"), dir.join("test.offset"));
        let mut writer = OutputWriter::open(source.output.clone(), 0).unwrap();
        let mut queue = PendingQueue::default();

        let got = process_source_tick(
            &mut source, &mut writer, &mut queue,
            &ViaMap::new(), &ViaMap::new(), Duration::from_secs(1), 0,
        );

        assert_eq!(got, line.len() as i64);
        assert_eq!(tail::load_offset(&source.state_path), Some(got), "and it is on disk");
    }

    #[test]
    fn a_failed_write_leaves_the_offset_where_it_was() {
        // /dev/full accepts the open and fails every write with ENOSPC,
        // which is exactly the shape of the disk-full case that lost data.
        let dir = temp_dir("tick-write-fail");
        let input = dir.join("in.json");
        std::fs::write(&input, b"{\"a\":1}\n").unwrap();

        let mut source = test_source(input, dir.join("out.json"), dir.join("test.offset"));
        let mut writer = OutputWriter::open(PathBuf::from("/dev/full"), 0).unwrap();
        let mut queue = PendingQueue::default();

        let got = process_source_tick(
            &mut source, &mut writer, &mut queue,
            &ViaMap::new(), &ViaMap::new(), Duration::from_secs(1), 0,
        );

        assert_eq!(got, 0, "unchanged, so the batch is read again next tick");
        assert_eq!(tail::load_offset(&source.state_path), None, "and nothing was persisted");
    }

    #[test]
    fn a_failed_offset_save_leaves_the_returned_offset_where_it_was() {
        // The subtler half. If the in-memory offset advanced while the
        // save failed, the next restart would read the persisted (older)
        // offset and re-emit everything in between -- the same lines
        // enriched and appended twice, forever.
        let dir = temp_dir("tick-save-fail");
        let input = dir.join("in.json");
        std::fs::write(&input, b"{\"a\":1}\n").unwrap();

        let mut source = test_source(
            input,
            dir.join("out.json"),
            dir.join("does-not-exist").join("test.offset"),
        );
        let mut writer = OutputWriter::open(source.output.clone(), 0).unwrap();
        let mut queue = PendingQueue::default();

        let got = process_source_tick(
            &mut source, &mut writer, &mut queue,
            &ViaMap::new(), &ViaMap::new(), Duration::from_secs(1), 0,
        );

        assert_eq!(got, 0, "the write succeeded but the offset did not stick");
    }

    // ---- #2181: a panicked enricher is a skip, not a death. The offset's
    // ---- ack/skip contract stays intact — the poisoned line produces no
    // ---- output but is still consumed — and the task keeps tailing.

    /// panics on any line carrying POISON, otherwise behaves exactly like
    /// the happy passthrough: resolved, unchanged.
    fn poison_on_marker(line: &[u8], vm: &ViaMap, tftp_vm: &ViaMap, persona: &str) -> (Vec<u8>, bool) {
        if line.windows(6).any(|w| w == b"POISON") {
            panic!("synthetic poisoned capture");
        }
        passthrough(line, vm, tftp_vm, persona)
    }

    fn poison_test_source(input: PathBuf, output: PathBuf, state_path: PathBuf) -> Source {
        Source {
            enrich: poison_on_marker,
            ..test_source(input, output, state_path)
        }
    }

    #[test]
    fn a_panicking_line_is_skipped_but_still_acked_by_the_offset() {
        let dir = temp_dir("tick-poison-line");
        let input = dir.join("in.json");
        std::fs::write(&input, b"{\"a\":1}\n{\"bad\":\"POISON\"}\n{\"a\":2}\n").unwrap();

        let mut source = poison_test_source(input.clone(), dir.join("out.json"), dir.join("test.offset"));
        let mut writer = OutputWriter::open(source.output.clone(), 0).unwrap();
        let mut queue = PendingQueue::default();

        let got = process_source_tick(
            &mut source, &mut writer, &mut queue,
            &ViaMap::new(), &ViaMap::new(), Duration::from_secs(1), 0,
        );

        let file_len = std::fs::metadata(&input).unwrap().len() as i64;
        assert_eq!(
            got, file_len,
            "the poisoned middle line is skipped for OUTPUT but still consumed by the offset"
        );
        assert_eq!(source.stats.poisoned.load(Ordering::Relaxed), 1, "and counted for diagnostics");

        let shipped = std::fs::read_to_string(dir.join("out.json")).unwrap();
        assert!(shipped.contains("{\"a\":1}"), "healthy sibling one shipped");
        assert!(shipped.contains("{\"a\":2}"), "healthy sibling two shipped");
        assert!(!shipped.contains("POISON"), "no output row exists for the poisoned line");
    }

    #[test]
    fn the_tail_continues_after_a_poisoned_line_on_the_next_tick() {
        let dir = temp_dir("tick-poison-continues");
        let input = dir.join("in.json");
        std::fs::write(&input, b"{\"bad\":\"POISON\"}\n").unwrap();

        let mut source = poison_test_source(input.clone(), dir.join("out.json"), dir.join("test.offset"));
        let mut writer = OutputWriter::open(source.output.clone(), 0).unwrap();
        let mut queue = PendingQueue::default();

        let got = process_source_tick(
            &mut source, &mut writer, &mut queue,
            &ViaMap::new(), &ViaMap::new(), Duration::from_secs(1), 0,
        );
        assert_eq!(
            got,
            std::fs::metadata(&input).unwrap().len() as i64,
            "first tick survives and acks past the poison"
        );

        use std::io::Write as _;
        let mut append = std::fs::OpenOptions::new().append(true).open(&input).unwrap();
        writeln!(append, "{{\"later\":\"good\"}}").unwrap();
        append.flush().unwrap();

        let got2 = process_source_tick(
            &mut source, &mut writer, &mut queue,
            &ViaMap::new(), &ViaMap::new(), Duration::from_secs(1), got,
        );
        assert_eq!(got2, std::fs::metadata(&input).unwrap().len() as i64);
        let shipped = std::fs::read_to_string(dir.join("out.json")).unwrap();
        assert!(
            shipped.contains("{\"later\":\"good\"}"),
            "the loop processes later lines after the poisoned one"
        );
    }

    #[test]
    fn an_offset_survives_a_save_and_load_round_trip() {
        let dir = temp_dir("offset-roundtrip");
        let path = dir.join("test.offset");
        assert_eq!(tail::load_offset(&path), None, "nothing yet");

        tail::save_offset(&path, 4096).unwrap();
        assert_eq!(tail::load_offset(&path), Some(4096));
    }
}
