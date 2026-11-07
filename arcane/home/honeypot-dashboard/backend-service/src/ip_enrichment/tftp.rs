//! Ported from ip-enrichment-worker/tftpsessions.go: dionaea's TFTP events
//! reach it over a plain UDP forward (tftp-relay, #747), never the
//! WireGuard/portbridge tunnel every other affected sensor goes through —
//! so they need a different trigger than the tunnel-peer check, and a
//! different port-to-real-IP map, joined against tftp-relay's own session
//! log instead of portbridge's.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use super::viamap::ViaMap;

/// The live sink tftp-relay appends to.
const LIVE: &str = "sessions.json";

/// Reads tftp-relay's own session log — a `{relay_port, client_ip}` line
/// per TFTP session — across the same two generations `ViaMapBuilder`
/// reads for portbridge: the most recent rotated segment first, then the
/// live file.
///
/// #2216 gave tftp-relay the fleet-standard self-rotator, so the premise
/// this loader used to rest on — "sessions.json never rotates, therefore
/// reading only the live file loses nothing" — is gone. Reading only
/// `sessions.json` after that change would silently drop every mapping in
/// the segment that had just been renamed aside: a TFTP session opened
/// before the rotation would stop resolving to its real client the moment
/// the file rolled, and a wrong-looking miss is indistinguishable from a
/// session that genuinely was not relayed. Reading the previous generation
/// too carries the map across the boundary.
///
/// Two deliberate differences from `ViaMapBuilder`, both because tftp-relay
/// is the low-volume end of this fleet:
///
/// - the previous generation is *found*, not hardcoded. portbridge's
///   builder joins a fixed `portbridge.json.1` — the copytruncate target
///   from before #1776 — while every rotating writer in the fleet, this one
///   included, now renames to `<name>.json.<YYYYMMDD-HHMMSS>` (plus a
///   `.2`/`.3` counter on a same-second collision, #1403). A fixed suffix
///   matches nothing under that scheme, so the newest segment is picked off
///   the directory listing by mtime instead — rename preserves mtime, so
///   generations order by it exactly as they were written.
/// - both files are still re-read whole every refresh tick rather than
///   tailed. The #1206 CPU incident that forced the incremental reader on
///   portbridge does not apply here: portbridge rotates a full 8MiB segment
///   several times a day (measured live), tftp-relay's session log has not
///   filled one 64MiB segment in the sensor's lifetime.
pub fn build_tftp_session_map(logs_dir: &Path) -> ViaMap {
    let dir = logs_dir.join("tftp-relay");
    let mut m = ViaMap::new();
    // Oldest generation first: `lookup` walks the history backwards, so a
    // relay port reused across a rotation must resolve to the newer
    // session, exactly as it does within one file.
    if let Some(previous) = previous_generation(&dir) {
        read_session_lines(&previous, &mut m);
    }
    read_session_lines(&dir.join(LIVE), &mut m);
    m
}

/// The most recently rotated `sessions.json.<stamp>` segment, if any.
///
/// Only one generation back: the retention pruner deletes older segments
/// anyway, and a relay port's useful life is the length of a TFTP session
/// — seconds — so anything older than the segment the rotation just closed
/// cannot explain an event still arriving.
fn previous_generation(dir: &Path) -> Option<PathBuf> {
    let prefix = format!("{LIVE}.");
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .filter_map(|entry| {
            let mtime = entry.metadata().ok()?.modified().ok()?;
            Some((mtime, entry.path()))
        })
        // Tie-break on the path so two segments sharing an mtime still pick
        // deterministically rather than by directory order.
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)))
        .map(|(_, path)| path)
}

/// Folds one session-log generation into `m`. A missing file is not an
/// error: the relay may not have run yet, and there is no previous
/// generation until the first rotation.
fn read_session_lines(path: &Path, m: &mut ViaMap) {
    let Ok(file) = File::open(path) else { return };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(e) = serde_json::from_str::<Value>(&line) else { continue };
        let Some(ip) = e.get("client_ip").and_then(Value::as_str).filter(|s| !s.is_empty()) else { continue };
        let Some(port) = e.get("relay_port").and_then(Value::as_f64).filter(|p| *p != 0.0) else { continue };
        // tftp-relay's sessions.json carries no timestamp, so these entries
        // opt out of #1771's causality check (at 0) and keep their previous
        // behaviour. Relay ports are handed out per
        // TFTP session from a small pool that turns over far more slowly
        // than portbridge's ephemeral range, so the reuse this guards
        // against is not a live concern here.
        m.entry(port as i64).or_default().push(super::viamap::ViaEntry {
            ip: ip.to_string(),
            at: 0,
            // tftp-relay's sessions.json records no destination port, and
            // this map is only ever consulted for dionaea's TFTP records,
            // so there is nothing to disambiguate against. 0 opts out of
            // #1917's destination-port check rather than failing it.
            target_port: 0,
            transport: super::viamap::Transport::Udp,
        });
    }
}

/// Reports whether `e` is one of dionaea's TFTP connection events, relayed
/// through tftp-relay — these carry the relay container's own internal
/// address as src_ip, never the tunnel peer IP.
pub fn is_tftp_relay_record(e: &Value, persona: &str) -> bool {
    if persona != "dionaea" {
        return false;
    }
    e.get("connection")
        .and_then(|c| c.get("protocol"))
        .and_then(Value::as_str)
        == Some("TftpServerHandler")
}


#[cfg(test)]
mod tests {
    // Ported from the Go worker's tftpsessions_test.go before that tree was
    // retired (#1890). This module had no tests at all on the Rust side,
    // which mattered more here than the count suggests: TFTP is the one
    // sensor path that does not go through portbridge, so nothing else
    // would have caught this map silently coming back empty.
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Same throwaway-directory pattern tail.rs and rotate.rs already use,
    // plus a counter so tests in this module cannot collide with each
    // other when the harness runs them in parallel.
    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn temp_logs_dir() -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("ip-enrich-tftp-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn logs_with(lines: &[&str]) -> PathBuf {
        let dir = temp_logs_dir();
        write_generation(&dir, "sessions.json", lines, 0);
        dir
    }

    /// Writes one session-log generation, stamping its mtime `age_secs`
    /// before now so generation order is exact rather than dependent on
    /// the filesystem's timestamp resolution. tftp-relay rotates by
    /// rename, which carries the segment's own mtime across, so this is
    /// what the reader actually sees on disk.
    fn write_generation(logs_dir: &Path, name: &str, lines: &[&str], age_secs: u64) {
        let relay = logs_dir.join("tftp-relay");
        std::fs::create_dir_all(&relay).unwrap();
        let f = std::fs::File::create(relay.join(name)).unwrap();
        {
            let mut w = &f;
            for line in lines {
                writeln!(w, "{line}").unwrap();
            }
        }
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
        f.set_times(std::fs::FileTimes::new().set_accessed(when).set_modified(when)).unwrap();
    }

    #[test]
    fn sessions_are_indexed_by_relay_port() {
        let dir = logs_with(&[
            r#"{"relay_port":42285,"client_ip":"203.0.113.9","timestamp":"2026-08-05T21:05:27Z"}"#,
            r#"{"relay_port":42286,"client_ip":"203.0.113.10","timestamp":"2026-08-05T21:06:00Z"}"#,
        ]);
        let m = build_tftp_session_map(&dir);

        assert_eq!(super::super::viamap::lookup(&m, 42285, 0), Some("203.0.113.9"));
        assert_eq!(super::super::viamap::lookup(&m, 42286, 0), Some("203.0.113.10"));
    }

    #[test]
    fn a_reused_relay_port_resolves_to_the_later_session() {
        // These entries carry no timestamp, so the plausibility check
        // cannot separate them -- the only thing that can is order.
        let dir = logs_with(&[
            r#"{"relay_port":42285,"client_ip":"203.0.113.9"}"#,
            r#"{"relay_port":42285,"client_ip":"203.0.113.99"}"#,
        ]);
        let m = build_tftp_session_map(&dir);

        assert_eq!(super::super::viamap::lookup(&m, 42285, 0), Some("203.0.113.99"));
    }

    #[test]
    fn malformed_lines_are_skipped_rather_than_fatal() {
        // One bad line in a session log must not cost the whole map --
        // the relay writes this file live while the worker reads it.
        let dir = logs_with(&[
            "not json",
            r#"{"relay_port":42285}"#,
            r#"{"client_ip":"203.0.113.9"}"#,
            r#"{"relay_port":42286,"client_ip":"203.0.113.10"}"#,
        ]);
        let m = build_tftp_session_map(&dir);

        assert_eq!(m.len(), 1, "only the well-formed entry survives");
        assert_eq!(super::super::viamap::lookup(&m, 42286, 0), Some("203.0.113.10"));
    }

    // ---- #2216: the sink rotates now, so one file is no longer the map ----

    #[test]
    fn sessions_survive_the_rotation_that_aged_them_out() {
        // The regression this guards: #2216 gave tftp-relay the fleet's
        // self-rotator, and a loader that reads only the live file forgets
        // every mapping the rename carried aside -- silently, the same way
        // an un-relayed session looks.
        let dir = temp_logs_dir();
        write_generation(
            &dir,
            "sessions.json.20260901-120000",
            &[r#"{"relay_port":42285,"client_ip":"203.0.113.9"}"#],
            60,
        );
        write_generation(
            &dir,
            "sessions.json",
            &[r#"{"relay_port":42286,"client_ip":"203.0.113.10"}"#],
            0,
        );

        let m = build_tftp_session_map(&dir);
        assert_eq!(
            super::super::viamap::lookup(&m, 42285, 0),
            Some("203.0.113.9"),
            "the rotated-aside generation still resolves",
        );
        assert_eq!(super::super::viamap::lookup(&m, 42286, 0), Some("203.0.113.10"));
    }

    #[test]
    fn a_relay_port_reused_across_a_rotation_resolves_to_the_later_session() {
        // Same ordering contract as within one file
        // (a_reused_relay_port_resolves_to_the_later_session), now across
        // the generation boundary: the live file is read last, so its
        // entry is the one `lookup` finds first walking backwards.
        let dir = temp_logs_dir();
        write_generation(
            &dir,
            "sessions.json.20260901-120000",
            &[r#"{"relay_port":42285,"client_ip":"203.0.113.9"}"#],
            60,
        );
        write_generation(
            &dir,
            "sessions.json",
            &[r#"{"relay_port":42285,"client_ip":"203.0.113.99"}"#],
            0,
        );

        let m = build_tftp_session_map(&dir);
        assert_eq!(super::super::viamap::lookup(&m, 42285, 0), Some("203.0.113.99"));
    }

    #[test]
    fn the_newest_rotated_generation_is_the_one_read() {
        // Segments pile up until the pruner ages them out, and rename
        // preserves each one's own mtime -- so "previous generation" is
        // the newest of them, not whatever the directory listed first.
        let dir = temp_logs_dir();
        write_generation(
            &dir,
            "sessions.json.20260901-090000",
            &[r#"{"relay_port":40001,"client_ip":"203.0.113.1"}"#],
            7200,
        );
        write_generation(
            &dir,
            "sessions.json.20260901-120000",
            &[r#"{"relay_port":40002,"client_ip":"203.0.113.2"}"#],
            60,
        );
        write_generation(&dir, "sessions.json", &[], 0);

        let m = build_tftp_session_map(&dir);
        assert_eq!(super::super::viamap::lookup(&m, 40002, 0), Some("203.0.113.2"));
        assert_eq!(
            super::super::viamap::lookup(&m, 40001, 0),
            None,
            "older segments are the pruner's business, not the join's",
        );
    }

    #[test]
    fn a_rotated_generation_alone_still_builds_a_map() {
        // The window right after a rotation: the reopened live file is
        // empty and every mapping that matters is in the segment beside it.
        let dir = temp_logs_dir();
        write_generation(
            &dir,
            "sessions.json.20260901-120000",
            &[r#"{"relay_port":42285,"client_ip":"203.0.113.9"}"#],
            60,
        );
        write_generation(&dir, "sessions.json", &[], 0);

        let m = build_tftp_session_map(&dir);
        assert_eq!(super::super::viamap::lookup(&m, 42285, 0), Some("203.0.113.9"));
    }

    #[test]
    fn a_missing_session_log_is_an_empty_map_not_an_error() {
        // tftp-relay may simply not have run yet.
        let dir = temp_logs_dir();
        assert!(build_tftp_session_map(&dir).is_empty());
    }

    #[test]
    fn only_dionaeas_tftp_connections_use_the_relay_join() {
        let tftp = json!({"connection": {"protocol": "TftpServerHandler"}});
        assert!(is_tftp_relay_record(&tftp, "dionaea"));
        assert!(!is_tftp_relay_record(&tftp, "conpot"), "another persona's record");

        let smb = json!({"connection": {"protocol": "SMBDServer"}});
        assert!(!is_tftp_relay_record(&smb, "dionaea"), "a non-TFTP protocol");

        assert!(!is_tftp_relay_record(&json!({}), "dionaea"), "no connection object");
    }
}
