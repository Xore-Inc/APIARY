//! Ported from ip-enrichment-worker/viamap.go: indexes portbridge's own
//! connection log by via_port (the tunnel-side ephemeral port portbridge
//! dialed the honeypot from, which equals the src_port a non-PROXY-wrapped
//! sensor observes for that same connection) — the same join
//! dashboard/classify.go's buildViaMap/viaLookup does read-time, done here
//! at ingest time instead.
//!
//! #3573: `resolve` is the join every enricher uses for portbridge. It
//! answers with one of three outcomes (attributed / ambiguous / unmatched)
//! instead of a best guess, and it is mirrored rule-for-rule by
//! scripts/backfill-tunnel-attribution.py so live attribution and the
//! historical backfill can never disagree about what counts as a match.

use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use super::tail::read_new_lines;

/// Which transport a portbridge rule (or a sensor line) used.
///
/// TCP and UDP ephemeral ports are separate namespaces on the VPS: a TCP dial
/// and a UDP session can hold the same local port number at the same time,
/// so a sensor line that says which one it saw must not join against the
/// other. `Unknown` matches either and is what a line that does not say gets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    #[default]
    Unknown,
}

impl Transport {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            "udp" => Transport::Udp,
            _ => Transport::Unknown,
        }
    }

    fn compatible(self, other: Transport) -> bool {
        self == Transport::Unknown || other == Transport::Unknown || self == other
    }
}

/// One portbridge connection, as the join needs to see it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ViaEntry {
    /// The real client address portbridge accepted the connection from.
    pub ip: String,
    /// portbridge's dial time (epoch seconds), 0 when the line carried none.
    pub at: i64,
    /// The sensor port portbridge dialled, from its `target` ("host:port").
    /// 0 when the line carried none.
    ///
    /// #1917: this is what tells a stale entry from the right one. An
    /// ephemeral port is reused constantly -- via_port 54674 was dialled
    /// six times in two days across telnet, HTTP and mssql -- and the time
    /// window alone cannot separate them, because it has to stay wide
    /// enough for a cowrie session that writes lines for hours. The
    /// destination port can: a connection to mssql on 1433 did not come
    /// from a dial to telnet on 23, whatever the clock says.
    pub target_port: i64,
    /// #3573: portbridge's `proto` for the rule that carried the connection.
    pub transport: Transport,
}

/// via_port -> the recent connections that used it, oldest first, plus the
/// newest dial time read so far.
///
/// #1771: this was `via_port -> ip`, keeping only the newest connection per
/// port, and the join took whatever was there. Ephemeral ports are reused
/// within seconds under this traffic (measured: the same via_port dialled
/// 29 seconds apart), and sensors emit many lines per connection over its
/// whole lifetime, so a connection's later lines routinely resolved against
/// a *different attacker's* entry -- silently, since a wrong address looks
/// exactly like a right one. One conpot connection was split across two
/// unrelated IPs this way.
///
/// Keeping a short history per port lets the join pick the connection that
/// was actually open when the sensor line was written, instead of the most
/// recent one to touch the port.
///
/// #3573: `newest_at` is how far the map has read. A join is only final once
/// the map has read past the end of the line's window -- before that, a
/// second dial on the same port that would make the answer ambiguous may
/// simply not have been read yet.
#[derive(Clone, Debug, Default)]
pub struct ViaMap {
    ports: HashMap<i64, Vec<ViaEntry>>,
    newest_at: i64,
}

impl ViaMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// The newest portbridge dial time this map has read (epoch seconds).
    pub fn newest_at(&self) -> i64 {
        self.newest_at
    }
}

impl Deref for ViaMap {
    type Target = HashMap<i64, Vec<ViaEntry>>;
    fn deref(&self) -> &Self::Target {
        &self.ports
    }
}

impl DerefMut for ViaMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ports
    }
}

/// How many connections to remember per via_port. The key space is bounded
/// by the port number range, so this bounds the whole map. #3573 raised it
/// from four: `resolve` has to *see* a competing dial to call a join
/// ambiguous, and an evicted competitor would turn ambiguity back into a
/// confident answer. Measured peak reuse is about five dials per port per six
/// hours, so eight still covers the longest window `resolve` uses.
const HISTORY: usize = 8;

/// How far before a sensor line a portbridge entry may have been dialled and
/// still plausibly describe it. Generous on purpose: a cowrie session can
/// stay open for a long time and every line it writes has to keep resolving
/// against the connect that opened it. It exists to reject a *backlog
/// replay* -- lines processed hours late against a live map -- not to
/// second-guess long sessions.
const MAX_AGE_SECONDS: i64 = 6 * 3600;

/// Tolerance for a sensor clock running slightly ahead of portbridge's.
/// portbridge logs at dial time, strictly before the honeypot can see the
/// connection, so an entry stamped meaningfully *after* the line cannot be
/// that line's origin -- that is the check doing the real work here.
pub const CLOCK_SKEW_SECONDS: i64 = 2;

/// #3573: how long before a connection's first sensor line portbridge's dial
/// may be stamped.
///
/// Measured on 10,000 cowrie `session.connect` events against portbridge-v2
/// (2026-09-26): the sensor stamp minus the dial stamp was 0s for 27%, 1s
/// for 69% and 2s for 4% -- portbridge truncates to whole seconds and logs
/// just after the dial completes. Nothing legitimate fell outside 0..2s;
/// everything outside was background reuse of the port by unrelated
/// connections, at about one per second per 10,000 lookups. Four seconds
/// keeps a margin without widening the window into that background.
pub const DIAL_LEAD_SECONDS: i64 = 4;

/// #3573: how long a UDP session may run before a line of it is no longer
/// joined against its opening dial when the sensor gives no session
/// identifier to anchor on.
///
/// UDP is different from TCP here. portbridge binds one wildcard socket per
/// client session, so while a session is alive no other session can hold
/// its local port -- for any target -- and a session only ends after two
/// minutes of silence. The newest dial on the port before the line is
/// therefore the line's own session, however long it has been running. The
/// cap only bounds how much a gap in the log could ever cost.
pub const UDP_SESSION_MAX_AGE_SECONDS: i64 = 3600;

/// #3573: how far back a rival client is looked for when a TCP line does not
/// say which port portbridge dialled.
///
/// With the target known, a late line of a long connection is safe: while the
/// connection is open nothing else can dial that target from the same port,
/// so a rival in the window cannot exist. Without it, a line written minutes
/// into a connection can meet an unrelated dial to another service that
/// reused the port a second earlier, and the narrow window would name that
/// stranger. Requiring the port to have been quiet for ten minutes before the
/// line turns that case into AMBIGUOUS. Only sensors that log no listen port
/// pay for it (beelzebub, TCP sentrypeer).
pub const RIVAL_LOOKBACK_SECONDS: i64 = 600;

pub fn read_portbridge_lines(path: &Path, m: &mut ViaMap) {
    let Ok(file) = File::open(path) else { return };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        parse_portbridge_line(line.as_bytes(), m);
    }
}

pub fn parse_portbridge_line(line: &[u8], m: &mut ViaMap) {
    let Ok(e) = serde_json::from_slice::<Value>(line) else { return };
    if e.get("sensor").and_then(Value::as_str) != Some("portbridge") {
        return;
    }
    let Some(ip) = e.get("src_ip").and_then(Value::as_str).filter(|s| !s.is_empty()) else { return };
    let Some(via_port) = e.get("via_port").and_then(Value::as_f64).filter(|p| *p != 0.0) else { return };
    let entry = ViaEntry {
        ip: ip.to_string(),
        at: e.get("time").and_then(Value::as_str).and_then(parse_time).unwrap_or(0),
        target_port: e
            .get("target")
            .and_then(Value::as_str)
            .and_then(|t| t.rsplit_once(':'))
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(0),
        transport: e.get("proto").and_then(Value::as_str).map(Transport::parse).unwrap_or_default(),
    };
    if entry.at > m.newest_at {
        m.newest_at = entry.at;
    }
    let slot = m.entry(via_port as i64).or_default();
    // portbridge ships each connection once; the duplicate-shipping bug that
    // made every line arrive twice (#1776) would otherwise fill the history
    // with copies of one connection and push real ones out. #3573: checked
    // against the whole slot, not just its last entry, because re-reading a
    // freshly rotated segment replays lines the live tail already took.
    if slot.contains(&entry) {
        return;
    }
    slot.push(entry);
    if slot.len() > HISTORY {
        slot.remove(0);
    }
}

/// portbridge writes RFC3339 with a `Z` (see connLogger's record builder).
fn parse_time(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value).ok().map(|t| t.timestamp())
}

/// The address that was behind `via_port` when a sensor line timestamped
/// `line_at` (epoch seconds; 0 when the line carried no usable timestamp)
/// was written.
///
/// #3573: only the TFTP relay's session map still joins through this, since
/// its entries carry no timestamp at all. Every portbridge join goes through
/// `resolve`, which refuses to pick between candidates instead of taking the
/// newest one inside a six-hour window.
///
/// Returns None rather than a best guess: an unattributed event is honest,
/// a confidently wrong attacker is not.
///
/// Deliberately does *not* cross-check the destination port. It looks like an
/// obvious second discriminator and it cannot work here: one connection
/// carries three different port numbers through this topology. A telnet
/// session is `portbridge.port` 23 (what the attacker dialled), forwarded to
/// `portbridge.target` 10.8.0.2:19023 (what the host publishes), and logged
/// by cowrie as dst_port 2223 (what it binds inside its container). Comparing
/// any two of those rejects every port-shifted service -- measured live, it
/// left all 3,046 of cowrie's hourly events unattributed while resolving
/// nothing extra. Causality below is what actually separates two connections
/// that shared an ephemeral port.
pub fn lookup(m: &ViaMap, via_port: i64, line_at: i64) -> Option<&str> {
    lookup_to_port(m, via_port, line_at, 0)
}

/// The same join, told which sensor port the event arrived on.
///
/// #1917: `lookup` alone resolved a dionaea mssql connection on port 1433
/// to the client of a *telnet* dial 21 minutes earlier that happened to
/// reuse the same ephemeral port. It was inside the plausibility window,
/// it was the newest entry the map had read, and it was a different
/// attacker entirely -- reported with no warning, because a wrong address
/// looks exactly like a right one.
///
/// Widening or narrowing the time window cannot fix that. It has to stay
/// generous for sensors that write lines throughout a long session, and no
/// setting distinguishes "21 minutes into a cowrie session" from "21
/// minutes stale". The destination port does, exactly and for free, since
/// portbridge already records what it dialled.
///
/// `want_port` of 0 means the caller does not know, and the check is
/// skipped -- as it is for entries whose own `target_port` is 0, so a
/// portbridge line without a usable `target` still joins as before rather
/// than dropping out.
pub fn lookup_to_port(m: &ViaMap, via_port: i64, line_at: i64, want_port: i64) -> Option<&str> {
    let slot = m.get(&via_port)?;
    slot.iter()
        .rev()
        .find(|entry| plausible(entry, line_at) && port_matches(entry, want_port))
        .map(|entry| entry.ip.as_str())
}

fn port_matches(entry: &ViaEntry, want_port: i64) -> bool {
    want_port == 0 || entry.target_port == 0 || entry.target_port == want_port
}

fn plausible(entry: &ViaEntry, line_at: i64) -> bool {
    // Without usable timestamps on both sides there is nothing to check, so
    // keep the pre-#1771 behaviour rather than dropping the join entirely.
    if entry.at == 0 || line_at == 0 {
        return true;
    }
    if entry.at > line_at + CLOCK_SKEW_SECONDS {
        return false; // dialled after the event it would explain
    }
    line_at - entry.at <= MAX_AGE_SECONDS
}

/// What one join against portbridge's log concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Join<'a> {
    /// Exactly one client could have produced the line.
    Attributed(&'a str),
    /// More than one client could have, so none is named. Counted, never
    /// guessed (#3573).
    Ambiguous,
    /// No dial on this port fits the line.
    Unmatched,
}

impl Join<'_> {
    /// The value a line carries in `tunnel_attribution` for this outcome.
    pub fn label(&self) -> &'static str {
        match self {
            Join::Attributed(_) => "portbridge",
            Join::Ambiguous => "ambiguous",
            Join::Unmatched => "unmatched",
        }
    }
}

/// One question for `resolve`.
#[derive(Clone, Copy, Debug, Default)]
pub struct JoinQuery {
    /// The sensor-observed source port, which is portbridge's via_port.
    pub via_port: i64,
    /// When the connection started, as epoch seconds: the first line the
    /// sensor wrote for this session if it names one, otherwise this line's
    /// own time. 0 when the sensor gave no usable time.
    pub at: i64,
    /// The port portbridge dialled (its `target` port), when the sensor's own
    /// listen port is known to equal it; 0 when it is not.
    pub want_port: i64,
    pub transport: Transport,
}

/// #3573: the portbridge join, answering only when the answer is certain.
///
/// The window is `[at - lead, at + CLOCK_SKEW_SECONDS]`, where `at` is the
/// connection's start and `lead` is DIAL_LEAD_SECONDS -- except for a known
/// UDP line, whose lead is UDP_SESSION_MAX_AGE_SECONDS (see that constant
/// for why a UDP session can be joined long after it opened and a TCP one
/// cannot).
///
/// * TCP / unknown transport: every candidate in the window must name the
///   same client. Two different clients means two connections shared the
///   port within seconds, and nothing on the line says which is which.
/// * UDP: the newest candidate is the line's own session. It is still
///   ambiguous if another client's dial sits in the narrow band around the
///   line itself, since then the clocks cannot order the two.
///
/// A line with no usable time only joins against entries that have none
/// either -- test fixtures, and nothing portbridge writes. A timed portbridge
/// entry is never matched to an untimed line: without a time there is no
/// window, and without a window every dial ever made on the port qualifies.
pub fn resolve(m: &ViaMap, q: JoinQuery) -> Join<'_> {
    if q.via_port == 0 {
        return Join::Unmatched;
    }
    let Some(slot) = m.get(&q.via_port) else { return Join::Unmatched };
    let fits = |entry: &&ViaEntry| port_matches(entry, q.want_port) && entry.transport.compatible(q.transport);

    let candidates: Vec<&ViaEntry> = if q.at == 0 {
        slot.iter().filter(|e| e.at == 0).filter(fits).collect()
    } else {
        let lead = if q.transport == Transport::Udp { UDP_SESSION_MAX_AGE_SECONDS } else { DIAL_LEAD_SECONDS };
        slot.iter()
            .filter(|e| e.at != 0 && e.at >= q.at - lead && e.at <= q.at + CLOCK_SKEW_SECONDS)
            .filter(fits)
            .collect()
    };
    let Some(newest) = candidates.iter().max_by_key(|e| e.at) else { return Join::Unmatched };

    let rivals = |pred: &dyn Fn(&ViaEntry) -> bool| candidates.iter().any(|e| e.ip != newest.ip && pred(e));
    let ambiguous = if q.transport == Transport::Udp && q.at != 0 {
        // Only a rival close enough to the line that the clocks cannot order
        // it against the newest dial makes a UDP join ambiguous.
        rivals(&|e: &ViaEntry| e.at >= q.at - DIAL_LEAD_SECONDS || e.at == newest.at)
    } else if q.want_port == 0 && q.at != 0 {
        rivals(&|_| true)
            || slot.iter().filter(fits).any(|e| {
                e.ip != newest.ip && e.at != 0 && e.at >= q.at - RIVAL_LOOKBACK_SECONDS && e.at <= q.at + CLOCK_SKEW_SECONDS
            })
    } else {
        rivals(&|_| true)
    };
    if ambiguous {
        Join::Ambiguous
    } else {
        Join::Attributed(newest.ip.as_str())
    }
}

/// Whether `resolve`'s answer for a line at `at` can no longer change: the
/// map has read past the end of the line's window, so no dial that would
/// make it ambiguous is still to come. An untimed line is always settled.
pub fn settled(m: &ViaMap, at: i64) -> bool {
    at == 0 || m.newest_at() >= at + CLOCK_SKEW_SECONDS
}

/// #3573: whether the worker can currently read portbridge's log.
///
/// The join failed silently for weeks because of exactly this: the log sits
/// on an sshfs mount whose `default_permissions` made the kernel enforce the
/// file's root:root 0640 against the worker's `nobody`, and the read error
/// was dropped. Every tunnel line then timed out unattributed while the
/// worker reported nothing but "timed_out" counts. The stats line now prints
/// this flag, and the transition is logged at error level.
static PORTBRIDGE_READABLE: AtomicBool = AtomicBool::new(true);

pub fn portbridge_readable() -> bool {
    PORTBRIDGE_READABLE.load(Ordering::Relaxed)
}

fn note_readability(path: &Path, result: Result<(), &std::io::Error>) {
    match result {
        Ok(()) => {
            if !PORTBRIDGE_READABLE.swap(true, Ordering::Relaxed) {
                tracing::info!(path = %path.display(), "ip-enrichment: portbridge log readable again; tunnel joins resume");
            }
        }
        Err(error) => {
            if PORTBRIDGE_READABLE.swap(false, Ordering::Relaxed) {
                tracing::error!(
                    path = %path.display(),
                    %error,
                    "ip-enrichment: cannot read the portbridge log -- every tunnel-peer event will stay unattributed until this is fixed (#3573; check the sshfs mount options and the file mode)"
                );
            }
        }
    }
}

/// The most recently rotated `portbridge.json.<stamp>` segment.
///
/// portbridge rotates by renaming to a UTC timestamp suffix (main.go's
/// connLogger.rotate), not to `.1` -- the fixed name this used to read never
/// exists, so after a worker restart the previous segment's dials were
/// missing from the map. Rename preserves mtime, so the newest segment is
/// the one written last.
fn previous_generation(dir: &Path) -> Option<(PathBuf, SystemTime, u64)> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("portbridge.json."))
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            Some((entry.path(), meta.modified().ok()?, meta.len()))
        })
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
}

/// Maintains the via_port -> src_ip map incrementally across `refresh()`
/// calls instead of re-reading both portbridge generations (up to ~10MiB
/// combined) from scratch every tick forever — a real production incident
/// (#1206): under a small CPU limit, full-file-every-2s cost compounded
/// with the live file's size across a container's uptime, throttling the
/// process (>95% of CFS scheduling periods) badly enough to push the
/// highest-volume sensor's join attempts outside PENDING_TIMEOUT almost
/// entirely after ~2 days up. The newest rotated `portbridge.json.<stamp>`
/// (the previous, static generation) is only re-parsed when it changes;
/// portbridge.json (the live, growing file) is tailed for new bytes only.
/// via_port's key space is a port number, so the accumulated map is
/// inherently bounded regardless of log volume or uptime — entries are
/// never explicitly evicted, only overwritten by a newer entry for the
/// same port.
pub struct ViaMapBuilder {
    portbridge_dir: PathBuf,
    map: ViaMap,
    live_offset: i64,
    gen_mtime: Option<SystemTime>,
    gen_size: u64,
}

impl ViaMapBuilder {
    pub fn new(portbridge_dir: PathBuf) -> Self {
        let mut b = Self { portbridge_dir, map: ViaMap::new(), live_offset: 0, gen_mtime: None, gen_size: 0 };
        b.refresh();
        b
    }

    /// Returns an independent snapshot each call — the builder's own map is
    /// never handed out directly, so a caller publishing it behind an
    /// `Arc`/`RwLock` never observes an in-progress mutation.
    pub fn refresh(&mut self) -> ViaMap {
        if let Some((gen_path, mtime, size)) = previous_generation(&self.portbridge_dir) {
            if Some(mtime) != self.gen_mtime || size != self.gen_size {
                read_portbridge_lines(&gen_path, &mut self.map);
                self.gen_mtime = Some(mtime);
                self.gen_size = size;
            }
        }

        let live_path = self.portbridge_dir.join("portbridge.json");
        match read_new_lines(&live_path, self.live_offset) {
            Ok((lines, new_offset)) => {
                note_readability(&live_path, Ok(()));
                for line in &lines {
                    parse_portbridge_line(line, &mut self.map);
                }
                self.live_offset = new_offset;
            }
            Err(error) => note_readability(&live_path, Err(&error)),
        }

        self.map.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-08-23T14:07:47Z, the conpot connection from the #1771 report.
    const T: i64 = 1787494067;

    fn line(ip: &str, at: &str, port: i64) -> String {
        format!(r#"{{"sensor":"portbridge","src_ip":"{ip}","via_port":4000,"time":"{at}","port":{port}}}"#)
    }

    fn feed(lines: &[String]) -> ViaMap {
        let mut m = ViaMap::new();
        for l in lines {
            parse_portbridge_line(l.as_bytes(), &mut m);
        }
        m
    }

    #[test]
    fn ignores_lines_from_a_different_sensor() {
        let mut m = ViaMap::new();
        parse_portbridge_line(br#"{"sensor":"cowrie","src_ip":"1.1.1.1","via_port":4000}"#, &mut m);
        assert!(m.is_empty());
    }

    #[test]
    fn resolves_the_connection_that_was_open_when_the_line_was_written() {
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 1025)]);
        assert_eq!(lookup(&m, 4000, T + 1), Some("1.1.1.1"));
    }

    #[test]
    fn a_reuse_after_the_event_cannot_explain_it() {
        // The measured #1771 case: one conpot connection's 51 lines all
        // stamped 14:07:47, and the port dialled again 18 seconds later.
        // Before this, the later lines took the newer entry and the single
        // connection was reported as two different attackers.
        let m = feed(&[
            line("1.1.1.1", "2026-08-23T14:07:47Z", 1025),
            line("2.2.2.2", "2026-08-23T14:08:05Z", 1025),
        ]);
        assert_eq!(lookup(&m, 4000, T), Some("1.1.1.1"));
    }

    #[test]
    fn the_newer_connections_own_lines_still_resolve_to_it() {
        let m = feed(&[
            line("1.1.1.1", "2026-08-23T14:07:47Z", 1025),
            line("2.2.2.2", "2026-08-23T14:08:05Z", 1025),
        ]);
        assert_eq!(lookup(&m, 4000, T + 30), Some("2.2.2.2"));
    }

    #[test]
    fn the_destination_port_is_not_used_to_discriminate() {
        // It looks like a free second discriminator and it is not: one
        // connection carries three different port numbers through this
        // topology (public 23 -> host-published 19023 -> cowrie's container
        // 2223). Cross-checking any two of them rejects every port-shifted
        // service; measured live it left all 3,046 of cowrie's hourly events
        // unattributed while resolving nothing extra. A join must not depend
        // on ports agreeing across that boundary.
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 23)]);
        assert_eq!(lookup(&m, 4000, T + 1), Some("1.1.1.1"));
    }

    #[test]
    fn a_long_session_still_resolves_against_the_connect_that_opened_it() {
        // A cowrie session can stay open for a long time and every line it
        // writes has to keep resolving. The guard must not turn those into
        // misses -- that would trade one bug for another.
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 22)]);
        assert_eq!(lookup(&m, 4000, T + 3000), Some("1.1.1.1"));
    }

    #[test]
    fn a_replayed_backlog_does_not_join_against_a_live_map() {
        // #1770's 45-hour outage recovery: lines processed long after the
        // fact, against entries for entirely unrelated connections.
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 22)]);
        assert_eq!(lookup(&m, 4000, T + 45 * 3600), None);
    }

    #[test]
    fn history_is_bounded_and_keeps_the_newest() {
        let mut m = ViaMap::new();
        for i in 0..10 {
            parse_portbridge_line(
                line(&format!("1.1.1.{i}"), "2026-08-23T14:07:47Z", 22).as_bytes(), &mut m);
        }
        assert_eq!(m[&4000].len(), HISTORY);
        assert_eq!(m[&4000].last().unwrap().ip, "1.1.1.9");
    }

    #[test]
    fn a_duplicated_line_does_not_evict_real_history() {
        // #1776 shipped every portbridge line twice for a while; that must
        // not halve the useful depth of this history.
        let mut m = ViaMap::new();
        let l = line("1.1.1.1", "2026-08-23T14:07:47Z", 22);
        parse_portbridge_line(l.as_bytes(), &mut m);
        parse_portbridge_line(l.as_bytes(), &mut m);
        assert_eq!(m[&4000].len(), 1);
    }

    #[test]
    fn entries_without_timestamps_keep_the_old_behaviour() {
        // tftp-relay's session map carries neither, and an unparseable
        // sensor timestamp yields 0 -- neither should start dropping joins.
        let m = feed(&[r#"{"sensor":"portbridge","src_ip":"1.1.1.1","via_port":4000}"#.to_string()]);
        assert_eq!(lookup(&m, 4000, 0), Some("1.1.1.1"));
        assert_eq!(lookup(&m, 4000, T), Some("1.1.1.1"));
    }

    #[test]
    fn an_unknown_port_is_still_a_miss() {
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 22)]);
        assert_eq!(lookup(&m, 4001, T), None);
    }

    // ---- #1917: the destination port separates a reused ephemeral port ----

    fn entry(ip: &str, at: i64, target_port: i64) -> ViaEntry {
        ViaEntry { ip: ip.to_string(), at, target_port, ..Default::default() }
    }

    /// The measured case, with the real numbers from the live logs.
    ///
    /// via_port 54674 was dialled six times in two days. At 06:28:26 it
    /// carried a telnet connection (portbridge `port: 23`); at 06:49:57 an
    /// mssql one (`port: 1433`). dionaea logged an mssql accept on
    /// `local_port: 1433` at 06:49:57.935930 and the worker answered
    /// 153.117.32.130 — the telnet client from 21 minutes earlier.
    ///
    /// It passed every check there was: inside the six-hour window, dialled
    /// before the line, and the newest entry the map had read at that
    /// moment. Nothing about it looked wrong.
    #[test]
    fn a_stale_entry_on_the_same_port_is_rejected_by_its_destination() {
        let mut m = ViaMap::new();
        m.insert(
            54674,
            vec![
                entry("153.117.32.130", 1_787_639_306, 23),   // 06:28:26, telnet
                entry("151.243.11.8", 1_787_640_597, 1433),   // 06:49:57, mssql
            ],
        );
        let line_at = 1_787_640_597; // the accept, same second as the dial

        assert_eq!(
            lookup_to_port(&m, 54674, line_at, 1433),
            Some("151.243.11.8"),
            "the mssql dial, not the telnet one",
        );
    }

    #[test]
    fn the_stale_entry_is_refused_rather_than_substituted() {
        // The case that produced the wrong answer: the correct dial has not
        // been read yet, so only the stale telnet entry is present. Better
        // to resolve nothing and let the pending queue retry than to answer
        // with a different attacker.
        let mut m = ViaMap::new();
        m.insert(54674, vec![entry("153.117.32.130", 1_787_639_306, 23)]);

        assert_eq!(lookup_to_port(&m, 54674, 1_787_640_597, 1433), None);
    }

    #[test]
    fn a_caller_that_does_not_know_the_port_still_joins() {
        // Most sensors do not record which of their own ports was hit.
        // They must keep resolving exactly as before.
        let mut m = ViaMap::new();
        m.insert(54674, vec![entry("153.117.32.130", 0, 23)]);

        assert_eq!(lookup_to_port(&m, 54674, 0, 0), Some("153.117.32.130"));
        assert_eq!(lookup(&m, 54674, 0), Some("153.117.32.130"));
    }

    #[test]
    fn an_entry_without_a_target_port_is_not_excluded_by_the_check() {
        // A portbridge line whose `target` did not parse must not drop out
        // of the join — that would trade wrong answers for missing ones.
        let mut m = ViaMap::new();
        m.insert(54674, vec![entry("151.243.11.8", 0, 0)]);

        assert_eq!(lookup_to_port(&m, 54674, 0, 1433), Some("151.243.11.8"));
    }

    #[test]
    fn the_target_port_is_read_off_a_real_portbridge_line() {
        let mut m = ViaMap::new();
        parse_portbridge_line(
            br#"{"sensor":"portbridge","src_ip":"151.243.11.8","src_port":41804,"via_port":54674,"port":1433,"target":"10.8.0.2:1433","time":"2026-08-25T06:49:57Z"}"#,
            &mut m,
        );

        let slot = m.get(&54674).expect("entry recorded");
        assert_eq!(slot[0].target_port, 1433, "from `target`, not from `port`");
        assert_eq!(slot[0].ip, "151.243.11.8");
    }

    // ---- #3573: resolve -- one answer, or an honest refusal ----

    fn timed(ip: &str, at: i64, target_port: i64, transport: Transport) -> ViaEntry {
        ViaEntry { ip: ip.to_string(), at, target_port, transport }
    }

    fn tcp(port: i64, at: i64) -> JoinQuery {
        JoinQuery { via_port: port, at, want_port: 0, transport: Transport::Tcp }
    }

    #[test]
    fn the_dial_that_opened_the_connection_is_attributed() {
        // The measured shape: portbridge stamps whole seconds just after the
        // dial, the sensor stamps the accept 0-2s later.
        let mut m = ViaMap::new();
        m.insert(48132, vec![timed("203.0.113.20", T, 19023, Transport::Tcp)]);
        assert_eq!(resolve(&m, tcp(48132, T + 1)), Join::Attributed("203.0.113.20"));
        assert_eq!(resolve(&m, tcp(48132, T)), Join::Attributed("203.0.113.20"));
    }

    #[test]
    fn a_dial_minutes_before_the_connection_is_not_its_origin() {
        // The old six-hour window took this. It is another connection that
        // happened to use the same port earlier; the right dial is missing.
        let mut m = ViaMap::new();
        m.insert(48132, vec![timed("203.0.113.20", T - 600, 19023, Transport::Tcp)]);
        assert_eq!(resolve(&m, tcp(48132, T)), Join::Unmatched);
    }

    #[test]
    fn two_clients_on_one_port_within_seconds_is_ambiguous_not_newest_wins() {
        let mut m = ViaMap::new();
        m.insert(
            48132,
            vec![timed("203.0.113.20", T - 1, 19023, Transport::Tcp), timed("198.51.100.30", T, 445, Transport::Tcp)],
        );
        assert_eq!(resolve(&m, tcp(48132, T + 1)), Join::Ambiguous);
    }

    #[test]
    fn the_same_client_twice_is_not_a_rival() {
        let mut m = ViaMap::new();
        m.insert(
            48132,
            vec![timed("203.0.113.20", T - 1, 19023, Transport::Tcp), timed("203.0.113.20", T, 19022, Transport::Tcp)],
        );
        assert_eq!(resolve(&m, tcp(48132, T + 1)), Join::Attributed("203.0.113.20"));
    }

    #[test]
    fn a_known_target_port_removes_a_rival_on_another_service() {
        let mut m = ViaMap::new();
        m.insert(
            48132,
            vec![timed("203.0.113.20", T, 23, Transport::Tcp), timed("198.51.100.30", T, 1433, Transport::Tcp)],
        );
        let q = JoinQuery { want_port: 1433, ..tcp(48132, T + 1) };
        assert_eq!(resolve(&m, q), Join::Attributed("198.51.100.30"));
    }

    #[test]
    fn a_wrong_target_port_can_only_cost_a_match() {
        // The right dial filtered away leaves nothing, not somebody else.
        let mut m = ViaMap::new();
        m.insert(48132, vec![timed("203.0.113.20", T, 23, Transport::Tcp)]);
        let q = JoinQuery { want_port: 1433, ..tcp(48132, T + 1) };
        assert_eq!(resolve(&m, q), Join::Unmatched);
    }

    #[test]
    fn tcp_and_udp_ports_are_separate_namespaces() {
        let mut m = ViaMap::new();
        m.insert(40000, vec![timed("203.0.113.20", T, 161, Transport::Udp)]);
        assert_eq!(resolve(&m, tcp(40000, T + 1)), Join::Unmatched);
        let unknown = JoinQuery { transport: Transport::Unknown, ..tcp(40000, T + 1) };
        assert_eq!(resolve(&m, unknown), Join::Attributed("203.0.113.20"), "a line that does not say matches either");
    }

    fn udp(port: i64, at: i64) -> JoinQuery {
        JoinQuery { via_port: port, at, want_port: 0, transport: Transport::Udp }
    }

    #[test]
    fn a_long_udp_session_resolves_to_its_opening_dial() {
        // conpot's SNMP floods: one session, one via_port, thousands of
        // datagrams over half an hour.
        let mut m = ViaMap::new();
        m.insert(
            40000,
            vec![timed("198.51.100.30", T - 3000, 161, Transport::Udp), timed("203.0.113.20", T - 1800, 161, Transport::Udp)],
        );
        assert_eq!(resolve(&m, udp(40000, T)), Join::Attributed("203.0.113.20"));
    }

    #[test]
    fn a_udp_dial_too_close_to_the_line_to_order_is_ambiguous() {
        let mut m = ViaMap::new();
        m.insert(
            40000,
            vec![timed("198.51.100.30", T - 1, 161, Transport::Udp), timed("203.0.113.20", T + 1, 161, Transport::Udp)],
        );
        assert_eq!(resolve(&m, udp(40000, T)), Join::Ambiguous);
    }

    #[test]
    fn a_udp_session_older_than_the_cap_is_not_joined() {
        let mut m = ViaMap::new();
        m.insert(40000, vec![timed("203.0.113.20", T - UDP_SESSION_MAX_AGE_SECONDS - 1, 161, Transport::Udp)]);
        assert_eq!(resolve(&m, udp(40000, T)), Join::Unmatched);
    }

    #[test]
    fn an_untimed_line_never_matches_a_timed_dial() {
        let mut m = ViaMap::new();
        m.insert(48132, vec![timed("203.0.113.20", T, 23, Transport::Tcp)]);
        assert_eq!(resolve(&m, tcp(48132, 0)), Join::Unmatched);
    }

    #[test]
    fn an_answer_is_settled_only_once_the_map_has_read_past_the_window() {
        let mut m = ViaMap::new();
        parse_portbridge_line(
            br#"{"sensor":"portbridge","src_ip":"203.0.113.20","via_port":48132,"proto":"tcp","target":"10.8.0.2:19023","time":"2026-08-23T14:07:47Z"}"#,
            &mut m,
        );
        assert_eq!(m.newest_at(), T);
        assert!(!settled(&m, T + 1), "a rival dial up to two seconds later may not be read yet");
        parse_portbridge_line(
            br#"{"sensor":"portbridge","src_ip":"198.51.100.30","via_port":1,"time":"2026-08-23T14:07:51Z"}"#,
            &mut m,
        );
        assert!(settled(&m, T + 1));
        assert_eq!(m[&48132][0].transport, Transport::Tcp, "proto is read off the line");
    }

    #[test]
    fn the_builder_reads_the_stamped_rotation_segment_and_reports_an_unreadable_log() {
        let dir = std::env::temp_dir().join(format!("viamap-builder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("portbridge.json.20261009-120000"),
            b"{\"sensor\":\"portbridge\",\"src_ip\":\"203.0.113.20\",\"via_port\":4000,\"time\":\"2026-08-23T14:07:47Z\"}\n",
        )
        .unwrap();
        // A directory where the log should be fails the read the way an
        // EACCES did live, without depending on who runs the test.
        std::fs::create_dir_all(dir.join("portbridge.json")).unwrap();

        let mut builder = ViaMapBuilder::new(dir.clone());
        assert!(!portbridge_readable(), "an unreadable live log is reported, not swallowed");
        let m = builder.refresh();
        assert_eq!(m[&4000][0].ip, "203.0.113.20", "the rotated segment is read under its real name");

        std::fs::remove_dir_all(dir.join("portbridge.json")).unwrap();
        std::fs::write(dir.join("portbridge.json"), b"").unwrap();
        builder.refresh();
        assert!(portbridge_readable(), "and the recovery is noticed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn without_a_target_port_an_earlier_rival_on_the_port_makes_it_ambiguous() {
        // A line written minutes into a connection whose port was dialled
        // again a second before the line, for another service: the narrow
        // window alone would name the stranger.
        let mut m = ViaMap::new();
        m.insert(
            48132,
            vec![timed("203.0.113.20", T - 300, 389, Transport::Tcp), timed("198.51.100.30", T - 1, 445, Transport::Tcp)],
        );
        assert_eq!(resolve(&m, tcp(48132, T)), Join::Ambiguous);
        let told = JoinQuery { want_port: 445, ..tcp(48132, T) };
        assert_eq!(resolve(&m, told), Join::Attributed("198.51.100.30"), "a known target needs no look-back");
    }
}
