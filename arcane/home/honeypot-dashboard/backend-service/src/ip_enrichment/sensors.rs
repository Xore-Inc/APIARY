//! Ported from ip-enrichment-worker/enrich.go plus the bespoke per-sensor
//! files (beelzebub.go/hellpot.go/galah.go/sentrypeer.go/wordpot.go): the
//! generic tunnel-peer src_ip join, dionaea_incident.json's nested-shape
//! variant, and five sensors whose raw log line doesn't match the generic
//! src_ip/src_port shape at all.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use serde_json::Value;

use super::canonical::promote_canonical_fields;
use super::tftp::is_tftp_relay_record;
use super::viamap::{resolve, settled, Join, JoinQuery, Transport, ViaMap};

#[cfg(test)]
pub const TUNNEL_PEER_IP: &str = crate::fleet::DEFAULT_TUNNEL_PEER_IP;

/// Loopback sources. A honeypot is reached from the network; nothing on this
/// fleet is legitimately attacked from inside its own container.
///
/// `pub(crate)` (#2900): attacker_identity.rs's entity-prune pass reuses
/// this exact constant rather than a second hand-copied list, so the
/// retrieval side and `mark_internal_probe` below can never disagree about
/// what counts as loopback.
pub(crate) const LOOPBACK_IPS: [&str; 2] = ["127.0.0.1", "::1"];

/// #1677: mark self-generated probe traffic instead of counting it as an attack.
///
/// Every sensor here is fronted by a Docker healthcheck that connects to the
/// sensor's own listening port -- `nc -z 127.0.0.1 5060` for sentrypeer, an
/// HTTP GET for http-honeypot, `conpot-healthcheck.py` for the conpot
/// personas -- and the sensor logs that connection exactly as it logs a real
/// one. Measured live: 312,905 such events in 24 hours, 13.5% of everything
/// ingested.
///
/// This is not the tunnel case and must not be enriched like one. There is no
/// attacker address hiding behind a healthcheck; the container probed itself.
/// Rewriting the IP would produce a better-labelled fiction, and dropping the
/// event outright would destroy the evidence that a probe happened at all.
///
/// So the document is marked and kept. Attack-facing queries filter on this
/// field, which lets `dashboard.rs`'s `top_ips` stop hard-coding an exclusion
/// list -- the exclusion exists today only because the documents carry no way
/// to tell the two apart.
///
/// Worth being precise about the damage this was doing: conpot's healthcheck
/// events arrive tagged `canonical_attck_techniques: ["T0886"]`, so Docker
/// liveness probes were being recorded as MITRE ICS technique usage.
fn mark_internal_probe(e: &mut Value) -> bool {
    let ip = str(e, "src_ip");
    mark_probe_from(e, &ip)
}

/// The same rule, for the enrichers that derive the address themselves.
///
/// mark_internal_probe reads `src_ip` off the event, which is a field
/// enrich_line has already populated by the time it runs. The per-sensor
/// enrichers do not have that: they read the address out of their own
/// sensor's field first -- sentrypeer's "source_ip", hellpot's
/// REMOTE_ADDR, galah's "srcIP" -- and only
/// write `src_ip` at the end, on paths that vary. So they pass what they
/// found instead of relying on a field that is not there yet.
///
/// This is why #1918 existed at all. Every one of those enrichers skipped
/// the probe marking entirely, so their healthchecks were excluded from
/// `source.ip` (loopback is not an attacker) but never flagged as probes
/// -- landing in the unattributed residue instead. Measured over 24h:
/// 2,879 loopback events unflagged, of which 2,864 came from these four
/// sensors and 2,857 from sentrypeer alone, which inflated that residue
/// roughly threefold.
fn mark_probe_from(e: &mut Value, ip: &str) -> bool {
    if !LOOPBACK_IPS.contains(&ip) {
        return false;
    }
    if e.get("internal_probe").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    e["internal_probe"] = Value::Bool(true);
    true
}

fn str(e: &Value, key: &str) -> String {
    e.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Mirrors dashboard/classify.go's eventSrcPort: a top-level "src_port"
/// first, dionaea's older nested connection.remote_port shape as a
/// defensive fallback.
fn extract_src_port(e: &Value) -> i64 {
    if let Some(p) = e.get("src_port").and_then(Value::as_f64).filter(|p| *p != 0.0) {
        return p as i64;
    }
    if let Some(p) = e.get("connection").and_then(|c| c.get("remote_port")).and_then(Value::as_f64) {
        return p as i64;
    }
    0
}

/// When the sensor says the event happened, as epoch seconds; 0 when it says
/// nothing this can read.
///
/// #1771 needs this to tell a via_port entry that could have produced the
/// line from one dialled afterwards for a different connection. Every key
/// and shape below was read off the live enriched logs rather than guessed:
/// `timestamp` (conpot's six personas, cowrie, dionaea, elasticpot, mailoney,
/// tanner), `time` (cisco-asa, citrix, dns-honeypot, hellpot, http-honeypot,
/// multipot, rdp-honeypot), `event_timestamp` (sentrypeer) and
/// `eventTime` (galah). beelzebub carries none, and gets the pre-#1771
/// behaviour.
///
/// Naive stamps are treated as UTC, which is what the sensors emit --
/// confirmed against wall clock on the live host.
fn extract_line_time(e: &Value) -> i64 {
    for key in ["timestamp", "time", "event_timestamp", "eventTime"] {
        let Some(raw) = e.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) else { continue };
        if let Some(seconds) = parse_sensor_time(raw) {
            return seconds;
        }
    }
    0
}

fn parse_sensor_time(raw: &str) -> Option<i64> {
    let normalized = raw.replacen(' ', "T", 1);
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&normalized) {
        return Some(t.timestamp());
    }
    // #3573: galah now logs Go's time.Time String() form,
    // "2026-09-29 08:51:15.402586836 +0200 CEST m=+485577.992530828" -- a
    // numeric offset followed by a zone abbreviation and the monotonic clock
    // reading. Only the first two tokens carry the instant. Before this the
    // whole stamp failed to parse, so galah's lines joined with no time check
    // at all.
    let mut tokens = normalized.split_whitespace();
    if let (Some(stamp), Some(offset)) = (tokens.next(), tokens.next()) {
        if offset.starts_with('+') || offset.starts_with('-') {
            if let Ok(t) = chrono::DateTime::parse_from_str(&format!("{stamp}{offset}"), "%Y-%m-%dT%H:%M:%S%.f%z") {
                return Some(t.timestamp());
            }
        }
    }
    // galah: "2026-08-23T08:38:23.441305976 +0200" -- an offset, space-separated.
    if let Some((head, tail)) = normalized.rsplit_once(' ') {
        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&format!("{head}{tail}")) {
            return Some(t.timestamp());
        }
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(&normalized, format) {
            return Some(t.and_utc().timestamp());
        }
    }
    None
}

/// Corrects "dst_port" for the two Siemens S7 personas whose
/// host-published Modbus/S7comm ports differ from the container-internal
/// port conpot itself binds and logs.
fn fix_conpot_dest_port(e: &mut Value, persona: &str) -> bool {
    let remap: &[(f64, f64)] = match persona {
        "conpot-s7-1200" => &[(502.0, 1502.0), (102.0, 1102.0)],
        "conpot-s7-1500" => &[(502.0, 2502.0), (102.0, 2102.0)],
        _ => return false,
    };
    let Some(p) = e.get("dst_port").and_then(Value::as_f64) else { return false };
    let Some((_, real)) = remap.iter().find(|(from, _)| *from == p) else { return false };
    e["dst_port"] = Value::from(*real);
    true
}

pub fn marshal_if_changed(line: &[u8], e: &Value, changed: bool) -> Vec<u8> {
    if !changed {
        return line.to_vec();
    }
    serde_json::to_vec(e).unwrap_or_else(|_| line.to_vec())
}

/// Sets `e[key]` to `value` if it differs from the current string value,
/// returning whether it actually changed anything.
fn set_if_changed(e: &mut Value, key: &str, value: impl Into<String>) -> bool {
    let value = value.into();
    if e.get(key).and_then(Value::as_str) == Some(value.as_str()) {
        return false;
    }
    e[key] = Value::from(value);
    true
}

/// #3573: writes the outcome of one portbridge join onto the line.
///
/// `tunnel_attribution` lands in Elasticsearch as
/// `honeypot.tunnel_attribution` ("portbridge", "ambiguous" or "unmatched"),
/// so an unattributed tunnel event says *why* it is unattributed and can be
/// counted, instead of looking identical to one the worker never saw.
/// `fleet_peer` keeps the tunnel address the sensor actually observed once
/// `src_ip` has been replaced with the client, the same field #3560's ingest
/// promotion writes when it passes over a fleet address.
fn mark_join(e: &mut Value, join: &Join) -> bool {
    let mut changed = set_if_changed(e, "tunnel_attribution", join.label());
    if matches!(join, Join::Attributed(_)) {
        changed |= set_if_changed(e, "fleet_peer", crate::fleet::tunnel_peer_ip());
    }
    changed
}

/// Connection start times by (sensor, session id), for sensors that name
/// their sessions (#3573).
///
/// The join window is a few seconds wide, and it has to be anchored on the
/// moment the connection opened: a cowrie session writes lines for minutes
/// or hours, and joining a late line on its own timestamp either finds
/// nothing or -- worse -- finds an unrelated dial that happened to reuse the
/// port seconds before that line. Remembering when the session's first line
/// was written makes every line of the session ask the same question its
/// connect line asked.
fn session_starts() -> &'static Mutex<HashMap<(String, String), i64>> {
    static STARTS: OnceLock<Mutex<HashMap<(String, String), i64>>> = OnceLock::new();
    STARTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A remembered start older than this is treated as a different session that
/// reused the identifier, never as the start of this one. Also the age past
/// which entries are swept once the map is full.
const SESSION_TTL_SECONDS: i64 = 6 * 3600;

/// Bounds the session map. Sessions are swept by age when it fills; if it is
/// still full afterwards, lines simply join on their own time.
const SESSION_CAPACITY: usize = 200_000;

/// When the connection behind this line started: the earliest time seen for
/// its session, or the line's own time when the sensor names no session.
fn connection_start(persona: &str, session: Option<&str>, line_at: i64) -> i64 {
    let Some(session) = session.filter(|s| !s.is_empty()) else { return line_at };
    if line_at == 0 {
        return 0;
    }
    let Ok(mut starts) = session_starts().lock() else { return line_at };
    let key = (persona.to_string(), session.to_string());
    if let Some(&start) = starts.get(&key) {
        if start <= line_at && line_at - start <= SESSION_TTL_SECONDS {
            return start;
        }
        if start > line_at && start - line_at <= SESSION_TTL_SECONDS {
            // An earlier line of the session arrived after a later one.
            starts.insert(key, line_at);
            return line_at;
        }
    }
    if starts.len() >= SESSION_CAPACITY {
        starts.retain(|_, start| (line_at - *start).abs() <= SESSION_TTL_SECONDS);
        if starts.len() >= SESSION_CAPACITY {
            return line_at;
        }
    }
    starts.insert(key, line_at);
    line_at
}

/// The session identifier a sensor writes on every line of one connection,
/// where it writes one that is unique. mailoney's `session_id` is a counter
/// that restarts with the container, so it is deliberately not used.
fn session_key<'a>(persona: &str, e: &'a Value) -> Option<&'a str> {
    let field = if persona == "cowrie" {
        "session"
    } else if persona == "conpot" || persona.starts_with("conpot-") {
        "id"
    } else {
        return None;
    };
    e.get(field).and_then(Value::as_str)
}

/// The transport a generic sensor line was carried over, where the line says.
fn line_transport(persona: &str, e: &Value) -> Transport {
    let declared = e
        .get("transport")
        .or_else(|| e.get("connection").and_then(|c| c.get("transport")))
        .and_then(Value::as_str)
        .map(Transport::parse)
        .unwrap_or_default();
    if declared != Transport::Unknown {
        return declared;
    }
    match persona {
        "cowrie" | "elasticpot" | "mailoney" => Transport::Tcp,
        p if p == "conpot" || p.starts_with("conpot-") => {
            let udp_kind = matches!(
                e.get("data_type").and_then(Value::as_str),
                Some("snmp") | Some("bacnet") | Some("ipmi") | Some("tftp")
            );
            let udp_port = matches!(e.get("dst_port").and_then(Value::as_i64), Some(161 | 623 | 47808 | 69));
            if udp_kind || udp_port {
                Transport::Udp
            } else {
                Transport::Tcp
            }
        }
        _ => Transport::Unknown,
    }
}

/// The port portbridge dialled, for sensors whose own listen port is the
/// same number (checked against the live portbridge RULES, 2026-10-09).
///
/// A wrong value here can only ever cost a match, never produce a wrong one:
/// two TCP connections to the same target cannot share a source port at the
/// same time, so filtering on the target can remove the right dial but never
/// promote an unrelated one. cowrie's ports are shifted by its own compose
/// file (19022 -> 2222, 19023 -> 2223) and mapped back here; conpot's UDP
/// services are shifted too (19161 -> 161), so only its TCP lines say.
fn want_port(persona: &str, e: &Value) -> i64 {
    let number = |field: &str| match e.get(field) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    match persona {
        "dionaea" | "elasticpot" | "mailoney" => number("dst_port"),
        "dns-honeypot" | "cisco-asa-honeypot" => number("port"),
        "cowrie" => match number("dst_port") {
            2222 => 19022,
            2223 => 19023,
            _ => 0,
        },
        p if (p == "conpot" || p.starts_with("conpot-")) && line_transport(p, e) == Transport::Tcp => number("dst_port"),
        _ => 0,
    }
}

/// The generic case: fix conpot dest port, promote canonical fields
/// unconditionally on every attempt (including retries — cheap, idempotent
/// against the same original line), then resolve src_ip via the
/// tunnel-peer or TFTP-relay join. A src_ip miss still returns whatever
/// dst_port/canonical-field changes were made — pendingQueue.drain calls
/// this again on every retry and writes *this* return value once the line
/// either resolves or times out, so those changes must not be dropped.
pub fn enrich_line(line: &[u8], vm: &ViaMap, tftp_vm: &ViaMap, persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true); // unparseable: nothing to retry, pass through as-is
    };

    let port_fixed = fix_conpot_dest_port(&mut e, persona);
    let canonical_changed = promote_canonical_fields(persona, &mut e);
    let attck_changed = super::attck::promote_attck_technique_fields(persona, &mut e);
    let probe_marked = mark_internal_probe(&mut e);
    let fields_changed = attck_changed || canonical_changed || port_fixed || probe_marked;

    let ip = str(&e, "src_ip");
    let port = extract_src_port(&e);
    let line_at = extract_line_time(&e);
    if ip != crate::fleet::tunnel_peer_ip() {
        if !is_tftp_relay_record(&e, persona) {
            return (marshal_if_changed(line, &e, fields_changed), true); // already correct or genuinely unknown
        }
        if port == 0 {
            return (marshal_if_changed(line, &e, fields_changed), true);
        }
        // The TFTP relay's own session log carries no timestamps, so this
        // keeps the plain port lookup (#1771's checks opt out at time 0).
        let Some(real) = super::viamap::lookup(tftp_vm, port, line_at) else {
            return (marshal_if_changed(line, &e, fields_changed), false);
        };
        e["src_ip"] = Value::from(real.to_string());
        return (marshal_if_changed(line, &e, true), true);
    }

    if port == 0 {
        let marked = mark_join(&mut e, &Join::Unmatched);
        return (marshal_if_changed(line, &e, fields_changed || marked), true); // no src_port to join on
    }
    // #1771/#3573: the dial has to be one that could actually have produced
    // this connection -- within a few seconds of when it opened, and the only
    // client that fits. Anything else is reported, not guessed.
    let query = JoinQuery {
        via_port: port,
        at: connection_start(persona, session_key(persona, &e), line_at),
        want_port: want_port(persona, &e),
        transport: line_transport(persona, &e),
    };
    let join = resolve(vm, query);
    let marked = mark_join(&mut e, &join);
    match join {
        Join::Attributed(real) => {
            e["src_ip"] = Value::from(real.to_string());
            (marshal_if_changed(line, &e, true), settled(vm, query.at))
        }
        // Final: more of the log can only add rivals, never remove one.
        Join::Ambiguous => (marshal_if_changed(line, &e, fields_changed || marked), true),
        // Retried -- portbridge's line for the dial may not have been read yet.
        Join::Unmatched => (marshal_if_changed(line, &e, fields_changed || marked), false),
    }
}

/// Recursively walks `v` (typically dionaea_incident.json's "data" field)
/// looking for every embedded connection-shape object — any map carrying
/// both "remote_ip" and "remote_port" — and rewrites remote_ip in place
/// wherever it's currently the tunnel peer and the port resolves. Matches
/// by shape, not a fixed key name, since the key varies by incident
/// origin ("connection" for most, "child"/"parent" for
/// dionaea.connection.link).
fn rewrite_dionaea_connections(v: &mut Value, vm: &ViaMap, line_at: i64) -> DionaeaWalk {
    let mut walk = DionaeaWalk { all_resolved: true, ..DionaeaWalk::default() };
    match v {
        Value::Object(map) => {
            if let Some(Value::String(ip)) = map.get("remote_ip") {
                // #1917: dionaea's own healthcheck opens a real connection
                // to itself -- smbd on 445 from 127.0.0.1 -- and it is
                // logged exactly like an attacker's. Measured at 40 per ten
                // minutes, about 5,760 a day, which was the whole of the
                // "unattributed dionaea connections" this issue was filed
                // for. They are not unattributable; they are ours.
                //
                // Same rule as #1918, reaching a shape that fix could not:
                // the address is nested at data.connection.remote_ip, not
                // at a top-level src_ip, so mark_internal_probe never saw
                // it.
                if LOOPBACK_IPS.contains(&ip.as_str()) {
                    walk.saw_loopback = true;
                }
                if ip == crate::fleet::tunnel_peer_ip() {
                    if let Some(port) = map.get("remote_port").and_then(Value::as_f64) {
                        // #1917: the connection object says which of its own
                        // ports the attacker reached, and that is what makes
                        // this join safe. Measured on live data: an mssql
                        // connection on 1433 resolved to the client of a
                        // telnet dial 21 minutes earlier that reused the same
                        // ephemeral port -- inside the time window, newest
                        // entry the map had, and a different attacker. The
                        // destination port rules it out outright.
                        //
                        // #3573: anchored on the connection's first record
                        // (its `id` is shared by accept, link and free), and
                        // ambiguous rather than newest-wins when two clients
                        // fit.
                        let want_port = map
                            .get("local_port")
                            .and_then(Value::as_f64)
                            .map(|p| p as i64)
                            .unwrap_or(0);
                        let transport = map
                            .get("transport")
                            .and_then(Value::as_str)
                            .map(Transport::parse)
                            .unwrap_or_default();
                        let id = map.get("id").and_then(Value::as_str).map(str::to_string);
                        let query = JoinQuery {
                            via_port: port as i64,
                            at: connection_start("dionaea-incident", id.as_deref(), line_at),
                            want_port,
                            transport,
                        };
                        match resolve(vm, query) {
                            Join::Attributed(real) => {
                                map.insert("remote_ip".to_string(), Value::from(real.to_string()));
                                walk.changed += 1;
                                // Better queued than answered before a rival
                                // dial could still arrive.
                                walk.all_resolved &= settled(vm, query.at);
                            }
                            Join::Ambiguous => walk.ambiguous += 1,
                            Join::Unmatched => {
                                // Better queued than answered wrongly: the
                                // right entry usually arrives within a
                                // second, and the pending queue flushes it
                                // unenriched if it never does.
                                walk.unmatched += 1;
                                walk.all_resolved = false;
                            }
                        }
                    }
                }
            }
            for child in map.values_mut() {
                walk.absorb(rewrite_dionaea_connections(child, vm, line_at));
            }
        }
        Value::Array(arr) => {
            for child in arr {
                walk.absorb(rewrite_dionaea_connections(child, vm, line_at));
            }
        }
        _ => {}
    }
    walk
}

/// What one pass over a dionaea incident's `data` found.
#[derive(Default)]
struct DionaeaWalk {
    /// How many nested remote_ip values were rewritten to a real client.
    changed: usize,
    /// #3573: tunnel connections two clients could have produced.
    ambiguous: usize,
    /// #3573: tunnel connections no dial fits (yet).
    unmatched: usize,
    /// False when a tunnel-peer address had no portbridge entry to join
    /// against, so the line should be retried rather than shipped as-is.
    all_resolved: bool,
    /// Whether any peer in the record was loopback -- dionaea talking to
    /// itself, not an attacker.
    saw_loopback: bool,
}

impl DionaeaWalk {
    fn absorb(&mut self, child: DionaeaWalk) {
        self.changed += child.changed;
        self.ambiguous += child.ambiguous;
        self.unmatched += child.unmatched;
        self.all_resolved = self.all_resolved && child.all_resolved;
        self.saw_loopback = self.saw_loopback || child.saw_loopback;
    }

    /// The record-level outcome: one answer per incident, the worst of its
    /// tunnel connections. None when it had no tunnel connection at all.
    fn join(&self) -> Option<Join<'static>> {
        if self.ambiguous > 0 {
            Some(Join::Ambiguous)
        } else if self.unmatched > 0 {
            Some(Join::Unmatched)
        } else if self.changed > 0 {
            Some(Join::Attributed(""))
        } else {
            None
        }
    }
}

/// dionaea_incident.json's own enrichLine: unlike the flat-log sensors, an
/// incident record carries no top-level src_ip at all — the real signal
/// is buried in "data". tftp_vm/persona are accepted only to match the
/// shared enrich-function signature and are unused here.
pub fn enrich_dionaea_incident_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let line_at = extract_line_time(&e);
    let walk = match e.get_mut("data") {
        Some(data) => rewrite_dionaea_connections(data, vm, line_at),
        None => DionaeaWalk { all_resolved: true, ..DionaeaWalk::default() },
    };
    let (changed, all_resolved) = (walk.changed, walk.all_resolved);
    let marked = walk.join().is_some_and(|join| mark_join(&mut e, &join));
    let probe_marked = walk.saw_loopback && mark_probe_from(&mut e, "127.0.0.1");
    let canonicalized = promote_canonical_fields("dionaea-incident", &mut e);
    let attck_changed = super::attck::promote_attck_technique_fields("dionaea-incident", &mut e);
    if changed == 0 && !marked && !canonicalized && !attck_changed && !probe_marked {
        return (line.to_vec(), all_resolved);
    }
    (serde_json::to_vec(&e).unwrap_or_else(|_| line.to_vec()), all_resolved)
}

// ---------------------------------------------------------------------------
// Bespoke per-sensor enrichers — each adapts one sensor's own non-standard
// raw log shape into the shared (line, resolved) enrich-function contract.
// ---------------------------------------------------------------------------

/// beelzebub.json: every standardOutStrategy line nests the actual
/// tracer.Event under a top-level "event" key. Three independent steps:
/// rewrite event.SourceIp when it's the tunnel peer and the port resolves;
/// mirror the (possibly just-rewritten) SourceIp/SourcePort as flat
/// top-level src_ip/src_port (the geoip ingest pipeline only ever promotes
/// h.src_ip at honeypot.* top level); mirror
/// User/Password/Command/RequestURI as flat lowercase fields. No
/// destination-port field: beelzebub's Event carries no listen-port of its
/// own.
pub fn enrich_beelzebub_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(ev) = e.get("event").cloned().filter(Value::is_object) else {
        return (line.to_vec(), true); // not a "New Event" line (e.g. startup/error log)
    };

    let mut changed = false;
    if let Some(proto) = ev.get("Protocol").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        changed |= set_if_changed(&mut e, "sensor", "beelzebub");
        changed |= set_if_changed(&mut e, "protocol", proto);
    }
    for (src_key, dst_key) in [("User", "username"), ("Password", "password"), ("Command", "command"), ("RequestURI", "path")] {
        if let Some(v) = ev.get(src_key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            changed |= set_if_changed(&mut e, dst_key, v);
        }
    }
    changed |= promote_canonical_fields("beelzebub", &mut e);
    changed |= super::attck::promote_attck_technique_fields("beelzebub", &mut e);

    let ip = ev.get("SourceIp").and_then(Value::as_str).unwrap_or("").to_string();
    if ip != crate::fleet::tunnel_peer_ip() {
        if !ip.is_empty() {
            changed |= set_if_changed(&mut e, "src_ip", ip);
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = ev.get("SourcePort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // #3573: beelzebub's only timestamp is the event's own `DateTime`; the
    // top-level line has none, which used to leave this join with no time
    // check at all.
    let at = ev.get("DateTime").and_then(Value::as_str).and_then(parse_sensor_time).unwrap_or(0);
    let query = JoinQuery { via_port: port, at, want_port: 0, transport: Transport::Tcp };
    let join = resolve(vm, query);
    changed |= mark_join(&mut e, &join);
    let Join::Attributed(real) = join else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), join == Join::Ambiguous);
    };
    let real = real.to_string();

    let mut ev = ev;
    ev["SourceIp"] = Value::from(real.clone());
    e["event"] = ev;
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), settled(vm, at))
}

/// One rule for deciding who sent a relayed request (#1876).
///
/// A sensor behind the tunnel can be told who its client was by more than
/// one mechanism, and they are not equally trustworthy:
///
///   * the via_port join answers from portbridge's own record of the
///     connection it relayed -- evidence *about* the connection;
///   * a forwarded header answers from inside the request -- content, and
///     on a path portbridge relays it is authored by the attacker.
///
/// So where both speak, the connection wins. Where they disagree the
/// disagreement is kept rather than resolved away: on a relayed path a
/// contradicting header is an attacker claiming a different source, and
/// discarding it erases the attempt while believing it is the bug #1419
/// removed. Where only one speaks it is used; where neither does the line
/// waits, because the tunnel peer is our own address and reporting it as a
/// source states something false.
///
/// Sensors record, this decides. A sensor cannot tell the paths apart --
/// both present the tunnel peer, and any header a relay adds an attacker
/// can also send -- so the decision belongs where portbridge's connection
/// log is, which is here.
pub struct SourceVerdict {
    pub ip: String,
    /// Set only when a second mechanism contradicted `ip`.
    pub claimed: Option<String>,
    pub resolved: bool,
}

pub fn adjudicate_source(observed: &str, relayed: Option<String>, claimed: Option<String>) -> SourceVerdict {
    // Not relayed: the sensor is looking straight at the client, so no join
    // applies and no header may override what the connection shows.
    if observed != crate::fleet::tunnel_peer_ip() {
        return SourceVerdict { ip: observed.to_string(), claimed: None, resolved: true };
    }
    match (relayed, claimed) {
        (Some(relayed), Some(claimed)) if relayed != claimed => {
            SourceVerdict { ip: relayed, claimed: Some(claimed), resolved: true }
        }
        (Some(relayed), _) => SourceVerdict { ip: relayed, claimed: None, resolved: true },
        // portbridge never saw this connection, so the header is the only
        // evidence there is.
        (None, Some(claimed)) => SourceVerdict { ip: claimed, claimed: None, resolved: true },
        (None, None) => SourceVerdict { ip: observed.to_string(), claimed: None, resolved: false },
    }
}

/// The hop a forwarded header appended last, or None if nothing usable.
///
/// The last hop, not the first: Cloudflare appends the real client to
/// whatever the client already sent rather than replacing it, so the
/// leftmost entry is attacker-controlled and the rightmost is the one
/// Cloudflare itself wrote. A value that is not an address is not evidence
/// and must never reach a field the dashboard renders as one.
/// Who the proxy chain in front of a sensor says the client is.
///
/// The obvious reading -- the last hop of X-Forwarded-For -- is wrong here,
/// and shipped wrong for months. Each proxy *appends the peer it saw*, so on
/// the Cloudflare -> Traefik -> sensor path the chain ends with the address
/// Traefik saw, which is Cloudflare's edge. Measured on a live request:
/// `X-Forwarded-For: <client>, 172.69.150.126`, the trailing address being a
/// Cloudflare edge node. #1511 took the last hop, so every proxied galah
/// event was filed against Cloudflare rather than against an attacker --
/// 172.69.x sitting in the source list looking like ordinary traffic.
///
/// Cf-Connecting-Ip is the direct answer wherever Cloudflare set it: one
/// value, the client, with no chain to index into. The fallback is the
/// second-to-last hop, which is the entry Cloudflare itself appended. Both
/// hold against a client that pre-seeds the header, because whatever an
/// attacker writes stays to the *left* of what Cloudflare appends and so
/// never becomes either answer.
///
/// This is only ever a claim. Whether it may be believed depends on the
/// request having genuinely arrived through that chain, which is the
/// caller's business and not this function's -- see enrich_galah_line.
pub fn forwarded_claim(e: &Value) -> Option<String> {
    if let Some(cf) = recorded(e, &["cf_connecting_ip", "CF_CONNECTING_IP"])
        .or_else(|| header_value(e, "cf-connecting-ip"))
        .and_then(|v| valid_ip(&v))
    {
        return Some(cf);
    }
    let raw = forwarded_header(e)?;
    let hops: Vec<&str> = raw.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
    // Two or more hops means a proxy appended its own peer behind the entry
    // that identifies the client; a single hop means nothing was appended.
    let idx = if hops.len() >= 2 { hops.len() - 2 } else { 0 };
    valid_ip(hops.get(idx)?)
}

fn valid_ip(candidate: &str) -> Option<String> {
    candidate.parse::<std::net::IpAddr>().ok().map(|_| candidate.to_string())
}

/// The raw X-Forwarded-For a sensor recorded, wherever it put it.
///
/// hellpot logs it as its own field, because it logs almost nothing else
/// (hellpot/xff_trust_patch.py). galah already logs every request header,
/// so it needs no patch to record one -- the value has been in
/// httpRequest.headers the whole time, and the sensor was resolving it
/// itself rather than leaving the decision to the worker (#1891).
///
/// Header names arrive in whatever case the client sent, so the lookup is
/// case-insensitive: an attacker choosing `x-forwarded-for` should not be
/// able to sidestep the adjudication by lowercasing it.
fn forwarded_header(e: &Value) -> Option<String> {
    recorded(e, &["XFF", "xff"]).or_else(|| header_value(e, "x-forwarded-for"))
}

/// A field a sensor recorded directly, under whichever name it uses.
///
/// Sensors that log their whole header map need no help -- galah is one.
/// The ones that log almost nothing have to be given a field: hellpot's
/// patch writes `XFF` next to its bare message (wordpot, before its
/// #2381 retirement, wrote `xff` and `cf_connecting_ip`). Renaming either
/// would orphan everything already on disk for no gain, so the spellings
/// live here -- this is the one place that has to know them anyway.
fn recorded(e: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        e.get(*name).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
    })
}

/// One request header out of whatever the sensor recorded, by name.
///
/// Header names arrive in the case the sender chose, so the match is
/// case-insensitive: an attacker writing `x-forwarded-for` must not get
/// different handling from one writing `X-Forwarded-For`.
fn header_value(e: &Value, name: &str) -> Option<String> {
    let headers = e.get("httpRequest")?.get("headers")?.as_object()?;
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Write a verdict onto a line, so every sensor records a contradicted
/// claim under the same field names.
pub fn apply_verdict(e: &mut Value, v: &SourceVerdict) -> bool {
    let mut changed = set_if_changed(e, "src_ip", v.ip.clone());
    if let Some(claimed) = &v.claimed {
        changed |= set_if_changed(e, "src_ip_claimed", claimed.clone());
        if e.get("src_ip_conflict").and_then(Value::as_bool) != Some(true) {
            e["src_ip_conflict"] = Value::Bool(true);
            changed = true;
        }
    }
    changed
}

/// Clients already resolved for a connection that is still open (#1876).
///
/// HellPot is a tarpit: it holds a connection for as long as the client will
/// stay, then writes FINISH when it finally closes. Observed live at 26 and
/// 60 hours. viamap only accepts a dial within MAX_AGE_SECONDS (6h), so the
/// closing line of a long hold can never join -- the dial it needs aged out
/// of the map long before.
///
/// Re-deriving per line cannot fix that. Remembering can: the port in
/// REMOTE_ADDR is stable across NEW -> FINISH for one connection, so the
/// answer found when it opened still applies when it closes, however much
/// later that is.
///
/// Port reuse is safe because the entry is dropped when the connection
/// closes. An operating system will not hand out a source port whose
/// connection is still established, so the only reuse that can happen is
/// after the FINISH that evicted the entry -- and the next NEW writes a
/// fresh one before anything reads it.
///
/// Widening MAX_AGE_SECONDS was the alternative and is the wrong lever: it
/// would loosen the join for every sensor to fix one, and a six-hour-old
/// dial genuinely is ambiguous for anything that is not a tarpit.
fn held_connections() -> &'static Mutex<HashMap<i64, (String, i64)>> {
    static HELD: OnceLock<Mutex<HashMap<i64, (String, i64)>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How long a remembered connection stays useful. Past this it is a leak
/// rather than a memory -- a connection nothing has written a line for in
/// four days is not still open.
const HELD_TTL_SECONDS: i64 = 4 * 24 * 3600;

/// Bounds the map even if closing lines are lost entirely. Ports are capped
/// at 65535, so this is a backstop against a pathological run rather than an
/// expected limit.
const HELD_CAPACITY: usize = 4096;

fn remember_connection(port: i64, client: &str, at: i64) {
    let Ok(mut held) = held_connections().lock() else { return };
    if held.len() >= HELD_CAPACITY {
        held.retain(|_, (_, seen)| at - *seen <= HELD_TTL_SECONDS);
        if held.len() >= HELD_CAPACITY {
            return; // still full: drop the new entry rather than grow without bound
        }
    }
    held.insert(port, (client.to_string(), at));
}

fn recall_connection(port: i64, at: i64) -> Option<String> {
    let Ok(held) = held_connections().lock() else { return None };
    let (client, seen) = held.get(&port)?;
    if at - *seen > HELD_TTL_SECONDS {
        return None;
    }
    Some(client.clone())
}

fn forget_connection(port: i64) {
    if let Ok(mut held) = held_connections().lock() {
        held.remove(&port);
    }
}

/// Whether this line is the last one a connection will produce.
fn closes_connection(e: &Value) -> bool {
    matches!(
        e.get("message").and_then(Value::as_str),
        Some("FINISH") | Some("END_ON_ERR")
    )
}

/// hellpot.json: REMOTE_ADDR is a single "ip:port" string (fasthttp's
/// RemoteAddr()). No destination-port field; every event is HTTP by
/// definition (a single-protocol tarpit).
/// hellpot's Traefik-facing listen port, as its own `DST_PORT` field
/// reports it. Same job as GALAH_PROXIED_PORT: a
/// port portbridge never dials, so the path is a fact rather than an
/// inference. Also spelled in hellpot's xff_trust_patch.py, hellpot's
/// compose.yml, and the socat dial target in vps/docker-compose.yml;
/// hellpot/tests/test_xff_trust_patch.py asserts those agree with this one
/// (#2192) instead of a keep-in-step comment hoping they do.
const HELLPOT_PROXIED_PORT: &str = "8090";

pub fn enrich_hellpot_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(remote_addr) = e.get("REMOTE_ADDR").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) else {
        return (line.to_vec(), true); // not a per-request line
    };

    let mut changed = false;
    changed |= set_if_changed(&mut e, "sensor", "hellpot");
    changed |= set_if_changed(&mut e, "protocol", "HTTP");
    if let Some(url) = e.get("URL").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "path", url);
    }
    if let Some(ua) = e.get("USERAGENT").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "user_agent", ua);
    }
    changed |= super::attck::promote_attck_technique_fields("hellpot", &mut e);

    let Some((ip, port_str)) = split_host_port(&remote_addr) else {
        return (marshal_if_changed(line, &e, changed), true); // malformed REMOTE_ADDR
    };
    changed |= mark_probe_from(&mut e, &ip);

    if ip != crate::fleet::tunnel_peer_ip() {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    // #1908: which door, before which evidence.
    //
    // #1876 left this asking portbridge and falling back to the header when
    // portbridge had nothing -- right on the raw path, and unsound on the
    // proxied one. The map is keyed by port alone over a six-hour window,
    // so "portbridge has an entry for socat's ephemeral source port" is a
    // coincidence there rather than an answer, and under this traffic a
    // likely one. It would then quietly file the request against an
    // unrelated attacker, which reads exactly like a correct result.
    //
    // The two doors are separate ports now (xff_trust_patch.py), so the
    // question is answered rather than inferred.
    if e.get("DST_PORT").and_then(Value::as_str) == Some(HELLPOT_PROXIED_PORT) {
        // Cloudflare -> Traefik is the only route to this port, so the
        // chain is the evidence, and no join is attempted at all.
        let Some(client) = forwarded_claim(&e) else {
            changed |= set_if_changed(&mut e, "src_ip", ip);
            return (marshal_if_changed(line, &e, changed), false);
        };
        e["REMOTE_ADDR"] = Value::from(join_host_port(&client, &port_str));
        changed |= set_if_changed(&mut e, "src_ip", client);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // #1876: the dial first, then what this connection already resolved to.
    //
    // Both are the same join -- portbridge's record of who it relayed --
    // one read live and one read from when this connection opened. The
    // live map is preferred where it still holds the entry; the memory
    // covers the case it cannot, which is a hold longer than the map's
    // window.
    // Every mechanism that can speak, then one rule to decide between them.
    //
    // The live dial map and this connection's remembered answer are the
    // same join read two ways -- one current, one from when the connection
    // opened -- so the memory is a fallback rather than a rival. The header
    // is a different mechanism entirely, and adjudicate_source ranks it.
    let at = extract_line_time(&e);
    // #3573: the raw door's DST_PORT is portbridge's target port (8080), so
    // it narrows the join; the line's own time is the anchor, since hellpot
    // writes NEW the moment the connection opens and every later line of the
    // connection resolves from the memory below instead.
    let query = JoinQuery {
        via_port: port,
        at,
        want_port: e.get("DST_PORT").and_then(Value::as_str).and_then(|p| p.parse().ok()).unwrap_or(0),
        transport: Transport::Tcp,
    };
    let join = resolve(vm, query);
    let joined = match join {
        Join::Attributed(real) => Some(real.to_string()),
        _ => None,
    };
    let relayed = joined.clone().or_else(|| recall_connection(port, at));
    let verdict = adjudicate_source(&ip, relayed, forwarded_claim(&e));

    if !verdict.resolved {
        changed |= mark_join(&mut e, &join);
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), join == Join::Ambiguous);
    }
    let from_join = joined.as_deref() == Some(verdict.ip.as_str());
    if from_join {
        mark_join(&mut e, &join);
    }

    if closes_connection(&e) {
        // Nothing further will be written for this connection, so the
        // entry stops being a memory and starts being a leak.
        forget_connection(port);
    } else {
        remember_connection(port, &verdict.ip, at);
    }

    e["REMOTE_ADDR"] = Value::from(join_host_port(&verdict.ip, &port_str));
    e["src_port"] = Value::from(port);
    apply_verdict(&mut e, &verdict);
    (marshal_if_changed(line, &e, true), !from_join || settled(vm, at))
}

/// galah's event_log.json: flat srcIP/srcPort fields already. Promotes
/// body_sha256 from httpRequest.bodySha256 and dst_port from the server's
/// own "port" string. srcHost/tags (galah's own pre-join enrichment,
/// looked up against the tunnel peer address) are deliberately left
/// untouched, not deleted, not trusted.
/// galah's Traefik-facing listen port, as it appears in the sensor's own
/// `port` field.
///
/// Its whole job is to be a port portbridge never dials, so that "which
/// door did this come through" is answerable from the log line instead of
/// inferred. Changing it means changing galah's config.yaml `ports:` list
/// and the socat target in vps/docker-compose.yml at the same time; leaving
/// it merely wrong makes proxied requests fall back to the raw-port branch,
/// where they resolve to the tunnel address rather than to anything untrue.
const GALAH_PROXIED_PORT: &str = "8890";

pub fn enrich_galah_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    if e.get("msg").and_then(Value::as_str) != Some("successfulResponse") {
        return (line.to_vec(), true); // not a per-request event line
    }

    let mut changed = false;
    changed |= set_if_changed(&mut e, "sensor", "galah");
    changed |= set_if_changed(&mut e, "protocol", "HTTP");
    if let Some(dst) = e.get("port").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "dst_port", dst);
    }
    if let Some(hr) = e.get("httpRequest").cloned().filter(Value::is_object) {
        if let Some(req) = hr.get("request").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            changed |= set_if_changed(&mut e, "path", req);
        }
        if let Some(ua) = hr.get("userAgent").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            changed |= set_if_changed(&mut e, "user_agent", ua);
        }
        if let Some(sha) = hr.get("bodySha256").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            changed |= set_if_changed(&mut e, "body_sha256", sha);
        }
    }
    changed |= super::attck::promote_attck_technique_fields("galah", &mut e);

    let ip = e.get("srcIP").and_then(Value::as_str).unwrap_or("").to_string();
    changed |= mark_probe_from(&mut e, &ip);
    if ip != crate::fleet::tunnel_peer_ip() {
        if !ip.is_empty() {
            changed |= set_if_changed(&mut e, "src_ip", ip);
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    // Which of galah's two front doors this arrived at decides what counts
    // as evidence, so the listen port is read before anything else.
    //
    // The two doors used to be one, and that is the whole defect behind
    // #1891. Traefik and portbridge both landed on :8888 and both dial from
    // the tunnel address, so a request that had crossed Cloudflare and one
    // sent straight at the raw port were indistinguishable by the time a
    // sensor or this worker saw them. Everything downstream was then a
    // guess. galah takes a `ports:` list natively, so the doors are simply
    // separate now (config.yaml, and the socat in vps/docker-compose.yml).
    if e.get("port").and_then(Value::as_str) == Some(GALAH_PROXIED_PORT) {
        // Only Traefik can reach this port. It is published on the
        // WireGuard address, no portbridge rule targets it, and the sole
        // dialler is socat-hp-galah -- so the Cloudflare -> Traefik chain
        // is the only way a request arrives, and what that chain says about
        // the client is the best evidence available. A via_port join is
        // deliberately *not* attempted: portbridge never carried this
        // connection, so any entry matching socat's ephemeral source port
        // would be a coincidence, and the map keeps six hours of them.
        let Some(client) = forwarded_claim(&e) else {
            changed |= set_if_changed(&mut e, "src_ip", ip);
            return (marshal_if_changed(line, &e, changed), false);
        };
        e["srcIP"] = Value::from(client.clone());
        changed |= set_if_changed(&mut e, "src_ip", client);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = e.get("srcPort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // The raw port: portbridge relayed this, so its connection log knows
    // who dialled, and a forwarding header is just bytes the attacker
    // chose to send. #1511 had it the other way round -- galah's own
    // xff_trust_patch.py rewrote srcIP from X-Forwarded-For whenever
    // RemoteAddr was the tunnel peer, which on this port is *always*.
    // Confirmed against the running stack before removing it: a request to
    // the raw port carrying `X-Forwarded-For: 198.51.100.77` was stored
    // with that as source.ip, so anyone could file their traffic under any
    // address they liked. Same defect as #1883, in the code #1883 was
    // copied from.
    //
    // portbridge's record wins here because it is evidence *about* the
    // connection rather than content carried inside it. A header that
    // disagrees is kept and flagged rather than dropped: on this path a
    // contradiction is someone trying the above, which is worth seeing.
    let at = extract_line_time(&e);
    // #3573: galah's `port` is the listen port portbridge dials (8888).
    let query = JoinQuery {
        via_port: port,
        at,
        want_port: e.get("port").and_then(Value::as_str).and_then(|p| p.parse().ok()).unwrap_or(0),
        transport: Transport::Tcp,
    };
    let join = resolve(vm, query);
    let relayed = match join {
        Join::Attributed(real) => Some(real.to_string()),
        _ => None,
    };
    let verdict = adjudicate_source(&ip, relayed.clone(), forwarded_claim(&e));

    if !verdict.resolved {
        changed |= mark_join(&mut e, &join);
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), join == Join::Ambiguous);
    }
    let from_join = relayed.as_deref() == Some(verdict.ip.as_str());
    if from_join {
        mark_join(&mut e, &join);
    }

    e["srcIP"] = Value::from(verdict.ip.clone());
    e["src_port"] = Value::from(port);
    apply_verdict(&mut e, &verdict);
    (marshal_if_changed(line, &e, true), !from_join || settled(vm, at))
}

/// sentrypeer.json: "source_ip" is a single "ip:port" string, same shape
/// as hellpot's REMOTE_ADDR. No destination-port field: "destination_ip"
/// is a fixed bind-address string, not the real per-request listen port.
pub fn enrich_sentrypeer_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(source_addr) = e.get("source_ip").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) else {
        return (line.to_vec(), true);
    };

    let mut changed = false;
    changed |= set_if_changed(&mut e, "sensor", "sentrypeer");
    changed |= set_if_changed(&mut e, "protocol", "SIP");
    if let Some(ua) = e.get("sip_user_agent").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "user_agent", ua);
    }
    changed |= super::attck::promote_attck_technique_fields("sentrypeer", &mut e);

    let Some((ip, port_str)) = split_host_port(&source_addr) else {
        return (marshal_if_changed(line, &e, changed), true);
    };
    changed |= mark_probe_from(&mut e, &ip);

    if ip != crate::fleet::tunnel_peer_ip() {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // #3573: SIP over UDP is the common case here, and a UDP session keeps
    // its via_port for as long as it stays active, so `transport_type` decides
    // which window applies.
    let at = extract_line_time(&e);
    let transport = e.get("transport_type").and_then(Value::as_str).map(Transport::parse).unwrap_or_default();
    let join = resolve(vm, JoinQuery { via_port: port, at, want_port: 0, transport });
    changed |= mark_join(&mut e, &join);
    let Join::Attributed(real) = join else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), join == Join::Ambiguous);
    };
    let real = real.to_string();

    e["source_ip"] = Value::from(join_host_port(&real, &port_str));
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), settled(vm, at))
}

/// net.SplitHostPort equivalent for the plain "ip:port" shape every
/// bespoke sensor here uses (no IPv6 brackets in any real captured line).
fn split_host_port(addr: &str) -> Option<(String, String)> {
    // IPv6 arrives bracketed. Go renders a v6 peer as "[::1]:1234", and
    // rsplit_once(':') leaves the brackets welded to the address -- so the
    // result matched no loopback constant, parsed as no IpAddr, and would
    // have been written into src_ip as "[::1]" for everything downstream
    // to trip over.
    //
    // Found by #1918's own IPv6 test rather than by a report: a v6 client
    // is rare enough against these sensors that nothing had exercised the
    // path, which is exactly how it stayed wrong quietly.
    if let Some(rest) = addr.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        if ip.is_empty() || port.is_empty() {
            return None;
        }
        return Some((ip.to_string(), port.to_string()));
    }
    let (ip, port) = addr.rsplit_once(':')?;
    if ip.is_empty() || port.is_empty() {
        return None;
    }
    Some((ip.to_string(), port.to_string()))
}

fn join_host_port(ip: &str, port: &str) -> String {
    format!("{ip}:{port}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn loopback_source_is_marked_as_an_internal_probe() {
        // #1677: every sensor here is fronted by a Docker healthcheck that
        // connects to its own listening port, and the sensor logs it exactly
        // as it logs a real connection.
        let line = json!({"src_ip": "127.0.0.1", "src_port": 37253, "sensor": "sentrypeer"}).to_string();
        let (out, resolved) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "sentrypeer");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
        assert!(resolved, "a probe is terminal, never queued for retry");
    }

    #[test]
    fn ipv6_loopback_counts_too() {
        let line = json!({"src_ip": "::1", "src_port": 1, "sensor": "http-honeypot"}).to_string();
        let (out, _) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "http-honeypot");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn a_real_attacker_is_never_marked() {
        let line = json!({"src_ip": "223.123.126.43", "src_port": 44321, "sensor": "cowrie"}).to_string();
        let (out, _) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "cowrie");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert!(e.get("internal_probe").is_none(), "only loopback is a probe");
        assert_eq!(e["src_ip"], json!("223.123.126.43"), "and the address is untouched");
    }

    #[test]
    fn marking_a_probe_does_not_rewrite_its_address() {
        // The address is the evidence that this was self-generated. Enriching
        // it away would turn a probe into a plausible-looking attack.
        let line = json!({"src_ip": "127.0.0.1", "src_port": 502, "sensor": "conpot"}).to_string();
        let (out, _) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "conpot");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["src_ip"], json!("127.0.0.1"));
        assert_eq!(e["internal_probe"], json!(true));
    }


    use super::*;
    use serde_json::json;

    // ── #3212: the capture fields survive the normalization pass ────────────
    //
    // The sensor-side tests prove the fields are emitted and byte-exact. This
    // proves they survive the one pass between the sensor and Elasticsearch:
    // http-honeypot has no bespoke enrich function, so the generic
    // enrich_line is the whole normalization, and filebeat tails the
    // enriched copy rather than the raw log (filebeat.yml's honeypot-json
    // input: only /logs/enriched/*.json is tailed for this decoy). A field
    // this pass dropped would never reach the index, and the backend's
    // record inspector -- which renders _source verbatim -- would have
    // nothing to show for it.

    #[test]
    fn the_capture_fields_survive_the_normalization_pass() {
        let line = json!({
            "sensor": "http-honeypot",
            "src_ip": "203.0.113.9",
            "src_port": 44321,
            "time": "2026-09-27T12:00:00Z",
            "body_capture_state": "truncated",
            "body_captured_bytes": 65536,
            "body_encoding": "base64",
            "body_b64": "rO0ABQ==",
            "body_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "body_sha256_scope": "captured-prefix-redacted",
            "body_declared_bytes": 4194304,
            "body_read_error": "unexpected EOF",
            "java_marker": "stream-magic"
        })
        .to_string();
        let (out, resolved) =
            enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "http-honeypot");
        assert!(resolved, "a complete event is never queued for retry");
        let out: Value = serde_json::from_slice(&out).unwrap();
        for key in [
            "body_capture_state",
            "body_captured_bytes",
            "body_encoding",
            "body_b64",
            "body_sha256",
            "body_sha256_scope",
            "body_declared_bytes",
            "body_read_error",
            "java_marker",
        ] {
            assert!(
                out.get(key).is_some(),
                "{key} did not survive the normalization pass: {out}"
            );
        }
        assert_eq!(out["body_capture_state"], json!("truncated"));
        assert_eq!(out["body_sha256_scope"], json!("captured-prefix-redacted"));
        assert_eq!(out["java_marker"], json!("stream-magic"));
    }

    fn vm_with(port: i64, ip: &str) -> ViaMap {
        let mut m = ViaMap::new();
        // at 0 so these keep exercising the join itself rather than
        // #1771's plausibility checks, which have their own tests in viamap.
        m.insert(port, vec![super::super::viamap::ViaEntry {
            // target_port 0 opts these fixtures out of #1917's
            // destination-port check; the tests that exercise it build
            // their own entries with a real port.
            ip: ip.to_string(), ..Default::default()
        }]);
        m
    }

    #[test]
    fn generic_enrich_resolves_tunnel_peer_via_viamap() {
        let line = json!({"src_ip": TUNNEL_PEER_IP, "src_port": 4000, "sensor": "cowrie"}).to_string();
        let vm = vm_with(4000, "203.0.113.5");
        let (out, resolved) = enrich_line(line.as_bytes(), &vm, &ViaMap::new(), "cowrie");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["src_ip"], "203.0.113.5");
    }

    #[test]
    fn generic_enrich_reports_unresolved_on_via_port_miss() {
        let line = json!({"src_ip": TUNNEL_PEER_IP, "src_port": 4000}).to_string();
        let (_out, resolved) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "cowrie");
        assert!(!resolved);
    }

    #[test]
    fn already_correct_ip_passes_through_unresolved_flag_true() {
        let line = json!({"src_ip": "198.51.100.9"}).to_string();
        let (_out, resolved) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "multipot");
        assert!(resolved);
    }

    #[test]
    fn dionaea_incident_rewrites_nested_remote_ip() {
        let line = json!({
            "origin": "dionaea.connection.tcp.accept",
            "data": {"connection": {"remote_ip": TUNNEL_PEER_IP, "remote_port": 5000}}
        })
        .to_string();
        let vm = vm_with(5000, "203.0.113.7");
        let (out, resolved) = enrich_dionaea_incident_line(line.as_bytes(), &vm, &ViaMap::new(), "dionaea-incident");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["data"]["connection"]["remote_ip"], "203.0.113.7");
    }

    #[test]
    fn beelzebub_line_flattens_nested_event_and_joins_ip() {
        let line = json!({"event": {"Protocol": "ssh", "SourceIp": TUNNEL_PEER_IP, "SourcePort": "4000", "User": "root", "Password": "toor"}}).to_string();
        let vm = vm_with(4000, "203.0.113.11");
        let (out, resolved) = enrich_beelzebub_line(line.as_bytes(), &vm, &ViaMap::new(), "beelzebub");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["src_ip"], "203.0.113.11");
        assert_eq!(out["canonical_user"], "root");
    }

    #[test]
    fn hellpot_line_splits_combined_remote_addr() {
        let line = json!({"REMOTE_ADDR": format!("{TUNNEL_PEER_IP}:4000"), "URL": "/", "USERAGENT": "curl/8"}).to_string();
        let vm = vm_with(4000, "203.0.113.12");
        let (out, resolved) = enrich_hellpot_line(line.as_bytes(), &vm, &ViaMap::new(), "hellpot");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["src_ip"], "203.0.113.12");
        assert_eq!(out["REMOTE_ADDR"], "203.0.113.12:4000");
    }

    // ---- #1876: the adjudication rule, and the tarpit's connection memory.

    fn hellpot_line(remote: &str, xff: Option<&str>, message: &str) -> Vec<u8> {
        let mut e = serde_json::json!({
            "level": "info",
            "REMOTE_ADDR": remote,
            "URL": "/wp-login.php",
            "USERAGENT": "curl/8.18.0",
            "message": message,
            "time": "2026-08-24T20:00:00Z",
        });
        if let Some(xff) = xff {
            e["XFF"] = Value::from(xff);
        }
        serde_json::to_vec(&e).unwrap()
    }

    /// #3573: a join is only final once the map has read past the line's
    /// window, so fixtures that expect a final answer feed one unrelated,
    /// later dial -- as the live log always does within seconds.
    fn read_past(vm: &mut ViaMap, at: &str) {
        super::super::viamap::parse_portbridge_line(
            serde_json::to_vec(&serde_json::json!({
                "sensor": "portbridge", "event": "connect",
                "src_ip": "198.51.100.250", "via_port": 1, "time": at,
            }))
            .unwrap()
            .as_slice(),
            vm,
        );
    }

    fn field(out: &[u8], key: &str) -> Option<String> {
        let e: Value = serde_json::from_slice(out).unwrap();
        e.get(key).and_then(Value::as_str).map(str::to_string)
    }

    #[test]
    fn the_connection_wins_over_a_contradicting_header() {
        // On a relayed path the header is attacker-authored, so a
        // disagreement is a spoof attempt rather than a puzzle -- and it is
        // kept, because discarding it would erase the attempt.
        let verdict = adjudicate_source(
            TUNNEL_PEER_IP,
            Some("203.0.113.7".into()),
            Some("198.51.100.9".into()),
        );
        assert_eq!(verdict.ip, "203.0.113.7");
        assert_eq!(verdict.claimed.as_deref(), Some("198.51.100.9"));
        assert!(verdict.resolved);
    }

    #[test]
    fn agreement_is_not_recorded_as_a_conflict() {
        let verdict = adjudicate_source(
            TUNNEL_PEER_IP,
            Some("203.0.113.7".into()),
            Some("203.0.113.7".into()),
        );
        assert_eq!(verdict.ip, "203.0.113.7");
        assert!(verdict.claimed.is_none());
    }

    #[test]
    fn the_header_answers_when_portbridge_never_saw_the_connection() {
        let verdict = adjudicate_source(TUNNEL_PEER_IP, None, Some("198.51.100.9".into()));
        assert_eq!(verdict.ip, "198.51.100.9");
        assert!(verdict.claimed.is_none());
        assert!(verdict.resolved);
    }

    #[test]
    fn nothing_answering_leaves_the_line_for_retry() {
        let verdict = adjudicate_source(TUNNEL_PEER_IP, None, None);
        assert!(!verdict.resolved, "the tunnel peer is our own address, not a source");
    }

    #[test]
    fn a_source_preserved_connection_ignores_any_header() {
        // RemoteAddr is already the attacker; no header may override what
        // the connection itself shows.
        let verdict = adjudicate_source("203.0.113.7", None, Some("198.51.100.9".into()));
        assert_eq!(verdict.ip, "203.0.113.7");
    }

    #[test]
    fn the_hop_cloudflare_appended_wins_not_the_last_one() {
        // This test used to assert the last hop, on the reasoning that
        // Cloudflare appends the real client to whatever the client sent,
        // so the attacker's own value ends up left of the truth. The first
        // half is right and the conclusion does not follow: Traefik sits
        // behind Cloudflare and appends the peer *it* saw, which is a
        // Cloudflare edge node. So the chain ends one hop past the client.
        //
        // Not a hypothetical -- a request through the live subdomain
        // arrived as `<client>, 172.69.150.126`, and every proxied galah
        // event had been filed against addresses like that one.
        let e: Value = serde_json::json!({"XFF": "1.2.3.4, 198.51.100.9, 172.69.150.126"});
        assert_eq!(forwarded_claim(&e).as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn a_lone_hop_is_taken_as_it_stands() {
        // Nothing appended anything, so there is no proxy entry to skip
        // past. hellpot's own patch records the header verbatim and can
        // see chains this short.
        let e: Value = serde_json::json!({"XFF": "198.51.100.9"});
        assert_eq!(forwarded_claim(&e).as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn a_header_that_is_not_an_address_is_not_evidence() {
        let e: Value = serde_json::json!({"XFF": "not-an-address"});
        assert!(forwarded_claim(&e).is_none());
        let empty: Value = serde_json::json!({});
        assert!(forwarded_claim(&empty).is_none());
    }

    #[test]
    fn a_tarpit_hold_longer_than_the_dial_window_still_attributes_on_close() {
        // The residue this exists for: HellPot held connections for 26 and
        // 60 hours, and viamap accepts a dial for six. The opening line
        // resolves against the live map; the closing line, days later, has
        // only what the connection already resolved to.
        let port = 60001_i64;
        forget_connection(port);
        let mut vm: ViaMap = ViaMap::new();
        super::super::viamap::parse_portbridge_line(
            serde_json::to_vec(&serde_json::json!({
                "sensor": "portbridge", "event": "connect",
                "src_ip": "203.0.113.7", "via_port": port,
                "time": "2026-08-24T20:00:00Z",
            }))
            .unwrap()
            .as_slice(),
            &mut vm,
        );
        read_past(&mut vm, "2026-08-24T20:00:10Z");

        let addr = format!("{TUNNEL_PEER_IP}:{port}");
        let (opened, resolved) = enrich_hellpot_line(&hellpot_line(&addr, None, "NEW"), &vm, &ViaMap::new(), "hellpot");
        assert!(resolved, "the opening line must resolve against the live map");
        assert_eq!(field(&opened, "src_ip").as_deref(), Some("203.0.113.7"));

        // The dial has aged out entirely by the time the tarpit lets go.
        let (closed, resolved) =
            enrich_hellpot_line(&hellpot_line(&addr, None, "FINISH"), &ViaMap::new(), &ViaMap::new(), "hellpot");
        assert!(resolved, "the closing line must not be left unattributed");
        assert_eq!(
            field(&closed, "src_ip").as_deref(),
            Some("203.0.113.7"),
            "the closing line must carry the answer the connection already had"
        );
    }

    #[test]
    fn a_closed_connection_is_forgotten_so_a_reused_port_is_not_mistaken() {
        let port = 60002_i64;
        forget_connection(port);
        let addr = format!("{TUNNEL_PEER_IP}:{port}");

        // Drive the real path rather than seeding the memory by hand, so
        // the remembered timestamp is the one the code itself would store.
        let mut vm: ViaMap = ViaMap::new();
        super::super::viamap::parse_portbridge_line(
            serde_json::to_vec(&serde_json::json!({
                "sensor": "portbridge", "event": "connect",
                "src_ip": "203.0.113.7", "via_port": port,
                "time": "2026-08-24T20:00:00Z",
            }))
            .unwrap()
            .as_slice(),
            &mut vm,
        );
        read_past(&mut vm, "2026-08-24T20:00:10Z");
        let (_, resolved) = enrich_hellpot_line(&hellpot_line(&addr, None, "NEW"), &vm, &ViaMap::new(), "hellpot");
        assert!(resolved, "the opening line must resolve");

        let (_, resolved) =
            enrich_hellpot_line(&hellpot_line(&addr, None, "FINISH"), &ViaMap::new(), &ViaMap::new(), "hellpot");
        assert!(resolved, "the closing line resolves from the memory");

        // Same port, a later connection, nothing to join against: it must
        // not inherit the previous connection's client.
        let (out, resolved) =
            enrich_hellpot_line(&hellpot_line(&addr, None, "NEW"), &ViaMap::new(), &ViaMap::new(), "hellpot");
        assert!(!resolved, "a reused port must not resolve from a closed connection");
        assert_eq!(field(&out, "src_ip").as_deref(), Some(TUNNEL_PEER_IP));
    }

    // ---- galah: which door a request came through (#1891) ----

    /// A galah line as the sensor writes one, with the headers it records.
    fn galah_line(listen_port: &str, src_port: &str, headers: Value) -> String {
        json!({
            "msg": "successfulResponse",
            "srcIP": TUNNEL_PEER_IP,
            "srcPort": src_port,
            "port": listen_port,
            "httpRequest": {"request": "/", "headers": headers},
        })
        .to_string()
    }

    #[test]
    fn a_forwarding_header_cannot_name_the_source_on_the_raw_port() {
        // The bug this whole change exists for. galah's own patch rewrote
        // srcIP from X-Forwarded-For whenever the peer was the tunnel
        // address -- which on the raw port is every single request -- so
        // sending the header was enough to choose your own identity.
        // Reproduced against the running stack before the fix: a request
        // carrying 198.51.100.77 was stored under exactly that address.
        let line = galah_line(
            "8888",
            "43112",
            json!({"X-Forwarded-For": "198.51.100.77"}),
        );
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &vm_with(43112, "203.0.113.9"), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"), "portbridge saw who dialled");
        // Kept rather than dropped: on this path the header is somebody
        // trying the above, and that is worth having in the record.
        assert_eq!(e["src_ip_claimed"], json!("198.51.100.77"));
        assert_eq!(e["src_ip_conflict"], json!(true));
    }

    #[test]
    fn the_raw_port_still_resolves_ordinary_traffic() {
        // Most galah traffic carries no forwarding header at all; the join
        // has to go on working exactly as before.
        let line = galah_line("8888", "51982", json!({"User-Agent": "curl/7.68.0"}));
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &vm_with(51982, "45.79.207.110"), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("45.79.207.110"));
        assert!(e.get("src_ip_conflict").is_none(), "nothing contradicted it");
    }

    #[test]
    fn the_proxied_port_reads_the_client_not_cloudflares_edge() {
        // Traefik appends the peer *it* saw, which is a Cloudflare edge
        // node, so the last hop of the chain is never the attacker.
        // Measured live: `<client>, 172.69.150.126`. #1511 took that last
        // hop, which is why Cloudflare addresses turned up in galah's
        // source list looking like ordinary traffic.
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34228",
            json!({"X-Forwarded-For": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn a_client_cannot_prepend_its_way_into_the_answer() {
        // Cloudflare appends the address it accepted the connection from,
        // so anything the client wrote itself stays to the left of it and
        // is never what gets read.
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34229",
            json!({"X-Forwarded-For": "198.51.100.77, 203.0.113.9, 172.69.150.126"}),
        );
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the hop Cloudflare appended");
    }

    #[test]
    fn cf_connecting_ip_is_preferred_where_cloudflare_set_it() {
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34230",
            json!({
                "Cf-Connecting-Ip": "203.0.113.9",
                "X-Forwarded-For": "198.51.100.77, 172.69.150.126",
            }),
        );
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn the_proxied_port_never_joins_against_portbridge() {
        // portbridge does not carry this connection, so socat's ephemeral
        // source port matching an entry is a coincidence -- and with six
        // hours of history per port under this traffic, a likely one.
        // Taking it would swap in an unrelated attacker's address.
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34228",
            json!({"X-Forwarded-For": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, _) = enrich_galah_line(
            line.as_bytes(), &vm_with(34228, "198.51.100.77"), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the colliding entry is ignored");
    }

    #[test]
    fn a_header_name_in_any_case_is_still_the_same_header() {
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34231",
            json!({"x-forwarded-for": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn a_proxied_request_with_no_chain_is_left_unresolved() {
        // Nothing to read and nothing to join against. Retrying later is
        // right; inventing an address is not.
        let line = galah_line(GALAH_PROXIED_PORT, "34232", json!({"User-Agent": "curl/8"}));
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(!resolved);
        assert_eq!(e["src_ip"], json!(TUNNEL_PEER_IP));
    }

    #[test]
    fn garbage_in_the_chain_does_not_become_a_source() {
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34233",
            json!({"X-Forwarded-For": "not-an-address, 172.69.150.126"}),
        );
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(!resolved);
        assert_eq!(e["src_ip"], json!(TUNNEL_PEER_IP));
    }

    // ---- hellpot: the same two doors (#1908) ----

    #[test]
    fn hellpot_resolves_the_proxied_door_from_the_chain() {
        let line = json!({
            "REMOTE_ADDR": format!("{}:44520", TUNNEL_PEER_IP),
            "DST_PORT": HELLPOT_PROXIED_PORT,
            "XFF": "203.0.113.9, 172.69.150.126",
            "URL": "/",
        })
        .to_string();
        let (out, resolved) = enrich_hellpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"), "not Cloudflare's edge");
        assert_eq!(e["REMOTE_ADDR"], json!("203.0.113.9:44520"));
    }

    #[test]
    fn hellpot_does_not_join_the_proxied_door_against_portbridge() {
        // The reason the door had to become a fact: this entry matches
        // socat's ephemeral source port by coincidence, and taking it
        // would file the request against an unrelated attacker.
        let line = json!({
            "REMOTE_ADDR": format!("{}:44520", TUNNEL_PEER_IP),
            "DST_PORT": HELLPOT_PROXIED_PORT,
            "XFF": "203.0.113.9, 172.69.150.126",
            "URL": "/",
        })
        .to_string();
        let (out, _) = enrich_hellpot_line(
            line.as_bytes(), &vm_with(44520, "198.51.100.77"), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the colliding entry is ignored");
    }

    #[test]
    fn hellpot_still_joins_the_raw_door() {
        let line = json!({
            "REMOTE_ADDR": format!("{}:44521", TUNNEL_PEER_IP),
            "DST_PORT": "8080",
            "URL": "/",
        })
        .to_string();
        let (out, resolved) = enrich_hellpot_line(
            line.as_bytes(), &vm_with(44521, "45.79.207.110"), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("45.79.207.110"));
    }

    // ---- #1918: every enricher marks its own healthchecks ----
    //
    // The generic enrich_line always did. The per-sensor enrichers never
    // did, and nothing noticed because the symptom is an absence: the
    // event is correctly kept out of source.ip, and simply never flagged,
    // so it lands in the unattributed residue looking like a sensor that
    // could not be attributed. 2,879 loopback events in 24h were sitting
    // there, 2,857 of them sentrypeer's.
    //
    // A test per sensor rather than one on the shared helper, because the
    // defect was never in the rule -- it was that each enricher has to opt
    // in, and four of them had not. A helper test would have passed
    // throughout.

    #[test]
    fn sentrypeer_healthchecks_are_marked_as_probes() {
        // sentrypeer writes source_ip as "ip:port", and its healthcheck is
        // a bare TCP connect: no SIP method, no message, no called number.
        let line = json!({
            "app_name": "sentrypeer",
            "source_ip": "127.0.0.1:44577",
            "destination_ip": "0.0.0.0:5060",
            "sip_method": "",
            "transport_type": "TCP",
        })
        .to_string();
        let (out, resolved) = enrich_sentrypeer_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "sentrypeer",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["internal_probe"], json!(true));
        assert!(resolved, "a probe is terminal, never queued for retry");
        // The address stays: it is the evidence that this was ours.
        assert_eq!(e["src_ip"], json!("127.0.0.1"));
    }

    #[test]
    fn hellpot_healthchecks_are_marked_as_probes() {
        let line = json!({"REMOTE_ADDR": "127.0.0.1:51234", "URL": "/"}).to_string();
        let (out, _) = enrich_hellpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn galah_healthchecks_are_marked_as_probes() {
        let line = json!({
            "msg": "successfulResponse",
            "srcIP": "127.0.0.1",
            "srcPort": "51235",
            "port": "8888",
            "httpRequest": {"request": "/"},
        })
        .to_string();
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn a_real_attacker_is_still_never_marked_by_the_per_sensor_enrichers() {
        // The other half. Flagging too eagerly would delete real traffic
        // from every view, which is worse than the bug being fixed.
        let line = json!({"app_name": "sentrypeer", "source_ip": "203.0.113.9:5060"}).to_string();
        let (out, _) = enrich_sentrypeer_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "sentrypeer",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(e.get("internal_probe").is_none());
        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn ipv6_loopback_counts_for_the_per_sensor_enrichers_too() {
        let line = json!({"REMOTE_ADDR": "[::1]:51237", "URL": "/"}).to_string();
        let (out, _) = enrich_hellpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    // ---- #1917, second half: dionaea's own healthchecks ----

    #[test]
    fn dionaea_loopback_connections_are_marked_as_probes() {
        // The residue that remained after the join was fixed, and the
        // actual content of "5,700 unattributed connections a day": they
        // are not unattributable, they are dionaea's healthcheck opening
        // smbd on 445 from 127.0.0.1 and being logged like an attacker.
        let line = json!({
            "timestamp": "2026-08-25T07:40:45.123456",
            "origin": "dionaea.connection.tcp.accept",
            "data": {"connection": {
                "protocol": "smbd",
                "local_ip": "127.0.0.1", "local_port": 445,
                "remote_ip": "127.0.0.1", "remote_port": 48894,
                "transport": "tcp",
            }},
        })
        .to_string();
        let (out, resolved) = enrich_dionaea_incident_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "dionaea-incident",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["internal_probe"], json!(true));
        assert!(resolved, "a probe is terminal, never queued for retry");
        // The address is left alone: it is what shows this was ours.
        assert_eq!(e["data"]["connection"]["remote_ip"], json!("127.0.0.1"));
    }

    #[test]
    fn a_real_dionaea_connection_is_never_marked_as_a_probe() {
        let line = json!({
            "origin": "dionaea.connection.tcp.accept",
            "data": {"connection": {
                "local_ip": "172.16.10.2", "local_port": 445,
                "remote_ip": "203.0.113.9", "remote_port": 44278,
            }},
        })
        .to_string();
        let (out, _) = enrich_dionaea_incident_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "dionaea-incident",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(e.get("internal_probe").is_none());
    }

    #[test]
    fn a_dionaea_connection_still_joins_on_its_destination_port() {
        // The other half of #1917, end to end through the real enricher:
        // two entries on one reused ephemeral port, and only the one whose
        // destination matches may answer.
        let mut vm = ViaMap::new();
        vm.insert(
            54674,
            vec![
                super::super::viamap::ViaEntry {
                    ip: "153.117.32.130".into(), target_port: 23, ..Default::default()
                },
                super::super::viamap::ViaEntry {
                    ip: "151.243.11.8".into(), target_port: 1433, ..Default::default()
                },
            ],
        );
        let line = json!({
            "origin": "dionaea.connection.tcp.accept",
            "data": {"connection": {
                "protocol": "mssqld",
                "local_ip": "172.16.10.2", "local_port": 1433,
                "remote_ip": TUNNEL_PEER_IP, "remote_port": 54674,
            }},
        })
        .to_string();
        let (out, resolved) = enrich_dionaea_incident_line(
            line.as_bytes(), &vm, &ViaMap::new(), "dionaea-incident",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(
            e["data"]["connection"]["remote_ip"],
            json!("151.243.11.8"),
            "the mssql dial, not the telnet client that reused the port",
        );
    }

    // ---- #3573: anchored, ambiguity-aware tunnel attribution ----

    fn pb(vm: &mut ViaMap, ip: &str, via_port: i64, time: &str, target: &str, proto: &str) {
        super::super::viamap::parse_portbridge_line(
            serde_json::to_vec(&json!({
                "sensor": "portbridge", "event": "connect", "proto": proto,
                "src_ip": ip, "via_port": via_port, "target": target, "time": time,
            }))
            .unwrap()
            .as_slice(),
            vm,
        );
    }

    fn cowrie(session: &str, port: i64, timestamp: &str, eventid: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "session": session, "protocol": "telnet", "src_ip": TUNNEL_PEER_IP, "src_port": port,
            "dst_port": 2223, "eventid": eventid, "sensor": "cowrie", "timestamp": timestamp,
        }))
        .unwrap()
    }

    #[test]
    fn a_tunnel_line_is_attributed_and_keeps_the_peer_it_saw() {
        let mut vm = ViaMap::new();
        pb(&mut vm, "203.0.113.40", 48132, "2026-10-09T23:31:44Z", "10.8.0.2:19023", "tcp");
        read_past(&mut vm, "2026-10-09T23:31:59Z");
        let (out, resolved) =
            enrich_line(&cowrie("3573a0000001", 48132, "2026-10-09T23:31:45.105167Z", "cowrie.session.connect"), &vm, &ViaMap::new(), "cowrie");
        assert!(resolved);
        assert_eq!(field(&out, "src_ip").as_deref(), Some("203.0.113.40"));
        assert_eq!(field(&out, "fleet_peer").as_deref(), Some(TUNNEL_PEER_IP));
        assert_eq!(field(&out, "tunnel_attribution").as_deref(), Some("portbridge"));
    }

    #[test]
    fn a_late_line_of_a_session_joins_on_when_the_session_opened() {
        // Ten minutes into the session the port is dialled again for an
        // unrelated connection. Joined on its own timestamp, the closing line
        // would pick that dial; anchored on the connect it cannot.
        let mut vm = ViaMap::new();
        pb(&mut vm, "203.0.113.41", 48133, "2026-10-09T23:00:00Z", "10.8.0.2:19023", "tcp");
        pb(&mut vm, "198.51.100.41", 48133, "2026-10-09T23:09:59Z", "10.8.0.2:445", "tcp");
        read_past(&mut vm, "2026-10-09T23:20:00Z");

        let (_, resolved) =
            enrich_line(&cowrie("3573a0000002", 48133, "2026-10-09T23:00:01Z", "cowrie.session.connect"), &vm, &ViaMap::new(), "cowrie");
        assert!(resolved);
        let (out, resolved) =
            enrich_line(&cowrie("3573a0000002", 48133, "2026-10-09T23:10:00Z", "cowrie.session.closed"), &vm, &ViaMap::new(), "cowrie");
        assert!(resolved);
        assert_eq!(field(&out, "src_ip").as_deref(), Some("203.0.113.41"), "not the 23:09:59 dial");
    }

    #[test]
    fn two_clients_on_the_port_leave_the_line_unattributed_and_say_so() {
        let mut vm = ViaMap::new();
        // Both telnet: the first connection closed within the second and the
        // port went straight to the next client. Nothing orders them.
        pb(&mut vm, "203.0.113.42", 48134, "2026-10-09T23:00:00Z", "10.8.0.2:19023", "tcp");
        pb(&mut vm, "198.51.100.42", 48134, "2026-10-09T23:00:01Z", "10.8.0.2:19023", "tcp");
        read_past(&mut vm, "2026-10-09T23:00:30Z");
        let (out, resolved) =
            enrich_line(&cowrie("3573a0000003", 48134, "2026-10-09T23:00:01.5Z", "cowrie.session.connect"), &vm, &ViaMap::new(), "cowrie");
        assert!(resolved, "ambiguity is final -- more of the log can only add rivals");
        assert_eq!(field(&out, "src_ip").as_deref(), Some(TUNNEL_PEER_IP));
        assert_eq!(field(&out, "tunnel_attribution").as_deref(), Some("ambiguous"));
        assert!(field(&out, "fleet_peer").is_none());
    }

    #[test]
    fn a_rival_on_another_service_is_ruled_out_by_cowries_own_port() {
        let mut vm = ViaMap::new();
        pb(&mut vm, "203.0.113.46", 48137, "2026-10-09T23:00:00Z", "10.8.0.2:19023", "tcp");
        pb(&mut vm, "198.51.100.46", 48137, "2026-10-09T23:00:01Z", "10.8.0.2:445", "tcp");
        read_past(&mut vm, "2026-10-09T23:00:30Z");
        let (out, _) =
            enrich_line(&cowrie("3573a0000006", 48137, "2026-10-09T23:00:01.5Z", "cowrie.session.connect"), &vm, &ViaMap::new(), "cowrie");
        assert_eq!(field(&out, "src_ip").as_deref(), Some("203.0.113.46"), "telnet on 2223 was dialled as 19023");
    }

    #[test]
    fn an_unmatched_line_waits_and_is_labelled_when_it_flushes() {
        let (out, resolved) =
            enrich_line(&cowrie("3573a0000004", 48135, "2026-10-09T23:00:00Z", "cowrie.session.connect"), &ViaMap::new(), &ViaMap::new(), "cowrie");
        assert!(!resolved, "queued: the dial may not have been read yet");
        assert_eq!(field(&out, "tunnel_attribution").as_deref(), Some("unmatched"));
    }

    #[test]
    fn an_answer_is_held_back_until_a_rival_could_no_longer_appear() {
        let mut vm = ViaMap::new();
        pb(&mut vm, "203.0.113.43", 48136, "2026-10-09T23:00:00Z", "10.8.0.2:19023", "tcp");
        let (out, resolved) =
            enrich_line(&cowrie("3573a0000005", 48136, "2026-10-09T23:00:01Z", "cowrie.session.connect"), &vm, &ViaMap::new(), "cowrie");
        assert!(!resolved, "retried until the map has read past the window");
        assert_eq!(field(&out, "src_ip").as_deref(), Some("203.0.113.43"), "but the flush still carries the answer");
    }

    #[test]
    fn a_conpot_snmp_flood_resolves_through_its_udp_session() {
        let mut vm = ViaMap::new();
        pb(&mut vm, "203.0.113.44", 38173, "2026-09-29T20:30:00Z", "10.8.0.2:19161", "udp");
        read_past(&mut vm, "2026-09-29T21:10:00Z");
        let line = serde_json::to_vec(&json!({
            "src_ip": TUNNEL_PEER_IP, "src_port": 38173, "dst_port": 161, "data_type": "snmp",
            "event_type": "SNMPv2 Bulk", "id": "3573-snmp-flood", "timestamp": "2026-09-29T21:02:34.307904",
        }))
        .unwrap();
        let (out, resolved) = enrich_line(&line, &vm, &ViaMap::new(), "conpot");
        assert!(resolved);
        assert_eq!(field(&out, "src_ip").as_deref(), Some("203.0.113.44"));
    }

    #[test]
    fn galahs_go_time_string_is_a_usable_time() {
        assert_eq!(
            parse_sensor_time("2026-09-29 08:51:15.402586836 +0200 CEST m=+485577.992530828"),
            parse_sensor_time("2026-09-29T06:51:15Z"),
        );
    }

    #[test]
    fn beelzebub_joins_on_its_events_own_time() {
        let mut vm = ViaMap::new();
        pb(&mut vm, "203.0.113.45", 56912, "2026-10-09T19:54:05Z", "10.8.0.2:389", "tcp");
        read_past(&mut vm, "2026-10-09T19:55:00Z");
        let line = |at: &str| {
            serde_json::to_vec(&json!({"event": {
                "Protocol": "TCP", "SourceIp": TUNNEL_PEER_IP, "SourcePort": "56912", "DateTime": at,
            }}))
            .unwrap()
        };
        let (out, resolved) = enrich_beelzebub_line(&line("2026-10-09T19:54:06Z"), &vm, &ViaMap::new(), "beelzebub");
        assert!(resolved);
        assert_eq!(field(&out, "src_ip").as_deref(), Some("203.0.113.45"));

        let (out, resolved) = enrich_beelzebub_line(&line("2026-10-09T21:54:06Z"), &vm, &ViaMap::new(), "beelzebub");
        assert!(!resolved, "two hours later the dial cannot be this connection's");
        assert_eq!(field(&out, "src_ip").as_deref(), Some(TUNNEL_PEER_IP));
    }
}
