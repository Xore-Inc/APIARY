//! attacker-identity-worker port (#1610 worker migration): the missing
//! piece #1204's gap analysis called out -- campaigns/clusters
//! (correlator-worker) are CIDR/fingerprint-bucket scoped and recomputed
//! from scratch every cycle; neither produces a durable attacker *entity*.
//! This does: it merges IPs into persistent `attackers-v1` entities when
//! they share >=2 of three strong signal categories (fingerprint, payload
//! sha256, credential pair) -- a single shared signal never merges two IPs
//! alone (the epic's own "decided up front" tunable). Entities are durable:
//! once created they're never deleted for going quiet, and membership only
//! grows -- the one exception is two previously-separate entities turning
//! out to share a member, which folds one into the other.
//!
//! Ported from honeypot-attacker-identity-worker/attacker-identity-worker/
//! (main.go/fetch.go/identity.go/verdicts.go/es.go). Pure ES, no host
//! mounts, no local state -- runs as the `attacker-identity` WORKER_LOOPS
//! entry on the existing (stateless-by-design) backend-worker service.

use crate::contract;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::Duration;

use crate::{
    events::{row_from_hit, EventsPage},
    AppState,
};

const ATTACKERS_INDEX: &str = "attackers-v1";
/// Ceiling on the *merge-candidate* half of a cycle's entity load (pass 2
/// of `load_candidate_entities`). A single popular credential pair can be
/// shared by a large slice of the population, so that pass needs a bound;
/// overflowing it costs a merge the next sighting will make again, never
/// stored history. Pass 1 -- the entities holding an IP this window
/// actually saw -- is deliberately not subject to it (#2651).
const MAX_MERGE_CANDIDATE_LOAD: usize = 20_000;
/// Terms per `terms` query. `index.max_terms_count` defaults to 65,536;
/// staying an order of magnitude under it leaves room for the noisiest
/// window (a 6h window on live data carries ~12k distinct credential
/// pairs) without ever having to reason about the limit.
const CANDIDATE_TERMS_CHUNK: usize = 4_096;
/// Pages of `CANDIDATE_PAGE_SIZE` per terms chunk.
const CANDIDATE_PAGE_SIZE: u64 = 10_000;
const CANDIDATE_MAX_PAGES: u32 = 10;
const MERGE_THRESHOLD: usize = 2;
const EVENT_PAGE_SIZE: u64 = 10_000;
const EVENT_MAX_PAGES: u32 = 50;
/// #2045: how many event pointers an entity keeps. "A few hundred" per the
/// proposal — enough to page real evidence behind even the noisiest
/// identity, small enough that absorb/merge stays cheap. Every pointer
/// comes from `honeypot-v2-*` (the only family fetch_recent_events reads),
/// so the evidence endpoint can resolve ids with one ids query over that
/// pattern and the persisted shape needs no per-entry index name.
const EVIDENCE_CAP: usize = 500;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn env_duration(name: &str, default: Duration) -> Duration {
    let raw = std::env::var(name).unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return default;
    }
    let (digits, unit) = raw.split_at(raw.len().saturating_sub(1));
    match (digits.parse::<u64>(), unit) {
        (Ok(n), "h") => Duration::from_secs(n * 3600),
        (Ok(n), "m") => Duration::from_secs(n * 60),
        (Ok(n), "s") => Duration::from_secs(n),
        _ => default,
    }
}

// --------------------------------------------------------------------
// fetch.go
// --------------------------------------------------------------------

struct CorrEvent {
    /// The event document's own `_id` (#2045): the evidence pointer the
    /// entity persists so its page can serve exact raw events instead of
    /// recomputing a bounded correlation per drill-in click.
    id: String,
    when: Option<chrono::DateTime<chrono::Utc>>,
    src_ip: String,
    sensor: String,
    /// #2047: destination shape — what makes "many hosts on few ports"
    /// vs "few hosts, many ports" distinguishable per IP without any
    /// query-time cardinality work.
    dst_ip: String,
    dst_port: String,
    protocol: String,
    user: String,
    pass: String,
    shasum: String,
    fingerprint: String,
    techniques: Vec<String>,
}

/// Ported verbatim from dashboard/links.go via fetch.go's own copy -- gates
/// which canonical_user/canonical_pass pairs count as a real credential
/// signal for entity merging.
/// #2047: destination.port arrives numeric or string depending on which
/// pipeline produced the doc; flatten both to their string form.
fn any_to_string(v: &serde_json::Value) -> String {
    if let Some(s) = v.as_str() {
        s.to_string()
    } else if let Some(n) = v.as_i64() {
        n.to_string()
    } else if let Some(f) = v.as_f64() {
        format!("{}", f as i64)
    } else {
        String::new()
    }
}

fn valid_credential_pair(user: &str, pass: &str) -> bool {
    if (user.is_empty() && pass.is_empty()) || user.len() > 128 || pass.len() > 512 {
        return false;
    }
    for value in [user, pass] {
        let lower = value.to_lowercase();
        if value.contains(['\0', '\r', '\n']) || lower.contains("\\x00") || lower.contains("\\u0000") {
            return false;
        }
    }
    if user.contains([' ', '\t', '/', ';', '|', '&', '<', '>']) {
        return false;
    }
    let lower_pass = pass.trim().to_lowercase();
    for marker in ["/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"] {
        if lower_pass.contains(marker) {
            return false;
        }
    }
    true
}

async fn fetch_recent_events(
    state: &AppState,
    since: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Vec<CorrEvent>> {
    let since_str = since.to_rfc3339();
    let hits = state
        .es
        .search_paginated(
            "honeypot-v2-*",
            |search_after| {
                let mut body = json!({
                    "sort": [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
                    "query": {"bool": {"filter": [
                        {"range": {"@timestamp": {"gte": since_str}}},
                        {"exists": {"field": "source.ip"}}
                    // #2145: this feed builds attacker identity entities; a
                    // probe doc that did carry a source.ip would otherwise
                    // merge fleet healthcheck activity into an identity.
                    ], "must_not": [crate::es::internal_probe_exclusion()]}},
                    "_source": [
                        "@timestamp", "source.ip", "event.sensor",
                        "destination.ip", "destination.port", "network.protocol",
                        "honeypot.canonical_user", "honeypot.canonical_pass", "honeypot.canonical_shasum",
                        "honeypot.canonical_fingerprint", "honeypot.canonical_attck_techniques"
                    ]
                });
                if let Some(sa) = search_after {
                    body["search_after"] = sa.clone();
                }
                body
            },
            EVENT_PAGE_SIZE,
            EVENT_MAX_PAGES,
        )
        .await?;

    // search_paginated stops silently once EVENT_MAX_PAGES is reached; a
    // completely full final page is indistinguishable from truncation by
    // anything cheaper than this equality, so say so when this cycle may
    // be building identities from a clipped window (#2043).
    if hits.len() as u64 >= EVENT_PAGE_SIZE * u64::from(EVENT_MAX_PAGES) {
        tracing::warn!(
            events = hits.len(),
            cap = EVENT_PAGE_SIZE * u64::from(EVENT_MAX_PAGES),
            "attacker-identity event fetch hit its pagination cap; entities built from a truncated window"
        );
    }

    let mut out = Vec::with_capacity(hits.len());
    for hit in hits {
        let src = &hit["_source"];
        let ip = src["source"]["ip"].as_str().unwrap_or("").to_string();
        if ip.is_empty() || ip == crate::fleet::tunnel_peer_ip() {
            continue;
        }
        let when = src["@timestamp"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let techniques = src["honeypot"]["canonical_attck_techniques"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        out.push(CorrEvent {
            id: hit["_id"].as_str().unwrap_or("").to_string(),
            when,
            src_ip: ip,
            sensor: src["event"]["sensor"].as_str().unwrap_or("").to_string(),
            dst_ip: src["destination"]["ip"].as_str().unwrap_or("").to_string(),
            dst_port: any_to_string(&src["destination"]["port"]),
            protocol: src["network"]["protocol"].as_str().unwrap_or("").to_string(),
            user: src["honeypot"]["canonical_user"].as_str().unwrap_or("").to_string(),
            pass: src["honeypot"]["canonical_pass"].as_str().unwrap_or("").to_string(),
            shasum: src["honeypot"]["canonical_shasum"].as_str().unwrap_or("").to_string(),
            fingerprint: src["honeypot"]["canonical_fingerprint"].as_str().unwrap_or("").to_string(),
            techniques,
        });
    }
    Ok(out)
}

// --------------------------------------------------------------------
// identity.go
// --------------------------------------------------------------------

#[derive(Default, Clone)]
struct SignalSet {
    fingerprints: HashSet<String>,
    payloads: HashSet<String>,
    creds: HashSet<String>,
}

impl SignalSet {
    fn merge(&mut self, other: &SignalSet) {
        self.fingerprints.extend(other.fingerprints.iter().cloned());
        self.payloads.extend(other.payloads.iter().cloned());
        self.creds.extend(other.creds.iter().cloned());
    }
}

fn intersects(a: &HashSet<String>, b: &HashSet<String>) -> bool {
    let (small, big) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().any(|k| big.contains(k))
}

/// How many of the three signal categories (fingerprint/payload/cred) have
/// at least one value in common between a and b. >=2 is a merge; 0 or 1 is
/// not, regardless of how many individual values overlap within one
/// category.
fn shared_signal_count(a: &SignalSet, b: &SignalSet) -> usize {
    let mut n = 0;
    if intersects(&a.fingerprints, &b.fingerprints) {
        n += 1;
    }
    if intersects(&a.payloads, &b.payloads) {
        n += 1;
    }
    if intersects(&a.creds, &b.creds) {
        n += 1;
    }
    n
}

/// One persisted evidence pointer (#2045): the event's document id plus the
/// timestamp that justifies its place in the newest-first vector — merges
/// need both, because two workings being folded together union their
/// pointers and then keep only the EVIDENCE_CAP most recent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvidencePointer {
    id: String,
    /// Millis since epoch. Missing parse (an event with no @timestamp) sorts
    /// oldest and is the first dropped by the cap; harmless.
    #[serde(default)]
    ts: i64,
}

struct IpObservation {
    ip: String,
    signals: SignalSet,
    sensors: HashSet<String>,
    sensor_counts: BTreeMap<String, i64>,
    techniques: HashSet<String>,
    /// This IP's in-window events, oldest→newest, capped: once EVIDENCE_CAP
    /// pointers sit here the earliest is dropped as each newer one arrives
    /// (hits are fetched @timestamp-asc, so VecDeque front = least recent).
    evidence: VecDeque<EvidencePointer>,
    /// #2047 scan shape: the distinct targets/ports/protocols this IP
    /// touched inside the evidence window.
    dst_ips: HashSet<String>,
    ports: HashSet<String>,
    protocols: HashSet<String>,
    first: Option<chrono::DateTime<chrono::Utc>>,
    last: Option<chrono::DateTime<chrono::Utc>>,
    events: i64,
}

/// Horizontal vs vertical scan classification from an IP's (or entity's)
/// touched sets. Pure so the thresholds stay in one tested place:
///   - "horizontal": swept >=25 distinct hosts (worm behaviour; port count
///     irrelevant — sweeping 25 hosts with one probe each is still a sweep)
///   - "vertical": >=25 distinct ports across <=5 distinct hosts
///   - "" everything else, which is ordinary service traffic by these
///     windows and must not grow a badge it doesn't mean.
pub(crate) fn scan_shape(dst_ips: usize, ports: usize) -> &'static str {
    const HORIZONTAL_HOSTS: usize = 25;
    const VERTICAL_PORTS: usize = 25;
    const VERTICAL_HOSTS_MAX: usize = 5;
    if dst_ips >= HORIZONTAL_HOSTS {
        "horizontal"
    } else if ports >= VERTICAL_PORTS && dst_ips <= VERTICAL_HOSTS_MAX {
        "vertical"
    } else {
        ""
    }
}

fn build_ip_observations(events: &[CorrEvent]) -> HashMap<String, IpObservation> {
    let mut out: HashMap<String, IpObservation> = HashMap::new();
    for e in events {
        let o = out.entry(e.src_ip.clone()).or_insert_with(|| IpObservation {
            ip: e.src_ip.clone(),
            signals: SignalSet::default(),
            sensors: HashSet::new(),
            sensor_counts: BTreeMap::new(),
            techniques: HashSet::new(),
            evidence: VecDeque::with_capacity(EVIDENCE_CAP),
            dst_ips: HashSet::new(),
            ports: HashSet::new(),
            protocols: HashSet::new(),
            first: None,
            last: None,
            events: 0,
        });
        // Missing destination on session-oriented records is normal (some
        // sensors only report their own address); skip empties rather than
        // counting a phantom "" host or port.
        if !e.dst_ip.is_empty() {
            o.dst_ips.insert(e.dst_ip.clone());
        }
        if !e.dst_port.is_empty() && e.dst_port != "0" {
            o.ports.insert(e.dst_port.clone());
        }
        if !e.protocol.is_empty() {
            o.protocols.insert(e.protocol.clone());
        }
        o.events += 1;
        if !e.sensor.is_empty() {
            o.sensors.insert(e.sensor.clone());
            *o.sensor_counts.entry(e.sensor.clone()).or_default() += 1;
        }
        if !e.id.is_empty() {
            if o.evidence.len() == EVIDENCE_CAP {
                o.evidence.pop_front();
            }
            let ts = e.when.map(|d| d.timestamp_millis()).unwrap_or(0);
            o.evidence.push_back(EvidencePointer { id: e.id.clone(), ts });
        }
        for t in &e.techniques {
            if !t.is_empty() {
                o.techniques.insert(t.clone());
            }
        }
        if !e.fingerprint.is_empty() {
            o.signals.fingerprints.insert(e.fingerprint.clone());
        }
        if !e.shasum.is_empty() {
            o.signals.payloads.insert(e.shasum.clone());
        }
        if valid_credential_pair(&e.user, &e.pass) {
            o.signals.creds.insert(format!("{} / {}", e.user, e.pass));
        }
        if let Some(when) = e.when {
            if o.first.is_none_or(|f| when < f) {
                o.first = Some(when);
            }
            if o.last.is_none_or(|l| when > l) {
                o.last = Some(when);
            }
        }
    }
    out
}

/// `attackers-v1`'s own persisted document shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Entity {
    id: String,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    fingerprints: Vec<String>,
    #[serde(default)]
    payloads: Vec<String>,
    #[serde(default)]
    credentials: Vec<String>,
    #[serde(default)]
    sensors: Vec<String>,
    /// Lifetime event count. NOT recomputed from source (the evidence fetch
    /// is capped, and events age out of the sliding window) and NOT
    /// accumulated naively either (#2040): each touched cycle advances it by
    /// how much this cycle's evidence-window count grew past the previous
    /// cycle's (`window_events`), so re-scanning the same still-active
    /// window every RUN_INTERVAL adds nothing. Docs written before #2040
    /// carry an inflated value from exactly that naive accumulation; they
    /// self-migrate on their first touched cycle (see finalize_entity).
    #[serde(default)]
    events: i64,
    /// This cycle's evidence-window count, persisted so the next cycle can
    /// take the delta against it. Absent on pre-#2040 docs, whose absence
    /// is the migration marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window_events: Option<i64>,
    #[serde(default)]
    first: String,
    #[serde(default)]
    last: String,
    #[serde(default)]
    updated: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    verdicts: Vec<String>,
    /// #2094: set when a cycle owed this entity a verdict refresh but an
    /// analysis-store lookup failed — applying freshly-built labels from a
    /// partial map is exactly how stored history used to get erased (one
    /// ES blip during a rewrite downgraded `["abc123: mirai"]` to `[]`,
    /// permanently for entities that then went quiet). Flagged docs are
    /// re-verified on the next cycle even though their payload set will by
    /// then compare unchanged, and the flag clears once labels apply from
    /// fully-successful lookups.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    verdicts_pending: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    techniques: Vec<String>,
    /// #2045: newest-first raw-evidence pointers (capped at EVIDENCE_CAP) —
    /// what GET /api/v1/attackers/{id}/events pages through. Absent on
    /// pre-#2045 docs (the serde default); a touched doc self-migrates the
    /// same way the #2040 counter does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence: Vec<EvidencePointer>,
    /// #2045: per-sensor event counts over this cycle's evidence window,
    /// refreshed on touch exactly like `window_events` (never accumulated —
    /// that was #2040's inflation). Empty until first touched post-#2045.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    sensor_counts: BTreeMap<String, i64>,
    /// #2047 scan shape over the evidence window as of the last touched
    /// cycle: distinct destinations/ports/protocols plus the derived
    /// horizontal/vertical label ("" when neither window applies).
    /// Absent on pre-#2047 docs, defaulted on load.
    #[serde(default)]
    ports_touched: usize,
    #[serde(default)]
    dest_ips: usize,
    #[serde(default)]
    protocols_touched: usize,
    #[serde(default, skip_serializing_if = "str::is_empty")]
    scan: String,
}

/// The in-memory working form `resolve_identities` merges into --
/// unexported set-based fields that `Entity`'s slice fields are flattened
/// into on load and flattened back out of on finalize, same shape as Go's
/// entity struct's own lazily-built unexported fields (entitySignals/
/// entityIPSet/entitySensorSet/entityTechniqueSet), just built eagerly here
/// instead of lazily -- Rust's ownership makes lazy memoization on a shared
/// struct awkward for no real benefit at this data size (a cycle loads the
/// entities it can actually touch, not the whole population -- see
/// `load_candidate_entities`).
struct Working {
    id: String,
    ip_set: HashSet<String>,
    signals: SignalSet,
    sensor_set: HashSet<String>,
    sensor_counts: BTreeMap<String, i64>,
    /// #2047: this cycle's destination-shape evidence, folded like the
    /// signal sets (persisted docs keep counts only; a touched entity's
    /// shape is recomputed from the current window every cycle).
    dst_ip_set: HashSet<String>,
    port_set: HashSet<String>,
    protocol_set: HashSet<String>,
    technique_set: HashSet<String>,
    /// Union of every observation's evidence pointers this cycle plus
    /// whatever the entity persisted before — deduped and pruned to the
    /// EVIDENCE_CAP newest in finalize_entity.
    evidence: Vec<EvidencePointer>,
    /// The persisted lifetime counter as loaded (#2040 semantics -- see
    /// Entity::events); finalize advances it by the cycle delta.
    events_base: i64,
    /// Sum of this cycle's per-IP observation counts. Rebuilt from scratch
    /// every cycle and never written straight to `events` -- that was the
    /// #2040 inflation, where a still-active IP's window got re-absorbed
    /// onto the persisted total once per RUN_INTERVAL.
    cycle_events: i64,
    /// The previous cycle's evidence-window count as persisted on the doc,
    /// or None on pre-#2040 docs (the migration marker) and fresh entities.
    prev_window_events: Option<i64>,
    // Formatted RFC3339 (whole-second, "Z"-suffixed) strings, compared
    // lexicographically -- matches Go's own absorb/mergeEntityInto, which
    // compares e.First/e.Last as strings (time.RFC3339, always whole-
    // second precision) rather than re-parsing them back into time.Time.
    // Lexicographic order over this exact fixed-width format is
    // chronological order, the same trick Go relies on.
    first: String,
    last: String,
    verdicts: Vec<String>,
    /// Carried through merge/finalize so a pending marker set on a merged
    /// entity survives onto the document written this cycle (#2094).
    verdicts_pending: bool,
}

fn working_from_entity(e: &Entity) -> Working {
    Working {
        id: e.id.clone(),
        ip_set: e.ips.iter().cloned().collect(),
        signals: SignalSet {
            fingerprints: e.fingerprints.iter().cloned().collect(),
            payloads: e.payloads.iter().cloned().collect(),
            creds: e.credentials.iter().cloned().collect(),
        },
        sensor_set: e.sensors.iter().cloned().collect(),
        sensor_counts: e.sensor_counts.clone(),
        technique_set: e.techniques.iter().cloned().collect(),
        evidence: e.evidence.clone(),
        // Scan-shape sets rebuild from the current window only — matching
        // cycle_events semantics, an untouched entity keeps whatever its
        // document says until new evidence writes it again.
        dst_ip_set: HashSet::new(),
        port_set: HashSet::new(),
        protocol_set: HashSet::new(),
        events_base: e.events,
        cycle_events: 0,
        prev_window_events: e.window_events,
        first: e.first.clone(),
        last: e.last.clone(),
        verdicts: e.verdicts.clone(),
        verdicts_pending: e.verdicts_pending,
    }
}

fn new_working(id: String) -> Working {
    Working {
        id,
        ip_set: HashSet::new(),
        signals: SignalSet::default(),
        sensor_set: HashSet::new(),
        sensor_counts: BTreeMap::new(),
        technique_set: HashSet::new(),
        evidence: Vec::new(),
        dst_ip_set: HashSet::new(),
        port_set: HashSet::new(),
        protocol_set: HashSet::new(),
        events_base: 0,
        cycle_events: 0,
        prev_window_events: None,
        first: String::new(),
        last: String::new(),
        verdicts: Vec::new(),
        verdicts_pending: false,
    }
}

fn fmt_rfc3339_whole_seconds(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Folds one IP observation's signals/sensors/techniques/events/time-range
/// into `e` in place. The event count lands in `cycle_events` (this cycle's
/// window sum), never straight onto the persisted lifetime counter -- #2040.
fn absorb(e: &mut Working, o: &IpObservation) {
    e.ip_set.insert(o.ip.clone());
    e.signals.merge(&o.signals);
    e.sensor_set.extend(o.sensors.iter().cloned());
    e.technique_set.extend(o.techniques.iter().cloned());
    // Evidence: union now, dedupe+prune in finalize_entity -- consecutive
    // cycles overlap on the sliding window, so the same event id can arrive
    // more than once across cycles; id-keyed dedup is what keeps that from
    // ever becoming an #2040-style double count.
    e.evidence.extend(o.evidence.iter().cloned());
    for (sensor, count) in &o.sensor_counts {
        *e.sensor_counts.entry(sensor.clone()).or_default() += count;
    }
    e.dst_ip_set.extend(o.dst_ips.iter().cloned());
    e.port_set.extend(o.ports.iter().cloned());
    e.protocol_set.extend(o.protocols.iter().cloned());
    e.cycle_events += o.events;
    if let Some(first) = o.first {
        let first_str = fmt_rfc3339_whole_seconds(first);
        if e.first.is_empty() || first_str < e.first {
            e.first = first_str;
        }
    }
    if let Some(last) = o.last {
        let last_str = fmt_rfc3339_whole_seconds(last);
        if last_str > e.last {
            e.last = last_str;
        }
    }
}

/// Folds `b`'s members/signals into `a` in place -- `a` survives, `b` is
/// discarded by the caller (the absorbed-id list). The absorbed entity's
/// lifetime counter and window baseline fold over too: its member IPs are
/// about to become `a`'s, so next cycle's delta must count their activity
/// as already-seen, not as new (#2040).
fn merge_entity_into(a: &mut Working, b: &Working) {
    a.ip_set.extend(b.ip_set.iter().cloned());
    a.signals.merge(&b.signals);
    a.sensor_set.extend(b.sensor_set.iter().cloned());
    a.technique_set.extend(b.technique_set.iter().cloned());
    a.evidence.extend(b.evidence.iter().cloned());
    a.dst_ip_set.extend(b.dst_ip_set.iter().cloned());
    a.port_set.extend(b.port_set.iter().cloned());
    a.protocol_set.extend(b.protocol_set.iter().cloned());
    a.events_base += b.events_base;
    a.cycle_events += b.cycle_events;
    // The merged window now spans both members' sensors (#2045), mirroring
    // how prev_window_events sums below.
    for (sensor, count) in &b.sensor_counts {
        *a.sensor_counts.entry(sensor.clone()).or_default() += count;
    }
    // Either side missing the #2040 marker makes the merged doc legacy:
    // finalize will restart its counter once from this cycle's window.
    a.prev_window_events = match (a.prev_window_events, b.prev_window_events) {
        (Some(x), Some(y)) => Some(x + y),
        _ => None,
    };
    // #2094: a pending verdict refresh survives absorption -- either side
    // owing one means the now-larger payload set is still owed its labels.
    a.verdicts_pending = a.verdicts_pending || b.verdicts_pending;
    if !b.first.is_empty() && (a.first.is_empty() || b.first < a.first) {
        a.first = b.first.clone();
    }
    if b.last > a.last {
        a.last = b.last.clone();
    }
}

/// Deliberately not timestamp-seeded: that was the KNOWN GAP surfaced by
/// #1628's worker-retirement research — see git history for the original
/// timestamp-seeded version and the race it had. This function is only
/// ever called once per IP for the lifetime of this index: resolve_identities
/// looks the IP up in `ip_to_index` (populated from every existing entity's
/// `ip_set`, loaded fresh from attackers-v1 each cycle) before ever reaching
/// here, so a previously-seen IP — by this worker or, since both read/write
/// the same shared index, by a prior run or even a differently-seeded past
/// version of this same function — never re-derives a new id. That
/// invariant is exactly what makes a pure function of the seed IP correct
/// and actually useful: two Rust instances (concurrent replicas, or the
/// same worker racing itself across a restart) that independently mint an
/// entity for the same never-before-seen IP in the same cycle now converge
/// on the identical id, so their concurrent writes land on one document
/// instead of two — the same "safe idempotent upsert on a deterministic
/// key" property agent-intrusion-worker's campaign_id already has.
///
/// This does NOT by itself make a Go+Rust dual-write bake period safe: the
/// old Go worker's own newEntityID still seeds on a timestamp and was
/// deliberately left alone (no reason to invest further in code slated for
/// deletion) — Go and Rust computing different ids for the same
/// simultaneously-first-seen IP remains possible for as long as both are
/// writing attackers-v1 at once. The safe retirement path for this
/// specific worker is still: stop the old worker, then start this one —
/// not an extended side-by-side bake period the way agent-intrusion-worker
/// (whose campaign_id has always been a pure function of event content) can
/// safely do.
fn new_entity_id(seed_ip: &str) -> String {
    let digest = Sha256::digest(format!("attacker:{seed_ip}").as_bytes());
    to_hex(&digest[..16])
}

/// Merges this cycle's per-IP observations into `existing`, returning the
/// full set of entities that changed this cycle (new or updated -- callers
/// upsert these) and the IDs of any entity absorbed into another and
/// therefore now stale (callers delete these). Entities that didn't change
/// this cycle are neither returned nor touched -- durable identity means
/// "leave it alone until there's new evidence", not "recompute and rewrite
/// everything every cycle".
fn resolve_identities(
    existing: Vec<Entity>,
    observations: &HashMap<String, IpObservation>,
) -> (Vec<Entity>, Vec<String>) {
    let mut candidates: Vec<Working> = existing.iter().map(working_from_entity).collect();
    let mut ip_to_index: HashMap<String, usize> = HashMap::new();
    for (i, e) in candidates.iter().enumerate() {
        for ip in &e.ip_set {
            ip_to_index.insert(ip.clone(), i);
        }
    }

    // Deterministic iteration order so a run over the same input always
    // merges the same way -- HashMap iteration order is randomized, and
    // two runs (or a test) over identical data would otherwise see
    // different entity groupings.
    let mut ips: Vec<&String> = observations.keys().collect();
    ips.sort();

    let mut touched: Vec<usize> = Vec::new();
    let mut touched_set: HashSet<usize> = HashSet::new();
    let mut absorbed_indices: HashSet<usize> = HashSet::new();
    // Real ids of absorbed entities, captured at the moment of absorption
    // -- candidates[extra] is overwritten with an empty placeholder right
    // below (to satisfy the borrow checker while merging it into
    // candidates[first]), so its `.id` can never be read back out
    // afterward the way the index-only bookkeeping might suggest.
    let mut absorbed_ids: Vec<String> = Vec::new();

    for ip in ips {
        let o = &observations[ip];
        let mut target_index = ip_to_index.get(ip).copied();

        if target_index.is_none() {
            // Not yet a member of anything -- look for a candidate entity
            // (pre-existing, or created earlier this same cycle) this IP's
            // signals now qualify it to join. Qualifying for more than one
            // means those entities merge together too (they were always
            // the same actor, this observation is just the first evidence
            // that reveals it).
            let matches: Vec<usize> = candidates
                .iter()
                .enumerate()
                .filter(|(i, e)| {
                    !absorbed_indices.contains(i) && shared_signal_count(&o.signals, &e.signals) >= MERGE_THRESHOLD
                })
                .map(|(i, _)| i)
                .collect();

            if let Some((&first, rest)) = matches.split_first() {
                target_index = Some(first);
                for &extra in rest {
                    let extra_ips: Vec<String> = candidates[extra].ip_set.iter().cloned().collect();
                    let extra_working = std::mem::replace(&mut candidates[extra], new_working(String::new()));
                    absorbed_ids.push(extra_working.id.clone());
                    merge_entity_into(&mut candidates[first], &extra_working);
                    absorbed_indices.insert(extra);
                    touched_set.remove(&extra);
                    touched.retain(|&t| t != extra);
                    for eip in extra_ips {
                        ip_to_index.insert(eip, first);
                    }
                }
            } else {
                let new_id = new_entity_id(ip);
                candidates.push(new_working(new_id));
                target_index = Some(candidates.len() - 1);
            }
            ip_to_index.insert(ip.clone(), target_index.unwrap());
        }

        let idx = target_index.unwrap();
        absorb(&mut candidates[idx], o);
        if touched_set.insert(idx) {
            touched.push(idx);
        }
    }

    let mut changed: Vec<Entity> = touched
        .into_iter()
        .map(|i| finalize_entity(&candidates[i]))
        .collect();
    changed.sort_by(|a, b| a.id.cmp(&b.id));

    let mut absorbed = absorbed_ids;
    absorbed.sort();

    (changed, absorbed)
}

/// Flattens a working entity's sets back into its persisted slice fields,
/// sorted for stable JSON output. This is also where the lifetime counter
/// advances (#2040): by the growth of this cycle's evidence-window count
/// over the previous cycle's, never by re-adding the whole window.
fn finalize_entity(e: &Working) -> Entity {
    let sorted = |s: &HashSet<String>| -> Vec<String> {
        let mut v: Vec<String> = s.iter().filter(|k| !k.trim().is_empty()).cloned().collect();
        v.sort();
        v
    };
    // A shrinking window (events aged out faster than they arrived) must
    // not rewind the lifetime counter -- only genuine growth advances it.
    let events = match e.prev_window_events {
        // Pre-#2040 doc: its `events` value accumulated whole sliding
        // windows once per cycle and cannot be trusted. Restart from what
        // this cycle actually observed; every touched doc migrates itself
        // on its first touched cycle, and untouched docs keep serving
        // their old number until there's new evidence to write them.
        None => e.cycle_events,
        Some(prev) => e.events_base + (e.cycle_events - prev).max(0),
    };
    // #2045 evidence: consecutive cycles overlap on the sliding window, so
    // the same event id can be absorbed more than once -- dedup by id is
    // what keeps that from becoming an #2040-style double count. Then keep
    // the EVIDENCE_CAP newest, persisted newest-first so the entity page
    // pages most-recent-first without a sort step; the ts/id ordering key
    // keeps two runs over identical input byte-identical.
    let mut evidence = e.evidence.clone();
    evidence.sort_by(|a, b| (b.ts, &b.id).cmp(&(a.ts, &a.id)));
    evidence.dedup_by(|a, b| a.id == b.id);
    evidence.truncate(EVIDENCE_CAP);
    let dest_ips = e.dst_ip_set.len();
    let ports_touched = e.port_set.len();
    let protocols_touched = e.protocol_set.len();
    let scan = scan_shape(dest_ips, ports_touched);
    Entity {
        id: e.id.clone(),
        ips: sorted(&e.ip_set),
        fingerprints: sorted(&e.signals.fingerprints),
        payloads: sorted(&e.signals.payloads),
        credentials: sorted(&e.signals.creds),
        sensors: sorted(&e.sensor_set),
        ports_touched,
        dest_ips,
        protocols_touched,
        scan: scan.to_string(),
        events,
        window_events: Some(e.cycle_events),
        first: e.first.clone(),
        last: e.last.clone(),
        updated: String::new(),
        verdicts: e.verdicts.clone(),
        verdicts_pending: e.verdicts_pending,
        techniques: sorted(&e.technique_set),
        evidence,
        sensor_counts: e.sensor_counts.clone(),
    }
}

// --------------------------------------------------------------------
// verdicts.go
// --------------------------------------------------------------------

/// #2047: the es-results-importer's materialized per-sample verdict
/// projection -- one doc per sha256, raw fields mirroring the four live
/// stores, read through the same label builders as those stores.
const IOC_VERDICTS_INDEX: &str = "ioc-verdicts-v1";

fn sandbox_risk_worth_reporting(level: &str) -> bool {
    matches!(level, "medium" | "high" | "critical")
}

const REVDECK_ANSWER_LIMIT: usize = 80;

fn sandbox_risk_rank(level: &str) -> u8 {
    match level {
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0,
    }
}

// The label builders below take a document source (a live analysis doc's
// or the #2047 projection's) and produce EXACTLY the label string the live
// path has always produced. Both readers go through them, so the
// materialized fast path and the legacy queries cannot drift apart in
// wording or truncation.

fn ghidra_label(src: &serde_json::Value) -> Option<String> {
    src["ghidra"]["ai_triage"]["family_guess"]
        .as_str()
        .filter(|f| !f.is_empty())
        .map(String::from)
}

fn github_label(src: &serde_json::Value) -> Option<String> {
    src["github_analysis"]["family"]
        .as_str()
        .filter(|f| !f.is_empty())
        .map(String::from)
}

fn revdeck_label(src: &serde_json::Value) -> Option<String> {
    let inner = &src["revdeck"]["revdeck"];
    let status = inner["status"].as_str().unwrap_or("");
    let answer = inner["answer"].as_str().unwrap_or("");
    if status != "completed" || answer.is_empty() {
        return None;
    }
    Some(format!("revdeck: {}", truncate_revdeck_answer(answer)))
}

fn truncate_revdeck_answer(answer: &str) -> String {
    if answer.chars().count() > REVDECK_ANSWER_LIMIT {
        format!("{}…", answer.chars().take(REVDECK_ANSWER_LIMIT).collect::<String>())
    } else {
        answer.to_string()
    }
}

/// The materialized form carries the already-reduced best level rather
/// than one document per run; only the worth-reporting bar applies.
fn sandbox_projection_label(src: &serde_json::Value) -> Option<String> {
    src["sandbox"]["risk_level"]
        .as_str()
        .filter(|level| sandbox_risk_worth_reporting(level))
        .map(|level| format!("sandbox: {level} risk"))
}

/// Every verdict label this cycle could produce, keyed by payload hash --
/// the batched replacement for what used to be four sequential lookups per
/// hash per entity (#2041).
#[derive(Default)]
struct VerdictMaps {
    ghidra: HashMap<String, String>,
    sandbox: HashMap<String, String>,
    github: HashMap<String, String>,
    revdeck: HashMap<String, String>,
}

/// Resolves the whole cycle's payload union against the four analysis
/// stores in one query each. Returns None when ANY store query failed:
/// labels built from a partial map would be written over persisted history
/// wholesale by apply_verdicts, erasing verdicts that are still true — the
/// transient-ES-blip erase #2094 documents. Callers defer the refresh
/// instead (verdicts_pending keeps it scheduled); a store failing no longer
/// takes the others down with it either — each arm logs its own warning.
///
/// Label values here are stored WITHOUT the "{short-hash}: " prefix -- that
/// formatting lives in apply_verdicts so it stays byte-identical to what
/// the old per-hash path wrote (a different format would churn every
/// stored verdict on the first post-deploy cycle).
async fn load_verdict_maps(state: &AppState, hashes: &HashSet<String>) -> Option<VerdictMaps> {
    let mut maps = VerdictMaps::default();
    if hashes.is_empty() {
        return Some(maps);
    }

    // #2047 fast path: the es-results-importer keeps ioc-verdicts-v1, a
    // per-sample projection of exactly the fields these four queries are
    // after. When it covers EVERY hash this cycle cares about, one ids
    // query replaces all four below. Coverage must be total to count:
    // falling back per-hash would mix a hash whose import predates the
    // projection (zero labels -- wrongly erasing still-true verdicts,
    // the exact #2094 hazard) with ones that genuinely have none.
    // Staleness between an analysis landing and its projection refresh is
    // bounded by the importer's own pass interval and self-heals on that
    // source's next trigger; cycles in between simply take the slow path.
    let mut projected = VerdictMaps::default();
    let mut covered: HashSet<String> = HashSet::new();
    let projection_body = json!({
        "query": {"ids": {"values": hashes.iter().cloned().collect::<Vec<_>>()}}
    });
    match state
        .es
        .search_index(&[IOC_VERDICTS_INDEX], projection_body)
        .await
    {
        Ok(result) => {
            for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
                let Some(hash) = hit["_id"].as_str() else { continue };
                covered.insert(hash.to_string());
                let src = &hit["_source"];
                if let Some(family) = ghidra_label(src) {
                    projected.ghidra.insert(hash.to_string(), family);
                }
                if let Some(label) = sandbox_projection_label(src) {
                    projected.sandbox.insert(hash.to_string(), label);
                }
                if let Some(family) = github_label(src) {
                    projected.github.insert(hash.to_string(), family);
                }
                if let Some(verdict) = revdeck_label(src) {
                    projected.revdeck.insert(hash.to_string(), verdict);
                }
            }
            if covered.len() == hashes.len() && !hashes.is_empty() {
                return Some(projected);
            }
            tracing::debug!(
                covered = covered.len(),
                wanted = hashes.len(),
                "verdict projection incomplete; falling back to live stores"
            );
        }
        Err(error) => {
            // A missing/failing projection is the normal pre-first-import
            // state and changes nothing downstream -- take the slow path.
            tracing::debug!(%error, "verdict projection lookup failed; using live stores");
        }
    }

    // Ghidra / GitHub / RevDeck are content-addressed docs with known ids:
    // one ids query each, keyed back by stripping the prefix off _id.
    let id_query = |prefix: &str, source: serde_json::Value| {
        json!({
            "_source": source,
            "query": {"ids": {"values": hashes.iter().map(|h| format!("{prefix}{h}")).collect::<Vec<_>>()}}
        })
    };
    let collect = |result: &serde_json::Value,
                   prefix: &str,
                   read: fn(&serde_json::Value) -> Option<String>|
     -> HashMap<String, String> {
        let mut out = HashMap::new();
        for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
            let Some(full_id) = hit["_id"].as_str() else { continue };
            let Some(hash) = full_id.strip_prefix(prefix) else { continue };
            if let Some(label) = read(&hit["_source"]) {
                out.insert(hash.to_string(), label);
            }
        }
        out
    };

    match state
        .es
        .search_index(
            &["ghidra-analysis-v1"],
            id_query(
                "ghidra:",
                json!(["ghidra.ai_triage.family_guess"]),
            ),
        )
        .await
    {
        Ok(result) => {
            maps.ghidra = collect(&result, "ghidra:", ghidra_label);
        }
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: ghidra verdict lookup failed");
            // #2094: a partial map must never reach apply_verdicts — the
            // labels it didn't see would be written over as if gone.
            return None;
        }
    }

    match state
        .es
        .search_index(
            &["github-analysis-v1"],
            id_query(
                "github_analysis:",
                json!(["github_analysis.family"]),
            ),
        )
        .await
    {
        Ok(result) => {
            maps.github = collect(&result, "github_analysis:", github_label);
        }
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: github verdict lookup failed");
            return None; // #2094: never write over persisted verdicts from a partial map
        }
    }

    match state
        .es
        .search_index(
            &["revdeck-analysis-v1"],
            id_query("revdeck:", json!(["revdeck.revdeck.status", "revdeck.revdeck.answer"])),
        )
        .await
    {
        Ok(result) => {
            maps.revdeck = collect(&result, "revdeck:", revdeck_label);
        }
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: revdeck verdict lookup failed");
            return None; // #2094: never write over persisted verdicts from a partial map
        }
    }

    // Sandbox runs are not content-addressed (one hash can have several
    // run documents), so this one stays a field terms query; best
    // worth-reporting risk level wins per hash, as before.
    let body = json!({
        "size": (hashes.len() * 5 + 10).min(2_000),
        "_source": ["sandbox.sha256", "sandbox.risk_level"],
        "query": {"terms": {"sandbox.sha256": hashes.iter().cloned().collect::<Vec<_>>()}}
    });
    match state.es.search_index(&["sandbox-analysis-v1"], body).await {
        Ok(result) => {
            // (rank, label) per hash; a hash whose runs are all below the
            // reporting bar ends with an empty label and is dropped.
            let mut best: HashMap<String, (u8, String)> = HashMap::new();
            for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
                let Some(sha) = hit["_source"]["sandbox"]["sha256"].as_str() else { continue };
                let Some(level) = hit["_source"]["sandbox"]["risk_level"].as_str() else { continue };
                if !sandbox_risk_worth_reporting(level) {
                    continue;
                }
                let entry = best.entry(sha.to_string()).or_insert((0, String::new()));
                if sandbox_risk_rank(level) > entry.0 {
                    *entry = (sandbox_risk_rank(level), format!("sandbox: {level} risk"));
                }
            }
            maps.sandbox = best
                .into_iter()
                .filter(|(_, (_, label))| !label.is_empty())
                .map(|(sha, (_, label))| (sha, label))
                .collect();
        }
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: sandbox verdict lookup failed");
            return None; // #2094: never write over persisted verdicts from a partial map
        }
    }

    Some(maps)
}

/// Applies the batched verdict maps to one entity: every payload hash gets
/// its non-empty labels, deduplicated, prefixed "{short-hash}: ". Must stay
/// byte-identical to the pre-#2041 per-hash formatting so stored verdicts
/// don't churn on rewrites.
fn apply_verdicts(e: &mut Entity, maps: &VerdictMaps) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut verdicts: Vec<String> = Vec::new();
    let add = |label: String, seen: &mut HashSet<String>, verdicts: &mut Vec<String>| {
        if seen.insert(label.clone()) {
            verdicts.push(label);
        }
    };
    for hash in &e.payloads {
        let short = &hash[..hash.len().min(12)];
        if let Some(family) = maps.ghidra.get(hash) {
            add(format!("{short}: {family}"), &mut seen, &mut verdicts);
        }
        if let Some(verdict) = maps.sandbox.get(hash) {
            add(format!("{short}: {verdict}"), &mut seen, &mut verdicts);
        }
        if let Some(family) = maps.github.get(hash) {
            add(format!("{short}: {family}"), &mut seen, &mut verdicts);
        }
        if let Some(verdict) = maps.revdeck.get(hash) {
            add(format!("{short}: {verdict}"), &mut seen, &mut verdicts);
        }
    }
    e.verdicts = verdicts;
}

/// True when this entity's payload set differs from the persisted doc's --
/// the only condition under which verdict labels can change (fresh
/// entities have no persisted baseline and always verify). A late-landing
/// analysis result is picked up on the entity's next payload change.
fn payloads_changed_since_persist(e: &Entity, persisted: Option<&Vec<String>>) -> bool {
    persisted.is_none_or(|p| p != &e.payloads)
}

/// The #2041 verify gate plus #2094's second arm: an entity whose previous
/// refresh was deferred by a failed analysis-store query (verdicts_pending)
/// stays in the verify set even though its payloads stopped changing --
/// without that, a blip-cycle entity would settle into "unchanged" forever
/// and never get its verdicts back.
fn needs_verdict_refresh(e: &Entity, persisted: Option<&Vec<String>>) -> bool {
    payloads_changed_since_persist(e, persisted) || e.verdicts_pending
}

// --------------------------------------------------------------------
// main.go
// --------------------------------------------------------------------

/// The term lists a cycle's candidate load queries on, deduped and sorted
/// so a run over the same window issues byte-identical queries.
#[derive(Debug, Default, PartialEq, Eq)]
struct CandidateTerms {
    ips: Vec<String>,
    fingerprints: Vec<String>,
    payloads: Vec<String>,
    creds: Vec<String>,
}

/// Every IP this window observed, and every signal any observation carries.
/// Together these reach a superset of the entities a cycle can touch: an
/// entity is only ever touched through one of its own IPs, and can only be
/// absorbed by clearing `MERGE_THRESHOLD` shared signals -- which needs at
/// least one signal in common, so at least one of these terms matches it.
fn candidate_terms(observations: &HashMap<String, IpObservation>) -> CandidateTerms {
    let mut fingerprints: BTreeSet<&str> = BTreeSet::new();
    let mut payloads: BTreeSet<&str> = BTreeSet::new();
    let mut creds: BTreeSet<&str> = BTreeSet::new();
    for o in observations.values() {
        fingerprints.extend(o.signals.fingerprints.iter().map(String::as_str));
        payloads.extend(o.signals.payloads.iter().map(String::as_str));
        creds.extend(o.signals.creds.iter().map(String::as_str));
    }
    let owned = |s: BTreeSet<&str>| -> Vec<String> { s.into_iter().map(String::from).collect() };
    let mut ips: Vec<String> = observations.keys().cloned().collect();
    ips.sort();
    CandidateTerms {
        ips,
        fingerprints: owned(fingerprints),
        payloads: owned(payloads),
        creds: owned(creds),
    }
}

/// Folds every entity whose `field` holds one of `values` into `out`, keyed
/// by entity id so the two passes below can overlap freely. `cap` bounds
/// how many distinct entities the map is allowed to reach; the return says
/// whether it stopped early on that bound.
async fn collect_entities_by_terms(
    state: &AppState,
    field: &str,
    values: &[String],
    cap: Option<usize>,
    out: &mut HashMap<String, Entity>,
) -> anyhow::Result<bool> {
    for chunk in values.chunks(CANDIDATE_TERMS_CHUNK) {
        if cap.is_some_and(|c| out.len() >= c) {
            return Ok(true);
        }
        let query = json!({"terms": {field: chunk}});
        let hits = state
            .es
            .search_paginated(
                ATTACKERS_INDEX,
                |search_after| {
                    let mut body = json!({"sort": [{"_shard_doc": "asc"}], "query": query.clone()});
                    if let Some(sa) = search_after {
                        body["search_after"] = sa.clone();
                    }
                    body
                },
                CANDIDATE_PAGE_SIZE,
                CANDIDATE_MAX_PAGES,
            )
            .await?;
        for hit in hits {
            if let Ok(e) = serde_json::from_value::<Entity>(hit["_source"].clone()) {
                out.insert(e.id.clone(), e);
            }
        }
    }
    Ok(false)
}

/// Loads the entities this cycle could actually touch, rather than the
/// whole `attackers-v1` population (#2651). Two passes, and the split is
/// the whole point:
///
/// 1. **By observed IP**, with no ceiling. This is what makes the old
///    20,000-doc load cap's data-loss path impossible by construction:
///    `new_entity_id` is a pure function of the seed IP and `index_doc` is
///    a full replace, so a stored entity that wasn't loaded came back as a
///    *blank* document under its own id -- resetting `first`, restarting
///    the lifetime counter, and dropping its signal sets, its verdicts and
///    the IPs it had absorbed. Loading every entity that holds an IP this
///    window saw means the "no candidate, so create one" branch can only
///    ever fire for an IP that genuinely has no entity yet.
/// 2. **By shared signal**, capped at `MAX_MERGE_CANDIDATE_LOAD`. Only an
///    entity sharing a fingerprint, payload hash or credential pair with
///    some observation can reach `MERGE_THRESHOLD`, and a popular
///    credential can be shared very widely -- so this half is best-effort,
///    degrading the way the old warning only claimed to: a missed merge,
///    never lost history.
///
/// An entity with no signal in common with any observation can be neither
/// touched nor absorbed, so leaving it unloaded is not an approximation.
/// The one edge it does give up: `credentials.keyword` carries
/// `ignore_above: 256`, so a merge whose only two shared signals are both
/// credential pairs longer than that is no longer found. Every shorter
/// signal still matches and pass 1 is unaffected, so no history is at risk.
///
/// The result is sorted by id: `resolve_identities` picks its merge target
/// by candidate order, and ES `_shard_doc` order is arbitrary, so sorting
/// is what makes two runs over the same data fold the same way.
async fn load_candidate_entities(
    state: &AppState,
    observations: &HashMap<String, IpObservation>,
) -> anyhow::Result<Vec<Entity>> {
    if observations.is_empty() {
        return Ok(Vec::new());
    }

    let terms = candidate_terms(observations);
    let mut out: HashMap<String, Entity> = HashMap::new();

    collect_entities_by_terms(state, "ips.keyword", &terms.ips, None, &mut out).await?;
    let by_ip = out.len();

    let mut truncated = false;
    for (field, values) in [
        ("fingerprints.keyword", &terms.fingerprints),
        ("payloads.keyword", &terms.payloads),
        ("credentials.keyword", &terms.creds),
    ] {
        truncated |=
            collect_entities_by_terms(state, field, values, Some(MAX_MERGE_CANDIDATE_LOAD), &mut out)
                .await?;
    }
    if truncated {
        tracing::warn!(
            candidates = out.len(),
            cap = MAX_MERGE_CANDIDATE_LOAD,
            "attacker-identity: merge-candidate load hit its cap -- entities sharing only a signal beyond it won't be considered this cycle (entities holding an observed IP are always loaded)"
        );
    }

    let mut entities: Vec<Entity> = out.into_values().collect();
    entities.sort_by(|a, b| a.id.cmp(&b.id));
    tracing::debug!(
        candidates = entities.len(),
        by_ip,
        observed_ips = observations.len(),
        "attacker-identity: candidate entities loaded"
    );
    Ok(entities)
}

async fn run_cycle(state: &AppState, window: Duration) {
    let start = chrono::Utc::now();
    let since = start - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::hours(6));

    let events = match fetch_recent_events(state, since).await {
        Ok(events) => events,
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: fetching recent events failed, skipping this cycle");
            return;
        }
    };
    let observations = build_ip_observations(&events);

    let existing = match load_candidate_entities(state, &observations).await {
        Ok(existing) => existing,
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: loading existing entities failed, skipping this cycle");
            return;
        }
    };
    let existing_count = existing.len();

    // #2041: verdict labels can only change when an entity's payload set
    // changed (fresh entities have no persisted baseline), so everything
    // else keeps its stored verdicts untouched -- re-verifying unchanged
    // payloads every cycle was 4 sequential ES lookups x hashes x entities
    // of pure busy-work.
    //
    // #2094: an entity whose last refresh was deferred by a failed store
    // query (verdicts_pending) stays in the verify set even though its
    // payloads stopped changing -- without that, a blip-cycle entity would
    // settle into "unchanged" forever and never get its verdicts back.
    let persisted_payloads: HashMap<String, Vec<String>> = existing
        .iter()
        .map(|e| (e.id.clone(), e.payloads.clone()))
        .collect();
    let (mut changed, absorbed) = resolve_identities(existing, &observations);

    let to_verify: Vec<usize> = changed
        .iter()
        .enumerate()
        .filter(|(_, e)| needs_verdict_refresh(e, persisted_payloads.get(&e.id)))
        .map(|(i, _)| i)
        .collect();

    // None = at least one analysis-store query failed this cycle; applying a
    // partial map would erase persisted verdicts that are still true (#2094),
    // so every to_verify entity defers instead and carries verdicts_pending.
    let verdict_maps = if to_verify.is_empty() {
        Some(VerdictMaps::default())
    } else {
        let hashes: HashSet<String> = to_verify
            .iter()
            .flat_map(|&i| changed[i].payloads.iter().cloned())
            .collect();
        load_verdict_maps(state, &hashes).await
    };

    for (i, e) in changed.iter_mut().enumerate() {
        e.updated = start.to_rfc3339();
        if to_verify.binary_search(&i).is_ok() {
            match &verdict_maps {
                Some(maps) => {
                    apply_verdicts(e, maps);
                    e.verdicts_pending = false;
                }
                None => e.verdicts_pending = true,
            }
        }
        let Ok(body) = serde_json::to_value(&*e) else { continue };
        if let Err(error) = state.es.index_doc(ATTACKERS_INDEX, &e.id, body).await {
            tracing::warn!(%error, id = %e.id, "attacker-identity: index entity failed");
        }
    }
    for id in &absorbed {
        if let Err(error) = state.es.delete_doc(ATTACKERS_INDEX, id).await {
            tracing::warn!(%error, id = %id, "attacker-identity: delete absorbed entity failed");
        }
    }

    tracing::info!(
        events = events.len(),
        ips_observed = observations.len(),
        changed = changed.len(),
        absorbed = absorbed.len(),
        candidates_loaded = existing_count,
        duration_ms = (chrono::Utc::now() - start).num_milliseconds(),
        "attacker-identity: cycle complete"
    );
}

/// #2900: every IP `fetch_recent_events` would now refuse to build an
/// entity from — loopback (the same `LOOPBACK_IPS` ip-enrichment-worker's
/// `mark_internal_probe` uses to set `honeypot.internal_probe`, #2145's
/// exclusion source) plus this deployment's own configured/tunnel
/// addresses (`dashboard::self_addresses()`, #1677/#1779). An entity whose
/// full `ips` membership is a subset of this set could only have been
/// built by a cycle that ran *before* the exclusion existed — going
/// forward, none of these IPs can ever reach `build_ip_observations`, so
/// such an entity can never be revisited by `run_cycle` (its IP never
/// reappears as a candidate) and stays frozen indefinitely otherwise.
fn self_only_prune_candidates() -> Vec<String> {
    let mut ips: Vec<String> = crate::ip_enrichment::sensors::LOOPBACK_IPS
        .iter()
        .map(|ip| ip.to_string())
        .collect();
    ips.extend(crate::dashboard::self_addresses());
    ips
}

/// True if every ip this entity ever accumulated is one this deployment
/// now treats as self/probe traffic, never a real attacker. An entity with
/// mixed membership (a real attacker IP that also happens to share a
/// signal with a self address, however that could occur) is deliberately
/// NOT pruned — only entities that are self-traffic *and nothing else*.
fn is_self_only_entity(ips: &[String], self_ips: &HashSet<String>) -> bool {
    !ips.is_empty() && ips.iter().all(|ip| self_ips.contains(ip))
}

/// #2900: one-time-in-spirit, cheap-every-cycle-in-practice cleanup for
/// entities like the pre-#2145 `127.0.0.1` one (16.1M events, still #1 by
/// score on the live `/attackers` page): built entirely from traffic that
/// predates the ingest-time exclusion, and never touched again since,
/// because that same exclusion is what stops the IP from ever reappearing
/// as a cycle candidate. This is a narrow, deliberate exception to this
/// module's own "entities are durable... never deleted for going quiet"
/// invariant (see the file's own top-of-file doc comment) — going quiet is
/// not the trigger here; the entity's *entire* membership having always
/// been self-traffic is. The query only ever fetches entities whose `ips`
/// contains one of a small, fixed self/loopback list, so this stays cheap
/// regardless of `attackers-v1`'s total size.
/// The retrieval half of the prune, split out so the field it matches on is
/// pinned by a test rather than by inspection.
///
/// `ips.keyword`, not `ips`. `attackers-v1` has no explicit mapping, so
/// dynamic mapping makes `ips` a `text` field with a `keyword` subfield.
/// Under the standard analyzer a dotted-quad IPv4 survives as one token --
/// which is why a `terms` query on bare `ips` still matched `127.0.0.1` --
/// but `::1` analyzes to the token `1`, so the literal `::1` could never
/// match a document whose `ips` is `::1`, silently killing half of
/// `LOOPBACK_IPS` on the retrieval side. `collect_entities_by_terms` above
/// already queries `ips.keyword` for the same reason; this matches it.
fn prune_query(candidates: &[String]) -> serde_json::Value {
    json!({
        "size": 100,
        "query": {"terms": {"ips.keyword": candidates}},
        "_source": ["ips"]
    })
}

async fn prune_self_only_entities(state: &AppState) -> anyhow::Result<usize> {
    let candidates = self_only_prune_candidates();
    if candidates.is_empty() {
        return Ok(0);
    }
    let self_ips: HashSet<String> = candidates.iter().cloned().collect();
    let result = state.es.search_index(&[ATTACKERS_INDEX], prune_query(&candidates)).await?;
    let mut pruned = 0;
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        let id = hit["_id"].as_str().unwrap_or_default();
        let ips: Vec<String> = hit["_source"]["ips"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !is_self_only_entity(&ips, &self_ips) {
            continue;
        }
        if let Err(error) = state.es.delete_doc(ATTACKERS_INDEX, id).await {
            tracing::warn!(%error, id, "attacker-identity: prune self-only entity failed");
            continue;
        }
        tracing::info!(id, ?ips, "attacker-identity: pruned entity built entirely from now-excluded self/loopback traffic");
        pruned += 1;
    }
    Ok(pruned)
}

pub async fn attacker_identity_loop(state: AppState) {
    let window = env_duration("EVIDENCE_WINDOW", Duration::from_secs(6 * 3600));
    let interval = env_duration("ATTACKER_IDENTITY_RUN_INTERVAL", Duration::from_secs(15 * 60));
    loop {
        // #2181: the cycle ingests raw honeypot documents inline. The parse
        // paths below use unwrap_or-style accessors that cannot panic today,
        // so a per-event split would guard nothing real — this cycle-level
        // boundary is what keeps future drift from ending the task. A lost
        // cycle self-heals: entities rebuild from scratch over the full
        // window next interval.
        crate::isolate::cycle("attacker-identity", run_cycle(&state, window)).await;
        // Behind the same panic boundary run_cycle uses (#2181): an
        // anyhow::Result catches errors but not a panic, and a panic here
        // would unwind the whole loop task, not just this pass.
        if let Some(Err(error)) =
            crate::isolate::cycle("attacker-identity-prune", prune_self_only_entities(&state)).await
        {
            tracing::warn!(%error, "attacker-identity: self-only entity prune failed");
        }
        tokio::time::sleep(interval).await;
    }
}

// --------------------------------------------------------------------
// GET /api/v1/attackers/{id}/events (#2045)
// --------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EntityEventsQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_page_size")]
    pub size: u64,
}

fn default_page_size() -> u64 {
    25
}

#[utoipa::path(
    get,
    path = "/api/v1/attackers/{id}/events",
    summary = "The raw evidence behind one attacker entity.",
    params(
        ("id" = inline(String), Path, description = "Attacker entity id from /api/v1/attackers."),
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PositiveInt>), Query, description = "Page size."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 404, description = "No such record, store, or route for the values given.", body = String, content_type = "text/plain"),
        (status = 500, description = "The handler failed in a way it does not model as a 4xx.", body = String, content_type = "text/plain"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
/// The raw evidence behind an entity: resolves the persisted evidence
/// pointers (the newest-first event document ids the identity cycle
/// records on `attackers-v1`) against `honeypot-v2-*` -- the same family
/// fetch_recent_events read when it recorded them -- and pages them in
/// @timestamp order. Events that have aged out of retention simply stop
/// resolving, so `total` reflects what is actually retrievable right now
/// rather than a pointer count that over-promises 404-shaped rows.
pub async fn entity_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<EntityEventsQuery>,
) -> Result<Json<EventsPage>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc(ATTACKERS_INDEX, &id)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let Some(doc) = doc else {
        return Err((StatusCode::NOT_FOUND, format!("no such attacker entity: {id}")));
    };
    let entity: Entity =
        serde_json::from_value(doc).map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let mut page =
        EventsPage { total: 0, offset: q.offset, rows: Vec::new(), fingerprint_ips: None };
    if entity.evidence.is_empty() {
        return Ok(Json(page)); // pre-#2045 doc or a quiet window: no evidence recorded yet
    }

    // Cap the page at the pointer cap itself (500): bigger requests are
    // meaningless here, and from+size stays tiny across the wildcard.
    let size = q.size.clamp(1, EVIDENCE_CAP as u64);
    let result = state
        .es
        .search(json!({
            "size": size,
            "from": q.offset,
            "track_total_hits": true,
            "query": {"ids": {"values":
                entity.evidence.iter().map(|pointer| pointer.id.clone()).collect::<Vec<_>>()
            }},
            "sort": [{"@timestamp": {"order": "desc"}}]
        }))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    page.total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    page.rows = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(row_from_hit).collect())
        .unwrap_or_default();
    Ok(Json(page))
}

// --------------------------------------------------------------------
// tests -- ported from identity_test.go
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_verdicts_formats_labels_exactly_as_the_per_hash_lookup_did() {
        // #2041: the batched path must write byte-identical verdict
        // strings to the per-hash lookups it replaced -- a different
        // format would rewrite every stored verdict on the first cycle.
        let mut maps = VerdictMaps::default();
        // Map keys are FULL hashes -- load_verdict_maps keys them by doc id
        // / sandbox.sha256; only the rendered label uses the short prefix.
        maps.ghidra.insert("aaaaaaaa1111ffffffffffffffff".into(), "downloader".into());
        maps.sandbox.insert("bbbbbbbb2222ffffffffffffffff".into(), "sandbox: high risk".into());
        maps.github.insert("cccccccc3333ffffffffffffffff".into(), "ransomware".into());
        maps.revdeck.insert("dddddddd4444ffffffffffffffff".into(), "revdeck: looks like a loader".into());

        let mut e = Entity {
            id: "entity-v".into(),
            payloads: vec![
                "aaaaaaaa1111ffffffffffffffff".into(),
                "bbbbbbbb2222ffffffffffffffff".into(),
                "cccccccc3333ffffffffffffffff".into(),
                "dddddddd4444ffffffffffffffff".into(),
            ],
            ..Default::default()
        };
        apply_verdicts(&mut e, &maps);
        assert_eq!(
            e.verdicts,
            vec![
                "aaaaaaaa1111: downloader",
                "bbbbbbbb2222: sandbox: high risk",
                "cccccccc3333: ransomware",
                "dddddddd4444: revdeck: looks like a loader",
            ]
        );

        // A hash with no verdicts anywhere contributes nothing.
        let quiet = VerdictMaps::default();
        let mut bare = Entity { id: "bare".into(), payloads: vec!["eeeeeeee5555".into()], ..Default::default() };
        apply_verdicts(&mut bare, &quiet);
        assert!(bare.verdicts.is_empty());
    }

    fn obs(ip: &str, fp: &str, payload: &str, cred: &str) -> IpObservation {
        let mut signals = SignalSet::default();
        if !fp.is_empty() {
            signals.fingerprints.insert(fp.to_string());
        }
        if !payload.is_empty() {
            signals.payloads.insert(payload.to_string());
        }
        if !cred.is_empty() {
            signals.creds.insert(cred.to_string());
        }
        IpObservation {
            ip: ip.to_string(),
            signals,
            sensors: HashSet::new(),
            techniques: HashSet::new(),
            sensor_counts: BTreeMap::new(),
            dst_ips: HashSet::new(),
            ports: HashSet::new(),
            protocols: HashSet::new(),
            first: Some(chrono::Utc::now()),
            last: Some(chrono::Utc::now()),
            events: 1,
            evidence: VecDeque::new(),
        }
    }

    #[test]
    fn new_entity_id_is_a_pure_function_of_the_seed_ip() {
        assert_eq!(new_entity_id("203.0.113.5"), new_entity_id("203.0.113.5"));
        assert_ne!(new_entity_id("203.0.113.5"), new_entity_id("203.0.113.6"));
    }

    #[test]
    fn candidate_terms_cover_every_observed_ip_and_signal() {
        // #2651: the candidate load replaced a whole-population scan, so
        // the term lists are now the only thing standing between a stored
        // entity and being recreated blank under its own id. Everything the
        // window saw has to be in them, deduped and sorted so two runs over
        // the same window issue identical queries.
        let mut observations = HashMap::new();
        observations.insert("198.51.100.9".to_string(), obs("198.51.100.9", "fp-b", "sha-b", "root / b"));
        observations.insert("198.51.100.8".to_string(), obs("198.51.100.8", "fp-a", "sha-a", "root / a"));
        // A second IP carrying the same fingerprint must not double it up.
        observations.insert("198.51.100.7".to_string(), obs("198.51.100.7", "fp-a", "", ""));

        let terms = candidate_terms(&observations);
        assert_eq!(terms.ips, vec!["198.51.100.7", "198.51.100.8", "198.51.100.9"]);
        assert_eq!(terms.fingerprints, vec!["fp-a", "fp-b"]);
        assert_eq!(terms.payloads, vec!["sha-a", "sha-b"]);
        assert_eq!(terms.creds, vec!["root / a", "root / b"]);
    }

    #[test]
    fn every_entity_a_cycle_can_touch_is_reachable_from_the_candidate_terms() {
        // The correctness argument for loading candidates instead of the
        // whole index: an entity is only reached through one of its own IPs
        // or by clearing MERGE_THRESHOLD shared signals, and either way at
        // least one of its stored field values is in a term list. An entity
        // with nothing in common is never touched, so never needed loading.
        let mut observations = HashMap::new();
        observations.insert(
            "203.0.113.10".to_string(),
            obs("203.0.113.10", "fp-shared", "sha-shared", ""),
        );
        let terms = candidate_terms(&observations);

        // Shares two signals, so it absorbs the new IP -- and the
        // fingerprint/payload terms both find it.
        let mergeable = Entity {
            id: new_entity_id("203.0.113.11"),
            ips: vec!["203.0.113.11".to_string()],
            fingerprints: vec!["fp-shared".to_string()],
            payloads: vec!["sha-shared".to_string()],
            ..Default::default()
        };
        assert!(mergeable
            .fingerprints
            .iter()
            .any(|f| terms.fingerprints.contains(f)));

        let (changed, _) = resolve_identities(vec![mergeable.clone()], &observations);
        assert_eq!(changed.len(), 1, "the shared signals should have merged, not forked");
        assert_eq!(changed[0].id, mergeable.id);

        // Shares nothing: no term matches it, and resolve_identities leaves
        // it alone -- the two statements have to agree for the scoped load
        // to be lossless.
        let unrelated = Entity {
            id: new_entity_id("203.0.113.99"),
            ips: vec!["203.0.113.99".to_string()],
            fingerprints: vec!["fp-other".to_string()],
            payloads: vec!["sha-other".to_string()],
            ..Default::default()
        };
        assert!(!terms.ips.contains(&unrelated.ips[0]));
        assert!(!terms.fingerprints.contains(&unrelated.fingerprints[0]));
        assert!(!terms.payloads.contains(&unrelated.payloads[0]));

        let (changed, absorbed) = resolve_identities(vec![unrelated.clone()], &observations);
        assert!(absorbed.is_empty());
        assert!(
            changed.iter().all(|e| e.id != unrelated.id),
            "an entity sharing no signal must not be touched, so not loading it loses nothing"
        );
    }

    #[test]
    fn rescanning_the_same_sliding_window_does_not_inflate_events() {
        // #2040: every cycle re-fetches the whole EVIDENCE_WINDOW, so an
        // active IP's window is re-absorbed onto the persisted entity once
        // per RUN_INTERVAL. The lifetime counter may only advance by what
        // actually grew past the previous cycle's window count.
        let mut observations = HashMap::new();
        let mut o = obs("203.0.113.7", "fp-e", "sha-e", "");
        o.events = 3;
        observations.insert("203.0.113.7".to_string(), o);

        let (first, _) = resolve_identities(Vec::new(), &observations);
        assert_eq!(first[0].events, 3);
        assert_eq!(first[0].window_events, Some(3));

        // Next cycle: same window re-fetched (nothing new arrived).
        let (second, _) = resolve_identities(first.clone(), &observations);
        assert_eq!(
            second[0].events, 3,
            "re-absorbing an unchanged evidence window must not inflate the lifetime counter"
        );

        // The window then slides: 2 events aged out, 4 new arrived.
        let mut observations = HashMap::new();
        let mut o = obs("203.0.113.7", "fp-e", "sha-e", "");
        o.events = 4;
        observations.insert("203.0.113.7".to_string(), o);
        let (third, _) = resolve_identities(second, &observations);
        assert_eq!(third[0].events, 4, "only growth over the previous window advances the counter");

        // And a shrinking window (everything aged out) must not rewind it.
        let mut observations = HashMap::new();
        let mut o = obs("203.0.113.7", "fp-e", "sha-e", "");
        o.events = 1;
        observations.insert("203.0.113.7".to_string(), o);
        let (fourth, _) = resolve_identities(third, &observations);
        assert_eq!(fourth[0].events, 4, "a shrinking window must not rewind the lifetime counter");
        assert_eq!(fourth[0].window_events, Some(1));
    }

    #[test]
    fn pre_2040_docs_restart_their_counter_on_first_touch() {
        // Docs written before #2040 accumulated whole windows per cycle and
        // carry inflated `events` with no `window_events` baseline; the
        // missing marker migrates them exactly once.
        let existing = vec![Entity {
            id: "legacy".into(),
            ips: vec!["9.9.9.9".into()],
            fingerprints: vec!["fp-legacy".into()],
            events: 987_654,
            ..Default::default()
        }];
        let mut observations = HashMap::new();
        let mut o = obs("9.9.9.9", "fp-legacy", "", "");
        o.events = 2;
        observations.insert("9.9.9.9".to_string(), o);

        let (changed, absorbed) = resolve_identities(existing, &observations);
        assert!(absorbed.is_empty());
        assert_eq!(changed.len(), 1);
        assert_eq!(
            changed[0].events, 2,
            "a legacy doc's inflated counter must be replaced by this cycle's window, not added to"
        );
        assert_eq!(changed[0].window_events, Some(2));

        // From there on it behaves like any other doc: unchanged window,
        // no inflation.
        let (again, _) = resolve_identities(changed, &observations);
        assert_eq!(again[0].events, 2);
    }

    #[test]
    fn absorbing_an_entity_folds_its_lifetime_and_window_baseline() {
        // A new IP sharing two signal categories with BOTH existing
        // entities is what triggers an absorption here -- already-member
        // IPs go straight to their own entity and never re-match. A
        // absorbs B; B's lifetime counter and window baseline must fold
        // into A so next cycle's delta treats B's IPs' activity as
        // already seen, not as new (#2040).
        let existing = vec![
            Entity {
                id: "entity-a".into(),
                ips: vec!["1.1.1.1".into()],
                fingerprints: vec!["fp-a".into()],
                payloads: vec!["sha-a".into()],
                events: 10,
                window_events: Some(4),
                ..Default::default()
            },
            Entity {
                id: "entity-b".into(),
                ips: vec!["2.2.2.2".into()],
                fingerprints: vec!["fp-a".into()],
                payloads: vec!["sha-a".into()],
                events: 6,
                window_events: Some(2),
                ..Default::default()
            },
        ];
        // Only 3.3.3.3 is active this cycle: 5 events. The merged doc's
        // previous-window baseline is 4+2=6, so the counter must hold at
        // the folded 16 -- absorbing must not let the shrink become a
        // rewind, and folding must not let B's baseline be lost.
        let mut observations = HashMap::new();
        let mut o = obs("3.3.3.3", "fp-a", "sha-a", "");
        o.events = 5;
        observations.insert("3.3.3.3".to_string(), o);

        let (changed, absorbed) = resolve_identities(existing, &observations);
        assert_eq!(absorbed, vec!["entity-b"]);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].events, 16);
        assert_eq!(changed[0].window_events, Some(5));
        assert_eq!(
            changed[0].ips,
            vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            "B's member IPs must land on the surviving entity"
        );
    }

    #[test]
    fn two_independent_first_sightings_of_the_same_ip_converge_on_one_entity_id() {
        // Simulates two uncoordinated writers (concurrent replicas, or the
        // same worker racing itself across a restart) each observing the
        // same never-before-seen IP with no existing entity yet -- the
        // scenario that used to mint two different, colliding entity ids
        // before new_entity_id dropped its timestamp seed.
        let mut observations = HashMap::new();
        observations.insert("203.0.113.9".to_string(), obs("203.0.113.9", "fp-x", "sha-x", ""));
        let (run_a, _) = resolve_identities(Vec::new(), &observations);
        let (run_b, _) = resolve_identities(Vec::new(), &observations);
        assert_eq!(run_a.len(), 1);
        assert_eq!(run_b.len(), 1);
        assert_eq!(run_a[0].id, run_b[0].id, "two independent first-sighting runs must mint the identical entity id");
    }

    #[test]
    fn single_shared_signal_never_merges() {
        let mut observations = HashMap::new();
        observations.insert("1.1.1.1".to_string(), obs("1.1.1.1", "fp-a", "", ""));
        observations.insert("2.2.2.2".to_string(), obs("2.2.2.2", "fp-a", "", ""));
        let (changed, absorbed) = resolve_identities(Vec::new(), &observations);
        assert!(absorbed.is_empty());
        assert_eq!(changed.len(), 2, "one shared signal category must create two separate entities, not merge");
    }

    #[test]
    fn two_shared_signals_merge_into_one_entity() {
        let mut observations = HashMap::new();
        observations.insert("1.1.1.1".to_string(), obs("1.1.1.1", "fp-a", "sha-a", ""));
        observations.insert("2.2.2.2".to_string(), obs("2.2.2.2", "fp-a", "sha-a", ""));
        let (changed, absorbed) = resolve_identities(Vec::new(), &observations);
        assert!(absorbed.is_empty());
        assert_eq!(changed.len(), 1, "two shared signal categories must merge into one entity");
        assert_eq!(changed[0].ips, vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn transitive_merge_in_one_cycle_folds_all_three() {
        // A<->B share fingerprint+payload; B<->C share fingerprint+cred.
        // Processed in IP-sorted order (deterministic), C's own match
        // against the entity A+B already formed this same cycle must still
        // fold C in, not create a separate entity.
        let mut observations = HashMap::new();
        observations.insert("1.1.1.1".to_string(), obs("1.1.1.1", "fp-shared", "sha-ab", ""));
        observations.insert("2.2.2.2".to_string(), obs("2.2.2.2", "fp-shared", "sha-ab", "user / pass"));
        observations.insert("3.3.3.3".to_string(), obs("3.3.3.3", "fp-shared", "", "user / pass"));
        let (changed, absorbed) = resolve_identities(Vec::new(), &observations);
        assert!(absorbed.is_empty(), "no pre-existing entities to absorb in a single-cycle transitive merge");
        assert_eq!(changed.len(), 1, "all three IPs must resolve to one entity");
        assert_eq!(changed[0].ips, vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    }

    #[test]
    fn merging_two_existing_entities_absorbs_one() {
        let existing = vec![
            Entity { id: "entity-a".into(), ips: vec!["1.1.1.1".into()], fingerprints: vec!["fp-a".into()], payloads: vec!["sha-a".into()], first: "2026-01-01T00:00:00Z".into(), last: "2026-01-01T00:00:00Z".into(), ..Default::default() },
            Entity { id: "entity-b".into(), ips: vec!["2.2.2.2".into()], fingerprints: vec!["fp-a".into()], payloads: vec!["sha-a".into()], first: "2026-01-02T00:00:00Z".into(), last: "2026-01-02T00:00:00Z".into(), ..Default::default() },
        ];
        let mut observations = HashMap::new();
        observations.insert("3.3.3.3".to_string(), obs("3.3.3.3", "fp-a", "sha-a", ""));
        let (changed, absorbed) = resolve_identities(existing, &observations);
        assert_eq!(absorbed, vec!["entity-b".to_string()]);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].id, "entity-a", "the first-encountered matching entity survives, later matches are absorbed into it");
        assert_eq!(changed[0].ips, vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    }

    #[test]
    fn untouched_existing_entities_are_not_returned() {
        let existing = vec![Entity {
            id: "entity-quiet".into(),
            ips: vec!["9.9.9.9".into()],
            ..Default::default()
        }];
        let observations = HashMap::new();
        let (changed, absorbed) = resolve_identities(existing, &observations);
        assert!(changed.is_empty(), "an entity with no new evidence this cycle must not be rewritten");
        assert!(absorbed.is_empty());
    }

    #[test]
    fn scan_shape_classifies_sweeps_and_port_rakes_only() {
        assert_eq!(scan_shape(30, 2), "horizontal");
        assert_eq!(scan_shape(25, 40), "horizontal"); // host count wins
        assert_eq!(scan_shape(4, 60), "vertical");
        assert_eq!(scan_shape(5, 25), "vertical");
        // Ordinary traffic never earns the badge.
        assert_eq!(scan_shape(3, 4), "");
        assert_eq!(scan_shape(24, 24), ""); // under both windows
        // Port-heavy but spread past the vertical host cap reads as neither.
        assert_eq!(scan_shape(6, 60), "");
    }

    #[test]
    fn valid_credential_pair_rejects_shell_markers() {
        assert!(!valid_credential_pair("root", "/bin/sh"));
        assert!(!valid_credential_pair("root", "powershell -enc AAAA"));
        assert!(valid_credential_pair("admin", "hunter2"));
        assert!(!valid_credential_pair("", ""));
    }

    #[test]
    fn shared_signal_count_requires_real_intersection() {
        let mut a = SignalSet::default();
        a.fingerprints.insert("fp-1".into());
        a.payloads.insert("sha-1".into());
        let mut b = SignalSet::default();
        b.fingerprints.insert("fp-1".into());
        b.payloads.insert("sha-2".into());
        assert_eq!(shared_signal_count(&a, &b), 1, "only fingerprints overlap");
    }

    /// #2094: the whole point of the pending marker -- an entity whose
    /// payloads stopped changing but whose last refresh was deferred by a
    /// failed store lookup goes back into the verify set; an entity that
    /// was refreshed normally does not.
    #[test]
    fn needs_verdict_refresh_requeues_a_deferred_entity() {
        let payloads = vec!["aaaaaaaa1111ffffffffffffffff".to_string()];
        let mut e = Entity { id: "e".into(), payloads: payloads.clone(), ..Default::default() };

        // Unchanged payloads, nothing deferred: the #2041 quiet path.
        assert!(!needs_verdict_refresh(&e, Some(&payloads)));

        // Same unchanged payloads, but the last cycle owed this entity a
        // refresh and couldn't run it.
        e.verdicts_pending = true;
        assert!(needs_verdict_refresh(&e, Some(&payloads)));

        // Changed payloads verify regardless of the marker.
        e.verdicts_pending = false;
        let other = vec!["bbbbbbbb2222ffffffffffffffff".to_string()];
        assert!(needs_verdict_refresh(&e, Some(&other)));
        // Fresh entities (no persisted baseline) always verify.
        assert!(needs_verdict_refresh(&e, None));
    }

    /// #2094: the marker must survive the Working roundtrip so it lands on
    /// the document written the cycle it was set -- and on merged entities
    /// that inherit it from one of their sources.
    #[test]
    fn verdicts_pending_survives_the_working_roundtrip() {
        let mut e = Entity {
            id: "entity-p".into(),
            payloads: vec!["aaaaaaaa1111ffffffffffffffff".into()],
            first: "2026-01-01T00:00:00Z".into(),
            last: "2026-01-01T00:00:00Z".into(),
            verdicts_pending: true,
            ..Default::default()
        };
        assert!(finalize_entity(&working_from_entity(&e)).verdicts_pending);

        // A freshly built working form starts clean.
        assert!(!new_working("entity-n".to_string()).verdicts_pending);

        // And clearing it on a later successful refresh persists too.
        e.verdicts_pending = false;
        assert!(!finalize_entity(&working_from_entity(&e)).verdicts_pending);

        // Absorption propagates it: an entity merged into one that owed a
        // refresh keeps the debt on the surviving document (#2094).
        let mut debtor = new_working("debtor".into());
        debtor.verdicts_pending = true;
        let mut survivor = new_working("survivor".into());
        merge_entity_into(&mut survivor, &debtor);
        assert!(survivor.verdicts_pending);
    }

    /// #2094: pre-fix documents have no verdicts_pending field at all --
    /// serde default keeps them deserializing as false, and a false flag
    /// stays out of the written JSON so the stored docs don't grow a
    /// permanent new key.
    #[test]
    fn verdicts_pending_is_defaulted_on_old_docs_and_omitted_when_false() {
        let old_doc = json!({
            "id": "entity-old",
            "payloads": ["aaaaaaaa1111ffffffffffffffff"],
            "verdicts": ["aaaaaaaa1111: downloader"]
        });
        let parsed: Entity = serde_json::from_value(old_doc).expect("pre-#2094 doc parses");
        assert!(!parsed.verdicts_pending);

        let mut flagged = Entity { id: "f".into(), ..Default::default() };
        let without = serde_json::to_value(&flagged).unwrap();
        assert!(without.get("verdicts_pending").is_none(), "false flag is not serialized");

        flagged.verdicts_pending = true;
        let with = serde_json::to_value(&flagged).unwrap();
        assert_eq!(with["verdicts_pending"], json!(true));
    }

    /// #2047: the projection reader and the live readers share these label
    /// builders -- pin their wording so a refactor can't make the fast path
    /// emit labels the slow path would never have written.
    #[test]
    fn projection_label_builders_match_the_live_wording() {
        assert_eq!(
            ghidra_label(&json!({"ghidra": {"ai_triage": {"family_guess": "win.lumma"}}})),
            Some("win.lumma".to_string())
        );
        assert_eq!(ghidra_label(&json!({"ghidra": {"ai_triage": {"family_guess": ""}}})), None);

        assert_eq!(
            github_label(&json!({"github_analysis": {"family": "apk.dropper"}})),
            Some("apk.dropper".to_string())
        );

        // Only completed runs with a non-empty answer count, truncated at
        // REVDECK_ANSWER_LIMIT by chars, never bytes.
        assert_eq!(
            revdeck_label(&json!({"revdeck": {"revdeck": {"status": "completed", "answer": "credential stealer"}}})),
            Some("revdeck: credential stealer".to_string())
        );
        assert_eq!(
            revdeck_label(&json!({"revdeck": {"revdeck": {"status": "failed", "answer": "nope"}}})),
            None
        );
        let long = "x".repeat(REVDECK_ANSWER_LIMIT + 10);
        if let Some(label) = revdeck_label(&json!({"revdeck": {"revdeck": {"status": "completed", "answer": long}}})) {
            let answer = label.strip_prefix("revdeck: ").unwrap();
            assert_eq!(answer.chars().count(), REVDECK_ANSWER_LIMIT + 1); // + ellipsis
            assert!(answer.ends_with('…'));
        } else {
            panic!("completed run with an answer must produce a label");
        }

        // The projection carries one reduced level; sub-threshold levels
        // are present data but not verdicts.
        assert_eq!(
            sandbox_projection_label(&json!({"sandbox": {"risk_level": "high"}})),
            Some("sandbox: high risk".to_string())
        );
        assert_eq!(
            sandbox_projection_label(&json!({"sandbox": {"risk_level": "low"}})),
            None
        );
    }

    // -- #2900: self-only entity pruning --

    #[test]
    fn loopback_only_membership_is_self_only() {
        let self_ips: HashSet<String> = self_only_prune_candidates().into_iter().collect();
        assert!(is_self_only_entity(&["127.0.0.1".to_string()], &self_ips));
        assert!(is_self_only_entity(&["::1".to_string()], &self_ips));
    }

    #[test]
    fn a_real_attacker_ip_is_never_pruned() {
        let self_ips: HashSet<String> = self_only_prune_candidates().into_iter().collect();
        assert!(!is_self_only_entity(&["203.0.113.55".to_string()], &self_ips));
    }

    /// The exact regression case (#2900): an entity that merged a genuine
    /// attacker IP together with loopback (e.g. via a shared signal) must
    /// survive pruning — only entities that are self-traffic and *nothing
    /// else* qualify.
    #[test]
    fn mixed_membership_survives_even_with_a_self_ip_present() {
        let self_ips: HashSet<String> = self_only_prune_candidates().into_iter().collect();
        assert!(!is_self_only_entity(
            &["127.0.0.1".to_string(), "203.0.113.55".to_string()],
            &self_ips
        ));
    }

    #[test]
    fn empty_ips_is_never_pruned() {
        let self_ips: HashSet<String> = self_only_prune_candidates().into_iter().collect();
        assert!(!is_self_only_entity(&[], &self_ips));
    }

    /// #2900: the prune must match on the `keyword` subfield. On the
    /// analyzed `ips` field the literal `::1` tokenises to `1` and can never
    /// match a document whose `ips` is `::1`, which would leave half of
    /// LOOPBACK_IPS dead on the retrieval side while the membership tests
    /// below still passed.
    #[test]
    fn the_prune_query_matches_the_keyword_subfield_not_the_analyzed_one() {
        let candidates = self_only_prune_candidates();
        let body = prune_query(&candidates);
        assert!(
            body["query"]["terms"]["ips.keyword"].is_array(),
            "prune query must filter on ips.keyword, got: {body}"
        );
        assert!(
            body["query"]["terms"]["ips"].is_null(),
            "prune query must not filter on the analyzed ips field, got: {body}"
        );
        let queried: Vec<&str> = body["query"]["terms"]["ips.keyword"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(queried.contains(&"127.0.0.1"));
        assert!(queried.contains(&"::1"));
    }

    #[test]
    fn prune_candidates_include_loopback_and_the_configured_self_addresses() {
        let candidates = self_only_prune_candidates();
        assert!(candidates.contains(&"127.0.0.1".to_string()));
        assert!(candidates.contains(&"::1".to_string()));
        // dashboard::self_addresses() always includes the tunnel peer.
        assert!(candidates.iter().any(|ip| ip == "10.8.0.1"));
    }
}
