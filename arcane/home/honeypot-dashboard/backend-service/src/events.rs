//! /api/v1/events — the event explorer's list slice: newest-first ECS
//! events with offset paging (the View-more contract: the client asks for
//! exactly the next batch, nothing loads on scroll) and the filter fields
//! the Go explorer exposes (ip, sensor, country, port, proto, since).

use crate::contract;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{event_detail::detail_for, secrets_boundary, AppState};

#[derive(Deserialize, Clone)]
pub struct EventsQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
    pub ip: Option<String>,
    /// #1682: comma-separated source IPs to narrow to — the "Isolate
    /// IP…" checklist (events.html:76-99) applies this alongside
    /// `fingerprint` to pick one attacker among several sharing it.
    /// Distinct from `ip` (the single-IP attack-chain view): this can
    /// carry more than one address.
    pub ips: Option<String>,
    pub sensor: Option<String>,
    pub country: Option<String>,
    /// City drill-in from the overview map pins (#2045): dashboard.rs's
    /// map_points bucket on `multi_terms(source.geo.city_name,
    /// source.geo.country_iso_code)`, so a pin click can now narrow to the
    /// exact city instead of the nearest-country fallback this endpoint
    /// previously documented as a caveat.
    pub city: Option<String>,
    pub port: Option<String>,
    pub proto: Option<String>,
    /// honeypot.event kind filter ("command", "login", ...).
    pub kind: Option<String>,
    /// Captured-payload hash pivot (a RevDeck/Ghidra/payload-analysis page
    /// linking back to "related events") — same honeypot.shasum field
    /// fusion.rs's own "Payload hash" pivot already filters on.
    pub shasum: Option<String>,
    /// #1783: one flow, across every sensor that saw it.
    ///
    /// network.community_id is the same v1 hash computed independently by
    /// Zeek, huginn, Suricata and portbridge, so filtering on it collapses a
    /// single TCP connection's records from all of them into one view. That
    /// is a different question from the src_ip filter above: an address
    /// answers "what else did this host do", a community_id answers "what
    /// happened on this connection".
    pub community_id: Option<String>,
    /// Free-text query_string search (the /history page's q=), same
    /// semantics as the Go tier's ES q= passthrough.
    pub q: Option<String>,
    /// Go-style duration ("24h", "7d") relative to now; defaults to the
    /// explorer's rolling window.
    pub since: Option<String>,
    // ── Pivot filters (#1653): the everow detail-pane links the Go
    // explorer rendered (events.html:23-26) all filter here. honeypot.*
    // is flattened — exact terms work; each pivot accepts the value its
    // corresponding link carries.
    /// Decoy persona (honeypot.persona_id).
    pub persona: Option<String>,
    /// Decoy site (honeypot.site_id).
    pub site: Option<String>,
    /// Decoy asset (honeypot.asset_id).
    pub asset: Option<String>,
    /// Client fingerprint — matches any of the fields sensors record one
    /// in (canonical_fingerprint, hassh, fingerprint, client, user_agent).
    pub fingerprint: Option<String>,
    /// Exact command text (canonical_command, command, input).
    pub cmd: Option<String>,
    /// "user / pass" credential pair, split on the legacy separator.
    ///
    /// #3213: a bare account is accepted on its own and filters the account
    /// half only. Still a filter rather than a response -- nothing is echoed
    /// back from it -- and the pass half simply stops matching for
    /// http-honeypot and cisco-asa-honeypot, whose documents no longer carry
    /// the field. It continues to work for the sensors outside this issue's
    /// scope.
    pub cred: Option<String>,
    /// Request path (honeypot.path, honeypot.url).
    pub path: Option<String>,
    /// Session id (honeypot.session / session.id / honeypot.session_id).
    pub session: Option<String>,
    /// Source AS number (source.as.asn).
    pub asn: Option<String>,
    /// Source network organization (source.as.organization_name).
    pub org: Option<String>,
    /// Provider class (source.as.type).
    pub provider: Option<String>,
    /// IDS alert signature, exact match (suricata.eve.alert.signature.keyword).
    pub sig: Option<String>,
    /// Detection category (suricata alert category or honeypot.category).
    pub cat: Option<String>,
}

fn default_size() -> u64 {
    25
}

/// The pivot values the explorer's detail pane renders as link groups —
/// the Go tier's classified-event fields (decoy / pivot / origin /
/// detection / recording, events.html:23-27), extracted here so the
/// frontend never re-derives per-sensor field naming. Empty string means
/// "absent"; the pane skips empty groups.
#[derive(Serialize)]
pub struct EventPivots {
    pub persona: String,
    pub site: String,
    pub asset: String,
    pub fingerprint: String,
    pub fingerprint_kind: String,
    pub command: String,
    pub user: String,
    /// #3213: empty for http-honeypot and cisco-asa-honeypot. The field
    /// stays because the sensors outside this issue's scope still populate
    /// it, and deleting it would be a breaking change to a dozen rows the
    /// issue is not about. A pivot is a FILTER value, so an empty one simply
    /// renders no link -- and the frontend builds the `cred` link only when
    /// both halves are present, rather than emitting a dangling
    /// `admin / ` that would filter on an empty password.
    pub pass: String,
    pub path: String,
    pub shasum: String,
    pub asn: String,
    pub org: String,
    pub provider: String,
    pub alert: String,
    pub category: String,
    /// What the request carried, as opposed to what it asked for (#1888).
    ///
    /// Separate from `category` because they answer different questions and
    /// routinely disagree: an SQL injection POSTed to a WordPress bait path
    /// is a "wordpress" request carrying an "sqli" payload, and until now
    /// the explorer could only show one of the two. Only http-honeypot
    /// emits it, so it is empty for most rows.
    pub payload_class: String,
    /// Route to the in-app TTY replay when this event closed a recorded
    /// session (cowrie.log.closed — its `shasum` is the recording's own
    /// hash, deliberately NOT surfaced as a payload hash; see
    /// classify.go's #638/#1266 note).
    pub tty_replay: String,
    /// DNP3 control-function severity ("critical"/"high"/""), from the
    /// frame's `app_function`. The Go tier carried this on
    /// `storedEvent.ICSSeverity` and badged it in the events explorer; the
    /// port dropped the field, so a DIRECT_OPERATE — a command that trips
    /// physical equipment with no confirmation step — rendered
    /// indistinguishably from a benign link-status read. See
    /// `ics_severity.rs`.
    pub ics_severity: String,
}

pub fn pivots_from_source(src: &Value) -> EventPivots {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    // #3213: `pass` is one of the pivots this function reads, so the guard
    // belongs here, on the function that reads it. For the two decoys in
    // scope `pass` now comes back empty -- the secret was removed at the
    // sensor for new events and by the boundary for stored ones -- while
    // cowrie, tanner and the rest keep theirs, which is the remaining
    // exposure #3213's PR body declares rather than hides.
    let scrubbed = secrets_boundary::scrub_event(&text(&src["event"]["sensor"]), &src["honeypot"]);
    let hp = scrubbed.as_ref().unwrap_or(&src["honeypot"]);
    let first = |keys: &[&str]| -> String {
        keys.iter().map(|k| text(&hp[*k])).find(|s| !s.is_empty()).unwrap_or_default()
    };
    let eventid = text(&hp["eventid"]);
    let is_tty_close = eventid == "cowrie.log.closed";
    let (fingerprint, fingerprint_kind) = {
        let canonical = text(&hp["canonical_fingerprint"]);
        if !canonical.is_empty() {
            (canonical, {
                let kind = text(&hp["canonical_fingerprint_kind"]);
                if kind.is_empty() { "fingerprint".to_string() } else { kind }
            })
        } else if !text(&hp["hassh"]).is_empty() {
            (text(&hp["hassh"]), "HASSH".to_string())
        } else if !text(&hp["fingerprint"]).is_empty() {
            (text(&hp["fingerprint"]), "SSH pubkey".to_string())
        } else if !text(&hp["client"]).is_empty() {
            (text(&hp["client"]), "client banner".to_string())
        } else if !text(&hp["user_agent"]).is_empty() {
            (text(&hp["user_agent"]), "User-Agent".to_string())
        } else {
            (String::new(), String::new())
        }
    };
    EventPivots {
        persona: text(&hp["persona_id"]),
        site: text(&hp["site_id"]),
        asset: text(&hp["asset_id"]),
        fingerprint,
        fingerprint_kind,
        command: first(&["canonical_command", "command", "input"]),
        user: first(&["canonical_user", "username"]),
        pass: first(&["canonical_pass", "password"]),
        path: first(&["path", "url", "query"]),
        shasum: if is_tty_close { String::new() } else { first(&["canonical_shasum", "shasum"]) },
        asn: src["source"]["as"]["asn"].as_u64().map(|n| n.to_string()).unwrap_or_default(),
        org: text(&src["source"]["as"]["organization_name"]),
        provider: text(&src["source"]["as"]["type"]),
        alert: text(&src["suricata"]["eve"]["alert"]["signature"]),
        payload_class: text(&hp["payload_class"]),
        category: {
            let sig_cat = text(&src["suricata"]["eve"]["alert"]["category"]);
            if sig_cat.is_empty() { text(&hp["category"]) } else { sig_cat }
        },
        tty_replay: if is_tty_close && !text(&hp["shasum"]).is_empty() {
            format!("/tty-replay/{}", text(&hp["shasum"]))
        } else {
            String::new()
        },
        ics_severity: crate::ics_severity::dnp3_function_severity(&text(&hp["app_function"])).to_string(),
    }
}

#[derive(Serialize)]
pub struct EventRow {
    /// #1876: the address the request claimed, when two joins disagreed.
    ///
    /// The enrichment worker resolves a relayed event two ways -- from the
    /// connection portbridge recorded, and from the forwarded header the
    /// request carried. Where both answer and they differ, the connection
    /// wins (it is evidence about the connection rather than content
    /// inside it) and the claim is kept here rather than discarded: on the
    /// portbridge path a disagreement is an attacker setting their own
    /// X-Forwarded-For, and dropping it would hide the attempt.
    ///
    /// Empty when the two agreed, or when only one of them answered.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub src_ip_claimed: String,
    /// The document id, so a row can link to its own full page (#1868).
    ///
    /// Empty where there is no hit to take it from: the SSE live stream
    /// carries a `_source` and nothing else, and the CSV export has no use
    /// for it. A row without an id simply offers no full-detail action,
    /// which is honest — the alternative is a link that 404s.
    #[serde(default)]
    pub id: String,
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub country: String,
    pub port: String,
    /// Source port of the attacker's connection, from `source.port`, or the
    /// Suricata alert's own `src_port` when that is all the document has.
    ///
    /// Absent when no document carries one, and absent when the row has no
    /// attacker address to attach it to: a fleet-address row's port belongs
    /// to the tunnel peer, not to anyone the analyst should be looking at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    /// City from `source.geo.city_name`. Absent when the address did not
    /// resolve to a city; the country code is always on the row separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Normalized severity: "high", "medium" or "low". Absent when the event
    /// carries no rating, which is most events: the honeypots write none of
    /// their own. See `severity_from_source` for the mapping. It is never
    /// defaulted to a value for an unrated event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<&'static str>,
    /// Normalized event kind: "connection", "login", "command", "download",
    /// "http" or "alert". Absent when the producer's own event name does not
    /// map onto one of these. See `kind_from_source` for the mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    /// MITRE ATT&CK technique ids the rule that fired assigned to this event,
    /// e.g. "T1190". Empty (and omitted) when no rule assigned one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub techniques: Vec<String>,
    pub proto: String,
    pub detail: String,
    pub session: String,
    /// Detail-pane pivot groups (#1653) — see EventPivots.
    pub pivots: EventPivots,
    /// The complete normalized ECS document, for the record inspector pane
    /// (the row click opens it). #1611 workstream E.4: this is also where
    /// `network.community_id` (when suricata populated it) is already
    /// visible and copyable — it's the exact join key an Arkime cross-link
    /// needs, so no separate field/endpoint is required on this side; the
    /// pivot link itself is a frontend concern.
    ///
    /// #3213: "nothing is hidden" is no longer literally true, and the
    /// exception is deliberate. For `http-honeypot` and
    /// `cisco-asa-honeypot` this field used to hand a captured password to
    /// every row of the list, the SSE live stream and both CSV exports —
    /// the widest read surface the document has. `secrets_boundary` scrubs
    /// it at construction, so what the inspector shows is the document with
    /// credential values replaced by `[redacted]`, alongside the two axes
    /// that describe them. Out-of-scope sensors are unchanged; see
    /// `secrets_boundary` for the sensors still carrying plaintext.
    pub record: Value,
}

/// One distinct source IP behind the current fingerprint match (#278 /
/// #1682's "Isolate IP…" checklist).
#[derive(Serialize)]
pub struct CorrelatedIp {
    pub ip: String,
    pub count: u64,
    pub checked: bool,
}

#[derive(Serialize)]
pub struct EventsPage {
    pub total: u64,
    pub offset: u64,
    pub rows: Vec<EventRow>,
    /// The distinct IPs behind `fingerprint`, pre-checked to match `ips`
    /// — absent unless a fingerprint filter is active AND more than one
    /// IP is behind it (nothing to isolate otherwise). Evaluated against
    /// every other active filter, but never `ips` itself, so narrowing
    /// the selection doesn't also shrink the checklist to just what's
    /// still checked (pages_data.go's fingerprintIPCorrelation).
    pub fingerprint_ips: Option<Vec<CorrelatedIp>>,
}

/// Distinct source IPs sharing the active fingerprint filter, most
/// frequent first (ties broken by IP for a stable order) — an ES terms
/// aggregation standing in for the Go tier's in-memory count-and-sort
/// over its full per-request event slice.
async fn fingerprint_ip_correlation(state: &AppState, q: &EventsQuery) -> Option<Vec<CorrelatedIp>> {
    if q.fingerprint.as_deref().unwrap_or("").is_empty() {
        return None;
    }
    let mut base = q.clone();
    base.ips = None;
    let filters = build_filters(&base);
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}},
        "aggs": {"ips": {"terms": {"field": "source.ip", "size": 50, "order": [{"_count": "desc"}, {"_key": "asc"}]}}}
    });
    let result = state.es.search(body).await.ok()?;
    let buckets = result["aggregations"]["ips"]["buckets"].as_array()?;
    if buckets.len() < 2 {
        return None;
    }
    let selected: Vec<&str> = q
        .ips
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    Some(
        buckets
            .iter()
            .filter_map(|bucket| {
                let ip = bucket["key"].as_str()?.to_string();
                let count = bucket["doc_count"].as_u64().unwrap_or(0);
                let checked = selected.is_empty() || selected.contains(&ip.as_str());
                Some(CorrelatedIp { ip, count, checked })
            })
            .collect(),
    )
}

/// Excludes suricata's high-volume, low-signal event types (flow/netflow/
/// stats — 5700+/hour on a real deployment vs. 50 alert/anomaly events in
/// the same window) from the default events view, matching
/// dashboard/classify.go's own legacy posture (`ev.skip = true` for every
/// suricata event_type except alert/anomaly — classify.go:1117). #1611
/// workstream A: unlike classify.go, this crate DOES render http/tls/ssh/
/// smtp/dns/fileinfo detail (src/detail.rs), so only the three genuinely
/// swamping types stay excluded here.
pub fn suricata_noise_exclusion() -> Value {
    json!([
        {"terms": {"suricata.eve.event_type": ["flow", "netflow", "stats"]}},
        // #1873: the fleet probing itself is not an event.
        //
        // dashboard.rs, health.rs and worker.rs all drop internal_probe
        // traffic; the explorer never got the filter, so it was the one
        // surface rendering it. Measured over six hours: 68,115 documents
        // marked internal_probe and 68,819 sourced from 127.0.0.1, none
        // with a source.ip -- roughly 270k rows a day of the fleet talking
        // to itself, shown as events with no attacker. That is the bulk of
        // what reads as "unattributed" in the explorer.
        crate::es::internal_probe_exclusion(),
        // #1892: a sensor's own startup and error logging, which is not an
        // event about anybody.
        //
        // Narrower than it first looked. The obvious rule -- drop anything
        // logged at debug or trace -- would have been wrong: of 9,007 such
        // lines in seven days, 6,810 carry a real source.ip, because
        // hellpot records a per-connection END_ON_ERR at trace level. Those
        // are attacker traffic wearing a low log level, and dropping them
        // would have lost real data to tidy up noise.
        //
        // So the rule is the conjunction: logged at debug or trace *and*
        // carrying no source at all. That is the shape of a sensor talking
        // about itself -- "error when serving connection", a startup
        // banner -- and it leaves anything with an attacker attached
        // exactly where it is.
        {"bool": {
            "filter": [{"terms": {"honeypot.level": ["debug", "trace"]}}],
            "must_not": [{"exists": {"field": "source.ip"}}]
        }}
    ])
}

/// Addresses that belong to this deployment rather than to an attacker.
///
/// #1873: attribution recovering a real address behind the tunnel is
/// best-effort -- 200 events a day carry no `network.community_id` at all,
/// so the zeek-proxy worker has no join key for them and can never reach
/// them. But failing to attribute must produce a *missing* answer, not a
/// *wrong* one: rendering our own WireGuard peer as the attacker states
/// something false, and it is the kind of false that gets acted on.
///
/// Membership is by shape, not by a list of literals, so a re-addressed
/// tunnel or a new docker network cannot quietly start being attributed.
/// Public addresses have no shape to match, so those come from the
/// deployment's existing `HONEYPOT_SELF_IPS` -- the same list #1677 added
/// for the overview aggregations, rather than a second env var that could
/// disagree with it. The two questions are the same question: is this
/// address ours?
pub fn is_fleet_address(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let Ok(parsed) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    if parsed.is_loopback() || parsed.is_unspecified() {
        return true;
    }
    // RFC1918 and link-local: the tunnel (10.8.0.0/24), the LAN
    // (192.168.42.0/24) and the container networks (172.16-31.x) are all
    // ours, and none of them can route in from outside.
    if let std::net::IpAddr::V4(v4) = parsed {
        if v4.is_private() || v4.is_link_local() {
            return true;
        }
    }
    if let std::net::IpAddr::V6(v6) = parsed {
        // fc00::/7 unique-local and fe80::/10 link-local.
        let first = v6.segments()[0];
        if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
            return true;
        }
    }
    crate::dashboard::self_addresses().iter().any(|own| own == ip)
}

/// The attacker address for a document, or empty when there is not one.
///
/// #1873: three rules, in order.
///
/// dionaea emits two shapes and only the flat one was ever read. The raw
/// shape nests the peer under `data.connection.*` or `data.parent.*`, so
/// 1,638 documents in six hours were rendered unattributed while the real
/// address sat in the same document -- a SIP attacker at 46.19.138.10, for
/// one. Those nested paths are checked when the promoted field is empty.
///
/// A fleet address is never returned. The tunnel peer is what the sensor
/// genuinely saw, and saying so would be honest if the field were labelled
/// "peer"; in a column headed "source ip" it reads as an accusation.
fn attacker_ip(src: &Value) -> String {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let candidates = [
        text(&src["source"]["ip"]),
        text(&src["honeypot"]["src_ip"]),
        text(&src["honeypot"]["data"]["connection"]["remote_ip"]),
        text(&src["honeypot"]["data"]["parent"]["remote_ip"]),
        text(&src["honeypot"]["data"]["child"]["remote_ip"]),
    ];
    candidates
        .into_iter()
        .find(|candidate| !candidate.is_empty() && !is_fleet_address(candidate))
        .unwrap_or_default()
}

fn since_to_range(since: &Option<String>) -> String {
    match since.as_deref() {
        Some(s) if !s.is_empty() && s.len() <= 8 && s.chars().all(|c| c.is_ascii_alphanumeric()) => {
            format!("now-{s}")
        }
        _ => "now-10d".to_string(),
    }
}

/// Normalized severity, from a rating the producer actually wrote.
///
/// - Suricata `suricata.eve.alert.severity`: 1 -> "high", 2 -> "medium",
///   3 -> "low". This is Suricata's own convention, where 1 is the most
///   severe. Any other number is unrated.
/// - DNP3 control functions: the `ics_severity` already computed from
///   `honeypot.app_function` ("critical" or "high"), mapped unchanged.
///
/// event_detail.rs labels the same numbers critical/major/minor for the
/// detail text; the row uses high/medium/low because that is the vocabulary
/// the dashboard's severity badge and filter expect.
///
/// The honeypot sensors write no rating of their own (no `event.severity`,
/// no `honeypot.severity` in the index), so their rows are unrated.
pub(crate) fn severity_from_source(src: &Value, pivots: &EventPivots) -> Option<&'static str> {
    if let Some(rating) = src["suricata"]["eve"]["alert"]["severity"].as_u64() {
        return match rating {
            1 => Some("high"),
            2 => Some("medium"),
            3 => Some("low"),
            _ => None,
        };
    }
    match pivots.ics_severity.as_str() {
        "critical" => Some("critical"),
        "high" => Some("high"),
        _ => None,
    }
}

/// Normalized event kind, from the producer's own event name.
///
/// Only the vocabularies checked against the index are mapped. Anything else
/// is absent, not guessed from the free text of the event:
/// - `honeypot.eventid` (cowrie): `cowrie.session.connect` -> connection;
///   `cowrie.login.*` -> login; `cowrie.command.*` -> command;
///   `cowrie.session.file_download*` -> download.
/// - `honeypot.event` (multipot): `connect` -> connection;
///   `auth_attempt` and `login` -> login; `command` -> command;
///   `http_request` -> http.
/// - `event.category` on Suricata alert documents (always "alert") -> alert.
/// - `event.category` on Zeek documents, which holds the Zeek log name:
///   `conn` -> connection, `http` -> http, `files` -> download (files.log
///   records each file transferred).
///
/// The honeypot docs' `event.category` is deliberately not read here. It is
/// the attack class ("scan", "login-probe", ...), not an event kind.
pub(crate) fn kind_from_source(src: &Value) -> Option<&'static str> {
    let hp = &src["honeypot"];
    match hp["eventid"].as_str().unwrap_or("") {
        "cowrie.session.connect" => return Some("connection"),
        "cowrie.login.failed" | "cowrie.login.success" => return Some("login"),
        "cowrie.command.input" | "cowrie.command.success" | "cowrie.command.failed" => return Some("command"),
        "cowrie.session.file_download" | "cowrie.session.file_download.failed" => return Some("download"),
        _ => {}
    }
    match hp["event"].as_str().unwrap_or("") {
        "connect" => return Some("connection"),
        "auth_attempt" | "login" => return Some("login"),
        "command" => return Some("command"),
        "http_request" => return Some("http"),
        _ => {}
    }
    match src["event"]["category"].as_str().unwrap_or("") {
        "alert" => Some("alert"),
        "conn" => Some("connection"),
        "http" => Some("http"),
        "files" => Some("download"),
        _ => None,
    }
}

/// MITRE ATT&CK technique ids from the Suricata rule that fired, read from
/// `suricata.eve.alert.metadata.mitre_technique_id` (an array in eve.json).
///
/// `threat.technique.id` is the ECS home for this, and it is written by no
/// producer in the index, so it is not read.
pub(crate) fn techniques_from_source(src: &Value) -> Vec<String> {
    match &src["suricata"]["eve"]["alert"]["metadata"]["mitre_technique_id"] {
        Value::Array(ids) => ids.iter().filter_map(Value::as_str).filter(|id| !id.is_empty()).map(String::from).collect(),
        Value::String(id) if !id.is_empty() => vec![id.clone()],
        _ => Vec::new(),
    }
}

/// `source.port`, or the Suricata alert's own `src_port` when the document
/// has no promoted one. Zero and out-of-range values are absent.
pub(crate) fn src_port_from_source(src: &Value) -> Option<u16> {
    [&src["source"]["port"], &src["suricata"]["eve"]["src_port"]]
        .into_iter()
        .filter_map(Value::as_u64)
        .find_map(|port| u16::try_from(port).ok().filter(|port| *port > 0))
}

/// One list/stream row from a normalized ECS `_source` (shared with the
/// SSE live stream so both emit identical shapes).
pub fn row_from_source(src: &Value) -> EventRow {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let sensor = text(&src["event"]["sensor"]);
    // #3213: the row is the one place every one of the explorer's outputs
    // comes from -- `detail`, `pivots.pass` and `record` all read the same
    // document -- so the boundary runs once here and everything below sees
    // the scrubbed copy. `record` is the sharpest edge: it is the complete
    // document "with nothing hidden", so for these two decoys it used to
    // carry a captured password into every row of the list, into the SSE
    // live stream and into both CSV exports. Out-of-scope sensors are
    // returned an untouched borrow, not a clone.
    let scrubbed = secrets_boundary::scrub_source(&sensor, src);
    let src = scrubbed.as_ref().unwrap_or(src);
    // Several sensors (multipot, conpot, dnp3) only ever carry proto/port
    // under honeypot.* — network.protocol/destination.port stay empty for
    // them, so fall back rather than showing a blank column (#1611
    // workstream A).
    let proto = {
        let p = text(&src["network"]["protocol"]);
        if p.is_empty() { text(&src["honeypot"]["proto"]) } else { p }
    };
    let num_or_str = |v: &Value| v.as_u64().map(|n| n.to_string()).unwrap_or_else(|| text(v));
    let port = [&src["destination"]["port"], &src["honeypot"]["port"], &src["honeypot"]["dst_port"]]
        .into_iter()
        .map(num_or_str)
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    // #3555: the new fields read the same scrubbed `src`, and `pivots` is
    // computed once because severity needs its ics_severity.
    let pivots = pivots_from_source(src);
    // #1873: never our own address, and dionaea's nested peer when
    // the promoted field is empty. See attacker_ip.
    let src_ip = attacker_ip(src);
    EventRow {
        src_ip_claimed: {
            let claimed = text(&src["honeypot"]["src_ip_claimed"]);
            // Never echo our own address as a claim, for the same reason
            // it is never shown as a source.
            if is_fleet_address(&claimed) { String::new() } else { claimed }
        },
        id: String::new(),
        time: text(&src["@timestamp"]),
        sensor: sensor.clone(),
        src_port: if src_ip.is_empty() { None } else { src_port_from_source(src) },
        src_ip,
        country: text(&src["source"]["geo"]["country_iso_code"]),
        city: Some(text(&src["source"]["geo"]["city_name"])).filter(|city| !city.is_empty()),
        severity: severity_from_source(src, &pivots),
        kind: kind_from_source(src),
        techniques: techniques_from_source(src),
        port,
        proto,
        // #1611 workstream A: per-sensor rich detail rendering, ported
        // from dashboard/classify.go (src/detail.rs).
        detail: detail_for(&sensor, src),
        session: {
            let s1 = text(&src["honeypot"]["session"]);
            if s1.is_empty() { text(&src["session"]["id"]) } else { s1 }
        },
        pivots,
        record: src.clone(),
    }
}

/// The same row, from a search hit rather than a bare `_source`, so it
/// carries the document id (#1868). Every caller that has the hit should
/// use this — the id is what makes the row's own full page reachable.
pub fn row_from_hit(hit: &Value) -> EventRow {
    EventRow {
        id: hit["_id"].as_str().unwrap_or("").to_string(),
        ..row_from_source(&hit["_source"])
    }
}

/// Shared between the paginated list below and exports.rs's full-scope CSV
/// The should-of-terms shape for one concept recorded under several keys
/// (the sensors disagree about vocabulary; any match is the semantics the
/// Go in-memory filter had). Module-level so every reader of a given id —
/// events, session detail, report scopes (#2119) — calls the same helper
/// instead of inlining its own field list and drifting.
pub fn any_of(fields: &[&str], value: &str) -> Value {
    let should: Vec<Value> = fields.iter().map(|f| json!({"term": {*f: value}})).collect();
    json!({"bool": {"should": should, "minimum_should_match": 1}})
}

/// Every field a user-supplied session id can live in. The mailoney/tanner/
/// http-honeypot family writes `honeypot.session_id` (mail.rs queries it to
/// fetch message bodies), most other sensors `honeypot.session`, ECS-shaped
/// sources `session.id` — a reader that matches only two of the three drops
/// exactly the sessions an operator copied an id off a page for.
pub const SESSION_FIELDS: &[&str] = &["honeypot.session", "honeypot.session_id", "session.id"];

/// export — same filter fields, same semantics, so an export always
/// matches exactly what the equivalent list view is currently showing
/// (#513's own "never a silently different scope than the page" rule).
pub fn build_filters(q: &EventsQuery) -> Vec<Value> {
    let mut filters = vec![json!({"range": {"@timestamp": {"gte": since_to_range(&q.since)}}})];
    if let Some(ip) = q.ip.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.ip": ip}}));
    }
    if let Some(ips) = q.ips.as_deref().filter(|v| !v.is_empty()) {
        let values: Vec<&str> = ips.split(',').map(str::trim).filter(|v| !v.is_empty()).collect();
        if !values.is_empty() {
            filters.push(json!({"terms": {"source.ip": values}}));
        }
    }
    if let Some(sensor) = q.sensor.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"event.sensor": sensor}}));
    }
    if let Some(country) = q.country.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.geo.country_iso_code": country}}));
    }
    if let Some(city) = q.city.as_deref().filter(|v| !v.is_empty()) {
        // Keyword field written by ip-enrichment; exact match matches the
        // multi_terms key dashboard.rs buckets map pins by (#2045).
        filters.push(json!({"term": {"source.geo.city_name": city}}));
    }
    if let Some(port) = q.port.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"destination.port": port}}));
    }
    if let Some(proto) = q.proto.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"network.protocol": proto}}));
    }
    if let Some(kind) = q.kind.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.event": kind}}));
    }
    if let Some(shasum) = q.shasum.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.shasum": shasum}}));
    }
    if let Some(flow) = q.community_id.as_deref().filter(|v| !v.is_empty()) {
        // Promoted to a real keyword field by the ingest pipeline on every
        // sensor family, so an exact term works and no per-sensor special
        // casing is needed.
        filters.push(json!({"term": {"network.community_id": flow}}));
    }
    if let Some(text) = q.q.as_deref().filter(|v| !v.is_empty()) {
        // lenient: a malformed user query returns no matches instead of a
        // shard failure, matching the legacy page's forgiving behavior.
        filters.push(json!({"query_string": {"query": text, "lenient": true}}));
    }
    // ── Pivot filters (#1653). A multi-field pivot is a should-of-terms:
    // the sensors record the same concept under different keys, and any
    // match is the semantics the Go in-memory filter had.
    // (#2119: any_of moved to module level so report scopes and the
    // session pane share this crate's one field vocabulary.)
    if let Some(persona) = q.persona.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.persona_id": persona}}));
    }
    if let Some(site) = q.site.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.site_id": site}}));
    }
    if let Some(asset) = q.asset.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.asset_id": asset}}));
    }
    if let Some(fp) = q.fingerprint.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(
            &[
                "honeypot.canonical_fingerprint",
                "honeypot.hassh",
                "honeypot.fingerprint",
                "honeypot.client",
                "honeypot.user_agent",
            ],
            fp,
        ));
    }
    if let Some(cmd) = q.cmd.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["honeypot.canonical_command", "honeypot.command", "honeypot.input"], cmd));
    }
    if let Some(cred) = q.cred.as_deref().filter(|v| !v.is_empty()) {
        // "user / pass", the exact separator the credential links carry.
        //
        // #3213: a bare account with no " / " used to emit a second filter
        // for an EMPTY password, which matches essentially nothing -- so
        // typing an account into the credential box returned an empty result
        // set and read as "this account was never seen". The pass half is
        // now emitted only when there is one, which both fixes that and
        // gives the sensors in scope a working account pivot: their rows no
        // longer carry a pass to put in the link, and an account on its own
        // is the half that survives.
        let (user, pass) = cred.split_once(" / ").unwrap_or((cred, ""));
        filters.push(any_of(&["honeypot.canonical_user", "honeypot.username"], user));
        if !pass.is_empty() {
            filters.push(any_of(&["honeypot.canonical_pass", "honeypot.password"], pass));
        }
    }
    if let Some(path) = q.path.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["honeypot.path", "honeypot.url"], path));
    }
    if let Some(session) = q.session.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(SESSION_FIELDS, session));
    }
    if let Some(asn) = q.asn.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.as.asn": asn}}));
    }
    if let Some(org) = q.org.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.as.organization_name": org}}));
    }
    if let Some(provider) = q.provider.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.as.type": provider}}));
    }
    if let Some(sig) = q.sig.as_deref().filter(|v| !v.is_empty()) {
        // #3570: the field is `text` (analysed), so a `term` on it can never
        // match a whole signature. Exact match on the `.keyword` subfield; the
        // value always comes from the signatures facet (itself a terms agg on
        // `.keyword`), so exact -- not partial/match_phrase -- is the contract.
        filters.push(json!({"term": {"suricata.eve.alert.signature.keyword": sig}}));
    }
    if let Some(cat) = q.cat.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["suricata.eve.alert.category", "honeypot.category"], cat));
    }
    filters
}

#[utoipa::path(
    get,
    path = "/api/v1/events",
    summary = "Event explorer page: the shared filter set, windowed.",
    params(
        ("offset" = inline(Option<contract::NonNegativeInt>), Query, description = "Result window start."),
        ("size" = inline(Option<contract::PageSize>), Query, description = "Page size, clamped to 100 by the handler."),
        ("ip" = inline(Option<String>), Query, description = "Single source address."),
        ("ips" = inline(Option<String>), Query, description = "Comma-separated source addresses."),
        ("sensor" = inline(Option<String>), Query, description = "Sensor name (honeypot.dionaea, suricata, ...)."),
        ("country" = inline(Option<String>), Query, description = "ISO country code."),
        ("city" = inline(Option<String>), Query, description = "City name, as bucketed on the overview map."),
        ("port" = inline(Option<String>), Query, description = "Destination port."),
        ("proto" = inline(Option<String>), Query, description = "Transport protocol."),
        ("kind" = inline(Option<String>), Query, description = "honeypot.event kind (command, login, ...)."),
        ("shasum" = inline(Option<String>), Query, description = "Captured-payload hash."),
        ("community_id" = inline(Option<String>), Query, description = "One flow across every sensor that saw it."),
        ("q" = inline(Option<String>), Query, description = "Free-text query_string, passed to Elasticsearch as-is."),
        ("since" = inline(Option<String>), Query, description = "Go-style relative window (24h, 7d)."),
        ("persona" = inline(Option<String>), Query, description = "Decoy persona id."),
        ("site" = inline(Option<String>), Query, description = "Decoy site id."),
        ("asset" = inline(Option<String>), Query, description = "Decoy asset id."),
        ("fingerprint" = inline(Option<String>), Query, description = "Client fingerprint, matched across every field sensors record one in."),
        ("cmd" = inline(Option<String>), Query, description = "Exact command text."),
        ("cred" = inline(Option<String>), Query, description = "\"user / pass\" pair."),
        ("path" = inline(Option<String>), Query, description = "Request path."),
        ("session" = inline(Option<String>), Query, description = "Session id."),
        ("asn" = inline(Option<String>), Query, description = "Source AS number."),
        ("org" = inline(Option<String>), Query, description = "Source network organization."),
        ("provider" = inline(Option<String>), Query, description = "Provider class."),
        ("sig" = inline(Option<String>), Query, description = "IDS alert signature."),
        ("cat" = inline(Option<String>), Query, description = "Detection category (Suricata alert category or honeypot.category)."),
    ),
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
        (status = 502, description = "Elasticsearch (or a sibling it proxies) refused or failed the query.", body = String, content_type = "text/plain"),
        (status = 400, description = "Rejected: the request was understood but its input is not acceptable.", body = String, content_type = "text/plain"),
    ),
    security(("serviceToken" = [])),
)]
pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<EventsPage>, (StatusCode, String)> {
    let size = q.size.min(100);
    let offset = q.offset.min(10_000 - size); // ES from+size window guard
    let filters = build_filters(&q);

    let body = json!({
        "from": offset,
        "size": size,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let rows = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(row_from_hit).collect())
        .unwrap_or_default();

    let fingerprint_ips = fingerprint_ip_correlation(&state, &q).await;
    Ok(Json(EventsPage { total, offset, rows, fingerprint_ips }))
}

#[cfg(test)]
mod fleet_attribution_tests {
    use super::*;

    #[test]
    fn a_fleet_address_is_never_an_attacker() {
        // #1873: the tunnel peer is what the sensor genuinely saw, but in a
        // column headed "source ip" it reads as an accusation. 200 events a
        // day carried 10.8.0.1 here.
        assert!(is_fleet_address("10.8.0.1"), "the VPS WireGuard peer");
        assert!(is_fleet_address("10.8.0.2"), "the homeserver WireGuard peer");
        assert!(is_fleet_address("127.0.0.1"), "loopback");
        assert!(is_fleet_address("192.168.42.7"), "a LAN address");
        assert!(is_fleet_address("172.16.10.3"), "a container network");
        assert!(is_fleet_address("0.0.0.0"), "unspecified");
        assert!(is_fleet_address("fe80::1"), "v6 link-local");
        assert!(is_fleet_address("fd00::1"), "v6 unique-local");
    }

    #[test]
    fn a_real_attacker_address_is_not_mistaken_for_ours() {
        // The guard must not swallow the addresses it exists to preserve.
        assert!(!is_fleet_address("46.19.138.10"));
        // Documentation range rather than the fleet's real WAN address:
        // this repo is public, and scripts/check-public-leaks.py rejects
        // those literals anywhere in tree.
        //
        // #2113: the two configuration-dependent cases (203.0.113.4 unconfigured
        // vs configured) live in dashboard.rs's single serialized HONEYPOT_SELF_IPS
        // test now -- this module asserting on them here raced that module's env
        // mutations on parallel test threads. Everything asserted below is a value
        // no test ever writes into the variable, so these reads are indifferent to
        // whatever any other test is doing to it.
        assert!(!is_fleet_address("8.8.8.8"));
        assert!(!is_fleet_address("2606:4700::1111"));
        assert!(!is_fleet_address(""), "absent is not ours");
        assert!(!is_fleet_address("not-an-ip"));
    }

    #[test]
    fn the_tunnel_peer_is_dropped_rather_than_shown_as_the_source() {
        let doc = json!({
            "source": {"ip": "10.8.0.1"},
            "honeypot": {"src_ip": "10.8.0.1", "REMOTE_ADDR": "10.8.0.1:35518"}
        });
        assert_eq!(attacker_ip(&doc), "", "a fleet address must leave the field empty");
    }

    #[test]
    fn dionaeas_nested_peer_is_promoted_when_the_flat_field_is_absent() {
        // #1873: 1,638 documents in six hours read as unattributed while
        // the real address sat in the same document under data.*.
        let connection = json!({
            "honeypot": {"data": {"connection": {"remote_ip": "46.19.138.10", "protocol": "smbd"}}}
        });
        assert_eq!(attacker_ip(&connection), "46.19.138.10");

        let parent = json!({
            "honeypot": {"data": {"parent": {"remote_ip": "46.19.138.10", "protocol": "SipSession"}}}
        });
        assert_eq!(attacker_ip(&parent), "46.19.138.10");
    }

    #[test]
    fn a_nested_peer_that_is_also_ours_stays_unattributed() {
        // dionaea's own loopback health probe nests 127.0.0.1 the same way
        // a real attacker nests a routable address.
        let doc = json!({
            "honeypot": {"data": {"connection": {"remote_ip": "127.0.0.1", "protocol": "smbd"}}}
        });
        assert_eq!(attacker_ip(&doc), "");
    }

    #[test]
    fn the_promoted_field_still_wins_when_it_holds_a_real_address() {
        let doc = json!({
            "source": {"ip": "203.0.113.7"},
            "honeypot": {"data": {"connection": {"remote_ip": "198.51.100.9"}}}
        });
        assert_eq!(attacker_ip(&doc), "203.0.113.7", "source.ip is the promoted answer");
    }

    #[test]
    fn a_low_log_level_alone_does_not_make_a_line_noise() {
        // #1892: hellpot records a per-connection END_ON_ERR at trace level
        // -- 6,810 of 9,007 debug/trace lines in seven days carry a real
        // source.ip. Excluding by level alone would drop those. The rule
        // has to be the conjunction, so this asserts both halves are
        // present rather than just the level term.
        let rendered = suricata_noise_exclusion().to_string();
        assert!(rendered.contains("honeypot.level"), "{rendered}");
        assert!(
            rendered.contains("\"must_not\":[{\"exists\":{\"field\":\"source.ip\"}}]"),
            "the level filter must be paired with the absence of a source: {rendered}"
        );
    }

    #[test]
    fn the_explorer_excludes_the_fleet_probing_itself() {
        // dashboard.rs, health.rs and worker.rs all drop internal_probe;
        // the explorer was the one surface that did not, and it was
        // rendering roughly 270k self-generated rows a day (#1873).
        let exclusion = suricata_noise_exclusion();
        let rendered = exclusion.to_string();
        assert!(rendered.contains("honeypot.internal_probe"), "{rendered}");
        assert!(rendered.contains("netflow"), "the suricata noise exclusion must survive: {rendered}");
    }
}

#[cfg(test)]
mod session_scope_tests {
    use super::*;

    fn filters_for(session: &str) -> Vec<Value> {
        let q: EventsQuery = serde_json::from_value(json!({"session": session})).unwrap();
        build_filters(&q)
    }

    #[test]
    fn the_session_clause_matches_all_three_id_fields() {
        // #2119: the report scope matched only two of the three and
        // silently dropped mailoney/tanner sessions, whose events carry
        // honeypot.session_id — an incident report scoped to such an id
        // came back reading as "no matching telemetry".
        let rendered = filters_for("sess-abc")
            .iter()
            .find(|f| f.to_string().contains("honeypot.session"))
            .expect("a session clause is emitted")
            .to_string();
        for field in SESSION_FIELDS {
            assert!(rendered.contains(field), "the session clause must match {field}: {rendered}");
        }
        assert!(rendered.contains("\"minimum_should_match\":1"), "{rendered}");
    }

    #[test]
    fn sig_filter_is_an_exact_term_on_the_keyword_subfield() {
        // #3570: a term on the analysed text field never matches a full signature.
        let q: EventsQuery = serde_json::from_value(json!({"sig": "ET SCAN Example Scan"})).unwrap();
        let filters = build_filters(&q);
        assert!(
            filters.contains(&json!({"term": {"suricata.eve.alert.signature.keyword": "ET SCAN Example Scan"}})),
            "{filters:?}"
        );
        assert!(
            !filters.iter().any(|f| f["term"].get("suricata.eve.alert.signature").is_some()),
            "{filters:?}"
        );
    }

    #[test]
    fn no_sig_clause_is_emitted_when_sig_is_empty() {
        let q: EventsQuery = serde_json::from_value(json!({"sig": ""})).unwrap();
        let rendered = build_filters(&q).iter().map(|f| f.to_string()).collect::<String>();
        assert!(!rendered.contains("alert.signature"), "{rendered}");
    }

    #[test]
    fn no_session_clause_is_emitted_when_the_scope_is_empty() {
        let q: EventsQuery = serde_json::from_value(json!({})).unwrap();
        let rendered = build_filters(&q).iter().map(|f| f.to_string()).collect::<String>();
        assert!(!rendered.contains("honeypot.session"), "{rendered}");
        assert!(!rendered.contains("session.id"), "{rendered}");
    }

    #[test]
    fn every_reader_shares_one_vocabulary() {
        // The whole point of #2119: the field list lives in exactly one
        // place, and events.rs, session.rs and reports_data.rs all call
        // through it. A fourth id field lands here once or nowhere.
        assert_eq!(SESSION_FIELDS, &["honeypot.session", "honeypot.session_id", "session.id"]);
    }

    // ── #3213: the API-response half of the secret-handling rule ──────────
    //
    // The sensors prove a password never reaches an emitted event or a log
    // line. This proves the other half: that a password ALREADY IN THE INDEX
    // never reaches a response. The document below is the pre-fix shape --
    // `password` present, body unredacted -- which is what every stored
    // event from before the sensor change looks like, and it is the only
    // version of this test that is worth writing, because a document the new
    // sensors produce has nothing left to leak.

    const SECRET: &str = "correct-horse-battery-staple-9f2c";

    fn stored_http_login() -> Value {
        json!({
            "@timestamp": "2026-09-01T00:00:00Z",
            "event": {"sensor": "http-honeypot"},
            "source": {"ip": "203.0.113.9"},
            "honeypot": {
                "sensor": "http-honeypot",
                "src_ip": "203.0.113.9",
                "method": "POST",
                "path": "/wp-login.php",
                "username": "admin",
                "password": SECRET,
                "body": format!("log=admin&pwd={SECRET}&wp-submit=Log+In"),
                "query": format!("redirect_to=/wp-admin&password={SECRET}"),
                "headers": {
                    "authorization": format!("Basic YWRtaW46{SECRET}"),
                    "user-agent": "curl/8.4.0",
                    "cookie": format!("wordpress_logged_in_{SECRET}=admin")
                }
            }
        })
    }

    #[test]
    fn a_stored_password_never_reaches_an_event_row() {
        // `row_from_source` feeds the explorer list, the SSE live stream and
        // both CSV exports, so this one assertion covers all four surfaces.
        // Serialized rather than field-checked on purpose: a new field added
        // to the row later is covered by the same assertion, and a field
        // checked by name is only as good as the name someone remembered.
        let row = row_from_source(&stored_http_login());
        let rendered = serde_json::to_string(&row).unwrap();
        assert!(!rendered.contains(SECRET), "a stored password reached an event row: {rendered}");
    }

    #[test]
    fn the_row_keeps_the_fields_an_analyst_actually_reads() {
        // A boundary that deleted the body would pass the test above and
        // destroy the evidence. The account, the path, the method and the
        // redacted body shape all have to survive.
        let row = row_from_source(&stored_http_login());
        assert_eq!(row.pivots.user, "admin");
        assert_eq!(row.detail, "POST /wp-login.php  (admin)  [credentials removed]");
        let record = row.record.to_string();
        assert!(record.contains("wp-submit=Log+In"), "the redacted body lost its shape: {record}");
        assert!(record.contains("curl/8.4.0"), "a non-secret header was destroyed: {record}");
    }

    #[test]
    fn the_detail_line_says_the_credential_was_removed_not_that_there_was_none() {
        // The distinction the whole issue turns on. This document had a
        // credential; the boundary took it away; reporting "absent" would be
        // reporting the scrubber's own effect as an observation about the
        // attacker.
        let row = row_from_source(&stored_http_login());
        assert!(row.detail.contains("credentials removed"), "{}", row.detail);
        assert!(!row.detail.contains("absent"), "{}", row.detail);
    }

    #[test]
    fn the_password_pivot_is_empty_but_the_account_pivot_is_not() {
        let row = row_from_source(&stored_http_login());
        assert_eq!(row.pivots.pass, "", "the password pivot must be empty for a boundary sensor");
        assert_eq!(row.pivots.user, "admin", "the account is the analytic value and must survive");
    }

    #[test]
    fn a_password_outside_this_issues_scope_is_left_exactly_as_it_was() {
        // The scoping proof. Without it, `scrub_source` returning `None` for
        // out-of-scope sensors is untested, and a future edit that widens the
        // sensor list silently would look like a harmless refactor.
        let cowrie = json!({
            "event": {"sensor": "cowrie"},
            "honeypot": {"eventid": "cowrie.login.failed", "username": "root", "password": "toor"}
        });
        let row = row_from_source(&cowrie);
        assert_eq!(row.pivots.pass, "toor", "cowrie is out of scope and must not change");
        assert_eq!(row.detail, "login.failed: root / toor", "cowrie is out of scope and must not change");
    }

    #[test]
    fn a_scrubbed_row_is_the_same_row_on_a_second_pass() {
        // Idempotence is what lets the boundary sit at the top of
        // `row_from_source` while `detail_for` and `pivots_from_source`
        // guard themselves as well. Without it the double guard would
        // double-redact, and a body read twice would stop matching its own
        // field names.
        let once = row_from_source(&stored_http_login());
        let twice = row_from_source(&once.record);
        assert_eq!(once.detail, twice.detail);
        assert_eq!(once.record, twice.record);
        assert_eq!(once.pivots.pass, twice.pivots.pass);
    }

    #[test]
    fn the_new_schema_reads_as_three_separate_questions() {
        // A post-fix document: the axes are populated and independent, and
        // the presence boolean survives as `null` for unknown rather than
        // collapsing to false.
        let fresh = json!({
            "event": {"sensor": "http-honeypot"},
            "honeypot": {
                "method": "POST", "path": "/api/v1/login",
                "username": "admin",
                "credential_status": "extracted",
                "credential_present": true,
                "credential_indicator_match": true,
                "auth_type": "form",
                "auth_outcome": "simulated"
            }
        });
        let row = row_from_source(&fresh);
        assert_eq!(row.detail, "POST /api/v1/login  (admin)  [extracted · decoy indicator · auth simulated]");
        let record = row.record.to_string();
        assert!(record.contains("\"credential_indicator_match\":true"), "{record}");
        assert!(record.contains("\"auth_outcome\":\"simulated\""), "{record}");
    }

    #[test]
    fn an_unknown_presence_is_not_reported_as_false() {
        // `credential_present: null` is the whole reason it is a pointer in
        // the sensor and an Option here. A defaulted false would tell the
        // analyst a request carried no credential when nobody knows.
        let unknown = json!({
            "event": {"sensor": "cisco-asa-honeypot"},
            "honeypot": {
                "event": "ike_unexpected_exchange", "data": "isakmp",
                "credential_status": "unknown", "credential_present": Value::Null,
                "auth_outcome": "unknown"
            }
        });
        let row = row_from_source(&unknown);
        // The `(type isakmp)` tail is the pre-existing IKE rendering and is
        // unaffected; the point of the assertion is the fragment before it.
        assert_eq!(row.detail, "ike_unexpected_exchange  [unknown · auth unknown] (type isakmp)", "{}", row.detail);
        assert!(
            row.record["honeypot"]["credential_present"].is_null(),
            "a null presence must stay null all the way to the response"
        );
    }

    // ── #3212: the capture fields reach the presentation layer ──────────────
    //
    // The sensor emits them; the normalization pass keeps them. This is the
    // last hop of the contract: a document carrying them, as stored in the
    // index, still carries them when the read path hands the record to the
    // browser -- and the byte-safe evidence field is not a way for a
    // credential to get there.

    /// The shape the sensor now writes for a clipped, credential-bearing,
    /// Java-marked POST: the redacted body, its bounded base64 head, the
    /// prefix hash under its scope label, the declared length, and the
    /// marker observation. `body_b64` is the base64 of `body` exactly as the
    /// sensor derives the two from one redacted string, so the event's own
    /// internal agreement can be asserted rather than assumed.
    fn stored_capture_event() -> Value {
        json!({
            "@timestamp": "2026-09-27T00:00:00Z",
            "event": {"sensor": "http-honeypot"},
            "source": {"ip": "203.0.113.9"},
            "honeypot": {
                "sensor": "http-honeypot",
                "src_ip": "203.0.113.9",
                "method": "POST",
                "path": "/api/v1/login",
                "username": "admin",
                "body": format!("username=admin&password={}&next=%2F", secrets_boundary::REDACT_MARKER),
                "headers": {"authorization": format!("Bearer {SECRET}")},
                "body_capture_state": "truncated",
                "body_captured_bytes": 65536,
                "body_encoding": "base64",
                "body_b64": "dXNlcm5hbWU9YWRtaW4mcGFzc3dvcmQ9W3JlZGFjdGVkXSZuZXh0PSUyRg==",
                "body_sha256": "05d129712d910c85a45c74ef9f1b825068ddc953e417ba75781e58fa40625eeb",
                "body_sha256_scope": "captured-prefix-redacted",
                "body_declared_bytes": 4194304,
                "java_marker": "stream-magic"
            }
        })
    }

    #[test]
    fn the_capture_fields_survive_into_the_record() {
        // row_from_source feeds the explorer list, the SSE live stream and
        // both CSV exports through one row shape, so this assertion covers
        // every surface the record is rendered on. Serialized rather than
        // field-checked for the same reason the #3213 test is: a field
        // checked by name is only as good as the name someone remembered.
        let row = row_from_source(&stored_capture_event());
        let record = row.record.to_string();
        for fragment in [
            "\"body_capture_state\":\"truncated\"",
            "\"body_captured_bytes\":65536",
            "\"body_encoding\":\"base64\"",
            "\"body_b64\":\"dXNlcm5hbWU9YWRtaW4mcGFzc3dvcmQ9W3JlZGFjdGVkXSZuZXh0PSUyRg==\"",
            "\"body_sha256_scope\":\"captured-prefix-redacted\"",
            "\"body_declared_bytes\":4194304",
            "\"java_marker\":\"stream-magic\"",
        ] {
            assert!(
                record.contains(fragment),
                "{fragment} did not survive into the record: {record}"
            );
        }
    }

    #[test]
    fn the_evidence_fields_carry_no_credential_material() {
        // The #3213 test proves a stored password never reaches a row. This
        // extends the same claim to #3212's evidence: the byte-safe head, the
        // prefix hash and the declared length must not become a second,
        // differently-encoded copy of a submitted secret -- a base64 blob is
        // not a disclosure control. Checked on the serialized row, which is
        // what a browser actually receives.
        let row = row_from_source(&stored_capture_event());
        let rendered = serde_json::to_string(&row).unwrap();
        assert!(
            !rendered.contains(SECRET),
            "a captured credential reached the response: {rendered}"
        );
        // The header credential has a second encoding -- its own base64,
        // which is what "Basic <base64(user:secret)>" puts on the wire. The
        // #3213 test established that this channel is checked too.
        let mut header_encoding = String::new();
        header_encoding.push_str("Basic ");
        header_encoding.push_str(
            &base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("admin:{SECRET}"),
            ),
        );
        assert!(
            !rendered.contains(&header_encoding),
            "a bearer credential's Basic encoding reached the response: {rendered}"
        );

        // And the boundary must not have destroyed the evidence while
        // keeping it secret: body_b64 is not a scrub target (the sensor
        // redacts before the field is built), so it has to survive intact
        // and still decode to the event's own redacted body.
        let hp = &row.record["honeypot"];
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, hp["body_b64"].as_str().unwrap())
                .unwrap();
        let expected = format!("username=admin&password={}&next=%2F", secrets_boundary::REDACT_MARKER);
        assert_eq!(decoded, expected.as_bytes(), "the evidence head was corrupted on the way out");
        assert_eq!(
            hp["body_sha256"].as_str().unwrap(),
            "05d129712d910c85a45c74ef9f1b825068ddc953e417ba75781e58fa40625eeb",
            "the hash covers the redacted captured prefix"
        );
    }
}

#[cfg(test)]
mod row_field_tests {
    //! #3555: the fields the dashboard used to fill with placeholders. Each
    //! value is read from a `_source` shaped like the documents the index
    //! holds (see the PR body for the field-presence counts); addresses are
    //! documentation ranges, as in the rest of this file.
    use super::*;

    /// A Suricata alert as eve.json lands in `suricata-v2-alert-*`.
    fn suricata_alert(severity: u64, technique: Value) -> Value {
        json!({
            "@timestamp": "2026-10-08T12:00:00.000Z",
            "event": {"sensor": "suricata", "category": "alert"},
            "source": {"ip": "203.0.113.7", "geo": {"country_iso_code": "DE", "city_name": "Frankfurt am Main"}},
            "destination": {"port": 80, "ip": "198.51.100.9"},
            "suricata": {"eve": {
                "event_type": "alert",
                "src_ip": "203.0.113.7",
                "alert": {
                    "severity": severity,
                    "signature": "ET WEB_SPECIFIC_APPS example signature",
                    "category": "Web Application Attack",
                    "metadata": {"mitre_technique_id": technique}
                }
            }}
        })
    }

    #[test]
    fn a_suricata_alert_carries_its_own_severity_and_techniques() {
        let row = row_from_source(&suricata_alert(1, json!(["T1190"])));
        assert_eq!(row.severity, Some("high"));
        assert_eq!(row.kind, Some("alert"));
        assert_eq!(row.techniques, vec!["T1190".to_string()]);
        assert_eq!(row.city.as_deref(), Some("Frankfurt am Main"));
    }

    #[test]
    fn suricata_severity_1_2_3_map_to_high_medium_low() {
        assert_eq!(row_from_source(&suricata_alert(2, json!(null))).severity, Some("medium"));
        assert_eq!(row_from_source(&suricata_alert(3, json!(null))).severity, Some("low"));
        // Any other number is not a rating this mapping knows, so it is unrated.
        assert_eq!(row_from_source(&suricata_alert(0, json!(null))).severity, None);
        assert_eq!(row_from_source(&suricata_alert(9, json!(null))).severity, None);
    }

    #[test]
    fn techniques_are_a_list_and_the_array_form_keeps_every_id() {
        let many = row_from_source(&suricata_alert(2, json!(["T1190", "T1059"])));
        assert_eq!(many.techniques, vec!["T1190".to_string(), "T1059".to_string()]);
        let single_string = row_from_source(&suricata_alert(2, json!("T0846")));
        assert_eq!(single_string.techniques, vec!["T0846".to_string()]);
    }

    #[test]
    fn the_suricata_src_port_is_used_when_the_document_has_no_promoted_one() {
        let mut alert = suricata_alert(2, json!(null));
        alert["suricata"]["eve"]["src_port"] = json!(34976);
        assert_eq!(row_from_source(&alert).src_port, Some(34976));

        // source.port wins when a document carries both.
        alert["source"]["port"] = json!(51515);
        assert_eq!(row_from_source(&alert).src_port, Some(51515));
    }

    #[test]
    fn a_cowrie_login_maps_to_login_and_carries_its_source_port() {
        let cowrie = json!({
            "@timestamp": "2026-09-27T08:15:00.000Z",
            "event": {"sensor": "cowrie"},
            "source": {"ip": "198.51.100.9", "port": 41822, "geo": {"city_name": "Shanghai"}},
            "honeypot": {"eventid": "cowrie.login.failed", "username": "root", "password": "toor"}
        });
        let row = row_from_source(&cowrie);
        assert_eq!(row.kind, Some("login"));
        assert_eq!(row.src_port, Some(41822));
        assert_eq!(row.city.as_deref(), Some("Shanghai"));
        // Cowrie writes no rating, so it stays unrated.
        assert_eq!(row.severity, None);
        assert!(row.techniques.is_empty());
    }

    #[test]
    fn the_cowrie_and_multipot_vocabularies_map_to_their_kinds() {
        let kind_of = |eventid: &str| {
            row_from_source(&json!({"event": {"sensor": "cowrie"}, "honeypot": {"eventid": eventid}})).kind
        };
        assert_eq!(kind_of("cowrie.session.connect"), Some("connection"));
        assert_eq!(kind_of("cowrie.command.input"), Some("command"));
        assert_eq!(kind_of("cowrie.session.file_download"), Some("download"));
        assert_eq!(kind_of("cowrie.telnet.option"), None, "an unmapped eventid is absent, not guessed");

        let multipot = |event: &str| {
            row_from_source(&json!({"event": {"sensor": "multipot"}, "honeypot": {"event": event}})).kind
        };
        assert_eq!(multipot("connect"), Some("connection"));
        assert_eq!(multipot("auth_attempt"), Some("login"));
        assert_eq!(multipot("http_request"), Some("http"));
        assert_eq!(multipot("handshake"), None);
    }

    #[test]
    fn a_zeek_log_name_maps_to_its_kind_and_a_honeypot_attack_class_does_not() {
        let zeek = json!({"event": {"sensor": "zeek", "category": "conn"}, "source": {"ip": "198.51.100.9", "port": 52000}});
        assert_eq!(row_from_source(&zeek).kind, Some("connection"));
        assert_eq!(row_from_source(&zeek).src_port, Some(52000));

        // honeypot event.category is the attack class, not an event kind.
        let attack_class = json!({
            "event": {"sensor": "http-honeypot", "category": "login-probe"},
            "source": {"ip": "198.51.100.9"},
            "honeypot": {"path": "/wp-login.php"}
        });
        let row = row_from_source(&attack_class);
        assert_eq!(row.kind, None, "login-probe must not become a login kind");
    }

    #[test]
    fn a_dnp3_control_function_is_critical_from_its_ics_rating() {
        let dnp3 = json!({
            "event": {"sensor": "dnp3"},
            "source": {"ip": "198.51.100.9"},
            "honeypot": {"app_function": "direct_operate", "proto": "dnp3"}
        });
        assert_eq!(row_from_source(&dnp3).severity, Some("critical"));
        let benign = json!({
            "event": {"sensor": "dnp3"},
            "source": {"ip": "198.51.100.9"},
            "honeypot": {"app_function": "read", "proto": "dnp3"}
        });
        assert_eq!(row_from_source(&benign).severity, None, "a read has no rating");
    }

    #[test]
    fn a_fleet_address_row_gets_no_source_port() {
        // The tunnel peer's port belongs to the tunnel, not to an attacker.
        let fleet = json!({
            "event": {"sensor": "http-honeypot"},
            "source": {"ip": "10.8.0.1", "port": 35518},
            "honeypot": {"src_ip": "10.8.0.1"}
        });
        assert_eq!(row_from_source(&fleet).src_port, None);
    }

    #[test]
    fn a_row_with_no_rating_or_technique_or_city_omits_those_keys() {
        let bare = json!({
            "event": {"sensor": "http-honeypot", "category": "scan"},
            "source": {"ip": "198.51.100.9"},
            "honeypot": {"path": "/"}
        });
        let row = row_from_source(&bare);
        assert_eq!(row.severity, None);
        assert_eq!(row.kind, None);
        assert!(row.techniques.is_empty());
        assert_eq!(row.city, None);
        assert_eq!(row.src_port, None);

        let rendered = serde_json::to_value(&row).unwrap();
        for absent in ["severity", "kind", "techniques", "city", "src_port"] {
            assert!(rendered.get(absent).is_none(), "{absent} must be omitted, not null: {rendered}");
        }
    }

    #[test]
    fn a_rated_row_serializes_the_new_fields_in_the_wire_shape() {
        let rendered = serde_json::to_value(row_from_source(&suricata_alert(1, json!(["T1190"])))).unwrap();
        assert_eq!(rendered["severity"], "high");
        assert_eq!(rendered["kind"], "alert");
        assert_eq!(rendered["techniques"], json!(["T1190"]));
        assert_eq!(rendered["city"], "Frankfurt am Main");
    }

    #[test]
    fn the_hit_builder_and_the_source_builder_agree() {
        // The live stream and the list both use row_from_hit (#1962); the new
        // fields must come out identical from either.
        let src = suricata_alert(3, json!(["T0846"]));
        let hit = json!({"_id": "abc", "_source": src});
        let from_hit = row_from_hit(&hit);
        let from_source = row_from_source(&src);
        assert_eq!(from_hit.severity, from_source.severity);
        assert_eq!(from_hit.kind, from_source.kind);
        assert_eq!(from_hit.techniques, from_source.techniques);
        assert_eq!(from_hit.city, from_source.city);
        assert_eq!(from_hit.src_port, from_source.src_port);
    }
}
