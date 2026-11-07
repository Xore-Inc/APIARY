//! Resolve the real attacker behind a zeek-proxy observation.
//!
//! zeek-proxy watches `wg0`, where every flow is `10.8.0.1 -> 10.8.0.2`: the
//! VPS forwarding inward. That is genuinely what crossed the wire, so the
//! sensor is not wrong — but a record whose `source.ip` is our own tunnel is
//! useless as attacker attribution, and reads on the dashboard as though our
//! infrastructure were attacking itself.
//!
//! portbridge logs both halves of every relayed connection: `community_id`
//! for the attacker's tuple as it arrived on the public NIC, and
//! `community_id_relayed` for the tunnel-side tuple it dialled inward. The
//! second is what zeek-proxy computes for the same flow, so one is a key into
//! the other.
//!
//! # The key is not unique, and that is the whole difficulty
//!
//! The relayed tuple is `10.8.0.1:<ephemeral> -> 10.8.0.2:<service>`, and the
//! ephemeral port is reused within seconds under this traffic. Measured on the
//! live cluster: one `community_id_relayed` matched four portbridge records
//! belonging to different attackers. Joining on the key alone and taking any
//! match attributes a flow to whoever happened to reuse that port — and a
//! wrong attacker is indistinguishable from a right one, which is worse than
//! leaving the tunnel address in place.
//!
//! This is the same trap #1771 documented for the `via_port` join, and the
//! constraint that fixes it is the one `ip_enrichment::viamap` already uses:
//! portbridge logs at *dial* time, strictly before the relayed flow can exist,
//! so a candidate dialled after the flow cannot explain it. Among those that
//! remain, the most recent opened it.
//!
//! Where no candidate survives, nothing is written. An unattributed flow is
//! honest; a confidently wrong attacker is not.
//!
//! # What it writes
//!
//!   source.ip                     the attacker, replacing the tunnel address
//!   network.relay_ip              the tunnel address, preserved
//!   network.community_id_attacker the attacker-side key, so a zeek-proxy
//!                                 record can also be joined to the VPS
//!                                 sensor's view of the same session
//!   network.relay_unresolved      set on a flow old enough that a missing
//!                                 portbridge dial is an answer rather than a
//!                                 delay: this one was never relayed. It
//!                                 records that the question was asked and
//!                                 settled, which is what stops the flow from
//!                                 being reconsidered on every later pass
//!
//! # `@timestamp` is the ingest time, not the event time
//!
//! Both indices carry an `@timestamp` that is when the record was *shipped*,
//! not when the thing happened. Measured on the live cluster: portbridge's
//! `@timestamp` runs 3-4s after its own `portbridge.time`, and zeek-proxy's
//! runs ~9.5s after `zeek.ts` for a short flow -- and **12.7 hours** after it
//! for a long-lived one, because Zeek writes a `conn.log` record when the
//! connection closes while `zeek.ts` is when it opened.
//!
//! Comparing those two ingest stamps as if they were event times breaks the
//! ordering rule below in both directions: a dial and its own flow are
//! shipped seconds apart in arbitrary order, so a valid dial is rejected for
//! appearing to happen "after" the flow it opened, and for a long connection
//! the age window is measured from a point hours away from the real one.
//! Measured cost before the fix: roughly half of every batch deferred.
//!
//! So the ordering uses event time -- `portbridge.time` and `zeek.ts` -- and
//! only the *grace* decision uses ingest time, because "has portbridge's
//! record had time to arrive yet" is genuinely a question about shipping.
//!
//! # The pipeline gets the last word on source.ip
//!
//! `geoip-honeypot` is these indices' `default_pipeline`, and a
//! `default_pipeline` runs on `_update`, not only on index. Its Zeek branch
//! derives `source.ip` from `zeek.id.orig_h`, which on zeek-proxy is always
//! the tunnel -- so it re-derived the tunnel address immediately after this
//! loop wrote the attacker, and the write appeared to succeed: ES returned
//! `"result":"updated"` with a bumped `_version` every time. Only `network.*`
//! survived, because the pipeline does not touch those fields, which made a
//! pipeline problem look like a join problem for a while.
//!
//! The pipeline now skips that assignment when `network.relay_ip` is present.
//! If this module ever stops writing that field, the pipeline will start
//! silently overwriting attacker attributions again.
//!
//! Overwriting `source.ip` rather than adding a field is deliberate: every
//! existing aggregation, filter and pivot already reads it, and the observed
//! value is not lost — Zeek's own `zeek.id.orig_h` still carries it, and
//! `network.relay_ip` records it explicitly. That field doubles as the
//! "already attributed" marker, so the write is idempotent and fully
//! reversible.

use crate::AppState;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

/// zeek-proxy documents considered per pass. Each resolved one costs its own
/// update, so this is not a bulk-rewrite batch -- but it does have to clear
/// the arrival rate, or the loop falls permanently behind. Measured on the
/// live cluster: ~9,200 zeek-proxy conn records an hour, of which roughly
/// three quarters are relayed and therefore attributable. At one pass every
/// 120s this ceiling is 15,000/hour, which keeps pace and still drains a
/// backlog. 200 did not: it capped the loop at 6,000/hour against 9,200
/// arriving, and the shortfall accumulated silently.
const BATCH: usize = 500;

/// How far back to look for unresolved documents. portbridge and zeek-proxy
/// write independently, so a zeek-proxy record can arrive before the
/// portbridge record that explains it; a narrow window would leave it
/// permanently unattributed for having been looked at once, too early.
const LOOKBACK: &str = "now-6h";

/// How recent is too recent to be worth looking at.
///
/// portbridge's record of a flow is not reliably visible the instant
/// zeek-proxy's is. Measured on the live cluster: of the 500 newest
/// unattributed flows, portbridge knew only **286** -- 57% -- while a sample
/// of flows aged one to ten minutes came out at 88-94%. The gap closes on
/// its own within a couple of minutes.
///
/// Without this bound the loop spends its batch on the newest flows
/// precisely because they are newest (see the sort below), finds no dial for
/// nearly half of them, defers them because they are inside the grace
/// period, and reads the same ones again next pass. Observed: deferred=380
/// of 500, pass after pass, while the resolvable backlog behind them went
/// untouched.
///
/// Two minutes is roughly thirty times the few seconds of shipping lag
/// actually measured between the two sensors, and costs at most one pass of
/// latency on a flow that would have resolved anyway.
const SETTLE: &str = "now-2m";

/// How long before a relayed flow a portbridge dial may have happened and
/// still explain it. Same bound, for the same reason, as
/// `ip_enrichment::viamap`'s MAX_AGE_SECONDS.
const MAX_DIAL_AGE_SECONDS: i64 = 6 * 3600;

/// How long to keep re-examining a flow that nothing explains yet.
///
/// Two very different situations look identical on any single pass: portbridge
/// simply has not written its side of a flow that *is* relayed, or the flow was
/// never relayed at all. wg0 carries our own traffic too -- the dashboard's
/// queries to Elasticsearch, the pcap sync hop, WireGuard's own keepalives --
/// and none of that has an attacker behind it or ever will.
///
/// Age separates them. portbridge logs at dial time, strictly before the
/// relayed flow exists, so once a flow is this old a missing dial is an answer
/// rather than a delay. Below the threshold the flow is left alone and looked
/// at again next pass; above it, it is marked so it stops being a candidate.
///
/// Marking matters more than it looks. Without it these flows stay candidates
/// forever, so every pass re-reads and re-rejects the same growing set, and
/// the share of each batch spent on work that can never succeed only rises --
/// a loop that looks busy while resolving less and less. That is true under
/// any sort order; reading newest-first bounds how far back the waste reaches
/// but does not remove it.
const GRACE_SECONDS: i64 = 30 * 60;

// The WireGuard endpoints. A flow whose source is one of these is our own
// relay rather than an attacker, which is the whole reason this loop exists.
//
// Only the via_port arm of the query needs them named: the community_id arm
// identifies its candidates by having a relayed key at all, but the via_port
// arm would otherwise match every unattributed flow in the window.

/// One portbridge dial: when it actually happened, and who was behind it.
///
/// `at` is `portbridge.time` -- the dial itself -- not the record's
/// `@timestamp`, which is when Filebeat shipped it.
#[derive(Debug, Clone, PartialEq)]
pub struct Dial {
    pub at: i64,
    pub attacker: String,
    pub attacker_key: String,
    /// The sensor port this dial was aimed at, parsed from portbridge's
    /// `target` ("10.8.0.2:5060" -> 5060). 0 when the record carried none.
    ///
    /// Only the via_port join reads it, and for that join it is not optional:
    /// an ephemeral port is reused within seconds, so `via_port` alone can
    /// match a dial to a different sensor entirely. The destination port
    /// separates them -- a flow to SIP on 5060 did not come from a dial to
    /// telnet on 19023, whatever the clock says. Same constraint
    /// `ip_enrichment::viamap` applies for the same reason (#1917).
    pub target_port: i64,
}

/// How a flow is joined back to portbridge.
#[derive(Debug, Clone, PartialEq)]
pub enum Join {
    /// zeek computed a community_id for the relayed tuple; portbridge logged
    /// the same value as `community_id_relayed`.
    Relayed(String),
    /// zeek did not. Every per-protocol log zeek writes (sip, files, http,
    /// ssh...) references a connection without repeating its community_id, so
    /// the first join cannot see them at all -- measured on the live cluster,
    /// 8,928 flows in 24h, every one of them still showing the tunnel as its
    /// source.
    ///
    /// The tunnel-side tuple is the join instead: the ephemeral port zeek
    /// sees as `source.port` is the very port portbridge dialled from and
    /// logged as `via_port`, and `destination.port` is the sensor it aimed
    /// at. Verified against a live pair before this was written: a SIP flow
    /// from 10.8.0.1:54197 to :5060 matched exactly one dial -- via_port
    /// 54197, target 10.8.0.2:5060, at the same second -- from 5.39.101.60.
    Via { via_port: i64, target_port: i64 },
}

fn interval() -> Duration {
    let secs = std::env::var("ZEEK_PROXY_ATTRIBUTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(120);
    Duration::from_secs(secs)
}

pub async fn zeek_proxy_attribution_loop(state: AppState) {
    let mut ticker = tokio::time::interval(interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // #2181: the join-side parsers (dials_by_key/dials_by_via_port)
        // digest portbridge records inline above the per-flow writes, so a
        // drifted shape poisons every flow's join rather than one record —
        // hence one cycle-level boundary instead of per-flow splits (the
        // flow rows themselves are built from total constructors, nothing
        // recoverable to carve off). Skip semantics stay queue-honest:
        // unmatched candidates defer until grace ages them into
        // relay_unresolved, so even repeated degraded passes empty
        // naturally instead of pinning the candidate window open forever.
        crate::isolate::cycle("zeek-proxy-attribution", async {
            if let Err(error) = resolve_once(&state).await {
                tracing::warn!(%error, "zeek-proxy-attribution: pass failed");
            }
        })
        .await;
    }
}

/// The dial that opened a flow seen at `flow_at`, or None.
///
/// Two rules, both there to refuse rather than guess:
///   * a dial after the flow cannot have opened it — portbridge logs at dial
///     time, strictly before the relayed connection exists;
///   * a dial older than the window is a different session that happened to
///     reuse the ephemeral port.
pub fn dial_for(dials: &[Dial], flow_at: i64) -> Option<&Dial> {
    dials
        .iter()
        .filter(|dial| dial.at <= flow_at && flow_at - dial.at <= MAX_DIAL_AGE_SECONDS)
        .max_by_key(|dial| dial.at)
}

/// The dial that opened a flow to `want_target_port`, or None.
///
/// dial_for's two rules, plus the one the via_port key needs: a dial aimed at
/// a different sensor did not open this flow. A record with no target port is
/// refused rather than allowed through -- it cannot be checked, and an
/// unchecked candidate on a reused ephemeral port is how a flow gets
/// confidently attributed to the wrong attacker.
pub fn dial_for_via(dials: &[Dial], flow_at: i64, want_target_port: i64) -> Option<&Dial> {
    dials
        .iter()
        .filter(|dial| dial.target_port != 0 && dial.target_port == want_target_port)
        .filter(|dial| dial.at <= flow_at && flow_at - dial.at <= MAX_DIAL_AGE_SECONDS)
        .max_by_key(|dial| dial.at)
}

/// The port half of portbridge's `target` ("10.8.0.2:5060" -> 5060).
pub fn target_port_of(target: &str) -> i64 {
    target
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<i64>().ok())
        .unwrap_or(0)
}

/// What to do with a flow that no dial explains.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Unmatched {
    /// Too recent to conclude anything -- portbridge's side may still arrive.
    Retry,
    /// Old enough that a missing dial is the answer: this flow was not relayed.
    Mark,
}

pub fn unmatched_action(flow_at: i64, now: i64) -> Unmatched {
    if now - flow_at > GRACE_SECONDS {
        Unmatched::Mark
    } else {
        Unmatched::Retry
    }
}

fn parse_seconds(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| parsed.timestamp())
}

/// Relayed key -> every dial seen for it, plus how many of those records had
/// no `portbridge.time` and fell back to the ship time.
///
/// That count is returned rather than swallowed because the fallback is
/// exactly how #1834's fix came undone: `portbridge.time` was read but never
/// requested in the query's `_source`, so every record took the fallback,
/// the join went back to comparing ship times, and nothing anywhere said so.
/// A silent graceful degradation on a field you have just introduced hides
/// the case where you forgot to fetch it.
fn dials_by_key(hits: &Value) -> (HashMap<String, Vec<Dial>>, usize) {
    let mut map: HashMap<String, Vec<Dial>> = HashMap::new();
    let mut without_dial_time = 0usize;
    for hit in hits["hits"]["hits"].as_array().into_iter().flatten() {
        let source = &hit["_source"];
        let pb = &source["portbridge"];
        // portbridge.time is the dial; @timestamp is only when the line was
        // shipped, and is 3-4s later. Fall back to it so a record missing the
        // real field still participates rather than vanishing from the join.
        let dialled_at = match pb["time"].as_str().and_then(parse_seconds) {
            Some(at) => Some(at),
            None => {
                without_dial_time += 1;
                source["@timestamp"].as_str().and_then(parse_seconds)
            }
        };
        let (Some(relayed), Some(attacker), Some(at)) =
            (pb["community_id_relayed"].as_str(), pb["src_ip"].as_str(), dialled_at)
        else {
            continue;
        };
        if relayed.is_empty() || attacker.is_empty() {
            continue;
        }
        map.entry(relayed.to_string()).or_default().push(Dial {
            at,
            attacker: attacker.to_string(),
            attacker_key: pb["community_id"].as_str().unwrap_or_default().to_string(),
            target_port: target_port_of(pb["target"].as_str().unwrap_or_default()),
        });
    }
    (map, without_dial_time)
}

/// via_port -> every dial seen from it, for the flows zeek gave no
/// community_id (#1876).
///
/// Same shape and same time-fallback reporting as dials_by_key; the key is
/// the tunnel-side ephemeral port instead of the relayed community_id, and a
/// record with no via_port or no target is skipped rather than kept, because
/// dial_for_via cannot check it.
fn dials_by_via_port(hits: &Value) -> (HashMap<i64, Vec<Dial>>, usize) {
    let mut map: HashMap<i64, Vec<Dial>> = HashMap::new();
    let mut without_dial_time = 0usize;
    for hit in hits["hits"]["hits"].as_array().into_iter().flatten() {
        let source = &hit["_source"];
        let pb = &source["portbridge"];
        let dialled_at = match pb["time"].as_str().and_then(parse_seconds) {
            Some(at) => Some(at),
            None => {
                without_dial_time += 1;
                source["@timestamp"].as_str().and_then(parse_seconds)
            }
        };
        let (Some(via_port), Some(attacker), Some(at)) =
            (pb["via_port"].as_i64(), pb["src_ip"].as_str(), dialled_at)
        else {
            continue;
        };
        let target_port = target_port_of(pb["target"].as_str().unwrap_or_default());
        if attacker.is_empty() || via_port == 0 || target_port == 0 {
            continue;
        }
        map.entry(via_port).or_default().push(Dial {
            at,
            attacker: attacker.to_string(),
            attacker_key: pb["community_id"].as_str().unwrap_or_default().to_string(),
            target_port,
        });
    }
    (map, without_dial_time)
}

async fn resolve_once(state: &AppState) -> anyhow::Result<()> {
    let pending = state
        .es
        .search_index(
            &["zeek-proxy-v1-*"],
            json!({
                "size": BATCH,
                "track_total_hits": false,
                "query": {"bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": LOOKBACK, "lte": SETTLE}}},
                        // Either join is enough to be worth fetching. This was
                        // `exists: network.community_id` alone, which silently
                        // excluded every per-protocol log zeek writes -- they
                        // reference a connection without repeating its
                        // community_id, so the loop never saw them and they
                        // kept the tunnel as their source indefinitely
                        // (#1876; 8,928 of them in 24h when measured).
                        //
                        // The second arm asks for the tunnel tuple explicitly.
                        // Without that it would match every unattributed flow
                        // in the window, including ones whose source is
                        // already a real attacker and which need nothing.
                        {"bool": {
                            "minimum_should_match": 1,
                            "should": [
                                {"exists": {"field": "network.community_id"}},
                                {"bool": {"filter": [
                                    {"terms": {"source.ip": [crate::fleet::tunnel_peer_ip(), crate::fleet::tunnel_sensor_ip()]}},
                                    {"exists": {"field": "source.port"}},
                                    {"exists": {"field": "destination.port"}}
                                ]}}
                            ]
                        }}
                    ],
                    "must_not": [
                        {"exists": {"field": "network.relay_ip"}},
                        {"exists": {"field": "network.relay_unresolved"}}
                    ]
                }},
                // Newest first. Oldest-first is the intuitive choice and it is
                // the wrong one: with a backlog larger than a pass, the loop
                // pins itself to the trailing edge of the window and spends
                // every batch on flows that are minutes from ageing out of it,
                // while the flows someone is actually looking at on the
                // dashboard stay unattributed. Measured that way: oldest
                // candidate 04:45 against a newest document of 10:45, six
                // hours of lag that would have taken most of a day to close.
                //
                // Capacity exceeds the arrival rate (BATCH per pass against
                // ~9,200/hour), so newest-first attributes new flows within a
                // pass or two of arrival and spends what is left over working
                // backwards into the backlog. The tail still ages out, but it
                // ages out having been the lowest-value part of the window
                // rather than the only part that got attention.
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": [
                    "network.community_id",
                    "source.ip",
                    // The via_port join's key and its guard. Fetching them is
                    // not optional in the way an unused field would be: a
                    // missing source.port drops the flow from the join
                    // entirely rather than degrading it, which is the failure
                    // dials_by_key's warning exists to make loud.
                    "source.port",
                    "destination.port",
                    "@timestamp",
                    "zeek.ts"
                ]
            }),
        )
        .await?;

    struct Pending {
        index: String,
        id: String,
        join: Join,
        /// When the flow opened (`zeek.ts`) -- compared against dial times.
        at: i64,
        /// When the record was shipped (`@timestamp`) -- used only to decide
        /// whether portbridge has plausibly had time to write its side.
        ingested_at: i64,
        observed: String,
    }

    let docs: Vec<Pending> = pending["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let source = &hit["_source"];
            Some(Pending {
                index: hit["_index"].as_str()?.to_string(),
                id: hit["_id"].as_str()?.to_string(),
                // The relayed community_id when zeek computed one, the
                // tunnel tuple when it did not. A flow offering neither is
                // dropped here rather than carried to a join that cannot
                // answer it.
                join: match source["network"]["community_id"].as_str() {
                    Some(cid) if !cid.is_empty() => Join::Relayed(cid.to_string()),
                    _ => Join::Via {
                        via_port: source["source"]["port"].as_i64()?,
                        target_port: source["destination"]["port"].as_i64()?,
                    },
                },
                // zeek.ts is epoch seconds as a float; @timestamp is the
                // ship time and is the wrong clock for the ordering rule,
                // but is the only one available if zeek.ts is missing.
                at: source["zeek"]["ts"]
                    .as_f64()
                    .map(|ts| ts as i64)
                    .or_else(|| source["@timestamp"].as_str().and_then(parse_seconds))?,
                ingested_at: source["@timestamp"].as_str().and_then(parse_seconds)?,
                observed: source["source"]["ip"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect();
    if docs.is_empty() {
        return Ok(());
    }

    let keys: Vec<&str> = docs
        .iter()
        .filter_map(|doc| match &doc.join {
            Join::Relayed(cid) => Some(cid.as_str()),
            Join::Via { .. } => None,
        })
        .collect();
    let via_ports: Vec<i64> = {
        let mut ports: Vec<i64> = docs
            .iter()
            .filter_map(|doc| match doc.join {
                Join::Via { via_port, .. } => Some(via_port),
                Join::Relayed(_) => None,
            })
            .collect();
        // A terms query wants each value once; a busy port appears in the
        // batch many times over.
        ports.sort_unstable();
        ports.dedup();
        ports
    };
    let relayed = state
        .es
        .search_index(
            &["portbridge-v2-*"],
            json!({
                // Several dials per key is the normal case, not an anomaly --
                // that is what makes the time constraint necessary -- so fetch
                // generously and let dial_for choose.
                "size": BATCH * 8,
                "track_total_hits": false,
                "query": {"terms": {"portbridge.community_id_relayed": keys}},
                // portbridge.time is the dial time and is what dials_by_key
                // actually joins on. Leaving it out of this list -- which is
                // how it shipped in #1834 -- does not fail: the parser falls
                // back to @timestamp and silently resumes comparing ship
                // times, which is the bug that change existed to fix.
                "_source": [
                    "@timestamp",
                    "portbridge.time",
                    "portbridge.community_id_relayed",
                    "portbridge.community_id",
                    "portbridge.src_ip"
                ]
            }),
        )
        .await?;

    // #2179: "fetch generously" is still finite, and with track_total_hits
    // false a full page is the only truncation signal ES hands back -- so say
    // so rather than letting those keys resolve thin this pass and converge
    // again only by retry luck.
    if relayed["hits"]["hits"].as_array().is_some_and(|a| a.len() >= BATCH * 8) {
        tracing::warn!(
            cap = BATCH * 8,
            "zeek-proxy-attribution: relayed-dial candidate fetch filled its size cap this pass, some keys may resolve on a later pass"
        );
    }

    // The via_port side. Skipped entirely when the batch happens to hold no
    // such flows, so the common case costs nothing.
    let via_hits = if via_ports.is_empty() {
        Value::Null
    } else {
        state
            .es
            .search_index(
                &["portbridge-v2-*"],
                json!({
                    "size": BATCH * 8,
                    "track_total_hits": false,
                    "query": {"terms": {"portbridge.via_port": via_ports}},
                    // portbridge.target is this join's guard, not decoration:
                    // without it dial_for_via refuses every candidate and the
                    // join silently resolves nothing. Same projection trap
                    // portbridge.time hit in #1834.
                    "_source": [
                        "@timestamp",
                        "portbridge.time",
                        "portbridge.via_port",
                        "portbridge.target",
                        "portbridge.community_id",
                        "portbridge.src_ip"
                    ]
                }),
            )
            .await?
    };

    let (dials, dials_without_time) = dials_by_key(&relayed);
    let (via_dials, via_without_time) = if via_hits.is_null() {
        (HashMap::new(), 0)
    } else {
        // #2179: same full-page disclosure as the relayed side above.
        if via_hits["hits"]["hits"].as_array().is_some_and(|a| a.len() >= BATCH * 8) {
            tracing::warn!(
                cap = BATCH * 8,
                "zeek-proxy-attribution: via-port dial candidate fetch filled its size cap this pass, some keys may resolve on a later pass"
            );
        }
        dials_by_via_port(&via_hits)
    };
    if via_without_time > 0 {
        tracing::warn!(
            via_without_time,
            "zeek-proxy-attribution: portbridge via_port records arrived without \
             portbridge.time, so the join fell back to ship times -- check the \
             query's _source projection"
        );
    }
    if dials_without_time > 0 {
        tracing::warn!(
            dials_without_time,
            "zeek-proxy-attribution: portbridge records arrived without portbridge.time, \
             so the join fell back to ship times -- check the query's _source projection"
        );
    }
    let now = chrono::Utc::now().timestamp();

    let (mut resolved, mut marked, mut deferred) = (0usize, 0usize, 0usize);
    for doc in &docs {
        let matched = match &doc.join {
            Join::Relayed(cid) => dials.get(cid).and_then(|candidates| dial_for(candidates, doc.at)),
            Join::Via { via_port, target_port } => via_dials
                .get(via_port)
                .and_then(|candidates| dial_for_via(candidates, doc.at, *target_port)),
        };

        let Some(dial) = matched else {
            // Nothing explains this flow. Whether that is temporary or
            // permanent is a question of age, not of this pass -- see
            // GRACE_SECONDS. Marking the permanent ones is what keeps the
            // candidate window from silting up.
            // Ingest time, not flow time: this asks whether portbridge has
            // had time to ship its side, which is a question about shipping.
            // Using the flow's start here would write off a long-lived
            // connection the moment it closed, however recently it was shipped.
            match unmatched_action(doc.ingested_at, now) {
                Unmatched::Retry => deferred += 1,
                Unmatched::Mark => {
                    let update = json!({"network": {"relay_unresolved": true}});
                    match state.es.update_doc(&doc.index, &doc.id, update).await {
                        Ok(()) => marked += 1,
                        Err(error) => tracing::warn!(
                            %error, doc_id = %doc.id,
                            "zeek-proxy-attribution: could not mark unresolved"
                        ),
                    }
                }
            }
            continue;
        };

        let mut network = json!({"relay_ip": doc.observed});
        if !dial.attacker_key.is_empty() {
            network["community_id_attacker"] = json!(dial.attacker_key);
        }
        let update = json!({"source": {"ip": dial.attacker}, "network": network});
        if let Err(error) = state.es.update_doc(&doc.index, &doc.id, update).await {
            tracing::warn!(%error, doc_id = %doc.id, "zeek-proxy-attribution: update failed");
            continue;
        }
        resolved += 1;
    }

    if resolved > 0 || marked > 0 || deferred > 0 {
        tracing::debug!(
            resolved,
            marked,
            deferred,
            candidates = docs.len(),
            "zeek-proxy-attribution pass complete"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dial(at: i64, attacker: &str) -> Dial {
        Dial { at, attacker: attacker.into(), attacker_key: format!("key-{attacker}"), target_port: 0 }
    }

    fn dial_to(at: i64, attacker: &str, target_port: i64) -> Dial {
        Dial { at, attacker: attacker.into(), attacker_key: format!("key-{attacker}"), target_port }
    }

    #[test]
    fn picks_the_most_recent_dial_before_the_flow() {
        // The live shape that broke the first attempt: one relayed key, several
        // dials, different attackers. Taking any match attributes the flow to
        // whoever reused the ephemeral port.
        let dials = vec![
            dial(1_000, "203.0.113.1"),
            dial(2_000, "198.51.100.2"),
            dial(3_000, "203.0.113.9"),
        ];
        assert_eq!(dial_for(&dials, 3_500).unwrap().attacker, "203.0.113.9");
        assert_eq!(dial_for(&dials, 2_500).unwrap().attacker, "198.51.100.2");
    }

    #[test]
    fn refuses_a_dial_that_happened_after_the_flow() {
        // portbridge logs at dial time, strictly before the relayed connection
        // can exist, so a later dial cannot explain this flow.
        let dials = vec![dial(5_000, "203.0.113.1")];
        assert!(dial_for(&dials, 4_999).is_none());
    }

    #[test]
    fn refuses_a_dial_older_than_the_window() {
        // Same port, a different session hours earlier.
        let dials = vec![dial(1_000, "203.0.113.1")];
        assert!(dial_for(&dials, 1_000 + MAX_DIAL_AGE_SECONDS + 1).is_none());
        assert!(dial_for(&dials, 1_000 + MAX_DIAL_AGE_SECONDS).is_some());
    }

    #[test]
    fn no_candidates_attributes_nothing() {
        assert!(dial_for(&[], 1_000).is_none());
    }

    #[test]
    fn a_recent_unmatched_flow_is_retried_not_written_off() {
        // portbridge's side may still be in flight; concluding "never relayed"
        // this early would mark a real attacker's flow as internal traffic.
        let now = 100_000;
        assert_eq!(unmatched_action(now - 60, now), Unmatched::Retry);
        assert_eq!(unmatched_action(now - GRACE_SECONDS, now), Unmatched::Retry);
    }

    #[test]
    fn an_old_unmatched_flow_is_marked_so_the_window_can_move() {
        // Past the grace period a missing dial is the answer. Without the mark
        // these flows stay candidates forever and crowd out attributable work.
        let now = 100_000;
        assert_eq!(unmatched_action(now - GRACE_SECONDS - 1, now), Unmatched::Mark);
        assert_eq!(unmatched_action(now - 6 * 3600, now), Unmatched::Mark);
    }

    #[test]
    fn groups_dials_by_relayed_key_and_keeps_all_of_them() {
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T07:00:00Z", "portbridge": {
                "community_id_relayed": "1:same=", "community_id": "1:a=", "src_ip": "203.0.113.1"}}},
            {"_source": {"@timestamp": "2026-08-24T07:05:00Z", "portbridge": {
                "community_id_relayed": "1:same=", "community_id": "1:b=", "src_ip": "198.51.100.2"}}}
        ]}});
        let (map, _) = dials_by_key(&hits);
        // Both must survive -- collapsing them is precisely the bug.
        assert_eq!(map.get("1:same=").map(Vec::len), Some(2));
    }

    #[test]
    fn the_dial_time_comes_from_portbridge_time_not_the_ship_time() {
        // Measured on the live cluster: @timestamp runs 3-4s behind
        // portbridge.time, because it is when Filebeat shipped the line.
        // Using it as the dial time makes a dial look later than the flow it
        // opened, and dial_for then refuses a perfectly good match -- which
        // is what was deferring roughly half of every batch.
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T13:48:29Z", "portbridge": {
                "time": "2026-08-24T13:48:26Z",
                "community_id_relayed": "1:same=", "community_id": "1:a=", "src_ip": "203.0.113.1"}}}
        ]}});
        let (map, _) = dials_by_key(&hits);
        let dial = &map.get("1:same=").expect("grouped")[0];
        let dialled = chrono::DateTime::parse_from_rfc3339("2026-08-24T13:48:26Z").unwrap().timestamp();
        assert_eq!(dial.at, dialled, "should use portbridge.time, not @timestamp");

        // A flow that opened one second after the dial: resolvable with the
        // real time, rejected if the ship time were used.
        assert!(dial_for(&map["1:same="], dialled + 1).is_some());
    }

    #[test]
    fn a_record_without_portbridge_time_still_joins() {
        // Falling back to @timestamp keeps an older or malformed record in
        // the join rather than silently dropping it -- a missing field should
        // cost precision, not the whole match.
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T13:48:29Z", "portbridge": {
                "community_id_relayed": "1:same=", "community_id": "1:a=", "src_ip": "203.0.113.1"}}}
        ]}});
        let (map, _) = dials_by_key(&hits);
        assert_eq!(map.get("1:same=").map(Vec::len), Some(1));
    }


    #[test]
    fn the_query_asks_for_every_field_the_parser_reads() {
        // #1834 read portbridge.time and never added it to the query's
        // _source, so every record took the fallback and the join quietly
        // went back to comparing ship times -- the exact bug that change
        // existed to remove. Nothing failed; the fallback was doing its job.
        //
        // Pin the projection against the fields dials_by_key actually
        // touches. A future field added to the parser and forgotten here
        // fails this rather than degrading in production.
        let source = include_str!("zeek_proxy_attribution.rs");

        // Anchor on something unique to each query rather than on the index
        // name: there are three queries now, two of them against
        // portbridge-v2-*, and counting occurrences of an index name breaks
        // the moment one is added -- or the moment this test mentions it.
        let projection_after = |marker: &str| -> String {
            source
                .split(marker)
                .nth(1)
                .and_then(|rest| rest.split("_source").nth(1))
                .and_then(|rest| rest.split(']').next())
                .unwrap_or_else(|| panic!("no _source list follows {marker}"))
                .to_string()
        };

        let relayed = projection_after("portbridge.community_id_relayed\": keys");
        for field in ["portbridge.time", "portbridge.community_id_relayed", "portbridge.community_id", "portbridge.src_ip"] {
            assert!(
                relayed.contains(field),
                "{field} is read by dials_by_key but not requested in the relayed query"
            );
        }

        // #1876's join has the same exposure, and one field more: without
        // portbridge.target every candidate has target_port 0, dial_for_via
        // refuses all of them, and the join resolves nothing at all while
        // looking perfectly healthy.
        let via = projection_after("portbridge.via_port\": via_ports");
        for field in ["portbridge.time", "portbridge.via_port", "portbridge.target", "portbridge.community_id", "portbridge.src_ip"] {
            assert!(
                via.contains(field),
                "{field} is read by dials_by_via_port but not requested in the via_port query"
            );
        }

        // And the flow side: source.port is the via_port join's key and
        // destination.port is its guard. A flow missing either is dropped
        // from the batch entirely rather than degraded.
        let flows = projection_after("\"lte\": SETTLE");
        for field in ["network.community_id", "source.ip", "source.port", "destination.port", "zeek.ts"] {
            assert!(
                flows.contains(field),
                "{field} is read when building Pending but not requested in the flow query"
            );
        }
    }

    #[test]
    fn a_record_without_a_dial_time_is_counted_not_hidden() {
        // The fallback is correct -- a missing field should cost precision,
        // not drop the record -- but it must be audible, or it hides a
        // forgotten projection the way it did in #1834.
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T13:48:29Z", "portbridge": {
                "community_id_relayed": "1:a=", "community_id": "1:x=", "src_ip": "203.0.113.1"}}},
            {"_source": {"@timestamp": "2026-08-24T13:48:29Z", "portbridge": {
                "time": "2026-08-24T13:48:26Z",
                "community_id_relayed": "1:b=", "community_id": "1:y=", "src_ip": "203.0.113.2"}}}
        ]}});
        let (map, without_time) = dials_by_key(&hits);
        assert_eq!(map.len(), 2, "both records still join");
        assert_eq!(without_time, 1, "the one that fell back is counted");
    }

    #[test]
    fn skips_portbridge_records_that_explain_nothing() {
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T07:00:00Z", "portbridge": {"community_id": "1:a="}}},
            {"_source": {"portbridge": {"community_id_relayed": "1:x=", "src_ip": "203.0.113.1"}}},
            {"_source": {"@timestamp": "2026-08-24T07:00:00Z", "portbridge": {
                "community_id_relayed": "1:y=", "src_ip": ""}}}
        ]}});
        assert!(dials_by_key(&hits).0.is_empty());
    }

    // ── the via_port join (#1876) ────────────────────────────────────────

    #[test]
    fn the_via_port_join_recovers_the_attacker_the_relayed_key_cannot() {
        // The live pair this was written against: a SIP flow from
        // 10.8.0.1:54197 to :5060, and exactly one dial from that ephemeral
        // port aimed at that sensor, at the same second, from 5.39.101.60.
        // zeek wrote no community_id for it -- sip.log references the
        // connection without repeating one -- so the relayed join never saw
        // it and the flow kept the tunnel as its source.
        let flow_at = 1_787_600_142;
        let dials = vec![dial_to(flow_at, "5.39.101.60", 5060)];
        assert_eq!(dial_for_via(&dials, flow_at, 5060).map(|d| d.attacker.as_str()), Some("5.39.101.60"));
    }

    #[test]
    fn a_dial_to_a_different_sensor_is_refused() {
        // The reason the destination port is part of the key. An ephemeral
        // port is reused within seconds across unrelated sensors, so a
        // via_port match alone will happily hand back whoever dialled telnet
        // when the flow was SIP -- and a wrong attacker is indistinguishable
        // from a right one.
        let flow_at = 2_000;
        let dials = vec![dial_to(flow_at, "203.0.113.9", 19023)];
        assert_eq!(dial_for_via(&dials, flow_at, 5060), None);
    }

    #[test]
    fn among_dials_to_the_same_sensor_the_most_recent_before_the_flow_wins() {
        let flow_at = 5_000;
        let dials = vec![
            dial_to(4_000, "203.0.113.1", 5060),
            dial_to(4_900, "203.0.113.2", 5060),
            dial_to(4_950, "198.51.100.7", 19023), // right time, wrong sensor
            dial_to(5_100, "203.0.113.3", 5060),   // after the flow
        ];
        assert_eq!(dial_for_via(&dials, flow_at, 5060).map(|d| d.attacker.as_str()), Some("203.0.113.2"));
    }

    #[test]
    fn the_via_join_keeps_dial_for_s_own_two_rules() {
        let flow_at = 5_000;
        assert_eq!(dial_for_via(&[dial_to(5_001, "a", 5060)], flow_at, 5060), None, "a dial after the flow");
        let stale = flow_at - MAX_DIAL_AGE_SECONDS - 1;
        assert_eq!(dial_for_via(&[dial_to(stale, "a", 5060)], flow_at, 5060), None, "older than the window");
    }

    #[test]
    fn a_dial_with_no_target_port_is_refused_rather_than_allowed_through() {
        // It cannot be checked, and an unchecked candidate on a reused
        // ephemeral port is exactly how a flow gets confidently misattributed.
        let flow_at = 5_000;
        assert_eq!(dial_for_via(&[dial_to(flow_at, "203.0.113.1", 0)], flow_at, 5060), None);
    }

    #[test]
    fn target_port_is_parsed_off_portbridge_s_target() {
        assert_eq!(target_port_of("10.8.0.2:5060"), 5060);
        assert_eq!(target_port_of("10.8.0.2:19023"), 19023);
        assert_eq!(target_port_of(""), 0, "no target at all");
        assert_eq!(target_port_of("10.8.0.2"), 0, "host with no port");
        assert_eq!(target_port_of("10.8.0.2:nonsense"), 0, "unparseable port");
        // An IPv6 target still yields the port after the last colon.
        assert_eq!(target_port_of("[fd00::2]:5060"), 5060);
    }

    #[test]
    fn via_dials_are_grouped_by_port_and_carry_their_target() {
        let hits = json!({"hits": {"hits": [
            {"_source": {"portbridge": {"time": "2026-08-24T19:35:42Z", "via_port": 54197,
                "target": "10.8.0.2:5060", "community_id": "1:a=", "src_ip": "5.39.101.60"}}},
            {"_source": {"portbridge": {"time": "2026-08-24T19:35:43Z", "via_port": 54197,
                "target": "10.8.0.2:19023", "community_id": "1:b=", "src_ip": "203.0.113.4"}}}
        ]}});
        let (map, without_time) = dials_by_via_port(&hits);
        assert_eq!(without_time, 0);
        let dials = map.get(&54197).expect("grouped under its via_port");
        assert_eq!(dials.len(), 2, "both dials kept -- the target port separates them, not this step");
        assert_eq!(dials.iter().filter(|d| d.target_port == 5060).count(), 1);
    }

    #[test]
    fn a_via_record_that_cannot_be_checked_is_skipped() {
        // No target, no via_port, or no attacker: each would otherwise become
        // a candidate that dial_for_via has no way to refuse on merit.
        let hits = json!({"hits": {"hits": [
            {"_source": {"portbridge": {"time": "2026-08-24T19:35:42Z", "via_port": 1,
                "community_id": "1:a=", "src_ip": "203.0.113.1"}}},
            {"_source": {"portbridge": {"time": "2026-08-24T19:35:42Z",
                "target": "10.8.0.2:5060", "community_id": "1:b=", "src_ip": "203.0.113.2"}}},
            {"_source": {"portbridge": {"time": "2026-08-24T19:35:42Z", "via_port": 3,
                "target": "10.8.0.2:5060", "community_id": "1:c=", "src_ip": ""}}}
        ]}});
        let (map, _) = dials_by_via_port(&hits);
        assert!(map.is_empty(), "none of the three can be checked, so none is a candidate");
    }

    #[test]
    fn a_via_record_without_a_dial_time_is_counted_not_hidden() {
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T19:35:46Z", "portbridge": {"via_port": 54197,
                "target": "10.8.0.2:5060", "community_id": "1:a=", "src_ip": "5.39.101.60"}}}
        ]}});
        let (map, without_time) = dials_by_via_port(&hits);
        assert_eq!(without_time, 1, "the fallback is reported, the way #1834 taught");
        assert_eq!(map.len(), 1, "and the record still participates");
    }

    #[test]
    fn the_relayed_join_now_carries_the_target_port_too() {
        // Same parser, one more field -- so a relayed dial is not silently
        // left with target_port 0 if the two joins are ever unified.
        let hits = json!({"hits": {"hits": [
            {"_source": {"portbridge": {"time": "2026-08-24T19:35:42Z",
                "community_id_relayed": "1:same=", "community_id": "1:a=",
                "target": "10.8.0.2:5060", "src_ip": "203.0.113.1"}}}
        ]}});
        let (map, _) = dials_by_key(&hits);
        assert_eq!(map["1:same="][0].target_port, 5060);
    }

}
