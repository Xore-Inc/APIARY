//! Fleet topology (#1989): the three joins no other endpoint makes.
//!
//! The dashboard answers "is this piece alive?" everywhere, but the
//! operator questions that only exist *between* the pieces — what exposes
//! what, where a byte flows, which stack owns a container — lived only in
//! docs/ and compose comments. This module serves that shape as data:
//!
//! * `sensors[]`  — sensor → ports → ingress path (exposure edges)
//! * `flow`       — layered DAG: ingress → sensor → Filebeat → raw index
//!   → worker → derived index → dashboard surface
//! * `stacks[]`   — stack → containers, flagged for services-adapter
//!   coverage so the runtime join knows what it can see
//!
//! Everything here is STATIC configuration knowledge; liveness comes from
//! `/api/v1/source-health` (freshness) and `/api/v1/services` (container
//! states), joined by the frontend. Keeping this handler free of ES and
//! Docker calls keeps it honest about what is config and what is state,
//! and keeps the whole module testable without either.
//!
//! Provenance of each table lives on the table. The drift test at the
//! bottom (`compose_rules_are_fully_claimed`) parses the portbridge RULES
//! line straight out of vps/docker-compose.yml and fails if exposure
//! config changes without this table changing with it — the same
//! fail-on-drift contract worker.rs's INGEST_FEEDS tests use against
//! EVENT_INDICES.
use axum::Json;
use chrono::Utc;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// One forwarded listener: VPS public port → home-side WireGuard port.
/// `public == 0` means the port is not reachable from the internet at all
/// (tunnel-only management surfaces).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedPort {
    proto: &'static str,
    /// Port an attacker connects to on the VPS. 0 = not internet-exposed.
    public: u16,
    /// Port the tunnel peer forwards to on 10.8.0.2 (the home sensor bind).
    host: u16,
    /// PROXY protocol v1 appended upstream — the only way these sensors can
    /// see a real client address (docs/NETWORK.md attribution table).
    proxy: bool,
}

/// Port constructors are `const fn` because EXPOSURE is a const table.
const fn tcp(public: u16, host: u16) -> ExposedPort {
    ExposedPort { proto: "tcp", public, host, proxy: false }
}
const fn tcpx(public: u16, host: u16) -> ExposedPort {
    ExposedPort { proto: "tcp", public, host, proxy: true }
}
const fn udp(public: u16, host: u16) -> ExposedPort {
    ExposedPort { proto: "udp", public, host, proxy: false }
}

/// How a surface is reached from outside. `traefik` = terminated HTTPS on a
/// hostname; `portbridge` = raw TCP/UDP forwarding; `tunnel-only` =
/// reachable from the WireGuard network only, never advertised.
const TRAEFIK: &str = "traefik";
const PORTBRIDGE: &str = "portbridge";
const TUNNEL_ONLY: &str = "tunnel-only";

/// One home-side decoy/producer and everything that reaches it.
///
/// Sensor names are `event.sensor` values (what source-health's freshness
/// rows are keyed by), NOT container names — the crosswalk between the two
/// naming spaces is exactly the knowledge that existed nowhere before this
/// table (#1989 gap 3). Ports mirror the compose `ports:` blocks plus the
/// VPS RULES string; the parity test below holds this table to both.
struct SensorExposure {
    sensor: &'static str,
    stack: &'static str,
    /// Containers in THIS stack that serve the sensor (sidecars included).
    containers: &'static [&'static str],
    ingress: &'static [&'static str],
    ports: &'static [ExposedPort],
    /// Traefik hostnames, where the ingress path is HTTP(S).
    hostnames: &'static [&'static str],
}

/// The exposure map, in docs/SENSORS.md table order. Every portbridge rule
/// in vps/docker-compose.yml must be claimed exactly once here.
const EXPOSURE: &[SensorExposure] = &[
    SensorExposure {
        sensor: "cowrie",
        stack: "honeypot-cowrie",
        containers: &["hp-cowrie"],
        ingress: &[PORTBRIDGE],
        // Cowrie listens on 2222/2223 in-container; the home binds are
        // 19022/19023 so the low ports stay free for the host sshd story.
        ports: &[tcp(22, 19022), tcp(23, 19023)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "endlessh",
        stack: "honeypot-endlessh",
        containers: &["hp-endlessh"],
        ingress: &[PORTBRIDGE],
        // Public 2022, deliberately NOT 2222 — that is the VPS's own real
        // sshd (#1509). PROXY protocol so endlessh logs real addresses.
        ports: &[tcpx(2022, 19024)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "beelzebub",
        stack: "honeypot-beelzebub",
        containers: &["hp-beelzebub"],
        ingress: &[PORTBRIDGE],
        // LDAP/MCP fill real protocol gaps; no Traefik hostname because
        // beelzebub cannot parse PROXY or read X-Forwarded-For (#1418).
        ports: &[tcp(2200, 2200), tcp(389, 389), tcp(8000, 8000), tcp(8880, 8880)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "mailoney",
        stack: "honeypot-mailoney",
        containers: &["hp-mailoney"],
        ingress: &[PORTBRIDGE],
        ports: &[tcp(25, 25)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "dionaea",
        stack: "honeypot-dionaea",
        containers: &["hp-dionaea", "hp-tftp-relay"],
        ingress: &[PORTBRIDGE],
        // Broad legacy/IoT surface; TFTP rides its own relay container
        // because RFC 1350 switches to a dynamic transfer-ID port.
        ports: &[
            tcp(21, 21),
            tcp(135, 135),
            tcp(445, 445),
            tcp(1433, 1433),
            tcp(1723, 1723),
            tcp(1883, 1883),
            tcp(27017, 27017),
            tcp(3306, 3306),
            tcp(5060, 5060),
            tcp(9100, 9100),
            tcp(11211, 11211),
            udp(69, 1069),
            udp(5060, 5060),
            udp(1900, 1900),
        ],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "multipot",
        stack: "honeypot-multipot",
        containers: &["hp-multipot"],
        ingress: &[PORTBRIDGE],
        // All PROXY-flagged: multipot is one Go binary speaking many
        // protocols, every one of them PROXY-aware (#403 notes ES-only).
        ports: &[
            tcpx(110, 110),
            tcpx(143, 143),
            tcpx(1080, 1080),
            tcpx(2375, 2375),
            tcpx(2575, 2575),
            tcpx(5432, 5432),
            tcpx(5555, 5555),
            tcpx(5900, 5900),
            tcpx(6379, 6379),
            tcpx(9200, 9200),
        ],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "conpot",
        stack: "honeypot-conpot",
        containers: &["hp-conpot"],
        ingress: &[PORTBRIDGE],
        // S7-200 persona: the flagship ICS surface. SNMP/BACnet/IPMI are UDP.
        ports: &[
            tcpx(102, 102),
            tcpx(502, 502),
            tcpx(44818, 44818),
            udp(161, 19161),
            udp(47808, 47808),
            udp(623, 623),
        ],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "conpot-s7-1200",
        stack: "honeypot-conpot",
        containers: &["hp-conpot-s7-1200"],
        ingress: &[PORTBRIDGE],
        // Water-treatment persona; shifted ports (1xxx/15xx) so six conpot
        // instances can share one stack without colliding.
        ports: &[tcpx(1102, 1102), tcpx(1502, 1502)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "conpot-s7-1500",
        stack: "honeypot-conpot",
        containers: &["hp-conpot-s7-1500"],
        ingress: &[PORTBRIDGE],
        // Chemical-process persona.
        ports: &[tcpx(2102, 2102), tcpx(2502, 2502)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "conpot-iec104",
        stack: "honeypot-conpot",
        containers: &["hp-conpot-iec104"],
        ingress: &[PORTBRIDGE],
        ports: &[tcpx(2404, 2404)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "conpot-guardian",
        stack: "honeypot-conpot",
        containers: &["hp-conpot-guardian"],
        ingress: &[PORTBRIDGE],
        ports: &[tcpx(10001, 10001)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "conpot-kamstrup",
        stack: "honeypot-conpot",
        containers: &["hp-conpot-kamstrup"],
        ingress: &[PORTBRIDGE],
        ports: &[tcpx(1025, 1025), tcpx(50100, 50100)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "dnp3",
        stack: "honeypot-dnp3",
        containers: &["hp-dnp3"],
        ingress: &[PORTBRIDGE],
        ports: &[tcpx(20000, 20000)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "dicompot",
        stack: "honeypot-dicompot",
        containers: &["hp-dicompot"],
        ingress: &[PORTBRIDGE],
        ports: &[tcpx(11112, 11112)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "dns-honeypot",
        stack: "honeypot-dns-honeypot",
        containers: &["hp-dns-honeypot"],
        ingress: &[PORTBRIDGE],
        ports: &[udp(53, 53)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "citrix-honeypot",
        stack: "honeypot-citrix-honeypot",
        containers: &["hp-citrix-honeypot"],
        ingress: &[PORTBRIDGE],
        // Public 4443 remapped to home 443 — the container's own TLS port.
        ports: &[tcpx(4443, 443)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "cisco-asa-honeypot",
        stack: "honeypot-cisco-asa-honeypot",
        containers: &["hp-cisco-asa-honeypot"],
        ingress: &[PORTBRIDGE],
        // Only WebVPN gets PROXY; IKE is UDP and speaks first itself, so it
        // stays blind-tunnel (SENSORS.md: replies once per source then quiet).
        ports: &[tcpx(8443, 8443), udp(500, 500)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "sonicwall-sma-honeypot",
        stack: "honeypot-sonicwall-sma",
        containers: &["hp-sonicwall-sma-honeypot"],
        ingress: &[PORTBRIDGE],
        // Public 8543 remapped to home 8543 — the container's own TLS port.
        ports: &[tcpx(8543, 8543)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "rdp-honeypot",
        stack: "honeypot-rdp-honeypot",
        containers: &["hp-rdp-honeypot"],
        ingress: &[PORTBRIDGE],
        ports: &[tcpx(3389, 3389)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "http-honeypot",
        stack: "honeypot-http",
        containers: &["hp-http"],
        // Dual path: Traefik hostnames AND a raw port. The raw leg carries
        // PROXY too (the RULES pp flag), so XFF/via_port both resolve.
        ingress: &[TRAEFIK, PORTBRIDGE],
        ports: &[tcpx(8081, 19081)],
        hostnames: &["decoy.<domain> + catch-all"],
    },
    SensorExposure {
        sensor: "api-honeypot",
        stack: "honeypot-http",
        containers: &["hp-api-honeypot"],
        ingress: &[PORTBRIDGE],
        // Same binary as http-honeypot; raw-only, cloud/K8s/LLM probe bait.
        ports: &[tcpx(8888, 18083)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "galah",
        stack: "honeypot-galah",
        containers: &["hp-galah", "hp-galah-llm-broker"],
        // #1511: galah's raw port is not on Cloudflare's proxied non-standard
        // allowlist, so the hostname leg is how it is actually reachable.
        ingress: &[TRAEFIK, PORTBRIDGE],
        ports: &[tcp(8889, 8888)],
        hostnames: &["hub.<domain>"],
    },
    SensorExposure {
        sensor: "hellpot",
        stack: "honeypot-hellpot",
        containers: &["hp-hellpot"],
        // Piggybacks the apex/www/static catch-all instead of owning a
        // dedicated honeypot hostname (#1509).
        ingress: &[TRAEFIK, PORTBRIDGE],
        ports: &[tcp(8080, 8080)],
        hostnames: &["apex / www / static catch-all"],
    },
    // wordpot exposure removed with its retirement (#2381): its raw
    // 8082/tcp rule went out of vps/docker-compose.yml's RULES and the
    // news.<domain> router out of traefik/dynamic.yml with it.
    SensorExposure {
        sensor: "snare",
        stack: "honeypot-tanner",
        containers: &["hp-snare", "hp-tanner"],
        // Traefik-only: the Meridian portal bait has no raw leg.
        ingress: &[TRAEFIK],
        ports: &[],
        hostnames: &["www-portal.<domain>", "snare.<domain>"],
    },
    SensorExposure {
        sensor: "sentrypeer",
        stack: "honeypot-sentrypeer",
        containers: &["hp-sentrypeer"],
        ingress: &[PORTBRIDGE],
        // Public 5070 → internal 5060 shift: dionaea already owns host 5060.
        ports: &[tcp(5070, 5070), udp(5070, 5070)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "elasticpot",
        stack: "honeypot-elasticpot",
        containers: &["hp-elasticpot"],
        ingress: &[PORTBRIDGE],
        // Own 9201 because multipot's hand-rolled ES decoy owns 9200.
        ports: &[tcp(9201, 9201)],
        hostnames: &[],
    },
    SensorExposure {
        sensor: "canarytokens",
        stack: "honeypot-canarytokens",
        containers: &[
            "hp-canarytokens-frontend",
            "hp-canarytokens-switchboard",
            "hp-canarytokens-http-router",
            "hp-canarytokens-adapter",
        ],
        // Management UI is tunnel-only; the trigger channel is the wildcard
        // *.honeypot.example router (#1487) reaching socat-hp-canarytokens.
        ingress: &[TUNNEL_ONLY, TRAEFIK],
        ports: &[ExposedPort { proto: "tcp", public: 0, host: 19426, proxy: false }],
        hostnames: &["*.honeypot.example (trigger wildcard)"],
    },
];

/// Which raw index family carries each sensor's events. Keys must match
/// EXPOSURE sensors one-to-one; values must appear in RAW_INDEX_NODES.
const SENSOR_RAW_INDEX: &[(&str, &str)] = &[
    ("cowrie", "honeypot-v2-*"),
    ("endlessh", "honeypot-v2-*"),
    ("beelzebub", "honeypot-v2-*"),
    ("mailoney", "honeypot-v2-*"),
    ("dionaea", "honeypot-v2-*"),
    ("multipot", "honeypot-v2-*"),
    ("conpot", "honeypot-v2-*"),
    ("conpot-s7-1200", "honeypot-v2-*"),
    ("conpot-s7-1500", "honeypot-v2-*"),
    ("conpot-iec104", "honeypot-v2-*"),
    ("conpot-guardian", "honeypot-v2-*"),
    ("conpot-kamstrup", "honeypot-v2-*"),
    ("dnp3", "honeypot-v2-*"),
    ("dicompot", "honeypot-v2-*"),
    ("dns-honeypot", "honeypot-v2-*"),
    ("citrix-honeypot", "honeypot-v2-*"),
    ("cisco-asa-honeypot", "honeypot-v2-*"),
    ("sonicwall-sma-honeypot", "honeypot-v2-*"),
    ("rdp-honeypot", "honeypot-v2-*"),
    ("http-honeypot", "honeypot-v2-*"),
    ("api-honeypot", "honeypot-v2-*"),
    ("galah", "honeypot-v2-*"),
    ("hellpot", "honeypot-v2-*"),
    ("snare", "honeypot-v2-*"),
    ("sentrypeer", "honeypot-v2-*"),
    ("elasticpot", "honeypot-v2-*"),
    ("canarytokens", "dashboard-canarytokens-v1"),
];

/// Raw index families the flow graph draws. Everything here is either in
/// es.rs's EVENT_INDICES (what the backend reads) or a specialist family
/// with its own consumer (tty replay, mail views, incident records).
const RAW_INDEX_NODES: &[&str] = &[
    "honeypot-v2-*",
    "suricata-v2-*",
    "portbridge-v2-*",
    "zeek-v1-*",
    "zeek-proxy-v1-*",
    "huginn-v1-*",
    "traefik-v1-*",
    "cowrie-ttylog-v1",
    "dionaea-incidents-v1",
    "mailoney-mail-v1",
    "extracted-files-v1",
];

/// The ingestion artery: every Filebeat-shipped family funnels through one
/// process, which is why source-health's ingest verdict watches it.
const FILEBEAT: &str = "Filebeat";

/// VPS-side producers — they generate events but are not home sensors and
/// have no exposure row. They enter the graph at their raw-index layer.
const VPS_PRODUCERS: &[(&str, &str)] = &[
    // (node label, raw index family)
    ("suricata IDS (VPS)", "suricata-v2-*"),
    ("zeek (VPS)", "zeek-v1-*"),
    ("zeek-proxy (relay side)", "zeek-proxy-v1-*"),
    ("huginn JA4T sidecar", "huginn-v1-*"),
    ("Traefik access log (VPS)", "traefik-v1-*"),
];

/// One derived-intelligence loop: (worker node, reads, writes, surfaces).
type WorkerLoop = (&'static str, &'static [&'static str], &'static [&'static str], &'static [&'static str]);

/// The loops themselves, verbatim from docs/PIPELINES.md §2's loop table.
/// Each derived index really does have exactly one writer (#1960 verified);
/// this table is that claim, executable.
const WORKER_LOOPS: &[WorkerLoop] = &[
    (
        "attacker-identity-worker",
        &["honeypot-v2-*", "ghidra-analysis-v1", "sandbox-analysis-v1", "github-analysis-v1", "cape-analysis-v1", "revdeck-analysis-v1"],
        &["attackers-v1"],
        &["/attackers · overview · graphs"],
    ),
    (
        "correlator-worker",
        &["honeypot-v2-*", "suricata-v2-*"],
        &["campaigns-v1", "attacker-clusters-v1"],
        &["/campaigns", "/clusters · kill-chain"],
    ),
    (
        "agent-intrusion loop",
        &["honeypot-v2-*", "suricata-v2-*"],
        &["agent-intrusion-campaigns"],
        &["/agent-campaigns"],
    ),
    (
        "zeek-proxy-attribution",
        &["zeek-v1-*", "portbridge-v2-*"],
        &["attributed flows (enriched docs)"],
        &["/sessions · /events"],
    ),
    (
        "ml-worker",
        &["suricata-v2-*", "zeek-v1-*"],
        &["ml-anomalies"],
        &["/ml-anomalies"],
    ),
    (
        "llm-worker",
        &["payload stores", "honeypot-v2-*"],
        &["llm-analysis"],
        &["/llm-analysis"],
    ),
    (
        "es-results-importer",
        &["result spools (root-owned)"],
        &["ghidra-analysis-v1", "sandbox-analysis-v1", "github-analysis-v1", "cape-analysis-v1", "revdeck-analysis-v1"],
        &["/payload-workbench/results"],
    ),
    (
        "yara scanner",
        &["payload stores"],
        &["yara-analysis-v1"],
        &["/investigate · charts"],
    ),
    (
        "payload-inventory-worker",
        &["payload stores"],
        &["dashboard-payload-inventory-v1", "dashboard-payload-bytes-v1"],
        &["/payloads · charts"],
    ),
    (
        "alert-notifier loop",
        &["attackers-v1", "campaigns-v1", "agent-intrusion-campaigns"],
        &["dashboard-alert-state-v1"],
        &["/alerts"],
    ),
    (
        "canarytokens-adapter",
        // Reads the sensor's trigger channel (HTTP switchboard), not a log
        // file — the one sensor whose events skip Filebeat entirely.
        &["canarytokens"],
        &["dashboard-canarytokens-v1"],
        &["/canarytokens · settings pane"],
    ),
    (
        "reporter",
        &["dashboard state (backend indices)"],
        &["reporter-metrics-v1"],
        &["/settings stats"],
    ),
];

/// Payload capture feeds the analysis workers too (PIPELINES.md §3); the
/// stores node is fed by the capturing sensors explicitly below.
const PAYLOAD_STORES: &str = "payload stores";

/// Elasticsearch's own reject path — documents Filebeat shipped fine but
/// the ingest pipeline could not index land here, not in filebeat-*.
const DEAD_LETTERS: (&str, &str, &str) = ("ES non-indexable policy", "dead-letter-honeypot", "/dead-letters");

/// Stack → container membership for the runtime section, transcribed from
/// the arcane/home/*/compose.yml `container_name:` declarations. Containers
/// absent from services-adapter's ALLOWED_CONTAINERS get `adapter: false`
/// so the UI can say "no live state" instead of implying "stopped".
const STACK_CONTAINERS: &[(&str, &[&str])] = &[
    ("honeypot-cowrie", &["hp-cowrie", "hp-honeyfs-implant"]),
    ("honeypot-endlessh", &["hp-endlessh"]),
    ("honeypot-beelzebub", &["hp-beelzebub"]),
    ("honeypot-mailoney", &["hp-mailoney"]),
    ("honeypot-dionaea", &["hp-dionaea", "hp-tftp-relay"]),
    ("honeypot-multipot", &["hp-multipot"]),
    ("honeypot-conpot", &["hp-conpot", "hp-conpot-s7-1200", "hp-conpot-s7-1500", "hp-conpot-iec104", "hp-conpot-guardian", "hp-conpot-kamstrup"]),
    ("honeypot-dnp3", &["hp-dnp3"]),
    ("honeypot-dicompot", &["hp-dicompot"]),
    ("honeypot-dns-honeypot", &["hp-dns-honeypot"]),
    ("honeypot-citrix-honeypot", &["hp-citrix-honeypot"]),
    ("honeypot-cisco-asa-honeypot", &["hp-cisco-asa-honeypot"]),
    ("honeypot-sonicwall-sma", &["hp-sonicwall-sma-honeypot"]),
    ("honeypot-rdp-honeypot", &["hp-rdp-honeypot"]),
    ("honeypot-http", &["hp-http", "hp-api-honeypot"]),
    ("honeypot-galah", &["hp-galah", "hp-galah-llm-broker"]),
    ("honeypot-hellpot", &["hp-hellpot"]),
    // honeypot-wordpot's stack entry left with its retirement (#2381).
    ("honeypot-tanner", &["hp-snare", "hp-tanner", "hp-tanner-api", "hp-tanner-web", "hp-tanner-redis", "hp-tanner-phpox", "hp-tanner-docker"]),
    ("honeypot-sentrypeer", &["hp-sentrypeer"]),
    ("honeypot-elasticpot", &["hp-elasticpot"]),
    ("honeypot-canarytokens", &["hp-canarytokens-frontend", "hp-canarytokens-switchboard", "hp-canarytokens-http-router", "hp-canarytokens-redis", "hp-canarytokens-adapter"]),
    ("honeypot-elk", &["hp-elasticsearch", "hp-kibana", "hp-filebeat", "hp-evebox", "hp-pcap-sync", "hp-arkime-capture", "hp-arkime-viewer", "hp-extracted-file-importer", "hp-zeek-proxy"]),
    ("honeypot-payload-analysis", &["hp-payload-dedupe", "hp-yara-scanner"]),
    ("honeypot-utilities", &["hp-log-maintenance", "hp-docker-socket-proxy", "hp-disk-space-monitor", "hp-autoheal", "hp-docker-hygiene", "hp-reporter"]),
    ("honeypot-keycloak", &["hp-keycloak-postgres", "hp-keycloak"]),
    ("honeypot-dashboard", &["hp-dashboard-next", "hp-apiary-backend-mounted", "hp-dashboard-oidc-sessions"]),
    // #3575: the sensor-bound workers and the local services adapter, as their
    // own homeserver project (GHCR image by digest).
    ("honeypot-backend-workers", &["hp-apiary-worker", "hp-apiary-worker-importer", "hp-apiary-worker-enrichment", "hp-apiary-worker-payload-inventory", "hp-services-adapter"]),
    // The standalone rewrite dashboard (Xore-Inc/apiary-dashboard).
    ("apiary-dashboard", &["hp-apiary-dashboard", "hp-apiary-dashboard-oidc-sessions"]),
    ("honeypot-dashboard-backend", &["hp-apiary-backend"]),
    ("honeypot-attacker-identity-worker", &["hp-attacker-identity-worker"]),
    ("honeypot-correlator-worker", &["hp-correlator-worker"]),
    ("honeypot-agent-intrusion-worker", &["hp-agent-intrusion-worker"]),
    ("honeypot-payload-inventory-worker", &["hp-payload-inventory-worker"]),
    // Deployed from the repo-root ml-worker/ and llm-worker/ stacks, not
    // under arcane/home — same fleet, different checkout.
    ("ml-worker", &["hp-ml-worker"]),
    ("llm-worker", &["hp-llm-worker"]),
    // The Ghidra tier lives outside Dockge entirely (deploy.yml rsync target,
    // /opt/stacks/apiary); compose-project naming gives it the ghidra-* names.
    (
        "ghidra tier",
        &["ghidra-ghidra-1", "ghidra-ollama-1", "ghidra-statictools-1", "ghidra-revdeck-1"],
    ),
];

/// Containers services-adapter's ALLOWED_CONTAINERS will report state for —
/// mirrored here so the runtime section can distinguish "stopped" from
/// "not observable". If the adapter's allowlist grows, grow this set with
/// it; the test below fails when the two drift apart.
const ADAPTER_VISIBLE: &[&str] = &[
    "hp-cowrie",
    "hp-multipot",
    "hp-http",
    "hp-api-honeypot",
    "hp-dionaea",
    "hp-tftp-relay",
    "hp-dnp3",
    "hp-dicompot",
    "hp-dns-honeypot",
    "hp-citrix-honeypot",
    "hp-cisco-asa-honeypot",
    "hp-sonicwall-sma-honeypot",
    "hp-rdp-honeypot",
    "hp-snare",
    "hp-tanner",
    "hp-tanner-api",
    "hp-tanner-web",
    "hp-tanner-redis",
    "hp-tanner-phpox",
    "hp-tanner-docker",
    "hp-conpot",
    "hp-conpot-s7-1200",
    "hp-conpot-s7-1500",
    "hp-conpot-iec104",
    "hp-conpot-guardian",
    "hp-conpot-kamstrup",
    "hp-yara-scanner",
    "hp-payload-dedupe",
    "hp-pcap-sync",
    "hp-arkime-capture",
    "hp-arkime-viewer",
    "hp-ml-worker",
    "hp-llm-worker",
    "ghidra-ghidra-1",
    "ghidra-ollama-1",
    "ghidra-statictools-1",
    "ghidra-revdeck-1",
    // Post-#1418 sensor stacks, allowlisted in #2089 -- kept identical to
    // services-adapter's ALLOWED_CONTAINERS.
    "hp-beelzebub",
    "hp-hellpot",
    // hp-wordpot mirrored the adapter allowlist until #2381 retired it.
    "hp-mailoney",
    "hp-galah",
    "hp-galah-llm-broker",
    "hp-sentrypeer",
    "hp-elasticpot",
    "hp-endlessh",
    "hp-honeyfs-implant",
    "hp-zeek-proxy",
    "hp-canarytokens-redis",
    "hp-canarytokens-frontend",
    "hp-canarytokens-switchboard",
    "hp-canarytokens-http-router",
    "hp-canarytokens-adapter",
];

// --- Response shapes -------------------------------------------------------

#[derive(Serialize)]
pub struct TopologyResponse {
    generated_at: String,
    sensors: Vec<SensorRow>,
    flow: FlowGraph,
    stacks: Vec<StackRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SensorRow {
    sensor: &'static str,
    stack: &'static str,
    containers: &'static [&'static str],
    ingress: &'static [&'static str],
    hostnames: &'static [&'static str],
    ports: &'static [ExposedPort],
    raw_index: &'static str,
}

#[derive(Serialize)]
pub struct FlowGraph {
    nodes: Vec<FlowNode>,
    links: Vec<FlowLink>,
}

#[derive(Serialize)]
pub struct FlowNode {
    name: String,
    layer: u8,
}

#[derive(Serialize)]
pub struct FlowLink {
    source: String,
    target: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackRow {
    stack: &'static str,
    containers: Vec<ContainerRef>,
}

#[derive(Serialize)]
pub struct ContainerRef {
    name: &'static str,
    adapter_visible: bool,
}

// --- Handler ---------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/topology",
    summary = "Decoy topology graph.",
    responses(
        (status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"),
    ),
    security(("serviceToken" = [])),
)]
/// GET /api/v1/topology — static fleet shape; liveness joins live elsewhere.
pub async fn topology() -> Json<TopologyResponse> {
    let raw_index_of: HashMap<&str, &str> = SENSOR_RAW_INDEX.iter().copied().collect();

    let sensors = EXPOSURE
        .iter()
        .map(|s| SensorRow {
            sensor: s.sensor,
            stack: s.stack,
            containers: s.containers,
            ingress: s.ingress,
            hostnames: s.hostnames,
            ports: s.ports,
            raw_index: raw_index_of.get(s.sensor).copied().unwrap_or("unmapped"),
        })
        .collect();

    let stacks = STACK_CONTAINERS
        .iter()
        .map(|(stack, containers)| StackRow {
            stack,
            containers: containers
                .iter()
                .map(|name| ContainerRef { name, adapter_visible: ADAPTER_VISIBLE.contains(name) })
                .collect(),
        })
        .collect();

    Json(TopologyResponse { generated_at: Utc::now().to_rfc3339(), sensors, flow: flow_graph(), stacks })
}

/// The layered DAG, assembled once per request from the tables above —
/// cheap enough not to cache and always consistent with them. Every node is
/// declared before any link is emitted, so an undeclared endpoint can never
/// reach the JSON (the well-formedness test holds this invariant anyway).
fn flow_graph() -> FlowGraph {
    let mut nodes: Vec<FlowNode> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    fn declare(nodes: &mut Vec<FlowNode>, seen: &mut HashSet<String>, name: &str, layer: u8) {
        if seen.insert(name.to_string()) {
            nodes.push(FlowNode { name: name.to_string(), layer });
        }
    }

    // Layer 0: the three ways in (docs/NETWORK.md's ingress split).
    for ingress in ["VPS Traefik (:443 hostnames)", "VPS portbridge (raw ports)", "WireGuard tunnel only"] {
        declare(&mut nodes, &mut seen, ingress, 0);
    }
    // Layer 1: home sensors and VPS producers.
    for s in EXPOSURE {
        declare(&mut nodes, &mut seen, s.sensor, 1);
    }
    for (label, _) in VPS_PRODUCERS {
        declare(&mut nodes, &mut seen, label, 1);
    }
    declare(&mut nodes, &mut seen, "portbridge conn-log (VPS)", 1);
    // Layers 2-3: the shipper, payload stores at rest, and raw families.
    declare(&mut nodes, &mut seen, FILEBEAT, 2);
    declare(&mut nodes, &mut seen, PAYLOAD_STORES, 2);
    declare(&mut nodes, &mut seen, "result spools (root-owned)", 3);
    declare(&mut nodes, &mut seen, "dashboard state (backend indices)", 3);
    for family in RAW_INDEX_NODES {
        declare(&mut nodes, &mut seen, family, 3);
    }
    declare(&mut nodes, &mut seen, "dashboard-canarytokens-v1", 5);
    // Layers 4-6: workers, what they write, where it is presented.
    for (worker, _, writes, surfaces) in WORKER_LOOPS {
        declare(&mut nodes, &mut seen, worker, 4);
        for written in *writes {
            declare(&mut nodes, &mut seen, written, 5);
        }
        for surface in *surfaces {
            declare(&mut nodes, &mut seen, surface, 6);
        }
    }
    let (dl_worker, dl_index, dl_page) = DEAD_LETTERS;
    declare(&mut nodes, &mut seen, dl_worker, 4);
    declare(&mut nodes, &mut seen, dl_index, 5);
    declare(&mut nodes, &mut seen, dl_page, 6);

    let s = |name: &str| name.to_string();
    let mut links: Vec<FlowLink> = Vec::new();

    // Ingress → sensor, one edge per path a sensor is reachable by.
    for exposure in EXPOSURE {
        for via in exposure.ingress {
            let via_label = match *via {
                TRAEFIK => "VPS Traefik (:443 hostnames)",
                PORTBRIDGE => "VPS portbridge (raw ports)",
                _ => "WireGuard tunnel only",
            };
            links.push(FlowLink { source: s(via_label), target: s(exposure.sensor) });
        }
    }
    // The portbridge conn-log observes the raw-forwarding ingress itself;
    // every forwarded connection is exactly what it records.
    links.push(FlowLink { source: s("VPS portbridge (raw ports)"), target: s("portbridge conn-log (VPS)") });

    // Sensors → Filebeat, except the trigger-channel sensor that skips it.
    for exposure in EXPOSURE.iter().filter(|e| e.sensor != "canarytokens") {
        links.push(FlowLink { source: s(exposure.sensor), target: s(FILEBEAT) });
    }
    // Captures bypass the log path entirely: content lands on disk stores.
    for captor in ["cowrie", "dionaea"] {
        links.push(FlowLink { source: s(captor), target: s(PAYLOAD_STORES) });
    }
    // VPS producers ride the same sshfs → Filebeat artery.
    for (label, _) in VPS_PRODUCERS {
        links.push(FlowLink { source: s(label), target: s(FILEBEAT) });
    }
    // Filebeat → every raw family it ships.
    for family in RAW_INDEX_NODES {
        links.push(FlowLink { source: s(FILEBEAT), target: s(family) });
    }

    // Workers read their inputs and write their outputs; each surface hangs
    // off the outputs that present it.
    for (worker, reads, writes, surfaces) in WORKER_LOOPS {
        for read in *reads {
            links.push(FlowLink { source: s(read), target: s(worker) });
        }
        for written in *writes {
            links.push(FlowLink { source: s(worker), target: s(written) });
        }
        for surface in *surfaces {
            for written in *writes {
                links.push(FlowLink { source: s(written), target: s(surface) });
            }
        }
    }

    // Analysis verdicts flow back into attacker identities (the union of
    // observed behavior + analysis verdicts) — a backward edge, still acyclic.
    for verdict in ["ghidra-analysis-v1", "sandbox-analysis-v1", "github-analysis-v1", "cape-analysis-v1", "revdeck-analysis-v1"] {
        links.push(FlowLink { source: s(verdict), target: s("attacker-identity-worker") });
    }

    // Dead letters: ES rejects after Filebeat succeeded — a separate failure
    // layer from filebeat-* decode failures (source-health's note).
    let (dl_worker, dl_index, dl_page) = DEAD_LETTERS;
    links.push(FlowLink { source: s("honeypot-v2-*"), target: s(dl_worker) });
    links.push(FlowLink { source: s(dl_worker), target: s(dl_index) });
    links.push(FlowLink { source: s(dl_index), target: s(dl_page) });

    FlowGraph { nodes, links }
}

// --- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only read contract: which raw families the backend reads.
    use crate::es::EVENT_INDICES;

    /// Parse the portbridge RULES line straight out of the VPS compose file.
    /// Format (vps/portbridge/main.go parseRules): proto:public:host-ip:port[:pp].
    fn compose_rules() -> Vec<(String, u16, u16, bool)> {
        let compose = include_str!("../../../../../vps/docker-compose.yml");
        let line = compose
            .lines()
            .find(|l| l.trim_start().starts_with("- \"RULES="))
            .expect("vps/docker-compose.yml must keep a RULES= line");
        let body = line.split("RULES=").nth(1).unwrap().trim_end_matches('"');
        body
            .split_whitespace()
            .map(|rule| {
                let parts: Vec<&str> = rule.split(':').collect();
                let proxy = parts.last().map(|p| *p == "pp").unwrap_or(false);
                let main_parts = if proxy { &parts[..parts.len() - 1] } else { &parts[..] };
                assert!(main_parts.len() == 4, "unexpected rule shape {rule}");
                (
                    main_parts[0].to_string(),
                    main_parts[1].parse::<u16>().expect("public port"),
                    main_parts[3].parse::<u16>().expect("home port"),
                    proxy,
                )
            })
            .collect()
    }

    fn claimed_rules() -> Vec<(String, u16, u16, bool)> {
        EXPOSURE
            .iter()
            .flat_map(|s| s.ports.iter())
            .filter(|p| p.public > 0)
            .map(|p| (p.proto.to_string(), p.public, p.host, p.proxy))
            .collect()
    }

    /// THE drift guard: every portbridge forwarding rule in the VPS compose
    /// is claimed by exactly one exposure row, and none are invented. A
    /// compose edit without a topology edit fails here, not silently on the
    /// new page.
    #[test]
    fn compose_rules_are_fully_claimed() {
        let mut actual = compose_rules();
        let mut claimed = claimed_rules();
        actual.sort();
        claimed.sort();
        assert_eq!(actual, claimed, "EXPOSURE ports and vps/docker-compose.yml RULES diverged");
    }

    /// Tunnel-only ports (public == 0) must never accidentally claim a
    /// compose rule — those are managed, not exposed.
    #[test]
    fn tunnel_only_ports_stay_unpublished() {
        let rules = compose_rules();
        for p in EXPOSURE.iter().flat_map(|s| s.ports.iter()).filter(|p| p.public == 0) {
            assert!(
                !rules.iter().any(|(proto, public, _host, _proxy)| *public == p.host && proto == p.proto),
                "{}:{} leaked into RULES",
                p.proto,
                p.host
            );
        }
    }

    /// Exposure rows and pipeline rows describe the same sensor set.
    #[test]
    fn every_sensor_has_a_pipeline_row_and_vice_versa() {
        let exposed: HashSet<&str> = EXPOSURE.iter().map(|s| s.sensor).collect();
        let pipelined: HashSet<&str> = SENSOR_RAW_INDEX.iter().map(|(s, _)| *s).collect();
        assert_eq!(exposed, pipelined);
    }

    /// Raw families named anywhere in the pipeline tables are known — either
    /// part of the read contract (EVENT_INDICES), a specialist family with
    /// its own consumer, or the adapter-written index canarytokens feeds
    /// directly (the one deliberate Filebeat bypass).
    #[test]
    fn raw_index_names_are_known_families() {
        let known: HashSet<&str> = EVENT_INDICES
            .iter()
            .chain(RAW_INDEX_NODES.iter())
            .chain(std::iter::once(&"dashboard-canarytokens-v1"))
            .copied()
            .collect();
        for (_, family) in SENSOR_RAW_INDEX {
            assert!(known.contains(family), "{family} is not a known raw family");
        }
        for (_, family) in VPS_PRODUCERS {
            assert!(known.contains(family));
        }
    }

    /// Each derived index keeps exactly one writer — the PIPELINES.md §4
    /// invariant, checked against the worker-loop table itself.
    #[test]
    fn every_derived_index_has_exactly_one_writer() {
        let mut writers: Vec<&str> = WORKER_LOOPS.iter().flat_map(|(_, _, w, _)| w.iter()).copied().collect();
        writers.sort();
        let count = writers.len();
        writers.dedup();
        assert_eq!(count, writers.len(), "a derived index gained a second writer: {writers:?}");
    }

    /// The runtime section's stack grouping is lossless and unique — every
    /// container appears once, and nothing the adapter can see is missing.
    #[test]
    fn stack_containers_are_unique_and_cover_the_adapter_allowlist() {
        let mut all: Vec<&str> = STACK_CONTAINERS.iter().flat_map(|(_, c)| c.iter()).copied().collect();
        let count = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(count, all.len(), "container listed under two stacks");
        for visible in ADAPTER_VISIBLE {
            assert!(
                STACK_CONTAINERS.iter().any(|(_, c)| c.contains(visible)),
                "adapter-visible {visible} belongs to no known stack"
            );
        }
    }

    /// The flow graph is a well-formed DAG: unique nodes, links only between
    /// declared nodes, and no cycles (ECharts sankey renders cycles as a
    /// blank chart rather than an error, so check it here instead).
    #[test]
    fn flow_graph_is_well_formed_and_acyclic() {
        let graph = flow_graph();
        let names: HashSet<&str> = graph.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names.len(), graph.nodes.len(), "duplicate flow node");
        for link in &graph.links {
            assert!(names.contains(link.source.as_str()), "link source {} undeclared", link.source);
            assert!(names.contains(link.target.as_str()), "link target {} undeclared", link.target);
        }
        // Kahn's algorithm over the link list; leftover nodes mean a cycle.
        let mut indegree: HashMap<&str, usize> = names.iter().map(|n| (*n, 0)).collect();
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for link in &graph.links {
            *indegree.get_mut(link.target.as_str()).unwrap() += 1;
            adjacency.entry(link.source.as_str()).or_default().push(link.target.as_str());
        }
        let mut queue: Vec<&str> = indegree.iter().filter(|(_, d)| **d == 0).map(|(n, _)| *n).collect();
        let mut visited = 0usize;
        while let Some(n) = queue.pop() {
            visited += 1;
            for next in adjacency.get(n).into_iter().flatten() {
                let d = indegree.get_mut(next).unwrap();
                *d -= 1;
                if *d == 0 {
                    queue.push(next);
                }
            }
        }
        assert_eq!(visited, names.len(), "flow graph has a cycle");
    }
}
