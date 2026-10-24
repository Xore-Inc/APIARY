# Sensors

[← back to README](../README.md)

| Sensor | Ports | Exposed via | Notes |
|---|---|---|---|
| **cowrie** | SSH 22, Telnet 23 | raw tunnel | seeded NexusAI Ubuntu GPU node ([cowrie/README-fs.md](../arcane/home/honeypot-cowrie/cowrie/README-fs.md)) |
| **multipot** | Postgres 5432, VNC 5900, Redis 6379, ES 9200, Docker 2375, POP3 110, IMAP 143, SOCKS5 1080, HL7/MLLP 2575, ADB 5555 | raw tunnel | light Go multi-protocol sensor — dashboard reads its events from Elasticsearch, not its log file (#403) |
| **dionaea** | FTP 21, TFTP 69/udp, MSRPC 135, SMB 445, MSSQL 1433, PPTP 1723, MQTT 1883, UPnP 1900/udp, MySQL 3306, SIP 5060 tcp/udp, printer 9100, Memcached 11211, Mongo 27017 | raw tunnel | broad legacy/IoT attack surface + **malware capture** |
| **conpot** | S7 102, Modbus 502, SNMP 161/udp, BACnet 47808/udp, IPMI 623/udp, ENIP 44818 | raw tunnel | **ICS/SCADA** (Siemens S7-200) |
| **conpot-s7-1200** | S7 1102, Modbus 1502 | raw tunnel | S7-1215C water-treatment persona |
| **conpot-s7-1500** | S7 2102, Modbus 2502 | raw tunnel | S7-1516 chemical-process persona |
| **conpot-iec104** | IEC-104 2404 | raw tunnel | S7-300 substation / IEC-60870-5-104 |
| **conpot-guardian** | Guardian AST 10001 | raw tunnel | fuel and tank-monitor attack surface |
| **conpot-kamstrup** | Kamstrup 1025, 50100 | raw tunnel | smart-meter data and management protocols |
| **dnp3** | DNP3 20000 | raw tunnel | ElbeGrid substation RTU -- decodes the link-layer function code plus, when the frame carries a transport+application-layer segment, the application-layer function code too (READ/WRITE/SELECT/OPERATE/DIRECT_OPERATE/etc., #610); the full frame is always captured as `frame_hex` regardless |
| **dicompot** | DICOM 11112 | raw tunnel + PROXY | vendored `nsmfoo/dicompot` medical-imaging decoy (C-ECHO/C-FIND/C-MOVE/C-GET/C-STORE) — ES-only from day one (#238, #413). #3155 sensor-fidelity audit (tier 3b) found 5 fingerprint tells; the wrapper (`arcane/home/honeypot-dicompot/dicompot/aetitle.go`) closes 3 of them below `RunProviderForConn` without forking upstream: the A-ASSOCIATE-AC now carries an Implementation Class UID/Version Name (tell 1), Max PDU Length in the AC is a fixed 16384 persona constant (never echoed from the SCU's proposal) instead of a hardcoded 4194304 (tell 3), and an unrecognized Called AE Title gets a real A-ASSOCIATE-RJ instead of a silent close (tell 4); a first PDU that isn't a well-formed A-ASSOCIATE-RQ now gets a real A-ABORT instead of falling through to a silent close. Tells 2 (any SOP Class UID accepted, including invalid ones) and 5 (C-FIND/C-MOVE/C-GET always return success) live inside the vendored library's own DIMSE handling, so the wrapper alone cannot reach them — #3179 therefore forks the dependency the way honeypot-cowrie patches `txtcmds`: a build-time patch program (`arcane/home/honeypot-dicompot/dicompot/dimse_status_patch/`) rewrites a writable copy of the pinned module inside the image build and `go mod edit -replace` points the build at that copy, leaving the committed `go.mod`/`go.sum` on the pristine pin. The A-ASSOCIATE-AC now answers result 3 (abstract syntax not supported) for a malformed or unknown Abstract Syntax UID, and a C-FIND/C-MOVE/C-GET whose query the decoy cannot serve answers 0xA702/0xA701 instead of unconditional success — while a supported SOP Class still negotiates and a valid C-FIND still returns 0x0000. Because the anchors are exact byte matches, a pin bump that moves the patched code fails the image build rather than silently shipping unpatched. That closes the remaining two, so all five #3155 tells are now closed in this decoy |
| **dns-honeypot** | DNS 53/udp | raw tunnel | from-scratch UDP reflection bait, response capped in code to at most 1.5x request size — never contacts a real resolver, so it cannot be abused as a DDoS amplification vector — ES-only from day one (#238, #415) |
| **citrix-honeypot** | raw 4443 (→ container 443) | raw tunnel + PROXY | Citrix ADC/NetScaler Gateway decoy (CVE-2019-19781 path traversal), Go port of `t3chn0m4g3/CitrixHoneypot`, own self-signed TLS — ES-only from day one (#238, #414) |
| **cisco-asa-honeypot** | WebVPN 8443, IKE 500/udp | raw tunnel + PROXY (8443) | Cisco ASA WebVPN + IKE decoy (CVE-2018-0101), Go port of `t3chn0m4g3/ciscoasa_honeypot` — the IKE side replies once per source with a real Diffie-Hellman/nonce exchange then goes silent, matching upstream's actual (not fully protocol-correct) behavior exactly — ES-only from day one (#238, #414). This is the ASA firewall persona and it stays that way: Cisco Secure FMC is a different product, and no FMC persona exists in this stack — the requirements any optional one would have to meet, and why the build is undecided, are recorded in [research/3214-fmc-inert-persona.md](research/3214-fmc-inert-persona.md) |
| **sonicwall-sma-honeypot** | raw 8543 (→ container 8443) | raw tunnel + PROXY | SonicWall SMA1000 Work Place/AMC decoy for the CVE-2026-83548 Work Place SSRF / CVE-2026-83549 AMC OS command injection chain — Work Place login page, `/cgi-bin/...` classified as the stage-one SSRF probe with a fixed non-attacker-steerable relay hop to `api-honeypot`'s cloud-metadata surface, synthetic AMC hop page whose own action route classifies the stage-two payload — no Suricata rule yet, no public PoC/vendor IOC gives a literal shape (#3033) |
| **rdp-honeypot** | RDP 3389 | raw tunnel + PROXY | RDP decoy, Go port of `CommunityHoneyNetwork/rdphoney` — reads the initial X.224 Connection Request, captures the `mstshash=` cookie username if present and the client's requested security protocols (plain RDP / TLS / CredSSP / RDSTLS / CredSSP-EarlyUserAuth) from the trailing `RDP_NEG_REQ` structure — ES-only from day one (#238, #412) |
| **http-honeypot** | `decoy.<domain>` (+ catch-all, + raw :8081 with PROXY protocol — portbridge rule carries the `pp` flag, same as citrix/cisco/rdp/dicom) | Traefik | fake nginx / login pages — unrecognized scan/rce-probe paths get a HellPot-style Markov-garbage tarpit instead of a fast reply by default (`HTTP_TARPIT=0` to disable, #246) |
| **api-honeypot** | raw 8888 | raw tunnel + PROXY | cloud metadata, Kubernetes, registry, DevOps and LLM API probes — same binary as http-honeypot, same tarpit behavior |
| **snare + tanner** | `www-portal.<domain>` | Traefik | fictional Meridian portal → payload analysis |
| **endlessh** | SSH 19024 (own port, not cowrie's) | raw tunnel + PROXY, public **2022** (#1509 -- not 2222, which is this VPS's own real sshd, confirmed live before picking a port) | SSH pre-auth tarpit, Go port of `skeeto/endlessh`'s core trick — sends random non-"SSH-" banner lines forever, real handshake never begins. Own port deliberately, not cowrie's: diverting an attacker here instead of cowrie's real fake-shell capture would trade depth for a cheap time-waste (#246) |
| **beelzebub** | SSH 2200 (2nd, LLM-capable listener, static-only here), LDAP 389, MCP 8000, HTTP 8880 | raw tunnel | vendored `beelzebub-labs/beelzebub` deception runtime (#1418) -- LDAP/MCP fill real protocol gaps, SSH is a second differently-fingerprinted listener alongside Cowrie, HTTP is a WordPress decoy; no Ollama wiring (would cross the `honeypot-llm` network's sensors-never-reach-the-model boundary, see arcane/home/honeypot-beelzebub/compose.yml) and no Traefik hostname (beelzebub can't parse PROXY protocol or read X-Forwarded-For, so a hostname-fronted copy would have an unattributable source IP) -- ES-only from day one |
| **hellpot** | HTTP 8080 | raw tunnel + Traefik (`www`/bare-domain/`static`, #1509 -- deliberately routed here, replacing a long-dead `socat-static` bridge; no *dedicated* honeypot hostname, this piggybacks the top-level domain's catch-all instead) | vendored `yunginnanet/HellPot` bot tarpit (#1419) -- streams endless Markov-chain garbage to any request, punishing scanners/scrapers rather than just logging them; upstream's own X-Real-IP trust is unconditional and client-spoofable -- confirmed live -- so `hellpot/router_patch.py` removes it and this stack resolves the real IP via `ip-enrichment-worker`'s via_port join instead (raw-tunnel path) or Traefik's XFF (Traefik-routed path), same as beelzebub/http-honeypot -- ES-only from day one |
| **elasticpot** | HTTP 9201 (own port -- multipot's own hand-rolled Elasticsearch decoy already owns 9200, see arcane/home/honeypot-elasticpot/compose.yml) | raw tunnel | vendored `gitlab.com/bontchev/elasticpot` (#1423), a second, deliberately distinct Elasticsearch decoy (own persona/asset_id, own container name, own port -- see arcane/home/honeypot-elasticpot/compose.yml's naming-care note; multipot's pre-existing 9200 decoy is itself self-written, flagged as a separate follow-up decision rather than replaced here); patched (`elasticpot/no_egress_patch.py`) to stop an unconditional startup call to `https://ident.me` that crashed the process outright when outbound internet wasn't reachable -- ES-only from day one |
| **galah** | HTTP 8888 (home), public 8889, plus Traefik `hub.<domain>` (#1511 -- galah's raw port isn't on Cloudflare's proxied non-standard-port allowlist, confirmed live unreachable through the domain otherwise) | raw tunnel + Traefik | vendored `0x4d31/galah` LLM-powered HTTP honeypot (#1420) -- generates a realistic fake response to any request via the shared Ollama instance, reached only through `galah-llm-broker`, a small purpose-built reverse proxy that's the sole bridge onto `honeypot-llm` for this sensor (galah's own container never joins that network, same invariant beelzebub's static-only choice preserved); model `qwen2.5:7b-instruct-q4_K_M`, not any already-pulled Qwen3/3.5 model -- galah's vendored LLM client has no way to send Ollama's `think: false` field, and a live test showed Qwen3.5's thinking mode running for 90s+ without stopping. `timeout_patch.py` raises galah's own hardcoded 10s response deadline to 100s and `galah-llm-broker`'s `UPSTREAM_TIMEOUT_SECONDS` to 90 (#1513) -- a cold-loaded model (Ollama's default 5-minute idle unload, the normal case for a honeypot) measured 15.1s of load_duration alone in one live sample and over 40s in a second sample under real GPU contention, comfortably past the original 8-10s ceiling and the actual cause of every real hit returning HTTP 500 instead of a decoy response; the new timeouts are set with real margin past either observed sample, not just the first. `xff_trust_patch.py` (#1511) trusts `X-Forwarded-For` from the WireGuard tunnel peer only, needed now that galah is reachable both raw-port (via_port resolution, unchanged) and Traefik-routed (XFF resolution, new) -- ES-only from day one |
| **sentrypeer** | SIP 5070 (public), 5060 internally -- a port shift, not a collision: dionaea already binds host 5060 for its own generic SIP banner-grab, sentrypeer's own listener is hardcoded to 5060 internally with no config option | raw tunnel | vendored `SentryPeer/SentryPeer` SIP/VoIP fraud-detection honeypot (#1424) -- real SIP protocol parsing (osip2), not a banner-grab; `sentrypeer/nul_byte_crash_patch.py` fixes a real, confirmed-live crash where any packet with an embedded NUL byte panicked the SIP listener thread; peer-to-peer bad-actor sharing and its RESTful API both left disabled (same no-third-party-sharing call as `docs/community-threat-intel-sharing.md`); no Traefik hostname (SIP has no HTTP-style header a proxy could set) -- ES-only from day one |
| **mailoney** | SMTP 25 | raw tunnel | vendored `awhitehatter/mailoney` (#1422), takes over port 25 from multipot's own retired self-written SMTP handler -- real DATA/message-body capture (multipot's handler never had this), EHLO/AUTH PLAIN credential capture. Upstream persists sessions to a SQLAlchemy DB only, no JSON log of its own; `mailoney/json_log_patch.py` adds a flat per-event JSON-line sink matching this stack's convention, and fixes a real found-live bug along the way -- upstream lowercases the whole request line (including the AUTH PLAIN base64 payload) before decoding it, silently corrupting any captured credential with an uppercase letter -- ES-only from day one |
| **canarytokens** | management UI/API 19426 (WireGuard-tunnel only); HTTP-channel 19427 also public via VPS Traefik `HostRegexp(\`^[a-z0-9]+\.honeypot\.example$\`)` (a wildcard on the bare apex, not a fixed Host()) -> `socat-hp-canarytokens` (#1487) | internal, `canarytokens-adapter`'s own webhook | self-hosted `thinkst/canarytokens` (#1426), a different deception *category* -- planted honeytokens (documents, URLs, DNS names, credentials) that alert the instant something touches them, not a listening decoy protocol. Token creation IS scriptable despite the #1415 research pass's premise: a real `POST` endpoint exists at a deliberately non-guessable path (`frontend/app.py`'s `ROOT_API_ENDPOINT`, an anti-scraping measure -- not `/api/generate`, confirmed live by actually calling it, not by reading the OpenAPI schema alone). #1487 uses it: the dashboard's Settings > Canarytokens pane creates PDF/Word/Excel/custom-image/Windows-Folder/QR tokens on demand for external use (planted anywhere outside this honeypot, not just its own personas), and the operator downloads the resulting artifact. `canarydrop.generate_random_hostname()` prepends each token's own random value as a subdomain of `CANARY_PUBLIC_HOSTNAME` -- the wildcard match (not a dedicated `cdn`/`canary`/`token*` subdomain) is what a wildcard-cert-covered domain and an actual, previously-unknown-at-DNS-time random label both require; see `docs/CGNAT-DEPLOYMENT.md`'s DNS section. `#1427`'s cross-honeypot breadcrumbs (baked into persona files at deploy time) remain a separate, still-internal-only use of the same platform. Which token types have actually been observed firing end to end -- and how to repeat the observation -- is tracked manually in [`docs/canarytoken-live-fire-checklist.md`](canarytoken-live-fire-checklist.md) (#2848). |
| **suricata** | (sniffs all traffic, runs on the **VPS**) | — | IDS over every honeypot packet → eve.json → ELK, pcap → Arkime |

multipot cedes FTP/MySQL/MSSQL/Mongo to Dionaea, and SMTP to mailoney, automatically
(`MULTIPOT_DISABLE`), so ports never clash.

Dionaea enables `log_json`, `log_incident`, and `store` at startup. Connection
summaries go to `logs/dionaea/dionaea.json`, complete incident records go to
`logs/dionaea/dionaea_incident.json`, and captured payloads are stored by hash
in the persistent `dionaea-lib` volume for the dashboard's `/payloads` page.
Cowrie's hash-addressed upload/download directory is persisted under
`logs/cowrie/downloads`, so script payloads (shell, PowerShell, VBS, Python,
JavaScript, PHP, Perl, and arbitrary binaries) survive container recreation.
Inline script commands are additionally retained as inert SHA-256 artifacts in
the dashboard state volume. The dashboard `/payloads` page inventories all
three stores recursively, identifies each contributing source, and offers
per-source filters while deduplicating identical hash-addressed artifacts.
Captured content is never executed.
The `payload-dedupe` service scans these stores hourly and atomically replaces
same-filesystem duplicates with hard links. Existing event/download URLs remain
valid while duplicate disk blocks are reclaimed; its last-run report is stored
at `state/dedupe/payload-dedupe.json`.
Neither service produces per-event chatter: `payload-dedupe` prints a single
JSON result line per pass, and `log-maintenance` writes one stderr line per
rotation. The `log-maintenance` sidecar copy-truncates and gzips
human-readable Dionaea, Conpot, and Cowrie logs at 256 MiB (four archives).
Structured JSON event streams are deliberately never rotated by that sidecar,
which preserves Filebeat offsets and dashboard ingestion.
Because RFC 1350 TFTP switches to a dynamic transfer-ID port, the internal
`tftp-relay` keeps public UDP 69 stable while forwarding that exchange to
Dionaea inside `honeynet`; it is infrastructure and is not shown as a sensor.

## Evidence that is not a sensor

One source is deliberately **not** in the table above, because it is not a
decoy and does not pretend to be one: an **authorized Cisco Secure FMC
management-audit export**. A sensor record says an attacker aimed something
here; a management-audit record says an operator changed something there, and
the two must never be read as the same kind of claim. The normalized shape such
an export would be reduced to — and the invariants that keep a request-shaped
record from ever becoming a completed-change event — are specified in
[FMC-MANAGEMENT-AUDIT-CONTRACT.md](FMC-MANAGEMENT-AUDIT-CONTRACT.md) (#3215).
That is a **contract only**: no normalizer, no connector, no live audit reader,
no index, no new sensor, no compose entry and no decoy exist or are authorized
by it, and #3215 stays blocked until an authorized audit source does. Cisco
Secure FMC is also a different product from this table's `cisco-asa-honeypot`
persona and never borrows its identity.

Filebeat writes sensor events to versioned `honeypot-v2-*` data streams. The
`elasticsearch-setup` one-shot maps each original `honeypot` object as
`flattened`, so heterogeneous Dionaea/Conpot/Cowrie fields cannot reject one
another due to type conflicts. Non-indexable events also fall back to
`dead-letter-honeypot` instead of being silently discarded.
GeoIP enrichment is best-effort: empty or malformed addresses are skipped, but
the original event is always retained.
ILM keeps raw Suricata indices for 7 days, honeypot data streams for 30 days,
and dead-letter records for 60 days so high-volume scans cannot fill the disk.
Those are the values at the *code* fallback `HONEYPOT_RETENTION_DAYS=30`. Every
window derives from that one knob, and the shipped configuration does **not**
use the fallback: all four tracked `.env.example` files set
`HONEYPOT_RETENTION_DAYS=21` (#2820), at which the three windows above become
**4d / 21d / 42d** — Suricata is `retention*7/30` (integer-truncated, floored
at 1) and dead-letter is `retention*2`. Only the ILM *policy names*
(`suricata-7d`, `honeypot-30d`, `dead-letter-60d`) stay fixed; they are
identifiers referenced by the index templates, not claims about duration.

## Runtime resource budgets

Every service has a CPU, memory, and Docker `json-file` log budget. The
limits are intentionally generous relative to the host (16 logical CPUs and
91 GiB RAM): Elasticsearch gets 12 GiB with a 6 GiB heap; Arkime capture 6 GiB;
Kibana, Filebeat, and the TANNER analyzer receive 2 GiB; EveBox, Dionaea, Arkime
viewer, and the live dashboard receive 1 GiB (the dashboard also has two CPUs). The
remaining lightweight sensors receive 128-512 MiB. Docker console logs rotate
at 25 MiB with three files, independently from sensor event files under
`./logs`.

## HTTPS investigation UIs (each its own subdomain, all Keycloak-gated)

| Dashboard | Subdomain | Container |
|---|---|---|
| Live sensor view (ours) | `honeypot.<domain>` | `dashboard-next` :8080 |
| Kibana (ELK + Suricata) | `kibana.<domain>` | `kibana` :5601 |
| TANNER web-attack analysis | `tanner.<domain>` | `tanner_web` :8091 |
| EveBox (Suricata events) | `evebox.<domain>` | `evebox` :5636 |
| Arkime (packet sessions) | `arkime.<domain>` | `arkime-viewer` :8005 |
| Rev·Deck (Ghidra AI chat) | `rev.<domain>` | `revdeck` :5000 (separate `analysis/ghidra/` stack, `revdeck` profile — see [analysis/ghidra/revdeck/README.md](analysis/ghidra/revdeck/README.md)) |
| Unsloth Studio (model training UI, #3689) | `unsloth.<domain>` | `hp-unsloth-studio` :8000, published on `UNSLOTH_BIND`:8899 (`arcane/home/unsloth`). **Not currently deployed on the homeserver** — the VPS gateway authenticates but upstream requests fail until Studio is brought back. |

Each is bridged to the VPS by its own `socat-hp-*` service (one socat per
service, the reliable/consistent way) and routed by
[Traefik](../vps/traefik/) through a per-service `oauth2-proxy` gateway
(ForwardAuth middleware), all backed by the same Keycloak realm running at
home (`honeypot-keycloak`, `arcane/home/honeypot-keycloak/compose.yml`). There is no
separate "auth portal" stack or container to deploy anymore — that was the
retired `Xore/auth-backend` runtime (hard cutover, see
[KEYCLOAK-CUTOVER.md](KEYCLOAK-CUTOVER.md)); `Xore/auth-backend` now only
supplies the Keycloak login/account/email theme
(`Xore/auth-backend`'s `themes/apiary`), not a running service. To stand
this up: deploy the Keycloak stack (`arcane/home/honeypot-keycloak/compose.yml`, Dockge-managed,
see [KEYCLOAK-OPERATIONS.md](KEYCLOAK-OPERATIONS.md)), configure each
investigation UI's `oauth2-proxy` client in `vps/docker-compose.yml`, then
point proxied Cloudflare records at the VPS for each subdomain.

## SNARE + TANNER

SNARE serves the repository-owned fictional Meridian customer portal and feeds every request to
TANNER, which emulates the vulnerabilities attackers probe for (SQLi, LFI/RFI,
XSS, command execution, PHP code/object injection, XXE, CRLF and template
injection) and stores sessions in Redis. TANNER's emulation containers are
isolated from the homeserver Docker socket and are not a malware detonation
environment. Suspicious payload detonation belongs in the separate KVM/libvirt
sandbox described in [`sandbox/README.md`](sandbox/README.md). Containers: `tanner_docker`
(the nested disposable emulator daemon), `tanner_redis`, `tanner_phpox`, `tanner_api`,
`tanner` (analyzer, `:8090`), `tanner_web` (dashboard, `:8091`), `snare` (`:8080`) --
seven services, all on `tanner_local`. The persona clone itself is not one of them:
`snare-clone` is a one-shot job in `honeypot-init` (`hp-snare-clone`) that writes the
`snare-pages` volume `snare` reads. The page source lives under
[snare/persona](../arcane/home/honeypot-tanner/snare/persona)
and is transformed into SNARE's content-addressed store during the image build;
no third-party site is cloned. All `mushorg/*` images are third-party
— verify tags/args upstream (needs a live build/pull).

## Suricata — analysing all the traffic

`suricata` runs **on the VPS** (host networking, sniffing the public interface
`CAPTURE_INTERFACE`, written at boot by `detect-capture-interface.service`,
falling back to the legacy `SURICATA_IFACE` and then to `eth0` — *not* the old
`ens6`, which a reboot has already renamed) so it sees real attacker source IPs
before the tunnel. It writes to `/opt/stacks/apiary/logs/suricata/` on the VPS:

- `eve.json` (alerts, http, dns, tls, flow) — Filebeat on the home server ships
  it to the `suricata-*` Elasticsearch index (stats events are dropped, see
  [analysis/filebeat.yml](../arcane/home/honeypot-elk/analysis/filebeat.yml)).
- `pcap/log.pcap.<epoch>` — full packet capture, rotated at **4mb**
  (Suricata's hard minimum; smaller values crash pcap-log) with
  `max-files: 12500` ≈ 50 GB retention. Consumed by Arkime, see below.

**BPF filter (important):** the af-packet section of
[`vps/suricata/suricata.yaml`](../vps/suricata/suricata.yaml) sets
`bpf-filter: "not udp port 51820"` to exclude the WireGuard tunnel. Without it
Suricata captures its own log-shipping traffic (sshfs reads of pcap/eve.json
ride the tunnel on the same interface) — a feedback loop that inflates
pcap-log to 100 MB every few seconds. A positional BPF arg on the suricata
command line is silently ignored; it must live in the yaml.

The home server mounts the VPS log dir read-only via sshfs/fstab. Use
`setup-home-network.sh` to select the required uplink and
`setup-suricata-logs-home.sh` to install WireGuard-aware mount ordering and
retries. Rule updates: `suricata-update` runs as a one-shot container before
each suricata start.

## Arkime — full packet capture search

Arkime capture **cannot watch the sshfs mount directly**: its `--monitor` uses
kernel inotify, and inotify never fires for writes done on another machine.
The `pcap-sync` sidecar bridges that: every 30 s it copies **closed** pcap
files (skipping the newest, still being written by Suricata) from the sshfs
mount to the local `logs/arkime-raw/`, where inotify works and
`arkime-capture -R file:///opt/arkime/raw --monitor --skip` imports each file
seconds after it lands. It deliberately uses plain `cp` to the final name —
Arkime reacts to `IN_CLOSE_WRITE` only, so a rename would be invisible.

End-to-end latency is one Suricata rotation (~1–5 min depending on traffic)
plus a few seconds. A pcap file only becomes visible to Arkime once Suricata
*closes* it — there is no time-based rotation in Suricata 7, so quiet periods
mean longer latency. Local copies are pruned after 50 days (~50 GB, matching
the VPS ring); the viewer serves packet payloads from these files.

Web UI: `http://<HP_BIND>:19080` (`arkime.<domain>` via Traefik).

> **Source IPs & the tunnel.** socat/portbridge terminate the attacker's TCP
> connection on the VPS and re-dial over WireGuard, so without help the sensors
> would see the **VPS WireGuard IP** (`10.8.0.1`) as the source. This stack
> recovers the real attacker IP three ways:
>
> - **PROXY protocol.** portbridge rules tagged `:pp` prepend a HAProxy PROXY v1
>   header carrying the real client address. **multipot** and the
>   **http/api-honeypots** (`PROXY_PROTOCOL=1`), **dnp3** (`PROXY_PROTOCOL=1`),
>   **dicompot** (`PROXY_PROTOCOL=1`), **citrix-honeypot**,
>   **sonicwall-sma-honeypot** (`PROXY_PROTOCOL=1`),
>   **cisco-asa-honeypot**'s WebVPN side and **rdp-honeypot** (`PROXY_PROTOCOL=1`),
>   **endlessh** (`PROXY_PROTOCOL=1`, public 2022) and **all conpot sensors**
>   (`CONPOT_PROXY_PROTOCOL=1`, gevent shim baked in
>   by `conpot/proxy_patch.py`) parse it, so those events log the true IP and
>   port. The http listener sniffs the header, so Traefik-routed requests (no
>   header) keep working too.
> - **X-Forwarded-For.** Traefik-routed **HTTP** requests arrive from the tunnel
>   peer with Traefik's XFF; the http-honeypot trusts XFF only from that peer.
> - **portbridge connection log.** For sensors that can't parse PROXY
>   (**cowrie** — Twisted's `haproxy:` endpoint parses but does not apply the
>   address — and **dionaea**), and for **every UDP port**, where PROXY protocol
>   has no meaning at all, portbridge's `CONN_LOG` records the real IP per
>   connection along with the upstream source port it will arrive on; ship that
>   dir to the home stack (same mount pattern as Suricata, but **without
>   `x-systemd.automount`** — autofs triggers return EPERM to container
>   processes) and the enrichment worker joins it by source port and
>   connection start time at ingest. The mount must not use
>   `default_permissions`, or the worker (uid 65534) cannot read the log and
>   attribution silently stops (#3573). Join rule, outcomes and the history
>   backfill: [TUNNEL-ATTRIBUTION.md](TUNNEL-ATTRIBUTION.md).
>
> Suricata already sees real IPs (it sniffs the public interface on the VPS).
> Net result: the live dashboard can pivot on a single attacker IP across every
> sensor. Running the whole stack **on the VPS** (`HP_BIND=0.0.0.0`, skip the
> tunnel) remains an option if you'd rather avoid PROXY protocol entirely.
