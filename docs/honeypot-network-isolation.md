# Network Isolation

> **Status (2026-07-31):** rewritten. The previous version was an 850-line
> best-practice guide for a four-zone single-host lab — `virbr-mal` at
> `10.66.0.1`, `virbr-honey` at `10.67.0.0/24`, a `honey-dmz` and `analysis-net`
> Docker pair, and a management NIC on `192.168.100.0/24`. None of those exist.
> It also shipped five scripts as finished work (`firewall-honeypot-dmz.sh`,
> `firewall-malware-analysis.sh`, `firewall-analysis-stack.sh`,
> `zone-crossing-alert.sh`, `isolation-audit.sh`) that were never written.
>
> The `analysis-net` name in it is where
> [#61](https://github.com/Xore/APIARY/issues/61) came from: an override
> file was written against this document instead of against the compose file,
> and attached the ML worker to a network that does not exist.
>
> Gaps found during the rewrite:
> [#88](https://github.com/Xore/APIARY/issues/88) (no automated
> isolation audit), [#89](https://github.com/Xore/APIARY/issues/89)
> (container hardening covers five services).

---

## 1. The actual shape

There is no single honeypot host. There are two machines and a tunnel, and that
split *is* the primary isolation boundary — the exposed services and the
analysis stack are not on the same hardware.

| | VPS | Home server |
|---|---|---|
| Faces | The public internet | Nothing. Outbound WireGuard only |
| Runs | Suricata on the public NIC, `portbridge`, the exposed listeners | The honeypot containers, Elasticsearch/Kibana, EveBox, Arkime, the dashboard, the sandboxes |
| Firewall | `ufw`, seeded by `vps/honeypot-firewall.sh` | No inbound exposure to reason about |
| Sees | Real attacker source IPs | Tunnel IPs, unless the record carries the original |

The consequence worth remembering: the sensor that sees the true source address
is the one on the VPS. See
[`vps/suricata/README.md`](vps/suricata/README.md) for the `HOME_NET`
trap that follows from it, and note that traffic arriving over the tunnel must
not be attributed to the WireGuard peer.

`vps/honeypot-firewall.sh` is the only firewall script in this repository that
*configures* anything. It is deliberately small: it idempotently `ufw allow`s
the raw OT ports that `portbridge` handles, and does nothing else. Egress
control on the VPS is not scripted here.

The second file with "firewall" in its name,
`vps/check-firewall-portbridge-sync.sh` (#152), configures nothing — it
statically diffs the ports `portbridge` actually forwards against the ports
`honeypot-firewall.sh` opens, because those two lists drifted silently once
already. It is not wired into any workflow, so run it by hand after editing
either file.

## 2. Sandbox isolation

This is where the isolation has teeth, and it is documented in full in
[`kvm-network-traffic-analysis.md`](kvm-network-traffic-analysis.md). In short:
two libvirt networks — `virbr-sandbox` (Windows, `10.10.10.0/24`, gateway `.254`,
INetSim at `.1`) and `virbr-hpsbx` (Linux, no IP, no DHCP at all).

Neither has a `<forward>` element. That absence *is* the isolation — the Windows
network XML carries a comment block explaining it precisely because a later
reader "fixing" the missing NAT would be undoing the design. Two further
barriers back it up: the gateway containers sit on a macvlan marked
`internal: true`, and Phase 0 installs an iptables DROP pair across the bridge.

Guests carry the `honeypot-sandbox-strict` nwfilter — the real version of what
the old §4 proposed as `clean-traffic` plus a hand-written `malware-vm-strict`.
It permits ordinary IPv4/IPv6/ARP and blocks source-MAC spoofing and other
layer-2 protocols, which is what makes the per-MAC capture filter unevadable
from inside the guest.

## 3. Container isolation

Each honeypot's own compose file (`arcane/home/honeypot-cowrie/compose.yml`,
`arcane/home/honeypot-dionaea/compose.yml`, `arcane/home/honeypot-conpot/compose.yml`, etc. — split out
of `docker-compose.yml` under #258, which is now an empty stub) gives it its
own single-member Docker network (`cowrie_net`, `dionaea_net`, `conpot_net`,
`conpot_s7_1200_net`, and so on) —
[#235](https://github.com/Xore/APIARY/issues/235): the stack used to
put every honeypot on one shared `honeynet` bridge with Docker's default
inter-container communication, so a compromise of one honeypot had a direct
network path to every other honeypot. None of them need it — each writes to
a bind-mounted log file for Filebeat to tail, not to another honeypot or to
Elasticsearch over the network. The one real exception is `tftp-relay`, which
has `depends_on: dionaea` and actually forwards TFTP traffic to it, so those
two share `dionaea_net` instead of each getting their own.

`honeynet` is now the trusted analysis/management plane only, and that
enumeration needs to be read as a category, not a list: 24 services across 11
compose files attach to it. The data plane is Elasticsearch, Kibana, Filebeat,
EveBox, Arkime (capture and viewer) and the dashboard stack; the *supporting*
trusted members are just as much a part of the plane and are easy to forget:

- the four Go worker stacks — `agent-intrusion-worker`,
  `attacker-identity-worker`, `correlator-worker`, `payload-inventory-worker`
  — all `profiles: ["legacy"]`;
- `honeypot-dashboard-backend`'s unprivileged `backend-service` and
  `honeypot-dashboard`'s `backend-service-mounted`, `backend-worker`,
  `backend-worker-importer` and `backend-worker-payload-inventory`;
- the one-shot `honeypot-init` containers `elasticsearch-setup`, `arkime-init`
  and `honeypot-kibana-setup`;
- `honeypot-utilities`' `log-maintenance` **and** `disk-space-monitor`;
- `honeypot-elk`'s `extracted-file-importer`;
- the two root-path stacks `auth-events-worker` and `ml-worker`.

Deliberately *not* on `honeynet`: `backend-worker-enrichment` and
`services-adapter` (both `network_mode: none`), and the dashboard's
`oidc-sessions`, which has its own single-member `oidc-session` network.

SNARE/TANNER and its dependencies keep their own separate `tanner_local`,
unchanged — all seven services of `honeypot-tanner`, including `snare`, are on
it.

- `tanner_docker` is `privileged: true`. This is deliberate and should stay:
  TANNER's Docker-backed emulators need a daemon, and the design gives them a
  disposable nested one on `tanner_local` with `/var/lib/docker` on tmpfs
  rather than a bind mount of the host socket. The comment above the service
  says so; do not "simplify" it into a socket mount.
- No other container is privileged, and no honeypot-facing container mounts
  `/var/run/docker.sock`.
- `cap_drop: [ALL]` and `no-new-privileges` are on every honeypot now
  (`cowrie`, `multipot`, `http-honeypot`, `api-honeypot`, `dionaea`, `conpot`
  and its personas, `snare`, `tanner` and its dependencies, `yara-scanner`) —
  [#89](https://github.com/Xore/APIARY/issues/89) (SNARE/TANNER) and
  the per-service measurement passes referenced next to `dionaea`'s and
  `conpot`'s own `cap_add` lists closed the gap this section used to describe.
- `NET_ADMIN`/`NET_RAW` are confined to sniffers that need the bridge device
  or a raw socket, never to a decoy. Three sit in `docker-compose.sandbox.yml`
  (`zeek`, `suricata`, `tcpdump`), a separate file brought up around a single
  detonation that must never be merged into `docker-compose.yml`. The rest are
  the passive-capture services that cannot sniff without them:
  `honeypot-elk`'s `zeek-proxy`, and the VPS's `zeek`, `huginn-sidecar`,
  `suricata`, and `p0f`.

## 4. Host posture

These are host-only procedures. They are real and worth doing, but they
configure a machine rather than ship as code — which is why there is nothing
here to implement and no issue to open. Verified by
`scripts/isolation-audit.sh` (#88), run as part of the
`.github/workflows/diagnostics.yml` `home` job.

- **sshd** bound to the management address only, never the honeypot-facing one.
  `ss -tlnp | grep :22` is the check.
- **libvirt socket** — `/var/run/libvirt/libvirt-sock` as `srwxrwx---
  root:libvirt`, and `listen_tcp = 0`. The TCP socket is off by default; the
  failure mode is someone enabling it while debugging remotely and leaving it.
- **AppArmor** profiles for `libvirtd`/QEMU enforcing, not complain. On Ubuntu
  these ship working; the risk is a profile dropped to complain mode during an
  unrelated libvirt problem and never restored.
- **Docker socket** never mounted into a honeypot-facing container. It is root
  equivalent — a container that has it has the host.

## 5. Pitfalls

| Symptom | Cause |
|---|---|
| A rule matches nothing on the VPS | `HOME_NET` excludes the VPS public IP. See the Suricata README |
| Attacks appear to come from the WireGuard peer | The tunnel IP was taken as the source; the original address has to be carried through |
| Sandbox guest reaches the internet | Something added `<forward>`, removed the macvlan `internal: true`, or flushed the Phase 0 DROP pair. Any one of the three is sufficient |
| Host cannot reach the sandbox gateway containers | Expected — macvlan. Read the bind-mounted results directory instead |
| A honeypot container restarts after a hardening change | It needed a capability `cap_drop: [ALL]` removed. Add that specific one back; do not revert the drop |

## References

- [`agent-intrusion-threat-model.md`](agent-intrusion-threat-model.md) — maps
  a real machine-speed autonomous-agent intrusion campaign to this stack's
  trust boundaries; cites this document's isolation zones directly (#154)
- [`kvm-network-traffic-analysis.md`](kvm-network-traffic-analysis.md) — the
  sandbox capture and isolation model in full
- [`vps/suricata/README.md`](vps/suricata/README.md) — VPS sensor,
  `HOME_NET`, and log retention
- [`sandbox/README.md`](sandbox/README.md) — the Linux runner
- [libvirt nwfilter](https://libvirt.org/formatnwfilter.html)
- [Docker network drivers](https://docs.docker.com/network/)
