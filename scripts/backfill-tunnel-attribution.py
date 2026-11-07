#!/usr/bin/env python3
"""backfill-tunnel-attribution.py -- attribute historical tunnelled honeypot
events to the client portbridge relayed (#3573).

Attacker connections reach the homeserver sensors through the VPS portbridge
over WireGuard, so a sensor that does not speak PROXY protocol records the
tunnel peer as its client. The ip-enrichment worker joins each such line to
portbridge's connection log at ingest time. From the 2026-09 rebuild until
#3573 it could not read that log at all (sshfs `default_permissions` against
root:root 0640), so every tunnelled event since then reached Elasticsearch
with only the tunnel peer, and none has `source.ip`.

This script repeats the worker's join over what is already indexed:
`honeypot-v2-*` documents without `source.ip` against `portbridge-v2-*`.
The rule is the worker's rule (backend-service ip_enrichment/viamap.rs
`resolve`), constant for constant:

* The join key is the sensor-observed source port, which is portbridge's
  `via_port`, and the time the *connection* started -- the earliest line of
  the session for sensors that name sessions (cowrie `session`, conpot `id`,
  dionaea's connection `id`), otherwise the line's own time.
* A dial matches when it was stamped up to DIAL_LEAD_SECONDS before that
  start or CLOCK_SKEW_SECONDS after it, on a compatible transport, and on the
  same target port where the sensor's listen port is known to equal it.
* TCP: every matching dial must name the same client, or the document is
  AMBIGUOUS. Where the sensor does not say which port portbridge dialled, a
  different client on the port in the RIVAL_LOOKBACK_SECONDS before the line
  also makes it AMBIGUOUS. UDP: the newest dial up to UDP_SESSION_MAX_AGE_SECONDS back is
  the session, unless a rival sits too close to the line to order.
* Backfill only: a window that overlaps a gap in portbridge-v2 (no dial at all
  for more than GAP_SECONDS) is NO_COVERAGE, never attributed -- the dial that
  would have made it ambiguous may be in the gap.

Nothing is guessed. Every document lands in exactly one outcome:

  attributed    exactly one client fits; --apply writes it
  ambiguous     two or more clients fit
  unmatched     no dial fits (the right one was never logged or indexed)
  no_coverage   portbridge-v2 has a gap over the window
  no_port       the document carries no tunnel-side source port
  no_time       the document carries no usable sensor time
  proxied       arrived through Traefik, not portbridge (galah 8890,
                hellpot 8090) -- not this join's to answer
  loopback      the sensor's own healthcheck (127.0.0.1/::1), never an attacker
  other         no tunnel address at all (another fleet address, or none)

A dionaea incident with several tunnel connections takes the worst outcome of
them, in the order above, and is attributed only when all of them are.

Writes (--apply only): one throttled `_update_by_query` per batch on the
document's own backing index, through the `geoip-honeypot` pipeline, so
`source.ip` and geo/ASN are derived exactly as at ingest. The script sets the
sensor's own address fields as the worker would have, plus
`honeypot.fleet_peer` and `honeypot.tunnel_attribution`. Each field is only
written while it still holds the tunnel value and while `source.ip` is still
absent, so a re-run or a concurrent writer is never clobbered. With
--mark-unattributed, ambiguous/unmatched/no_coverage documents get only
`honeypot.tunnel_attribution`, so they stay countable in Elasticsearch.

Elasticsearch has no host-published port, so run it from a throwaway
container on the honeynet network (full runbook: docs/TUNNEL-ATTRIBUTION.md):

    docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" \\
      python:3-alpine python /s/backfill-tunnel-attribution.py              # dry run
    docker run ... python /s/backfill-tunnel-attribution.py --apply --mark-unattributed

Env:
    ES_URL   Elasticsearch base URL (default: http://elasticsearch:9200)
"""

from __future__ import annotations

import argparse
import bisect
import collections
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# -- the join rule; keep in step with backend-service ip_enrichment/viamap.rs
TUNNEL_PEER_IP = "10.8.0.1"
LOOPBACK_IPS = ("127.0.0.1", "::1")
CLOCK_SKEW_SECONDS = 2
DIAL_LEAD_SECONDS = 4
UDP_SESSION_MAX_AGE_SECONDS = 3600
RIVAL_LOOKBACK_SECONDS = 600
# backfill only: silence in portbridge-v2 longer than this is a gap
GAP_SECONDS = 300

HONEYPOT_INDEX = "honeypot-v2-*"
PORTBRIDGE_INDEX = "portbridge-v2-*"
PIPELINE = "geoip-honeypot"

ATTRIBUTED, AMBIGUOUS, UNMATCHED = "attributed", "ambiguous", "unmatched"
NO_COVERAGE, NO_PORT, NO_TIME = "no_coverage", "no_port", "no_time"
PROXIED, LOOPBACK, OTHER = "proxied", "loopback", "other"
OUTCOMES = (ATTRIBUTED, AMBIGUOUS, UNMATCHED, NO_COVERAGE, NO_PORT, NO_TIME, PROXIED, LOOPBACK, OTHER)
# Severity order for combining several joins in one document (worst last).
_SEVERITY = {o: i for i, o in enumerate((ATTRIBUTED, NO_TIME, NO_PORT, NO_COVERAGE, UNMATCHED, AMBIGUOUS))}
# What the worker writes into tunnel_attribution for each joined outcome.
LABELS = {ATTRIBUTED: "portbridge", AMBIGUOUS: "ambiguous", UNMATCHED: "unmatched",
          NO_COVERAGE: "unmatched", NO_PORT: "unmatched", NO_TIME: "unmatched"}

TCP, UDP, UNKNOWN = "tcp", "udp", ""

# Sensors whose listen port equals portbridge's target port (live RULES,
# 2026-10-09). A wrong entry can only cost a match, never create one: two TCP
# connections to one target cannot share a source port at the same time.
WANT_PORT_FIELD = {
    "dionaea": "dst_port",
    "elasticpot": "dst_port",
    "mailoney": "dst_port",
    "dns-honeypot": "port",
    "cisco-asa-honeypot": "port",
}
# cowrie's compose publishes 19022 -> 2222 and 19023 -> 2223.
COWRIE_TARGETS = {2222: 19022, 2223: 19023}
CONPOT_UDP_KINDS = ("snmp", "bacnet", "ipmi", "tftp")
CONPOT_UDP_PORTS = (161, 623, 47808, 69)
GALAH_PROXIED_PORT = "8890"
HELLPOT_PROXIED_PORT = "8090"

_TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?"
)


def parse_time(raw) -> float:
    """Epoch seconds for any stamp a sensor writes; 0 when unusable.

    Mirrors sensors.rs parse_sensor_time: RFC 3339 with Z or an offset,
    space-separated date and time, galah's Go form ("... +0200 CEST m=+...")
    and naive stamps, which the sensors write in UTC.
    """
    if not isinstance(raw, str) or not raw:
        return 0
    m = _TIME_RE.match(raw.strip())
    if not m:
        return 0
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        base = dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=dt.timezone.utc)
    except ValueError:
        return 0
    seconds = base.timestamp() + (float("0." + frac) if frac else 0.0)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        seconds -= sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    return seconds


def transport_of(raw) -> str:
    value = str(raw or "").strip().lower()
    return value if value in (TCP, UDP) else UNKNOWN


def as_port(raw) -> int:
    """A port from an int, a numeric string, or an "addr:port" string."""
    if isinstance(raw, bool):
        return 0
    if isinstance(raw, (int, float)):
        return int(raw)
    if isinstance(raw, str):
        tail = raw.rsplit(":", 1)[-1].strip()
        return int(tail) if tail.isdigit() else 0
    return 0


def split_host_port(addr) -> tuple[str, str] | None:
    if not isinstance(addr, str) or not addr:
        return None
    if addr.startswith("["):
        host, sep, port = addr[1:].partition("]:")
        return (host, port) if sep and host and port else None
    host, sep, port = addr.rpartition(":")
    return (host, port) if sep and host and port else None


# -- portbridge-v2 ------------------------------------------------------------


@dataclass(frozen=True)
class Dial:
    at: int
    ip: str
    target_port: int
    transport: str


@dataclass
class Portbridge:
    """via_port -> dials, plus where portbridge-v2 has no data at all."""

    by_port: dict = field(default_factory=lambda: collections.defaultdict(list))
    times: list = field(default_factory=list)
    gaps: list = field(default_factory=list)  # (start, end): no dial strictly between
    _gap_starts: list = field(default_factory=list)
    _seen: set = field(default_factory=set)

    def add(self, source: dict) -> None:
        pb = source.get("portbridge") or {}
        ip = pb.get("src_ip")
        via = as_port(pb.get("via_port"))
        at = int(parse_time(pb.get("time")))
        if not ip or not via or not at:
            return
        target = pb.get("target")
        target_port = as_port(target) if isinstance(target, str) and ":" in target else 0
        key = (via, at, ip, target_port)
        if key in self._seen:  # #1776 shipped some lines twice
            return
        self._seen.add(key)
        self.by_port[via].append(Dial(at, ip, target_port, transport_of(pb.get("proto"))))
        self.times.append(at)

    def finish(self, gap_seconds: int = GAP_SECONDS) -> None:
        self._seen = set()
        self.times.sort()
        self.gaps = [(a, b) for a, b in zip(self.times, self.times[1:]) if b - a > gap_seconds]
        self._gap_starts = [a for a, _ in self.gaps]

    def covered(self, lo: float, hi: float) -> bool:
        """Whether portbridge-v2 has data throughout [lo, hi]."""
        if not self.times or lo < self.times[0] or hi > self.times[-1]:
            return False
        # Gaps are disjoint and sorted, so the last one starting before `hi`
        # is the only one that can still reach past `lo`.
        i = bisect.bisect_left(self._gap_starts, hi)
        return not (i > 0 and self.gaps[i - 1][1] > lo)


def resolve(pb: Portbridge, via_port: int, at: float, want_port: int = 0,
            transport: str = UNKNOWN) -> tuple[str, str | None, int | None]:
    """The worker's join (viamap.rs `resolve`). Returns (outcome, client, dial time)."""
    if not via_port:
        return NO_PORT, None, None
    if not at:
        return NO_TIME, None, None
    lead = UDP_SESSION_MAX_AGE_SECONDS if transport == UDP else DIAL_LEAD_SECONDS
    lo, hi = at - lead, at + CLOCK_SKEW_SECONDS

    def fits(d: Dial) -> bool:
        return (
            lo <= d.at <= hi
            and (not want_port or not d.target_port or d.target_port == want_port)
            and (not transport or not d.transport or d.transport == transport)
        )

    candidates = [d for d in pb.by_port.get(via_port, ()) if fits(d)]
    if not candidates:
        return (UNMATCHED if pb.covered(lo, hi) else NO_COVERAGE), None, None
    newest = max(candidates, key=lambda d: d.at)
    if transport == UDP:
        rival = any(d.ip != newest.ip and (d.at >= at - DIAL_LEAD_SECONDS or d.at == newest.at) for d in candidates)
        window = (newest.at, hi)
    elif not want_port:
        look = at - RIVAL_LOOKBACK_SECONDS
        rival = any(
            d.ip != newest.ip and look <= d.at <= hi and (not transport or not d.transport or d.transport == transport)
            for d in pb.by_port.get(via_port, ())
        )
        window = (look, hi)
    else:
        rival = any(d.ip != newest.ip for d in candidates)
        window = (lo, hi)
    if rival:
        return AMBIGUOUS, None, None
    if not pb.covered(*window):
        return NO_COVERAGE, None, None
    return ATTRIBUTED, newest.ip, newest.at


# -- honeypot-v2 documents ----------------------------------------------------


@dataclass
class Need:
    """One tunnel address in a document that the join has to answer."""

    via_port: int
    line_at: float
    session: tuple | None
    want_port: int
    transport: str
    # (honeypot-relative path, value it must still hold, new value with {ip})
    writes: tuple = ()


def sensor_of(source: dict) -> str:
    return str((source.get("event") or {}).get("sensor") or (source.get("honeypot") or {}).get("sensor") or "")


def _peer(ip) -> str | None:
    """Terminal outcome for a sensor-observed address that is not the tunnel."""
    if ip in LOOPBACK_IPS:
        return LOOPBACK
    if ip != TUNNEL_PEER_IP:
        return OTHER
    return None


def classify(source: dict) -> tuple[str | None, list]:
    """Either a terminal outcome, or the joins this document needs.

    One branch per sensor shape the worker has a bespoke enricher for
    (sensors.rs), then the generic flat src_ip/src_port shape, then
    dionaea_incident.json's nested connections.
    """
    h = source.get("honeypot") or {}
    sensor = sensor_of(source)

    if "REMOTE_ADDR" in h:  # hellpot
        hp = split_host_port(h.get("REMOTE_ADDR"))
        if not hp:
            return OTHER, []
        ip, port = hp
        if (done := _peer(ip)) is not None:
            return done, []
        if str(h.get("DST_PORT")) == HELLPOT_PROXIED_PORT:
            return PROXIED, []
        writes = (("src_ip", TUNNEL_PEER_IP, "{ip}"), ("REMOTE_ADDR", h["REMOTE_ADDR"], "{ip}:" + port))
        return None, [Need(as_port(port), parse_time(h.get("time")), None, as_port(h.get("DST_PORT")), TCP, writes)]

    if "source_ip" in h and ("sip_message" in h or sensor == "sentrypeer"):  # sentrypeer
        hp = split_host_port(h.get("source_ip"))
        if not hp:
            return OTHER, []
        ip, port = hp
        if (done := _peer(ip)) is not None:
            return done, []
        writes = (("src_ip", TUNNEL_PEER_IP, "{ip}"), ("source_ip", h["source_ip"], "{ip}:" + port))
        return None, [Need(as_port(port), parse_time(h.get("event_timestamp")), None, 0,
                           transport_of(h.get("transport_type")), writes)]

    if "srcIP" in h:  # galah
        if (done := _peer(h.get("srcIP"))) is not None:
            return done, []
        if str(h.get("port")) == GALAH_PROXIED_PORT:
            return PROXIED, []
        writes = (("src_ip", TUNNEL_PEER_IP, "{ip}"), ("srcIP", TUNNEL_PEER_IP, "{ip}"))
        return None, [Need(as_port(h.get("srcPort")), parse_time(h.get("eventTime")), None,
                           as_port(h.get("port")), TCP, writes)]

    ev = h.get("event")
    if isinstance(ev, dict) and "SourceIp" in ev:  # beelzebub
        if (done := _peer(ev.get("SourceIp"))) is not None:
            return done, []
        writes = (("src_ip", TUNNEL_PEER_IP, "{ip}"), ("event.SourceIp", TUNNEL_PEER_IP, "{ip}"))
        return None, [Need(as_port(ev.get("SourcePort")), parse_time(ev.get("DateTime")), None, 0, TCP, writes)]

    if h.get("src_ip"):  # the generic flat shape
        if (done := _peer(h.get("src_ip"))) is not None:
            return done, []
        transport = transport_of(h.get("transport") or (h.get("connection") or {}).get("transport"))
        conpot = sensor.startswith("conpot")
        if not transport:
            if sensor in ("cowrie", "elasticpot", "mailoney"):
                transport = TCP
            elif conpot:
                udp = h.get("data_type") in CONPOT_UDP_KINDS or as_port(h.get("dst_port")) in CONPOT_UDP_PORTS
                transport = UDP if udp else TCP
        session = None
        if sensor == "cowrie" and h.get("session"):
            session = (sensor, str(h["session"]))
        elif conpot and h.get("id"):
            session = (sensor, str(h["id"]))
        want_field = WANT_PORT_FIELD.get(sensor)
        if want_field:
            want = as_port(h.get(want_field))
        elif sensor == "cowrie":
            want = COWRIE_TARGETS.get(as_port(h.get("dst_port")), 0)
        elif conpot and transport == TCP:
            want = as_port(h.get("dst_port"))
        else:
            want = 0
        line_at = parse_time(h.get("timestamp") or h.get("time") or h.get("event_timestamp") or h.get("eventTime"))
        return None, [Need(as_port(h.get("src_port")), line_at, session, want, transport,
                           (("src_ip", TUNNEL_PEER_IP, "{ip}"),))]

    data = h.get("data")  # dionaea_incident.json
    if isinstance(data, dict):
        needs, saw_loopback = [], False
        line_at = parse_time(h.get("timestamp"))
        for key in ("connection", "parent", "child"):
            conn = data.get(key)
            if not isinstance(conn, dict):
                continue
            rip = conn.get("remote_ip")
            saw_loopback = saw_loopback or rip in LOOPBACK_IPS
            if rip != TUNNEL_PEER_IP:
                continue
            session = ("dionaea-incident", str(conn["id"])) if conn.get("id") else None
            needs.append(Need(as_port(conn.get("remote_port")), line_at, session, as_port(conn.get("local_port")),
                              transport_of(conn.get("transport")),
                              ((f"data.{key}.remote_ip", TUNNEL_PEER_IP, "{ip}"),)))
        if needs:
            return None, needs
        return (LOOPBACK if saw_loopback else OTHER), []
    return OTHER, []


@dataclass
class Decision:
    outcome: str
    # honeypot-relative path -> [value it must still hold (None: absent), new value]
    writes: dict = field(default_factory=dict)
    lag: list = field(default_factory=list)  # anchor minus dial time, attributed joins


def decide(source: dict, pb: Portbridge, starts: dict) -> Decision:
    """The outcome for one document, and what --apply would write."""
    terminal, needs = classify(source)
    if terminal is not None:
        return Decision(terminal)
    outcomes, writes, lags = [], {}, []
    for need in needs:
        at = need.line_at
        if need.session is not None and need.line_at:
            at = min(starts.get(need.session, need.line_at), need.line_at)
        outcome, ip, dial_at = resolve(pb, need.via_port, at, need.want_port, need.transport)
        outcomes.append(outcome)
        if outcome == ATTRIBUTED:
            lags.append(round(at - dial_at))
            for path, old, template in need.writes:
                writes[path] = [old, template.format(ip=ip)]
    worst = max(outcomes, key=_SEVERITY.__getitem__)
    if worst != ATTRIBUTED:
        return Decision(worst, {"tunnel_attribution": [None, LABELS[worst]]})
    writes["fleet_peer"] = [None, TUNNEL_PEER_IP]
    writes["tunnel_attribution"] = [None, LABELS[ATTRIBUTED]]
    return Decision(ATTRIBUTED, writes, lags)


def record_start(starts: dict, source: dict) -> None:
    """Pass 1: the earliest time seen for every named session."""
    _, needs = classify(source)
    for need in needs:
        if need.session is not None and need.line_at:
            known = starts.get(need.session)
            if known is None or need.line_at < known:
                starts[need.session] = need.line_at


# -- Elasticsearch ------------------------------------------------------------


class Elasticsearch:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def request(self, method: str, path: str, body: dict | None = None, timeout: int = 300) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.url}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as e:
            sys.exit(f"elasticsearch {method} {path} -> {e.code}: {e.read().decode(errors='replace')[:600]}")

    def scan(self, index: str, query: dict, source: list[str], page: int = 10000) -> Iterator[dict]:
        """Every hit, through a point in time (read-only; closed afterwards)."""
        pit = self.request("POST", f"/{index}/_pit?keep_alive=5m")["id"]
        after = None
        try:
            while True:
                body = {"size": page, "query": query, "_source": source,
                        "pit": {"id": pit, "keep_alive": "5m"}, "sort": [{"_shard_doc": "asc"}],
                        "track_total_hits": False}
                if after is not None:
                    body["search_after"] = after
                result = self.request("POST", "/_search", body)
                pit = result.get("pit_id", pit)
                hits = result["hits"]["hits"]
                if not hits:
                    return
                yield from hits
                after = hits[-1]["sort"]
        finally:
            self.request("DELETE", "/_pit", {"id": pit})


HONEYPOT_SOURCE = [
    "@timestamp", "event.sensor",
    "source.ip",
    "honeypot.sensor", "honeypot.src_ip", "honeypot.src_port", "honeypot.timestamp", "honeypot.time",
    "honeypot.event_timestamp", "honeypot.eventTime", "honeypot.session", "honeypot.id",
    "honeypot.dst_port", "honeypot.port", "honeypot.transport", "honeypot.data_type",
    "honeypot.connection.transport", "honeypot.REMOTE_ADDR", "honeypot.DST_PORT",
    "honeypot.source_ip", "honeypot.sip_message", "honeypot.transport_type",
    "honeypot.srcIP", "honeypot.srcPort",
    "honeypot.event.SourceIp", "honeypot.event.SourcePort", "honeypot.event.DateTime",
    "honeypot.data.connection", "honeypot.data.parent", "honeypot.data.child",
]
# sip_message is fetched only to recognise sentrypeer's shape.


def time_filter(since: str | None, until: str | None) -> list:
    if not since and not until:
        return []
    rng = {}
    if since:
        rng["gte"] = since
    if until:
        rng["lt"] = until
    return [{"range": {"@timestamp": rng}}]


def unattributed_query(since: str | None, until: str | None, sensors: list[str]) -> dict:
    filters = time_filter(since, until)
    if sensors:
        filters.append({"terms": {"event.sensor": sensors}})
    return {"bool": {"filter": filters, "must_not": [{"exists": {"field": "source.ip"}}]}}


def sessions_query(since: str | None, until: str | None) -> dict:
    """Every document that can carry a session start, attributed or not."""
    filters = time_filter(since, until)
    return {"bool": {"filter": filters, "should": [
        {"term": {"event.sensor": "cowrie"}},
        {"prefix": {"event.sensor": "conpot"}},
        {"exists": {"field": "honeypot.data.connection.id"}},
        {"exists": {"field": "honeypot.data.parent.id"}},
        {"exists": {"field": "honeypot.data.child.id"}},
    ], "minimum_should_match": 1}}


UPDATE_SCRIPT = """
if (ctx._source.source != null && ctx._source.source.ip != null) { ctx.op = 'noop'; return; }
def h = ctx._source.honeypot;
def writes = params.docs[ctx._id];
if (h == null || writes == null) { ctx.op = 'noop'; return; }
boolean changed = false;
for (def w : writes.entrySet()) {
  def parts = w.getKey().splitOnToken('.');
  def cur = h;
  for (int i = 0; i < parts.length - 1 && cur != null; i++) {
    cur = (cur instanceof Map) ? cur.get(parts[i]) : null;
  }
  if (!(cur instanceof Map)) continue;
  def last = parts[parts.length - 1];
  def expected = w.getValue()[0];
  if (expected == null ? cur.get(last) == null : expected.equals(cur.get(last))) {
    cur.put(last, w.getValue()[1]);
    changed = true;
  }
}
if (!changed) { ctx.op = 'noop'; }
"""


def apply_batch(es: Elasticsearch, index: str, docs: dict, rps: float) -> dict:
    body = {
        "query": {"ids": {"values": list(docs)}},
        "script": {"lang": "painless", "source": UPDATE_SCRIPT, "params": {"docs": docs}},
    }
    path = (f"/{index}/_update_by_query?pipeline={PIPELINE}&conflicts=proceed&refresh=false"
            f"&wait_for_completion=true&requests_per_second={rps}")
    return es.request("POST", path, body, timeout=3600)


# -- the run ------------------------------------------------------------------


def run(es, since, until, sensors, apply=False, mark_unattributed=False, batch=500, rps=500.0,
        gap_seconds=GAP_SECONDS, log=print, limit=0) -> dict:
    log(f"loading {PORTBRIDGE_INDEX} ...")
    pb = Portbridge()
    for hit in es.scan(PORTBRIDGE_INDEX, {"exists": {"field": "portbridge.via_port"}},
                       ["portbridge.via_port", "portbridge.time", "portbridge.src_ip",
                        "portbridge.target", "portbridge.proto"]):
        pb.add(hit["_source"])
    pb.finish(gap_seconds)
    log(f"  {len(pb.times)} dials on {len(pb.by_port)} ports, {len(pb.gaps)} gaps > {gap_seconds}s")

    log("pass 1: session start times ...")
    starts: dict = {}
    for hit in es.scan(HONEYPOT_INDEX, sessions_query(since, until), HONEYPOT_SOURCE):
        record_start(starts, hit["_source"])
    log(f"  {len(starts)} sessions")

    log("pass 2: deciding ..." + (" (writing)" if apply else " (dry run, nothing is written)"))
    counts: dict = collections.defaultdict(collections.Counter)
    lags: collections.Counter = collections.Counter()
    pending: dict = collections.defaultdict(dict)
    written = collections.Counter()
    seen = 0

    def flush(index: str) -> None:
        docs = pending.pop(index, None)
        if not docs:
            return
        result = apply_batch(es, index, docs, rps)
        written["updated"] += result.get("updated", 0)
        written["noops"] += result.get("noops", 0)
        written["version_conflicts"] += result.get("version_conflicts", 0)
        written["failures"] += len(result.get("failures", []))

    for hit in es.scan(HONEYPOT_INDEX, unattributed_query(since, until, sensors), HONEYPOT_SOURCE):
        source = hit["_source"]
        decision = decide(source, pb, starts)
        counts[sensor_of(source) or "(unknown)"][decision.outcome] += 1
        lags.update(decision.lag)
        seen += 1
        if apply and (decision.outcome == ATTRIBUTED or (mark_unattributed and decision.outcome in LABELS)):
            pending[hit["_index"]][hit["_id"]] = decision.writes
            if len(pending[hit["_index"]]) >= batch:
                flush(hit["_index"])
        if seen % 500000 == 0:
            log(f"  {seen} documents")
        if limit and seen >= limit:
            break
    for index in list(pending):
        flush(index)

    return {
        "documents": seen,
        "per_sensor": {s: dict(c) for s, c in sorted(counts.items(), key=lambda kv: -sum(kv[1].values()))},
        "totals": dict(sum(counts.values(), collections.Counter())),
        "dial_lag_seconds": dict(sorted(lags.items())),
        "portbridge": {"dials": len(pb.times), "gaps": len(pb.gaps),
                       "first": pb.times[0] if pb.times else None, "last": pb.times[-1] if pb.times else None},
        "written": dict(written) if apply else None,
    }


def render(report: dict) -> str:
    cols = OUTCOMES
    width = max([len(s) for s in report["per_sensor"]] + [6])
    lines = [f"{'sensor':<{width}} " + " ".join(f"{c:>12}" for c in cols) + f" {'total':>10}"]
    rows = list(report["per_sensor"].items()) + [("TOTAL", report["totals"])]
    for name, c in rows:
        lines.append(f"{name:<{width}} " + " ".join(f"{c.get(o, 0):>12}" for o in cols)
                     + f" {sum(c.values()):>10}")
    lines.append("")
    lines.append(f"anchor minus dial (s), attributed joins: {report['dial_lag_seconds']}")
    pbinfo = report["portbridge"]
    if pbinfo["first"]:
        first = dt.datetime.fromtimestamp(pbinfo["first"], dt.timezone.utc).isoformat()
        last = dt.datetime.fromtimestamp(pbinfo["last"], dt.timezone.utc).isoformat()
        lines.append(f"portbridge-v2: {pbinfo['dials']} dials, {first} .. {last}, {pbinfo['gaps']} gaps")
    if report["written"] is not None:
        lines.append(f"written: {report['written']}")
    return "\n".join(lines)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="write the attributions (default: dry run)")
    ap.add_argument("--mark-unattributed", action="store_true",
                    help="with --apply, also label ambiguous/unmatched documents in honeypot.tunnel_attribution")
    ap.add_argument("--since", help="@timestamp lower bound (inclusive), e.g. 2026-09-24")
    ap.add_argument("--until", help="@timestamp upper bound (exclusive)")
    ap.add_argument("--sensor", action="append", default=[], help="restrict to event.sensor (repeatable)")
    ap.add_argument("--batch", type=int, default=500, help="documents per _update_by_query")
    ap.add_argument("--requests-per-second", type=float, default=500.0, help="_update_by_query throttle")
    ap.add_argument("--gap-seconds", type=int, default=GAP_SECONDS,
                    help="portbridge-v2 silence treated as missing data")
    ap.add_argument("--limit", type=int, default=0, help="stop after this many documents (testing)")
    ap.add_argument("--report-json", help="also write the report as JSON to this path")
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.mark_unattributed and not args.apply:
        ap.error("--mark-unattributed only makes sense with --apply")

    es = Elasticsearch(os.environ.get("ES_URL", "http://elasticsearch:9200"))
    started = time.monotonic()
    report = run(es, args.since, args.until, args.sensor, apply=args.apply,
                 mark_unattributed=args.mark_unattributed, batch=args.batch,
                 rps=args.requests_per_second, gap_seconds=args.gap_seconds,
                 log=lambda m: print(m, file=sys.stderr, flush=True), limit=args.limit)
    report["elapsed_seconds"] = round(time.monotonic() - started)
    print(render(report))
    if args.report_json:
        with open(args.report_json, "w") as fh:
            json.dump(report, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
