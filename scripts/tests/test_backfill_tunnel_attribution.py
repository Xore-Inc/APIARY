#!/usr/bin/env python3
"""Tests for scripts/backfill-tunnel-attribution.py (#3573).

The join rule is the ip-enrichment worker's (backend-service
ip_enrichment/viamap.rs `resolve`); these pin the same cases its Rust tests
pin, plus what only the backfill has: coverage gaps, session starts from
pass 1, the per-sensor document shapes as they sit in Elasticsearch, and the
write set --apply would send. No Elasticsearch: a fake serves fixed hits.
Every address is an RFC 5737 documentation address.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("backfill_tunnel", ROOT / "scripts" / "backfill-tunnel-attribution.py")
bt = importlib.util.module_from_spec(_spec)
sys.modules["backfill_tunnel"] = bt  # dataclasses resolve annotations through it
_spec.loader.exec_module(bt)

T = 1791588000  # 2026-10-09T...Z, any whole second works
PEER = bt.TUNNEL_PEER_IP


def iso(epoch: float) -> str:
    import datetime as dt
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dial(ip, via_port, at, target="10.8.0.2:19023", proto="tcp"):
    return {"portbridge": {"src_ip": ip, "via_port": via_port, "time": iso(at), "target": target, "proto": proto}}


def portbridge(*dials, background=True):
    pb = bt.Portbridge()
    for d in dials:
        pb.add(d)
    if background:
        # Steady unrelated traffic on other ports, so the fixtures' windows
        # are covered the way the real log covers them.
        for t in range(T - 7200, T + 7200, 60):
            pb.add(dial("192.0.2.250", 1, t))
    pb.finish()
    return pb


def cowrie(session, port, at, eventid="cowrie.session.connect"):
    return {"event": {"sensor": "cowrie"}, "honeypot": {
        "session": session, "src_ip": PEER, "src_port": port, "dst_port": 2223,
        "eventid": eventid, "timestamp": iso(at).replace("Z", ".500000Z")}}


class ResolveRule(unittest.TestCase):
    def test_the_dial_that_opened_the_connection_is_attributed(self):
        pb = portbridge(dial("203.0.113.20", 48132, T))
        self.assertEqual(bt.resolve(pb, 48132, T + 1, transport=bt.TCP)[:2], (bt.ATTRIBUTED, "203.0.113.20"))

    def test_a_dial_minutes_earlier_is_not_the_origin(self):
        pb = portbridge(dial("203.0.113.20", 48132, T - 600))
        self.assertEqual(bt.resolve(pb, 48132, T, transport=bt.TCP)[0], bt.UNMATCHED)

    def test_two_clients_within_seconds_is_ambiguous(self):
        pb = portbridge(dial("203.0.113.20", 48132, T - 1), dial("198.51.100.30", 48132, T, "10.8.0.2:445"))
        self.assertEqual(bt.resolve(pb, 48132, T + 1, transport=bt.TCP)[0], bt.AMBIGUOUS)

    def test_a_known_target_port_removes_a_rival_on_another_service(self):
        pb = portbridge(dial("203.0.113.20", 48132, T, "10.8.0.2:23"), dial("198.51.100.30", 48132, T, "10.8.0.2:1433"))
        self.assertEqual(bt.resolve(pb, 48132, T + 1, 1433, bt.TCP)[:2], (bt.ATTRIBUTED, "198.51.100.30"))

    def test_without_a_target_an_earlier_rival_makes_it_ambiguous(self):
        pb = portbridge(dial("203.0.113.20", 48132, T - 300, "10.8.0.2:389"),
                        dial("198.51.100.30", 48132, T - 1, "10.8.0.2:445"))
        self.assertEqual(bt.resolve(pb, 48132, T, 0, bt.TCP)[0], bt.AMBIGUOUS)
        self.assertEqual(bt.resolve(pb, 48132, T, 445, bt.TCP)[:2], (bt.ATTRIBUTED, "198.51.100.30"))

    def test_tcp_and_udp_ports_are_separate(self):
        pb = portbridge(dial("203.0.113.20", 40000, T, "10.8.0.2:19161", "udp"))
        self.assertEqual(bt.resolve(pb, 40000, T + 1, transport=bt.TCP)[0], bt.UNMATCHED)

    def test_a_long_udp_session_resolves_to_its_opening_dial(self):
        pb = portbridge(dial("198.51.100.30", 40000, T - 3000, "10.8.0.2:19161", "udp"),
                        dial("203.0.113.20", 40000, T - 1800, "10.8.0.2:19161", "udp"))
        self.assertEqual(bt.resolve(pb, 40000, T, transport=bt.UDP)[:2], (bt.ATTRIBUTED, "203.0.113.20"))

    def test_a_gap_in_the_log_is_never_attributed_across(self):
        # The right dial may be in the gap; the one found may be a stranger.
        pb = bt.Portbridge()
        pb.add(dial("203.0.113.20", 40000, T - 1800, "10.8.0.2:19161", "udp"))
        pb.add(dial("192.0.2.250", 1, T - 1790))
        pb.add(dial("192.0.2.250", 1, T + 10))  # 30 minutes of silence before the line
        pb.finish()
        self.assertEqual(bt.resolve(pb, 40000, T, transport=bt.UDP)[0], bt.NO_COVERAGE)

    def test_outside_the_indexed_range_is_no_coverage_not_unmatched(self):
        pb = portbridge(background=True)
        self.assertEqual(bt.resolve(pb, 48132, T - 86400, transport=bt.TCP)[0], bt.NO_COVERAGE)


class Shapes(unittest.TestCase):
    def test_times_every_sensor_writes(self):
        base = bt.parse_time("2026-09-29T06:51:15Z")
        for raw in ("2026-09-29T06:51:15.000000Z", "2026-09-29T06:51:15", "2026-09-29 06:51:15.000000000",
                    "2026-09-29 08:51:15.402586836 +0200 CEST m=+485577.992530828", "2026-09-29T08:51:15+02:00"):
            self.assertAlmostEqual(bt.parse_time(raw), base, delta=1, msg=raw)
        self.assertEqual(bt.parse_time("garbage"), 0)

    def test_loopback_is_a_healthcheck_never_a_join(self):
        doc = {"event": {"sensor": "conpot"}, "honeypot": {"src_ip": "127.0.0.1", "src_port": 1}}
        self.assertEqual(bt.classify(doc)[0], bt.LOOPBACK)

    def test_hellpots_proxied_door_is_not_portbridges(self):
        doc = {"event": {"sensor": "hellpot"}, "honeypot": {"REMOTE_ADDR": f"{PEER}:4000", "DST_PORT": "8090"}}
        self.assertEqual(bt.classify(doc)[0], bt.PROXIED)

    def test_hellpot_keeps_its_port_in_remote_addr(self):
        pb = portbridge(dial("203.0.113.21", 43664, T, "10.8.0.2:8080"))
        doc = {"event": {"sensor": "hellpot"}, "honeypot": {
            "REMOTE_ADDR": f"{PEER}:43664", "DST_PORT": "8080", "src_ip": PEER, "time": iso(T + 1)}}
        d = bt.decide(doc, pb, {})
        self.assertEqual(d.outcome, bt.ATTRIBUTED)
        self.assertEqual(d.writes["REMOTE_ADDR"], [f"{PEER}:43664", "203.0.113.21:43664"])
        self.assertEqual(d.writes["src_ip"], [PEER, "203.0.113.21"])
        self.assertEqual(d.writes["fleet_peer"], [None, PEER])
        self.assertEqual(d.writes["tunnel_attribution"], [None, "portbridge"])

    def test_dionaea_incident_rewrites_the_nested_connection(self):
        pb = portbridge(dial("203.0.113.22", 50556, T, "10.8.0.2:445"))
        doc = {"event": {"sensor": "dionaea"}, "honeypot": {"timestamp": iso(T + 1).rstrip("Z"), "data": {
            "connection": {"remote_ip": PEER, "remote_port": 50556, "local_port": 445, "transport": "tcp", "id": "c1"}}}}
        d = bt.decide(doc, pb, {})
        self.assertEqual((d.outcome, d.writes["data.connection.remote_ip"]), (bt.ATTRIBUTED, [PEER, "203.0.113.22"]))

    def test_one_ambiguous_link_side_makes_the_whole_incident_ambiguous(self):
        pb = portbridge(dial("203.0.113.22", 50556, T, "10.8.0.2:445"),
                        dial("203.0.113.23", 50557, T, "10.8.0.2:445"), dial("198.51.100.23", 50557, T, "10.8.0.2:445"))
        doc = {"event": {"sensor": "dionaea"}, "honeypot": {"timestamp": iso(T + 1).rstrip("Z"), "data": {
            "parent": {"remote_ip": PEER, "remote_port": 50556, "local_port": 445},
            "child": {"remote_ip": PEER, "remote_port": 50557, "local_port": 445}}}}
        d = bt.decide(doc, pb, {})
        self.assertEqual(d.outcome, bt.AMBIGUOUS)
        self.assertEqual(d.writes, {"tunnel_attribution": [None, "ambiguous"]}, "no partial attribution is written")

    def test_a_session_joins_on_when_it_opened(self):
        # The closing line ten minutes on would otherwise meet an unrelated
        # dial that reused the port a second before it.
        pb = portbridge(dial("203.0.113.24", 48133, T), dial("198.51.100.24", 48133, T + 599, "10.8.0.2:445"))
        starts = {}
        connect, closed = cowrie("s1", 48133, T + 1), cowrie("s1", 48133, T + 600, "cowrie.session.closed")
        for doc in (closed, connect):  # order must not matter
            bt.record_start(starts, doc)
        self.assertEqual(bt.decide(closed, pb, starts).writes["src_ip"], [PEER, "203.0.113.24"])
        # Unanchored, the rival sits in the line's own window -- and it is a
        # dial to 445, which cowrie's telnet port (2223 -> 19023) rules out.
        self.assertEqual(bt.decide(closed, pb, {}).outcome, bt.UNMATCHED, "never the stranger")


class FakeES:
    def __init__(self, pb_hits, hp_hits):
        self.pb_hits, self.hp_hits, self.updates = pb_hits, hp_hits, []

    def scan(self, index, query, source, page=10000):
        hits = self.pb_hits if index == bt.PORTBRIDGE_INDEX else self.hp_hits
        for i, (idx, src) in enumerate(hits):
            yield {"_index": idx, "_id": f"d{i}", "_source": src}

    def request(self, method, path, body=None, timeout=300):
        self.updates.append((method, path, body))
        return {"updated": len(body["query"]["ids"]["values"]), "noops": 0, "version_conflicts": 0, "failures": []}


class Run(unittest.TestCase):
    def fixture(self):
        pb = [("portbridge-v2-x", dial("203.0.113.30", 48140, T)),
              ("portbridge-v2-x", dial("203.0.113.31", 48141, T - 1)),
              ("portbridge-v2-x", dial("198.51.100.31", 48141, T))]
        pb += [("portbridge-v2-x", dial("192.0.2.250", 1, t)) for t in range(T - 3600, T + 3600, 60)]
        hp = [(".ds-honeypot-v2-a", cowrie("a", 48140, T + 1)),
              (".ds-honeypot-v2-a", cowrie("b", 48141, T + 1)),
              (".ds-honeypot-v2-a", cowrie("c", 48142, T + 1)),
              (".ds-honeypot-v2-a", {"event": {"sensor": "cowrie"}, "honeypot": {"src_ip": "127.0.0.1", "src_port": 9}})]
        return FakeES(pb, hp)

    def test_the_dry_run_counts_every_outcome_and_writes_nothing(self):
        es = self.fixture()
        report = bt.run(es, None, None, [], log=lambda m: None)
        self.assertEqual(report["per_sensor"]["cowrie"],
                         {bt.ATTRIBUTED: 1, bt.AMBIGUOUS: 1, bt.UNMATCHED: 1, bt.LOOPBACK: 1})
        self.assertEqual(es.updates, [], "a dry run sends no request")
        self.assertIn("TOTAL", bt.render(report))

    def test_apply_writes_only_the_attributed_through_the_ingest_pipeline(self):
        es = self.fixture()
        report = bt.run(es, None, None, [], apply=True, log=lambda m: None)
        self.assertEqual(len(es.updates), 1)
        method, path, body = es.updates[0]
        self.assertEqual(method, "POST")
        self.assertTrue(path.startswith("/.ds-honeypot-v2-a/_update_by_query?pipeline=geoip-honeypot&conflicts=proceed"))
        self.assertEqual(body["query"]["ids"]["values"], ["d0"])
        self.assertEqual(body["script"]["params"]["docs"]["d0"]["src_ip"], [PEER, "203.0.113.30"])
        self.assertEqual(report["written"]["updated"], 1)

    def test_mark_unattributed_labels_the_ambiguous_and_unmatched_too(self):
        es = self.fixture()
        bt.run(es, None, None, [], apply=True, mark_unattributed=True, log=lambda m: None)
        docs = es.updates[0][2]["script"]["params"]["docs"]
        self.assertEqual(docs["d1"], {"tunnel_attribution": [None, "ambiguous"]})
        self.assertEqual(docs["d2"], {"tunnel_attribution": [None, "unmatched"]})
        self.assertNotIn("d3", docs, "a healthcheck is not a tunnel event and is left alone")


if __name__ == "__main__":
    unittest.main()
