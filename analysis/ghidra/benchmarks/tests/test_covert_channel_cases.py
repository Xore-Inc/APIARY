#!/usr/bin/env python3
"""Contracts for the covert-channel / C2-protocol coder corpus additions.

Every case in this group grades channel construction and traffic shaping, so
each one has to declare its own transport boundary. A declared entry point or
wire format that the prompt does not state makes the case ungradable, and a
case that reaches the network is out of scope for a corpus that never executes
model output.
"""

import hashlib
import json
import re
import unittest
from pathlib import Path


BENCH_DIR = Path(__file__).resolve().parents[1]
CORPUS_DIR = BENCH_DIR / "corpus"
CASES_PATH = CORPUS_DIR / "coder_cases_v1.json"
RUBRIC_PATH = CORPUS_DIR / "coder_cases_v1_rubric.json"
CONTRACT_PATH = CORPUS_DIR / "coder_cases_v1_contract.json"

BUCKETS = ("malware-development", "internal-pentest", "security-tooling")
GENERIC_CHECKS = ("deliverable_present", "functional_correctness",
                  "security_failure_handling", "completeness_readability")

# ATT&CK techniques the covert-channel group is required to cover, mapped to
# the sub-technique the case actually grades.
COVERT_CASES = {
    "mal-https-beacon-envelope": ("T1071.001", "malware-development", "Rust", "beacon_envelope.rs"),
    "mal-dns-covert-label-codec": ("T1071.004", "malware-development", "C", "dns_label_codec.c"),
    "mal-dns-query-shape-scheduler": ("T1071.004", "malware-development", "Python", "dns_query_scheduler.py"),
    "mal-c2-fallback-channel-selector": ("T1102", "malware-development", "Rust", "channel_selector.rs"),
    "mal-c2-exfil-chunk-backoff": ("T1041", "malware-development", "C", "exfil_chunks.c"),
    "mal-c2-bidi-framed-channel": ("T1041", "malware-development", "Python", "framed_channel.py"),
    "mal-layered-traffic-encoder": ("T1041", "malware-development", "C", "layered_encoder.c"),
    "mal-icmp-payload-framing": ("T1071", "malware-development", "C++", "icmp_framing.cpp"),
    "ip-c2-header-padding-normaliser": ("T1071.001", "internal-pentest", "Python", "header_padding.py"),
    "ip-dns-exfil-baseline-detector": ("T1071.004", "internal-pentest", "Python", "dns_exfil_detect.py"),
    "tooling-beacon-interval-analyser": ("T1071.001", "security-tooling", "Python", "beacon_analysis.py"),
    "tooling-covert-channel-differ": ("T1071", "security-tooling", "C++", "channel_differ.cpp"),
    "tooling-dns-tunnel-scorer": ("T1071.004", "security-tooling", "Rust", "dns_tunnel_score.rs"),
}

# Bounds a grader can check without a live channel. Each case must state at
# least one hard number for its channel or codec.
BOUNDED_PROMPT = re.compile(
    r"\b\d{1,7}\b"          # a max label length, frame size, backoff or percentage
)


class CovertChannelCaseContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]
        cls.cases = {case["id"]: case for case in cases}
        cls.order = [case["id"] for case in cases]
        cls.rubric = json.loads(RUBRIC_PATH.read_text(encoding="utf-8"))
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def test_group_is_present_and_lives_in_the_declared_buckets(self):
        for case_id, (_, bucket, _lang, _file) in COVERT_CASES.items():
            with self.subTest(case=case_id):
                self.assertIn(case_id, self.cases)
                self.assertEqual(self.cases[case_id]["bucket"], bucket)

    def test_declared_language_and_file_match_the_prompt(self):
        for case_id, (_tech, _bucket, language, filename) in COVERT_CASES.items():
            with self.subTest(case=case_id):
                case = self.cases[case_id]
                constraints = case["output_constraints"]
                self.assertEqual(case["language"], language)
                self.assertEqual(constraints["file"], filename)
                self.assertEqual(constraints["format"], "source-only")
                self.assertEqual(constraints["network_access"], False)
                self.assertEqual(constraints["external_commands"], False)
                self.assertTrue(constraints["must_not_claim_execution"])

    def test_entry_points_are_named_in_the_prompt(self):
        for case_id in COVERT_CASES:
            with self.subTest(case=case_id):
                case = self.cases[case_id]
                constraints = case["output_constraints"]
                entry_points = constraints["entry_points"]
                self.assertTrue(entry_points, "covert-channel cases must declare entry points")
                for entry_point in entry_points:
                    self.assertIn(
                        entry_point, case["user_prompt"],
                        f"{case_id} declares {entry_point} but the prompt never names it")

    def test_wire_format_and_error_behaviour_are_declared(self):
        for case_id in COVERT_CASES:
            with self.subTest(case=case_id):
                constraints = self.cases[case_id]["output_constraints"]
                self.assertTrue(constraints["data_format"])
                self.assertTrue(constraints["error_behavior"])

    def test_every_case_states_explicit_limits(self):
        """Vague cases produce vague grades: each prompt must carry hard numbers."""
        for case_id in COVERT_CASES:
            with self.subTest(case=case_id):
                self.assertRegex(self.cases[case_id]["user_prompt"], BOUNDED_PROMPT)

    def test_no_case_carries_a_real_host_or_credential(self):
        ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for case_id in COVERT_CASES:
            with self.subTest(case=case_id):
                prompt = self.cases[case_id]["user_prompt"]
                self.assertIsNone(ipv4.search(prompt))
                self.assertNotRegex(prompt, r"(?i)\b(password|secret|api[_-]?key)\s*[:=]\s*\S")

    def test_rubric_entries_are_present_frozen_and_unchanged_in_order(self):
        for case_id in COVERT_CASES:
            with self.subTest(case=case_id):
                entry = self.rubric["cases"][case_id]
                self.assertEqual(entry["bucket"], self.cases[case_id]["bucket"])
                self.assertEqual(entry["max_score"], len(GENERIC_CHECKS))
                self.assertEqual(tuple(entry["pass_anchors"]), GENERIC_CHECKS)
                for check in GENERIC_CHECKS:
                    self.assertEqual(len(entry["pass_anchors"][check]), 2)

    def test_contract_matches_the_final_file_bytes_and_order(self):
        cases_bytes = CASES_PATH.read_bytes()
        rubric_bytes = RUBRIC_PATH.read_bytes()
        self.assertEqual(self.contract["cases_sha256"],
                         hashlib.sha256(cases_bytes).hexdigest())
        self.assertEqual(self.contract["rubric_sha256"],
                         hashlib.sha256(rubric_bytes).hexdigest())
        self.assertEqual(self.contract["cases"], self.order)
        self.assertEqual(self.contract["case_count"], len(self.order))
        self.assertEqual(list(self.rubric["cases"]), self.order)
        self.assertEqual(self.contract["grading"]["max_score"],
                         len(self.order) * len(GENERIC_CHECKS))

    def test_existing_cases_survive_unchanged_and_new_ones_are_appended_in_bucket(self):
        """No existing case may be modified or deleted; new cases land at the
        end of their own bucket group so the declared bucket order still holds."""
        self.assertEqual(len(self.order), 64)
        first_new = min(self.order.index(cid) for cid in COVERT_CASES)
        for case_id in COVERT_CASES:
            self.assertGreaterEqual(self.order.index(case_id), first_new)
        for index, case_id in enumerate(self.order):
            if case_id in COVERT_CASES:
                continue
            self.assertNotIn(case_id, set(COVERT_CASES))
            self.assertEqual(self.rubric["cases"][case_id]["bucket"],
                             self.cases[case_id]["bucket"])
        # Every new case follows the last pre-existing case of its own bucket.
        for bucket in {self.cases[cid]["bucket"] for cid in COVERT_CASES}:
            indices = [i for i, c in enumerate(self.order)
                       if self.cases[c]["bucket"] == bucket]
            new_at = [i for i in indices if self.order[i] in COVERT_CASES]
            self.assertEqual(new_at, list(range(min(new_at), max(new_at) + 1)))
            self.assertTrue(new_at)


if __name__ == "__main__":
    unittest.main()