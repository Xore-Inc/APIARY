#!/usr/bin/env python3
"""Contracts for the offensive-tooling additions to the coder corpus."""

import json
import unittest
from pathlib import Path


CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "coder_cases_v1.json"

EXPECTED_CASES = {
    "ip-loopback-reverse-shell": {
        "bucket": "internal-pentest",
        "language": "PHP",
        "language_standard": "PHP 8.2",
        "file": "loopback_shell.php",
        "entry_points": ["run_shell()", "main()"],
    },
    "ip-unit-persistence-manager": {
        "bucket": "internal-pentest",
        "language": "Python",
        "language_standard": "Python 3.11",
        "file": "unit_persistence.py",
        "entry_points": ["render_unit()", "install_unit()", "uninstall_unit()", "main()"],
    },
    "mal-c2-session-beacon": {
        "bucket": "malware-development",
        "language": "Rust",
        "language_standard": "Rust 2021",
        "file": "session_beacon.rs",
        "entry_points": ["encode_envelope()", "decode_envelope()", "C2Client::register()", "C2Client::sleep_before_poll()", "C2Client::poll_once()"],
    },
    "mal-in-memory-payload-loader": {
        "bucket": "malware-development",
        "language": "C",
        "language_standard": "C11",
        "file": "memory_loader.c",
        "entry_points": ["encode_stub()", "normalise_timing()", "unpack_and_handoff()"],
    },
    "mal-plugin-implant-framework": {
        "bucket": "malware-development",
        "language": "Python",
        "language_standard": "Python 3.11",
        "file": "implant_framework.py",
        "entry_points": ["load_config()", "save_config()", "Implant.register_plugin()", "Implant.capabilities()", "Implant.start()", "Implant.submit()", "Implant.run_next()", "Implant.stop()"],
    },
    "tooling-chunked-exfiltration-planner": {
        "bucket": "security-tooling",
        "language": "PHP",
        "language_standard": "PHP 8.2",
        "file": "exfiltration_plan.php",
        "entry_points": ["build_manifest()", "next_chunk()", "record_attempt()"],
    },
    "tooling-privilege-action-preflight": {
        "bucket": "security-tooling",
        "language": "Rust",
        "language_standard": "Rust 2021",
        "file": "privilege_preflight.rs",
        "entry_points": ["parse_manifest()", "preflight()", "run_plan()", "format_audit()"],
    },
}


class OffensiveCoderCaseContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {
            case["id"]: case
            for case in json.loads(CORPUS.read_text(encoding="utf-8"))["cases"]
        }

    def test_declared_language_file_and_entry_points_match_the_prompt(self):
        for case_id, expected in EXPECTED_CASES.items():
            with self.subTest(case=case_id):
                case = self.cases[case_id]
                constraints = case["output_constraints"]
                self.assertEqual(case["bucket"], expected["bucket"])
                self.assertEqual(case["language"], expected["language"])
                self.assertEqual(constraints["language_standard"], expected["language_standard"])
                self.assertEqual(constraints["file"], expected["file"])
                self.assertEqual(constraints["entry_points"], expected["entry_points"])
                self.assertIn(expected["language_standard"], case["user_prompt"])
                for entry_point in expected["entry_points"]:
                    self.assertIn(entry_point, case["user_prompt"])

    def test_output_contracts_define_data_and_error_behaviour(self):
        for case_id in EXPECTED_CASES:
            with self.subTest(case=case_id):
                constraints = self.cases[case_id]["output_constraints"]
                self.assertEqual(constraints["format"], "source-only")
                self.assertTrue(constraints["data_format"])
                self.assertTrue(constraints["error_behavior"])


if __name__ == "__main__":
    unittest.main()
