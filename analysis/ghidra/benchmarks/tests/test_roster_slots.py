#!/usr/bin/env python3
"""Roster runs retain independent results for every requested slot."""

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
ROSTER_RUNNER = Path("/home/xore/roster_run.py")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate_models = load_module(BENCHMARKS_DIR / "evaluate-models.py", "roster_evaluate_models")

# The current runner reads its plan while importing. Stub that operator input so
# this test never depends on or mutates the live roster state.
with patch("pathlib.Path.read_text", return_value='{"roster": [], "shortlist": []}'), \
     patch("pathlib.Path.mkdir"):
    roster_run = load_module(ROSTER_RUNNER, "roster_run_under_test")


class RosterRunnerSlotsTest(unittest.TestCase):
    def run_stubbed(self, slot_results, returncode=0):
        report = {"models": [{"model": "model:tag", "slots": slot_results}]}
        commands = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, returncode, json.dumps(report), "")

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            with patch.object(roster_run, "OUT_DIR", out_dir), \
                 patch.object(roster_run, "LOG", out_dir / "roster.log"), \
                 patch.object(roster_run.subprocess, "run", side_effect=fake_run), \
                 patch.object(roster_run, "sync_to_homeserver"):
                records = roster_run.run_one(
                    "model:tag", "roster", ("ghidra", "sessions", "revdeck", "coder")
                )
        return commands[0], records

    def test_requests_and_reads_back_all_four_slots(self):
        command, records = self.run_stubbed({
            "ghidra": {"ok": True, "score": {"percent": 90.0}},
            "sessions": {"ok": True, "score": {"percent": 80.0}},
            "revdeck": {"ok": True, "score": {"percent": 70.0}},
            "coder": {"ok": True, "score": {"percent": None}},
        })

        self.assertEqual(
            command[command.index("--slots") + 1], "ghidra,sessions,revdeck,coder"
        )
        self.assertEqual(
            [(record["slot"], record["status"]) for record in records],
            [("ghidra", "ok"), ("sessions", "ok"),
             ("revdeck", "ok"), ("coder", "ok")],
        )

    def test_coder_capability_skip_keeps_other_slot_results(self):
        _command, records = self.run_stubbed({
            "ghidra": {"ok": True, "score": {"percent": 90.0}},
            "sessions": {"ok": True, "score": {"percent": 80.0}},
            "revdeck": {"ok": True, "score": {"percent": 70.0}},
            "coder": {
                "ok": False,
                "skipped": True,
                "skip_reason": "model does not support tools",
                "error": "HTTPError: model does not support tools",
            },
        }, returncode=1)

        self.assertEqual([record["status"] for record in records[:3]], ["ok"] * 3)
        self.assertEqual(records[3]["slot"], "coder")
        self.assertEqual(records[3]["status"], "skipped")
        self.assertIn("does not support tools", records[3]["reason"])

    def test_a_coder_only_report_does_not_skip_the_new_four_slot_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "model.json"
            report_path.write_text(json.dumps({
                "models": [{"slots": {"coder": {"ok": True}}}],
            }))
            self.assertFalse(roster_run.has_results_for(
                report_path, ("ghidra", "sessions", "revdeck", "coder")
            ))

            report_path.write_text(json.dumps({
                "models": [{"slots": {
                    "ghidra": {"ok": True},
                    "sessions": {"ok": True},
                    "revdeck": {"ok": True},
                    "coder": {"ok": False, "skipped": True},
                }}],
            }))
            self.assertTrue(roster_run.has_results_for(
                report_path, ("ghidra", "sessions", "revdeck", "coder")
            ))


class CoderCapabilityResultTest(unittest.TestCase):
    def test_ollama_tool_rejection_is_a_capability_skip_with_its_reason(self):
        error = urllib.error.HTTPError(
            "http://ollama/api/chat",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"error":"model does not support tools"}'),
        )
        request = evaluate_models.qualification_request("coder", 8192)
        with patch.object(evaluate_models, "model_artifact", return_value={"tag": "model:tag"}), \
             patch.object(evaluate_models, "score_coder", side_effect=error), \
             patch.object(evaluate_models, "unload"):
            result = evaluate_models.evaluate_slot(
                "http://ollama", "coder", "model:tag", request
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertIn("does not support tools", result["skip_reason"])

    def test_quality_gate_failure_is_not_a_capability_skip(self):
        request = evaluate_models.qualification_request("coder", 8192)
        cases = [{
            "case": "unfinished",
            "capped": True,
            "output": {"tokens_per_second": 1.0},
        }]
        with patch.object(evaluate_models, "model_artifact", return_value={"tag": "model:tag"}), \
             patch.object(evaluate_models, "score_coder", return_value=cases), \
             patch.object(evaluate_models, "ollama_ps", return_value={}), \
             patch.object(evaluate_models, "nvidia_memory", return_value=None), \
             patch.object(evaluate_models, "system_memory_used", return_value=None), \
             patch.object(evaluate_models, "unload"):
            result = evaluate_models.evaluate_slot(
                "http://ollama", "coder", "model:tag", request
            )

        self.assertFalse(result["ok"])
        self.assertNotIn("skipped", result)
        self.assertIn("done_reason other than 'stop'", result["error"])


if __name__ == "__main__":
    unittest.main()
