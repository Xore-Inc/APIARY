#!/usr/bin/env python3
"""The coder slot asks the server what a model can do before it sends a tools request.

Capability used to be discovered by failing: the harness posted a tools array,
read the rejection, and recorded a skip only after a model load and a failed
generation had been spent -- with a skip that nothing surfaced, so a capability
gap and an opaque 500 read the same in the run's output. `/api/show` reports
`capabilities` up front, so the verdict can be reached without the round trip.
"""

import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate_models = load_module(BENCHMARKS_DIR / "evaluate-models.py", "capability_evaluate_models")
sys.path.insert(0, str(BENCHMARKS_DIR))
import transcripts  # noqa: E402 -- the harness imports it by path, so set the path first


class CapabilityProbeTest(unittest.TestCase):
    """model_capabilities: three answers, not two."""

    def assert_capabilities(self, response, expected):
        with patch.object(evaluate_models, "request_json", return_value=response):
            self.assertEqual(evaluate_models.model_capabilities("http://ollama", "m:t"), expected)

    def test_reports_the_advertised_capabilities(self):
        self.assert_capabilities(
            {"capabilities": ["completion", "tools", "thinking"]},
            ["completion", "tools", "thinking"],
        )

    def test_a_server_that_sends_no_capabilities_is_unknown_not_empty(self):
        # The distinction that matters: [] is a verdict that would skip the slot,
        # and an absent key is not one. Ollama before /api/show reported
        # capabilities simply has no such field.
        self.assert_capabilities({"modelfile": "FROM x", "details": {}}, None)

    def test_a_non_list_capabilities_field_is_unknown(self):
        self.assert_capabilities({"capabilities": "tools"}, None)

    def test_a_failing_or_absent_endpoint_is_unknown(self):
        for failure in (
            urllib.error.URLError("connection refused"),
            TimeoutError("timed out"),
            ValueError("expected object"),
            OSError("broken pipe"),
        ):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(evaluate_models, "request_json", side_effect=failure):
                self.assertIsNone(evaluate_models.model_capabilities("http://ollama", "m:t"))

    def test_it_posts_a_body_because_get_is_rejected(self):
        # Measured on 0.32.13: GET /api/show is 405 method not allowed. A GET
        # here would read as "endpoint absent" and silently disable the probe
        # on every server.
        with patch.object(evaluate_models, "request_json") as request_json:
            request_json.return_value = {"capabilities": ["tools"]}
            evaluate_models.model_capabilities("http://ollama", "m:t")
        url, body = request_json.call_args[0]
        self.assertEqual(url, "http://ollama/api/show")
        self.assertEqual(body, {"model": "m:t"})


class CoderSlotPreflightTest(unittest.TestCase):
    """score_coder is the slot body; the probe's whole claim is that it is
    never reached for a model that cannot serve tools."""

    def run_slot(self, capabilities, *, raises=None):
        """Run the coder slot with `capabilities` as the probe's verdict.

        `raises` makes score_coder throw instead of returning cases, which is
        how the advertising-but-rejecting model reaches the existing 400 handler.
        """
        request = evaluate_models.qualification_request("coder", 8192)
        stub = patch.object(
            evaluate_models, "score_coder",
            side_effect=raises if raises is not None else [self.clean_cases()],
        )
        with patch.object(evaluate_models, "model_artifact", return_value={"tag": "m:t"}), \
             patch.object(evaluate_models, "model_capabilities", return_value=capabilities), \
             stub as scored, \
             patch.object(evaluate_models, "ollama_ps", return_value={}), \
             patch.object(evaluate_models, "nvidia_memory", return_value=None), \
             patch.object(evaluate_models, "system_memory_used", return_value=None), \
             patch.object(evaluate_models, "unload"):
            result = evaluate_models.evaluate_slot("http://ollama", "coder", "m:t", request)
        self.slot_ran = scored.called
        return result

    def clean_cases(self):
        """One finished coder case, so an attempted slot reports ok."""
        return [{
            "case": evaluate_models.CODER_CASES[0].name,
            "capped": False,
            "output": {"tokens_per_second": 1.0},
        }]

    def test_a_model_without_tools_is_skipped_without_the_slot_running(self):
        result = self.run_slot(["completion"])

        self.assertFalse(self.slot_ran, "the slot ran for a model that cannot serve tools")
        self.assertFalse(result["ok"])
        self.assertTrue(result["skipped"])
        # The reason names the capability that is actually absent and what the
        # server said -- not a hardcoded "does not support tools" that would
        # still read correctly if the verdict were for some other capability.
        self.assertIn("does not support tools", result["skip_reason"])
        self.assertIn("[completion]", result["skip_reason"])
        # The existing roster contract reads skip_reason; run() prints it.
        self.assertEqual(evaluate_models.slot_summary(result),
                         f"skipped: {result['skip_reason']}")

    def test_a_tools_capable_model_still_runs_the_slot(self):
        result = self.run_slot(["completion", "tools"])

        self.assertTrue(self.slot_ran)
        self.assertNotIn("skipped", result)
        self.assertTrue(result["ok"])
        self.assertIn("pending human review", evaluate_models.slot_summary(result))

    def test_an_unknown_verdict_runs_the_slot_rather_than_skipping_a_capable_model(self):
        # The fallback the probe exists to be safe under: an old server, an
        # absent endpoint, a failed request. Skipping here would be a false
        # negative the run can never correct, and today's behaviour -- send the
        # tools request and let the 400 handler decide -- is the correct one.
        result = self.run_slot(None)

        self.assertTrue(self.slot_ran)
        self.assertNotIn("skipped", result)
        self.assertTrue(result["ok"])

    def test_the_advertising_but_rejecting_model_still_reaches_the_existing_catch(self):
        # The probe is a fast path, not a replacement: a model can claim tools
        # and reject them, and that handler is what turns it into a skip.
        rejection = urllib.error.HTTPError(
            "http://ollama/api/chat", 400, "Bad Request", {},
            io.BytesIO(b'{"error":"model does not support tools"}'),
        )
        result = self.run_slot(["tools"], raises=rejection)

        self.assertTrue(self.slot_ran)
        self.assertTrue(result["skipped"])
        self.assertIn("does not support tools", result["skip_reason"])

    def test_the_existing_catch_is_unconditional_about_the_probe(self):
        source = (BENCHMARKS_DIR / "evaluate-models.py").read_text(encoding="utf-8")
        self.assertIn('exc.code == 400 and "does not support tools" in error.lower()', source)


class NonCoderSlotsAreUntouchedTest(unittest.TestCase):
    def test_prose_slots_are_never_probed(self):
        # ghidra/sessions/revdeck send plain text. A probe there would skip a
        # capable model over a capability none of them need.
        for slot in ("ghidra", "sessions", "revdeck"):
            with self.subTest(slot=slot), \
                 patch.object(evaluate_models, "model_artifact", return_value={"tag": "m:t"}), \
                 patch.object(evaluate_models, "model_capabilities") as probe, \
                 patch.object(evaluate_models, "ollama_ps", return_value={}), \
                 patch.object(evaluate_models, "nvidia_memory", return_value=None), \
                 patch.object(evaluate_models, "system_memory_used", return_value=None), \
                 patch.object(evaluate_models, "unload"):
                evaluate_models.evaluate_slot(
                    "http://ollama", slot, "m:t",
                    evaluate_models.qualification_request(
                        slot, 16384 if slot == "ghidra" else 8192),
                )
        probe.assert_not_called()


class ProbeIsRecordedTest(unittest.TestCase):
    """A skip must be reconstructable from the run artifacts, not inferred."""

    def run_with_writer(self, capabilities):
        """Run the coder slot with a real transcript writer attached.

        Returns (records, slot_ran). The writer is the artifact the run's
        evidence lives in, so a probe that only shows up when one is passed is
        not a probe the run records.
        """
        request = evaluate_models.qualification_request("coder", 8192)
        with tempfile.TemporaryDirectory() as tmp:
            writer = evaluate_models.TranscriptWriter(
                tmp, evaluate_models.RunMetadata(
                    benchmark=evaluate_models.BENCHMARK_VERSION,
                    provenance=transcripts.PROVENANCE_LIVE_MODEL,
                ))
            with patch.object(evaluate_models, "model_artifact", return_value={"tag": "m:t"}), \
                 patch.object(evaluate_models, "model_capabilities", return_value=capabilities), \
                 patch.object(evaluate_models, "score_coder") as score_coder, \
                 patch.object(evaluate_models, "unload"):
                evaluate_models.evaluate_slot(
                    "http://ollama", "coder", "m:t", request, writer)
            slot_ran = score_coder.called
            summary = writer.close()
            records = [json.loads(line) for line in
                       Path(summary["transcripts"]).read_text().splitlines() if line.strip()]
        return records, slot_ran

    def probe_records(self, records):
        found = [r for r in records if r["case"] == evaluate_models.CAPABILITY_PROBE_CASE]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_a_skip_leaves_the_capability_verdict_in_the_transcript(self):
        records, slot_ran = self.run_with_writer(["completion"])
        self.assertFalse(slot_ran)

        record = self.probe_records(records)
        # The verdict itself, so the skip is readable from the file.
        self.assertEqual(record["response"]["message"], {"capabilities": ["completion"]})
        # The request body that produced it, so it can be re-derived.
        self.assertEqual(record["request"]["body"], {"model": "m:t"})
        self.assertIsNone(record["error"])
        # A skip is not an error, and nothing downstream reads it as one.
        self.assertEqual(record["outcome"], transcripts.OUTCOME_OK)

    def test_a_capable_model_records_the_same_probe_for_the_same_reason(self):
        # The probe runs before the slot either way, so a run that did attempt
        # the slot carries the evidence for why it was allowed to.
        records, slot_ran = self.run_with_writer(["tools", "completion"])
        self.assertTrue(slot_ran)

        record = self.probe_records(records)
        self.assertEqual(record["response"]["message"]["capabilities"],
                         ["tools", "completion"])

    def test_an_unknown_verdict_is_stored_as_unknown_rather_than_omitted(self):
        # "The probe could not reach a verdict" is itself the evidence, and it
        # is what tells a reader the slot was attempted for want of an answer
        # rather than because the model refused.
        records, slot_ran = self.run_with_writer(None)
        self.assertTrue(slot_ran)

        record = self.probe_records(records)
        self.assertIsNone(record["response"]["message"]["capabilities"])

    def test_the_probe_case_is_not_a_coder_case_a_rescore_could_match(self):
        # rescore_from() matches stored case names against the frozen corpus, so
        # a probe record filed under a real case name would become an unmatched
        # entry or, worse, be scored as an answer.
        self.assertNotIn(
            evaluate_models.CAPABILITY_PROBE_CASE,
            {case.name for case in evaluate_models.CODER_CASES},
        )


if __name__ == "__main__":
    unittest.main()