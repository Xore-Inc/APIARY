#!/usr/bin/env python3
"""A tool call llama.cpp's PEG parser rejects must not abort the coder slot.

`baronllm-llama3.1:q6_k` answers the coder contract with
`{"name":"main","parameters":{}}` -- a tool it was never offered -- and
llama-server rejects the whole generation with a 500. Verified live; the body is
in tests/fixtures/llamacpp_structured_capture.json under `coder-first-case-tools`.

That is a capability result for that model, the same class of fact as `does not
support tools`. It is NOT a transport failure, and treating it as one cost the
whole run: the exception escaped chat() on case 1 of 44, so the model was left
with no coder record at all. These tests pin the three things that must hold --
the case is recorded, the slot finishes, and the cause is named.
"""

import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# evaluate-models.py is hyphenated; the tests load it under a plain name.
_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(Path(__file__).resolve().parents[1] / "evaluate-models.py"))
em = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("evaluate_models", em)
_spec.loader.exec_module(em)

import serving  # noqa: E402


def _peg_body() -> dict:
    """The exact body the live server returned, as a dict.

    Read off `docker logs` on the live llama-server, not invented: the message
    sits at `error.message` and there is no top-level `message`.
    """
    return {
        "error": {
            "code": 500,
            "message": "The model produced output that does not match the "
                       "expected peg-native format",
            "type": "server_error",
        }
    }


def _peg_error() -> urllib.error.HTTPError:
    """The exact failure the live server returns, as urllib raises it.

    `fp` is a single-use stream, which is why the body may only be read once --
    the same shape as a real urlopen failure.
    """
    return urllib.error.HTTPError(
        "http://stub:8080/v1/chat/completions", 500, "Internal Server Error",
        {}, io.BytesIO(json.dumps(_peg_body()).encode()),
    )


def _raise_peg_error(url, body=None, timeout=None):
    raise _peg_error()


class ClassificationTest(unittest.TestCase):
    def test_the_live_500_body_is_a_malformed_tool_call(self):
        self.assertTrue(serving.is_malformed_tool_call(
            "The model produced output that does not match the expected "
            "peg-native format"))

    def test_a_transport_failure_is_not_a_malformed_tool_call(self):
        """Only the PEG rejection is a capability. A timeout, an OOM and a
        connection reset are not, and recording one of those as a model
        capability would be a different wrong substitution."""
        for text in ("timed out", "CUDA error: out of memory",
                     "Connection reset by peer", "model is not loaded"):
            self.assertFalse(serving.is_malformed_tool_call(text), text)


class ErrorBodyShapeTest(unittest.TestCase):
    """Both engines nest the cause differently, and reading only one of them
    made a llama.cpp 500 indistinguishable from any other 500.

    llama.cpp answers `{"error": {"code": 500, "message": ...}}`; Ollama answers
    a bare `{"error": "..."}`. Reading the top-level `message` -- or
    interpolating `error` directly, which puts a whole dict in the sentence --
    found nothing on every llama.cpp failure. That is how the first version of
    the malformed-tool-call path shipped broken and the 500 escaped anyway.
    """

    def test_the_nested_llamacpp_shape_is_read(self):
        """The cause is at `error.message`, and there is no top-level `message`
        key at all. Asserting only the outcome was not enough: a reader that
        found the cause by another route still passed while the nested read --
        the thing actually under test -- was gone."""
        body = _peg_body()
        self.assertNotIn("message", body, "the nested shape has no top-level message")
        self.assertEqual(body["error"]["code"], 500)
        self.assertIn("peg-native", em._http_error_detail(_peg_error()))

    def test_the_flat_ollama_shape_is_read(self):
        exc = urllib.error.HTTPError(
            "http://stub:11434/api/chat", 400, "Bad Request", {},
            io.BytesIO(json.dumps({"error": "model does not support tools"}).encode()),
        )
        self.assertEqual(em._http_error_detail(exc), "model does not support tools")

    def test_a_bodyless_error_is_none(self):
        exc = urllib.error.HTTPError(
            "http://stub:11434/api/chat", 500, "Internal Server Error", {},
            io.BytesIO(b""),
        )
        self.assertIsNone(em._http_error_detail(exc))


class ChatAbsorbsTheRejectionTest(unittest.TestCase):
    def test_chat_returns_a_result_instead_of_raising(self):
        result = em.chat(
            "http://stub:11434", "test-model:latest", em.CODER_TOOL_SYSTEM,
            "write main.rs", 8192, False, num_predict=512,
            tools=list(__import__("bench_tools").FILE_TOOLS),
            transport=_raise_peg_error,
        )
        self.assertEqual(result["done_reason"], "malformed_tool_call")
        self.assertIn("peg-native", result["malformed_tool_call"])
        # No tokens, because the generation was rejected, not shortened. A
        # reader that saw tokens here would read a truncated answer.
        self.assertIsNone(result["output_tokens"])

    def test_a_transport_failure_still_raises(self):
        """The fix is narrow on purpose: a timeout is a real transport failure
        and the slot's existing error path still owns it."""
        def boom(url, body=None, timeout=None):
            raise TimeoutError("timed out")

        with self.assertRaises(TimeoutError):
            em.chat("http://stub:11434", "test-model:latest", em.CODER_TOOL_SYSTEM,
                    "write main.rs", 8192, False, num_predict=512,
                    tools=[{"type": "function", "function": {"name": "write_file",
                              "parameters": {"type": "object"}}}],
                    transport=boom)

    def test_a_no_tools_slot_is_unaffected(self):
        """A slot that offered no tools cannot have emitted a malformed tool
        call, so the same 500 stays a transport failure there."""
        with self.assertRaises(urllib.error.HTTPError):
            em.chat("http://stub:11434", "test-model:latest", em.REV_SYSTEM,
                    "analyse", 8192, False, num_predict=512,
                    transport=_raise_peg_error)


class TheRecordTest(unittest.TestCase):
    def _run_coder_slot(self, transport):
        from transcripts import Reproducibility, RunMetadata, SlotRecorder, TranscriptWriter

        run = RunMetadata(benchmark="test", provenance="synthetic")
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="coder",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    # The real slot always passes `engine=session.engine`; this
                    # mirrors it, so the record here is shaped like the records
                    # a run writes rather than like a recorder that forgot it.
                    reproducibility=Reproducibility(tier="A", engine="llama.cpp"),
                )
                cases = em.score_coder("http://stub:11434", "test-model:latest",
                                       8192, recorder, None, transport)
            lines = [json.loads(line) for line
                     in writer.path.read_text(encoding="utf-8").splitlines() if line]
        return cases, lines

    def test_the_slot_finishes_and_every_case_is_scored(self):
        """The whole bug: one 500 on case 1 used to end the run, leaving the
        model with no coder score at all."""
        cases, _ = self._run_coder_slot(_raise_peg_error)
        self.assertEqual(len(cases), len(em.CODER_CASES))
        for case in cases:
            self.assertIsNotNone(case["case"])
            # Still a pending human review, never an automated zero: a
            # capability result is not a score.
            self.assertEqual(case["grading_status"], "pending_human_review")

    def test_the_failure_and_its_cause_are_recorded(self):
        cases, lines = self._run_coder_slot(_raise_peg_error)
        first = cases[0]
        self.assertEqual(first["stopped_because"], "malformed_tool_call")
        self.assertIn("peg-native", first["malformed_tool_call"])
        self.assertEqual(first["capability"],
                         "emits_tool_calls_the_server_rejects")
        # The round loop stopped rather than re-sending the same prompt to a
        # model that 500s every time.
        self.assertEqual(first["round_count"], 1)
        # And the transcript line carries the same cause, so a reader of the
        # run file is not left with a bare 500.
        peg = [line for line in lines if line.get("error")
               and "peg-native" in line["error"]]
        self.assertTrue(peg, "the rejection reached the transcript")
        self.assertNotEqual(peg[0]["outcome"], "ok")

    def test_the_record_still_names_the_engine_that_refused(self):
        """A capability result is still an answer from an engine. The record
        must name the one that produced it, or a llama.cpp row that was refused
        by llama.cpp reads as an unattributed gap."""
        _, lines = self._run_coder_slot(_raise_peg_error)
        peg = [line for line in lines if line.get("error")
               and "peg-native" in line["error"]]
        self.assertTrue(peg[0]["reproducibility"]["engine"])


if __name__ == "__main__":
    unittest.main()
