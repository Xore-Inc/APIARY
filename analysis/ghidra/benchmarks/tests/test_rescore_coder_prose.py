#!/usr/bin/env python3
"""A rescore must see what a live run saw: the coder scorer's own words.

`rescore_from()` rebuilds the coder scorer's `raw` by hand from a stored
transcript record. `chat()` records the model's words twice, under two keys
that are NOT interchangeable -- `content` is assistant_text(), which falls
back to serializing tool_calls when a turn produced no prose, and `prose` is
the model's own words. `_pending_coder_case()` and
write_coder_artifact_file() read `prose`.

When the rescore rebuilt only `content`, both consumers read "" on every
rescored run. Two failures, both silent:
  * the degenerate-repetition gate never fired, so a looping model scored as
    if it had answered;
  * no source file was written at all, so a rescored coder run yielded zero
    gradeable artifacts -- only compile-report.json.

These tests drive the real producer (chat() -> SlotRecorder ->
TranscriptWriter) and the real consumer (rescore_from()), so neither the
transcript fixture nor the expected shape can drift from what production does.
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(Path(__file__).resolve().parents[1] / "evaluate-models.py"))
evaluate_models = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("evaluate_models", evaluate_models)
_spec.loader.exec_module(evaluate_models)

import transcripts  # noqa: E402
from transcripts import (  # noqa: E402
    PROVENANCE_SYNTHETIC,
    Reproducibility,
    RunMetadata,
    SlotRecorder,
    TranscriptWriter,
)

CODER_ARTIFACTS_DIRNAME = evaluate_models.CODER_ARTIFACTS_DIRNAME

# A looped emit: the same statement over and over, which is what the
# degenerate gate exists to catch. Alignment matters -- the sampling stride is
# 20, so the block is padded to a multiple of it.
LOOP = ("for (uint32_t i=0;i<node.tri_count;++i){const auto& t=mesh.triangles[node.first_tri+i];"
        "if(trace(t)){hit.distance=t;break;}}")
LOOPED = (LOOP + " " * (20 - len(LOOP) % 20)) * 12

CLEAN = ("fn main() {\n    let mut total = 0u32;\n    for i in 0..10 { total += i; }\n"
         "    println!(\"{}\", total);\n}\n")


def write_coder_run(root, answer, message_content=None):
    """One coder-slot record written through the real producer.

    `answer` is what chat() stored as `response.raw` (assistant_text()).
    `message_content` is the assistant turn's own words, which is what `prose`
    is derived from. A record written by a real chat() always carries both;
    `message_content=None` models a legacy row stored before `message` was
    persisted, where `raw` is the only evidence there is.
    """
    case = evaluate_models.CODER_CASES[0]
    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
    with TranscriptWriter(root, run) as writer:
        recorder = SlotRecorder(
            writer=writer, slot="coder",
            model={"tag": "test-model:latest", "digest": "d" * 64},
            reproducibility=Reproducibility(tier="A"),
        )
        message = {"role": "assistant"}
        if message_content is not None:
            message["content"] = message_content
        recorder.record(
            case=case.name, workflow="coder_generation",
            request_body={"messages": [{"role": "user", "content": case.prompt}]},
            response={
                "content": answer,
                "message": message,
                "prose": (message_content or "").strip(),
                "output_tokens": 512,
                "done_reason": "stop",
            },
        )
    return writer.directory


class RescoreCoderProseTest(unittest.TestCase):
    """The two consumers of `prose` must see it on a rescore, not just live."""

    def _live_and_rescored(self, answer, message_content=None):
        case = evaluate_models.CODER_CASES[0]
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_coder_run(tmp, answer, message_content)
            report = evaluate_models.rescore_from(run_dir)
            rescored = report["models"]["test-model:latest"]["coder"]["cases"][case.name]
            # The artifact set is the second consumer: write_coder_artifact_file
            # reads the same `record["output"]["prose"]`, and produced nothing at
            # all when the rescore left the key unset.
            written = evaluate_models.write_coder_artifacts(
                _Writer(run_dir), {"tag": "test-model:latest"}, {case.name: rescored})
            root = run_dir / CODER_ARTIFACTS_DIRNAME / "test-model:latest"
            artifacts = sorted(p.name for p in root.iterdir()
                               if p.name != "compile-report.json")
        live = evaluate_models._pending_coder_case(
            case, {"content": answer, "prose": (message_content or answer).strip(),
                   "done_reason": "stop"})
        return live, rescored, artifacts, written

    def test_a_looped_rescored_answer_is_still_flagged_degenerate(self):
        live, rescored, _, _ = self._live_and_rescored(LOOPED, LOOPED)
        self.assertTrue(live["degenerate"])
        self.assertEqual(rescored["degenerate"], live["degenerate"])
        self.assertEqual(rescored["repetition_ratio"], live["repetition_ratio"])

    def test_a_rescored_coder_run_yields_the_same_artifact_set(self):
        case = evaluate_models.CODER_CASES[0]
        with tempfile.TemporaryDirectory() as tmp:
            live_record = evaluate_models._pending_coder_case(
                case, evaluate_models._rescore_raw({"response": {"raw": CLEAN},
                                                     "timing": {"done_reason": "stop"}}))
            run_dir = write_coder_run(tmp, CLEAN, CLEAN)
            report = evaluate_models.rescore_from(run_dir)
            rescored = report["models"]["test-model:latest"]["coder"]["cases"][case.name]
            live_n = evaluate_models.write_coder_artifacts(
                _Writer(run_dir / "live"), {"tag": "m"}, {case.name: live_record})
            rescore_n = evaluate_models.write_coder_artifacts(
                _Writer(run_dir), {"tag": "m"}, {case.name: rescored})
            root = run_dir / CODER_ARTIFACTS_DIRNAME / "m"
            artifacts = sorted(p.name for p in root.iterdir()
                               if p.name != "compile-report.json")
            graded = (root / f"{case.name}.rs").read_text()
        self.assertGreater(live_n, 0)
        self.assertEqual(rescore_n, live_n)
        self.assertEqual(artifacts, [f"{case.name}.rs"])
        self.assertIn("fn main()", graded)

    def test_tool_call_serialization_is_never_scored_as_source(self):
        """`content` is allowed to hold a serialized tool call; `prose` is not.

        This is why the fix is not "fall back to `content`": with only a
        serialized call in `content`, the rescore must still see the model's
        real words from `message`, and the artifact must hold prose rather than
        a JSON blob.
        """
        call = json.dumps({"function": {"name": "write_file", "arguments": {}}})
        _, rescored, artifacts, written = self._live_and_rescored(call, CLEAN)
        self.assertFalse(rescored["output"]["prose"].startswith("{"))
        self.assertEqual(rescored["output"]["prose"], CLEAN.strip())
        self.assertEqual(written, 1)
        self.assertEqual(artifacts, [f"{evaluate_models.CODER_CASES[0].name}.rs"])

    def test_a_legacy_record_without_a_stored_message_still_scores(self):
        """Rows written before `message` was persisted have only `raw`."""
        _, rescored, artifacts, written = self._live_and_rescored(LOOPED, None)
        self.assertTrue(rescored["degenerate"])
        self.assertEqual(written, 1)
        self.assertEqual(artifacts, [f"{evaluate_models.CODER_CASES[0].name}.rs"])


class _Writer:
    """The one attribute write_coder_artifacts() reads off a writer."""

    def __init__(self, directory):
        self.directory = Path(directory)


if __name__ == "__main__":
    unittest.main()