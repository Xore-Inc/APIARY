#!/usr/bin/env python3
"""A rescore must see the same guard input a live run saw, in every slot.

`rescore_from()` rebuilds each scorer's `raw` from a stored transcript record.
It did that with a hand-written dict literal per slot, and the sessions one
carried only `parsed` and `done_reason`. Sessions is the one slot scored from
`parsed` rather than from prose, so `_degenerate_answer()` -- which reads prose
via `_model_prose()` -- found no `content` key, returned "", and the guard
never fired. On an answer that looped *and* still carried valid parseable JSON
(a real shape: a model cycling a JSON object), live scored 0/12 and the rescore
scored 8/12. A full score awarded to a loop.

This is the same shape as the coder `_coder_raw` defect that was already fixed
once, re-created in a different slot, which is why the fix is `_rescore_raw()`
rather than a patched line: one builder every slot calls, so the next slot
cannot omit a key. These tests pin the property that makes that hold -- for a
stored record, live and rescore agree on `degenerate` and on the score -- rather
than pinning the dict's shape.

Driven through the real producer (SlotRecorder -> TranscriptWriter) and the real
consumer (rescore_from()), so the fixture cannot drift from what a run writes.

No model, no network.
"""

import importlib.util
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

from transcripts import (  # noqa: E402
    PROVENANCE_SYNTHETIC,
    Reproducibility,
    RunMetadata,
    SlotRecorder,
    TranscriptWriter,
)

MODEL_TAG = "test-model:latest"

# One block, long enough to clear is_looped()'s 24-char floor with margin and
# padded to a whole number of tokens' worth of characters so a truncation lands
# mid-block the way a budget cut does.
LOOP_BLOCK = ("The service must verify the presented token signature against the "
              "trusted issuer before it grants any scope to the caller. ")


def looped_text(blocks=40):
    """A clean lead-in, then the same block over and over."""
    return ("An initial inspection of the deployment found three separate gaps in "
            "how the token was validated before a scope was handed out.\n\n"
            + LOOP_BLOCK * blocks)


# The coder slot's guard is `is_degenerate` (repetition_ratio), not `is_looped`
# -- a different, already-correct predicate that its review verified, and the
# one it has always used. So its fixture has to loop the way that detector
# measures: aligned to repetition_ratio's 20-char stride.
CODER_LOOP = ("for (uint32_t i=0;i<node.tri_count;++i){const auto& t=mesh.triangles[node.first_tri+i];"
              "if(trace(t)){hit.distance=t;break;}}")
CODER_LOOPED = (CODER_LOOP + " " * (20 - len(CODER_LOOP) % 20)) * 12


def looped_text_for(slot):
    return CODER_LOOPED if slot == "coder" else looped_text()


def session_parsed():
    """Valid parseable JSON of exactly the shape _score_session_case reads.

    A looping model that emits a well-formed object still carries this, which
    is the whole difficulty: the loop is in the prose, the parse succeeded.
    """
    return {
        "summary": "Repeated token validation gap in the authentication path.",
        "intent": "Credential access",
        "mitre_attack": ["T1078"],
        "iocs": [],
        "severity": "high",
        "confidence": 0.7,
    }


def write_slot_run(root, slot, case_name, workflow, answer, parsed):
    """One stored record for `slot`, written through the real producer.

    The ghidra slot scores a (case, workflow) *pair*, so that slot writes both
    of its workflows -- rescore_from() refuses an incomplete pair, and a test
    that asserted nothing because its fixture was refused would pass for the
    wrong reason.
    """
    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
    with TranscriptWriter(root, run) as writer:
        recorder = SlotRecorder(
            writer=writer, slot=slot,
            model={"tag": MODEL_TAG, "digest": "d" * 64},
            reproducibility=Reproducibility(tier="A"),
        )
        workflows = (["program_triage", "suspicious_behavior"]
                     if slot == "ghidra" else [workflow])
        for wf in workflows:
            recorder.record(
                case=case_name, workflow=wf,
                request_body={"messages": [{"role": "user", "content": "prompt"}]},
                response={
                    "content": answer,
                    "message": {"role": "assistant", "content": answer},
                    "prose": answer.strip(),
                    "output_tokens": 4096,
                    "done_reason": "stop",
                },
                parsed=parsed,
            )
    return writer.directory


class RescoreSeesTheSameGuardInputTest(unittest.TestCase):
    """Live and rescore must agree on degenerate and on the score."""

    def _live_and_rescored(self, slot, answer, parsed, workflow=None):
        case = self._cases[slot][0]
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_slot_run(tmp, slot, case.name, workflow or "w", answer, parsed)
            report = evaluate_models.rescore_from(run_dir)
            self.assertNotIn(
                f"{slot}/{case.name}", report["unmatched_cases"],
                f"{slot}: the fixture was refused before scoring, so this "
                f"assertion would pass for the wrong reason",
            )
            rescored = report["models"][MODEL_TAG][slot]["cases"][case.name]
        return self._score(slot, case, answer, parsed, workflow), rescored

    # The four slots' live scorers, addressed the same way rescore_from does.
    _cases = {
        "sessions": None, "revdeck": None, "ghidra": None, "coder": None,
    }

    def setUp(self):
        self._cases = {
            "sessions": evaluate_models.SESSION_CASES,
            "revdeck": evaluate_models.REV_CASES,
            "ghidra": evaluate_models.TRIAGE_CASES,
            "coder": evaluate_models.CODER_CASES,
        }

    def _score(self, slot, case, answer, parsed, workflow):
        if slot == "sessions":
            return evaluate_models._score_session_case(
                case, {"content": answer, "prose": answer.strip(),
                       "parsed": parsed, "done_reason": "stop"})
        if slot == "revdeck":
            return evaluate_models._score_revdeck_case(
                case, {"content": answer, "prose": answer.strip(),
                       "done_reason": "stop"})
        if slot == "ghidra":
            return evaluate_models._score_triage_case(
                case, {workflow or "program_triage": {
                    "content": answer, "prose": answer.strip(),
                    "parsed": parsed, "done_reason": "stop"}})
        return evaluate_models._pending_coder_case(
            case, {"content": answer, "prose": answer.strip(), "done_reason": "stop"})

    def test_a_looped_sessions_answer_is_flagged_on_both_paths(self):
        """The reviewer's reproduction, as a test.

        live    degenerate=True   score=0/12
        rescore degenerate=None   score=8/12

        The rescore's 8/12 was a real score awarded to a loop, and it was
        possible only because that slot's `raw` had no `content` for the guard
        to read. `degenerate is None` (not False) is the shape of the failure:
        the key was absent, so the guard branch never ran at all.
        """
        live, rescored = self._live_and_rescored(
            "sessions", looped_text(), session_parsed())
        self.assertTrue(live["degenerate"],
                        "fixture is wrong: this answer is not a loop")
        self.assertEqual(live["score"], 0)
        # The assertion that fails without _rescore_raw carrying `content`.
        self.assertTrue(
            rescored.get("degenerate"),
            "a looped sessions answer rescored as non-degenerate: the rescore "
            f"raw carried no prose for the guard to read (got "
            f"{rescored.get('degenerate')!r})",
        )
        self.assertEqual(rescored["score"], live["score"])
        self.assertEqual(rescored["max_score"], live["max_score"])

    def test_every_slot_agrees_between_live_and_rescore_on_degenerate(self):
        """The property the shared builder exists to hold, for all four slots.

        Asserted per slot rather than for sessions alone, because the defect
        was per-slot by construction: a builder that one slot does not call, or
        a key one slot's guard reads, is invisible to any single-slot test.
        """
        ghidra_workflow = "program_triage"
        for slot, parsed in (
            ("sessions", session_parsed()),
            ("revdeck", None),
            ("ghidra", {"risk": "high", "confidence": 0.7, "summary": "gap"}),
            ("coder", None),
        ):
            with self.subTest(slot=slot):
                workflow = ghidra_workflow if slot == "ghidra" else "w"
                live, rescored = self._live_and_rescored(
                    slot, looped_text_for(slot), parsed, workflow)
                self.assertTrue(live.get("degenerate"),
                                f"{slot}: fixture is not a loop")
                self.assertEqual(
                    rescored.get("degenerate"), live.get("degenerate"),
                    f"{slot}: rescore and live disagree on degenerate",
                )
                self.assertEqual(rescored.get("score"), live.get("score"),
                                 f"{slot}: rescore and live disagree on score")

    def test_a_clean_sessions_answer_still_scores_on_both_paths(self):
        """The green side. A guard that refused everything would pass the test
        above, and a rescore would stop being a rescore."""
        parsed = session_parsed()
        clean = ("The session shows a failed login, a successful login on the "
                 "second attempt, and a single file write afterwards. Nothing "
                 "in the sequence repeats and nothing was cut short.\n")
        live, rescored = self._live_and_rescored("sessions", clean, parsed)
        self.assertFalse(live.get("degenerate"))
        self.assertEqual(rescored.get("degenerate"), live.get("degenerate"))
        self.assertEqual(rescored["score"], live["score"])
        self.assertGreater(live["score"], 0)

    def test_the_rescore_reads_content_that_was_actually_persisted(self):
        """No field the rescore needs may be one nothing ever wrote.

        `response.raw` is what chat() recorded and TranscriptWriter stores, so
        a legacy row has the text even though it predates `message`. This
        builds that row -- no `message` key at all -- and requires the rescore
        to reach the same verdict from `raw` alone.
        """
        case = evaluate_models.SESSION_CASES[0]
        with tempfile.TemporaryDirectory() as tmp:
            run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
            with TranscriptWriter(Path(tmp), run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="sessions",
                    model={"tag": MODEL_TAG, "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(
                    case=case.name, workflow="session_analysis",
                    request_body={"messages": []},
                    response={"content": looped_text(), "output_tokens": 4096,
                              "done_reason": "stop"},
                    parsed=session_parsed(),
                )
            report = evaluate_models.rescore_from(writer.directory)
        rescored = report["models"][MODEL_TAG]["sessions"]["cases"][case.name]
        self.assertTrue(rescored.get("degenerate"),
                        "a loop stored before `message` was persisted must still "
                        "be caught from response.raw alone")


if __name__ == "__main__":
    unittest.main()