#!/usr/bin/env python3
"""The guard for reclassifying the 940 committed records cut by the output cap.

`classify_outcome()` returns `truncated` for `done_reason: "length"`, but it
runs only at write time (transcripts.py, TranscriptWriter.record) and the writer
refuses to reopen an existing transcript, so the 940 records committed before
that fix still read `outcome: "ok"`. Every consumer filters on
`outcome != "ok"`, so those half-written answers are still being scored as
complete ones.

Reinterpreting them is a storage decision that has not been made yet: the repo's
only documented convention (docs/benchmarks/runs/README.md, "Rules") supersedes
a *misconfigured run* by re-running it into a new run directory that names the
old run_id in `supersedes`, and nothing in the tree reads `supersedes`. So this
file does not restate any committed record. It does two things:

1. Pins the guard predicate itself against the real producer, so the check that
   will enforce the reclassification is known to be correct before it is trusted
   with 940 records.
2. Pins the *current* grandfathered inventory exactly, so the set of records
   awaiting reclassification can never grow silently, and so the moment a
   reclassification lands this test fails loudly instead of being quietly
   updated to match new drift.

`assert_committed_runs_are_reclassified()` at the bottom is the enforcing form.
It is red against today's data by 940 records -- that redness is the standing
proof that the reclassification has not been applied yet. It becomes the gate
the moment a storage convention is chosen; call it from the suite then, and
delete `CommittedRunsAwaitingReclassificationTest`, which exists only to keep
the suite green while the decision is open.
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
    OUTCOME_OK,
    OUTCOME_TRUNCATED,
    PROVENANCE_SYNTHETIC,
    REPO_ROOT,
    Reproducibility,
    RunMetadata,
    SlotRecorder,
    TranscriptWriter,
)

RUNS_ROOT = REPO_ROOT / "docs" / "benchmarks" / "runs"

# Measured on the committed runs and re-measured by this file's inventory test.
# 928 revdeck + 12 sessions, spread over 62 of the 66 run directories; the three
# empty-content `ok` records (sessions, agentic-encoded-exfiltration,
# output_tokens 0) are deliberately NOT in this set -- see the module docstring
# of test_truncation_outcome.py on why absent done_reason is not truncation.
EXPECTED_AWAITING_TOTAL = 940
EXPECTED_AWAITING_BY_SLOT = {"revdeck": 928, "sessions": 12}
EXPECTED_AWAITING_RUN_DIRS = 62


def needs_reclassification(record):
    """True when a record is stored as a pass but the cap ended its generation.

    The single definition of the defect, used by both the pinning test and the
    enforcing assertion, so the two can never disagree about what is being
    counted. Keyed on `done_reason` -- the evidence -- and not on `outcome`,
    which is the field that is wrong.
    """
    if record.get("outcome") != OUTCOME_OK:
        return False
    return (record.get("timing") or {}).get("done_reason") == "length"


def iter_committed_records():
    """(run_dir_name, line_number, record) for every record under docs/benchmarks/runs/."""
    for run_dir in sorted(p for p in RUNS_ROOT.iterdir() if p.is_dir()):
        transcripts = run_dir / "transcripts.jsonl"
        if not transcripts.exists():
            continue
        with transcripts.open(encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, start=1):
                if line.strip():
                    yield run_dir.name, lineno, json.loads(line)


def committed_reclassifiable():
    return [(d, n, r) for d, n, r in iter_committed_records() if needs_reclassification(r)]


def assert_committed_runs_are_reclassified():
    """The enforcing gate: no stored record may claim `ok` after the cap ended it.

    Raises AssertionError naming the offending records, so a reclassification
    that is applied to only some of a run's records -- or applied to the run
    directory but not the records inside it -- cannot pass.
    """
    offenders = committed_reclassifiable()
    if offenders:
        by_slot = {}
        for _d, _n, record in offenders:
            by_slot[record.get("slot")] = by_slot.get(record.get("slot"), 0) + 1
        listing = "\n".join(
            f"  {d}/transcripts.jsonl:{n} slot={r.get('slot')} case={r.get('case')!r}"
            for d, n, r in offenders[:20]
        )
        more = f"\n  ... and {len(offenders) - 20} more" if len(offenders) > 20 else ""
        raise AssertionError(
            f"{len(offenders)} committed records are still stored as outcome='ok' "
            f"although done_reason='length' means the num_predict cap ended them. "
            f"By slot: {by_slot}. Every consumer filters on outcome != 'ok', so "
            f"these half-written answers are still scoring as complete ones.\n"
            f"{listing}{more}"
        )


def pre_fix_classify_outcome(*, error, done_reason=None):
    """The classification as it stood when the 940 records were written.

    `transcripts.py` used to decide a stored outcome with `"error" if error else
    "ok"` and drop `done_reason` on the floor. The defect only exists in records
    written by that version -- the current writer already stores `truncated` --
    so reproducing a historical row means reproducing that writer, not asserting
    against a hand-written dict that could drift from the real record shape.
    """
    return "error" if error else OUTCOME_OK


def stored_record(done_reason, *, content="a partial answer that stops mid-sentence",
                  output_tokens=512, slot="revdeck"):
    """One stored record, written by a writer behaving as it did pre-fix.

    Driven through chat() -> SlotRecorder -> TranscriptWriter against a stubbed
    transport, so the record under test comes out of the real producer. Only the
    outcome decision is rewound, to reach the historical row shape.
    """
    def fake_request_json(url, body=None, timeout=300):
        return {
            "message": {"content": content},
            "eval_count": output_tokens,
            "eval_duration": 1_000_000,
            "done_reason": done_reason,
        }

    case = evaluate_models.REV_CASES[0]
    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
    with tempfile.TemporaryDirectory() as tmp:
        with TranscriptWriter(tmp, run) as writer:
            recorder = SlotRecorder(
                writer=writer, slot=slot,
                model={"tag": "test-model:latest", "digest": "d" * 64},
                reproducibility=Reproducibility(tier="A"),
            )
            original_request = evaluate_models.request_json
            original_classify = transcripts.classify_outcome
            evaluate_models.request_json = fake_request_json
            transcripts.classify_outcome = pre_fix_classify_outcome
            try:
                evaluate_models.chat(
                    "http://stub:11434", "test-model:latest", evaluate_models.REV_SYSTEM,
                    case.prompt, 8192, False,
                    num_predict=evaluate_models.budget_for(slot),
                    recorder=recorder, case=case.name, workflow="rev_analysis",
                )
            finally:
                evaluate_models.request_json = original_request
                transcripts.classify_outcome = original_classify
            line = writer.path.read_text(encoding="utf-8").strip()
    return json.loads(line)


class ReclassificationGuardTest(unittest.TestCase):
    """The predicate has to be right before it is trusted with 940 records.

    Each case is a record produced by the real producer, so the guard is
    exercised against the same shape of row the scan will meet in the repo.
    """

    def test_a_stored_pass_cut_by_the_cap_is_caught(self):
        record = stored_record("length")
        # Precondition: this is exactly the defect -- stored as a pass.
        self.assertEqual(record["outcome"], OUTCOME_OK)
        self.assertTrue(needs_reclassification(record))

    def test_a_clean_finish_is_not_caught(self):
        """The guard must not sweep in clean answers: over-triggering would
        delete good measurements along with the truncated ones."""
        record = stored_record("stop")
        self.assertEqual(record["outcome"], OUTCOME_OK)
        self.assertFalse(needs_reclassification(record))

    def test_a_record_already_reclassified_is_not_caught(self):
        """Once restated, the record is no longer a stored pass and the guard
        goes quiet -- otherwise applying the fix would keep it failing."""
        record = stored_record("length")
        record["outcome"] = OUTCOME_TRUNCATED
        self.assertFalse(needs_reclassification(record))

    def test_an_empty_answer_is_not_caught(self):
        """The 3 committed records with no done_reason, content "" and
        output_tokens 0 were empty when written -- the cap did not cut them,
        there was nothing to cut. They are a separate defect (an empty answer
        scoring points) and are deliberately outside this reclassification."""
        record = stored_record(None, content="", output_tokens=0)
        self.assertEqual(record["outcome"], OUTCOME_OK)
        self.assertEqual(record["timing"]["output_tokens"], 0)
        self.assertEqual(record["response"]["raw"], "")
        self.assertFalse(needs_reclassification(record))

    def test_an_error_is_not_caught(self):
        """An error is already excluded by every consumer; reclassifying it
        would be a no-op dressed up as a fix."""
        record = stored_record("length")
        record["outcome"] = "error"
        self.assertFalse(needs_reclassification(record))

    def test_the_current_writer_already_stores_truncated(self):
        """Why the guard has to be about history only.

        With no rewind, the present writer classifies the same cap-cut response
        as `truncated`, so no new record can enter the outstanding set. The 940
        are a closed historical population, not a growing one -- which is what
        makes pinning them in CommittedRunsAwaitingReclassificationTest safe.
        """
        def fake_request_json(url, body=None, timeout=300):
            return {"message": {"content": "cut off"}, "eval_count": 512,
                    "eval_duration": 1_000_000, "done_reason": "length"}

        case = evaluate_models.REV_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="revdeck",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                original_request = evaluate_models.request_json
                evaluate_models.request_json = fake_request_json
                try:
                    evaluate_models.chat(
                        "http://stub:11434", "test-model:latest", evaluate_models.REV_SYSTEM,
                        case.prompt, 8192, False,
                        num_predict=evaluate_models.budget_for("revdeck"),
                        recorder=recorder, case=case.name, workflow="rev_analysis",
                    )
                finally:
                    evaluate_models.request_json = original_request
                record = json.loads(writer.path.read_text(encoding="utf-8").strip())
        self.assertEqual(record["outcome"], OUTCOME_TRUNCATED)
        self.assertFalse(needs_reclassification(record))


def _row(outcome, done_reason, *, case="checksum_rotate", slot="revdeck"):
    """A minimal stored row, shaped only as far as the guard reads it.

    `iter_committed_records` hands back whatever JSON is on the line, so the
    gate can be driven without standing up a whole producer run. The fields
    here are the ones `needs_reclassification` and the assertion's message
    depend on: outcome, timing.done_reason, slot, case.
    """
    return {
        "schema_version": "apiary-benchmark-transcript-v1",
        "slot": slot,
        "case": case,
        "outcome": outcome,
        "error": None,
        "timing": {"done_reason": done_reason, "output_tokens": 512 if done_reason == "length" else 10},
        "response": {"raw": "x"},
    }


class EnforcingGateTest(unittest.TestCase):
    """`assert_committed_runs_are_reclassified()` is the gate Niklas's decision
    needs, and until now nothing exercised it.

    It is the only thing in the tree that can fail when a reclassified record
    still reads as `ok`, so it has to be known to fire -- otherwise a typo, an
    inverted comparison, or a guard pointed at the wrong field would leave it
    permanently green and the 940 would be reclassified on trust. Both
    directions are driven here: red on a stored pass the cap ended, quiet once
    that row is restated.
    """

    def setUp(self):
        self._real_root = RUNS_ROOT

    def tearDown(self):
        globals()["RUNS_ROOT"] = self._real_root

    def _gate_over(self, rows_by_dir):
        """Point the gate at a throwaway tree of run dirs and run it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, rows in rows_by_dir.items():
                (root / name).mkdir()
                (root / name / "transcripts.jsonl").write_text(
                    "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                    encoding="utf-8",
                )
            globals()["RUNS_ROOT"] = root
            return committed_reclassifiable()

    def test_the_gate_fails_on_a_stored_pass_the_cap_ended(self):
        offenders = self._gate_over({"run-a": [_row(OUTCOME_OK, "length")]})
        self.assertEqual(len(offenders), 1)
        self.assertEqual(offenders[0][0], "run-a")
        self.assertEqual(offenders[0][1], 1)

    def test_the_gate_raises_and_names_the_offending_record(self):
        """The message has to locate the row, or 940 records are unactionable."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "run-a").mkdir()
            (root / "run-a" / "transcripts.jsonl").write_text(
                json.dumps(_row(OUTCOME_OK, "length", case="xor_decode_loop"), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            globals()["RUNS_ROOT"] = root
            with self.assertRaises(AssertionError) as caught:
                assert_committed_runs_are_reclassified()
        message = str(caught.exception)
        self.assertIn("1 committed records are still stored as outcome='ok'", message)
        self.assertIn("run-a/transcripts.jsonl:1", message)
        self.assertIn("xor_decode_loop", message)
        self.assertIn("revdeck", message)

    def test_the_gate_goes_quiet_once_the_row_is_restated(self):
        """The green side. Applying the reclassification must not leave the gate
        red -- otherwise the gate cannot be the thing that confirms the fix."""
        self.assertEqual(
            self._gate_over({"run-a": [_row(OUTCOME_TRUNCATED, "length")]}),
            [],
            "a restated record must stop tripping the gate",
        )

    def test_the_gate_does_not_sweep_in_clean_answers_or_errors(self):
        self.assertEqual(
            self._gate_over({
                "run-a": [
                    _row(OUTCOME_OK, "stop"),
                    _row("error", "length"),
                    _row(OUTCOME_OK, None, case="agentic-encoded-exfiltration", slot="sessions"),
                ],
            }),
            [],
            "a clean stop, an error, and one of the 3 empty-content ok records "
            "must all stay out of the reclassification",
        )

    def test_the_gate_is_red_against_the_committed_tree_by_exactly_940(self):
        """Why this gate is not yet in the suite.

        Run against the real repository the assertion is red, naming every
        outstanding record -- so it is live and correctly aimed, not a stub that
        would pass vacuously once promoted. It is the reason
        `CommittedRunsAwaitingReclassificationTest` exists: pinning the count
        keeps the suite green while this stays the enforcing form, and the two
        cannot disagree because both call `needs_reclassification`.
        """
        globals()["RUNS_ROOT"] = self._real_root
        with self.assertRaises(AssertionError) as caught:
            assert_committed_runs_are_reclassified()
        message = str(caught.exception)
        self.assertIn(f"{EXPECTED_AWAITING_TOTAL} committed records are still stored as outcome='ok'",
                      message)
        self.assertIn(str(EXPECTED_AWAITING_BY_SLOT), message)


class CommittedRunsAwaitingReclassificationTest(unittest.TestCase):
    """Pins the outstanding set so it cannot grow, and cannot be quietly
    re-pinned to match new drift.

    These are the numbers Niklas's decision is scoped to. If this test fails,
    either a reclassification landed (good -- promote
    `assert_committed_runs_are_reclassified` into the suite and delete this
    class) or the committed data changed underneath the decision (investigate
    before trusting anything derived from it).
    """

    @classmethod
    def setUpClass(cls):
        cls.offenders = committed_reclassifiable()

    def test_the_outstanding_total_is_still_940(self):
        self.assertEqual(len(self.offenders), EXPECTED_AWAITING_TOTAL,
                         "the count of records awaiting reclassification moved; "
                         "if a reclassification landed, replace this class with "
                         "assert_committed_runs_are_reclassified()")

    def test_the_split_is_still_928_revdeck_and_12_sessions(self):
        by_slot = {}
        for _d, _n, record in self.offenders:
            by_slot[record.get("slot")] = by_slot.get(record.get("slot"), 0) + 1
        self.assertEqual(by_slot, EXPECTED_AWAITING_BY_SLOT)

    def test_the_outstanding_set_spans_still_62_run_directories(self):
        dirs = {d for d, _n, _r in self.offenders}
        self.assertEqual(len(dirs), EXPECTED_AWAITING_RUN_DIRS)

    def test_every_outstanding_record_was_cut_exactly_at_the_cap(self):
        """The 512-token cap is what makes these truncations rather than short
        answers: all 940 stop at exactly the budget while the longest clean
        answer is 488. A record in this set that stopped short of the cap was
        not cut by it and does not belong in the reclassification."""
        off_cap = [
            (d, n, r["timing"].get("output_tokens"))
            for d, n, r in self.offenders
            if r["timing"].get("output_tokens") != 512
        ]
        self.assertEqual(off_cap, [], f"{len(off_cap)} outstanding records did not stop at the cap")

    def test_the_reclassifiable_set_is_exactly_the_940_and_nothing_else(self):
        """Guards against a partially-applied reclassification hiding here: the
        committed tree must contain no record that is already `truncated`."""
        already = [
            (d, n) for d, n, r in iter_committed_records()
            if r.get("outcome") == OUTCOME_TRUNCATED
        ]
        self.assertEqual(already, [],
                         "committed records already carry outcome='truncated'; the "
                         "reclassification has started, so this pinning class is now "
                         "the wrong shape -- promote the enforcing assertion")


if __name__ == "__main__":
    unittest.main(verbosity=2)
