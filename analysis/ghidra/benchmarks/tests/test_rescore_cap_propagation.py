#!/usr/bin/env python3
"""An answer the output cap ended, or that never recorded ending at all, earns
nothing when a stored baseline is rescored offline.

`corpus/regenerate_pre_2393.py` is the third path that turns model output into a
number. `evaluate-models.py` and `corpus/record_baseline.py` both hand a stored
answer to `transcripts.was_capped()` before it is scored, and `claims.py` drops
a capped record before it contributes claims; this one called
`record_baseline.score()` with no `done_reason` at all, so an answer the output
cap ended collected every group hit it happened to complete, plus the
forbidden-avoidance point it earned by never finishing, and landed in the
artifact's `total_score` and `percent` -- the numbers a reader compares across
generations.

So the stored `done_reason` travels into the scorer, and the scorer decides,
through the one predicate every other path uses. This file does not get a second
cap test of its own: a reimplementation here would be free to disagree with
`was_capped()` about which generations finished, which is the failure mode the
single predicate exists to prevent. The one thing that is decided here is
eligibility, not capping: an answer that recorded no `done_reason` at all.

That case is real rather than hypothetical. All three pre-#2393 sources -- 42
stored cases -- carry no `done_reason` anywhere, because the report shape that
records one (`meta`, #2694) did not exist when they were written. Their stored
scores are therefore unverifiable: nothing in the file says the generation
finished, and a missing signal is not evidence of completion. They are
published as unscorable rather than credited, which is why the artifacts those
sources regenerate to now read zero and list every case in `unscorable_cases`.
The stored files are not touched to achieve that, and the source rows keep
whatever they said.

No model, no GPU, no Ollama, no network: the scorer is driven over in-memory
documents and the adjudicator is a constant lambda.

Run: python analysis/ghidra/benchmarks/tests/test_rescore_cap_propagation.py  (CI quality.yml)
"""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
CORPUS_DIR = BENCHMARKS_DIR / "corpus"
sys.path.insert(0, str(BENCHMARKS_DIR))

regen = importlib.util.module_from_spec(
    importlib.util.spec_from_file_location(
        "regenerate_pre_2393", CORPUS_DIR / "regenerate_pre_2393.py"))
sys.modules.setdefault("regenerate_pre_2393", regen)
regen.__spec__.loader.exec_module(regen)

record_baseline = importlib.util.module_from_spec(
    importlib.util.spec_from_file_location(
        "record_baseline", CORPUS_DIR / "record_baseline.py"))
sys.modules.setdefault("record_baseline", record_baseline)
record_baseline.__spec__.loader.exec_module(record_baseline)

from transcripts import was_capped  # noqa: E402  (path set above so the sibling resolves)

# Every group is one word this answer contains and the forbidden list is empty,
# so an answer allowed to score scores the maximum. A guard that could be
# satisfied by scoring everything zero would not be caught by these fixtures.
FULL_MARK_ANSWER = "alpha beta gamma delta, and nothing forbidden at all."
CASE_RUBRIC = {
    "required_groups": [["alpha"], ["beta"], ["gamma"], ["delta"]],
    "forbidden": [],
}
MAX_SCORE = len(CASE_RUBRIC["required_groups"]) + 1


def _no_adjudicator(case_name):
    """The offline matcher (polarity.py's cue list), as every run without a
    reachable chat model gets. Nothing here needs the claim adjudicator, and
    asking for one would put a model in the test."""
    return None


def _stored(case="case_one", **extra):
    row = {"score": MAX_SCORE, "max_score": MAX_SCORE,
           "group_hits": [True] * 4, "answer": FULL_MARK_ANSWER,
           "wall_seconds": 1.0}
    row.update(extra)
    return {"cases": {case: row}}


def _rescore(doc, rubric=None):
    return regen.rescore_source(doc, rubric or {"case_one": CASE_RUBRIC},
                                record_baseline, _no_adjudicator)


class StoredDoneReasonReachesTheScorerTest(unittest.TestCase):
    """The propagation itself: the value the source recorded is the value the
    scorer is asked about."""

    def test_a_cap_cut_stored_answer_scores_nothing_here_too(self):
        result = _rescore(_stored(done_reason="length"))
        row = result["cases"]["case_one"]

        self.assertEqual(row["score"], 0)
        self.assertEqual(row["group_hits"], [False] * 4)
        self.assertEqual(result["total_score"], 0)
        # The case still counts in the denominator, so a cap lowers the
        # reported percentage instead of quietly shrinking the sample.
        self.assertEqual(result["total_max_score"], MAX_SCORE)
        self.assertEqual(result["percent"], 0.0)
        self.assertEqual(row["stored_done_reason"], "length")
        # Same verdict the live scorer reaches for the same record, from the
        # same predicate: this path cannot disagree with the other two.
        self.assertTrue(was_capped({"done_reason": "length"}))
        self.assertTrue(record_baseline.score(
            FULL_MARK_ANSWER, CASE_RUBRIC, done_reason="length")["capped"])

    def test_an_unknown_finish_reason_is_refused_too(self):
        """`length` is the reason this harness has measured. A finish reason it
        has not seen is a generation it cannot vouch for, and reading one as a
        completed answer is the same defect with a different string."""
        self.assertEqual(_rescore(_stored(done_reason="some_new_engine_reason"))
                         ["cases"]["case_one"]["score"], 0)

    def test_the_same_answer_that_stopped_on_its_own_still_scores_full(self):
        """The green side. Without it a guard that refused everything would pass
        the test above, and the offline rescore would stop being a rescore."""
        result = _rescore(_stored(done_reason="stop"))
        row = result["cases"]["case_one"]

        self.assertEqual(row["group_hits"], [True] * 4)
        self.assertEqual(row["score"], MAX_SCORE)
        self.assertEqual(result["percent"], 100.0)
        self.assertNotIn("unscorable", row)

    def test_a_transcripts_shaped_timing_block_is_read_too(self):
        """record_baseline's report puts done_reason on the case row; a
        transcripts record puts it in `timing`. Both are stored answers, so
        both are read -- and neither is invented when it is absent."""
        self.assertEqual(regen.stored_done_reason({"timing": {"done_reason": "length"}}),
                         "length")
        self.assertEqual(regen.stored_done_reason({"done_reason": "stop"}), "stop")
        self.assertIsNone(regen.stored_done_reason({}))
        self.assertIsNone(regen.stored_done_reason({"answer": "text"}))


class UnverifiableStoredAnswerIsUnscorableTest(unittest.TestCase):
    """No recorded finish reason is not the same as a recorded clean finish.

    `was_capped()` reads an absent `done_reason` as "not capped" on purpose --
    transcripts.py carves `None` out because 14 committed records carry none and
    rewriting their fate from a missing field is not what that predicate is for.
    Here it is the opposite question: this script re-publishes a score, and an
    answer with no completion signal is one nothing can vouch for. Failing closed
    is the only honest answer, and it has to be a *different* decision from the
    cap -- otherwise the fix would mean changing a predicate three other paths
    already depend on.
    """

    def test_a_row_with_no_done_reason_earns_nothing_and_says_why(self):
        result = _rescore(_stored())
        row = result["cases"]["case_one"]

        self.assertEqual(row["score"], 0)
        self.assertEqual(row["group_hits"], [False] * 4)
        self.assertEqual(result["total_score"], 0)
        self.assertEqual(result["percent"], 0.0)
        self.assertEqual(row["unscorable"], regen.NO_DONE_REASON_NOTE)
        self.assertIn("done_reason", row["unscorable"])
        # `capped` stays absent: nothing in this record says the cap ended it,
        # and claiming it did would be the guess this rule exists to refuse.
        self.assertNotIn("capped", row)
        # ... and it is not reported as a model that said nothing, which is a
        # different, published, flag.
        self.assertFalse(row["empty_answer"])
        self.assertEqual(result["unscorable_cases"], ["case_one"])
        self.assertEqual(result["done_reason_absent_cases"], 1)

    def test_the_stored_result_is_still_shown_beside_the_zero(self):
        """Refusing to rescore a row is not deleting it. The stored score stays
        in the artifact so the zero reads as "not scorable", not as "the model
        scored nothing"."""
        row = _rescore(_stored())["cases"]["case_one"]
        self.assertEqual(row["stored_score"], MAX_SCORE)
        self.assertEqual(row["stored_group_hits"], [True] * 4)
        self.assertIsNone(row["stored_done_reason"])
        self.assertTrue(row["moved"])

    def test_a_capped_row_and_an_unverifiable_row_are_different_failures(self):
        """Both score zero, and the artifact has to be able to say which was
        which -- the reader's next step differs."""
        capped = _rescore(_stored(done_reason="length"))["cases"]["case_one"]
        absent = _rescore(_stored())["cases"]["case_one"]

        self.assertTrue(capped["capped"])
        self.assertNotIn("unscorable", capped)
        self.assertNotIn("capped", absent)
        self.assertIn("unscorable", absent)


class CommittedSourcesCarryNoDoneReasonTest(unittest.TestCase):
    """Why the fail-closed branch is the live one for these three sources.

    This is a fact about the committed inputs, not about the guard: it says the
    42 stored cases predate anything that recorded a finish reason, so the
    offline rescore has no evidence of completion to score them on. If a future
    regeneration re-records a source with the reason present, this test is what
    tells you the unscorable branch is no longer being exercised for it.

    `rescore_source()` is driven directly rather than through `regenerate()`,
    which is deliberate: that entry point hands this function the rubric
    ENVELOPE instead of its `cases` (a pre-existing defect, documented at
    regenerate()), so every case misses the lookup and takes the out_of_rubric
    carry-forward branch. Going through it would exercise neither rule.
    """

    def test_every_committed_pre_2393_case_records_no_done_reason(self):
        absent = 0
        total = 0
        for name in regen.SOURCES:
            doc = json.loads((CORPUS_DIR / name).read_text())
            for case_name, stored in doc.get("cases", {}).items():
                total += 1
                if regen.stored_done_reason(stored) is None:
                    absent += 1
        self.assertEqual((total, absent), (42, 42))

    def test_regenerating_one_of_them_writes_nothing_over_the_stored_file(self):
        """Refusing a row must not be a way to edit history: the rescore reads
        the sources and writes a fresh artifact elsewhere."""
        before = {name: hashlib.sha256((CORPUS_DIR / name).read_bytes()).hexdigest()
                  for name in regen.SOURCES}
        _rescore(json.loads((CORPUS_DIR / regen.SOURCES[0]).read_text()),
                 json.loads((CORPUS_DIR / "rev_cases_v2_rubric.json").read_text())["cases"])
        after = {name: hashlib.sha256((CORPUS_DIR / name).read_bytes()).hexdigest()
                 for name in regen.SOURCES}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)