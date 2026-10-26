#!/usr/bin/env python3
"""A repetition loop the budget cut mid-block is still a loop.

`is_looped()` is the prose guard the three analysis slots score with. It looked
for a block repeated exactly to the end of the tail (`block * min_repeats ==
tail[-span:]`), which a truncation defeats: an answer cut mid-token by the
output budget never reaches a clean block boundary. Truncation is precisely the
situation loops occur in -- the 940 committed `done_reason: length` records are
almost all of them -- so requiring the repetition to land on the final character
was requiring the one alignment a cut answer is least likely to have.

Two properties have to hold at once, and both are asserted here because either
one alone is easy to get by making the other worse:

  * a loop that runs into the budget is still flagged, at any cut offset;
  * an answer that looped and then *recovered* is NOT flagged -- the recovery
    is real evidence, and a guard that cannot see it would zero out honest
    answers.

Plus the false positive the review measured on committed data rather than
hypothetically: `injection_gate.is_degenerate()` normalises digits, so a correct
ATT&CK list -- T1037.001 .. T1037.019 -- collapses to one repeated line and a
complete, correct sessions answer is flagged degenerate. That is asserted as a
negative so the property cannot quietly come back.

The committed-corpus property is checked too, by reading the real records: over
all analysis-slot records the guard flags only `done_reason: length` answers.

No model, no network.
"""

import glob
import json
import os
import sys
import unittest
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BENCHMARKS_DIR.parents[2]
sys.path.insert(0, str(BENCHMARKS_DIR))

import injection_gate  # noqa: E402
import transcripts  # noqa: E402
from transcripts import is_looped  # noqa: E402

# One block long enough to clear the 24-char floor with margin, ending in a
# space so a cut lands mid-sentence the way a token budget ends one.
BLOCK = ("The service must verify the presented token signature against the "
         "trusted issuer before it grants any scope to the caller. ")

LEAD_IN = ("An initial inspection of the deployment found three separate gaps in "
           "how the token was validated before a scope was handed out.\n\n")

# A long, entirely distinct answer. Used where the loop has to start *late*:
# a model that writes a great deal of correct prose and only drops into a loop
# at the very end, which is where the budget then cuts it. Without a lead-in
# this long the loop sits inside the tail window and the old detector caught it
# by luck of alignment rather than on purpose.
DISTINCT = "".join(
    f"Finding {n}: the handler for event {n} validates the payload header "
    f"before dispatching it to worker {n % 7}, and rejects a payload whose "
    f"declared length disagrees with the body.\n" for n in range(120))


def looped(blocks=40, lead_in=LEAD_IN):
    return lead_in + BLOCK * blocks


def late_loop(whole_blocks, partial_chars):
    """Distinct prose, then `whole_blocks` whole copies and a partial copy.

    The shape the defect is about: the loop begins late, so the only evidence
    of it is the two or three copies that fit before the budget ended.
    """
    return (DISTINCT + BLOCK * whole_blocks
            + BLOCK[:partial_chars])


class TruncatedLoopTest(unittest.TestCase):
    """The loop the budget cut, at every offset inside the final block."""

    def _assert_flagged_at_every_offset(self, whole_blocks):
        """Cut a late loop at each character position of its trailing copy.

        Starts one character into the partial copy: two whole copies and
        nothing after them is not evidence of a loop (see
        test_the_floor_is_where_the_evidence_stops), so the sweep covers the
        partial copies, which is what a budget cut actually produces.
        """
        start = len(DISTINCT) + len(BLOCK) * whole_blocks + 1
        full = late_loop(whole_blocks, len(BLOCK))
        missed = []
        for cut in range(start, len(full) + 1):
            if not is_looped(full[:cut]):
                missed.append(cut - start)
        self.assertEqual(
            missed, [],
            f"a loop cut mid-block was missed at {len(missed)} of "
            f"{len(full) - start + 1} offsets (first: {missed[:8]})",
        )

    def test_a_loop_cut_mid_block_is_still_a_loop(self):
        """The defect. A budget cut lands mid-token, never on a clean boundary.

        Two whole copies plus a partial is the shape that was missed: the old
        detector needed three whole copies AND needed the repetition to reach
        the final character, so a loop that started late enough to fit only two
        before the cut was invisible at every offset.
        """
        self._assert_flagged_at_every_offset(2)

    def test_a_long_loop_is_still_a_loop(self):
        """The easy case, kept so the relaxation cannot be a coincidence."""
        self._assert_flagged_at_every_offset(20)

    def test_it_holds_for_several_block_lengths(self):
        """Block length is not controlled -- it is whatever the model emitted.

        The floor is 24 chars and the ceiling 1200, so the sweep covers a short
        bullet through to a whole paragraph.
        """
        for period in (24, 37, 68, 91, 150):
            block = (BLOCK * 8)[:period]
            for whole in (2, 6):
                start = len(DISTINCT) + period * whole + 1
                full = DISTINCT + block * whole + block
                missed = [c for c in range(start, len(full) + 1)
                          if not is_looped(full[:c])]
                with self.subTest(period=period, whole=whole):
                    self.assertEqual(missed, [],
                                     f"period {period}: missed {len(missed)}")

    def test_the_floor_is_where_the_evidence_stops(self):
        """One whole copy, or two with nothing after, is not a loop.

        The floor of the relaxation, asserted so it cannot be lowered by a
        later change to `min_repeats` without someone noticing. A model that
        emits a sentence twice and stops is not evidence of degeneration, and
        flagging it would zero honest answers.
        """
        for text in (
            DISTINCT + BLOCK,
            DISTINCT + BLOCK * 2,
            BLOCK,
            BLOCK * 2,
        ):
            with self.subTest(chars=len(text)):
                self.assertFalse(is_looped(text))

    def test_min_repeats_below_three_is_refused(self):
        """The evidence floor is structural, not conventional.

        Two whole copies plus one character is the least that counts as a
        loop; a smaller min_repeats would make the arithmetic below mean
        something else, so it is refused rather than honoured.
        """
        for bad in (0, 1, 2):
            with self.subTest(min_repeats=bad):
                with self.assertRaises(ValueError):
                    is_looped(DISTINCT + BLOCK * 5, min_repeats=bad)

    def test_text_shorter_than_the_floor_is_not_inspected(self):
        """Below min_period * min_repeats the guard does not even scan.

        The floor is a length, not a distinctness requirement: a short answer
        that happens to be periodic is still caught, and one that is simply
        too short to carry a block cannot be judged.
        """
        floor = transcripts.LOOP_MIN_PERIOD_CHARS * transcripts.LOOP_MIN_REPEATS
        self.assertFalse(is_looped("a" * (floor - 1)))
        self.assertFalse(is_looped(""))
        self.assertFalse(is_looped(None))
        self.assertTrue(is_looped("x" * floor))
        self.assertTrue(is_looped("ab " * (floor // 3)))

    def test_a_loop_that_recovered_is_not_flagged(self):
        """The property the strict end-alignment used to give, for free.

        It must survive the relaxation. The differing tail breaks the
        repetition, which is exactly what a recovered answer looks like, so
        this is the honest call rather than a limitation to paper over.
        """
        recovered = looped(40) + (
            "On closer inspection, however, the finding was a false positive: the "
            "gap was a stale cache entry rather than a missing check, and the "
            "token was in fact verified on every call path. Severity is downgraded "
            "and no further remediation is required.\n")
        self.assertTrue(is_looped(looped(40)), "fixture is not a loop")
        self.assertFalse(is_looped(recovered),
                         "an answer that looped and then recovered must not be "
                         "flagged; the recovery is real evidence against a loop")

    def test_a_correct_long_answer_is_not_flagged(self):
        """The green side for the relaxation: 120 distinct sentences."""
        answer = "".join(
            f"Finding {n}: the handler for event {n} validates the payload "
            f"header before dispatching it to worker {n % 7}, and rejects a "
            f"payload whose declared length disagrees with the body.\n"
            for n in range(120))
        self.assertGreater(len(answer), 6000, "must span the whole tail window")
        self.assertFalse(is_looped(answer))


class CorrectStructuredAnswerTest(unittest.TestCase):
    """The ATT&CK-list false positive, as a negative.

    `injection_gate.is_degenerate()` normalises digits, so T1037.001 through
    T1037.019 become one repeated line and a complete, correct sessions answer
    is flagged degenerate. That is the reason the analysis slots use is_looped()
    instead, and it is measured on a committed record -- so it is asserted here,
    or the reason can quietly stop being true.
    """

    ATTACK_ANSWER = (
        "Summary: the session shows a beacon establishing persistence via a "
        "scheduled task, followed by a single outbound connection.\n"
        "Intent: Persistence\n"
        "MITRE ATT&CK techniques observed:\n"
        + "".join(f"- T1037.{n:03d} Boot or Logon Autostart Execution: Run Once "
                  f"or Run at Startup\n" for n in range(1, 20))
        + "iocs: none\nseverity: high\nconfidence: 0.8\n"
    )

    def test_a_correct_attack_list_is_not_a_loop(self):
        self.assertFalse(is_looped(self.ATTACK_ANSWER))

    def test_the_detector_this_replaces_is_what_fails_on_it(self):
        """Why is_looped() exists: the older predicate flags this answer.

        If injection_gate ever stops normalising digits this assertion fails,
        which is fine -- but it means the reason for a second predicate should
        be revisited deliberately rather than assumed.
        """
        self.assertTrue(
            injection_gate.is_degenerate(self.ATTACK_ANSWER),
            "injection_gate.is_degenerate no longer flags the ATT&CK list; the "
            "measured reason for is_looped() has changed and this file's "
            "premise needs re-checking",
        )


class CommittedRecordsTest(unittest.TestCase):
    """The corpus property, read from the committed records themselves.

    Over all committed analysis-slot records the guard flags only answers the
    budget cut. Any flag on an answer that finished on its own terms is a
    false positive on real data, which is the number that decides whether this
    guard can be trusted at all.
    """

    RUNS = sorted(glob.glob(str(REPO_ROOT / "docs" / "benchmarks" / "runs" / "*")))

    def _analysis_records(self):
        for run in self.RUNS:
            path = Path(run) / transcripts.TRANSCRIPT_FILENAME
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("schema_version") != transcripts.SCHEMA_VERSION:
                    continue
                if rec.get("slot") in ("revdeck", "sessions"):
                    yield rec

    def test_no_answer_that_finished_on_its_own_terms_is_flagged(self):
        records = list(self._analysis_records())
        self.assertGreater(len(records), 0,
                           "no committed analysis-slot records found; the corpus "
                           "moved and this assertion needs re-pointing")
        flagged = [r for r in records
                   if is_looped((r.get("response") or {}).get("raw") or "")]
        offenders = [r for r in flagged
                     if (r.get("timing") or {}).get("done_reason") != "length"]
        self.assertEqual(
            offenders, [],
            f"{len(offenders)} answer(s) that finished on their own terms were "
            f"flagged as loops, e.g. "
            f"{[o['case'] for o in offenders[:3]]}",
        )

    def test_loops_are_actually_caught_on_real_records(self):
        """The green side of the same corpus: a guard that flags nothing at all
        would pass the test above."""
        records = list(self._analysis_records())
        flagged = [r for r in records
                   if is_looped((r.get("response") or {}).get("raw") or "")]
        self.assertGreater(
            len(flagged), 0,
            "no committed analysis-slot answer was flagged as a loop; either "
            "the corpus moved or the guard has stopped detecting anything",
        )


if __name__ == "__main__":
    unittest.main()