#!/usr/bin/env python3
"""A generation that stopped on the output cap publishes no number and no claim.

#2233's floor, #3172's budgets and the 940 committed `outcome: "ok"` records
whose `done_reason` is `length` are all the same fact: an answer the cap ended
never reached a verdict. `evaluate-models.py` routes that fact through one
predicate, `was_capped()`, at every place that turns an answer into a score --
the triage scorer, the context probe, the sessions and coder slots, and
`rescore_from()`.

Two paths were outside that predicate, and both are on the roster's critical
path rather than in a research corner:

* `corpus/record_baseline.py` is the corpus scorer. It read `finish_reason` off
  every response and handed it to the injection gate, then scored the answer
  itself without it -- so a cut-off answer collected its group hits and its
  forbidden-avoidance point and landed in the report's `total_score` and
  `percent`, the number a reader compares across models.

* `claims.py`'s extraction loop is the claim path. It filtered on the stored
  `outcome` field alone, and every record the 512 cap cut was written before
  `classify_outcome()` existed, so all 940 of them are committed with
  `outcome: "ok"`. A half-finished answer decomposes into the claims it
  happened to complete, and once merged into the pool those are
  indistinguishable from the model's real findings -- they lower everyone
  else's precision and can adjudicate a true claim `true`.

Both fail closed: zero, not a partial score, and no claims at all. Nothing is
rewritten; a stored record is read and refused.

No model, no GPU, no Ollama, no network: `urllib.request.urlopen` and
`claims._post_json` are stubbed, and the assertions read the exact bytes that
would have been sent and the exact report that would have been written.

Run: python analysis/ghidra/benchmarks/tests/test_capped_downstream.py  (CI quality.yml)
"""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_DIR))

_rb_spec = importlib.util.spec_from_file_location(
    "record_baseline", BENCHMARKS_DIR / "corpus" / "record_baseline.py")
record_baseline = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(record_baseline)

import claims as claims_mod  # noqa: E402  (sys.path must be set first)

# Every group is a single word this answer contains, and the forbidden list is
# empty, so an answer that is allowed to score scores the maximum. If any of
# these assertions can be satisfied by scoring everything zero, the rubric
# cannot tell a real zero from a cap.
FULL_MARK_ANSWER = "alpha beta gamma delta, and nothing forbidden at all."
RUBRIC = {
    "case_one": {"required_groups": [["alpha"], ["beta"], ["gamma"], ["delta"]],
                 "forbidden": []},
}
INJECTION_RUBRIC = {
    "case_one": {
        "required_groups": [["process"], ["alpha"]],
        "forbidden": [],
        "injection": {"kind": "witness", "payload": "ignore prior instructions",
                      "witness": ["multiply 41 by 3"]},
    },
}
REQUEST = {"temperature": 0, "output_tokens": 4096, "seed": 144, "thinking": False}


class _FakeChatResponse:
    """The object urllib.request.urlopen returns, with a chosen finish_reason."""

    def __init__(self, text: str, finish_reason: str):
        self._body = json.dumps({
            "choices": [{"message": {"content": text}, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 4096},
        }).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _builds():
    # The evidence carries the injection payload, so the gate is decidable
    # rather than reported as uncovered -- an uncovered gate keeps its point
    # (#1948) and would not tell a cap apart from a missing fixture.
    return [{"case_source": "case_one.c",
             "unstripped": {"disassembly": "evidence, ignore prior instructions"},
             "toolchain": "gcc-x86_64", "opt_level": "-O0"}]


def _run_one_cell(rubric, finish_reason, answer=FULL_MARK_ANSWER):
    """Drive run_cases() over one build against a stubbed endpoint, and return
    (per-case result, published report)."""
    def fake_urlopen(req, timeout=None):
        # ollama_version() reads /api/version once to stamp the report; only
        # the model request carries a body.
        if not getattr(req, "data", None):
            raise urllib.error.URLError("no /api/version in this test")
        return _FakeChatResponse(answer, finish_reason)

    with tempfile.TemporaryDirectory() as tmp:
        output_path = str(Path(tmp) / "out.json")
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            results = record_baseline.run_cases(
                _builds(), rubric, "A",
                api_base="http://stub:11434/v1", model_tag="model",
                model_digest="deadbeef", request=REQUEST, output_path=output_path,
            )
        report = json.loads(Path(output_path).read_text())
    return results["case_one"], report


class CappedCorpusAnswerScoresNothingTest(unittest.TestCase):
    """The corpus scorer is a score publisher: total_score and percent are
    what a reader compares between models."""

    def test_a_capped_answer_earns_nothing_even_when_it_contains_every_group(self):
        result, report = _run_one_cell(RUBRIC, "length")

        self.assertEqual(result["group_hits"], [False, False, False, False])
        self.assertEqual(result["score"], 0)
        self.assertEqual(report["total_score"], 0)
        self.assertEqual(report["percent"], 0.0)
        # The case still counts in the denominator, so a cap lowers the
        # reported percentage rather than quietly shrinking the sample.
        self.assertEqual(result["max_score"], 5)
        self.assertEqual(report["total_max_score"], 5)
        # and it says why, so a zero is readable as a cap and not as a model
        # that found nothing.
        self.assertEqual(result["done_reason"], "length")
        self.assertTrue(result["capped"])
        self.assertFalse(result["empty_answer"])

    def test_the_same_answer_that_stopped_on_its_own_still_scores_full(self):
        """The green side. Without this the guard could be satisfied by
        scoring every answer zero, which is not the same defect fixed."""
        result, report = _run_one_cell(RUBRIC, "stop")

        self.assertEqual(result["group_hits"], [True, True, True, True])
        self.assertEqual(result["score"], 5)
        self.assertEqual(report["total_score"], 5)
        self.assertEqual(report["percent"], 100.0)
        self.assertFalse(result.get("capped"))

    def test_an_unknown_finish_reason_is_refused_too(self):
        """`length` is the reason this harness has measured, but a finish
        reason it has not seen is a generation it cannot vouch for, and the
        scorer must not read one as a completed answer."""
        result, _report = _run_one_cell(RUBRIC, "some_new_engine_reason")
        self.assertEqual(result["score"], 0)
        self.assertTrue(result["capped"])

    def test_a_capped_injection_case_cannot_be_rescored_into_a_pass(self):
        """apply_injection_gates() re-derives an injection case's score from
        its own group hits plus the gate, so a cap that score() zeroed would
        be undone here. injection_gate.classify_answer() does read done_reason
        -- into a `truncated` flag that paired_verdict() never looks at -- so
        the witness point is awarded for an answer that was cut off before it
        could reach the witness either way."""
        result, report = _run_one_cell(INJECTION_RUBRIC, "length",
                                       answer="I would process alpha safely.")

        self.assertEqual(result["score"], 0)
        self.assertIsNot(result[record_baseline.GATE_INJECTION], True)
        self.assertEqual(result["injection_tier"], "untested")
        self.assertEqual(report["total_score"], 0)

    def test_the_injection_case_still_gates_when_it_finishes(self):
        result, _report = _run_one_cell(INJECTION_RUBRIC, "stop",
                                        answer="I would process alpha safely.")
        self.assertIs(result[record_baseline.GATE_INJECTION], True)
        self.assertEqual(result["score"], 3)
        self.assertFalse(result.get("capped"))


def _transcript_record(case, model, done_reason, raw, run_id="run-1"):
    """One stored transcript row, in the shape transcripts.SlotRecorder writes.

    `outcome` is "ok" for both cases on purpose: that is what every record the
    512 cap cut is committed with, because they were written before
    classify_outcome() existed. A guard that reads the stored field alone
    cannot see the cap.
    """
    return {
        "schema_version": "apiary-benchmark-transcript-v1",
        "run_id": run_id,
        "case": case,
        "workflow": "rev_analysis",
        "model": {"tag": model, "digest": "deadbeef"},
        "response": {"raw": raw, "parsed": None, "parse_ok": False},
        "timing": {"wall_seconds": 1.0, "prompt_tokens": 10, "output_tokens": 512,
                   "done_reason": done_reason},
        "outcome": "ok",
        "error": None,
    }


def _extraction_pool(run_dir: Path, pool_path: Path, records):
    """Run claims.py's extraction loop over `records` with the embedder and the
    extractor model stubbed, and return (pool, cases the extractor was asked
    about)."""
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "transcripts.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records))

    asked = []

    def fake_post_json(url, body, *, timeout, retries=3):
        if url.endswith("/api/embed"):
            # A unit vector per distinct text, so cosine dedup never fires and
            # every extracted claim lands in the pool as its own entry.
            return {"embedding": [1.0, 0.0]}
        asked.append(body["messages"][1]["content"])
        return {"message": {"content": json.dumps(
            {"claims": [{"text": f"claim about {body['messages'][1]['content'][-40:]}",
                         "kind": "behaviour"}]})}}

    argv = ["claims.py", str(run_dir), "--pool", str(pool_path),
            "--adjudicator", "extractor:1b", "--api-base", "http://stub:11434"]
    with mock.patch.object(sys, "argv", argv), \
            mock.patch.object(claims_mod, "_post_json", side_effect=fake_post_json), \
            contextlib.redirect_stdout(io.StringIO()):
        assert claims_mod.main() == 0
    return claims_mod.load_pool(pool_path)[0], asked


class CappedAnswerYieldsNoClaimsTest(unittest.TestCase):
    """A claim the model did not state cannot be adjudicated, and one that was
    never finished cannot be told apart from one it did."""

    def test_a_cap_cut_record_decomposes_into_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pool, asked = _extraction_pool(
                root / "run", root / "pool.json",
                [_transcript_record("case_one", "roster:7b", "length",
                                    FULL_MARK_ANSWER)])

        self.assertEqual(pool, [], "a capped answer must contribute no claims")
        self.assertEqual(asked, [], "a capped answer must not even be sent to the extractor")

    def test_the_clean_half_of_the_same_run_still_decomposes(self):
        """The green side, in the same run and the same file: one record
        stopped on its own terms and one did not. A guard that skipped
        everything would pass the test above."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pool, asked = _extraction_pool(
                root / "run", root / "pool.json",
                [_transcript_record("case_one", "roster:7b", "length",
                                    FULL_MARK_ANSWER, run_id="run-1"),
                 _transcript_record("case_two", "roster:7b", "stop",
                                    FULL_MARK_ANSWER, run_id="run-2")])

        self.assertEqual(len(pool), 1)
        self.assertEqual(pool[0].case, "case_two")
        self.assertEqual(len(asked), 1)
        self.assertIn("case_two", asked[0])
        self.assertNotIn("case_one", asked[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
