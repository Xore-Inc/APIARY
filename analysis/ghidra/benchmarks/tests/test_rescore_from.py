#!/usr/bin/env python3
"""Tests for evaluate-models.py --rescore-from (#2266).

Writes real transcripts via transcripts.TranscriptWriter (not hand-built
JSON) so these tests exercise the exact producer the tool reads, then
confirms rescore_from() reproduces exactly what a live evaluate_slot() call
would have scored for the same stored answers.
"""

import hashlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# The sibling module that owns the historical writer's outcome decision; see
# write_legacy_revdeck_run() below.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_committed_reclassification import pre_fix_classify_outcome  # noqa: E402

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


def write_session_run(root, case, parsed):
    """One sessions-slot record for `case`, written the way evaluate_slot()
    itself writes it (through SlotRecorder), so the fixture matches the real
    producer exactly."""
    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
    with TranscriptWriter(root, run) as writer:
        recorder = SlotRecorder(
            writer=writer, slot="sessions",
            model={"tag": "test-model:latest", "digest": "d" * 64},
            reproducibility=Reproducibility(tier="A"),
        )
        recorder.record(
            case=case.name, workflow="session_analysis",
            request_body={"messages": [{"role": "system", "content": "x"},
                                       {"role": "user", "content": "y"}]},
            response={"content": json.dumps(parsed)}, parsed=parsed,
        )
    return writer.directory


class RescoreSessionsTest(unittest.TestCase):
    def test_matches_a_live_score_for_the_same_stored_answer(self):
        case = evaluate_models.SESSION_CASES[0]
        parsed = {
            "summary": "test summary " + " ".join(case.required_summary_groups[0][:1] if case.required_summary_groups else []),
            "intent": next(iter(case.expected_intent)),
            "mitre_attack": [],
            "iocs": list(case.required_iocs),
            "severity": next(iter(case.expected_severity)),
            "confidence": "high",
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_session_run(tmp, case, parsed)
            report = evaluate_models.rescore_from(run_dir)

        live = evaluate_models._score_session_case(case, {"parsed": parsed})
        rescored = report["models"]["test-model:latest"]["sessions"]["cases"][case.name]
        self.assertEqual(rescored["score"], live["score"])
        self.assertEqual(rescored["critical_ok"], live["critical_ok"])
        self.assertEqual(rescored["summary_groups_ok"], live["summary_groups_ok"])
        self.assertEqual(report["unmatched_cases"], [])
        self.assertEqual(report["records_read"], 1)

    def test_never_writes_into_the_run_directory(self):
        case = evaluate_models.SESSION_CASES[0]
        parsed = {"summary": "x", "intent": "unknown", "mitre_attack": [],
                  "iocs": [], "severity": "low", "confidence": "low"}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_session_run(tmp, case, parsed)
            before = sorted(p.name for p in run_dir.iterdir())
            before_bytes = (run_dir / "transcripts.jsonl").read_bytes()
            evaluate_models.rescore_from(run_dir)
            after = sorted(p.name for p in run_dir.iterdir())
            after_bytes = (run_dir / "transcripts.jsonl").read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(before_bytes, after_bytes)

    def test_error_outcome_records_are_excluded_and_counted(self):
        case = evaluate_models.SESSION_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="sessions",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="session_analysis",
                                request_body={"messages": []}, error="timeout")
            report = evaluate_models.rescore_from(writer.directory)
        self.assertEqual(report["records_skipped_error_outcome"], 1)
        self.assertEqual(report["models"], {})

    def test_a_case_no_longer_in_the_current_scorer_is_reported_unmatched(self):
        """Prompts/case rosters drift over time (this test file's own docstring
        rationale) -- a stored case name the current scorer no longer knows
        must be surfaced, not silently dropped or crashed on."""
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="sessions",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case="retired-case-name-xyz", workflow="session_analysis",
                                request_body={"messages": []}, response={"content": "{}"}, parsed={})
            report = evaluate_models.rescore_from(writer.directory)
        self.assertIn("sessions/retired-case-name-xyz", report["unmatched_cases"])
        self.assertEqual(report["models"], {})

    def test_malformed_transcript_line_is_skipped_not_fatal(self):
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            case = evaluate_models.SESSION_CASES[0]
            parsed = {"summary": "x", "intent": "unknown", "mitre_attack": [],
                      "iocs": [], "severity": "low", "confidence": "low"}
            run_dir = write_session_run(tmp, case, parsed)
            with (run_dir / "transcripts.jsonl").open("a") as f:
                f.write("not json\n")
            report = evaluate_models.rescore_from(run_dir)
        self.assertEqual(report["records_read"], 1)  # the malformed line isn't counted


def write_legacy_revdeck_run(root, content, done_reason):
    """A run whose records are stored the way the 512-cap runs in the tree are.

    `pre_fix_classify_outcome` is imported from the sibling module that owns the
    definition rather than restated here: it is the writer's own old decision,
    `"error" if error else "ok"`, so rewinding only that reproduces a genuine
    historical row -- `outcome: "ok"` on an answer the cap cut, with the
    done_reason beside it saying so. Everything else about the record comes out
    of the real producer (chat() -> SlotRecorder -> TranscriptWriter), because
    a hand-written row could drift from the shape rescore_from actually meets.
    """
    case = evaluate_models.REV_CASES[0]
    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)

    def fake_request_json(url, body=None, timeout=300):
        return {
            "message": {"content": content},
            "eval_count": 512,
            "eval_duration": 1_000_000,
            "done_reason": done_reason,
        }

    with tempfile.TemporaryDirectory() as tmp:
        with TranscriptWriter(root, run) as writer:
            recorder = SlotRecorder(
                writer=writer, slot="revdeck",
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
                    num_predict=evaluate_models.budget_for("revdeck"),
                    recorder=recorder, case=case.name, workflow="rev_analysis",
                )
            finally:
                evaluate_models.request_json = original_request
                transcripts.classify_outcome = original_classify
        return writer.directory


class StoredOkCappedRecordsAreNotRescoredTest(unittest.TestCase):
    """`--rescore-from` must not be the one path the reclassification leaks through.

    All 940 committed records the 512 cap cut are stored with `outcome: "ok"`,
    because they were written before classify_outcome() existed. Filtering on
    that field alone therefore re-admits every one of them -- and a rescore is
    the one place that turns stored answers back into *numbers*, so the defect
    that is a mislabelled row everywhere else is a published score here.

    Same answer, same rubric, one word different in the record: the finished one
    scores, the cut one does not.
    """

    COMPLETE_ANSWER = (
        "The loop xors each byte as it decodes, loading each source byte into esi, "
        "storing the destination byte to edi, and running ecx times as the count. "
        "The function is not inherently malicious by itself; what settles it is the "
        "call site, so cross-reference the callers and the callers' inputs."
    )

    def _report(self, done_reason):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_legacy_revdeck_run(tmp, self.COMPLETE_ANSWER, done_reason)
            record = json.loads((run_dir / "transcripts.jsonl").read_text().strip())
            before = (run_dir / "transcripts.jsonl").read_bytes()
            report = evaluate_models.rescore_from(run_dir)
            after = (run_dir / "transcripts.jsonl").read_bytes()
        # Precondition, and the shape under test: this is the historical row --
        # a stored pass whose done_reason says the cap ended it.
        self.assertEqual(record["outcome"], "ok")
        self.assertEqual(record["timing"]["done_reason"], done_reason)
        # Never rewritten, whichever way the rescore decides.
        self.assertEqual(before, after)
        return report

    def test_a_stored_ok_row_the_cap_ended_publishes_no_score(self):
        report = self._report("length")
        self.assertEqual(report["records_read"], 1)
        # Counted, and counted separately from the errors: a report that quietly
        # dropped a record would otherwise look like a clean run.
        self.assertEqual(report["records_skipped_error_outcome"], 1)
        self.assertEqual(report["records_skipped_stored_ok_capped"], 1)
        self.assertEqual(report["models"], {},
                         "a capped row must not reach a score, however complete its answer")
        self.assertEqual(report["unmatched_cases"], [])

    def test_the_same_row_is_scored_when_generation_finished(self):
        """The green side: the filter keys on the evidence, not on the field
        being old, so a rescore of a completed answer is unaffected."""
        report = self._report("stop")
        self.assertEqual(report["records_skipped_error_outcome"], 0)
        self.assertEqual(report["records_skipped_stored_ok_capped"], 0)
        cases = report["models"]["test-model:latest"]["revdeck"]["cases"]
        self.assertEqual(len(cases), 1)
        self.assertEqual(
            cases[evaluate_models.REV_CASES[0].name]["score"],
            len(evaluate_models.REV_CASES[0].required_groups) + 2,
        )


class RescoreRevdeckAndTriageTest(unittest.TestCase):
    def test_revdeck_case_matches_a_live_score(self):
        case = evaluate_models.REV_CASES[0]
        content = " ".join(g[0] for g in case.required_groups)
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="revdeck",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="rev_analysis",
                                request_body={"messages": []},
                                response={"content": content}, parsed=None)
            report = evaluate_models.rescore_from(writer.directory)
        live = evaluate_models._score_revdeck_case(case, {"content": content})
        rescored = report["models"]["test-model:latest"]["revdeck"]["cases"][case.name]
        self.assertEqual(rescored["score"], live["score"])

    def test_triage_needs_both_workflows_or_is_unmatched(self):
        """A case missing its second workflow (interrupted run, partial
        transcript) is not silently scored on half the pair."""
        case = evaluate_models.TRIAGE_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="ghidra",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="program_triage",
                                request_body={"messages": []},
                                response={"content": "{}"}, parsed={"family_guess": "x", "risk_level": "low"})
            report = evaluate_models.rescore_from(writer.directory)
        self.assertIn(f"ghidra/{case.name} (incomplete workflow pair)", report["unmatched_cases"])

    def test_triage_full_pair_matches_a_live_score(self):
        case = evaluate_models.TRIAGE_CASES[0]
        program = {"family_guess": next(iter(case.family_terms), "x"), "risk_level": next(iter(case.expected_risk))}
        behavior = {"behaviors": [t for group in case.behavior_groups for t in group[:1]]}
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="ghidra",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="program_triage",
                                request_body={"messages": []},
                                response={"content": json.dumps(program)}, parsed=program)
                recorder.record(case=case.name, workflow="suspicious_behavior",
                                request_body={"messages": []},
                                response={"content": json.dumps(behavior)}, parsed=behavior)
            report = evaluate_models.rescore_from(writer.directory)
        live = evaluate_models._score_triage_case(
            case, {"program_triage": {"parsed": program, "content": json.dumps(program)},
                   "suspicious_behavior": {"parsed": behavior, "content": json.dumps(behavior)}})
        rescored = report["models"]["test-model:latest"]["ghidra"]["cases"][case.name]
        self.assertEqual(rescored["score"], live["score"])


class RequestBodyTest(unittest.TestCase):
    def _capture_requests(self, score):
        bodies = []

        def fake_request_json(url, body=None, timeout=300):
            bodies.append(body)
            return {"message": {"content": "source"}, "eval_count": 1, "eval_duration": 1}

        original = evaluate_models.request_json
        evaluate_models.request_json = fake_request_json
        try:
            score("http://ollama", "test-model", 8192)
        finally:
            evaluate_models.request_json = original
        return bodies

    def test_coder_uses_its_complete_source_output_budget(self):
        """Every coder request carries the full source budget.

        Coder now runs up to CODER_MAX_ROUNDS generations per case, so the
        call count is cases x rounds, not cases. The invariant being defended
        is the budget on each request, which is why it is asserted over every
        captured body rather than by counting.
        """
        bodies = self._capture_requests(evaluate_models.score_coder)
        self.assertGreaterEqual(len(bodies), len(evaluate_models.CODER_CASES))
        self.assertLessEqual(
            len(bodies),
            len(evaluate_models.CODER_CASES) * evaluate_models.CODER_MAX_ROUNDS,
        )
        self.assertTrue(all(
            body["options"]["num_predict"] == evaluate_models.CODER_NUM_PREDICT
            for body in bodies
        ), "a coder request dropped below the full source budget")

    def test_revdeck_request_body_shape(self):
        """The recorded wire shape, byte for byte, apart from the budget.

        The recorded rows this test was written against were captured at
        num_predict 512, the cap that truncated 93% of revdeck answers. Only
        that number moves; the rest of the body is what those 1,005 stored
        requests prove the harness must keep sending unchanged. num_ctx moved
        with it when every slot's budget went to 16000 and the four
        per-slot window clamps became one NUM_CTX: it is read from the
        constant rather than restated as a literal, so this pins the wire
        *shape* and cannot silently go stale when the window moves again.
        """
        bodies = self._capture_requests(evaluate_models.score_revdeck)
        expected = [
            {
                "model": "test-model",
                "messages": [
                    {"role": "system", "content": evaluate_models.REV_SYSTEM},
                    {"role": "user", "content": case.prompt},
                ],
                "stream": False,
                "think": False,
                "keep_alive": "10m",
                "options": {
                    "temperature": 0,
                    "num_ctx": evaluate_models.num_ctx_for(8192),
                    "num_predict": evaluate_models.budget_for("revdeck"),
                    "seed": 144,
                    # Read the constant rather than repeating it: revdeck is
                    # scored under its own sampling because at 1.0 the models
                    # loop instead of terminating. Duplicating the values here
                    # made this test fail for the right reason and the wrong fix.
                    **evaluate_models.REVDECK_SAMPLING,
                },
            }
            for case in evaluate_models.REV_CASES
        ]
        self.assertEqual(bodies, expected)


class CoderArtifactValidationTest(unittest.TestCase):
    def assert_artifacts_rejected(self, mutate):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = {
                "cases": root / evaluate_models.CODER_CASES_PATH.name,
                "rubric": root / evaluate_models.CODER_RUBRIC_PATH.name,
                "contract": root / evaluate_models.CODER_CONTRACT_PATH.name,
            }
            shutil.copy2(evaluate_models.CODER_CASES_PATH, paths["cases"])
            shutil.copy2(evaluate_models.CODER_RUBRIC_PATH, paths["rubric"])
            shutil.copy2(evaluate_models.CODER_CONTRACT_PATH, paths["contract"])
            mutate(paths)
            originals = (
                evaluate_models.CODER_CASES_PATH,
                evaluate_models.CODER_RUBRIC_PATH,
                evaluate_models.CODER_CONTRACT_PATH,
            )
            evaluate_models.CODER_CASES_PATH = paths["cases"]
            evaluate_models.CODER_RUBRIC_PATH = paths["rubric"]
            evaluate_models.CODER_CONTRACT_PATH = paths["contract"]
            try:
                with self.assertRaises(ValueError):
                    evaluate_models._load_coder_artifacts()
            finally:
                (
                    evaluate_models.CODER_CASES_PATH,
                    evaluate_models.CODER_RUBRIC_PATH,
                    evaluate_models.CODER_CONTRACT_PATH,
                ) = originals

    def test_rejects_mutated_rubric_hash(self):
        def mutate(paths):
            contract = json.loads(paths["contract"].read_text(encoding="utf-8"))
            contract["rubric_sha256"] = hashlib.sha256(b"mutated").hexdigest()
            paths["contract"].write_text(json.dumps(contract), encoding="utf-8")

        self.assert_artifacts_rejected(mutate)

    def test_rejects_reordered_bucket_list(self):
        def mutate(paths):
            contract = json.loads(paths["contract"].read_text(encoding="utf-8"))
            contract["buckets"] = list(reversed(contract["buckets"]))
            paths["contract"].write_text(json.dumps(contract), encoding="utf-8")

        self.assert_artifacts_rejected(mutate)

    def test_rejects_added_case_id(self):
        def mutate(paths):
            contract = json.loads(paths["contract"].read_text(encoding="utf-8"))
            contract["cases"].append("added-case")
            paths["contract"].write_text(json.dumps(contract), encoding="utf-8")

        self.assert_artifacts_rejected(mutate)


class ScorerGitShaTest(unittest.TestCase):
    """The field the documented "run at two commits and diff" workflow leans on.

    A bare `git rev-parse HEAD` names a commit that need not contain the scorer
    that produced the report, and two reports produced from two different
    working trees can carry the identical sha -- which makes the diff
    unattributable exactly when it matters. So the dirty state is part of the
    field's contract, not a nicety.
    """

    def test_returns_a_hex_sha_or_none(self):
        sha = evaluate_models.scorer_git_sha()
        self.assertTrue(
            sha is None or re.fullmatch(r"[0-9a-f]{40}(-dirty|-unknown-dirty)?", sha),
            f"unexpected scorer_git_sha {sha!r}")

    def _with_fake_git(self, head, status):
        """Drive scorer_git_sha against canned `git` results."""
        class Result:
            def __init__(self, returncode, stdout):
                self.returncode, self.stdout = returncode, stdout

        def fake_run(argv, **kwargs):
            if argv[1:] == ["rev-parse", "HEAD"]:
                if head is None:
                    raise OSError("no git")
                return Result(*head)
            if argv[1:] == ["status", "--porcelain"]:
                if status is None:
                    raise OSError("no git")
                return Result(*status)
            raise AssertionError(f"unexpected git call {argv}")

        original = evaluate_models.subprocess.run
        evaluate_models.subprocess.run = fake_run
        try:
            return evaluate_models.scorer_git_sha()
        finally:
            evaluate_models.subprocess.run = original

    def test_a_clean_tree_reports_the_bare_sha(self):
        sha = self._with_fake_git((0, "a" * 40 + "\n"), (0, "\n"))
        self.assertEqual(sha, "a" * 40)

    def test_a_dirty_tree_is_marked(self):
        sha = self._with_fake_git((0, "a" * 40 + "\n"),
                                  (0, " M analysis/ghidra/benchmarks/evaluate-models.py\n"))
        self.assertEqual(sha, "a" * 40 + "-dirty")

    def test_an_unanswerable_status_does_not_claim_clean(self):
        """No .git, a shallow clone, or a git that errors: HEAD may still be
        knowable while cleanliness is not. Saying so beats implying clean."""
        self.assertEqual(self._with_fake_git((0, "a" * 40 + "\n"), (128, "")),
                         "a" * 40 + "-unknown-dirty")
        self.assertEqual(self._with_fake_git((0, "a" * 40 + "\n"), None),
                         "a" * 40 + "-unknown-dirty")

    def test_no_git_at_all_is_none(self):
        self.assertIsNone(self._with_fake_git(None, None))
        self.assertIsNone(self._with_fake_git((128, ""), (0, "")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
