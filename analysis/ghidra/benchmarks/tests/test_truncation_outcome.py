#!/usr/bin/env python3
"""A generation that hit the output cap is never recorded as a successful run.

Before this, evaluate-models.py captured `done_reason` from every Ollama
response and then dropped it on the floor: the record's outcome was
`"error" if error else "ok"`, so `done_reason: "length"` -- Ollama's word for
"generation stopped at num_predict" -- was stored as `ok`. Every consumer
filters on `outcome != "ok"`, so a half-written answer was invisible
downstream and scored as a full one.

Measured on the committed runs: all 940 records with `done_reason: "length"`
carry `output_tokens == 512` exactly, while the longest answer that stopped on
its own is 488 tokens. The cap, not the model, decided where those answers
ended.

These tests drive the real producer -- chat() against a stubbed transport,
written through SlotRecorder -- so they fail if the classification is ever
removed, inverted, or bypassed.
"""

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# The committed-run inventory lives in the sibling test module and is the one
# definition of how a stored record is walked; importing it rather than
# repeating the loop keeps the cap inventory and the qualification inventory
# reading the same tree the same way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_committed_reclassification import (  # noqa: E402
    RUNS_ROOT,
    iter_committed_records,
)

_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(Path(__file__).resolve().parents[1] / "evaluate-models.py"))
evaluate_models = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("evaluate_models", evaluate_models)
_spec.loader.exec_module(evaluate_models)

# The promotion tool itself, so the archived-report hash below is computed by
# the same function `model-governance.py promote` uses to write it rather than
# by a restatement of hashlib that could drift from the tool's own.
_governance_spec = importlib.util.spec_from_file_location(
    "model_governance",
    str(Path(__file__).resolve().parents[2] / "models" / "model-governance.py"))
governance = importlib.util.module_from_spec(_governance_spec)
_governance_spec.loader.exec_module(governance)

from transcripts import (  # noqa: E402
    PROVENANCE_SYNTHETIC,
    OUTCOME_ERROR,
    OUTCOME_OK,
    OUTCOME_TRUNCATED,
    REPO_ROOT,
    Reproducibility,
    RunMetadata,
    SlotRecorder,
    TranscriptWriter,
)

# A revdeck answer that is *complete and correct* on every one of
# x86-code-intent's rubric groups, so the only reason it can lose points is
# that generation stopped on the cap. Anything less would let a test pass for
# the wrong reason: a scorer that already gave this answer zero would look
# correct while scoring nothing.
COMPLETE_REVDECK_ANSWER = (
    "The loop xors each byte as it decodes, loading each source byte into esi, "
    "storing the destination byte to edi, and running ecx times as the count. "
    "The function is not inherently malicious by itself; what settles it is the "
    "call site, so cross-reference the callers and the callers' inputs."
)

# JSON cut off mid-object, the shape a real num_predict stop leaves behind:
# an opening brace, no closing one, so parse_object() cannot recover it.
TRUNCATED_JSON = '{"family_guess": "ransom", "risk_level": "high"'

# context_probe()'s own sentinel. It appears in the probe's prompt and nowhere
# else in the harness, which is how the stub below tells the probe apart from
# the scored cases without counting calls.
PROBE_SENTINEL = "ISSUE_144_CONTEXT_SENTINEL_9f3a"
# A parseable triage answer, so a test can have the cases finish cleanly while
# the probe does not and the slot is held down by the probe alone.
TRIAGE_ANSWER = '{"family_guess": "wget", "risk_level": "low", "behaviors": []}'


def stub_transport(test, content, done_reason, *, eval_count=4096, module=None,
                   tag="test-model:latest"):
    """Install a fake request_json for the duration of one test, and return the
    list it appends every posted body to.

    One stub serves all four endpoints evaluate_slot() touches (/api/tags,
    /api/chat, /api/ps, /api/generate), so a slot can be driven end to end
    with no model, no GPU and no network -- the same stubbing the rest of this
    suite uses.

    `module` names the evaluate-models copy to patch. Each test file loads its
    own copy through importlib (the sibling files therefore each hold a
    distinct module object), so a test importing this helper from another file
    has to say which copy it wants patched or it will patch the other one and
    then reach for the network.

    `tag` is the model /api/tags reports as installed, which is also the model
    evaluate_slot() is asked about: model_artifact() resolves the identity
    before the first call and refuses a tag the runtime does not serve.
    """
    bodies = []
    module = module or evaluate_models

    def fake_request_json(url, body=None, timeout=300):
        bodies.append(body)
        if url.endswith("/api/tags"):
            return {"models": [{
                "name": tag, "model": tag,
                "digest": "d" * 64, "size": 1,
                "details": {"family": "qwen", "parameter_size": "14B",
                            "quantization_level": "Q4_K_M"},
            }]}
        if url.endswith("/api/ps"):
            return {"models": []}
        if url.endswith("/api/chat"):
            return {
                "message": {"content": content},
                "eval_count": eval_count,
                "eval_duration": 1_000_000,
                "done_reason": done_reason,
            }
        return {}

    original = module.request_json
    module.request_json = fake_request_json
    test.addCleanup(setattr, module, "request_json", original)
    return bodies


def stub_probe_and_cases(test, state):
    """A transport whose finish reason depends on which request it is answering.

    The ghidra slot's context probe is a separate call from the scored cases,
    so a test that needs one to be capped and the other clean has to tell them
    apart on the wire rather than by call order -- otherwise the cases are
    capped too and the slot is held down by the wrong answer. `state` is a
    mutable {"probe": ..., "case": ...} so one installed stub can answer the
    probe twice under different finish reasons.

    Same endpoints as stub_transport(), for the same reason: a slot driven end
    to end with no model, no GPU and no network.
    """
    bodies = []

    def fake_request_json(url, body=None, timeout=300):
        bodies.append(body)
        if url.endswith("/api/tags"):
            return {"models": [{
                "name": "test-model:latest", "model": "test-model:latest",
                "digest": "d" * 64, "size": 1,
                "details": {"family": "qwen", "parameter_size": "14B",
                            "quantization_level": "Q4_K_M"},
            }]}
        if url.endswith("/api/ps"):
            return {"models": []}
        if url.endswith("/api/chat"):
            is_probe = PROBE_SENTINEL in json.dumps(body or {})
            return {
                "message": {"content": json.dumps({"sentinel": PROBE_SENTINEL})
                            if is_probe else TRIAGE_ANSWER},
                "eval_count": 512,
                "eval_duration": 1_000_000,
                "done_reason": state["probe"] if is_probe else state["case"],
            }
        return {}

    original = evaluate_models.request_json
    evaluate_models.request_json = fake_request_json
    test.addCleanup(setattr, evaluate_models, "request_json", original)
    return bodies


def chat_record(done_reason, *, slot="revdeck", model="test-model:latest"):
    """One stored transcript for a stubbed chat() response, written the way a
    real run writes it: through chat() -> SlotRecorder -> TranscriptWriter."""
    def fake_request_json(url, body=None, timeout=300):
        return {
            "message": {"content": "a partial answer that stops mid-sentence"},
            "eval_count": 512,
            "eval_duration": 1_000_000,
            "done_reason": done_reason,
        }

    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
    with tempfile.TemporaryDirectory() as tmp:
        with TranscriptWriter(tmp, run) as writer:
            recorder = SlotRecorder(
                writer=writer, slot=slot,
                model={"tag": model, "digest": "d" * 64},
                reproducibility=Reproducibility(tier="A"),
            )
            original = evaluate_models.request_json
            evaluate_models.request_json = fake_request_json
            try:
                case = evaluate_models.REV_CASES[0]
                evaluate_models.chat(
                    "http://stub:11434", model, evaluate_models.REV_SYSTEM,
                    case.prompt, 8192, False,
                    num_predict=evaluate_models.budget_for(slot),
                    recorder=recorder, case=case.name, workflow="rev_analysis",
                )
            finally:
                evaluate_models.request_json = original
            line = writer.path.read_text(encoding="utf-8").strip()
        return json.loads(line)


class TruncatedAnswerIsNotOkTest(unittest.TestCase):
    """The whole bug, in one assertion per path."""

    def test_done_reason_length_is_not_recorded_as_ok(self):
        record = chat_record("length")
        self.assertNotEqual(record["outcome"], OUTCOME_OK)
        self.assertEqual(record["outcome"], OUTCOME_TRUNCATED)

    def test_done_reason_stop_is_still_ok(self):
        """The fix must not turn clean finishes into failures -- that would
        hide truncation just as thoroughly as storing it as `ok` did."""
        self.assertEqual(chat_record("stop")["outcome"], OUTCOME_OK)

    def test_a_transport_failure_stays_an_error(self):
        """`error` outranks the done_reason check, so a timeout is not
        relabelled as a truncated answer."""
        def boom(url, body=None, timeout=300):
            raise TimeoutError("timed out")

        case = evaluate_models.REV_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="revdeck",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                original = evaluate_models.request_json
                evaluate_models.request_json = boom
                try:
                    with self.assertRaises(TimeoutError):
                        evaluate_models.chat(
                            "http://stub:11434", "test-model:latest",
                            evaluate_models.REV_SYSTEM, case.prompt, 8192, False,
                            num_predict=evaluate_models.budget_for("revdeck"),
                            recorder=recorder, case=case.name, workflow="rev_analysis",
                        )
                finally:
                    evaluate_models.request_json = original
                record = json.loads(writer.path.read_text(encoding="utf-8").strip())
        self.assertEqual(record["outcome"], OUTCOME_ERROR)

    def test_an_unseen_done_reason_is_not_vouched_for_as_ok(self):
        """`stop` is a positive list, not a blocklist of known-bad values: a
        finish reason this harness does not recognise is a generation it
        cannot vouch for."""
        self.assertNotEqual(chat_record("some_future_reason")["outcome"], OUTCOME_OK)

    def test_absent_done_reason_is_not_treated_as_truncation(self):
        """Ollama omits done_reason on some paths -- the #2233 harmony
        signature returns empty content with none at all. Absent is not
        evidence that the cap ended generation."""
        self.assertEqual(chat_record(None)["outcome"], OUTCOME_OK)


class TruncationReachesTheConsumersTest(unittest.TestCase):
    """classify_outcome only helps if the readers downstream honour it. Both
    readers filter on `outcome != "ok"`; these pin that a truncated record is
    actually excluded by each."""

    def test_rescore_from_excludes_and_counts_truncated_records(self):
        case = evaluate_models.REV_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="revdeck",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                for done_reason in ("length", "stop"):
                    recorder.record(
                        case=case.name, workflow="rev_analysis",
                        request_body={"messages": [{"role": "user", "content": "x"}]},
                        response={"content": "answer", "done_reason": done_reason},
                    )
                run_dir = writer.directory
            report = evaluate_models.rescore_from(run_dir)

        self.assertEqual(report["records_read"], 2)
        self.assertEqual(report["records_skipped_error_outcome"], 1)
        # Only the clean answer scored; the truncated one never reached a score.
        cases = report["models"]["test-model:latest"]["revdeck"]["cases"]
        self.assertEqual(list(cases), [case.name])

    def test_the_skip_counter_counts_truncation_not_just_errors(self):
        """The field is named for errors, so assert the number moves for a
        truncation too -- otherwise a report would look clean while silently
        dropping half its answers."""
        case = evaluate_models.REV_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="revdeck",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(
                    case=case.name, workflow="rev_analysis",
                    request_body={"messages": [{"role": "user", "content": "x"}]},
                    response={"content": "cut off", "done_reason": "length"},
                )
                run_dir = writer.directory
            report = evaluate_models.rescore_from(run_dir)
        self.assertEqual(report["records_skipped_error_outcome"], 1)
        self.assertNotIn("test-model:latest", report["models"])


class OutputBudgetTest(unittest.TestCase):
    """The budget has to be a chosen number, not a default nobody picked, and
    it has to fit inside the context window that actually gets sent."""

    def test_chat_refuses_to_default_the_output_budget(self):
        """`num_predict` is required. When it had a default of 512 that no call
        site could see, the coder slot's own 4096 was the only way to escape
        it -- and a new slot added later would silently inherit 512 again."""
        import inspect
        parameters = inspect.signature(evaluate_models.chat).parameters
        self.assertIs(
            parameters["num_predict"].default, inspect.Parameter.empty,
            "chat() must require an explicit output budget, not default one",
        )

    def test_coder_budget_is_not_the_analysis_budget_by_accident(self):
        """Both are 4096 today; pinning that they are separate names stops a
        later edit to one from quietly moving the other."""
        self.assertEqual(evaluate_models.OUTPUT_BUDGETS["coder"],
                         evaluate_models.CODER_NUM_PREDICT)
        self.assertEqual(evaluate_models.OUTPUT_BUDGETS["revdeck"],
                         evaluate_models.ANALYSIS_NUM_PREDICT)

    def test_no_slot_was_lowered(self):
        """512 was the shared floor. Every slot must be at or above it."""
        for slot, budget in evaluate_models.OUTPUT_BUDGETS.items():
            self.assertGreaterEqual(budget, 512, f"{slot} budget was lowered")

    # The widest prompt this harness sends is the ghidra slot's context probe
    # (420 filler lines plus TRIAGE_SYSTEM, 15,209 chars -> ~7,176 tokens at the
    # 2.12 chars/token measured on the one committed record storing both). It is
    # not a case: the widest real case is revdeck at ~2,512. Probing the probe is
    # what NUM_CTX was sized for, so it is the number the window has to cover.
    WIDEST_PROMPT_TOKENS = 7176

    # 2.12 chars/token, measured on the one committed record storing both the
    # prompt and prompt_tokens (revdeck `tlv_parser`, 4,487 / 2,117). The same
    # divisor the NUM_CTX comment uses, so a test and the constant it checks
    # cannot disagree about how many tokens a string is.
    CHARS_PER_TOKEN = 2.12

    def _tokens(self, text):
        return round(len(text) / self.CHARS_PER_TOKEN)

    def test_every_slot_budget_fits_inside_the_window_it_is_sent(self):
        """num_ctx is the real ceiling: a num_predict larger than the window
        minus the prompt is cut short by the window instead of the cap, and
        does so silently -- the answer stops at the window, not at num_predict,
        which reads as a model failure in the transcript (done_reason: length).

        There is one window now (NUM_CTX, via num_ctx_for()) rather than a
        per-slot clamp that had to be restated here, so the assertion is made
        per slot against the number that slot actually sends."""
        for slot, budget in evaluate_models.OUTPUT_BUDGETS.items():
            # 8192 is what the committed manifest declares for sessions and
            # revdeck, so it is the smallest window any slot can be handed.
            num_ctx = evaluate_models.num_ctx_for(8192)
            self.assertLess(
                budget, num_ctx - self.WIDEST_PROMPT_TOKENS,
                f"{slot} budget {budget} does not fit in its num_ctx {num_ctx} "
                f"beside the widest prompt ({self.WIDEST_PROMPT_TOKENS})",
            )

    def test_the_window_covers_every_budget_and_the_widest_prompt(self):
        """The 8192 coder window allowed only 6075 tokens, so a raised
        num_predict was cut by the window and the fix looked like it had not
        worked. The window must exceed every budget plus its prompt, not
        merely the old 4096."""
        for slot, budget in evaluate_models.OUTPUT_BUDGETS.items():
            self.assertGreater(
                evaluate_models.NUM_CTX, budget + self.WIDEST_PROMPT_TOKENS,
                f"num_ctx {evaluate_models.NUM_CTX} must cover the {slot} budget "
                f"({budget}) plus the widest prompt, or the window truncates the "
                f"answer below num_predict",
            )

    def test_the_coder_window_covers_the_budget_plus_accumulated_history(self):
        """The assertion that was missing, and the one the review found.

        The two tests above assert `window > budget + widest_first_prompt`.
        Coder is multi-round, so round 2 does not send round 1's prompt -- it
        sends `_continuation_prompt(case, previous, 2)`, and while that prompt
        re-sent the whole previous answer it grew with the previous answer.
        Measured before this fix: 65,209 chars, ~16,302 tokens, so
        16000 + 16,302 = 32,302 against a 24,576 window. From round 2 on, a
        model that spent its budget was window-truncated *silently* -- cut by
        the window rather than the cap, which is indistinguishable from a model
        failure in the transcript -- and the round-1 test could not see it.

        So this one measures the real continuation prompt, over every coder
        case, with the system prompt chat() sends alongside it. It is the
        widest prompt the coder slot ever sends, which is the number the window
        has to cover.
        """
        widest = max(
            self._tokens(evaluate_models.CODER_TOOL_SYSTEM
                         + evaluate_models._continuation_prompt(case, "", 2))
            for case in evaluate_models.CODER_CASES
        )
        budget = evaluate_models.budget_for("coder")
        num_ctx = evaluate_models.num_ctx_for(8192)
        self.assertGreater(
            num_ctx, budget + widest,
            f"the coder window {num_ctx} must cover its budget ({budget}) plus "
            f"the widest continuation prompt ({widest} tokens), or a model that "
            f"spent its budget is window-truncated from round 2 on -- silently, "
            f"and reading as a model failure",
        )

    def test_the_continuation_prompt_does_not_grow_with_the_previous_answer(self):
        """The cap that makes the assertion above hold, asserted directly.

        `_continuation_prompt` re-sent the whole previous answer, which is both
        the owner's complaint ("do not simply resend the whole source code as
        answer") and the measured window defect. It must now be a function of
        the case alone, so the window needed in round N is the same in every
        round no matter how much the answer in round N-1 grew -- including when
        that answer spent the entire budget.
        """
        case = max(evaluate_models.CODER_CASES, key=lambda c: len(c.prompt))
        # A prior answer that spent the whole budget: 16000 tokens at 2.12
        # chars/token, which is the case the old prompt measured at 16,302.
        full_budget_answer = "x" * round(evaluate_models.budget_for("coder")
                                         * self.CHARS_PER_TOKEN)
        short = evaluate_models._continuation_prompt(case, "fn main() {}", 2)
        full = evaluate_models._continuation_prompt(case, full_budget_answer, 2)
        self.assertEqual(
            len(short), len(full),
            "the continuation prompt grew with the previous answer; re-sending "
            "it is what pushed round 2 past the window",
        )
        self.assertNotIn(full_budget_answer, full)
        # And the prompt it replaced would not have fit, so this is a real
        # regression assertion rather than a restatement of the same number.
        old = f"{case.prompt}\n\n---\n{full_budget_answer}\n---\n"
        self.assertGreater(
            self._tokens(old) + evaluate_models.budget_for("coder"),
            evaluate_models.num_ctx_for(8192),
            "the old continuation prompt is asserted to have overflowed the "
            "window; if it now fits, the fixture is wrong and this test has "
            "stopped proving anything",
        )

    def test_the_window_is_raised_not_clamped_to_the_declared_context(self):
        """The committed manifest declares 8192 for sessions and revdeck, which
        would put back the exact defect NUM_CTX exists to remove -- a 16000
        budget cut at 8192 by the window, which reads as a model failure. The
        operator may still go wider by declaring more."""
        self.assertEqual(evaluate_models.num_ctx_for(8192), evaluate_models.NUM_CTX)
        self.assertEqual(evaluate_models.num_ctx_for(32768), 32768)

    def test_harmony_never_lowers_a_slot_budget(self):
        """A slot asking for more than the harmony floor keeps what it asked for.

        Asserted on the wire rather than as `max(8192, FLOOR) == 8192`, which
        was arithmetic about the two constants and said nothing about what
        chat() would send. The floor may not raise a slot's budget either --
        see test_harmony_chat.py's TestHarmonyFloorCannotExceedTheDeclaredBudget
        -- so this direction is the only one left for the branch to get wrong.
        """
        bodies = []

        def fake_request_json(url, body=None, timeout=300):
            bodies.append(body)
            return {"message": {"content": "{}"}, "eval_count": 10,
                    "eval_duration": 1_000_000, "done_reason": "stop"}

        original = evaluate_models.request_json
        evaluate_models.request_json = fake_request_json
        try:
            evaluate_models.chat(
                "http://stub:11434", "gpt-oss:20b", "system prompt", "user prompt",
                8192, False, num_predict=8192,
            )
        finally:
            evaluate_models.request_json = original
        self.assertEqual(bodies[0]["options"]["num_predict"], 8192)

    def test_unknown_slot_has_no_budget(self):
        with self.assertRaises(KeyError):
            evaluate_models.budget_for("not-a-slot")


class CappedAnswerScoresNothingTest(unittest.TestCase):
    """Blocker: the record was honest but the published score was not.

    Storing `truncated` only stops the value travelling in the *transcript*.
    The number a report publishes is computed by the scorers from the same
    `raw` dict, and they were handed the cap-cut content directly -- so a
    done_reason="length" answer still collected the session injectleg, the
    triage refusal point, and on revdeck every rubric group plus the full
    on-task credit, while evaluate_slot() reported `"ok": True`.

    Driven through the real score_*() entry points against a stubbed
    transport, so the raws under test are the shape chat() actually produces
    rather than hand-written dicts that could drift from it.
    """

    def test_a_capped_answer_scores_zero_in_every_slot_and_is_never_ok(self):
        # --- revdeck: a complete, correct answer, cut off at the cap -------
        stub_transport(self, COMPLETE_REVDECK_ANSWER, "length")
        revdeck = evaluate_models.score_revdeck("http://ollama", "test-model:latest", 8192)
        # Precondition: this answer is worth full marks when it is not capped.
        # Asserted rather than assumed, so a zero below cannot be a zero
        # because the rubric never matched.
        self.assertEqual(
            evaluate_models._score_revdeck_case(
                evaluate_models.REV_CASES[0],
                {"content": COMPLETE_REVDECK_ANSWER, "done_reason": "stop"},
            )["score"],
            len(evaluate_models.REV_CASES[0].required_groups) + 2,
        )
        for case in revdeck:
            self.assertEqual(case["score"], 0, f"{case['case']} scored a capped answer")
            self.assertTrue(case["capped"], f"{case['case']} did not record the cap")
            # Not a refusal: it never got to state a verdict, so it must not
            # be credited as a deliberate decline, nor certified against a gate.
            self.assertIs(case["injection_ok"], False)
            self.assertIs(case["critical_ok"], False)
            # max_score is unchanged -- the denominator still describes the
            # rubric, so a capped run reads as a measured zero, not a smaller
            # benchmark that flattered the model.
            rubric = next(c for c in evaluate_models.REV_CASES if c.name == case["case"])
            self.assertEqual(case["max_score"], len(rubric.required_groups) + 2)

        # --- sessions: parse-based, so verified rather than assumed ---------
        stub_transport(self, TRUNCATED_JSON, "length")
        for case in evaluate_models.score_sessions("http://ollama", "test-model:latest", 8192):
            self.assertEqual(case["score"], 0, f"{case['case']} scored a capped answer")
            self.assertTrue(case["capped"], f"{case['case']} did not record the cap")

        # --- triage: a dict of per-workflow outputs, not one raw ----------
        stub_transport(self, TRUNCATED_JSON, "length")
        for case in evaluate_models.score_triage("http://ollama", "test-model:latest", 8192):
            self.assertEqual(case["score"], 0, f"{case['case']} scored a capped answer")
            self.assertTrue(case["capped"], f"{case['case']} did not record the cap")

        # --- coder: human-graded, so no number may appear at all ----------
        stub_transport(self, "fn main() { let x = 1;", "length")
        for case in evaluate_models.score_coder("http://ollama", "test-model:latest", 8192):
            self.assertIsNone(case["score"])
            self.assertIsNone(case["percent"])
            self.assertTrue(case["capped"])

        # --- and the slot itself is not ok -------------------------------
        stub_transport(self, COMPLETE_REVDECK_ANSWER, "length")
        result = evaluate_models.evaluate_slot(
            "http://ollama", "revdeck", "test-model:latest",
            evaluate_models.qualification_request("revdeck", 8192),
        )
        self.assertIs(result["ok"], False)
        # run() prints result['error'] on the not-ok path, so a capped slot has
        # to carry one -- and it has to name the cases, or the zero is
        # unactionable.
        case_count = len(evaluate_models.REV_CASES)
        self.assertIn(f"{case_count} of {case_count} revdeck answers", result["error"])
        self.assertIn(evaluate_models.REV_CASES[0].name, result["error"])
        # The evidence survives: a capped run is a measurement, and "why is
        # this zero" has to be answerable from the artifact.
        self.assertEqual(len(result["cases"]), len(evaluate_models.REV_CASES))
        self.assertEqual(result["score"]["score"], 0)

    def test_a_clean_slot_is_still_ok(self):
        """The green side. Zeroing caps must not turn healthy runs into
        failures, or truncation is hidden as thoroughly as it was before."""
        stub_transport(self, COMPLETE_REVDECK_ANSWER, "stop")
        result = evaluate_models.evaluate_slot(
            "http://ollama", "revdeck", "test-model:latest",
            evaluate_models.qualification_request("revdeck", 8192),
        )
        self.assertIs(result["ok"], True)
        self.assertNotIn("error", result)
        self.assertGreater(result["score"]["score"], 0)

    def test_a_capped_context_probe_is_not_a_pass_and_does_not_leave_the_slot_ok(self):
        """The last path where a cap-cut answer could still read as a clean run.

        was_capped() guards the three scorers, and the ghidra slot's context
        probe is a model answer recorded through the same chat() and the same
        recorder -- but it carries no rubric, so it is in no case list and
        nothing counted it. It reported `passed: True` for an answer that
        stopped mid-generation (the sentinel is the first thing a model echoes,
        so a cut-off probe frequently has it), and approved-models.json's
        require_context_probe reads exactly that field: model-governance turns
        it into a pass, so the one gate that is supposed to prove the model
        survived the window certified an unfinished generation.
        """
        state = {"probe": "stop", "case": "stop"}
        stub_probe_and_cases(self, state)

        # Precondition, as a precondition: this answer does pass the probe when
        # generation finishes, so a failure below cannot be a probe that was
        # always going to fail for want of the sentinel. `passed` is asserted
        # first on both halves, because `passed` is the field the gate reads --
        # a test that tripped over the missing `capped` flag first would prove
        # only that the flag is absent.
        clean = evaluate_models.context_probe("http://ollama", "test-model:latest", 16384)
        self.assertTrue(clean["passed"])

        # The same answer, stopped on the cap: not a pass. `passed` is asserted
        # first because it is the field the gate reads -- a test that tripped
        # over a missing `capped` flag first would prove only that the flag is
        # absent, not that the verdict moved.
        state["probe"] = "length"
        capped = evaluate_models.context_probe("http://ollama", "test-model:latest", 16384)
        self.assertFalse(capped["passed"],
                         "a probe that never finished is not a pass")
        self.assertIs(capped.get("capped"), True)

        # And end to end, with every scored case finishing cleanly -- so the
        # slot is held down by the probe alone, which is the case nothing
        # counted before.
        result = evaluate_models.evaluate_slot(
            "http://ollama", "ghidra", "test-model:latest",
            evaluate_models.qualification_request("ghidra", 16384),
        )
        self.assertEqual([name for name, case in result["cases"].items() if case["capped"]],
                         [], "precondition: the scored cases all finished")
        self.assertIs(result["ok"], False,
                      "a slot whose context probe stopped on the cap is not ok")
        self.assertIs(result["context_probe"]["passed"], False)
        self.assertIs(result["context_probe"].get("capped"), True)
        # run() prints result["error"] on the not-ok path, so it has to name the
        # probe -- otherwise the zero is unactionable.
        self.assertIn("context probe did not stop on its own terms", result["error"])
        # The evidence survives, exactly as it does for a capped case.
        self.assertEqual(len(result["cases"]), len(evaluate_models.TRIAGE_CASES))
        self.assertIn("output", result["context_probe"])

    def test_a_clean_probe_is_still_a_pass_and_leaves_the_slot_ok(self):
        """The green side for the same path, so the guard above cannot be
        satisfied by refusing every probe."""
        state = {"probe": "stop", "case": "stop"}
        stub_probe_and_cases(self, state)
        result = evaluate_models.evaluate_slot(
            "http://ollama", "ghidra", "test-model:latest",
            evaluate_models.qualification_request("ghidra", 16384),
        )
        self.assertIs(result["context_probe"]["passed"], True)
        self.assertIs(result["context_probe"].get("capped"), False)
        self.assertIs(result["ok"], True)
        self.assertNotIn("error", result)


class RecordedProvenanceIsTheRequestThatWasSentTest(unittest.TestCase):
    """Blocker: QUALIFICATION_REQUEST restated output_tokens as 512 while every
    call site sent budget_for(slot)=4096.

    evaluate_slot() stored that 512 as `qualification_request` and run() echoed
    it, so the run artifact carried `"output_tokens": 512` beside a request
    body holding `num_predict: 4096` -- a record describing a benchmark that
    was not the one that ran. The declared request has to be the sent request.
    """

    def test_the_recorded_request_reports_the_output_budget_actually_sent(self):
        bodies = stub_transport(self, COMPLETE_REVDECK_ANSWER, "stop")
        result = evaluate_models.evaluate_slot(
            "http://ollama", "revdeck", "test-model:latest",
            evaluate_models.qualification_request("revdeck", 8192),
        )
        sent = [body["options"]["num_predict"] for body in bodies if body and "options" in body]
        self.assertTrue(sent, "no /api/chat body was posted")
        # The provenance number and the wire number are one number, for every
        # request the slot made.
        self.assertEqual(
            {result["qualification_request"]["output_tokens"]},
            set(sent),
            "the recorded qualification_request disagrees with the num_predict "
            "the harness actually sent",
        )
        self.assertEqual(result["qualification_request"]["output_tokens"],
                         evaluate_models.budget_for("revdeck"))

        # The manifest guard is still exact, and still rejects a declared
        # budget the harness would not send -- fixing the number must not have
        # been done by loosening the comparison.
        stale = {**result["qualification_request"], "output_tokens": 512}
        with self.assertRaises(ValueError) as caught:
            evaluate_models.evaluate_slot(
                "http://ollama", "revdeck", "test-model:latest", stale,
            )
        self.assertIn("benchmark code must be reviewed", str(caught.exception))


class CommittedManifestSessionsBudgetTest(unittest.TestCase):
    """The committed manifest has to be one this harness can actually run.

    `evaluate_slot()` compares the manifest's `qualification_request` against
    `qualification_request(slot, context)` by exact dict equality and raises
    "benchmark code must be reviewed" otherwise. That guard is the only thing
    standing between the manifest and a run artifact that reports one budget
    and sends another, so it is not to be loosened -- the two sides have to be
    made to agree instead.

    They did not. `approved-models.json` approved the sessions slot at
    `output_tokens: 512` while `budget_for("sessions")` sent 4096, so the
    sessions slot could not be run through the manifest at all. Both sides had
    to be moved together, and did, at 2048 and then at 16000.

    16000 is above `env_int("LLM_OUTPUT_TOKENS", 512, 128, 2048)` in
    `llm-worker/worker.py`, so the qualified budget no longer describes a
    production worker -- the benchmark asks for more than production can send.
    That is acceptable only while the manifest says so out loud, which is what
    the second assertion here checks: `qualification_status` names the budget
    as measuring the benchmark, and `runtime_request` still declares the
    production 512. A budget past the ceiling with neither admission would
    read as an approved deployment budget, and this test is what stops that.
    """

    MANIFEST = REPO_ROOT / "analysis" / "ghidra" / "models" / "approved-models.json"
    # llm-worker/worker.py: `env_int("LLM_OUTPUT_TOKENS", 512, 128, 2048)`.
    # Above this the production worker silently clamps, so a qualified budget
    # higher than it describes a deployment that cannot exist.
    PRODUCTION_OUTPUT_TOKEN_CEILING = 2048

    def test_the_committed_sessions_qualification_request_is_the_one_the_harness_sends(self):
        manifest = json.loads(self.MANIFEST.read_text(encoding="utf-8"))
        request = manifest["slots"]["sessions"]["qualification_request"]

        # The guard's own comparison, restated against the real file.
        self.assertEqual(
            request,
            evaluate_models.qualification_request("sessions", request["context_tokens"]),
            "approved-models.json's sessions qualification_request is not the "
            "request evaluate_slot() would send, so the committed manifest "
            "cannot run the sessions slot",
        )

        # The number is the harness's own, and it is a raise past both the 512
        # cap that ended answers mid-sentence and the 2048 production ceiling.
        self.assertEqual(
            request["output_tokens"], evaluate_models.budget_for("sessions"),
        )
        self.assertGreater(
            request["output_tokens"], self.PRODUCTION_OUTPUT_TOKEN_CEILING,
            "the sessions budget should be above the llm-worker ceiling, or the "
            "raise to 16000 did not land",
        )

        # Past that ceiling, the manifest has to say the qualified budget
        # measures the benchmark rather than a deployment it cannot produce.
        slot = manifest["slots"]["sessions"]
        status = slot.get("qualification_status", "")
        self.assertIn(
            f"output_tokens {request['output_tokens']}", status,
            "the sessions budget exceeds what llm-worker will ever send, so the "
            "manifest must admit that it describes the benchmark and not a "
            "deployment",
        )
        self.assertLessEqual(
            slot["runtime_request"]["output_tokens"],
            self.PRODUCTION_OUTPUT_TOKEN_CEILING,
            "runtime_request is what the deployed worker sends; it must stay "
            "inside the ceiling even though the benchmark budget does not",
        )

        # End to end, against a stubbed transport: the committed manifest's own
        # dict is what the harness is handed, so this fails if the guard ever
        # rejects it again.
        bodies = stub_transport(self, json.dumps({
            "summary": "An SSH session performed reconnaissance commands.",
            "intent": "reconnaissance",
            "mitre_attack": ["T1087"],
            "iocs": [],
            "severity": "low",
            "confidence": "high",
        }), "stop")
        result = evaluate_models.evaluate_slot(
            "http://ollama", "sessions", "test-model:latest", request,
        )
        sent = {body["options"]["num_predict"] for body in bodies if body and "options" in body}
        self.assertEqual(sent, {request["output_tokens"]})
        self.assertEqual(result["qualification_request"], request)


class SessionsBudgetQualificationStatusTest(unittest.TestCase):
    """The `unmeasured` marker answers to promotion state, not to evidence.

    `output_tokens: 2048` is what the harness has to send for the sessions
    slot -- `evaluate_slot()` compares `qualification_request` by exact
    equality, so a manifest declaring 512 cannot run the slot at all -- and it
    is the ceiling llm-worker clamps at, so it is a budget production can
    actually produce. Neither of those is a measurement. So the manifest
    carries `slots.sessions.qualification_status` to record that the approval
    does not rest on one.

    A committed run at 2048 now exists (run `2026-10-02-...b7230ed5`, qwen3:14b
    at the approved digest), so "nothing was ever measured at 2048" stopped
    being true of the tree. What did not change is promotion: that run is not
    approved, the owner has not promoted it, and nothing cites it. The marker
    stays.

    This test used to read the marker's life off that evidence -- a run
    appearing at the declared budget demanded deleting the marker. That is the
    wrong dependency. Producing a measurement and approving one are separate
    acts with separate owners, and collapsing them strips the admission on the
    strength of an unapproved run: an unqualified budget reading as approved,
    reached from the opposite side. So the marker is tied to promotion, which
    is what actually governs it.

    How far promotion state can be read from the tree.
    `model-governance.py promote` requires `--approval-date` and stamps
    `slot["approval"]` with it (`command_promote`), in the same write as the
    `report_sha256` of the report it just verified. An approval therefore
    cannot predate the run that produced its report, which makes the recorded
    `approval.date` against the earliest run captured at the declared budget a
    real question rather than a proxy. Today it answers no -- the approval
    predates every committed 2048 run, so it provably was not made from one,
    the slot is not promoted at the declared budget, and the marker must be
    present. Promoting the run moves `approval.date` onto or past that run's
    date and flips the answer, which is the point.

    The stronger oracle is unavailable, and this says so rather than papering
    over it. `verify-report` needs the archived report, and
    `approval.report_sha256` (70c394e8...) is deliberately not in the tree --
    `docs/local-llm-model-evaluation.md` records that verbose reports stay in
    the mode-0700 operator archive on the analysis host because they contain
    full model replies. So coverage cannot be re-derived, and the date
    ordering above is the strongest oracle the tree supports. That absence is
    asserted too: if the report is ever committed this goes red on purpose,
    because `verify_report` would then be strictly stronger and the check has
    to be upgraded rather than left standing on the weaker footing.

    Two-sided, as it always was. A slot promoted at 2048 must not go on
    claiming `unmeasured`; a slot that is not promoted must say so. Promotion
    is the only thing that may remove the marker.
    """

    MANIFEST = REPO_ROOT / "analysis" / "ghidra" / "models" / "approved-models.json"
    # Where a qualification report could plausibly be committed if that policy
    # ever changed. Scoped to the trees the harness and the governance tool
    # actually read -- this corroborates the oracle's validity, it is not a
    # content-addressed index of the whole repository.
    REPORT_ROOTS = (REPO_ROOT / "analysis" / "ghidra", REPO_ROOT / "docs")

    def _run_evidence_date(self, run_dir_name):
        """The day a run that captured a record started.

        `started_at` from the run's own run.json when it wrote one, else the
        YYYY-MM-DD prefix every run directory name carries. The start rather
        than the finish, because it is the earliest moment the evidence could
        exist -- which makes "promoted" the harder claim to earn. For a test
        whose subject is a recorded absence, the strict direction is the safe
        one.
        """
        started = None
        run_json = RUNS_ROOT / run_dir_name / "run.json"
        if run_json.is_file():
            started = json.loads(run_json.read_text(encoding="utf-8")).get("started_at")
        if isinstance(started, str) and started[:10].count("-") == 2:
            return dt.date.fromisoformat(started[:10])
        return dt.date.fromisoformat(run_dir_name[:10])

    def _promotion_covers_declared_budget(self, slot, declared, evidence_dates):
        """(promoted, why) -- does the recorded approval cover `declared`?

        Decided by date ordering, which is the strongest thing the tree can be
        asked: promote writes `approval.date` and the `report_sha256` it
        verified together, so an approval older than every run captured at the
        declared budget cannot be an approval of one.
        """
        recorded = (slot.get("approval") or {}).get("date")
        self.assertRegex(
            recorded or "", r"^\d{4}-\d{2}-\d{2}$",
            "slots.sessions.approval.date must be an ISO date, or promotion state "
            "is not readable from the manifest and this test cannot check anything",
        )
        approved_on = dt.date.fromisoformat(recorded)
        if not evidence_dates:
            return False, (
                f"no committed sessions run was captured at num_predict >= {declared}, "
                f"so nothing could have been promoted at it"
            )
        earliest = min(evidence_dates)
        return approved_on >= earliest, (
            f"approval dated {recorded}, and the earliest run at num_predict >= "
            f"{declared} started {earliest}"
        )

    def test_the_unmeasured_marker_is_governed_by_promotion_and_not_by_evidence(self):
        slot = json.loads(self.MANIFEST.read_text(encoding="utf-8"))["slots"]["sessions"]
        declared = slot["qualification_request"]["output_tokens"]
        self.assertEqual(declared, evaluate_models.budget_for("sessions"))

        # Evidence: every committed sessions answer with the num_predict it was
        # actually sent -- the same walk test_committed_reclassification.py
        # inventories, imported rather than restated so the two cannot drift.
        # This is an *input* to the promotion question and never the question
        # itself: a run at the declared budget shows a measurement exists, and
        # says nothing about whether anyone approved it.
        evidence_dates, sent = set(), []
        for run_dir_name, _lineno, record in iter_committed_records():
            if record.get("slot") != "sessions":
                continue
            num_predict = (((record.get("request") or {}).get("body") or {})
                           .get("options") or {}).get("num_predict")
            sent.append(num_predict)
            if isinstance(num_predict, int) and num_predict >= declared:
                evidence_dates.add(self._run_evidence_date(run_dir_name))
        self.assertTrue(sent, "no committed sessions record to inventory")

        promoted, why = self._promotion_covers_declared_budget(slot, declared, evidence_dates)
        status = slot.get("qualification_status", "")

        if promoted:
            self.assertNotIn(
                "unmeasured", status,
                f"slots.sessions is promoted at num_predict {declared} ({why}), so the "
                f"manifest may no longer claim the budget is unmeasured. Delete "
                f"slots.sessions.qualification_status as part of that promotion, "
                f"which is the only thing that may remove it.",
            )
        else:
            self.assertIn(
                "unmeasured", status,
                "slots.sessions declares an output budget its approval record does "
                f"not cover ({why}), and the manifest does not say so. An approval "
                "record that asserts an unmeasured budget is the defect. Either "
                "promote the run with `model-governance.py promote` and delete "
                "slots.sessions.qualification_status, or record the admission here.",
            )
            # The admission is anchored to the budget it is about, so it cannot
            # go on quietly covering a different number if the budget moves.
            self.assertIn(
                f"output_tokens {declared}", status,
                "the admission must name the budget it qualifies, so it cannot "
                "silently keep describing a number that is no longer declared",
            )
            # Why the date ordering above is the oracle and `verify-report` is
            # not. Asserted rather than assumed: committing the archived report
            # would make the stronger check available, and this test must be
            # upgraded to run it instead of continuing to infer promotion.
            archived = slot["approval"]["report_sha256"]
            committed = [
                str(path.relative_to(REPO_ROOT))
                for root in self.REPORT_ROOTS
                for path in sorted(root.rglob("*.json"))
                if path.is_file()
                and governance.sha256_bytes(path.read_bytes()) == archived
            ]
            self.assertEqual(
                committed, [],
                f"approval.report_sha256 {archived} is committed at {committed}. "
                "Promotion state can now be re-derived with `model-governance.py "
                "verify-report` against it, which is strictly stronger than the "
                "date ordering used above -- replace the oracle rather than leaving "
                "the weaker one in place.",
            )

        # The slot is still runnable. This is a gap in the evidence, not a
        # proposal to put the budget back to the 512 cap that ended answers
        # mid-sentence -- nor, now that it is past the production ceiling, a
        # claim that the deployed worker sends it. `runtime_request` is the
        # deployment-facing number and stays inside the ceiling; the qualified
        # budget measures the benchmark, which is what `qualification_status`
        # above admits and anchors to this budget.
        self.assertEqual(slot["qualification_request"],
                         evaluate_models.qualification_request("sessions", 8192))
        self.assertLessEqual(
            slot["runtime_request"]["output_tokens"],
            self.PRODUCTION_OUTPUT_TOKEN_CEILING,
        )

    PRODUCTION_OUTPUT_TOKEN_CEILING = 2048


class NewCapTestsRunInCiTest(unittest.TestCase):
    """Blocker: 315 tests passed locally and CI ran none of the new ones.

    There is no pytest discovery over analysis/ghidra/benchmarks/tests/ and no
    pytest config in the repo at all -- .github/workflows/quality.yml names
    every file by hand, which is how #2980 found four files executing only by
    hand. A test that is not named there is not a test; it is a local script.
    """

    WORKFLOW = REPO_ROOT / ".github" / "workflows" / "quality.yml"
    NEW_TESTS = ("test_truncation_outcome.py", "test_committed_reclassification.py")

    def test_the_new_cap_tests_are_named_in_the_ci_workflow(self):
        workflow = self.WORKFLOW.read_text(encoding="utf-8")
        for name in self.NEW_TESTS:
            path = f"analysis/ghidra/benchmarks/tests/{name}"
            self.assertTrue(
                (REPO_ROOT / path).exists(), f"{path} does not exist to be run"
            )
            self.assertIn(
                f"python {path}", workflow,
                f"{path} is not run by .github/workflows/quality.yml, so its "
                f"tests only ever execute by hand",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
