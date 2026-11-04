#!/usr/bin/env python3
"""The harmony output-budget floor is one check, reached by both producers.

#2233's serving adaptation cannot be applied to a slot whose declared output
budget is below the floor: the analysis channel is spent out of the same
budget, so the cap lands mid-reasoning and `final` never starts. The only
honest responses are to send at least the floor or to refuse, and the floor is
above what one slot may declare, so the answer is to refuse.

`evaluate-models.py` chat() did refuse. `corpus/record_baseline.py` -- the
second producer of model answers, building its own OpenAI-compatible payload --
did `max(output_tokens, 4096)` instead: a gpt-oss tag in a slot declaring 2048
was sent 4096 and the report's `qualification_request` still said 2048. The
same declared-vs-sent lie the 512 constant told one layer down, on a harness
whose output feeds model approval.

So the floor is asserted through evaluate-models.py's own
`require_harmony_output_budget()` -- the single definition, called by both
producers -- rather than a second copy in this scorer that the next constant
bump silently invalidates. These tests hold that to the property that matters:
record_baseline.py cannot put a request on the wire that exceeds what it
declares.

No Ollama and no GPU: `urllib.request.urlopen` is stubbed, and the assertions
read the exact bytes that would have been sent.

Run: python analysis/ghidra/benchmarks/tests/test_harmony_budget_guard.py  (CI quality.yml)
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_DIR))


def _load(path, name):
    """Load a module by path, reusing the one already in sys.modules.

    The reuse is load-bearing rather than tidiness. `evaluate-models.py` and
    `record_baseline.py` both reach the harmony check through the module
    object named "evaluate_models" in sys.modules, so the tests below that
    patch `require_harmony_output_budget` and read HARMONY_NUM_PREDICT have to
    be holding that same object. A second copy on the side would make every
    assertion below pass or fail for the wrong reason depending on which sibling
    test module pytest happened to import first.
    """
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Registered before exec: dataclass processing looks its own module up in
    # sys.modules, which spec-created modules are not in until inserted.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate_models = _load(BENCHMARKS_DIR / "evaluate-models.py", "evaluate_models")
record_baseline = _load(BENCHMARKS_DIR / "corpus" / "record_baseline.py", "record_baseline")

# A tag the /api/tags response has already vouched for as harmony-served, so
# these tests exercise the adaptation itself rather than the family lookup.
HARMONY_TAG = "gpt-oss:20b"
# 2048 is the sessions slot's declared budget and the ceiling llm-worker clamps
# at in production, i.e. exactly the number a real caller passes here.
BELOW_FLOOR = {"temperature": 0, "output_tokens": 2048, "seed": 144, "thinking": False}
AT_FLOOR = {"temperature": 0, "output_tokens": 4096, "seed": 144, "thinking": False}
ABOVE_FLOOR = {"temperature": 0, "output_tokens": 8192, "seed": 144, "thinking": False}


class _FakeChatResponse:
    """The object urllib.request.urlopen returns, with a chosen finish_reason."""

    def __init__(self, text: str = "an answer", finish_reason: str = "stop"):
        self._body = json.dumps({
            "choices": [{"message": {"content": text}, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class RecordBaselineCannotOverSendTest(unittest.TestCase):
    """record_baseline.py is a producer of model answers, so it has to be
    unable to measure one at a budget it did not send."""

    def setUp(self):
        # is_harmony_served() reads this cache, which resolve_digest() fills
        # from the /api/tags architecture. Seeding it is the no-network
        # equivalent of a served gpt-oss checkpoint.
        self._was_harmony = record_baseline._harmony_by_tag.get(HARMONY_TAG)
        record_baseline._harmony_by_tag[HARMONY_TAG] = True
        self.sent = []

    def tearDown(self):
        if self._was_harmony is None:
            record_baseline._harmony_by_tag.pop(HARMONY_TAG, None)
        else:
            record_baseline._harmony_by_tag[HARMONY_TAG] = self._was_harmony

    def _capture(self, request, model=HARMONY_TAG):
        def fake_urlopen(req, timeout=None):
            self.sent.append(json.loads(req.data))
            return _FakeChatResponse()
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            return record_baseline.ask_model(
                "http://stub:11434/v1", model, request, "user prompt")

    def test_a_harmony_cell_declaring_less_than_the_floor_puts_nothing_on_the_wire(self):
        """The refusal has to happen before the request, not after it. A cell
        that was sent and then refused has still been measured at a budget the
        report does not state, and a run that continued past the refusal has
        published it."""
        with self.assertRaises(ValueError) as caught:
            self._capture(BELOW_FLOOR)

        self.assertEqual(self.sent, [], "a refused cell must send no request at all")
        self.assertIn(str(evaluate_models.HARMONY_NUM_PREDICT), str(caught.exception))
        self.assertIn("2048", str(caught.exception))

    def test_a_harmony_cell_at_the_floor_sends_exactly_what_it_declares(self):
        self._capture(AT_FLOOR)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["max_tokens"], evaluate_models.HARMONY_NUM_PREDICT)

    def test_a_harmony_cell_above_the_floor_is_never_lowered_to_it(self):
        """The floor is a floor. Silently trimming an over-declaring slot would
        be the same declared-vs-sent lie with the sign flipped."""
        self._capture(ABOVE_FLOOR)
        self.assertEqual(self.sent[0]["max_tokens"], 8192)

    def test_a_non_harmony_cell_declaring_2048_still_sends_2048(self):
        """The guard is about the harmony adaptation only. Every other family
        must keep the budget the caller declared, or this would have quietly
        moved the calibrated Qwen request shape (#2233's stated premise)."""
        self._capture(BELOW_FLOOR, model="qwen3:14b")
        self.assertEqual(self.sent[0]["max_tokens"], 2048)


class OneCheckNotTwoTest(unittest.TestCase):
    """The floor has a single owner. These are the tests that fail if someone
    re-inlines a `max(..., 4096)` here instead of calling evaluate-models.py's
    check -- which is how the two producers drifted apart in the first place."""

    def setUp(self):
        self._was_harmony = record_baseline._harmony_by_tag.get(HARMONY_TAG)
        record_baseline._harmony_by_tag[HARMONY_TAG] = True
        self.sent = []

    def tearDown(self):
        if self._was_harmony is None:
            record_baseline._harmony_by_tag.pop(HARMONY_TAG, None)
        else:
            record_baseline._harmony_by_tag[HARMONY_TAG] = self._was_harmony

    def _ask(self, request, model=HARMONY_TAG):
        def fake_urlopen(req, timeout=None):
            self.sent.append(json.loads(req.data))
            return _FakeChatResponse()
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            return record_baseline.ask_model(
                "http://stub:11434/v1", model, request, "user prompt")

    def test_the_scorer_calls_evaluate_models_own_check(self):
        """Patched out, the scorer widens 2048 to the floor and sends it. That
        is the pre-fix behaviour, and it is what proves the refusal above is
        the shared check doing the work rather than a private copy of the
        rule that happens to agree today."""
        seen = []
        original = evaluate_models.require_harmony_output_budget

        def spy(model, num_predict):
            seen.append((model, num_predict))

        evaluate_models.require_harmony_output_budget = spy
        try:
            self._ask(BELOW_FLOOR)
        finally:
            evaluate_models.require_harmony_output_budget = original

        self.assertEqual(seen, [(HARMONY_TAG, 2048)])
        self.assertEqual(self.sent[0]["max_tokens"], evaluate_models.HARMONY_NUM_PREDICT)

    def test_raising_the_floor_in_evaluate_models_also_raises_what_the_scorer_refuses(self):
        """The scorer reads the constant, it does not restate 4096. Bump the
        one definition and the scorer's refusal moves with it; a private copy
        would keep waving the old number through."""
        original = evaluate_models.HARMONY_NUM_PREDICT
        evaluate_models.HARMONY_NUM_PREDICT = 8192
        try:
            with self.assertRaises(ValueError):
                self._ask(AT_FLOOR)
            self.assertEqual(self.sent, [])
        finally:
            evaluate_models.HARMONY_NUM_PREDICT = original


class BothProducersRefuseTheSameCellTest(unittest.TestCase):
    """The point of sharing the check: the two producers cannot disagree about
    which cells are runnable, so a report's qualification_request and the
    bytes on the wire describe the same measurement."""

    def setUp(self):
        self._was_harmony = record_baseline._harmony_by_tag.get(HARMONY_TAG)
        record_baseline._harmony_by_tag[HARMONY_TAG] = True

    def tearDown(self):
        if self._was_harmony is None:
            record_baseline._harmony_by_tag.pop(HARMONY_TAG, None)
        else:
            record_baseline._harmony_by_tag[HARMONY_TAG] = self._was_harmony

    def test_evaluate_models_refuses_the_cell_with_the_same_reason(self):
        sent = []

        def fake_request_json(url, body):
            sent.append(body)
            return {"message": {"content": "{}"}, "done_reason": "stop"}

        original = evaluate_models.request_json
        evaluate_models.request_json = fake_request_json
        try:
            with self.assertRaises(ValueError) as chat_caught:
                evaluate_models.chat(
                    "http://stub:11434", HARMONY_TAG, "system", "user", 16384,
                    False, num_predict=2048)
            with self.assertRaises(ValueError) as scorer_caught:
                with mock.patch("urllib.request.urlopen",
                                side_effect=AssertionError("nothing may be sent")):
                    record_baseline.ask_model(
                        "http://stub:11434/v1", HARMONY_TAG, BELOW_FLOOR, "user prompt")
        finally:
            evaluate_models.request_json = original

        self.assertEqual(sent, [])
        self.assertEqual(str(chat_caught.exception), str(scorer_caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
