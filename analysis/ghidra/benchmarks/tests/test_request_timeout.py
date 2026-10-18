#!/usr/bin/env python3
"""The request timeout is sized by the work asked for, not a constant.

`evaluate-models.py` request_json() is the shared transport for every model call
in the benchmark, and it defaulted to a flat `timeout=300`. One wall-clock
allowance therefore covered an 8-token context probe and the coder slot's
4096-token answer alike, and on the homeserver (RTX 4000 Ada, 20 GB VRAM,
~92 GB RAM) any model decoding slower than ~7 tok/s could not finish a
4096-token budget inside it. Measured there at `num_predict: 256`:

    GLM-4.6-REAP-218B IQ1_S   2.71 tok/s  ->  4096 tokens needs 25.2 min
    Trendyol Qwen3-32B Q8_0   2.45 tok/s  ->  4096 tokens needs 27.9 min
    Seneca 32B Q4_Medium      5.12 tok/s  ->  4096 tokens needs 13.3 min

All three were excluded from the benchmark by a transport timeout rather than by
any property of the model. A timeout is not a measurement, and the fix that is
easy to reach for -- lowering CODER_NUM_PREDICT until the slow models fit in
300s -- would change what the benchmark measures instead.

So the allowance is derived from the request's own num_predict at a floor
decode rate, and clamped at both ends: a short probe still fails fast instead of
waiting on a stalled server, and no caller can buy an unbounded wait. This test
holds the three properties that make that a measurement rather than a different
constant -- a big budget buys more time than a small one, a small one keeps the
old floor, and both ends clamp.

No Ollama, no GPU and no network: `urllib.request.urlopen` is stubbed, and the
assertions read the `timeout` the real transport would have been handed.

Run: python analysis/ghidra/benchmarks/tests/test_request_timeout.py  (CI quality.yml)
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

    Same reason as the sibling benchmark tests give: a second copy of
    `evaluate-models.py` on the side would make these assertions read constants
    off an object the harness under test is not using.
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


class _FakeResponse:
    """The object urllib.request.urlopen returns, as a context manager."""

    def __init__(self):
        self._body = json.dumps({"done": True}).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _timeout_for(body):
    """The `timeout` request_json() would hand urlopen for `body`."""
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(timeout)
        return _FakeResponse()

    with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        evaluate_models.request_json("http://stub:11434/api/chat", body)
    if len(seen) != 1:
        raise AssertionError(f"expected exactly one request, saw {len(seen)}")
    return seen[0]


def _chat_body(num_predict):
    """A body shaped like chat()'s, carrying the given output budget."""
    return {"model": "stub:32b", "stream": False, "options": {"num_predict": num_predict}}


class RequestTimeoutFollowsTheOutputBudgetTest(unittest.TestCase):
    def test_a_large_budget_buys_more_time_than_a_small_one_and_both_stay_clamped(self):
        # The coder slot's real budget, and a token-cheap probe for contrast.
        large = _timeout_for(_chat_body(evaluate_models.CODER_NUM_PREDICT))
        small = _timeout_for(_chat_body(8))

        # Proportional: the whole point. A multi-thousand-token answer is
        # hundreds of times the work of an 8-token one, so equal wall-clock
        # allowances are the defect.
        self.assertGreater(
            large, small,
            "a full-budget request is given no more time than an 8-token one, so "
            "any model slower than ~7 tok/s is excluded by the transport",
        )
        # Sized from the request's own budget at the measured floor rate, not
        # hand-picked: num_predict / 2.0 tok/s.
        self.assertEqual(large, int(evaluate_models.CODER_NUM_PREDICT / evaluate_models.FLOOR_DECODE_TOKENS_PER_SECOND))
        # And enough for the model the defect actually excluded: the slowest
        # rate measured on the homeserver (Trendyol Qwen3-32B Q8_0, 2.45 tok/s)
        # needs the budget / 2.45 of decode. An allowance at or below that is
        # the same timeout, spelled differently.
        self.assertGreaterEqual(large, evaluate_models.CODER_NUM_PREDICT / 2.45)
        # The coder budget is the largest in OUTPUT_BUDGETS, so a max that
        # clamps it would be a ceiling that reproduces the defect at one slot.
        self.assertLess(
            large, evaluate_models.MAX_REQUEST_TIMEOUT_SECONDS,
            "the coder slot's real budget is clamped by the ceiling",
        )

        # Clamped low: an 8-token probe answers in seconds, and a stalled or
        # dead server must still be reported inside the 300s the old constant
        # gave every request.
        self.assertEqual(small, 300)
        self.assertEqual(small, evaluate_models.MIN_REQUEST_TIMEOUT_SECONDS)

        # Clamped high: no caller may buy an unbounded wait by asking for a
        # budget no slot declares.
        absurd = _timeout_for(_chat_body(10 ** 6))
        self.assertEqual(absurd, evaluate_models.MAX_REQUEST_TIMEOUT_SECONDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
