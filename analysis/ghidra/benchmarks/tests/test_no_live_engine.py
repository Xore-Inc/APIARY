#!/usr/bin/env python3
"""The suite cannot reach the GPU host, and this says so when it tries.

The suite-level guard lives in `conftest.py`: it replaces `serving.Remote` so a
test that reaches for ssh, docker or the card gets an unreachable host instead
of a ten-minute `wait_for_gpu()` poll. A guard nothing tests is a guard that
gets deleted by the next person who does not know why it is there, so the two
directions are pinned here:

- the guard is *installed* -- `Remote` is not the real one during a test;
- the guard is *load-bearing* -- the exact call that hung the suite, the one
  whose tag resolves against a manifest on disk, now returns in milliseconds.

Both are cheap. A regression here costs the suite ten minutes, not a red mark.
"""

import importlib.util
import sys
import time
import unittest
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import serving  # noqa: E402 -- imported by path, so the path comes first

_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(BENCHMARKS_DIR / "evaluate-models.py"))
evaluate_models = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("evaluate_models", evaluate_models)
_spec.loader.exec_module(evaluate_models)


def _pristine_serving():
    """A second copy of serving.py, loaded unpatched.

    `conftest.py` replaces `serving.Remote` in the module the suite imports, so
    the only way to see the class that would really open the ssh route is to
    load the file again under another name. Distinct module, distinct class --
    which is what makes the identity comparison below mean something.
    """
    spec = importlib.util.spec_from_file_location(
        "serving_pristine", str(BENCHMARKS_DIR / "serving.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules["serving_pristine"] = module
    spec.loader.exec_module(module)
    return module


class TheGuardIsInstalledTest(unittest.TestCase):
    def test_remote_is_not_the_one_that_would_reach_ssh(self):
        self.assertIsNot(serving.Remote, _pristine_serving().Remote,
                         "conftest's guard has stopped applying; a test can now "
                         "reach ssh, docker or the GPU card")

    def test_the_real_constructor_is_still_ssh_and_docker(self):
        """The guard patches a name; it does not redefine the route.

        Pinned so a future change cannot make the fixture install something that
        only *looks* like the ssh route while the real one stays open. Both
        substrings are load-bearing in production: `run` shells out to `ssh`,
        and `docker` is the argv prefix every container call carries.
        """
        import inspect
        real = _pristine_serving().Remote
        self.assertIn('"ssh"', inspect.getsource(real.run))
        self.assertIn('"docker"', inspect.getsource(real.docker))


class TheHangCannotComeBackTest(unittest.TestCase):
    """`test_harmony_chat.py`'s slot test hung the suite at ~40% on this.

    `gpt-oss:20b` is a tag the GPU host really does have a manifest for, so with
    no `session=` the engine resolved a GGUF over ssh and started polling a card
    it never asked about -- 600s, 5s apart. This is that same call, under the
    guard, with the harmony refusal still the thing under test.
    """

    def test_a_resolvable_tag_without_a_session_returns_instead_of_polling(self):
        import test_truncation_outcome as truncation

        truncation.stub_transport(
            self, "{}", "stop", module=evaluate_models, tag="gpt-oss:20b")
        evaluate_models.OUTPUT_BUDGETS["sessions"] = (
            evaluate_models.HARMONY_NUM_PREDICT - 512)
        try:
            started = time.monotonic()
            result = evaluate_models.evaluate_slot(
                "http://ollama", "sessions", "gpt-oss:20b",
                evaluate_models.qualification_request("sessions", 8192),
            )
            elapsed = time.monotonic() - started
        finally:
            evaluate_models.OUTPUT_BUDGETS["sessions"] = (
                evaluate_models.HARMONY_NUM_PREDICT)

        # The assertion this call exists for is unchanged: a slot under the
        # floor is not ok and says why.
        self.assertIs(result["ok"], False)
        self.assertIn("harmony floor", result["error"])
        self.assertNotIn("score", result, "a refused slot publishes no score")
        # And it got there on the Ollama transport, having reached no engine.
        self.assertEqual(result["serving"]["engine"], "ollama")
        self.assertLess(elapsed, 10, f"evaluate_slot took {elapsed:.1f}s; a slot "
                                     f"that opens an engine waits on wait_for_gpu")


if __name__ == "__main__":
    unittest.main()