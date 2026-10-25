"""The slot verdict names whose failure a zeroed answer was (#3706 cause 0)."""

import importlib.util
import sys
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nonstop_evaluate_models",
                                              BENCH / "evaluate-models.py")
evaluate_models = importlib.util.module_from_spec(spec)
sys.modules["nonstop_evaluate_models"] = evaluate_models
spec.loader.exec_module(evaluate_models)


def case(name, **raw):
    return {"case": name, "capped": True, "outputs": {"triage": raw}}


class NonstopVerdictTest(unittest.TestCase):
    def test_each_cause_gets_its_own_clause(self):
        clauses = evaluate_models.describe_nonstops("sessions", 5, [
            case("looped", done_reason="length"),
            case("http", done_reason="error", error="HTTPError 500: boom",
                 error_kind="backend"),
            case("cli", done_reason="error", error="Claude Code exited 1",
                 error_kind="cli"),
            case("notools", done_reason="error",
                 error="HTTPError 400: m does not support tools", error_kind="capability"),
        ])
        text = "; ".join(clauses)
        self.assertEqual(len(clauses), 3)
        self.assertIn("1 of 5 sessions answers did not stop on their own terms", text)
        self.assertIn("2 of 5 sessions answers were lost to a harness", text)
        self.assertIn("cli, http", text)
        self.assertIn("1 of 5 sessions answers were skipped because the model does not "
                      "support", text)

    def test_transport_errors_never_read_as_did_not_stop(self):
        clauses = evaluate_models.describe_nonstops("revdeck", 1, [
            case("timeout", done_reason="error", error="Claude Code timed out after 9000s")])
        self.assertNotIn("did not stop", " ".join(clauses))

    def test_agent_turn_cap_is_a_model_nonstop(self):
        self.assertEqual(evaluate_models.nonstop_kind(
            {"output": {"done_reason": "error", "error_kind": "model",
                        "error": "agent turn cap reached (16 turns) without a final answer"}}),
            evaluate_models.NONSTOP_MODEL)

    def test_capability_is_recognised_without_error_kind(self):
        self.assertEqual(evaluate_models.nonstop_kind(
            {"output": {"done_reason": "error",
                        "error": "HTTPError 400: x does not support tools"}}),
            evaluate_models.NONSTOP_CAPABILITY)

    def test_model_nonstop_wins_over_a_harness_error_in_the_same_case(self):
        self.assertEqual(evaluate_models.nonstop_kind({"outputs": [
            {"done_reason": "error", "error": "boom"},
            {"done_reason": "length"}]}), evaluate_models.NONSTOP_MODEL)


if __name__ == "__main__":
    unittest.main()
