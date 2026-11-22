#!/usr/bin/env python3
"""#3319: the lane-summary renderer that separates "ran" from "skipped".

Drives scripts/ci-lane-summary.py's real classify/render/exit-code paths
against hand-built `needs` contexts covering the four states a reader must
be able to tell apart: a lane that ran and passed, one whose executor twin
skipped because routing chose the other, one where NEITHER twin reported
(the bug this exists for), and one that failed.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "ci-lane-summary.py"
_spec = importlib.util.spec_from_file_location("ci_lane_summary", SCRIPT)
assert _spec and _spec.loader
ci_lane_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_lane_summary)


def needs(*pairs: tuple[str, str]) -> dict[str, object]:
    return {job: {"result": result, "outputs": {}} for job, result in pairs}


class ClassifyTest(unittest.TestCase):
    def test_bare_named_pair_becomes_one_lane(self):
        lanes = ci_lane_summary.classify(
            needs(("go-fmt", "success"), ("go-fmt-cloud", "skipped"))
        )
        self.assertEqual(len(lanes), 1)
        self.assertTrue(lanes[0]["pair"])
        self.assertEqual(lanes[0]["job"], "go-fmt")
        self.assertEqual(lanes[0]["homeserver"]["job"], "go-fmt")
        self.assertEqual(lanes[0]["cloud"]["job"], "go-fmt-cloud")

    def test_homeserver_suffixed_pair_becomes_one_lane(self):
        """go-test-homeserver/go-test-cloud: the twin's job id carries -homeserver."""
        lanes = ci_lane_summary.classify(
            needs(
                ("go-test-homeserver", "success"),
                ("go-test-cloud", "skipped"),
            )
        )
        self.assertEqual(len(lanes), 1)
        self.assertEqual(lanes[0]["job"], "go-test-homeserver")
        self.assertEqual(lanes[0]["cloud"]["job"], "go-test-cloud")

    def test_unpaired_job_stays_its_own_lane(self):
        lanes = ci_lane_summary.classify(needs(("quality-gate", "success")))
        self.assertEqual(len(lanes), 1)
        self.assertNotIn("pair", lanes[0])
        self.assertEqual(lanes[0]["job"], "quality-gate")

    def test_a_pair_whose_cloud_twin_is_itself_paired_is_not_double_counted(self):
        """Guards the handled-set: one -cloud entry is consumed exactly once."""
        lanes = ci_lane_summary.classify(
            needs(
                ("go-fmt", "success"),
                ("go-fmt-cloud", "skipped"),
                ("go-test-homeserver", "skipped"),
                ("go-test-cloud", "success"),
            )
        )
        self.assertEqual(len(lanes), 2)


class PairCellTest(unittest.TestCase):
    def _cell(self, home: str, cloud: str) -> tuple[str, str, str]:
        lane = ci_lane_summary.classify(
            needs(("go-fmt", home), ("go-fmt-cloud", cloud))
        )[0]
        return ci_lane_summary._pair_cell(lane)

    def test_homeserver_win_names_the_executor(self):
        verdict, _detail, worst = self._cell("success", "skipped")
        self.assertIn("honeypot-ci", verdict)
        self.assertEqual(worst, "success")

    def test_cloud_win_names_the_executor(self):
        verdict, _detail, worst = self._cell("skipped", "success")
        self.assertIn("ubuntu-latest", verdict)
        self.assertEqual(worst, "success")

    def test_both_skipped_is_not_a_pass(self):
        _verdict, _detail, worst = self._cell("skipped", "skipped")
        self.assertNotEqual(worst, "success")
        self.assertEqual(worst, "skipped")

    def test_failure_outranks_a_passing_twin(self):
        _verdict, _detail, worst = self._cell("success", "failure")
        self.assertEqual(worst, "failure")

    def test_cancellation_is_distinct_from_failure(self):
        _verdict, _detail, worst = self._cell("success", "cancelled")
        self.assertEqual(worst, "cancelled")

    def test_detail_names_both_legs(self):
        _verdict, detail, _worst = self._cell("success", "skipped")
        self.assertIn("go-fmt-cloud", detail)
        self.assertIn("homeserver", detail)

    def test_lanes_render_in_needs_order_not_cloud_order(self):
        """A -cloud leg discovered first must not jump ahead of its twin."""
        lanes = ci_lane_summary.classify(
            needs(
                ("go-test-homeserver", "skipped"),
                ("go-test-cloud", "success"),
                ("public-safety", "success"),
                ("public-safety-cloud", "skipped"),
            )
        )
        self.assertEqual(
            [ci_lane_summary._lane_key(lane) for lane in lanes],
            ["go-test-homeserver", "public-safety"],
        )


class RenderTest(unittest.TestCase):
    def test_ran_and_skipped_read_differently(self):
        report = ci_lane_summary.render(
            needs(("go-fmt", "success"), ("go-fmt-cloud", "skipped")),
            title="Go formatting and tests",
        )
        self.assertIn("Go formatting and tests", report)
        self.assertIn("honeypot-ci", report)
        self.assertIn("1/1 lanes ran and passed", report)
        self.assertNotIn("Not green", report)

    def test_unavailable_lane_is_called_out(self):
        report = ci_lane_summary.render(
            needs(("go-fmt", "skipped"), ("go-fmt-cloud", "skipped"))
        )
        self.assertIn("Not green", report)
        self.assertIn("neither executor reported a result", report)

    def test_skipped_lane_is_listed_as_skipped_not_passed(self):
        report = ci_lane_summary.render(needs(("design-lab-readonly", "skipped")))
        self.assertIn("skipped", report)
        self.assertIn("0/1 lanes ran and passed", report)

    def test_failure_is_listed(self):
        report = ci_lane_summary.render(needs(("backend-service", "failure")))
        self.assertIn("failed", report)
        self.assertIn("Not green", report)

    def test_empty_needs_does_not_raise(self):
        self.assertIn("No lanes", ci_lane_summary.render({}))


class MainExitCodeTest(unittest.TestCase):
    """The guard: anything that is not a passing result exits non-zero."""

    def _exit(self, ctx: dict[str, object]) -> int:
        import contextlib
        import io
        import json
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(ctx, handle)
            path = handle.name
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = ci_lane_summary.main(["--needs-json", path])
        pathlib.Path(path).unlink()
        return code

    def test_all_green_exits_zero(self):
        self.assertEqual(
            self._exit(needs(("ci-target", "success"), ("go-fmt", "success"),
                             ("go-fmt-cloud", "skipped"))),
            0,
        )

    def test_router_skip_with_passing_twin_exits_zero(self):
        self.assertEqual(
            self._exit(needs(("go-fmt", "skipped"), ("go-fmt-cloud", "success"))), 0
        )

    def test_neither_twin_reported_exits_nonzero(self):
        self.assertNotEqual(
            self._exit(needs(("go-fmt", "skipped"), ("go-fmt-cloud", "skipped"))), 0
        )

    def test_lone_skip_exits_nonzero(self):
        self.assertNotEqual(self._exit(needs(("design-lab-readonly", "skipped"))), 0)

    def test_failure_exits_nonzero(self):
        self.assertNotEqual(self._exit(needs(("backend-service", "failure"))), 0)

    def test_cancellation_exits_nonzero(self):
        self.assertNotEqual(self._exit(needs(("backend-service", "cancelled"))), 0)

    def test_allowed_skip_exits_zero_and_names_the_reason(self):
        import contextlib
        import io
        import json
        import tempfile

        ctx = needs(("ci-target", "success"), ("ai-attribution", "skipped"))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(ctx, handle)
            path = handle.name
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = ci_lane_summary.main(
                [
                    "--needs-json",
                    path,
                    "--allow-skip",
                    "ai-attribution:pull_request only",
                ]
            )
        pathlib.Path(path).unlink()
        self.assertEqual(code, 0)
        report = buffer.getvalue()
        self.assertIn("pull_request only", report)
        self.assertIn("skipped", report)
        self.assertNotIn("Not green", report)

    def test_parse_allow_skips_defaults_the_reason(self):
        self.assertEqual(
            ci_lane_summary.parse_allow_skips(["a", "b:because"]),
            {"a": "skipped by design", "b": "because"},
        )


if __name__ == "__main__":
    unittest.main()
