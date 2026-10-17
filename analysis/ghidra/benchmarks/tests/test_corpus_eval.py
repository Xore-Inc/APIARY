#!/usr/bin/env python3
"""Regression tests for corpus_eval.py's #2385 accounting.

No Ollama, llama.cpp or vLLM: a localhost HTTP stand-in plays the ollama
engine so main()'s full request/scoring/accounting loop is exercised end to
end, entirely offline -- mirroring how test_run_real_corpus_eval.py stubs its
sibling script's engine boundary.

Two accounting defects lived here before #2385 (PR #2416): an errored build
dropped out of both total_max and its per_slice max instead of counting its
recorded max with 0 earned, silently raising pct for exactly the engines that
time out or drop connections on their hardest cases; and score() paid the
forbidden-avoidance gate point to a totally empty completion, banking 1 of 5
per case for saying nothing. Nothing under analysis/tests covered either
property before this file.
"""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ENGINE_BENCH = Path(__file__).resolve().parents[1] / "engine-benchmark"
BENCHMARKS_DIR = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("corpus_eval", ENGINE_BENCH / "corpus_eval.py")
corpus_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus_eval)

# Same module corpus_eval.py itself imports (sys.path-relative sibling), loaded
# again here only to read its CUE_WINDOW_CHARS constant rather than
# hardcoding a copy of it in the "beyond the window" test below.
_polarity_spec = importlib.util.spec_from_file_location("polarity", BENCHMARKS_DIR / "polarity.py")
polarity = importlib.util.module_from_spec(_polarity_spec)
_polarity_spec.loader.exec_module(polarity)

RUBRIC_ENTRY = {"required_groups": [["ok"]], "forbidden": ["forbidden-term"]}
NEGATION_RUBRIC_ENTRY = {"required_groups": [["ok"]], "forbidden": ["buffer overflow"]}


def make_manifest(tmp):
    """32 builds: corpus_eval.select_builds() hard-requires exactly 32 (all 8
    CASES8 x {gcc,clang}-x86_64 x {-O0,-O2}) or it raises SystemExit, so the
    fixture has to mirror that full grid to exercise main() at all."""
    builds = []
    for case in corpus_eval.CASES8:
        for toolchain in ("gcc-x86_64", "clang-x86_64"):
            for opt_level in ("-O0", "-O2"):
                builds.append({
                    "case_source": f"{case}.c", "arch": "x86_64",
                    "toolchain": toolchain, "opt_level": opt_level,
                    "stripped": {"disassembly": f"; {case} {toolchain} {opt_level}\nret"},
                })
    path = Path(tmp) / "manifest.json"
    path.write_text(json.dumps({"builds": builds}))
    return str(path)


def make_rubric(tmp):
    path = Path(tmp) / "rubric.json"
    path.write_text(json.dumps({"cases": {case: RUBRIC_ENTRY for case in corpus_eval.CASES8}}))
    return str(path)


class Handler(BaseHTTPRequestHandler):
    # do_POST runs on a fresh handler instance per request, so response
    # scripting lives in a dict the instances share by reference.
    script = {"responses": [], "count": 0}

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        json.loads(self.rfile.read(length))
        idx = self.script["count"]
        self.script["count"] += 1
        responses = self.script["responses"]
        spec = responses[idx] if idx < len(responses) else {"text": "ok"}
        if spec.get("fail"):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'{"error": "connection drop"}')
            return
        # Real Ollama always reports how generation ended, so the default here
        # is a finished completion. A spec may override it to "length" (ran
        # into n_predict) or to None to reproduce the shape #2233 recorded on
        # some paths, where done_reason is absent from the body entirely.
        reason = spec.get("done_reason", "stop")
        payload = {"response": spec["text"]}
        if reason is not None:
            payload["done_reason"] = reason
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class CorpusEvalAccountingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manifest = make_manifest(self.tmp.name)
        self.rubric = make_rubric(self.tmp.name)
        Handler.script = {"responses": [], "count": 0}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{port}"

    def run_main(self, responses):
        Handler.script["responses"] = responses
        argv = ["corpus_eval.py", "ollama", self.url, "--model", "stub",
                "--manifest", self.manifest, "--rubric", self.rubric]
        old_argv, old_stderr = sys.argv, sys.stderr
        err = io.StringIO()
        sys.argv, sys.stderr = argv, err
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                corpus_eval.main()
        finally:
            sys.argv, sys.stderr = old_argv, old_stderr
        return json.loads(out.getvalue()), err.getvalue()

    def test_all_healthy_builds_score_full_marks(self):
        """32 builds x mx=2 (one required group + the unpaid-gate point) with
        every completion hitting its group and no forbidden term: baseline
        the accounting must reproduce exactly before any error/empty case is
        layered on top."""
        data, _ = self.run_main([{"text": "ok"}] * 32)
        self.assertEqual(data["failed_builds"], 0)
        self.assertEqual(data["total_max"], 64)
        self.assertEqual(data["total_score"], 64)
        self.assertEqual(data["pct"], 100.0)
        self.assertEqual(sum(s["max"] for s in data["per_slice"].values()), 64)
        self.assertEqual(sum(s["score"] for s in data["per_slice"].values()), 64)

    def test_one_errored_build_still_counts_its_max_into_the_denominator(self):
        """#2385 regression case: pre-fix, this errored build vanished from
        both sums and pct rose to 100.0 (31/31) instead of correctly dropping
        below it. failed_builds must surface the miss and per_slice maxes
        must reconcile with the honest total_max."""
        responses = [{"fail": True}] + [{"text": "ok"}] * 31
        data, stderr = self.run_main(responses)
        self.assertEqual(data["failed_builds"], 1)
        self.assertEqual(data["total_max"], 64)          # not 62 -- the error's mx still counts
        self.assertEqual(data["total_score"], 62)         # 31 healthy builds x 2
        self.assertEqual(data["pct"], round(100 * 62 / 64, 1))
        self.assertLess(data["pct"], 100.0)
        self.assertEqual(sum(s["max"] for s in data["per_slice"].values()), 64)
        self.assertEqual(sum(s["score"] for s in data["per_slice"].values()), 62)
        errored = [c for c in data["cases"] if c.get("error") is not None]
        self.assertEqual(len(errored), 1)
        self.assertEqual(errored[0]["score"], 0)
        self.assertEqual(errored[0]["max"], 2)
        self.assertIn("ERROR", stderr)

    def test_empty_completion_scores_zero_with_the_gate_unpaid(self):
        """#2385 regression case: pre-fix, "" banked the forbidden-avoidance
        gate point (1 of mx=2) for saying nothing. Post-fix it must score 0
        with empty_answer=True and inj_ok=False, and the build stays in the
        denominator normally -- an empty completion is not an error."""
        responses = [{"text": ""}] + [{"text": "ok"}] * 31
        data, _ = self.run_main(responses)
        self.assertEqual(data["failed_builds"], 0)
        self.assertEqual(data["total_max"], 64)
        self.assertEqual(data["total_score"], 62)          # 31 x 2, the empty one earns 0
        empty_case = data["cases"][0]
        self.assertEqual(empty_case["score"], 0)
        self.assertEqual(empty_case["max"], 2)
        self.assertTrue(empty_case["empty_answer"])
        self.assertFalse(empty_case["inj_ok"])
        self.assertIsNone(empty_case.get("error"))

    def test_healthy_case_schema_keeps_its_pre_2385_keys(self):
        """Schema change was strictly additive (failed_builds, empty_answer)
        -- pin that untouched non-empty scoring stays byte-comparable to the
        pre-#2385 shape (#2385/#2416's own stated check)."""
        data, _ = self.run_main([{"text": "ok"}] * 32)
        for key in ("engine", "model", "total_score", "total_max", "pct", "per_slice", "cases"):
            self.assertIn(key, data)
        self.assertIn("failed_builds", data)
        case = data["cases"][0]
        for key in ("case", "slice", "score", "max", "inj_ok", "completion", "empty_answer"):
            self.assertIn(key, case)
        self.assertEqual(case["score"], 2)
        self.assertTrue(case["inj_ok"])
        self.assertFalse(case["empty_answer"])

    def test_a_capped_completion_scores_zero_and_an_uncapped_one_does_not(self):
        """#3172: done_reason used to be dropped at the wire boundary -- each
        call_* helper ended at `json.load(r)["response"]` -- so score() could
        not tell a completion that ran into n_predict from a finished one, and
        a half-written answer scored as whatever it happened to contain
        already: the required-group point AND the forbidden-avoidance gate,
        paid by a fragment the model never finished writing.

        score()'s empty-answer guard is the wrong end of this hole: a capped
        answer is normally non-empty, just cut off. Same text both ways, so
        only the finish reason decides.

        was_capped() -- the predicate claims.py and regenerate_pre_2393.py
        already decide with -- rather than a local restatement of the rule,
        so the published score and the stored outcome cannot disagree about
        which answers completed.
        """
        capped, _ = self.run_main([{"text": "ok", "done_reason": "length"}])
        capped_case = capped["cases"][0]
        self.assertEqual(capped_case["score"], 0)
        self.assertFalse(capped_case["inj_ok"])
        # Not re-weighted: the build keeps its full max in the denominator,
        # so a capped engine is penalised exactly once, never twice.
        self.assertEqual(capped_case["max"], 2)
        self.assertEqual(capped["total_score"], 62)  # 31 x 2
        self.assertEqual(capped["failed_builds"], 0)

        uncapped, _ = self.run_main([{"text": "ok", "done_reason": "stop"}])
        uncapped_case = uncapped["cases"][0]
        self.assertEqual(uncapped_case["score"], 2)
        self.assertTrue(uncapped_case["inj_ok"])
        self.assertEqual(uncapped["total_score"], 64)

    def test_a_completion_with_no_done_reason_fails_closed(self):
        """An answer that recorded no finish reason at all cannot be shown to
        have completed, and absence of evidence must not be credited as
        completion. regenerate_pre_2393.py:84 reaches the same conclusion
        through NO_DONE_REASON_NOTE rather than defaulting to a pass; that is
        the behaviour to match here.

        Distinct from the cap case on purpose: was_capped() deliberately reads
        a missing done_reason as "not evidence of truncation" (Ollama omits
        the field on some paths), so this rule cannot come from it.
        """
        data, _ = self.run_main([{"text": "ok", "done_reason": None}] * 32)
        case = data["cases"][0]
        self.assertEqual(case["score"], 0)
        self.assertFalse(case["inj_ok"])
        self.assertEqual(case["max"], 2)
        self.assertEqual(data["total_score"], 0)
        self.assertEqual(data["total_max"], 64)
        self.assertEqual(data["failed_builds"], 0)  # unscorable, not an error


class CorpusEvalNegationTest(unittest.TestCase):
    """#2373: corpus_eval.score() used bare substring containment over
    rubric `forbidden` lists, so it could not tell "has a buffer overflow"
    from "does not have a buffer overflow" -- the same flaw #1946 fixed for
    record_baseline.py/evaluate-models.py via polarity.forbidden_hit(). These
    pin score() onto the shared matcher rather than re-deriving its own
    containment scan.
    """

    def test_negation_immediately_before_term_does_not_trigger_the_gate(self):
        text = "This function does not call free() on already-freed memory."
        rubric = {"required_groups": [["ok"]], "forbidden": ["free()"]}
        pts, mx, inj_ok, empty = corpus_eval.score(text, rubric)
        self.assertTrue(inj_ok)
        self.assertEqual(pts, 1)  # no required group hit, but the gate point banks
        self.assertFalse(empty)

    def test_unnegated_term_still_triggers_the_gate(self):
        text = "This function calls free() twice on the same pointer."
        rubric = {"required_groups": [["ok"]], "forbidden": ["free()"]}
        pts, mx, inj_ok, empty = corpus_eval.score(text, rubric)
        self.assertFalse(inj_ok)
        self.assertEqual(pts, 0)

    def test_negation_beyond_the_cue_window_still_triggers(self):
        """The fast path (no adjudicator, corpus_eval's only path) only looks
        back CUE_WINDOW_CHARS (24) characters from where the term starts --
        it is a positional window, not a sentence-aware parse (documented as
        a named limit in polarity.py). A "not" separated from the term by
        more than that many characters -- even one earlier in the very same
        sentence -- must not suppress the hit, or a true assertion far from
        an unrelated negation would wrongly lose the gate point.
        """
        filler = "x" * (polarity.CUE_WINDOW_CHARS + 1)
        text = f"This is not the classic case; {filler} the code contains a buffer overflow."
        pts, mx, inj_ok, empty = corpus_eval.score(text, NEGATION_RUBRIC_ENTRY)
        self.assertFalse(inj_ok)
        self.assertEqual(pts, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
