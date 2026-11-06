#!/usr/bin/env python3
"""A producer with no harmony adaptation refuses a harmony-served model.

#2233's serving adaptation cannot be pointed at a checkpoint from Ollama's
harmony renderer by every producer in this tree. It is a request-shape change
-- `think`, anti-repetition sampling, reasoning effort -- and only
`evaluate-models.py` and `corpus/record_baseline.py` carry it. The other
producers build a body with a `num_predict` and `think: false` and nothing else,
which for the gpt-oss family returns `content: ""` with the whole budget spent
in an analysis channel nobody reads. That was #2233's measured signature, and a
producer that cannot see it publishes the resulting zeros as scores.

Nothing was wrong with any of them: they are pointed at Qwen-family models. The
defect is that nothing said so, so the unsafe case was one `--adjudicator` or
`--model` away, and the failure would have been silent -- a 150-token budget
spent before `final` starts, in a script whose whole output is a number.

So they refuse, and the refusal is one function
(`evaluate-models.require_no_harmony_serving`, reached through
`harmony_policy`) rather than a rule per producer: these sites had already
drifted once by having no shared guard, and the two family tests in the tree
(evaluate-models' tag test, record_baseline's architecture test) do not answer
the same question -- CyberPal2.0-20B is GptOssForCausalLM under a tag that
never says gpt-oss.

Every assertion here reads the refusal, not a widened budget: a floor that
silently widened these budgets would be the declared-vs-sent lie REVIEW4 Q2 was
filed about, one layer out.

No model, no GPU, no Ollama, no network: each producer is driven with the model
it would have been pointed at and every request sink is asserted not to have
been reached.

Run: python analysis/ghidra/benchmarks/tests/test_harmony_producer_refusal.py  (CI quality.yml)
"""

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
CORPUS_DIR = BENCHMARKS_DIR / "corpus"
ENGINE_BENCH = BENCHMARKS_DIR / "engine-benchmark"
sys.path.insert(0, str(BENCHMARKS_DIR))

HARMONY_TAG = "gpt-oss:20b"
PLAIN_TAG = "qwen3:14b"


def _load(path, name):
    """Load a script by path, reusing the one already in sys.modules.

    Same reason test_harmony_budget_guard.py gives: harmony_policy resolves the
    module named "evaluate_models" out of sys.modules, so every assertion below
    has to be holding that same object rather than a private second copy.
    """
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate_models = _load(BENCHMARKS_DIR / "evaluate-models.py", "evaluate_models")
harmony_policy = _load(BENCHMARKS_DIR / "harmony_policy.py", "harmony_policy")
claims = _load(BENCHMARKS_DIR / "claims.py", "claims")
regen = _load(CORPUS_DIR / "regenerate_pre_2393.py", "regenerate_pre_2393")
probe = _load(BENCHMARKS_DIR / "probe-judge-repeat-stability.py",
              "probe_judge_repeat_stability")
corpus_eval = _load(ENGINE_BENCH / "corpus_eval.py", "corpus_eval")
real_corpus_eval = _load(ENGINE_BENCH / "run_real_corpus_eval.py", "run_real_corpus_eval")

PRODUCERS = (
    ("claims.py", claims),
    ("corpus/regenerate_pre_2393.py", regen),
    ("probe-judge-repeat-stability.py", probe),
    ("engine-benchmark/corpus_eval.py", corpus_eval),
    ("engine-benchmark/run_real_corpus_eval.py", real_corpus_eval),
)


def _budget_of(module, fallback):
    """The output budget the module's own request body carries."""
    return getattr(module, "EXTRACTION_NUM_PREDICT", None) or \
        getattr(module, "ADJUDICATOR_NUM_PREDICT", None) or fallback


def _make_manifest(directory):
    """corpus_eval.select_builds() hard-requires its full 32-build grid, so the
    fixture has to mirror it for main() to be reached at all."""
    path = Path(directory) / "manifest.json"
    builds = [{
        "case_source": f"{case}.c", "arch": "x86_64", "toolchain": toolchain,
        "opt_level": opt, "stripped": {"disassembly": f"; {case}\nret"},
    } for case in corpus_eval.CASES8
        for toolchain in ("gcc-x86_64", "clang-x86_64")
        for opt in ("-O0", "-O2")]
    path.write_text(json.dumps({"builds": builds}))
    return path


def _make_rubric(directory):
    path = Path(directory) / "rubric.json"
    path.write_text(json.dumps({"cases": {c: {"required_groups": [["ok"]],
                                               "forbidden": ["nope"]}
                                          for c in corpus_eval.CASES8}}))
    return path


class OneRefusalReachesEveryProducerTest(unittest.TestCase):
    """The property: a harmony-served model is refused, loudly, everywhere.

    Before the propagation each of these producers accepted the tag and would
    have put its own budget on the wire -- 1024 for the claim paths, 150/180 for
    the engine sweeps -- all of them below the floor, none of them saying so.
    """

    def test_every_producer_refuses_a_harmony_served_model(self):
        refusals = {}
        for name, module in PRODUCERS:
            budget = _budget_of(module, 150)
            with self.subTest(producer=name):
                with self.assertRaises(SystemExit) as caught:
                    harmony_policy.refuse_harmony_model_without_adaptation(
                        HARMONY_TAG, producer=name, num_predict=budget)
                refusals[name] = str(caught.exception)

                # The message has to name the producer, so an operator reading a
                # failure knows which script refused, and the floor from the one
                # definition, so a later bump moves every refusal with it.
                self.assertIn(name, refusals[name])
                self.assertIn(str(evaluate_models.HARMONY_NUM_PREDICT), refusals[name])

        # Apart from the producer it names and the budget that producer sends,
        # every refusal is the same sentence: they are one function. Five
        # differently-worded refusals would be five chances to drift back into
        # silence, which is how the two producers disagreed in the first place.
        without_names = {name: re.sub(r"[0-9]+", "N", msg.replace(name, ""))
                         for name, msg in refusals.items()}
        self.assertEqual(len(set(without_names.values())), 1)

    def test_the_floor_moves_with_the_one_definition(self):
        """A private copy of 4096 in any producer would keep waving an
        under-declaring cell through after the floor moved. Bump the owner and
        every refusal follows."""
        original = evaluate_models.HARMONY_NUM_PREDICT
        evaluate_models.HARMONY_NUM_PREDICT = 16384
        try:
            for name, module in PRODUCERS:
                with self.subTest(producer=name):
                    with self.assertRaises(SystemExit) as caught:
                        harmony_policy.refuse_harmony_model_without_adaptation(
                            HARMONY_TAG, producer=name,
                            num_predict=_budget_of(module, 150))
                    self.assertIn("16384", str(caught.exception))
        finally:
            evaluate_models.HARMONY_NUM_PREDICT = original

    def test_a_model_these_producers_can_serve_is_not_refused(self):
        """The green side, without which a guard that refuses everything would
        satisfy the test above."""
        for name, module in PRODUCERS:
            with self.subTest(producer=name):
                self.assertIsNone(harmony_policy.refuse_harmony_model_without_adaptation(
                    PLAIN_TAG, producer=name, num_predict=150))
        # ... and the family test is the owner's, not a copy of the tag list:
        # a qwen tag and a cyberpal alias are the two answers that differ.
        self.assertTrue(evaluate_models.is_harmony_served(HARMONY_TAG))
        self.assertFalse(evaluate_models.is_harmony_served(PLAIN_TAG))


class ClaimsRefusesAtThePointTheModelIsChosenTest(unittest.TestCase):
    """claims.py's adjudicator is what the whole claim pool is built from, and
    its refusal has to land before the extraction loop asks it anything."""

    def _run_main(self, adjudicator, tmp, sent):
        pool = Path(tmp) / "pool.json"
        run_dir = Path(tmp) / "run"
        run_dir.mkdir()
        (run_dir / "transcripts.jsonl").write_text("")
        argv = ["claims.py", str(run_dir), "--pool", str(pool),
                "--adjudicator", adjudicator, "--api-base", "http://stub:11434"]
        old = sys.argv
        sys.argv = argv
        try:
            claims.main()
        finally:
            sys.argv = old

    def test_a_harmony_adjudicator_ends_the_run_before_any_request(self):
        import contextlib
        import io
        from unittest import mock

        def explode(*a, **kw):
            raise AssertionError("a refused adjudicator must send no request")

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(claims, "_post_json", side_effect=explode), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    self._run_main(HARMONY_TAG, tmp, [])
        self.assertIn("claims.py", str(caught.exception))
        self.assertIn(str(claims.EXTRACTION_NUM_PREDICT), str(caught.exception))

    def test_the_rulings_path_never_asks_the_model_so_it_is_not_refused(self):
        """`--rulings` applies a human decision file and prompts nothing. A
        refusal there would fail a run that never sends a request."""
        import contextlib
        import io
        import tempfile as tf
        from unittest import mock

        with tf.TemporaryDirectory() as tmp:
            pool = Path(tmp) / "pool.json"
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            (run_dir / "transcripts.jsonl").write_text("")
            rulings = Path(tmp) / "rulings.json"
            rulings.write_text(json.dumps([]))
            argv = ["claims.py", str(run_dir), "--pool", str(pool),
                    "--rulings", str(rulings), "--adjudicator", HARMONY_TAG,
                    "--api-base", "http://stub:11434"]
            old = sys.argv
            sys.argv = argv
            try:
                with mock.patch.object(claims, "_post_json",
                                       side_effect=AssertionError("no request here")), \
                     contextlib.redirect_stdout(io.StringIO()):
                    claims.main()
            finally:
                sys.argv = old


class RescoreAdjudicatorRefusedTest(unittest.TestCase):
    """regenerate_pre_2393.py re-runs claims.py's adjudicator call over the
    stored pre-#2393 answers, so its refusal has to be in build_chat -- before
    the closure exists, hence before any request can be built."""

    def test_a_harmony_adjudicator_is_refused_and_no_chat_closure_is_built(self):
        with self.assertRaises(SystemExit) as caught:
            regen.build_chat("http://stub:11434", HARMONY_TAG)
        self.assertIn("regenerate_pre_2393.py", str(caught.exception))
        self.assertIn(str(regen.ADJUDICATOR_NUM_PREDICT), str(caught.exception))

    def test_the_serveable_adjudicator_still_builds_a_chat(self):
        chat = regen.build_chat("http://stub:11434", PLAIN_TAG)
        self.assertTrue(callable(chat))


class JudgeProbeRefusedTest(unittest.TestCase):
    """The probe exists to tell a stable judge from a drifting one. A harmony
    adjudicator answers nothing, so every trial hashes to the same empty claim
    set and the probe reports STABLE -- a stability finding about silence."""

    def _main(self, argv):
        import contextlib
        import io
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                return probe.main()
        finally:
            sys.argv = old

    def test_the_live_path_refuses_a_harmony_adjudicator(self):
        argv = ["probe-judge-repeat-stability.py", "--base-url", "http://stub:11434",
                "--adjudicator", HARMONY_TAG, "--case", "c", "--answer", "text",
                "--repeats", "2"]
        with self.assertRaises(SystemExit) as caught:
            self._main(argv)
        self.assertIn("probe-judge-repeat-stability.py", str(caught.exception))

    def test_the_dry_run_refuses_too(self):
        """--dry-run's entire output is the request that would go out. Printing
        that template for a cell this probe would refuse is how the refusal gets
        read past and copied into a real run."""
        argv = ["probe-judge-repeat-stability.py", "--base-url", "http://stub:11434",
                "--adjudicator", HARMONY_TAG, "--case", "c", "--dry-run"]
        with self.assertRaises(SystemExit):
            self._main(argv)

    def test_a_serveable_adjudicator_plans_as_before(self):
        argv = ["probe-judge-repeat-stability.py", "--base-url", "http://stub:11434",
                "--adjudicator", PLAIN_TAG, "--case", "c", "--dry-run"]
        self.assertEqual(self._main(argv), 0)

    def test_the_planned_body_still_matches_the_one_claims_sends(self):
        """The probe's premise is byte-parity with claims.py's own call, so the
        budget it plans has to be the budget claims.py sends."""
        body = probe._chat_body(PLAIN_TAG, claims.EXTRACTION_SYSTEM, "prompt")
        self.assertEqual(body["options"]["num_predict"], claims.EXTRACTION_NUM_PREDICT)


class _EngineScriptBase(unittest.TestCase):
    """Both engine-benchmark scorers are driven through main() against a real
    localhost HTTP stand-in, so the refusal is proven to land at the model
    choice and before the first /api/generate."""

    engine_arg = "ollama"

    def setUp(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        posts = []
        script = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                posts.append(json.loads(self.rfile.read(length)))
                body = (b'{"response": "ok"}' if script.is_ollama_engine
                        else b'{"content": "ok"}')
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.posts = posts
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def run_main(self, extra_argv):
        import contextlib
        import io
        old_argv, old_stderr = sys.argv, sys.stderr
        out, err = io.StringIO(), io.StringIO()
        sys.argv, sys.stderr = extra_argv, err
        try:
            with contextlib.redirect_stdout(out):
                self.module.main()
        finally:
            sys.argv, sys.stderr = old_argv, old_stderr
        return out.getvalue()


class CorpusEvalRefusesHarmonyTest(_EngineScriptBase):
    module = corpus_eval
    is_ollama_engine = True

    def setUp(self):
        super().setUp()
        scratch = self.enterContext(tempfile.TemporaryDirectory())
        self.manifest = _make_manifest(scratch)
        self.rubric = _make_rubric(scratch)

    def _argv(self, model):
        return ["corpus_eval.py", "ollama", self.url, "--model", model,
                "--manifest", str(self.manifest), "--rubric", str(self.rubric)]

    def test_a_harmony_model_is_refused_and_nothing_is_requested(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_main(self._argv(HARMONY_TAG))
        self.assertIn("corpus_eval.py", str(caught.exception))
        # 150 is this script's own default -- the number on the wire, which the
        # refusal names against the floor.
        self.assertIn("150", str(caught.exception))
        self.assertEqual(self.posts, [],
                         "a refused model must send no /api/generate at all")

    def test_the_sweep_still_runs_for_a_serveable_model(self):
        """The green side, end to end: 32 builds, all requested, all scored."""
        data = json.loads(self.run_main(self._argv(PLAIN_TAG)))
        self.assertEqual(len(self.posts), 32)
        self.assertEqual(data["total_max"], 64)


class RealCorpusEvalRefusesHarmonyTest(_EngineScriptBase):
    module = real_corpus_eval
    is_ollama_engine = False

    def setUp(self):
        super().setUp()
        self.evidence_dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for i in range(2):
            (self.evidence_dir / f"samp{i}.evidence.json").write_text(json.dumps({
                "machine": "0x14c", "is_dll": False,
                "imports": ["kernel32.dll!fn"], "imports_count": 1,
                "strings_sample": ["a"], "sections": [{"name": ".text", "entropy": 1.0}],
            }))
        self.rubric = self.evidence_dir / "rubric.json"
        self.rubric.write_text(json.dumps(
            {"required_groups": [{"label": "net", "terms": ["socket"]}]}))

    def _argv(self, model):
        return ["run_real_corpus_eval.py", "ollama", self.url, "--model", model,
                "--evidence-dir", str(self.evidence_dir), "--rubric", str(self.rubric)]

    def test_a_harmony_model_is_refused_and_nothing_is_requested(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_main(self._argv(HARMONY_TAG))
        self.assertIn("run_real_corpus_eval.py", str(caught.exception))
        self.assertIn("180", str(caught.exception))
        self.assertEqual(self.posts, [])

    def test_the_sweep_still_runs_for_a_serveable_model(self):
        data = json.loads(self.run_main(self._argv(PLAIN_TAG)))
        self.assertEqual(len(self.posts), 2)
        self.assertEqual(data["n_samples"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)