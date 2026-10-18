"""Tests for the opt-in web-tooling path in the benchmark harness.

Registered in .github/workflows/quality.yml. Kept as a plain unittest script
because that is how CI executes the rest of benchmarks/tests/.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench_tools as bt
import transcripts as tr


def _load_evaluator():
    """evaluate-models.py is not importable by name (hyphen); load by path."""
    import importlib.util
    # The target filename contains a hyphen, so spec_from_file_location needs
    # the explicit ".py" suffix or it returns a spec with no loader.
    path = Path(__file__).resolve().parents[1] / "evaluate-models.py"
    spec = importlib.util.spec_from_file_location("coder_evaluator", str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load evaluator from {path}")
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves annotations via sys.modules; without this the
    # decorators blow up on a module that was never registered.
    sys.modules["coder_evaluator"] = module
    spec.loader.exec_module(module)
    return module


class TestToolDefinitions(unittest.TestCase):
    def test_both_tools_well_formed(self):
        for tool in bt.DEFAULT_TOOLS:
            self.assertEqual(tool["type"], "function")
            fn = tool["function"]
            self.assertIn(fn["name"], ("web_search", "web_fetch"))
            self.assertEqual(fn["parameters"]["type"], "object")
            self.assertTrue(fn["parameters"]["required"])
            self.assertTrue(fn["description"].strip())

    def test_fetch_rejects_non_http_scheme(self):
        self.assertIn("refused", bt.fetch_text("file:///etc/passwd"))
        self.assertIn("refused", bt.fetch_text("ftp://example.invalid/x"))


class TestExtractCall(unittest.TestCase):
    def test_structured_tool_call(self):
        got = bt.extract_call({"tool_calls": [{"function": {
            "name": "web_search", "arguments": '{"query":"x"}'}}]})
        self.assertEqual(got, ("web_search", {"query": "x"}))

    def test_textual_tool_call(self):
        # The common case on this roster: Ollama returned tool_calls=None and the
        # model emitted the call as JSON text. A loop that only reads the
        # structured field silently does nothing here.
        got = bt.extract_call({"content": '{"name":"web_search","arguments":{"query":"x"}}'})
        self.assertEqual(got, ("web_search", {"query": "x"}))

    def test_plain_prose_is_not_a_call(self):
        self.assertIsNone(bt.extract_call({"content": "Here is a C23 example: int x;"}))

    def test_malformed_json_is_not_a_call(self):
        self.assertIsNone(bt.extract_call({"content": '{"name":"web_search",'}))

    def test_non_dict_json_is_not_a_call(self):
        self.assertIsNone(bt.extract_call({"content": '[1, 2, 3]'}))

    def test_call_without_arguments_is_ignored(self):
        self.assertIsNone(bt.extract_call({"content": '{"name":"web_search"}'}))

    def test_string_arguments_are_parsed(self):
        got = bt.extract_call({"tool_calls": [{"function": {
            "name": "web_search", "arguments": '{"query":"y"}'}}]})
        self.assertEqual(got[1]["query"], "y")


class TestToolRounds(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._orig = bt._SEARCH_BACKEND
        bt.set_search_backend(lambda q, l: [
            {"title": "Advisory", "url": "https://example.invalid/a", "description": "d"}])

    def tearDown(self):
        bt.set_search_backend(self._orig)

    def test_loop_executes_tool_then_answers(self):
        first = {"message": {"role": "assistant", "content":
                 '{"name":"web_search","arguments":{"query":"cve"}}'},
                 "done_reason": "stop"}

        def post(url, body):
            # The first response is passed in, so post() is only ever a
            # follow-up turn -- here exactly one.
            self.calls.append(body)
            return {"message": {"content": "answer citing the advisory"},
                    "done_reason": "stop"}

        out = bt.conduct_tool_rounds(post, "http://x/api/chat", {
            "model": "m", "messages": [{"role": "user", "content": "find"}],
            "stream": False}, first)
        self.assertEqual(out["message"]["content"], "answer citing the advisory")
        self.assertEqual(len(out["tool_turns"]), 1)
        self.assertEqual(out["tool_turns"][0]["tool"], "web_search")
        # The original body must not be mutated by the follow-up turns.
        self.assertEqual(len(self.calls[0]["messages"]), 3)
        self.assertEqual(self.calls[0]["messages"][-2], first["message"])

    def test_structured_tool_call_is_preserved_in_followup_history(self):
        message = {"role": "assistant", "content": "", "tool_calls": [{
            "function": {"name": "web_search", "arguments": {"query": "cve"}},
        }]}
        calls = []

        def post(url, body):
            calls.append(body)
            return {"message": {"role": "assistant", "content": "done"},
                    "done_reason": "stop"}

        bt.conduct_tool_rounds(post, "u", {"messages": []}, {"message": message})

        self.assertEqual(calls[0]["messages"][-2], message)
        self.assertEqual(calls[0]["messages"][-1]["role"], "tool")

    def test_no_call_means_no_extra_post(self):
        calls = []

        def post(url, body):
            calls.append(body)
            return {"message": {"content": "no tools needed"}, "done_reason": "stop"}

        out = bt.conduct_tool_rounds(post, "u", {"messages": []},
                                     {"message": {"content": "plain"}, "done_reason": "stop"})
        self.assertEqual(len(calls), 0)  # nothing to fetch, so no follow-up post
        self.assertNotIn("tool_turns", out)

    def test_round_cap_is_enforced(self):
        def post(url, body):
            return {"message": {"content": '{"name":"web_search","arguments":{"query":"loop"}}'},
                    "done_reason": "stop"}

        out = bt.conduct_tool_rounds(post, "u", {"messages": []},
                                     {"message": {"content": '{"name":"web_search",'
                                                            '"arguments":{"query":"loop"}}'},
                                      "done_reason": "stop"},
                                     max_rounds=3)
        self.assertEqual(len(out["tool_turns"]), 3)

    def test_tool_failure_is_reported_not_raised(self):
        def boom(q, l):
            raise RuntimeError("backend down")

        bt.set_search_backend(boom)
        out = bt.run_tool("web_search", {"query": "x"})
        self.assertIn("unavailable", out)
        self.assertIn("backend down", out)

    def test_unknown_tool_is_reported(self):
        self.assertIn("unknown tool", bt.run_tool("rm_rf", {}))

    def test_result_turn_shape_matches_ollama(self):
        turn = bt.tool_result_turn("web_fetch", "body text")
        self.assertEqual(turn["role"], "tool")
        self.assertEqual(turn["tool_name"], "web_fetch")
        self.assertEqual(turn["content"], "body text")


class TestCoderArtifacts(unittest.TestCase):
    """One readable source file per generated answer.

    The answers were already captured, but only inside JSON. Grading code out
    of an escaped string is the tax these files remove, so they must exist and
    must be readable. They are inert: nothing here executes or compiles them.
    """

    def _writer(self, tmp):
        class W:
            directory = tmp
        return W()

    def _cases(self):
        return {
            "command-control-http-beacon": {
                "case": "command-control-http-beacon", "capped": False,
                "degenerate": False,
                "output": {"content": "import socket\ns = socket.socket()\ns.connect(('192.168.1.100', 8080))\nprint('connected')\n",
                           "prose": "import socket\ns = socket.socket()\ns.connect(('192.168.1.100', 8080))\nprint('connected')\n"},
            },
            "credential-access-shadow-parser": {
                "case": "credential-access-shadow-parser", "capped": True,
                "degenerate": False,
                "output": {"content": "#include <stdio.h>\nint main() { return 0; }\n",
                           "prose": "#include <stdio.h>\nint main() { return 0; }\n"},
            },
        }

    def test_writes_one_file_per_case_with_declared_extension(self):
        import tempfile
        ev=_load_evaluator()
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            w = self._writer(Path(tmp))
            n = ev.write_coder_artifacts(w, {"tag": "m:q4"}, self._cases())
            self.assertEqual(n, 2)
            root = Path(tmp) / "coder-artifacts" / "m:q4"
            sources = sorted(p.name for p in root.iterdir() if p.suffix in (".py", ".c"))
            self.assertEqual(sources, ["command-control-http-beacon.py",
                                       "credential-access-shadow-parser.c"])
            self.assertTrue((root / "compile-report.json").exists())

    def test_file_carries_provenance_header_and_content(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            ev.write_coder_artifacts(w, {"tag": "m:q4"}, self._cases())
            p = Path(tmp) / "coder-artifacts" / "m:q4" / "credential-access-shadow-parser.c"
            body = p.read_text()
            self.assertIn("model: m:q4", body)
            self.assertIn("case:  credential-access-shadow-parser", body)
            self.assertIn("capped: True", body)
            self.assertIn("INERT MODEL OUTPUT", body)
            self.assertNotIn("never executed, compiled or parsed", body)
            self.assertTrue(body.rstrip().endswith("return 0; }"))

    def test_tag_directory_is_exactly_the_tag_with_slashes_removed(self):
        # Only "/" is rewritten. A colon is legal in a directory name on Linux
        # and appears in every Ollama tag, so rewriting it would lose the
        # identity of the model in the path.
        import tempfile
        ev = _load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            ev.write_coder_artifacts(w, {"tag": "hf.co/a/b:Q4_K_M"}, self._cases())
            self.assertTrue((Path(tmp) / "coder-artifacts" / "hf.co_a_b:Q4_K_M").is_dir())

    def test_tag_with_slash_cannot_escape_the_directory(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            ev.write_coder_artifacts(w, {"tag": "hf.co/a/b:c"}, self._cases())
            self.assertTrue((Path(tmp) / "coder-artifacts" / "hf.co_a_b:c").is_dir())

    def test_no_prose_or_written_file_skips_the_graded_artifact(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            record = {"case": "re-pe-pe-section-walker",
                      "output": {"content": "serialized call", "prose": ""}}
            n = ev.write_coder_artifacts(
                w, {"tag": "m"}, {"re-pe-pe-section-walker": record})
            root = Path(tmp) / "coder-artifacts" / "m"
            self.assertEqual(n, 0)
            self.assertFalse(record["source_artifact_present"])
            self.assertFalse((root / "re-pe-pe-section-walker.c").exists())
            report = __import__("json").loads((root / "compile-report.json").read_text())
            self.assertFalse(report["re-pe-pe-section-walker"]["attempted"])
            self.assertIn("no source", report["re-pe-pe-section-walker"]["reason"])

    def test_no_cases_writes_no_model_directory(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            self.assertEqual(ev.write_coder_artifacts(w, {"tag": "m"}, {}), 0)
            self.assertFalse((Path(tmp) / "coder-artifacts").exists())

    def test_artifact_index_appends_each_case_and_matches_copied_paths(self):
        import json
        from unittest import mock

        ev = _load_evaluator()
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp)
            root = run_root / "coder-artifacts" / "m:q4"
            root.mkdir(parents=True)
            index = run_root / "artifact-index.jsonl"
            records = []
            for case_id, rel, mechanism in (
                ("case-a", "src/main.rs", "api_tool"),
                ("case-b", "extractor.py", "text_block"),
            ):
                sandbox = run_root / f"sandbox-{case_id}"
                source = sandbox / rel
                source.parent.mkdir(parents=True)
                source.write_text(f"// {case_id}\n")
                record = {
                    "case": case_id,
                    "sandbox_dir": str(sandbox),
                    "output": {"prose": ""},
                    "files_written_paths": [rel] if mechanism == "api_tool" else [],
                    "text_block_paths": [rel] if mechanism == "text_block" else [],
                }
                records.append(record)

            metadata = {
                "case-a": ("Rust", "src/main.rs"),
                "case-b": ("Python", "extractor.py"),
                "case-empty": ("Rust", "main.rs"),
            }
            with (mock.patch.object(ev, "_coder_case_files", return_value=metadata),
                  mock.patch.object(ev, "compile_check", return_value={"ok": True})):
                for record in records:
                    ev.write_coder_artifact_file(
                        root, {"tag": "m:q4"}, record["case"], record, {},
                        run_root / "compile", artifact_index=index)

                lines = [json.loads(line) for line in index.read_text().splitlines()]
                self.assertEqual([line["case"] for line in lines], ["case-a", "case-b"])
                self.assertEqual(lines[0]["paths"], {
                    "tool-written/src/main.rs": "api_tool",
                })
                self.assertEqual(lines[1]["paths"], {
                    "text-block/extractor.py": "text_block",
                })
                indexed_paths = {path for line in lines for path in line["paths"]}
                copied_paths = {
                    path.relative_to(root).as_posix()
                    for tier in (root / "tool-written", root / "text-block")
                    for path in tier.rglob("*")
                    if path.is_file() and path.name != "source-manifest.json"
                }
                self.assertEqual(indexed_paths, copied_paths)

                empty_sandbox = run_root / "sandbox-case-empty"
                empty_sandbox.mkdir()
                empty_record = {
                    "case": "case-empty", "sandbox_dir": str(empty_sandbox),
                    "output": {"prose": ""}, "files_written_paths": [],
                    "text_block_paths": [],
                }
                ev.write_coder_artifact_file(
                    root, {"tag": "m:q4"}, "case-empty", empty_record, {},
                    run_root / "compile", artifact_index=index)

            lines = [json.loads(line) for line in index.read_text().splitlines()]
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[-1], {
                "case": "case-empty", "model": "m:q4", "paths": {},
            })

    def test_every_corpus_case_resolves_to_an_extension(self):
        ev=_load_evaluator()
        meta = ev._coder_case_files()
        self.assertGreater(len(meta), 0)
        for case_id, (language, declared) in meta.items():
            ext = Path(declared).suffix or ev._EXT_BY_LANGUAGE.get(language, ".txt")
            self.assertTrue(ext.startswith("."), case_id)
            self.assertNotEqual(ext, ".txt", f"{case_id} fell back to .txt")


class TestStreamingArtifacts(unittest.TestCase):
    """Artifacts must appear per case, not after the whole model finishes.

    A run interrupted mid-model used to leave no artifacts at all, which reads
    as "the feature never worked" rather than "the run stopped".
    """

    def _module(self):
        return _load_evaluator()

    def test_score_coder_calls_sink_per_case(self):
        m = self._module()
        seen = []

        def fake_chat(*a, **k):
            return {"content": "DONE: complete", "output_tokens": 5}

        m.chat = fake_chat
        m.CODER_MAX_ROUNDS = 2
        m.CODER_CASES = [
            type("C", (), {"name": "a.rs", "prompt": "p", "bucket": "b"})(),
            type("C", (), {"name": "b.rs", "prompt": "p", "bucket": "b"})(),
        ]
        m.score_coder("u", "mod", 4096, None, seen.append)
        self.assertEqual([r["case"] for r in seen], ["a.rs", "b.rs"])

    def test_sink_is_optional(self):
        m = self._module()
        m.chat = lambda *a, **k: {"content": "DONE", "output_tokens": 1}
        m.CODER_MAX_ROUNDS = 1
        m.CODER_CASES = [type("C", (), {"name": "a.rs", "prompt": "p",
                                        "bucket": "b"})()]
        self.assertEqual(len(m.score_coder("u", "mod", 4096, None)), 1)

    def test_streamed_file_is_on_disk_before_end(self):
        m = self._module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "arts"
            root.mkdir()
            compile_results = {}
            workdir = Path(tempfile.mkdtemp())
            rec = {"output": {"content": "fn main() {}", "prose": "fn main() {}"},
                   "capped": False, "degenerate": False}
            m._coder_case_files = lambda: {"a.rs": ("rust", "a.rs")}
            m.write_coder_artifact_file(root, {"tag": "mod:q4"}, "a.rs", rec,
                                        compile_results, workdir)
            f = root / "a.rs"
            self.assertTrue(f.exists())
            self.assertIn("fn main() {}", f.read_text())
            self.assertIn("a.rs", compile_results)
            self.assertFalse((root / ".compile.rs").exists())


class TestCompileCheck(unittest.TestCase):
    """Compilation is a diagnostic: it may produce a binary, it never runs one,
    and no result moves a score. The critical property is that nothing built
    from generated code survives the check."""

    def setUp(self):
        self.ev = _load_evaluator()

    def test_every_corpus_source_extension_has_a_checker(self):
        extensions = {
            Path(declared).suffix
            for _, declared in self.ev._coder_case_files().values()
        }
        self.assertEqual(extensions, {".c", ".cpp", ".php", ".py", ".rs", ".sh"})
        self.assertEqual(extensions - self.ev._COMPILE.keys(), set())
        self.assertEqual(self.ev._COMPILE[".py"][0][:3],
                         ["python3", "-m", "py_compile"])
        self.assertEqual(self.ev._COMPILE[".php"][0][:2], ["php", "-l"])
        self.assertEqual(self.ev._COMPILE[".sh"][0][:2], ["bash", "-n"])

    def test_valid_cpp_compiles(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "ok.cpp"
            src.write_text("int main(){return 0;}\n")
            r = self.ev.compile_check(src, Path(t) / "work")
            self.assertTrue(r["attempted"])
            self.assertTrue(r["ok"])
            self.assertEqual(r["returncode"], 0)

    def test_invalid_cpp_fails_with_diagnostics(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "bad.cpp"
            src.write_text("int main(){ this is not c++ }\n")
            r = self.ev.compile_check(src, Path(t) / "work")
            self.assertTrue(r["attempted"])
            self.assertFalse(r["ok"])
            self.assertNotEqual(r["returncode"], 0)
            self.assertTrue(r["diagnostics"].strip())

    def test_rust_compile_uses_an_explicit_valid_crate_name(self):
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / ".compile.rs"
            src.write_text("fn main() {}\n")
            with mock.patch.object(self.ev.shutil, "which", return_value="/usr/bin/rustc"), \
                 mock.patch.object(self.ev.subprocess, "run",
                                   return_value=SimpleNamespace(returncode=0, stderr="", stdout="")) as run:
                result = self.ev.compile_check(src, Path(t) / "work")
            argv = run.call_args.args[0]
            self.assertEqual(argv[argv.index("--crate-name") + 1], "benchmark_artifact")
            self.assertTrue(result["ok"])

    def test_binary_is_deleted_on_success_and_failure(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            work = Path(t) / "work"
            for name, body in (("ok.cpp", "int main(){return 0;}\n"),
                               ("bad.cpp", "int main(){ @@@ }\n")):
                src = Path(t) / name
                src.write_text(body)
                self.ev.compile_check(src, work)
                self.assertEqual(list(work.glob("*.bin")), [], f"{name} left a binary")

    def test_python_syntax_check_keeps_bytecode_out_of_the_artifact_directory(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            artifact_dir = Path(t) / "artifacts"
            artifact_dir.mkdir()
            src = artifact_dir / "x.py"
            src.write_text("print(1)\n")
            r = self.ev.compile_check(src, Path(t) / "work")
            self.assertTrue(r["attempted"])
            self.assertTrue(r["ok"])
            self.assertFalse((artifact_dir / "__pycache__").exists())

    def test_python_syntax_error_is_a_failed_check(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "x.py"
            src.write_text("def broken(:\n")
            r = self.ev.compile_check(src, Path(t) / "work")
            self.assertTrue(r["attempted"])
            self.assertFalse(r["ok"])
            self.assertTrue(r["diagnostics"].strip())

    def test_shell_syntax_is_checked_without_execution(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            marker = Path(t) / "executed"
            good = Path(t) / "good.sh"
            good.write_text(f"touch {marker}\n")
            bad = Path(t) / "bad.sh"
            bad.write_text("if true; then\n")
            self.assertTrue(self.ev.compile_check(good, Path(t) / "work")["ok"])
            self.assertFalse(marker.exists())
            self.assertFalse(self.ev.compile_check(bad, Path(t) / "work")["ok"])

    def test_missing_php_is_an_unavailable_check_not_a_syntax_failure(self):
        import tempfile
        from pathlib import Path
        from unittest import mock
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "x.php"
            src.write_text("<?php echo 1;\n")
            with mock.patch.object(self.ev.shutil, "which", return_value=None):
                r = self.ev.compile_check(src, Path(t) / "work")
            self.assertTrue(r["attempted"])
            self.assertIsNone(r["ok"])
            self.assertEqual(r["reason"], "php not installed")

    def test_missing_compiler_is_reported_not_raised(self):
        import tempfile
        from pathlib import Path
        from unittest import mock
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "x.cpp"
            src.write_text("int main(){return 0;}\n")
            with mock.patch.object(self.ev.shutil, "which", return_value=None):
                r = self.ev.compile_check(src, Path(t) / "work")
            self.assertTrue(r["attempted"])
            self.assertIsNone(r["ok"])
            self.assertIn("not installed", r["reason"])

    def test_compiler_crash_does_not_propagate(self):
        import tempfile
        from pathlib import Path
        from unittest import mock
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "x.cpp"
            src.write_text("int main(){return 0;}\n")
            with mock.patch.object(self.ev.subprocess, "run",
                                   side_effect=OSError("boom")):
                r = self.ev.compile_check(src, Path(t) / "work")
            self.assertFalse(r["ok"])
            self.assertIn("boom", r["diagnostics"])

    def test_compile_report_is_written_alongside_artifacts(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as t:
            class W:
                directory = Path(t)
            ev = self.ev
            ev.CODER_CASES = ev.CODER_CASES[:1]
            cases = {"credential-access-shadow-parser": {
                "case": "credential-access-shadow-parser",
                "output": {"content": "int main(){return 0;}\n",
                           "prose": "int main(){return 0;}\n"}}}
            ev.write_coder_artifacts(W(), {"tag": "m:q4"}, cases)
            report = Path(t) / "coder-artifacts" / "m:q4" / "compile-report.json"
            self.assertTrue(report.exists())
            import json
            data = json.loads(report.read_text())
            self.assertIn("credential-access-shadow-parser", data)
            self.assertTrue(data["credential-access-shadow-parser"]["ok"])


class TestCoderRounds(unittest.TestCase):
    """The model continues its own work until it declares completion.

    A one-shot generation is not a fair coding test -- most single-round
    answers are incomplete rather than wrong. The loop must therefore carry
    the previous answer forward, stop on the marker, and always record why it
    stopped.
    """

    def setUp(self):
        self.ev = _load_evaluator()

    def test_marker_detection(self):
        for text in ("...\nIMPLEMENTATION COMPLETE", "Task Complete", "all checks pass"):
            self.assertTrue(self.ev._declares_done(text), text)
        for text in ("", "here is the file", "complete=1", "unfinished"):
            self.assertFalse(self.ev._declares_done(text), text)

    def test_continuation_prompt_does_not_resend_the_previous_answer(self):
        """The prior answer is delegated to read_file, not re-sent inline.

        Re-sending it whole is what the owner's complaint named ("do not
        simply resend the whole source code as answer"), and it is also a
        measured window defect: at the 16000-token budget a full-budget answer
        is ~64,000 chars, so the continuation prompt needed 32,302 tokens
        against a 24,576 window and truncated silently from round 2 on. The
        window-sizing assertion lives in test_truncation_outcome.py; this one
        pins the prompt's own shape.
        """
        case = self.ev.CODER_CASES[0]
        prompt = self.ev._continuation_prompt(case, "int main(){}", 2)
        self.assertNotIn("int main(){}", prompt)
        self.assertIn(case.prompt, prompt)
        self.assertIn("Continuation round 2", prompt)
        self.assertIn("IMPLEMENTATION COMPLETE", prompt)
        # The iteration is delegated to the file on disk, which is what the
        # model reads instead -- so the prompt has to name that tool.
        self.assertIn("read_file", prompt)

    def test_continuation_prompt_requires_real_platform_code(self):
        """Explicit Windows and Linux, real APIs, no simulated lookups.

        The owner's requirement verbatim: make the code explicit for windows
        and linux, no fake group searches or whatever, always use windows API
        or linux. Asserted on the prompt because the prompt is the only lever
        the harness has -- there is no other place a model is told what to do.
        """
        case = self.ev.CODER_CASES[0]
        prompt = self.ev._continuation_prompt(case, "", 2).lower()
        for needle in ("windows", "linux", "/proc", "hkey_local_machine",
                       "systemroot", "never fake"):
            self.assertIn(needle, prompt)
        # The named anti-patterns, not just the platforms.
        self.assertIn("simulated group lookup", prompt)
        self.assertIn("invented api", prompt)

    def test_continuation_prompt_is_not_a_review_request(self):
        """Not "here is the source code, find what is missing and implement".

        The complaint being fixed was exactly that shape, so the replacement
        has to be a procedure the model can execute: read back, walk the
        requirements one at a time, fix, write back, re-read.
        """
        case = self.ev.CODER_CASES[0]
        prompt = self.ev._continuation_prompt(case, "", 2)
        self.assertIn("one at a time", prompt)
        self.assertIn("actually on disk", prompt)
        self.assertIn("Re-read the file", prompt)
        self.assertNotIn("here is the source code", prompt.lower())

    def _run_with(self, replies, max_rounds=5):
        """Drive score_coder against canned replies; return the records."""
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]
        self.ev.CODER_MAX_ROUNDS = max_rounds
        seen = []

        def fake_chat(base_url, model, system, prompt, context, thinking, **kw):
            seen.append(prompt)
            reply = replies[len(seen) - 1]
            # `prose` is what scoring reads: chat() sets it to the model's own
            # words, keeping `content` free to be a tool_calls serialization.
            return {"content": reply, "prose": reply, "output_tokens": 10,
                    "done_reason": "stop", "prompt_tokens": 5, "wall_seconds": 1.0}
        self.ev.chat = fake_chat
        return self.ev.score_coder("u", "m", 16384), seen

    def test_stops_immediately_when_declared_done(self):
        records, seen = self._run_with(["int main(){}\nIMPLEMENTATION COMPLETE"])
        self.assertEqual(len(seen), 1)
        self.assertEqual(records[0]["round_count"], 1)
        self.assertEqual(records[0]["stopped_because"], "declared_complete")

    def test_loops_until_the_marker(self):
        records, seen = self._run_with(
            ["draft one", "draft two", "final\nIMPLEMENTATION COMPLETE"])
        self.assertEqual(len(seen), 3)
        self.assertEqual(records[0]["round_count"], 3)
        self.assertEqual(records[0]["stopped_because"], "declared_complete")
        # Each round is a continuation of the work, not a fresh start: round N's
        # prompt carries the case and the iteration protocol, and reads the
        # prior state off disk rather than re-sending the prior answer (see
        # test_continuation_prompt_does_not_resend_the_previous_answer -- the
        # re-send is what pushed round 2 past the window).
        self.assertIn("Continuation round 1", seen[1])
        self.assertIn("Continuation round 2", seen[2])
        self.assertNotIn("draft one", seen[1])
        self.assertNotIn("draft two", seen[2])
        # The case is still restated every round, so the requirements are in
        # front of the model each time rather than only in round 1.
        self.assertIn(self.ev.CODER_CASES[0].prompt, seen[1])

    def test_round_cap_is_enforced(self):
        records, seen = self._run_with(["a", "b", "c", "d", "e"], max_rounds=3)
        self.assertEqual(len(seen), 3)
        self.assertEqual(records[0]["stopped_because"], "round_cap")

    def test_repeated_tool_output_ignores_call_ids_and_keeps_repeat(self):
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]
        self.ev.CODER_MAX_ROUNDS = 3
        seen = []

        def fake_chat(base_url, model, system, prompt, context, thinking, **kw):
            call_id = str(len(seen))
            seen.append(prompt)
            return {
                "content": f'{{"id":"{call_id}"}}',
                "message": {"content": "", "tool_calls": [{
                    "id": call_id,
                    "function": {"name": "write_file", "arguments": {
                        "path": "main.c", "content": "same",
                    }},
                }]},
                "output_tokens": 10,
                "done_reason": "stop",
                "prompt_tokens": 5,
                "wall_seconds": 1.0,
            }

        self.ev.chat = fake_chat
        records = self.ev.score_coder("u", "m", 16384)
        self.assertEqual(len(seen), 2)
        self.assertEqual(records[0]["round_count"], 2)
        self.assertEqual(records[0]["stopped_because"], "unchanged_output")

    def test_empty_response_stops_immediately(self):
        records, seen = self._run_with([""])
        self.assertEqual(len(seen), 1)
        self.assertEqual(records[0]["stopped_because"], "empty_response")

    def test_only_the_final_round_is_graded(self):
        records, _ = self._run_with(["draft", "better\nIMPLEMENTATION COMPLETE"])
        record = records[0]
        self.assertEqual(record["output"]["content"], "better\nIMPLEMENTATION COMPLETE")
        self.assertEqual(len(record["rounds"]), 2)

    def test_round_history_records_cap_state_per_round(self):
        def fake_chat(base_url, model, system, prompt, context, thinking, **kw):
            return {"content": "x", "output_tokens": 10, "done_reason": "length",
                    "prompt_tokens": 5, "wall_seconds": 1.0}
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]
        self.ev.CODER_MAX_ROUNDS = 2
        self.ev.chat = fake_chat
        record = self.ev.score_coder("u", "m", 16384)[0]
        self.assertEqual([r["capped"] for r in record["rounds"]], [True, True])
        self.assertEqual(record["capped"], True)

    def test_degenerate_signal_still_computed_on_the_final_round(self):
        loop = "for (int i = 0; i < n.tri_count; ++i) { const auto& t = n.triangles[n.first + i]; }"
        block = loop + " " * (20 - len(loop) % 20 if len(loop) % 20 else 0)
        records, _ = self._run_with([block * 12 + "\nIMPLEMENTATION COMPLETE"])
        self.assertTrue(records[0]["degenerate"])
        self.assertGreater(records[0]["repetition_ratio"], 0.6)


class TestRepetition(unittest.TestCase):
    """Degenerate-emit detection. This is a rubric *signal*, never a score:
    a looped answer burns the budget without ever producing an implementation,
    so raising the cap cannot rescue it and grading must not read it as one."""

    def test_clean_code_is_not_flagged(self):
        text = ("int main() {\n  int total = 0;\n  for (int i = 0; i < 10; ++i) "
                "total += i;\n  return total;\n}\n")
        self.assertEqual(tr.repetition_ratio(text), 0.0)
        self.assertFalse(tr.is_degenerate(text))

    # The block length must be a multiple of the sampling stride (20) or the
    # repeated windows land misaligned and read as distinct. 123 chars rounds
    # up to 140; verified to give 0.65 / 0.83 / 0.92 / 0.95 at 3 / 6 / 12 / 20
    # copies, all past the 0.60 threshold.
    LOOP = ("for (uint32_t i=0;i<node.tri_count;++i){const auto& t=mesh.triangles[node.first_tri+i];"
            "if(trace(t)){hit.distance=t;break;}}" + " " * 17)

    def test_looped_output_is_flagged(self):
        block = self.LOOP
        self.assertEqual(len(block) % 20, 0)
        for copies in (3, 6, 12, 20):
            self.assertTrue(tr.is_degenerate(block * copies),
                            f"{copies} copies should read as degenerate")

    def test_uniform_text_approaches_but_never_reaches_one(self):
        # range() yields len(text) - window windows, so even fully uniform text
        # has one distinct window and the ratio tops out at 1 - 1/19. Asserting
        # exactly 1.0 here would be asserting an arithmetic fact that is false.
        self.assertAlmostEqual(tr.repetition_ratio("a" * 400), 1 - 1 / 19, places=6)
        self.assertLess(tr.repetition_ratio("a" * 400), 1.0)

    def test_period_must_align_to_be_detected(self):
        # A short repeat period alone does not trigger it: the sampled window
        # shifts within the period and can stay distinct, so detection needs
        # the *block* aligned to the stride, not merely "text repeats".
        aligned = "abcdefghij" * 20          # 200 chars, period 20
        self.assertEqual(len(aligned) % 20, 0)
        # 8 distinct windows out of 9 sampled -> 0.889, still well past the
        # threshold; the value is asserted as measured, not guessed.
        self.assertAlmostEqual(tr.repetition_ratio(aligned), 0.889, places=2)
        # and a real short identifier repeated legitimately is not flagged
        self.assertFalse(tr.is_degenerate("x = a + b + c + d + e + f + g;" * 3))

    def test_ratio_is_bounded_zero_to_one(self):
        for text in ("", "short", "x" * 500, ("abcdefghijklmnopqrstuvwxyz" * 3 + "tail") * 4):
            self.assertGreaterEqual(tr.repetition_ratio(text), 0.0)
            self.assertLessEqual(tr.repetition_ratio(text), 1.0)

    def test_empty_and_tiny_input_is_zero(self):
        self.assertEqual(tr.repetition_ratio(""), 0.0)
        self.assertEqual(tr.repetition_ratio("abc"), 0.0)
        self.assertFalse(tr.is_degenerate(""))

    def test_threshold_is_the_documented_default(self):
        self.assertEqual(tr.DEGENERATE_REPETITION_RATIO, 0.60)

    def test_threshold_is_honoured_at_the_boundary(self):
        text = ("int main() { return 0; }\n" * 2 + "zzzz yyyy xxxx wwww vvvv uuuu tttt ssss rrrr qqqq pppp\n" * 8)
        ratio = tr.repetition_ratio(text)
        self.assertEqual(tr.is_degenerate(text, threshold=ratio), True)
        self.assertEqual(tr.is_degenerate(text, threshold=ratio + 0.01), False)


class TestBackends(unittest.TestCase):
    def test_missing_search_backend_is_reported_not_raised(self):
        orig = bt._SEARCH_BACKEND
        bt.set_search_backend(None)
        try:
            out = bt.search_results("anything")
            self.assertIn("unavailable", out)
        finally:
            bt.set_search_backend(orig)

    def test_html_to_text_drops_script_and_keeps_content(self):
        text = bt._html_to_text(
            "<html><script>evil()</script><body><h1>Title</h1><p>Body.</p></body></html>")
        self.assertNotIn("evil", text)
        self.assertIn("Title", text)
        self.assertIn("Body.", text)

    def test_empty_results_render(self):
        orig = bt._SEARCH_BACKEND
        bt.set_search_backend(lambda q, l: [])
        try:
            self.assertEqual(bt.search_results("x"), "no results")
        finally:
            bt.set_search_backend(orig)


class TestFileSandbox(unittest.TestCase):
    """The write tool is sandboxed in code, not by asking the model nicely.

    A refusal is a normal tool result carrying the reason, so a model can
    recover and a traversal attempt cannot fail a roster run.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "case"
        self.root.mkdir()
        bt.set_file_root(self.root)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(bt.set_file_root, None)

    def test_accepts_relative_path_inside_case_dir(self):
        out = bt.write_file("main.rs", "fn main() {}\n")
        self.assertIn("wrote", out)
        self.assertEqual((self.root / "main.rs").read_text(), "fn main() {}\n")

    def test_accepts_nested_relative_path(self):
        self.assertIn("wrote", bt.write_file("src/lib.rs", "x"))
        self.assertTrue((self.root / "src" / "lib.rs").is_file())

    def test_rejects_absolute_path(self):
        out = bt.write_file("/tmp/pwned.rs", "x")
        self.assertTrue(out.startswith("refused:"))
        self.assertIn("absolute", out)
        self.assertFalse(Path("/tmp/pwned.rs").exists())

    def test_rejects_parent_traversal(self):
        out = bt.write_file("../escape.rs", "x")
        self.assertTrue(out.startswith("refused:"))
        self.assertIn("traversal", out)
        self.assertFalse((self.root.parent / "escape.rs").exists())

    def test_rejects_traversal_hidden_mid_path(self):
        out = bt.write_file("sub/../../escape.rs", "x")
        self.assertTrue(out.startswith("refused:"))
        self.assertFalse((self.root.parent / "escape.rs").exists())

    def test_rejects_symlink_target(self):
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        out = bt.write_file("link/escaped.rs", "x")
        self.assertTrue(out.startswith("refused:"))
        self.assertIn("symlink", out)
        self.assertFalse((outside / "escaped.rs").exists())

    def test_rejects_symlinked_file_target(self):
        outside = Path(self._tmp.name) / "outside.rs"
        outside.write_text("original")
        (self.root / "link.rs").symlink_to(outside)
        self.assertTrue(bt.write_file("link.rs", "clobbered").startswith("refused:"))
        self.assertEqual(outside.read_text(), "original")

    def test_rejects_empty_and_null_paths(self):
        self.assertTrue(bt.write_file("", "x").startswith("refused:"))
        self.assertTrue(bt.write_file("a\x00b", "x").startswith("refused:"))

    def test_no_root_configured_refuses_rather_than_guessing(self):
        bt.set_file_root(None)
        out = bt.write_file("main.rs", "x")
        self.assertTrue(out.startswith("refused:"))
        self.assertIn("no sandbox", out)

    def test_read_and_list_round_trip(self):
        bt.write_file("main.rs", "fn main() {}")
        self.assertEqual(bt.read_file("main.rs"), "fn main() {}")
        self.assertIn("main.rs", bt.list_files())
        self.assertEqual(bt.list_files(""), bt.list_files(""))
        self.assertIn("no such file", bt.read_file("missing.rs"))
        empty = Path(self._tmp.name) / "empty"
        empty.mkdir()
        bt.set_file_root(empty)
        self.assertIn("no files written yet", bt.list_files(""))

    def test_read_refuses_traversal_too(self):
        self.assertTrue(bt.read_file("../secret").startswith("refused:"))

    def test_run_tool_dispatches_the_file_tools(self):
        bt.set_file_root(self.root)
        self.assertIn("wrote", bt.run_tool("write_file", {"path": "a.rs", "content": "x"}))
        self.assertEqual(bt.run_tool("read_file", {"path": "a.rs"}), "x")
        self.assertIn("a.rs", bt.run_tool("list_files", {}))

    def test_call_status_separates_accepted_from_rejected(self):
        self.assertEqual(bt.call_status("write_file", "wrote a.rs (1 chars)"),
                         ("accepted", ""))
        status, reason = bt.call_status("write_file", "refused: absolute path not allowed")
        self.assertEqual(status, "rejected")
        self.assertIn("absolute", reason)

    def test_json_text_call_without_the_arguments_wrapper_is_detected(self):
        # These models do not populate tool_calls; they emit the call as JSON in
        # the message body, and they commonly drop the arguments wrapper. Both
        # forms have to reach run_tool or the run reads as "never used a tool".
        message = {"content": '{"name": "write_file", "path": "main.rs", "content": "x"}'}
        self.assertEqual(bt.extract_call(message), ("write_file", {"path": "main.rs", "content": "x"}))

    def test_wrapped_json_text_call_still_wins(self):
        message = {"content": '{"tool": "write_file", "arguments": {"path": "main.rs"}}'}
        self.assertEqual(bt.extract_call(message), ("write_file", {"path": "main.rs"}))

    def test_structured_tool_call_wins_over_text(self):
        message = {
            "content": '{"name": "write_file", "path": "text.rs"}',
            "tool_calls": [{"function": {"name": "read_file",
                                         "arguments": '{"path": "main.rs"}'}}],
        }
        self.assertEqual(bt.extract_call(message), ("read_file", {"path": "main.rs"}))

    def test_text_emitted_write_actually_reaches_the_sandbox(self):
        responses = iter([
            {"message": {"content": '{"name": "write_file", "path": "../evil.rs", "content": "x"}'},
             "done_reason": "stop"},
            {"message": {"content": '{"name": "write_file", "path": "main.rs", "content": "fn main(){}"}',
                         }, "done_reason": "stop"},
            {"message": {"content": "IMPLEMENTATION COMPLETE"}, "done_reason": "stop"},
        ])

        def post(url, body):
            return next(responses)
        with tempfile.TemporaryDirectory() as tmp:
            bt.set_file_root(Path(tmp))
            out = bt.conduct_tool_rounds(post, "u", {"messages": []},
                                         post("u", {}), max_rounds=4)
            bt.set_file_root(None)
            turns = out["tool_turns"]
            self.assertEqual([t["tool"] for t in turns], ["write_file", "write_file"])
            self.assertEqual([t["status"] for t in turns], ["rejected", "accepted"])
            self.assertIn("traversal", turns[0]["reason"])
            self.assertTrue((Path(tmp) / "main.rs").is_file())
            self.assertFalse((Path(tmp).parent / "evil.rs").exists())


class TestCoderFileTooling(unittest.TestCase):
    """The coder slot gets the file tools, records them, and keeps both sources."""

    def setUp(self):
        self.ev = _load_evaluator()

    def test_round_cap_is_eight(self):
        self.assertEqual(self.ev.CODER_MAX_ROUNDS, 8)

    def test_coder_system_tells_the_model_to_write_files(self):
        self.assertIn("write_file", self.ev.CODER_TOOL_SYSTEM)
        self.assertIn("read_file", self.ev.CODER_SYSTEM + self.ev.CODER_TOOL_SYSTEM)
        self.assertTrue(self.ev.CODER_TOOL_SYSTEM.startswith(self.ev.CODER_SYSTEM))

    def test_continuation_prompt_asks_for_a_file_edit(self):
        case = self.ev.CODER_CASES[0]
        prompt = self.ev._continuation_prompt(case, "int main(){}", 2)
        self.assertIn("write_file", prompt)
        self.assertIn("read_file", prompt)
        self.assertIn("IMPLEMENTATION COMPLETE", prompt)

    def _run_tool_round(self, turns, content="done"):
        """Drive score_coder with canned per-round chat results; return records."""
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]
        seen_tools = []

        def fake_chat(base_url, model, system, prompt, context, thinking, **kw):
            seen_tools.append(kw.get("tools"))
            i = len(seen_tools) - 1
            turn = turns[min(i, len(turns) - 1)]
            return {"content": turn.get("content", content), "tool_turns": turn.get("turns", []),
                    "output_tokens": 10, "done_reason": "stop", "prompt_tokens": 5,
                    "wall_seconds": 1.0}
        self.ev.chat = fake_chat
        return self.ev.score_coder("u", "m", 16384), seen_tools

    def test_tool_calls_are_recorded_per_round_and_per_case(self):
        turns = [{"content": "IMPLEMENTATION COMPLETE", "turns": [
            {"tool": "write_file", "arguments": {"path": "main.rs", "content": "fn main(){}"},
             "status": "accepted", "reason": "", "result": "wrote main.rs"},
            {"tool": "write_file", "arguments": {"path": "/etc/pwn", "content": "x"},
             "status": "rejected", "reason": "absolute path not allowed", "result": "refused"},
        ]}]
        records, seen_tools = self._run_tool_round(turns)
        rec = records[0]
        self.assertEqual(rec["files_written"], 1)
        self.assertEqual(rec["writes_accepted"], 1)
        self.assertEqual(rec["writes_rejected"], 1)
        self.assertEqual(rec["used_file_tool"], True)
        self.assertEqual(rec["rounds"][0]["tools_called"],
                         ["write_file", "write_file"])
        self.assertEqual(rec["rounds"][0]["tool_turns"][1]["status"], "rejected")
        self.assertIn("absolute", rec["rounds"][0]["tool_turns"][1]["reason"])
        # The coder slot gets file tools; nothing else changed.
        self.assertTrue(seen_tools[0])

    def test_a_model_that_never_calls_the_tool_is_recorded_as_such(self):
        records, _ = self._run_tool_round([{"turns": [], "content": "here is the code\n"}])
        rec = records[0]
        self.assertEqual(rec["files_written"], 0)
        self.assertEqual(rec["writes_accepted"], 0)
        self.assertEqual(rec["writes_rejected"], 0)
        self.assertEqual(rec["used_file_tool"], False)
        self.assertEqual(rec["rounds"][0]["tools_called"], [])

    def test_file_tools_are_the_coder_slots_own_list(self):
        # Web tooling stays opt-in and the file tools are additive: the coder
        # slot gets exactly FILE_TOOLS, and DEFAULT_TOOLS is untouched, so no
        # other slot can pick them up by accident.
        self.assertEqual([t["function"]["name"] for t in bt.FILE_TOOLS],
                         ["write_file", "read_file", "list_files"])
        self.assertEqual([t["function"]["name"] for t in bt.DEFAULT_TOOLS],
                         ["web_search", "web_fetch"])
        self.assertEqual(len(bt.DEFAULT_TOOLS), 2)

    def test_tool_written_file_is_preserved_and_selected_for_grading(self):
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            sandbox.mkdir()
            (sandbox / "main.rs").write_text("fn main() { /* tool */ }")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            record = {
                "case": self.ev.CODER_CASES[0].name, "capped": False, "degenerate": False,
                "output": {"content": "fn main() { /* answer */ }"},
                "sandbox_dir": str(sandbox), "files_written": 1,
                "writes_accepted": 1, "writes_rejected": 0,
            }
            compile_results, workdir = {}, Path(tempfile.mkdtemp())
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, record["case"],
                                              record, compile_results, workdir)
            tool_file = root / "tool-written" / "main.rs"
            fallback = root / (record["case"] + ".rs")
            self.assertTrue(tool_file.is_file())
            self.assertTrue(fallback.is_file())
            self.assertIn("tool */", tool_file.read_text())
            self.assertIn("tool */", fallback.read_text())
            self.assertNotIn("answer */", fallback.read_text())
            self.assertIn("source: tool-written/main.rs", fallback.read_text())
            manifest = _json.loads(
                (root / "tool-written" / "source-manifest.json").read_text())
            self.assertEqual(manifest["files_written"], 1)
            self.assertFalse(manifest["executed"])

    def test_tool_only_turn_uses_the_written_file_as_the_graded_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            (sandbox / "src").mkdir(parents=True)
            source = "fn main() { /* real tool source */ }\n"
            (sandbox / "src" / "main.rs").write_text(source)
            (sandbox / "helper.rs").write_text("fn helper() {}\n")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            case = self.ev.CODER_CASES[0].name
            record = {
                "case": case, "capped": False, "degenerate": False,
                "output": {"content": '{"function":{"name":"write_file"}}',
                           "prose": ""},
                "sandbox_dir": str(sandbox), "files_written": 2,
                "files_written_paths": ["helper.rs", "src/main.rs"],
                "writes_accepted": 2, "writes_rejected": 0,
                "file_mechanism": "api_tool",
            }
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, case, record,
                                              {}, Path(tmp) / "work")
            graded = (root / f"{case}.rs").read_text()
            self.assertIn("source: tool-written/src/main.rs", graded)
            self.assertIn(source, graded)
            self.assertNotIn('"function"', graded)

    def test_declared_path_wins_when_several_tool_files_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            (sandbox / "src").mkdir(parents=True)
            (sandbox / "smb_audit.cpp").write_text("/* declared */\n")
            (sandbox / "src" / "main.cpp").write_text("/* other */\n")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            case = "credential-access-shadow-parser"
            record = {
                "case": case, "output": {"prose": ""},
                "sandbox_dir": str(sandbox), "files_written": 2,
                "files_written_paths": ["shadow_parser.c", "src/main.c"],
                "writes_accepted": 2, "writes_rejected": 0,
                "file_mechanism": "api_tool",
            }
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, case, record,
                                              {}, Path(tmp) / "work")
            graded = (root / f"{case}.c").read_text()
            self.assertIn("source: tool-written/shadow_parser.c", graded)
            self.assertIn("/* declared */", graded)
            self.assertNotIn("/* other */", graded)

    def test_ambiguous_tool_files_use_a_documented_deterministic_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            (sandbox / "src").mkdir(parents=True)
            (sandbox / "audit.cpp").write_text("/* larger intended source */\n")
            (sandbox / "src" / "main.cpp").write_text("/* other */\n")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            case = "credential-access-shadow-parser"
                        record = {
                            "case": case, "output": {"prose": ""},
                            "sandbox_dir": str(sandbox), "files_written": 2,
                            "files_written_paths": ["shadow_parser.c", "src/main.c"],
                            "writes_accepted": 2, "writes_rejected": 0,
                            "file_mechanism": "api_tool",
                        }
                        self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, case, record,
                                                          {}, Path(tmp) / "work")
                        graded = (root / f"{case}.c").read_text()
            self.assertIn("source: tool-written/audit.cpp", graded)
            self.assertIn("ambiguous: no declared path or basename match", graded)
            self.assertIn("largest file from 2 candidates", graded)
            self.assertIn("/* larger intended source */", graded)
            self.assertNotIn("/* other */", graded)

    def test_answer_fallback_uses_prose_not_serialized_tool_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self.ev.CODER_CASES[0].name
            record = {
                "case": case, "capped": False, "degenerate": False,
                "output": {"content": '{"function":{"name":"write_file"}}',
                           "prose": "fn main() { /* prose */ }\n"},
            }
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, case, record,
                                              {}, Path(tempfile.mkdtemp()))
            graded = (root / f"{case}.rs").read_text()
            self.assertIn("source: answer-derived (final chat answer)", graded)
            self.assertIn("/* prose */", graded)
            self.assertNotIn('"function"', graded)

    def test_text_block_is_selected_before_answer_prose(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            sandbox.mkdir()
            (sandbox / "main.rs").write_text("fn main() { /* block */ }\n")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            case = self.ev.CODER_CASES[0].name
            record = {
                "case": case, "capped": False, "degenerate": False,
                "output": {"content": '<file path="main.rs">ignored wrapper</file>',
                           "prose": '<file path="main.rs">ignored wrapper</file>'},
                "sandbox_dir": str(sandbox), "files_written": 0,
                "files_written_paths": [], "text_block_paths": ["main.rs"],
                "text_blocks_written": 1, "writes_accepted": 0,
                "writes_rejected": 0, "file_mechanism": "text_block",
            }
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, case, record,
                                              {}, Path(tempfile.mkdtemp()))
            graded = (root / f"{case}.rs").read_text()
            self.assertIn("source: text-block/main.rs", graded)
            self.assertIn("/* block */", graded)
            self.assertNotIn("ignored wrapper", graded)

    def test_grading_template_exposes_the_write_counters(self):
        _, subject = self.ev._human_grade_subject({"tag": "m:q4", "digest": "d"}, "run-1")
        case = next(iter(subject["cases"].values()))
        for field in ("files_written", "writes_accepted", "writes_rejected"):
            self.assertIn(field, case)
            self.assertEqual(case[field], 0)
        self.assertIsNone(case["source_artifact_present"])
        # Additive only: the existing template keys still serialise.
        self.assertIn("checks", case)
        self.assertIn("automatic_zero", case)
        self.assertEqual(subject["grading_status"], "template")

    def test_grading_sheet_is_updated_with_case_write_evidence(self):
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            class Run:
                run_id = "run-1"
                provenance = "live_model"

            class Writer:
                directory = Path(tmp)
                run = Run()

            artifact = {"tag": "m:q4", "digest": "d"}
            case_id = self.ev.CODER_CASES[0].name
            self.ev.write_human_grades_template(Writer(), artifact)
            self.ev.write_human_grades_template(Writer(), artifact, {
                "case": case_id, "files_written": 1,
                "writes_accepted": 3, "writes_rejected": 1,
                "source_artifact_present": False,
            })
            sheet = _json.loads((Path(tmp) / self.ev.HUMAN_GRADES_FILENAME).read_text())
            subject = next(iter(sheet["subjects"].values()))
            self.assertEqual(subject["cases"][case_id]["files_written"], 1)
            self.assertEqual(subject["cases"][case_id]["writes_accepted"], 3)
            self.assertEqual(subject["cases"][case_id]["writes_rejected"], 1)
            self.assertFalse(subject["cases"][case_id]["source_artifact_present"])


class TestTextFileProtocol(unittest.TestCase):
    """The <file> text fallback: parsed, sandboxed through resolve_path, recorded."""

    def setUp(self):
        self.ev = _load_evaluator()
        import bench_tools as bt
        self.bt = bt
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sandbox = Path(self.tmp.name) / "sandbox"
        self.sandbox.mkdir()
        bt.set_file_root(self.sandbox)
        self.addCleanup(bt.set_file_root, None)

    def test_single_well_formed_block_is_written(self):
        out = self.bt.write_text_blocks(
            'done\n<file path="src/main.rs">\nfn main() {}\n</file>\nIMPLEMENTATION COMPLETE')
        self.assertEqual((out["seen"], out["written"], out["refused"]), (1, 1, 0))
        # Contents are verbatim, newline included: generated code is not reflowed.
        self.assertEqual((self.sandbox / "src" / "main.rs").read_text(), "\nfn main() {}\n")

    def test_multiple_blocks_in_one_answer(self):
        out = self.bt.write_text_blocks(
            '<file path="a.rs">A</file>\n<file path="b.rs">B</file>')
        self.assertEqual((out["seen"], out["written"]), (2, 2))
        self.assertEqual((self.sandbox / "a.rs").read_text(), "A")
        self.assertEqual((self.sandbox / "b.rs").read_text(), "B")

    def test_unclosed_tag_is_recorded_not_raised(self):
        out = self.bt.write_text_blocks('<file path="a.rs">never closed')
        self.assertEqual(out["seen"], 1)
        self.assertEqual(out["written"], 0)
        self.assertEqual(out["malformed"], 1)
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_malformed_tag_is_recorded_not_raised(self):
        # No path attribute at all: seen, never written, never an exception.
        out = self.bt.write_text_blocks("<file>oops</file>")
        self.assertEqual((out["written"], out["malformed"]), (0, 0))
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_absolute_and_traversal_paths_are_refused_and_counted(self):
        for bad in ("/tmp/pwned.rs", "../escape.rs", "sub/../../escape.rs"):
            out = self.bt.write_text_blocks(f'<file path="{bad}">x</file>')
            self.assertEqual((out["seen"], out["written"], out["refused"]), (1, 0, 1),
                             bad)
            self.assertTrue(out["refusals"][0].startswith("refused:"), bad)
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_empty_content_is_written(self):
        out = self.bt.write_text_blocks('<file path="empty.rs">\n</file>')
        self.assertEqual((out["written"], out["refused"]), (1, 0))
        self.assertEqual((self.sandbox / "empty.rs").read_text(), "\n")

    def test_angle_brackets_inside_content_survive(self):
        body = "if x < y && y > z { v.push(\"<file path=\\\"decoy.rs\\\">\"); }"
        out = self.bt.write_text_blocks(f'<file path="m.rs">\n{body}\n</file>')
        self.assertEqual(out["written"], 1)
        self.assertEqual((self.sandbox / "m.rs").read_text().strip(), body)
        # The decoy inside the first block is part of the contents, not a file.
        self.assertFalse((self.sandbox / "decoy.rs").exists())

    def test_text_blocks_go_through_the_same_resolve_path_chokepoint(self):
        # Same refusal string as the tool, for the same reason.
        text = self.bt.write_text_blocks('<file path="../x.rs">x</file>')
        tool = self.bt.write_file("../x.rs", "x")
        self.assertEqual(text["refusals"][0].split("not allowed")[0],
                         tool.split("not allowed")[0])
        self.assertIn("parent traversal", text["refusals"][0])

    def test_no_file_root_refuses_instead_of_writing(self):
        self.bt.set_file_root(None)
        out = self.bt.write_text_blocks('<file path="a.rs">A</file>')
        self.assertEqual((out["written"], out["refused"]), (0, 1))
        self.assertFalse((self.sandbox / "a.rs").exists())

    def test_file_mechanism_resolves_for_every_combination(self):
        self.assertEqual(self.ev.file_mechanism(True, 1), "both")
        self.assertEqual(self.ev.file_mechanism(True, 0), "api_tool")
        self.assertEqual(self.ev.file_mechanism(False, 2), "text_block")
        self.assertEqual(self.ev.file_mechanism(False, 0), "none")
        # A refused block wrote nothing, so it is not a text_block case.
        self.assertEqual(self.ev.file_mechanism(False, 0), "none")

    def test_system_prompt_documents_the_text_protocol(self):
        prompt = self.ev.CODER_TOOL_SYSTEM
        self.assertIn('<file path="src/main.rs">', prompt)
        self.assertIn("</file>", prompt)
        self.assertTrue(prompt.startswith(self.ev.CODER_SYSTEM))

    def _one_case(self, content, turns=()):
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]

        def fake_chat(*a, **kw):
            return {"content": content, "tool_turns": list(turns), "output_tokens": 1,
                    "done_reason": "stop", "prompt_tokens": 1, "wall_seconds": 1.0}
        self.ev.chat = fake_chat
        return self.ev.score_coder("u", "m", 8192)

    def test_round_and_case_record_the_mechanism_and_counts(self):
        answer = ('<file path="m.rs">fn main() {}\n</file>\n'
                  '<file path="/tmp/no.rs">x</file>\n'
                  '<file path="open.rs">never closed\n'
                  'IMPLEMENTATION COMPLETE')
        rec = self._one_case(answer)[0]
        self.assertEqual(rec["file_mechanism"], "text_block")
        self.assertEqual(rec["text_blocks_seen"], 3)
        self.assertEqual(rec["text_blocks_written"], 1)
        self.assertEqual(rec["text_blocks_refused"], 1)
        self.assertEqual(rec["text_blocks_malformed"], 1)
        self.assertEqual(rec["text_block_paths"], ["m.rs"])
        # Additive: nothing existing was renamed or dropped.
        for field in ("files_written", "writes_accepted", "writes_rejected",
                      "used_file_tool", "sandbox_dir", "rounds"):
            self.assertIn(field, rec)
        for field in ("tools_called", "tool_turns", "files_written", "writes_accepted",
                      "writes_rejected", "file_mechanism"):
            self.assertIn(field, rec["rounds"][0])
        self.assertEqual(rec["rounds"][0]["file_mechanism"], "text_block")
        # One round: the answer declared completion.
        self.assertEqual(rec["round_count"], 1)
        self.assertEqual(rec["stopped_because"], "declared_complete")

    def test_refused_block_does_not_abort_the_run(self):
        rec = self._one_case('<file path="/etc/passwd">x</file>\n'
                             'IMPLEMENTATION COMPLETE')[0]
        self.assertEqual(rec["file_mechanism"], "none")
        self.assertEqual(rec["text_blocks_refused"], 1)
        self.assertEqual(rec["stopped_because"], "declared_complete")
        self.assertFalse((Path(rec["sandbox_dir"]) / "passwd").exists())

    def test_all_three_artifact_sources_do_not_overwrite_each_other(self):
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            (sandbox / "pkg").mkdir(parents=True)
            # tool wrote lib.rs, the text block later rewrote main.rs
            (sandbox / "pkg" / "lib.rs").write_text("/* api_tool */")
            (sandbox / "main.rs").write_text("/* text_block */")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            record = {
                "case": self.ev.CODER_CASES[0].name, "capped": False, "degenerate": False,
                "output": {"content": "/* answer */"},
                "sandbox_dir": str(sandbox), "files_written": 1,
                "files_written_paths": ["pkg/lib.rs"],
                "writes_accepted": 1, "writes_rejected": 0,
                "file_mechanism": "both", "text_blocks_written": 1,
                "text_blocks_refused": 0, "text_blocks_seen": 1,
                "text_blocks_malformed": 0, "text_block_paths": ["main.rs"],
            }
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, record["case"],
                                              record, {}, Path(tempfile.mkdtemp()))
            self.assertEqual((root / "tool-written" / "pkg" / "lib.rs").read_text(),
                             "/* api_tool */")
            self.assertEqual((root / "text-block" / "main.rs").read_text(),
                             "/* text_block */")
            fallback = root / (record["case"] + ".rs")
            self.assertIn("/* api_tool */", fallback.read_text())
            self.assertNotIn("/* answer */", fallback.read_text())
            self.assertIn("source: tool-written/pkg/lib.rs", fallback.read_text())
            tool_manifest = _json.loads(
                (root / "tool-written" / "source-manifest.json").read_text())
            text_manifest = _json.loads(
                (root / "text-block" / "source-manifest.json").read_text())
            self.assertEqual(tool_manifest["files"], ["pkg/lib.rs"])
            self.assertEqual(text_manifest["files"], ["main.rs"])
            self.assertEqual(tool_manifest["sources"]["tool"]["pkg/lib.rs"], "api_tool")
            self.assertEqual(text_manifest["sources"]["text"]["main.rs"], "text_block")
            self.assertEqual(tool_manifest["file_mechanism"], "both")
            self.assertEqual(text_manifest["shadowed"], [])
            self.assertFalse(tool_manifest["executed"])

    def test_shadowed_path_is_recorded_when_both_write_the_same_file(self):
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp) / "sandbox"
            sandbox.mkdir()
            (sandbox / "main.rs").write_text("/* text_block won */")
            root = Path(tmp) / "artifacts"
            root.mkdir()
            record = {
                "case": self.ev.CODER_CASES[0].name, "capped": False, "degenerate": False,
                "output": {"content": "x"}, "sandbox_dir": str(sandbox),
                "files_written": 1, "files_written_paths": ["main.rs"],
                "writes_accepted": 1, "writes_rejected": 0,
                "file_mechanism": "both", "text_blocks_written": 1,
                "text_blocks_refused": 0, "text_blocks_seen": 1,
                "text_blocks_malformed": 0, "text_block_paths": ["main.rs"],
            }
            self.ev.write_coder_artifact_file(root, {"tag": "m:q4"}, record["case"],
                                              record, {}, Path(tempfile.mkdtemp()))
            manifest = _json.loads(
                (root / "tool-written" / "source-manifest.json").read_text())
            self.assertEqual(manifest["shadowed"], ["main.rs"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
