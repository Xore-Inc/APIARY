"""OpenCode v2.0.26 integration against a deterministic in-process backend."""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))
from coding_cli import CodingCLI, _to_backend_messages, _to_cli_calls
from transcripts import (Reproducibility, RunMetadata, SlotRecorder,
                         TranscriptWriter)

spec = importlib.util.spec_from_file_location("cli_evaluator", BENCH / "evaluate-models.py")
ev = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ev
spec.loader.exec_module(ev)

RUN_OPENCODE_INTEGRATION = os.environ.get("APIARY_OPENCODE_INTEGRATION") == "1"
if RUN_OPENCODE_INTEGRATION:
    opencode = shutil.which("opencode")
    if not opencode:
        raise RuntimeError("APIARY_OPENCODE_INTEGRATION=1 requires OpenCode v2.0.26")
    installed = subprocess.run([opencode, "--version"], capture_output=True,
                               text=True, check=False)
    if installed.returncode or installed.stdout.strip() != "opencode v2.0.26":
        raise RuntimeError("APIARY_OPENCODE_INTEGRATION=1 requires OpenCode v2.0.26")


class CodingCLITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.body = {"model": "real-model", "messages": [
            {"role": "system", "content": "Write a source file."},
            {"role": "user", "content": "Write main.c then finish."}],
            "options": {"temperature": 0, "seed": 144, "num_ctx": 16384,
                        "num_predict": 16000}, "stream": False}

    def cli(self, backend, steps=4, binary="opencode", timeout=30):
        cli = CodingCLI("real-model", backend, binary, timeout, steps,
                        self.root / "coder-artifacts" / "real-model")
        cli.set_case("coder", "case.c")
        cli.workspace = self.root / "workspace"
        return cli

    def test_wire_converters_always_run_in_ci(self):
        calls, mapping = _to_cli_calls([
            {"function": {"name": "write", "arguments": {"path": "a.c", "content": "a"}}},
            {"id": "original", "function": {"name": "write", "arguments": {"path": "b.c"}}},
        ], 3)
        self.assertEqual([call["id"] for call in calls], ["call_3_0", "original"])
        self.assertEqual([call["index"] for call in calls], [0, 1])
        self.assertEqual(json.loads(calls[0]["function"]["arguments"])["path"], "a.c")
        self.assertEqual(mapping[1]["backend_id"], "original")
        converted = _to_backend_messages([
            {"role": "assistant", "content": [{"type": "text", "text": "hello"}],
             "tool_calls": calls},
            {"role": "tool", "tool_call_id": "call_3_0",
             "content": [{"type": "text", "text": "written"}]},
        ])
        self.assertEqual(converted[0]["content"], "hello")
        self.assertEqual(converted[0]["tool_calls"][0]["function"]["arguments"]["path"], "a.c")
        self.assertEqual(converted[1]["content"], "written")
        self.assertNotIn("id", converted[0]["tool_calls"][0])
        self.assertNotIn("tool_call_id", converted[1])

    def test_open_session_keeps_physical_engine_identity(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        class Session:
            engine = None
            fallback_engine = None

            def __init__(self, *_args, **_kwargs):
                self.transport = None

        backend = object()
        cli_transport = object()
        args = SimpleNamespace(
            engine=ev.ENGINE_OLLAMA, harness="opencode", colibri_base_url=None,
            coding_cli_bin="opencode", coding_cli_timeout=30, coding_cli_steps=4,
            coding_cli_root=self.root / "coder-artifacts")
        with (patch.object(ev, "canonical_model_tag", return_value="real-model"),
              patch.object(ev, "ModelSession", Session),
              patch.object(ev, "serving_ollama_transport", return_value=backend),
              patch.object(ev, "CodingCLI", return_value=cli_transport)):
            session = ev.open_session(args, "url", "real-model", 16384)
        self.assertEqual(session.engine, ev.ENGINE_OLLAMA)
        self.assertEqual(session.cli_backend_engine, ev.ENGINE_OLLAMA)
        self.assertIs(session.transport, cli_transport)

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_real_cli_preserves_tool_ids_results_and_budget(self):
        requests = []

        def backend(_url, body):
            requests.append(body)
            if len(requests) == 1:
                return {"message": {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "write", "arguments": {
                        "path": "main.c", "content": "int main(void){return 0;}"}}},
                    {"function": {"name": "write", "arguments": {
                        "path": "helper.h", "content": "#define HELPER 1"}}}]},
                    "done_reason": "stop", "eval_count": 7}
            return {"message": {"role": "assistant", "content": "IMPLEMENTATION COMPLETE"},
                    "done_reason": "stop", "eval_count": 4}

        result = self.cli(backend)("http://backend/api/chat", self.body)
        self.assertEqual(result["done_reason"], "stop", result.get("error"))
        self.assertEqual((self.root / "workspace" / "main.c").read_text(),
                         "int main(void){return 0;}")
        self.assertEqual((self.root / "workspace" / "helper.h").read_text(),
                         "#define HELPER 1")
        self.assertEqual(sorted(turn["id"] for turn in result["tool_turns"]),
                         ["call_1_0", "call_1_1"])
        self.assertTrue(any(m["role"] == "system" and
                            self.body["messages"][0]["content"] in m["content"]
                            for m in requests[0]["messages"]))
        self.assertEqual(next(m["content"] for m in requests[0]["messages"]
                              if m["role"] == "user"), self.body["messages"][1]["content"])
        self.assertTrue(all("tool_call_id" not in m for m in requests[1]["messages"]
                            if m["role"] == "tool"))
        self.assertEqual(next(m for m in requests[1]["messages"]
                              if m["role"] == "assistant" and m.get("tool_calls"))
                         ["tool_calls"][0]["function"]["arguments"],
                         {"path": "main.c", "content": "int main(void){return 0;}"})
        self.assertNotIn("id", next(m for m in requests[1]["messages"]
                                     if m["role"] == "assistant" and m.get("tool_calls"))
                         ["tool_calls"][0])
        self.assertTrue(all("Created file successfully" in m["content"]
                            for m in requests[1]["messages"] if m["role"] == "tool"))
        self.assertTrue(all(req["options"]["num_predict"] == 16000 for req in requests))
        self.assertTrue(all(req["model"] == "real-model" for req in requests))
        self.assertTrue(all("bash" not in [t["function"]["name"] for t in req["tools"]]
                            for req in requests))
        artifacts = Path(result["cli_artifacts"])
        self.assertTrue((artifacts / "cli.jsonl").is_file())
        self.assertEqual(len((artifacts / "wire.jsonl").read_text().splitlines()), 2)
        self.assertTrue(json.loads((artifacts / "session.json").read_text()))
        self.assertTrue((artifacts / "home" / ".config" / "opencode" / "opencode.json").is_file())
        config = json.loads((artifacts / "home" / ".config" / "opencode" /
                             "opencode.json").read_text())
        self.assertEqual(config["agent"]["build"]["prompt"],
                         self.body["messages"][0]["content"])
        index = [json.loads(line) for line in
                 (self.root / "artifact-index.jsonl").read_text().splitlines()]
        self.assertTrue(index)
        self.assertTrue(all((self.root / "coder-artifacts" / path).is_file()
                            for item in index for path in item["paths"]))

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_backend_failure_is_recorded(self):
        def broken(_url, _body):
            raise RuntimeError("backend down")

        result = self.cli(broken)("url", self.body)
        self.assertEqual(result["done_reason"], "error")
        self.assertIn("backend down", result["error"])
        self.assertIn("backend down", Path(result["cli_artifacts"], "wire.jsonl").read_text())

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_external_write_is_denied(self):
        target = self.root / "outside.c"
        workspace = self.root / "workspace"
        calls = [0]

        def backend(_url, _body):
            calls[0] += 1
            if calls[0] == 1:
                return {"message": {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "call_escape", "type": "function", "function": {
                        "name": "write", "arguments": {"path": str(target), "content": "bad"}}}]},
                    "done_reason": "stop"}
            return {"message": {"role": "assistant", "content": "done"},
                    "done_reason": "stop"}

        result = self.cli(backend)("url", self.body)
        self.assertFalse(target.exists())
        self.assertEqual(result["tool_turns"][0]["status"], "rejected")

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_same_backend_tool_rejection_uses_file_block_fallback(self):
        import bench_tools as bt
        for detail in ("does not support tools", "invalid tool call arguments",
                       "HTTPError: does not support tools"):
            with self.subTest(detail=detail):
                requests = []

                def backend(_url, body):
                    requests.append(body)
                    if body["tools"]:
                        if detail.startswith("HTTPError"):
                            raise urllib.error.HTTPError(
                                "http://backend/v1/chat/completions", 400,
                                "Bad Request", {},
                                io.BytesIO(b'{"error":{"message":"does not support tools"}}'))
                        raise RuntimeError(detail)
                    return {"message": {"role": "assistant", "content":
                            '<file path="main.c">int main(void){return 0;}</file>\nIMPLEMENTATION COMPLETE'},
                            "done_reason": "stop"}

                cli = self.cli(backend)
                result = ev.chat("url", "real-model", ev.CODER_TOOL_SYSTEM,
                                 self.body["messages"][1]["content"], 16384, False, 16000,
                                 tools=list(bt.FILE_TOOLS), transport=cli)
                self.assertTrue(result["file_block_fallback"], result)
                self.assertIn("does not support tools" if detail.startswith("HTTPError") else detail,
                              result["tool_fallback_reason"])
                failed = Path(result["tool_fallback_artifacts"])
                self.assertIn("does not support tools" if detail.startswith("HTTPError") else detail,
                              (failed / "wire.jsonl").read_text())
                self.assertEqual(result["tool_turns"], [])
                self.assertEqual([bool(request["tools"]) for request in requests], [True, False])
                self.assertTrue(all(request["model"] == "real-model" for request in requests))
                bt.set_file_root(self.root / "workspace")
                try:
                    self.assertEqual(bt.write_text_blocks(result["content"])["written"], 1)
                finally:
                    bt.set_file_root(None)
                self.assertTrue((self.root / "workspace" / "main.c").is_file())

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_partial_file_survives_backend_error(self):
        from unittest.mock import patch
        case = next(case for case in ev.CODER_CASES
                    if case.name == "credential-access-shadow-parser")
        calls = [0]

        def backend(_url, _body):
            calls[0] += 1
            if calls[0] == 1:
                return {"message": {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "write", "arguments": {
                        "path": "shadow_parser.c", "content": "int main(void){return 0;}"}}}]},
                    "done_reason": "stop"}
            raise RuntimeError("backend down")

        cli = self.cli(backend)
        with patch.object(ev, "CODER_CASES", (case,)):
            records = ev.score_coder("url", "real-model", 16384, transport=cli)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue(record["capped"])
        self.assertEqual(record["files_written_paths"], ["shadow_parser.c"])
        self.assertEqual(record["writes_accepted"], 1)
        self.assertTrue((Path(record["sandbox_dir"]) / "shadow_parser.c").is_file())
        root = self.root / "coder-artifacts" / "real-model"
        compiled = {}
        ev.write_coder_artifact_file(root, {"tag": "real-model"}, case.name,
                                     record, compiled, self.root / "compile",
                                     retain_products=True)
        self.assertTrue((root / "cases" / case.name / "tool-written" /
                         "shadow_parser.c").is_file())
        self.assertTrue((root / "compiled" / case.name / ".compile.bin").is_file())

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_step_cap_fails_closed(self):
        def looping(_url, _body):
            return {"message": {"role": "assistant", "content": "progress", "tool_calls": [
                {"id": "call_loop", "type": "function", "function": {
                    "name": "read", "arguments": {"path": "."}}}]}, "done_reason": "stop"}

        result = self.cli(looping, steps=2)("url", self.body)
        self.assertEqual(result["done_reason"], "error")
        self.assertIn("step cap", result["error"])

    def test_timeout_keeps_partial_artifacts(self):
        binary = self.root / "slow-cli"
        binary.write_text("#!/bin/sh\nsleep 5\n")
        binary.chmod(0o755)
        result = self.cli(lambda _url, _body: {}, binary=str(binary), timeout=1)(
            "url", self.body)
        self.assertEqual(result["done_reason"], "error")
        self.assertIn("timed out", result["error"])
        self.assertTrue(Path(result["cli_artifacts"], "cli.jsonl").is_file())

    def test_missing_cli_binary_is_a_case_error(self):
        result = self.cli(lambda _url, _body: {}, binary=str(self.root / "missing"))(
            "url", self.body)
        self.assertEqual(result["done_reason"], "error")
        self.assertIn("FileNotFoundError", result["error"])
        self.assertTrue(Path(result["cli_artifacts"], "prompt.json").is_file())

    def test_no_id_text_events_return_only_the_last_message(self):
        binary = self.root / "text-cli"
        binary.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' '{\"type\":\"text\",\"part\":{\"text\":\"intermediate\"}}'\n"
            "printf '%s\\n' '{\"type\":\"text\",\"part\":{\"text\":\"final\"}}'\n")
        binary.chmod(0o755)
        result = self.cli(lambda _url, _body: {}, binary=str(binary))("url", self.body)
        self.assertEqual(result["message"]["content"], "final")

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_backend_finish_reasons_fail_closed(self):
        for reason in (None, "mystery", "length"):
            with self.subTest(reason=reason):
                cli = self.cli(lambda _url, _body: {
                    "message": {"role": "assistant", "content": "partial"},
                    "done_reason": reason})
                cli.set_case("coder", f"finish-{reason}")
                result = cli("url", self.body)
                self.assertEqual(result["done_reason"], "error")
                self.assertIn("done_reason", result["error"])

    @unittest.skipUnless(RUN_OPENCODE_INTEGRATION, "set APIARY_OPENCODE_INTEGRATION=1")
    def test_earlier_missing_or_unknown_finish_fails_after_final_success(self):
        for reason in (None, "mystery"):
            with self.subTest(reason=reason):
                calls = [0]

                def backend(_url, _body):
                    calls[0] += 1
                    if calls[0] == 1:
                        return {"message": {"role": "assistant", "content": "",
                                "tool_calls": [{"function": {"name": "write", "arguments": {
                                    "path": "main.c", "content": "int main(void){return 0;}"}}}]},
                                "done_reason": reason}
                    return {"message": {"role": "assistant", "content": "done"},
                            "done_reason": "stop"}

                result = self.cli(backend)("url", self.body)
                self.assertGreaterEqual(calls[0], 2)
                self.assertEqual(result["done_reason"], "error")
                self.assertIn("done_reason", result["error"])

    def test_compile_products_retained_only_when_requested(self):
        if not shutil.which("gcc"):
            self.skipTest("gcc unavailable")
        source = self.root / "main.c"
        source.write_text("int main(void){return 0;}\n")
        native = ev.compile_check(source, self.root / "native")
        self.assertTrue(native["ok"], native)
        self.assertFalse((self.root / "native" / "main.bin").exists())
        retained = ev.compile_check(source, self.root / "retained", retain_products=True)
        self.assertTrue(retained["ok"], retained)
        self.assertTrue((self.root / "retained" / "main.bin").is_file())
        self.assertEqual(retained["products"], [str(self.root / "retained" / "main.bin")])
        self.assertEqual(retained["command"][0], "gcc")
        self.assertEqual(retained["returncode"], 0)
        self.assertEqual(retained["stdout"], "")
        self.assertEqual(retained["stderr"], "")

        python_source = self.root / "valid.py"
        python_source.write_text("value = 1\n")
        python_result = ev.compile_check(
            python_source, self.root / "python-retained", retain_products=True)
        self.assertTrue(python_result["ok"], python_result)
        self.assertTrue(python_result["products"])
        self.assertTrue(all(Path(path).is_file() for path in python_result["products"]))
        self.assertTrue(any(path.endswith(".pyc") for path in python_result["products"]))

    def test_cli_case_keeps_source_manifest_and_compiled_product(self):
        if not shutil.which("gcc"):
            self.skipTest("gcc unavailable")
        case = "credential-access-shadow-parser"
        sandbox = self.root / "sandbox"
        sandbox.mkdir()
        (sandbox / "shadow_parser.c").write_text("int main(void){return 0;}\n")
        record = {"case": case, "sandbox_dir": str(sandbox),
                  "cli_artifacts": str(self.root / "round-01"),
                  "output": {"prose": ""}, "files_written": 1,
                  "files_written_paths": ["shadow_parser.c"],
                  "writes_accepted": 1, "writes_rejected": 0,
                  "file_mechanism": "api_tool"}
        root = self.root / "artifacts"
        root.mkdir()
        results = {}
        self.assertEqual(ev.write_coder_artifact_file(
            root, {"tag": "model"}, case, record, results, self.root / "scratch",
            retain_products=True), 1)
        self.assertTrue((root / "cases" / case / "tool-written" / "source-manifest.json").is_file())
        self.assertTrue((root / "compiled" / case / ".compile.bin").is_file())
        self.assertTrue(results[case]["ok"])

    def test_evaluate_slot_indexes_cli_sources_and_products_from_coder_root(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        run_root = self.root / "run"
        run_root.mkdir()
        writer = SimpleNamespace(directory=run_root, run=SimpleNamespace(
            run_id="run-1", provenance="live_model"))
        sandbox = self.root / "sandbox"
        sandbox.mkdir()
        (sandbox / "shadow_parser.c").write_text("int main(void){return 0;}\n")
        record = {
            "case": "credential-access-shadow-parser", "sandbox_dir": str(sandbox),
            "cli_artifacts": str(self.root / "round-01"), "output": {
                "prose": "", "tokens_per_second": None}, "capped": False,
            "degenerate": False, "files_written": 1,
            "files_written_paths": ["shadow_parser.c"], "writes_accepted": 1,
            "writes_rejected": 0, "file_mechanism": "api_tool",
        }

        class Transport:
            is_coding_cli = True

        class Session:
            transport = Transport()
            engine = "ollama"
            fallback_engine = None
            cli_backend_engine = "ollama"

            def provenance(self, *_args):
                return {"engine": "ollama", "n_ctx_requested": 16384}

        def score_coder(_url, _model, _context, _recorder, sink, _transport):
            sink(record)
            return [record]

        request = ev.qualification_request("coder", 16384)
        with (patch.object(ev, "model_artifact", return_value={
                  "tag": "real-model", "digest": "sha256:test"}),
              patch.object(ev, "score_coder", side_effect=score_coder),
              patch.object(ev, "write_human_grades_template"),
              patch.object(ev, "nvidia_memory", return_value=None),
              patch.object(ev, "ollama_ps", return_value=None),
              patch.object(ev, "system_memory_used", return_value=None)):
            result = ev.evaluate_slot("url", "coder", "real-model", request,
                                      writer=writer, session=Session())
        self.assertTrue(result["ok"], result)
        entries = [json.loads(line) for line in
                   (run_root / ev.ARTIFACT_INDEX_FILENAME).read_text().splitlines()]
        paths = entries[-1]["paths"]
        self.assertTrue(all(path.startswith("real-model/") for path in paths))
        self.assertTrue(all((run_root / ev.CODER_ARTIFACTS_DIRNAME / path).is_file()
                            for path in paths))
        self.assertTrue(any("source-manifest.json" in path for path in paths))
        self.assertTrue(any(path.endswith(".compile.bin") for path in paths))
        self.assertIn("real-model/compile-report.json", paths)

    def test_cli_errors_do_not_skip_later_cases_in_any_slot(self):
        class FailingCLI:
            is_coding_cli = True
            workspace = None

            def __init__(self):
                self.cases = []

            def set_case(self, slot, case):
                self.cases.append((slot, case))

            def __call__(self, _url, _body):
                return {"message": {"content": ""}, "done_reason": "error",
                        "error": "backend down", "tool_turns": []}

        for slot, scorer, expected in (
            ("ghidra", ev.score_triage, len(ev.TRIAGE_CASES) * 2),
            ("sessions", ev.score_sessions, len(ev.SESSION_CASES)),
            ("revdeck", ev.score_revdeck, len(ev.REV_CASES)),
            ("coder", ev.score_coder, len(ev.CODER_CASES)),
        ):
            cli = FailingCLI()
            cases = scorer("url", "model", 16384, transport=cli)
            self.assertEqual(len(cases), len(getattr(ev, {
                "ghidra": "TRIAGE_CASES", "sessions": "SESSION_CASES",
                "revdeck": "REV_CASES", "coder": "CODER_CASES"}[slot])))
            self.assertEqual(len(cli.cases), expected, slot)
            self.assertTrue(all(case["capped"] for case in cases), slot)

    def test_harmony_guard_refuses_each_case_without_calling_cli(self):
        class GuardedCLI:
            is_coding_cli = True
            calls = 0
            cases = []

            def set_case(self, slot, case):
                self.cases.append((slot, case))

            def __call__(self, _url, _body):
                self.calls += 1
                raise AssertionError("harmony refusal must happen before transport")

        class Recorder:
            slot = "sessions"
            records = []

            def record(self, **fields):
                self.records.append(fields)

        cli, recorder = GuardedCLI(), Recorder()
        from unittest.mock import patch
        with patch.dict(ev.OUTPUT_BUDGETS, {"sessions": 512}):
            cases = ev.score_sessions("url", "gpt-oss:20b", 16384, recorder, cli)
        self.assertEqual(len(cases), len(ev.SESSION_CASES))
        self.assertEqual(cli.calls, 0)
        self.assertEqual(len(cli.cases), len(ev.SESSION_CASES))
        self.assertEqual(len(recorder.records), len(ev.SESSION_CASES))
        self.assertTrue(all("harmony floor" in item["error"]
                            for item in recorder.records))
        self.assertTrue(all(item["request_body"]["options"]["num_predict"] == 512
                            for item in recorder.records))

    def test_cli_error_reaches_transcript_recorder(self):
        class Recorder:
            slot = "sessions"
            saved = None

            def record(self, **fields):
                self.saved = fields

        class FailedCLI:
            is_coding_cli = True

            def set_case(self, slot, case):
                pass

            def __call__(self, _url, _body):
                return {"message": {"content": "partial"}, "done_reason": "error",
                        "error": "OpenCode exited 1", "cli_artifacts": "/run/case"}

        recorder = Recorder()
        raw = ev.chat("url", "model", "system", "prompt", 16384, False, 512,
                      recorder=recorder, case="case", transport=FailedCLI())
        self.assertEqual(raw["done_reason"], "error")
        self.assertEqual(recorder.saved["error"], "OpenCode exited 1")
        self.assertEqual(recorder.saved["response"]["cli_artifacts"], "/run/case")

    def test_cli_prompt_wire_session_and_physical_engine_persist_in_transcript(self):
        class RecordedCLI:
            is_coding_cli = True

            def set_case(self, _slot, _case):
                pass

            def __call__(self, _url, _body):
                return {
                    "message": {"role": "assistant", "content": "done"},
                    "done_reason": "stop", "cli_artifacts": "/run/case",
                    "cli_artifacts_relative": "model/sessions/case/round-01",
                    "cli_session_id": "session-1", "cli_wire_sha256": "abc123",
                    "cli_messages": [{"role": "system", "content": "actual cli system"}],
                    "backend_options": [{"num_predict": 512}],
                }

        writer = TranscriptWriter(self.root / "transcripts", RunMetadata(benchmark="test"))
        recorder = SlotRecorder(
            writer=writer, slot="sessions",
            model={"tag": "real-model", "digest": "sha256:test"},
            reproducibility=Reproducibility(
                engine="ollama", harness="opencode", backend_engine="ollama"))
        ev.chat("url", "real-model", "original system", "original user", 16384,
                False, 512, recorder=recorder, case="case", transport=RecordedCLI())
        writer.close()
        record = json.loads(writer.path.read_text().splitlines()[0])
        self.assertEqual(record["request"]["system_prompt"], "original system")
        self.assertEqual(record["request"]["user_prompt"], "original user")
        self.assertEqual(record["response"]["cli_messages"][0]["content"],
                         "actual cli system")
        self.assertEqual(record["response"]["cli_session_id"], "session-1")
        self.assertEqual(record["response"]["cli_artifacts_relative"],
                         "model/sessions/case/round-01")
        self.assertEqual(record["reproducibility"]["engine"], "ollama")
        self.assertEqual(record["reproducibility"]["harness"], "opencode")


if __name__ == "__main__":
    unittest.main()
