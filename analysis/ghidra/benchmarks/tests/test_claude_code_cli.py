"""Claude Code protocol bridge and optional real-CLI integration checks."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))
from claude_code_cli import (ClaudeCodeCLI, _cli_conversation, _has_expected_prompt,
                             _to_anthropic_content, _to_backend_messages)

RUN_CLAUDE = os.environ.get("APIARY_CLAUDE_INTEGRATION") == "1"
if RUN_CLAUDE:
    claude = shutil.which("claude")
    if not claude:
        raise RuntimeError("APIARY_CLAUDE_INTEGRATION=1 requires Claude Code")
    version = subprocess.run([claude, "--version"], capture_output=True, text=True,
                             check=False, timeout=10)
    if version.returncode or "Claude Code" not in version.stdout:
        raise RuntimeError("APIARY_CLAUDE_INTEGRATION=1 requires Claude Code CLI")


class ClaudeProtocolTest(unittest.TestCase):
    @unittest.skipUnless(RUN_CLAUDE, "set APIARY_CLAUDE_INTEGRATION=1 to run Claude Code against a local stub")
    def test_backend_500_is_reported_without_duplicate_model_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []

            def backend(_url, body):
                calls.append(body)
                raise RuntimeError("HTTPError 500: model backend failed")

            root = Path(tmp)
            cli = ClaudeCodeCLI("stub-model", backend, shutil.which("claude"), 90, 2,
                                root / "coder-artifacts" / "stub-model", version="integration")
            cli.set_case("coder", "backend-500")
            result = cli("ignored", {"model": "stub-model", "messages": [
                {"role": "system", "content": "Answer the user."},
                {"role": "user", "content": "Say hello."}],
                "options": {"num_predict": 16}})
            self.assertEqual(result["done_reason"], "error")
            self.assertIn("HTTPError 500", result["error"])
            self.assertEqual(len(calls), 1)
            events = (Path(result["cli_artifacts"]) / "cli.jsonl").read_text()
            self.assertNotIn('"type":"api_retry"', events)

    def test_original_prompt_survives_claude_continuation_messages(self):
        messages = [
            {"role": "user", "content": "original benchmark prompt"},
            {"role": "assistant", "content": "partial"},
            {"role": "user", "content": "[Please continue from the prior answer.]"},
            {"role": "tool", "content": "tool output"},
        ]
        self.assertTrue(_has_expected_prompt(messages, "original benchmark prompt"))
        self.assertFalse(_has_expected_prompt(messages[1:], "original benchmark prompt"))

    def test_final_result_does_not_duplicate_last_assistant_message(self):
        events = [
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "text", "text": " IMPLEMENTATION COMPLETE."}]}},
            {"type": "result", "result": "IMPLEMENTATION COMPLETE."},
        ]
        self.assertEqual(len(_cli_conversation(events)), 1)

    def test_anthropic_tool_use_and_results_map_to_existing_backend_messages(self):
        messages = _to_backend_messages("system prompt", [
            {"role": "user", "content": "write a file"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "tu1",
             "name": "Write", "input": {"file_path": "main.c", "content": "int main(void){}"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu1",
             "content": "wrote main.c"}]},
        ])
        self.assertEqual(messages[0], {"role": "system", "content": "system prompt"})
        self.assertEqual(messages[2]["tool_calls"][0]["function"]["name"], "Write")
        self.assertEqual(messages[3]["role"], "tool")
        self.assertEqual(messages[3]["tool_name"], "Write")
        self.assertEqual(messages[3]["content"], "wrote main.c")

    def test_backend_tool_calls_map_to_anthropic_tool_use_blocks(self):
        content = _to_anthropic_content({"content": "", "tool_calls": [{"id": "c1",
            "function": {"name": "Write", "arguments": {"file_path": "a.c"}}}]})
        self.assertEqual(content, [{"type": "tool_use", "id": "c1", "name": "Write",
                                    "input": {"file_path": "a.c"}}])

    @unittest.skipUnless(RUN_CLAUDE, "set APIARY_CLAUDE_INTEGRATION=1 to run Claude Code against a local stub")
    def test_real_claude_cli_writes_source_and_keeps_session_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            calls = []
            backend_urls = []

            def backend(_url, body):
                backend_urls.append(_url)
                calls.append(body)
                tool_returned = any(message.get("role") == "tool" for message in body["messages"])
                if not tool_returned:
                    return {"message": {"role": "assistant", "content": "", "tool_calls": [{
                        "id": "call_write", "type": "function", "function": {
                            "name": "write_file", "arguments": {"path": "main.c",
                                                                  "content": "int main(void){return 0;}\n"}}}]},
                        "done_reason": "length", "prompt_eval_count": 80, "eval_count": 12,
                        "eval_duration": 1000000000}
                return {"message": {"role": "assistant", "content": "IMPLEMENTATION COMPLETE"},
                        "done_reason": "stop", "prompt_eval_count": 90, "eval_count": 6,
                        "eval_duration": 1000000000}

            cli = ClaudeCodeCLI("stub-model", backend, shutil.which("claude"), 90, 8,
                                root / "coder-artifacts" / "stub-model", version="integration")
            cli.workspace = workspace
            cli.set_case("coder", "claude-cli-smoke")
            result = cli("ignored", {"model": "stub-model", "messages": [
                {"role": "system", "content": "Use file tools only. Never execute source code."},
                {"role": "user", "content": "Create main.c with one trivial C main function, then finish."}],
                "options": {"temperature": 0, "seed": 144, "num_ctx": 16384,
                            "num_predict": 512}})
            self.assertEqual(result["done_reason"], "stop", result.get("error"))
            self.assertEqual(result["backend_done_reasons"], ["length", "stop"])
            self.assertEqual(result["cli_control_model"], "sonnet")
            self.assertGreaterEqual(len(calls), 2)
            self.assertEqual(set(backend_urls), {"ignored"})
            self.assertIn("IMPLEMENTATION COMPLETE", result["message"]["content"])
            self.assertTrue((workspace / "main.c").is_file(),
                (result, calls, (Path(result["cli_artifacts"]) / "cli.jsonl").read_text(),
                 (Path(result["cli_artifacts"]) / "stderr.txt").read_text()))
            self.assertEqual((workspace / "main.c").read_text(), "int main(void){return 0;}\n")
            artifacts = Path(result["cli_artifacts"])
            self.assertTrue((artifacts / "session.jsonl").is_file())
            self.assertTrue((artifacts / "wire.jsonl").is_file())
            self.assertTrue(any("IMPLEMENTATION COMPLETE" in str(turn)
                                for turn in result["cli_conversation"]))
            self.assertFalse((root / "artifact-index.jsonl").exists())
            self.assertFalse((artifacts / "home").exists())
            self.assertNotIn("metadata", result["cli_messages"])
            self.assertNotIn("user_id", (artifacts / "wire.jsonl").read_text())
            self.assertTrue(any(turn["cli_tool"] == "mcp__apiary__write_file" and
                                turn["status"] == "accepted"
                                for turn in result["tool_turns"]))


if __name__ == "__main__":
    unittest.main()
