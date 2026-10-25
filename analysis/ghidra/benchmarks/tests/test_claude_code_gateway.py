"""Offline checks of the Claude Code gateway (#3706).

A fake `claude` executable stands in for Claude Code: it reads the benchmark
prompt from stdin, posts one streaming Anthropic Messages request to the
gateway (with Claude Code's own tool definitions attached, as the real CLI
always does), records every SSE event it receives and prints a stream-json
result. The backend is a plain callable or a fake HTTP engine, so nothing here
needs a model, a GPU or the network.
"""

import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from unittest import mock

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))
import claude_code_cli  # noqa: E402
from claude_code_cli import ClaudeCodeCLI  # noqa: E402

FAKE_CLI = r'''#!{python}
import http.client, json, os, sys, time
from urllib.parse import urlparse
args = sys.argv[1:]
system = open(args[args.index("--system-prompt-file") + 1]).read()
prompt = json.loads(sys.stdin.readline())["message"]["content"][0]["text"]
base = urlparse(os.environ["ANTHROPIC_BASE_URL"])
body = {{"model": "sonnet", "stream": True, "max_tokens": 32000,
        "system": [{{"type": "text", "text": system}}],
        "messages": [{{"role": "user", "content": [{{"type": "text", "text": prompt}}]}}],
        "tools": [{{"name": "mcp__apiary__write_file", "description": "write",
                   "input_schema": {{"type": "object"}}}}]}}
conn = http.client.HTTPConnection(base.hostname, base.port, timeout={read_timeout})
started = time.monotonic()
log = open(os.path.join(os.getcwd(), "fake-cli-events.jsonl"), "w")
try:
    conn.request("POST", "/v1/messages", json.dumps(body),
                 {{"Content-Type": "application/json"}})
    response = conn.getresponse()
    log.write(json.dumps({{"headers_after": time.monotonic() - started,
                          "status": response.status}}) + "\n"); log.flush()
    text, event = "", None
    while True:
        line = response.readline()
        if not line:
            break
        line = line.decode().strip()
        if line.startswith("event: "):
            event = line[7:]
        elif line.startswith("data: "):
            data = json.loads(line[6:])
            log.write(json.dumps({{"event": event, "at": time.monotonic() - started,
                                  "data": data}}) + "\n"); log.flush()
            if data.get("type") == "content_block_delta":
                text += data["delta"].get("text", "")
except Exception as exc:  # the real CLI's "Request timed out"
    print("API Error: " + type(exc).__name__, file=sys.stderr)
    conn.close()
    time.sleep({linger})
    sys.exit(1)
print(json.dumps({{"type": "result", "subtype": "success", "is_error": False,
                  "result": text, "session_id": "fake"}}))
'''


def fake_cli(directory: Path, read_timeout: float = 30, linger: float = 0) -> str:
    path = directory / "claude"
    path.write_text(FAKE_CLI.format(python=sys.executable, read_timeout=read_timeout,
                                    linger=linger))
    path.chmod(0o755)
    return str(path)


def benchmark_body(**extra):
    body = {"model": "stub", "stream": False, "messages": [
        {"role": "system", "content": "Answer."},
        {"role": "user", "content": "Return the sentinel."}],
        "options": {"num_ctx": 4096, "num_predict": 64}}
    body.update(extra)
    return body


def ok_answer(reason="stop", content="ANSWER"):
    return {"message": {"role": "assistant", "content": content},
            "done_reason": reason, "prompt_eval_count": 10, "eval_count": 3,
            "eval_duration": 1_000_000}


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, backend, body, slot="sessions", timeout=60, **cli_kwargs):
        cli = ClaudeCodeCLI("stub", backend, fake_cli(self.root, **cli_kwargs), timeout, 4,
                            self.root / "run" / "transcripts" / "stub", version="fake")
        cli.workspace = self.workspace
        cli.set_case(slot, "case-1")
        return cli("http://backend", body)

    def events(self):
        path = self.workspace / "fake-cli-events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    # Cause A: tools only where the benchmark asked for them.
    def test_no_tools_reach_the_backend_on_a_slot_that_did_not_ask(self):
        seen = []
        result = self.run_cli(lambda _u, b: (seen.append(b), ok_answer())[1],
                              benchmark_body(format="json"))
        self.assertIsNone(result["error"])
        self.assertEqual(result["done_reason"], "stop")
        self.assertNotIn("tools", seen[0])
        self.assertEqual(seen[0]["format"], "json")
        self.assertEqual(result["backend_tools_sent"], [False])

    def test_tools_reach_the_backend_when_the_coder_slot_asked(self):
        seen = []
        result = self.run_cli(lambda _u, b: (seen.append(b), ok_answer())[1],
                              benchmark_body(tools=[{"type": "function"}]), slot="coder")
        self.assertIsNone(result["error"])
        self.assertEqual([tool["function"]["name"] for tool in seen[0]["tools"]],
                         ["write_file"])
        self.assertEqual(result["backend_tools_sent"], [True])

    # Cause B: never tools and a grammar `format` in one request.
    def test_tools_and_grammar_format_are_never_sent_together(self):
        seen = []
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        result = self.run_cli(lambda _u, b: (seen.append(b), ok_answer())[1],
                              benchmark_body(tools=[{"type": "function"}], format=schema),
                              slot="coder")
        self.assertIsNone(result["error"])
        for request in seen:
            self.assertFalse("tools" in request and "format" in request, request)
        self.assertIn("tools", seen[0])
        wire = [json.loads(line) for line in
                (Path(result["cli_artifacts"]) / "wire.jsonl").read_text().splitlines()]
        self.assertEqual(wire[0]["format_dropped_for_tools"], schema)

    def test_grammar_guard_helper(self):
        body = {"tools": [{}], "format": "json"}
        self.assertEqual(claude_code_cli._without_grammar_conflict(body), "json")
        self.assertNotIn("format", body)
        body = {"format": "json"}
        self.assertIsNone(claude_code_cli._without_grammar_conflict(body))
        self.assertEqual(body["format"], "json")

    # Cause 0: the backend's real reason, and errors labelled by kind.
    def test_real_length_is_reported_as_length_not_error(self):
        result = self.run_cli(lambda _u, _b: ok_answer("length"), benchmark_body())
        self.assertIsNone(result["error"])
        self.assertIsNone(result["error_kind"])
        self.assertEqual(result["done_reason"], "length")
        self.assertEqual(result["backend_done_reason"], "length")

    def test_missing_tool_support_is_a_capability_error(self):
        def backend(_u, _b):
            raise urllib.error.HTTPError(
                "http://backend/api/chat", 400, "Bad Request", {},
                BytesIO(b'{"error":"stub does not support tools"}'))
        result = self.run_cli(backend, benchmark_body(tools=[{}]), slot="coder")
        self.assertEqual(result["done_reason"], "error")
        self.assertEqual(result["error_kind"], "capability")
        self.assertIn("does not support tools", result["error"])

    def test_transport_failure_is_a_backend_error(self):
        def backend(_u, _b):
            raise ConnectionResetError("reset by peer")
        result = self.run_cli(backend, benchmark_body())
        self.assertEqual(result["done_reason"], "error")
        self.assertEqual(result["error_kind"], "backend")

    # Cause C: headers at once, keepalive pings while the backend works.
    def test_stream_starts_at_once_and_pings_while_the_backend_works(self):
        def slow(_u, _b):
            time.sleep(1.6)
            return ok_answer()
        with mock.patch.object(claude_code_cli, "_KEEPALIVE_SECONDS", 0.3), \
                mock.patch.object(claude_code_cli, "_DISCONNECT_POLL_SECONDS", 0.05):
            result = self.run_cli(slow, benchmark_body())
        self.assertIsNone(result["error"])
        events = self.events()
        self.assertLess(events[0]["headers_after"], 1.0)
        self.assertEqual(events[1]["event"], "message_start")
        pings = [e for e in events if e.get("event") == "ping" and e["at"] < 1.5]
        self.assertGreaterEqual(len(pings), 3)
        self.assertEqual(events[-1]["event"], "message_stop")

    def test_stream_watchdogs_follow_the_harness_deadline(self):
        captured = {}
        real_popen = claude_code_cli.subprocess.Popen

        def popen(*args, **kwargs):
            captured.update(kwargs["env"])
            return real_popen(*args, **kwargs)
        with mock.patch.object(claude_code_cli.subprocess, "Popen", popen):
            self.run_cli(lambda _u, _b: ok_answer(), benchmark_body(), timeout=9000)
        for key in ("API_TIMEOUT_MS", "CLAUDE_STREAM_IDLE_TIMEOUT_MS",
                    "CLAUDE_BYTE_STREAM_IDLE_TIMEOUT_MS",
                    "CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS"):
            self.assertEqual(captured[key], "9000000")

    # Cause C: a CLI that hangs up cancels the engine's generation.
    def test_cli_disconnect_aborts_the_upstream_generation(self):
        closed = threading.Event()

        class Engine(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                try:  # a generation that would run for 30 s
                    for _ in range(300):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    closed.set()

        engine = ThreadingHTTPServer(("127.0.0.1", 0), Engine)
        threading.Thread(target=engine.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{engine.server_port}/api/chat"

        def backend(_u, body):
            request = urllib.request.Request(url, json.dumps(body).encode(),
                                             {"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=60) as response:
                response.read()
            return ok_answer()

        try:
            with mock.patch.object(claude_code_cli, "_DISCONNECT_POLL_SECONDS", 0.05):
                started = time.monotonic()
                result = self.run_cli(backend, benchmark_body(), read_timeout=1, linger=3)
                self.assertTrue(closed.wait(10), "engine never saw the client go away")
            self.assertLess(time.monotonic() - started, 15)
            self.assertEqual(result["done_reason"], "error")
            self.assertEqual(result["error_kind"], "cli")
            self.assertIn("exited 1", result["error"])
            self.assertNotIn("did not stop", result["error"])
            self.assertEqual(len(result["upstream_aborted"]), 1)
        finally:
            engine.shutdown()
            engine.server_close()


if __name__ == "__main__":
    unittest.main()
