"""Claude Code CLI adapter for APIARY's existing model transports.

Claude Code speaks Anthropic Messages to a loopback shim. The shim maps that
protocol to the benchmark's existing Ollama-shaped transport, keeping the
selected llama.cpp/Ollama/Colibri engine and its request budgets intact.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


def _block_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    return "".join(str(block.get("text", "")) for block in value
                   if isinstance(block, dict) and block.get("type") == "text")


def _canonical_tool(name: str) -> str:
    prefix = "mcp__apiary__"
    return name[len(prefix):] if name.startswith(prefix) else name


def _has_expected_prompt(messages: list[dict[str, Any]], expected: str) -> bool:
    """Check that the original benchmark prompt remains in the conversation."""
    for message in messages:
        if message.get("role") != "user":
            continue
        value = str(message.get("content", ""))
        if expected and expected in value:
            return True
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError):
            continue
        if decoded == expected:
            return True
    return False


def _cli_conversation(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return readable user/assistant/tool turns from Claude's streamed events."""
    turns: list[dict[str, Any]] = []
    for event in events:
        message = event.get("message") or {}
        role = message.get("role")
        content = message.get("content") or []
        if role in ("user", "assistant"):
            blocks = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                kind = block.get("type")
                if kind in ("text", "tool_use", "tool_result"):
                    blocks.append(block)
            if blocks:
                turns.append({"role": role, "content": blocks})
        if event.get("type") == "result" and event.get("result"):
            turns.append({"role": "assistant", "content": [
                {"type": "text", "text": str(event["result"])}]})
    return turns


def _to_backend_messages(system: Any, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate Anthropic content blocks into the existing chat message shape."""
    result: list[dict[str, Any]] = []
    system_text = _block_text(system)
    if system_text:
        result.append({"role": "system", "content": system_text})
    tool_names: dict[str, str] = {}
    for message in messages:
        role = message.get("role")
        blocks = message.get("content", "")
        if isinstance(blocks, str):
            result.append({"role": role, "content": blocks})
            continue
        if not isinstance(blocks, list):
            raise ValueError("Anthropic message content must be text or a block list")
        text_parts: list[str] = []
        calls: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                text_parts.append(str(block.get("text", "")))
            elif role == "assistant" and kind == "tool_use":
                call_id = str(block.get("id") or f"claude_tool_{len(tool_names)}")
                name = _canonical_tool(str(block.get("name") or ""))
                tool_names[call_id] = name
                calls.append({"id": call_id, "type": "function", "function": {
                    "name": name, "arguments": block.get("input") or {}}})
            elif kind == "tool_result":
                content = block.get("content", "")
                if isinstance(content, list):
                    content = _block_text(content)
                tool_results.append({"role": "tool", "tool_call_id": block.get("tool_use_id"),
                                     "tool_name": tool_names.get(str(block.get("tool_use_id")), ""),
                                     "content": str(content)})
        if text_parts or calls:
            entry: dict[str, Any] = {"role": role, "content": "\n".join(text_parts)}
            if calls:
                entry["tool_calls"] = calls
            result.append(entry)
        if role == "user":
            result.extend(tool_results)
    return result


def _to_anthropic_content(message: dict[str, Any]) -> list[dict[str, Any]]:
    content: list[dict[str, Any]] = []
    text = message.get("content") or ""
    if text:
        content.append({"type": "text", "text": str(text)})
    for index, call in enumerate(message.get("tool_calls") or []):
        function = call.get("function") or {}
        arguments = function.get("arguments") or {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                arguments = {"_raw": arguments}
        if not isinstance(arguments, dict):
            arguments = {"_raw": arguments}
        name = str(function.get("name") or "unknown")
        if name in {"write_file", "read_file", "list_files"}:
            name = "mcp__apiary__" + name
        content.append({"type": "tool_use", "id": str(call.get("id") or f"toolu_{index}"),
                        "name": name, "input": arguments})
    return content


def _exception_detail(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read().decode("utf-8", errors="replace").strip()
        except OSError:
            body = ""
        if body:
            try:
                payload = json.loads(body)
                detail = payload.get("error", payload.get("message", payload))
                if isinstance(detail, dict):
                    detail = detail.get("message", detail)
                return f"HTTPError {exc.code}: {detail}"
            except (ValueError, TypeError):
                return f"HTTPError {exc.code}: {body}"
        return f"HTTPError {exc.code}: {exc.reason}"
    return f"{type(exc).__name__}: {exc}"


class ClaudeCodeCLI:
    """Run one Claude Code print session against an existing model transport."""

    is_coding_cli = True
    harness_name = "claude-code"

    def __init__(self, model: str, backend: Callable[..., dict[str, Any]], binary: str,
                 timeout: int, steps: int, artifact_root: Path, version: str = "unknown"):
        self.model, self.backend = model, backend
        self.binary, self.timeout, self.steps = binary, timeout, steps
        self.artifact_root, self.version = artifact_root, version
        self.slot = self.case = ""
        self.workspace: Path | None = None
        self.round = 0

    def set_case(self, slot: str, case: str) -> None:
        if (slot, case) != (self.slot, self.case):
            self.slot, self.case, self.round = slot, case, 0

    def __call__(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        self.backend_url = url
        try:
            return self._run(body)
        except Exception as exc:  # preserve one case's failure and evidence
            error = _exception_detail(exc)
            safe_case = self.case.replace("/", "_").replace("..", "_")
            root = self.artifact_root / self.slot / safe_case / f"round-{self.round:02d}"
            root.mkdir(parents=True, exist_ok=True)
            (root / "error.txt").write_text(error + "\n", encoding="utf-8")
            run_root = self.artifact_root.parent.parent
            return {"message": {"role": "assistant", "content": ""},
                    "done_reason": "error", "error": error, "tool_turns": [],
                    "cli_artifacts": str(root),
                    "cli_artifacts_relative": str(root.relative_to(run_root)),
                    "cli_version": self.version}

    def _run(self, body: dict[str, Any]) -> dict[str, Any]:
        self.round += 1
        safe_case = self.case.replace("/", "_").replace("..", "_")
        root = self.artifact_root / self.slot / safe_case / f"round-{self.round:02d}"
        root.mkdir(parents=True, exist_ok=True)
        workspace = self.workspace or root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        prompt = body["messages"][-1]["content"]
        system_prompt = body["messages"][0]["content"]
        (root / "system-prompt.txt").write_text(system_prompt, encoding="utf-8")
        (root / "prompt.json").write_text(json.dumps({
            "benchmark_request": body, "slot": self.slot, "case": self.case,
            "round": self.round, "cli_version": self.version}, indent=2), encoding="utf-8")
        wire = root / "wire.jsonl"
        requests: list[dict[str, Any]] = []
        answers: list[dict[str, Any]] = []
        backend_errors: list[str] = []
        backend_done_reasons: list[str | None] = []
        backend = self.backend
        self_outer = self
        expected_user = prompt

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_HEAD(self) -> None:
                self.send_response(200 if self.path == "/api/hello" else 404)
                self.end_headers()

            def do_GET(self) -> None:
                if self.path == "/v1/models":
                    self._json({"data": [{"id": model, "type": "model", "display_name": model}]})
                else:
                    self.send_error(404)

            def _json(self, value: dict[str, Any], status: int = 200) -> None:
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _event(self, name: str, value: dict[str, Any]) -> None:
                data = json.dumps(value, separators=(",", ":")).encode()
                self.wfile.write(b"event: " + name.encode() + b"\ndata: " + data + b"\n\n")

            def do_POST(self) -> None:
                if self.path == "/v1/messages/count_tokens":
                    try:
                        incoming = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                        text = _block_text(incoming.get("system")) + _block_text(incoming.get("messages", []))
                        self._json({"input_tokens": max(1, (len(text) + 3) // 4)})
                    except Exception as exc:
                        self._json({"type": "error", "error": {"type": "invalid_request_error",
                                  "message": _exception_detail(exc)}}, 400)
                    return
                if self.path.split("?", 1)[0] != "/v1/messages":
                    self.send_error(404)
                    return
                try:
                    incoming = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                    # Claude CLI attaches persistent device/account identifiers that
                    # are unrelated to benchmark behavior. Never retain or forward them.
                    incoming.pop("metadata", None)
                    requests.append(incoming)
                    forwarded: dict[str, Any] = dict(body)
                    forwarded.pop("_cli_file_block_fallback", None)
                    forwarded["model"] = model
                    forwarded["messages"] = _to_backend_messages(
                        incoming.get("system"), incoming.get("messages") or [])
                    user_messages = [item.get("content", "") for item in forwarded["messages"]
                                     if item.get("role") == "user"]
                    if not user_messages:
                        raise ValueError("Claude Code request omitted benchmark user prompt")
                    if not _has_expected_prompt(forwarded["messages"], expected_user):
                        raise ValueError("Claude Code conversation omitted benchmark user prompt")
                    tool_defs = []
                    if not body.get("_cli_file_block_fallback"):
                        for tool in incoming.get("tools") or []:
                            if not isinstance(tool, dict) or not tool.get("name"):
                                continue
                            tool_defs.append({"type": "function", "function": {
                                "name": _canonical_tool(str(tool["name"])),
                                "description": tool.get("description", ""),
                                "parameters": tool.get("input_schema") or {"type": "object"}}})
                    forwarded["tools"] = tool_defs
                    forwarded["stream"] = False
                    forwarded["options"] = dict(body.get("options") or {})
                    # The callback belongs to the selected engine transport. Ollama
                    # honors its URL argument; llama.cpp and Colibri own their endpoint.
                    answer = backend(self_outer.backend_url, forwarded)
                    answers.append({"request": incoming, "backend_request": forwarded,
                                    "response": answer})
                    message = answer.get("message") or {}
                    content = _to_anthropic_content(message)
                    calls = message.get("tool_calls") or []
                    reason = answer.get("done_reason")
                    backend_done_reasons.append(reason)
                    if reason not in ("stop", "length"):
                        backend_errors.append(f"backend done_reason {reason!r}")
                    stop_reason = ("max_tokens" if reason == "length" else
                                   "tool_use" if calls else "end_turn")
                    reply = {"id": f"msg_{uuid.uuid4().hex}", "type": "message",
                             "role": "assistant", "model": str(incoming.get("model") or model),
                             "content": content, "stop_reason": stop_reason,
                             "stop_sequence": None,
                             "usage": {"input_tokens": answer.get("prompt_eval_count") or 0,
                                       "output_tokens": answer.get("eval_count") or 0}}
                    answers[-1]["cli_response"] = reply
                    with wire.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(answers[-1]) + "\n")
                    if incoming.get("stream"):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Cache-Control", "no-cache")
                        self.end_headers()
                        self._event("message_start", {"type": "message_start", "message": {
                            **{**reply, "content": [], "stop_reason": None},
                            "usage": {"input_tokens": reply["usage"]["input_tokens"],
                                      "output_tokens": 0}}})
                        self._event("ping", {"type": "ping"})
                        for index, block in enumerate(content):
                            if block["type"] == "text":
                                self._event("content_block_start", {"type": "content_block_start",
                                    "index": index, "content_block": {"type": "text", "text": ""}})
                                self._event("content_block_delta", {"type": "content_block_delta",
                                    "index": index, "delta": {"type": "text_delta", "text": block["text"]}})
                            else:
                                self._event("content_block_start", {"type": "content_block_start",
                                    "index": index, "content_block": {"type": "tool_use",
                                        "id": block["id"], "name": block["name"], "input": {}}})
                                self._event("content_block_delta", {"type": "content_block_delta",
                                    "index": index, "delta": {"type": "input_json_delta",
                                        "partial_json": json.dumps(block["input"])}})
                            self._event("content_block_stop", {"type": "content_block_stop",
                                                                  "index": index})
                        self._event("message_delta", {"type": "message_delta", "delta": {
                            "stop_reason": stop_reason, "stop_sequence": None},
                            "usage": {"output_tokens": reply["usage"]["output_tokens"]}})
                        self._event("message_stop", {"type": "message_stop"})
                    else:
                        self._json(reply)
                except Exception as exc:
                    error = _exception_detail(exc)
                    backend_errors.append(error)
                    with wire.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"request": requests[-1] if requests else None,
                            "backend_request": forwarded if "forwarded" in locals() else None,
                            "error": error}) + "\n")
                    self._json({"type": "error", "error": {"type": "api_error",
                               "message": error}}, 502)

        model = self.model
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        home = root / "home"
        config_dir = home / ".claude"
        config_dir.mkdir(parents=True, exist_ok=True)
        system_path = root / "system-prompt.txt"
        mcp_config = root / "mcp-config.json"
        mcp_config.write_text(json.dumps({"mcpServers": {"apiary": {
            "type": "stdio", "command": sys.executable,
            "args": [str(Path(__file__).with_name("mcp_tools_server.py"))],
            "env": {"APIARY_WORKSPACE": str(workspace),
                    "PYTHONDONTWRITEBYTECODE": "1"}}}}), encoding="utf-8")
        env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
        env.update({"HOME": str(home), "CLAUDE_CONFIG_DIR": str(config_dir),
                    "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                    "ANTHROPIC_AUTH_TOKEN": "benchmark-local",
                    "ANTHROPIC_MODEL": "sonnet", "NO_COLOR": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
                    "DISABLE_AUTOUPDATER": "1"})
        session_id = str(uuid.uuid4())
        command = [self.binary, "--bare", "--restricted", "-p", "--input-format", "stream-json",
                   "--output-format", "stream-json", "--verbose", "--model", "sonnet",
                   "--system-prompt-file", str(system_path), "--session-id", session_id,
                   "--max-turns", str(self.steps), "--permission-mode", "dontAsk",
                   "--mcp-config", str(mcp_config), "--tools", "",
                   "--allowedTools", "mcp__apiary__write_file",
                   "mcp__apiary__read_file", "mcp__apiary__list_files"]
        input_message = json.dumps({"type": "user", "message": {"role": "user",
                                     "content": [{"type": "text", "text": prompt}]}})
        error = None
        try:
            with (root / "cli.jsonl").open("w", encoding="utf-8") as stdout, \
                    (root / "stderr.txt").open("w", encoding="utf-8") as stderr:
                proc = subprocess.Popen(command, cwd=workspace, env=env,
                    stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    proc.stdin.write((input_message + "\n").encode())
                    proc.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
                deadline = time.monotonic() + self.timeout
                while proc.poll() is None:
                    if backend_errors:
                        error = backend_errors[0]
                        os.killpg(proc.pid, signal.SIGTERM)
                        break
                    if time.monotonic() >= deadline:
                        error = f"Claude Code timed out after {self.timeout}s"
                        os.killpg(proc.pid, signal.SIGTERM)
                        break
                    time.sleep(0.1)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                if error is None and proc.returncode:
                    stderr_text = (root / "stderr.txt").read_text(encoding="utf-8",
                                                                   errors="replace")
                    detail = stderr_text.strip().splitlines()
                    error = f"Claude Code exited {proc.returncode}"
                    if detail:
                        error += f": {detail[-1][-500:]}"
        except OSError as exc:
            error = _exception_detail(exc)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        events = []
        for line in (root / "cli.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        result_event = next((event for event in reversed(events)
                             if event.get("type") == "result"), {})
        native_sessions = list(config_dir.rglob("*.jsonl"))
        if native_sessions:
            # Keep the actual session transcript, then discard Claude config,
            # device identity, and cache files generated in this private HOME.
            (root / "session.jsonl").write_bytes(native_sessions[0].read_bytes())
        shutil.rmtree(home, ignore_errors=True)
        turns = []
        tool_results: dict[str, dict[str, Any]] = {}
        for event in events:
            msg = event.get("message") or {}
            for block in msg.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    tool_results[str(block.get("tool_use_id"))] = block
        for event in events:
            msg = event.get("message") or {}
            for block in msg.get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                tool = block.get("name") or "unknown"
                arguments = dict(block.get("input") or {})
                canonical_tool = _canonical_tool(tool)
                if canonical_tool in ("write_file", "Write", "Edit"):
                    path = arguments.get("file_path") or arguments.get("path")
                    if isinstance(path, str):
                        try:
                            arguments["path"] = str(Path(path).resolve().relative_to(workspace.resolve()))
                        except ValueError:
                            arguments["path"] = path
                result = tool_results.get(str(block.get("id")), {})
                turns.append({"id": block.get("id"),
                    "tool": "write_file" if canonical_tool in ("write_file", "Write", "Edit") else canonical_tool,
                    "cli_tool": tool, "arguments": arguments,
                    "status": "rejected" if result.get("is_error") else "accepted",
                    "reason": result.get("is_error"),
                    "result": _block_text(result.get("content"))})
        final = result_event.get("result") or ""
        if not error and not result_event:
            error = "Claude Code emitted no final result event"
        if not error and result_event.get("is_error"):
            error = str(final or result_event.get("subtype") or "Claude Code result error")
        if not error and not answers:
            error = "Claude Code made no benchmark model request"
        if not error and backend_errors:
            error = backend_errors[0]
        if not error and answers and answers[-1]["response"].get("done_reason") == "length":
            error = "backend done_reason length (no completed recovery request)"
        if error:
            (root / "error.txt").write_text(error + "\n", encoding="utf-8")
        run_root = self.artifact_root.parent.parent
        paths = sorted(str(path.relative_to(run_root)) for path in root.rglob("*") if path.is_file())
        with (self.artifact_root / "cli-index.jsonl").open("a", encoding="utf-8") as index:
            index.write(json.dumps({"slot": self.slot, "case": self.case, "round": self.round,
                                    "artifacts": str(root), "error": error}) + "\n")
        conversation = _cli_conversation(events)
        return {"message": {"role": "assistant", "content": str(final)},
                "done_reason": "error" if error else "stop", "error": error,
                "tool_turns": turns,
                "eval_count": sum(item["response"].get("eval_count") or 0 for item in answers),
                "prompt_eval_count": sum(item["response"].get("prompt_eval_count") or 0
                                          for item in answers),
                "eval_duration": sum(item["response"].get("eval_duration") or 0 for item in answers),
                "cli_artifacts": str(root),
                "cli_artifacts_relative": str(root.relative_to(run_root)),
                "cli_session_id": result_event.get("session_id") or session_id,
                "cli_wire_sha256": hashlib.sha256(wire.read_bytes()).hexdigest()
                    if wire.exists() else None,
                "cli_messages": requests[0] if requests else None,
                "cli_conversation": conversation,
                "backend_done_reasons": backend_done_reasons,
                "cli_control_model": "sonnet",
                "backend_options": [item["backend_request"]["options"] for item in answers],
                "cli_version": self.version}

