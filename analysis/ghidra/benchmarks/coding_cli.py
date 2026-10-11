"""Run one benchmark request through an isolated OpenCode agent and local wire bridge."""

from __future__ import annotations

import json
import hashlib
import os
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        if any(not isinstance(part, dict) or part.get("type") != "text"
               for part in content):
            raise ValueError("non-text CLI message part")
        return "".join(part.get("text", "") for part in content
                       if isinstance(part, dict))
    if content is None:
        return ""
    raise ValueError("unsupported CLI message content")


def _to_backend_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    converted = []
    for item in messages:
        message = {"role": item.get("role"), "content": _text(item.get("content"))}
        if item.get("tool_calls"):
            calls = []
            for call in item["tool_calls"]:
                function = dict(call.get("function") or {})
                arguments = function.get("arguments")
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                if arguments is None:
                    arguments = {}
                if not isinstance(arguments, dict):
                    raise ValueError("tool call arguments must decode to an object")
                function["arguments"] = arguments
                calls.append({"function": function})
            message["tool_calls"] = calls
        converted.append(message)
    return converted


def _to_cli_calls(calls: list[dict[str, Any]], turn: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    converted, mapping = [], []
    for index, call in enumerate(calls):
        function = dict(call.get("function") or {})
        if not isinstance(function.get("arguments"), str):
            function["arguments"] = json.dumps(function.get("arguments") or {})
        call_id = call.get("id") or f"call_{turn}_{index}"
        converted.append({"index": index, "id": call_id, "type": "function",
                          "function": function})
        mapping.append({"backend_id": call.get("id"), "cli_id": call_id, "index": index})
    return converted, mapping


class CodingCLI:
    is_coding_cli = True

    def __init__(self, model: str, backend: Callable[..., dict[str, Any]], binary: str,
                 timeout: int, steps: int, artifact_root: Path):
        self.model, self.backend = model, backend
        self.binary, self.timeout, self.steps = binary, timeout, steps
        self.artifact_root = artifact_root
        self.slot = self.case = ""
        self.workspace: Path | None = None
        self.round = 0

    def set_case(self, slot: str, case: str) -> None:
        if (slot, case) != (self.slot, self.case):
            self.slot, self.case, self.round = slot, case, 0

    def __call__(self, _url: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._run(_url, body)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            root = (self.artifact_root / self.slot /
                    self.case.replace("/", "_").replace("..", "_") /
                    f"round-{self.round:02d}")
            root.mkdir(parents=True, exist_ok=True)
            (root / "error.txt").write_text(error + "\n", encoding="utf-8")
            with (self.artifact_root / "cli-index.jsonl").open("a", encoding="utf-8") as index:
                index.write(json.dumps({"slot": self.slot, "case": self.case,
                                        "round": self.round, "artifacts": str(root),
                                        "error": error}) + "\n")
            coder_root = self.artifact_root.parent
            with (coder_root.parent / "artifact-index.jsonl").open(
                    "a", encoding="utf-8") as index:
                index.write(json.dumps({"slot": self.slot, "case": self.case,
                                        "model": self.model, "round": self.round,
                                        "paths": sorted(str(path.relative_to(coder_root))
                                                        for path in root.rglob("*")
                                                        if path.is_file())}) + "\n")
            return {"message": {"role": "assistant", "content": ""},
                    "done_reason": "error", "error": error, "tool_turns": [],
                    "cli_artifacts": str(root),
                    "cli_artifacts_relative": str(root.relative_to(coder_root))}

    def _run(self, _url: str, body: dict[str, Any]) -> dict[str, Any]:
        self.round += 1
        # Case IDs are fixture-owned; still keep every artifact under the run root.
        safe_case = self.case.replace("/", "_").replace("..", "_")
        root = self.artifact_root / self.slot / safe_case / f"round-{self.round:02d}"
        root.mkdir(parents=True, exist_ok=True)
        (root / "prompt.json").write_text(json.dumps({
            "benchmark_request": body, "slot": self.slot, "case": self.case,
            "round": self.round}, indent=2), encoding="utf-8")
        workspace = self.workspace or root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        wire = root / "wire.jsonl"
        requests: list[dict[str, Any]] = []
        answers: list[dict[str, Any]] = []
        backend_errors: list[str] = []
        backend_issues: list[str] = []
        backend = self.backend
        model = self.model

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_GET(self) -> None:
                if self.path != "/v1/models":
                    self.send_error(404)
                    return
                self._json({"object": "list", "data": [{"id": "benchmark-model", "object": "model"}]})

            def _json(self, value: dict[str, Any], status: int = 200) -> None:
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                try:
                    request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    requests.append(request)
                    forwarded = None
                    forwarded = dict(body)
                    forwarded.pop("_cli_file_block_fallback", None)
                    forwarded["model"] = model
                    forwarded["messages"] = _to_backend_messages(request["messages"])
                    user = next((item for item in forwarded["messages"]
                                 if item.get("role") == "user"), None)
                    original_user = body["messages"][-1]["content"]
                    if user is None:
                        raise ValueError("CLI request omitted benchmark user prompt")
                    if user["content"] != original_user:
                        try:
                            decoded_user = json.loads(user["content"])
                        except ValueError:
                            decoded_user = None
                        if decoded_user != original_user:
                            raise ValueError("CLI changed benchmark user prompt")
                        user["content"] = original_user
                    forwarded["tools"] = request.get("tools", [])
                    forwarded["stream"] = False
                    # OpenCode v2 sends max_completion_tokens. The benchmark's
                    # declared budget is pinned for every backend request.
                    forwarded["options"] = dict(body["options"])
                    answer = backend(_url, forwarded)
                    auxiliary = False
                    answers.append({"auxiliary": auxiliary, "request": request,
                                    "backend_request": forwarded, "response": answer})
                    message = answer.get("message") or {}
                    calls, call_ids = _to_cli_calls(message.get("tool_calls") or [], len(answers))
                    answers[-1]["call_id_mapping"] = call_ids
                    reason = answer.get("done_reason")
                    if reason not in ("stop",):
                        backend_issues.append(f"backend done_reason {reason!r}")
                    finish = "length" if reason == "length" else (
                        "tool_calls" if calls else "stop")
                    usage = {"prompt_tokens": answer.get("prompt_eval_count") or 0,
                             "completion_tokens": answer.get("eval_count") or 0}
                    if request.get("stream"):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.end_headers()
                        chunks = [
                            {"choices": [{"index": 0, "delta": {
                                "role": "assistant", "content": message.get("content") or "",
                                **({"tool_calls": calls} if calls else {})},
                                "finish_reason": None}]},
                            {"choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                             "usage": usage},
                        ]
                        answers[-1]["cli_response"] = chunks
                        with wire.open("a", encoding="utf-8") as stream:
                            stream.write(json.dumps(answers[-1]) + "\n")
                        for chunk in chunks:
                            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                        self.wfile.write(b"data: [DONE]\n\n")
                    else:
                        payload = {"choices": [{"message": {**message, "tool_calls": calls},
                                                "finish_reason": finish}], "usage": usage}
                        answers[-1]["cli_response"] = payload
                        with wire.open("a", encoding="utf-8") as stream:
                            stream.write(json.dumps(answers[-1]) + "\n")
                        self._json(payload)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    backend_errors.append(error)
                    with wire.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"request": requests[-1] if requests else None,
                                                 "backend_request": forwarded if "forwarded" in locals() else None,
                                                 "error": error}) + "\n")
                    self._json({"error": {"message": error}}, 502)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        home = root / "home"
        config_dir = home / ".config" / "opencode"
        config_dir.mkdir(parents=True, exist_ok=True)
        config = {
            "$schema": "https://opencode.ai/config.json",
            "enabled_providers": ["benchmark"],
            "provider": {"benchmark": {"npm": "@ai-sdk/openai-compatible",
                "name": "Benchmark", "options": {
                    "baseURL": f"http://127.0.0.1:{server.server_port}/v1", "apiKey": "local"},
                "models": {"benchmark-model": {"name": "benchmark-model", "tool_call": True,
                    "limit": {"context": body["options"]["num_ctx"],
                              "output": body["options"]["num_predict"]}}}}},
            "model": "benchmark/benchmark-model", "small_model": "benchmark/benchmark-model",
            "autoupdate": False, "share": "disabled", "snapshot": False,
            "permission": {"*": "deny", "read": "allow", "glob": "allow",
                           "grep": "allow", "edit": "allow", "write": "allow",
                           "bash": "deny", "task": "deny", "external_directory": "deny"},
            "agent": {"build": {"steps": self.steps, "temperature": 0,
                                 "prompt": body["messages"][0]["content"],
                                 **({"tools": {"*": False}} if body.get("_cli_file_block_fallback")
                                    else {})}},
        }
        (config_dir / "opencode.json").write_text(json.dumps(config), encoding="utf-8")
        env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
        env.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                    "XDG_DATA_HOME": str(home / ".local" / "share"),
                    "XDG_CACHE_HOME": str(home / ".cache"),
                    "XDG_STATE_HOME": str(home / ".local" / "state"),
                    "NO_COLOR": "1"})
        prompt = body["messages"][-1]["content"]
        # A fixed title suppresses OpenCode's auxiliary title generation.
        command = [self.binary, "run", "--standalone", "--format", "json",
                   "--model", "benchmark/benchmark-model", "--title", "Benchmark case",
                   prompt]
        try:
            with (root / "cli.jsonl").open("w", encoding="utf-8") as stdout, \
                    (root / "stderr.txt").open("w", encoding="utf-8") as stderr:
                proc = subprocess.Popen(command, cwd=workspace, env=env, stdout=stdout,
                                        stderr=stderr, start_new_session=True)
                deadline = time.monotonic() + self.timeout
                error = None
                while proc.poll() is None:
                    if backend_errors:
                        error = backend_errors[0]
                        os.killpg(proc.pid, signal.SIGTERM)
                        break
                    if time.monotonic() >= deadline:
                        error = f"OpenCode timed out after {self.timeout}s"
                        os.killpg(proc.pid, signal.SIGTERM)
                        break
                    time.sleep(0.1)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                if error is None and proc.returncode:
                    error = f"OpenCode exited {proc.returncode}"
        except OSError as exc:
            error = f"{type(exc).__name__}: {exc}"
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
        session_id = next((event.get("sessionID") for event in events
                           if event.get("sessionID")), None)
        if session_id:
            try:
                with (root / "session.json").open("w", encoding="utf-8") as output, \
                        (root / "export-stderr.txt").open("w", encoding="utf-8") as diagnostics:
                    export = subprocess.run(
                        [self.binary, "session", "export", "--standalone", session_id],
                        cwd=workspace, env=env, stdout=output, stderr=diagnostics,
                        timeout=30, check=False)
                if export.returncode:
                    (root / "export-error.txt").write_text(
                        f"session export exited {export.returncode}\n", encoding="utf-8")
            except (OSError, subprocess.TimeoutExpired) as exc:
                (root / "export-error.txt").write_text(
                    f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        if not error and (root / "export-error.txt").exists():
            error = (root / "export-error.txt").read_text(encoding="utf-8").strip()
        texts = [event["part"].get("text", "") for event in events
                 if event.get("type") == "text" and isinstance(event.get("part"), dict)]
        turns = []
        for event in events:
            if event.get("type") != "tool_use":
                continue
            part = event.get("part") or {}
            state = part.get("state") or {}
            tool = part.get("tool")
            arguments = dict(state.get("input") or {})
            if tool in ("write", "edit", "apply_patch", "patch"):
                path = arguments.get("path") or arguments.get("filePath") or arguments.get("file_path")
                if isinstance(path, str):
                    try:
                        arguments["path"] = str((workspace / path).resolve().relative_to(workspace.resolve()))
                    except ValueError:
                        arguments["path"] = path
            turns.append({"id": part.get("id"), "tool": "write_file" if tool in
                          ("write", "edit", "apply_patch", "patch") else tool,
                          "cli_tool": tool, "arguments": arguments,
                          "status": "accepted" if state.get("status") == "completed" else "rejected",
                          "reason": state.get("error"), "result": state.get("output") or ""})
        if not error and not texts:
            error = (f"OpenCode reached step cap {self.steps}"
                     if len(answers) >= self.steps else "OpenCode produced no final answer")
        if not error and "maximum steps" in "".join(texts).lower():
            error = f"OpenCode reached step cap {self.steps}"
        if not error and not answers:
            error = "OpenCode made no benchmark model request"
        if not error and backend_errors:
            error = backend_errors[0]
        if not error and backend_issues:
            error = backend_issues[0]
        meaningful = [event for event in events if event.get("type") in ("text", "tool_use")]
        if not error and meaningful and meaningful[-1].get("type") != "text":
            error = f"OpenCode reached step cap {self.steps} without a final answer"
        if error:
            (root / "error.txt").write_text(error + "\n", encoding="utf-8")
        with (self.artifact_root / "cli-index.jsonl").open("a", encoding="utf-8") as index:
            index.write(json.dumps({"slot": self.slot, "case": self.case,
                                    "round": self.round, "artifacts": str(root),
                                    "error": error}) + "\n")
        coder_root = self.artifact_root.parent
        with (coder_root.parent / "artifact-index.jsonl").open("a", encoding="utf-8") as index:
            index.write(json.dumps({"slot": self.slot, "case": self.case,
                                    "model": self.model, "round": self.round,
                                    "paths": sorted(str(path.relative_to(coder_root))
                                                    for path in root.rglob("*")
                                                    if path.is_file())}) + "\n")
        reasons = [item["response"].get("done_reason") for item in answers
                   if not item["auxiliary"]]
        done_reason = next((reason or "missing_done_reason" for reason in reasons
                            if reason != "stop"), "stop")
        text_events = [event for event in events if event.get("type") == "text" and
                       isinstance(event.get("part"), dict)]
        final_message_id = (text_events[-1]["part"].get("messageID") if text_events else None)
        final_text = ((text_events[-1]["part"].get("text", "") if text_events else "")
                      if final_message_id is None else
                      "".join(event["part"].get("text", "") for event in text_events
                              if event["part"].get("messageID") == final_message_id))
        return {"message": {"role": "assistant", "content": final_text},
                "done_reason": "error" if error else done_reason,
                "error": error, "tool_turns": turns,
                "eval_count": sum((item["response"].get("eval_count") or 0)
                                  for item in answers if not item["auxiliary"]),
                "prompt_eval_count": sum((item["response"].get("prompt_eval_count") or 0)
                                         for item in answers if not item["auxiliary"]),
                "eval_duration": sum((item["response"].get("eval_duration") or 0)
                                     for item in answers if not item["auxiliary"]),
                "cli_artifacts": str(root), "cli_session_id": session_id,
                "cli_wire_sha256": hashlib.sha256(wire.read_bytes()).hexdigest()
                if wire.exists() else None,
                "cli_messages": requests[0].get("messages") if requests else None,
                "backend_options": [item["backend_request"]["options"] for item in answers
                                    if item.get("backend_request")],
                "cli_artifacts_relative": str(root.relative_to(self.artifact_root.parent))}
