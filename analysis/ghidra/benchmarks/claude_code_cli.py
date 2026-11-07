"""Claude Code CLI adapter for APIARY's existing model transports.

Claude Code speaks Anthropic Messages to a loopback shim. The shim maps that
protocol to the benchmark's existing Ollama-shaped transport, keeping the
selected llama.cpp/Ollama/Colibri engine and its request budgets intact.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import select
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


# #3706 cause 3. The gateway used to answer a streaming Claude Code request only
# once the whole backend answer existed, so the CLI saw no byte at all for as
# long as the model took. Claude Code 2.1.294 gives up on a silent stream after
# roughly 360 s ("Request timed out") whatever API_TIMEOUT_MS says, because
# API_TIMEOUT_MS is the SDK request timeout, not the stream watchdogs. Read from
# the shipped binary (read-only), the watchdogs are:
#   * a first-byte window -- no response headers yet -- defaulting to the byte
#     idle timeout (CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS overrides it);
#   * a byte idle timeout, clamped to [10 s, 30 min], fed by any byte;
#   * an event idle watchdog of max(CLAUDE_STREAM_IDLE_TIMEOUT_MS, 300 s), fed
#     by stream events. `ping` events feed it only for the first 30 in a row,
#     so pings alone keep a stream alive for 30 pings plus that timeout.
# The gateway therefore sends headers and `message_start` at once, a `ping`
# every _KEEPALIVE_SECONDS while the backend works, and raises the event
# watchdog to the harness's own per-case timeout (see the env in _run). Which
# of the watchdogs fired at ~360 s in the stopped run is not verified; the
# fix feeds all three.
_KEEPALIVE_SECONDS = 15.0
# How often the gateway looks at the CLI's socket for a disconnect while the
# backend is still generating. Cheap (a zero-timeout select), and short enough
# that an aborted CLI frees the GPU within a second rather than after the
# hour a 16000-token answer can take.
_DISCONNECT_POLL_SECONDS = 0.5

# #3706 cause 3, the other half: when the CLI hangs up, the backend request
# has to be cancelled, not left to finish for nobody. One stopped run produced a
# complete 7250-token answer 3653 s after the CLI had aborted and then failed
# writing it to a closed socket -- an hour of GPU for a thrown-away answer, and
# the next case queued behind it.
#
# The backend is whatever serving.py bound -- Ollama's /api/chat, llama.cpp,
# Colibri -- and every one of those is a blocking urllib call with no cancel
# handle. Closing the upstream socket is the one cancellation all three engines
# honour (Ollama and llama-server stop a generation whose client went away), so
# the gateway runs each backend call on its own thread and records the HTTP
# connections that thread opens. Hooking HTTPConnection.connect is the only
# place that sees them without changing serving.py's transports; the hook is
# installed once, does nothing on threads that did not ask for it, and calls
# the original connect unchanged.
_UPSTREAM = threading.local()
_UPSTREAM_HOOK_LOCK = threading.Lock()
_UPSTREAM_HOOKED = False


def _install_upstream_tracking() -> None:
    global _UPSTREAM_HOOKED
    with _UPSTREAM_HOOK_LOCK:
        if _UPSTREAM_HOOKED:
            return
        original = http.client.HTTPConnection.connect

        def connect(connection: http.client.HTTPConnection, *args: Any, **kwargs: Any) -> Any:
            result = original(connection, *args, **kwargs)
            call = getattr(_UPSTREAM, "call", None)
            if call is not None:
                call.register(connection)
            return result

        http.client.HTTPConnection.connect = connect  # type: ignore[method-assign]
        _UPSTREAM_HOOKED = True


class _UpstreamCall:
    """One backend request on its own thread, abortable from the gateway.

    `abort()` shuts down every socket the call opened, which makes the blocked
    urllib read fail on the worker thread and tells the engine its client is
    gone. The socket is taken from `connection.sock` right after connect()
    returns -- for HTTPS that is the wrapped socket actually in use -- and kept
    here, because urllib drops `connection.sock` (closing only its reference;
    the response still reads from the open fd) as soon as the headers arrive,
    so by the time an abort is needed the connection no longer names it.
    """

    def __init__(self, backend: Callable[..., dict[str, Any]], url: str,
                 body: dict[str, Any]):
        self._backend, self._url, self._body = backend, url, body
        self._lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self.done = threading.Event()
        self.aborted = False
        self.answer: dict[str, Any] | None = None
        self.exception: BaseException | None = None
        _install_upstream_tracking()
        self._thread = threading.Thread(target=self._work, daemon=True)

    def start(self) -> "_UpstreamCall":
        self._thread.start()
        return self

    def register(self, connection: http.client.HTTPConnection) -> None:
        sock = getattr(connection, "sock", None)
        if sock is None:
            return
        with self._lock:
            self._sockets.append(sock)
            abort_now = self.aborted
        if abort_now:
            self._shutdown(sock)

    def _work(self) -> None:
        _UPSTREAM.call = self
        try:
            self.answer = self._backend(self._url, self._body)
        except BaseException as exc:  # handed to the gateway thread
            self.exception = exc
        finally:
            _UPSTREAM.call = None
            self.done.set()

    @staticmethod
    def _shutdown(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def abort(self) -> None:
        with self._lock:
            if self.done.is_set():
                return
            self.aborted = True
            sockets = list(self._sockets)
        for sock in sockets:
            self._shutdown(sock)


def _client_gone(connection: socket.socket) -> bool:
    """True when the CLI closed its end of the gateway connection.

    A request was read in full before the backend call started, so the only
    thing that can make the socket readable now is EOF (or a reset).
    """
    try:
        readable, _, _ = select.select([connection], [], [], 0)
        if not readable:
            return False
        return connection.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def _without_grammar_conflict(forwarded: dict[str, Any]) -> str | None:
    """Drop a grammar-producing `format` from a request that carries tools.

    #3706 cause 2: Ollama builds one sampler grammar per request. A JSON
    `format` (the sessions slot sends a JSON-schema object; ghidra and the
    context probe send "json") together with a `tools` array fails before a
    token is produced -- `400 Failed to initialize samplers: failed to parse
    grammar` after 0.84 s, sessions 10/10 on nine models, while the same model
    scored 136/136 on the no-CLI run where no tools were sent. Tools are the
    request's point when they are present (only the coder slot asks for them,
    and it sends no format), so the format is the one that goes, and the
    request records that it went. Returns the dropped format, or None.
    """
    if forwarded.get("tools") and "format" in forwarded:
        return forwarded.pop("format")
    return None


# Backend error texts that describe what the model did, not a failure to get
# an answer (#3706). Lower case; matched as substrings of the error.
_MODEL_OUTCOME_ERRORS = (
    "token repeat limit reached",            # Ollama's degenerate-loop stop
    "xml syntax error",                      # Ollama's qwen tool-call parser
    "returned invalid tool call arguments",  # llama-server tool-call parser
)


def _error_kind(error: str | None, source: str) -> str | None:
    """Which kind of non-answer an error is (#3706 cause 0).

    `capability` is a backend refusing a feature the request needs -- a model
    whose template has no tool support. It is a skip, not an answer and not a
    transport fault. Otherwise `source` says where the error was raised:
    `backend` for an HTTP or transport failure between the gateway and the
    engine, `cli` for Claude Code itself failing (non-zero exit, the harness's
    deadline, no final result). `model` is the agent turn cap: the model kept
    calling tools for every allowed turn and never finished -- a real non-stop,
    not a harness fault. None means no error.

    Some backend errors are the engine reporting a model outcome rather than
    failing to produce one: Ollama aborting a degenerate repetition loop, or
    rejecting a tool call the model wrote malformed. Those are `model` too.
    """
    if not error:
        return None
    if source == "model":
        return "model"
    lowered = error.lower()
    if any(phrase in lowered for phrase in _MODEL_OUTCOME_ERRORS):
        return "model"
    # Ollama's wording for a template without the feature: "<model> does not
    # support tools" (also "... thinking", "... insert").
    if "does not support" in error.lower():
        return "capability"
    return source


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
        final = str(event.get("result") or "")
        already_present = any(
            block.get("type") == "text" and
            str(block.get("text") or "").strip() == final.strip()
            for turn in turns for block in turn.get("content", [])
            if isinstance(block, dict)
        )
        if event.get("type") == "result" and final and not already_present:
            turns.append({"role": "assistant", "content": [
                {"type": "text", "text": final}]})
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
        # A user turn that carries tool results answers the preceding
        # assistant tool call, so the results come first and any text the CLI
        # added after them (its "no visible output" nudge) follows. Text first
        # put a user message between the call and its result, which templates
        # that enforce role alternation (Mistral) reject with a 500.
        if role == "user":
            result.extend(tool_results)
        if text_parts or calls:
            entry: dict[str, Any] = {"role": role, "content": "\n".join(text_parts)}
            if calls:
                entry["tool_calls"] = calls
            result.append(entry)
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
                    "done_reason": "error", "error": error,
                    "error_kind": _error_kind(error, "cli"), "tool_turns": [],
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
        # A backend answer that ended on a model-side reason other than `stop`
        # (e.g. a repetition stop). Not an error -- the model answered and did
        # not finish -- but the CLI cannot do anything useful with it, so it
        # ends the case exactly as before (#3706 cause 0). A text-only `length`
        # stop is one too: Claude Code answers `max_tokens` by asking the model
        # to resume, up to three times, and then exits 1. That gave a model
        # four output budgets instead of one, cost up to 4x the GPU time, and
        # reported the budget stop as a CLI error.
        backend_halts: list[str] = []
        # Backend requests in flight, so a harness-side kill of the CLI (its
        # deadline, a backend error) can abort them too instead of leaving a
        # handler thread waiting on a generation nobody will read.
        in_flight: set[_UpstreamCall] = set()
        in_flight_lock = threading.Lock()
        backend = self.backend
        self_outer = self
        expected_user = prompt
        # #3706 cause 1: only the coder slot asks for tools (chat() puts them on
        # the benchmark body). Claude Code attaches its mcp__apiary__* tool
        # definitions to every request regardless, and forwarding those on the
        # ghidra, sessions and revdeck slots and the context probe sent a tool
        # array to models that never needed one -- an instant `400 ... does not
        # support tools` with 0 tokens on 13 models. The CLI still offers the
        # tools to its own session; the backend only sees them when the
        # benchmark request did.
        forward_tools = bool(body.get("tools")) and not body.get("_cli_file_block_fallback")
        tools_sent: list[bool] = []
        # Backend requests cancelled because the CLI hung up first. Evidence,
        # not the case's error: the CLI's own failure (its exit, the harness
        # deadline) is what ended the case, and is reported as such.
        upstream_aborts: list[str] = []

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
                self.wfile.flush()

            def _await_backend(self, forwarded: dict[str, Any],
                               streaming: bool) -> dict[str, Any] | None:
                """Run the backend call, keeping the CLI fed and watching it.

                Returns the backend answer, or None when the CLI hung up first;
                in that case the backend request has been aborted. A backend
                exception is re-raised here, on the handler thread, so the
                existing error path below reports it unchanged.
                """
                call = _UpstreamCall(backend, self_outer.backend_url, forwarded)
                with in_flight_lock:
                    in_flight.add(call)
                call.start()
                last_ping = time.monotonic()
                try:
                    while not call.done.wait(_DISCONNECT_POLL_SECONDS):
                        gone = _client_gone(self.connection)
                        if not gone and streaming and \
                                time.monotonic() - last_ping >= _KEEPALIVE_SECONDS:
                            try:
                                self._event("ping", {"type": "ping"})
                                last_ping = time.monotonic()
                            except OSError:
                                gone = True
                        if gone:
                            call.abort()
                            call.done.wait(5)
                            return None
                finally:
                    with in_flight_lock:
                        in_flight.discard(call)
                if call.aborted and call.answer is None:
                    return None
                if call.exception is not None:
                    raise call.exception
                return call.answer

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
                streaming = False
                headers_sent = False
                started = time.monotonic()
                if backend_halts:
                    # The case already ended on a model-side stop and the CLI
                    # is being stopped. Its follow-up (a resume request) must
                    # not reach the engine.
                    self.rfile.read(int(self.headers.get("Content-Length", 0)))
                    self._json({"type": "error", "error": {"type": "api_error",
                               "message": backend_halts[0]}}, 502)
                    return
                if backend_errors:
                    # The case already failed and the CLI is being stopped. A
                    # backend error delivered mid-stream makes Claude Code fall
                    # back to a second, non-streaming request; never pay the
                    # engine for that duplicate.
                    self.rfile.read(int(self.headers.get("Content-Length", 0)))
                    self._json({"type": "error", "error": {"type": "api_error",
                               "message": backend_errors[0]}}, 502)
                    return
                try:
                    incoming = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                    # Claude CLI attaches persistent device/account identifiers that
                    # are unrelated to benchmark behavior. Never retain or forward them.
                    incoming.pop("metadata", None)
                    requests.append(incoming)
                    streaming = bool(incoming.get("stream"))
                    forwarded: dict[str, Any] = dict(body)
                    forwarded.pop("_cli_file_block_fallback", None)
                    # Rebuilt below from the CLI's own definitions, or left out.
                    forwarded.pop("tools", None)
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
                    if forward_tools:
                        for tool in incoming.get("tools") or []:
                            if not isinstance(tool, dict) or not tool.get("name"):
                                continue
                            tool_defs.append({"type": "function", "function": {
                                "name": _canonical_tool(str(tool["name"])),
                                "description": tool.get("description", ""),
                                "parameters": tool.get("input_schema") or {"type": "object"}}})
                    if tool_defs:
                        forwarded["tools"] = tool_defs
                    tools_sent.append(bool(tool_defs))
                    dropped_format = _without_grammar_conflict(forwarded)
                    forwarded["stream"] = False
                    forwarded["options"] = dict(body.get("options") or {})
                    message_id = f"msg_{uuid.uuid4().hex}"
                    reply_model = str(incoming.get("model") or model)
                    if streaming:
                        # Headers and message_start before the backend is even
                        # called: the first-byte window is satisfied at once and
                        # every later ping lands on a stream the CLI accepted.
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Cache-Control", "no-cache")
                        self.end_headers()
                        headers_sent = True
                        self._event("message_start", {"type": "message_start", "message": {
                            "id": message_id, "type": "message", "role": "assistant",
                            "model": reply_model, "content": [], "stop_reason": None,
                            "stop_sequence": None,
                            "usage": {"input_tokens": 0, "output_tokens": 0}}})
                        self._event("ping", {"type": "ping"})
                    # The callback belongs to the selected engine transport. Ollama
                    # honors its URL argument; llama.cpp and Colibri own their endpoint.
                    answer = self._await_backend(forwarded, streaming)
                    if answer is None:
                        waited = round(time.monotonic() - started, 1)
                        note = (f"upstream request aborted: Claude Code disconnected after "
                                f"{waited}s while the backend was still generating")
                        upstream_aborts.append(note)
                        with wire.open("a", encoding="utf-8") as stream:
                            stream.write(json.dumps({"request": incoming,
                                "backend_request": forwarded, "error": note,
                                "upstream_aborted": True}) + "\n")
                        self.close_connection = True
                        return
                    answers.append({"request": incoming, "backend_request": forwarded,
                                    "response": answer})
                    if dropped_format is not None:
                        answers[-1]["format_dropped_for_tools"] = dropped_format
                    message = answer.get("message") or {}
                    content = _to_anthropic_content(message)
                    calls = message.get("tool_calls") or []
                    reason = answer.get("done_reason")
                    backend_done_reasons.append(reason)
                    if reason not in ("stop", "length") or (reason == "length" and not calls):
                        backend_halts.append(f"backend done_reason {reason!r}")
                    stop_reason = ("max_tokens" if reason == "length" else
                                   "tool_use" if calls else "end_turn")
                    reply = {"id": message_id, "type": "message",
                             "role": "assistant", "model": reply_model,
                             "content": content, "stop_reason": stop_reason,
                             "stop_sequence": None,
                             "usage": {"input_tokens": answer.get("prompt_eval_count") or 0,
                                       "output_tokens": answer.get("eval_count") or 0}}
                    answers[-1]["cli_response"] = reply
                    with wire.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(answers[-1]) + "\n")
                    if streaming:
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
                        # message_start went out before the prompt was evaluated,
                        # so the input count rides on the final delta.
                        self._event("message_delta", {"type": "message_delta", "delta": {
                            "stop_reason": stop_reason, "stop_sequence": None},
                            "usage": {"input_tokens": reply["usage"]["input_tokens"],
                                      "output_tokens": reply["usage"]["output_tokens"]}})
                        self._event("message_stop", {"type": "message_stop"})
                    else:
                        self._json(reply)
                except Exception as exc:
                    error = _exception_detail(exc)
                    if answers and answers[-1].get("request") is requests[-1] and \
                            isinstance(exc, OSError):
                        # The backend answered and only the write back to the
                        # CLI failed: the CLI is gone and the answer is in the
                        # wire log. Not a backend error.
                        return
                    backend_errors.append(error)
                    with wire.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"request": requests[-1] if requests else None,
                            "backend_request": forwarded if "forwarded" in locals() else None,
                            "error": error}) + "\n")
                    payload = {"type": "error", "error": {"type": "api_error", "message": error}}
                    try:
                        if headers_sent:
                            self._event("error", payload)
                        else:
                            self._json(payload, 502)
                    except OSError:
                        pass

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
                    # The backend may legitimately need up to 8000s for a
                    # 16000-token answer. Claude's 600s default cancels it
                    # first and retries the same expensive request.
                    "API_TIMEOUT_MS": str(self.timeout * 1000),
                    # #3706 cause 3: the stream watchdogs are separate from
                    # API_TIMEOUT_MS. The gateway sends headers at once and a
                    # ping every _KEEPALIVE_SECONDS; these let a silent model
                    # run as long as the harness's own per-case deadline (the
                    # byte watchdog is clamped to 30 min by the CLI, and the
                    # pings keep it fed).
                    "CLAUDE_STREAM_IDLE_TIMEOUT_MS": str(self.timeout * 1000),
                    "CLAUDE_BYTE_STREAM_IDLE_TIMEOUT_MS": str(self.timeout * 1000),
                    "CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS": str(self.timeout * 1000),
                    "CLAUDE_CODE_MAX_RETRIES": "0",
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
        # Where the case's error came from (#3706 cause 0): `backend` for an
        # HTTP or transport failure between gateway and engine, `cli` for Claude
        # Code itself. A capability refusal is told apart by _error_kind().
        error_source = "cli"
        halted = False
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
                        error, error_source = backend_errors[0], "backend"
                        os.killpg(proc.pid, signal.SIGTERM)
                        break
                    if backend_halts:
                        # The model stopped for a reason of its own that the
                        # CLI cannot continue from. A model outcome, not an
                        # error: the case ends on that done_reason.
                        halted = True
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
                if error is None and backend_halts and not backend_errors:
                    # The CLI can exit on its own (the refused resume) before
                    # the poll above sees the halt; the halt is still the cause.
                    halted = True
                if error is None and not halted and proc.returncode:
                    stderr_text = (root / "stderr.txt").read_text(encoding="utf-8",
                                                                   errors="replace")
                    detail = stderr_text.strip().splitlines()
                    error = f"Claude Code exited {proc.returncode}"
                    if detail:
                        error += f": {detail[-1][-500:]}"
        except OSError as exc:
            error = _exception_detail(exc)
        finally:
            # Whatever ended the CLI, no backend generation outlives it.
            with in_flight_lock:
                pending = list(in_flight)
            for call in pending:
                call.abort()
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
        if halted and answers:
            # The CLI was stopped on the model's own stop, so its result event
            # (if any) is not the answer; the halting generation's text is,
            # as the direct transport would return it.
            final = str((answers[-1]["response"].get("message") or {}).get("content") or "")
        if result_event.get("subtype") == "error_max_turns" and not backend_errors and \
                error and error.startswith("Claude Code exited"):
            error = f"agent turn cap reached ({self.steps} turns) without a final answer"
            error_source = "model"
        if backend_errors:
            # A backend failure is the cause even when the CLI's reaction to
            # it (an error result, a non-zero exit, no model request on
            # record) was seen first.
            error, error_source = backend_errors[0], "backend"
        if not error and not halted and not result_event:
            error = "Claude Code emitted no final result event"
        if not error and not halted and result_event.get("is_error"):
            error = str(final or result_event.get("subtype") or "Claude Code result error")
            if result_event.get("subtype") == "error_max_turns":
                error = f"agent turn cap reached ({self.steps} turns) without a final answer"
                error_source = "model"
        if not error and not answers:
            error = "Claude Code made no benchmark model request"
        # #3706 cause 0: the backend's own reason is the answer's done_reason.
        # `length` and any other model-side stop are real non-stops and stay
        # what the engine said; only a failure to get an answer at all is
        # `error`, and error_kind says whose failure it was.
        backend_reason = backend_done_reasons[-1] if backend_done_reasons else None
        error_kind = _error_kind(error, error_source)
        done_reason = "error" if error else (backend_reason or "stop")
        if error:
            (root / "error.txt").write_text(error + "\n", encoding="utf-8")
        run_root = self.artifact_root.parent.parent
        paths = sorted(str(path.relative_to(run_root)) for path in root.rglob("*") if path.is_file())
        with (self.artifact_root / "cli-index.jsonl").open("a", encoding="utf-8") as index:
            index.write(json.dumps({"slot": self.slot, "case": self.case, "round": self.round,
                                    "artifacts": str(root), "error": error}) + "\n")
        conversation = _cli_conversation(events)
        return {"message": {"role": "assistant", "content": str(final)},
                "done_reason": done_reason, "error": error,
                "error_kind": error_kind,
                "backend_done_reason": backend_reason,
                "backend_tools_sent": tools_sent,
                "upstream_aborted": upstream_aborts,
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

