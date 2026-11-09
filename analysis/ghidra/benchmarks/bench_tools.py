"""Opt-in web-search tooling for the benchmark harness.

Imported lazily by `chat()` only when a `tools` argument is passed, so a default
run never touches this module and the request body stays byte-identical to the
no-tools path. That matters: a corpus run must not silently change shape because
a capability was added.

Fetched page text DOES reach the model's answer. That is a deliberate owner
decision, and it costs reproducibility -- the same prompt against the same model
can differ between runs purely because a search index moved. Any run that uses
tools must record `tools_used`, or two runs are not comparable.

Local models served through Ollama frequently do NOT populate the structured
`tool_calls` field; they emit the call as assistant text, usually as a JSON
object. So a loop that only reads `tool_calls` silently does nothing on exactly
the roster this benchmark cares about. `extract_call` accepts both: the
structured field when present, otherwise a JSON object parsed out of the text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_SEARCH_BACKEND = None
_FETCH_BACKEND = None
_FILE_ROOT: "Path | None" = None


def set_search_backend(fn) -> None:
    """Install (query, limit) -> [{title, url, description}] for web_search."""
    global _SEARCH_BACKEND
    _SEARCH_BACKEND = fn


def set_fetch_backend(fn) -> None:
    """Install (url) -> str for web_fetch. None restores the stdlib fetcher."""
    global _FETCH_BACKEND
    _FETCH_BACKEND = fn


MAX_TOOL_ROUNDS = 3
MAX_FETCH_CHARS = 12000
MAX_TOOL_RESULT_CHARS = 4000

SEARCH_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": (
            "Search the public web. Returns titles, URLs and snippets. Use it for "
            "documentation, advisories, API references and version facts."
        ),
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "The search query."}},
            "required": ["query"],
        },
    },
}

FETCH_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_fetch",
        "description": "Fetch one http or https URL and return its readable text, truncated.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Absolute URL."}},
            "required": ["url"],
        },
    },
}

DEFAULT_TOOLS = (SEARCH_TOOL, FETCH_TOOL)

# --- sandboxed file tools (coder slot only) --------------------------------
#
# The coder corpus asks for a complete implementation. Measured, models answer
# with a text blob: 76 answers, 11 code fences in a whole run. So the coder
# slot gets a file tool and the model has to actually write its artifact.
#
# The sandbox is enforced in code, not requested politely. `resolve_path` is
# the single chokepoint every file tool goes through and it refuses, with a
# reason string the model can read and act on: absolute paths, `..` anywhere,
# anything resolving outside the case directory, and symlinks (including a
# symlinked parent component, which is the real escape).
#
# Written files are NEVER executed, and nothing written here gates or moves a
# grade; compile_check stays a diagnostic.

WRITE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "write_file",
        "description": (
            "Write a text file into this case's sandbox directory, creating or "
            "overwriting it. Paths must be relative and stay inside the case "
            "directory: absolute paths, '..' and symlinks are refused. Write your "
            "implementation here instead of pasting it into the chat answer, then "
            "read it back to check and improve it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Relative path inside the case directory, e.g. main.rs."},
                "content": {"type": "string", "description": "Full file content to write."},
            },
            "required": ["path", "content"],
        },
    },
}

READ_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": (
            "Read one file back out of this case's sandbox directory. Use it to "
            "review what you already wrote before improving it."
        ),
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Relative path inside the case directory."}},
            "required": ["path"],
        },
    },
}

LIST_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "list_files",
        "description": "List the files written in this case's sandbox directory, with their sizes.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string",
                                    "description": "Optional relative subdirectory; omit for the case root."}},
        },
    },
}

FILE_TOOLS = (WRITE_TOOL, READ_TOOL, LIST_TOOL)

MAX_FILE_READ_CHARS = 12000


def set_file_root(root: "Path | str | None") -> None:
    """Point the file tools at this case's sandbox directory.

    Injectable for the same reason the web backends are: a test (or a future
    runtime) can drive the tools without touching the filesystem layout, and a
    run with no root configured refuses every write instead of guessing one.
    """
    global _FILE_ROOT
    _FILE_ROOT = Path(root) if root is not None else None


def resolve_path(raw: str) -> tuple["Path | None", str]:
    """Map a model-supplied path to one inside the case dir, or say why not.

    Returns (path, "") on success and (None, refusal) otherwise. The refusal is
    a normal tool result the model sees and can recover from -- never an
    exception, so a path-traversal attempt cannot fail a roster run.
    """
    root = _FILE_ROOT
    if root is None:
        return None, "refused: no sandbox directory is configured for this case"
    rel = (raw or "").strip()
    if not rel:
        return None, "refused: empty path"
    if "\x00" in rel:
        return None, "refused: path contains a null byte"
    if rel.startswith("/") or Path(rel).is_absolute() or (len(rel) > 1 and rel[1] == ":"):
        return None, f"refused: absolute path not allowed: {rel!r}"
    parts = Path(rel).parts
    if any(part == ".." for part in parts):
        return None, f"refused: parent traversal not allowed: {rel!r}"
    root_resolved = root.resolve()
    target = root_resolved / Path(rel)
    # is_symlink() on the final component AND on every parent: a symlinked
    # directory turns a relative path into an arbitrary write without any '..'.
    probe = target
    while True:
        if probe.is_symlink():
            return None, f"refused: symlink target not allowed: {rel!r}"
        if probe == root_resolved or probe.parent == probe:
            break
        probe = probe.parent
    resolved = target.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        return None, f"refused: path escapes the case directory: {rel!r}"
    return resolved, ""


def write_file(path: str, content: str) -> str:
    """Write one file into the case sandbox, or refuse with a reason."""
    target, refusal = resolve_path(path)
    if target is None:
        return refusal
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {target.name} ({len(content)} chars)"


def read_file(path: str) -> str:
    target, refusal = resolve_path(path)
    if target is None:
        return refusal
    if not target.is_file():
        return f"no such file in this case directory: {path}"
    return target.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_READ_CHARS]


def list_files(path: str = "") -> str:
    if not (path or "").strip():
        root = _FILE_ROOT
        if root is None:
            return "refused: no sandbox directory is configured for this case"
        base = root.resolve()
    else:
        base, refusal = resolve_path(path)
        if base is None:
            return refusal
    if not base.is_dir():
        return f"no such directory in this case directory: {path}"
    rows = sorted(
        f"{item.relative_to(base).as_posix()}  {item.stat().st_size}"
        for item in base.rglob("*") if item.is_file() and not item.is_symlink()
    )
    return "\n".join(rows) if rows else "(no files written yet)"


# --- text file protocol -----------------------------------------------------
#
# Measured: of 8 roster models probed against the Ollama API, 1 produced a real
# tool call, 3 were rejected with "does not support tools", 3 accepted the tools
# array and then answered in prose anyway, 1 returned HTTP 500. So API tool
# calls alone leave ~88% of the roster writing nothing, and "this model cannot
# use tools" is only a benchmark finding if it is RECORDED rather than silently
# collapsed into the answer-fallback.
#
# The fallback is a literal block in the answer:
#     <file path="src/main.rs">
#     ...contents...
#     </file>
# The path goes through the SAME resolve_path chokepoint write_file uses, so a
# traversal attempt is refused identically here. Parsing is total: a malformed
# or unclosed block is counted as a parse failure, never an exception.

FILE_BLOCK_OPEN_RE = re.compile(r"<file\s+path\s*=\s*\"[^\"]*\"\s*>", re.I)
FILE_BLOCK_RE = re.compile(r"<file\s+path\s*=\s*\"([^\"]*)\"\s*>(.*?)</file\s*>", re.I | re.S)
MAX_FILE_BLOCKS = 32


def extract_file_blocks(text: str) -> list[tuple[str, str]]:
    """Pull (path, contents) pairs out of an answer's <file> blocks.

    Total by construction: an unclosed tag, a missing attribute or nested angle
    brackets simply do not match. `contents` is returned verbatim, so code that
    contains `</file>`-looking text or arbitrary `<` `>` stays intact.
    """
    return FILE_BLOCK_RE.findall(text or "")[:MAX_FILE_BLOCKS]


def write_text_blocks(text: str) -> dict[str, Any]:
    """Write every <file> block in one answer into the case sandbox.

    Returns the counts the transcript records: seen / written / refused plus the
    accepted relative paths and the refusal reasons. Refusals are returned, not
    raised, so a sandbox escape attempt in generated text is a normal recorded
    result that cannot abort a run.
    """
    blocks = extract_file_blocks(text)
    seen = len(FILE_BLOCK_OPEN_RE.findall(text or ""))
    written: list[str] = []
    refusals: list[str] = []
    for raw_path, contents in blocks:
        result = write_file(raw_path, contents)
        if result.startswith("refused:"):
            refusals.append(result)
        else:
            written.append(raw_path.strip())
    return {
        "seen": seen,
        "written": len(written),
        "refused": len(refusals),
        # An opening tag with no matching close (or a malformed attribute) is
        # seen but not written: recorded, not fatal.
        "malformed": max(seen - len(blocks), 0),
        "paths": written,
        "refusals": refusals,
    }


def search_results(query: str, limit: int = 5) -> str:
    """A real web search, returned as a compact text block.

    The search backend is injectable because the benchmark cannot assume a
    particular agent runtime: `set_search_backend(fn)` takes a callable
    (query, limit) -> list[dict] with title/url/description keys. Without one,
    the tool reports that it is unavailable rather than failing the run.
    """
    backend = _SEARCH_BACKEND
    if backend is None:
        return "web_search unavailable: no search backend configured on this host"
    try:
        rows = backend(query, limit)
    except Exception as exc:  # tooling is optional; never fail a run on it
        return f"web_search unavailable: {type(exc).__name__}: {exc}"
    if not rows:
        return "no results"
    return "\n".join(
        f"- {r.get('title', '')}\n  {r.get('url', '')}\n  {r.get('description', '')}"
        for r in rows[:limit]
    )


def fetch_text(url: str) -> str:
    from urllib.parse import urlparse
    scheme = urlparse(url).scheme
    if scheme not in ("http", "https"):
        return f"refused: only http and https are allowed, got {scheme!r}"
    backend = _FETCH_BACKEND
    if backend is None:
        return _html_to_text(urlopen_text(url))
    try:
        return backend(url)[:MAX_FETCH_CHARS]
    except Exception as exc:
        return f"web_fetch unavailable: {type(exc).__name__}: {exc}"


def urlopen_text(url: str, timeout: int = 25) -> str:
    """Fetch raw HTML with the standard library. There is no other dependency."""
    import urllib.request
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; apiary-benchmark/1.0)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


_TAG = __import__("re").compile(r"<[^>]+>")
_SCRIPT = __import__("re").compile(r"<(script|style)\b[^>]*>.*?</\1>", __import__("re").S | __import__("re").I)


def _html_to_text(raw: str) -> str:
    import re as _re
    stripped = _SCRIPT.sub(" ", raw)
    stripped = _re.sub(r"<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", stripped, flags=_re.I)
    return _re.sub(r"\n{3,}", "\n\n", _TAG.sub(" ", stripped)).strip()


def run_tool(name: str, args: dict[str, Any]) -> str:
    if name == "web_search":
        return search_results(str(args.get("query", "")))
    if name == "web_fetch":
        return fetch_text(str(args.get("url", "")))
    if name == "write_file":
        return write_file(str(args.get("path", "")), str(args.get("content", "")))
    if name == "read_file":
        return read_file(str(args.get("path", "")))
    if name == "list_files":
        return list_files(str(args.get("path", "") or ""))
    return f"unknown tool: {name}"


def call_status(tool: str, result: str) -> tuple[str, str]:
    """Classify one tool turn as accepted or rejected, with the reason.

    Recorded per round, because "the model never called the tool" and "the model
    called it and was refused" are different results and both are real.
    """
    if isinstance(result, str) and result.startswith("refused:"):
        return "rejected", result.split(":", 1)[1].strip()
    if isinstance(result, str) and result.startswith("no such"):
        return "rejected", result
    return "accepted", ""


def extract_call(message: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Pull a tool call out of a model turn, structured or textual.

    Returns (name, arguments) or None. A text-emitted call is the common case
    here, not the edge case.
    """
    calls = message.get("tool_calls")
    if calls:
        fn = (calls[0] or {}).get("function", {}) if isinstance(calls[0], dict) else {}
        name = fn.get("name")
        raw = fn.get("arguments")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = {"query": raw}
        if name:
            return str(name), raw if isinstance(raw, dict) else {}
    text = (message.get("content") or "").strip()
    if text.startswith("{"):
        try:
            value = json.loads(text)
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        name = value.get("name") or value.get("tool") or value.get("function")
        args = value.get("arguments") or value.get("parameters") or value.get("args")
        if name and not isinstance(args, dict):
            # These models frequently emit the call flat, with the arguments as
            # siblings of the name rather than nested under an `arguments` key.
            # Requiring the wrapper made a well-formed write call look like no
            # call at all, which is silently the "model ignored the tool" result.
            flat = {k: v for k, v in value.items()
                    if k not in ("name", "tool", "function")}
            if flat:
                args = flat
        if name and isinstance(args, dict):
            return str(name), args
    return None


def assistant_text(message: dict[str, Any]) -> str:
    """One assistant turn as the text that turn actually produced.

    A structured tool call has empty `content`, so serialize its `tool_calls`
    rather than erasing the turn from `response.raw`.
    """
    text = (message.get("content") or "").strip()
    if text:
        return text
    return "\n".join(json.dumps(call, sort_keys=True)
                     for call in (message.get("tool_calls") or []))


def conduct_tool_rounds(request_json, url: str, body: dict[str, Any],
                        first_response: dict[str, Any],
                        max_rounds: int | None = None) -> dict[str, Any]:
    """Drive the assistant/tool exchange and return the final model response.

    `request_json` is the harness's own transport, injected rather than
    reimplemented so timeout and cap handling stay in exactly one place.
    `body` is not mutated.
    """
    rounds = MAX_TOOL_ROUNDS if max_rounds is None else max_rounds
    transcript_turns: list[dict[str, Any]] = []
    response = first_response
    history = list(body.get("messages") or [])
    for _ in range(rounds):
        message = response.get("message") or {}
        call = extract_call(message)
        if not call:
            break
        name, args = call
        result = run_tool(name, args)
        status, reason = call_status(name, result)
        transcript_turns.append({"tool": name, "arguments": args, "status": status,
                                 "reason": reason, "result": result[:2000]})
        # Ollama needs the structured call in the assistant history. Keeping
        # only its empty content makes the following tool result an orphan and
        # can produce an empty stop response after burning real output tokens.
        history.append(message)
        history.append(tool_result_turn(name, result))
        followup = dict(body)
        followup["messages"] = history
        followup["stream"] = False
        response = request_json(url, followup)
    if transcript_turns:
        response = dict(response)
        response["tool_turns"] = transcript_turns
    return response


def tool_result_turn(name: str, result: str) -> dict[str, Any]:
    """Return Ollama's tool-result message shape."""
    return {
        "role": "tool",
        "content": result[:MAX_TOOL_RESULT_CHARS],
        "tool_name": name,
    }
