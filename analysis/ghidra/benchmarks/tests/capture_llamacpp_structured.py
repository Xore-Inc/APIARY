"""Capture REAL llama.cpp request/response pairs for the three failing slots.

Not a test. It starts a live llama-server through the same Remote/LlamaCppServer
serving.py uses, replays the three wire shapes the harness actually sends
(sessions json-schema, coder tools, revdeck prose) plus the failing shapes the
issue names, and writes every raw request and raw response to
tests/fixtures/llamacpp_structured_capture.json.

Run:  python3 tests/capture_llamacpp_structured.py
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _load(path: Path, name: str):
    """evaluate-models.py is hyphenated; the tests load it under a plain name."""
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
serving = _load(BENCHMARKS_DIR / "serving.py", "serving")

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "llamacpp_structured_capture.json"


def post(url: str, body: dict, timeout: int = 900) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def probe(label: str, api_root: str, harness_body: dict) -> dict:
    """One harness-shaped request through to_wire -> socket -> from_wire."""
    wire = serving.to_wire(harness_body)
    url = f"{api_root}/v1/chat/completions"
    captured = {"label": label, "harness_body": harness_body, "wire_request": wire}
    try:
        raw = post(url, wire)
        captured["raw_response"] = raw
        captured["translated"] = serving.from_wire(raw)
        captured["error"] = None
    except urllib.error.HTTPError as exc:
        captured["raw_response"] = None
        captured["translated"] = None
        captured["http_status"] = exc.code
        captured["error"] = json.loads(exc.read().decode(errors="replace"))
    except Exception as exc:  # noqa: BLE001
        captured["raw_response"] = None
        captured["translated"] = None
        captured["error"] = f"{type(exc).__name__}: {exc}"
    print(f"  [{label}] error={captured['error']}", flush=True)
    return captured


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="qwen3.5:4b")
    parser.add_argument("--base-url", default="http://127.0.0.1:11435")
    parser.add_argument("--context", type=int, default=8192)
    parser.add_argument("--reuse-port", type=int, default=0,
                        help="probe an already-running server instead of loading one")
    args = parser.parse_args()

    em = _load(BENCHMARKS_DIR / "evaluate-models.py", "evaluate_models")

    num_ctx = em.num_ctx_for(args.context)
    if args.reuse_port:
        # The load is ~10 minutes; iterating on the probe set against a server
        # that is already up costs seconds. The container and tunnel are left
        # alone -- teardown belongs to whoever started it.
        session = None
        api_root = f"http://127.0.0.1:{args.reuse_port}"
        print(f"reusing llama-server at {api_root}", flush=True)
    else:
        session = serving.ModelSession(
            args.model, args.base_url,
            num_ctx=num_ctx,
            request_json=em.request_json,
            request_timeout=em.request_timeout,
        )
        print(f"opening {args.model} on llama.cpp (num_ctx={num_ctx})", flush=True)
        session.open()
        if session.engine != "llama.cpp":
            print(f"NOT on llama.cpp: {session.fallback_reason}", flush=True)
            raise SystemExit(1)
        api_root = session.server.api_root

    schema = em.session_schema()
    coder_tools = list(__import__("bench_tools").FILE_TOOLS)
    opts = {"temperature": 0, "num_ctx": num_ctx, "num_predict": 512, "seed": 144}

    def harness(messages, *, fmt=None, tools=None, num_predict=512, sampling=None):
        body = {
            "model": args.model,
            "messages": messages,
            "stream": False,
            "think": False,
            "keep_alive": "10m",
            "options": {**opts, "num_predict": num_predict, **(sampling or {})},
        }
        if fmt is not None:
            body["format"] = fmt
        if tools:
            body["tools"] = tools
        return body

    msgs2 = lambda s, u: [{"role": "system", "content": s}, {"role": "user", "content": u}]

    probes = [
        # -- sessions: the schema-shaped format that 400s today.
        ("sessions-schema-asis", harness(msgs2(em.SESSION_SYSTEM, "Analyze this session. "
                                              "Return JSON matching the schema."), fmt=schema)),
        ("sessions-schema-json_object", harness(msgs2(em.SESSION_SYSTEM, "Analyze this session. "
                                                    "Return JSON matching the schema."),
                                               fmt={"type": "json_object"})),
        ("sessions-json-string", harness(msgs2(em.SESSION_SYSTEM, "Return {\"intent\": string}."),
                                         fmt="json")),
        # -- ghidra, the one that already works: the control.
        ("ghidra-json-object", harness(msgs2(em.TRIAGE_SYSTEM, "Return JSON {\"risk\": string}."),
                                       fmt="json")),
        # -- coder: tools on the wire.
        ("coder-tools", harness(msgs2(em.CODER_TOOL_SYSTEM,
                                       "Write a Rust program to main.rs with write_file."),
                                tools=coder_tools)),
        ("coder-first-case-tools", harness(msgs2(
            em.CODER_TOOL_SYSTEM, em.CODER_CASES[0].prompt), tools=coder_tools,
            num_predict=em.budget_for("coder"))),
        # -- coder: a raw PEG grammar, which has no OpenAI equivalent.
        ("coder-peg-grammar", harness(msgs2(em.CODER_TOOL_SYSTEM, "Write main.rs."),
                                      fmt={"type": "object",
                                            "properties": {"path": {"type": "string"}},
                                            "required": ["path"]})),
        # -- revdeck: plain prose, no format at all.
        ("revdeck-prose", harness(msgs2(em.REV_SYSTEM,
                                        "Analyse the following x86 function and explain it."),
                                 num_predict=1024)),
        ("revdeck-process-injection-default", harness(msgs2(
            em.REV_SYSTEM,
            next(case.prompt for case in em.REV_CASES
                 if case.name == "process-injection")),
            num_predict=em.budget_for("revdeck"))),
        ("revdeck-process-injection-repeat-penalty", harness(msgs2(
            em.REV_SYSTEM,
            next(case.prompt for case in em.REV_CASES
                 if case.name == "process-injection")),
            num_predict=em.budget_for("revdeck"),
            sampling=em.REVDECK_SAMPLING)),
    ]

    captures = []
    try:
        for label, body in probes:
            print(f"probing {label}", flush=True)
            captures.append(probe(label, api_root, body))
            FIXTURE.parent.mkdir(parents=True, exist_ok=True)
            FIXTURE.write_text(json.dumps({
                "captured_against": {
                    "model": args.model,
                    "image": serving.LLAMA_IMAGE,
                    "binary": serving.LLAMA_BINARY,
                    "num_ctx": num_ctx,
                    "flags": serving.server_flags(num_ctx),
                    "gguf": session.provenance().get("gguf") if session else None,
                },
                "captures": captures,
            }, indent=2))
    finally:
        if session is not None:
            print("provenance:", json.dumps(session.provenance(), indent=2)[:1500], flush=True)
            session.close()
    print(f"wrote {FIXTURE}", flush=True)


if __name__ == "__main__":
    main()
