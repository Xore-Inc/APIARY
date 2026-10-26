#!/usr/bin/env python3
"""Capture a COMPLETE llama.cpp tool round-trip: every wire body, every turn.

`capture_llamacpp_structured.py` stops at the first `tool_calls`. This goes
through the exchange to the end -- tools offered, a tool call returned, the tool
result sent back, the final answer -- and writes the real wire body of every
request, so `tool_call_id` pairing and the assistant `tool_calls` message can be
read off the socket rather than inferred from to_wire().

Not a test. Run:  python3 tests/capture_llamacpp_tool_roundtrip.py
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

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "llamacpp_tool_roundtrip.json"


def post(url: str, body: dict, timeout: int = 900) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def round_trip(api_root: str, harness_body: dict) -> dict:
    """One full exchange, recording the wire body of every request."""
    url = f"{api_root}/v1/chat/completions"
    history = list(harness_body.get("messages") or [])
    turns: list[dict] = []

    body = dict(harness_body)
    wire = serving.to_wire(body)
    try:
        raw = post(url, wire)
    except urllib.error.HTTPError as exc:
        return {"turns": turns, "stopped": f"turn 1 rejected: {exc.code}",
                "error": json.loads(exc.read().decode(errors="replace"))}
    turns.append({"turn": 1, "request_wire": wire, "response_raw": raw,
                  "response_translated": serving.from_wire(raw)})
    translated = serving.from_wire(raw)
    message = translated["message"]

    # Drive the exchange with the harness's own loop, so what is recorded is
    # the code the benchmark actually runs rather than a reimplementation.
    import bench_tools

    rounds = 0
    while rounds < bench_tools.MAX_TOOL_ROUNDS:
        call = bench_tools.extract_call(message)
        if not call:
            break
        name, args = call
        result = bench_tools.run_tool(name, args)
        history.append(message)
        history.append(bench_tools.tool_result_turn(name, result))
        body = dict(harness_body)
        body["messages"] = history
        wire = serving.to_wire(body)
        try:
            raw = post(url, wire)
        except urllib.error.HTTPError as exc:
            turns.append({"turn": len(turns) + 1, "request_wire": wire,
                          "response_raw": None,
                          "error": json.loads(exc.read().decode(errors="replace"))})
            return {"turns": turns, "stopped": f"turn {len(turns)} rejected"}
        translated = serving.from_wire(raw)
        turns.append({"turn": len(turns) + 1, "request_wire": wire,
                      "response_raw": raw, "response_translated": translated,
                      "tool_executed": {"tool": name, "arguments": args,
                                        "result": result[:2000]}})
        message = translated["message"]
        rounds += 1

    # The acceptance check, on the real wire bodies rather than in prose.
    checks = {}
    if len(turns) >= 2:
        second = turns[1]["request_wire"]["messages"]
        assistants = [m for m in second if m.get("tool_calls")]
        results = [m for m in second if m.get("role") == "tool"]
        offered = [c["id"] for m in assistants for c in m["tool_calls"]]
        keyed = [m["tool_call_id"] for m in results]
        checks = {
            "assistant_carries_tool_calls": bool(assistants),
            "every_result_has_a_tool_call_id": all(k for k in keyed),
            "every_result_matches_an_offered_call": bool(keyed) and set(keyed) <= set(offered),
            "every_offered_call_was_answered": set(offered) <= set(keyed),
            "no_duplicate_ids_across_turns": len(offered) == len(set(offered)),
        }
    return {"turns": turns, "final_message": message, "checks": checks}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="baronllm-llama3.1:q6_k")
    parser.add_argument("--base-url", default="http://127.0.0.1:11435")
    parser.add_argument("--context", type=int, default=18400)
    parser.add_argument("--reuse-port", type=int, default=0)
    args = parser.parse_args()

    em = _load(BENCHMARKS_DIR / "evaluate-models.py", "evaluate_models")
    num_ctx = em.num_ctx_for(args.context)

    if args.reuse_port:
        session = None
        api_root = f"http://127.0.0.1:{args.reuse_port}"
    else:
        session = serving.ModelSession(
            args.model, args.base_url, num_ctx=num_ctx,
            request_json=em.request_json, request_timeout=em.request_timeout,
        )
        print(f"opening {args.model} on llama.cpp (num_ctx={num_ctx})", flush=True)
        session.open()
        if session.engine != "llama.cpp":
            print(f"NOT on llama.cpp: {session.fallback_reason}", flush=True)
            raise SystemExit(1)
        api_root = session.server.api_root

    import bench_tools
    body = {
        "model": args.model,
        "messages": [
            {"role": "system", "content": em.CODER_TOOL_SYSTEM},
            {"role": "user", "content": "Write a Rust program to src/main.rs that "
                                        "prints hello."},
        ],
        "stream": False,
        "think": False,
        "keep_alive": "10m",
        "options": {"temperature": 0, "num_ctx": num_ctx,
                    "num_predict": 1024, "seed": 144},
        # One tool on purpose. This model, offered FILE_TOOLS, answers with a
        # `parameters` key where the grammar wants `arguments` and then loops
        # the same call to the output cap -- measured, see the fixture's
        # `stopped`. A single tool is a shape it completes, which is what makes
        # this fixture evidence about the WIRING rather than about the model's
        # capability. The capability is a separate fact, recorded separately.
        "tools": [bench_tools.FILE_TOOLS[0]],
    }

    captured = {"model": args.model, "num_ctx": num_ctx,
                "image": serving.LLAMA_IMAGE, "binary": serving.LLAMA_BINARY}
    try:
        import tempfile
        sandbox = Path(tempfile.mkdtemp(prefix="roundtrip-coder-"))
        bench_tools.set_file_root(sandbox)
        captured.update(round_trip(api_root, body))
        bench_tools.set_file_root(None)
    finally:
        if session is not None:
            print("provenance:", json.dumps(session.provenance(), indent=2)[:1200], flush=True)
            session.close()
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(captured, indent=2))
    print(json.dumps(captured.get("checks", {}), indent=2), flush=True)
    print(f"wrote {FIXTURE}", flush=True)


if __name__ == "__main__":
    main()
