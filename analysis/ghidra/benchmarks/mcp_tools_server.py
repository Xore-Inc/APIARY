"""Claude Code MCP stdio server for the benchmark's sandboxed file tools."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import bench_tools


TOOLS = [
    {"name": "write_file", "description": "Write a file inside this benchmark case workspace.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"}, "content": {"type": "string"}},
         "required": ["path", "content"], "additionalProperties": False}},
    {"name": "read_file", "description": "Read a text file inside this benchmark case workspace.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
         "required": ["path"], "additionalProperties": False}},
    {"name": "list_files", "description": "List files inside this benchmark case workspace.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string", "default": ""}}, "additionalProperties": False}},
]


def _reply(request_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}) + "\n")
    sys.stdout.flush()


def main() -> int:
    root = os.environ.get("APIARY_WORKSPACE")
    if not root:
        raise RuntimeError("APIARY_WORKSPACE is required")
    bench_tools.set_file_root(Path(root))
    for line in sys.stdin:
        try:
            request = json.loads(line)
            method = request.get("method")
            request_id = request.get("id")
            if method == "notifications/initialized":
                continue
            if method == "initialize":
                params = request.get("params") or {}
                _reply(request_id, {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "apiary-benchmark", "version": "1.0.0"}})
            elif method == "ping":
                _reply(request_id, {})
            elif method == "tools/list":
                _reply(request_id, {"tools": TOOLS})
            elif method == "tools/call":
                params = request.get("params") or {}
                args = params.get("arguments") or {}
                name = params.get("name")
                function = {"write_file": bench_tools.write_file,
                            "read_file": bench_tools.read_file,
                            "list_files": bench_tools.list_files}.get(name)
                if function is None:
                    result, is_error = f"unknown tool: {name}", True
                else:
                    result = function(**args)
                    is_error = isinstance(result, str) and result.startswith("refused:")
                _reply(request_id, {"content": [{"type": "text", "text": str(result)}],
                       "isError": is_error})
            elif request_id is not None:
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32601, "message": f"unsupported method: {method}"}}) + "\n")
                sys.stdout.flush()
        except Exception as exc:  # errors are returned to Claude as tool errors
            sys.stderr.write(f"MCP request failed: {type(exc).__name__}: {exc}\n")
            request_id = locals().get("request", {}).get("id")
            if request_id is not None:
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32603, "message": str(exc)}}) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
