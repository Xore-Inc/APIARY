#!/usr/bin/env python3
"""arkime-init's composable-templates.js against Elasticsearch's real shapes.

- GET /_index_template returns system-managed fields (created_date_millis,
  modified_date_millis) that Elasticsearch refuses on PUT. Stashing the body
  verbatim made every restore fail with HTTP 400 (#3549).
- _simulate_index returns settings nested (index.lifecycle.name as
  {"lifecycle": {"name": ...}}). Reading the flat key failed the retention
  self-check although the policy applied (#3551).

Runs the real script's `shadow` and `generate` passes against a fake
Elasticsearch that behaves the same way.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "arcane" / "home" / "honeypot-init" / "arkime" / "composable-templates.js"
SYSTEM_FIELDS = {"created_date", "created_date_millis", "modified_date", "modified_date_millis"}
CATCH_ALL = {
    "index_patterns": ["*"],
    "priority": 1,
    "template": {"settings": {"index.number_of_replicas": 0}},
}


LEGACY_SESSIONS = {
    "index_patterns": ["arkime_sessions3-*"],
    "order": 99,
    "settings": {"index": {"number_of_shards": 1}},
    "mappings": {"properties": {"source": {"properties": {"ip": {"type": "ip"}}}}},
}


def nested(flat: dict) -> dict:
    """index.lifecycle.name -> {"lifecycle": {"name": ...}}, as the API returns it."""
    out: dict = {}
    for key, value in flat.items():
        node = out
        parts = key.removeprefix("index.").split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


def flat_settings(settings: dict, prefix: str = "") -> dict:
    out = {}
    for key, value in settings.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out |= flat_settings(value, f"{name}.")
        else:
            out[name if name.startswith("index.") else f"index.{name}"] = value
    return out


class FakeElasticsearch(BaseHTTPRequestHandler):
    templates: dict[str, dict] = {}
    legacy: dict[str, dict] = {}

    def log_message(self, *_args) -> None:
        pass

    def reply(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/_index_template":
            listed = [
                {"name": name, "index_template": body | {"created_date_millis": 1, "modified_date_millis": 2}}
                for name, body in self.templates.items()
            ]
            return self.reply(200, {"index_templates": listed})
        if self.path.startswith("/_template/"):
            name = self.path.rsplit("/", 1)[1]
            if name in self.legacy:
                return self.reply(200, {name: self.legacy[name]})
        if self.path.startswith("/_cat/indices/"):
            return self.reply(200, [])
        self.reply(404, {})

    def do_PUT(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        if self.path.startswith("/_index_template/"):
            managed = SYSTEM_FIELDS & body.keys()
            if managed:
                return self.reply(400, {"error": f"managed by the system: {sorted(managed)[0]}"})
            self.templates[self.path.rsplit("/", 1)[1]] = body
        self.reply(200, {"acknowledged": True})

    def do_DELETE(self) -> None:
        self.templates.pop(self.path.rsplit("/", 1)[1], None)
        self.reply(200, {"acknowledged": True})

    def do_POST(self) -> None:
        if self.path.startswith("/_index_template/_simulate_index/"):
            index = self.path.rsplit("/", 1)[1]
            matching = [
                t for t in self.templates.values()
                if any(index.startswith(p.rstrip("*")) for p in t.get("index_patterns", []))
            ]
            winner = max(matching, key=lambda t: t.get("priority", 0))
            settings = nested(flat_settings(winner.get("template", {}).get("settings", {})))
            return self.reply(200, {"template": {"settings": {"index": settings}}})
        self.reply(404, {})


@unittest.skipUnless(shutil.which("node"), "node is required")
class ArkimeComposableRestoreTest(unittest.TestCase):
    def run_passes(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeElasticsearch)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                env = os.environ | {
                    "ARKIME__elasticsearch": f"http://127.0.0.1:{server.server_port}",
                    "SHADOW_FILE": str(Path(temp) / "shadow" / "shadow.json"),
                }
                for mode in ("shadow", "generate"):
                    proc = subprocess.run(
                        ["node", str(SCRIPT), mode], env=env, capture_output=True, text=True, timeout=60
                    )
                    self.assertEqual(proc.returncode, 0, f"{mode}: {proc.stdout}\n{proc.stderr}")
        finally:
            server.shutdown()

    def test_shadowed_catch_all_is_put_back_without_system_fields(self) -> None:
        FakeElasticsearch.templates = {"single-node-replica-default": dict(CATCH_ALL)}
        FakeElasticsearch.legacy = {}
        self.run_passes()
        self.assertEqual(FakeElasticsearch.templates.get("single-node-replica-default"), CATCH_ALL)

    def test_generated_sessions_template_passes_its_retention_check(self) -> None:
        FakeElasticsearch.templates = {"single-node-replica-default": dict(CATCH_ALL)}
        FakeElasticsearch.legacy = {"arkime_sessions3_template": LEGACY_SESSIONS}
        self.run_passes()
        generated = FakeElasticsearch.templates["arkime-sessions3"]
        settings = flat_settings(generated["template"]["settings"])
        self.assertEqual(settings.get("index.lifecycle.name"), "arkime-sessions-30d")
        self.assertEqual(FakeElasticsearch.templates.get("single-node-replica-default"), CATCH_ALL)


if __name__ == "__main__":
    unittest.main()
