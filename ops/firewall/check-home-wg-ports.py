#!/usr/bin/env python3
"""Fail if the hub firewall would drop a declared or live WG-published port."""
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
allowlist = Path(__file__).with_name("hosts") / "homeserver-wg-ports.txt"
allowed = {tuple(line.split()) for line in allowlist.read_text().splitlines() if line and not line.startswith("#")}
required = set()

import yaml  # Already used by the repository's Compose checks.

for path in (root / "arcane/home").rglob("compose.y*ml"):
    for service in (yaml.safe_load(path.read_text()).get("services") or {}).values():
        for spec in service.get("ports", []) or []:
            if not isinstance(spec, str):
                raise ValueError(f"unsupported Compose port in {path}: {spec!r}")
            spec = re.sub(r"\$\{[^}:]+:-([^}]+)\}", r"\1", spec)
            if "${" in spec:
                raise ValueError(f"unresolved Compose port in {path}: {spec}")
            host, published, target = spec.rsplit(":", 2)
            if host in {"10.8.0.2", "0.0.0.0"}:
                required.add((target.partition("/")[2] or "tcp", published))

if len(sys.argv) > 2:
    raise SystemExit("usage: check-home-wg-ports.py [live-ports-file]")
if len(sys.argv) == 2:
    live = {tuple(line.split()) for line in Path(sys.argv[1]).read_text().splitlines()}
    # Wildcard pentagi terminal ports have no documented hub consumer (#3604).
    live -= {("tcp", "28012"), ("tcp", "28013")}
    required |= live

missing = sorted(required - allowed)
if missing:
    print("Missing WG-published ports:", *[f"{proto}/{port}" for proto, port in missing], sep="\n", file=sys.stderr)
    sys.exit(1)
print(f"WG allowlist covers {len(required)} required ports")
