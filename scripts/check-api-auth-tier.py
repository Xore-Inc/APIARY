#!/usr/bin/env python3
"""Fail when a running backend-service does not enforce the auth tier its
OpenAPI contract claims (#3325).

The contract publishes a `security` block on every operation outside the
service-token tier, and openapi.rs's own test asserts the public set is
exactly /healthz and /metrics. That proves the *document* is internally
consistent -- it says nothing about whether the middleware agrees. This
asks the running service, over HTTP, with no token at all: every secured
operation must answer 401/403, and every public operation must not.

That second half is the reason this exists as a script and not as a
schemathesis check. `ignored_auth` skips any operation the contract
declares public, so marking a live /api/v1 route public makes the check
silently pass while the route keeps serving unauthenticated callers --
verified on this very service, where demoting /api/v1/events produced a
green run and one warning. A gate that can be switched off by editing the
document it is supposed to police is not a gate. Deriving the expected
answer from the document but never trusting it about *which* operations
are secured is the whole design: a leak shows up as a 200 here, and a
route wrongly demoted in the document trips openapi.rs's test instead.

Stdlib only, matching the other checkers in this directory.

Usage:
    python scripts/check-api-auth-tier.py --base-url http://127.0.0.1:8081
    python scripts/check-api-auth-tier.py --base-url ... \\
        --contract arcane/home/honeypot-dashboard/backend-service/openapi.json

Exits non-zero on any mismatch, naming the operation and the status it
answered instead.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "arcane/home/honeypot-dashboard/backend-service/openapi.json"
TIMEOUT = 15
WORKERS = 8


def parameters_of(item: dict, operation: dict) -> list[dict]:
    """Every parameter that applies to one operation.

    OpenAPI allows `parameters` on the Path Item as well as on the
    Operation, and an operation's own entry wins where a name repeats.
    This document puts them all on the operation, but reading only the
    path item is a silent no-op: every path parameter would go out as a
    literal `{id}`, which the router does not match, and the probe would
    report a 404 as an auth failure.
    """
    merged: dict[tuple[str, str], dict] = {}
    for source in (item.get("parameters") or [], operation.get("parameters") or []):
        if isinstance(source, dict):  # a $ref is not resolvable offline
            continue
        for parameter in source:
            if isinstance(parameter, dict) and "name" in parameter:
                merged[(parameter.get("in", ""), parameter["name"])] = parameter
    return list(merged.values())


def sample_path(path: str, parameters: list[dict]) -> str:
    """Fill every `{param}` in a path template with something the router
    will match.

    The value is irrelevant to the verdict -- require_service_token is a
    Router-wide layer, so it answers before the handler, before extractors,
    and even for a path that matches no route at all (verified: an unknown
    /api/v1 path is 401, not 404). It is built from the parameter's own
    declared schema anyway so this script keeps working if the middleware
    is ever moved inward to a per-route layer, where a bad substitution
    would answer 404 and read as a leak.
    """
    for parameter in parameters:
        name = parameter.get("name")
        if not name or parameter.get("in") != "path" or name not in path:
            continue
        schema = parameter.get("schema") or {}
        if "enum" in schema and schema["enum"]:
            value = str(schema["enum"][0])
        elif schema.get("type") in ("integer", "number"):
            value = "1"
        else:
            value = "check-api-auth-tier"
        path = path.replace("{" + name + "}", value)
    return path


def request(base_url: str, method: str, path: str, headers: dict[str, str]):
    """(status, body) for one call. A connection error is a status of 0:
    the service not being up is a failure of the run, not a pass."""
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(url, method=method)
    for name, value in headers.items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.status, response.read(2048)
    except urllib.error.HTTPError as error:
        return error.code, error.read(2048)
    except urllib.error.URLError as error:
        return 0, str(error.reason).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="a running backend-service")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()

    contract = json.loads(args.contract.read_text())
    secured: list = []
    public: list = []
    skipped: list = []
    for path, item in contract.get("paths", {}).items():
        for method, operation in item.items():
            if method in ("parameters", "summary", "description"):
                continue
            # Every required header the contract declares, so the probe
            # measures the *token* tier and nothing else. The Workbench's
            # six actor-gated routes answer their own JSON 401 when
            # X-Actor-Username is absent, which is indistinguishable from
            # the middleware refusing a valid caller -- so without this,
            # a service with auth wide open still passes on exactly the
            # routes an operator would most want checked. Only required
            # headers: an optional one (If-Match) is the caller's choice,
            # and sending it would move the probe onto a different status.
            headers = {
                parameter["name"]: "check-api-auth-tier"
                for parameter in parameters_of(item, operation)
                if parameter.get("in") == "header" and parameter.get("required")
            }
            if operation.get("x-endless-stream"):
                # /api/v1/live is a text/event-stream that never ends. On a
                # service enforcing auth it answers 401 before a byte is
                # written, but on the very service this script exists to
                # catch -- one serving unauthenticated callers -- it answers
                # 200 and then holds the socket open forever, so probing it
                # would hang the run instead of reporting the leak. The
                # contract marks it for exactly this; the fuzz job excludes
                # it for the same reason.
                skipped.append((method.upper(), path))
                continue
            (secured if operation.get("security") else public).append(
                (
                    method.upper(),
                    sample_path(path, parameters_of(item, operation)),
                    path,
                    headers,
                )
            )

    if not secured:
        print(f"{args.contract} declares no secured operations -- refusing to pass", file=sys.stderr)
        return 1
    print(f"{len(secured)} secured, {len(public)} public, per {args.contract.name}")
    for _, path in skipped:
        print(f"skipping {path}: marked x-endless-stream (the body never ends)")

    def probe(entry):
        method, concrete, template, headers = entry
        return entry, request(args.base_url, method, concrete, headers)

    failures = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for (_, _, template, _), (status, body) in pool.map(probe, secured):
            if status not in (401, 403):
                failures.append(
                    f"  {template}\n      served an unauthenticated request: "
                    f"HTTP {status} {body[:120]!r}"
                )

        # The other direction. A route the contract calls public that
        # answers 401 is not an auth leak, but it means the document and
        # the service disagree about who may call what, which is the same
        # defect one tier over -- and a public route is the one an
        # operator is most likely to hardcode into a health probe.
        for (_, _, template, _), (status, body) in pool.map(probe, public):
            if status in (401, 403):
                failures.append(
                    f"  {template}\n      is published as public but answered "
                    f"HTTP {status} {body[:120]!r}"
                )

    if failures:
        unreachable = sum(1 for failure in failures if "HTTP 0 " in failure)
        if unreachable == len(failures):
            print(
                f"\n{unreachable} probes could not reach {args.base_url} at all "
                "(connection refused or timed out)."
            )
            print("That is the service being down, not an auth finding -- the run")
            print("never tested anything. Start backend-service and try again.")
            return 1
        print("\nauth tier does not match the contract:")
        print("\n".join(failures))
        return 1
    print(
        f"every secured operation refused the unauthenticated request, and all "
        f"{len(public)} public operations answered without a token"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
