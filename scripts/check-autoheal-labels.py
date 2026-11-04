#!/usr/bin/env python3
"""Fail CI when a service has a healthcheck (compose-level OR baked into its
image's Dockerfile) but no `autoheal=true` label and no documented opt-out.

#119 asked for this guard when it first fixed the healthcheck/autoheal
pairing across the fleet; the gap came back anyway (#2051: keycloak,
postgres, galah-llm-broker, oidc-sessions), and a first sweep for the guard
missed a second blind spot on top of that (#2051's own follow-up comment):
services whose healthcheck is an image-level Dockerfile `HEALTHCHECK`
instruction are invisible to a plain `grep healthcheck: compose.yml` sweep.
This scans both layers, which is the whole point -- a compose-only matcher
reproduces the exact blind spot that let http-honeypot/api-honeypot/
multipot/dicompot hide.

A service opts out of the label by carrying a comment containing the word
"autoheal" anywhere in its own block in the compose file -- e.g. explaining
why a wedge there should not trigger a restart. That comment is the
documentation the issue asked for; this script does not judge its content,
only that one exists.

Scope: every `compose.yml`/`docker-compose.yml` this repo actually deploys
from -- `arcane/home/*/compose.yml` plus the handful of root-level and
sandbox operational composes, and now `vps/docker-compose.yml` too (#2762:
the VPS runs its own docker-socket-proxy + autoheal pair as of that issue,
the same narrow-proxy shape as honeypot-utilities' instance on the
homeserver, so the pairing gap this guard exists to catch now applies there
the same way). Excluded: anything under a vendored tree (upstream-verbatim
per VENDORED.md, not this repo's own service definition) and the honeyfs
decoy filesystem prop under honeypot-cowrie (a fake file served *to*
attackers, not a real compose stack).

Usage: python3 scripts/check-autoheal-labels.py
"""
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

EXCLUDE_SUBSTRINGS = ("/vendor/", "/honeyfs/")
EXCLUDE_FILES = ()

HEALTHCHECK_INSTRUCTION_RE = re.compile(r"^\s*HEALTHCHECK\b", re.IGNORECASE | re.MULTILINE)
HEALTHCHECK_NONE_RE = re.compile(r"^\s*HEALTHCHECK\s+NONE\b", re.IGNORECASE | re.MULTILINE)


def tracked_compose_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    paths = []
    for line in out.splitlines():
        if not re.search(r"(^|/)(docker-)?compose\.ya?ml$", line):
            continue
        if any(s in f"/{line}" for s in EXCLUDE_SUBSTRINGS):
            continue
        if line in EXCLUDE_FILES:
            continue
        paths.append(REPO_ROOT / line)
    return paths


def dockerfile_has_healthcheck(build_dir: Path, dockerfile_name: str) -> bool:
    dockerfile = build_dir / dockerfile_name
    if not dockerfile.is_file():
        return False
    text = dockerfile.read_text()
    if HEALTHCHECK_NONE_RE.search(text):
        return False
    return bool(HEALTHCHECK_INSTRUCTION_RE.search(text))


def service_labels(service: dict) -> list[str]:
    labels = service.get("labels")
    if labels is None:
        return []
    if isinstance(labels, dict):
        return [f"{k}={v}" for k, v in labels.items()]
    return list(labels)


def service_block_text(raw_lines: list[str], service_name: str) -> str:
    # Compose services are 2-space-indented keys directly under `services:`.
    # Grab from the service's own line up to (not including) the next
    # sibling key at the same indentation, or EOF.
    pattern = re.compile(rf"^  {re.escape(service_name)}:\s*$")
    start = None
    for i, line in enumerate(raw_lines):
        if pattern.match(line):
            start = i
            break
    if start is None:
        return ""
    end = len(raw_lines)
    for i in range(start + 1, len(raw_lines)):
        if re.match(r"^  \S.*:\s*$", raw_lines[i]) or re.match(r"^\S", raw_lines[i]):
            end = i
            break
    return "\n".join(raw_lines[start:end])


def check_compose_file(path: Path) -> list[str]:
    failures: list[str] = []
    raw_lines = path.read_text().splitlines()
    try:
        doc = yaml.safe_load("\n".join(raw_lines))
    except yaml.YAMLError as exc:
        return [f"{path}: does not parse as YAML: {exc}"]
    if not doc or "services" not in doc:
        return failures

    for name, service in (doc.get("services") or {}).items():
        if not isinstance(service, dict):
            continue

        has_compose_hc = "healthcheck" in service and service["healthcheck"] != "none"

        has_dockerfile_hc = False
        build = service.get("build")
        if isinstance(build, str):
            has_dockerfile_hc = dockerfile_has_healthcheck(path.parent / build, "Dockerfile")
        elif isinstance(build, dict):
            context = build.get("context", ".")
            dockerfile_name = build.get("dockerfile", "Dockerfile")
            has_dockerfile_hc = dockerfile_has_healthcheck(path.parent / context, dockerfile_name)

        if not (has_compose_hc or has_dockerfile_hc):
            continue

        if "autoheal=true" in service_labels(service):
            continue

        block = service_block_text(raw_lines, name)
        if "autoheal" in block.lower():
            continue  # documented opt-out

        layer = "compose healthcheck:" if has_compose_hc else "image-level Dockerfile HEALTHCHECK"
        failures.append(
            f"{path.relative_to(REPO_ROOT)}: service '{name}' has a {layer} "
            f"but no autoheal=true label and no in-file comment mentioning "
            f"'autoheal' documenting why not"
        )
    return failures


def main() -> int:
    all_failures = []
    for path in tracked_compose_files():
        all_failures.extend(check_compose_file(path))

    if all_failures:
        for f in all_failures:
            print(f"FAIL: {f}")
        print(f"\n{len(all_failures)} failure(s)")
        return 1

    print("OK: every healthcheck (compose-level and image-level) is paired "
          "with autoheal=true or a documented opt-out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
