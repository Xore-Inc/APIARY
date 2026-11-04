#!/usr/bin/env python3
"""Fail CI when a stack's compose.yml interpolates a variable its own
.env.example never documents (#1982).

.env.example is what a deployer copies when standing a stack up manually,
and what Arcane's project.env gets validated against -- it is where an
interpolated knob must be discoverable at setup time, not discovered at
first boot through a service refusing to start (ZEEK_PROXY_IFACE) or a
token platform quietly pointing at the placeholder domain
(CANARY_PUBLIC_HOSTNAME). Seven such undocumented variables shipped across
three stacks by 2026-08-26, purely by drift: honeypot-dashboard documents
60+ knobs meticulously while its newer siblings grew interpolated variables
faster than anyone revisited their (much older) example files. This check
is the mechanical version of the cross-stack contract review that found
them, so re-growing the gap fails CI naming exactly which stack forgot
which knob.

Two rules per arcane/home/<stack>/:

1. Every `${VAR[:...]}` interpolated by compose.yml must appear as a
   `KEY=` line in that stack's `.env.example`. Per-stack, not
   "documented somewhere else": each stack's file is copied on ITS OWN
   during manual stand-up, so a pointer to a sibling's docs defeats the
   purpose (that pointer is what dashboard-backend had for three of its
   four tiers' knobs).
2. Within any single `environment:` block, a key may not be listed twice.
   The original finding was two identical lines for
   ZEEK_PROXY_ATTRIBUTION_INTERVAL_SECONDS -- harmless until someone tunes
   line one and silently changes nothing.

Deliberately comment-aware: prose like "sh's ${VAR:-default} treats empty
as..." legitimately lives in compose comments, and stripping those lines
keeps documentation examples from being misread as interpolation (that
exact false positive exists in honeypot-utilities' compose). Shell-local
forms are skipped too: `$${VAR}` inside entrypoint scripts is container
sh, not compose interpolation.

Usage: python scripts/check-compose-env-docs.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOME = ROOT / "arcane" / "home"

# Any `${NAME` prefix -- deliberately terminator-agnostic so nested forms
# (${OUTER:-${INNER:-x}}, a real pattern here: BISTREAMS_RETENTION_DAYS'
# fallback chain) and end-of-line bare `${NAME}` are both counted, but NOT
# `$${NAME}` (an escaped shell-runtime reference in a run/entrypoint script).
INTERP = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)")
KEY_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")
ENV_ITEM = re.compile(r"^\s*-\s+([A-Za-z_][A-Za-z0-9_]*)=")


def interpolated_vars(compose_text: str) -> set[str]:
    """Every compose-interpolated name, ignoring commented-out lines."""
    found = set()
    for line in compose_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        found.update(INTERP.findall(line))
    return found


def documented_keys(env_example_path: Path) -> set[str]:
    found: set[str] = set()
    if not env_example_path.is_file():
        return found
    for line in env_example_path.read_text().splitlines():
        match = KEY_LINE.match(line.strip())
        if match:
            found.add(match.group(1))
    return found


def duplicated_environment_keys(compose_text: str) -> list[str]:
    """Keys listed twice inside ONE contiguous `environment:` block.

    Deliberately indentation-based rather than YAML-parsed: stdlib only,
    and the repo's compose files use one uniform style (environment: under
    a service, dash-list items nested one level deeper; any line dedenting
    back out ends the block).
    """
    duplicates: list[str] = []
    env_indent: int | None = None
    seen_in_block: dict[str, int] = {}

    for line in compose_text.splitlines() + [""]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^(\s*)environment:\s*$", line)
        if match:
            env_indent = len(match.group(1))
            seen_in_block = {}
            continue
        if env_indent is not None:
            item = ENV_ITEM.match(line)
            if item:
                name = item.group(1)
                seen_in_block[name] = seen_in_block.get(name, 0) + 1
                if seen_in_block[name] == 2:
                    duplicates.append(name)
            elif not line.startswith(" ") or len(line) - len(line.lstrip()) <= env_indent:
                env_indent = None
                seen_in_block = {}
    return duplicates


def main() -> int:
    failures: list[str] = []

    for stack in sorted(HOME.iterdir()):
        compose = stack / "compose.yml"
        if not stack.is_dir() or not compose.is_file():
            continue
        rel_compose = compose.relative_to(ROOT)
        compose_text = compose.read_text(errors="replace")

        env_example = stack / ".env.example"
        documented = documented_keys(env_example)

        missing = sorted(interpolated_vars(compose_text) - documented)
        if missing:
            label = str(rel_compose) if env_example.is_file() else f"{rel_compose} (no .env.example at all)"
            failures.append(f"{label}: interpolated but undocumented in {env_example.name}: {', '.join(missing)}")

        for name in duplicated_environment_keys(compose_text):
            failures.append(f"{rel_compose}: '{name}' is set more than once in a single environment: block")

    if failures:
        print(f"{len(failures)} compose/env.example drift failure(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("compose.yml <-> .env.example contract holds across all stacks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
