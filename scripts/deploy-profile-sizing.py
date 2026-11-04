#!/usr/bin/env python3
"""Sum the CPU/memory limits the compose files already declare, per profile.

#3328 asks for resource sizing per host role in docs/deploy-profiles/README.md.
Hand-writing that table means it is wrong the first time somebody edits a
`cpus:` or a `mem_limit:` line, so derive it from the compose files instead and
let a test compare the published table against this.

A limit is a ceiling, not a reservation, so the total is an upper bound on what
that profile can ask the host for -- not a prediction of steady-state use. A
stack with no declared limit contributes nothing and is reported separately,
because an undeclared limit is the one number that can silently exceed the
host: Docker will not stop it.

Sizing the analysis-plane workers, the dashboard/elk/keycloak backbone and the
VPS is deliberately out of scope, the same way the profile roster itself scopes
them (see the "Not covered here" note in the README).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = ROOT / "arcane" / "home"
PROFILES = ROOT / "deploy-profiles"

MEM_UNITS = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
COMPOSE = re.compile(r"(?:^|/)(?:docker-)?compose[^/]*\.ya?ml$")


def to_bytes(value: str) -> int:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGT]?)", str(value).strip(), re.I)
    if not m:
        return 0
    return int(float(m.group(1)) * MEM_UNITS.get(m.group(2).upper(), 1))


def declared_limits(text: str) -> tuple[float, int]:
    """Sum every cpus/mem_limit/memory value declared in one compose file."""
    cpus = sum(float(x) for x in re.findall(r"cpus:\s*\"?([0-9.]+)", text))
    mem = sum(to_bytes(x) for x in re.findall(
        r"(?:mem_limit|memory):\s*\"?([0-9.]+\s*[KMGT]?)", text, re.I))
    return cpus, mem


def stack_for(entry: str) -> Path | None:
    """Map one profile line to its compose file, or None if it has none."""
    stack = HOME / f"honeypot-{entry}"
    for cand in sorted(stack.glob("compose.y*ml")) if stack.is_dir() else []:
        return cand
    return None


def profile_entries(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def main() -> int:
    for profile in sorted(PROFILES.glob("*.txt")):
        entries = profile_entries(profile)
        cpus: float = 0.0
        mem = 0
        undeclared = []
        for entry in entries:
            compose = stack_for(entry)
            if compose is None:
                undeclared.append(entry)
                continue
            c, m = declared_limits(compose.read_text(encoding="utf-8", errors="replace"))
            cpus += c
            mem += m
            if not c and not m:
                undeclared.append(entry)
        gib = mem / 1024**3
        print(f"{profile.stem}: {len(entries)} stacks, {cpus:g} cpus, {gib:.1f} GiB")
        if undeclared:
            print(f"  no declared limit: {', '.join(undeclared)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
