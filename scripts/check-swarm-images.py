#!/usr/bin/env python3
"""GHCR image coverage, digest manifest and swarm stack lint (#3597).

Part of epic #3587 (Docker Swarm across vps, homeserver and precision). Swarm
ignores `build:`, and a worker node cannot pull a local tag such as
`apiary-backend:latest`, so every image a stack runs has to be built by CI,
pushed to GHCR and referenced from the stack by digest. This script is the
repo-side half of that contract. One file, five subcommands:

  completeness  every compose `build:` context has a row in
                .github/workflows/containers.yml, and the row builds the same
                image the compose file would (Dockerfile, target, build args)
  stacks        no swarm stack file contains `build:`, and every `image:` is
                pinned `name@sha256:<64 hex>` (`name:tag@sha256:...` is fine)
  all           completeness + stacks (what the CI row runs)
  scope         which path-scoped rows a pull request has to build
  manifest      resolve every pushed image to its index digest and write the
                machine-readable manifest phase 3 (#3590) pins stack files from

Honest limits:

- completeness is static. It proves the row and the compose `build:` block
  agree; it does not build anything. containers.yml itself builds every row.
- a context shared by byte-identical directories (snare lives in two stacks)
  is declared once on the row as `also_contexts`, and the checker proves the
  directories really are identical, so the shared image cannot silently fork.
- the stack lint matches SWARM_STACK_GLOBS. Phase 3 (#3590) has not created
  that directory yet, so on today's tree the lint passes with "no stack files".
  Change the constant in ONE place if #3590 lands a different layout.

Needs PyYAML (CI installs it; the stdlib has no YAML parser).

Usage:
  python scripts/check-swarm-images.py all
  python scripts/check-swarm-images.py completeness [--root DIR] [--workflow FILE]
  python scripts/check-swarm-images.py stacks [--root DIR]
  python scripts/check-swarm-images.py scope --base SHA [--event pull_request]
  python scripts/check-swarm-images.py manifest --owner OWNER --sha SHA --out FILE
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on a bare interpreter
    sys.stderr.write("check-swarm-images.py needs PyYAML: python3 -m pip install pyyaml\n")
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/containers.yml"
REGISTRY = "ghcr.io"
# containers.yml pushes ghcr.io/<owner>/honeypot-<matrix.image>. Keep in step
# with the `images:` input of the metadata step there.
IMAGE_PREFIX = "honeypot-"

# THE stack glob. #3590 names `swarm/stacks/<name>/stack.yml` as its example
# layout; if phase 3 settles elsewhere, change this tuple and nothing else.
SWARM_STACK_GLOBS = (
    "swarm/stacks/*/stack.yml",
    "swarm/stacks/*/stack.yaml",
)

# Build contexts a compose file references that CI cannot build, with the
# reason. An entry that no compose file references any more is itself an
# error, so this cannot rot into a silent allowlist.
EXEMPT_CONTEXTS = {
    "analysis/ghidra/revdeck/ai-reverse-engineering": (
        "third-party checkout the operator clones at install time; neither the "
        "context nor its Dockerfile is in this repository"
    ),
}

COMPOSE_NAME = re.compile(r"^(docker-)?compose([.-].+)?\.ya?ml$")
SKIP_DIRS = {"node_modules", "vendor", "__pycache__"}
IMAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
PINNED_IMAGE = re.compile(r"^[A-Za-z0-9][^\s@$]*@sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


# --------------------------------------------------------------------------
# compose side
# --------------------------------------------------------------------------


@dataclass
class Build:
    file: str  # repo-relative compose file
    service: str
    context: str | None  # repo-relative, None when remote or unresolvable
    raw_context: str
    dockerfile: str
    target: str | None
    args: dict[str, str | None]
    problem: str | None = None


def _load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def compose_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Dot-directories also keep the walk out of .git, .grit/worktrees and
        # .claude, which would otherwise yield every compose file N times.
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIP_DIRS)
        for name in sorted(filenames):
            if COMPOSE_NAME.match(name):
                found.append(Path(dirpath) / name)
    return found


def _args(raw) -> dict[str, str | None]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): (None if v is None else str(v)) for k, v in raw.items()}
    out: dict[str, str | None] = {}
    for item in raw:
        key, sep, value = str(item).partition("=")
        out[key] = value if sep else None
    return out


def compose_builds(root: Path) -> list[Build]:
    builds: list[Build] = []
    for path in compose_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            doc = _load(path)
        except yaml.YAMLError as exc:
            builds.append(Build(rel, "?", None, "", "Dockerfile", None, {}, f"unparseable YAML: {exc}"))
            continue
        services = doc.get("services") if isinstance(doc, dict) else None
        if not isinstance(services, dict):
            continue
        for name, svc in services.items():
            build = (svc or {}).get("build")
            if not build:
                continue
            if isinstance(build, str):
                build = {"context": build}
            raw = str(build.get("context", "."))
            problem = None
            context: str | None = None
            if "://" in raw or raw.startswith("git@"):
                problem = "remote"  # not a repository path: nothing to cover
            elif "${" in raw or "$(" in raw:
                problem = f"context {raw!r} is interpolated; CI cannot know what it resolves to"
            else:
                resolved = os.path.normpath(os.path.join(os.path.dirname(rel), raw))
                if resolved.startswith(".."):
                    problem = f"context {raw!r} escapes the repository"
                else:
                    context = "." if resolved == "" else resolved
            builds.append(
                Build(
                    file=rel,
                    service=str(name),
                    context=context,
                    raw_context=raw,
                    dockerfile=str(build.get("dockerfile", "Dockerfile")),
                    target=build.get("target"),
                    args=_args(build.get("args")),
                    problem=problem,
                )
            )
    return builds


def dockerfile_arg_defaults(path: Path) -> dict[str, str | None]:
    defaults: dict[str, str | None] = {}
    if not path.is_file():
        return defaults
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?\s*$", line)
        if m:
            value = m.group(2)
            defaults[m.group(1)] = value.strip().strip("\"'") if value is not None else None
    return defaults


def tree_digest(directory: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(directory).as_posix().encode())
            h.update(b"\0")
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


# --------------------------------------------------------------------------
# containers.yml side
# --------------------------------------------------------------------------


@dataclass
class Row:
    image: str
    context: str
    dockerfile: str = "Dockerfile"
    target: str | None = None
    scoped: bool = False
    stamp: bool = False
    also_contexts: list[str] = field(default_factory=list)

    @property
    def contexts(self) -> list[str]:
        return [self.context, *self.also_contexts]


def matrix_rows(root: Path, workflow: str = WORKFLOW) -> list[Row]:
    doc = _load(root / workflow)
    include = doc["jobs"]["build"]["strategy"]["matrix"]["include"]
    rows = []
    for entry in include:
        also = entry.get("also_contexts") or ""
        rows.append(
            Row(
                image=str(entry["image"]),
                context=os.path.normpath(str(entry["context"])),
                dockerfile=str(entry.get("dockerfile") or "Dockerfile"),
                target=entry.get("target"),
                scoped=entry.get("scoped") is True,
                stamp=entry.get("stamp") is True,
                also_contexts=[os.path.normpath(c) for c in str(also).replace(",", " ").split()],
            )
        )
    return rows


def check_completeness(
    root: Path, workflow: str = WORKFLOW, exempt: dict[str, str] | None = None
) -> tuple[list[str], list[str]]:
    """Return (errors, report lines)."""
    exempt = EXEMPT_CONTEXTS if exempt is None else exempt
    errors: list[str] = []
    report: list[str] = []
    rows = matrix_rows(root, workflow)
    builds = compose_builds(root)

    # -- row sanity ------------------------------------------------------
    seen_images: dict[str, Row] = {}
    # keyed by (context, Dockerfile): two images may build different
    # Dockerfiles out of one context (sandbox/ghosts).
    by_context: dict[tuple[str, str], Row] = {}
    for row in rows:
        if not IMAGE_NAME.match(row.image):
            errors.append(f"row {row.image!r}: not a valid image name ({IMAGE_NAME.pattern})")
        if row.image in seen_images:
            errors.append(f"row {row.image!r}: duplicate image name in the containers.yml matrix")
        seen_images[row.image] = row
        primary = root / row.context
        if not (primary / row.dockerfile).is_file():
            errors.append(
                f"row {row.image!r}: {row.context}/{row.dockerfile} does not exist (stale row?)"
            )
        for ctx in row.contexts:
            key = (ctx, row.dockerfile)
            if key in by_context and by_context[key] is not row:
                errors.append(
                    f"context {ctx} ({row.dockerfile}): claimed by both "
                    f"{by_context[key].image!r} and {row.image!r}"
                )
            by_context[key] = row
        if (primary).is_dir():
            want = tree_digest(primary)
            for extra in row.also_contexts:
                if not (root / extra).is_dir():
                    errors.append(f"row {row.image!r}: also_contexts entry {extra} does not exist")
                elif tree_digest(root / extra) != want:
                    errors.append(
                        f"row {row.image!r}: {extra} is not byte-identical to {row.context}; "
                        "they cannot share one image (give the copy its own row)"
                    )

    # -- compose vs rows ---------------------------------------------------
    referenced: set[str] = set()
    for b in builds:
        where = f"{b.file} service {b.service}"
        if b.problem == "remote":
            report.append(f"skip   {where}: remote context {b.raw_context}")
            continue
        if b.problem:
            errors.append(f"{where}: {b.problem}")
            continue
        assert b.context is not None
        referenced.add(b.context)
        if b.context in exempt:
            report.append(f"exempt {where}: {b.context} ({exempt[b.context]})")
            continue
        row = by_context.get((b.context, b.dockerfile))
        if row is None:
            errors.append(
                f"{where}: build context {b.context} ({b.dockerfile}) has no row in {workflow}. "
                f"Add one (image name, context, dockerfile if not Dockerfile) so CI "
                f"pushes {REGISTRY}/<owner>/{IMAGE_PREFIX}<image>."
            )
            continue
        report.append(f"ok     {where}: {b.context} -> {row.image}")
        if (b.target or None) != (row.target or None):
            errors.append(
                f"{where}: compose target {b.target!r} differs from row {row.image!r} "
                f"target {row.target!r}"
            )
        defaults = dockerfile_arg_defaults(root / b.context / b.dockerfile)
        for key, value in b.args.items():
            if key == "GIT_SHA":
                if not row.stamp:
                    errors.append(f"{where}: passes GIT_SHA but row {row.image!r} has no `stamp: true`")
                continue
            if value is None or "$" in value:
                errors.append(
                    f"{where}: build arg {key} is taken from the environment ({value!r}); "
                    "CI cannot reproduce it"
                )
            elif defaults.get(key) != value:
                errors.append(
                    f"{where}: build arg {key}={value!r} but the Dockerfile default is "
                    f"{defaults.get(key)!r} and row {row.image!r} sets no build arg; "
                    "CI would publish a different image than compose builds"
                )

    for ctx in exempt:
        if ctx not in referenced:
            errors.append(f"EXEMPT_CONTEXTS entry {ctx} is not referenced by any compose file; remove it")
    return errors, report


# --------------------------------------------------------------------------
# stack lint
# --------------------------------------------------------------------------


def stack_files(root: Path, globs=SWARM_STACK_GLOBS) -> list[Path]:
    found: set[Path] = set()
    for pattern in globs:
        found.update(p for p in root.glob(pattern) if p.is_file())
    return sorted(found)


def check_stacks(root: Path, globs=SWARM_STACK_GLOBS) -> tuple[list[str], list[Path]]:
    errors: list[str] = []
    files = stack_files(root, globs)
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            doc = _load(path)
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: unparseable YAML: {exc}")
            continue
        services = doc.get("services") if isinstance(doc, dict) else None
        if not isinstance(services, dict) or not services:
            errors.append(f"{rel}: no services")
            continue
        for name, svc in services.items():
            svc = svc or {}
            if "build" in svc:
                errors.append(f"{rel}: service {name} has `build:`; swarm ignores it. Reference a pushed image by digest")
            image = svc.get("image")
            if image is None:
                if "build" not in svc:
                    errors.append(f"{rel}: service {name} has no `image:`")
            elif not isinstance(image, str) or not PINNED_IMAGE.match(image):
                errors.append(
                    f"{rel}: service {name} image {image!r} is not pinned; use "
                    "`name@sha256:<64 hex>` (a `name:tag@sha256:...` form is allowed)"
                )
    return errors, files


# --------------------------------------------------------------------------
# scope (which scoped rows a PR must build)
# --------------------------------------------------------------------------


def changed_files(base: str, head: str = "HEAD", root: Path = ROOT) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", base, head],
            cwd=root, check=True, capture_output=True, text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return [line for line in out.splitlines() if line]


def scoped_images(rows: list[Row], event: str, changed: list[str] | None, workflow: str = WORKFLOW) -> list[str]:
    """Images of `scoped` rows that must build.

    Everything outside a pull_request builds in full (a push to main is what
    publishes the digests). On a pull_request a row builds when a changed
    path lies inside one of its contexts, or when the workflow itself
    changed. An unknown diff builds everything: skipping a build on a guess
    is the unsafe direction.
    """
    scoped = [r for r in rows if r.scoped]
    if event != "pull_request" or changed is None or workflow in changed:
        return [r.image for r in scoped]
    out = []
    for row in scoped:
        prefixes = tuple(c.rstrip("/") + "/" for c in row.contexts)
        if any(path.startswith(prefixes) for path in changed):
            out.append(row.image)
    return out


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------


def registry_digest(ref: str, attempts: int = 3, delay: int = 15) -> str:
    """Index digest `ref` currently resolves to, straight from the registry.

    This is the digest `docker pull <repo>@<digest>` resolves: for a
    multi-platform push the OCI index, for a single image its manifest, which
    is exactly what build-push-action reports as `digest`. ghcr's read path
    can trail its write path by seconds, hence the retries.
    """
    last = ""
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}"],
            capture_output=True, text=True,
        )
        value = proc.stdout.strip()
        if proc.returncode == 0 and DIGEST.match(value):
            return value
        last = (proc.stderr or proc.stdout).strip()
        if attempt < attempts:
            time.sleep(delay)
    raise RuntimeError(f"could not resolve {ref}: {last}")


def build_manifest(
    root: Path,
    owner: str,
    sha: str,
    resolve: Callable[[str], str] = registry_digest,
    workflow: str = WORKFLOW,
    repository: str = "",
    run_id: str = "",
) -> dict:
    rows = matrix_rows(root, workflow)
    services: dict[tuple[str, str], list[str]] = {}
    for b in compose_builds(root):
        if b.context:
            services.setdefault((b.context, b.dockerfile), []).append(f"{b.file}:{b.service}")
    short = sha[:7]
    images = {}
    for row in sorted(rows, key=lambda r: r.image):
        repo = f"{REGISTRY}/{owner.lower()}/{IMAGE_PREFIX}{row.image}"
        digest = resolve(f"{repo}:sha-{short}")
        if not DIGEST.match(digest):
            raise RuntimeError(f"{row.image}: {digest!r} is not a sha256 digest")
        compose = sorted({s for c in row.contexts for s in services.get((c, row.dockerfile), [])})
        images[row.image] = {
            "repository": repo,
            "digest": digest,
            "ref": f"{repo}@{digest}",
            "context": row.context,
            "compose_services": compose,
        }
    return {
        "schema": 1,
        "repository": repository,
        "commit": sha,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "images": images,
    }


def manifest_markdown(manifest: dict) -> str:
    lines = [
        f"### Image digests for `{manifest['commit'][:12]}`",
        "",
        "| image | ref |",
        "|---|---|",
    ]
    for name, info in manifest["images"].items():
        lines.append(f"| `{name}` | `{info['ref']}` |")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _print_errors(title: str, errors: list[str]) -> None:
    sys.stderr.write(f"{title}: {len(errors)} problem(s)\n")
    for e in errors:
        sys.stderr.write(f"  - {e}\n")


def run_completeness(root: Path, workflow: str, verbose: bool) -> int:
    errors, report = check_completeness(root, workflow)
    if verbose:
        print("\n".join(report))
    if errors:
        _print_errors("GHCR coverage (#3597)", errors)
        return 1
    print(f"GHCR coverage ok: every compose build context has a row in {workflow}")
    return 0


def run_stacks(root: Path) -> int:
    errors, files = check_stacks(root)
    if errors:
        _print_errors("swarm stack lint (#3597)", errors)
        return 1
    if files:
        print(f"swarm stack lint ok: {len(files)} stack file(s) pinned by digest")
    else:
        print(f"swarm stack lint ok: no stack files match {', '.join(SWARM_STACK_GLOBS)} yet")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["completeness", "stacks", "all", "scope", "manifest"])
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--workflow", default=WORKFLOW)
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", "push"))
    ap.add_argument("--base", default="")
    ap.add_argument("--owner", default="")
    ap.add_argument("--sha", default="")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    root = args.root.resolve()

    if args.command == "completeness":
        return run_completeness(root, args.workflow, args.verbose)
    if args.command == "stacks":
        return run_stacks(root)
    if args.command == "all":
        return run_completeness(root, args.workflow, args.verbose) | run_stacks(root)

    if args.command == "scope":
        changed = changed_files(args.base, root=root) if args.base else None
        images = scoped_images(matrix_rows(root, args.workflow), args.event, changed, args.workflow)
        text = json.dumps(images)
        print(text)
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a", encoding="utf-8") as fh:
                fh.write(f"images={text}\n")
        return 0

    # manifest
    if not (args.owner and args.sha and args.out):
        ap.error("manifest needs --owner, --sha and --out")
    manifest = build_manifest(
        root, args.owner, args.sha, workflow=args.workflow,
        repository=os.environ.get("GITHUB_REPOSITORY", ""), run_id=os.environ.get("GITHUB_RUN_ID", ""),
    )
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    text = manifest_markdown(manifest)
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
