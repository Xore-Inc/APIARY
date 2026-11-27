#!/usr/bin/env python3
"""Base-image CVE gate (#3964): a no-regression gate with no exemption list.

image-security-scan.yml calls this script in one of two modes.

--mode pr --base-rev REV   (pull requests)
    Every base image reference the PR's head tree pulls that REV's tree did
    not is one of two things:

    - an ADDED image (no reference in REV for the same image repository):
      it must scan clean, i.e. 0 fixable CRITICAL/HIGH findings;
    - a CHANGED image (same repository, new tag or digest, paired with the
      reference REV pulled for it): it passes only if the new digest has no
      more fixable CRITICAL/HIGH findings than the old one, and no CRITICAL
      finding (compared by CVE ID) that the old digest did not already have.

    Both digests are scanned with the same trivy flags. An image that cannot
    be measured, on either side, fails the gate: a regression cannot be ruled
    out on a number we do not have.

--mode full                (push to main, weekly schedule, manual)
    Every base image the repository pulls must scan clean. Drift on an
    unchanged pin turns this red on purpose (#3923). An image that cannot be
    resolved, or that trivy aborts on, is a coverage gap: reported as a
    warning, as before (#2763, #3520), not a finding.

There is no exemption mechanism. A finding that upstream has not fixed is
tracked on #3923, not written off here. Fixes the repository can make itself
(a package update in one of its own stages) are required instead.

The decision logic is in pure functions (`pair_references`, `verdict`,
`scan_from_trivy_json`) so the four cases in the #3964 "Done when" are tested
without pulling images. scripts/tests/test_3964_base_image_no_regression_gate.py.

Usage:
  python3 scripts/check-base-image-gate.py --mode pr --base-rev <sha> [--report FILE]
  python3 scripts/check-base-image-gate.py --mode full [--report FILE]
Exit status: 0 when the gate passes, 1 when it fails.
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
GATED_SEVERITIES = ("CRITICAL", "HIGH")

# Classification of a trivy failure, copied from the outcomes image-security-scan.yml
# has always separated (#2763, #3520): a reference that will not resolve is a
# coverage gap, a scan that aborts is a coverage gap, anything else is an error.
UNRESOLVED_RE = re.compile(
    r"MANIFEST_UNKNOWN|manifest unknown|repository .* not found|name unknown"
    r"|could not (be )?(found|resolved)|failed to (fetch|resolve|find) the image",
    re.IGNORECASE,
)
SCAN_FAILED_RE = re.compile(r"FATAL.*run error: image scan error")


def _load_lister():
    spec = importlib.util.spec_from_file_location(
        "list_docker_base_images", SCRIPT_DIR / "list-docker-base-images.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Reference handling
# ---------------------------------------------------------------------------

def split_reference(ref: str) -> tuple[str, str | None]:
    """(repository, tag) for a reference; the digest is dropped.

    `postgres:16.8@sha256:...` -> ("postgres", "16.8"); `alpine@sha256:...` ->
    ("alpine", None); `ghcr.io/x/y:v1` -> ("ghcr.io/x/y", "v1"). A colon that
    belongs to a registry port (`host:5000/img`) is not a tag separator.
    """
    base = ref.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        name_tail, tag = last.rsplit(":", 1)
        repo = base[: len(base) - len(last)] + name_tail
        return repo, tag
    return base, None


def pair_references(added: list[str], base_refs: list[str]) -> list[tuple[str, str | None]]:
    """Pair each head reference with the base reference it replaces, or None.

    A reference is CHANGED when the base tree pulled the same repository. If
    several base references share the repository, the one with the same tag
    wins; failing that, the repository must have exactly one base reference to
    pair with. Anything still ambiguous is treated as ADDED, which is the strict
    reading: it must then scan clean on its own.
    """
    pairs: list[tuple[str, str | None]] = []
    for new in sorted(added):
        repo, tag = split_reference(new)
        candidates = sorted(b for b in base_refs if split_reference(b)[0] == repo)
        same_tag = [b for b in candidates if split_reference(b)[1] == tag]
        if same_tag:
            pairs.append((new, same_tag[0]))
        elif len(candidates) == 1:
            pairs.append((new, candidates[0]))
        else:
            pairs.append((new, None))
    return pairs


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ScanResult:
    ref: str
    measured: bool
    # Fixable CRITICAL/HIGH rows as (VulnerabilityID, Severity, PkgName, InstalledVersion).
    findings: tuple[tuple[str, str, str, str], ...] = ()
    reason: str = ""  # why the image was not measured, when measured is False

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def critical_ids(self) -> frozenset[str]:
        return frozenset(cve for cve, sev, _, _ in self.findings if sev == "CRITICAL")


def scan_from_trivy_json(ref: str, report: dict) -> ScanResult:
    """Fixable CRITICAL/HIGH rows of a `trivy image --format json` report.

    --ignore-unfixed already drops rows without a FixedVersion; the filter is
    repeated here so the gate's meaning does not depend on the flag.
    """
    rows = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = (vuln.get("Severity") or "").upper()
            if severity not in GATED_SEVERITIES or not vuln.get("FixedVersion"):
                continue
            rows.append((
                vuln.get("VulnerabilityID", "?"),
                severity,
                vuln.get("PkgName", "?"),
                vuln.get("InstalledVersion", "?"),
            ))
    return ScanResult(ref=ref, measured=True, findings=tuple(sorted(rows)))


def unmeasured(ref: str, reason: str) -> ScanResult:
    return ScanResult(ref=ref, measured=False, reason=reason)


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def verdict(new: ScanResult, old: ScanResult | None) -> tuple[bool, str]:
    """Pass or fail for one reference. `old` is None for an ADDED reference."""
    if not new.measured:
        return False, f"not measured ({new.reason}); cannot show it is clean"
    if old is None:
        if new.count == 0:
            return True, "added, 0 fixable CRITICAL/HIGH"
        return False, f"added with {new.count} fixable CRITICAL/HIGH"
    if not old.measured:
        return False, f"replaced reference not measured ({old.reason}); cannot show no regression"
    if new.count > old.count:
        return False, f"regression: {new.count} fixable CRITICAL/HIGH, was {old.count}"
    new_criticals = sorted(new.critical_ids - old.critical_ids)
    if new_criticals:
        return False, "new CRITICAL not in the old digest: " + ", ".join(new_criticals)
    return True, f"no regression: {new.count} fixable CRITICAL/HIGH, was {old.count}"


def full_verdict(new: ScanResult) -> tuple[bool, str]:
    """Push/schedule rule: clean or red. Unmeasured is a warning, not a finding."""
    if not new.measured:
        return True, f"not measured ({new.reason}): coverage gap, not a finding"
    if new.count == 0:
        return True, "clean"
    return False, f"{new.count} fixable CRITICAL/HIGH"


# ---------------------------------------------------------------------------
# trivy
# ---------------------------------------------------------------------------

TRIVY_FLAGS = [
    "--scanners", "vuln", "--severity", "CRITICAL,HIGH", "--ignore-unfixed",
    "--no-progress", "--format", "json",
]


def scan(ref: str, workdir: Path) -> ScanResult:
    out = workdir / f"trivy-{abs(hash(ref))}.json"
    log = workdir / f"trivy-{abs(hash(ref))}.log"
    proc = subprocess.run(
        ["trivy", "image", *TRIVY_FLAGS, "--output", str(out), ref],
        capture_output=True, text=True,
    )
    log.write_text(proc.stdout + proc.stderr)
    if proc.returncode != 0:
        text = proc.stdout + proc.stderr
        if UNRESOLVED_RE.search(text):
            return unmeasured(ref, "reference did not resolve")
        if SCAN_FAILED_RE.search(text):
            return unmeasured(ref, "trivy aborted the scan")
        return unmeasured(ref, f"trivy exited {proc.returncode}")
    return scan_from_trivy_json(ref, json.loads(out.read_text()))


class Scanner:
    """Scans each reference once, however many pairs it appears in."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.cache: dict[str, ScanResult] = {}

    def __call__(self, ref: str) -> ScanResult:
        if ref not in self.cache:
            print(f"::group::trivy {ref}", flush=True)
            self.cache[ref] = scan(ref, self.workdir)
            print("::endgroup::", flush=True)
        return self.cache[ref]


def describe(result: ScanResult) -> dict:
    return {
        "ref": result.ref,
        "measured": result.measured,
        "reason": result.reason,
        "count": result.count,
        "findings": [
            {"id": cve, "severity": sev, "pkg": pkg, "installed": ver}
            for cve, sev, pkg, ver in result.findings
        ],
    }


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def run_pr(lister, base_rev: str, scanner: Scanner) -> list[dict]:
    head = lister.collect_images()
    base = lister.collect_images(base_rev)
    added = sorted((head - base) - lister.UNSCANNABLE.keys())
    base_list = sorted(base - lister.UNSCANNABLE.keys())
    entries = []
    for new_ref, old_ref in pair_references(added, base_list):
        new = scanner(new_ref)
        old = scanner(old_ref) if old_ref else None
        ok, message = verdict(new, old)
        entries.append({
            "mode": "changed" if old_ref else "added",
            "new": describe(new),
            "old": describe(old) if old else None,
            "pass": ok,
            "message": message,
        })
    return entries


def run_full(lister, scanner: Scanner) -> list[dict]:
    entries = []
    for ref in sorted(lister.collect_images() - lister.UNSCANNABLE.keys()):
        result = scanner(ref)
        ok, message = full_verdict(result)
        entries.append({"mode": "full", "new": describe(result), "old": None,
                        "pass": ok, "message": message})
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=("pr", "full"), required=True)
    parser.add_argument("--base-rev", help="pr mode: the merge-base the PR is compared against")
    parser.add_argument("--report", type=Path, help="write the per-reference JSON here")
    parser.add_argument("--workdir", type=Path, help="trivy output directory (default: a temp dir)")
    args = parser.parse_args(argv)
    if args.mode == "pr" and not args.base_rev:
        parser.error("--mode pr needs --base-rev")

    lister = _load_lister()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = args.workdir or Path(tmp)
        workdir.mkdir(parents=True, exist_ok=True)
        scanner = Scanner(workdir)
        if args.mode == "pr":
            entries = run_pr(lister, args.base_rev, scanner)
            if not entries:
                print("::notice title=Base-image gate::This PR adds or changes no base image reference; nothing to measure.")
        else:
            entries = run_full(lister, scanner)

    failures = [e for e in entries if not e["pass"]]
    for entry in entries:
        verb = "PASS" if entry["pass"] else "FAIL"
        print(f"{verb} [{entry['mode']}] {entry['new']['ref']}: {entry['message']}")
        if not entry["pass"]:
            print(f"::error title=Base-image gate::{entry['new']['ref']}: {entry['message']}")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"mode": args.mode, "base_rev": args.base_rev,
                                           "entries": entries}, indent=2) + "\n")
    if failures:
        print(f"Base-image gate: {len(failures)} reference(s) failed.")
        return 1
    print(f"Base-image gate: {len(entries)} reference(s) checked, all pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
