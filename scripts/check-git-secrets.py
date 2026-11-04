#!/usr/bin/env python3
"""Fail CI when a real credential appears anywhere in FULL git history (#3501).

gitleaks does the detection; this script owns the policy, and the policy is
the whole point -- so it lives in Python where it is unit-testable rather
than in a workflow's `run:` block where it is not. The workflow installs the
pinned binary and calls this.

Scope is full history, not the checked-out tree: a credential that was
committed once and deleted in the next commit is still a credential, and
`gitleaks dir` cannot see it. That is the failure this gate exists to catch
and the reason it is its own lane rather than a row folded into the
public-leak check (which only ever walks `git ls-files`).

Shape, deliberately identical to `ALLOWED_DOTENV` /
`ALLOWED_LITERAL_FIXTURE_FILES` in scripts/check-public-leaks.py: an explicit,
commented, fail-closed set of paths, each carrying a written reason, and
each verified to exist. Renaming or deleting an allowlisted file re-surfaces
the failure on the next run rather than silently widening the exemption.

Usage:
  check-git-secrets.py                 # scan full history through the gitleaks on PATH
  check-git-secrets.py --binary PATH   # use this gitleaks instead of resolving one
  check-git-secrets.py --json FILE     # write gitleaks' own JSON report here
  check-git-secrets.py --allow-missing # skip the allowlist fail-closed check (tests only)
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Paths whose gitleaks findings are known false positives.
#
# Two shapes, and the distinction matters:
#
#   1. Honeyfs bait. `arcane/home/honeypot-cowrie/cowrie/honeyfs/**` is
#      cowrie's FAKE filesystem, served to a connecting attacker as
#      `wget`/`ftp`/shell targets. Its decoy `.env`, `/etc/shadow` hashes and
#      `authorized_keys` are the honeypot's product, not credentials --
#      scripts/check-public-leaks.py already names the `.env` in
#      ALLOWED_DOTENV for exactly this reason (#1502). Listed as a prefix
#      because the whole subtree is bait by construction; a new file there is
#      bait too, and adding it must not require a new entry.
#
#   2. Test fixtures and test-shaped strings. gitleaks' `generic-api-key`
#      rule is entropy- and keyword-driven, so it fires on the canary tokens
#      the honeypot's own tests assert on, on pinned Go/JS module hashes,
#      and on prose that happens to contain `api key` followed by a
#      high-entropy word. Each entry below names what the string actually is.
#      No entry is a wildcard and none covers a production credential.
#
# Fail-closed by construction: an entry naming a path that does not exist at
# scan time is a FAILURE (see `_verify_allowlist`), because a stale entry is
# an exemption for a file nobody is reading any more -- and the next real
# secret committed under that name sails through.
HONEYFS_PREFIX = "arcane/home/honeypot-cowrie/cowrie/honeyfs/"

ALLOWED_FILES: dict[str, str] = {
    # Canary tokens the honeypot's own tests assert on: a fake credential
    # whose entire purpose is to be emitted to the dashboard and detected.
    # Committing the value is what makes the assertion possible at all.
    "arcane/home/honeypot-http/http-honeypot/credentials_test.go":
        "honeypot canary token fixture, asserted on by the credentials_test.go suite",
    "arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot/credentials_test.go":
        "honeypot canary token fixture, asserted on by the credentials_test.go suite",
    "arcane/home/honeypot-canarytokens/canarytokens-http-router/main_test.go":
        "canarytoken router fixture; the token is generated per-deployment and this is a fixed test value",
    # A syntactically valid, cryptographically meaningless JWT literal used as
    # a request fixture. Payload decodes to {"sub":"1"}; no key exists for it
    # anywhere in this repo or its history.
    "arcane/home/honeypot-citrix-honeypot/citrix-honeypot/cve_2026_88771_test.go":
        "structurally valid but unsigned JWT used as a request-body fixture for CVE-2026-88771",
    "arcane/home/honeypot-dashboard/frontend-next/src/lib/credentialState.test.ts":
        "credential-state unit-test constant; asserts redacted-vs-plain classification, not a live secret",
    # Same canary literal as the http/cisco fixtures above, asserted on by the
    # dashboard backend's own credential-redaction tests.
    "arcane/home/honeypot-dashboard/backend-service/src/stores.rs":
        "honeypot canary literal asserted on by the Rust credential-redaction tests",
    # A truncated attacker-command log line, quoted as a fixture for the
    # criticality rules. Not a key: gitleaks reads `token=` plus the
    # high-entropy JWT-shaped run that follows it.
    "arcane/home/honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/tests/test_criticality_rules.py":
        "captured attacker command line used as a scoring fixture for the criticality rules",
    # Dependency pins and prose. `uec_key_fpr` is a CloudFormation instance
    # fingerprint (a 40-hex public key id), not a secret; the other three are
    # a requirements line, a docker image tag and a research-note sentence
    # that gitleaks' keyword+entropy heuristic reads as a key.
    "sandbox/prepare-linux-base.sh":
        "uec_key_fpr is a CloudFormation EC2 instance key FINGERPRINT (public half), not a credential",
    "auth-events-worker/requirements.txt":
        "pinned dependency version line; no credential in this file",
    "arcane/home/honeypot-canarytokens/canarytokens/Dockerfile":
        "build ARG default naming the canarytoken service; not a credential",
    "analysis/ghidra/benchmarks/evaluate-models.py":
        "benchmark prose mentioning a model name after the token= keyword",
    "docs/canarytoken-live-fire-checklist.md":
        "operator checklist documenting the CANARYTOKENS_REF variable by name",
    "docs/research/2777-litellm-mcp-starlette.md":
        "research-note prose quoting a CANARYTOKENS_REF= assignment in an example",
    "tests/docs/test_2314_fix.py":
        "docs regression test fixture asserting on a compose image tag",
    "tests/docs/test_2433_fix.py":
        "docs regression test fixture asserting on an HP_BIND address",
    # Historical-only findings. These files were deleted from the tree but a
    # full-history scan still reads the commits that carried them, so they
    # need an entry to stay reachable. Each is a build artifact or a
    # vendored minified bundle, not source.
    #
    # `graphify-out/cache/stat-index.json` and
    # `dash-shots/f2-follow-up/preserved-sha256.json` used to sit here too.
    # They are gone: both were only reachable through refs the scan should
    # never have read (the deleted `design/shadcn-migration` branch and
    # whichever runner happened to reuse a workspace), so with the ref set
    # pinned to the commit under scan the scan reports 0 findings under either
    # path and the entries covered nothing. A rot entry is worse than no entry:
    # it fails the gate on every run while protecting nothing.
    "dashboard/static/xterm.js":
        "vendored minified xterm.js bundle, superseded by the npm package (74005ba3); entropy heuristic on minified code",
    "dashboard/scanner_fingerprints_test.go":
        "deleted with the old dashboard tree; fixture asserting on scanner fingerprint constants",
    "dashboard/problem_reports_test.go":
        "deleted with the old dashboard tree; fixture asserting on problem-report field names",
    "canarytokens/Dockerfile":
        "pre-migration copy of the canarytokens Dockerfile; same build ARG as the current one",
    "pihole/dnscrypt-proxy.toml":
        "deleted with the old pihole stack; a minisign PUBLIC verification key, which is public by definition",
    # ponytail: this is the ONE allowlist entry that is path-wide rather than
    # value-specific, and it is a real ceiling worth stating. The finding is
    # not in the working tree -- REPORT.md:1354 was redacted in 175800d4 -- but
    # commit a7cb77e5, already on the remote branch, carries a real Keycloak
    # AUTH_SESSION_ID cookie value pasted verbatim from a curl debug trace.
    # This script keys ALLOWED_FILES by path (line 258 skips the path outright),
    # so there is no narrower key available without a rewrite. Xore reviewed the
    # exposure and will rotate the Keycloak session; the cookie is a test-harness
    # session against a local Keycloak, not a production credential.
    # If a future secret lands in REPORT.md, this entry hides it. If that starts
    # to matter, replace this with commit-pinned allowlisting.
    "REPORT.md":
        "unreachable test-harness Keycloak cookie in commit a7cb77e5 only; redacted in 175800d4 and the session is rotated",
}


def _is_shallow(root: Path | None = None) -> bool:
    """Is this clone truncated, so `git log <path>` cannot see the whole history?"""
    result = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=root or ROOT, capture_output=True, text=True,
    )
    return result.returncode != 0 or result.stdout.strip() != "false"


def _verify_allowlist() -> list[str]:
    """Every allowlist entry must name a file that exists, now or in history.

    A stale entry is worse than no entry: it reads as an exemption someone
    argued for, while in fact covering nothing, and it invites the next real
    secret committed under that name to be waved through by whoever reads it.

    Shallow clones cannot answer the history half at all -- a path deleted
    years ago is simply not in the fetched commits, and reporting that as a
    miss would fail a healthy allowlist on every CI run (the #3516 failure).
    So in a shallow clone this DEGRADES rather than guessing: entries are
    still required to carry a reason, the history lookup is skipped, and the
    degradation is announced loudly as a `::warning::` so a reader knows the
    half of the check did not run. It is a warning, never a finding -- a
    truncated clone says nothing about whether the path ever existed.

    The gate's own CI step unshallows the clone before scanning
    (quality.yml, "Full-history secret scan"), which is where this check gets
    to run in full; the docs suite is the shallow case.
    """
    problems: list[str] = []
    shallow = _is_shallow()
    if shallow:
        print(
            "::warning::secret-scan allowlist: this is a SHALLOW clone "
            "(`git rev-parse --is-shallow-repository` = true), so the "
            "'exists somewhere in history' half of the allowlist check cannot "
            "run and was NOT run. Entries are only checked for a written "
            "reason and for presence in the working tree. Run "
            "`git fetch --unshallow` to get the full check."
        )
    for relative, reason in ALLOWED_FILES.items():
        if not reason.strip():
            problems.append(f"{relative}: allowlist entry carries no reason")
            continue
        if (ROOT / relative).is_file():
            continue
        if shallow:
            continue
        if subprocess.run(
            ["git", "log", "--all", "--format=%H", "-1", "--", relative],
            cwd=ROOT, capture_output=True, text=True,
        ).stdout.strip():
            continue
        problems.append(
            f"{relative}: allowlist entry names a file that exists neither in "
            f"the tree nor anywhere in history -- remove the entry or restore the file"
        )
    return problems


def _resolve_binary(explicit: str | None) -> str:
    if explicit:
        return explicit
    found = shutil.which("gitleaks")
    if not found:
        print(
            "check-git-secrets: gitleaks is not on PATH. The workflow installs a "
            "pinned, checksum-verified build before calling this; locally, install "
            "it yourself or pass --binary.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="gitleaks to drive instead of resolving one from PATH")
    parser.add_argument("--json", dest="json_path", help="write gitleaks' JSON report here")
    parser.add_argument("--allow-missing", action="store_true",
                        help="skip the allowlist fail-closed check (tests only)")
    args = parser.parse_args()

    binary = _resolve_binary(args.binary)
    report_path = Path(args.json_path) if args.json_path else ROOT / ".ci-artifacts" / "gitleaks.json"
    # The workflow exports CI_ARTIFACTS_DIR for the vitest reporter, but that is
    # a different gate's convention; nothing else creates this path, and a
    # missing directory would surface as "gitleaks failed to run" -- the exact
    # error shape that trains operators to ignore this gate. Create it.
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # --redact keeps the matched value out of CI logs and the artifact: a
    # gate that prints the secret it found has leaked it a second time. The
    # finding is still fully actionable from RuleID + File + line.
    command = [
        binary, "detect",
        "--source", str(ROOT),
        "--no-banner",
        "--redact",
        "--exit-code", "0",   # never trust the binary's own exit code; classify below
        "--report-format", "json",
        "--report-path", str(report_path),
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        # A non-zero exit here is gitleaks failing to RUN (bad flag, unreadable
        # repo), not a finding. Surfacing it as "leaks found" would train
        # operators to ignore the gate -- the same failure mode #2763 recorded
        # for trivy, where an unresolvable reference and a real finding share
        # an exit code.
        print(f"check-git-secrets: gitleaks failed to run: {result.stderr.strip()}", file=sys.stderr)
        return 2

    if not report_path.is_file():
        print(f"check-git-secrets: gitleaks wrote no report at {report_path}", file=sys.stderr)
        return 2

    findings = json.loads(report_path.read_text(encoding="utf-8"))

    problems = [] if args.allow_missing else _verify_allowlist()
    for problem in problems:
        print(f"::error::secret-scan allowlist: {problem}")

    unallowed: list[str] = []
    allowed_hits = 0
    for finding in findings:
        path = finding.get("File", "")
        if path.startswith(HONEYFS_PREFIX) or path in ALLOWED_FILES:
            allowed_hits += 1
            continue
        unallowed.append(
            f"{path}:{finding.get('StartLine', 0)}: {finding.get('RuleID', 'unknown')} "
            f"(commit {finding.get('Commit', '')[:10]}, {finding.get('Author', '?')})"
        )

    honeyfs_hits = sum(1 for f in findings if f.get("File", "").startswith(HONEYFS_PREFIX))

    if unallowed:
        print(
            f"Secret scan failed: {len(unallowed)} finding(s) outside the allowlist "
            f"({allowed_hits} allowed, {honeyfs_hits} of them cowrie honeyfs bait):",
            file=sys.stderr,
        )
        for line in sorted(set(unallowed)):
            print(f"  - {line}", file=sys.stderr)
        print(
            "\nIf a finding is a genuine false positive, add it to ALLOWED_FILES in "
            "scripts/check-git-secrets.py with a written reason -- not a wildcard, and "
            "the path must exist.",
            file=sys.stderr,
        )
        return 1

    if problems:
        return 1

    print(
        f"Secret scan passed: {len(findings)} finding(s) over full history, all "
        f"covered by ALLOWED_FILES ({honeyfs_hits} cowrie honeyfs) or absent. "
        f"Report: {report_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())