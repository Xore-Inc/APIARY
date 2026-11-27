#!/usr/bin/env python3
"""Regression tests for #3964: the base-image gate is no-regression, with no exemptions.

scripts/check-base-image-gate.py decides pass or fail per image reference:

- an ADDED reference (no reference for the same repository in the base tree)
  must scan clean;
- a CHANGED reference (same repository, new tag or digest) passes only if the
  new digest has no more fixable CRITICAL/HIGH findings than the old one and
  no CRITICAL, compared by CVE ID, that the old one did not have;
- an image that cannot be measured fails a PR, because no regression can be
  ruled out without numbers.

The four cases in the #3964 "Done when" are the first four tests. The
findings are trivy `--format json` shaped fixtures, so nothing is pulled.
There is also a guard that no exemption list exists anywhere in the gate.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve the module by name
    spec.loader.exec_module(module)
    return module


gate = _load("check_base_image_gate", "check-base-image-gate.py")

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


def report(*rows):
    """A trivy JSON report: each row is (CVE, severity, fixed_version)."""
    return {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": cve, "Severity": sev, "PkgName": "pkg",
         "InstalledVersion": "1.0", "FixedVersion": fixed}
        for cve, sev, fixed in rows
    ]}]}


def scanned(ref, *rows):
    return gate.scan_from_trivy_json(ref, report(*rows))


HIGH_A = ("CVE-2026-0001", "HIGH", "1.1")
HIGH_B = ("CVE-2026-0002", "HIGH", "1.1")
HIGH_C = ("CVE-2026-0003", "HIGH", "1.1")
CRIT_X = ("CVE-2026-0100", "CRITICAL", "2.0")


# --- the four cases from the issue -----------------------------------------

def test_improving_digest_passes():
    old = scanned(f"img:1@{OLD}", HIGH_A, HIGH_B, HIGH_C)
    new = scanned(f"img:1@{NEW}", HIGH_A)
    ok, message = gate.verdict(new, old)
    assert ok, message


def test_regressing_digest_fails():
    old = scanned(f"img:1@{OLD}", HIGH_A)
    new = scanned(f"img:1@{NEW}", HIGH_A, HIGH_B)
    ok, message = gate.verdict(new, old)
    assert not ok
    assert "regression" in message


def test_new_flagged_reference_fails():
    new = scanned(f"img:2@{NEW}", HIGH_A)
    ok, message = gate.verdict(new, None)
    assert not ok
    assert "added" in message


def test_new_clean_reference_passes():
    new = scanned(f"img:2@{NEW}")
    ok, message = gate.verdict(new, None)
    assert ok, message


# --- the comparison is by CVE ID for CRITICAL -------------------------------

def test_new_critical_fails_even_with_fewer_findings():
    old = scanned(f"img:1@{OLD}", HIGH_A, HIGH_B)
    new = scanned(f"img:1@{NEW}", CRIT_X)
    ok, message = gate.verdict(new, old)
    assert not ok
    assert "CVE-2026-0100" in message


def test_critical_already_present_in_old_digest_passes():
    old = scanned(f"img:1@{OLD}", CRIT_X, HIGH_A, HIGH_B)
    new = scanned(f"img:1@{NEW}", CRIT_X, HIGH_A)
    ok, message = gate.verdict(new, old)
    assert ok, message


def test_critical_count_is_compared_by_id_not_by_number():
    old = scanned(f"img:1@{OLD}", ("CVE-2026-0200", "CRITICAL", "1"))
    new = scanned(f"img:1@{NEW}", ("CVE-2026-0300", "CRITICAL", "1"))
    ok, _ = gate.verdict(new, old)
    assert not ok


# --- unmeasured images fail a PR ------------------------------------------

def test_unmeasured_new_reference_fails():
    ok, _ = gate.verdict(gate.unmeasured("img:3", "reference did not resolve"), None)
    assert not ok


def test_unmeasured_old_reference_fails_a_change():
    old = gate.unmeasured(f"img:1@{OLD}", "trivy aborted the scan")
    ok, _ = gate.verdict(scanned(f"img:1@{NEW}"), old)
    assert not ok


def test_full_scan_treats_unmeasured_as_warning_not_finding():
    ok, message = gate.full_verdict(gate.unmeasured("img:3", "reference did not resolve"))
    assert ok
    assert "coverage gap" in message


def test_full_scan_fails_on_any_fixable_finding():
    ok, _ = gate.full_verdict(scanned(f"img:1@{OLD}", HIGH_A))
    assert not ok


# --- only fixable CRITICAL/HIGH rows count ----------------------------------

def test_unfixed_and_low_rows_are_not_findings():
    result = scanned(f"img:1@{OLD}",
                     ("CVE-2026-0400", "HIGH", ""),
                     ("CVE-2026-0401", "MEDIUM", "9"))
    assert result.count == 0
    assert gate.verdict(result, None)[0]


# --- pairing ----------------------------------------------------------------

def test_same_repository_is_a_change_and_tag_is_preferred():
    base = [f"node:22@{OLD}", f"node:26@{OLD}"]
    pairs = gate.pair_references([f"node:26@{NEW}"], base)
    assert pairs == [(f"node:26@{NEW}", f"node:26@{OLD}")]


def test_single_base_reference_pairs_when_tag_moves():
    pairs = gate.pair_references([f"rust:1.100-slim@{NEW}"], [f"rust:1-slim@{OLD}"])
    assert pairs == [(f"rust:1.100-slim@{NEW}", f"rust:1-slim@{OLD}")]


def test_ambiguous_repository_is_treated_as_added():
    base = [f"node:22@{OLD}", f"node:24@{OLD}"]
    pairs = gate.pair_references([f"node:27@{NEW}"], base)
    assert pairs == [(f"node:27@{NEW}", None)]


def test_new_repository_is_added():
    assert gate.pair_references(["quay.io/x/y:1"], ["alpine:3"]) == [("quay.io/x/y:1", None)]


def test_split_reference_handles_registry_port_and_digest():
    assert gate.split_reference("reg.local:5000/app:v2@sha256:" + "c" * 64) == ("reg.local:5000/app", "v2")
    assert gate.split_reference("alpine@sha256:" + "c" * 64) == ("alpine", None)


# --- guards -----------------------------------------------------------------

def test_no_exemption_list_is_left_anywhere():
    # Text check, not an import: the lister needs PyYAML, which the docs job
    # does not install, and the point is what the files say, not what loads.
    assert not hasattr(gate, "ACCEPTED_CVES")
    for rel in ("scripts/list-docker-base-images.py", "scripts/check-base-image-gate.py",
                ".github/workflows/image-security-scan.yml", "docs/CI-CD.md"):
        text = (REPO / rel).read_text()
        assert "ACCEPTED_CVES" not in text, rel
        assert "allow_cve_findings" not in text, rel


def test_trivy_is_run_with_the_gated_severities_and_no_ignore_file():
    flags = " ".join(gate.TRIVY_FLAGS)
    assert "--severity CRITICAL,HIGH" in flags
    assert "--ignore-unfixed" in flags
    assert "ignore" not in flags.replace("--ignore-unfixed", "")
