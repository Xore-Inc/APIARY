#!/usr/bin/env python3
"""Regression tests for #3321: the two dashboard images must leave a
digest-bound CycloneDX SBOM behind, and the scan that grades it must be the
same pinned scan that grades every base image.

What could quietly undo this, and is therefore asserted here rather than
assumed:

* an SBOM keyed to a tag instead of the pushed digest -- an inventory of
  "whatever that tag pointed at when syft ran" answers no CVE question;
* the SBOM steps quietly applying to all 18 matrix rows, which would put a
  syft run and a Trivy advisory-DB download in front of every honeypot build
  for the sake of two images;
* the steps dropping out of the required `Containers gate`, which is the
  only reason a missing inventory is loud rather than invisible;
* a second trivy pin appearing in a workflow. That is how the base-image
  scan and the SBOM scan end up grading the same CVE two different ways,
  which is the outcome this issue was filed to prevent;
* /var/image-sbom never being provisioned, so the homeserver copy silently
  degrades to nothing on every box a #1609 rebuild creates.

The tests/docs/ CI row installs pytest and nothing else (see quality.yml),
so every PyYAML-backed assertion is paired with a dependency-free text
check, the same harness test_2639_fix.py established.
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTAINERS = REPO_ROOT / ".github/workflows/containers.yml"
BASE_IMAGE_SCAN = REPO_ROOT / ".github/workflows/image-security-scan.yml"
INSTALLER = REPO_ROOT / "scripts/install-homeserver.sh"
INSTALL_TRIVY = REPO_ROOT / "scripts/install-trivy.sh"

SBOM_IMAGES = {"backend-service", "dashboard-next"}


def _load(path: pathlib.Path) -> dict:
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; workflow parse skipped")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _steps(workflow: dict) -> list[dict]:
    return workflow["jobs"]["build"]["steps"]


def _step_running(workflow: dict, needle: str) -> dict:
    matches = [s for s in _steps(workflow) if needle in str(s.get("run", ""))]
    assert len(matches) == 1, f"expected exactly one step running {needle!r}, found {len(matches)}"
    return matches[0]


# --------------------------------------------------------------- matrix ----


def test_only_the_two_dashboard_rows_opt_into_the_sbom():
    workflow = _load(CONTAINERS)
    rows = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    opted_in = {r["image"] for r in rows if r.get("sbom") is True}
    assert opted_in == SBOM_IMAGES, (
        "exactly backend-service and dashboard-next carry `sbom: true` (#3321); "
        f"got {sorted(opted_in)}. Adding it to another row puts a syft run and a "
        "Trivy advisory-DB download in front of that image's build."
    )


def test_every_sbom_step_is_gated_on_the_matrix_opt_in():
    """A step that is not gated runs on all 18 rows, honeypots included."""
    workflow = _load(CONTAINERS)
    sbom_steps = [
        s
        for s in _steps(workflow)
        if any(
            needle in str(s.get("run", "")) or needle in str(s.get("uses", ""))
            for needle in (
                "generate-image-sbom.sh",
                "scan-image-sbom.sh",
                "prune-image-sbom.sh",
                "upload-artifact",
            )
        )
    ]
    assert sbom_steps, "no SBOM steps found in containers.yml's build job (#3321)"
    for step in sbom_steps:
        assert "matrix.sbom == true" in str(step.get("if", "")), (
            f"step {step.get('name', step.get('uses'))!r} is not gated on the "
            "`sbom: true` matrix opt-in, so it runs for every image (#3321)"
        )


def test_only_pushing_events_generate_one():
    """A pull_request row builds with push=false and load=false: no image,
    no digest, nothing to key an inventory to. The SBOM contract is main-only
    (decided in #3609), so the pull_request notice step is retired rather
    than kept as a recurring annotation."""
    workflow = _load(CONTAINERS)
    generate = _step_running(workflow, "generate-image-sbom.sh")
    condition = str(generate.get("if", ""))
    assert "github.event_name != 'pull_request'" in condition, (
        "SBOM generation must be limited to events that push the image (#3321); "
        f"got if: {condition!r}"
    )
    assert not any(
        "no sbom" in str(s.get("name", "")).lower() for s in _steps(workflow)
    ), "the pull_request 'no SBOM' notice was retired by decision #3609; do not re-add it"


# -------------------------------------------------------------- digest ----


def test_the_key_is_the_pushed_digest_not_a_tag():
    workflow = _load(CONTAINERS)
    build = [s for s in _steps(workflow) if s.get("uses", "").startswith("docker/build-push-action@")]
    assert len(build) == 1
    assert build[0].get("id") == "build", (
        "docker/build-push-action needs `id: build` for steps.build.outputs.digest "
        "to be addressable (#3321)"
    )
    generate = _step_running(workflow, "generate-image-sbom.sh")
    digest = generate.get("env", {}).get("IMAGE_DIGEST", "")
    assert "steps.build.outputs.digest" in digest, (
        "the SBOM must be keyed to the pushed manifest digest (#3321); got "
        f"IMAGE_DIGEST: {digest!r}"
    )


def test_the_sbom_survives_the_run_as_an_artifact():
    workflow = _load(CONTAINERS)
    uploads = [s for s in _steps(workflow) if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(uploads) == 1, "expected exactly one upload-artifact step for the SBOM (#3321)"
    upload = uploads[0]
    with_ = upload.get("with", {})
    assert with_.get("if-no-files-found") == "error", (
        "a silently empty artifact reads as 'nobody looked'; #3321's whole "
        "value is that the file is there"
    )
    assert "sbom_digest_hex" in str(with_.get("name", "")), (
        "the artifact name must be keyed by the digest, in its hex form -- a "
        f"colon is not a legal artifact-name character. Got {with_.get('name')!r}"
    )
    # GitHub's expression grammar reads '-' as an operator, so a hyphenated
    # output key is a subtraction rather than a property lookup.
    assert not re.search(r"outputs\.[A-Za-z0-9_]*-", str(with_.get("name", ""))), (
        f"read the output back by a name that is a valid expression property; "
        f"got {with_.get('name')!r}"
    )


def test_the_sbom_scan_reads_the_same_file_the_inventory_wrote():
    workflow = _load(CONTAINERS)
    generate = _step_running(workflow, "generate-image-sbom.sh")
    scan = _step_running(workflow, "scan-image-sbom.sh")
    gen_out = str(generate.get("env", {}).get("SBOM_DIR", ""))
    scan_dir = str(scan.get("env", {}).get("SBOM_DIR", ""))
    assert gen_out and gen_out == scan_dir, (
        "generation and scanning must agree on where the SBOM lives, or the "
        "scan and the inventory describe different files (#3321)"
    )
    assert "runner.temp" in gen_out, f"SBOM_DIR should be under runner.temp, got {gen_out!r}"


# --------------------------------------------------------------- shared ----


def test_both_scans_use_one_pinned_trivy():
    """Two copies of a (version, asset, sha256) triple is how the same CVE
    gets graded two ways with no visible cause (#3321)."""
    for path in (CONTAINERS, BASE_IMAGE_SCAN):
        text = path.read_text(encoding="utf-8")
        assert "scripts/install-trivy.sh" in text, (
            f"{path.name} must install trivy through the shared scripts/install-trivy.sh (#3321)"
        )
        assert not re.search(r"TRIVY_SHA256", text), (
            f"{path.name} still carries its own trivy pin; the pin lives in "
            "scripts/install-trivy.sh so the two scans cannot drift (#3321)"
        )

    pin = INSTALL_TRIVY.read_text(encoding="utf-8")
    assert re.search(r"PINNED_TRIVY_VERSION=0\.74\.0", pin), (
        "the shared installer must carry the 0.74.0 pin image-security-scan.yml "
        "was already using, so adopting it here is not a version bump (#3321)"
    )
    assert re.search(r"PINNED_TRIVY_SHA256=[0-9a-f]{64}", pin), (
        "the pin must be a hardcoded sha256, not a fetched sidecar -- a sidecar "
        "fetched over the same TLS session detects transport corruption, which "
        "TLS already covers (#3321, same discipline as #3115)"
    )


def test_the_sbom_stays_inside_the_required_gate():
    """`Containers gate` is main's only required context for this workflow.
    A build job that stopped being in its needs: would make a failed SBOM
    step invisible to a merge."""
    workflow = _load(CONTAINERS)
    gate = workflow["jobs"]["containers-gate"]
    assert "build" in gate.get("needs", []), (
        "containers-gate must still need the build job, or #3321's steps can "
        "fail without gating anything"
    )
    assert gate.get("if") == "always()", "containers-gate must keep its always() (#3311)"


# ---------------------------------------------------------- provisioning ----


def test_the_homeserver_directory_is_provisioned_not_assumed():
    text = INSTALLER.read_text(encoding="utf-8")
    assert "step_provision_image_sbom()" in text, (
        "scripts/install-homeserver.sh must provision /var/image-sbom (#3321). /var is "
        "root:root 0755, so the workflow cannot create it -- the runner's mkdir gets "
        "EACCES, exactly as /var/buildx-cache did before #2822's step."
    )
    assert re.search(
        r"run_step provision-image-sbom\s+\"[^\"]*\"\s+step_provision_image_sbom", text
    ), "provision-image-sbom must be wired into the installer's run order (#3321)"
    # Provisioned, then proven: an install(1) that the runner still cannot
    # write to is the exact check #2822 found missing.
    assert "runuser -u" in text.split("step_provision_image_sbom()", 1)[1], (
        "the provision step must verify writability with runuser rather than "
        "assuming install(1) implies it (#3321, #2822's lesson)"
    )
    assert "/var/image-sbom" in text


# ------------------------------------------------- dependency-free controls ----


def test_pins_are_not_duplicated_anywhere_by_grep():
    """Runs even where PyYAML is absent. The single most consequential
    property here is that the trivy pin is not spelled out twice."""
    for path in CONTAINERS, BASE_IMAGE_SCAN:
        text = path.read_text(encoding="utf-8")
        assert "scripts/install-trivy.sh" in text, f"{path.name}: shared trivy installer missing"
        assert "TRIVY_SHA256" not in text, (
            f"{path.name}: inline trivy pin reintroduced (#3321)"
        )

    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in REPO_ROOT.rglob("*")
        if p.is_file()
        and p.suffix in {".yml", ".yaml", ".sh"}
        and ".git/" not in p.relative_to(REPO_ROOT).as_posix()
        and "node_modules" not in p.relative_to(REPO_ROOT).as_posix()
        and "PINNED_TRIVY_SHA256" not in p.name
        and "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
        in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert offenders == [INSTALL_TRIVY.relative_to(REPO_ROOT).as_posix()], (
        "the trivy release sha256 must appear in exactly one file -- "
        f"scripts/install-trivy.sh. Also found it in: {offenders}"
    )


def test_the_sbom_opt_in_is_spelled_out_by_grep():
    text = CONTAINERS.read_text(encoding="utf-8")
    # Line-anchored: the workflow's own comments quote `sbom: true` when
    # explaining the flag, and those are prose, not opt-ins.
    opt_ins = [ln for ln in text.splitlines() if ln.strip() == "sbom: true"]
    assert len(opt_ins) == len(SBOM_IMAGES), (
        f"expected `sbom: true` exactly twice in containers.yml (#3321); found {len(opt_ins)}"
    )
    for image in SBOM_IMAGES:
        block = re.search(rf"- image: {re.escape(image)}\n(?:(?!- image:).)*", text, re.S)
        assert block, f"matrix row {image} not found in containers.yml"
        assert "sbom: true" in block.group(0), f"{image} must opt into the SBOM steps (#3321)"
    assert "steps.build.outputs.digest" in text, "the digest must reach the workflow env (#3321)"


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
