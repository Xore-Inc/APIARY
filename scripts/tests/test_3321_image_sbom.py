#!/usr/bin/env python3
"""Exercise the #3321 SBOM scripts against stub syft/trivy binaries.

The point of these is the wiring, not the tools: syft's cataloguing and
trivy's advisory database are somebody else's problem, and downloading
either one is not something a unit test should do. So SYFT_BIN / TRIVY_BIN
point at stubs and every assertion is about what *our* scripts promise --
that the digest ends up in the document, that the homeserver copy is named
for it, that a Trivy failure is classified as "found CVEs" or "measured
nothing" rather than conflated, and that pruning leaves a store whose
latest.sbom.json names a digest that still exists.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATE = ROOT / "scripts" / "generate-image-sbom.sh"
SCAN = ROOT / "scripts" / "scan-image-sbom.sh"
PRUNE = ROOT / "scripts" / "prune-image-sbom.sh"
INSTALL_TRIVY = ROOT / "scripts" / "install-trivy.sh"

DIGEST = "sha256:" + "ab" * 32
HEX = DIGEST.removeprefix("sha256:")
REF = f"ghcr.io/Xore/honeypot-backend-service:main@{DIGEST}"

# Mirrors what syft 1.52.0 actually emits for a container image: name plus
# tag, and no digest anywhere. That absence is the whole reason
# generate-image-sbom.sh stamps one in, so the fixture has to reproduce it
# rather than a convenient document that already carries one.
SYFT_STUB = """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then echo "syft 1.52.0"; exit 0; fi
out=""
prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out=${a#cyclonedx-json=}
  prev=$a
done
[ -n "$out" ] || { echo "stub: no cyclonedx-json= output requested" >&2; exit 1; }
[ "${STUB_SYFT_FAIL:-0}" = "1" ] && { echo "stub: unable to resolve source" >&2; exit 1; }
cat >"$out" <<'JSON'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "container",
      "name": "ghcr.io/Xore/honeypot-backend-service",
      "version": "main"
    }
  },
  "components": [{"type": "library", "name": "openssl", "version": "3.3.2"}]
}
JSON
"""

NOT_CYCLONEDX_STUB = """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then echo "syft 1.52.0"; exit 0; fi
out=""
prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out=${a#cyclonedx-json=}
  prev=$a
done
printf '{"bomFormat":"SPDX","spdxVersion":"SPDX-2.3"}\\n' >"$out"
"""

# One stub per classification, keyed by what it puts on stderr: trivy logs
# "Detected SBOM format" only once it has actually parsed the document, and
# that line is what separates "found CVEs" from "measured nothing".
TRIVY_STUBS = {
    "clean": (0, b"", b'{"SchemaVersion":2,"Results":[{"Target":"x","Vulnerabilities":[]}]}'),
    "flagged": (
        1,
        b'INFO\t[detector] Detected SBOM format\tformat="cyclonedx-json"\n',
        b'{"SchemaVersion":2,"Results":[{"Target":"x","Vulnerabilities":'
        b'[{"VulnerabilityID":"CVE-2024-0001","Severity":"HIGH"}]}]}',
    ),
    "unreadable": (1, b"FATAL\tunable to parse the SBOM\n", b"not json"),
}


def _write_exec(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    merged.pop("SYFT_BIN", None)
    merged.pop("TRIVY_BIN", None)
    merged.pop("GITHUB_OUTPUT", None)
    if env:
        merged.update(env)
    return subprocess.run(
        [str(a) for a in args],
        capture_output=True,
        text=True,
        env=merged,
        check=False,
    )


class GenerateImageSbom(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.syft = _write_exec(self.tmp / "syft", SYFT_STUB)
        self.addCleanup(self._tmp.cleanup)

    def generate(self, *extra: str, env: dict[str, str] | None = None, image: str = REF):
        out = self.tmp / "out.sbom.json"
        res = run(
            GENERATE,
            "--image",
            image,
            "--out",
            str(out),
            *extra,
            env={"SYFT_BIN": str(self.syft), **(env or {})},
        )
        return res, out

    def test_refuses_a_reference_that_is_not_digest_pinned(self) -> None:
        """The binding is the feature; a tag-keyed inventory describes
        whatever the tag pointed at when syft ran, which is not the thing a
        CVE question is about."""
        res, out = self.generate(image="ghcr.io/Xore/honeypot-backend-service:main")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("pinned by digest", res.stderr)
        self.assertFalse(out.exists(), "an unpinned reference must not leave an SBOM behind")

    def test_stamps_the_digest_into_the_document(self) -> None:
        res, out = self.generate()
        self.assertEqual(res.returncode, 0, res.stderr)
        component = json.loads(out.read_text())["metadata"]["component"]
        props = {p["name"]: p["value"] for p in component["properties"]}
        self.assertEqual(props["apiary:image-digest"], DIGEST)
        self.assertEqual(props["apiary:image-reference"], REF)
        # syft leaves `version` as the tag; a viewer that shows only
        # name/version has to be able to see which image this is.
        self.assertEqual(component["version"], DIGEST)

    def test_publishes_both_the_record_and_the_pointer(self) -> None:
        publish = self.tmp / "image-sbom"
        res, out = self.generate("--name", "backend-service", "--publish-dir", str(publish))
        self.assertEqual(res.returncode, 0, res.stderr)
        target = publish / "backend-service"
        self.assertTrue((target / f"{HEX}.sbom.json").is_file())
        self.assertTrue((target / "latest.sbom.json").is_file())
        for name in (f"{HEX}.sbom.json", "latest.sbom.json"):
            self.assertEqual(
                json.loads((target / name).read_text()),
                json.loads(out.read_text()),
                f"{name} must be the same document as the generated one",
            )

    def test_publish_needs_a_name_to_lay_the_store_out(self) -> None:
        publish = self.tmp / "image-sbom"
        res, _ = self.generate("--publish-dir", str(publish))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("needs --name", res.stdout)
        self.assertFalse(publish.exists())

    def test_unwritable_publish_dir_warns_and_still_leaves_the_artifact(self) -> None:
        """A homeserver without the provision-image-sbom step loses the
        local copy, not the build: the CI artifact is written first."""
        blocker = self.tmp / "not-a-dir"
        blocker.write_text("occupied\n", encoding="utf-8")
        res, out = self.generate("--name", "backend-service", "--publish-dir", str(blocker))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("SBOM not published to the homeserver", res.stdout)
        self.assertTrue(out.is_file() and out.stat().st_size > 0)

    def test_syft_failure_is_a_hard_failure(self) -> None:
        res, out = self.generate(env={"STUB_SYFT_FAIL": "1"})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("could not inventory", res.stderr)
        self.assertFalse(out.exists())

    def test_a_non_cyclonedx_document_is_rejected(self) -> None:
        syft = _write_exec(self.tmp / "syft-spdx", NOT_CYCLONEDX_STUB)
        res, _ = self.generate(env={"SYFT_BIN": str(syft)})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("bomFormat", res.stderr)

    def test_writes_actions_outputs_for_the_artifact_name(self) -> None:
        outputs = self.tmp / "gh-output"
        res, out = self.generate(
            "--name", "backend-service", env={"GITHUB_OUTPUT": str(outputs)}
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        written = dict(
            line.split("=", 1) for line in outputs.read_text().splitlines() if "=" in line
        )
        self.assertEqual(written["sbom_digest"], DIGEST)
        self.assertEqual(written["sbom_digest_hex"], HEX)
        self.assertEqual(written["sbom_ref"], REF)
        self.assertEqual(written["sbom_path"], str(out))
        # A colon is not a legal artifact-name character, so the hex form is
        # the one the workflow's upload step has to use.
        self.assertNotIn(":", written["sbom_digest_hex"])

    def test_output_keys_survive_as_github_expression_properties(self) -> None:
        """GitHub's expression grammar reads '-' as an operator, so
        steps.<id>.outputs.sbom-digest-hex is a subtraction, not a property
        lookup. The workflow reads these back by name."""
        outputs = self.tmp / "gh-output"
        self.generate(env={"GITHUB_OUTPUT": str(outputs)})
        for line in outputs.read_text().splitlines():
            key = line.split("=", 1)[0]
            self.assertRegex(key, r"^[A-Za-z_][A-Za-z0-9_]*$", f"{key!r} is not a usable property name")


class ScanImageSbom(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.sbom = self.tmp / "backend-service.sbom.json"
        self.sbom.write_text('{"bomFormat":"CycloneDX","components":[]}\n', encoding="utf-8")
        self.addCleanup(self._tmp.cleanup)

    def stub_trivy(self, kind: str) -> Path:
        rc, err, out = TRIVY_STUBS[kind]
        return _write_exec(
            self.tmp / f"trivy-{kind}",
            f"""#!/usr/bin/env bash
if [ "${{1:-}}" = "--version" ]; then echo "Version: 0.76.2"; exit 0; fi
cat >&2 <<'ERR'
{err.decode()}
ERR
printf '%s' {json.dumps(out.decode())}
exit {rc}
""",
        )

    def scan(self, kind: str):
        trivy = self.stub_trivy(kind)
        report = self.tmp / f"{kind}.trivy.json"
        res = run(
            SCAN,
            "--sbom",
            str(self.sbom),
            "--name",
            "backend-service",
            "--report",
            str(report),
            env={"TRIVY_BIN": str(trivy)},
        )
        return res, report

    def test_clean_sbom_says_so(self) -> None:
        res, report = self.scan("clean")
        self.assertEqual(res.returncode, 0)
        self.assertIn("no fixable CRITICAL/HIGH vulnerabilities", res.stdout)
        self.assertEqual(json.loads(report.read_text())["SchemaVersion"], 2)

    def test_findings_are_reported_without_failing_the_required_gate(self) -> None:
        """Report-only, like the base-image scan this mirrors. A CVE backlog
        must not redden main, and the finding has to be visible either way."""
        res, report = self.scan("flagged")
        self.assertEqual(res.returncode, 0)
        self.assertIn("Vulnerable image (from SBOM)", res.stdout)
        self.assertIn("not failing the build", res.stdout)
        self.assertEqual(
            json.loads(report.read_text())["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"],
            "CVE-2024-0001",
        )

    def test_an_unreadable_sbom_is_a_coverage_gap_not_a_vulnerability(self) -> None:
        """trivy exits non-zero for both, and they are opposite findings. One
        is a result; the other means we measured nothing."""
        res, report = self.scan("unreadable")
        self.assertEqual(res.returncode, 0)
        self.assertIn("Unscannable SBOM", res.stdout)
        self.assertNotIn("Vulnerable image", res.stdout)
        # The report still records that a scan was attempted and did not
        # complete -- an absent file would read as "nobody looked".
        self.assertIn("scan_error", json.loads(report.read_text())["apiary"])

    def test_a_missing_sbom_is_a_hard_error(self) -> None:
        res = run(SCAN, "--sbom", str(self.tmp / "absent.json"))
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("no such SBOM", res.stderr)

    def test_the_flags_match_the_base_image_scan(self) -> None:
        """Same policy as image-security-scan.yml, or a digest's finding and
        a base image's finding get graded two different ways."""
        trivy = self.stub_trivy("clean")
        recorder = self.tmp / "recorder"
        _write_exec(
            recorder,
            """#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then echo "Version: 0.76.2"; exit 0; fi
printf '%s\\n' "$@" >"$ARGS_FILE"
printf '{}'
""",
        )
        args_file = self.tmp / "args.txt"
        run(
            SCAN,
            "--sbom",
            str(self.sbom),
            env={"TRIVY_BIN": str(recorder), "ARGS_FILE": str(args_file)},
        )
        self.assertTrue(args_file.is_file(), "the trivy stub was never invoked")
        args = args_file.read_text().split()
        self.assertEqual(args[0], "sbom")
        for flag, value in (
            ("--scanners", "vuln"),
            ("--severity", "CRITICAL,HIGH"),
        ):
            self.assertIn(flag, args)
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--ignore-unfixed", args)
        self.assertIn("--exit-code", args)
        self.assertNotIn("--quiet", args, "--quiet would hide the log line that classifies the run")


class PruneImageSbom(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def seed(self, image: str, digests: list[str]) -> Path:
        target = self.root / image
        target.mkdir(parents=True, exist_ok=True)
        for i, digest in enumerate(digests):
            # mtime ordering is what prune-image-sbom.sh sorts on, so make
            # the list order the age order explicitly.
            path = target / f"{digest}.sbom.json"
            path.write_text(json.dumps({"digest": digest}), encoding="utf-8")
            os.utime(path, (1_700_000_000 + i, 1_700_000_000 + i))
        return target

    def test_keeps_the_newest_and_drops_the_tail(self) -> None:
        digests = [f"{i:064x}" for i in range(5)]
        target = self.seed("dashboard-next", digests)
        res = run(PRUNE, str(self.root), env={"KEEP": "2"})
        self.assertEqual(res.returncode, 0, res.stderr)
        remaining = sorted(p.name for p in target.glob("*.sbom.json"))
        self.assertEqual(
            remaining,
            sorted([f"{digests[3]}.sbom.json", f"{digests[4]}.sbom.json", "latest.sbom.json"]),
        )

    def test_latest_points_at_a_digest_that_still_exists(self) -> None:
        """A latest.sbom.json naming a pruned digest is worse than none: it
        looks authoritative and is wrong."""
        digests = [f"{i:064x}" for i in range(4)]
        target = self.seed("dashboard-next", digests)
        run(PRUNE, str(self.root), env={"KEEP": "1"})
        latest = json.loads((target / "latest.sbom.json").read_text())
        self.assertEqual(latest["digest"], digests[-1])
        self.assertTrue((target / f"{digests[-1]}.sbom.json").is_file())

    def test_records_are_per_image(self) -> None:
        a = self.seed("dashboard-next", [f"{i:064x}" for i in range(3)])
        b = self.seed("backend-service", [f"{i:064x}" for i in range(3)])
        run(PRUNE, str(self.root), env={"KEEP": "1"})
        self.assertEqual(len(list(a.glob("[0-9a-f]*.sbom.json"))), 1)
        self.assertEqual(len(list(b.glob("[0-9a-f]*.sbom.json"))), 1)

    def test_absent_root_is_not_an_error(self) -> None:
        res = run(PRUNE, str(self.root / "never-provisioned"))
        self.assertEqual(res.returncode, 0)
        self.assertIn("nothing to do", res.stdout)


class InstallTrivy(unittest.TestCase):
    def test_explicit_binary_is_used_verbatim(self) -> None:
        """scan-image-sbom.sh depends on this, and a test depends on that."""
        stub = _write_exec(
            self._tmp_path() / "trivy", '#!/usr/bin/env bash\necho "Version: 0.76.2"\n'
        )
        res = run(INSTALL_TRIVY, "--print-path", env={"TRIVY_BIN": str(stub)})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), str(stub))

    def test_a_version_override_without_a_checksum_is_refused(self) -> None:
        """Otherwise the pinned sha256 would be reused for a different
        release, and the guard would be a lie."""
        res = run(INSTALL_TRIVY, "--print-path", env={"TRIVY_VERSION": "0.99.0"})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("no pinned sha256", res.stderr)

    def _tmp_path(self) -> Path:
        if not hasattr(self, "_tmpdir"):
            self._tmpdir = tempfile.TemporaryDirectory()
            self.addCleanup(self._tmpdir.cleanup)
        return Path(self._tmpdir.name)


if __name__ == "__main__":
    unittest.main()
