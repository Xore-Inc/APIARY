#!/usr/bin/env python3
"""Exercise the #3315 revision stamp end to end, without a live host.

Three things this covers, and why each needs its own harness:

* The shared revision corpus -- backend-service's normalizer is held to it.
  (frontend-next's write-build-info.mjs, the JavaScript twin it was the
  comparison for, left with #3749.)

* The Dockerfile/compose wiring -- asserted as text. Neither cargo nor vitest
  can see that `ARG GIT_SHA` is declared in *both* stages of a multi-stage
  build, or that the label lands on the runtime image rather than the discarded
  build stage. Those are the ways this feature can exist in the repository
  and not exist in any image, and they are silent.

* `scripts/verify-deploy.sh` -- driven against a real throwaway git repo with
  stub `curl`/`docker` binaries, because the script's whole value is the
  verdict it returns, and a verdict is not worth much if the only thing anyone
  ever checks is that the file parses.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-deploy.sh"
# #3749: frontend-next (its write-build-info.mjs, Dockerfile and compose
# service) is gone; the backend image is the only stamped one left.
BACKEND_DOCKERFILE = ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "Dockerfile"
BACKEND_COMPOSE = ROOT / "arcane" / "home" / "honeypot-dashboard-backend" / "compose.yml"
BACKEND_ENV_EXAMPLE = ROOT / "arcane" / "home" / "honeypot-dashboard-backend" / ".env.example"
BUILD_RS = ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "build.rs"
BACKEND_SRC = ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "src"
# #3325 moved every backend-service module and the route table out of
# `src/main.rs` and into `src/lib.rs`, so the crate root is `lib.rs` and
# `main.rs` keeps only what is genuinely a process: the environment, the
# #2183 boot gate, state construction, the listener. `normalize_revision`,
# `REVISION_UNKNOWN` and the test module that pins them to the shared corpus
# all moved with the rest, so that is the file this reads.
#
# One named file rather than a scan of the tree, deliberately: an assertion
# against the whole of `src/` dumps every module into the failure message
# when it trips, and a multi-thousand-line diff for "the include_str! moved"
# is the kind of report that gets skimmed rather than read. If the next move
# relocates these again, the assertion fails with the file it looked in --
# which is the whole signal this test is for.
LIB_RS = BACKEND_SRC / "lib.rs"
CORPUS_JSON = ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service" / "src" / "revision-corpus.json"
CONTAINERS_YML = ROOT / ".github" / "workflows" / "containers.yml"

FULL = "3dca4457f1b2c0d4e5a69788796a5b4c3d2e1f0ab"


def load_corpus() -> tuple[str, list[tuple[str, str]]]:
    """The one table both normalizers are held to, read from the repo.

    backend-service's normalize_revision is Rust and lives in a cargo test
    lane; the corpus is a fixture rather than a literal list so another
    implementation can be held to the same cases.
    """
    doc = json.loads(CORPUS_JSON.read_text(encoding="utf-8"))
    return doc["unknown"], [tuple(case) for case in doc["cases"]]


UNKNOWN, CORPUS = load_corpus()


def run(*args: str, env: dict[str, str] | None = None, cwd: Path | None = None):
    merged = dict(os.environ)
    for leaked in ("CURL_BIN", "DOCKER_BIN", "PYTHON_BIN", "GIT_BIN", "GIT_SHA", "GIT_SOURCE"):
        merged.pop(leaked, None)
    if env:
        merged.update(env)
    return subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, env=merged, cwd=cwd, check=False
    )


def write_exec(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class NormalizerParity(unittest.TestCase):
    """The JS and Rust normalizers are one rule in two languages."""

    def test_the_rust_side_is_held_to_the_same_table(self) -> None:
        # backend-service/src/lib.rs is a different CI lane with a different
        # toolchain, and its own test module is the only thing that pins
        # normalize_revision. What makes the two sides comparable is that both
        # read the same file: if the Rust test ever drifts to a literal list of
        # its own, the disagreement becomes invisible again. The failure mode
        # is subtle -- the two tiers stamping different strings for the same
        # build, which verify-deploy.sh would then report as a disagreement
        # that is not one.
        self.assertIn(
            'include_str!("revision-corpus.json")',
            LIB_RS.read_text(encoding="utf-8"),
            "the Rust normalizer is no longer pinned to the shared corpus",
        )
        # A stubbed-out corpus would pass every assertion above it.
        self.assertGreaterEqual(len(CORPUS), 10, "the shared corpus has been hollowed out")
        self.assertEqual(UNKNOWN, "unknown", "both sides spell the sentinel the same way")
        self.assertIn(
            f'pub const REVISION_UNKNOWN: &str = "{UNKNOWN}"',
            LIB_RS.read_text(encoding="utf-8"),
        )
        # Internal coherence: every expectation is either the sentinel or a
        # value the rule accepts unchanged. Anything else is a case one side
        # could not produce and the table would be describing a third
        # normalizer nobody implements.
        hexdigits = set("0123456789abcdef")
        for raw_value, expected in CORPUS:
            with self.subTest(git_sha=raw_value):
                self.assertTrue(
                    expected == UNKNOWN or (7 <= len(expected) <= 64 and set(expected) <= hexdigits),
                    f"corpus expects {expected!r}, which is neither the sentinel nor an object name",
                )

    def test_the_rust_build_script_passes_the_arg_through(self) -> None:
        build_rs = BUILD_RS.read_text(encoding="utf-8")
        # Without rerun-if-env-changed, a second build of an identical tree with
        # a different GIT_SHA reuses the first one's compiled-in revision --
        # the exact "green, running the old code" shape this issue is about,
        # produced by the fix itself.
        self.assertIn("cargo:rerun-if-env-changed=GIT_SHA", build_rs)
        self.assertIn("APIARY_GIT_SHA", build_rs)


class DockerfileWiring(unittest.TestCase):
    """The three ways this can be in the repo and in no image."""

    @staticmethod
    def stages(text: str) -> list[str]:
        """One entry per `FROM` line, preamble excluded.

        Splitting on "\\nFROM " is wrong for a real Dockerfile: the header
        comment block means the text before the first FROM is a real, non-empty
        chunk, so the naive split counts a stage that does not exist and every
        index is off by one.
        """
        parts = re.split(r"(?m)^FROM\s+", text)
        return parts[1:]

    def test_backend_declares_the_arg_in_both_stages(self) -> None:
        # Docker scopes an ARG to the stage that declares it. The build stage
        # needs it (build.rs compiles it in); the runtime stage needs it again
        # for the label. Declaring it once is the mistake this pins.
        for name, path in (("backend", BACKEND_DOCKERFILE),):
            with self.subTest(image=name):
                parts = self.stages(path.read_text(encoding="utf-8"))
                self.assertEqual(len(parts), 2, f"{name}: expected a two-stage build")
                for index, part in enumerate(parts):
                    self.assertRegex(
                        part, r"(?m)^ARG GIT_SHA$", f"{name}: stage {index} does not declare ARG GIT_SHA"
                    )

    def test_both_images_carry_the_oci_revision_label(self) -> None:
        # `Labels: null` on apiary-backend:latest is the state this issue was
        # filed about; the label is what replaces it.
        for name, path in (("backend", BACKEND_DOCKERFILE),):
            with self.subTest(image=name):
                text = path.read_text(encoding="utf-8")
                # On the runtime stage, not the build stage: a label on a stage
                # that is never pushed is a label nobody can read.
                runtime = self.stages(text)[-1]
                self.assertIn('org.opencontainers.image.revision="${GIT_SHA:-unknown}"', runtime)
                self.assertIn('org.opencontainers.image.source="${GIT_SOURCE}"', runtime)
                self.assertIn('org.opencontainers.image.created="${BUILD_DATE:-unknown}"', runtime)


class ComposeWiring(unittest.TestCase):
    def test_both_stacks_pass_the_arg_to_their_build(self) -> None:
        for name, path in (("honeypot-dashboard-backend", BACKEND_COMPOSE),):
            with self.subTest(stack=name):
                self.assertIn("GIT_SHA: ${GIT_SHA:-}", path.read_text(encoding="utf-8"))

    def test_both_env_examples_document_the_knob(self) -> None:
        # scripts/check-compose-env-docs.py already gates this; asserting it
        # here too means the gate's own failure explains what the knob is for.
        for name, path in (("honeypot-dashboard-backend", BACKEND_ENV_EXAMPLE),):
            with self.subTest(stack=name):
                self.assertRegex(path.read_text(encoding="utf-8"), r"(?m)^GIT_SHA=")

    def test_the_short_form_compose_still_validates(self) -> None:
        if shutil.which("docker") is None:
            self.skipTest("docker is not available to render compose config")
        for name, path, workdir in (
            ("honeypot-dashboard-backend", BACKEND_COMPOSE, BACKEND_COMPOSE.parent),
        ):
            with self.subTest(stack=name):
                res = run("docker", "compose", "-f", path, "config", "--quiet", cwd=workdir)
                self.assertEqual(res.returncode, 0, res.stderr)

    def test_ci_passes_the_same_sha_the_labels_already_carry(self) -> None:
        # metadata-action already stamps an org.opencontainers.revision on
        # every image this workflow pushes. Passing GIT_SHA as well is what
        # makes the compiled-in /healthz value and the image label come from
        # one source instead of two that can drift.
        text = CONTAINERS_YML.read_text(encoding="utf-8")
        self.assertIn("stamp: true", text)
        self.assertEqual(
            text.count("stamp: true"),
            1,
            "exactly the backend Dockerfile declares ARG GIT_SHA (#3749: dashboard-next is gone)",
        )
        self.assertIn("format('GIT_SHA={0}', github.sha)", text)


class VerifyDeploy(unittest.TestCase):
    """verify-deploy.sh, against a real repo and stub curl/docker."""

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("git") is None:
            raise unittest.SkipTest("git is not on PATH")
        if shutil.which("python3") is None:
            raise unittest.SkipTest("python3 is not on PATH")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "verify-deploy test")
        self.write_file("a", "one")
        self.git("add", "-A")
        # The first commit is backdated, because the lag check measures the age
        # of the *deployed commit* rather than the age of the container. A
        # fixture made entirely of commits written "now" has no age to measure,
        # so every lag assertion here would be testing a zero.
        thirty_days_ago = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self.git(
            "commit", "-qm", "one",
            env={"GIT_AUTHOR_DATE": thirty_days_ago, "GIT_COMMITTER_DATE": thirty_days_ago},
        )
        self.first = self.rev()
        self.write_file("a", "two")
        self.git("commit", "-qam", "two")
        self.head = self.rev()
        self.git("update-ref", "refs/remotes/origin/main", self.head)

    def git(self, *args: str, env: dict[str, str] | None = None) -> str:
        res = run("git", "-C", self.repo, *args, env=env or {})
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout.strip()

    def rev(self) -> str:
        return self.git("rev-parse", "HEAD")

    def write_file(self, name: str, body: str) -> None:
        (self.repo / name).write_text(body, encoding="utf-8")

    def healthz(self, body: str) -> str:
        """A --healthz-exec that answers `body` verbatim."""
        return f"printf '%s' {json.dumps(body)}"

    def check(self, *args: str, env: dict[str, str] | None = None):
        return run(
            SCRIPT, "--repo-root", self.repo, *args, env=env or {}, cwd=self.tmp
        )

    def docker_stub(self, label: str, exists: bool = True) -> Path:
        return write_exec(
            self.tmp / "docker",
            f"""#!/usr/bin/env bash
# Stub for the two `docker image inspect` shapes verify-deploy.sh uses: the
# --format label read, and the plain existence probe behind it.
if [ "${{1:-}}" = "image" ] && [ "${{2:-}}" = "inspect" ]; then
  if [ "${{3:-}}" = "--format" ]; then
    printf '%s\\n' {json.dumps(label)}
    exit 0
  fi
  exit {0 if exists else 1}
fi
exit 1
""",
        )

    # ---- the verdict is the product ----

    def test_a_deploy_at_main_passes(self) -> None:
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'), "--behind-days", "0")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("PASS", res.stdout)

    def test_a_stale_deploy_fails_and_says_by_how_much(self) -> None:
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{self.first}"}}'), "--behind-days", "0")
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn(f"deployed {self.first}", res.stdout)
        self.assertIn(f"expected {self.head}", res.stdout)

    def test_a_short_revision_is_not_a_mismatch(self) -> None:
        # `git rev-parse --short HEAD` is what an operator reaches for first.
        # Reporting it as a wrong deploy on every run would teach people to
        # ignore the tool.
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{self.head[:7]}"}}'), "--behind-days", "0")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("abbreviation", res.stdout)

    def test_an_unstamped_deploy_fails_loudly(self) -> None:
        # The state this whole issue was filed about, stated as a failure
        # rather than as a pass with nothing to report.
        res = self.check("--healthz-exec", self.healthz('{"revision":"unknown"}'), "--behind-days", "0")
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("not stamped", res.stdout)

    def test_a_malformed_revision_is_distinguished_from_a_stale_one(self) -> None:
        # A value that is not an object name is a broken stamp, and telling an
        # operator their deploy is merely out of date sends them to rebuild
        # instead of to find whoever passed "main" as a revision.
        res = self.check("--healthz-exec", self.healthz('{"revision":"main"}'), "--behind-days", "0")
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("not a git object name", res.stdout)

    def test_a_stale_but_matching_deploy_is_still_flagged_by_the_lag_check(self) -> None:
        # Pinning an explicit expected revision and finding it deployed exactly
        # is a legitimate "yes, that is the release we chose" answer. Lag is
        # then the only thing left to say, so it has to be measured from the
        # commit rather than from the container's creation time.
        old = self.git("rev-parse", self.first)
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{old}"}}'), old, "--behind-days", "3")
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("commits behind", res.stdout)

    def test_a_deploy_at_main_is_not_behind(self) -> None:
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("at or ahead", res.stdout)

    def test_a_revision_this_clone_has_never_seen_is_reported_not_guessed(self) -> None:
        absent = "deadbeef" * 5
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{absent}"}}'))
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("not in this clone", res.stdout)
        # No invented commit count: the honest answer is that it cannot be
        # measured, not that it is current.
        self.assertNotIn("commits behind", res.stdout)

    def test_lag_can_be_switched_off(self) -> None:
        # A host that has not fetched origin, or a caller measuring one image
        # against a fixed expected revision, should not be forced to have a
        # lag answer.
        absent = "deadbeef" * 5
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{absent}"}}'), absent, "--behind-days", "0")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertNotIn("not in this clone", res.stdout)

    def test_warn_only_reports_without_failing(self) -> None:
        # The mode diagnostics.yml uses: this workflow's own red X is the
        # alert, and a stale deploy is not on #2222's list of things that
        # should redden a scheduled run.
        res = self.check(
            "--healthz-exec", self.healthz('{"revision":"unknown"}'), "--behind-days", "0", "--warn-only"
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("not stamped", res.stdout)

    # ---- "could not tell" must never read as "it is fine" ----

    def test_an_unreadable_body_exits_two_not_one(self) -> None:
        # Traefik's 401 page, an HTML error from a wrong port, a plain "ok"
        # from a different service: all of them are this script being pointed
        # at the wrong thing. Exiting 1 would report them as a stale deploy.
        for body in ("ok", "<html>nope</html>", '{"ok":true,"es":true}', "[]"):
            with self.subTest(body=body):
                res = self.check("--healthz-exec", self.healthz(body), "--behind-days", "0")
                self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_an_unreachable_endpoint_exits_two(self) -> None:
        res = self.check("--healthz-url", "http://127.0.0.1:1/healthz", "--behind-days", "0")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)

    def test_no_endpoint_at_all_is_a_usage_error(self) -> None:
        res = self.check()
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("nothing to check", res.stderr)

    def test_a_branch_name_is_refused_as_the_expected_revision(self) -> None:
        # "Is main deployed?" is the question; "main" is not the answer to it,
        # and resolving it here would make the tool's own comparison circular.
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'), "main")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("not a git object name", res.stderr)

    def test_a_missing_origin_main_says_how_to_fix_it(self) -> None:
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        res = self.check("--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'))
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("fetch origin main", res.stderr)

    def test_a_nonsense_lag_threshold_is_refused(self) -> None:
        res = self.check("--healthz-exec", self.healthz("{}"), "--behind-days", "soon")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("whole number of days", res.stderr)

    def test_two_expected_revisions_are_refused(self) -> None:
        res = self.check("--healthz-exec", self.healthz("{}"), self.head, self.first)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("only one expected revision", res.stderr)

    def test_help_prints_the_headers_own_usage(self) -> None:
        # A help text that has drifted from the flags is worse than none, and
        # this one is generated from the header so it cannot.
        res = run(SCRIPT, "--help")
        self.assertEqual(res.returncode, 0)
        for flag in ("--healthz-url", "--healthz-exec", "--image", "--repo-root", "--behind-days", "--warn-only"):
            self.assertIn(flag, res.stdout)

    # ---- the image label half ----

    def test_the_image_label_is_checked_too(self) -> None:
        res = self.check(
            "--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'),
            "--image", "apiary-backend:latest", "--behind-days", "0",
            env={"DOCKER_BIN": str(self.docker_stub(self.head))},
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_an_image_whose_label_disagrees_with_the_running_container_is_a_finding(self) -> None:
        # The failure this catches is real and cheap to miss by eye: a
        # `docker compose up` that recreated a container from an older image
        # than the one whose label an operator just read.
        res = self.check(
            "--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'),
            "--image", "apiary-backend:latest", "--behind-days", "0",
            env={"DOCKER_BIN": str(self.docker_stub(self.first))},
        )
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn(f"deployed {self.first}", res.stdout)

    def test_an_image_with_no_revision_label_names_the_missing_build_arg(self) -> None:
        res = self.check(
            "--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'),
            "--image", "apiary-backend:latest", "--behind-days", "0",
            env={"DOCKER_BIN": str(self.docker_stub(""))},
        )
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("GIT_SHA", res.stdout)

    def test_a_missing_image_is_not_reported_as_an_unstamped_one(self) -> None:
        # Two different facts with the same evidence (an empty label): the
        # image is not on this host, versus it was built without the arg. The
        # first is a wrong flag, the second is a rebuild.
        res = self.check(
            "--healthz-exec", self.healthz(f'{{"revision":"{self.head}"}}'),
            "--image", "nope:latest", "--behind-days", "0",
            env={"DOCKER_BIN": str(self.docker_stub("", exists=False))},
        )
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("no such image", res.stderr)

    def test_the_curl_path_is_driven_through_the_same_comparison(self) -> None:
        # --healthz-exec is the form this fleet needs (backend-service
        # publishes no port), but the HTTP form is what a proxied dashboard
        # gives, and both must reach the same verdict.
        stub = write_exec(
            self.tmp / "curl",
            f"""#!/usr/bin/env bash
# Stub: the real curl is called with -sf --max-time 10 <url>.
printf '%s\\n' {json.dumps(f'{{"revision":"{self.head}"}}')}
""",
        )
        res = self.check(
            "--healthz-url", "http://dashboard.invalid/healthz", "--behind-days", "0",
            env={"CURL_BIN": str(stub)},
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
