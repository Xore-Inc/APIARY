#!/usr/bin/env python3
"""Tests for scripts/check-swarm-images.py (#3597).

Four groups:

* stack lint, against the committed fixtures (one passing file, one with
  `build:`, one with `:latest`, one with an untagged name) copied into the
  default `swarm/stacks/<name>/stack.yml` layout, so the glob constant is
  exercised too;
* completeness, against small synthetic repositories, so each failure mode
  (missing row, wrong Dockerfile, build-arg drift, forked shared context,
  stale exemption) is proven in isolation;
* scope and manifest, as pure functions with an injected registry;
* the real tree: every compose build context has a row today.

Needs PyYAML, like the script (the CI step installs it).

Usage: python3 -m unittest scripts/tests/test_3597_swarm_images.py
"""
import importlib.util
import json
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parent.parent / "check-swarm-images.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "swarm-stacks"
REPO = Path(__file__).resolve().parents[2]

spec = importlib.util.spec_from_file_location("check_swarm_images", SCRIPT)
mod = importlib.util.module_from_spec(spec)
# dataclasses resolves string annotations through sys.modules.
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

WORKFLOW = ".github/workflows/containers.yml"


def write(root: Path, rel: str, text: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


class StackLint(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def install(self, *names):
        for name in names:
            dest = self.tmp / "swarm" / "stacks" / name
            dest.mkdir(parents=True)
            shutil.copy(FIXTURES / name / "stack.yml", dest / "stack.yml")

    def lint(self):
        return mod.check_stacks(self.tmp)

    def test_default_glob_is_the_layout_3590_names(self):
        self.assertIn("swarm/stacks/*/stack.yml", mod.SWARM_STACK_GLOBS)

    def test_no_stack_directory_yet_passes(self):
        errors, files = self.lint()
        self.assertEqual((errors, files), ([], []))

    def test_pinned_stack_passes_including_tag_at_digest(self):
        self.install("good")
        errors, files = self.lint()
        self.assertEqual(errors, [])
        self.assertEqual(len(files), 1)

    def test_build_is_rejected_even_next_to_a_pinned_image(self):
        self.install("build")
        errors, _ = self.lint()
        self.assertTrue(any("build:" in e for e in errors), errors)

    def test_latest_tag_is_rejected(self):
        self.install("latest")
        errors, _ = self.lint()
        self.assertTrue(any(":latest" in e and "not pinned" in e for e in errors), errors)

    def test_untagged_name_is_rejected(self):
        self.install("untagged")
        errors, _ = self.lint()
        self.assertTrue(any("not pinned" in e for e in errors), errors)

    def test_one_bad_file_fails_the_whole_run_and_names_it(self):
        self.install("good", "latest")
        errors, files = self.lint()
        self.assertEqual(len(files), 2)
        self.assertEqual(len(errors), 1)
        self.assertIn("swarm/stacks/latest/stack.yml", errors[0])

    def test_short_and_interpolated_digests_are_rejected(self):
        for image in ("repo/x@sha256:abc", "repo/x@sha256:" + "A" * 64, "repo/x@sha256:${DIGEST}"):
            with self.subTest(image=image):
                write(self.tmp, "swarm/stacks/t/stack.yml", f"services:\n  a:\n    image: '{image}'\n")
                errors, _ = self.lint()
                self.assertEqual(len(errors), 1, errors)

    def test_service_without_image_or_build_is_rejected(self):
        write(self.tmp, "swarm/stacks/t/stack.yml", "services:\n  a:\n    command: x\n")
        errors, _ = self.lint()
        self.assertTrue(any("no `image:`" in e for e in errors), errors)

    def test_yaml_extension_is_matched(self):
        write(self.tmp, "swarm/stacks/t/stack.yaml", "services:\n  a:\n    image: repo/x:latest\n")
        errors, files = self.lint()
        self.assertEqual(len(files), 1)
        self.assertEqual(len(errors), 1)


def minimal_repo(root: Path, rows: list, compose: str, dockerfile: str = "FROM scratch\n") -> None:
    workflow = {"jobs": {"build": {"strategy": {"matrix": {"include": rows}}}}}
    write(root, WORKFLOW, yaml.safe_dump(workflow))
    write(root, "stack/compose.yml", compose)
    write(root, "stack/app/Dockerfile", dockerfile)
    write(root, "stack/app/main.sh", "echo hi\n")


def row(image="app", context="stack/app", **extra) -> dict:
    return {"image": image, "context": context, **extra}


ROW = [row()]
COMPOSE = "services:\n  app:\n    build: ./app\n"


class Completeness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_check(self, exempt=None):
        # Synthetic repos start with no exemptions: the real ones name paths
        # that exist only in the real tree.
        return mod.check_completeness(self.tmp, exempt={} if exempt is None else exempt)[0]

    def test_covered_context_passes(self):
        minimal_repo(self.tmp, ROW, COMPOSE)
        self.assertEqual(self.run_check(), [])

    def test_context_without_row_fails_and_names_the_service(self):
        minimal_repo(self.tmp, [row("other", "stack/other")], COMPOSE)
        write(self.tmp, "stack/other/Dockerfile", "FROM scratch\n")
        errors = self.run_check()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("stack/compose.yml service app", errors[0])
        self.assertIn("no row", errors[0])

    def test_services_sharing_a_context_share_one_row(self):
        minimal_repo(self.tmp, ROW, COMPOSE + "  twin:\n    build:\n      context: ./app\n")
        self.assertEqual(self.run_check(), [])

    def test_dockerfile_mismatch_fails(self):
        minimal_repo(self.tmp, ROW, "services:\n  app:\n    build:\n      context: ./app\n      dockerfile: Containerfile\n")
        write(self.tmp, "stack/app/Containerfile", "FROM scratch\n")
        errors = self.run_check()
        self.assertTrue(any("Containerfile" in e for e in errors), errors)

    def test_row_dockerfile_matches_compose_dockerfile(self):
        minimal_repo(
            self.tmp,
            [row(dockerfile="Containerfile")],
            "services:\n  app:\n    build:\n      context: ./app\n      dockerfile: Containerfile\n",
        )
        write(self.tmp, "stack/app/Containerfile", "FROM scratch\n")
        self.assertEqual(self.run_check(), [])

    def test_target_mismatch_fails(self):
        minimal_repo(self.tmp, ROW, "services:\n  app:\n    build:\n      context: ./app\n      target: prod\n")
        self.assertTrue(any("target" in e for e in self.run_check()))

    def test_build_arg_equal_to_dockerfile_default_passes(self):
        minimal_repo(
            self.tmp, ROW,
            "services:\n  app:\n    build:\n      context: ./app\n      args:\n        PORT: '8080'\n",
            "FROM scratch\nARG PORT=8080\n",
        )
        self.assertEqual(self.run_check(), [])

    def test_build_arg_that_changes_the_image_fails(self):
        minimal_repo(
            self.tmp, ROW,
            "services:\n  app:\n    build:\n      context: ./app\n      args:\n        PORT: '9090'\n",
            "FROM scratch\nARG PORT=8080\n",
        )
        errors = self.run_check()
        self.assertTrue(any("PORT" in e and "different image" in e for e in errors), errors)

    def test_git_sha_arg_needs_stamp(self):
        compose = "services:\n  app:\n    build:\n      context: ./app\n      args:\n        GIT_SHA: ${GIT_SHA:-}\n"
        minimal_repo(self.tmp, ROW, compose)
        self.assertTrue(any("stamp" in e for e in self.run_check()))
        minimal_repo(self.tmp, [row(stamp=True)], compose)
        self.assertEqual(self.run_check(), [])

    def test_interpolated_context_fails(self):
        minimal_repo(self.tmp, ROW, "services:\n  app:\n    build: ${CTX}\n")
        self.assertTrue(any("interpolated" in e for e in self.run_check()))

    def test_also_contexts_must_be_byte_identical(self):
        compose = "services:\n  app:\n    build: ./app\n  copy:\n    build: ./copy\n"
        minimal_repo(self.tmp, [row(also_contexts="stack/copy")], compose)
        write(self.tmp, "stack/copy/Dockerfile", "FROM scratch\n")
        write(self.tmp, "stack/copy/main.sh", "echo hi\n")
        self.assertEqual(self.run_check(), [])
        write(self.tmp, "stack/copy/main.sh", "echo changed\n")
        errors = self.run_check()
        self.assertTrue(any("not byte-identical" in e for e in errors), errors)

    def test_stale_row_without_dockerfile_fails(self):
        minimal_repo(self.tmp, ROW + [row("gone", "stack/gone")], COMPOSE)
        self.assertTrue(any("stale row" in e for e in self.run_check()))

    def test_duplicate_image_name_fails(self):
        minimal_repo(self.tmp, ROW + [row("app", "stack/app2")], COMPOSE)
        write(self.tmp, "stack/app2/Dockerfile", "FROM scratch\n")
        self.assertTrue(any("duplicate" in e for e in self.run_check()))

    def test_unreferenced_exemption_fails(self):
        minimal_repo(self.tmp, ROW, COMPOSE)
        errors = self.run_check({"stack/nowhere": "test"})
        self.assertTrue(any("EXEMPT_CONTEXTS" in e for e in errors), errors)

    def test_exempt_context_needs_no_row(self):
        minimal_repo(self.tmp, [row("other", "stack/other")], COMPOSE)
        write(self.tmp, "stack/other/Dockerfile", "FROM scratch\n")
        self.assertEqual(self.run_check({"stack/app": "test"}), [])

    def test_vendored_and_fixture_composes_are_not_scanned(self):
        minimal_repo(self.tmp, ROW, COMPOSE)
        write(self.tmp, "stack/vendor/up/docker-compose.yml", "services:\n  x:\n    build: .\n")
        write(self.tmp, "swarm/stacks/t/stack.yml", "services:\n  x:\n    build: .\n")
        self.assertEqual(self.run_check(), [])


class ScopeAndManifest(unittest.TestCase):
    ROWS = [
        mod.Row("old", "a/old"),
        mod.Row("one", "a/one", scoped=True),
        mod.Row("two", "b/two", scoped=True, also_contexts=["c/two-copy"]),
    ]

    def test_non_pr_events_build_every_scoped_row(self):
        for event in ("push", "workflow_dispatch"):
            self.assertEqual(mod.scoped_images(self.ROWS, event, ["a/one/x"]), ["one", "two"])

    def test_pr_builds_only_touched_contexts(self):
        self.assertEqual(mod.scoped_images(self.ROWS, "pull_request", ["a/one/Dockerfile"]), ["one"])
        self.assertEqual(mod.scoped_images(self.ROWS, "pull_request", ["c/two-copy/x"]), ["two"])
        self.assertEqual(mod.scoped_images(self.ROWS, "pull_request", ["docs/x.md"]), [])

    def test_prefix_is_a_directory_not_a_string_prefix(self):
        self.assertEqual(mod.scoped_images(self.ROWS, "pull_request", ["a/one-extra/x"]), [])

    def test_workflow_change_or_unknown_diff_builds_everything(self):
        self.assertEqual(mod.scoped_images(self.ROWS, "pull_request", [WORKFLOW]), ["one", "two"])
        self.assertEqual(mod.scoped_images(self.ROWS, "pull_request", None), ["one", "two"])

    def test_manifest_records_the_registry_digest_per_image(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        minimal_repo(tmp, ROW, COMPOSE)
        seen = []

        def resolve(ref):
            seen.append(ref)
            return "sha256:" + "b" * 64

        manifest = mod.build_manifest(tmp, "Example-Org", "0123456789abcdef", resolve)
        self.assertEqual(seen, ["ghcr.io/example-org/honeypot-app:sha-0123456"])
        info = manifest["images"]["app"]
        self.assertEqual(info["ref"], "ghcr.io/example-org/honeypot-app@sha256:" + "b" * 64)
        self.assertEqual(info["compose_services"], ["stack/compose.yml:app"])
        self.assertEqual(manifest["schema"], 1)
        json.dumps(manifest)  # machine-readable
        self.assertIn(info["ref"], mod.manifest_markdown(manifest))

    def test_manifest_refuses_a_non_digest(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        minimal_repo(tmp, ROW, COMPOSE)
        with self.assertRaises(RuntimeError):
            mod.build_manifest(tmp, "o", "0123456", lambda ref: "latest")


class RealTree(unittest.TestCase):
    def test_every_compose_build_context_has_a_ghcr_row(self):
        errors, report = mod.check_completeness(REPO)
        self.assertEqual(errors, [], "\n".join(errors))
        self.assertTrue(report)

    def test_repo_has_no_unpinned_stack_files(self):
        errors, _ = mod.check_stacks(REPO)
        self.assertEqual(errors, [], "\n".join(errors))

    def test_scoped_rows_exist_and_image_names_are_unique(self):
        rows = mod.matrix_rows(REPO)
        names = [r.image for r in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreater(sum(r.scoped for r in rows), 20)


if __name__ == "__main__":
    unittest.main()
