#!/usr/bin/env python3
"""A stored run has to say what its answers actually are, and the enum has to
be able to say it.

`docs/benchmarks/runs/2026-10-02-20261002T192742Z-052d890b/` holds five real
coder answers produced by a live Ollama model (qwen2.5-coder-7b-base) on the
homeserver, and its `run.json` labelled them `provenance: "synthetic"`. That is
the false label: `synthetic` is transcripts.py's class for #159's corpus
binaries and this benchmark's own fixtures, the ones committed to the repo
because there is no secret in them. Reading a live run's answers as fixture
answers is exactly the mistake that lets a fabricated-looking measurement pass
unexamined, and it is silent -- nothing downstream checks the field, so a wrong
label simply propagates into whatever analysis reads the run later.

Relabelling it `captured` was also wrong, and for a reason that is enforced in
code rather than by convention. `captured` means the *input* was real honeypot
data; `TranscriptWriter.__init__` (transcripts.py:249) refuses to write a
`captured` run inside the repository because real transcripts carry attacker IPs
and payloads. This run has no such input: its prompts are the committed
`coder_cases_v1` fixtures and hold zero IPv4 addresses. Only the ANSWERS are
live.

So the enum grows a third member for that case -- `live_model`, synthetic input
and live answers -- which is committable *because its input is synthetic* and is
not a rename of `captured`. `PROVENANCE_LIVE_MODEL` is an enum member, not a
private string, so `RunMetadata.__post_init__`'s existing membership check is
still the validator and a value outside the tuple raises.

Two things this deliberately does not do:

- It does not edit `transcripts.jsonl`. `docs/benchmarks/runs/README.md`,
  "Rules", forbids it -- a stored transcript is superseded by a new run, never
  rewritten -- and the per-record `provenance` each line carries was stamped
  from the run metadata at write time, so it is left reading `synthetic` in a
  run whose `run.json` now says `live_model`. The directory is internally
  inconsistent by that much, and it is a known, bounded one: 5 records, and the
  answer text is untouched.
- It does not touch the recorded `transcripts_sha256`. Because the transcript
  is unchanged, the honest value is the one already there, and the test below
  re-verifies it, so the guard cannot be satisfied by recomputing a hash over a
  rewritten file.
"""

import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(Path(__file__).resolve().parents[1] / "evaluate-models.py")
)
evaluate_models = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("evaluate_models", evaluate_models)
_spec.loader.exec_module(evaluate_models)

import transcripts  # noqa: E402
from transcripts import (  # noqa: E402
    PROVENANCE_CAPTURED,
    PROVENANCE_LIVE_MODEL,
    PROVENANCE_SYNTHETIC,
    PROVENANCES,
    REPO_ROOT,
    RunMetadata,
    TranscriptWriter,
)

LIVE_CODER_RUN = REPO_ROOT / "docs" / "benchmarks" / "runs" / "2026-10-02-20261002T192742Z-052d890b"

# An IPv4 address is the thing the repository's real-data prohibition is about
# (docs/benchmarks/runs/README.md, "What must never land here"), so its
# absence from the stored prompts is what separates `live_model` from
# `captured` here rather than a claim in the module docstring.
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LiveCoderRunIsLabelledLiveModelTest(unittest.TestCase):
    """The whole decision, in one assertion per surface it is recorded on."""

    def test_the_live_coder_run_is_labelled_live_model(self):
        self.assertTrue(LIVE_CODER_RUN.is_dir(), f"{LIVE_CODER_RUN} is not in the tree")

        run = json.loads((LIVE_CODER_RUN / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(
            run["provenance"], PROVENANCE_LIVE_MODEL,
            "a run of live model answers is neither synthetic (fixture answers) "
            "nor captured (real attacker input); live_model is what it is",
        )
        # Reused, not restated: the enum is the validator. A value that means
        # nothing to any other reader fails here rather than passing quietly.
        self.assertIn(run["provenance"], PROVENANCES)
        self.assertNotEqual(run["provenance"], PROVENANCE_SYNTHETIC)
        # Not a rename of `captured`: the two mean opposite things about the
        # input, and the run's own records show which one it is.
        self.assertNotEqual(run["provenance"], PROVENANCE_CAPTURED)

        # The sidecar carries the same label. It used to carry none at all,
        # which is the unresolvable middle: not fixture data, not declared
        # captured. A grader opening the sheet had no way to tell what the
        # answers under it were.
        grades = json.loads((LIVE_CODER_RUN / "human-grades.json").read_text(encoding="utf-8"))
        self.assertEqual(grades.get("provenance"), PROVENANCE_LIVE_MODEL)
        self.assertEqual(grades["run_id"], run["run_id"])

        records = [
            json.loads(line)
            for line in (LIVE_CODER_RUN / "transcripts.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(records), run["record_count"])

        # Why the label is `live_model` and not `synthetic`: real served tag, an
        # exact digest, a finished generation and a non-empty body -- none of
        # which a fixture placeholder has. This is the precondition that stops
        # the test passing by renaming a fixture.
        answered = [r for r in records if (r.get("response") or {}).get("raw")]
        self.assertTrue(answered, "the run holds no model answers to label")
        for record in answered:
            self.assertEqual(len(record["model"]["digest"]), 64,
                             "a run of live answers pins an exact model digest")
            self.assertEqual(record["timing"]["done_reason"], "stop")
            self.assertGreater(record["timing"]["output_tokens"], 0)

        # And why it is not `captured`: the INPUT is synthetic. Not one stored
        # prompt or answer carries an IPv4 address, so there is no attacker IP
        # or payload here for the repository's real-data prohibition to keep
        # out -- which is the only reason committing this run is safe.
        leaked = [
            (record["case"], IPV4.findall(json.dumps(record["request"])))
            for record in records
            if IPV4.search(json.dumps(record["request"]))
        ]
        self.assertEqual(
            leaked, [],
            "a stored request carries an IPv4 address; that is real attacker input, "
            "which makes this a captured run rather than a live-model one",
        )

        # The hash guard is intact, and the value in run.json is still the
        # honest one over the untouched transcript -- proof the label was
        # corrected without recomputing a hash to cover an edited file.
        recorded = run["transcripts_sha256"]
        self.assertEqual(
            recorded,
            hashlib.sha256((LIVE_CODER_RUN / "transcripts.jsonl").read_bytes()).hexdigest(),
        )

        # And it has to hold for the next run, not just this file: a
        # hand-corrected artifact the writer immediately regenerates without
        # the field is a fix that does not survive the next coder round. The
        # producer is pinned to the same `writer.run` provenance run.json and
        # every transcript record already carry.
        fresh = RunMetadata(benchmark="test", provenance=PROVENANCE_LIVE_MODEL)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, fresh) as writer:
                sheet = json.loads(
                    evaluate_models.write_human_grades_template(
                        writer, {"tag": "qwen2.5-coder-7b-base:Q4_K_M", "digest": "d" * 64}
                    ).read_text(encoding="utf-8")
                )
        self.assertEqual(sheet["provenance"], PROVENANCE_LIVE_MODEL)
        self.assertIn(sheet["provenance"], PROVENANCES)
        self.assertEqual(sheet["run_id"], fresh.run_id)


class CapturedIsStillRefusedInRepoTest(unittest.TestCase):
    """Adding a member must not move the guard that was there before it.

    This is the half of decision 1 that can regress silently. `live_model` is
    permitted inside the repository -- that is the point of it -- and the
    obvious wrong way to write that is to express the refusal as "not
    committable" and let the new member fall outside it, or to widen the
    condition until `captured` passes. Both would keep every other test in
    this file green while real attacker transcripts landed in the working tree.
    """

    def test_captured_is_refused_inside_a_repo_and_live_model_is_permitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A stand-in for the repository, so "inside the repo" is exercised
            # without a run directory landing in the real tree.
            fake_repo = Path(tmp) / "repo"
            (fake_repo / "docs" / "benchmarks" / "runs").mkdir(parents=True)
            outside = Path(tmp) / "operator-only"

            with patch.object(transcripts, "REPO_ROOT", fake_repo):
                # The guard, unchanged and still aimed at `captured` alone.
                with self.assertRaises(ValueError) as caught:
                    TranscriptWriter(
                        fake_repo / "docs" / "benchmarks" / "runs",
                        RunMetadata(benchmark="test", provenance=PROVENANCE_CAPTURED),
                    )
                self.assertIn("refusing to write captured-data transcripts",
                              str(caught.exception))
                self.assertEqual(
                    list((fake_repo / "docs" / "benchmarks" / "runs").iterdir()), [],
                    "the refusal must fire before anything is created on disk",
                )

                # The new member is permitted in the repository, and only
                # because its input is synthetic.
                permitted = TranscriptWriter(
                    fake_repo / "docs" / "benchmarks" / "runs",
                    RunMetadata(benchmark="test", provenance=PROVENANCE_LIVE_MODEL),
                )
                permitted.close()
                self.assertTrue(permitted.path.exists())
                # Committable means committable: no operator-only 0700 on a
                # directory that is meant to be tracked by git.
                self.assertNotEqual(
                    permitted.directory.stat().st_mode & 0o777, 0o700,
                    "live_model is a committed member and must not get captured's "
                    "operator-only directory mode",
                )

            # Outside the repository `captured` remains the one allowed value
            # with an operator-only path, unchanged.
            with TranscriptWriter(
                outside, RunMetadata(benchmark="test", provenance=PROVENANCE_CAPTURED)
            ) as captured_writer:
                self.assertEqual(captured_writer.directory.stat().st_mode & 0o777, 0o700)

    def test_captured_is_still_refused_by_the_real_repository(self):
        """The unpatched path, so the guard is not merely proven against a stub.

        The refusal fires before the directory is created, so this leaves
        nothing behind in docs/benchmarks/runs/.
        """
        runs_root = REPO_ROOT / "docs" / "benchmarks" / "runs"
        before = sorted(p.name for p in runs_root.iterdir()) if runs_root.is_dir() else []
        with self.assertRaises(ValueError) as caught:
            TranscriptWriter(
                runs_root, RunMetadata(benchmark="test", provenance=PROVENANCE_CAPTURED)
            )
        self.assertIn("refusing to write captured-data transcripts", str(caught.exception))
        after = sorted(p.name for p in runs_root.iterdir()) if runs_root.is_dir() else []
        self.assertEqual(after, before, "the refusal must not have created a run directory")


class LiveModelInputIsCheckedTest(unittest.TestCase):
    """`live_model` has to mean something a program can check.

    It is committable only because its *input* is this repository's fixtures:
    that is the whole difference from `captured`, and it is the only reason the
    answers in a live-model run may land in the working tree. Both
    `--provenance` setters are argparse `choices=PROVENANCES`, so before the
    check below a caller could file real attacker data under the one label the
    captured refusal does not catch, and nothing in the tree would have looked.
    The enum member asserted a property no code read.

    The rule is transcripts.py's and both producers go through it; what is
    tested here is that it fires, that it fires before anything is written, and
    that it has not been quietly widened to cover the other two members --
    which is a behaviour change nobody asked for.
    """

    def test_live_model_is_refused_when_a_prompt_source_is_not_a_repository_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            # An operator-only path standing in for real attacker data, or a
            # corpus fetched at run time: a file, just not one in this tree.
            outside = Path(tmp) / "attacker-corpus.json"
            outside.write_text('{"cases": []}', encoding="utf-8")

            # The rule itself.
            with self.assertRaises(ValueError) as caught:
                transcripts.assert_repository_fixture_input(PROVENANCE_LIVE_MODEL, outside)
            self.assertIn("refusing to label this run 'live_model'", str(caught.exception))
            self.assertIn(str(outside), str(caught.exception))

            # And through main(), at the point the label is set: the coder
            # slot's prompts are read from the corpus file, so pointing that at
            # the operator-only path must stop the run before it creates a
            # directory. Nothing below main()'s provenance check may run --
            # there is no model, no manifest and no network in this test, so
            # any escape from the check fails loudly instead of quietly
            # proceeding.
            original_cases = evaluate_models.CODER_CASES_PATH
            evaluate_models.CODER_CASES_PATH = outside
            runs_root = Path(tmp) / "runs"
            try:
                # The manifest path deliberately does not exist: if the check
                # is gone, main() walks past it and fails on the missing file
                # instead of reaching for a model, so the test names the
                # missing check rather than a network error.
                argv = [
                    "evaluate-models.py", "--manifest", str(Path(tmp) / "manifest.json"),
                    "--output", str(Path(tmp) / "report.json"),
                    "--provenance", PROVENANCE_LIVE_MODEL, "--slots", "coder",
                    "--transcript-dir", str(runs_root),
                ]
                with patch.object(sys, "argv", argv):
                    with self.assertRaises(ValueError):
                        evaluate_models.main()
            finally:
                evaluate_models.CODER_CASES_PATH = original_cases
            self.assertFalse(runs_root.exists(), "a refused run must leave no directory behind")

    def test_the_real_prompt_sources_of_every_slot_are_repository_fixtures(self):
        """The green side, and it is not vacuous: the check refuses an outside
        path, so passing here means these really are inside the repository.

        prompt_fixture_sources() is the single answer to "where do this slot's
        prompts come from", so a slot that grows an external prompt source has
        to name it there -- the check cannot keep pointing at this module while
        the prompts come from somewhere else.
        """
        for slot in ("ghidra", "sessions", "revdeck", "coder"):
            sources = evaluate_models.prompt_fixture_sources(slot)
            self.assertTrue(sources, f"{slot} names no prompt source at all")
            for source in sources:
                self.assertTrue(source.is_file(), f"{source} does not exist")
                transcripts.assert_repository_fixture_input(PROVENANCE_LIVE_MODEL, source)

    def test_the_check_does_not_touch_the_other_two_members(self):
        """Scoped to the member that claims repository-fixture input.

        `synthetic` and `captured` keep exactly the freedom they had: the
        captured refusal is the destination-side check and is untouched by
        this, and validating `synthetic`'s sources would be a new rule for a
        member that predates this one. Asserted so a later edit cannot widen
        this into a blanket "your prompts must be in the repo" and quietly
        refuse ordinary runs.
        """
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "operator-only.json"
            outside.write_text("{}", encoding="utf-8")
            transcripts.assert_repository_fixture_input(PROVENANCE_SYNTHETIC, outside)
            transcripts.assert_repository_fixture_input(PROVENANCE_CAPTURED, outside)

    def test_captured_is_still_refused_in_the_repository_after_the_new_check(self):
        """The refusal this file has always gated, re-checked now that a second
        guard sits above it -- the new check must not have become the thing
        that decides, and the old one must not have been loosened to make room
        for `live_model`."""
        runs_root = REPO_ROOT / "docs" / "benchmarks" / "runs"
        before = sorted(p.name for p in runs_root.iterdir()) if runs_root.is_dir() else []
        with self.assertRaises(ValueError) as caught:
            TranscriptWriter(
                runs_root, RunMetadata(benchmark="test", provenance=PROVENANCE_CAPTURED)
            )
        self.assertIn("refusing to write captured-data transcripts", str(caught.exception))
        self.assertEqual(sorted(p.name for p in runs_root.iterdir()), before)


class StoredProvenanceAgreementTest(unittest.TestCase):
    """The mixed-artifact residue in `20261002T192742Z-052d890b`, bounded.

    run.json and human-grades.json there say `live_model`; the five stored
    records still say `synthetic`, because each line's provenance is stamped
    from the run metadata at write time and `docs/benchmarks/runs/README.md`
    ("Never edit a stored transcript") forbids restating it. So the directory
    is internally inconsistent by five lines and this is the finding: is that
    acceptable, or must it be resolved without editing the transcript?

    It cannot be resolved in place, and this test is what makes that a pinned
    property rather than a shrug:

    * it pins the residue at exactly one directory and five records, so it
      cannot spread;
    * it permits only the under-claiming direction -- a run labelled
      `live_model` whose records say `synthetic` says something strictly
      weaker per record, and each record names the `run_id` that resolves it to
      the run-level label, so a reader can always get to the accurate one;
    * it forbids the over-claiming direction, which is what the tree carried
      before the relabel: a run.json claiming `captured` over `synthetic`
      records claims real attacker data that is not there, and it is the label
      the writer refuses to create inside a repository at all.

    Removing the residue itself needs a superseding re-run against a live model
    on the homeserver (`supersedes: 20261002T192742Z-052d890b`), which is not
    something a commit can do. The stored text is untouched here.
    """

    EXPECTED_RESIDUE_DIR = "2026-10-02-20261002T192742Z-052d890b"
    EXPECTED_RESIDUE_RECORDS = 5
    # The only disagreement a stored transcript may keep with its run.json: the
    # run claims more than the records do. Per record `synthetic` is a strictly
    # weaker claim than `live_model`, and each record names the run_id that
    # resolves it to the stronger label.
    UNDER_CLAIMING = (PROVENANCE_SYNTHETIC, PROVENANCE_LIVE_MODEL)

    @staticmethod
    def _run_records():
        runs_root = REPO_ROOT / "docs" / "benchmarks" / "runs"
        for run_dir in sorted(p for p in runs_root.iterdir() if p.is_dir()):
            run_json = run_dir / "run.json"
            if not run_json.is_file():
                continue
            run = json.loads(run_json.read_text(encoding="utf-8"))
            transcript = run_dir / "transcripts.jsonl"
            if not transcript.is_file():
                continue
            for lineno, line in enumerate(transcript.read_text(encoding="utf-8").splitlines(), 1):
                if line.strip():
                    yield run_dir.name, lineno, json.loads(line), run

    def test_the_only_provenance_disagreement_under_claims_and_is_bounded(self):
        disagreements = []
        for run_dir, lineno, record, run in self._run_records():
            if record.get("provenance") != run.get("provenance"):
                disagreements.append((run_dir, lineno, record.get("provenance"),
                                      run.get("provenance"), record.get("run_id")))
        self.assertTrue(disagreements, "precondition: the known residue still exists")

        # Only the under-claiming direction is allowed. Anything else is a
        # false claim in one direction or the other, and the over-claiming one
        # -- a run.json saying `captured` over `synthetic` records -- is exactly
        # what this tree carried before the relabel: it claims real attacker
        # data that is not there, under the label the writer refuses to create
        # inside a repository at all.
        unexpected = [
            entry for entry in disagreements
            if (entry[2], entry[3]) != self.UNDER_CLAIMING
        ]
        self.assertEqual(
            unexpected, [],
            "a stored record disagrees with its run.json in the over-claiming "
            "direction, which is a false claim rather than a residue",
        )

        # Bounded, so a new relabelled run cannot quietly add more of these.
        self.assertEqual(
            {(d, run_value) for d, _n, _r, run_value, _i in disagreements},
            {(self.EXPECTED_RESIDUE_DIR, PROVENANCE_LIVE_MODEL)},
        )
        self.assertEqual(len(disagreements), self.EXPECTED_RESIDUE_RECORDS)

        # And each disagreement is resolvable from the record alone: every
        # record names the run it belongs to, and that run_id is the directory
        # holding the label that disagrees with it. This is what makes the
        # residue under-claiming rather than contradictory.
        run_ids = {
            json.loads((REPO_ROOT / "docs" / "benchmarks" / "runs" / d / "run.json")
                       .read_text(encoding="utf-8"))["run_id"]
            for d, _n, _r, _rv, _i in disagreements
        }
        self.assertEqual(run_ids, {"20261002T192742Z-052d890b"})
        for _d, _n, _record_value, _run_value, run_id in disagreements:
            self.assertIsNotNone(run_id)

        # The transcript itself is byte-identical to what its run.json recorded,
        # which is what forbids resolving this by editing it.
        run_dir = REPO_ROOT / "docs" / "benchmarks" / "runs" / self.EXPECTED_RESIDUE_DIR
        run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(
            run["transcripts_sha256"],
            hashlib.sha256((run_dir / "transcripts.jsonl").read_bytes()).hexdigest(),
        )
        self.assertEqual(run["record_count"], self.EXPECTED_RESIDUE_RECORDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)