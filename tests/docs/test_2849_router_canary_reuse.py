#!/usr/bin/env python3
"""Regression test for #2849: ci-router's liveness canary must be shared,
not re-dispatched by every router.

The bug this pins down is not a crash -- it is a routing decision that
gets *less* accurate the busier the box is. Every workflow on every PR
dispatched its own ci-heartbeat canary; those canaries queue on the same
executors as the jobs they gate; so a fan-out deep enough to fill the
queue makes each router time out and declare a perfectly healthy box
offline. Measured on run 33553809659: five runners online and executing,
every canary in the surrounding hour `success`, and the router still
concluded `online=false` after burning its full 420s window.

So the properties worth locking in are about *who dispatches* and *what
counts as evidence*, and they cannot be tested by reading the YAML for
substrings -- a comment mentioning "reuse" would pass that. This file
therefore extracts the router's real `run:` block and executes it, with
`gh` and `curl` replaced by stubs whose responses each test controls.
That way a test can assert the thing that actually matters: that no
dispatch happened.

Two deliberate choices in the harness:

* The workflow is parsed textually rather than with PyYAML. The
  `tests/docs/` row in quality.yml installs pytest and nothing else, and
  no other CI-run Python here imports yaml -- adding that import would
  make this file the one that needs a new CI dependency.
* The stub `gh` serves a *sequence* of API responses, so a test can model
  "in flight now, succeeded on the next poll" rather than only steady
  states. Several of the behaviours here only exist across two polls.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ROUTER = REPO_ROOT / ".github" / "workflows" / "ci-router.yml"


def extract_run_block() -> str:
    """Pull the route step's `run: |` body out of ci-router.yml.

    Textual on purpose (see module docstring). Finds the `run: |` line,
    then takes every following line that is blank or indented deeper than
    it, dedented back to column 0.
    """
    lines = ROUTER.read_text().splitlines()
    start = None
    indent = 0
    for i, line in enumerate(lines):
        m = re.match(r"^(\s+)run: \|\s*$", line)
        if m:
            start = i + 1
            indent = len(m.group(1))
            break
    assert start is not None, "no `run: |` block found in ci-router.yml"

    body = []
    for line in lines[start:]:
        if line.strip() == "":
            body.append("")
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line[indent + 2:])
    assert body, "extracted an empty run block"
    return "\n".join(body)


def iso(offset_seconds: int) -> str:
    """An ISO8601 UTC stamp `offset_seconds` in the past."""
    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - offset_seconds)
    )


def run_object(rid, status, conclusion, age_seconds, event="workflow_dispatch"):
    stamp = iso(age_seconds)
    return {
        "id": rid,
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "run_started_at": stamp,
        "updated_at": stamp,
    }


class RouterHarness:
    """Executes the real router block with stubbed `gh` and `curl`."""

    def __init__(self, responses, http_code="204"):
        self.tmp = Path(tempfile.mkdtemp(prefix="router-2849-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.dispatch_log = self.tmp / "dispatches.log"
        self.dispatch_log.write_text("")

        # gh stub: serve responses[0], then [1], ... then repeat the last.
        resp_dir = self.tmp / "responses"
        resp_dir.mkdir()
        for i, payload in enumerate(responses):
            (resp_dir / f"{i}.json").write_text(
                json.dumps({"workflow_runs": payload})
            )
        counter = self.tmp / "gh.count"
        counter.write_text("0")
        (self.bin / "gh").write_text(
            "#!/usr/bin/env bash\n"
            f'n="$(cat {counter})"\n'
            f'echo $((n + 1)) > {counter}\n'
            f'last={len(responses) - 1}\n'
            '[ "$n" -gt "$last" ] && n="$last"\n'
            f'cat {resp_dir}/"$n".json\n'
        )
        # curl stub: record that a dispatch was attempted, return the code.
        (self.bin / "curl").write_text(
            "#!/usr/bin/env bash\n"
            f'echo "dispatch" >> {self.dispatch_log}\n'
            f'printf "%s" "{http_code}"\n'
        )
        for name in ("gh", "curl"):
            (self.bin / name).chmod(0o755)

        self.script = self.tmp / "router.sh"
        self.script.write_text("#!/usr/bin/env bash\n" + extract_run_block())
        self.script.chmod(0o755)

    def run(self, event_name="push", homeserver_prs="true",
            force_github_hosted="", same_repo=True):
        event = self.tmp / "event.json"
        head_repo = "Xore/APIARY" if same_repo else "someone/APIARY"
        event.write_text(json.dumps({
            "pull_request": {
                "base": {"repo": {"full_name": "Xore/APIARY"}},
                "head": {"repo": {"full_name": head_repo}, "ref": "some-branch"},
            }
        }))
        out = self.tmp / "gh_output"
        summary = self.tmp / "summary"
        out.write_text("")
        summary.write_text("")

        env = dict(os.environ)
        env.update({
            "PATH": f"{self.bin}:{env['PATH']}",
            "GITHUB_EVENT_NAME": event_name,
            "GITHUB_EVENT_PATH": str(event),
            "EVENT_PATH": str(event),
            "CI_HOMESERVER_PRS": homeserver_prs,
            "FORCE_GITHUB_HOSTED": force_github_hosted,
            "GITHUB_REPOSITORY": "Xore/APIARY",
            "GITHUB_REF_NAME": "some-branch",
            "GITHUB_API_URL": "https://api.github.com",
            "GH_TOKEN": "not-a-real-token",
            "GITHUB_OUTPUT": str(out),
            "GITHUB_STEP_SUMMARY": str(summary),
            "RUNNER_TEMP": str(self.tmp),
            # Keep the windows tiny so a "times out" case costs ~2s.
            "HEARTBEAT_APPEAR_SECONDS": "1",
            "HEARTBEAT_DECIDE_SECONDS": "1",
            "HEARTBEAT_POLL_SECONDS": "1",
            "HEARTBEAT_FRESH_SECONDS": "300",
        })
        proc = subprocess.run(
            ["bash", str(self.script)], env=env,
            capture_output=True, text=True, timeout=120,
        )
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "output": out.read_text(),
            "dispatches": len(
                [x for x in self.dispatch_log.read_text().splitlines() if x]
            ),
        }

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


@unittest.skipIf(shutil.which("jq") is None, "router block requires jq")
class RouterCanaryReuseTest(unittest.TestCase):
    def tearDown(self):
        harness = getattr(self, "harness", None)
        if harness:
            harness.cleanup()

    def _run(self, responses, **kw):
        http = kw.pop("http_code", "204")
        self.harness = RouterHarness(responses, http_code=http)
        return self.harness.run(**kw)

    # --- the storm-cutter itself -------------------------------------

    def test_recent_success_is_reused_and_nothing_is_dispatched(self):
        """The whole point of #2849: a canary that just succeeded answers
        the question for every router behind it."""
        res = self._run([[run_object(1, "completed", "success", 60)]])
        self.assertIn("homeserver=true", res["output"])
        self.assertEqual(res["dispatches"], 0, "reuse must not dispatch")
        self.assertIn("reusing successful canary", res["stdout"])

    def test_many_routers_share_one_canary(self):
        """Concretely: N routers meeting the same fresh success dispatch
        nothing between them. This is the fan-out property the issue is
        about, not just a single-call optimisation."""
        total = 0
        for _ in range(8):
            harness = RouterHarness([[run_object(1, "completed", "success", 30)]])
            try:
                res = harness.run()
                self.assertIn("homeserver=true", res["output"])
                total += res["dispatches"]
            finally:
                harness.cleanup()
        self.assertEqual(total, 0, "8 routers, one canary, zero dispatches")

    def test_inflight_canary_is_adopted_rather_than_duplicated(self):
        """A canary already queued is waited on, not raced. Response 0 has
        it in flight; response 1 has it finished."""
        res = self._run([
            [run_object(7, "in_progress", None, 45)],
            [run_object(7, "completed", "success", 0)],
        ])
        self.assertEqual(res["dispatches"], 0, "must adopt, not dispatch")
        self.assertIn("already in flight", res["stdout"])
        self.assertIn("homeserver=true", res["output"])

    # --- the freshness and correctness guards ------------------------

    def test_stale_success_is_not_reused(self):
        """Evidence expires. An hour-old success says nothing about now."""
        res = self._run([[run_object(2, "completed", "success", 3600)]])
        self.assertEqual(res["dispatches"], 1, "stale success must re-probe")
        self.assertNotIn("reusing successful canary", res["stdout"])

    def test_failed_canary_is_never_reused_as_evidence_of_life(self):
        """Fail-safe direction: only a success may vouch."""
        res = self._run([[run_object(3, "completed", "failure", 30)]])
        self.assertEqual(res["dispatches"], 1)
        self.assertNotIn("reusing successful canary", res["stdout"])
        self.assertIn("homeserver=false", res["output"])

    def test_no_canary_at_all_falls_back(self):
        res = self._run([[]])
        self.assertEqual(res["dispatches"], 1)
        self.assertIn("homeserver=false", res["output"])

    def test_non_dispatch_events_do_not_vouch(self):
        """A push-triggered ci-heartbeat run is not the router's canary."""
        res = self._run([[
            run_object(4, "completed", "success", 30, event="push")
        ]])
        self.assertEqual(res["dispatches"], 1)
        self.assertNotIn("reusing successful canary", res["stdout"])

    # --- unchanged guarantees ----------------------------------------

    def test_untrusted_pr_never_probes_or_routes_home(self):
        """Fork PRs must not reach the box, and must not even dispatch."""
        res = self._run([[run_object(5, "completed", "success", 30)]],
                        event_name="pull_request", same_repo=False)
        self.assertIn("homeserver=false", res["output"])
        self.assertEqual(res["dispatches"], 0)

    def test_same_repo_pr_never_routes_home_even_when_opted_in(self):
        """Unreviewed PR content must never run on the persistent runner:
        a same-repository PR stays GitHub-hosted and dispatches nothing,
        even with CI_HOMESERVER_PRS=true and a fresh successful canary."""
        res = self._run([[run_object(8, "completed", "success", 30)]],
                        event_name="pull_request", homeserver_prs="true",
                        same_repo=True)
        self.assertIn("homeserver=false", res["output"])
        self.assertEqual(res["dispatches"], 0)
        self.assertNotIn("reusing successful canary", res["stdout"])

    def test_force_github_hosted_overrides_a_reusable_success(self):
        res = self._run([[run_object(6, "completed", "success", 30)]],
                        force_github_hosted="true")
        self.assertIn("homeserver=false", res["output"])
        self.assertEqual(res["dispatches"], 0)

    def test_refused_dispatch_does_not_burn_the_full_window(self):
        """Nothing adopted and the dispatch refused means no canary is
        coming; waiting for one is pure router time."""
        res = self._run([[]], http_code="422")
        self.assertIn("homeserver=false", res["output"])
        self.assertIn("not waiting", res["stdout"])

    def test_always_emits_an_explicit_homeserver_value(self):
        """Downstream compares `== 'true'`; an empty value must never be
        what it reads."""
        for responses in ([[]], [[run_object(9, "completed", "success", 30)]]):
            harness = RouterHarness(responses)
            try:
                res = harness.run()
                self.assertRegex(res["output"], r"homeserver=(true|false)")
            finally:
                harness.cleanup()


if __name__ == "__main__":
    unittest.main()
