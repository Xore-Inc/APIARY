#!/usr/bin/env python3
"""Behaviour tests for scripts/honeypot-pause.sh (#3135).

The classification table in that script is the substance of the issue: a wrong
"safe" does not fail loudly, it silently breaks a decoy that was carrying the
honeypot surface. So what is worth pinning is the table's *shape* and the
refusals, not today's container names -- Arcane can and does add stacks, and
these tests should fail when someone adds one without classifying it, not when
a decoy is legitimately renamed.

The cases below are each a way this could quietly go wrong:

- a stack added to the host but never classified, so `pause` neither accepts
  it nor explains why -- the operator is left guessing, and guessing is how a
  GPU container gets paused;
- the GPU/training stacks drifting out of NEVER, which is the one prohibition
  #3135 names in so many words;
- a container in the runbook table that the script does not actually gate on,
  so the runbook and the enforcement drift apart in the direction that
  matters;
- the cold-run interlock losing a pattern, so a pause could land on top of
  STOP_WORKERS=1 + the restore trap it is explicitly not allowed to touch;
- the autoheal gate going missing, which does not fail -- it silently
  restores every decoy about 30s after it is paused (measured 2026-09-27);
- default-deny turning into default-allow, so an unclassified name reaches
  `docker pause` instead of being refused by name.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "honeypot-pause.sh"
RUNBOOK = ROOT / "docs" / "OPERATIONS.md"

VERDICTS = {"SAFE", "UNIT", "NEVER"}


def run(*args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    env.setdefault("APIARY_PAUSE_DIR", "/tmp/apiary-pause-test-never-used")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def classification() -> list[tuple[str, str, list[str], str, str]]:
    """The table as (verdict, stack, containers, probe, reason) tuples.

    Parsed line-by-line rather than by splitting on a delimiter, because
    `list` pads the verdict column and a reason may contain the delimiter.
    """
    out = run("list")
    rows: list[tuple[str, str, list[str], str, str]] = []
    cur: dict | None = None
    for line in out.stdout.splitlines():
        m = re.match(r"^(SAFE|UNIT|NEVER)\s+(\S+)\s*$", line)
        if m:
            if cur:
                rows.append(_finish(cur))
            cur = {"verdict": m.group(1), "stack": m.group(2), "containers": "",
                   "probe": "-", "reason": ""}
            continue
        if cur is None:
            continue
        mc = re.match(r"^\s+containers:\s+(.+)$", line)
        if mc:
            cur["containers"] = mc.group(1)
            continue
        mp = re.match(r"^\s+probe:\s+(\S+)", line)
        if mp:
            cur["probe"] = mp.group(1)
            continue
        mr = re.match(r"^\s+reason:\s+(.+)$", line)
        if mr:
            cur["reason"] = mr.group(1).strip()
    if cur:
        rows.append(_finish(cur))
    return rows


def _finish(cur: dict) -> tuple[str, str, list[str], str, str]:
    return (
        cur["verdict"],
        cur["stack"],
        [c.strip() for c in cur["containers"].split(",") if c.strip()],
        cur["probe"],
        cur["reason"],
    )


class TestTableShape(unittest.TestCase):
    def test_every_row_has_five_fields_and_a_known_verdict(self):
        rows = classification()
        self.assertGreater(len(rows), 20, "classification looks truncated")
        for verdict, stack, containers, _probe, reason in rows:
            self.assertIn(verdict, VERDICTS, stack)
            self.assertTrue(stack.strip(), "empty stack name")
            self.assertTrue(containers, f"{stack}: no containers")
            self.assertTrue(reason.strip(), f"{stack}: a verdict with no reason")

    def test_every_stack_name_is_unique(self):
        names = [r[1] for r in classification()]
        dupes = {n for n in names if names.count(n) > 1}
        self.assertEqual(dupes, set(), f"duplicate stack rows: {sorted(dupes)}")

    def test_every_pauseable_stack_has_a_real_probe(self):
        """`resume` verifies with one real probe request, so SAFE/UNIT rows
        must carry a probe spec the script can actually execute."""
        for verdict, stack, _c, probe, _r in classification():
            if verdict in ("SAFE", "UNIT"):
                self.assertRegex(
                    probe,
                    r"^(tcp:\d+|http:\d+/\S*)$",
                    f"{stack} is pauseable but has no usable probe ({probe!r})",
                )

    def test_pauseable_containers_are_named_with_the_hp_prefix(self):
        for verdict, stack, containers, _p, _r in classification():
            if verdict in ("SAFE", "UNIT"):
                for c in containers:
                    self.assertTrue(
                        c.startswith("hp-"), f"{stack}: {c} is not a honeypot container"
                    )


class TestHardRules(unittest.TestCase):
    def test_gpu_and_training_stacks_are_never_pauseable(self):
        """#3135: never pause ghidra-ollama-1 while a benchmark holds the GPU
        slot. This is the one prohibition the issue states in so many words, so
        it is pinned per-container and not merely per-stack."""
        rows = classification()
        by_container = {c: (v, s) for v, s, cs, _p, _r in rows for c in cs}
        for container in (
            "ghidra-ollama-1",
            "ghidra-revdeck-1",
            "ghidra-statictools-1",
            "ghidra-ghidra-1",
            "hp-unsloth-studio",
            "rex86-eval",
        ):
            self.assertIn(container, by_container, f"{container} is unclassified")
            verdict, stack = by_container[container]
            self.assertEqual(verdict, "NEVER", f"{container} ({stack}) is not NEVER")

    def test_pipeline_dashboard_and_identity_are_never_pauseable(self):
        """The capture pipeline, the operator surface and the identity tier are
        the three things whose loss is silent rather than visible."""
        rows = classification()
        by_container = {c: v for v, _s, cs, _p, _r in rows for c in cs}
        for container in (
            "hp-elasticsearch",
            "hp-arkime-capture",
            "hp-filebeat",
            "hp-zeek-proxy",
            "hp-apiary-dashboard",
            "hp-apiary-backend",
            "hp-apiary-worker",
            "hp-keycloak",
            "hp-arcane",
        ):
            self.assertEqual(
                by_container.get(container), "NEVER", f"{container} is not NEVER"
            )

    def test_the_ml_worker_is_never_pauseable(self):
        """It is in the cold protocol's LIVE_WORKERS, so pausing it would make
        two mechanisms disagree about whether a worker is running."""
        by_container = {c: v for v, _s, cs, _p, _r in rows_of() for c in cs}
        self.assertEqual(by_container.get("hp-ml-worker"), "NEVER")

    def test_the_script_never_manages_worker_state(self):
        """#3135 says the cold-run mechanism is unchanged. This script must not
        stop or start a worker, and must not set STOP_WORKERS.

        The classification table is excluded: the ml-worker row *explains* that
        the cold protocol owns that container via STOP_WORKERS=1 + trap, and
        that prose is the reason for the verdict. What is forbidden is
        executing it."""
        text = SCRIPT.read_text()
        code = [
            ln
            for ln in text.splitlines()
            if not ln.startswith(("SAFE|", "UNIT|", "NEVER|"))
        ]
        for forbidden in ("STOP_WORKERS", "LIVE_WORKERS", "docker stop", "docker start"):
            hits = [
                ln
                for ln in code
                if forbidden in ln
                and not ln.lstrip().startswith("#")
                and "must not" not in ln
                and "unchanged" not in ln
            ]
            self.assertEqual(
                hits, [], f"honeypot-pause.sh must not touch {forbidden}: {hits}"
            )

    def test_cold_run_interlock_covers_the_protocol_script(self):
        """The refusal has to know what 'the cold run is running' means. The
        pattern list is the same one coldrun.sh uses to avoid double-booking
        the GPU, so it is pinned here too."""
        text = SCRIPT.read_text()
        m = re.search(r"COLD_RUN_PATTERNS=\(([^)]*)\)", text)
        self.assertIsNotNone(m, "COLD_RUN_PATTERNS not found")
        patterns = m.group(1).split()
        self.assertIn("sweep_extra.sh", patterns)
        self.assertIn("record_baseline.py", patterns)

    def test_the_autoheal_gate_is_paused_first_and_recorded_first(self):
        """Without the gate, autoheal restores every paused decoy within
        AUTOHEAL_INTERVAL -- measured at 17s on 2026-09-27. This is a silent
        failure, so the gate is pinned rather than trusted."""
        text = SCRIPT.read_text()
        self.assertIn("AUTOHEAL_CONTAINER", text)
        pause_idx = text.index("docker pause \"$AUTOHEAL_CONTAINER\"")
        # the gate must be written to the inventory before any target stack,
        # because resume walks the inventory in reverse and un-pauses the
        # last-recorded container first.
        self.assertLess(pause_idx, text.index("cmd_resume()"))
        self.assertIn('printf \'%s\\n\' "$AUTOHEAL_CONTAINER" >>"$INVENTORY"', text)

    def test_resume_walks_the_inventory_in_reverse(self):
        text = SCRIPT.read_text()
        self.assertIn('tac "$INVENTORY"', text)


class TestDefaultDeny(unittest.TestCase):
    def test_pause_refuses_an_unclassified_stack(self):
        out = run("pause", "not-a-real-stack")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("unknown stack", out.stderr)

    def test_pause_refuses_a_never_stack_and_prints_the_reason(self):
        out = run("pause", "honeypot-elk")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("NEVER", out.stderr)
        self.assertIn("capture pipeline", out.stderr)

    def test_pause_refuses_the_gpu_stack_by_name(self):
        out = run("pause", "ghidra")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("GPU", out.stderr)

    def test_pause_refuses_the_active_test_fixtures(self):
        """'Depended on by an active test' is an explicit not-pause-safe
        condition in the issue."""
        out = run("pause", "dashkcnext-dashkcchaos")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("active test", out.stderr)

    def test_a_refused_pause_writes_no_record(self):
        """A refusal must not leave an inventory behind, or `resume` would
        later try to un-pause something that was never paused."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            run("pause", "honeypot-elk", env_extra={"APIARY_PAUSE_DIR": td})
            self.assertEqual(list(Path(td).glob("inventory")), [])

    def test_usage_lists_only_pauseable_stacks(self):
        out = run("nonsense-subcommand")
        self.assertEqual(out.returncode, 2)
        self.assertIn("Pause-safe stacks", out.stderr)
        for never in ("honeypot-elk", "ghidra", "honeypot-keycloak"):
            self.assertNotIn(f"  {never} ", out.stderr)


class TestRunbookMatchesTheScript(unittest.TestCase):
    """The runbook table and the script's gate must agree. Drift here is the
    dangerous direction: a container documented as pause-safe that the script
    refuses, or worse, one the script accepts that the runbook never
    mentioned."""

    def test_the_runbook_documents_the_procedure(self):
        text = RUNBOOK.read_text()
        for needed in (
            "Pausing decoys to free host CPU",
            "scripts/honeypot-pause.sh",
            "strict reverse order",
            "hp-autoheal",
            "STOP_WORKERS",
        ):
            self.assertIn(needed, text, f"runbook does not mention {needed!r}")

    def test_the_runbook_names_every_pauseable_stack(self):
        text = RUNBOOK.read_text()
        for verdict, stack, _c, _p, _r in classification():
            if verdict in ("SAFE", "UNIT"):
                self.assertIn(stack, text, f"{stack} is pauseable but undocumented")

    def test_the_runbook_gives_a_reason_for_every_never_stack(self):
        text = RUNBOOK.read_text()
        section = text.split("#### Never pause", 1)
        self.assertEqual(len(section), 2, "runbook has no 'Never pause' table")
        for verdict, stack, _c, _p, reason in classification():
            if verdict != "NEVER":
                continue
            self.assertIn(stack, section[1], f"{stack} is NEVER but not in the table")

    def test_the_runbook_records_the_measured_ram_caveat(self):
        """The issue says pause frees RAM; it does not. The runbook has to say
        so, or the next operator will size a leg against a lever that does
        not move."""
        text = RUNBOOK.read_text()
        self.assertIn("frees CPU, not RAM", text)
        self.assertIn("36,339,712", text)

    def test_the_runbook_records_the_autoheal_measurement(self):
        text = RUNBOOK.read_text()
        self.assertIn("18:12:38", text)
        self.assertIn("found to be unhealthy", text)


def rows_of() -> list[tuple[str, str, list[str], str, str]]:
    return classification()


if __name__ == "__main__":
    unittest.main()
