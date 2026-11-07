#!/usr/bin/env python3
"""Tests for scripts/workbench-owner-migration.py (#3577, dashboard#249).

No Elasticsearch: FakeEs keeps documents in memory and answers the four calls
the script makes (owner aggregation, settings, _update_by_query), recording
each request so the tests can pin what was written and what was not.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("owner_migration", ROOT / "scripts" / "workbench-owner-migration.py")
om = importlib.util.module_from_spec(_spec)
sys.modules["owner_migration"] = om
_spec.loader.exec_module(om)

RUNS, RECIPES = om.INDICES


class FakeEs:
    def __init__(self, docs: dict[str, list[dict]], settings: dict[str, dict] | None = None):
        self.docs = docs
        self.settings = settings or {}
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(self, method, path, body=None, timeout=0):
        self.calls.append((method, path, body))
        index = path.split("/")[1]
        if index not in self.docs:
            raise om.EsError(404, "index_not_found_exception")
        if "/_search" in path:
            counts: dict[str, int] = {}
            for doc in self.docs[index]:
                counts[doc["owner"]] = counts.get(doc["owner"], 0) + 1
            return {"aggregations": {"o": {"sum_other_doc_count": 0, "buckets": [{"key": k, "doc_count": v} for k, v in counts.items()]}}}
        if "/_settings/" in path:
            return {index: {"settings": self.settings.get(index, {})}}
        if "/_update_by_query" in path:
            old, new = body["script"]["params"]["old"], body["script"]["params"]["new"]
            updated = 0
            for doc in self.docs[index]:
                if doc["owner"] == body["query"]["term"]["owner"] and doc["owner"] == old:
                    doc["owner"] = new
                    updated += 1
            return {"updated": updated, "version_conflicts": 0, "failures": []}
        raise AssertionError(path)

    def writes(self):
        return [call for call in self.calls if "_update_by_query" in call[1]]


def docs():
    return {
        RUNS: [{"id": "run_1", "owner": "Alice Example"}, {"id": "run_2", "owner": "Alice Example"}, {"id": "run_3", "owner": "bob"}, {"id": "run_4", "owner": "Nobody Known"}],
        RECIPES: [{"id": "recipe_1", "owner": "Alice Example"}, {"id": "recipe_2", "owner": "Shared Name"}],
    }


PAIRS = [("Alice Example", "alice"), ("Bob Builder", "bob"), ("Shared Name", "carol"), ("Shared Name", "dave")]


def owners(es, index):
    return sorted(doc["owner"] for doc in es.docs[index])


class Plan(unittest.TestCase):
    def test_unambiguous_names_move(self):
        plan = om.build_plan(PAIRS)
        self.assertEqual(plan.moves, {"Alice Example": "alice", "Bob Builder": "bob"})

    def test_a_name_two_users_share_is_skipped_not_guessed(self):
        plan = om.build_plan(PAIRS)
        self.assertEqual(plan.skipped["Shared Name"], ("ambiguous", ["carol", "dave"]))
        self.assertNotIn("Shared Name", plan.moves)

    def test_a_display_name_that_is_another_users_username_is_skipped(self):
        plan = om.build_plan([("bob", "alice"), ("Bob Builder", "bob")])
        self.assertEqual(plan.skipped["bob"], ("collision", ["alice"]))
        self.assertEqual(plan.moves, {"Bob Builder": "bob"})

    def test_a_name_equal_to_its_own_username_is_nothing_to_do(self):
        self.assertEqual(om.build_plan([("erin", "erin")]).moves, {})

    def test_reverse_swaps_only_the_unambiguous_pairs(self):
        plan = om.build_plan(PAIRS, reverse=True)
        self.assertEqual(plan.moves, {"alice": "Alice Example", "bob": "Bob Builder"})

    def test_reverse_skips_a_user_with_two_display_names(self):
        plan = om.build_plan([("A One", "alice"), ("A Two", "alice")], reverse=True)
        self.assertEqual(plan.moves, {})
        self.assertEqual(plan.skipped["alice"][0], "ambiguous")


class Run(unittest.TestCase):
    def run_migration(self, es, apply, plan=None):
        lines: list[str] = []
        code = om.migrate(es, plan or om.build_plan(PAIRS), apply, out=lines.append)
        return code, "\n".join(lines)

    def test_dry_run_writes_nothing_and_reports_everything(self):
        es = FakeEs(docs())
        code, report = self.run_migration(es, apply=False)
        self.assertEqual(code, 0)
        self.assertEqual(es.writes(), [])
        self.assertIn("would move", report)
        self.assertIn("'Alice Example' -> 'alice'", report)
        self.assertIn("SKIPPED ambiguous", report)
        self.assertIn("SKIPPED unmapped", report)
        self.assertIn("'Nobody Known'", report)
        self.assertIn("nothing written", report)
        self.assertEqual(owners(es, RUNS), ["Alice Example", "Alice Example", "Nobody Known", "bob"])

    def test_apply_rewrites_owner_in_both_indices_and_only_that(self):
        es = FakeEs(docs())
        code, _ = self.run_migration(es, apply=True)
        self.assertEqual(code, 0)
        self.assertEqual(owners(es, RUNS), ["Nobody Known", "alice", "alice", "bob"])
        self.assertEqual(owners(es, RECIPES), ["Shared Name", "alice"])
        self.assertEqual([doc["id"] for doc in es.docs[RUNS]], ["run_1", "run_2", "run_3", "run_4"])

    def test_a_second_apply_changes_nothing(self):
        es = FakeEs(docs())
        self.run_migration(es, apply=True)
        before = json.dumps(es.docs, sort_keys=True)
        es.calls.clear()
        code, report = self.run_migration(es, apply=True)
        self.assertEqual(code, 0)
        self.assertEqual(es.writes(), [])
        self.assertEqual(json.dumps(es.docs, sort_keys=True), before)
        self.assertIn("0 documents updated", report)

    def test_the_write_bypasses_the_default_pipeline_and_guards_on_the_old_owner(self):
        es = FakeEs(docs(), {RUNS: {"index.default_pipeline": "geoip-honeypot"}})
        _, report = self.run_migration(es, apply=True)
        method, path, body = es.writes()[0]
        self.assertIn("pipeline=_none", path)
        self.assertIn("conflicts=proceed", path)
        self.assertIn("ctx._source.owner == params.old", body["script"]["source"])
        self.assertIn("default bypassed", report)

    def test_a_final_pipeline_refuses_apply_for_that_index(self):
        es = FakeEs(docs(), {RUNS: {"index.final_pipeline": "audit"}})
        code, report = self.run_migration(es, apply=True)
        self.assertEqual(code, 1)
        self.assertIn("cannot be bypassed", report)
        self.assertEqual(owners(es, RUNS), ["Alice Example", "Alice Example", "Nobody Known", "bob"])
        self.assertEqual(owners(es, RECIPES), ["Shared Name", "alice"])

    def test_a_missing_index_is_reported_not_fatal(self):
        es = FakeEs({RUNS: docs()[RUNS]})
        code, report = self.run_migration(es, apply=True)
        self.assertEqual(code, 0)
        self.assertIn("absent", report)
        self.assertEqual(owners(es, RUNS), ["Nobody Known", "alice", "alice", "bob"])

    def test_reverse_restores_the_display_names(self):
        es = FakeEs(docs())
        self.run_migration(es, apply=True)
        self.run_migration(es, apply=True, plan=om.build_plan(PAIRS, reverse=True))
        self.assertEqual(owners(es, RUNS), ["Alice Example", "Alice Example", "Bob Builder", "Nobody Known"])
        self.assertEqual(owners(es, RECIPES), ["Alice Example", "Shared Name"])


class Mapping(unittest.TestCase):
    def write(self, text):
        handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        handle.write(text)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name

    def test_tsv_and_json(self):
        tsv = self.write("# comment\n\nAlice Example\talice\nShared Name\tcarol\nShared Name\tdave\n")
        self.assertEqual(om.load_mapping(tsv), [("Alice Example", "alice"), ("Shared Name", "carol"), ("Shared Name", "dave")])
        js = self.write(json.dumps({"Alice Example": "alice", "Shared Name": ["carol", "dave"]}))
        self.assertEqual(om.load_mapping(js), [("Alice Example", "alice"), ("Shared Name", "carol"), ("Shared Name", "dave")])

    def test_a_malformed_line_is_an_error(self):
        with self.assertRaises(SystemExit):
            om.load_mapping(self.write("no tab here\n"))

    def test_keycloak_users_use_first_and_last_name_as_the_name_claim_does(self):
        users = self.write(json.dumps([{"username": "alice", "firstName": "Alice", "lastName": "Example"}, {"username": "svc", "firstName": "", "lastName": ""}, {"username": "mono", "firstName": "Mono"}]))
        self.assertEqual(om.load_keycloak_users(users), [("Alice Example", "alice"), ("svc", "svc"), ("Mono", "mono")])

    def test_a_user_with_no_name_still_counts_as_a_known_username(self):
        plan = om.build_plan([("svc", "svc"), ("svc", "alice")])
        self.assertEqual(plan.skipped["svc"][0], "ambiguous")

    def test_main_requires_a_mapping(self):
        with self.assertRaises(SystemExit):
            om.main([])


if __name__ == "__main__":
    unittest.main()
