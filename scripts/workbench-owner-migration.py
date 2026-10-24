#!/usr/bin/env python3
"""workbench-owner-migration.py -- move Workbench run and recipe ownership from
operator display names to OIDC usernames (#3577, Xore-Inc/apiary-dashboard#249).

Until the dashboard signs actor assertions, `owner` in
`dashboard-workbench-runs-v1` and `dashboard-workbench-recipes-v1` is whatever
the BFF put in `x-actor-username`: the session's display name (Keycloak's
`name` claim, "First Last"). The signing dashboard sends `Session.username`
(the `preferred_username` claim) in both the plain header and the assertion,
and the backend scopes by it, so documents owned by a display name stop being
visible to their operator. This rewrites `owner` from the display name to the
username. Nothing else in the document changes: run ids (which embed a hash of
the old owner) and recipe ids stay as they are.

Dry run by default: it reads, prints what it would change and what it will not
touch, and writes nothing. `--apply` writes.

The mapping, display name -> username, comes from files you hand it:

  --mapping FILE         JSON object {"Display Name": "username"} (a list of
                         usernames as the value marks the name ambiguous), or
                         text, one `display name<TAB>username` per line
                         (`#` comments and blank lines ignored).
  --keycloak-users FILE  the JSON `kcadm.sh get users -r apiary` prints (see
                         docs/BACKEND-TRUST-BOUNDARY.md). The display name is
                         firstName + lastName, as Keycloak's `name` claim is;
                         a user with neither already shows as the username.

Both may be given and are combined. Nothing here logs in to Keycloak, and no
credential is read.

Nothing is guessed. A display name is SKIPPED, and reported, when:

  ambiguous   two or more users carry it
  collision   it is also another user's username, so a document owned by that
              string may already belong to that user (and a second run would
              move it again)
  unmapped    (owners found in the indices) it names no user in the mapping

Re-running changes nothing: a migrated document is owned by a username, and a
username is never rewritten (the collision rule above is what guarantees it).

Write path: one `_update_by_query` per name and index, on the real index, with
`pipeline=_none` so an index's `default_pipeline` (which `_update_by_query`
re-runs) cannot re-derive anything -- the only field touched is `owner`. The
indices have none today (no `index.default_pipeline` in
elasticsearch-setup.sh); the check is made anyway. A `final_pipeline` cannot be
bypassed, so --apply refuses to run against an index that has one. The script
also guards on `owner == from` inside the update, so a document changed
between the count and the write is left alone.

Rollback: `--reverse` with the same mapping files moves usernames back to
display names, for the pairs that were unambiguous.

Elasticsearch has no host-published port; run from a throwaway container on
the honeynet network, as for backfill-tunnel-attribution.py:

    docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" -v "$PWD/map:/m:ro" \\
      python:3-alpine python /s/workbench-owner-migration.py --keycloak-users /m/users.json
    ... --apply

Env:
    ES_URL   Elasticsearch base URL (default: http://elasticsearch:9200)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

INDICES = ("dashboard-workbench-runs-v1", "dashboard-workbench-recipes-v1")
MAX_OWNERS = 10000


# -- mapping ------------------------------------------------------------------


def load_mapping(path: str) -> list[tuple[str, str]]:
    """(display name, username) pairs from a JSON object or a TSV file."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    pairs: list[tuple[str, str]] = []
    if text.lstrip().startswith("{"):
        for name, users in json.loads(text).items():
            for user in [users] if isinstance(users, str) else users:
                pairs.append((name.strip(), str(user).strip()))
    else:
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            name, tab, user = line.partition("\t")
            if not tab or not name.strip() or not user.strip():
                raise SystemExit(f"{path}:{number}: expected `display name<TAB>username`")
            pairs.append((name.strip(), user.strip()))
    return [(name, user) for name, user in pairs if name and user]


def load_keycloak_users(path: str) -> list[tuple[str, str]]:
    """Pairs from `kcadm.sh get users` output. A user whose `name` claim would
    be empty shows as the username, so contributes (username, username): known,
    nothing to migrate."""
    with open(path, encoding="utf-8") as handle:
        users = json.load(handle)
    if not isinstance(users, list):
        raise SystemExit(f"{path}: expected the JSON array `kcadm.sh get users` prints")
    pairs = []
    for user in users:
        username = str(user.get("username") or "").strip()
        if not username:
            continue
        display = " ".join(part for part in (str(user.get("firstName") or "").strip(), str(user.get("lastName") or "").strip()) if part)
        pairs.append((display or username, username))
    return pairs


@dataclass
class Plan:
    moves: dict[str, str] = field(default_factory=dict)  # owner now -> owner after
    skipped: dict[str, tuple[str, list[str]]] = field(default_factory=dict)  # name -> (reason, users)
    usernames: set[str] = field(default_factory=set)


def build_plan(pairs: list[tuple[str, str]], reverse: bool = False) -> Plan:
    """Decide which names may move. Pure: no Elasticsearch."""
    plan = Plan(usernames={user for _, user in pairs})
    users_of: dict[str, set[str]] = {}
    for name, user in pairs:
        users_of.setdefault(name, set()).add(user)
    candidates: dict[str, str] = {}
    for name, users in sorted(users_of.items()):
        if len(users) > 1:
            plan.skipped[name] = ("ambiguous", sorted(users))
        elif name in plan.usernames and name not in users:
            plan.skipped[name] = ("collision", sorted(users))
        elif name not in users:
            candidates[name] = next(iter(users))
    # Reverse swaps direction over the pairs that were unambiguous going forward.
    if reverse:
        names_of: dict[str, list[str]] = {}
        for name, user in candidates.items():
            names_of.setdefault(user, []).append(name)
        candidates = {}
        for user, names in sorted(names_of.items()):
            if len(names) > 1:
                plan.skipped[user] = ("ambiguous", names)
            else:
                candidates[user] = names[0]
    plan.moves = candidates
    return plan


# -- Elasticsearch ------------------------------------------------------------


class EsError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status = status


class Elasticsearch:
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def request(self, method: str, path: str, body: dict | None = None, timeout: int = 600) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.url}{path}", data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            raise EsError(error.code, error.read().decode(errors="replace")[:600]) from None
        except urllib.error.URLError as error:
            raise EsError(0, str(error.reason)) from None


def owners_in(es, index: str) -> dict[str, int] | None:
    """Owner -> document count, or None when the index does not exist."""
    try:
        result = es.request("POST", f"/{index}/_search", {"size": 0, "track_total_hits": False, "aggs": {"o": {"terms": {"field": "owner", "size": MAX_OWNERS}}}})
    except EsError as error:
        if error.status == 404:
            return None
        raise
    agg = result.get("aggregations", {}).get("o", {})
    if agg.get("sum_other_doc_count"):
        raise SystemExit(f"{index}: more than {MAX_OWNERS} distinct owners; refusing to guess")
    return {bucket["key"]: bucket["doc_count"] for bucket in agg.get("buckets", [])}


def pipelines_of(es, index: str) -> dict[str, str]:
    """The non-trivial default/final pipelines of the index (and its backing
    indices, if it is an alias or data stream)."""
    result = es.request("GET", f"/{index}/_settings/index.default_pipeline,index.final_pipeline?flat_settings=true")
    found: dict[str, str] = {}
    for settings in result.values():
        for key in ("index.default_pipeline", "index.final_pipeline"):
            value = settings.get("settings", {}).get(key)
            if value and value != "_none":
                found[key.split(".")[1]] = value
    return found


def move_owner(es, index: str, old: str, new: str) -> dict:
    """Rewrite `owner` old -> new in one index. `pipeline=_none` stops the
    index's default pipeline from re-running on these updates."""
    body = {
        "query": {"term": {"owner": old}},
        "script": {"lang": "painless", "source": "if (ctx._source.owner == params.old) { ctx._source.owner = params.new } else { ctx.op = 'noop' }", "params": {"old": old, "new": new}},
    }
    return es.request("POST", f"/{index}/_update_by_query?pipeline=_none&conflicts=proceed&refresh=true&wait_for_completion=true", body)


# -- run ----------------------------------------------------------------------


def migrate(es, plan: Plan, apply: bool, out=print) -> int:
    """Report, and with `apply` write. Returns the process exit code."""
    failed = False
    changed_total = 0
    for index in INDICES:
        owners = owners_in(es, index)
        out(f"\n{index}")
        if owners is None:
            out("  absent: nothing to do")
            continue
        pipelines = pipelines_of(es, index)
        if pipelines:
            out(f"  pipelines: {pipelines}" + ("  (default bypassed with pipeline=_none)" if "default_pipeline" in pipelines else ""))
        blocked = "final_pipeline" in pipelines
        if blocked:
            out("  final_pipeline cannot be bypassed: --apply is refused for this index")
        moving = {name: count for name, count in owners.items() if name in plan.moves}
        for name, count in sorted(moving.items()):
            out(f"  {'move' if apply and not blocked else 'would move'}  {count:>6}  {name!r} -> {plan.moves[name]!r}")
        for name, count in sorted(owners.items()):
            if name in plan.moves:
                continue
            if name in plan.skipped:
                reason, users = plan.skipped[name]
                out(f"  SKIPPED {reason:<10} {count:>6}  {name!r}  (users: {', '.join(users)})")
            elif name in plan.usernames or name in plan.moves.values():
                out(f"  ok (no change needed) {count:>6}  {name!r}")
            else:
                out(f"  SKIPPED unmapped   {count:>6}  {name!r}  (no user in the mapping)")
        if not apply or blocked:
            failed = failed or (apply and blocked)
            continue
        for name in sorted(moving):
            try:
                result = move_owner(es, index, name, plan.moves[name])
            except EsError as error:
                out(f"  FAILED {name!r}: {error}")
                failed = True
                continue
            problems = result.get("failures") or []
            conflicts = result.get("version_conflicts", 0)
            changed_total += result.get("updated", 0)
            out(f"  updated {result.get('updated', 0)} for {name!r}" + (f"; {conflicts} version conflicts (re-run)" if conflicts else ""))
            if problems:
                out(f"  FAILED {name!r}: {problems[:3]}")
                failed = True
    out(f"\n{'applied' if apply else 'dry run: nothing written; re-run with --apply'}" + (f", {changed_total} documents updated" if apply else ""))
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mapping", action="append", default=[], metavar="FILE", help="display name -> username (JSON object or TSV)")
    ap.add_argument("--keycloak-users", action="append", default=[], metavar="FILE", help="output of `kcadm.sh get users -r apiary`")
    ap.add_argument("--apply", action="store_true", help="write (default: dry run)")
    ap.add_argument("--reverse", action="store_true", help="rollback: usernames back to display names")
    args = ap.parse_args(argv)
    if not args.mapping and not args.keycloak_users:
        ap.error("give --mapping and/or --keycloak-users: the mapping is never guessed")
    pairs = [pair for path in args.mapping for pair in load_mapping(path)] + [pair for path in args.keycloak_users for pair in load_keycloak_users(path)]
    es = Elasticsearch(os.environ.get("ES_URL", "http://elasticsearch:9200"))
    try:
        return migrate(es, build_plan(pairs, reverse=args.reverse), args.apply)
    except EsError as error:
        print(f"elasticsearch: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
