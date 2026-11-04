#!/usr/bin/env python3
"""Export (and restore) the dashboard's operator-authored Elasticsearch state.

The stack's Elasticsearch store (`es-data`) is deliberately outside every
backup: it is tens of gigabytes of captured telemetry that a rebuilt stack
does not need in order to come back up. But `es-data` also holds a handful
of small indices whose contents nothing in the pipeline can regenerate --
the ones written by a human through the dashboard, and by nobody else:

  * `dashboard-config-v1`               the admin configuration singleton
  * `dashboard-users-v1`                user projections + per-user preferences
  * `dashboard-alert-state-v1`          operator acks / cooldowns
  * `dashboard-canarytokens-v1`         deployed decoy token definitions
  * `dashboard-credentials-v1`          bait credentials provisioned into honeypots
  * `dashboard-ip-block-v1`             the manual IP block list
  * `dashboard-reports-definitions-v1`  report definitions
  * `dashboard-workbench-recipes-v1`    analysis recipes (immutable revisions)
  * `dashboard-ml-anomaly-ack-v1`       operator acks/notes on ML anomalies
  * `dashboard-problem-reports-v1`      operator-submitted problem reports

`docs/settings-operations.md` used to describe config and users as "covered
by whatever snapshot/backup policy this cluster's other Elasticsearch-owned
dashboard data already has". No such policy has ever existed: `GET _slm/policy`
returns `{}`, the only script that took an ES snapshot was removed, and per
`docs/BACKUP-ESSENTIALS.md` §History it never succeeded once. So these
indices were in no backup at all.

An SLM policy into the `honeypot-fs` repository would NOT fix that. That
repository is `state/elasticsearch-snapshots` on the same host as `es-data`
-- a snapshot there dies with the disk, and `analysis/backup-honeypot.sh`
excludes that path from its archive, so the snapshot would not be backed up
either. It would also reintroduce exactly the coupling
`docs/BACKUP-ESSENTIALS.md` §History blames for taking the config backup
down for a week. So this tool exports the documents instead, as NDJSON, into
the same archive the secrets already travel in -- three destinations, off the
host, encrypted.

What it does NOT do, by design:

* No snapshots, no ILM, no cluster-level state. The bulk telemetry indices
  (`honeypot-v2-*` and the derived `dashboard-*` set listed in `DERIVED`
  below) stay out: every one of them is a pure function of something else,
  so deleting the index is the correct response to losing it. `--list`
  prints the whole split from the same ledger the export walks, so the
  scope cannot drift from the documentation of it.
* No `settings` block in the exported mapping. `GET _mapping` answers with
  server-generated values (`index.uuid`, `index.creation_date`,
  `index.provided_name`, `index.version.created`) that a create-index
  request is not guaranteed to accept, while the part that actually matters
  for reading the documents back -- the field mappings -- is what a restore
  needs. Index templates and ILM policies are re-applied by
  `arcane/home/honeypot-init/analysis/elasticsearch-setup.sh` on a fresh
  cluster anyway, so carrying them would be carrying a copy of the repo.

Reaching Elasticsearch: it publishes no host port (reached by name over the
`honeynet` Docker network), so the default transport is a throwaway
`curlimages/curl` container, digest-pinned on the same policy form as the
fleet's compose images (#1955) for the same reason reset-logs.sh pins its
own (#2348). Set `ES_CURL_BIN` to use a local curl instead -- that is how
the unit tests drive this against a stub.

Usage:
  scripts/es-operator-state-backup.py --dest DIR     # export (what the backups call)
  scripts/es-operator-state-backup.py --list         # print the ledger and the exclusions
  scripts/es-operator-state-backup.py --restore DIR  # put the documents back
  scripts/es-operator-state-backup.py --restore DIR --into 'check-{index}'
                                                       # ...into scratch indices

Env:
  ES_URL               base URL                     (default http://elasticsearch:9200)
  ES_NETWORK           Docker network to join       (default honeynet)
  ES_CURL_BIN          command used to reach ES instead of the pinned
                       container (shlex-split; e.g. `curl`)
  ES_CURL_TIMEOUT      seconds per request          (default 120)
  ES_PAGE_SIZE         documents per scroll page    (default 500)
  ES_MAX_INDEX_BYTES   per-index cap; a page that
                       crosses it is dropped whole   (default 33554432)
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from typing import Any
from dataclasses import dataclass
from pathlib import Path

# --- the ledger -------------------------------------------------------------
#
# One row per index, with the reason it is here. This list is the entire
# scope of the tool: an index not named here is never read. DERIVED below
# names the ones that were checked and left out, so "we looked at the other
# dashboard-*-v1 indices" is a claim the repo can re-verify rather than
# re-litigate.
LEDGER: tuple[tuple[str, str], ...] = (
    ("dashboard-config-v1",
     "admin configuration singleton; only written by an admin save"),
    ("dashboard-users-v1",
     "user projections and per-user preferences; only written by a user"),
    ("dashboard-alert-state-v1",
     "operator acknowledgements and cooldowns; no ILM, so nothing prunes it"),
    ("dashboard-canarytokens-v1",
     "deployed decoy token definitions created through the canarytokens page"),
    ("dashboard-credentials-v1",
     "bait credentials provisioned into honeypot filesystems, with their ids"),
    ("dashboard-ip-block-v1",
     "the manual IP block list the VPS firewall puller consumes every 5 minutes"),
    ("dashboard-reports-definitions-v1",
     "report definitions singleton, operator-authored alongside config"),
    ("dashboard-workbench-recipes-v1",
     "analysis recipes, one immutable document per id:revision"),
    ("dashboard-ml-anomaly-ack-v1",
     "operator acknowledgements and notes on ML anomalies"),
    ("dashboard-problem-reports-v1",
     "operator-submitted problem reports; append-only, no ILM"),
)

# The other dashboard-owned indices, and why they stay out.
DERIVED: tuple[tuple[str, str], ...] = (
    ("dashboard-payload-inventory-v1",
     "rescanned from the payload stores by payload-inventory-worker"),
    ("dashboard-payload-bytes-v1",
     "byte accounting derived from the same scan"),
    ("dashboard-static-analysis-v1",
     "a pure function of a payload's bytes, content-hash keyed"),
    ("dashboard-generated-reports-v1",
     "produced by the reporter from a report definition"),
    ("dashboard-workbench-runs-v1",
     "the result of running a recipe; re-runnable once the recipe is back"),
    ("dashboard-bff-v1-*",
     "auth/session telemetry, written per request"),
    ("dashboard-intelligence-archive-v1",
     "derived from the upstream intel feeds"),
)

LEDGER_INDEXES = tuple(name for name, _ in LEDGER)

# Same pin reset-logs.sh and the fleet's compose images use (#2348/#1955): a
# bare tag would make the backup's HTTP client an unowned mutable input.
CURL_IMAGE = "curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777"

SCROLL_KEEPALIVE = "5m"
NDJSON = "application/x-ndjson"
JSON_CT = "application/json"
ABSENT = "absent"


class TransportError(RuntimeError):
    """The HTTP client itself failed -- curl missing, docker missing, ES down."""


class EsError(RuntimeError):
    """Elasticsearch answered, and the answer was an error."""


@dataclass
class Response:
    status: int
    document: dict

    @property
    def absent(self) -> bool:
        return self.status == 404 and isinstance(self.document.get("error"), dict) \
            and self.document["error"].get("type") == "index_not_found_exception"


class Es:
    """Minimal Elasticsearch client over an external command.

    Every request writes its body to the command's stdin and reads the
    response out of a temp file, so a document larger than any pipe buffer
    (a 200 KB problem-report DOM snapshot is routine here) cannot deadlock
    a `subprocess.run(input=...)` that is also waiting for the response.
    """

    def __init__(self, base: str, command: list[str], timeout: int) -> None:
        self.base = base.rstrip("/")
        self.command = command
        self.timeout = timeout

    def request(self, method: str, path: str, *, body: bytes | None = None,
                content_type: str = JSON_CT,
                body_file: Path | None = None) -> Response:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "response"
            argv = list(self.command) + [
                "-sS", "-X", method, "--max-time", str(self.timeout),
                "-o", str(target), "-w", "%{http_code}",
            ]
            if body is not None or body_file is not None:
                argv += ["-H", f"Content-Type: {content_type}"]
                argv += ["--data-binary", f"@{body_file}" if body_file else "@-"]
            argv.append(self.base + path)
            try:
                proc = subprocess.run(
                    argv,
                    input=b"" if body_file is not None else (body or b""),
                    capture_output=True,
                    check=False,
                )
            except FileNotFoundError as exc:
                raise TransportError(f"{argv[0]}: {exc.strerror}") from exc
            if proc.returncode != 0:
                detail = proc.stderr.decode("utf-8", "replace").strip()
                raise TransportError(
                    f"{method} {path}: {' '.join(argv[:2])} failed "
                    f"(exit {proc.returncode})" + (f": {detail}" if detail else "")
                )
            raw = proc.stdout.decode("ascii", "replace").strip()
            payload = target.read_bytes() if target.is_file() else b""
            try:
                status = int(raw or 0)
            except ValueError as exc:
                raise TransportError(
                    f"{method} {path}: no HTTP status from the client "
                    f"(stdout {raw!r})") from exc
            return Response(status, _decode(method, path, status, payload))

    def json_request(self, method: str, path: str, body: dict | None = None) -> Response:
        return self.request(method, path,
                            body=json.dumps(body).encode() if body is not None else None)

    def file_request(self, method: str, path: str, body_file: Path) -> Response:
        return self.request(method, path, body_file=body_file, content_type=NDJSON)

    def alive(self) -> bool:
        try:
            response = self.json_request("GET", "/")
        except (TransportError, EsError):
            return False
        return response.status == 200

    def index_exists(self, index: str) -> bool:
        response = self.json_request("GET", f"/{index}/_mapping")
        if response.status == 404:
            return False
        if response.status >= 400 or response.document.get("error"):
            raise EsError(f"GET /{index}/_mapping: HTTP {response.status}: "
                          f"{_brief(response.document.get('error'))}")
        return True

    def maybe_exists(self, index: str) -> bool:
        """`index_exists` for the preflight sweep, where an unreadable index
        is 'unknown' rather than fatal: the per-index export that follows
        reports it properly, and one bad index must not abort the sweep
        before the other nine have been refreshed."""
        try:
            return self.index_exists(index)
        except (TransportError, EsError):
            return False


def _decode(method: str, path: str, status: int, payload: bytes) -> dict:
    if not payload:
        return {}
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise EsError(f"{method} {path}: response is not JSON: {payload[:200]!r}") from exc
    if not isinstance(document, dict):
        raise EsError(f"{method} {path}: response is not a JSON object")
    return document


def _brief(error: object) -> str:
    if isinstance(error, dict):
        reason = error.get("reason") or error.get("type") or "error"
        root = error.get("root_cause")
        if isinstance(root, list) and root and isinstance(root[0], dict):
            reason = root[0].get("reason", reason)
        return str(reason)[:300]
    return str(error)[:300]


# --- export -----------------------------------------------------------------


@dataclass
class IndexResult:
    index: str
    status: str          # "ok" | "truncated" | "empty" | "absent" | "failed"
    documents: int = 0
    size: int = 0
    detail: str = ""


def export_index(es: Es, index: str, dest: Path, page_size: int,
                 max_bytes: int) -> IndexResult:
    """Mapping plus every document, as a `_bulk` body for that one index."""
    response = es.json_request("GET", f"/{index}/_mapping")
    if response.absent:
        return IndexResult(index, ABSENT, detail="index does not exist on this cluster")
    if response.status >= 400 or response.document.get("error"):
        raise EsError(f"GET /{index}/_mapping: HTTP {response.status}: "
                      f"{_brief(response.document.get('error'))}")

    # Unwrap the single `{index: {...}}` envelope and keep only `mappings`;
    # see the module docstring for why settings are dropped.
    body: Any = next(iter(response.document.values()), {})
    mappings = body.get("mappings") if isinstance(body, dict) else None
    if not isinstance(mappings, dict):
        raise EsError(f"GET /{index}/_mapping: no mappings block")
    (dest / f"{index}.mapping.json").write_bytes(
        json.dumps({"mappings": mappings}, indent=2, sort_keys=True).encode() + b"\n")

    docs = dest / f"{index}.docs.ndjson"
    total = 0
    written = 0
    truncated = False
    scroll_id = None
    with docs.open("wb") as out:
        while True:
            if scroll_id is None:
                page = es.json_request(
                    "POST",
                    f"/{index}/_search?scroll={SCROLL_KEEPALIVE}&size={page_size}",
                    {"query": {"match_all": {}}})
            else:
                page = es.json_request(
                    "POST", "/_search/scroll",
                    {"scroll": SCROLL_KEEPALIVE, "scroll_id": scroll_id})
            if page.status >= 400 or page.document.get("error"):
                raise EsError(f"scrolling {index}: HTTP {page.status}: "
                              f"{_brief(page.document.get('error'))}")
            scroll_id = page.document.get("_scroll_id") or scroll_id
            hits = (page.document.get("hits") or {}).get("hits") or []
            if not hits:
                break
            for hit in hits:
                # The action line deliberately carries no `_index`: the
                # body is only valid POSTed to `/<index>/_bulk`, which is
                # exactly what `--restore` and the runbook do. Putting the
                # name in the file as well would make it ambiguous which
                # of a mismatching path or a mismatching line wins.
                action = json.dumps({"index": {"_id": hit["_id"]}},
                                    separators=(",", ":")).encode()
                source = json.dumps(hit.get("_source") or {},
                                    separators=(",", ":"), sort_keys=True).encode()
                out.write(action + b"\n" + source + b"\n")
                total += 1
                written += len(action) + 2 + len(source) + 2
            if max_bytes and written > max_bytes:
                # A page boundary, always between documents, so the file
                # stays a valid bulk body for exactly what it holds.
                truncated = True
                break
    if scroll_id:
        # Best effort: a leaked scroll is a resource the cluster ages out
        # on its own, and a failure here must not fail an export that has
        # already produced good files.
        try:
            es.json_request("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})
        except (TransportError, EsError):
            pass

    if total == 0:
        # An index that exists with no documents still gets its mapping
        # recorded -- an empty .ndjson is noise in every archive.
        docs.unlink(missing_ok=True)
        return IndexResult(index, "empty", detail="index exists, no documents")
    return IndexResult(index, "truncated" if truncated else "ok", total, written)


def run_export(es: Es, dest: Path, indexes: tuple[str, ...], page_size: int,
               max_bytes: int) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    if not es.alive():
        print(f"es-operator-state: Elasticsearch is not reachable at {es.base} "
              f"-- nothing exported", file=sys.stderr)
        return 3

    # A document indexed microseconds before the read is invisible to
    # _search until it is refreshed. One refresh across the whole set
    # instead of one per index.
    present = [name for name in indexes if es.maybe_exists(name)]
    if present:
        try:
            es.json_request("POST", f"/{','.join(present)}/_refresh")
        except (TransportError, EsError) as exc:
            print(f"es-operator-state: refresh skipped ({exc})", file=sys.stderr)

    results: list[IndexResult] = []
    for name in indexes:
        try:
            result = export_index(es, name, dest, page_size, max_bytes)
        except (TransportError, EsError) as exc:
            # Per-index isolation: one index that cannot be read must not
            # cost the other nine, which is the entire point of a backup.
            print(f"es-operator-state: {name}: FAILED ({exc})", file=sys.stderr)
            result = IndexResult(name, "failed", detail=str(exc)[:300])
        results.append(result)
        _report(result, max_bytes)

    _write_manifest(dest, results, es.base)
    if not [r for r in results if r.status in ("ok", "truncated")]:
        print("es-operator-state: no index could be exported", file=sys.stderr)
        return 1
    return 0


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB"):
        if value < 1024 or unit == "MiB":
            return f"{value:.0f} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} MiB"


def _report(result: IndexResult, max_bytes: int) -> None:
    if result.status == "ok":
        print(f"  {result.index}: {result.documents} document(s), {_human(result.size)}")
    elif result.status == "truncated":
        print(f"  {result.index}: {result.documents} document(s), "
              f"{_human(result.size)} -- TRUNCATED at the {max_bytes}-byte "
              f"per-index cap", file=sys.stderr)
    elif result.status in (ABSENT, "empty"):
        print(f"  {result.index}: {result.detail}")
    else:
        print(f"  {result.index}: FAILED -- {result.detail}", file=sys.stderr)


def _write_manifest(dest: Path, results: list[IndexResult], source: str) -> None:
    lines = [
        "# APIARY operator state export",
        f"# created  {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"# source   {source}",
        "# tool     scripts/es-operator-state-backup.py",
        "#",
        "# status   index                            documents       size",
        "#   ok / truncated / empty / absent / failed",
        "#",
        "# Restore with:",
        "#   scripts/es-operator-state-backup.py --restore <this directory>",
        "#",
    ]
    for result in results:
        count = f"{result.documents} doc" + ("" if result.documents == 1 else "s")
        detail = f"   # {result.detail}" if result.detail else ""
        lines.append(f"{result.status:<10} {result.index:<34} {count:>9} "
                     f"{_human(result.size):>10}{detail}")
    kept = [r for r in results if r.status in ("ok", "truncated")]
    lines += [
        "#",
        f"# {len(kept)} of {len(results)} indices captured, "
        f"{_human(sum(r.size for r in kept))} of documents.",
    ]
    if any(r.status == "truncated" for r in results):
        lines.append("# TRUNCATED: raise ES_MAX_INDEX_BYTES and re-run -- this "
                     "archive is incomplete for the indices marked so.")
    if any(r.status == "failed" for r in results):
        lines.append("# FAILED: these indices are missing from this archive.")
    (dest / "MANIFEST.txt").write_text("\n".join(lines) + "\n")


# --- restore ----------------------------------------------------------------


def parse_bulk(text: str) -> list[tuple[str, dict]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) % 2:
        raise ValueError(f"bulk body has {len(lines)} lines -- not whole "
                         f"action/document pairs (truncated file?)")
    pairs = []
    for action, source in zip(lines[0::2], lines[1::2]):
        parsed = json.loads(action)
        operation, metadata = next(iter(parsed.items()))
        pairs.append((metadata["_id"], json.loads(source)))
    return pairs


def restore_one(es: Es, index: str, source: Path, template: str) -> tuple[str, int, str]:
    target = template.format(index=index)
    mapping = source / f"{index}.mapping.json"
    docs = source / f"{index}.docs.ndjson"
    if not docs.is_file():
        return target, 0, f"no {index}.docs.ndjson in {source}"
    # Parse before creating anything: a malformed body must not leave a
    # freshly-created empty index behind, which reads as a successful
    # restore of an index that holds nothing.
    try:
        pairs = parse_bulk(docs.read_text(encoding="utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        return target, 0, f"{docs.name} is not a usable bulk body: {exc}"

    if mapping.is_file():
        created = es.request("PUT", f"/{target}", body=mapping.read_bytes())
        if created.status not in (200, 201) and not es.index_exists(target):
            # 400 with the target already present is the normal "restoring
            # over a live index" case; anything else has to be loud.
            return target, 0, (f"could not create {target}: HTTP {created.status}: "
                               f"{_brief(created.document.get('error'))}")

    response = es.file_request("POST", f"/{target}/_bulk", docs)
    if response.status >= 400:
        return target, 0, (f"bulk index into {target} failed: HTTP "
                           f"{response.status}: {_brief(response.document.get('error'))}")
    if response.document.get("errors"):
        return target, 0, f"bulk index into {target} reported failures: " \
                          f"{_bulk_failure(response.document)}"
    es.json_request("POST", f"/{target}/_refresh")
    return target, len(pairs), ""


def _bulk_failure(document: dict) -> str:
    for item in document.get("items", []):
        if not isinstance(item, dict):
            continue
        for result in item.values():
            if isinstance(result, dict) and result.get("error"):
                return _brief(result["error"])
    return "no failing item reported"


def run_restore(es: Es, source: Path, template: str, only: tuple[str, ...]) -> int:
    if not source.is_dir():
        print(f"es-operator-state: {source} is not a directory", file=sys.stderr)
        return 2
    if not es.alive():
        print(f"es-operator-state: Elasticsearch is not reachable at {es.base} "
              f"-- nothing restored", file=sys.stderr)
        return 3

    found = sorted(path.name[: -len(".docs.ndjson")]
                   for path in source.glob("*.docs.ndjson"))
    if only:
        found = [name for name in found if name in only]
    if not found:
        print(f"es-operator-state: no *.docs.ndjson in {source}", file=sys.stderr)
        return 2

    failures = 0
    for index in found:
        target, count, problem = restore_one(es, index, source, template)
        if problem:
            failures += 1
            print(f"  {index} -> {target}: FAILED -- {problem}", file=sys.stderr)
        else:
            print(f"  {index} -> {target}: {count} document(s) restored")
    return 1 if failures else 0


# --- cli --------------------------------------------------------------------


def default_transport() -> list[str]:
    override = os.environ.get("ES_CURL_BIN", "").strip()
    if override:
        return shlex.split(override)
    return ["docker", "run", "--rm", "--network",
            os.environ.get("ES_NETWORK", "honeynet"), CURL_IMAGE]


def positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit(f"{name}={raw!r} is not an integer")
    if value <= 0:
        raise SystemExit(f"{name}={raw!r} must be positive")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="es-operator-state-backup.py",
        description="Export or restore the dashboard's operator-authored "
                    "Elasticsearch state.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dest", type=Path, metavar="DIR",
                      help="export the ledger's indices into DIR")
    mode.add_argument("--restore", type=Path, metavar="DIR",
                      help="restore the documents exported into DIR")
    mode.add_argument("--list", action="store_true",
                      help="print the ledger and the deliberate exclusions")
    parser.add_argument("--into", default="{index}", metavar="TEMPLATE",
                        help="target index name for --restore; {index} expands "
                             "to the exported name (default: %(default)s)")
    parser.add_argument("--index", action="append", default=[], metavar="NAME",
                        help="restrict to NAME; repeatable")
    args = parser.parse_args(argv)

    if args.list:
        print("exported -- operator-authored, nothing regenerates it:")
        for name, why in LEDGER:
            print(f"  {name:<34} {why}")
        print("not exported -- derived from something else, regenerate it instead:")
        for name, why in DERIVED:
            print(f"  {name:<34} {why}")
        return 0

    es = Es(os.environ.get("ES_URL", "http://elasticsearch:9200"),
            default_transport(), positive_int("ES_CURL_TIMEOUT", 120))

    if args.restore is not None:
        return run_restore(es, args.restore, args.into, tuple(args.index))
    indexes = tuple(args.index) or LEDGER_INDEXES
    unknown = [name for name in indexes if name not in LEDGER_INDEXES]
    if unknown:
        print(f"es-operator-state: not in the ledger: {', '.join(unknown)} -- "
              f"either add it with a reason or accept it is never backed up",
              file=sys.stderr)
        return 2
    return run_export(es, args.dest, indexes,
                      positive_int("ES_PAGE_SIZE", 500),
                      positive_int("ES_MAX_INDEX_BYTES", 32 * 1024 * 1024))


if __name__ == "__main__":
    sys.exit(main())
