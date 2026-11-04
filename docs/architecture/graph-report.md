# Knowledge graph — index

[← back to docs map](../README.md) · [System architecture](../ARCHITECTURE.md)

An auto-generated map of this repository: every file, function, type and test,
grouped into communities by what it touches. Two artifacts are published here:

| Artifact | What it is |
|---|---|
| [`graphify-out/graph.html`](../../graphify-out/graph.html) | explorable graph viewer — open it in a browser, search, filter by community |
| [`graphify-out/GRAPH_REPORT.md`](../../graphify-out/GRAPH_REPORT.md) | the human-readable report: hubs, communities, cohesion, suggested questions |

**Generated:** 2026-10-04, AST-only extraction — no model was called, so the
run cost nothing and node identity is exact. The report records the commit it
was built from, so staleness is checkable:

```sh
git rev-parse HEAD        # compare against the stamp inside the report
```

**Scope:** 27,274 nodes, 54,458 edges, 1,421 communities.

The viewer is a **community meta-graph**: node count sits above the 5000-node
visualization limit, so graphify aggregates one node per community and the
viewer draws 1,421 nodes with 1,927 cross-community edges. Node size is
community member count. Click a node to expand what lives inside it.

## What is not published

The run produces tens of megabytes. Only the two reader-facing artifacts above
are committed; the rest is regenerable and stays out of git.

| Path | Why not |
|---|---|
| `graphify-out/graph.json` | the full graph. `graphify path` / `explain` / `query` read it locally; 38 MB of JSON has no place in a public repository |
| `graphify-out/cache/` | AST cache, rebuild index. Machine-local derived state |
| `graphify-out/manifest.json` | a path→metadata index of every scanned file. Nothing consumes it, and `graphify update` rewrites it whole — a large diff per run for a file no reader opens |
| `graphify-out/.graphify_*.json`, `*.sig`, `.graphify_root` | cluster-label, signature and analysis sidecars. Intermediates, not reader output |

Everything above is listed in `.gitignore`, so a `git add -A` cannot pull a
large generated blob into the public repository.

## Regenerating

```sh
graphify update .     # AST-only, no API cost
```

`graphify update .` re-extracts code files and rewrites `graph.json`,
`GRAPH_REPORT.md` and the viewer. Semantic extraction (the doc/paper/image
corpus) is a separate, model-backed pass — this repo's graph is AST-only, so a
plain `update` is the whole cost. The repo's AGENTS.md already asks for this
after code changes.

To rebuild only the viewer from an existing `graph.json`, without re-extracting:

```sh
graphify export html --graph graphify-out/graph.json \
  --labels graphify-out/.graphify_labels.json --node-limit 5000
```

## Caveats

- **The graph is stale by construction once code lands.** Both published
  artifacts carry the commit they were built from. Treat them as a map of that
  commit, not of `HEAD`.
- **Ad-hoc coder worktrees are excluded.** `oc-*-wt/` directories created in the
  repository root during dispatch are ignored (see `.gitignore`), so they never
  enter the graph. Without that, every artifact counted them as real files —
  which is how a report came to cite a script inside one of them that #3310 had
  already deleted from the mainline tree.
- **Vendored trees still dominate the corpus.** `sandbox/ghosts/vendor/` and the
  bundled frontend libraries appear as their own communities. They are real
  nodes, not noise, but they are not ours to maintain.
- **Community names are labels, not truth.** The label sidecar is regenerated
  per run and the assignment shifts when the graph shifts.