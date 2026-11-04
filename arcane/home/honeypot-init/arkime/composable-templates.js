// composable-templates.js -- run by arkime-init either side of db.pl (#3343).
//
// Arkime's db.pl installs LEGACY index templates (arkime_sessions3_template,
// arkime_sessions3_ecs_template, arkime_history_v1_template) and re-installs
// them on every init/upgrade run. Elasticsearch applies no legacy template to
// an index once ANY composable template matches it, and this cluster always
// has one: elasticsearch-setup.sh's single-node-replica-default matches "*".
// (It used to carry "-arkime_sessions3-*" alongside, hoping to exclude Arkime;
// composable templates have no exclusion syntax, so those were literal index
// names matching nothing and the claim was false. #3343 removed them rather
// than leaving the comment asserting a mechanism that does not exist.)
// Every arkime_sessions3-* index was therefore created from dynamic defaults --
// firstPacket as long instead of date, node/tags as text, no wordSplit
// analyzer, no dynamic templates.
//
// Two subcommands, run either side of db.pl by honeypot-init/compose.yml:
//
//   shadow    before db.pl: delete every composable template that would cover
//             an Arkime index family -- the two generated below, the #1191
//             arkime-sessions3-ip-fix fragment on clusters that predate them,
//             and single-node-replica-default -- stashing each body first.
//             Decided by glob, not by name, so a renamed or added catch-all is
//             covered too.
//   generate  after db.pl (no argument): read the live legacy templates, merge
//             them the way Elasticsearch merges legacy templates, install one
//             composable template per family, then put everything the shadow
//             stashed back.
//
// Why the shadow cannot be skipped: a composable template covering those
// families is exactly what makes db.pl's own template installation fail.
//
//   illegal_argument_exception: legacy template [arkime_sessions3_template] has
//   index patterns [arkime_sessions3-*] matching patterns from existing
//   composable templates [arkime-sessions3, single-node-replica-default] --
//   use composable templates (/_index_template) instead
//
// Only a CREATE is refused. Re-PUTting a legacy template whose index patterns
// are unchanged is only a warning -- ES 9.5's
// MetadataIndexTemplateService.innerPutTemplate takes the "may be ignored in
// favor of a composable template" branch whenever isUpdateAndPatternsAreUnchanged
// holds -- so a steady-state redeploy survives even unshadowed. `db.pl init` is
// the case that is not: it DELETEs all three legacy templates and creates them
// again, and it is exactly what a fresh cluster and a half-finished earlier
// deploy both need. So a single composable template left behind by a failed
// run refuses init, the next deploy fails the same way, and the stack can
// never finish initialising again without a hand-deleted template: the thing
// that would have to be cleaned up is created by the one-shot that already
// succeeded. Shadowing makes that self-healing; the retry in compose.yml
// covers the one race a shadow cannot -- a template created *while* db.pl runs.
//
// The generated templates translate Arkime's live legacy templates into one
// composable template per index family, merged the way Elasticsearch merges
// legacy templates (ascending order, later wins; dynamic_templates by name),
// plus the three things this cluster needs on top: number_of_replicas 0
// (single node, #3283), ip-typed source.ip/destination.ip (the viewer's
// fixSessionFields crashes on text IPs, #1191), and delete-only retention on
// the sessions family (#3283). Regenerated on every arkime-init run, so it
// follows whatever templates the running Arkime version's db.pl installed.
//
// #3283 retention, and why it lives here rather than in
// elasticsearch-setup.sh next to the other twelve policies:
//
//   * It was missing. Every daily index family in this stack is ILM-managed
//     except arkime_sessions3-*, which grew one index a day forever. #3362
//     removed the dominant term (Zeek's 84 per-day families became 84 per
//     month) and this was the last unbounded one left, so the shard
//     arithmetic still had a term that only ever adds. That is one more way
//     the single node reaches cluster.max_shards_per_node's 1000 default and
//     dead-letters all sensor ingest, as it did on 2026-09-21.
//   * The policy has to exist BEFORE the template that names it, and this
//     script is the only thing that installs that template. Elasticsearch
//     validates index.lifecycle.name at index creation, so a template
//     naming a policy that is not there yet fails the creation outright --
//     and arkime-init and elasticsearch-setup are independent one-shots that
//     race (elasticsearch-setup.sh waits for db.pl's legacy template because
//     of the mirror-image problem). A policy created in elasticsearch-setup
//     could not be relied on to exist before arkime-capture creates an
//     index, and arkime-capture waits only on arkime-init.done, not on
//     elasticsearch-setup.done. Creating the policy here, immediately before
//     the template that references it, is the ordering that cannot lose.
//   * The age is HONEYPOT_RETENTION_DAYS, the same single knob every other
//     window in this stack scales from (#261), passed into this container by
//     honeypot-init/compose.yml. Same window as the raw event stream rather
//     than suricata-7d's 7/30 share: the Arkime viewer and the Kibana "Arkime
//     Sessions" data view (docs/OPERATIONS.md) are supported workflows, and
//     21 shards is not the problem -- unbounded growth was.
//
// A composable template only governs indices created AFTER it is installed,
// so the run also adopts the arkime_sessions3-* indices already on disk.
// Adoption never overwrites an index that carries some other lifecycle name:
// that is an operator's deliberate choice, and this one-shot init job's log
// is the only place a warning about it can surface.
//
// DRY_RUN=1 prints the policy, the generated templates and the adoption
// plan, and changes nothing.
//
// Node 22 (shipped in the Arkime image), no dependencies. Exits non-zero on
// any failure so arkime-init's `set -e` never writes its done-marker over a
// half-applied state.
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ES = (process.env.ARKIME__elasticsearch || 'http://elasticsearch:9200').replace(/\/+$/, '');
const PRIORITY = 11; // above the #1191 ip-fix template (10) it replaces, so there is no gap
const LEGACY_IP_FIX = 'arkime-sessions3-ip-fix';
// /tmp on purpose: the stash only has to outlive the two subcommands in one
// arkime-init run. If db.pl dies, the shadowed templates stay deleted until the
// next deploy, which re-PUTs the catch-all (elasticsearch-setup.sh always does)
// and re-shadows + regenerates here -- so the loss is one deploy of
// number_of_replicas on newly created indices, not a permanent one. Kept out of
// the shared init-markers volume, which is a *.done readiness contract.
// The stash is one deploy's worth of deleted templates and the only record
// that db.pl's originals existed. The `shadow` and `generate` passes are two
// separate processes, so the path is a fixed name under os.tmpdir() rather
// than a fresh mkdtemp (which would not be shared). writeShadow() creates the
// parent 0700 and the file 0600, so it is not exposed through a
// world-writable /tmp -- CodeQL js/insecure-temp-file, and a real
// pre-creation/symlink window on a shared host. SHADOW_FILE still moves it.
const SHADOW_FILE =
  process.env.SHADOW_FILE ||
  path.join(os.tmpdir(), 'arkime-composable-shadow', 'shadow.json');
const DRY_RUN = Boolean(process.env.DRY_RUN);

// #3283: same knob, same 30-day default as elasticsearch-setup.sh's
// `retention_days="${HONEYPOT_RETENTION_DAYS:-30}"`. Junk falls back rather
// than throwing, matching what a missing variable does; a value the shell
// would have choked on stops the whole stack before either of us gets here.
const RETENTION_DAYS = (() => {
  const raw = (process.env.HONEYPOT_RETENTION_DAYS || '').trim();
  if (!raw) return 30;
  const days = Number(raw);
  return Number.isInteger(days) && days > 0 ? days : 30;
})();
// Policy names stay fixed identifiers whose suffix states the shape of the
// window, not the number it currently resolves to -- the same convention
// suricata-7d/dashboard-app-30d follow, for the same reason.
const SESSIONS_POLICY = 'arkime-sessions-30d';

const FAMILIES = [
  {
    name: 'arkime-sessions3',
    pattern: 'arkime_sessions3-*',
    legacy: ['arkime_sessions3_template', 'arkime_sessions3_ecs_template'],
    ipFix: true,
    // #3283: the retention that makes this family bounded.
    retention: SESSIONS_POLICY,
  },
  {
    name: 'arkime-history-v1',
    pattern: 'arkime_history_v1-*',
    legacy: ['arkime_history_v1_template'],
    ipFix: false,
    // No retention, deliberately. config.ini never sets `history=`, so
    // Arkime's default applies and this family is not created at all; it is
    // here only so the template is translated correctly if an operator turns
    // it on, and search history is a different data class from session
    // telemetry with its own retention question to answer (#3283).
    retention: null,
  },
];

// The literal stem of every real index in a family -- anything with a longer
// suffix is still an index of that family, so this is what "does this template
// cover Arkime" has to be asked about.
const STEMS = FAMILIES.map((f) => f.pattern.replace(/\*+$/, ''));

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Recursive object merge; `over` wins on scalar and array conflicts.
function deepMerge(base, over) {
  if (!isObj(base) || !isObj(over)) return over === undefined ? base : over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = k in out ? deepMerge(out[k], v) : v;
  return out;
}

// dynamic_templates is a list of single-key {name: spec} objects, and
// Elasticsearch uses the FIRST entry that matches a field. A higher-order
// template must take precedence, so its entries go first and a same-named
// entry from a lower-order template is dropped. Getting this backwards puts
// arkime_sessions3_ecs_template's catch-all strings_as_keyword (order 1)
// ahead of Arkime's own *Ip / *Tokens rules (order 99), and every *Ip field
// lands as keyword -- verified on a throwaway index.
function mergeDynamicTemplates(listsAscending) {
  const seen = new Set();
  const out = [];
  for (const list of [...listsAscending].reverse()) {
    for (const entry of list || []) {
      const name = Object.keys(entry)[0];
      if (seen.has(name)) continue;
      seen.add(name);
      out.push(entry);
    }
  }
  return out;
}

// Elasticsearch answers "does this template cover that index" with
// Regex.simpleMatch: '*' matches any run of characters, '?' exactly one,
// everything else literal, with no escape character. Mirror that exactly
// instead of hard-coding the names of the templates that happen to overlap
// today, so a catch-all that is renamed, or a second one added later, is
// shadowed too -- that is the whole point of the exercise.
function simpleMatch(pattern, value) {
  const source = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
  return new RegExp(source).test(value);
}

// A template covers a family when its patterns can match *some* index of that
// family, not only the shortest one: `arkime_sessions3-2*` is a per-month
// refinement of a real family, and db.pl's `arkime_sessions3-*` overlaps it just
// as hard as the bare `*` does. Two conditions together cover the shapes that
// actually occur -- the pattern matches the stem outright (a bare `*`, an
// `arkime_*`, an `arkime_sessions3?*`), or the pattern's literal (wildcard-
// free) prefix starts with the stem (`arkime_sessions3-2*`,
// `arkime_history_v1-?`). Testing one invented probe name instead would miss
// both while looking perfectly correct.
function coversStem(patterns, stem) {
  return patterns.some(
    (pattern) => simpleMatch(pattern, stem) || pattern.split(/[*?]/)[0].startsWith(stem)
  );
}

const coversArkime = (template) =>
  (template.index_patterns || []).some((pattern) => STEMS.some((stem) => coversStem([pattern], stem)));

async function es(method, path_, body) {
  const res = await fetch(ES + path_, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}

// ------------------------------------------------------------- the shadow ----

function readShadow() {
  try {
    return JSON.parse(fs.readFileSync(SHADOW_FILE, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw new Error(`reading ${SHADOW_FILE}: ${err.message}`);
  }
}

function writeShadow(shadow) {
  // 0700 dir + 0600 file, and never widened on rewrite: the stash holds the
  // full body of templates that were deleted from the cluster.
  fs.mkdirSync(path.dirname(SHADOW_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(SHADOW_FILE, JSON.stringify(shadow, null, 2) + '\n', { mode: 0o600 });
}

async function shadow() {
  const listed = await es('GET', '/_index_template');
  if (listed.status !== 200) throw new Error(`GET _index_template: HTTP ${listed.status}`);
  const shadowed = readShadow();
  // Anything already in the stash is already deleted, so re-running shadow is
  // a no-op for it and a crash mid-run loses nothing.
  const doomed = (listed.json.index_templates || []).filter(
    (entry) => !(entry.name in shadowed) && coversArkime(entry.index_template || {})
  );
  if (!doomed.length) {
    console.log('shadow: no composable template covers an Arkime index family -- nothing to delete');
    return;
  }
  for (const entry of doomed) {
    if (DRY_RUN) {
      console.log(`shadow (dry run): would stash and delete ${entry.name}`);
      continue;
    }
    // Stash before deleting, never the other way round: a crash in between
    // then leaves a stashed entry for a template that still exists, and
    // re-PUTting that is a no-op, whereas deleting first can lose the body.
    shadowed[entry.name] = entry.index_template;
    writeShadow(shadowed);
    const del = await es('DELETE', `/_index_template/${entry.name}`);
    if (del.status !== 200) throw new Error(`DELETE _index_template/${entry.name}: HTTP ${del.status}`);
    console.log(`shadow: ${entry.name} stashed in ${SHADOW_FILE} and deleted so db.pl can install Arkime's legacy templates`);
  }
}

async function restore(keepOut) {
  const shadowed = readShadow();
  // Never resurrect these from the stash: the generated templates were just
  // rebuilt from the legacy templates db.pl installed a moment ago (or were
  // deliberately skipped because no legacy template exists), and the ip-fix
  // fragment is the #1191 workaround this file replaced.
  for (const name of keepOut) delete shadowed[name];
  for (const name of Object.keys(shadowed)) {
    if (DRY_RUN) {
      console.log(`restore (dry run): would put ${name} back`);
      continue;
    }
    // GET returns these and PUT refuses them as system-managed (#3549). Stripped
    // here rather than at stash time, so a stash written by an older run
    // restores too.
    const { created_date, created_date_millis, modified_date, modified_date_millis, ...body } = shadowed[name];
    const put = await es('PUT', `/_index_template/${name}`, body);
    if (put.status !== 200) {
      throw new Error(`restoring _index_template/${name}: HTTP ${put.status} ${JSON.stringify(put.json)}`);
    }
    delete shadowed[name];
    console.log(`restore: ${name} put back`);
  }
  if (!DRY_RUN) writeShadow(shadowed);
}

// ------------------------------------------------------------ the generate ----

function build(family, legacyTemplates) {
  const sorted = [...legacyTemplates].sort((a, b) => (a.order || 0) - (b.order || 0));
  let settings = {};
  let mappings = {};
  let aliases = {};
  const dyn = [];
  for (const t of sorted) {
    settings = deepMerge(settings, t.settings || {});
    const { dynamic_templates: d, ...rest } = t.mappings || {};
    mappings = deepMerge(mappings, rest);
    dyn.push(d);
    aliases = deepMerge(aliases, t.aliases || {});
  }
  // Cluster-local settings, applied last so they win over whatever the
  // legacy templates said. #3283: same reason number_of_replicas is here --
  // a composable template does not merge with a legacy one, it replaces it,
  // so anything this cluster needs has to be stated explicitly.
  const clusterSettings = { number_of_replicas: '0' };
  if (family.retention) clusterSettings['lifecycle.name'] = family.retention;
  settings = deepMerge(settings, { index: clusterSettings });
  const merged = mergeDynamicTemplates(dyn);
  if (merged.length) mappings.dynamic_templates = merged;
  if (family.ipFix) {
    mappings = deepMerge(mappings, {
      properties: {
        source: { properties: { ip: { type: 'ip' } } },
        destination: { properties: { ip: { type: 'ip' } } },
      },
    });
  }
  const added = family.retention
    ? ` Retained by ${family.retention}; replicas 0 for this single node (#3283).`
    : ' Replicas 0 for this single node (#3283).';
  return {
    index_patterns: [family.pattern],
    priority: PRIORITY,
    template: { settings, mappings, aliases },
    _meta: {
      description: `Generated by arkime-init from Arkime's legacy ${family.legacy.join(' + ')} (#3343).${added} Do not edit; re-run arkime-init.`,
      source: '#3343, #3283',
    },
  };
}

// #3283: delete-only, the same shape as every policy in
// elasticsearch-setup.sh's loop. `hot` has to be present and empty: a
// policy's phases are replaced wholesale, not merged, so omitting it drops
// the phase rather than defaulting it.
function policyBody(minAge) {
  return {
    policy: {
      phases: {
        hot: { actions: {} },
        delete: { min_age: minAge, actions: { delete: {} } },
      },
    },
  };
}

async function ensurePolicy(name, minAge) {
  const body = policyBody(minAge);
  if (process.env.DRY_RUN) {
    console.log(JSON.stringify({ [`_ilm/policy/${name}`]: body }));
    return;
  }
  // PUT is the create-or-replace verb, so this is idempotent across the
  // re-runs arkime-init does on every deploy.
  const put = await es('PUT', `/_ilm/policy/${name}`, body);
  if (put.status !== 200 && put.status !== 201) throw new Error(`PUT _ilm/policy/${name}: HTTP ${put.status} ${JSON.stringify(put.json)}`);
  console.log(`${name}: delete-only ILM policy installed, delete.min_age ${minAge}`);
}

// #3283: put the indices that predate this template under the same policy.
// A composable template only governs what is created after it exists, so
// without this the ~12 daily indices already on disk would stay unmanaged
// forever and the family would keep its current size while appearing fixed.
async function adoptExisting(pattern, policy) {
  // expand_wildcards=all so a closed index is adopted too, and h=index so
  // the reply is a bare list of names.
  const list = await es('GET', `/_cat/indices/${encodeURIComponent(pattern)}?format=json&h=index&expand_wildcards=all`);
  if (list.status !== 200) throw new Error(`GET _cat/indices/${pattern}: HTTP ${list.status} ${JSON.stringify(list.json)}`);
  const rows = Array.isArray(list.json) ? list.json : [];
  const names = rows.map((row) => row && row.index).filter((name) => typeof name === 'string');
  if (process.env.DRY_RUN) {
    console.log(`${policy}: would adopt ${names.length} existing ${pattern} index(es): ${names.join(' ') || '(none)'}`);
    return;
  }
  let adopted = 0;
  let kept = 0;
  for (const name of names) {
    const current = await es('GET', `/${encodeURIComponent(name)}/_settings?flat_settings=true`);
    if (current.status !== 200) throw new Error(`GET /${name}/_settings: HTTP ${current.status} ${JSON.stringify(current.json)}`);
    const existing = ((current.json || {})[name] || {}).settings?.['index.lifecycle.name'];
    if (existing === policy) {
      kept += 1;
      continue;
    }
    if (existing) {
      // Not an error and not something to overwrite: this is the one place
      // an operator-set lifecycle name on an Arkime index can be seen.
      console.log(`${name}: left alone, it already carries index.lifecycle.name=${existing} (this stack's policy is ${policy})`);
      continue;
    }
    const put = await es('PUT', `/${encodeURIComponent(name)}/_settings`, { 'index.lifecycle.name': policy });
    if (put.status !== 200) throw new Error(`PUT /${name}/_settings: HTTP ${put.status} ${JSON.stringify(put.json)}`);
    adopted += 1;
    console.log(`${name}: adopted ${policy}`);
  }
  console.log(`${pattern}: ${adopted} index(es) adopted, ${kept} already on ${policy}`);
}

// Returns the names it installed, so restore() can leave those alone.
async function generate() {
  const installed = new Set();
  // #3283: the families this run actually translated, so adoption can be told
  // apart from a family that was skipped because no legacy template exists.
  const managed = [];
  for (const family of FAMILIES) {
    const found = [];
    for (const name of family.legacy) {
      const r = await es('GET', `/_template/${name}`);
      if (r.status === 404) continue;
      if (r.status !== 200) throw new Error(`GET _template/${name}: HTTP ${r.status}`);
      found.push(r.json[name]);
    }
    if (!found.length) {
      console.log(`${family.name}: none of ${family.legacy.join(', ')} exist yet -- skipped`);
      continue;
    }
    managed.push(family);
    // #3283: before the template, never after. See the header comment.
    if (family.retention) await ensurePolicy(family.retention, `${RETENTION_DAYS}d`);
    const body = build(family, found);
    if (DRY_RUN) {
      console.log(JSON.stringify({ [family.name]: body }));
      continue;
    }
    const put = await es('PUT', `/_index_template/${family.name}`, body);
    if (put.status !== 200) throw new Error(`PUT _index_template/${family.name}: HTTP ${put.status} ${JSON.stringify(put.json)}`);
    // replaceAll, not replace: replace() substitutes only the first '*', so a
    // pattern carrying more than one wildcard would be only partly replaced and
    // the probe would POST against a real index name instead of the synthetic
    // one. Both current patterns hold a single '*', so behaviour is unchanged
    // today; replaceAll keeps it correct as the family table grows.
    const sim = await es('POST', `/_index_template/_simulate_index/${family.pattern.replaceAll('*', 'composable-check')}`);
    const replicas = sim.json?.template?.settings?.index?.number_of_replicas;
    if (replicas !== '0') throw new Error(`${family.name}: simulate shows number_of_replicas=${replicas}, expected 0`);
    if (family.retention) {
      // The #3283 half of the same check. A template whose retention never
      // made it into the composed settings would install cleanly and leave
      // every new index unmanaged -- the exact state this exists to end, and
      // invisible from here, so it is verified rather than assumed.
      // The simulate API returns settings nested ({lifecycle: {name}}), not as
      // the flat key the template was written with (#3551); accept either.
      const index = sim.json?.template?.settings?.index;
      const lifecycle = index?.lifecycle?.name ?? index?.['lifecycle.name'];
      if (lifecycle !== family.retention) {
        throw new Error(`${family.name}: simulate shows index.lifecycle.name=${lifecycle}, expected ${family.retention}`);
      }
    }
    installed.add(family.name);
    console.log(`${family.name}: composable template installed from ${found.length} legacy template(s), priority ${PRIORITY}`);
  }
  // #3283: retention reaches the indices that already exist. Before the
  // dead-template delete below, so a failure there cannot cost this -- and
  // before the DRY_RUN return, so a preview includes the adoption plan.
  for (const family of managed) {
    if (family.retention) await adoptExisting(family.pattern, family.retention);
  }
  if (DRY_RUN) return installed;
  const old = await es('DELETE', `/_index_template/${LEGACY_IP_FIX}`);
  if (old.status === 200) console.log(`${LEGACY_IP_FIX}: removed (superseded by arkime-sessions3)`);
  else if (old.status !== 404) throw new Error(`DELETE _index_template/${LEGACY_IP_FIX}: HTTP ${old.status}`);
  return installed;
}

async function main() {
  const mode = process.argv[2] || 'generate';
  if (mode === 'shadow') return shadow();
  if (mode !== 'generate') throw new Error(`unknown subcommand "${mode}" (expected "shadow" or "generate")`);
  // The restore runs even when generate() throws: the shadowed templates
  // include the replicas catch-all for every index family in the stack, and
  // leaving it deleted because a session mapping went wrong would turn one
  // failure into a yellow cluster until the next deploy.
  const installed = new Set();
  try {
    for (const name of await generate()) installed.add(name);
  } finally {
    await restore(new Set([...installed, LEGACY_IP_FIX]));
  }
}

main().catch((err) => {
  console.error(`composable-templates: ${err.message}`);
  process.exit(1);
});
