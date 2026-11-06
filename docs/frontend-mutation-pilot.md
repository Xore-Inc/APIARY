> **Retired (#3749, 2026-10-30).** The pilot ran against `frontend-next`, which was
> removed after production moved to Xore-Inc/apiary-dashboard. Its workflow
> (`frontend-testing-pilot.yml`) went with it. This page stays as the record.

# Frontend mutation and property testing pilot (#3326)

Status: pilot complete. **Advisory.** No gate, no ratchet, nothing reads the
score. This page records what was measured, what the measurement is worth, and
why the answer to the issue's actual question — *should there be a ratchet?* —
is not yet.

Scope is the issue's: two checks the dashboard-next frontend did not have, on
the pure logic modules of `arcane/home/honeypot-dashboard/frontend-next`. The
one sentence the argument rests on is that line coverage shows code was
executed, not that a test would notice it changing — a module can be at 100%
line coverage and every one of its tests can still pass when the function is
made to return the wrong thing.

| | |
|---|---|
| Property tests (fast-check) | 9 properties, `src/lib/appearanceCookie.property.test.ts` |
| Mutation run (Stryker) | `stryker.conf.mjs`, 2 files, 466 mutants |
| Runs in PR CI | the property pass only, at 100 runs on a pinned seed |
| Runs nightly | property at 2000 runs on a fresh seed, and the mutation run |
| Gate | none. `continue-on-error`, no `thresholds` block, no reader of the score |

The property file matches `vitest.config.ts`'s own include glob, so it needs no
CI step, no second install and no second run of the same assertions: `npm test`
already picks it up. That is the whole reason the property lane costs nothing
per PR, and it is why the pilot workflow has no `pull_request` trigger at all.

## Results

`stryker run` with `coverageAnalysis: 'off'`, so every mutant met the whole
suite and no verdict depends on Stryker's coverage attribution being right.
Node 22.23.2 (the major the image serves, per #3331), 12 cores, concurrency 6.
**Zero timeouts and zero errors across all 466 mutants** — every mutant was
decided, which is the property that makes the rest of the table mean anything.

| File | Mutation score | Covered score | Killed | Survived | No coverage | Timeout |
|---|---|---|---|---|---|---|
| `appearanceCookie.ts` | 71.43% | 75.27% | 70 | 23 | 5 | 0 |
| `prefs.ts` | 30.16% | 49.12% | 111 | 115 | 142 | 0 |
| **All files** | **38.84%** | **56.74%** | **181** | **138** | **147** | **0** |

"Covered score" is `killed / (killed + survived)`; "mutation score" counts the
no-coverage mutants in the denominator as well. The gap between the two columns
on `prefs.ts` — 30% against 49% — is the whole story of that file: a third of
its mutants are in code nothing reaches, so the score that ignores them looks
nearly twice as good as the one that does not.

### The verdicts are trustworthy, and that was checked rather than assumed

The obvious way for a mutation score to be worthless is for the tool to be
wrong about which mutants its tests cover. Three runs say it is not:

| `coverageAnalysis` | Killed | Survived | No coverage | Timeouts |
|---|---|---|---|---|
| `perTest` | 181 | 138 | 147 | 0 |
| `all` | 181 | 138 | 147 | 0 |
| `off` | 181 | 138 | 147 | 0 |

All 466 mutants were compared individually by id, not just in aggregate: **zero
status differences** between the three. The score is not an artifact of the
coverage strategy.

Seven individual verdicts were then re-derived by hand, with Stryker out of the
loop entirely — the exact replacement applied to the pristine source, the full
suite run, and the mutant's own execution confirmed with a `console.log`
sentinel at the mutation site (because "the suite stayed green" cannot tell an
unreachable mutant from an equivalent one):

| Site | Stryker said | By hand | Verdict correct? |
|---|---|---|---|
| line 48 `modePart = ''` | NoCoverage | never executed; suite green | yes — see below |
| line 48 `themePart = ''` | Survived | executed 259×, suite green | yes — equivalent |
| line 48 `raw.split(':')` | Killed | executed 899×, suite red | yes |
| line 70 decode `catch` | NoCoverage | never entered; suite green | yes |
| line 87 `'; Secure'` | NoCoverage | line reached 23×, branch never taken | yes |
| line 101 `'light'` | NoCoverage | `matchMedia` called once, `matches` always true | yes |
| line 102 `resolveMode` `catch` | NoCoverage | never entered; suite green | yes |

Seven for seven. Two of them are worth spelling out because the first reading of
them is wrong in an interesting way.

**`modePart = ''` is dead code, and Stryker found it.** `String.prototype.split`
always returns at least one element, so index 0 of its result is never
`undefined` and a default value on the *first* destructured element can never
fire. Stryker reported `NoCoverage` with `coveredBy: []` while a mutant 30
columns to the right on the same statement reported 13 covering tests; the
tempting conclusion is a coverage-attribution bug, and it is not one. Stryker
instruments each mutant's own sub-expression separately (the sandbox shows
`stryMutAct("14") ? … : (stryCov("14"), '')` beside `stryCov("16")` on
`split`), and this particular sub-expression genuinely never runs. The
instrumentation confirmed it independently: the sentinel logged zero times.

**`themePart = ''` is an equivalent mutant.** Its default *is* reached — 259
times in one pass — but it is unobservable, because the only thing done with it
is `THEME_NAME.test()`, and `"Stryker was here!"` fails that test exactly as `''`
does. A mutant nobody can kill is a fact about the mutator, not a gap in the
tests, and a ratchet that counted it would be measuring Stryker's string
mutator. The same is true of the other equivalent mutant in the file, the
`if (typeof matchMedia !== 'function') return null` guard on line 99: forcing
its condition to `false` changes nothing, because `matchMedia` is a function in
every environment the suite runs in.

### What the 28 non-killed mutants of `appearanceCookie.ts` actually are

A survivor count is not a to-do list, so each of the 28 was classified by hand.
The classes are worth separating, because only two of the three are work.

| Class | Count | What it is |
|---|---|---|
| A real gap | 25 | code no test looks at |
| Equivalent mutant | 2 | reachable, but no input can distinguish it from the original |
| Dead code | 1 | the unreachable default above |

The 25 real gaps are not evenly spread, and one cluster is most of them:

- **`writeAppearanceCookie` — 17 survivors, lines 84–89.** The suite calls this
  function 23 times, so the code runs; nothing ever reads `document.cookie` back.
  Every assertion on the write path is missing: the `Secure` attribute, the
  `Path`, the `Max-Age`, the `SameSite`, the encode/decode round trip, and the
  `catch` that swallows a blocked cookie. This is the single highest-value
  follow-up in the pilot and it is left in place on purpose — see below.
- **`MAX_AGE_SECONDS` — 3 survivors, line 27.** The cookie's one-year lifetime
  is arithmetic nobody asserts. All three arithmetic mutants survive.
- **`APPEARANCE_COOKIE` — 1 survivor, line 22.** The name `'hp_appearance'` is
  a wire contract with the server and the legacy Go tier, and it is symmetric
  within the file, so no local test can catch a change to it. Arguably
  unkillable in this file by construction.
- **4 more no-coverage gaps** — the `decodeURIComponent` failure path, the
  `Secure` branch, the light branch of `resolveMode`, and its `catch`.

Two of these are *test-environment* gaps rather than logic gaps, which is worth
separating out: the `'; Secure'` mutant and the `'light'` mutant are both
survivors because jsdom serves `http:` and the mocked `matchMedia` always
reports dark. No amount of property over the parser reaches them; they need a
test that sets the environment up.

### `prefs.ts` is a bad mutation target, and that is a result

`prefs.ts` is the issue's own example module, and at 30% it earns its place in
this page for what it shows rather than for its score. Its 142 no-coverage and
115 surviving mutants are overwhelmingly module-scope wiring —
`createServerFn({ method: 'GET' })` literals, the `DEFAULT_MAP_PREFS` object, and
the `createServerFn` call shape. A mutant that changes `'GET'` to `''` is not a
bug in the code; it is a statement that the server-function transport is not
unit-tested, which is a different problem with a different fix (a transport
double), and folding it into a logic score dilutes the score for the modules
that have logic.

## What the property tests are worth

Nine properties, and the number that matters is not the pass rate but what they
catch. Fifteen defects were injected into the pair — one at a time, each
asserted to have actually applied before the suite ran, since two mutations in
an earlier ad-hoc harness had silently failed to apply and been scored as
survivors:

| # | Injected defect | Result |
|---|---|---|
| D01 | parse drops the theme shape rule | killed |
| D02 | parse also accepts `system` as a mode | killed |
| D03 | parse case-folds the mode | killed |
| D04 | parse trims the mode | killed |
| D05 | serialise emits `system` for the null mode | killed |
| D06 | serialise upper-cases the theme | killed |
| D07 | serialise drops the theme unconditionally | killed |
| D08 | serialise joins with `-` instead of `:` | killed |
| D09 | `readAppearanceCookie` matches on suffix | killed |
| D10 | `readAppearanceCookie` does not decode | killed |
| D11 | parse reads the two segments in the wrong order | killed |
| D12 | parse returns the theme part unvalidated | killed |
| D13 | cookie bound widened to `{2,32}`, applier left at `{2,31}` | killed |
| D14 | applier bound narrowed to `{2,30}`, cookie left at `{2,31}` | killed |
| D15 | `readAppearanceCookie` scans an empty list | killed |

**15 of 15, and deterministically** — every one verified red on five
consecutive runs, not once.

## Two defects the pilot found in the pilot's own test file

Worth recording because they are the argument for the defect-injection harness
being a real artifact rather than a throwaway, and because the second one is a
flaky test in a suite that PRs depend on.

**The property suite was not deterministic.** `PARAMS` pinned a seed only when
`FC_SEED` was set, and nothing sets it — CI runs plain `npm test`. fast-check's
default seed is `Date.now()`, so every PR drew a different hundred cases. The
file's own header claimed the opposite ("a red run is a red run forever rather
than a coin flip"), and the claim was false. Concretely: with `prefs.ts`
narrowed to `{2,30}`, D14 went red on one run of three and green on the next
two, so a real cross-layer defect could be merged on a green run. Fixed by
pinning a default seed; `FC_SEED=random` remains the nightly's opt-in.

**The length bound was never generated.** The theme-name generator built its
tail with `fc.array(…, { minLength: 2, maxLength: 31 })`, and an array's length
tracks fast-check's `size`, which starts small — over a 100-run pass the longest
name it produced was **15 characters**. A one-character edit to the theme-shape
bound announces itself only as a name of exactly length 32 or 33, so the
generator was not reaching the only case the cross-layer property exists for.

The first fix was wrong in an instructive way. Drawing the length explicitly and
slicing a full-length tail made D14 reliable — and then D13 passed silently on
every run, because the now-pinned seed's hundred draws happened not to include a
33-character name. Pinning a seed turns a flaky miss into a *permanent* one,
which is worse in the way that matters. A sampled list is not a guarantee, so
the bound is now swept exhaustively: `themeLength` enumerates the lengths around
the bound and a ninth property asserts the two files agree at each. With both
directions of drift caught 5/5 and the clean suite green 5/5.

## TypeScript 7 incompatibility, and the workaround

Stryker 10.0.0 cannot run against this repository's pinned `typescript@7.0.2`.
It fails before the first mutant:

```text
TypeError: ts.parseConfigFileTextToJson is not a function
    at TSConfigPreprocessor.rewriteTSConfigFile
```

TypeScript 7 is the native (Go) compiler; its entry point exports `version` and
`versionMajorMinor` and none of the TypeScript 5 compiler API Stryker reaches
for. `tsconfigFile: null` is the other door out and Stryker's own schema
validator rejects it (`should be a string, but was a null`).

The workaround is `ignorePatterns: ['/tsconfig.json']`, and it is safe *for this
project specifically* on evidence rather than on hope: the tsconfig has no
`extends` and no `references`, so the rewrite Stryker wants is a no-op here;
`grep -rl "from '#/\|from '@/" src/` returns zero files, so no source resolves
through the `paths` it carries; there are no `.test.tsx` files for `jsx` to
apply to; and the full suite passes 206/206 with the file moved aside. The full
reasoning, and the two conditions under which the line should be revisited, are
at the bottom of `stryker.conf.mjs`.

## Recommendation: no ratchet yet

The issue asks for a decision on a ratchet. The answer is **not yet**, for four
reasons, in order of how much they would matter:

1. **#3318 is still open.** The issue names it as the blocker and it has not
   landed. A mutation ratchet with no line-coverage baseline underneath it has
   nothing to sit on, and the two metrics disagree sharply enough here (30% vs
   49% on one file) that reading one without the other is how a number gets
   quoted out of context.
2. **The number is not yet a statement about test quality.** Of 28 non-killed
   mutants on the one well-targeted file, 2 are unkillable and 1 is dead code.
   A ratchet would move when Stryker's mutator set changes, which is not
   something a test author did.
3. **The biggest finding is unfixed.** 17 of those 28 sit in
   `writeAppearanceCookie`, which no test observes at all. Any baseline
   recorded today sits 17 mutants below where the same week could put it, and a
   ratchet anchored to a number you already know is wrong is a ratchet that
   fires on its first honest improvement.
4. **The file list is not ratchet-shaped.** `prefs.ts` is 30% mostly because it
   is a transport-wiring module, and gating on it measures the file's shape.

What the pilot does support: keep the nightly, and when #3318 lands a baseline,
re-measure and reconsider — for the pure module only, after the cookie-write
path is covered, and with the equivalent mutants either excluded or written
down. The nightly is already positioned for that: the score is recorded and a
human reads it.

## Follow-ups, in the order they are worth doing

1. **Cover `writeAppearanceCookie`** — the 17-mutant cluster. The write path is
   the one part of this module that talks to the browser, and it is the one part
   with no assertion on it.
2. **Assert the cookie's lifetime and name** — `MAX_AGE_SECONDS` and
   `APPEARANCE_COOKIE` are three and one survivors respectively, and the name is
   a contract with the Go tier that no TypeScript test can see.
3. **Give `resolveMode` a light case and an `https` case** — two of the four
   no-coverage gaps are test-environment gaps, closable by setting up the
   environment rather than by writing new logic.
4. **Delete the unreachable `modePart = ''` default**, or leave it and note why.
   It is Stryker's only dead-code finding here and it is a one-character change
   that removes a mutant nothing can ever kill.
5. **Do not add `prefs.ts` to a ratchet** without a server-function transport
   double first.

The first four are left undone on purpose. Closing them here would make this
page's numbers a record of a suite that had already been fixed rather than a
baseline a later ratchet could be measured against, which is the one thing the
pilot was run to produce.

## Reproducing

```bash
cd arcane/home/honeypot-dashboard/frontend-next
npm ci
npm test                                    # includes the 9 properties, pinned seed
npm run test:mutation                        # the two-module run
FC_SEED=random FC_NUM_RUNS=2000 npm run test:property   # the nightly search
```

Use the node major the image serves (22.23.2). The mutation run is ~3 minutes
at concurrency 6, ~6 at the config's default 2, against 466 mutants and 65
tests in the dry run. `stryker.conf.mjs` mutates only the two named files and
has no `thresholds` block; `workflow_dispatch` can narrow it to one file
through the `mutate` input while reproducing a specific survivor.
