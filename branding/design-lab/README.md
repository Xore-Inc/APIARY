# The design lab

The tooling and the record behind the dashboard's current look.

Until this directory existed, all of it lived in one Claude job's temp
directory and nowhere else. `theme.css` is full of comments like *pick 6E,
supersedes 6D* and *AS-D*, and there was no way to find out what 6D had been
or why 6E replaced it. That is what this preserves (#1763).

The 28M of variant trees and ~150M of `logskel` and harness binaries were
deliberately left out — they are reproducible, and the small files here are
the part that is not.

Real hostnames, the internal server address and a captured attacker IP were
replaced with documentation-range placeholders when these files were moved
into the public repository. Nothing else was edited. This tree is the published
one — `pages.yml` builds `branding/` — so the redaction lives here and not in
the fork that used to hold it; #3310 removed that fork.

## What the pick letters mean

Two rounds of review, and they are easy to get backwards — one local note
already had them the wrong way round. The **second** round is what shipped.

| round | picks | shipped as |
|---|---|---|
| Design refresh | elements `1D/2D/3B/4C/5D/6D/7D/8B/9C/10C`, layouts `OV-B/EV-B/AS-C/RP-C`, shell `11C/12B/13B/14B` | #1573 + Xore/theme#79 |
| **Design refresh 2 — "claude-pure"** | all-**E** element set, `scroll:D events:D sources:D reports:D` | **#1588** + Xore/theme#84–#89, pin `68e3f09` |

So a `pick NE, supersedes ND` comment in `theme.css` is the second round
replacing the first. The letter is the option's position in that component's
gallery in `playground/elements.html` — open it and the letters resolve.

Round two is the live design: floating pill topbar with breadcrumb and
avatar, focus-column overview, minute-grouped event feed with the normalized
record opening only on row click, profile-card source grid, document-style
reports studio, circular scroll button, serif empty states with line icons.

## Standing rules set in the same sessions

Recorded here because they are design decisions with no other home, and they
still apply:

- **No lazy-loading.** A "view more" button instead — infinite scroll hides
  how much there is.
- **Skeleton-first hydration** for anything Elasticsearch populates.
- **One page width** across every page.
- **SPA-feel navigation**: only the centre content refreshes.

## Colour research

The palettes came from a 2026 UI colour-trend pass, not a brand benchmark.
Its findings were mostly about **grounds and neutrals** — elevated neutrals
(soft greys, warm sand, stone, muted clay, oatmeal, taupe), zinc/slate as the
dominant direction for technology products, lime with cool whites for
dashboards, "avoid grey-on-grey fatigue" in dark mode, and earth tones for a
sense of long-term value.

Only the accent half was implementable at the time, because a preset could
reach eight accent tokens. Finishing the other half is #1753.

## The files

| file | what it is |
|---|---|
| `gen_palettes.py` | Generates the accent/link token set per palette per mode and **auto-tunes lightness until every WCAG AA pair passes**. The only executable record of why the palettes are the colours they are. |
| `contrast_scan.js` | The scanning half of the same check, run against a rendered page. |
| `palettes.css` | `gen_palettes.py`'s output, as it was generated. |
| `playground/elements.html` | The decision tool: a per-component option gallery that captures picks in `localStorage` with a "copy picks" export. This is the page the pick letters come from. |
| `playground/compare.html` | Side-by-side variant compare with a drag split. |
| `playground/index.html`, `layouts.html` | The lab's index and layout options. |
| `v5-picks-override.css` | The authoring pattern — a named variant as a token-override block layered on the vendored `theme.css`. |
| `design-notes.md` | The raw review log the picks came out of, per page and per card. |

## Why `v5-picks-override.css` is kept even though v5 lost

It shows the pattern most legibly, and the pattern is the point:

```css
/* VARIANT v5 — "Your Picks"
   claude.ai schema on the Xore palette, with the chosen elements: … */
:root {
  --radius-panel: 16px;
  --radius-control: 12px;
}
.app-sidebar { background: transparent; … }
```

A variant is a small override block on top of the vendored stylesheet, served
on its own port against real Elasticsearch data and reviewed beside the
others. #1753 wants the theme set drafted the same way rather than authored in
the abstract and committed straight upstream.

## What is still missing

The harness that served the variants was an env-guarded Go test
(`dev_serve_test.go`) that booted the real dashboard with a stubbed OIDC
session, a `STATIC_DIR` override and nil write-services so real Elasticsearch
stayed read-only. It went with the Go dashboard in `cb77cdf8` and is not
recoverable from here.

`lab.mjs` was the `frontend-next` equivalent (#1828): it served variants
through the legacy dashboard's dev server behind a read-only backend gate. It
went with `frontend-next` in #3749, and its CI job (`Design lab is read-only`)
with it. The production dashboard (Xore-Inc/apiary-dashboard) does not use
Xore/theme, so there is no UI to serve these variants against. The stylesheets
and notes here stay as the record of the palette decisions; the vendored
`theme.css` they layer on is now `branding/vendor/xore-theme/theme.css`.

`OIDC_DISABLED=1` supplies the stubbed session, so there is no login
round-trip per variant per page.

`gen_palettes.py` has meanwhile been superseded upstream by
`scripts/theme-tokens.mjs` and `check-contrast.mjs` in Xore/theme, which do the
same job in CI over 422 pairs. It is kept here as the record of how the
palettes were derived, not as something to run.

## Related

- #1753 — the multi-theme epic this is a prerequisite for
- #1758 — the theme gallery, which should be built from `elements.html`
  rather than beside it
- Xore/theme#101 — got the AA validation into CI, which is where
  `gen_palettes.py`'s job now lives
