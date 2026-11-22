<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/apiary-lockup-for-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo/apiary-lockup-for-light.png">
    <img src="assets/logo/apiary-lockup-for-light.png" alt="APIARY — Automated Payload Intelligence &amp; Attacker Response" width="820">
  </picture>
</p>

# APIARY brand system

This folder is the canonical, reusable visual system for APIARY. It packages
the approved bee-and-honeycomb preset into web, repository, social, favicon,
and print-ready forms, with the dark and light palettes below.

This folder is the brand spec, not the dashboard's stylesheet. The live
dashboard is [Xore-Inc/apiary-dashboard](https://github.com/Xore-Inc/apiary-dashboard):
its themes live in that repo's `src/themes/`, are generated with the Astryx
CLI, and its visual decisions are recorded in its `DESIGN.md`. APIARY carries
no dashboard stylesheet and no vendored copy of one. (Until #3834 this folder
was checked against a vendored `Xore/theme` stylesheet, the theme of the
retired in-repo dashboard; that check and the copy were removed with it.)

**Live specimen:** <https://xore.github.io/APIARY/>

## Quick asset selection

| Need | Use |
|---|---|
| Dark website, README, or slide | `assets/logo/apiary-lockup-for-dark.png` |
| Light website, document, or print | `assets/logo/apiary-lockup-for-light.png` |
| App navigation, avatar, or square placement | `assets/logo/apiary-mark-for-dark.png` or `apiary-mark-for-light.png` |
| Navigation below 64 px | `assets/logo/apiary-compact-mark-for-dark.png` or `apiary-compact-mark-for-light.png` |
| Small horizontal placement | `assets/logo/apiary-wordmark-for-dark.png` or `apiary-wordmark-for-light.png` |
| Fixed dark/light raster | `assets/logo/apiary-lockup-on-charcoal.png` or `apiary-lockup-on-ivory.png` |
| Browser and installed-app icons | `assets/favicon/` |
| Link previews | `assets/social/apiary-open-graph-1200x630.png` |
| Social avatar | `assets/social/apiary-avatar-1024.png` |
| Website hero or PDF cover texture | `assets/backgrounds/apiary-hero-background.webp` |
| Web implementation reference | `templates/web/index.html` and `apiary-theme.css` |
| Portable design tokens | `tokens.json` |
| Printable reference | `pdf/APIARY-brand-guide.pdf` |

## Logo system

The horizontal lockup is primary. Use the emblem alone only when the available
space cannot carry the full wordmark and tagline. The themed transparent PNGs
discard the RGB data from the chroma-key pass and rebuild the artwork from its
alpha geometry in approved copper values; this prevents green edge spill.

Rules:

- Keep clear space equal to the height of one `A` stem around the lockup.
- Do not show the horizontal lockup below 420 px wide. Switch to the emblem.
- Do not show the full emblem below 64 px. Use the optically simplified favicon.
- Never stretch, rotate, outline, recolor, glow, or place the mark on a busy image.
- Use the `for-dark` asset on charcoal/dark photography and `for-light` on ivory/white.
- Preserve the tagline exactly: **Automated Payload Intelligence & Attacker Response**.

## Color

### Dark interface

| Token | Hex | Role |
|---|---:|---|
| Background | `#20201f` | page and PDF canvas |
| Sidebar | `#1e1e1c` | navigation and header bands |
| Surface | `#2c2c2a` | cards and controls |
| Raised surface | `#383835` | table heads and emphasized panels |
| Primary text | `#e9e6df` | headings and body copy |
| Secondary text | `#a8a49c` | descriptions |
| Muted text | `#a5a9a6` | metadata |
| Copper | `#d97757` | brand accent and primary actions |

### Light interface

| Token | Hex | Role |
|---|---:|---|
| Background | `#f7f6f2` | page and print canvas |
| Sidebar | `#f0efeb` | navigation and header bands |
| Surface | `#f4f2ed` | cards and controls |
| Raised surface | `#fffefa` | emphasized panels and dialogs |
| Primary text | `#2f2b27` | headings and body copy |
| Secondary text | `#68615a` | descriptions |
| Muted text | `#66615b` | metadata |
| Copper | `#af593f` | brand accent and primary actions |

`#c76548` is the *old* light copper and is not the accent any more. It
survives inside one alpha tint (`--apiary-copper-soft:
rgba(199, 101, 72, 0.12)` in `templates/web/apiary-theme.css`) and in the
print and raster tooling under `scripts/`, so grepping for it still finds
hits; those are leftovers, not the token.

Semantic colors are evidence states, not decoration. Dark mode uses
information blue `#78a9d4`, green `#79c99e`, amber `#deb36a`, and red
`#dc7774`; light-mode values live beside them in `tokens.json`.

Links are **not** blue. They derive from the accent — `#de866b` in dark,
`#9b4f3a` in light. They used to be a standalone blue (`#6da7ec` /
`#2a78d6`), and the light one measured 3.95:1 against a card, below the AA
floor for text; Xore/theme#103 fixed that by deriving links from the accent
rather than keeping a brand blue that failed. A link colour is therefore
theme-scoped, not a brand invariant: a theme is expected to move it, as long
as the result still clears AA.

## Typography and voice

Use Fira Sans for prose, Space Grotesk for headings, and Fira Code for evidence
IDs, timestamps, hashes, protocol labels, and compact eyebrows. The published
stacks include platform-native fallbacks for offline or blocked font requests.
Large headings are tight and direct; operational copy is calm, specific, and
free of hype.

Preferred voice examples:

- “Know the payload. Understand the attacker.”
- “From first touch to analyst-ready context.”
- “Evidence sealed. Analysis queued.”

## Website implementation

Copy `templates/web/apiary-theme.css`, then reuse the assets rather than
embedding them as base64. A minimal responsive header uses theme-aware images:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="apiary-lockup-for-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="apiary-lockup-for-light.png">
  <img src="apiary-lockup-for-light.png" alt="APIARY" width="900">
</picture>
```

Install the favicon family with:

```html
<link rel="icon" href="favicon.ico" sizes="any">
<link rel="icon" type="image/png" sizes="32x32" href="favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="favicon-16x16.png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<link rel="manifest" href="site.webmanifest">
```

## PDF and document branding

Use the light palette for printable reports and the dark palette for
screen-first analyst reports. Keep the mark in a 16-22 mm header zone, copper
section rules at 0.75-1 pt, 18-24 mm page margins, and semantic colors limited
to findings or state. The PDF in `pdf/` demonstrates cover, logo use, palette,
typography, components, and do/don't guidance.

## Repository structure

```text
branding/
├── assets/
│   ├── backgrounds/    # PNG and WebP atmosphere artwork
│   ├── favicon/        # ICO, PNG app icons, manifest
│   ├── logo/           # transparent and fixed-background lockups
│   └── social/         # Open Graph and avatar exports
├── pdf/                # rendered brand guide
├── scripts/            # deterministic export/build tooling
├── source/             # approved preset and alpha geometry masters
├── templates/web/      # reusable HTML/CSS implementation
├── README.md
└── tokens.json
```

Regenerate derived raster assets with:

```powershell
python branding/scripts/export_brand_assets.py
```

Assemble the exact GitHub Pages artifact locally with:

```powershell
python branding/scripts/build_pages_site.py --output tmp/pages-site
```

The source preset and alpha masks are archival production inputs. Do not use
the masks directly in a UI.
