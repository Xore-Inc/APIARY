#!/usr/bin/env python3
"""Fail when portable APIARY tokens drift from the vendored Xore/theme.

Covers colours (per theme, both modes), radii and type families. Anything
not listed here is unchecked and will drift without anyone noticing -- which
is how the radii got three steps out of date (#1760).
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
# #1659: repointed at frontend-next after the Go dashboard's retirement;
# #3749: the vendored copy moved to branding/vendor when frontend-next left.
THEME = ROOT / "branding" / "vendor" / "xore-theme" / "theme.css"
TOKENS = ROOT / "branding" / "tokens.json"

# Xore/theme#104 renamed the surface and text tokens to numbered ramps and
# moved both modes into a single light-dark() declaration. The old names on
# the right of this map (app-bg, surface-1, text-primary, ...) no longer
# exist. Where a rename was not one-to-one it is called out, because picking
# the wrong rung is a silent mismatch rather than an error:
#
#   surface -> bg-200, not bg-100. bg-100 is the raised card tint; bg-200 is
#   the surface the old surface-1 actually carried (#f4f2ed light).
MAPPING = {
    "background": "bg-000",
    "sidebar": "bg-sidebar",
    "surface": "bg-200",
    "surfaceRaised": "bg-raised",
    "text": "text-000",
    "textSecondary": "text-100",
    "textMuted": "text-200",
    "accent": "accent",
    "link": "text-link",
    "info": "info",
    "success": "success",
    "warning": "warning",
    "danger": "danger",
}

# The default theme's block. Its selector list is `:root, [data-hp-theme=
# "claude"], [data-hp-palette="claude"]`, so anchoring on the palette alias
# finds it without depending on which of the three comes first.
DEFAULT_THEME_MARKER = '[data-hp-palette="claude"] {'

# Radii are not theme-scoped -- they live in the base :root block, not in a
# theme's token set -- so they are read from there rather than from the
# default theme's block.
#
# These were drifting silently until #1760: tokens.json said 9/14/18 while
# the stylesheet had moved to 12/16/24 in the design refresh, and this script
# passed the whole time because it only compared colours. A check that covers
# one kind of token reports "in sync" about everything it does not look at.
RADIUS_MAPPING = {
    "control": "radius-control",
    "panel": "radius-panel",
    "dialog": "radius-dialog",
}



def block(css: str, marker: str) -> str:
    start = css.index(marker) + len(marker)
    end = css.index("\n}", start)
    return css[start:end]


def variables(css_block: str) -> dict[str, dict[str, str]]:
    """Both modes of every hex token in a block.

    Tokens are declared once as `light-dark(#light, #dark)` rather than twice
    in two blocks, so a single parse yields both modes. Non-hex values --
    the rgba() borders and soft fills -- are skipped: they are not part of
    the portable brand contract, and matching them here would mean teaching
    this script alpha compositing to say anything useful about them.
    """
    pairs = re.findall(
        r"--([\w-]+):\s*light-dark\(\s*(#[0-9a-fA-F]{6})\s*,\s*(#[0-9a-fA-F]{6})\s*\)\s*;",
        css_block,
    )
    return {name: {"light": light, "dark": dark} for name, light, dark in pairs}


def main() -> None:
    css = THEME.read_text(encoding="utf-8")
    token_data = json.loads(TOKENS.read_text(encoding="utf-8"))
    theme_values = variables(block(css, DEFAULT_THEME_MARKER))

    failures: list[str] = []
    missing = sorted(set(MAPPING.values()) - set(theme_values))
    if missing:
        # A rename upstream, not a drifted value. Say which, because the
        # KeyError this used to raise named one token and implied a broken
        # script rather than a moved contract.
        failures.append(
            "these tokens are no longer in the default theme block, so the "
            "mapping above is stale: " + ", ".join(f"--{name}" for name in missing)
        )
    else:
        for mode in ("light", "dark"):
            branded = token_data["color"][mode]
            for token_name, theme_name in MAPPING.items():
                expected = theme_values[theme_name][mode].lower()
                actual = branded[token_name]["$value"].lower()
                if actual != expected:
                    failures.append(
                        f"color.{mode}.{token_name} is {actual}, "
                        f"but Xore/theme --{theme_name} is {expected}"
                    )

    radius_declared = dict(re.findall(r"--(radius-[\w-]+):\s*(\d+px)\s*;", css))
    branded_radius = token_data.get("radius", {})
    for token_name, theme_name in RADIUS_MAPPING.items():
        expected = radius_declared.get(theme_name)
        if expected is None:
            failures.append(f"Xore/theme --{theme_name} is not declared as a plain px value")
            continue
        actual = branded_radius.get(token_name, {}).get("$value")
        if actual != expected:
            failures.append(
                f"radius.{token_name} is {actual}, but Xore/theme --{theme_name} is {expected}"
            )

    font_mapping = {"sans": "font-sans", "display": "font-display", "mono": "font-mono"}
    for token_name, theme_name in font_mapping.items():
        match = re.search(rf"--{theme_name}:\s*\"([^\"]+)\"", css)
        if not match:
            failures.append(f"Xore/theme --{theme_name} has no primary quoted family")
            continue
        actual = token_data["font"][token_name]["$value"]
        if actual != match.group(1):
            failures.append(
                f"font.{token_name} is {actual!r}, "
                f"but Xore/theme --{theme_name} starts with {match.group(1)!r}"
            )

    if failures:
        raise SystemExit("APIARY brand tokens have drifted from Xore/theme:\n- " + "\n- ".join(failures))
    print("APIARY brand tokens match the vendored Xore/theme contract")


if __name__ == "__main__":
    main()
