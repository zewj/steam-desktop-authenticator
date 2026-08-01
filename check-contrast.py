"""WCAG contrast audit for the glass themes. Run: python check-contrast.py

Glass makes this non-obvious: text does not sit on a flat colour, it sits on a
composite of base -> tonal wash -> translucent panel. The wash varies across
the window, so each text colour is checked against both extremes of that range
(bare base, and base with the whole wash stacked). Passing both means it passes
everywhere in between.

Reads the tokens straight out of styles.css so the check cannot drift from what
actually ships.
"""

import re
import sys
from pathlib import Path

CSS = Path(__file__).parent / "src" / "styles.css"
AA_TEXT = 4.5
AA_LARGE = 3.0     # >=24px or >=18.66px bold
AA_NON_TEXT = 3.0


def parse_blocks(text: str) -> dict[str, dict[str, str]]:
    """Pull the token blocks for each theme out of the stylesheet."""
    blocks = {}
    for selector, body in re.findall(r"(:root(?:\[data-theme=\"\w+\"\])?)\s*\{([^}]*)\}", text):
        name = "light" if "light" in selector else "dark"
        found = dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body))
        blocks.setdefault(name, {}).update({k: v.strip() for k, v in found.items()})
    # The light block only overrides; start from dark and layer it on.
    merged = dict(blocks.get("dark", {}))
    merged.update(blocks.get("light", {}))
    return {"dark": blocks.get("dark", {}), "light": merged}


def to_rgba(value: str) -> tuple[float, float, float, float]:
    value = value.strip()
    if value.startswith("#"):
        v = value[1:]
        if len(v) == 3:
            v = "".join(c * 2 for c in v)
        return (int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16), 1.0)

    match = re.match(r"rgba?\(([^)]+)\)", value)
    if not match:
        raise ValueError(f"cannot parse colour: {value}")
    parts = [p.strip() for p in match.group(1).replace("/", ",").split(",")]
    r, g, b = (float(p) for p in parts[:3])
    a = float(parts[3]) if len(parts) > 3 else 1.0
    return (r, g, b, a)


def over(top: str, bottom: tuple) -> tuple:
    """Source-over composite of `top` onto an opaque `bottom`."""
    tr, tg, tb, ta = to_rgba(top)
    br, bg, bb, _ = bottom
    return (
        ta * tr + (1 - ta) * br,
        ta * tg + (1 - ta) * bg,
        ta * tb + (1 - ta) * bb,
        1.0,
    )


def luminance(rgb: tuple) -> float:
    def channel(v: float) -> float:
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = rgb[:3]
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def ratio(fg: tuple, bg: tuple) -> float:
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def audit(theme: str, tokens: dict[str, str]) -> list[str]:
    base = to_rgba(tokens["--base"])
    # Extremes of the tonal field. The wash has a bright end (the light from
    # above) and a dark end (the floor shadow); text has to clear both, so each
    # is composited separately rather than averaged.
    lightest = base
    for layer in ("--wash-b", "--wash-a"):
        lightest = over(tokens[layer], lightest)
    darkest = over(tokens["--wash-c"], base)

    surfaces = {}
    for label, token in (("glass", "--glass"), ("glass-hi", "--glass-hi"),
                         ("dialog", "--glass-strong")):
        surfaces[f"{label}/lit"] = over(tokens[token], lightest)
        surfaces[f"{label}/shade"] = over(tokens[token], darkest)

    checks = [
        ("--text", AA_TEXT), ("--muted", AA_TEXT), ("--faint", AA_TEXT),
        ("--accent", AA_TEXT), ("--good", AA_TEXT), ("--warn", AA_TEXT),
        ("--danger", AA_TEXT),
    ]

    failures = []
    print(f"\n=== {theme} ===")
    for token, need in checks:
        fg = to_rgba(tokens[token])
        worst_name, worst = min(
            ((name, ratio(fg, bg)) for name, bg in surfaces.items()),
            key=lambda pair: pair[1],
        )
        ok = worst >= need
        print(f"  {token:<10} worst {worst:5.2f}:1 on {worst_name:<16} "
              f"need {need}  {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"{theme}: {token} is {worst:.2f}:1 on {worst_name}")

    # Primary button: label on the accent fill, both rest and hover.
    on_accent = to_rgba(tokens["--on-accent"])
    for token in ("--accent", "--accent-hi"):
        fill = to_rgba(tokens[token])
        value = ratio(on_accent, fill)
        ok = value >= AA_TEXT
        print(f"  button on {token:<12} {value:5.2f}:1  need {AA_TEXT}  "
              f"{'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(f"{theme}: button label on {token} is {value:.2f}:1")

    # The glass border has to stay visible against the field it sits on.
    for name, bg in (("lit", lightest), ("shade", darkest)):
        edge = over(tokens["--glass-border"], bg)
        panel = over(tokens["--glass"], bg)
        print(f"  glass border/{name:<5} {ratio(edge, panel):5.2f}:1 vs panel  "
              f"(informational)")

    return failures


def main() -> int:
    themes = parse_blocks(CSS.read_text(encoding="utf-8"))
    failures: list[str] = []
    for theme in ("dark", "light"):
        failures += audit(theme, themes[theme])

    print()
    if failures:
        print(f"{len(failures)} FAILING pair(s):")
        for line in failures:
            print(f"  - {line}")
        return 1
    print("All contrast checks pass in both themes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
