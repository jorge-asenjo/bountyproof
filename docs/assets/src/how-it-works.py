# /// script
# requires-python = ">=3.10"
# dependencies = ["fonttools>=4.40", "brotli>=1.0"]
# ///
"""Build the README diagram: docs/assets/how-it-works.svg and how-it-works.es.svg.

    uv run docs/assets/src/how-it-works.py

The canvas is 840 units wide because GitHub shows README images at 838px on desktop, so one unit is one
pixel on screen and the font sizes below are the sizes people read. Keep body text at 14px or more.

The SVGs embed subsets of Inter and JetBrains Mono (SIL Open Font License 1.1) so the layout is the
same on every OS; the fonts are downloaded from Google Fonts once and cached in the temp folder.
`--system-fonts` skips the embedding, to check how the fallback fonts fit.
"""

from __future__ import annotations

import argparse
import base64
import io
import re
import tempfile
import urllib.request
from html import escape, unescape
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent

W, H = 840, 524
TOP = 148  # Radar and the payout, above the fence
FX1, FY1, FX2, FY2 = 24, 252, 816, 452  # the scope-guard fence
CY = 350  # the agents, inside the fence
R = 30
X = {"recon": 132, "hunters": 276, "validator": 420, "judge": 564, "writer": 708}
MID = (FX1 + FX2) / 2

BG, BORDER = "#0b1018", "#232c3b"
FG, DIM = "#e6edf3", "#93a0b2"
BLUE, BLUE_FILL, BLUE_ICON = "#3b82f6", "#111d33", "#9cc0ff"
CORAL, CORAL_FILL, CORAL_ICON = "#d97757", "#2a1711", "#f4a682"
GREEN, GREEN_FILL, GREEN_ICON = "#22c55e", "#0f2418", "#7ee2a4"
GOLD, GOLD_FILL, GOLD_TEXT = "#f2c14e", "#231b08", "#f6e7bf"
RED, RED_TEXT, RED_FILL = "#e5545e", "#ff9aa1", "#1c1015"

SANS = 'bpInter, "Segoe UI", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif'
MONO = 'bpMono, ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'
FONTS_CSS = "https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;700"
FACES = [("Inter", "bpInter", 400), ("Inter", "bpInter", 600), ("Inter", "bpInter", 700)]
FACES += [("JetBrains Mono", "bpMono", 400), ("JetBrains Mono", "bpMono", 700)]

# The lead counts come from the real run in docs/examples/juice-shop/funnel.txt.
STRINGS = {
    "en": {
        "eyebrow": "HOW BOUNTYPROOF WORKS",
        "headline": "The agents hunt and prove. You approve the scope and press submit.",
        "radar": ("Radar", "watches 3 platforms"),
        "alert": "alerts you",
        "you": "YOU",
        "gate1": "approve the scope",
        "gate2": "press submit",
        "hunt": "runs this on its own",
        "names": {"recon": "Recon", "hunters": "Hunters", "validator": "Validator", "judge": "Judge"},
        "writer": "Writer",
        "counts": [("22", "leads"), ("17", "reproduced"), ("16", "passed")],
        "payout": "payout",
        "guard": "SCOPE GUARD",
        "guard_desc": "blocks anything out of scope",
        "caption": "Numbers from one real run against the demo lab.",
        "desc": (
            "Radar watches the bug bounty platforms and alerts you. You approve the scope. Inside the scope "
            "guard, which blocks anything out of scope, /bountyproof:hunt runs Recon, the Hunters in parallel, "
            "the Validator, the Judge and the Writer on its own. In one real run against the demo lab, 22 leads "
            "became 17 reproduced and 16 passed. You press submit and get the payout."
        ),
    },
    "es": {
        "eyebrow": "CÓMO FUNCIONA BOUNTYPROOF",
        "headline": "Los agentes cazan y lo prueban. Tú apruebas el scope y pulsas enviar.",
        "radar": ("Radar", "vigila 3 plataformas"),
        "alert": "te avisa",
        "you": "TÚ",
        "gate1": "apruebas el scope",
        "gate2": "pulsas enviar",
        "hunt": "hace todo esto solo",
        "names": {"recon": "Recon", "hunters": "Cazadores", "validator": "Validador", "judge": "Juez"},
        "writer": "Redactor",
        "counts": [("22", "pistas"), ("17", "reproducidas"), ("16", "aprobadas")],
        "payout": "cobras",
        "guard": "GUARD DE SCOPE",
        "guard_desc": "bloquea todo lo que está fuera de scope",
        "caption": "Cifras de una ejecución real contra el lab de demo.",
        "desc": (
            "El Radar vigila las plataformas de bug bounty y te avisa. Tú apruebas el scope. Dentro del guard "
            "de scope, que bloquea todo lo que está fuera de scope, /bountyproof:hunt ejecuta solo Recon, los "
            "Cazadores en paralelo, el Validador, el Juez y el Redactor. En una ejecución real contra el lab de "
            "demo, 22 pistas se quedaron en 17 reproducidas y 16 aprobadas. Tú pulsas enviar y cobras."
        ),
    },
}

# Every text style: (font size in px, weight, letter-spacing in em, mono). The CSS and the measuring share it.
TYPE = {
    "eyebrow": (13, 700, 0.16, False),
    "h1": (20, 700, 0, False),
    "name": (17, 700, 0, False),
    "desc": (14, 400, 0, False),
    "unit": (14, 400, 0, False),
    "count": (15, 700, 0, False),
    "xn": (12.5, 700, 0, False),
    "youtag": (12, 700, 0.14, False),
    "youlabel": (16, 600, 0, False),
    "cmd": (14, 700, 0, True),
    "tab": (14, 400, 0, False),
    "guard": (13, 700, 0.12, False),
    "guarddesc": (14, 400, 0, False),
    "cap": (13, 400, 0, False),
    "coin": (19, 700, 0, False),
}
COLOR = {
    "eyebrow": DIM,
    "h1": FG,
    "name": FG,
    "desc": DIM,
    "unit": DIM,
    "count": FG,
    "xn": "#ffffff",
    "youtag": GOLD,
    "youlabel": GOLD_TEXT,
    "cmd": FG,
    "tab": "#c9d6ea",
    "guard": RED_TEXT,
    "guarddesc": "#d9b8bc",
    "cap": "#7d8a9b",
    "coin": "#5a3d05",
}

STYLE = """
      text {{ font-family: {sans}; }}
{classes}
      .wire {{ stroke: #3d4a5e; stroke-width: 2.5; fill: none; }}
      .flow {{ stroke: {blue}; stroke-width: 2.5; stroke-linecap: round; stroke-dasharray: 0.1 10;
               fill: none; opacity: .9; animation: flow 1.1s linear infinite; }}
      .sweep {{ transform-origin: 0 0; animation: spin 3.2s linear infinite; }}
      .blip {{ animation: blip 3.2s ease-in-out infinite; }}
      .pulse {{ transform-box: fill-box; transform-origin: center; animation: pulse 2.6s ease-out infinite; }}
      @keyframes flow {{ to {{ stroke-dashoffset: -10.1; }} }}
      @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
      @keyframes blip {{ 0%, 20% {{ opacity: .15; }} 36% {{ opacity: 1; }} 75%, 100% {{ opacity: .15; }} }}
      @keyframes pulse {{ 0% {{ opacity: .9; transform: scale(.9); }} 100% {{ opacity: 0; transform: scale(1.3); }} }}
      @media (prefers-reduced-motion: reduce) {{ .flow, .sweep, .blip, .pulse {{ animation: none; }} }}
"""

DEFS = """
    <pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse">
      <circle cx="1.5" cy="1.5" r="1" fill="#ffffff" opacity=".045"/>
    </pattern>
    <radialGradient id="glowBlue" cx="50%" cy="50%" r="60%">
      <stop offset="0" stop-color="{BLUE}" stop-opacity=".10"/><stop offset="1" stop-color="{BLUE}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="glowCoral" cx="50%" cy="50%" r="50%">
      <stop offset="0" stop-color="{CORAL}" stop-opacity=".16"/><stop offset="1" stop-color="{CORAL}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="sweepGrad" gradientUnits="userSpaceOnUse" x1="-14.7" y1="-8.5" x2="0" y2="-17">
      <stop offset="0" stop-color="{BLUE_ICON}" stop-opacity=".02"/>
      <stop offset="1" stop-color="{BLUE_ICON}" stop-opacity=".6"/>
    </linearGradient>
    <radialGradient id="coin" cx="40%" cy="35%" r="70%">
      <stop offset="0" stop-color="#ffe08a"/><stop offset=".6" stop-color="{GOLD}"/>
      <stop offset="1" stop-color="#b9861f"/>
    </radialGradient>
    <filter id="blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="8"/></filter>
    <marker id="arrow" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="11" markerHeight="11"
            markerUnits="userSpaceOnUse" orient="auto">
      <path d="M0 0 L10 5 L0 10 z" fill="#5b6b82"/>
    </marker>
"""


def css_classes():
    rules = []
    for cls, (size, weight, spacing, mono) in TYPE.items():
        extra = f" letter-spacing: {spacing}em;" if spacing else ""
        extra += f" font-family: {MONO};" if mono else ""
        rules.append(f"      .{cls} {{ font-size: {size}px; font-weight: {weight}; fill: {COLOR[cls]};{extra} }}")
    return "\n".join(rules)


_METRICS = {}


def width(s, cls):
    """Width of `s` in px, from the advance widths of the font that gets embedded (kerning ignored)."""
    size, weight, spacing, mono = TYPE[cls]
    key = ("JetBrains Mono" if mono else "Inter", weight)
    if key not in _METRICS:
        from fontTools.ttLib import TTFont

        font = TTFont(font_files()[key])
        _METRICS[key] = (font.getBestCmap(), font["hmtx"], font["head"].unitsPerEm)
    cmap, hmtx, upm = _METRICS[key]
    units = sum(hmtx[cmap.get(ord(c), cmap[32])][0] for c in s)
    return units * size / upm + spacing * size * len(s)


def text(x, y, s, cls, anchor="middle"):
    return f'<text x="{x:g}" y="{y:g}" class="{cls}" text-anchor="{anchor}">{escape(s)}</text>'


# ---------- icons, drawn around (0, 0) in a ~40px box ----------
def icon_radar(c):
    # The sweep trails the line: it rotates clockwise, the fade sits counter-clockwise of it.
    return f"""
    <circle r="17" fill="none" stroke="{c}" stroke-width="1.6" opacity=".45"/>
    <circle r="10" fill="none" stroke="{c}" stroke-width="1.6" opacity=".45"/>
    <g class="sweep">
      <path d="M0 0 L0 -17 A17 17 0 0 0 -14.7 -8.5 Z" fill="url(#sweepGrad)"/>
      <line x1="0" y1="0" x2="0" y2="-17" stroke="{c}" stroke-width="2.2" stroke-linecap="round"/>
    </g>
    <circle r="2.6" fill="{c}"/>
    <circle cx="9" cy="6" r="2.4" fill="#ffb27a" class="blip"/>"""


def icon_recon(c):
    pts = [(-12, -9), (11, -12), (-9, 11), (12, 9), (1, 0)]
    edges = [(0, 4), (1, 4), (2, 4), (3, 4), (0, 2), (1, 3)]
    lines = "".join(f'<line x1="{pts[a][0]}" y1="{pts[a][1]}" x2="{pts[b][0]}" y2="{pts[b][1]}"/>' for a, b in edges)
    dots = "".join(f'<circle cx="{x}" cy="{y}" r="3.6" fill="{BLUE_FILL}"/>' for x, y in pts)
    return f'<g stroke="{c}" stroke-width="2" stroke-linecap="round" fill="none">{lines}{dots}</g>'


def icon_hunt(c):
    return f"""<g stroke="{c}" stroke-width="2.6" stroke-linecap="round" fill="none">
      <circle cx="-4" cy="-4" r="10"/><line x1="3.5" y1="3.5" x2="13" y2="13"/></g>"""


def icon_validate(c):
    return f"""<g stroke="{c}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" fill="none">
      <path d="M13 -2 A13 13 0 1 1 7 -11"/><path d="M2 -14 L8 -11 L5.5 -5"/><path d="M-6 0 L-1.5 4.5 L6 -4"/></g>"""


def icon_judge(c):
    return f"""<g stroke="{c}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none">
      <line x1="0" y1="-13" x2="0" y2="13"/><line x1="-8" y1="13" x2="8" y2="13"/>
      <line x1="-15" y1="-8" x2="15" y2="-8"/><circle cy="-14" r="2" fill="{c}"/>
      <path d="M-15 -8 L-20 3 M-15 -8 L-10 3"/><path d="M-21 3 Q-15 10 -9 3 Z"/>
      <path d="M15 -8 L10 3 M15 -8 L20 3"/><path d="M9 3 Q15 10 21 3 Z"/></g>"""


def icon_write(c):
    return f"""<g stroke="{c}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none">
      <path d="M-12 -14 H4 L10 -8 V14 H-12 Z"/><path d="M4 -14 V-8 H10"/>
      <line x1="-7" y1="-3" x2="5" y2="-3"/><line x1="-7" y1="3" x2="5" y2="3"/>
      <line x1="-7" y1="9" x2="0" y2="9"/></g>"""


def icon_unlock(c):
    return f"""<g stroke="{c}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" fill="none">
      <rect x="-8" y="-2" width="16" height="12" rx="2.5"/>
      <path d="M-5 -2 V-7 A5 5 0 0 1 5 -7 V-5"/><line x1="0" y1="2.5" x2="0" y2="5.5"/></g>"""


def icon_send(c):
    return f"""<g stroke="{c}" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" fill="none">
      <path d="M-10 -1 L10 -9 L4 10 L0 2 Z"/><line x1="0" y1="2" x2="10" y2="-9"/></g>"""


def icon_shield(c):
    return (
        f'<path d="M0 -8 L6.5 -5.5 V0 C6.5 4.5 3.5 7 0 8.5 C-3.5 7 -6.5 4.5 -6.5 0 V-5.5 Z" '
        f'fill="none" stroke="{c}" stroke-width="1.8" stroke-linejoin="round"/>'
    )


# ---------- pieces ----------
def agent(x, y, ring, fill, icon, r=R, glow=False, stack=False):
    out = []
    if stack:  # the hunters: a stack of agents working in parallel
        for dx, op in ((-9, ".35"), (-4.5, ".6")):
            out.append(
                f'<circle cx="{x + dx}" cy="{y}" r="{r}" fill="{fill}" stroke="{ring}" '
                f'stroke-width="1.4" opacity="{op}"/>'
            )
    if glow:
        out.append(f'<circle cx="{x}" cy="{y}" r="{r + 10}" fill="{ring}" opacity=".18" filter="url(#blur)"/>')
    out.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}" stroke="{ring}" stroke-width="{2.6 if glow else 2}"/>')
    out.append(f'<g transform="translate({x} {y}) scale({r / 34:.3f})">{icon}</g>')
    if stack:
        out.append(
            f'<rect x="{x + 12}" y="{y - 41}" width="32" height="21" rx="10.5" fill="{BLUE}" '
            f'stroke="{BG}" stroke-width="2.5"/>'
        )
        out.append(text(x + 28, y - 26, "×N", "xn"))
    return "\n".join(out)


def wire(x1, y1, x2, y2):
    """An arrow along one axis, with the moving dots stopping short of the arrowhead."""
    fx = x2 - 9 * ((x2 > x1) - (x2 < x1))
    fy = y2 - 9 * ((y2 > y1) - (y2 < y1))
    return (
        f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" class="wire" marker-end="url(#arrow)"/>'
        f'<line x1="{x1:g}" y1="{y1:g}" x2="{fx:g}" y2="{fy:g}" class="flow"/>'
    )


def badge(mx, n, label):
    return "\n".join(
        [
            f'<rect x="{mx - 20:g}" y="{CY - 13}" width="40" height="26" rx="13" fill="#162641" '
            f'stroke="{BLUE}" stroke-width="1.5"/>',
            text(mx, CY + 5.5, n, "count"),
            text(mx, CY + 33, label, "unit"),
        ]
    )


GATE_H = 52


def gate_width(you, label):
    return 12 + 36 + 12 + max(width(you, "youtag"), width(label, "youlabel")) + 18


def gate(cx, you, label, icon):
    """A human step: a gold pill sitting on the top edge of the fence."""
    w = gate_width(you, label)
    x0 = cx - w / 2
    ix, tx = x0 + 12 + 18, x0 + 12 + 36 + 12
    return f"""
  <g>
    <rect x="{x0:g}" y="{FY1 - GATE_H / 2:g}" width="{w:g}" height="{GATE_H}" rx="14" fill="{GOLD_FILL}"
          stroke="{GOLD}" stroke-width="1.8"/>
    <circle cx="{ix:g}" cy="{FY1}" r="18" fill="none" stroke="{GOLD}" stroke-width="1.4" class="pulse"/>
    <circle cx="{ix:g}" cy="{FY1}" r="17" fill="{BG}" stroke="{GOLD}" stroke-width="2"/>
    <g transform="translate({ix:g} {FY1}) scale(.9)">{icon}</g>
    {text(tx, FY1 - 6, you, "youtag", "start")}
    {text(tx, FY1 + 14, label, "youlabel", "start")}
  </g>"""


def tab(cx, cy, fill, stroke, parts, icon=None):
    """A pill on the fence edge holding a run of (text, class) parts."""
    gap = 8
    inner = sum(width(s, cls) for s, cls in parts) + gap * (len(parts) - 1) + (24 if icon else 0)
    w = inner + 32
    x = cx - inner / 2
    out = [
        f'<rect x="{cx - w / 2:g}" y="{cy - 15}" width="{w:g}" height="30" rx="15" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="1.5"/>'
    ]
    if icon:
        out.append(f'<g transform="translate({x + 7:g} {cy})">{icon}</g>')
        x += 24
    for s, cls in parts:
        out.append(text(x, cy + 5, s, cls, "start"))
        x += width(s, cls) + gap
    return "\n".join(out)


def check_fits(s):
    """Fail loudly when a translation outgrows its slot, instead of shipping overlapping text."""
    slots = [
        (s["headline"], "h1", W - 48),
        (s["radar"][1], "desc", MID - X["recon"] - 44 - 40),
        # the count labels sit below the circles' widest point, where each circle is ~20px wide either side
        *((label, "unit", X["hunters"] - X["recon"] - 48) for _, label in s["counts"]),
        *((name, "name", X["hunters"] - X["recon"] - 16) for name in [*s["names"].values(), s["writer"]]),
    ]
    for value, cls, room in slots:
        if width(value, cls) > room:
            raise SystemExit(f"{value!r} is {width(value, cls):.0f}px wide, the slot has {room}px")


def build(lang):
    s = STRINGS[lang]
    check_fits(s)
    xr, xw = X["recon"], X["writer"]
    style = STYLE.format(sans=SANS, classes=css_classes(), blue=BLUE_ICON)
    defs = DEFS.format(**globals())
    gate_top, gate_bot = FY1 - GATE_H / 2, FY1 + GATE_H / 2
    hunt_x = (xr + gate_width(s["you"], s["gate1"]) / 2 + xw - gate_width(s["you"], s["gate2"]) / 2) / 2
    p = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" '
        f'aria-labelledby="title desc" lang="{lang}">',
        f'  <title id="title">{escape(s["eyebrow"].capitalize())}</title>',
        f'  <desc id="desc">{escape(s["desc"])}</desc>',
        f"  <defs>\n    <style>\n/*FONTFACE*/{style}    </style>{defs}  </defs>",
        f'  <rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="18" fill="{BG}" stroke="{BORDER}"/>',
        f'  <rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="18" fill="url(#dots)"/>',
        f'  <ellipse cx="{MID}" cy="{CY}" rx="440" ry="200" fill="url(#glowBlue)"/>',
        f'  <ellipse cx="{X["judge"]}" cy="{CY}" rx="110" ry="100" fill="url(#glowCoral)"/>',
        text(MID, 44, s["eyebrow"], "eyebrow"),
        text(MID, 75, s["headline"], "h1"),
        # the scope-guard fence
        f'<rect x="{FX1}" y="{FY1}" width="{FX2 - FX1}" height="{FY2 - FY1}" rx="18" fill="{RED}" '
        f'fill-opacity=".035" stroke="{RED}" stroke-opacity=".75" stroke-width="1.8" stroke-dasharray="9 7"/>',
        # down the left: Radar alerts you, you open the gate
        agent(xr, TOP, BLUE, BLUE_FILL, icon_radar(BLUE_ICON), r=28),
        text(xr + 44, TOP - 3, s["radar"][0], "name", "start"),
        text(xr + 44, TOP + 18, s["radar"][1], "desc", "start"),
        wire(xr, TOP + 32, xr, gate_top - 3),
        text(xr + 14, (TOP + 28 + gate_top) / 2 + 9, s["alert"], "unit", "start"),
        wire(xr, gate_bot + 2, xr, CY - R - 4),
        # across, inside the fence
        wire(xr + R + 4, CY, X["hunters"] - R - 13, CY),
    ]
    for (a, b), (num, label) in zip(
        [("hunters", "validator"), ("validator", "judge"), ("judge", "writer")], s["counts"], strict=True
    ):
        xa, xb = X[a] + R + 4, X[b] - R - 4
        p += [wire(xa, CY, xb, CY), badge((xa + xb) / 2, num, label)]
    p += [
        agent(xr, CY, BLUE, BLUE_FILL, icon_recon(BLUE_ICON)),
        agent(X["hunters"], CY, BLUE, BLUE_FILL, icon_hunt(BLUE_ICON), stack=True),
        agent(X["validator"], CY, BLUE, BLUE_FILL, icon_validate(BLUE_ICON)),
        agent(X["judge"], CY, CORAL, CORAL_FILL, icon_judge(CORAL_ICON), glow=True),
        agent(xw, CY, GREEN, GREEN_FILL, icon_write(GREEN_ICON)),
        *(text(X[k], CY + R + 28, name, "name") for k, name in s["names"].items()),
        text(xw, CY + R + 28, s["writer"], "name"),
        # up the right: you press submit, you get paid
        wire(xw, CY - R - 4, xw, gate_bot + 3),
        wire(xw, gate_top - 2, xw, TOP + 26),
        f'<circle cx="{xw}" cy="{TOP}" r="22" fill="url(#coin)" stroke="#ffe7a3" stroke-width="1.2"/>',
        f'<circle cx="{xw}" cy="{TOP}" r="16.5" fill="none" stroke="#9a6d12" stroke-width="1.2" opacity=".6"/>',
        text(xw, TOP + 7, "$", "coin"),
        text(xw - 38, TOP + 6, s["payout"], "unit", "end"),
        # labels on the fence: what runs on its own, the two things you do, what keeps it in scope
        # the hunt tab is centred in the gap between the two gates
        tab(hunt_x, FY1, BG, "#2d3a50", [("/bountyproof:hunt", "cmd"), (s["hunt"], "tab")]),
        gate(xr, s["you"], s["gate1"], icon_unlock(GOLD)),
        gate(xw, s["you"], s["gate2"], icon_send(GOLD)),
        tab(MID, FY2, RED_FILL, RED, [(s["guard"], "guard"), (s["guard_desc"], "guarddesc")], icon_shield(RED_TEXT)),
        text(MID, H - 26, s["caption"], "cap"),
        "</svg>\n",
    ]
    return "\n".join(p)


# ---------- font embedding ----------
def font_files():
    """Download the static TTFs once (Google Fonts serves TTF to non-browser clients) and cache them."""
    cache = Path(tempfile.gettempdir()) / "bountyproof-fonts"
    cache.mkdir(exist_ok=True)
    paths = {(f, w): cache / f"{f.replace(' ', '')}-{w}.ttf" for f, _, w in FACES}
    if not all(p.exists() for p in paths.values()):
        req = urllib.request.Request(FONTS_CSS, headers={"User-Agent": "curl/8"})
        css = urllib.request.urlopen(req, timeout=30).read().decode()
        for block in css.split("@font-face")[1:]:
            family = re.search(r"font-family: '([^']+)'", block).group(1)
            weight = int(re.search(r"font-weight: (\d+)", block).group(1))
            url = re.search(r"url\((https://[^)]+\.ttf)\)", block).group(1)
            if (family, weight) in paths:
                paths[(family, weight)].write_bytes(urllib.request.urlopen(url, timeout=30).read())
    return paths


def embed_fonts(svg):
    from fontTools import subset
    from fontTools.ttLib import TTFont

    body = svg.split("</defs>", 1)[1]
    chars = {" "}.union(*(set(unescape(m)) for m in re.findall(r">([^<>]+)<", body)))
    paths = font_files()
    css = ["      /* Subsets of Inter and JetBrains Mono, both SIL Open Font License 1.1. */"]
    for family, alias, weight in FACES:
        font = TTFont(paths[(family, weight)])
        opts = subset.Options()
        opts.hinting = False
        opts.layout_features = ["kern", "liga", "calt", "ccmp", "locl", "mark", "mkmk"]
        opts.name_IDs = [0, 1, 2, 3, 4, 5, 6, 13, 14]  # keeps the copyright and license notice
        subsetter = subset.Subsetter(opts)
        subsetter.populate(unicodes=[ord(c) for c in chars])
        subsetter.subset(font)
        font.flavor = "woff2"
        buf = io.BytesIO()
        font.save(buf)
        data = base64.b64encode(buf.getvalue()).decode()
        css.append(
            f"      @font-face {{ font-family: {alias}; font-weight: {weight}; "
            f"src: url(data:font/woff2;base64,{data}) format('woff2'); }}"
        )
    return svg.replace("/*FONTFACE*/", "\n".join(css))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ASSETS, help="output folder (default: docs/assets)")
    ap.add_argument("--system-fonts", action="store_true", help="don't embed fonts")
    args = ap.parse_args()
    for lang, name in (("en", "how-it-works.svg"), ("es", "how-it-works.es.svg")):
        svg = build(lang)
        svg = svg.replace("/*FONTFACE*/", "") if args.system_fonts else embed_fonts(svg)
        (args.out / name).write_text(svg, encoding="utf-8", newline="\n")
        print(f"wrote {args.out / name} ({len(svg) // 1024} KB)")


if __name__ == "__main__":
    main()
