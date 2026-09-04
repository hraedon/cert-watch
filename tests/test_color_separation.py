"""Guardrail: status colours stay separable, including under colour-vision
deficiency (WI-145).

The status quad (--ok, --warn, --crit, --expired) is the one thing an operator
must never confuse on a triage page. WI-145 showed how separation can silently
collapse when a palette refresh retunes one token without re-checking the pair
distances, and that nobody had ever computed the distances under CVD simulation
(patina's check_contrast.py explicitly did not). This test computes CIELAB dE76
for every status pair in both themes, for normal vision and under the three
dichromacy simulations (Machado et al. 2009, severity 1.0), and fails if any
pair drops below the floors patina's plan-004 constraint search used:

  * normal vision: dE76 >= 15
  * each CVD simulation: dE76 >= 8

The values are parsed from tokens.css and the app-owned cw.css (not duplicated here),
so the test tracks whatever the stylesheet actually ships. Pure stdlib — no colour library.
"""

from __future__ import annotations

import itertools
import math
import re
from pathlib import Path

import pytest

TOKENS_CSS = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "cert_watch"
    / "static"
    / "css"
    / "tokens.css"
)

STATUS_TOKENS = ("ok", "warn", "crit", "expired")

NORMAL_FLOOR = 15.0
CVD_FLOOR = 8.0

# Machado, Oliveira, Fernandes (2009) dichromacy matrices, severity 1.0,
# applied in linear sRGB.
_CVD_MATRICES = {
    "protanopia": (
        (0.152286, 1.052583, -0.204868),
        (0.114503, 0.786281, 0.099216),
        (-0.003882, -0.048116, 1.051998),
    ),
    "deuteranopia": (
        (0.367322, 0.860646, -0.227968),
        (0.280085, 0.672501, 0.047413),
        (-0.011820, 0.042940, 0.968881),
    ),
    "tritanopia": (
        (1.255528, -0.076749, -0.178779),
        (-0.078411, 0.930809, 0.147602),
        (0.004733, 0.691367, 0.303900),
    ),
}


def _srgb_to_linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _linear_to_srgb(c: float) -> float:
    c = max(0.0, min(1.0, c))
    return c * 12.92 if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def hex_to_linear_rgb(value: str) -> tuple[float, float, float]:
    value = value.lstrip("#")
    return tuple(_srgb_to_linear(int(value[i : i + 2], 16) / 255) for i in (0, 2, 4))  # type: ignore[return-value]


def _linear_rgb_to_lab(rgb: tuple[float, float, float]) -> tuple[float, float, float]:
    def f(t: float) -> float:
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

    r, g, b = rgb
    x = 0.4124564 * r + 0.3575761 * g + 0.1804375 * b
    y = 0.2126729 * r + 0.7151522 * g + 0.0721750 * b
    z = 0.0193339 * r + 0.1191920 * g + 0.9503041 * b
    fx, fy, fz = f(x / 0.95047), f(y / 1.0), f(z / 1.08883)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def hex_to_lab(value: str) -> tuple[float, float, float]:
    return _linear_rgb_to_lab(hex_to_linear_rgb(value))


def simulate_lab(value: str, kind: str) -> tuple[float, float, float]:
    rgb = hex_to_linear_rgb(value)
    m = _CVD_MATRICES[kind]
    simulated = tuple(
        max(0.0, min(1.0, sum(m[i][j] * rgb[j] for j in range(3))))
        for i in range(3)
    )
    return _linear_rgb_to_lab(simulated)  # type: ignore[arg-type]


def delta_e76(
    lab1: tuple[float, float, float], lab2: tuple[float, float, float]
) -> float:
    total = 0.0
    for a, b in zip(lab1, lab2, strict=True):
        total += (a - b) ** 2
    return math.sqrt(total)


def _parse_theme_colors() -> dict[str, dict[str, str]]:
    """Extract {theme: {token: hex}} for the status tokens from tokens.css."""
    css = TOKENS_CSS.read_text(encoding="utf-8")
    app_css = TOKENS_CSS.with_name("cw.css").read_text(encoding="utf-8")
    themes: dict[str, dict[str, str]] = {}
    # The default :root block is the dark theme; data-theme="light" overrides.
    blocks = {
        "dark": re.search(r':root\[data-theme="dark"\]\s*\{(.*?)\n\}', css, re.DOTALL),
        "light": re.search(
            r':root\[data-theme="light"\]\s*\{(.*?)\n\}', css, re.DOTALL
        ),
    }
    for theme, match in blocks.items():
        assert match, f"could not locate the {theme} theme block in tokens.css"
        body = match.group(1)
        app_match = re.search(
            rf':root\[data-theme="{theme}"\]\s*\{{(.*?)\n\}}', app_css, re.DOTALL
        )
        assert app_match, f"could not locate the {theme} theme block in cw.css"
        body += app_match.group(1).replace("--cw-expired:", "--expired:")
        found = {}
        for token in STATUS_TOKENS:
            m = re.search(rf"--{token}:\s*(#[0-9a-fA-F]{{6}})\s*;", body)
            assert m, f"--{token} not found in the {theme} theme block"
            found[token] = m.group(1).lower()
        themes[theme] = found
    return themes


_THEMES = _parse_theme_colors()


@pytest.mark.parametrize("theme", sorted(_THEMES))
@pytest.mark.parametrize("pair", list(itertools.combinations(STATUS_TOKENS, 2)))
def test_status_pair_separation_normal_vision(
    theme: str, pair: tuple[str, str]
) -> None:
    a, b = pair
    de = delta_e76(hex_to_lab(_THEMES[theme][a]), hex_to_lab(_THEMES[theme][b]))
    assert de >= NORMAL_FLOOR, (
        f"{theme} theme: --{a} ({_THEMES[theme][a]}) and --{b} "
        f"({_THEMES[theme][b]}) are only dE76 {de:.1f} apart (floor {NORMAL_FLOOR}). "
        f"Operators must distinguish these statuses at a glance (WI-145)."
    )


@pytest.mark.parametrize("theme", sorted(_THEMES))
@pytest.mark.parametrize("pair", list(itertools.combinations(STATUS_TOKENS, 2)))
@pytest.mark.parametrize("kind", sorted(_CVD_MATRICES))
def test_status_pair_separation_under_cvd(
    theme: str, pair: tuple[str, str], kind: str
) -> None:
    a, b = pair
    de = delta_e76(
        simulate_lab(_THEMES[theme][a], kind), simulate_lab(_THEMES[theme][b], kind)
    )
    assert de >= CVD_FLOOR, (
        f"{theme} theme under {kind}: --{a} ({_THEMES[theme][a]}) and --{b} "
        f"({_THEMES[theme][b]}) collapse to dE76 {de:.1f} (floor {CVD_FLOOR}). "
        f"Retune the offending token so every status survives simulation (WI-145)."
    )


def test_pipeline_matches_wi145_reference_measurements() -> None:
    """Anchor the simulation against the independently computed values recorded
    in WI-145 (normal-vision dE76 of the historical light-theme pair), so a
    future "simplification" of the colour math can't silently change what the
    floors mean."""
    before = delta_e76(hex_to_lab("#dc3030"), hex_to_lab("#c41d6f"))
    feared = delta_e76(hex_to_lab("#b64461"), hex_to_lab("#c41d6f"))
    assert before == pytest.approx(45.9, abs=0.15)
    assert feared == pytest.approx(21.2, abs=0.15)


def test_expired_palette_retains_separation_with_vendored_status_colors() -> None:
    distances = []
    for colors in _THEMES.values():
        for token in ("ok", "warn", "crit"):
            distances.append(
                delta_e76(hex_to_lab(colors["expired"]), hex_to_lab(colors[token]))
            )
            for kind in _CVD_MATRICES:
                distances.append(
                    delta_e76(
                        simulate_lab(colors["expired"], kind),
                        simulate_lab(colors[token], kind),
                    )
                )
    assert min(distances) >= CVD_FLOOR
