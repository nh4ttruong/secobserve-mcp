"""Render the brand assets: the mark and the GitHub social preview card.

Run with:  uv run --with pillow --no-project python docs/assets/make_assets.py

The card carries text, so it is generated rather than exported by hand — a
typo or a stale tool count is fixed here and re-rendered, not retouched in a
PNG. Geometry and palette follow BRAND.md.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).parent
FONTS = OUT / "fonts"

NAVY = (28, 23, 71)
ACCENT = (34, 166, 179)
PAPER = (242, 247, 248)
MUTED = (201, 198, 228)

WORDMARK = FONTS / "Poppins-SemiBold.ttf"
BODY = FONTS / "Poppins-Medium.ttf"
MONO = FONTS / "IBMPlexMono-Medium.ttf"


def font(path: Path, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(path), size)


def mark(size: int, tile: tuple[int, int, int], ground: tuple[int, int, int] | None) -> Image.Image:
    """Tile with two bars knocked out to whatever sits behind it.

    The 48-unit grid is the one BRAND.md specifies; drawing at 4x and
    downsampling is the cheapest antialiasing available in Pillow.
    """
    scale = size * 4 / 48
    img = Image.new("RGBA", (size * 4, size * 4), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    def unit(x: float, y: float, w: float, h: float) -> tuple[float, float, float, float]:
        return (x * scale, y * scale, (x + w) * scale, (y + h) * scale)

    d.rounded_rectangle(unit(3, 3, 42, 42), radius=10 * scale, fill=tile)
    # A knockout has to reveal the ground, so punch through with a fill of it,
    # or with full transparency when the mark is meant to sit on anything.
    hole = ground + (255,) if ground else (0, 0, 0, 0)
    for x, y, h in ((14, 11, 26), (28, 19, 18)):
        d.rounded_rectangle(unit(x, y, 6, h), radius=3 * scale, fill=hole)

    return img.resize((size, size), Image.LANCZOS)


def social_card() -> None:
    img = Image.new("RGBA", (1280, 640), NAVY + (255,))
    d = ImageDraw.Draw(img)
    d.rectangle((0, 0, 10, 640), fill=ACCENT)

    glyph = mark(228, PAPER, NAVY)
    img.alpha_composite(glyph, (982, 206))

    d.text((96, 124), "secobserve-mcp", font=font(WORDMARK, 74), fill=PAPER)
    d.text((96, 246), "MCP server for SecObserve —", font=font(WORDMARK, 33), fill=ACCENT)
    d.text((96, 292), "vulnerability & license management", font=font(WORDMARK, 33), fill=ACCENT)
    d.text((96, 372), "Triage findings, import scan reports and SBOMs,", font=font(BODY, 29), fill=MUTED)
    d.text((96, 416), "run scans and generate VEX — from your agent.", font=font(BODY, 29), fill=MUTED)

    d.text((96, 496), "github.com/nh4ttruong/secobserve-mcp", font=font(MONO, 24), fill=(150, 146, 186))

    img.convert("RGB").save(OUT / "social-card.png", optimize=True)


def logo() -> None:
    # Solid bars rather than a true knockout: one file has to sit on both the
    # light and the dark GitHub theme, and a transparent bar vanishes on dark.
    mark(512, NAVY, PAPER).save(OUT / "logo.png", optimize=True)


if __name__ == "__main__":
    social_card()
    logo()
    print("wrote", OUT / "social-card.png", "and", OUT / "logo.png")
