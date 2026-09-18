# Brand

Design by Claude, exported and then re-implemented in
[`make_assets.py`](make_assets.py) so the text-bearing assets stay
regenerable — a typo or a stale tool count is fixed in the script, not
retouched in a PNG.

## Mark

A tile with two bars knocked out of it, on a 48-unit grid: tile
`rect(3,3,42,42) rx 10`, bars `rect(14,11,6,26)` and `rect(28,19,6,18)`,
both `rx 3`. [`mark.svg`](mark.svg) is the vector original.

Clear space around the lockup is one bar width — 6 of 48 units.

## Colour

| Token | Hex | Use |
| --- | --- | --- |
| navy | `#1c1747` | Ground, and the tile on light backgrounds |
| accent | `#22a6b3` | Tagline and rules |
| teal | `#0b7285` | The SecObserve badge in the README only |
| paper | `#f2f7f8` | Wordmark, and the tile on dark backgrounds |
| mist | `#c9c6e4` | Body copy on navy |

`#0b7285` on navy is 2.9:1, under AA. Anything teal on the navy ground uses
the accent instead — that is the only reason two teals exist.

## Type

Poppins SemiBold for the wordmark and tagline, Poppins Medium for body,
IBM Plex Mono for the URL. Both families are vendored under
[`fonts/`](fonts/) with their OFL licences, because the card has to render
the same on any machine that regenerates it.

## Files

| File | Use |
| --- | --- |
| `social-card.png` | 1280×640. GitHub → Settings → Social preview |
| `logo.png` | 512×512 README mark |
| `mark.svg` | Vector original of the mark |

`logo.png` fills the bars solid rather than knocking them out. One file has
to sit on both GitHub themes, and a transparent bar disappears against the
dark one.

## Rules

- No gradients and no drop shadows on text; everything flattens to PNG unchanged.
- The bars never take a third colour — they are either the ground or paper.
- Never `#0b7285` on navy.
