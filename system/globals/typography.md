# Typography

Tokens in `src/styles/tokens/typography.css`, mapped to Tailwind in `global.css`.

## Font families

| Token            | Family                  | Use       |
| ---------------- | ----------------------- | --------- |
| `--font-sans`    | Source Sans 3 Variable  | body text |
| `--font-heading` | Source Sans 3 Variable  | headings  |
| `--font-mono`    | JetBrains Mono Variable | code      |

Fonts are **self-hosted** via Fontsource (no CDN). Metric-adjusted fallback
`@font-face` rules prevent layout shift (CLS).

## Fluid type scale

`clamp()`-based, fluid between mobile and desktop:

`--text-xs` 12–14 · `--text-sm` 14–16 · `--text-base` 16–18 · `--text-lg` 18–20 ·
`--text-xl` 20–24 · `--text-2xl` 22–28 · `--text-3xl` 28–36 · `--text-4xl` 34–44 ·
`--text-5xl` 40–52.

Heading aliases: `--heading-h1`…`--heading-h6` map to the scale.

## Weights & rhythm

- Weights: `--font-weight-{light,normal,medium,semibold,bold,extrabold}`.
- Headings default to `--font-weight-semibold`, `--leading-tight`.
- Body uses `--leading-normal`; long-form prose uses `--text-reading` at
  approximately 16.5px on phones and 18px on desktop with
  `--leading-reading` (1.72). Article-specific title,
  description, lead, h2, and h3 tokens keep editorial pages compact without
  shrinking the general component scale.
- Letter-spacing tokens: `--tracking-tight` for large headings, default elsewhere.

## Rules

- Use heading elements semantically (one `h1` per page; never skip levels).
- Prose/long-form content is capped to `--measure-reading` (74ch).
- Prefer the scale tokens over arbitrary font sizes.
- Section eyebrows: uppercase, `--text-xs`, tracked, `--muted-foreground` or `--primary`.
