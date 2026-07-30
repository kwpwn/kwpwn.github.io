# Implementation report

## Architecture retained

- Astro 7 static output and existing stable URLs.
- Markdown/MDX content collection and TypeScript-backed handbook/service data.
- Tailwind 4, scoped Astro styles, Starlight, RSS, sitemap, Open Graph, JSON-LD,
  and GitHub Pages deployment.
- English as the only currently configured locale. Existing locale-aware route
  components were preserved; no unsupported translation was fabricated.

## Core implementation

### Design system

- Updated canonical color, typography, spacing, container, and reading-measure
  tokens in `src/styles/tokens/` and mirrored the decisions in
  `system/globals/`.
- Changed the visual baseline to warm off-white and soft charcoal surfaces,
  restrained blue links, 16.5–18px long-form type, 1.72 line height, and a
  74-character reading measure.
- Moved code highlighting to a high-contrast Shiki theme and corrected dark
  secondary-text contrast after an axe-core failure.

### Navigation and article reading

- Rebuilt `BlogLayout.astro` as one responsive documentation shell with one
  library navigation, one article column, and one TOC.
- Replaced duplicated desktop/mobile learning blocks with one responsive
  `ArticleGuide.astro`.
- Added article evidence state, path navigation, previous/next order, reading
  progress, local completion state, print, source/issue links, heading
  permalinks, and code copy/wrap controls.
- Added a research callout primitive with explicit labels for notes, important
  details, warnings, build-specific observations, evidence, hypotheses, and
  pitfalls. The label carries meaning independently of color.
- Removed the unused share-button component and excluded repeated page chrome
  from Pagefind.

### Search

- Added Pagefind generation to the production build.
- Rebuilt the search dialog with lazy local-index loading, Ctrl/Cmd+K,
  highlighted excerpts, keyboard result navigation, mobile support, and result
  groups for lessons, concepts, CVEs, services, labs, and references.

### Homepage and library entry points

- Rebuilt the homepage around search, three ordered paths, task-based browsing,
  recently reviewed material, and evidence terminology.
- Rebuilt the article directory as filterable rows with content type,
  difficulty, path, review state, date, and reading time.
- Simplified handbook and Service Atlas entry pages.
- Added three-region handbook concept pages with an explicit conceptual
  synthesis evidence warning.

### Content model and integrity

- Extended `src/content.config.ts` with content type, review/evidence state,
  review dates, source records, Windows versions/builds, architectures, CVEs,
  related material, and changelog metadata.
- Conservatively migrated all 76 MDX entries to explicit preliminary and
  unverified states.
- Made generated-lesson updates non-destructive by default.
- Removed validator incentives for long template filler: research-topic
  validation now enforces placement and a modest completeness floor, while the
  integrity report separately flags repetition and missing evidence.
- Migrated the retired MSRC security-guidance URL to the official Microsoft
  Security Update Guide URL.

## Validation and tests

- Added `scripts/validate-content-integrity.mjs` for metadata, dates, slugs,
  headings, CVEs, Windows builds, references, code fences, generated duplicate
  sections, built routes, anchors, and duplicate IDs.
- Added migration scripts for metadata and source URLs.
- Added a deterministic Lighthouse summarizer that preserves scores, metrics,
  runtime errors, and warnings without retaining large embedded filmstrips.
- Expanded Playwright coverage for the root duplication bugs, full-text search,
  filters, completion persistence, code wrapping, dark mode, mobile Escape/focus
  behavior, concept navigation, and responsive overflow.
- Added `@axe-core/playwright` because automated WCAG A/AA checks are a required
  deployment gate; it is test-only and adds no client JavaScript.

## Changed-file groups

- Build/configuration: `package.json`, `pnpm-lock.yaml`, `astro.config.ts`,
  `playwright.config.ts`, `README.md`.
- Layout/search/navigation: `src/layouts/`, `src/components/layout/`,
  `src/components/blog/`.
- Browse/reference pages: `src/components/sections/`,
  `src/components/handbook/`.
- Design system: `src/styles/`, `system/globals/`, `src/registry.json`.
- Metadata/data: `src/content.config.ts`,
  `src/pages/data/published-blogs.json.ts`, and all 76 files under
  `src/content/blog/`.
- Validation/migration: `scripts/validate-content-integrity.mjs`,
  `scripts/migrate-content-metadata.mjs`, `scripts/migrate-source-urls.mjs`,
  `scripts/validate-research-topics.mjs`,
  `scripts/generate-yunolay-lessons.mjs`.
- QA: `src/test/` and `reports/`.

Generated `dist/`, temporary Playwright output, tool state, and transient build
logs are not part of the implementation commit.
