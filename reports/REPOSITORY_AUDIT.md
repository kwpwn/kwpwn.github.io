# Repository audit

Audit date: 2026-07-30

## Current stack and data flow

- **Framework:** Astro 7, static output.
- **Content:** Astro content collections with Markdown/MDX blog entries and
  TypeScript data modules for the handbook and Windows Service Atlas.
- **Styling:** Tailwind CSS 4 plus semantic CSS tokens and scoped Astro styles.
- **Typography:** self-hosted Source Sans 3 Variable and JetBrains Mono
  Variable.
- **Search:** Pagefind 1.5.2. Before this audit the package was installed, but
  the build script did not generate an index.
- **Docs:** Starlight remains available for documentation routes.
- **Client JavaScript:** small inline scripts for theme, navigation, filters,
  search, article progress, completion state, heading links, and code tools.
- **SEO:** canonical metadata, Open Graph, JSON-LD, RSS, sitemap, and generated
  social images.
- **Deployment:** `.github/workflows/deploy.yml` uses `withastro/action` and
  `actions/deploy-pages` for GitHub Pages.
- **Build command:** `corepack pnpm build`.

The article route reads one content entry, renders its MDX, and passes the entry
and extracted headings to `BlogLayout.astro`. Learning-path placement is derived
from `src/lib/research-topics.ts`. Handbook and service pages use separate
structured TypeScript datasets.

## Baseline inventory

| Area | Count |
| --- | ---: |
| Generated HTML pages | 363 |
| Blog/lesson entries | 76 |
| Ordered lesson articles | 75 |
| Handbook concept pages | 154 |
| Service target families | 103 |
| Service vulnerability records | 2,371 |
| Unique service CVEs | 2,363 |

The exact content-integrity state is generated in
`reports/CONTENT_INTEGRITY.md`.

## Findings and root causes

| Priority | Finding | Root cause | Related files | Treatment |
| --- | --- | --- | --- | --- |
| Critical | Search was presented in production but no Pagefind index was created by `pnpm build`. | `pagefind --site dist` was absent from the build pipeline. | `package.json`, `SearchModal.astro` | Pagefind is now part of the deterministic build; all 363 pages are indexed. |
| Critical | Articles appeared to contain two TOCs, two learning-outcome blocks, and two prerequisite blocks. | Mobile and desktop variants were rendered twice and hidden with CSS. | `BlogLayout.astro`, `ArticleGuide.astro`, `TableOfContents.astro` | Replaced with one responsive DOM instance for each concern. |
| High | The original homepage behaved like a marketing landing page and emphasized slogans and counts over learning choices. | A generic starter section used cards, metrics, and a promotional method loop. | `ResearchTopicDirectory.astro`, `site.config.ts` | Rebuilt around search, three learning paths, tasks, recently updated material, and research standards. |
| High | Long articles were difficult to orient within and had no library hierarchy. | The article template had only a main column and repeated TOC variants; no persistent learning-path navigation existed. | `BlogLayout.astro`, new article navigation components | Added a controlled three-region documentation shell with responsive collapse. |
| High | The library did not expose whether an article was draft, reviewed, or evidence-backed. | Frontmatter lacked content type, review status, evidence level, build scope, structured sources, and changelog fields. | `content.config.ts`, 76 MDX entries | Added a validated schema and conservatively migrated every article to `preliminary` / `unverified`. |
| High | 63 articles share a large generated outline and repeated research-method wording. | `generate-yunolay-lessons.mjs --refresh` overwrote existing files with one 600+ line body template. | Generator and 63 MDX entries | Default generation is now non-destructive; the integrity report identifies every template-heavy article for editorial rewrite. |
| High | Important claims generally cite sources only in a final table. | The generator optimized for a reference appendix instead of claim-adjacent citations. | 75 article bodies | Articles remain preliminary; missing claim-adjacent coverage is reported rather than fabricated. |
| Medium | General page headings reached 64px and several browse pages retained a marketing tone. | The general `--text-5xl` token and inherited starter hero patterns were oversized for a reference portal. | Typography tokens, handbook/service/blog directory sections | Reduced the heading scale and simplified the handbook, Service Atlas, and article directory entry points. |
| Medium | Article results could be matched only because another article appeared in “Related posts.” | Pagefind indexed navigation, TOC, related links, and other duplicate chrome inside the page body. | `BaseLayout.astro`, `BlogLayout.astro` | Index scope now covers main content while explicitly excluding navigation, TOC, related links, header, footer, and search UI. |
| Medium | Mobile navigation closed visually but did not restore focus on Escape. | The menu only toggled `hidden` and `aria-expanded`. | `Header.astro` | Added first-link focus, Escape handling, focus restoration, and link-close behavior. |
| Medium | One retired Microsoft Security Guidance URL returned 404 in 22 published locations. | The generator embedded an obsolete URL. | Generator and 21 MDX entries | Migrated to the official MSRC Update Guide URL with an auditable migration script. |
| Low | Four configured collections are empty. | Starter collections remain defined without content. | `content.config.ts` | Kept for compatibility; Astro emits non-blocking build warnings. |
| Low | The local aggregate lint command failed although individual gates passed. | Nested scripts invoked a missing bare `pnpm` shim in this Windows environment. | `package.json` | The aggregate command now invokes each gate directly and remains package-manager independent inside the script. |

## Content and document-quality findings

- No article is automatically declared technically confirmed.
- 63 articles are template-heavy.
- 75 articles have no detected claim-adjacent external citation.
- Structured frontmatter source records still require manual migration and
  claim mapping.
- Existing references generally include at least one primary Microsoft source;
  this does not substitute for claim-level coverage.
- The automated validator does not claim that code compiles or commands were
  executed.
- No internal route, anchor, or duplicate generated ID failed the current built
  output audit.

## Accessibility findings

Baseline checks found no representative horizontal overflow on valid routes and
no duplicate IDs. The redesign adds a skip link, visible focus, semantic
landmarks, native dialog focus trapping, Escape behavior, keyboard-search
navigation, text labels in addition to color, reduced-motion handling, and
print styles. Final automated and manual results are recorded in
`reports/VERIFICATION.md`.

## Performance findings

- The site remains static-first.
- Search and article enhancements use small, framework-free scripts.
- Pagefind is loaded only when search opens.
- Navigation, TOC, and filters are server-rendered HTML.
- Source Sans 3 and JetBrains Mono remain self-hosted; no third-party font
  request was added.
- Related content and navigation are excluded from the search corpus, reducing
  index noise.

## SEO and longevity findings

Canonical URL, sitemap, RSS, Open Graph, and TechArticle JSON-LD were preserved.
TechArticle output now supports content section, keywords, and structured
citations when source records exist. Existing slugs were not changed, so no
redirect migration was required.

## Migration risk

1. The stricter content schema intentionally exposes missing evidence instead
   of filling it with guessed values.
2. All current articles are labeled preliminary until a human evidence review
   supplies claim-level sources and version context.
3. The Pagefind index increases build time but removes the previous production
   failure mode where search assets did not exist.
4. The generator no longer refreshes existing lessons by default; overwriting
   requires the explicit `--overwrite-generated` option.
5. Structured source migration must be editorial, not a blind transformation
   of the final reference tables.

## Baseline screenshots

- `reports/screenshots/before/production-home-desktop.png`
- `reports/screenshots/before/production-home-mobile.png`
- `reports/screenshots/before/production-access-tokens-sids-integrity-privileges-desktop.png`
- `reports/screenshots/before/production-access-tokens-sids-integrity-privileges-mobile.png`
