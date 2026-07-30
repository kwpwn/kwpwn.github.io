# Verification report

Verification date: 2026-07-30

This report records executed results only. It does not treat automated checks as
a substitute for a human Windows technical review.

## Final local quality gates

| Gate                         | Result                       | Executed evidence                                                                                                                                 |
| ---------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Production build             | Pass                         | Astro generated 363 static pages. Four empty starter collections emitted non-blocking warnings.                                                   |
| Search build                 | Pass                         | Pagefind 1.5.2 indexed 363 English pages and 25,203 words.                                                                                        |
| Aggregate lint               | Pass                         | ESLint reported 0 errors and 11 pre-existing warnings; Stylelint, Astro check, KPI, catalog, content, i18n, and secret gates completed.           |
| Astro type check             | Pass                         | 0 errors; framework/Zod deprecation hints remain non-blocking.                                                                                    |
| CSS lint                     | Pass                         | `stylelint src/styles/` completed without an error.                                                                                               |
| Unit tests                   | Pass                         | 35/35 Vitest tests.                                                                                                                               |
| E2E and interaction tests    | Pass                         | 16/16 Playwright tests, including search, filters, single-instance article chrome, theme, mobile menu, completion persistence, and code wrapping. |
| Automated accessibility      | Pass                         | 5/5 axe-core WCAG A/AA scans: home, directory, article, concept, and dark article. No violations were reported.                                   |
| Content integrity            | Pass with editorial warnings | 76 articles, 0 blocking errors, 214 warnings.                                                                                                     |
| Internal link/anchor checker | Pass                         | 0 broken routes, 0 broken anchors, and 0 duplicate built IDs.                                                                                     |
| Code-fence structural check  | Pass                         | 0 unbalanced fences and 0 unlabeled fenced blocks. This does not prove snippets compile or commands were executed.                                |

The aggregate secret scan completed but produced 1,069 medium-confidence
heuristic findings, mainly false positives for the ordinary Windows security
word `token`. No finding is silently promoted to a verified secret.

## Lighthouse

Lighthouse 13.4.1 ran against the final local production preview in headless
Windows Chrome. The concise JSON evidence artifacts are
`lighthouse-home.json` and `lighthouse-article.json`; embedded filmstrips were
removed after the run because they are not needed to verify scores or metrics.

| Page                   | Performance | Accessibility | Best practices | SEO |
| ---------------------- | ----------: | ------------: | -------------: | --: |
| Home                   |          99 |           100 |            100 | 100 |
| Representative article |          99 |           100 |            100 | 100 |

The final article cumulative layout shift was `0.000346`. An earlier audit
found a `0.632` shift caused by server-rendering compact disclosure content as
open and closing it after JavaScript loaded. The navigation and TOC now render
closed on compact layouts without a post-paint collapse.

On this Windows host Lighthouse wrote complete JSON reports, then returned a
non-zero process status while cleaning its temporary Chrome directory
(`EPERM`). Scores above are read from the completed artifacts, not inferred.

## Browser and responsive review

The final production preview was exercised on home, directory, article, and
concept routes.

| Environment                                | Result                                                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Google Chrome 150.0.7871.187 on Windows    | No page/console error and no horizontal overflow on representative routes.                       |
| Microsoft Edge 150.0.4078.105 on Windows   | No page/console error and no horizontal overflow on representative routes.                       |
| Playwright Chromium with Pixel 7 profile   | No page error or horizontal overflow on home, article, and concept routes.                       |
| Playwright Chromium with iPhone 13 profile | No page error or horizontal overflow on home, article, and concept routes.                       |
| Firefox                                    | Not run: Firefox is not installed on this host and its Playwright browser binary is unavailable. |

Playwright also covered 390px compact layouts, 1440px desktop layouts, keyboard
operation, Escape/focus restoration, reduced duplicate chrome, and light/dark
contrast. A 720px reflow width was used as the practical 200% zoom equivalent;
representative pages retained one-column flow and did not introduce horizontal
page scrolling.

## Search verification

- `Ctrl+K` and `Cmd+K` use the same native search dialog.
- `ALPC` returned grouped lesson, concept, service, and reference results.
- `CVE-2021-34527` returned CVE and service groups.
- Arrow Down moves from the input to the first result.
- Escape closes the dialog and restores focus.
- Header, footer, library navigation, article TOC, related posts, and browse
  lists are excluded from the Pagefind content corpus.

## Content integrity limits

- Confirmed articles: 0.
- Articles requiring expert revision: 76.
- Articles without detected claim-adjacent citation coverage: 75.
- Template-heavy articles: 63.
- Articles without structured frontmatter source records: 76.
- Missing-primary-source heuristic: 0, but a final reference list does not
  establish claim-level coverage.

The complete article-by-article queue is in `CONTENT_INTEGRITY.md` and
`content-integrity.json`. No missing build, CVE mapping, source, reproduction,
or experiment result was filled by inference.

## Deployment

The functional release commit `76fb3c7` was pushed to `main`.

| Remote gate | Result | Evidence |
| --- | --- | --- |
| GitHub Pages | Pass | [Deploy to GitHub Pages run 30558583863](https://github.com/kwpwn/kwpwn.github.io/actions/runs/30558583863) completed successfully. |
| GitHub CI | Pass | [CI run 30558582241](https://github.com/kwpwn/kwpwn.github.io/actions/runs/30558582241) completed successfully. |
| Skills verification | Pass | [Skills Verification run 30558578561](https://github.com/kwpwn/kwpwn.github.io/actions/runs/30558578561) completed successfully. |

The deployed production site was then exercised in installed Windows Chrome:

- Home, article directory, representative article, and arbitrary-file-delete
  concept routes returned HTTP 200 with the expected unique title and H1.
- Pagefind JavaScript returned HTTP 200. Searching `ALPC` returned 36 results
  grouped as lessons, concepts, services, and references.
- The representative article contained exactly one library navigation, one TOC,
  one learning-outcomes heading, one prerequisites heading, and one safe-lab
  heading.
- Representative desktop routes and the 390px article had zero horizontal page
  overflow.
- No page error or console error was observed during the production smoke test.
