# KWPWN Research Library

An evidence-led Windows security learning and research library built with Astro
and published at <https://kwpwn.github.io>.

The site combines ordered learning paths, long-form lessons, a concept
handbook, case studies, and the Windows Service Atlas. Technical material is
explicit about review status, evidence level, Windows scope, and unresolved
questions.

## Requirements

- Node.js 24
- pnpm 8.15 through Corepack

## Run locally

```bash
corepack enable
corepack prepare pnpm@8.15.0 --activate
pnpm install --frozen-lockfile
pnpm dev
```

The development server prints its local URL. Full-text search is generated only
during a production build, so use the preview workflow when testing Pagefind:

```bash
pnpm build
pnpm preview
```

## Content model

Articles live in `src/content/blog/` as MDX. New material should use the
validated metadata model in `src/content.config.ts`. A minimal preliminary
article looks like this:

```yaml
---
title: "Article title"
description: "A specific summary that helps a reader decide whether to open it."
locale: "en"
publishDate: 2026-07-30
updatedAt: 2026-07-30
author: "kwpwn"
draft: false
content_type: "research-note"
status: "preliminary"
evidence_level: "unverified"
tags:
  - windows
prerequisites: []
learningObjectives: []
windows_versions: []
windows_builds: []
architectures: []
sources: []
---
```

Do not mark an article `confirmed` until its important claims have
claim-adjacent citations and its structured source/evidence record satisfies
the validator. Unknown build scope should remain empty and will be shown as
unverified in the interface.

## Verification

Run the same quality gates used before deployment:

```bash
pnpm build
pnpm lint
pnpm run lint:css
pnpm test
pnpm test:e2e
pnpm validate:content
```

`pnpm lint` includes type checking, design KPI checks, metadata validation,
internal route and anchor checks, handbook/service validation, i18n checks, and
the repository secret scan. Playwright E2E tests include axe-core WCAG A/AA
checks for representative light and dark pages.

Audit findings and executed QA results are in `reports/`.

## Deploy to GitHub Pages

Push a verified commit to `main`. `.github/workflows/deploy.yml` builds the
static Astro output, uploads it as a GitHub Pages artifact, and deploys it to
<https://kwpwn.github.io>.

Generated `dist/` output is not committed. Pagefind runs as part of
`pnpm build`, so the uploaded artifact contains the local search index.
