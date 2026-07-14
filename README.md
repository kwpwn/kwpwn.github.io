# Blogs

A minimal personal blog built with Astro and deployed to GitHub Pages.

## Local development

Requires Node.js 24 and pnpm 8.15.

```bash
corepack enable
corepack prepare pnpm@8.15.0 --activate
pnpm install
pnpm dev
```

## Add a post

Create a Markdown or MDX file in `src/content/blog/`:

```yaml
---
title: "Post title"
description: "A short description of the post."
locale: "en"
publishDate: 2026-07-15
draft: false
tags:
  - notes
author: "kwpwn"
---
```

Set `draft: true` to keep an unfinished post out of production.

## Deploy to GitHub Pages

The repository is published automatically from `main` by
`.github/workflows/deploy.yml`.

Production URL: `https://kwpwn.github.io`.

## Verification

```bash
pnpm build
pnpm lint
pnpm test
```
