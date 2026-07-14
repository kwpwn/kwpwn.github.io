# CTF Writeups

A minimal, static CTF writeup blog built with Astro. It contains a single
writeup index and individual Markdown post pages.

## Local development

Requires Node.js 24 and pnpm 8.15.

```bash
corepack enable
corepack prepare pnpm@8.15.0 --activate
pnpm install
pnpm dev
```

## Add a writeup

Create a Markdown or MDX file in `src/content/blog/`. Use this frontmatter:

```yaml
---
title: "Challenge name"
description: "What the challenge covered and how it was solved."
locale: "en"
publishDate: 2026-07-15
draft: false
tags:
  - web
  - picoctf
author: "kwpwn"
---
```

Set `draft: true` to keep an unfinished writeup out of production.

## Deploy to GitHub Pages

1. Create a public GitHub repository named `kwpwn.github.io`.
2. Push this project to the repository's `main` branch.
3. In **Settings → Pages → Build and deployment**, select **GitHub Actions**.
4. The `Deploy to GitHub Pages` workflow publishes the site automatically.

The production URL is `https://kwpwn.github.io`.

## Verification

```bash
pnpm build
pnpm lint
pnpm test
```
