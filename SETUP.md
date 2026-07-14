# GitHub Pages setup

This project is configured as a GitHub user site. The repository must be named
`kwpwn.github.io`; this keeps the site at the domain root and avoids a
repository subpath.

## Publish

```bash
git remote set-url origin https://github.com/kwpwn/kwpwn.github.io.git
git add .
git commit -m "Set up blog"
git push -u origin main
```

Then open the repository on GitHub and choose **Settings → Pages → GitHub
Actions** as the publishing source. Every push to `main` runs
`.github/workflows/deploy.yml`.

The workflow derives `SITE_URL` from the repository owner, so canonical URLs,
the sitemap, RSS, and Open Graph metadata use the final `github.io` domain.
