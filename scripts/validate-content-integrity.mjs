import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const blogDirectory = path.join(root, "src", "content", "blog");
const distDirectory = path.join(root, "dist");
const reportsDirectory = path.join(root, "reports");

const allowedContentTypes = new Set([
  "concept",
  "vulnerability",
  "service-dossier",
  "lab",
  "research-note",
  "reference",
  "interactive-atlas",
]);
const allowedStatuses = new Set([
  "draft",
  "preliminary",
  "reviewed",
  "confirmed",
  "superseded",
  "archived",
]);
const allowedEvidenceLevels = new Set([
  "documented",
  "observed",
  "inferred",
  "hypothesis",
  "mixed",
  "unverified",
]);
const templateHeadings = new Set([
  "scope and evidence contract",
  "architecture at a glance",
  "mechanism deep dive",
  "key terms in plain language",
  "version and environment scope",
  "evidence matrix",
  "safe guided lab",
  "worked case-study method",
  "detection and hardening",
  "failure modes and review checklist",
  "takeaways",
  "check your understanding",
  "limitations and next research",
  "source coverage and reliability",
]);
const primaryHosts = new Set([
  "learn.microsoft.com",
  "msrc.microsoft.com",
  "cve.org",
  "www.cve.org",
  "cisa.gov",
  "www.cisa.gov",
]);

const stripQuotes = (value = "") => {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
};

const scalar = (frontmatter, key) => {
  const match = frontmatter.match(
    new RegExp(
      `^${key.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")}:\\s*(.+)$`,
      "m",
    ),
  );
  return match ? stripQuotes(match[1]) : undefined;
};

const list = (frontmatter, key) => {
  const lines = frontmatter.split(/\r?\n/);
  const index = lines.findIndex((line) => line === `${key}:`);
  if (index < 0) return [];

  const values = [];
  for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
    const line = lines[cursor];
    if (!line.startsWith("  ")) break;
    const match = line.match(/^\s+-\s+(.+)$/);
    if (match) values.push(stripQuotes(match[1]));
  }
  return values;
};

const normalizeHeading = (heading) =>
  heading
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .toLowerCase();

const isValidDate = (value) =>
  /^\d{4}-\d{2}-\d{2}$/.test(value || "") &&
  !Number.isNaN(Date.parse(`${value}T00:00:00Z`));

const markdownFiles = (await readdir(blogDirectory))
  .filter((file) => /\.(?:md|mdx)$/i.test(file))
  .sort();
const slugMap = new Map();
const articles = [];
const errors = [];
const warnings = [];

for (const file of markdownFiles) {
  const filePath = path.join(blogDirectory, file);
  const source = await readFile(filePath, "utf8");
  const frontmatterMatch = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);

  if (!frontmatterMatch) {
    errors.push({ file, kind: "missing-frontmatter" });
    continue;
  }

  const slug = file.replace(/\.(?:md|mdx)$/i, "");
  const frontmatter = frontmatterMatch[1];
  const body = source.slice(frontmatterMatch[0].length);
  const bodyWithoutCode = body.replace(
    /^```[^\r\n]*\r?\n[\s\S]*?^```\s*$/gm,
    "",
  );
  const title = scalar(frontmatter, "title");
  const description = scalar(frontmatter, "description");
  const contentType = scalar(frontmatter, "content_type");
  const status = scalar(frontmatter, "status");
  const evidenceLevel = scalar(frontmatter, "evidence_level");
  const publishDate = scalar(frontmatter, "publishDate");
  const updatedAt = scalar(frontmatter, "updatedAt");
  const reviewedAt = scalar(frontmatter, "reviewed_at");
  const difficulty = scalar(frontmatter, "difficulty");
  const cves = list(frontmatter, "cves");
  const windowsBuilds = list(frontmatter, "windows_builds");
  const structuredSourceCount = (frontmatter.match(/^\s+-\s+title:\s+/gm) || [])
    .length;

  const duplicateSlug = slugMap.get(slug);
  if (duplicateSlug) {
    errors.push({
      file,
      kind: "duplicate-slug",
      detail: `Also used by ${duplicateSlug}`,
    });
  } else {
    slugMap.set(slug, file);
  }

  for (const [key, value] of [
    ["title", title],
    ["description", description],
    ["content_type", contentType],
    ["status", status],
    ["evidence_level", evidenceLevel],
    ["publishDate", publishDate],
  ]) {
    if (!value) errors.push({ file, kind: "missing-metadata", detail: key });
  }

  if (description !== undefined && description.trim().length === 0) {
    errors.push({ file, kind: "empty-description" });
  }
  if (contentType && !allowedContentTypes.has(contentType)) {
    errors.push({ file, kind: "invalid-content-type", detail: contentType });
  }
  if (status && !allowedStatuses.has(status)) {
    errors.push({ file, kind: "invalid-status", detail: status });
  }
  if (evidenceLevel && !allowedEvidenceLevels.has(evidenceLevel)) {
    errors.push({
      file,
      kind: "invalid-evidence-level",
      detail: evidenceLevel,
    });
  }
  for (const [key, value] of [
    ["publishDate", publishDate],
    ["updatedAt", updatedAt],
    ["reviewed_at", reviewedAt],
  ]) {
    if (value && !isValidDate(value)) {
      errors.push({ file, kind: "invalid-date", detail: `${key}: ${value}` });
    }
  }
  for (const cve of cves) {
    if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) {
      errors.push({ file, kind: "invalid-cve", detail: cve });
    }
  }
  for (const build of windowsBuilds) {
    if (!/^(?:10\.0\.)?\d{4,5}(?:\.\d+)?$/.test(build)) {
      errors.push({ file, kind: "invalid-windows-build", detail: build });
    }
  }

  const headings = [...bodyWithoutCode.matchAll(/^(#{1,6})\s+(.+)$/gm)].map(
    (match) => ({
      depth: match[1].length,
      text: match[2].trim(),
      normalized: normalizeHeading(match[2]),
    }),
  );
  const headingCounts = new Map();
  for (const heading of headings) {
    headingCounts.set(
      heading.normalized,
      (headingCounts.get(heading.normalized) || 0) + 1,
    );
  }
  const duplicateHeadings = [...headingCounts]
    .filter(([, count]) => count > 1)
    .map(([heading]) => heading);
  if (duplicateHeadings.length) {
    errors.push({
      file,
      kind: "duplicate-heading",
      detail: duplicateHeadings.join(", "),
    });
  }

  const hierarchyJumps = [];
  let previousDepth = 1;
  for (const heading of headings) {
    if (heading.depth > previousDepth + 1) {
      hierarchyJumps.push(`${previousDepth}→${heading.depth}: ${heading.text}`);
    }
    previousDepth = heading.depth;
  }
  if (hierarchyJumps.length) {
    warnings.push({
      file,
      kind: "heading-hierarchy",
      detail: hierarchyJumps.join("; "),
    });
  }

  const referencesIndex = body.search(/^##\s+References\s*$/m);
  const hasReferences = referencesIndex >= 0;
  if (!hasReferences && contentType !== "interactive-atlas") {
    errors.push({ file, kind: "missing-references" });
  }

  const claimBody =
    referencesIndex >= 0 ? body.slice(0, referencesIndex) : body;
  const inlineCitationCount = (
    claimBody.match(/\[[^\]]+\]\(https?:\/\/[^)]+\)/g) || []
  ).length;
  const urls = [...body.matchAll(/https?:\/\/[^\s)>\]]+/g)].map((match) =>
    match[0].replace(/[.,;:]$/, ""),
  );
  const primarySourceCount = urls.filter((url) => {
    try {
      const parsed = new URL(url);
      return (
        primaryHosts.has(parsed.hostname) ||
        (parsed.hostname === "github.com" &&
          /^\/microsoft\//i.test(parsed.pathname))
      );
    } catch {
      return false;
    }
  }).length;

  if (structuredSourceCount === 0) {
    warnings.push({ file, kind: "missing-structured-sources" });
  }
  if (inlineCitationCount === 0 && contentType !== "interactive-atlas") {
    warnings.push({ file, kind: "no-claim-adjacent-citations" });
  }
  if (primarySourceCount === 0 && contentType !== "interactive-atlas") {
    warnings.push({ file, kind: "missing-primary-source" });
  }
  if (
    status === "confirmed" &&
    (structuredSourceCount === 0 || inlineCitationCount === 0)
  ) {
    errors.push({
      file,
      kind: "confirmed-without-evidence",
      detail:
        "Confirmed content requires structured sources and claim-adjacent citations.",
    });
  }

  const templateHeadingCount = headings.filter((heading) =>
    templateHeadings.has(heading.normalized),
  ).length;
  const templateHeavy = templateHeadingCount >= 10;
  if (templateHeavy) {
    warnings.push({
      file,
      kind: "template-heavy",
      detail: `${templateHeadingCount} shared curriculum headings`,
    });
  }

  const prerequisiteHeadingCount = headings.filter(
    (heading) => heading.normalized === "prerequisites",
  ).length;
  if (prerequisiteHeadingCount > 1) {
    errors.push({ file, kind: "duplicate-prerequisites" });
  }
  const tocHeadingCount = headings.filter(
    (heading) => heading.normalized === "table of contents",
  ).length;
  if (tocHeadingCount > 1) {
    errors.push({ file, kind: "duplicate-table-of-contents" });
  }

  const fences = [...body.matchAll(/^```([^\r\n]*)$/gm)];
  const codeFenceBalanced = fences.length % 2 === 0;
  if (!codeFenceBalanced) {
    errors.push({ file, kind: "unbalanced-code-fence" });
  }
  const unlabeledCodeFences = fences.filter(
    (match, index) => index % 2 === 0 && !match[1].trim(),
  ).length;

  const wordCount = body
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<[^>]+>/g, " ")
    .split(/\s+/)
    .filter(Boolean).length;

  articles.push({
    file,
    slug,
    title,
    contentType,
    status,
    evidenceLevel,
    difficulty,
    wordCount,
    hasReferences,
    inlineCitationCount,
    structuredSourceCount,
    primarySourceCount,
    templateHeavy,
    templateHeadingCount,
    unlabeledCodeFences,
  });
}

const htmlFiles = [];
const walk = async (directory) => {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await walk(fullPath);
    } else if (entry.name.endsWith(".html")) {
      htmlFiles.push(fullPath);
    }
  }
};

try {
  await stat(distDirectory);
  await walk(distDirectory);
} catch {
  warnings.push({
    file: "dist",
    kind: "dist-not-found",
    detail: "Run the build before validating generated links and anchors.",
  });
}

const routeForFile = (filePath) => {
  const relative = path.relative(distDirectory, filePath).replaceAll("\\", "/");
  if (relative === "index.html") return "/";
  if (relative.endsWith("/index.html")) {
    return `/${relative.slice(0, -"/index.html".length)}/`;
  }
  return `/${relative}`;
};

const routeMap = new Map();
const duplicateIds = [];
for (const htmlFile of htmlFiles) {
  const html = await readFile(htmlFile, "utf8");
  const route = routeForFile(htmlFile);
  const ids = [...html.matchAll(/\sid=["']([^"']+)["']/g)].map(
    (match) => match[1],
  );
  const idSet = new Set();
  for (const id of ids) {
    if (idSet.has(id)) duplicateIds.push({ route, id });
    idSet.add(id);
  }
  routeMap.set(route, { html, ids: idSet });
}

const normalizeRoute = (pathname) => {
  if (pathname === "/") return "/";
  return pathname.endsWith("/") ? pathname : `${pathname}/`;
};

const fileExists = async (pathname) => {
  const relative = pathname.replace(/^\/+/, "");
  if (!relative) return true;
  try {
    await stat(path.join(distDirectory, relative));
    return true;
  } catch {
    return false;
  }
};

const brokenInternalLinks = [];
const brokenAnchors = [];
for (const [route, { html }] of routeMap) {
  const hrefs = [
    ...html.matchAll(/<a\b[^>]*\bhref=["']([^"']+)["'][^>]*>/gi),
  ].map((match) => match[1]);

  for (const href of hrefs) {
    if (
      /^(?:https?:|mailto:|tel:|javascript:|data:)/i.test(href) ||
      href === ""
    ) {
      continue;
    }

    let parsed;
    try {
      parsed = new URL(href, `https://local.test${route}`);
    } catch {
      brokenInternalLinks.push({ route, href, reason: "invalid-url" });
      continue;
    }

    const normalized = normalizeRoute(parsed.pathname);
    const target =
      routeMap.get(parsed.pathname) ||
      routeMap.get(normalized) ||
      routeMap.get(parsed.pathname.replace(/\/$/, ""));
    const targetExists = Boolean(target) || (await fileExists(parsed.pathname));

    if (!targetExists) {
      brokenInternalLinks.push({ route, href, reason: "missing-target" });
      continue;
    }

    if (parsed.hash && target) {
      let anchor = parsed.hash.slice(1);
      try {
        anchor = decodeURIComponent(anchor);
      } catch {
        // Keep the original fragment so the report can expose the invalid encoding.
      }
      if (anchor && !target.ids.has(anchor)) {
        brokenAnchors.push({ route, href, target: normalized, anchor });
      }
    }
  }
}

for (const issue of duplicateIds) {
  errors.push({
    file: issue.route,
    kind: "duplicate-html-id",
    detail: issue.id,
  });
}
for (const issue of brokenInternalLinks) {
  errors.push({
    file: issue.route,
    kind: "broken-internal-link",
    detail: `${issue.href} (${issue.reason})`,
  });
}
for (const issue of brokenAnchors) {
  errors.push({
    file: issue.route,
    kind: "broken-anchor",
    detail: issue.href,
  });
}

const count = (predicate) => articles.filter(predicate).length;
const unsupported = articles.filter(
  (article) =>
    article.inlineCitationCount === 0 &&
    article.structuredSourceCount === 0 &&
    article.contentType !== "interactive-atlas",
);
const missingPrimary = articles.filter(
  (article) =>
    article.primarySourceCount === 0 &&
    article.contentType !== "interactive-atlas",
);
const templateHeavy = articles.filter((article) => article.templateHeavy);
const advancedReview = articles.filter(
  (article) =>
    article.difficulty === "Advanced" &&
    article.status !== "confirmed" &&
    article.inlineCitationCount === 0,
);
const longTemplateArticles = articles.filter(
  (article) => article.templateHeavy && article.wordCount > 4000,
);

const report = {
  generatedAt: new Date().toISOString(),
  summary: {
    totalArticles: articles.length,
    confirmedArticles: count((article) => article.status === "confirmed"),
    articlesRequiringRevision: count(
      (article) => !["confirmed", "archived"].includes(article.status),
    ),
    articlesWithUnsupportedClaimCoverage: unsupported.length,
    articlesMissingPrimarySources: missingPrimary.length,
    templateHeavyArticles: templateHeavy.length,
    brokenInternalLinks: brokenInternalLinks.length,
    brokenAnchors: brokenAnchors.length,
    duplicateHtmlIds: duplicateIds.length,
    unbalancedCodeSnippets: errors.filter(
      (issue) => issue.kind === "unbalanced-code-fence",
    ).length,
    unlabeledCodeBlocks: articles.reduce(
      (total, article) => total + article.unlabeledCodeFences,
      0,
    ),
  },
  errors,
  warnings,
  articles,
  recommendations: {
    merge:
      "Move the repeated research method into /windows-security-concepts/research-evidence/ and link to it from topic-specific lessons.",
    splitCandidates: longTemplateArticles.map((article) => article.file),
    downgradeAdvancedCandidates: advancedReview.map((article) => article.file),
    archive:
      "No article was auto-archived. Archive decisions require a human technical review and replacement/redirect plan.",
  },
};

await mkdir(reportsDirectory, { recursive: true });
await writeFile(
  path.join(reportsDirectory, "content-integrity.json"),
  `${JSON.stringify(report, null, 2)}\n`,
  "utf8",
);

const articleRows = articles.map((article) => {
  const citation =
    article.inlineCitationCount > 0
      ? String(article.inlineCitationCount)
      : "None detected";
  const sourceStatus =
    article.structuredSourceCount > 0
      ? `${article.structuredSourceCount} structured`
      : "Migration required";
  const notes = [
    article.templateHeavy ? "Template-heavy" : "",
    article.primarySourceCount === 0 ? "No primary source detected" : "",
    article.unlabeledCodeFences
      ? `${article.unlabeledCodeFences} unlabeled code fences`
      : "",
  ]
    .filter(Boolean)
    .join("; ");
  return `| \`${article.file}\` | ${article.contentType} | ${article.status} | ${article.evidenceLevel} | ${citation} | ${sourceStatus} | ${notes || "—"} |`;
});

const issueLines = (issues) =>
  issues.length
    ? issues.map(
        (issue) =>
          `- \`${issue.file}\` — **${issue.kind}**${issue.detail ? `: ${issue.detail}` : ""}`,
      )
    : ["- None."];

const markdown = `# Content integrity report

Generated: ${report.generatedAt}

This report is conservative. “Unsupported claim coverage” means the automated
audit found neither structured source records nor claim-adjacent links; it does
not prove that every sentence is false. Technical confirmation still requires a
human review and, where applicable, version-matched reproduction.

## Summary

| Measure | Result |
| --- | ---: |
| Total articles | ${report.summary.totalArticles} |
| Confirmed articles | ${report.summary.confirmedArticles} |
| Articles requiring revision | ${report.summary.articlesRequiringRevision} |
| Unsupported claim coverage | ${report.summary.articlesWithUnsupportedClaimCoverage} |
| Missing primary sources | ${report.summary.articlesMissingPrimarySources} |
| Template-heavy articles | ${report.summary.templateHeavyArticles} |
| Broken internal links | ${report.summary.brokenInternalLinks} |
| Broken anchors | ${report.summary.brokenAnchors} |
| Duplicate generated IDs | ${report.summary.duplicateHtmlIds} |
| Unbalanced code fences | ${report.summary.unbalancedCodeSnippets} |
| Unlabeled code blocks | ${report.summary.unlabeledCodeBlocks} |

## Blocking validation errors

${issueLines(errors).join("\n")}

## Review warnings

${issueLines(warnings).join("\n")}

## Article-by-article review state

| File | Type | Status | Evidence | Inline citations | Structured sources | Notes |
| --- | --- | --- | --- | ---: | --- | --- |
${articleRows.join("\n")}

## Recommended actions

### Merge

${report.recommendations.merge}

### Split candidates

${
  report.recommendations.splitCandidates.length
    ? report.recommendations.splitCandidates
        .map((file) => `- \`${file}\``)
        .join("\n")
    : "- None identified automatically."
}

### Difficulty downgrade candidates

These articles are marked Advanced but remain unconfirmed and have no
claim-adjacent citations. Review them manually before retaining the label:

${
  report.recommendations.downgradeAdvancedCandidates.length
    ? report.recommendations.downgradeAdvancedCandidates
        .map((file) => `- \`${file}\``)
        .join("\n")
    : "- None."
}

### Archive

${report.recommendations.archive}

## Code verification limit

The validator checks fenced-block balance and language labels. It does not claim
that snippets compile or that commands were executed. Snippets requiring build,
syntax, or lab verification remain manual-review items.
`;

await writeFile(
  path.join(reportsDirectory, "CONTENT_INTEGRITY.md"),
  markdown,
  "utf8",
);

console.log(
  `Content integrity: ${articles.length} articles, ${errors.length} errors, ${warnings.length} warnings.`,
);
console.log(
  `Internal links: ${brokenInternalLinks.length} broken routes, ${brokenAnchors.length} broken anchors, ${duplicateIds.length} duplicate IDs.`,
);

if (errors.length) process.exitCode = 1;
