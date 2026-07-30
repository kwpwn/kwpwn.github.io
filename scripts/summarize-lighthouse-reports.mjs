import fs from "node:fs";
import path from "node:path";

const reportPaths = process.argv.slice(2);

if (reportPaths.length === 0) {
  console.error("Usage: node scripts/summarize-lighthouse-reports.mjs <report.json> [...]");
  process.exit(1);
}

const metricIds = [
  "first-contentful-paint",
  "largest-contentful-paint",
  "total-blocking-time",
  "cumulative-layout-shift",
  "speed-index",
];

for (const reportPath of reportPaths) {
  const absolutePath = path.resolve(reportPath);
  const report = JSON.parse(fs.readFileSync(absolutePath, "utf8"));
  const categories = Object.fromEntries(
    Object.entries(report.categories ?? {}).map(([id, category]) => [
      id,
      Math.round((category.score ?? 0) * 100),
    ]),
  );
  const metrics = Object.fromEntries(
    metricIds.map((id) => {
      const audit = report.audits?.[id];
      return [
        id,
        {
          score: audit?.score ?? null,
          numericValue: audit?.numericValue ?? null,
          numericUnit: audit?.numericUnit ?? null,
          displayValue: audit?.displayValue ?? null,
        },
      ];
    }),
  );
  const summary = {
    lighthouseVersion: report.lighthouseVersion,
    requestedUrl: report.requestedUrl,
    finalUrl: report.finalUrl,
    fetchTime: report.fetchTime,
    runtimeError: report.runtimeError ?? null,
    runWarnings: report.runWarnings ?? [],
    categories,
    metrics,
  };

  fs.writeFileSync(absolutePath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  console.log(`Summarized ${path.relative(process.cwd(), absolutePath)}`);
}
