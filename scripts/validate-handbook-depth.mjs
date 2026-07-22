import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const handbookRoot = path.resolve("dist/windows-security-concepts");
const minimumConcepts = 150;
const minimumWords = 1500;
const minimumHeadings = 15;
const minimumCodeCharacters = 180;
const requiredSections = [
  "meaning",
  "context",
  "invariant",
  "capability",
  "example",
  "constraints",
  "mechanics",
  "audit",
  "pitfalls",
  "lab",
  "defenses",
  "sources",
];
const mojibakePatterns = [/Â/u, /Ã/u, /â€/u, /ï¿½/u, /�/u];

function articleBody(html, file) {
  const start = html.indexOf('<article class="concept-document"');
  const end = html.indexOf('<aside class="concept-document__rail"', start);

  if (start === -1 || end === -1 || end <= start) {
    throw new Error(`Could not isolate the concept document in ${file}.`);
  }

  return html.slice(start, end);
}

function visibleText(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:[a-z][a-z0-9]+|#\d+|#x[a-f0-9]+);/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const entries = await readdir(handbookRoot, { withFileTypes: true });
const conceptFiles = entries
  .filter((entry) => entry.isDirectory() && entry.name !== "topics")
  .map((entry) => path.join(handbookRoot, entry.name, "index.html"));

if (conceptFiles.length < minimumConcepts) {
  throw new Error(
    `Built handbook contains ${conceptFiles.length} concept pages; expected at least ${minimumConcepts}.`,
  );
}

const failures = [];
const measurements = [];

for (const file of conceptFiles) {
  const html = await readFile(file, "utf8");
  const body = articleBody(html, file);
  const text = visibleText(body);
  const words = text.match(/[A-Za-z0-9][A-Za-z0-9'/-]*/g)?.length ?? 0;
  const headings = body.match(/<h[23]\b/gi)?.length ?? 0;
  const codeBlocks = [
    ...body.matchAll(
      /<pre\b[^>]*>[\s\S]*?<code\b[^>]*>([\s\S]*?)<\/code>[\s\S]*?<\/pre>/gi,
    ),
  ];
  const codeCharacters = codeBlocks.reduce(
    (total, match) => total + visibleText(match[1]).length,
    0,
  );
  const missingSections = requiredSections.filter(
    (section) => !body.includes(`id="${section}"`),
  );
  const mojibake = mojibakePatterns.some((pattern) => pattern.test(body));

  measurements.push({ file, words, headings, codeBlocks: codeBlocks.length });

  if (words < minimumWords) failures.push(`${file}: ${words} words`);
  if (headings < minimumHeadings)
    failures.push(`${file}: ${headings} h2/h3 headings`);
  if (!codeBlocks.length) failures.push(`${file}: no educational code block`);
  if (codeCharacters < minimumCodeCharacters)
    failures.push(`${file}: only ${codeCharacters} code characters`);
  if (missingSections.length)
    failures.push(`${file}: missing sections ${missingSections.join(", ")}`);
  if (mojibake) failures.push(`${file}: possible mojibake`);
}

if (failures.length) {
  throw new Error(
    `Handbook depth validation failed:\n- ${failures.join("\n- ")}`,
  );
}

const wordCounts = measurements.map((item) => item.words).sort((a, b) => a - b);
const headingCounts = measurements.map((item) => item.headings);
const average = Math.round(
  wordCounts.reduce((total, count) => total + count, 0) / wordCounts.length,
);
const median = wordCounts[Math.floor(wordCounts.length / 2)];

console.log(
  `Handbook depth valid: ${measurements.length} pages, ${wordCounts[0]}-${wordCounts.at(-1)} words (median ${median}, average ${average}), ${Math.min(...headingCounts)}+ headings, and code on every page.`,
);
