import { readFile } from "node:fs/promises";

const source = await readFile("src/components/blog/ResearchCheatsheet.astro", "utf8");
const start = source.indexOf("const researchers =");
const end = source.indexOf("const total =");

if (start === -1 || end === -1 || end <= start) {
  throw new Error("Could not locate the research catalog in ResearchCheatsheet.astro");
}

const catalogSource = source.slice(start, end).replaceAll(" as const", "");
const { groups, researchers } = Function(`${catalogSource}; return { groups, researchers };`)();
const errors = [];
const seenUrls = new Map();
const seenIds = new Set();
const currentYear = new Date().getUTCFullYear();

const fail = (message) => errors.push(message);
const validUrl = (value) => {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
};

for (const researcher of researchers) {
  if (researcher.length !== 5) fail(`Researcher tuple must have 5 fields: ${researcher[0]}`);
  if (!validUrl(researcher[2]) || !validUrl(researcher[3])) fail(`Researcher links must use HTTPS: ${researcher[0]}`);
  if (researcher[4].length < 60) fail(`Researcher description is too short: ${researcher[0]}`);
}

for (const group of groups) {
  if (seenIds.has(group.id)) fail(`Duplicate group id: ${group.id}`);
  seenIds.add(group.id);

  for (const item of group.items) {
    const [title, url, author, year, rating, keywords, description] = item;
    if (item.length !== 7) fail(`Resource tuple must have 7 fields: ${title}`);
    if (!validUrl(url)) fail(`Resource link must use HTTPS: ${title}`);
    if (!author?.trim()) fail(`Resource has no author: ${title}`);
    if (!(year === "Living" || (/^\d{4}$/.test(year) && Number(year) <= currentYear))) fail(`Invalid year for ${title}: ${year}`);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) fail(`Invalid rating for ${title}: ${rating}`);
    if (keywords.trim().split(/\s+/).length < 3) fail(`Add at least three search keywords: ${title}`);
    if (description.length < 140) fail(`Description is too short (${description.length} chars): ${title}`);
    const normalized = url.replace(/\/$/, "").toLowerCase();
    if (seenUrls.has(normalized)) fail(`Duplicate URL in ${group.id} and ${seenUrls.get(normalized)}: ${url}`);
    seenUrls.set(normalized, group.id);
  }
}

const counts = Object.fromEntries(groups.map((group) => [group.id, group.items.length]));
if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Research catalog valid: ${researchers.length} researchers, ${seenUrls.size} unique resources.`);
  console.log(counts);
}
