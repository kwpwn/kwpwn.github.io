import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const blogDirectory = "src/content/blog";
const topicContract = {
  "windows-privesc": {
    tracks: new Set([
      "foundations",
      "privilege-boundaries",
      "execution",
      "analysis",
    ]),
    recommendedStart: "windows-privesc-trust-boundary-model",
  },
  "malware-c2": {
    tracks: new Set(["foundations", "analysis", "execution", "telemetry"]),
    recommendedStart: "malware-c2-execution-tasking-telemetry-model",
  },
  "windows-internals": {
    tracks: new Set([
      "foundations",
      "privilege-boundaries",
      "kernel-boundaries",
      "execution",
    ]),
    recommendedStart: "windows-process-thread-token-handle-model",
  },
};

const topicPosts = new Map(
  Object.keys(topicContract).map((topic) => [topic, []]),
);
const errors = [];
const entries = await readdir(blogDirectory, { withFileTypes: true });

function fail(file, message) {
  errors.push(`${file}: ${message}`);
}

function scalar(frontmatter, key) {
  const match = frontmatter.match(new RegExp(`^${key}:\\s*([^\\r\\n]+)$`, "m"));
  return match?.[1].trim().replace(/^["']|["']$/g, "");
}

function hasBlock(frontmatter, key) {
  return new RegExp(
    `^${key}:\\s*(?:\\[[^\\]]+\\]|\\r?\\n(?:\\s+-\\s+[^\\r\\n]+\\r?\\n?)+)`,
    "m",
  ).test(frontmatter);
}

function proseWordCount(body) {
  const prose = body
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/^## References[\s\S]*$/m, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[`*_#[\]()>|~-]/g, " ");
  return prose.match(/\b[\p{L}\p{N}][\p{L}\p{N}'-]*\b/gu)?.length ?? 0;
}

for (const entry of entries) {
  if (!entry.isFile() || !/\.(?:md|mdx)$/i.test(entry.name)) continue;

  const file = path.join(blogDirectory, entry.name);
  const source = await readFile(file, "utf8");
  const frontmatterMatch = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  if (!frontmatterMatch) continue;

  const frontmatter = frontmatterMatch[1];
  const topic = scalar(frontmatter, "topic");
  if (!topic) continue;

  const contract = topicContract[topic];
  if (!contract) {
    fail(file, `unknown research topic "${topic}"`);
    continue;
  }

  const slug = entry.name.replace(/\.(?:md|mdx)$/i, "");
  const track = scalar(frontmatter, "track");
  const seriesOrder = Number(scalar(frontmatter, "seriesOrder"));
  const difficulty = scalar(frontmatter, "difficulty");
  const labEnvironment = scalar(frontmatter, "labEnvironment");
  const body = source.slice(frontmatterMatch[0].length);
  const references = body.match(/^## References\s*$([\s\S]*)/m)?.[1] ?? "";
  const referenceUrls = new Set(
    references
      .match(/https:\/\/[^\s)>]+/g)
      ?.map((url) => url.replace(/[.,]$/, "")) ?? [],
  );
  const headingCount = body.match(/^##? .+$/gm)?.length ?? 0;
  const codeBlockCount = Math.floor((body.match(/^```/gm)?.length ?? 0) / 2);
  const words = proseWordCount(body);

  if (!contract.tracks.has(track)) {
    fail(file, `track "${track ?? ""}" does not belong to ${topic}`);
  }
  if (!Number.isInteger(seriesOrder) || seriesOrder < 1) {
    fail(file, "seriesOrder must be a positive integer");
  }
  if (!["Foundation", "Intermediate", "Advanced"].includes(difficulty)) {
    fail(file, "difficulty must be Foundation, Intermediate, or Advanced");
  }
  if (!hasBlock(frontmatter, "prerequisites")) {
    fail(file, "prerequisites must contain at least one item");
  }
  if (!hasBlock(frontmatter, "learningObjectives")) {
    fail(file, "learningObjectives must contain at least one item");
  }
  if (!labEnvironment || labEnvironment.length < 40) {
    fail(file, "labEnvironment must explain the safe test boundary");
  }
  if (words < 700) {
    fail(file, `only ${words} prose words; expected at least 700`);
  }
  if (headingCount < 6) {
    fail(file, `only ${headingCount} headings; expected at least 6`);
  }
  if (codeBlockCount < 2) {
    fail(file, `only ${codeBlockCount} code examples; expected at least 2`);
  }
  if (!references) {
    fail(file, "missing a final ## References section");
  }
  if (referenceUrls.size < 5) {
    fail(
      file,
      `only ${referenceUrls.size} reference URLs; expected at least 5`,
    );
  }
  if (!references.includes("https://yunolay.com/")) {
    fail(file, "References must include a relevant Yunolay resource");
  }

  topicPosts.get(topic).push({ slug, seriesOrder, track });
}

for (const [topic, posts] of topicPosts) {
  if (posts.length < 4) {
    errors.push(`${topic}: only ${posts.length} lessons; expected at least 4`);
  }

  const duplicateOrders = posts
    .map((post) => post.seriesOrder)
    .filter(
      (order, index, orders) =>
        Number.isInteger(order) && orders.indexOf(order) !== index,
    );
  if (duplicateOrders.length) {
    errors.push(
      `${topic}: duplicate seriesOrder values ${[...new Set(duplicateOrders)].join(", ")}`,
    );
  }

  for (const track of topicContract[topic].tracks) {
    if (!posts.some((post) => post.track === track)) {
      errors.push(`${topic}: learning lane "${track}" has no lesson`);
    }
  }

  if (
    !posts.some(({ slug }) => slug === topicContract[topic].recommendedStart)
  ) {
    errors.push(`${topic}: recommended start article is missing`);
  }
}

if (errors.length) {
  console.error(`Research topic validation failed:\n- ${errors.join("\n- ")}`);
  process.exit(1);
}

const lessonCount = [...topicPosts.values()].reduce(
  (total, posts) => total + posts.length,
  0,
);
console.log(
  `Research topic validation passed: ${Object.keys(topicContract).length} topics, ${lessonCount} structured lessons.`,
);
