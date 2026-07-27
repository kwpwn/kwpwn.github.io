import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const blogDirectory = "src/content/blog";
const coverageFile = "src/data/yunolay-topic-coverage.json";
const topicContract = {
  "windows-privesc": {
    expectedSources: 41,
    expectedLessons: 27,
    tracks: new Set([
      "foundations",
      "discovery-evidence",
      "service-boundaries",
      "execution-persistence",
      "token-ipc",
      "credentials-recovery",
      "policy-controls",
      "lateral-boundaries",
    ]),
    recommendedStart: "windows-privesc-trust-boundary-model",
  },
  "malware-c2": {
    expectedSources: 20,
    expectedLessons: 20,
    tracks: new Set([
      "foundations",
      "static-analysis",
      "dynamic-analysis",
      "memory-execution",
      "execution-persistence",
      "detection-engineering",
      "c2-operations",
    ]),
    recommendedStart: "malware-c2-execution-tasking-telemetry-model",
  },
  "windows-internals": {
    expectedSources: 31,
    expectedLessons: 32,
    tracks: new Set([
      "boot-architecture",
      "processes-execution",
      "memory-manager",
      "security-objects",
      "io-drivers",
      "ipc-services",
      "telemetry-runtime",
      "kernel-platform",
    ]),
    recommendedStart: "windows-process-thread-token-handle-model",
  },
};

const topicPosts = new Map(
  Object.keys(topicContract).map((topic) => [topic, []]),
);
const postSources = new Map();
const errors = [];
const coverage = JSON.parse(await readFile(coverageFile, "utf8"));
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

function placements(frontmatter) {
  const block =
    frontmatter.match(
      /^topicPlacements:\s*\r?\n((?:(?: {2}-| {4})[^\r\n]*\r?\n?)*)/m,
    )?.[1] ?? "";
  const parsed = [];
  const placementPattern =
    /^ {2}- topic:\s*["']?([^"'\r\n]+)["']?\r?\n {4}track:\s*["']?([^"'\r\n]+)["']?\r?\n {4}order:\s*(\d+)\s*$/gm;

  for (const match of block.matchAll(placementPattern)) {
    parsed.push({
      topic: match[1].trim(),
      track: match[2].trim(),
      order: Number(match[3]),
    });
  }

  if (parsed.length) return parsed;

  const topic = scalar(frontmatter, "topic");
  const track = scalar(frontmatter, "track");
  const order = Number(scalar(frontmatter, "seriesOrder"));
  return topic && track && Number.isInteger(order)
    ? [{ topic, track, order }]
    : [];
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
  const postPlacements = placements(frontmatter);
  if (!postPlacements.length) continue;

  const slug = entry.name.replace(/\.(?:md|mdx)$/i, "");
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
  const difficulty = scalar(frontmatter, "difficulty");
  const labEnvironment = scalar(frontmatter, "labEnvironment");

  if (!["Foundation", "Intermediate", "Advanced"].includes(difficulty)) {
    fail(file, "difficulty must be Foundation, Intermediate, or Advanced");
  }
  if (!hasBlock(frontmatter, "prerequisites")) {
    fail(file, "prerequisites must contain at least one item");
  }
  if (!hasBlock(frontmatter, "learningObjectives")) {
    fail(file, "learningObjectives must contain at least one item");
  }
  if (!labEnvironment || labEnvironment.length < 60) {
    fail(file, "labEnvironment must explain the safe test boundary");
  }
  if (words < 700) {
    fail(file, `only ${words} prose words; expected at least 700`);
  }
  if (headingCount < 8) {
    fail(file, `only ${headingCount} headings; expected at least 8`);
  }
  if (codeBlockCount < 3) {
    fail(file, `only ${codeBlockCount} code examples; expected at least 3`);
  }
  if (!references) {
    fail(file, "missing a final ## References section");
  }
  if (referenceUrls.size < 6) {
    fail(
      file,
      `only ${referenceUrls.size} reference URLs; expected at least 6`,
    );
  }

  const duplicateTopics = postPlacements
    .map(({ topic }) => topic)
    .filter((topic, index, topics) => topics.indexOf(topic) !== index);
  if (duplicateTopics.length) {
    fail(
      file,
      `duplicates topic placements: ${[...new Set(duplicateTopics)].join(", ")}`,
    );
  }

  for (const placement of postPlacements) {
    const contract = topicContract[placement.topic];
    if (!contract) {
      fail(file, `unknown research topic "${placement.topic}"`);
      continue;
    }
    if (!contract.tracks.has(placement.track)) {
      fail(
        file,
        `track "${placement.track}" does not belong to ${placement.topic}`,
      );
    }
    if (!Number.isInteger(placement.order) || placement.order < 1) {
      fail(file, "placement order must be a positive integer");
    }
    topicPosts.get(placement.topic).push({
      slug,
      order: placement.order,
      track: placement.track,
    });
  }

  postSources.set(slug, { file, references });
}

for (const [topic, contract] of Object.entries(topicContract)) {
  const sources = coverage.filter((entry) => entry.topic === topic);
  if (sources.length !== contract.expectedSources) {
    errors.push(
      `${coverageFile}: ${topic} has ${sources.length} source entries; expected ${contract.expectedSources}`,
    );
  }

  const posts = topicPosts.get(topic);
  if (posts.length !== contract.expectedLessons) {
    errors.push(
      `${topic}: ${posts.length} lessons; expected exactly ${contract.expectedLessons}`,
    );
  }

  const duplicateOrders = posts
    .map(({ order }) => order)
    .filter(
      (order, index, orders) =>
        Number.isInteger(order) && orders.indexOf(order) !== index,
    );
  if (duplicateOrders.length) {
    errors.push(
      `${topic}: duplicate lesson orders ${[...new Set(duplicateOrders)].join(", ")}`,
    );
  }

  const expectedOrders = Array.from(
    { length: contract.expectedLessons },
    (_, index) => index + 1,
  );
  const actualOrders = posts.map(({ order }) => order).sort((a, b) => a - b);
  if (actualOrders.join(",") !== expectedOrders.join(",")) {
    errors.push(
      `${topic}: lesson orders must be the complete range 1-${contract.expectedLessons}; got ${actualOrders.join(", ")}`,
    );
  }

  for (const track of contract.tracks) {
    if (!posts.some((post) => post.track === track)) {
      errors.push(`${topic}: learning lane "${track}" has no lesson`);
    }
  }

  if (!posts.some(({ slug }) => slug === contract.recommendedStart)) {
    errors.push(`${topic}: recommended start article is missing`);
  }
}

for (const sourceEntry of coverage) {
  const post = postSources.get(sourceEntry.localSlug);
  if (!post) {
    errors.push(
      `${coverageFile}: ${sourceEntry.url} maps to missing lesson "${sourceEntry.localSlug}"`,
    );
    continue;
  }
  if (!post.references.includes(sourceEntry.url)) {
    errors.push(
      `${post.file}: References do not contain mapped source ${sourceEntry.url}`,
    );
  }
  if (
    !topicPosts
      .get(sourceEntry.topic)
      .some(({ slug }) => slug === sourceEntry.localSlug)
  ) {
    errors.push(
      `${post.file}: source ${sourceEntry.url} requires a ${sourceEntry.topic} placement`,
    );
  }
}

if (errors.length) {
  console.error(`Research topic validation failed:\n- ${errors.join("\n- ")}`);
  process.exit(1);
}

const uniqueLessons = new Set(
  [...topicPosts.values()].flat().map(({ slug }) => slug),
).size;
const placementsCount = [...topicPosts.values()].reduce(
  (total, posts) => total + posts.length,
  0,
);
console.log(
  `Research topic validation passed: ${coverage.length} source articles, ${uniqueLessons} unique lessons, ${placementsCount} topic placements.`,
);
