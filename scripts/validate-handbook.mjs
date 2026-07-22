import { readFile } from "node:fs/promises";

const conceptFiles = [
  "src/data/windows-security-handbook.ts",
  "src/data/windows-security-primitives.ts",
  "src/data/windows-security-vulnerability-classes.ts",
  "src/data/windows-security-attack-surfaces.ts",
  "src/data/windows-security-driver-types.ts",
  "src/data/windows-security-lpe.ts",
  "src/data/windows-security-mitigations.ts",
  "src/data/windows-security-workflow.ts",
];

const requiredKernelSightMappings = [
  "arbitrary-increment-decrement",
  "direct-ioctl-read-write",
  "dma-mmio-access",
  "mdl-mapping",
  "pipe-attribute-primitives",
  "pool-overflow-to-read-write",
  "pte-manipulation",
  "registry-based-primitives",
  "token-manipulation",
  "write-what-where",
  "acl-security-descriptor-manipulation",
  "bit-manipulation",
  "io-ring",
  "kuser-shared-data",
  "named-pipe-objects",
  "palette-bitmap-objects",
  "pool-spray-feng-shui",
  "previous-mode-manipulation",
  "exploit-chain-patterns",
  "token-swapping",
  "wnf-state-data",
  "arbitrary-read-write-primitives",
  "buffer-overflow",
  "integer-overflow",
  "logic-bugs",
  "null-pointer-dereference",
  "race-conditions",
  "toctou-double-fetch",
  "type-confusion",
  "uninitialized-memory",
  "use-after-free",
  "alpc",
  "filesystem-irps",
  "ioctl-handlers",
  "ndis-network",
  "pnp-and-power",
  "registry-callbacks",
  "shared-memory",
  "wdf-kmdf",
  "wmi-etw",
  "core-kernel",
  "filesystem-drivers",
  "kernel-streaming-drivers",
  "log-transaction-drivers",
  "minifilter-drivers",
  "network-stack-drivers",
  "performance-and-gpu-drivers",
  "security-policy-drivers",
  "storage-caching-drivers",
  "third-party-security-drivers",
  "vendor-utility-drivers",
  "win32k-subsystem",
  "acg",
  "kaslr",
  "kaslr-bypasses",
  "kcfg-kcet",
  "kdp",
  "pool-hardening",
  "secure-pool",
  "smep-smap",
  "vbs-hvci",
  "corpus-analytics",
  "exploit-chain-patterns",
  "mitigation-timeline",
  "patch-patterns",
  "secure-driver-anatomy",
  "why-kernel-drivers",
  "kernel-debugging",
  "driver-fuzzing",
  "patch-diffing",
  "static-analysis",
  "autopiff-integration",
  "byovd",
  "kdu-provider-compatibility",
  "loldrivers-deep-analysis",
  "symbols-and-structures",
  "research-evidence",
];

const sourceTexts = await Promise.all(
  conceptFiles.map((file) => readFile(file, "utf8")),
);
const conceptSource = sourceTexts.join("\n");
const slugs = [...conceptSource.matchAll(/slug:\s*"([^"]+)"/g)].map(
  (match) => match[1],
);
const duplicateSlugs = slugs.filter(
  (slug, index) => slugs.indexOf(slug) !== index,
);

if (duplicateSlugs.length) {
  throw new Error(
    `Duplicate handbook slugs: ${[...new Set(duplicateSlugs)].join(", ")}`,
  );
}

if (slugs.length < 150) {
  throw new Error(
    `Handbook concept coverage dropped to ${slugs.length}; expected at least 150.`,
  );
}

const missingMappings = requiredKernelSightMappings.filter(
  (slug) => !slugs.includes(slug),
);
if (missingMappings.length) {
  throw new Error(
    `Missing KernelSight concept mappings: ${missingMappings.join(", ")}`,
  );
}

if (
  !conceptSource.includes(
    "https://www.exploitpack.com/blogs/news/kernel-driver-gates-and-handshakes",
  )
) {
  throw new Error("Kernel Driver Gates and Handshakes source is missing.");
}

const caseSource = await readFile(
  "src/data/windows-security-case-studies.ts",
  "utf8",
);
const caseBlock = caseSource.match(
  /const kernelSightCaseStudySlugs = \[([\s\S]*?)\] as const;/,
);
const caseSlugs = caseBlock
  ? [...caseBlock[1].matchAll(/"([^"]+)"/g)].map((match) => match[1])
  : [];

if (caseSlugs.length !== 160) {
  throw new Error(
    `KernelSight case-study coverage is ${caseSlugs.length}; expected 160.`,
  );
}

if (new Set(caseSlugs).size !== caseSlugs.length) {
  throw new Error("KernelSight case-study ledger contains duplicate slugs.");
}

const apiSource = await readFile("src/data/windows-api-cheatsheet.ts", "utf8");
const apiEntries = [...apiSource.matchAll(/name:\s*"([^"]+)",\s*\n\s*group:/g)];
const flagFamilies = [...apiSource.matchAll(/id:\s*"([^"]+)",\s*\n\s*title:/g)];

if (apiEntries.length < 35) {
  throw new Error(
    `API cheatsheet dropped to ${apiEntries.length} entries; expected at least 35.`,
  );
}

if (flagFamilies.length < 12) {
  throw new Error(
    `Flag reference dropped to ${flagFamilies.length} families; expected at least 12.`,
  );
}

const depthSource = await readFile(
  "src/data/windows-security-depth.ts",
  "utf8",
);
const scenarioBlock = depthSource.match(
  /const scenarioBySlug:[\s\S]*?= \{([\s\S]*?)\n\};/,
);
const scenarioSlugs = scenarioBlock
  ? [
      ...scenarioBlock[1].matchAll(/^\s*(?:"([^"]+)"|([a-z][a-z0-9-]*))\s*:/gm),
    ].map((match) => match[1] ?? match[2])
  : [];
const missingScenarios = slugs.filter((slug) => !scenarioSlugs.includes(slug));
const unknownScenarios = scenarioSlugs.filter((slug) => !slugs.includes(slug));

if (missingScenarios.length) {
  throw new Error(
    `Missing authored worked examples: ${missingScenarios.join(", ")}`,
  );
}

if (unknownScenarios.length) {
  throw new Error(
    `Worked examples reference unknown concepts: ${unknownScenarios.join(", ")}`,
  );
}

if (new Set(scenarioSlugs).size !== scenarioSlugs.length) {
  throw new Error("Worked-example catalog contains duplicate slugs.");
}

const documentSource = await readFile(
  "src/components/handbook/ConceptDocument.astro",
  "utf8",
);

for (const requiredSection of [
  'id="context"',
  'id="invariant"',
  'id="example"',
  'id="constraints"',
  'id="pitfalls"',
  'id="defenses"',
  "deepDive.lab.demo",
]) {
  if (!documentSource.includes(requiredSection)) {
    throw new Error(
      `Concept document is missing deep section: ${requiredSection}`,
    );
  }
}

console.log(
  `Handbook valid: ${slugs.length} concepts, ${scenarioSlugs.length} authored examples, ${caseSlugs.length} KernelSight case studies, ${apiEntries.length} APIs, ${flagFamilies.length} flag families.`,
);
