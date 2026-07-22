import { access, readFile } from "node:fs/promises";
import {
  WINDOWS_SERVICE_ROUTE_SCHEMA,
  getWindowsServiceTargetRoute,
  getWindowsServiceTopicRoute,
  getWindowsServiceRecords,
  slugifyWindowsServiceTopic,
  windowsServiceCatalog,
  windowsServiceCategoryGroups,
  windowsServiceTopicContent,
} from "../src/lib/windows-service-catalog.ts";

const requiredFiles = [
  "src/components/sections/WindowsServiceHub.astro",
  "src/components/sections/WindowsServiceTarget.astro",
  "src/components/sections/WindowsServiceTopic.astro",
  "src/pages/windows-service-vulnerabilities/targets/[service].astro",
  "src/pages/[locale]/windows-service-vulnerabilities/targets/[service].astro",
  "src/pages/windows-service-vulnerabilities/topics/[topic].astro",
  "src/pages/[locale]/windows-service-vulnerabilities/topics/[topic].astro",
];

const errors = [];
const fail = (message) => errors.push(message);

const existingFiles = await Promise.all(
  requiredFiles.map(async (file) => {
    try {
      await access(file);
      return file;
    } catch {
      fail(`Required multi-page catalog file is missing: ${file}`);
      return null;
    }
  }),
);

const routeContracts = [
  {
    file: "src/pages/windows-service-vulnerabilities/targets/[service].astro",
    param: "service",
    collection: /(?:catalog|windowsServiceCatalog)\.services/,
    component: /<WindowsServiceTarget\b/,
  },
  {
    file: "src/pages/[locale]/windows-service-vulnerabilities/targets/[service].astro",
    param: "service",
    collection: /(?:catalog|windowsServiceCatalog)\.services/,
    component: /<WindowsServiceTarget\b/,
  },
  {
    file: "src/pages/windows-service-vulnerabilities/topics/[topic].astro",
    param: "topic",
    collection:
      /(?:windowsServiceTopicContent|windowsServiceCategoryGroups)\.map/,
    component: /<WindowsServiceTopic\b/,
  },
  {
    file: "src/pages/[locale]/windows-service-vulnerabilities/topics/[topic].astro",
    param: "topic",
    collection:
      /(?:windowsServiceTopicContent|windowsServiceCategoryGroups)\.map/,
    component: /<WindowsServiceTopic\b/,
  },
];

for (const contract of routeContracts) {
  try {
    const source = await readFile(contract.file, "utf8");
    if (!/export\s+function\s+getStaticPaths\s*\(/.test(source)) {
      fail(`Dynamic route does not export getStaticPaths: ${contract.file}`);
    }
    if (!contract.collection.test(source)) {
      fail(
        `Dynamic route does not enumerate its full catalog collection: ${contract.file}`,
      );
    }
    if (
      !new RegExp(`params\\s*:\\s*\\{[^}]*\\b${contract.param}\\s*:`).test(
        source,
      )
    ) {
      fail(
        `Dynamic route does not emit the ${contract.param} parameter: ${contract.file}`,
      );
    }
    if (!contract.component.test(source)) {
      fail(
        `Dynamic route does not render its required catalog component: ${contract.file}`,
      );
    }
  } catch {
    // The required-file check above reports a single actionable missing-file error.
  }
}

const interactionContracts = [
  {
    file: "src/components/sections/WindowsServiceTarget.astro",
    checks: [
      [
        /id=\{record\.id\.toLowerCase\(\)\}/,
        "target records do not expose stable CVE/advisory fragment IDs",
      ],
      [
        /window\.location\.hash/,
        "target pages do not resolve the requested record fragment",
      ],
      [
        /window\.addEventListener\("hashchange",\s*revealHashTarget\)/,
        "target pages do not react to record fragment changes",
      ],
      [
        /card\.open\s*=\s*true/,
        "target fragments do not open the requested evidence record",
      ],
      [
        /card\.scrollIntoView\(/,
        "target fragments do not scroll the requested evidence record into view",
      ],
    ],
  },
  {
    file: "src/components/sections/WindowsServiceHub.astro",
    checks: [
      [
        /form\.addEventListener\("submit",\s*\(event\)\s*=>\s*\{\s*event\.preventDefault\(\);\s*filter\(\);/s,
        "target finder submits and reloads instead of applying filters in place",
      ],
    ],
  },
];

for (const contract of interactionContracts) {
  try {
    const source = await readFile(contract.file, "utf8");
    for (const [pattern, message] of contract.checks) {
      if (!pattern.test(source)) fail(`${message}: ${contract.file}`);
    }
  } catch {
    // The required-file check above reports a single actionable missing-file error.
  }
}

if (WINDOWS_SERVICE_ROUTE_SCHEMA.targetParam !== "service") {
  fail(
    `Target route parameter must match [service].astro; received ${WINDOWS_SERVICE_ROUTE_SCHEMA.targetParam}`,
  );
}
if (WINDOWS_SERVICE_ROUTE_SCHEMA.topicParam !== "topic") {
  fail(
    `Topic route parameter must match [topic].astro; received ${WINDOWS_SERVICE_ROUTE_SCHEMA.topicParam}`,
  );
}

const catalogServiceSlugs = new Set(
  windowsServiceCatalog.services.map((service) => service.slug),
);
const targetRoutes = new Map();
const targetRecordKeys = new Set();

for (const service of windowsServiceCatalog.services) {
  const records = getWindowsServiceRecords(service);
  const route = getWindowsServiceTargetRoute(service);

  if (service.vulnerabilityCount !== records.length) {
    fail(
      `${service.name} declares ${service.vulnerabilityCount} records but its target route receives ${records.length}`,
    );
  }
  if (service.vulnerabilityCount > 0 && records.length === 0) {
    fail(
      `Service with catalog records has no target-route payload: ${service.slug}`,
    );
  }
  if (
    route !== `${WINDOWS_SERVICE_ROUTE_SCHEMA.targetPrefix}${service.slug}/`
  ) {
    fail(`Non-canonical target route for ${service.slug}: ${route}`);
  }
  if (targetRoutes.has(route)) {
    fail(
      `Target route collision: ${service.slug} and ${targetRoutes.get(route)} both map to ${route}`,
    );
  }
  targetRoutes.set(route, service.slug);

  const localizedRoute = getWindowsServiceTargetRoute(service, "id");
  if (localizedRoute !== `/id${route}`) {
    fail(
      `Incorrect localized target route for ${service.slug}: ${localizedRoute}`,
    );
  }

  for (const record of records) {
    if (record.serviceSlug !== service.slug) {
      fail(
        `Target route ${route} received ${record.id} from ${record.serviceSlug}`,
      );
    }
    const key = `${record.serviceSlug}|${record.id}`;
    if (targetRecordKeys.has(key)) {
      fail(`Record appears in more than one target-route payload: ${key}`);
    }
    targetRecordKeys.add(key);
  }
}

const topicContentByCategory = new Map();
const topicContentSlugs = new Set();

for (const topic of windowsServiceTopicContent) {
  if (topicContentByCategory.has(topic.category)) {
    fail(`Duplicate topic content for category: ${topic.category}`);
  }
  if (topicContentSlugs.has(topic.slug)) {
    fail(`Duplicate topic slug: ${topic.slug}`);
  }
  topicContentByCategory.set(topic.category, topic);
  topicContentSlugs.add(topic.slug);

  if (slugifyWindowsServiceTopic(topic.category) !== topic.slug) {
    fail(
      `Category does not resolve to its stable topic slug: ${topic.category} -> ${topic.slug}`,
    );
  }
  if (
    !topic.summary ||
    !topic.boundary ||
    !topic.whyItMatters ||
    topic.weaknessPatterns.length < 3 ||
    topic.auditQuestions.length < 3 ||
    topic.labWorkflow.length < 3
  ) {
    fail(`Topic theory is incomplete: ${topic.slug}`);
  }
}

const catalogCategories = new Set(
  windowsServiceCatalog.services.map((service) => service.category),
);
const topicRoutes = new Map();
const topicRecordKeys = new Set();

for (const group of windowsServiceCategoryGroups) {
  const route = getWindowsServiceTopicRoute(group.category);

  if (!topicContentByCategory.has(group.category)) {
    fail(`Catalog category has no theory content: ${group.category}`);
  }
  if (group.slug !== slugifyWindowsServiceTopic(group.category)) {
    fail(`Category group uses a non-canonical slug: ${group.category}`);
  }
  if (route !== `${WINDOWS_SERVICE_ROUTE_SCHEMA.topicPrefix}${group.slug}/`) {
    fail(`Non-canonical topic route for ${group.category}: ${route}`);
  }
  if (topicRoutes.has(route)) {
    fail(
      `Topic route collision: ${group.category} and ${topicRoutes.get(route)} both map to ${route}`,
    );
  }
  topicRoutes.set(route, group.category);

  const localizedRoute = getWindowsServiceTopicRoute(group.category, "id");
  if (localizedRoute !== `/id${route}`) {
    fail(
      `Incorrect localized topic route for ${group.category}: ${localizedRoute}`,
    );
  }
  if (group.services.length === 0) {
    fail(`Topic route has no service targets: ${group.slug}`);
  }

  const groupServiceSlugs = new Set(
    group.services.map((service) => service.slug),
  );
  for (const serviceSlug of groupServiceSlugs) {
    if (!catalogServiceSlugs.has(serviceSlug)) {
      fail(`Topic ${group.slug} references an unknown service: ${serviceSlug}`);
    }
  }
  for (const record of group.records) {
    if (!groupServiceSlugs.has(record.serviceSlug)) {
      fail(
        `Topic ${group.slug} received ${record.id} from a service outside the category`,
      );
    }
    const key = `${record.serviceSlug}|${record.id}`;
    if (topicRecordKeys.has(key)) {
      fail(`Record appears in more than one topic-route payload: ${key}`);
    }
    topicRecordKeys.add(key);
  }
}

for (const category of catalogCategories) {
  if (!topicContentByCategory.has(category)) {
    fail(`Generated category is absent from topic content: ${category}`);
  }
  const route = getWindowsServiceTopicRoute(category);
  if (!topicRoutes.has(route)) {
    fail(`Generated category is absent from topic routes: ${category}`);
  }
}
for (const topic of windowsServiceTopicContent) {
  if (!catalogCategories.has(topic.category)) {
    fail(`Topic content has no generated catalog category: ${topic.category}`);
  }
}

const catalogRecordKeys = new Set(
  windowsServiceCatalog.vulnerabilities.map(
    (record) => `${record.serviceSlug}|${record.id}`,
  ),
);

for (const record of windowsServiceCatalog.vulnerabilities) {
  const key = `${record.serviceSlug}|${record.id}`;
  if (!catalogServiceSlugs.has(record.serviceSlug)) {
    fail(`Catalog record is orphaned from the service taxonomy: ${key}`);
  }
  if (!targetRecordKeys.has(key)) {
    fail(`Catalog record is orphaned from target routes: ${key}`);
  }
  if (!topicRecordKeys.has(key)) {
    fail(`Catalog record is orphaned from topic routes: ${key}`);
  }
}

if (targetRecordKeys.size !== catalogRecordKeys.size) {
  fail(
    `Target routes cover ${targetRecordKeys.size} record keys; catalog contains ${catalogRecordKeys.size}`,
  );
}
if (topicRecordKeys.size !== catalogRecordKeys.size) {
  fail(
    `Topic routes cover ${topicRecordKeys.size} record keys; catalog contains ${catalogRecordKeys.size}`,
  );
}
if (targetRoutes.size !== windowsServiceCatalog.services.length) {
  fail(
    `Expected ${windowsServiceCatalog.services.length} unique target routes; found ${targetRoutes.size}`,
  );
}
if (topicRoutes.size !== catalogCategories.size) {
  fail(
    `Expected ${catalogCategories.size} unique topic routes; found ${topicRoutes.size}`,
  );
}

if (errors.length > 0) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(
    `Windows service routes valid: ${targetRoutes.size} target pages and ${topicRoutes.size} topic pages cover all ${catalogRecordKeys.size} service/record mappings.`,
  );
  console.log(
    `Route shells present: ${existingFiles.filter(Boolean).length}/${requiredFiles.length}; root and localized variants share canonical lookup data.`,
  );
}
