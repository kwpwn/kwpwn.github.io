import { readFile } from "node:fs/promises";
import { WINDOWS_SERVICES } from "./windows-service-taxonomy.mjs";

const catalog = JSON.parse(
  await readFile(
    "src/data/windows-service-vulnerabilities.generated.json",
    "utf8",
  ),
);
const audit = JSON.parse(
  await readFile("system/research/windows-service-catalog-audit.json", "utf8"),
);
const errors = [];
const fail = (message) => errors.push(message);
const serviceSlugs = new Set(catalog.services.map((entry) => entry.slug));
const taxonomySlugs = new Set(WINDOWS_SERVICES.map((entry) => entry.slug));
const recordKeys = new Set();
const cves = new Set();

if (!/^\d{4}-\d{2}-\d{2}$/.test(catalog.meta.snapshotDate)) {
  fail(`Invalid snapshot date: ${catalog.meta.snapshotDate}`);
}
if (catalog.meta.microsoftCnaRecordCount < catalog.meta.uniqueCveCount) {
  fail("Microsoft source census is smaller than the included CVE count");
}
if (catalog.meta.serviceCount !== catalog.services.length) {
  fail("Service count does not match the service array");
}
if (catalog.meta.vulnerabilityCount !== catalog.vulnerabilities.length) {
  fail("Vulnerability count does not match the record array");
}

for (const service of catalog.services) {
  if (!taxonomySlugs.has(service.slug))
    fail(`Unknown service taxonomy slug: ${service.slug}`);
  if (service.description.length < 60)
    fail(`Service description is too short: ${service.name}`);
  if (!service.category || !service.kind || !service.exposure)
    fail(`Incomplete service metadata: ${service.name}`);
  const actual = catalog.vulnerabilities.filter(
    (record) => record.serviceSlug === service.slug,
  ).length;
  if (actual !== service.vulnerabilityCount)
    fail(
      `Incorrect vulnerability count for ${service.name}: ${service.vulnerabilityCount} vs ${actual}`,
    );
}

for (const record of catalog.vulnerabilities) {
  const key = `${record.serviceSlug}|${record.id}`;
  if (recordKeys.has(key)) fail(`Duplicate service/CVE record: ${key}`);
  recordKeys.add(key);
  if (/^CVE-/i.test(record.id)) cves.add(record.id);
  if (!/^(?:CVE-\d{4}-\d{4,}|ADV\d{6})$/i.test(record.id))
    fail(`Invalid security record id: ${record.id}`);
  if (
    record.recordType !==
    (/^CVE-/i.test(record.id) ? "cve" : "security-advisory")
  )
    fail(`Inconsistent security record type: ${record.id}`);
  if (!serviceSlugs.has(record.serviceSlug))
    fail(`Record maps to a missing service: ${key}`);
  if (!record.title || !record.bugClass || !record.impactExplanation)
    fail(`Incomplete analysis fields: ${key}`);
  if (!record.disclosed) fail(`Missing disclosure date: ${key}`);
  if (!Array.isArray(record.affectedProducts))
    fail(`Invalid affected-product matrix: ${key}`);
  if (
    record.affectedProducts.length === 0 &&
    record.versionDataStatus !== "not-published"
  )
    fail(`Missing affected-version status: ${key}`);
  if (
    record.affectedProducts.length > 0 &&
    record.versionDataStatus !== "published"
  )
    fail(`Inconsistent affected-version status: ${key}`);
  if (
    record.affectedProducts.length > 0 &&
    record.affectedProducts.every((product) =>
      /(?:\bMac\b|\bLinux\b|\bAndroid\b|\bIoT\b)/i.test(product),
    )
  )
    fail(`Out-of-scope non-Windows product matrix: ${key}`);
  if (!record.sources?.msrc?.startsWith("https://msrc.microsoft.com/"))
    fail(`Missing MSRC source: ${key}`);
  if (
    record.recordType === "cve" &&
    !record.sources?.cve?.startsWith("https://www.cve.org/")
  )
    fail(`Missing CVE source: ${key}`);
  if (record.recordType === "security-advisory" && record.sources?.cve)
    fail(`Advisory has an invalid CVE source: ${key}`);
  if (record.exploited && record.zeroDayStatus === "not-reported")
    fail(`Inconsistent exploitation state: ${key}`);
  if (record.poc.status === "none-located" && record.poc.url)
    fail(`No-PoC record has a URL: ${key}`);
  if (
    record.poc.status !== "none-located" &&
    !record.poc.url?.startsWith("https://")
  )
    fail(`PoC status lacks an HTTPS URL: ${key}`);
}

if (
  catalog.meta.uniqueCveCount !==
  catalog.vulnerabilities.filter((record) => record.recordType === "cve").length
)
  fail("Unique CVE count does not match CVE records");
if (
  catalog.meta.advisoryCount !==
  catalog.vulnerabilities.filter(
    (record) => record.recordType === "security-advisory",
  ).length
)
  fail("Advisory count does not match advisory records");
if (audit.microsoftCnaRecordCount !== catalog.meta.microsoftCnaRecordCount)
  fail("Audit census does not match catalog census");
if (
  !Array.isArray(audit.unmatchedSignalTitles) ||
  !Array.isArray(audit.excludedSignalTitles)
)
  fail("Audit decision ledgers are missing");
if (audit.unmatchedSignalTitles.length > 0) {
  fail(
    `${audit.unmatchedSignalTitles.length} Microsoft service-signal titles remain unclassified`,
  );
}

if (errors.length) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(
    `Windows service catalog valid: ${catalog.services.length} service families, ${catalog.vulnerabilities.length} security records, ${cves.size} unique CVEs, ${catalog.meta.advisoryCount} advisories, ${catalog.meta.knownExploitedCount} known exploited, and ${catalog.meta.publicPocCount} PoC leads.`,
  );
  console.log(
    `Scope audit: ${audit.excludedSignalTitles.length} explicit title exclusions, ${audit.recordsOutsideProductScope?.length ?? 0} product-matrix exclusions, ${audit.recordsWithoutProductMatrix?.length ?? 0} transparently retained records without a published product matrix, and zero unclassified service-signal titles.`,
  );
}
