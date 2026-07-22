import {
  windowsServiceTopicByCategory,
  windowsServiceTopicBySlug,
  windowsServiceTopicContent,
  type WindowsServiceTopicContent,
} from "../data/windows-service-topic-content.ts";
import catalogData from "../data/windows-service-vulnerabilities.generated.json" with { type: "json" };

export {
  windowsServiceTopicByCategory,
  windowsServiceTopicBySlug,
  windowsServiceTopicContent,
};

export type WindowsServiceCategory =
  | "Identity & directory"
  | "Network services"
  | "Remote access"
  | "File & print services"
  | "Web & messaging"
  | "IPC & management"
  | "Deployment & maintenance"
  | "System services"
  | "Storage & devices"
  | "Security services"
  | "Discovery services"
  | "Virtualization & containers";

export type WindowsServiceKind =
  | "server-role"
  | "service-protocol"
  | "scm-service"
  | "service-hosted-component"
  | "service-client"
  | "service-substrate";

export type WindowsServiceRecordType = "cve" | "security-advisory";

export type WindowsServicePocStatus =
  "none-located" | "indexed-unverified" | "credible-reproducer";

export type WindowsServiceZeroDayStatus =
  | "not-reported"
  | "exploitation-detected-timing-unconfirmed"
  | "public-before-or-at-fix"
  | "exploited-and-publicly-disclosed"
  | "known-exploited-timing-unconfirmed";

export interface WindowsServiceKbArticle {
  readonly id: string;
  readonly url: string;
  readonly fixedBuild: string | null;
}

export interface WindowsServicePoc {
  readonly status: WindowsServicePocStatus;
  readonly url: string | null;
  readonly repository: string | null;
  readonly starsAtSnapshot?: number;
}

export interface WindowsServiceKevEntry {
  readonly dateAdded: string;
  readonly requiredAction: string;
  readonly dueDate: string;
  readonly ransomwareUse: string;
}

export interface WindowsServiceVulnerability {
  readonly id: string;
  readonly serviceSlug: string;
  readonly title: string;
  readonly disclosed: string;
  readonly severity: string;
  readonly impact: string;
  readonly cvss: number | null;
  readonly vector: string | null;
  readonly cwe: readonly string[];
  readonly bugClass: string;
  readonly impactExplanation: string;
  readonly publiclyDisclosed: boolean;
  readonly exploited: boolean;
  readonly zeroDayStatus: WindowsServiceZeroDayStatus;
  readonly affectedProducts: readonly string[];
  readonly fixedBuilds: readonly string[];
  readonly kbArticles: readonly WindowsServiceKbArticle[];
  readonly poc: WindowsServicePoc;
  readonly sources: {
    readonly msrc: string;
    readonly cve: string | null;
    readonly kev: string | null;
    readonly pocIndex: string | null;
  };
  readonly kev: WindowsServiceKevEntry | null;
  readonly versionDataStatus?: "published" | "not-published";
  readonly recordType: WindowsServiceRecordType;
}

export interface WindowsServiceTarget {
  readonly slug: string;
  readonly name: string;
  readonly category: WindowsServiceCategory;
  readonly kind: WindowsServiceKind;
  readonly exposure: string;
  readonly description: string;
  readonly scmNames: readonly string[];
  readonly vulnerabilityCount: number;
}

export interface WindowsServiceCatalogMeta {
  readonly title: string;
  readonly snapshotDate: string;
  readonly sourceUrl: string;
  readonly sourceGuideUrl: string;
  readonly definition: string;
  readonly exclusions: string;
  readonly generatedAt: string;
  readonly msrcRecordCount: number;
  readonly microsoftCnaRecordCount: number;
  readonly serviceCount: number;
  readonly vulnerabilityCount: number;
  readonly uniqueCveCount: number;
  readonly advisoryCount: number;
  readonly knownExploitedCount: number;
  readonly publicPocCount: number;
  readonly methodology: readonly string[];
}

export interface WindowsServiceCatalog {
  readonly meta: WindowsServiceCatalogMeta;
  readonly services: readonly WindowsServiceTarget[];
  readonly vulnerabilities: readonly WindowsServiceVulnerability[];
}

export interface WindowsServiceKindTheory {
  readonly label: string;
  readonly explanation: string;
  readonly primaryBoundary: string;
}

export const WINDOWS_SERVICE_KIND_THEORY: Readonly<
  Record<WindowsServiceKind, WindowsServiceKindTheory>
> = {
  "server-role": {
    label: "Server role",
    explanation:
      "A deployable Windows Server capability composed of multiple services, protocols, policy stores, and management interfaces.",
    primaryBoundary:
      "Reason about both the externally reachable role and the privileged management plane that configures it.",
  },
  "service-protocol": {
    label: "Service protocol",
    explanation:
      "A protocol implementation that may be shared by clients, listeners, libraries, and several hosting processes.",
    primaryBoundary:
      "Identify which endpoint and process parses each message before assigning exploit prerequisites or impact.",
  },
  "scm-service": {
    label: "SCM service",
    explanation:
      "A concrete Service Control Manager registration with a service identity, configuration, start policy, and one or more control surfaces.",
    primaryBoundary:
      "Inspect service ACLs, binary and dependency paths, named endpoints, impersonation, and privileged side effects.",
  },
  "service-hosted-component": {
    label: "Service-hosted component",
    explanation:
      "A subsystem or library executing inside a service host, often sharing a process and token with other components.",
    primaryBoundary:
      "Map the component's caller and data path without assuming the vulnerability is reachable through every host configuration.",
  },
  "service-client": {
    label: "Service client",
    explanation:
      "A Windows client component that consumes remote service content and may parse it under a user or system context.",
    primaryBoundary:
      "Account for content origin, user interaction, authentication relay, and the authority of the consuming process.",
  },
  "service-substrate": {
    label: "Service substrate",
    explanation:
      "Shared infrastructure used to host, dispatch, isolate, or manage many services rather than one product endpoint.",
    primaryBoundary:
      "A substrate flaw can multiply reachability; validate the specific consumer, hosting model, and system configuration.",
  },
};

export interface WindowsServiceMetrics {
  readonly recordCount: number;
  readonly uniqueRecordCount: number;
  readonly cveCount: number;
  readonly advisoryCount: number;
  readonly knownExploitedCount: number;
  readonly publicDisclosureCount: number;
  readonly publicPocCount: number;
  readonly latestDisclosure: string | null;
  readonly severityCounts: Readonly<Record<string, number>>;
  readonly impactCounts: Readonly<Record<string, number>>;
}

export interface WindowsServiceCategoryGroup {
  readonly slug: string;
  readonly category: WindowsServiceCategory;
  readonly theory: WindowsServiceTopicContent;
  readonly services: readonly WindowsServiceTarget[];
  readonly records: readonly WindowsServiceVulnerability[];
  readonly metrics: WindowsServiceMetrics;
}

/** Read-only view over the generated artifact. No consumer-side data is added. */
export const windowsServiceCatalog =
  catalogData as unknown as WindowsServiceCatalog;

function fallbackSlugify(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/&/g, " and ")
    .replace(/[’']/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Resolves a category name to its editorially stable topic slug. Unknown labels
 * receive a deterministic fallback slug, so callers can use one function for
 * both known catalog values and future taxonomy additions.
 */
export function slugifyWindowsServiceTopic(value: string): string {
  return (
    windowsServiceTopicByCategory.get(value)?.slug ??
    windowsServiceTopicBySlug.get(value)?.slug ??
    fallbackSlugify(value)
  );
}

export const WINDOWS_SERVICE_ROUTE_SCHEMA = {
  index: "/windows-service-vulnerabilities/",
  targetPrefix: "/windows-service-vulnerabilities/targets/",
  topicPrefix: "/windows-service-vulnerabilities/topics/",
  targetParam: "service",
  topicParam: "topic",
} as const;

function localizedPath(path: string, locale?: string): string {
  if (!locale || locale === "en") return path;
  return `/${locale}${path}`;
}

export function getWindowsServiceTargetRoute(
  serviceOrSlug: WindowsServiceTarget | string,
  locale?: string,
): string {
  const slug =
    typeof serviceOrSlug === "string" ? serviceOrSlug : serviceOrSlug.slug;
  return localizedPath(
    `${WINDOWS_SERVICE_ROUTE_SCHEMA.targetPrefix}${slug}/`,
    locale,
  );
}

export function getWindowsServiceTopicRoute(
  categoryOrSlug: WindowsServiceCategory | string,
  locale?: string,
): string {
  const topicSlug = slugifyWindowsServiceTopic(categoryOrSlug);
  return localizedPath(
    `${WINDOWS_SERVICE_ROUTE_SCHEMA.topicPrefix}${topicSlug}/`,
    locale,
  );
}

export function aggregateWindowsServiceRecords(
  records: readonly WindowsServiceVulnerability[],
): WindowsServiceMetrics {
  const recordIds = new Set<string>();
  const cveIds = new Set<string>();
  const advisoryIds = new Set<string>();
  const severityCounts: Record<string, number> = {};
  const impactCounts: Record<string, number> = {};
  let knownExploitedCount = 0;
  let publicDisclosureCount = 0;
  let publicPocCount = 0;
  let latestDisclosure: string | null = null;

  for (const record of records) {
    recordIds.add(record.id);
    if (record.recordType === "cve") cveIds.add(record.id);
    else advisoryIds.add(record.id);
    if (record.exploited) knownExploitedCount += 1;
    if (record.publiclyDisclosed) publicDisclosureCount += 1;
    if (record.poc.status !== "none-located") publicPocCount += 1;
    if (!latestDisclosure || record.disclosed > latestDisclosure) {
      latestDisclosure = record.disclosed;
    }
    severityCounts[record.severity] =
      (severityCounts[record.severity] ?? 0) + 1;
    impactCounts[record.impact] = (impactCounts[record.impact] ?? 0) + 1;
  }

  return Object.freeze({
    recordCount: records.length,
    uniqueRecordCount: recordIds.size,
    cveCount: cveIds.size,
    advisoryCount: advisoryIds.size,
    knownExploitedCount,
    publicDisclosureCount,
    publicPocCount,
    latestDisclosure,
    severityCounts: Object.freeze(severityCounts),
    impactCounts: Object.freeze(impactCounts),
  });
}

const serviceBySlug: ReadonlyMap<string, WindowsServiceTarget> = new Map(
  windowsServiceCatalog.services.map((service) => [service.slug, service]),
);

const recordsByService = new Map<string, WindowsServiceVulnerability[]>();
const recordsById = new Map<string, WindowsServiceVulnerability[]>();

for (const record of windowsServiceCatalog.vulnerabilities) {
  const serviceRecords = recordsByService.get(record.serviceSlug) ?? [];
  serviceRecords.push(record);
  recordsByService.set(record.serviceSlug, serviceRecords);

  const matchingIdRecords = recordsById.get(record.id) ?? [];
  matchingIdRecords.push(record);
  recordsById.set(record.id, matchingIdRecords);
}

const categoryGroups: readonly WindowsServiceCategoryGroup[] =
  windowsServiceTopicContent.map((theory) => {
    const category = theory.category as WindowsServiceCategory;
    const services = windowsServiceCatalog.services.filter(
      (service) => service.category === category,
    );
    const serviceSlugs = new Set(services.map((service) => service.slug));
    const records = windowsServiceCatalog.vulnerabilities.filter((record) =>
      serviceSlugs.has(record.serviceSlug),
    );

    return Object.freeze({
      slug: theory.slug,
      category,
      theory,
      services: Object.freeze(services),
      records: Object.freeze(records),
      metrics: aggregateWindowsServiceRecords(records),
    });
  });

const categoryBySlug: ReadonlyMap<string, WindowsServiceCategoryGroup> =
  new Map(categoryGroups.map((group) => [group.slug, group]));

export const windowsServiceCategoryGroups = Object.freeze(categoryGroups);

export function getWindowsServiceBySlug(
  slug: string,
): WindowsServiceTarget | undefined {
  return serviceBySlug.get(slug);
}

export function getWindowsServiceCategoryBySlug(
  slug: string,
): WindowsServiceCategoryGroup | undefined {
  return categoryBySlug.get(slug);
}

export function getWindowsServiceRecords(
  serviceOrSlug: WindowsServiceTarget | string,
): readonly WindowsServiceVulnerability[] {
  const slug =
    typeof serviceOrSlug === "string" ? serviceOrSlug : serviceOrSlug.slug;
  return Object.freeze([...(recordsByService.get(slug) ?? [])]);
}

export function getWindowsServiceRecordsById(
  id: string,
): readonly WindowsServiceVulnerability[] {
  return Object.freeze([...(recordsById.get(id.toUpperCase()) ?? [])]);
}

export function getWindowsServiceMetrics(
  serviceOrSlug: WindowsServiceTarget | string,
): WindowsServiceMetrics {
  return aggregateWindowsServiceRecords(
    getWindowsServiceRecords(serviceOrSlug),
  );
}

export function getWindowsServiceTopicMetrics(
  categoryOrSlug: WindowsServiceCategory | string,
): WindowsServiceMetrics | undefined {
  return categoryBySlug.get(slugifyWindowsServiceTopic(categoryOrSlug))
    ?.metrics;
}

export function getWindowsServiceKindTheory(
  serviceOrKind: WindowsServiceTarget | WindowsServiceKind,
): WindowsServiceKindTheory {
  const kind =
    typeof serviceOrKind === "string" ? serviceOrKind : serviceOrKind.kind;
  return WINDOWS_SERVICE_KIND_THEORY[kind];
}

/** Builds a complete, search-result-sized description for a target dossier. */
export function getWindowsServiceTargetMetaDescription(
  service: Pick<WindowsServiceTarget, "name" | "vulnerabilityCount">,
): string {
  const recordLabel = service.vulnerabilityCount === 1 ? "record" : "records";
  let description = `${service.name}: ${service.vulnerabilityCount} mapped security ${recordLabel} covering vulnerability classes, affected versions, fixes, exploitation evidence, audit guidance, and public PoCs.`;

  if (description.length > 170) {
    description = `${service.name}: ${service.vulnerabilityCount} mapped security ${recordLabel} covering bug classes, affected versions, fixes, exploitation evidence, audit guidance, and PoCs.`;
  }
  if (description.length < 150) {
    description = `${description.slice(0, -1)} for triage.`;
  }

  return description;
}

/** Builds a complete, search-result-sized description for a topic dossier. */
export function getWindowsServiceTopicMetaDescription(
  category: string,
  targetCount: number,
  recordCount: number,
): string {
  const targetLabel = targetCount === 1 ? "target" : "targets";
  const recordLabel = recordCount === 1 ? "record" : "records";
  const description = `${category} research across ${targetCount} Windows ${targetLabel} and ${recordCount} evidence-backed ${recordLabel}, with trust boundaries, weakness patterns, audit questions, and lab workflows.`;

  return description.length > 170
    ? description.replace("lab workflows", "lab work")
    : description;
}
