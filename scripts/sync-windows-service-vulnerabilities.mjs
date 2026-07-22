import { mkdir, readFile, writeFile } from "node:fs/promises";
import {
  EXCLUDED_PRODUCT_PATTERNS,
  SERVICE_SIGNAL_PATTERN,
  WINDOWS_SERVICES,
  WINDOWS_SERVICE_SCOPE,
  compileServicePatterns,
} from "./windows-service-taxonomy.mjs";

const OUT = "src/data/windows-service-vulnerabilities.generated.json";
const AUDIT_OUT = "system/research/windows-service-catalog-audit.json";
const API = `${WINDOWS_SERVICE_SCOPE.sourceUrl}?$filter=${encodeURIComponent("issuingCna eq 'Microsoft'")}`;
const AFFECTED_API =
  "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct";
const POC_BASE =
  "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master";
const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const snapshotDate = new Intl.DateTimeFormat("en-CA", {
  timeZone: "Asia/Bangkok",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
}).format(new Date());
const reuseExisting = process.argv.includes("--reuse-existing");

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function fetchJson(url, { optional = false, attempts = 4 } = {}) {
  let error;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, {
        headers: { "User-Agent": "kwpwn-windows-service-atlas/1.0" },
      });
      if (optional && response.status === 404) return null;
      if (!response.ok)
        throw new Error(`${response.status} ${response.statusText}`);
      return await response.json();
    } catch (currentError) {
      error = currentError;
      if (attempt < attempts) await sleep(attempt * 500);
    }
  }
  throw new Error(`Failed to fetch ${url}: ${error}`);
}

async function fetchPaged(url) {
  const values = [];
  let next = url;
  while (next) {
    const page = await fetchJson(next);
    values.push(...(page.value ?? []));
    next = page["@odata.nextLink"];
    process.stdout.write(
      `\rFetched ${values.length.toLocaleString()} MSRC records`,
    );
  }
  process.stdout.write("\n");
  return values;
}

const compiledServices = WINDOWS_SERVICES.map((entry) => ({
  ...entry,
  compiledPatterns: compileServicePatterns(entry),
}));

function classify(title) {
  return compiledServices.find((entry) =>
    entry.compiledPatterns.some((pattern) => pattern.test(title)),
  );
}

function isExcluded(title) {
  return EXCLUDED_PRODUCT_PATTERNS.some((pattern) => pattern.test(title));
}

function inferBugClass(record) {
  const title = record.cveTitle ?? "";
  const cwes = [...(record.cweList ?? []), ...(record.cweDetailsList ?? [])]
    .map((value) =>
      typeof value === "string"
        ? value
        : (value?.name ?? value?.description ?? ""),
    )
    .filter(Boolean);
  if (cwes.length) return [...new Set(cwes)].join("; ");
  const rules = [
    [/use.after.free|\bUAF\b/i, "Use-after-free / lifetime error"],
    [/type confusion/i, "Type confusion"],
    [/race condition|time.of.check|TOCTOU/i, "Race condition / TOCTOU"],
    [
      /buffer overflow|heap overflow|stack overflow|out.of.bounds write/i,
      "Out-of-bounds write / buffer overflow",
    ],
    [/out.of.bounds read/i, "Out-of-bounds read"],
    [/integer overflow|integer underflow/i, "Integer overflow or underflow"],
    [/authentication bypass/i, "Authentication bypass"],
    [/security feature bypass/i, "Security control bypass"],
    [/spoofing/i, "Identity or trust validation failure"],
    [
      /information disclosure/i,
      "Information disclosure / insufficient data protection",
    ],
    [/denial of service/i, "Availability failure"],
    [
      /remote code execution/i,
      "Memory-safety or input-validation defect enabling code execution",
    ],
    [
      /elevation of privilege/i,
      "Authorization, identity, or memory-safety defect enabling elevation",
    ],
  ];
  return (
    rules.find(([pattern]) => pattern.test(title))?.[1] ??
    "MSRC did not publish a CWE; root cause requires patch or advisory analysis"
  );
}

function toBoolean(value) {
  if (value === true || value === 1) return true;
  if (typeof value !== "string") return false;
  return ["yes", "true", "1", "exploited", "public"].includes(
    value.trim().toLowerCase(),
  );
}

function explainImpact(record, serviceName) {
  const impact = record.impact || "Security boundary violation";
  const map = {
    "Remote Code Execution": `Successful exploitation can execute attacker-controlled code in the ${serviceName} trust context. Reachability and resulting privilege depend on the affected endpoint and deployment.`,
    "Elevation of Privilege": `Successful exploitation can cross a local or service-side privilege boundary associated with ${serviceName}; the final principal depends on the vulnerable process token and exploit prerequisites.`,
    "Information Disclosure": `Successful exploitation can disclose data available to ${serviceName}, which may include process memory, credentials, addresses, or protocol data depending on the flaw.`,
    "Denial of Service": `Successful exploitation can stop, hang, or destabilize ${serviceName} or its host, affecting service availability and potentially the operating system.`,
    "Security Feature Bypass": `Successful exploitation can bypass a security guarantee enforced by ${serviceName}, but normally requires a second action or vulnerability for full compromise.`,
    Spoofing: `Successful exploitation can make ${serviceName} trust attacker-controlled identity or content, enabling impersonation or follow-on attacks.`,
    Tampering: `Successful exploitation can modify state protected by ${serviceName}, affecting integrity and potentially enabling a stronger follow-on primitive.`,
  };
  return (
    map[impact] ??
    `MSRC classifies the impact as ${impact}. The concrete consequence depends on the endpoint, caller privileges, and affected Windows role.`
  );
}

function summarizeAffectedProducts(products) {
  const included = products;
  const productNames = [
    ...new Set(included.map((item) => item.product).filter(Boolean)),
  ].sort();
  const fixedBuilds = [
    ...new Set(
      included
        .flatMap((item) => item.kbArticles ?? [])
        .map((kb) => kb.fixedBuildNumber)
        .filter(Boolean),
    ),
  ].sort();
  const kbArticles = [];
  const seenKb = new Set();
  for (const kb of included.flatMap((item) => item.kbArticles ?? [])) {
    const key = `${kb.articleName}|${kb.fixedBuildNumber ?? ""}`;
    if (!kb.articleName || seenKb.has(key)) continue;
    seenKb.add(key);
    kbArticles.push({
      id: `KB${String(kb.articleName).replace(/^KB/i, "")}`,
      url: kb.articleUrl || kb.downloadUrl,
      fixedBuild: kb.fixedBuildNumber || null,
    });
  }
  return { productNames, fixedBuilds, kbArticles };
}

async function mapConcurrent(values, concurrency, mapper) {
  const output = new Array(values.length);
  let cursor = 0;
  async function worker() {
    while (cursor < values.length) {
      const index = cursor++;
      output[index] = await mapper(values[index], index);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return output;
}

function choosePoc(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return { status: "none-located", url: null, repository: null };
  }
  const ranked = candidates
    .filter((item) => item?.html_url?.startsWith("https://github.com/"))
    .sort(
      (left, right) =>
        (right.stargazers_count ?? 0) - (left.stargazers_count ?? 0),
    );
  const candidate = ranked[0];
  if (!candidate)
    return { status: "none-located", url: null, repository: null };
  return {
    status: "indexed-unverified",
    url: candidate.html_url,
    repository: candidate.full_name ?? candidate.name ?? null,
    starsAtSnapshot: candidate.stargazers_count ?? null,
  };
}

const curatedPocs = {
  "CVE-2017-0144": {
    status: "credible-reproducer",
    url: "https://github.com/3ndG4me/AutoBlue-MS17-010",
    repository: "3ndG4me/AutoBlue-MS17-010",
  },
  "CVE-2019-0708": {
    status: "credible-reproducer",
    url: "https://github.com/zerosum0x0/CVE-2019-0708",
    repository: "zerosum0x0/CVE-2019-0708",
  },
  "CVE-2020-0796": {
    status: "credible-reproducer",
    url: "https://github.com/chompie1337/SMBGhost_RCE_PoC",
    repository: "chompie1337/SMBGhost_RCE_PoC",
  },
  "CVE-2020-1472": {
    status: "credible-reproducer",
    url: "https://github.com/SecuraBV/CVE-2020-1472",
    repository: "SecuraBV/CVE-2020-1472",
  },
  "CVE-2020-1350": {
    status: "credible-reproducer",
    url: "https://github.com/maxpl0it/CVE-2020-1350-DoS",
    repository: "maxpl0it/CVE-2020-1350-DoS",
  },
  "CVE-2021-1675": {
    status: "credible-reproducer",
    url: "https://github.com/afwu/PrintNightmare",
    repository: "afwu/PrintNightmare",
  },
  "CVE-2021-34527": {
    status: "credible-reproducer",
    url: "https://github.com/ly4k/PrintNightmare",
    repository: "ly4k/PrintNightmare",
  },
};

async function main() {
  const [sourceSummary, allRecords] = await Promise.all([
    fetchJson(WINDOWS_SERVICE_SCOPE.sourceUrl),
    fetchPaged(API),
  ]);
  const excludedSignalTitles = new Set();
  const unmatchedSignalTitles = new Set();
  const included = [];

  for (const record of allRecords) {
    const title = record.cveTitle ?? "";
    const match = classify(title);
    if (match && !isExcluded(title)) {
      included.push({ record, service: match });
    } else if (SERVICE_SIGNAL_PATTERN.test(title)) {
      (isExcluded(title) ? excludedSignalTitles : unmatchedSignalTitles).add(
        title,
      );
    }
  }

  const deduplicated = [
    ...new Map(
      included.map((item) => [
        `${item.service.slug}|${item.record.cveNumber}`,
        item,
      ]),
    ).values(),
  ];
  console.log(
    `Classified ${deduplicated.length.toLocaleString()} service/CVE records across ${new Set(deduplicated.map((item) => item.service.slug)).size} services.`,
  );

  let cachedByCve = new Map();
  if (reuseExisting) {
    try {
      const previous = JSON.parse(await readFile(OUT, "utf8"));
      cachedByCve = new Map(
        previous.vulnerabilities.map((record) => [record.id, record]),
      );
      console.log(
        `Loaded ${cachedByCve.size.toLocaleString()} records from the previous snapshot.`,
      );
    } catch {
      console.log(
        "No reusable service snapshot was found; performing a full sync.",
      );
    }
  }

  let completed = 0;
  const kevFeed = await fetchJson(KEV_URL, { optional: true });
  const kevByCve = new Map(
    (kevFeed?.vulnerabilities ?? []).map((item) => [item.cveID, item]),
  );
  const enrichedCandidates = await mapConcurrent(
    deduplicated,
    10,
    async ({ record, service }) => {
      const cve = record.cveNumber;
      const isCve = /^CVE-\d{4}-\d{4,}$/i.test(cve);
      const cached = cachedByCve.get(cve);
      if (cached?.serviceSlug === service.slug) {
        completed += 1;
        if (completed % 25 === 0 || completed === deduplicated.length) {
          process.stdout.write(
            `\rEnriched ${completed}/${deduplicated.length} records`,
          );
        }
        return {
          ...cached,
          recordType: isCve ? "cve" : "security-advisory",
          versionDataStatus: cached.affectedProducts.length
            ? "published"
            : "not-published",
          poc: isCve
            ? cached.poc
            : { status: "none-located", url: null, repository: null },
          sources: {
            ...cached.sources,
            cve: isCve ? `https://www.cve.org/CVERecord?id=${cve}` : null,
            pocIndex: isCve ? cached.sources.pocIndex : null,
          },
        };
      }
      const filter = encodeURIComponent(`cveNumber eq '${cve}'`);
      const [affectedResponse, pocResponse] = await Promise.all([
        fetchJson(`${AFFECTED_API}?$filter=${filter}`),
        isCve
          ? fetchJson(`${POC_BASE}/${cve.slice(4, 8)}/${cve}.json`, {
              optional: true,
            })
          : null,
      ]);
      completed += 1;
      if (completed % 25 === 0 || completed === deduplicated.length) {
        process.stdout.write(
          `\rEnriched ${completed}/${deduplicated.length} records`,
        );
      }
      const versions = summarizeAffectedProducts(affectedResponse.value ?? []);
      const cwe = [
        ...new Set(
          (record.cweList ?? [])
            .map((item) => (typeof item === "string" ? item : item?.name))
            .filter(Boolean),
        ),
      ];
      const kev = kevByCve.get(cve);
      const publiclyDisclosed = toBoolean(record.publiclyDisclosed);
      const msrcExploited = toBoolean(record.exploited);
      const exploited = msrcExploited || Boolean(kev);
      return {
        id: cve,
        recordType: isCve ? "cve" : "security-advisory",
        serviceSlug: service.slug,
        title: record.cveTitle,
        disclosed: record.releaseDate?.slice(0, 10) ?? null,
        severity: record.severity ?? "Not rated",
        impact: record.impact ?? "Not specified",
        cvss: record.baseScore ? Number(record.baseScore) : null,
        vector: record.vectorString ?? null,
        cwe,
        bugClass: inferBugClass(record),
        impactExplanation: explainImpact(record, service.name),
        publiclyDisclosed,
        exploited,
        zeroDayStatus:
          msrcExploited && publiclyDisclosed
            ? "exploited-and-publicly-disclosed"
            : msrcExploited
              ? "exploitation-detected-timing-unconfirmed"
              : publiclyDisclosed
                ? "public-before-or-at-fix"
                : kev
                  ? "known-exploited-timing-unconfirmed"
                  : "not-reported",
        affectedProducts: versions.productNames,
        versionDataStatus: versions.productNames.length
          ? "published"
          : "not-published",
        fixedBuilds: versions.fixedBuilds,
        kbArticles: versions.kbArticles,
        poc: isCve
          ? (curatedPocs[cve] ?? choosePoc(pocResponse))
          : { status: "none-located", url: null, repository: null },
        sources: {
          msrc: `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`,
          cve: isCve ? `https://www.cve.org/CVERecord?id=${cve}` : null,
          kev: kev
            ? `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve}`
            : null,
          pocIndex:
            isCve && pocResponse
              ? `https://github.com/nomi-sec/PoC-in-GitHub/blob/master/${cve.slice(4, 8)}/${cve}.json`
              : null,
        },
        kev: kev
          ? {
              dateAdded: kev.dateAdded,
              requiredAction: kev.requiredAction,
              dueDate: kev.dueDate,
              ransomwareUse: kev.knownRansomwareCampaignUse,
            }
          : null,
      };
    },
  );
  process.stdout.write("\n");
  const recordsOutsideProductScope = enrichedCandidates.filter(
    (record) =>
      record.affectedProducts.length > 0 &&
      record.affectedProducts.every((product) =>
        /(?:\bMac\b|\bLinux\b|\bAndroid\b|\bIoT\b)/i.test(product),
      ),
  );
  const outsideProductScopeIds = new Set(
    recordsOutsideProductScope.map((record) => record.id),
  );
  const enriched = enrichedCandidates.filter(
    (record) => !outsideProductScopeIds.has(record.id),
  );
  const recordsWithoutProductMatrix = enriched.filter(
    (record) => record.versionDataStatus === "not-published",
  );
  if (recordsWithoutProductMatrix.length) {
    console.log(
      `Retained ${recordsWithoutProductMatrix.length} records with an explicit unpublished product-matrix status.`,
    );
  }

  const services = WINDOWS_SERVICES.map(({ patterns, ...entry }) => ({
    ...entry,
    vulnerabilityCount: enriched.filter(
      (record) => record.serviceSlug === entry.slug,
    ).length,
  })).filter((entry) => entry.vulnerabilityCount > 0);

  const payload = {
    meta: {
      ...WINDOWS_SERVICE_SCOPE,
      snapshotDate,
      generatedAt: new Date().toISOString(),
      msrcRecordCount: sourceSummary["@odata.count"] ?? allRecords.length,
      microsoftCnaRecordCount: allRecords.length,
      serviceCount: services.length,
      vulnerabilityCount: enriched.length,
      uniqueCveCount: enriched.filter((record) => record.recordType === "cve")
        .length,
      advisoryCount: enriched.filter(
        (record) => record.recordType === "security-advisory",
      ).length,
      knownExploitedCount: enriched.filter((record) => record.exploited).length,
      publicPocCount: enriched.filter(
        (record) => record.poc.status !== "none-located",
      ).length,
      methodology: [
        "CVE identity, title, severity, impact, disclosure, exploitation, CVSS, CWE, affected products, KBs, and fixed builds are sourced from the Microsoft Security Update Guide OData feed.",
        "CISA Known Exploited Vulnerabilities is used as a second authoritative exploitation signal.",
        "PoC-in-GitHub is used only as discovery metadata. Indexed repositories are explicitly unverified unless promoted through a curated primary or credible reproducer override.",
        "No public PoC located means none was found in the indexed source at snapshot time; it is not proof that private exploit code does not exist.",
      ],
    },
    services,
    vulnerabilities: enriched.sort(
      (left, right) =>
        (right.disclosed ?? "").localeCompare(left.disclosed ?? "") ||
        left.id.localeCompare(right.id),
    ),
  };

  await mkdir("src/data", { recursive: true });
  await mkdir("system/research", { recursive: true });
  await writeFile(OUT, `${JSON.stringify(payload, null, 2)}\n`);
  await writeFile(
    AUDIT_OUT,
    `${JSON.stringify(
      {
        snapshotDate,
        msrcRecordCount: sourceSummary["@odata.count"] ?? allRecords.length,
        microsoftCnaRecordCount: allRecords.length,
        includedServiceCveRecords: enriched.length,
        excludedSignalTitles: [...excludedSignalTitles].sort(),
        unmatchedSignalTitles: [...unmatchedSignalTitles].sort(),
        recordsWithoutProductMatrix: recordsWithoutProductMatrix.map(
          ({ id, title, serviceSlug }) => ({ id, title, serviceSlug }),
        ),
        recordsOutsideProductScope: recordsOutsideProductScope.map(
          ({ id, title, serviceSlug, affectedProducts }) => ({
            id,
            title,
            serviceSlug,
            affectedProducts,
          }),
        ),
      },
      null,
      2,
    )}\n`,
  );
  console.log(`Wrote ${OUT} and ${AUDIT_OUT}.`);
}

await main();
