import type { APIRoute } from "astro";
import catalog from "../../../../data/windows-service-vulnerabilities.generated.json";
import { getWindowsServiceTargetRoute } from "../../../../lib/windows-service-catalog";
import { canonicalUrl } from "../../../../lib/seo";
import { SITE_CONFIG } from "../../../../lib/site-config";

export function getStaticPaths() {
  return catalog.services.map((service) => ({
    params: { service: service.slug },
  }));
}

export const GET: APIRoute = ({ params }) => {
  const service = catalog.services.find(
    (entry) => entry.slug === params.service,
  );
  if (!service) return new Response("Not found", { status: 404 });
  const vulnerabilities = catalog.vulnerabilities.filter(
    (entry) => entry.serviceSlug === service.slug,
  );
  const pageCanonicalUrl = canonicalUrl(
    "en",
    getWindowsServiceTargetRoute(service.slug),
  );
  const selfUrl = new URL(
    `/data/windows-service-vulnerabilities/targets/${service.slug}.json`,
    SITE_CONFIG.url,
  ).href;
  return Response.json({
    schemaVersion: 1,
    canonicalUrl: pageCanonicalUrl,
    selfUrl,
    meta: {
      snapshotDate: catalog.meta.snapshotDate,
      service: service.slug,
      recordCount: vulnerabilities.length,
      knownExploitedCount: vulnerabilities.filter((entry) => entry.exploited)
        .length,
      publicPocCount: vulnerabilities.filter(
        (entry) => entry.poc.status !== "none-located",
      ).length,
    },
    service,
    vulnerabilities,
  });
};
