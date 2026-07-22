import type { APIRoute } from "astro";
import { windowsServiceTopicBySlug } from "../../../../data/windows-service-topic-content";
import catalog from "../../../../data/windows-service-vulnerabilities.generated.json";
import { getWindowsServiceTopicRoute } from "../../../../lib/windows-service-catalog";
import { canonicalUrl } from "../../../../lib/seo";
import { SITE_CONFIG } from "../../../../lib/site-config";

export function getStaticPaths() {
  return [...windowsServiceTopicBySlug.keys()].map((topic) => ({
    params: { topic },
  }));
}

export const GET: APIRoute = ({ params }) => {
  const topic = windowsServiceTopicBySlug.get(params.topic ?? "");
  if (!topic) return new Response("Not found", { status: 404 });
  const services = catalog.services.filter(
    (service) => service.category === topic.category,
  );
  const serviceSlugs = new Set(services.map((service) => service.slug));
  const vulnerabilities = catalog.vulnerabilities.filter((entry) =>
    serviceSlugs.has(entry.serviceSlug),
  );
  const pageCanonicalUrl = canonicalUrl(
    "en",
    getWindowsServiceTopicRoute(topic.slug),
  );
  const selfUrl = new URL(
    `/data/windows-service-vulnerabilities/topics/${topic.slug}.json`,
    SITE_CONFIG.url,
  ).href;
  return Response.json({
    schemaVersion: 1,
    canonicalUrl: pageCanonicalUrl,
    selfUrl,
    meta: {
      snapshotDate: catalog.meta.snapshotDate,
      topic: topic.slug,
      category: topic.category,
      serviceCount: services.length,
      recordCount: vulnerabilities.length,
      knownExploitedCount: vulnerabilities.filter((entry) => entry.exploited)
        .length,
      publicPocCount: vulnerabilities.filter(
        (entry) => entry.poc.status !== "none-located",
      ).length,
    },
    theory: topic,
    services,
    vulnerabilities,
  });
};
