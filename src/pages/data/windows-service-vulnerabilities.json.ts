import type { APIRoute } from "astro";
import catalog from "../../data/windows-service-vulnerabilities.generated.json";

export const prerender = true;

export const GET: APIRoute = () =>
  new Response(JSON.stringify(catalog), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
      "X-Content-Type-Options": "nosniff",
    },
  });
