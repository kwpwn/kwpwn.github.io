import { getCollection, type CollectionEntry } from "astro:content";
import type { APIRoute } from "astro";
import {
  getBlogFormatLabel,
  getBlogReadingStats,
} from "../../lib/blog-presentation";
import { SITE_CONFIG } from "../../lib/site-config";

export const prerender = true;

function comparePosts(a: CollectionEntry<"blog">, b: CollectionEntry<"blog">) {
  return (
    b.data.publishDate.getTime() - a.data.publishDate.getTime() ||
    a.id.localeCompare(b.id, "en")
  );
}

export const GET: APIRoute = async () => {
  const now = Date.now();
  const collection: CollectionEntry<"blog">[] = await getCollection("blog");
  const posts = collection
    .filter(
      (post) =>
        post.data.locale === SITE_CONFIG.defaultLocale &&
        !post.data.draft &&
        post.data.publishDate.getTime() <= now,
    )
    .sort(comparePosts)
    .map((post) => ({
      id: post.id,
      slug: post.id,
      url: `/blog/${post.id}/`,
      title: post.data.title,
      description: post.data.description,
      locale: post.data.locale,
      publishedAt: post.data.publishDate.toISOString(),
      updatedAt: post.data.updatedAt?.toISOString() ?? null,
      author: post.data.author,
      tags: [...post.data.tags].sort((a, b) =>
        a.localeCompare(b, "en", { sensitivity: "base" }),
      ),
      featured: post.data.featured,
      format: post.data.format,
      formatLabel: getBlogFormatLabel(post.data.format),
      reading: getBlogReadingStats(post.body ?? "", post.data.format),
    }));
  const tags = [...new Set(posts.flatMap((post) => post.tags))].sort((a, b) =>
    a.localeCompare(b, "en", { sensitivity: "base" }),
  );
  const years = [
    ...new Set(posts.map((post) => Number(post.publishedAt.slice(0, 4)))),
  ].sort((a, b) => b - a);
  const payload = {
    schemaVersion: 1,
    locale: SITE_CONFIG.defaultLocale,
    count: posts.length,
    filters: { tags, years },
    posts,
  };

  return new Response(`${JSON.stringify(payload, null, 2)}\n`, {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
      "X-Content-Type-Options": "nosniff",
    },
  });
};
