import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { siteConfig } from "../config/site.config";

export const prerender = true;

export const GET: APIRoute = async () => {
  const base = siteConfig.url.replace(/\/$/, "");
  const posts = (await getCollection("blog"))
    .filter((post) => post.data.locale === "en" && !post.data.draft)
    .sort((a, b) => b.data.publishDate.getTime() - a.data.publishDate.getTime());
  const links = posts
    .map((post) => `- [${post.data.title}](${base}/blog/${post.id}): ${post.data.description}`)
    .join("\n");

  return new Response(`# ${siteConfig.name}\n\n> ${siteConfig.description}\n\n## Writeups\n\n${links}\n`, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
};
