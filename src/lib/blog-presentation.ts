export type BlogFormat = "article" | "interactive-atlas";

export interface ReadingStats {
  words: number;
  minutes: number;
}

export const BLOG_FORMAT_LABELS: Readonly<Record<BlogFormat, string>> = {
  article: "Article",
  "interactive-atlas": "Interactive atlas",
};

export function getBlogFormatLabel(format: BlogFormat): string {
  return BLOG_FORMAT_LABELS[format];
}

/**
 * Reading time is meaningful for prose articles, but not for MDX pages whose
 * substantive content and interactions are rendered by imported components.
 */
export function getBlogReadingStats(
  body: string,
  format: BlogFormat,
): ReadingStats | null {
  if (format === "interactive-atlas") return null;

  const readableText = body
    .replace(/^import\s.+$/gm, " ")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[^\p{L}\p{N}'’-]+/gu, " ")
    .trim();
  const words = readableText ? readableText.split(/\s+/u).length : 0;

  return {
    words,
    minutes: Math.max(1, Math.ceil(words / 200)),
  };
}
