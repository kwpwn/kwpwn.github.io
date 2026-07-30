import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

// Add locale codes here (e.g. ["en", "id"]) when introducing new languages.
const localeSchema = z.enum(["en"]);

const researchTopicSchema = z.enum([
  "windows-privesc",
  "malware-c2",
  "windows-internals",
]);

const researchTrackSchema = z.enum([
  "foundations",
  "discovery-evidence",
  "service-boundaries",
  "execution-persistence",
  "token-ipc",
  "credentials-recovery",
  "policy-controls",
  "lateral-boundaries",
  "static-analysis",
  "dynamic-analysis",
  "memory-execution",
  "c2-operations",
  "detection-engineering",
  "boot-architecture",
  "processes-execution",
  "memory-manager",
  "security-objects",
  "io-drivers",
  "ipc-services",
  "telemetry-runtime",
  "kernel-platform",
]);

const contentTypeSchema = z.enum([
  "concept",
  "vulnerability",
  "service-dossier",
  "lab",
  "research-note",
  "reference",
  "interactive-atlas",
]);

const reviewStatusSchema = z.enum([
  "draft",
  "preliminary",
  "reviewed",
  "confirmed",
  "superseded",
  "archived",
]);

const evidenceLevelSchema = z.enum([
  "documented",
  "observed",
  "inferred",
  "hypothesis",
  "mixed",
  "unverified",
]);

const sourceSchema = z.object({
  title: z.string().min(1),
  url: z.string().url(),
  type: z.enum([
    "official-docs",
    "official-header",
    "official-advisory",
    "cve-record",
    "symbols",
    "source-code",
    "research",
    "academic",
    "poc",
    "other",
  ]),
  supports: z.array(z.string()).default([]),
  reliability: z
    .enum(["primary", "supporting", "context-only"])
    .default("supporting"),
  accessed_at: z.coerce.date().optional(),
  version_caveat: z.string().optional(),
});

const changelogEntrySchema = z.object({
  date: z.coerce.date(),
  summary: z.string().min(1),
});

const blog = defineCollection({
  loader: glob({
    pattern: "**/*.{md,mdx}",
    base: "./src/content/blog",
    generateId: ({ entry }) => entry.replace(/\.[^/.]+$/, ""),
  }),
  schema: z.object({
    title: z.string().min(1),
    description: z.string().min(1),
    locale: localeSchema,
    publishDate: z.date(),
    updatedAt: z.coerce.date().optional(),
    reviewed_at: z.coerce.date().optional(),
    draft: z.boolean().default(false),
    featured: z.boolean().default(false),
    content_type: contentTypeSchema.default("concept"),
    status: reviewStatusSchema.default("preliminary"),
    evidence_level: evidenceLevelSchema.default("unverified"),
    reviewers: z.array(z.string()).default([]),
    estimated_reading_time: z.number().int().positive().optional(),
    windows_versions: z.array(z.string().min(1)).default([]),
    windows_builds: z
      .array(z.string().regex(/^(?:10\.0\.)?\d{4,5}(?:\.\d+)?$/))
      .default([]),
    architectures: z
      .array(z.enum(["x86", "x64", "arm64", "wow64", "unknown"]))
      .default([]),
    cves: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/i)).default([]),
    sources: z.array(sourceSchema).default([]),
    related_concepts: z.array(z.string()).default([]),
    related_articles: z.array(z.string()).default([]),
    related_labs: z.array(z.string()).default([]),
    changelog: z.array(changelogEntrySchema).default([]),
    tags: z.array(z.string()).default([]),
    author: z.string().default("Admin"),
    authorId: z.string().optional(),
    uid: z
      .string()
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
      .optional(),
    faqs: z
      .array(z.object({ question: z.string(), answer: z.string() }))
      .optional(),
    toc: z.boolean().optional(),
    wide: z.boolean().default(false),
    format: z.enum(["article", "interactive-atlas"]).default("article"),
    svgSlug: z.string().optional(),
    translationKey: z.string().optional(),
    topic: researchTopicSchema.optional(),
    track: researchTrackSchema.optional(),
    seriesOrder: z.number().int().positive().optional(),
    topicPlacements: z
      .array(
        z.object({
          topic: researchTopicSchema,
          track: researchTrackSchema,
          order: z.number().int().positive(),
        }),
      )
      .default([]),
    difficulty: z.enum(["Foundation", "Intermediate", "Advanced"]).optional(),
    prerequisites: z.array(z.string()).default([]),
    learningObjectives: z.array(z.string()).default([]),
    labEnvironment: z.string().optional(),
  }),
});

const pageSectionSchema = z.object({
  type: z.enum(["hero", "cta", "features", "faq", "trust"]),
  title: z.string().optional(),
  content: z.string().optional(),
  ctaText: z.string().optional(),
  ctaHref: z.string().optional(),
  items: z
    .array(
      z.object({
        title: z.string().optional(),
        description: z.string().optional(),
        icon: z.string().optional(),
      }),
    )
    .optional(),
});

const pages = defineCollection({
  loader: glob({
    pattern: "**/*.md",
    base: "./src/content/pages",
    generateId: ({ entry }) => entry.replace(/\.[^/.]+$/, ""),
  }),
  schema: z.object({
    locale: localeSchema,
    slug: z.string(),
    title: z.string(),
    description: z.string(),
    sections: z.array(pageSectionSchema).default([]),
    isLegal: z.boolean().default(false),
    order: z.number().default(0),
    translationKey: z.string().optional(),
  }),
});

const services = defineCollection({
  loader: glob({
    pattern: "**/*.{md,mdx}",
    base: "./src/content/services",
    generateId: ({ entry }) => entry.replace(/\.[^/.]+$/, ""),
  }),
  schema: z.object({
    locale: localeSchema,
    slug: z.string(),
    title: z.string(),
    description: z.string(),
    image: z.string().optional(),
    featured: z.boolean().default(false),
    tags: z.array(z.string()).default([]),
    features: z.array(z.string()).default([]),
    priceRange: z.string().optional(),
    order: z.number().default(0),
    translationKey: z.string().optional(),
  }),
});

const authors = defineCollection({
  loader: glob({
    pattern: "**/*.json",
    base: "./src/content/authors",
    generateId: ({ entry }) => entry.replace(/\.json$/, ""),
  }),
  schema: z.object({
    name: z.string(),
    bio: z.string(),
    avatar: z.string().optional(),
    social: z
      .object({
        twitter: z.string().optional(),
        github: z.string().optional(),
        linkedin: z.string().optional(),
        email: z.string().optional(),
      })
      .optional(),
  }),
});

const faqs = defineCollection({
  loader: glob({
    pattern: "**/*.json",
    base: "./src/content/faqs",
    generateId: ({ entry }) => entry.replace(/\.json$/, ""),
  }),
  schema: z.object({
    question: z.string(),
    answer: z.string(),
    category: z.string().optional(),
    order: z.number().default(0),
    locale: localeSchema,
  }),
});

const stack = defineCollection({
  loader: glob({
    pattern: "**/*.{md,mdx}",
    base: "./src/content/stack",
    generateId: ({ entry }) => entry.replace(/\.[^/.]+$/, ""),
  }),
  schema: z.object({
    name: z.string(),
    description: z.string(),
    version: z.string(),
    url: z.string().url(),
    icon: z.string(),
    colorOklch: z.string(),
    order: z.number().default(0),
  }),
});

const settings = defineCollection({
  loader: glob({
    pattern: "settings.yml",
    base: "./src/content",
    generateId: ({ entry }) => entry.replace(/\.[^/.]+$/, ""),
  }),
  schema: z.object({
    name: z.string(),
    description: z.string().optional(),
    url: z.string().optional(),
    defaultLocale: localeSchema.default("en"),
    analyticsProvider: z.enum(["none", "gtm", "umami"]).default("none"),
    gtmId: z.string().optional(),
    umamiUrl: z.string().optional(),
    umamiId: z.string().optional(),
    mapLatitude: z.string().optional(),
    mapLongitude: z.string().optional(),
    orgName: z.string().optional(),
    orgEmail: z.string().optional(),
  }),
});

export const collections = {
  blog,
  pages,
  services,
  settings,
  authors,
  faqs,
  stack,
};
