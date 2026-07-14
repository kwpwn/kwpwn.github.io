// To add a language: extend this union (e.g. "en" | "id"), add the code to
// SITE_CONFIG.locales, add label/prefix entries below, create a matching
// translations file in src/i18n, and add localized content + [locale] routes.
export type Locale = "en";

export const SITE_CONFIG = {
  url: process.env.SITE_URL ?? "https://kwpwn.github.io",
  /** Default locale for fallback. */
  defaultLocale: "en" as const,
  /** Supported locales. */
  locales: ["en"] as const,
  /** Human-readable locale labels. */
  localeLabels: {
    en: "English",
  } as const,
  /** Short locale codes for URL prefixes. */
  localePrefixes: {
    en: "en",
  } as const,
  /** Site name for metadata and JSON-LD. */
  name: "CTF Writeups",
  /** Short description for metadata. */
  description: "Capture the flag writeups, techniques, and notes from past challenges.",
} as const;
