import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const wcagTags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

const routes = [
  "/",
  "/blogs/",
  "/blog/access-tokens-sids-integrity-privileges/",
  "/windows-security-concepts/arbitrary-file-delete/",
];

test.describe("WCAG accessibility", () => {
  for (const route of routes) {
    test(`${route} has no automated WCAG A/AA violations`, async ({ page }) => {
      await page.goto(route, { waitUntil: "networkidle" });
      const results = await new AxeBuilder({ page })
        .withTags(wcagTags)
        .analyze();

      expect(
        results.violations,
        results.violations
          .map(
            (violation) =>
              `${violation.id}: ${violation.nodes
                .map((node) => node.target.join(" "))
                .join(", ")}`,
          )
          .join("\n"),
      ).toEqual([]);
    });
  }

  test("article dark mode has no automated WCAG A/AA violations", async ({
    page,
  }) => {
    await page.addInitScript(() => localStorage.setItem("theme", "dark"));
    await page.goto("/blog/access-tokens-sids-integrity-privileges/", {
      waitUntil: "networkidle",
    });
    const results = await new AxeBuilder({ page }).withTags(wcagTags).analyze();

    expect(results.violations).toEqual([]);
  });
});
