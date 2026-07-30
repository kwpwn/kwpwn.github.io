import { test, expect } from "@playwright/test";

test.describe("navigation chrome", () => {
  test("homepage loads with nav links", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.locator("h1").first()).toBeVisible({ timeout: 30_000 });
    // Positive proof we're on this site, not a colliding dev server on 4321
    await expect(page.locator(".logo").first()).toHaveAttribute(
      "aria-label",
      "KWPWN Research Library",
      { timeout: 30_000 },
    );
    await expect(page.locator(".header__list a").first()).toBeVisible({
      timeout: 30_000,
    });
  });

  test("dark mode toggle flips the html dark class", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const toggle = page.locator("[data-theme-toggle]").first();
    await expect(toggle).toBeVisible({ timeout: 30_000 });
    const before = await page.evaluate(() =>
      document.documentElement.classList.contains("dark"),
    );
    await toggle.click();
    const after = await page.evaluate(() =>
      document.documentElement.classList.contains("dark"),
    );
    expect(after).toBe(!before);
  });

  test("Ctrl+K opens the search modal", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.locator("h1").first()).toBeVisible({ timeout: 30_000 });
    await page.keyboard.press("Control+k");
    const dialog = page.locator("#search-modal").first();
    await expect(dialog).toBeVisible({ timeout: 30_000 });
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible({ timeout: 30_000 });
  });

  test("search uses the local full-text index and keyboard navigation", async ({
    page,
  }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.keyboard.press("Control+k");

    const input = page.locator("[data-search-input]");
    await input.fill("ALPC");
    await expect(page.locator("[data-search-status]")).toContainText(
      "results found",
      { timeout: 30_000 },
    );
    await expect(
      page.locator("[data-search-results] h3", { hasText: "Concepts" }),
    ).toBeVisible();

    await input.press("ArrowDown");
    await expect(page.locator("[data-search-results] a").first()).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(page.locator("#search-modal")).not.toBeVisible();
  });

  test("mobile menu toggle opens the panel", async ({ page }) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 375, height: 800 });
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const toggle = page.locator("[data-menu-toggle]").first();
    await expect(toggle).toBeVisible({ timeout: 30_000 });
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-expanded", "true", {
      timeout: 30_000,
    });
    await page.keyboard.press("Escape");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toggle).toBeFocused();
  });

  test("concept pages provide one handbook nav and one local table of contents", async ({
    page,
  }) => {
    await page.goto("/windows-security-concepts/arbitrary-file-delete/", {
      waitUntil: "domcontentloaded",
    });

    await expect(page.locator(".logo")).toBeVisible();
    await expect(page.locator(".header__desktop-nav")).toBeVisible();
    await expect(page.locator(".header__actions")).toBeVisible();
    await expect(
      page.getByRole("complementary", { name: "Handbook navigation" }),
    ).toHaveCount(1);
    await expect(
      page.getByRole("complementary", { name: "On this page" }),
    ).toHaveCount(1);
    await expect(
      page.getByText("Evidence status:", { exact: false }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () =>
          document.documentElement.scrollWidth -
          document.documentElement.clientWidth,
      ),
    ).toBe(0);
  });
});
