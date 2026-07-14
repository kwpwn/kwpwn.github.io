import { test, expect } from "@playwright/test";

test.describe("empty blog", () => {
  test("homepage renders the empty state", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.locator("h1")).toHaveText("Blogs");
    await expect(page.locator(".posts__empty")).toHaveText("No posts yet.");
  });
});
