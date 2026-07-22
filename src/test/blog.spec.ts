import { test, expect } from "@playwright/test";

test.describe("published blog", () => {
  test("homepage renders the published research atlas", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.locator("h1")).toHaveText("Blogs");
    await expect(
      page.getByRole("link", { name: "Windows Security Research Atlas" }),
    ).toBeVisible();
    await expect(
      page.getByText("Interactive atlas", { exact: true }),
    ).toBeVisible();
  });

  test("blog directory exposes the published release and JSON feed", async ({
    page,
  }) => {
    await page.goto("/blogs/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "Blog directory",
    );
    await expect(page.locator("[data-blog-post]")).toHaveCount(1);
    await expect(
      page.getByRole("link", { name: "Windows Security Research Atlas" }),
    ).toBeVisible();
    await expect(page.getByRole("link", { name: "JSON feed" })).toHaveAttribute(
      "href",
      "/data/published-blogs.json",
    );
  });
});
