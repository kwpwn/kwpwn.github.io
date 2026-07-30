import { test, expect } from "@playwright/test";

test.describe("published blog", () => {
  test("homepage renders the research learning paths", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.locator("h1")).toHaveText(
      "Learn Windows security through evidence, not folklore.",
    );
    const paths = page.getByRole("region", { name: "Three guided paths" });
    await expect(
      paths.getByText("Windows Privilege Escalation", { exact: true }),
    ).toBeVisible();
    await expect(
      paths.getByText("Malware Analysis & C2", { exact: true }),
    ).toBeVisible();
    await expect(
      paths.getByText("Windows Internals", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Browse library" }),
    ).toHaveAttribute("href", "/blogs/");
  });

  test("blog directory matches the published JSON feed", async ({ page }) => {
    await page.goto("/blogs/", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "Browse lessons and research notes",
    );

    const response = await page.request.get("/data/published-blogs.json");
    expect(response.ok()).toBe(true);
    const feed = (await response.json()) as {
      count: number;
      posts: Array<{ title: string }>;
    };
    expect(feed.count).toBe(feed.posts.length);
    expect(feed.count).toBeGreaterThanOrEqual(75);
    await expect(page.locator("[data-library-entry]")).toHaveCount(feed.count);
    await expect(
      page.getByRole("link", { name: feed.posts[0].title }),
    ).toBeVisible();
    await expect(page.getByRole("link", { name: "JSON feed" })).toHaveAttribute(
      "href",
      "/data/published-blogs.json",
    );
  });

  test("directory filters update the visible article set", async ({ page }) => {
    await page.goto("/blogs/", { waitUntil: "domcontentloaded" });

    const entries = page.locator("[data-library-entry]");
    const total = await entries.count();
    await page.locator("[data-library-query]").fill("ALPC");
    await expect(page.locator("[data-library-result-status]")).toContainText(
      `of ${total} entries`,
    );
    expect(await entries.filter({ visible: true }).count()).toBeLessThan(total);

    await page.getByRole("button", { name: "Reset filters" }).click();
    await expect(page.locator("[data-library-result-status]")).toHaveText(
      `Showing all ${total} entries.`,
    );
  });

  test("article chrome and learning brief render once", async ({ page }) => {
    await page.goto("/blog/access-tokens-sids-integrity-privileges/", {
      waitUntil: "domcontentloaded",
    });

    await expect(page.locator("[data-toc-root]")).toHaveCount(1);
    await expect(
      page.getByRole("complementary", { name: "Library navigation" }),
    ).toHaveCount(1);
    await expect(
      page.getByRole("heading", { name: "What you will learn" }),
    ).toHaveCount(1);
    await expect(
      page.getByRole("heading", { name: "Prerequisites" }),
    ).toHaveCount(1);
    await expect(
      page.getByRole("heading", { name: "Safe lab boundary" }),
    ).toHaveCount(1);
    await expect(page.locator("[data-article-tools]")).toHaveCount(1);
  });

  test("article completion and code wrapping persist as reader choices", async ({
    page,
  }) => {
    await page.goto("/blog/access-tokens-sids-integrity-privileges/", {
      waitUntil: "domcontentloaded",
    });

    const completion = page.locator("[data-complete]");
    await completion.click();
    await expect(completion).toHaveAttribute("aria-pressed", "true");

    const firstPre = page.locator(".blog-layout__article pre").first();
    const wrap = page
      .locator(".code-tools button", { hasText: "Wrap" })
      .first();
    await expect(firstPre).toHaveCSS("white-space", "pre");
    await wrap.click();
    await expect(wrap).toHaveAttribute("aria-pressed", "true");
    await expect(firstPre).toHaveCSS("white-space", "pre-wrap");

    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.locator("[data-complete]")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });
});
