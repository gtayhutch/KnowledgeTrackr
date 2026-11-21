import { expect, test } from "@playwright/test";

test("sign-in page asks for an email", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
});

test("the local API answers", async ({ request }) => {
  await expect
    .poll(
      async () => {
        try {
          const response = await request.get(
            "http://127.0.0.1:8787/api/health",
          );
          return response.ok();
        } catch {
          return false;
        }
      },
      { timeout: 240_000 },
    )
    .toBe(true);
});
