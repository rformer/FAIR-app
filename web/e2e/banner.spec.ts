import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// F-001 T-19 (AC-34): after sign-in the system-use notification is all a
// user gets, through the UI and the API alike, until it is acknowledged;
// every new session acknowledges again.

let problems: string[] = [];
test.beforeEach(({ page }) => {
  problems = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/.test(m.text())) problems.push(`CSP violation: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(`script error: ${e.message}`));
});
test.afterEach(() => {
  expect(problems, "CSP violations and script errors").toEqual([]);
});

test("no access before acknowledgment (AC-34), accessibly", async ({ page }) => {
  await page.goto("/dev/as/auditor");
  await expect(page.getByRole("heading", { level: 1, name: "System use notification" })).toBeVisible();
  await expect(page.getByText("authorized use only")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Security posture" })).toHaveCount(0);
  const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(axe.violations.map((v) => v.id), "banner page").toEqual([]);

  // The API refuses the session too, whatever the UI does.
  const blocked = await page.request.get("/api/v1/posture/settings");
  expect(blocked.status()).toBe(403);
  expect((await blocked.json()).error).toBe("banner_required");

  await page.getByRole("button", { name: "Acknowledge and continue" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Security posture" })).toBeVisible();
  expect((await page.request.get("/api/v1/posture/settings")).status()).toBe(200);

  // Acknowledged for this session: a reload goes straight to the page.
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Security posture" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "System use notification" })).toHaveCount(0);

  // A new session acknowledges again.
  await page.goto("/dev/as/auditor");
  await expect(page.getByRole("heading", { level: 1, name: "System use notification" })).toBeVisible();
});

test("signing out from the notification ends the session", async ({ page }) => {
  await page.goto("/dev/as/auditor");
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("alert")).toContainText("Sign in again");
  expect((await page.request.get("/api/v1/me")).status()).toBe(401);
});
