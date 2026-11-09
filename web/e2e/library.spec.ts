import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-003 T-13 (AC-08, AC-11, AC-12, AC-22, AC-27): the library and control
// pages and the starter library, against the real risk API and what
// db/tests/ui_harness_test.go seeds (a risk analyst at the root, a library,
// the starter library). These tests make their own entries: the scenario
// pages' tests rely on the seeded ones as they are. WCAG 2.1 AA with axe.

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

async function as(page: Page, user: string) {
  await page.goto(`/dev/as/${user}`);
  await page.getByRole("button", { name: "Acknowledge and continue" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

test("the library and the starter library: copy an entry to adapt (AC-08, AC-11), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.getByRole("link", { name: "Library", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Library");
  const entries = page.getByRole("region", { name: "Entries" });
  await expect(entries.getByRole("link", { name: "Claims database" })).toBeVisible();
  const starter = page.getByRole("region", { name: "Starter library" });
  await expect(starter).toContainText("not industry data");
  await expect(starter.getByRole("row", { name: /Nation-state actors/ })).toContainText("Illustrative values");
  await expectAccessible(page, "the library");

  await starter.getByRole("button", { name: "Copy Nation-state actors" }).click();
  const dialog = page.getByRole("dialog", { name: "Copy Nation-state actors" });
  await expectAccessible(page, "the copy dialog");
  await dialog.getByRole("button", { name: "Copy" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Nation-state actors");
  await expect(page.getByText(/Threat community · .* · version 1/)).toBeVisible();
  await expect(page.getByRole("region", { name: "Threat community" })).toContainText("70 – 85 – 99 percentile");
  await expectAccessible(page, "a copied entry");
});

test("an asset: create, save a version, compare, archive and restore (AC-08, AC-15, AC-17, AC-22)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/library");
  await page.getByRole("link", { name: "New asset", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("New asset");
  await expectAccessible(page, "the asset editor");
  // A refused save lists its problems.
  await page.getByLabel("Change note").fill("First");
  await page.getByRole("button", { name: "Create the asset" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Not saved" }).getByRole("link", { name: "/name" })).toBeVisible();
  await page.getByLabel("Name", { exact: true }).fill("Policy administration system");
  await page.getByLabel("Asset type").fill("Application");
  await page.getByLabel("Value basis").fill("Cost to rebuild and restore the policy data.");
  await page.getByRole("button", { name: "Create the asset" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Policy administration system");

  await page.getByRole("link", { name: "Edit" }).click();
  await page.getByLabel("Asset type").fill("Core application");
  await page.getByLabel("Change note").fill("Reclassified");
  await page.getByRole("button", { name: "Save a new version" }).click();
  await expect(page.getByText(/version 2/)).toBeVisible();
  const history = page.getByRole("region", { name: "Versions" });
  await history.getByRole("button", { name: "Compare" }).click();
  await expect(page.getByRole("region", { name: "Changes from version 1 to 2" }).getByRole("row", { name: /\/asset_type/ })).toContainText("Core application");

  await page.getByRole("button", { name: "Archive" }).click();
  const archive = page.getByRole("dialog", { name: "Archive this asset" });
  await archive.getByLabel("Reason").fill("Replaced");
  await archive.getByRole("button", { name: "Archive" }).click();
  await expect(page.getByText("Archived", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
  await expectAccessible(page, "an archived entry");
  await page.getByRole("button", { name: "Restore" }).click();
  const restore = page.getByRole("dialog", { name: "Restore this asset" });
  await restore.getByLabel("Reason").fill("Still in use");
  await restore.getByRole("button", { name: "Restore" }).click();
  await expect(page.getByRole("link", { name: "Edit" })).toBeVisible();
});

test("a control with its effects and references (AC-12, AC-14), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Controls" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Controls");
  await page.getByRole("link", { name: "New control" }).click();
  await page.getByLabel("Name", { exact: true }).fill("Multi-factor authentication");
  const effect = page.getByRole("group", { name: /^Resistance strength provided/ });
  await effect.getByLabel("Minimum").fill("60");
  await effect.getByLabel("Most likely").fill("75");
  await effect.getByLabel("Maximum").fill("90");
  await effect.getByLabel("Rationale").fill("Phishing-resistant factors for all staff.");
  await effect.getByLabel("Source 1", { exact: true }).fill("Security architecture review");
  await page.getByRole("button", { name: "Add a framework reference" }).click();
  await page.getByLabel("Framework 1").fill("NIST SP 800-53r5");
  await page.getByLabel("Identifier 1").fill("IA-2(1)");
  await page.getByLabel("Change note").fill("New control");
  await expectAccessible(page, "the control editor");
  await page.getByRole("button", { name: "Create the control" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Multi-factor authentication");
  const control = page.getByRole("region", { name: "Control" });
  await expect(control).toContainText("60 – 75 – 90 percentile");
  await expect(control).toContainText("IA-2(1)");
  await expectAccessible(page, "a control");
});

test("a viewer reads the library without changing it", async ({ page }) => {
  await as(page, "nobody");
  await page.goto("/library");
  await expect(page.getByRole("link", { name: "New asset", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Copy / })).toHaveCount(0);
  await page.getByRole("link", { name: "Claims database" }).click();
  await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Archive" })).toHaveCount(0);
});
