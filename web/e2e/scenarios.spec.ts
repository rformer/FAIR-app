import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-003 T-12 (AC-10, AC-17, AC-27, AC-28): the scenario pages against the
// real risk API and the scenario db/tests/ui_harness_test.go seeds: a risk
// analyst at the root, a library, and "Ransomware on the claims platform"
// at version 2 with a newer threat community version to adopt. "nobody"
// (Executive Viewer) reads without editing. WCAG 2.1 AA is checked with axe
// on every view (constitution Q3).

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

const seeded = "Ransomware on the claims platform";

test("the list, a scenario's taxonomy, pins and history (AC-28, AC-17), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.getByRole("link", { name: "Scenarios", exact: true }).click();
  await expect(page).toHaveURL("/scenarios");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Scenarios");
  await expect(page.getByRole("link", { name: "New scenario" })).toBeVisible();
  await expectAccessible(page, "the scenario list");

  await page.getByRole("link", { name: seeded }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(seeded);
  await expect(page).toHaveTitle(`${seeded} · FAIR Risk Platform`);
  // AC-28: entered and derived factors.
  const taxonomy = page.getByRole("region", { name: "FAIR taxonomy" });
  await expect(taxonomy.getByText(/Contact frequency\s*Entered/)).toBeVisible();
  await expect(taxonomy.getByText(/Loss event frequency\s*Derived/)).toBeVisible();
  await expect(taxonomy.getByText("2 – 6 – 12 events per year (90% confidence)")).toBeVisible();
  // AC-10: the newer threat community version.
  const pins = page.getByRole("region", { name: "Library and controls used" });
  await expect(pins.getByRole("row", { name: /\/threat_community/ })).toContainText("Newer available");
  await expectAccessible(page, "a scenario");

  // AC-17: what changed between versions 1 and 2.
  const history = page.getByRole("region", { name: "Versions" });
  await history.getByLabel("From version").selectOption("1");
  await history.getByLabel("To version").selectOption("2");
  await history.getByRole("button", { name: "Compare" }).click();
  const diff = page.getByRole("region", { name: "Changes from version 1 to 2" });
  await expect(diff.getByRole("row", { name: /\/scope\/out/ })).toContainText("Changed");
  await expectAccessible(page, "a comparison");
});

test("adopting a newer library version (AC-10)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/scenarios");
  await page.getByRole("link", { name: seeded }).click();
  await page.getByRole("button", { name: "Adopt newer versions" }).click();
  const dialog = page.getByRole("dialog", { name: "Adopt newer versions" });
  await expectAccessible(page, "the adopt dialog");
  await dialog.getByLabel("Change note").fill("Adopt the renamed threat community");
  await dialog.getByRole("button", { name: "Adopt" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText(/version 3/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Adopt newer versions" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Versions" }).getByRole("row", { name: /Adopt the renamed threat community/ })).toBeVisible();
});

test("creating a scenario: every problem listed and linked, then saved (AC-01 to AC-06, AC-27)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/scenarios/new");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("New scenario");
  await expectAccessible(page, "the editor");

  // Saving the blank form: the API lists every problem; each links to its field.
  await page.getByLabel("Change note").fill("First draft");
  await page.getByRole("button", { name: "Create the scenario" }).click();
  const alert = page.getByRole("alert").filter({ hasText: "The scenario was not saved" });
  await expect(alert).toBeVisible();
  await expect(alert.getByRole("link", { name: "/name" })).toBeVisible();
  await expect(alert.getByRole("link", { name: "/lef/estimate/min" })).toBeVisible();
  await expectAccessible(page, "the editor with problems");
  await alert.getByRole("link", { name: "/name" }).click();
  await expect(page.getByLabel("Name", { exact: true })).toBeFocused();

  // A complete scenario at the simplest levels.
  await page.getByLabel("Name", { exact: true }).fill("Laptop theft");
  await page.getByLabel("Loss event", { exact: true }).fill("A laptop holding customer data is stolen.");
  await page.getByLabel("In scope", { exact: true }).fill("Staff laptops.");
  await page.getByRole("checkbox", { name: "Confidentiality" }).check();
  await page.getByLabel("Asset", { exact: true }).selectOption({ label: "Claims database" });
  await page.getByLabel("Threat community").selectOption({ label: "Organised cyber crime" });
  const lef = page.getByRole("group", { name: /^Loss event frequency/ });
  await lef.getByLabel("Minimum").fill("0.5");
  await lef.getByLabel("Most likely").fill("1");
  await lef.getByLabel("Maximum").fill("3");
  await lef.getByLabel("Rationale").fill("Two thefts in the last four years.");
  await lef.getByLabel("Source 1", { exact: true }).fill("Facilities incident log");
  await page.getByRole("region", { name: "Primary loss" }).getByRole("checkbox", { name: "Response" }).check();
  const response = page.getByRole("group", { name: /^Response/ });
  await response.getByLabel("Minimum").fill("2000");
  await response.getByLabel("Most likely").fill("10000");
  await response.getByLabel("Maximum").fill("80000");
  await response.getByLabel("Rationale").fill("Notification and device replacement.");
  await response.getByLabel("Source 1", { exact: true }).fill("Finance");
  await page.getByRole("button", { name: "Create the scenario" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Laptop theft");
  await expect(page.getByRole("region", { name: "FAIR taxonomy" }).getByText(/Loss event frequency\s*Entered/)).toBeVisible();
  await expectAccessible(page, "the new scenario");
});

test("a viewer reads scenarios without editing them", async ({ page }) => {
  await as(page, "nobody");
  await page.goto("/scenarios");
  await expect(page.getByRole("link", { name: "New scenario" })).toHaveCount(0);
  await page.getByRole("link", { name: seeded }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(seeded);
  await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
  await expectAccessible(page, "a scenario, read only");
});

// Last: it renames the seeded scenario.
test("editing saves a new version (AC-15)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/scenarios");
  await page.getByRole("link", { name: seeded }).click();
  await page.getByRole("link", { name: "Edit" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Edit ${seeded}`);
  await expectAccessible(page, "the editor on an existing scenario");
  await page.getByLabel("Name", { exact: true }).fill("Ransomware on claims, reviewed");
  await page.getByLabel("Change note").fill("Reviewed with the claims team");
  await page.getByRole("button", { name: "Save a new version" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Ransomware on claims, reviewed");
  await expect(page.getByText(/version 4/)).toBeVisible();
  await expect(page.getByRole("region", { name: "Versions" }).getByRole("row", { name: /Reviewed with the claims team/ })).toBeVisible();
});
