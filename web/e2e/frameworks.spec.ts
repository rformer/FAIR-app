import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-013 T-10 (F-013-AC-01 to AC-18): the framework pages against the real
// framework and risk APIs, as db/tests/ui_harness_frameworks_test.go seeds
// them: the shipped frameworks (NIST SP 800-53 5.2.0 and 5.1.1, 800-171r3,
// the NIST and FedRAMP baselines, the 800-171r3 crosswalk); "riskanalyst"
// (Risk Analyst at Enterprise) keeps "Account management reviews", in place
// and mapped in full to AC-2, used by no scenario; "admin" (Platform Admin)
// imports. WCAG 2.1 AA is checked with axe on every page.

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
  await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/api/v1/auth/banner/ack") && r.ok()),
    page.getByRole("button", { name: "Acknowledge and continue" }).click(),
  ]);
  await expect(page.getByRole("heading", { level: 1 })).not.toHaveText("System use notification");
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

test("frameworks, a version with its changes and requirements, a baseline and a crosswalk (AC-01, AC-02, AC-05, AC-10), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Frameworks" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Frameworks");
  const nist = page.getByRole("region", { name: /NIST SP 800-53/ });
  await expect(nist.getByRole("link", { name: "5.2.0" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Import a framework, baseline or crosswalk" })).toHaveCount(0); // not a manager
  await expectAccessible(page, "frameworks");

  await nist.getByRole("link", { name: "5.2.0" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("5.2.0");
  // Shipped versions carry no diff (an imported one records what changed since its family's latest).
  await expect(page.getByRole("region", { name: "What changed" })).toContainText(/first version of the framework here|Since /);
  await page.getByLabel("Identifier, title or text").fill("account management");
  await page.getByRole("button", { name: "Search" }).click();
  const reqs = page.getByRole("region", { name: "Requirements" });
  await expect(reqs.getByRole("link", { name: "AC-2", exact: true })).toBeVisible();
  await expectAccessible(page, "a version");

  await page.getByRole("region", { name: "Baselines" }).getByRole("link", { name: /LOW IMPACT/ }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("LOW IMPACT");
  await expect(page.getByRole("region", { name: "Requirements it selects" })).toContainText("ac-2");
  await expectAccessible(page, "a baseline");

  await page.goto("/frameworks");
  await page.getByRole("region", { name: "Crosswalks" }).getByRole("link").first().click();
  await expect(page.getByRole("region", { name: "Relationships" }).getByRole("row").nth(1)).toContainText("intersecting");
  await expectAccessible(page, "a crosswalk");
});

test("a requirement's controls and scenarios, and a proposal opened in the editor, not saved (AC-16, AC-17)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/frameworks");
  await page.getByRole("region", { name: /NIST SP 800-53/ }).getByRole("link", { name: "5.2.0" }).click();
  await page.getByLabel("Identifier, title or text").fill("account management");
  await page.getByRole("button", { name: "Search" }).click();
  await page.getByRole("region", { name: "Requirements" }).getByRole("link", { name: "AC-2", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Account Management");
  const controls = page.getByRole("region", { name: "Controls mapped to it" });
  await expect(controls.getByRole("row", { name: /Account management reviews/ })).toContainText("Full");
  await expect(controls.getByRole("row", { name: /Account management reviews/ })).toContainText("In place");
  await expect(page.getByRole("region", { name: "Scenarios that use them" })).toContainText("None you can see.");
  await expectAccessible(page, "a requirement");

  const propose = page.getByRole("link", { name: "Propose Account management reviews for Phishing of claims staff" });
  await propose.click();
  await expect(page.getByRole("status")).toContainText('Proposed: a new control set "With Account management reviews"');
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Edit");
  await expectAccessible(page, "a proposal in the editor");
});

test("coverage of a baseline for a business unit, counts and no score, downloaded (AC-12 to AC-15)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/frameworks");
  await page.getByRole("region", { name: /NIST SP 800-53/ }).getByRole("link", { name: "5.2.0" }).click();
  await page.getByRole("link", { name: "Coverage", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Coverage of");
  await page.getByLabel("Business unit (and the units below it)").selectOption({ label: "Enterprise" });
  const low = await page.getByLabel("Baseline").locator("option", { hasText: "LOW IMPACT" }).getAttribute("value");
  await page.getByLabel("Baseline").selectOption(low ?? "");
  const counts = page.getByRole("region", { name: "Requirements by state" });
  await expect(counts.getByRole("definition").first()).toHaveText("1");
  await expect(counts).not.toContainText(/score|%|rating/i); // states and counts only (AC-13)
  const row = page.getByRole("region", { name: "Requirements" }).getByRole("row", { name: /AC-2 Account Management/ });
  await expect(row).toContainText("Covered, every mapped control in place");
  await expect(row.getByRole("link", { name: "Account management reviews" })).toBeVisible();
  await expectAccessible(page, "coverage");

  // Enterprise's subtree holds the restricted R, where a reason is required (F-010's rule).
  await page.getByRole("button", { name: "Download as CSV" }).click();
  const dialog = page.getByRole("dialog", { name: "Why are you taking this data out?" });
  await dialog.getByLabel("Reason for the export").fill("Control coverage for the audit committee");
  const download = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Continue" }).click();
  expect((await download).suggestedFilename()).toMatch(/^coverage-nist-800-53-5\.2\.0-.*\.csv$/);
});

test("a control's mappings, with a suggestion from its references (AC-07, AC-08)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/controls");
  await page.getByRole("link", { name: "Account management reviews" }).click();
  await expect(page.getByRole("region", { name: "Framework mappings" })).toContainText("nist-800-53 5.2.0 ac-2: Full");
  await page.getByRole("link", { name: "Edit" }).click();
  const suggested = page.getByRole("region", { name: "Suggested mappings" });
  await expect(suggested).toContainText("AC-2(1)");
  await expectAccessible(page, "the mapping editor");
  await suggested.getByRole("button", { name: "Add AC-2(1)" }).click();
  await expect(page.getByLabel("Requirement identifier").nth(1)).toHaveValue("ac-2.1");
  await page.getByLabel("Strength").nth(1).selectOption("supports");
  await page.getByLabel("Change note").fill("Also supports AC-2(1)");
  await page.getByRole("button", { name: "Save a new version" }).click();
  await expect(page.getByRole("region", { name: "Framework mappings" })).toContainText("nist-800-53 5.2.0 ac-2.1: Supports");
});

test("importing a simple framework: a dry run, then the import (AC-03), as a manager", async ({ page }) => {
  await as(page, "admin");
  await page.goto("/frameworks");
  await page.getByRole("link", { name: "Import a framework, baseline or crosswalk" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Import");
  await page.getByLabel("What it is").selectOption("simple");
  const file = {
    format: "fair.framework.v1",
    family: { key: "e2e-policy", title: "Internal security policy" },
    version: { label: "2026", title: "Internal security policy 2026" },
    requirements: [
      { identifier: "P-1", title: "Access is reviewed" },
      { identifier: "P-1.1", title: "Quarterly", parent: "P-1" },
    ],
  };
  await page.getByLabel("File (JSON or CSV, up to 50 MiB)").setInputFiles({ name: "policy.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(file)) });
  await expectAccessible(page, "the import form");
  await page.getByRole("button", { name: "Dry run" }).click();
  const outcome = page.getByRole("region", { name: "Dry run: it would be imported" });
  await expect(outcome).toContainText("requirements");
  await expect(outcome).toContainText("Nothing was applied.");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByRole("region", { name: "Imported" })).toBeVisible();
  await page.getByRole("link", { name: "Open the version" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Internal security policy 2026");
});
