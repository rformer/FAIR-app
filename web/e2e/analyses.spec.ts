import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Locator, type Page } from "@playwright/test";

// F-005 T-13 (AC-01 to AC-05, AC-13, AC-16, AC-18): simulation runs and
// aggregates against the real API and the real engine, as
// db/tests/ui_harness_test.go seeds them: "Ransomware on the claims
// platform" (version 2, control sets Current and With MFA) with a succeeded
// run of 20,000 iterations (seed 2026) and an older one of version 1 (F-006
// T-06), and "Phishing of claims staff". WCAG 2.1 AA is checked with axe on
// every view (constitution Q3). This file runs first
// (the specs run in name order), on the seeded data as it is.

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

const ransomware = "Ransomware on the claims platform";
const phishing = "Phishing of claims staff";

async function openScenario(page: Page, name: string) {
  await page.goto("/scenarios");
  await page.getByRole("link", { name, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(name);
}

/** The runs table's data rows, newest first. */
function runRows(runs: Locator) {
  return runs.getByRole("table", { name: /Simulation runs of this scenario/ }).getByRole("row").filter({ has: runs.page().getByRole("cell") });
}

async function requestRun(runs: Locator, iterations: string, seed?: string) {
  await runs.getByLabel("Iterations").fill(iterations);
  if (seed) await runs.getByLabel("Seed").fill(seed);
  await runs.getByRole("button", { name: "Run the simulation" }).click();
  await expect(runs.getByRole("status").filter({ hasText: "The run is queued." })).toBeVisible();
}

test("a scenario's runs: results, a new run, a reproduction and a cancellation (AC-01 to AC-05, AC-13, AC-16), accessibly", async ({ page }) => {
  test.setTimeout(240_000);
  await as(page, "riskanalyst");
  await openScenario(page, ransomware);
  const runs = page.getByRole("region", { name: "Simulations" });
  await expect(runs).toContainText("Every input is sampled independently");
  const seeded = runRows(runs).first();
  await expect(seeded).toContainText("Succeeded");
  await expect(seeded).toContainText("20,000");
  await expect(seeded.getByRole("cell").nth(5)).toContainText("$");

  // The seeded run in full: results, convergence, the inputs that matter.
  await seeded.getByRole("button", { name: /^Details/ }).click();
  const current = page.getByRole("region", { name: "Results: Current" });
  await expect(current).toContainText("Mean annual loss");
  await expect(current).toContainText("1 year in 20 (95th percentile)");
  await expect(current).toContainText(/Converged|Not converged/);
  await expect(current.getByRole("table")).toContainText("/lef/");
  await expect(page.getByText("seed 2026")).toBeVisible();
  await expectAccessible(page, "a scenario's runs with a run's results");

  // A new run, 2,000 iterations with seed 7: queued, then succeeded.
  await requestRun(runs, "2000", "7");
  await expect(runRows(runs)).toHaveCount(3);
  await expect(runRows(runs).first()).toContainText("Succeeded", { timeout: 60_000 });

  // Reproduced on the same engine: identical.
  await runRows(runs).first().getByRole("button", { name: "Reproduce" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Reproduce" }).click();
  await expect(runRows(runs)).toHaveCount(4);
  await expect(runRows(runs).first()).toContainText("Reproduced exactly", { timeout: 60_000 });

  // A long run, cancelled while it runs: no results kept.
  await requestRun(runs, "2000000");
  await expect(runRows(runs)).toHaveCount(5);
  await expect(runRows(runs).first()).toContainText(/Running|Queued/);
  await runRows(runs).first().getByRole("button", { name: "Cancel" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Reason").fill("Too many iterations for a first look");
  await expectAccessible(page, "the cancel dialog");
  await dialog.getByRole("button", { name: "Cancel the run" }).click();
  await expect(runRows(runs).first()).toContainText("Cancelled", { timeout: 30_000 });
  await expect(runRows(runs).first().getByRole("cell").nth(5)).toHaveText("—");

  // Out of bounds: the API's reason, announced.
  await runs.getByLabel("Iterations").fill("10");
  await runs.getByLabel("Seed").fill("");
  await runs.getByRole("button", { name: "Run the simulation" }).click();
  await expect(runs.getByRole("alert")).toContainText("iterations are between 1000 and 2000000");
  await expectAccessible(page, "a scenario's runs after changes");
});

test("an aggregate of two scenarios' runs (AC-18), accessibly", async ({ page }) => {
  test.setTimeout(240_000);
  await as(page, "riskanalyst");
  // A run of the second scenario with the seeded run's iterations.
  await openScenario(page, phishing);
  const runs = page.getByRole("region", { name: "Simulations" });
  await requestRun(runs, "20000", "11");
  await expect(runRows(runs).first()).toContainText("Succeeded", { timeout: 90_000 });

  await page.getByRole("link", { name: "Aggregates" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Aggregates");
  await page.getByRole("link", { name: "New aggregate" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("New aggregate");
  await page.getByLabel("Business unit").selectOption({ label: "Enterprise" });
  await page.getByLabel("Name").fill("Claims portfolio");
  const choose = async (n: number, scenario: string, run: RegExp) => {
    await page.getByLabel(`Member ${n} scenario`).selectOption({ label: scenario });
    const option = page.getByLabel(`Member ${n} run`).locator("option").filter({ hasText: run });
    await expect(option).toHaveCount(1);
    await page.getByLabel(`Member ${n} run`).selectOption((await option.getAttribute("value")) ?? "");
    await expect(page.getByLabel(`Member ${n} control set`)).toHaveValue("Current");
  };
  await choose(1, ransomware, /version 2, 20,000 iterations, seed 2026/);
  await choose(2, phishing, /seed 11/);
  await expectAccessible(page, "the aggregate form");
  await page.getByRole("button", { name: "Request the aggregate" }).click();

  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Claims portfolio");
  await expect(page.getByText("Succeeded").first()).toBeVisible({ timeout: 60_000 });
  const result = page.getByRole("region", { name: "Annualized loss" });
  await expect(result).toContainText("Members are combined as independent");
  await expect(result).toContainText("Mean annual loss");
  const members = page.getByRole("region", { name: "Members" });
  await expect(members.getByRole("row").filter({ hasText: "(Current)" })).toHaveCount(2);
  await expect(members).toContainText("%");
  await expectAccessible(page, "an aggregate");

  await page.getByRole("link", { name: "Aggregates" }).first().click();
  await expect(page.getByRole("link", { name: "Claims portfolio" })).toBeVisible();
  await expectAccessible(page, "the aggregates list");
});

test("a viewer reads runs and aggregates but cannot run or change them", async ({ page }) => {
  await as(page, "nobody");
  await openScenario(page, ransomware);
  const runs = page.getByRole("region", { name: "Simulations" });
  await expect(runRows(runs).first()).toBeVisible();
  await expect(runs.getByRole("button", { name: "Run the simulation" })).toHaveCount(0);
  await expect(runs.getByRole("button", { name: "Reproduce" })).toHaveCount(0);
  await expect(runs.getByRole("button", { name: "Cancel" })).toHaveCount(0);
  await page.getByRole("link", { name: "Aggregates" }).click();
  await expect(page.getByRole("link", { name: "New aggregate" })).toHaveCount(0);
  await expectAccessible(page, "runs as a viewer");
});
