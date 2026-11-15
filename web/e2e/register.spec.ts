import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-007 T-08 (AC-01 to AC-10, AC-19, AC-20): the register pages against the
// real register API and what db/tests/ui_harness_test.go seeds: a risk
// owner at the root ("riskowner"), "Claims platform outage and fraud"
// covering two scenarios with pinned runs on the real engine (its exposure
// combined, and a newer run of one scenario to adopt), "Payroll provider
// failure" (unquantified, at Claims) and "Legacy fax gateway" (closed).
// "nobody" (Executive Viewer) reads without changing. WCAG 2.1 AA is
// checked with axe on every view.

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

const seeded = "Claims platform outage and fraud";

test("the register, its coverage and filters (AC-09, AC-19), accessibly", async ({ page }) => {
  await as(page, "riskowner");
  await page.getByRole("link", { name: "Risk register", exact: true }).click();
  await expect(page).toHaveURL("/register");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Risk register");
  await expect(page.getByRole("region", { name: "Coverage" })).toContainText("1 of 2 open risks (50%)");
  const risks = page.getByRole("region", { name: "Risks" });
  await expect(risks.getByRole("row", { name: new RegExp(seeded) })).toContainText("Current");
  await expect(risks.getByRole("row", { name: /Payroll provider failure/ })).toContainText("Unquantified");
  await expect(risks.getByRole("link", { name: "Legacy fax gateway" })).toHaveCount(0);
  await expectAccessible(page, "the register");

  await risks.getByLabel("State").selectOption({ label: "Open and closed" });
  await risks.getByRole("button", { name: "Apply" }).click();
  await expect(risks.getByRole("row", { name: /Legacy fax gateway/ })).toContainText("Closed");

  await risks.getByLabel("State").selectOption({ label: "Open" });
  await risks.getByLabel("Exposure").selectOption({ label: "Unquantified" });
  await risks.getByRole("button", { name: "Apply" }).click();
  await expect(risks.getByRole("link", { name: "Payroll provider failure" })).toBeVisible();
  await expect(risks.getByRole("link", { name: seeded })).toHaveCount(0);
  await expectAccessible(page, "a filtered register");
});

test("a risk's scenarios, exposure and history; adopting a newer run (AC-03, AC-06, AC-07, AC-10)", async ({ page }) => {
  await as(page, "riskowner");
  await page.goto("/register");
  await page.getByRole("link", { name: seeded }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(seeded);
  await expect(page).toHaveTitle(`${seeded} · Risk register · FAIR Risk Platform`);
  const scenarios = page.getByRole("region", { name: "Scenarios and pinned analyses" });
  await expect(scenarios.getByRole("row", { name: /Claims system outage/ })).toContainText("1 newer run");
  await expect(scenarios.getByRole("row", { name: /Payment fraud/ })).toContainText("Current");
  const exposure = page.getByRole("region", { name: "Exposure" });
  await expect(exposure).toContainText("assuming their losses are independent");
  await expect(exposure.getByText("Mean annual loss")).toBeVisible();
  await expect(exposure.getByRole("figure", { name: `Loss exceedance, ${seeded}` })).toBeVisible();
  await expect(exposure.getByRole("link", { name: /Every view of this result/ })).toHaveAttribute("href", /^\/analyses\/aggregates\//);
  await expectAccessible(page, "a risk");

  await scenarios.getByRole("button", { name: "Adopt newer runs" }).click();
  const dialog = page.getByRole("dialog", { name: "Adopt newer runs" });
  await expectAccessible(page, "the adopt dialog");
  await dialog.getByLabel("Change note").fill("Adopt the newer outage analysis");
  await dialog.getByRole("button", { name: "Adopt" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".lede")).toContainText("version 2");
  await expect(scenarios.getByRole("button", { name: "Adopt newer runs" })).toHaveCount(0);
  // The combined exposure is computed again, then current.
  await expect(page.locator(".lede")).toContainText("Exposure Current", { timeout: 90_000 });

  const history = page.getByRole("region", { name: "History" });
  await expect(history.getByRole("row", { name: /Adopt the newer outage analysis/ })).toBeVisible();
  await history.getByLabel("From version").selectOption("1");
  await history.getByLabel("To version").selectOption("2");
  await history.getByRole("button", { name: "Compare" }).click();
  const diff = page.getByRole("region", { name: "Changes to the risk from version 1 to 2" });
  await expect(diff.getByRole("row", { name: /\/scenarios\/0\/pin\/run_id/ })).toContainText("Changed");
  await expectAccessible(page, "a comparison");
});

test("a new risk, its problems shown; closed, reopened and moved (AC-01, AC-02, AC-04, AC-05)", async ({ page }) => {
  await as(page, "riskowner");
  await page.goto("/register");
  await page.getByRole("link", { name: "New risk" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("New risk");
  await page.getByLabel("Business unit").selectOption({ label: "Enterprise" });
  await page.getByLabel("Title").fill("Vendor data breach");
  await page.getByLabel("Description").fill("Customer data exposed at a claims-handling vendor.");
  await page.getByLabel("Owner").selectOption({ label: "Rio Owner" });
  await page.getByLabel("Category").selectOption({ label: "Data privacy" });
  // A scenario linked to another open risk is refused (AC-02).
  await page.getByLabel("Link a scenario").selectOption({ label: "Payment fraud" });
  await page.getByRole("button", { name: "Link", exact: true }).click();
  await expect(page.getByRole("group", { name: "Payment fraud" })).toBeVisible();
  await page.getByLabel("Change note").fill("Raised at the vendor review");
  await expectAccessible(page, "the new-risk form");
  await page.getByRole("button", { name: "Create risk" }).click();
  await expect(page.getByRole("alert")).toContainText("linked to another open risk");
  await page.getByRole("group", { name: "Payment fraud" }).getByRole("button", { name: "Unlink" }).click();
  await page.getByRole("button", { name: "Create risk" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Vendor data breach");
  await expect(page.locator(".lede")).toContainText("Unquantified");
  await expect(page.getByRole("region", { name: "Risk" })).toContainText("Rio Owner");

  await page.getByRole("button", { name: "Close", exact: true }).click();
  let dialog = page.getByRole("dialog", { name: "Close this risk" });
  await dialog.getByLabel("Reason").fill("Vendor contract ended");
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".lede")).toContainText("Closed");
  await expect(page.getByRole("region", { name: "Risk" })).toContainText("Vendor contract ended");
  await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);

  await page.getByRole("button", { name: "Reopen" }).click();
  dialog = page.getByRole("dialog", { name: "Reopen this risk" });
  await dialog.getByLabel("Reason").fill("New contract signed");
  await dialog.getByRole("button", { name: "Reopen" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".lede")).toContainText("Open");

  await page.getByRole("button", { name: "Move" }).click();
  dialog = page.getByRole("dialog", { name: "Move this risk" });
  await expectAccessible(page, "the move dialog");
  await dialog.getByLabel("Move to").selectOption({ label: "Claims" });
  await dialog.getByLabel("Reason").fill("Claims manages the vendor");
  await dialog.getByRole("button", { name: "Move" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".lede")).toContainText("Claims");
  await expect(page.getByRole("region", { name: "History" }).getByRole("row")).toHaveCount(4); // header and three versions
});

test("a viewer reads the register without changing it (AC-21)", async ({ page }) => {
  await as(page, "nobody");
  await page.goto("/register");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Risk register");
  await expect(page.getByRole("link", { name: "New risk" })).toHaveCount(0);
  await page.getByRole("link", { name: seeded }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(seeded);
  for (const name of ["Close", "Move", "Adopt newer runs"]) {
    await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
  }
  await expect(page.getByRole("link", { name: "Edit" })).toHaveCount(0);
  await expectAccessible(page, "a risk, read only");
});
