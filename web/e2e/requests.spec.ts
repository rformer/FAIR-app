import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-004 T-13 (AC-01 to AC-06, AC-13, AC-15 to AC-19): the analyst's estimate
// pages against the real API and what db/tests/ui_harness_test.go seeds: the
// risk analyst ("riskanalyst"), two estimators at the root (Ellis Estimator,
// Sam Okafor), and "Phishing of claims staff" with a request both answered
// (Ellis: contact frequency 2 – 5 – 10, response declined; Sam: 4 – 7 – 12
// and 40000 – 120000 – 500000). WCAG 2.1 AA is checked with axe on every
// view (constitution Q3).

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

const phishing = "Phishing of claims staff";
const seeded = "Phishing frequency and response";

async function openScenario(page: Page, name: string) {
  await page.goto("/scenarios");
  await page.getByRole("link", { name, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(name);
}

test("a reference class: counts, then losses as a new version (AC-13), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/library");
  await page.getByRole("link", { name: "New reference class" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("New reference class");
  await page.getByLabel("Name", { exact: true }).fill("Phishing reports, claims");
  await page.getByLabel("Start", { exact: true }).fill("2024-01-01");
  await page.getByLabel("End", { exact: true }).fill("2026-01-01");
  await page.getByLabel("Period 1 start").fill("2024-01-01");
  await page.getByLabel("Period 1 end").fill("2025-01-01");
  await page.getByLabel("Period 1 events").fill("3");
  await page.getByRole("button", { name: "Add a period" }).click();
  await page.getByLabel("Period 2 end").fill("2026-01-01");
  await page.getByLabel("Period 2 events").fill("5");
  await page.getByLabel("Source 1", { exact: true }).fill("Mail gateway reports");
  await expectAccessible(page, "the reference class editor");
  await page.getByLabel("Change note").fill("From the mail gateway");
  await page.getByRole("button", { name: "Create the reference class" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Phishing reports, claims");
  const entry = page.getByRole("region", { name: "Reference class" });
  await expect(entry).toContainText("8 in 2 periods");
  await expect(entry).toContainText("Mail gateway reports");

  await page.getByRole("link", { name: "Edit" }).click();
  await page.getByLabel(/Observed loss amounts/).check();
  await page.getByLabel("Observed losses, one amount per line").fill("12000\n4,500\n80000");
  await page.getByLabel("Change note").fill("Losses instead");
  await page.getByRole("button", { name: "Save a new version" }).click();
  await expect(page.getByText(/version 2/).first()).toBeVisible();
  await expect(page.getByRole("region", { name: "Reference class" })).toContainText("3 amounts (USD)");
  await expectAccessible(page, "a reference class");
});

test("sending a request from a scenario, changing and cancelling it (AC-01 to AC-04), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await openScenario(page, phishing);
  const requests = page.getByRole("region", { name: "Estimate requests" });
  await expect(requests.getByRole("row", { name: new RegExp(seeded) })).toContainText("Every estimator has answered");
  await requests.getByRole("link", { name: "Request estimates" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Request estimates");
  await expect(page.getByLabel("Title")).toHaveValue(`Estimates for ${phishing}`);
  const who = page.getByRole("group", { name: "Estimators to ask" });
  await expect(who.getByRole("checkbox")).toHaveCount(2);
  await expectAccessible(page, "the request form");

  // Every problem at once: nothing chosen.
  await page.getByRole("button", { name: "Send the request" }).click();
  await expect(page.getByRole("alert")).toContainText("Choose at least one factor and one estimator.");

  await page.getByLabel("Title").fill("Contact frequency, second opinion");
  await page.getByRole("group", { name: "Factors to estimate" }).getByLabel("Contact frequency").check();
  await who.getByLabel("Ellis Estimator").check();
  await page.getByRole("group", { name: "Scenario context to share" }).getByLabel("Description").uncheck();
  await page.getByRole("group", { name: "Reference classes to attach" }).getByLabel(/Ransomware incidents, claims division/).check();
  await page.getByRole("button", { name: "Send the request" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Contact frequency, second opinion");
  await expect(page.getByText(/at 90% confidence/)).toBeVisible();
  const status = page.getByRole("region", { name: "Factors and estimators" });
  await expect(status.getByRole("list", { name: "Estimators" })).toContainText("Ellis Estimator");
  await expect(status).toContainText("Ransomware incidents, claims division (version 1)");
  await expectAccessible(page, "a request");

  // AC-03: add an estimator, then cancel with a reason.
  const change = page.getByRole("region", { name: "Change the request" });
  await change.getByRole("group", { name: "Add estimators" }).getByLabel("Sam Okafor").check();
  await change.getByRole("button", { name: "Save the changes" }).click();
  await expect(change.getByRole("status")).toHaveText("The request was changed.");
  await expect(status.getByRole("list", { name: "Estimators" })).toContainText("Sam Okafor");
  await page.getByRole("button", { name: "Cancel the request" }).click();
  await page.getByRole("dialog").getByLabel("Reason").fill("Asked the wrong question");
  await page.getByRole("dialog").getByRole("button", { name: "Cancel the request" }).click();
  await expect(page.getByText("Cancelled: Asked the wrong question")).toBeVisible();
  await expect(page.getByRole("region", { name: "Change the request" })).toHaveCount(0);
});

test("reviewing answers side by side and accepting them, with provenance on the scenario (AC-15 to AC-19), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await openScenario(page, phishing);
  await page.getByRole("region", { name: "Estimate requests" }).getByRole("link", { name: seeded }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(seeded);

  // AC-15: answers, declines, calibration then, and the pools' previews.
  const answers = page.getByRole("region", { name: "Answers" });
  const cf = answers.getByRole("group", { name: "Contact frequency" });
  await expect(cf.getByRole("row", { name: /Ellis Estimator/ })).toContainText("2 – 5 – 10 events per year (90% confidence)");
  await expect(cf.getByRole("row", { name: /Sam Okafor/ })).toContainText("4 – 7 – 12 events per year");
  await expect(cf.getByRole("row", { name: /Sam Okafor/ })).toContainText("Not measured");
  await expect(cf).toContainText("3 – 6 – 11 (90%)");
  const response = answers.getByRole("group", { name: "Response" });
  await expect(response.getByRole("row", { name: /Ellis Estimator/ })).toContainText("Declined: Not my area");
  await expect(response.getByRole("row", { name: /Sam Okafor/ })).toContainText("40000 – 120000 – 500000 USD");
  await expectAccessible(page, "the answers");

  // AC-16, AC-19: contact frequency by the equal-weight pool now.
  const accept = page.getByRole("region", { name: "Accept into the scenario" });
  await accept.getByLabel("Accept contact frequency").check();
  await expect(accept.getByLabel("Method for contact frequency")).toHaveValue("equal");
  await accept.getByLabel("Change note").fill("Pooled the service desk's view");
  await expectAccessible(page, "the accept form");
  await accept.getByRole("button", { name: "Accept into a new version" }).click();
  await expect(accept.getByRole("status")).toContainText("Saved as version 2 of the scenario.");
  const factors = page.getByRole("region", { name: "Factors and estimators" });
  await expect(factors.getByRole("row", { name: /Contact frequency/ })).toContainText("Into version 2");
  await expect(factors.getByRole("row", { name: /Response/ })).toContainText("Not yet");

  // AC-18: the provenance on the scenario.
  await accept.getByRole("link", { name: "Open the scenario" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(phishing);
  const prov = page.getByRole("region", { name: "Estimates from experts" });
  await expect(prov).toContainText("Equal-weight pool: 3 – 6 – 11 events per year (90% confidence).");
  await expect(prov.getByRole("row", { name: /Ellis Estimator/ })).toContainText("2 – 5 – 10 (90%), revision 1");
  await expect(prov.getByRole("row", { name: /Sam Okafor/ })).toContainText("Not measured");
  await expect(prov.getByRole("link", { name: "estimate request" })).toBeVisible();
  await expectAccessible(page, "a scenario with provenance");
});

