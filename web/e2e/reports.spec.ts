import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";

// F-010 T-17 (F-010-AC-01 to AC-07, AC-15 to AC-19; design §6): the report
// pages against the real API, the real report worker and the real engine,
// as db/tests/ui_harness_reports_test.go seeds them: "publisher"
// (Executive Viewer and Report Publisher at Enterprise) with a roll-up of
// Enterprise, two snapshots a week apart, a register report and a weekly
// portfolio schedule; "investigator" publishes reports at the restricted R,
// where export.reason_required is on. WCAG 2.1 AA is checked with axe on
// every page.

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
  await expect(page.getByRole("heading", { level: 1 })).not.toHaveText("System use notification");
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

test("the dashboard: exposure as a distribution, the largest risks, coverage, what is left out, trends (AC-01 to AC-07), accessibly", async ({ page }) => {
  await as(page, "publisher");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Reports" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Portfolio dashboard");
  await page.getByLabel("Business unit (with everything below it)").selectOption({ label: "Enterprise" });

  const exposure = page.getByRole("region", { name: "Exposure" });
  await expect(exposure.getByText("Mean annual loss")).toBeVisible();
  await expect(exposure.getByText("1 year in 10 is above (90th percentile)")).toBeVisible();
  await expect(exposure.getByRole("link", { name: /your roll-up of/ })).toBeVisible();
  await expect(exposure.getByRole("figure", { name: "Loss exceedance, roll-up of Enterprise" })).toBeVisible();
  // AC-02: nothing is scored.
  await expect(page.getByText(/heat map|rating|score/i)).toHaveCount(0);

  const largest = page.getByRole("region", { name: "Largest open risks" });
  await expect(largest.getByRole("link", { name: "Claims platform outage and fraud" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Coverage" }).getByRole("link", { name: "Unquantified" })).toHaveAttribute("href", /\/register\?bu=.*&status=unquantified/);
  await expect(page.getByRole("region", { name: "Acceptances" }).getByRole("link", { name: "Expiring within 30 days" })).toBeVisible();

  // AC-04: the restricted R is aggregate only: totals, never its risks.
  const left = page.getByRole("region", { name: "What this leaves out" });
  await expect(left).toContainText("Restricted business units (totals only)");
  await expect(left).toContainText("Their risks are not shown.");
  await expect(page.getByRole("link", { name: "Investigations data leak" })).toHaveCount(0);

  // AC-07: two snapshots; the first before the roll-up, the second after.
  const trend = page.getByRole("region", { name: "Over time" });
  const exp = trend.getByRole("figure", { name: "Exposure over time" });
  await expect(exp).toContainText("2 snapshots from");
  await exp.getByRole("button", { name: "Show data table" }).click();
  const rows = exp.getByRole("table").getByRole("row");
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(1)).toContainText("No roll-up you can see");
  await expect(trend.getByRole("figure", { name: "Coverage over time" })).toBeVisible();
  await expectAccessible(page, "the dashboard");

  // AC-05: a child unit's figures link to its own dashboard.
  const children = page.getByRole("region", { name: "Business units below" });
  await children.getByRole("link", { name: "Claims", exact: true }).click();
  await expect(page.getByLabel("Business unit (with everything below it)")).toHaveValue(/[0-9a-f-]{36}/);
  await expect(page.getByRole("region", { name: "Largest open risks" })).toBeVisible();
});

test("a register report: requested, generated in the background, downloaded with its digest (AC-14, AC-15, AC-17), accessibly", async ({ page }) => {
  test.setTimeout(180_000);
  await as(page, "publisher");
  await page.goto("/reports/new");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Generate a report");
  await expectAccessible(page, "the report form");
  const form = page.getByRole("form", { name: "The report to generate" });
  await form.getByLabel("Report", { exact: true }).selectOption({ label: "Risk register" });
  await form.getByLabel("Business unit (with everything below it)").selectOption({ label: "Enterprise" });
  await form.getByLabel("Exposure status").selectOption({ label: "Current" });
  await form.getByLabel("JSON (fair.report.v1)").check();
  // Enterprise's subtree holds the restricted R: a reason, given in the form.
  await form.getByLabel("Reason").fill("Risk committee pack");
  await form.getByRole("button", { name: "Generate" }).click();

  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Risk register report of Enterprise");
  await expect(page.locator(".lede")).toContainText("Ready", { timeout: 120_000 });
  await expect(page.getByRole("region", { name: "About this report" })).toContainText("exposure current");
  await expect(page.getByRole("region", { name: "About this report" })).toContainText("Risk committee pack");
  const files = page.getByRole("region", { name: "Files" });
  const pdfRow = files.getByRole("row", { name: /^PDF/ });
  const digest = (await pdfRow.locator(".mono").textContent()) ?? "";
  expect(digest).toMatch(/^[0-9a-f]{64}$/);
  await expect(files.getByRole("row", { name: /^JSON/ })).toBeVisible();
  await expectAccessible(page, "a ready report");

  const download = page.waitForEvent("download");
  await pdfRow.getByRole("button", { name: "Download PDF" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe("report.pdf");
  const body = await readFile((await file.path()) ?? "");
  expect(body.subarray(0, 5).toString("latin1")).toBe("%PDF-");
  await expect(files.getByRole("status")).toContainText(`SHA-256 of the file: ${digest}`);

  await page.getByRole("link", { name: "My reports" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("My reports");
  const mine = page.getByRole("table", { name: "Your reports, newest first" });
  await expect(mine.getByRole("row").filter({ hasText: "Risk register" })).toHaveCount(2);
  await expect(mine.getByRole("row").nth(1)).toContainText("exposure current");
  await expectAccessible(page, "my reports");
});

test("a report in a restricted subtree asks for a reason and records it (AC-16), accessibly", async ({ page }) => {
  test.setTimeout(180_000);
  await as(page, "investigator");
  const bus = (await (await page.request.get("/api/v1/reports/bus?permission=report.export")).json()) as { bus: { id: string; code: string; name: string }[] };
  const r = bus.bus.find((b) => b.code === "R");
  expect(r).toBeDefined();
  await page.goto("/reports/new");
  const form = page.getByRole("form", { name: "The report to generate" });
  await form.getByLabel("Report", { exact: true }).selectOption({ label: "Treatment" });
  await form.getByLabel("Business unit (with everything below it)").selectOption(r!.id);
  await form.getByRole("button", { name: "Generate" }).click();

  const dialog = page.getByRole("dialog", { name: "Why are you taking this data out?" });
  await expect(dialog).toBeVisible();
  await expectAccessible(page, "the reason prompt");
  await dialog.getByLabel("Reason for the export").fill("Quarterly review of the investigations unit");
  await dialog.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Treatment report of ${r!.name}`);
  await expect(page.getByRole("region", { name: "About this report" })).toContainText("Quarterly review of the investigations unit");
  await expect(page.locator(".lede")).toContainText(/Ready|Failed/, { timeout: 120_000 });
  await expect(page.locator(".lede")).toContainText("Ready");
});

test("a results download in a restricted subtree asks for a reason first (F-006; AC-16)", async ({ page }) => {
  test.setTimeout(120_000);
  await as(page, "investigator");
  await page.goto("/scenarios");
  await page.getByRole("link", { name: "Investigations data leak", exact: true }).click();
  const runs = page.getByRole("region", { name: "Simulations" });
  await runs.getByRole("button", { name: /^Details/ }).first().click();
  await page.getByRole("link", { name: "Charts and comparisons of this run" }).click();
  const curves = page.getByRole("figure", { name: "Loss exceedance curves" });
  await curves.getByRole("button", { name: "Download CSV" }).click();
  const dialog = page.getByRole("dialog", { name: "Why are you taking this data out?" });
  await dialog.getByLabel("Reason for the export").fill("Shared with the investigations lead");
  const download = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Continue" }).click();
  const csv = await download;
  expect(csv.suggestedFilename()).toMatch(/-curve\.csv$/);

  // Closing the prompt downloads nothing, and says so.
  await curves.getByRole("button", { name: "Download CSV" }).click();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(curves.getByRole("alert")).toHaveText("No reason was given, so nothing was exported.");
});

test("schedules: listed, created, changed and deleted by their owner (AC-19), accessibly", async ({ page }) => {
  await as(page, "publisher");
  await page.goto("/reports/schedules");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Scheduled reports");
  const list = page.getByRole("table", { name: "Your scheduled reports" });
  await expect(list.getByRole("row", { name: /Portfolio/ })).toContainText("Every Monday at 06:00 UTC");
  await expectAccessible(page, "the schedules");

  await page.getByRole("link", { name: "Schedule a report" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Schedule a report");
  const form = page.getByRole("form", { name: "The report to schedule" });
  await form.getByLabel("Report", { exact: true }).selectOption({ label: "Treatment" });
  await form.getByLabel("Business unit (with everything below it)").selectOption({ label: "Enterprise" });
  await form.getByLabel("Every", { exact: true }).selectOption({ label: "Month" });
  await form.getByLabel("On day").selectOption("15");
  await form.getByLabel("At (UTC)").selectOption({ label: "07:00" });
  await form.getByLabel("Reason").fill("Monthly treatment review");
  await expectAccessible(page, "the schedule form");
  await form.getByRole("button", { name: "Schedule" }).click();

  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Treatment report of Enterprise, scheduled");
  await expect(page.locator(".lede")).toContainText("On day 15 of every month at 07:00 UTC");
  await expectAccessible(page, "a schedule");
  await page.getByRole("button", { name: "Change" }).click();
  const change = page.getByRole("form", { name: "Change the schedule" });
  await change.getByLabel("At (UTC)").selectOption({ label: "08:00" });
  await change.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved." })).toBeVisible();
  await expect(page.locator(".lede")).toContainText("On day 15 of every month at 08:00 UTC");

  await page.getByRole("button", { name: "Delete" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Reason for deleting it").fill("The committee meets weekly now");
  await dialog.getByRole("button", { name: "Delete the schedule" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Scheduled reports");
  await expect(page.getByRole("table", { name: "Your scheduled reports" }).getByRole("row", { name: /Treatment/ })).toHaveCount(0);
});

test("another user's report is not found (AC-15)", async ({ page }) => {
  await as(page, "publisher");
  const mine = (await (await page.request.get("/api/v1/reports")).json()) as { reports: { id: string }[] };
  const id = mine.reports[0]?.id ?? "";
  await as(page, "investigator");
  await page.goto(`/reports/${id}`);
  await expect(page.getByRole("alert")).toHaveText("Not found, or not visible to you.");
  await expectAccessible(page, "a report not found");
});
