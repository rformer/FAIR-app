import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-008 T-07 (AC-01 to AC-20): the acceptance pages against the real
// acceptance and register APIs and what db/tests/ui_harness_test.go seeds
// (seedAcceptances) inside the restricted R, at R1: "investigator" owns the
// risks and requests; "approver" and "approver2" approve at R. "Vendor data
// breach" is accepted with its renewal pending; "Records retention fine" is
// tier 2 with one of its two approvals; "Insider misuse of case files" is
// pending; "Case system outage" is accepted in treatment, not yet as a risk.
// WCAG 2.1 AA is checked with axe on every page.

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
  // Wait for the acknowledgement to be recorded: navigating before it is
  // would show the banner again.
  await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/api/v1/auth/banner/ack") && r.ok()),
    page.getByRole("button", { name: "Acknowledge and continue" }).click(),
  ]);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

async function openRisk(page: Page, title: string) {
  await page.goto("/register");
  await page.getByRole("region", { name: "Risks" }).getByRole("link", { name: title }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
}

test("the list, its filters and the register's acceptance column (AC-19, AC-20), accessibly", async ({ page }) => {
  await as(page, "investigator");
  await page.getByRole("link", { name: "Acceptances", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Risk acceptances");
  const list = page.getByRole("region", { name: "Acceptances" });
  await expect(list.getByRole("row", { name: /Vendor data breach \(renewal\)/ })).toContainText("Pending approval");
  await expect(list.getByRole("row", { name: /Records retention fine/ })).toContainText("1 of 2 approvals");
  await expectAccessible(page, "the acceptances");

  await list.getByLabel("State").selectOption({ label: "Accepted" });
  await list.getByRole("button", { name: "Apply" }).click();
  await expect(list.getByRole("link", { name: "Vendor data breach" })).toHaveCount(1);
  await expect(list.getByRole("link", { name: "Records retention fine" })).toHaveCount(0);
  await expectAccessible(page, "accepted acceptances");

  await page.goto("/register");
  const risks = page.getByRole("region", { name: "Risks" });
  await expect(risks.getByRole("row", { name: /Vendor data breach/ })).toContainText("Accepted");
  await risks.getByLabel("Acceptance").selectOption({ label: "Not accepted" });
  await risks.getByRole("button", { name: "Apply" }).click();
  await expect(risks.getByRole("link", { name: "Case system outage" })).toBeVisible();
  await expect(risks.getByRole("link", { name: "Vendor data breach" })).toHaveCount(0);
});

test("requesting acceptance of a risk (AC-01, AC-02, AC-04), accessibly", async ({ page }) => {
  await as(page, "investigator");
  await openRisk(page, "Case system outage");
  const section = page.getByRole("region", { name: "Acceptance" });
  await expect(section).toContainText("Not accepted yet");
  await expectAccessible(page, "a risk to accept");
  await section.getByRole("link", { name: "Request acceptance" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Request acceptance");
  await expect(page.getByRole("region", { name: "Approval" })).toContainText("Tier");
  await expectAccessible(page, "the request form");

  await page.getByRole("button", { name: "Request acceptance" }).click();
  await expect(page.getByRole("alert")).toContainText("A justification is required.");
  await page.getByLabel("Justification").fill("Recovery within a day is within appetite.");
  await page.getByLabel("Conditions (optional)").fill("Test the recovery plan twice a year.");
  const soon = new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10);
  await page.getByLabel("Expires on").fill(soon);
  await page.getByRole("button", { name: "Request acceptance" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Acceptance of Case system outage");
  await expect(page.locator(".lede")).toContainText("Pending approval");
  const terms = page.getByRole("region", { name: "Terms" });
  await expect(terms).toContainText("Recovery within a day is within appetite.");
  await expect(terms).toContainText(soon);
  await expect(page.getByRole("region", { name: "History" }).getByRole("row", { name: /Requested.*Ines Investigator/ })).toBeVisible();
  // The requester cannot decide; may withdraw.
  await expect(page.getByRole("region", { name: "Your decision" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Withdraw" })).toBeVisible();
  await expectAccessible(page, "a pending acceptance");

  await openRisk(page, "Case system outage");
  await expect(page.getByRole("region", { name: "Acceptance" })).toContainText("Pending approval");
  await expect(page.getByRole("region", { name: "Acceptance" }).getByRole("link", { name: "Request acceptance" })).toHaveCount(0);
});

test("the approver's inbox and a decision (AC-05 to AC-08, AC-16), accessibly", async ({ page }) => {
  await as(page, "approver");
  await page.goto("/acceptances");
  await page.getByRole("link", { name: "Waiting for your decision" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Waiting for your decision");
  const inbox = page.getByRole("region", { name: "Requests" });
  await expect(inbox.getByRole("link", { name: "Insider misuse of case files" })).toBeVisible();
  await expect(inbox.getByRole("link", { name: "Vendor data breach" })).toBeVisible();
  // Already approved by this approver in its round.
  await expect(inbox.getByRole("link", { name: "Records retention fine" })).toHaveCount(0);
  await expectAccessible(page, "the inbox");

  await inbox.getByRole("link", { name: "Insider misuse of case files" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Acceptance of Insider misuse of case files");
  const evidence = page.getByRole("region", { name: "Evidence" });
  await expect(evidence).toContainText("Current");
  await expect(evidence.getByRole("link", { name: "Analysis run" })).toBeVisible();
  const decide = page.getByRole("region", { name: "Your decision" });
  await expectAccessible(page, "an acceptance to decide");
  await decide.getByRole("button", { name: "Record the decision" }).click();
  await expect(decide.getByRole("alert")).toContainText("A rationale is required.");
  await decide.getByLabel("Rationale").fill("Proportionate; the access logging is in place.");
  await decide.getByRole("button", { name: "Record the decision" }).click();
  await expect(page.locator(".lede")).toContainText("Accepted");
  await expect(page.getByRole("region", { name: "Your decision" })).toHaveCount(0);
  const history = page.getByRole("region", { name: "History" });
  await expect(history.getByRole("row", { name: /Approved.*Ada Approver.*Proportionate/ })).toBeVisible();
  await expect(history.getByRole("row", { name: /^Accepted/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke" })).toBeVisible();
  await expectAccessible(page, "an accepted risk");
});

test("a two-approval tier and a renewal without a gap (AC-06, AC-07, AC-11), accessibly", async ({ page }) => {
  await as(page, "approver2");
  await page.goto("/acceptances/inbox");
  const inbox = page.getByRole("region", { name: "Requests" });
  await inbox.getByRole("link", { name: "Records retention fine" }).click();
  const decide = page.getByRole("region", { name: "Your decision" });
  await expect(decide).toContainText("needs 2 approvals from different approvers; 1 given so far");
  await expect(page.getByRole("region", { name: "Terms" })).toContainText("1 of 2");
  await decide.getByLabel("Rationale").fill("Second approval: the retention schedule is approved.");
  await decide.getByRole("button", { name: "Record the decision" }).click();
  await expect(page.locator(".lede")).toContainText("Accepted");
  await expect(page.getByRole("region", { name: "History" }).getByRole("row", { name: /^Approved/ })).toHaveCount(2);
  await expectAccessible(page, "a tier-2 acceptance");

  await page.goto("/acceptances/inbox");
  await inbox.getByRole("link", { name: "Vendor data breach" }).click();
  await expect(page.getByRole("link", { name: "The acceptance it renews" })).toBeVisible();
  await page.getByRole("region", { name: "Your decision" }).getByLabel("Rationale").fill("Renewed: the vendor's audit report is clean.");
  await page.getByRole("region", { name: "Your decision" }).getByRole("button", { name: "Record the decision" }).click();
  await expect(page.locator(".lede")).toContainText("Accepted");
  await page.getByRole("link", { name: "The acceptance it renews" }).click();
  await expect(page.locator(".lede")).toContainText("Replaced by its renewal");
  await expectAccessible(page, "a replaced acceptance");
});

test("withdrawing a request and the renewal form (AC-03, AC-11), accessibly", async ({ page }) => {
  await as(page, "investigator");
  await page.goto("/acceptances");
  const list = page.getByRole("region", { name: "Acceptances" });
  await list.getByRole("link", { name: "Case system outage" }).click();
  await page.getByRole("button", { name: "Withdraw" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Reason").fill("The recovery plan is being revised.");
  await dialog.getByRole("button", { name: "Withdraw" }).click();
  await expect(page.locator(".lede")).toContainText("Withdrawn");
  await expect(page.getByRole("region", { name: "History" }).getByRole("row", { name: /Withdrawn.*revised/ })).toBeVisible();

  await openRisk(page, "Insider misuse of case files");
  await page.getByRole("region", { name: "Acceptance" }).getByRole("link", { name: /Accepted/ }).click();
  await page.getByRole("link", { name: "Renew" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Renew the acceptance");
  await expect(page.getByLabel("Justification")).toHaveValue("Within appetite; the controls in place are proportionate.");
  await expectAccessible(page, "the renewal form");
});
