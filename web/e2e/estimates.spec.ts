import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-004 T-12 (AC-05, AC-07 to AC-12, AC-14): the estimator's pages against
// the real estimate API and what db/tests/ui_harness_test.go seeds: an
// estimator at the root ("estimator", Estimator only) addressed by a request
// on "Ransomware on the claims platform" for contact frequency and response
// costs, with a reference class of the organization's own incident counts.
// WCAG 2.1 AA is checked with axe on every view (constitution Q3).

let problems: string[] = [];
test.beforeEach(({ page }) => {
  problems = [];
  page.on("console", (m) => {
    if (m.type() === "error" && /Content Security Policy/.test(m.text()))
      problems.push(`CSP violation: ${m.text()}`);
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
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(
    results.violations.map(
      (v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`,
    ),
    what,
  ).toEqual([]);
}

const seeded = "Contact frequency and response costs";

test("the inbox and a request's context and reference data (AC-05, AC-07, AC-14), accessibly", async ({
  page,
}) => {
  await as(page, "estimator");
  await page
    .getByRole("link", { name: "Estimate requests", exact: true })
    .click();
  await expect(page).toHaveURL("/estimates");
  const row = page.getByRole("row", { name: new RegExp(seeded) });
  await expect(row).toContainText("Ransomware on the claims platform");
  await expect(row).toContainText("0 of 2");
  await expect(row).toContainText("Open");
  await expectAccessible(page, "the inbox");

  await row.getByRole("link", { name: seeded }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(seeded);
  await expect(page).toHaveTitle(
    `${seeded} · Estimate requests · FAIR Risk Platform`,
  );
  await expect(page.getByText("answer at 90% confidence")).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Instructions" }),
  ).toContainText("service desk");
  const context = page.getByRole("region", {
    name: "What the estimates are about",
  });
  await expect(context).toContainText("Ransomware on the claims platform");
  // AC-14: the customer's own data, said to be so.
  const refs = page.getByRole("region", { name: "Reference data" });
  await expect(refs).toContainText("not industry data");
  await expect(refs).toContainText("Ransomware incidents, claims division");
  await expect(refs).toContainText("5 events in 3 periods, about 1.7 a year");
  await expect(
    page.getByRole("region", { name: "Contact frequency" }),
  ).toBeVisible();
  await expect(page.getByRole("region", { name: "Response" })).toBeVisible();
  await expectAccessible(page, "a request");
});

test("the aids, drafts, a decline and submission (AC-08 to AC-12)", async ({
  page,
}) => {
  await as(page, "estimator");
  await page.goto("/estimates");
  await page.getByRole("link", { name: seeded }).click();
  const cf = page.getByRole("region", { name: "Contact frequency" });
  await cf.getByLabel("Minimum").fill("2");
  await cf.getByLabel("Most likely").fill("2");
  await cf.getByLabel("Maximum").fill("12");
  await cf.getByLabel("Confidence (0 to 1)").fill("0.8");
  // AC-11, AC-12: advice, never a refusal; the bet; the illustrative curve.
  const advice = cf.getByRole("list", { name: "Advice on this estimate" });
  await expect(advice).toContainText("at a bound of the range");
  await expect(advice).toContainText(
    "The request asks for 90% confidence; this estimate states 80%.",
  );
  await expect(
    cf.getByText(
      /Would you rather win a prize if the true value is between 2 and 12/,
    ),
  ).toBeVisible();
  await expect(
    cf.getByRole("img", { name: /Illustrative curve of the range/ }),
  ).toBeVisible();
  await expectAccessible(page, "an estimate with the aids");
  await cf.getByLabel("Confidence (0 to 1)").fill("0.9");
  await expect(advice).not.toContainText("asks for 90% confidence");
  await cf
    .getByLabel("Rationale")
    .fill("Service desk tickets for the last two years.");
  await cf.getByLabel("Source 1", { exact: true }).fill("Service desk queue");

  // AC-09: a draft only the estimator sees.
  await page.getByRole("button", { name: "Save drafts" }).click();
  await expect(page.getByRole("status")).toHaveText(
    "Drafts saved: only you can see them.",
  );
  await page.reload();
  await expect(
    page.getByRole("region", { name: "Contact frequency" }),
  ).toContainText("revision 1, a draft only you can see");
  await expect(
    page
      .getByRole("region", { name: "Contact frequency" })
      .getByLabel("Maximum"),
  ).toHaveValue("12");

  // AC-10: declining a factor, with a reason; then submitting both.
  const response = page.getByRole("region", { name: "Response" });
  await response.getByLabel("Decline this factor").check();
  await response
    .getByLabel("Why you decline")
    .fill("Response costs are finance's, not mine.");
  await page.getByRole("button", { name: "Submit answers" }).click();
  await expect(page.getByRole("status")).toHaveText("Submitted 2 answers.");
  await expect(page.getByText("You have answered every factor")).toBeVisible();
  await page.goto("/estimates");
  await expect(
    page.getByRole("row", { name: new RegExp(seeded) }),
  ).toContainText("2 of 2");
});

test("someone addressed by no request (AC-05)", async ({ page }) => {
  await as(page, "nobody");
  await page.goto("/estimates");
  await expect(
    page.getByText("No estimate requests are addressed to you."),
  ).toBeVisible();
  await expectAccessible(page, "an empty inbox");
});
