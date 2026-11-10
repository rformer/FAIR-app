import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-004 T-14 (AC-20 to AC-27): the calibration pages against the real API
// and the shipped question bank: an exercise of 20 questions (10 ranges, 10
// true or false) taken by keyboard with no time limit, the feedback after
// submitting, the person's own record, and question set administration by
// a holder of calibration.manage ("admin"). WCAG 2.1 AA is checked with axe
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

test("an exercise by keyboard, its feedback, and the person's record (AC-20 to AC-23, AC-27), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.getByRole("link", { name: "Calibration", exact: true }).click();
  await expect(page).toHaveURL("/calibration");
  await expect(page.getByRole("region", { name: "Your score" })).toContainText("Not measured yet");
  // Only managers see the question sets.
  await expect(page.getByRole("link", { name: "Question sets" })).toHaveCount(0);
  await expectAccessible(page, "the calibration record");

  await page.getByRole("button", { name: "Start an exercise" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Calibration exercise");
  await expect(page.getByText("There is no time limit")).toBeVisible();
  const lows = page.getByLabel(/^Question \d+ low$/);
  const confidences = page.getByLabel(/^Question \d+ confidence$/);
  await expect(lows).toHaveCount(10);
  await expect(confidences).toHaveCount(10);
  // AC-21: no answer is in the page before submitting.
  await expect(page.getByText(/^Source:/)).toHaveCount(0);
  await expectAccessible(page, "an exercise");

  await page.getByRole("button", { name: "Submit the exercise" }).click();
  await expect(page.getByRole("alert")).toHaveText("Answer every question first: 20 still open.");

  // By keyboard: type into each field, Space on the radio, arrows in the select (two steps: 60%).
  for (let i = 1; i <= 20; i++) {
    const low = page.getByLabel(`Question ${i} low`);
    if ((await low.count()) > 0) {
      await low.focus();
      await page.keyboard.type("-1000000000000");
      await page.keyboard.press("Tab");
      await page.keyboard.type("1000000000000000");
    } else {
      await page.getByRole("group", { name: `Question ${i}: true or false` }).getByLabel("True").focus();
      await page.keyboard.press("Space");
      await page.getByLabel(`Question ${i} confidence`).focus();
      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("ArrowDown");
    }
  }
  await page.getByRole("button", { name: "Submit the exercise" }).focus();
  await page.keyboard.press("Enter");

  // AC-22: each answer against the truth with its source, hits against 90%, accuracy against confidence, the bet.
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Your results");
  const summary = page.getByRole("region", { name: "This exercise" });
  await expect(summary).toContainText(/\d+ of 10 held the truth; at 90% you would expect about 9/);
  await expect(summary).toContainText(/\d+ of 10 correct; your stated confidence expected about 6/);
  await expect(summary).toContainText("would you rather win a prize");
  const answers = page.getByRole("region", { name: "Answers" });
  await expect(answers.getByText(/^Source:/)).toHaveCount(20);
  await expect(answers.getByText(/You said true at 60%/)).toHaveCount(10);
  await expect(page.getByRole("region", { name: "Your score now" })).toContainText("Class");
  await expectAccessible(page, "the feedback");

  // AC-23, AC-27: the record now has the exercise and a score.
  await answers.getByRole("link", { name: "Back to your record" }).click();
  await expect(page.getByRole("region", { name: "Score history" }).getByRole("row")).toHaveCount(2);
  const exercises = page.getByRole("region", { name: "Your exercises" });
  await expect(exercises.getByRole("row", { name: /Submitted/ })).toHaveCount(1);
  await exercises.getByRole("row", { name: /Submitted/ }).getByRole("link").click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Your results");
});

test("question sets: the shipped set read-only, a custom set built, edited and activated (AC-24 to AC-26), accessibly", async ({ page }) => {
  await as(page, "admin");
  await page.goto("/calibration");
  await page.getByRole("link", { name: "Question sets" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Question sets");
  const shipped = page.getByRole("row", { name: /Shipped \(release/ });
  await expect(shipped).toContainText("120");
  await expect(shipped).toContainText("Active");
  await expectAccessible(page, "the question sets");
  await shipped.getByRole("link").click();
  await expect(page.getByText(/^Shipped set, release .*: read-only/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Activate the set" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Add a question" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Questions" }).getByText(/^Answer:/).first()).toBeVisible();

  await page.goto("/calibration/question-sets");
  await page.getByLabel("Name", { exact: true }).fill("Claims operations");
  await page.getByRole("button", { name: "Create the set" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Claims operations");
  await expect(page.getByText("Draft", { exact: true })).toBeVisible();
  const add = page.getByRole("region", { name: "Add a question" });
  await add.getByLabel("Question", { exact: true }).fill("How many claims did the claims division settle in 2024?");
  await add.getByLabel("Answer (a number)").fill("48210");
  await add.getByLabel("Unit (optional)").fill("claims");
  await add.getByLabel("Source").fill("Claims annual report 2024, page 3");
  await add.getByRole("button", { name: "Add the question" }).click();
  await expect(page.getByRole("status")).toHaveText("The question was added.");
  await add.getByLabel("A true-or-false statement").check();
  await add.getByLabel("Statement", { exact: true }).fill("The claims platform moved to the new data centre in 2023.");
  await add.getByLabel("Answer", { exact: true }).selectOption("false");
  await add.getByLabel("Source").fill("Infrastructure change record CHG-2041");
  await add.getByRole("button", { name: "Add the question" }).click();
  const questions = page.getByRole("region", { name: "Questions" });
  await expect(questions.getByRole("listitem")).toHaveCount(2);
  await expectAccessible(page, "a custom set");

  // Editing saves a new version; retiring takes a question out of new exercises.
  await questions.getByRole("button", { name: /^Edit: How many claims/ }).click();
  await questions.getByLabel("Answer (a number)").fill("48211");
  await questions.getByRole("button", { name: "Save a new version" }).click();
  await expect(page.getByRole("status")).toHaveText("The question was saved as a new version.");
  await expect(questions.getByRole("listitem").filter({ hasText: "How many claims" })).toContainText("version 2");
  await expect(questions.getByRole("listitem").filter({ hasText: "How many claims" })).toContainText("Answer: 48211.");
  await questions.getByRole("button", { name: /^Retire: The claims platform/ }).click();
  await expect(questions.getByRole("listitem").filter({ hasText: "The claims platform" })).toContainText("Retired");

  await page.getByRole("button", { name: "Activate the set" }).click();
  await expect(page.getByRole("status")).toHaveText("The set is active: new exercises draw from it.");
  await expect(page.getByText("Active", { exact: true })).toBeVisible();
});

test("without calibration.manage the question sets are not shown (AC-26)", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/calibration/question-sets");
  await expect(page.getByText("Question sets are managed by holders of calibration.manage.")).toBeVisible();
  await expectAccessible(page, "question sets refused");
});
