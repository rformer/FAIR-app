import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-011 T-18 (F-011-AC-20 to AC-22; design §3.6): importing a risk register
// from a CSV file, as "riskowner" (Risk Owner at Enterprise; see
// db/tests/ui_harness_integrations_test.go). It runs after register.spec.ts
// (the specs run in name order): the risks it creates would change that
// spec's coverage counts. WCAG 2.1 AA is checked with axe.

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
  await expect(page.getByRole("heading", { level: 1 })).not.toHaveText("System use notification");
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

test("importing a register: every column mapped, ratings refused, a dry run first (AC-20 to AC-22), accessibly", async ({ page }) => {
  await as(page, "riskowner");
  await page.goto("/register");
  await page.getByRole("link", { name: "Import a register" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Import a register");
  await page.getByLabel("Source name").fill("2026 ERM register");
  await page.getByLabel("CSV file").setInputFiles({
    name: "erm.csv",
    mimeType: "text/csv",
    buffer: Buffer.from("Ref,Risk,Detail,Heat\nERM-1,Vendor concentration,Two vendors run claims intake,High\nERM-2,Key person loss,One actuary prices flood,Medium\n"),
  });
  const columns = page.getByRole("group", { name: "What each column holds" });
  await columns.getByLabel("Ref").selectOption("external_id");
  await columns.getByLabel("Risk").selectOption("title");
  await columns.getByLabel("Detail").selectOption("description");
  await columns.getByLabel("Heat").selectOption("rating");
  await expectAccessible(page, "the register import");
  await page.getByRole("button", { name: "Check the file (dry run)" }).click();
  const dry = page.getByRole("region", { name: "What importing would do" });
  await expect(dry).toContainText("Refused columns, not imported: Heat.");
  await page.getByRole("button", { name: "Import" }).click();
  await expect(page.getByText("Imported: 2 risks created, 0 changes proposed for review.")).toBeVisible();
  await page.goto("/register?status=unquantified");
  await expect(page.getByRole("link", { name: "Vendor concentration" })).toBeVisible();
});
