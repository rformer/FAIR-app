import { readFile, writeFile } from "node:fs/promises";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-003 T-13 (AC-24, AC-25): export a business unit's risk data as a
// fair.risk.v1 file and import it, dry run first. Runs last: the import adds
// copies of what the other specs expect to find once.

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

test("export a subtree, then import it with a dry run first (AC-24, AC-25), accessibly", async ({ page }, info) => {
  await as(page, "riskanalyst");
  await page.goto("/scenarios");
  await page.getByRole("link", { name: "Export or import" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Export and import");
  await expectAccessible(page, "the export and import page");

  const exp = page.getByRole("region", { name: "Export" });
  await exp.getByLabel("Business unit").selectOption({ label: "Enterprise" });
  const download = page.waitForEvent("download");
  await exp.getByRole("button", { name: "Download the export" }).click();
  const file = await download;
  await expect(exp.getByRole("status")).toContainText(/SHA-256 of the file: [0-9a-f]{64}/);
  const path = info.outputPath("export.json");
  await file.saveAs(path);
  const parsed = JSON.parse(await readFile(path, "utf8")) as { format: string };
  expect(parsed.format).toBe("fair.risk.v1");

  const imp = page.getByRole("region", { name: "Import" });
  await imp.getByLabel("Into business unit").selectOption({ label: "Claims" });
  await expect(imp.getByRole("button", { name: "Import" })).toBeDisabled();
  await imp.getByLabel("fair.risk.v1 file").setInputFiles(path);
  await imp.getByRole("button", { name: "Check the file (dry run)" }).click();
  await expect(imp.getByRole("status")).toContainText("nothing has been written yet");
  await expect(imp.getByRole("cell", { name: "Would be created" }).first()).toBeVisible();
  await expectAccessible(page, "a dry run");
  await imp.getByRole("button", { name: "Import" }).click();
  await expect(imp.getByRole("heading", { name: "Imported" })).toBeVisible();
  await expect(imp.getByRole("link", { name: "Created" }).first()).toBeVisible();

  // A file that is not fair.risk.v1 lists its problems and imports nothing.
  const bad = info.outputPath("bad.json");
  await writeFile(bad, JSON.stringify({ format: "fair.risk.v0" }));
  await imp.getByLabel("fair.risk.v1 file").setInputFiles(bad);
  await imp.getByRole("button", { name: "Check the file (dry run)" }).click();
  await expect(imp.getByRole("alert")).toBeVisible();
  await expect(imp.getByRole("button", { name: "Import" })).toBeDisabled();
});
