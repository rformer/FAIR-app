import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-015 T-32 (AC-43, AC-44): the Posture page against the real Posture API
// and the scenario db/tests/ui_harness_test.go seeds. WCAG 2.1 AA is checked
// with axe on every view (constitution Q3).

// Every page must run under the UI's CSP without violations and without
// script errors.
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
  await expect(page.getByRole("heading", { level: 1, name: "Security posture" })).toBeVisible();
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

function section(page: Page, name: string) {
  return page.getByRole("region", { name });
}

test("an auditor sees every part of the posture (AC-43), accessibly", async ({ page }) => {
  await as(page, "auditor");

  // The persistent warning while Kubernetes access is undecided (AC-40).
  await expect(page.getByRole("region", { name: "Deployment drift detection warning" })).toContainText("has not been decided");

  const profile = section(page, "Profile and conformance");
  await expect(profile).toContainText("Enterprise Baseline");
  await expect(profile.getByRole("list", { name: "Conformance" })).toContainText("under an approved exception");

  const deviations = section(page, "Deviations and exceptions");
  await expect(deviations.getByRole("row", { name: /tls\.min_version/ })).toContainText("Below hard floor");
  await expect(deviations.getByRole("row", { name: /auth\.lockout_threshold/ }).first()).toContainText("Exception");
  const exceptionRow = deviations.getByRole("table").nth(1).getByRole("row", { name: /auth\.lockout_threshold/ });
  await expect(exceptionRow).toContainText("legacy kiosk accounts");
  await expect(exceptionRow.getByRole("button", { name: "Renew" })).toBeVisible();

  const expiries = section(page, "Upcoming expiries and recent reverts");
  await expect(expiries).toContainText(/auth\.lockout_threshold expires .* \(10 days\)/);
  await expect(expiries).toContainText("token.max_lifetime reverted to the profile value");

  const sw = section(page, "Pending profile switch");
  await expect(sw).toContainText("fedramp-moderate@1.1.0");
  await expect(sw.getByRole("row", { name: /session\.idle_timeout/ })).toContainText("unresolved");

  const drift = section(page, "Drift findings");
  await expect(drift.getByRole("row", { name: /hard_floor_violation/ })).toContainText("critical");
  await expect(drift.getByRole("row", { name: /row_mac_mismatch/ })).toContainText("open");

  const k8s = section(page, "Kubernetes access");
  await expect(k8s).toContainText("undecided");
  await expect(k8s.getByRole("row", { name: /Nodes run in FIPS mode/ })).toContainText("Not assessed");

  const controls = section(page, "Per-control status");
  await expect(controls.getByRole("row", { name: /^CM-6\b/ })).toContainText("Open finding");
  await expect(controls.getByRole("row", { name: /^SC-8\b/ })).toContainText("Not assessed");
  await expect(controls.getByRole("row", { name: /^AC-7\b/ })).toContainText("Exception");
  await expect(controls.getByRole("row", { name: /^SC-28\b/ })).toContainText("Not assessed");

  // AC-44: audit history links for every item.
  await expect(deviations.getByRole("link", { name: "Audit history of tls.min_version" })).toHaveAttribute(
    "href",
    "/audit?target=setting%3Atls.min_version",
  );
  await expect(sw.getByRole("link", { name: "Audit history" })).toHaveAttribute("href", /^\/audit\?target=switch%3A/);

  await expectAccessible(page, "the Posture page");
});

test("acknowledging a drift finding by keyboard (AC-44 action)", async ({ page }) => {
  await as(page, "admin");
  const drift = section(page, "Drift findings");
  const row = drift.getByRole("row", { name: /hard_floor_violation/ });
  const trigger = row.getByRole("button", { name: "Acknowledge" });

  // Escape closes the dialog and returns focus to the button.
  await trigger.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", { name: /Acknowledge hard_floor_violation/ });
  await expect(dialog).toBeVisible();
  await expectAccessible(page, "the acknowledge dialog");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();

  // A reason is required.
  await trigger.focus();
  await page.keyboard.press("Enter");
  await dialog.getByRole("button", { name: "Acknowledge finding" }).focus();
  await page.keyboard.press("Enter");
  await expect(dialog).toBeVisible();

  await dialog.getByLabel("Reason").focus();
  await page.keyboard.type("Change ticket CHG-4711: restoring TLS 1.2");
  await dialog.getByRole("button", { name: "Acknowledge finding" }).focus();
  await page.keyboard.press("Enter");
  await expect(dialog).toBeHidden();
  await expect(row).toContainText("acknowledged");
  await expect(row).toContainText("Change ticket CHG-4711");
});

test("an action the user may not take reports the refusal", async ({ page }) => {
  await as(page, "auditor");
  const row = section(page, "Drift findings").getByRole("row", { name: /row_mac_mismatch/ }).first();
  await row.getByRole("button", { name: "Acknowledge" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Reason").fill("seen");
  await dialog.getByRole("button", { name: "Acknowledge finding" }).click();
  await expect(dialog.getByRole("alert")).toContainText("You do not hold the permission");
  await expectAccessible(page, "the dialog with an error");
});

test("without posture.view the page says so, accessibly", async ({ page }) => {
  await page.goto("/dev/as/nobody");
  await expect(page.getByRole("alert")).toContainText("You do not have access to the security posture");
  await expectAccessible(page, "the no-access page");
});
