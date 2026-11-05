import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-002 T-14 (AC-15 to AC-18, AC-21, AC-35, AC-37): the audit pages against
// the real Audit API and the trail db/tests/ui_harness_test.go seeds: the
// posture scenario's events (an out-of-bounds change approved by a second
// administrator), a closed and signed segment, a failed verification at its
// last record, and one request recorded by two services. WCAG 2.1 AA is
// checked with axe on every view (constitution Q3).

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

// Signs in as user (a new session) and acknowledges the system-use banner.
async function as(page: Page, user: string) {
  await page.goto(`/dev/as/${user}`);
  await page.getByRole("button", { name: "Acknowledge and continue" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
}

async function expectAccessible(page: Page, what: string) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`), what).toEqual([]);
}

function section(page: Page, name: string) {
  return page.getByRole("region", { name, exact: true });
}

const target = "setting:auth.lockout_threshold";

test("the Posture page's audit links open the matching history (AC-37, AC-16, AC-18), accessibly", async ({ page }) => {
  await as(page, "auditor");
  await page.getByRole("link", { name: "Audit history of auth.lockout_threshold" }).first().click();
  await expect(page).toHaveURL(`/audit?target=${encodeURIComponent(target)}`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`History of ${target}`);
  await expect(page).toHaveTitle(`History of ${target} · FAIR Risk Platform`);
  const rows = section(page, "Records").getByRole("row");
  // In order: the request, then the exception it became once approved.
  await expect(rows.filter({ hasText: "setting.change_requested" })).toHaveCount(1);
  await expect(rows.filter({ hasText: "setting.exception_created" })).toHaveCount(1);
  const types = await rows.locator("td:nth-child(3) .mono").allTextContents();
  expect(types.indexOf("setting.change_requested")).toBeLessThan(types.indexOf("setting.exception_created"));
  // AC-18: display names beside stable ids, and the integrity status.
  const requested = rows.filter({ hasText: "setting.change_requested" });
  await expect(requested).toContainText(/Admin [0-9a-f]{8}-/);
  await expect(requested).toContainText("legacy kiosk accounts");
  await expect(requested).toContainText("Verified");
  await expectAccessible(page, "a target's history");

  // The actor's activity, by name.
  await requested.getByRole("link", { name: /^Admin / }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Activity of Admin");
  const own = section(page, "Records").getByRole("row").filter({ hasText: "setting.change_requested" });
  await expect(own.first()).toBeVisible();
  await expectAccessible(page, "an actor's activity");
  // And back to a target's history from one of its records.
  await own.getByRole("link", { name: target }).first().click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`History of ${target}`);
});

test("one approval's evidence: request, both parties, decision, the applied change (AC-35), accessibly", async ({ page }) => {
  await as(page, "auditor");
  await page.goto(`/audit?target=${encodeURIComponent(target)}`);
  await section(page, "Records")
    .getByRole("row")
    .filter({ hasText: "setting.exception_created" })
    .getByRole("link", { name: /^Approval / })
    .click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Approval evidence");
  const summary = section(page, "Approval");
  await expect(summary).toContainText("settings.out_of_bounds");
  await expect(summary).toContainText("approved");
  await expect(summary.getByRole("definition").filter({ hasText: /^Admin [0-9a-f]{8}-/ })).toHaveCount(1);
  await expect(summary.getByRole("definition").filter({ hasText: /^Admin 2 [0-9a-f]{8}-/ })).toHaveCount(1);
  await expect(section(page, "Request")).toContainText("approval.requested");
  await expect(section(page, "Request")).toContainText("legacy kiosk accounts");
  await expect(section(page, "Decision")).toContainText("approval.approved");
  await expect(section(page, "Applied")).toContainText("approval.consumed");
  const changes = section(page, "Changes naming this approval");
  await expect(changes).toContainText("setting.change_requested");
  await expect(changes).toContainText("setting.exception_created");
  await expectAccessible(page, "approval evidence");
});

test("a record and its proof against the signed checkpoint, accessibly", async ({ page }) => {
  await as(page, "auditor");
  await page.goto(`/audit?target=${encodeURIComponent(target)}`);
  const row = section(page, "Records").getByRole("row").filter({ hasText: "setting.change_requested" });
  const seq = (await row.getByRole("rowheader").innerText()).replace(/\D/g, "");
  await row.getByRole("link", { name: `Record ${seq}` }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Audit record ${seq}`);
  const rec = section(page, "Record");
  await expect(rec).toContainText("setting.change_requested");
  await expect(rec.getByRole("table", { name: "Attributes" })).toContainText("approval_id");
  await expect(page.getByLabel("The record's body as recorded")).toContainText('"reason": "legacy kiosk accounts"');
  const proof = section(page, "Proof");
  await expect(proof).toContainText(/The record is leaf \d+ of \d+ in segment \d+/);
  await expect(page.getByLabel("The signed checkpoint statement")).not.toBeEmpty();
  await expectAccessible(page, "a record with its proof");
});

test("search: newest first, filters combine, refused filters are explained (AC-15), accessibly", async ({ page }) => {
  await as(page, "auditor");
  await page.goto("/audit");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Audit trail");
  const latest = section(page, "Latest records").getByRole("row");
  await expect(latest.nth(1)).toBeVisible();
  const seqs = (await section(page, "Latest records").getByRole("rowheader").allInnerTexts()).map((s) => Number(s.replace(/\D/g, "")));
  expect(seqs).toEqual([...seqs].sort((a, b) => b - a));
  await expectAccessible(page, "the search page");
  // Older pages continue below the oldest record shown.
  await page.getByRole("link", { name: "Older records" }).click();
  await expect(page).toHaveURL(new RegExp(`before=${Math.min(...seqs)}`));
  await expect(section(page, "Latest records").getByRole("rowheader").first()).toBeVisible();
  const older = (await section(page, "Latest records").getByRole("rowheader").allInnerTexts()).map((s) => Number(s.replace(/\D/g, "")));
  expect(older.length).toBeGreaterThan(0);
  expect(Math.max(...older)).toBeLessThan(Math.min(...seqs));
  // Times are entered in the browser's zone and sent as RFC 3339.
  await page.goto("/audit");
  await page.getByLabel("From").fill("2020-01-01T00:00");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/from=2020-01-01T\d\d%3A\d\d%3A00\.000Z|from=2019-12-31T\d\d%3A\d\d%3A00\.000Z/);
  await expect(section(page, "Matching records").getByRole("rowheader").first()).toBeVisible();
  // A target filter is a search (newest first), not the target's history.
  await page.goto("/audit");
  await page.getByLabel("Target").fill(target);
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/view=search&target=/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Audit trail");
  const bySeq = (await section(page, "Matching records").getByRole("rowheader").allInnerTexts()).map((s) => Number(s.replace(/\D/g, "")));
  expect(bySeq.length).toBeGreaterThan(1);
  expect(bySeq).toEqual([...bySeq].sort((a, b) => b - a));
  await page.goto("/audit");

  await page.getByLabel("Category").selectOption("approval");
  await page.getByLabel("Severity").selectOption("high");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/\/audit\?view=search&category=approval&severity=high$/);
  const found = section(page, "Matching records");
  await expect(found.getByRole("row").filter({ hasText: "approval.approved" }).first()).toBeVisible();
  for (const t of await found.locator("td:nth-child(3) .mono").allTextContents()) {
    expect(t).toBe("approval.approved"); // the only high-severity approval event
  }
  await expect(page.getByLabel("Category")).toHaveValue("approval");
  await expectAccessible(page, "search results");

  await page.getByLabel("Source address or CIDR range").fill("not-an-address");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(section(page, "Matching records").getByRole("alert")).toContainText("source_ip is an address or a CIDR range");
  await expectAccessible(page, "a refused search");
});

test("one request across services (AC-17), with integrity after a failed verification (AC-18), accessibly", async ({ page }) => {
  await as(page, "auditor");
  await page.goto("/audit?request=req-ui-1");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Request req-ui-1");
  const rows = section(page, "Records").getByRole("row").filter({ hasText: "two services, one request" });
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("Failed");
  await expectAccessible(page, "a request");
  // Nothing visible under an id: not found.
  await page.goto("/audit?request=no-such-request");
  await expect(page.getByRole("alert")).toContainText("Not found, or not visible to you.");
});

test("exporting the matching records, by keyboard (F-002 T-15, AC-32 to AC-34), accessibly", async ({ page }) => {
  await as(page, "auditor");
  await page.goto("/audit?view=search&category=approval");
  // What the search shows (one page: no older records) is what is exported.
  await expect(section(page, "Matching records").getByRole("rowheader").first()).toBeVisible();
  const shown = await section(page, "Matching records").getByRole("rowheader").count();
  expect(shown).toBeGreaterThan(1);
  await expect(page.getByRole("link", { name: "Older records" })).toHaveCount(0);
  const exp = section(page, "Export");
  await expect(exp).toContainText("the records matching category approval");
  await expectAccessible(page, "the export action");

  // A reason is required.
  await exp.getByRole("button", { name: "Export these records" }).focus();
  await page.keyboard.press("Enter");
  await expect(exp.getByRole("alert")).toHaveText("Give a reason for the export.");

  // By keyboard: CSV, a reason, export.
  await exp.getByLabel("CSV (a table, with the records as recorded alongside)").focus();
  await page.keyboard.press("Space");
  await expect(exp.getByLabel("CSV (a table, with the records as recorded alongside)")).toBeChecked();
  await exp.getByLabel("Reason").focus();
  await page.keyboard.type("Change-management evidence for Q4");
  await exp.getByRole("button", { name: "Export these records" }).focus();
  await page.keyboard.press("Enter");
  const status = exp.getByRole("status");
  await expect(status).toContainText(new RegExp(`The export is ready: ${shown} records, up to checkpoint \\d+\\.`), { timeout: 30_000 });
  await expect(status).toContainText(/SHA-256 [0-9a-f]{64}/);
  await expect(exp.getByRole("alert")).toHaveCount(0);
  await expectAccessible(page, "a ready export");

  // The bundle downloads as a ZIP in the chosen format (entry names are
  // stored uncompressed).
  const [download] = await Promise.all([page.waitForEvent("download"), status.getByRole("link", { name: "Download the export (ZIP)" }).click()]);
  expect(download.suggestedFilename()).toMatch(/^fair-audit-export-[0-9a-f-]{36}\.zip$/);
  const chunks: Buffer[] = [];
  for await (const c of await download.createReadStream()) chunks.push(c as Buffer);
  const zip = Buffer.concat(chunks).toString("latin1");
  expect(zip.startsWith("PK")).toBe(true);
  for (const name of ["records.csv", "bodies.jsonl", "proofs.jsonl", "checkpoints.jsonl", "manifest.json", "manifest.sig"]) {
    expect(zip, name).toContain(name);
  }
  expect(zip).not.toContain("records.jsonl");
});

test("an export the user may not make reports the refusal", async ({ page }) => {
  await as(page, "auditor");
  await page.route("**/api/v1/audit/exports", (route) =>
    route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "forbidden", detail: "audit.export is required" }) }),
  );
  await page.goto("/audit");
  const exp = section(page, "Export");
  await exp.getByLabel("Reason").fill("seen");
  await exp.getByRole("button", { name: "Export these records" }).click();
  await expect(exp.getByRole("alert")).toHaveText("You do not hold the permission this action needs.");
  await expect(exp.getByRole("status")).toBeEmpty();
  await expectAccessible(page, "a refused export");
});

test("without audit.view the audit pages say so, accessibly", async ({ page }) => {
  await as(page, "nobody");
  for (const path of ["/audit", `/audit?target=${encodeURIComponent(target)}`]) {
    await page.goto(path);
    await expect(page.getByRole("alert")).toContainText("You do not have access to the audit trail");
    await expect(page.getByRole("alert")).toHaveCount(1);
  }
  await expectAccessible(page, "the no-access page");
});
