import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-011 T-18 (F-011-AC-01 to AC-25): the integration pages against the real
// integrations and imports APIs, as db/tests/ui_harness_integrations_test.go
// seeds them: "admin" (Platform Admin at Enterprise) manages "Asset
// inventory" (an upload left three asset proposals and a refused record),
// "Incident register" (three loss events) and the connector "CMDB pull"
// (its source credential set; sources allowed at cmdb.example.test);
// "riskanalyst" reviews the proposals and derives "Phishing incidents,
// enterprise" from the events. The register import is upload.spec.ts's
// (it runs after register.spec.ts, whose counts it would change). WCAG 2.1
// AA is checked with axe on every page.

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

test("integrations and their runs: counts, refused records by position and reason (AC-01, AC-06, AC-08), accessibly", async ({ page }) => {
  await as(page, "admin");
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Integrations" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Integrations");
  const list = page.getByRole("region", { name: "Integrations" });
  for (const name of ["Asset inventory", "CMDB pull", "Incident register"]) await expect(list.getByRole("link", { name })).toBeVisible();
  await expectAccessible(page, "integrations");

  await list.getByRole("link", { name: "Asset inventory" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Asset inventory");
  const runs = page.getByRole("region", { name: "Runs" });
  await expect(runs.getByRole("cell", { name: "Uploaded" })).toBeVisible();
  await expect(runs).toContainText("4 received, 3 valid, 1 refused");
  await expectAccessible(page, "an integration");

  await runs.getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(/^Run of /);
  const refused = page.getByRole("region", { name: "Refused records" });
  await expect(refused.getByRole("row", { name: /app-104/ })).toContainText("/name");
  await expectAccessible(page, "a run");
  await expect(page.getByRole("link", { name: "Review the changes this run proposed" })).toBeVisible();
});

test("a connector: credentials write-only, a test through the guard, run now (AC-03, AC-04, AC-08), accessibly", async ({ page }) => {
  await as(page, "admin");
  await page.goto("/integrations");
  await page.getByRole("link", { name: "CMDB pull" }).click();
  const creds = page.getByRole("region", { name: "Credentials" });
  await expect(creds).toContainText(/Source credential\s*Set/);
  await expect(page.getByText("harness-source-token")).toHaveCount(0);
  await page.getByRole("button", { name: "Test the source" }).click();
  await expect(page.getByText(/The first page held 3 records/)).toBeVisible();
  await page.getByRole("button", { name: "Run now" }).click();
  await expect(page.getByText("A run was queued; it starts within a minute.")).toBeVisible();
  await expectAccessible(page, "a connector");

  // A new client secret is saved and never shown.
  await creds.getByLabel("Credential", { exact: true }).selectOption("client");
  await creds.getByLabel("Client secret").fill("harness-client-secret");
  await creds.getByRole("button", { name: "Save credential" }).click();
  await expect(creds.getByText("Saved. It is not shown again.")).toBeVisible();
  await expect(creds).toContainText(/client secret\s*Set/);
  await expect(page.locator("body")).not.toContainText("harness-client-secret");
});

test("creating, refusing an unlisted source, and deleting an integration (AC-01, AC-04, AC-05)", async ({ page }) => {
  await as(page, "admin");
  await page.goto("/integrations/new");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("New integration");
  await page.getByLabel("Name", { exact: true }).fill("Vendor feed");
  await page.getByLabel("Delivery").selectOption("connector");
  await page.getByLabel("Source URL").fill("https://vendor.example.com/assets");
  await page.getByLabel("Mapping (JSON)").fill('{"columns": {"/id": "external_id", "/name": "name"}}');
  await page.getByLabel("Service account").selectOption({ label: "cmdb-connector (Enterprise)" });
  await expectAccessible(page, "the integration form");
  await page.getByRole("button", { name: "Create integration" }).click();
  await expect(page.getByRole("alert")).toContainText("not in integration.allowed_hosts");

  await page.getByLabel("Delivery").selectOption("file");
  await page.getByLabel("Mapping (JSON)").fill('{"columns": {"ID": "external_id", "Name": "name", "Type": "asset_type"}}');
  await page.getByRole("button", { name: "Create integration" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Vendor feed");
  await page.getByRole("button", { name: "Delete" }).click();
  await page.getByLabel("Why it is deleted").fill("Created by mistake");
  await page.getByRole("button", { name: "Delete integration" }).click();
  await expect(page.getByText(/Deleted .*Its runs and the provenance of what it brought in are kept\./)).toBeVisible();
});

test("the review queue: a diff to review, reject with a reason, accept one, accept the rest at once, provenance (AC-10 to AC-12, AC-25), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/integrations/proposals");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Proposed changes");
  const queue = page.getByRole("region", { name: "Pending proposals" });
  for (const name of ["Policy administration", "Claims document store", "Agent portal"]) await expect(queue.getByRole("row", { name: new RegExp(name) })).toBeVisible();
  await expectAccessible(page, "the review queue");

  await queue.getByRole("row", { name: /Agent portal/ }).getByRole("link").click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Create asset");
  await expect(page.getByRole("region", { name: "The record accepting would write" })).toContainText("Agent portal");
  await expectAccessible(page, "a proposal");
  await page.getByRole("button", { name: "Reject" }).click();
  await page.getByLabel("Why it is rejected").fill("Retired last year");
  await page.getByRole("dialog").getByRole("button", { name: "Reject" }).click();
  await expect(page.getByText("Rejected.")).toBeVisible();

  await page.goto("/integrations/proposals");
  await queue.getByRole("row", { name: /Policy administration/ }).getByRole("link").click();
  await page.getByRole("button", { name: "Accept" }).click();
  await expect(page.getByText("Accepted: the record has a new version.")).toBeVisible();

  await page.goto("/integrations/proposals");
  await page.getByRole("button", { name: "Select all" }).click();
  await page.getByRole("button", { name: "Accept selected (1)" }).click();
  await expect(page.getByText("Accepted 1 change.")).toBeVisible();
  await expect(page.getByText("No pending proposals you may review.")).toBeVisible();

  // AC-25: the accepted asset says where its version came from.
  await page.goto("/library");
  await page.getByRole("link", { name: "Policy administration" }).click();
  const history = page.getByRole("region", { name: "Versions" });
  await expect(history.getByRole("cell", { name: /From Asset inventory \(app-101\)/ })).toBeVisible();
});

test("loss events and a derived reference class (AC-17, AC-18), accessibly", async ({ page }) => {
  await as(page, "riskanalyst");
  await page.goto("/integrations/loss-events");
  const events = page.getByRole("region", { name: "Events" });
  await expect(events.getByRole("row")).toHaveCount(4); // the header and three events
  await expect(events).toContainText("Claims platform outage");
  await expectAccessible(page, "loss events");

  await page.goto("/library");
  await page.getByRole("link", { name: "Phishing incidents, enterprise" }).click();
  const derivation = page.getByRole("region", { name: "Derived from loss events" });
  await expect(derivation).toContainText("not derived from loss events");
  await derivation.getByRole("button", { name: "Derive from loss events" }).click();
  await derivation.getByLabel("Event types (comma separated)").fill("phishing");
  await derivation.getByLabel("From").fill("2026-01-01");
  await derivation.getByLabel("Before").fill("2027-01-01");
  await expectAccessible(page, "the derivation form");
  await derivation.getByRole("button", { name: "Save the derivation" }).click();
  await expect(derivation.getByText("Saved; a new version of the class is proposed for review.")).toBeVisible();
  await derivation.getByRole("link", { name: "Waiting for review" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Update reference class");
  await expect(page.getByRole("region", { name: /What changes from version 1/ })).toBeVisible();
});
