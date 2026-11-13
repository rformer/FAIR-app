import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";
import { expect, test, type Locator, type Page } from "@playwright/test";

// F-006 T-05 (F-006-AC-01 to AC-06, AC-09, AC-14 to AC-17): a run's page
// against the real API and the real engine, as db/tests/ui_harness_test.go
// seeds it: "Ransomware on the claims platform" version 2, with control
// sets Current and With MFA, and its run of 20,000 iterations (seed 2026),
// the oldest of the scenario's runs. WCAG 2.1 AA is checked with axe.

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

const ransomware = "Ransomware on the claims platform";

/** Opens the seeded run's page from its scenario (the oldest run). */
async function openSeededRun(page: Page): Promise<string> {
  await page.goto("/scenarios");
  await page.getByRole("link", { name: ransomware, exact: true }).click();
  const runs = page.getByRole("region", { name: "Simulations" });
  const rows = runs.getByRole("table", { name: /Simulation runs of this scenario/ }).getByRole("row").filter({ has: page.getByRole("cell") });
  await rows.last().getByRole("button", { name: /^Details/ }).click();
  await page.getByRole("link", { name: "Charts and comparisons of this run" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Simulation of ${ransomware}, version 2`);
  return page.url().split("/").pop() ?? "";
}

function figure(scope: Locator | Page, caption: string | RegExp): Locator {
  return scope.getByRole("figure", { name: caption });
}

/** Downloads through a figure's button, waiting for the record first. */
async function downloadImage(page: Page, fig: Locator, format: "SVG" | "PNG") {
  const recorded = page.waitForResponse((r) => r.url().endsWith("/api/v1/analyses/downloads") && r.request().method() === "POST");
  const download = page.waitForEvent("download");
  await fig.getByRole("button", { name: `Download ${format}` }).click();
  expect((await recorded).status()).toBe(201);
  const d = await download;
  return { name: d.suggestedFilename(), body: await readFile((await d.path()) ?? "") };
}

test("a run's views: record, curves with cursor and lookups, distribution, breakdown, drivers, control sets (AC-01 to AC-06, AC-09, AC-14 to AC-16)", async ({ page }) => {
  test.setTimeout(120_000);
  await as(page, "riskanalyst");
  const id = await openSeededRun(page);

  // What was simulated (AC-06).
  const record = page.getByRole("region", { name: "What was simulated" });
  await expect(record).toContainText("Every input is sampled independently");
  await expect(record).toContainText("20,000 iterations, seed 2026");
  await expect(record).toContainText("Current, With MFA");
  await expect(record.getByText(/^[0-9a-f]{64}$/)).toHaveCount(2);
  await expect(record).toContainText(/Convergence \(Current\)/);

  // Loss exceedance (AC-01, AC-15): both sets, the current one solid.
  const exceedance = page.getByRole("region", { name: "Loss exceedance" });
  const curves = figure(exceedance, "Loss exceedance curves");
  await expect(curves).toContainText(/Chance of losing more than \$[\d.]+[KMB]? in a year\. Current \(solid line, circles\): [\d.]+%; With MFA \(dashed line, squares\): [\d.<]+%\./);
  await expect(curves.locator("svg")).toContainText("logarithmic scale");
  await exceedance.getByRole("radio", { name: "Linear" }).check();
  await expect(curves.locator("svg")).toContainText("linear scale");

  // The cursor by keyboard (AC-05, AC-16): a slider reading every set.
  const cursor = curves.getByRole("slider", { name: "Cursor on the loss exceedance curves" });
  await cursor.focus();
  await page.keyboard.press("Home");
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("PageUp");
  await expect(cursor).toHaveAttribute("aria-valuenow", "11");
  await expect(cursor).toHaveAttribute("aria-valuetext", /^Annual loss \$[\d.]+[KMB]?: Current [\d.<]+%, With MFA [\d.<]+%$/);
  await expect(curves).toContainText(/Annual loss \$[\d.]+[KMB]?: Current .*\(read from the curve\)\./);
  await page.keyboard.press("End");
  await expect(cursor).toHaveAttribute("aria-valuetext", /Current 0%/);

  // Lookups both ways (AC-05).
  await exceedance.getByLabel("Annual loss (USD)").fill("100000");
  await exceedance.getByLabel("Chance of exceeding (%)").fill("10");
  await exceedance.getByRole("button", { name: "Read" }).click();
  const read = exceedance.getByRole("status");
  await expect(read).toContainText(/Chance of losing more than \$100,000 in a year: Current .+; With MFA .+\./);
  await expect(read).toContainText(/Annual loss exceeded with a 10% chance: Current \$[\d,]+.*; With MFA \$[\d,]+/);

  // The data table (AC-14).
  await curves.getByRole("button", { name: "Show data table" }).click();
  const table = curves.getByRole("table", { name: "Loss exceedance curve points" });
  await expect(table.getByRole("row")).not.toHaveCount(0);
  expect(await table.getByRole("row").count()).toBeGreaterThan(200);
  await expect(table).toContainText("p90");

  // The distribution (AC-02): years with no loss apart, markers, another set.
  const dist = page.getByRole("region", { name: "Distribution of annual loss" });
  const hist = figure(dist, "Annual loss, Current");
  await expect(hist).toContainText(/of years have no loss/);
  await expect(hist.locator("svg")).toContainText("(not drawn)");
  await expect(hist.locator("svg")).toContainText("P90");
  await dist.getByLabel("Control set").selectOption("With MFA");
  await expect(figure(dist, "Annual loss, With MFA")).toBeVisible();

  // The breakdown (AC-03) and the drivers (AC-04).
  const breakdown = page.getByRole("region", { name: "Annual loss by part" });
  await expect(figure(breakdown, "Mean annual loss by part, Current")).toContainText(/Primary loss \$/);
  await expect(figure(breakdown, "Mean annual loss by part, With MFA")).toBeVisible();
  const drivers = page.getByRole("region", { name: "What drives the result" });
  const tornado = figure(drivers, "Inputs that drive annual loss, Current");
  await expect(tornado).toContainText("The inputs that move the mean annual loss most");
  await tornado.getByRole("button", { name: "Show data table" }).click();
  await expect(tornado.getByRole("table")).toContainText("/lef/");

  // Control sets (AC-09): With MFA against Current, and the per-year difference.
  const sets = page.getByRole("region", { name: "Control sets against Current" });
  await expect(sets.getByRole("table", { name: "Differences from Current" }).getByRole("row", { name: /With MFA/ })).toContainText(/reduction|increase|no change/);
  const diff = figure(sets, "Year-by-year difference, With MFA minus Current");
  await expect(diff).toContainText("show no difference");
  await expect(diff).toContainText("A negative difference is a reduction.");

  await expectAccessible(page, "a run's page with its tables open");
  expect(id).toMatch(/^[0-9a-f-]{36}$/);
});

test("downloads: SVG and PNG recorded first, with the footer; CSV from the service (AC-17, AC-18)", async ({ page }) => {
  test.setTimeout(120_000);
  await as(page, "riskanalyst");
  const id = await openSeededRun(page);
  const curves = figure(page, "Loss exceedance curves");

  const svg = await downloadImage(page, curves, "SVG");
  expect(svg.name).toBe(`run-${id.slice(0, 8)}-curve.svg`);
  const text = svg.body.toString("utf8");
  expect(text).toMatch(/^<svg /);
  expect(text).toContain(`Loss exceedance curves: ${ransomware}, version 2`);
  expect(text).toMatch(/Download [0-9a-f-]{36}/);
  expect(text).toContain("Every input is sampled independently");
  expect(text).not.toMatch(/<script|<foreignObject|\son[a-z]+=|\sstyle=|class=/i);

  const png = await downloadImage(page, curves, "PNG");
  expect(png.name).toBe(`run-${id.slice(0, 8)}-curve.png`);
  expect(png.body.subarray(0, 8)).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));

  const download = page.waitForEvent("download");
  await curves.getByRole("link", { name: "Download CSV" }).click();
  const csv = await download;
  expect(csv.suggestedFilename()).toBe(`run-${id.slice(0, 8)}-curve.csv`);
  const body = (await readFile((await csv.path()) ?? "")).toString("utf8");
  expect(body).toContain("control_set,annual_loss,probability_of_exceeding");
  expect(body).toMatch(/download,[0-9a-f-]{36}/);
});

test("an exported chart keeps a scenario name with markup as text (design §7)", async ({ page }) => {
  test.setTimeout(180_000);
  await as(page, "riskanalyst");
  // A copy of the seeded scenario named with markup, and a small run of it.
  const me = await (await page.request.get("/api/v1/me")).json();
  const headers = { "X-CSRF-Token": me.csrf_token, "Content-Type": "application/json", Origin: new URL(page.url()).origin };
  const list = await (await page.request.get("/api/v1/scenarios")).json();
  const seeded = (list.scenarios as { id: string; name: string; bu_id: string }[]).find((s) => s.name === ransomware);
  expect(seeded).toBeTruthy();
  const view = await (await page.request.get(`/api/v1/scenarios/${seeded!.id}`)).json();
  const name = `<script>alert(1)</script> & "Claims"`;
  const created = await page.request.post("/api/v1/scenarios", {
    headers: { ...headers, "Idempotency-Key": crypto.randomUUID() },
    data: { bu_id: seeded!.bu_id, document: { ...view.version.document, name }, change_note: "F-006 export test" },
  });
  expect(created.status(), await created.text()).toBe(201);
  const scenario = (await created.json()).id as string;
  const requested = await page.request.post("/api/v1/analyses/runs", {
    headers: { ...headers, "Idempotency-Key": crypto.randomUUID() },
    data: { scenario_id: scenario, version: 1, iterations: 2000, seed: "5" },
  });
  expect(requested.status(), await requested.text()).toBe(202);
  const run = (await requested.json()).id as string;
  await expect
    .poll(async () => (await (await page.request.get(`/api/v1/analyses/runs/${run}`)).json()).state, { timeout: 90_000 })
    .toBe("succeeded");

  await page.goto(`/analyses/runs/${run}`);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Simulation of ${name}, version 1`);
  const svg = await downloadImage(page, figure(page, "Loss exceedance curves"), "SVG");
  const text = svg.body.toString("utf8");
  expect(text).toContain("&lt;script&gt;alert(1)&lt;/script&gt; &amp; \"Claims\"");
  expect(text).not.toMatch(/<script/i);
});

test("a viewer reads the run's views and downloads them", async ({ page }) => {
  await as(page, "nobody");
  await openSeededRun(page);
  await expect(figure(page, "Loss exceedance curves")).toBeVisible();
  const svg = await downloadImage(page, figure(page, "Loss exceedance curves"), "SVG");
  expect(svg.body.toString("utf8")).toContain("Download ");
  await expectAccessible(page, "a viewer's run page");
});
