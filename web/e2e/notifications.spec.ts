import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

// F-009 T-13 (AC-02, AC-11, AC-17 to AC-19): the notification pages against
// the real notify API and what db/tests/ui_harness_test.go seeds: the
// estimate request addressed to "estimator" becomes a notification within
// seconds (the harness runs the collector and fan-out); "admin" configures
// the harness's STARTTLS test relay (GET /dev/smtp) and a webhook, and sends
// a test message. WCAG 2.1 AA is checked with axe on every page.

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

interface Relay {
  host: string;
  port: string;
  ca: string;
  messages: { to: string; subject: string }[];
}

test("the unread count, the list, and marking read", async ({ page }) => {
  await as(page, "estimator");
  const header = page.getByRole("navigation", { name: "Primary" });
  await expect(async () => {
    await page.goto("/notifications");
    await expect(header.getByRole("link", { name: /Notifications \d+ unread/ })).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 30000 });
  const list = page.getByRole("region", { name: "All notifications" });
  await expect(list.getByRole("link", { name: /An estimate request is addressed to you/ }).first()).toBeVisible();
  await expect(list.getByText("Unread").first()).toBeVisible();
  await expectAccessible(page, "notifications");

  await page.getByRole("link", { name: "Show unread only" }).click();
  await expect(page.getByRole("region", { name: "Unread notifications" }).getByRole("link", { name: /estimate request/ }).first()).toBeVisible();
  await page.getByRole("button", { name: "Mark all as read" }).click();
  await expect(page.getByRole("region", { name: "Unread notifications" }).getByText("No notifications.")).toBeVisible();

  // Opening a notification goes to the item.
  await page.goto("/notifications");
  await page.getByRole("region", { name: "All notifications" }).getByRole("link", { name: /An estimate request is addressed to you/ }).first().click();
  await expect(page).toHaveURL(/\/estimates\//);
});

test("preferences: optional kinds by email, the digest; mandatory ones always sent", async ({ page }) => {
  await as(page, "estimator");
  await page.goto("/notifications/preferences");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Notification preferences");
  const email = page.getByRole("region", { name: "Email" });
  await expect(email.getByRole("row", { name: /An estimate request is addressed to you/ }).getByText("Always sent")).toBeVisible();
  const finished = email.getByRole("checkbox", { name: /An estimate request you answered has finished/ });
  await expect(finished).toBeChecked();
  await finished.uncheck();
  await page.getByRole("checkbox", { name: "Send optional notices as one daily digest" }).check();
  await page.getByLabel("Digest time (UTC)").selectOption("6");
  await page.getByRole("button", { name: "Save preferences" }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");
  await expectAccessible(page, "preferences");
  await page.reload();
  await expect(page.getByRole("region", { name: "Email" }).getByRole("checkbox", { name: /An estimate request you answered has finished/ })).not.toBeChecked();
  await expect(page.getByLabel("Digest time (UTC)")).toHaveValue("6");
});

test("channels: the relay over STARTTLS, a test message, a webhook secret shown once", async ({ page, request }) => {
  const relay = (await (await request.get("/dev/smtp")).json()) as Relay;
  await as(page, "admin");
  await page.goto("/notifications/channels");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Notification channels");
  await expect(page.getByText("No relay is configured: notices go to the app only.")).toBeVisible();
  await expectAccessible(page, "channels (empty)");

  // A refused destination is answered, and nothing is saved.
  const form = page.getByRole("form", { name: "Configure the SMTP relay" });
  await form.getByLabel("Relay host").fill("127.0.0.1");
  await form.getByLabel("Port").fill(relay.port);
  await form.getByLabel("From address").fill("FAIR <fair@example.com>");
  await form.getByLabel("Reason").fill("the test relay");
  await form.getByRole("button", { name: "Save the relay" }).click();
  await expect(form.getByRole("alert")).toBeVisible();
  await expect(page.getByText("No relay is configured: notices go to the app only.")).toBeVisible();

  await form.getByLabel("Relay host").fill(relay.host);
  await form.getByLabel("Username (optional)").fill("fair");
  await form.getByLabel("Password file name").fill("relay");
  await form.getByLabel("Trust anchors (PEM, optional)").fill(relay.ca);
  await form.getByRole("button", { name: "Save the relay" }).click();
  const card = page.getByRole("group", { name: "SMTP relay" });
  await expect(card.getByText("Enabled")).toBeVisible();
  await card.getByRole("button", { name: "Send a test message through SMTP relay" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Test message sent through SMTP relay" })).toBeVisible();
  const got = (await (await request.get("/dev/smtp")).json()) as Relay;
  expect(got.messages.map((m) => m.to)).toContain("admin@example.test");

  // A webhook: the secret is shown once.
  const hook = page.getByRole("form", { name: "Add a webhook" });
  await hook.getByLabel("Name").fill("Ticketing");
  await hook.getByLabel("URL (https)").fill(`https://${relay.host}/fair`);
  await hook.getByRole("checkbox", { name: "A risk acceptance waits for your decision" }).check();
  await hook.getByLabel("Reason").fill("open tickets for decisions");
  await hook.getByRole("button", { name: "Add the webhook" }).click();
  await expect(page.getByText("The signing secret of Ticketing, shown this once.", { exact: false })).toBeVisible();
  await expect(page.getByText(/^whsec_/)).toBeVisible();
  await expectAccessible(page, "channels");
  await page.reload();
  await expect(page.getByText(/^whsec_/)).toHaveCount(0);

  // Disable with a reason.
  const tickets = page.getByRole("group", { name: "Ticketing" });
  await tickets.getByRole("button", { name: "Disable Ticketing" }).click();
  const dialog = page.getByRole("dialog", { name: "Disable Ticketing" });
  await dialog.getByLabel("Reason").fill("receiver maintenance");
  await dialog.getByRole("button", { name: "Disable" }).click();
  await expect(tickets.getByText("Disabled")).toBeVisible();
});

test("the delivery log, for notification.view and manage only", async ({ page }) => {
  await as(page, "admin");
  await page.goto("/notifications/deliveries");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Delivery log");
  await expect(page.getByRole("region", { name: "Deliveries" })).toBeVisible();
  await page.getByLabel("State").selectOption("failed");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page).toHaveURL(/state=failed/);
  await expectAccessible(page, "deliveries");

  await as(page, "estimator");
  await page.goto("/notifications/deliveries");
  await expect(page.getByRole("alert")).toHaveText("Not found, or not visible to you.");
  await page.goto("/notifications/channels");
  await expect(page.getByRole("alert")).toHaveText("Not found, or not visible to you.");
});
