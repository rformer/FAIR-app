import { defineConfig, devices } from "@playwright/test";

// F-015 T-32: end-to-end tests against the real Posture API behind the
// test-only dev gateway (scripts/ui-e2e.sh starts it on :8099).
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.FAIR_UI_URL ?? "http://localhost:8099",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
