import { defineConfig } from "@playwright/test";

/** Smoke tests against the Vite app and the local Worker. */
export default defineConfig({
  testDir: "./e2e",
  timeout: 300_000,
  use: { baseURL: "http://localhost:5173" },
  webServer: {
    command: "pnpm --dir .. dev",
    url: "http://localhost:5173",
    reuseExistingServer: true,
    timeout: 300_000,
  },
});
