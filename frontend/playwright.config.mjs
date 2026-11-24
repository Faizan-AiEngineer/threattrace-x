import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

const chrome = "C:/Program Files/Google/Chrome/Application/chrome.exe";
export default defineConfig({
  testDir: "./tests",
  workers: 1,
  reporter: "list",
  use: {
    baseURL: process.env.TTX_BROWSER_URL || "http://127.0.0.1:5173",
    launchOptions: { executablePath: existsSync(chrome) ? chrome : undefined },
    viewport: { width: 1440, height: 1000 },
  },
});
