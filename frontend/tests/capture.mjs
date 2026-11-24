import { chromium } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const password = process.env.TTX_TEST_PASSWORD;
if (!password) throw new Error("TTX_TEST_PASSWORD is required");
const chrome = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const out = resolve("../docs/screenshots");
const temporary = process.env.TEMP;
await mkdir(out, { recursive: true });
const browser = await chromium.launch({
  executablePath: existsSync(chrome) ? chrome : undefined,
});
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
    baseURL: process.env.TTX_BROWSER_URL || "http://127.0.0.1:5173",
  });
  const page = await context.newPage();
  await page.goto("/");
  await page
    .getByLabel("Username")
    .fill(process.env.TTX_TEST_USER || "demo-investigator");
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("heading", { name: "Investigation overview" }).waitFor();
  const endpoint = async (path) =>
    (await context.request.get("/api/v1" + path)).json();
  const cases = (await endpoint("/cases?limit=50")).items;
  const identity = cases.find(
    (item) => item.title === "Suspicious account access",
  );
  const network = cases.find(
    (item) => item.title === "Unusual outbound communication",
  );
  const identityPath = "/cases/" + identity.id;
  const networkPath = "/cases/" + network.id;
  const evidence = (await endpoint(identityPath + "/evidence")).items.find(
    (item) => item.filename === "identity-export.json",
  );
  const shot = async (filename, heading) => {
    await page.getByRole("heading", { name: heading, exact: true }).waitFor();
    await page.screenshot({
      path: resolve(out, filename),
      animations: "disabled",
    });
  };
  const view = async (path, filename, heading, ready) => {
    await page.goto("/#" + path);
    if (ready) await ready();
    await shot(filename, heading);
  };
  await shot("01-overview.png", "Investigation overview");
  await view(identityPath, "02-investigation.png", identity.title, () =>
    page.getByRole("heading", { name: "Investigation scope" }).waitFor(),
  );
  await view(
    identityPath + "/evidence",
    "03-evidence-vault.png",
    "Evidence vault",
    () => page.getByRole("link", { name: /identity-export/ }).waitFor(),
  );
  await page.getByRole("link", { name: /identity-export/ }).click();
  await page.getByRole("button", { name: "Verify SHA-256" }).click();
  await page.getByText(/Preserved bytes match/).waitFor();
  await shot("04-integrity-verification.png", evidence.filename);
  await view(
    identityPath + "/timeline",
    "05-timeline.png",
    "Incident timeline",
    () =>
      page.getByRole("columnheader", { name: "Source reference" }).waitFor(),
  );
  await page.goto("/#" + identityPath + "/graph");
  await page
    .getByRole("button", { name: /Select event/ })
    .first()
    .click();
  await shot("06-correlation-graph.png", "Correlation graph");
  await view(
    networkPath + "/network",
    "07-network-forensics.png",
    "Protocol distribution",
    () => page.getByText("Reported volume").waitFor(),
  );
  await view(
    networkPath + "/intelligence",
    "08-threat-intelligence.png",
    "Threat intelligence",
    () => page.getByText("203.0.113.44", { exact: true }).waitFor(),
  );
  await view(
    identityPath + "/custody/" + evidence.id,
    "09-chain-of-custody.png",
    "Chain of custody",
    () => page.getByText(/Custody chain verified/).waitFor(),
  );
  await view("/research", "10-research-lab.png", "Research Lab", () =>
    page.getByRole("heading", { name: "Measured results" }).waitFor(),
  );
  const credentials = { "X-TTX-Request": "1" };
  for (const format of ["html", "pdf"]) {
    const response = await context.request.post(
      "/api/v1" + identityPath + "/reports/" + format,
      { headers: credentials },
    );
    if (!response.ok()) throw new Error(await response.text());
    await writeFile(
      resolve(temporary, "ttx-generated-report." + format),
      await response.body(),
    );
  }
  await page.goto(
    new URL(
      "file:///" +
        resolve(temporary, "ttx-generated-report.html").replaceAll("\\", "/"),
    ).href,
  );
  await shot("11-generated-report.png", identity.title);
  await page.setViewportSize({ width: 390, height: 844 });
  await view("/", "12-mobile-overview.png", "Investigation overview");
} finally {
  await browser.close();
}
