import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

const user = process.env.TTX_TEST_USER || "demo-investigator";
const password = process.env.TTX_TEST_PASSWORD;
test.beforeEach(async ({ page }) => {
  if (!password)
    throw new Error(
      "TTX_TEST_PASSWORD must be set. Use scripts/run-tests.ps1.",
    );
  await page.goto("/");
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(
    page.getByRole("heading", { name: "Investigation overview" }),
  ).toBeVisible();
});

test("dashboard, case navigation and evidence custody", async ({ page }) => {
  await expect(
    page.getByText("Synthetic demonstration", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Suspicious account access" })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: "Suspicious account access" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Evidence", exact: true }).click();
  await page.getByRole("link", { name: /identity-export/ }).click();
  await page.getByRole("button", { name: "Verify SHA-256" }).click();
  await expect(page.getByText(/Preserved bytes match/)).toBeVisible();
  await page.getByRole("link", { name: "Custody history" }).click();
  await expect(page.getByText(/Custody chain verified/)).toBeVisible();
});

test("case creation, upload, finding and report export", async ({ page }) => {
  await page.getByRole("link", { name: "New investigation" }).click();
  await page.getByLabel("Case title").fill("Browser workflow investigation");
  await page.getByRole("button", { name: "Create investigation" }).click();
  await page.getByRole("link", { name: "Evidence", exact: true }).click();
  await page.getByRole("button", { name: "Import evidence" }).click();
  await page
    .getByRole("dialog", { name: "Import evidence" })
    .locator("input[type=file]")
    .setInputFiles({
      name: "browser-test.json",
      mimeType: "application/json",
      buffer: Buffer.from(
        JSON.stringify([
          {
            timestamp: "2025-04-08T14:00:00Z",
            action: "privilege_change",
            category: "account",
            hostname: "orchid-test",
          },
        ]),
      ),
    });
  await page.getByLabel("Source description").fill("Synthetic browser fixture");
  await page.getByRole("button", { name: "Preserve and parse" }).click();
  await expect(
    page.getByRole("link", { name: /browser-test.json/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Run analysis" }).click();
  await expect(page.getByText(/Analysis completed/)).toBeVisible();
  await page.getByRole("link", { name: "Findings", exact: true }).click();
  await page.getByRole("link", { name: /Unexpected privilege change/ }).click();
  await expect(
    page.getByRole("heading", { name: "Confidence assessment" }),
  ).toBeVisible();
  await page.getByRole("link", { name: /Event 1/ }).click();
  await expect(page.getByText("Original timestamp")).toBeVisible();
  await page.getByRole("link", { name: "Reports", exact: true }).last().click();
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "PDF report" }).click();
  expect((await event).suggestedFilename()).toMatch(/\.pdf$/);
  await expect(page.getByText(/Report exported/)).toBeVisible();
});

test("timeline filtering and accessible graph selection", async ({ page }) => {
  await page
    .getByRole("link", { name: "Suspicious account access" })
    .first()
    .click();
  await page.getByRole("link", { name: "Timeline", exact: true }).click();
  await page.getByLabel("Category").selectOption("account");
  await expect(
    page.getByRole("table").getByRole("link", { name: /Admin activity/ }),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: /Login/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Zoom in timeline" }).click();
  await expect(page.getByLabel("From (UTC)")).not.toHaveValue("");
  await page.getByRole("button", { name: "Reset time range" }).click();
  await page.getByLabel("Show local time").check();
  await expect(
    page.getByRole("columnheader", { name: "Time (local)" }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Correlation graph", exact: true })
    .last()
    .click();
  const node = page.getByRole("button", { name: /Select event/ }).first();
  await node.focus();
  await node.press("Enter");
  await expect(page.getByRole("link", { name: "Inspect event" })).toBeVisible();
  await page.getByRole("button", { name: "Zoom in graph" }).click();
  await expect(page.getByLabel("Graph zoom")).toHaveText("125%");
  const canvas = page.getByLabel("Event correlation diagram");
  const originalViewBox = await canvas.getAttribute("viewBox");
  await canvas.press("ArrowRight");
  await expect(canvas).not.toHaveAttribute("viewBox", originalViewBox!);
  await page.getByRole("button", { name: "Fit graph" }).click();
  await expect(page.getByLabel("Graph zoom")).toHaveText("100%");
  await page
    .getByLabel("Relationship", { exact: true })
    .selectOption("inferred");
  await expect(
    page.getByRole("button", { name: /Select inferred relationship/ }).first(),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Select observed relationship/ }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: /Select inferred relationship/ })
    .first()
    .press("Enter");
  await expect(
    page
      .getByRole("complementary", { name: "Graph selection details" })
      .getByRole("heading", { name: "Supporting evidence" }),
  ).toBeVisible();
  await page.getByLabel("Relationship", { exact: true }).selectOption("");
  await page.getByLabel("Graph view").selectOption("entities");
  await page.getByLabel("Entity type").selectOption("finding");
  await expect(
    page.getByRole("link", { name: "Inspect finding" }),
  ).toBeVisible();
});

test("mobile navigation fits the viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("link", { name: "Investigations", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Investigations", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await expect(
    page.getByRole("button", { name: "Open navigation" }),
  ).toHaveAttribute("aria-expanded", "false");
});

test("unauthorized rule controls, loading and error states", async ({
  page,
  request,
}) => {
  const login = await request.post("/api/v1/auth/login", {
    data: { username: user, password },
    headers: { "X-TTX-Request": "1" },
  });
  expect(login.ok()).toBeTruthy();
  const unique = "browser-analyst-" + Date.now();
  const add = await request.post("/api/v1/users", {
    headers: { "X-TTX-Request": "1" },
    data: {
      username: unique,
      password,
      role: "investigator",
    },
  });
  expect(add.status()).toBe(201);
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByLabel("Username").fill(unique);
  await page.getByLabel("Password").fill("incorrect-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("Invalid credentials");
  await page.getByLabel("Password").fill(password!);
  const pending = page.waitForRequest("**/api/v1/dashboard");
  let release: (() => void) | undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/dashboard", async (route) => {
    await hold;
    await route.continue();
  });
  await page.getByRole("button", { name: "Sign in" }).click();
  await pending;
  await expect(page.getByText("Loading records…")).toBeVisible();
  release?.();
  await expect(
    page.getByRole("heading", { name: "Investigation overview" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Detection Rules" }).click();
  await expect(
    page.getByRole("heading", { name: "Rule catalog" }),
  ).toBeVisible();
  await expect(page.getByRole("checkbox").first()).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Save", exact: true }),
  ).toHaveCount(0);
});

test("filtered timeline export matches the displayed case and filters", async ({
  page,
}) => {
  const register = page.getByRole("navigation", { name: "Primary navigation" });
  await register
    .getByRole("link", { name: "Investigations", exact: true })
    .click();
  await page
    .getByRole("link", { name: "Open Suspicious account access", exact: true })
    .click();
  await page.getByRole("link", { name: "Timeline", exact: true }).click();
  await page.getByLabel("Category").selectOption("account");
  await expect(
    page.getByText("1 matching event", { exact: true }),
  ).toBeVisible();
  const [csv] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Export filtered timeline" }).click(),
  ]);
  const file = await readFile((await csv.path())!, "utf-8");
  expect(file.trim().split(/\r?\n/)).toHaveLength(2);
  expect(file).toContain("admin_activity");
  expect(file).not.toContain(",login,");
});

test("workspaces retain the selected investigation until explicitly changed", async ({
  page,
}) => {
  const sidebar = page.getByRole("navigation", { name: "Primary navigation" });
  const heading = (title: string) =>
    page.getByRole("heading", { name: title, exact: true });
  const breadcrumb = page.getByRole("navigation", { name: "Breadcrumb" });
  await sidebar.getByRole("link", { name: "Network Forensics" }).click();
  const selector = page.getByLabel("Active investigation");
  await expect(selector).toHaveValue("");
  await expect(
    page.getByText("Select the investigation you want to work on."),
  ).toBeVisible();
  await selector.selectOption({ label: "Unusual outbound communication" });
  const key = await selector.inputValue();
  await expect(heading("Unusual outbound communication")).toBeVisible();
  for (const workspace of [
    "Threat Intelligence",
    "Evidence Vault",
    "Incident Timeline",
    "Correlation Graph",
    "Chain of Custody",
    "Reports",
  ]) {
    await sidebar.getByRole("link", { name: workspace, exact: true }).click();
    await expect(selector).toHaveValue(key);
    await expect(heading("Unusual outbound communication")).toBeVisible();
    await expect(
      breadcrumb.getByText(workspace, { exact: true }),
    ).toBeVisible();
  }
  await page.getByRole("link", { name: "Open findings" }).click();
  await expect(breadcrumb.getByText("Findings", { exact: true })).toBeVisible();
  await expect(selector).toHaveValue(key);
  await page.reload();
  await expect(selector).toHaveValue(key);
  await sidebar
    .getByRole("link", { name: "Investigations", exact: true })
    .click();
  await page
    .getByRole("link", { name: "Open Suspicious account access", exact: true })
    .click();
  await expect(heading("Suspicious account access")).toBeVisible();
  await page.getByRole("link", { name: "Open findings" }).click();
  await expect(
    breadcrumb.getByText("Suspicious account access", { exact: true }),
  ).toBeVisible();
  await expect(breadcrumb.getByText("Findings", { exact: true })).toBeVisible();
  await sidebar.getByRole("link", { name: "Network Forensics" }).click();
  await expect(heading("Suspicious account access")).toBeVisible();
  await expect(selector).not.toHaveValue(key);
});

test("access settings show explicit grants and require a password change after reset", async ({
  page,
  browser,
}) => {
  const account = "access-analyst-" + Date.now();
  const replacement = "synthetic-replacement-7719";
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByLabel("New username").fill(account);
  await page.getByLabel("Initial password").fill(password!);
  await page.getByRole("button", { name: "Create local account" }).click();
  await expect(page.getByText("Local account created.")).toBeVisible();
  const investigatorRow = page
    .getByRole("row")
    .filter({ hasText: account })
    .first();
  const grantPanel = page
    .getByRole("heading", { name: "Investigation access" })
    .locator("xpath=ancestor::section[1]");
  await grantPanel
    .getByLabel("Investigation", { exact: true })
    .selectOption({ label: "Suspicious account access" });
  await grantPanel
    .getByLabel("Grant access to")
    .selectOption({ label: account });
  await grantPanel
    .getByRole("button", { name: "Grant access", exact: true })
    .click();
  const grantRow = grantPanel.getByRole("row").filter({ hasText: account });
  await expect(grantRow).toBeVisible();
  await grantPanel
    .getByRole("row")
    .filter({ hasText: account })
    .getByRole("button", { name: "Revoke access" })
    .click();
  await page.getByRole("button", { name: "Confirm revoke" }).click();
  await expect(grantRow).toHaveCount(0);
  await investigatorRow.getByRole("button", { name: "Reset password" }).click();
  await page.getByLabel("Replacement temporary password").fill(replacement);
  await page.getByLabel("Your administrator password").fill(password!);
  await page.getByRole("button", { name: "Confirm password reset" }).click();
  await expect(
    investigatorRow.getByText("Password reset pending"),
  ).toBeVisible();
  const second = await browser.newContext();
  try {
    const investigator = await second.newPage();
    await investigator.goto(new URL("/", page.url()).href);
    await investigator.getByLabel("Username").fill(account);
    await investigator
      .getByLabel("Password", { exact: true })
      .fill(replacement);
    await investigator.getByRole("button", { name: "Sign in" }).click();
    await expect(
      investigator.getByRole("heading", { name: "Change temporary password" }),
    ).toBeVisible();
    await investigator.getByLabel("Temporary password").fill(replacement);
    await investigator
      .getByLabel("New password", { exact: true })
      .fill(password!);
    await investigator.getByLabel("Confirm new password").fill(password!);
    await investigator
      .getByRole("button", { name: "Save new password" })
      .click();
    await expect(
      investigator.getByRole("heading", { name: "Sign in" }),
    ).toBeVisible();
    await investigator.getByLabel("Username").fill(account);
    await investigator.getByLabel("Password", { exact: true }).fill(password!);
    await investigator.getByRole("button", { name: "Sign in" }).click();
    await expect(
      investigator.getByRole("heading", { name: "Investigation overview" }),
    ).toBeVisible();

    await investigatorRow
      .getByRole("button", { name: "Disable", exact: true })
      .click();
    await page.getByLabel("Your administrator password").fill(password!);
    await page
      .getByRole("button", { name: "Disable account", exact: true })
      .click();
    await expect(
      investigatorRow.getByText("Disabled", { exact: true }),
    ).toBeVisible();
    await investigator.reload();
    await expect(
      investigator.getByRole("heading", { name: "Sign in" }),
    ).toBeVisible();
    await investigatorRow
      .getByRole("button", { name: "Enable", exact: true })
      .click();
    await page.getByLabel("Your administrator password").fill(password!);
    await page
      .getByRole("button", { name: "Enable account", exact: true })
      .click();
    await expect(
      investigatorRow.getByText("Active", { exact: true }),
    ).toBeVisible();
  } finally {
    await second.close();
  }
});
