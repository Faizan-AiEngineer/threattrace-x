import { expect, test } from "@playwright/test";

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
  await expect(
    page.locator('svg[aria-label="Event correlation diagram"]'),
  ).toHaveAttribute("style", "width: 125%; min-width: 560px;");
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
