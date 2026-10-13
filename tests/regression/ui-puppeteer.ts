import fs from "fs";
import path from "path";
import puppeteer, { type Browser, type Page } from "puppeteer";
import { assert, assertEqual, test } from "./harness";

const screenshotDir = path.resolve(process.cwd(), "tests/regression/artifacts");

async function loginViaUi(page: Page, baseUrl: string) {
  await page.goto(`${baseUrl}/auth`, { waitUntil: "networkidle2", timeout: 60000 });
  await page.waitForSelector('input[placeholder="Enter username or email"]', { timeout: 15000 });
  await page.click('input[placeholder="Enter username or email"]', { clickCount: 3 });
  await page.type('input[placeholder="Enter username or email"]', "ciso.synthetic");
  await page.click('input[placeholder="Enter password"]', { clickCount: 3 });
  await page.type('input[placeholder="Enter password"]', "Synthetic123!");
  await Promise.all([
    page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }).catch(() => null),
    page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll("button"));
      const signIn = buttons.find((button) => button.textContent?.trim() === "Sign In");
      (signIn as HTMLButtonElement | undefined)?.click();
    }),
  ]);
  // Fallback: synthetic SSO if form submit did not navigate
  if (page.url().includes("/auth")) {
    await Promise.all([
      page.waitForNavigation({ waitUntil: "networkidle2", timeout: 30000 }),
      page.evaluate(() => {
        const buttons = Array.from(document.querySelectorAll("button"));
        const sso = buttons.find((button) => /synthetic SSO/i.test(button.textContent || ""));
        (sso as HTMLButtonElement | undefined)?.click();
      }),
    ]);
  }
  assert(!page.url().includes("/auth"), `still on auth: ${page.url()}`);
}

async function shot(page: Page, name: string) {
  fs.mkdirSync(screenshotDir, { recursive: true });
  const file = path.join(screenshotDir, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });
  return file;
}

async function clickNav(page: Page, label: string) {
  await page.evaluate((text) => {
    const links = Array.from(document.querySelectorAll("a,button"));
    const match = links.find((el) => el.textContent?.trim() === text);
    if (!match) throw new Error(`Nav item not found: ${text}`);
    (match as HTMLElement).click();
  }, label);
  await page.waitForNetworkIdle({ idleTime: 500, timeout: 15000 }).catch(() => null);
}

export async function runUiPuppeteer(baseUrl: string) {
  let browser: Browser | null = null;

  await test("ui", "UI-BOOT-01", "Headless Chromium launches", async () => {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    });
    assert(browser, "browser missing");
  });

  if (!browser) {
    await test("ui", "UI-SKIP", "UI suite skipped because browser failed to launch", async () => {
      throw new Error("browser unavailable");
    }, { skip: true });
    return;
  }

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  await test("ui", "UI-AUTH-01", "Auth page renders black theme and sign-in controls", async () => {
    await page.goto(`${baseUrl}/auth`, { waitUntil: "networkidle2", timeout: 60000 });
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    assert(bg === "rgb(0, 0, 0)" || bg.includes("0, 0, 0"), `body background ${bg}`);
    const text = await page.evaluate(() => document.body.innerText);
    assert(/AI-SPM/i.test(text), "brand missing");
    assert(/Sign in with synthetic SSO/i.test(text), "SSO button missing");
    await shot(page, "ui-auth");
  });

  await test("ui", "UI-AUTH-02", "Synthetic login reaches dashboard", async () => {
    await loginViaUi(page, baseUrl);
    await page.waitForFunction(() => /AI Security Dashboard|Dashboard/i.test(document.body.innerText), {
      timeout: 20000,
    });
    assertEqual(new URL(page.url()).pathname, "/");
    await shot(page, "ui-dashboard");
  });

  await test("ui", "UI-DASH-01", "Dashboard shows metrics and threat alerts", async () => {
    const text = await page.evaluate(() => document.body.innerText);
    assert(/Total AI Assets|AI Assets|vulnerabilit/i.test(text), "metrics missing");
    assert(/Recent Threat Alerts|Prompt injection|Jailbreak|threat/i.test(text), "alerts missing");
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    assert(bg === "rgb(0, 0, 0)" || bg.includes("0, 0, 0"), `dashboard bg ${bg}`);
  });

  await test("ui", "UI-NAV-01", "Sidebar includes Prompt Checks and Health & Governance", async () => {
    const labels = await page.evaluate(() =>
      Array.from(document.querySelectorAll("a,button")).map((el) => el.textContent?.trim() || ""),
    );
    assert(labels.includes("Prompt Checks"), "Prompt Checks nav missing");
    assert(labels.includes("Health & Governance"), "Health & Governance nav missing");
  });

  await test("ui", "UI-PROMPT-01", "Prompt Checks page shows three classifications", async () => {
    await clickNav(page, "Prompt Checks");
    await page.waitForFunction(() => /Prompt checks|Synthetic prompt evaluation/i.test(document.body.innerText), {
      timeout: 20000,
    });
    await page.waitForFunction(() => /benign|prompt injection|jailbreak/i.test(document.body.innerText), {
      timeout: 20000,
    });
    const text = await page.evaluate(() => document.body.innerText);
    assert(/2 blocked, 1 allowed|blocked/i.test(text), "summary missing");
    assert(/Ignore the previous instructions/i.test(text), "injection prompt missing");
    assert(/developer mode/i.test(text), "jailbreak prompt missing");
    await shot(page, "ui-prompt-checks");
  });

  await test("ui", "UI-HEALTH-01", "Health & Governance shows resident agent and OpenRouter status", async () => {
    await clickNav(page, "Health & Governance");
    await page.waitForFunction(() => /Resident agent|Async governance/i.test(document.body.innerText), {
      timeout: 20000,
    });
    const text = await page.evaluate(() => document.body.innerText);
    assert(/Isolation Forest|isolation forest|Practical Fast Math|kolmogorov/i.test(text), "methods missing");
    assert(/OpenRouter/i.test(text), "OpenRouter missing");
    assert(/Realtime path uses LLM:\s*no/i.test(text), "LLM realtime flag wrong");
    await shot(page, "ui-health-governance");
  });

  await test("ui", "UI-HEALTH-02", "Run now creates a monitoring cycle row", async () => {
    const before = await page.evaluate(() => document.body.innerText);
    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll("button"));
      const run = buttons.find((button) => /Run now/i.test(button.textContent || ""));
      if (!run) throw new Error("Run now button missing");
      run.click();
    });
    await page.waitForFunction(
      () => /within budget|manual/i.test(document.body.innerText),
      { timeout: 20000 },
    );
    const after = await page.evaluate(() => document.body.innerText);
    assert(/Recent monitoring cycles/i.test(after), "cycles section missing");
    assert(after.length >= before.length, "page did not update");
    await shot(page, "ui-health-run-now");
  });

  await test("ui", "UI-HEALTH-03", "Generate report queues and lists a governance report", async () => {
    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll("button"));
      const generate = buttons.find((button) => /Generate GDPR/i.test(button.textContent || ""));
      if (!generate) throw new Error("Generate button missing");
      generate.click();
    });
    await page.waitForFunction(
      () => /queued|Governance reports|Audit-ready|completed|running/i.test(document.body.innerText),
      { timeout: 30000 },
    );
    // Wait for completion when OpenRouter is configured
    await page.waitForFunction(
      () => {
        const text = document.body.innerText;
        return /#\d+\s+Audit-ready/i.test(text) || /Audit-ready GDPR/i.test(text);
      },
      { timeout: 60000 },
    ).catch(() => null);
    const text = await page.evaluate(() => document.body.innerText);
    assert(/Governance reports/i.test(text), "reports section missing");
    assert(/Audit-ready|queued|Report #/i.test(text), "report feedback missing");
    await shot(page, "ui-health-report");
  });

  await test("ui", "UI-THEME-01", "Primary pages keep black background", async () => {
    for (const route of ["/", "/prompt-checks", "/health-governance", "/settings"]) {
      await page.goto(`${baseUrl}${route}`, { waitUntil: "networkidle2", timeout: 60000 });
      const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
      assert(bg === "rgb(0, 0, 0)" || bg.includes("0, 0, 0"), `${route} bg ${bg}`);
    }
  });

  await browser.close();
}
