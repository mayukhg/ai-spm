#!/usr/bin/env node
/**
 * Silent live-app walkthrough with burned-in hybrid PM captions.
 * No voice. No SRT. Output: docs/interview/AI_SPM_PM_Demo.mp4
 *
 * Usage: node docs/interview/build-silent-walkthrough.mjs
 */
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "../..");
const outDir = __dirname;
const framesDir = path.join(outDir, "walk-frames");
const baseUrl = process.env.BASE_URL || "http://127.0.0.1:5050";
const W = 1440;
const H = 900;
const FPS = 3; // smoother silent walkthrough

fs.rmSync(framesDir, { recursive: true, force: true });
fs.mkdirSync(framesDir, { recursive: true });

let frameIdx = 0;
/** @type {import('puppeteer').Page} */
let page;

async function loginCiso(browserPage) {
  const loginRes = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "ciso.synthetic", password: "Synthetic123!" }),
  });
  if (!loginRes.ok) throw new Error(`login ${loginRes.status}`);
  const setCookies = loginRes.headers.getSetCookie?.() ?? [];
  const fallback = loginRes.headers.get("set-cookie");
  const raw = setCookies.length ? setCookies : fallback ? [fallback] : [];
  if (!raw.length) throw new Error("no session cookie");
  const origin = new URL(baseUrl);
  await browserPage.setCookie(
    ...raw.map((entry) => {
      const [pair] = entry.split(";");
      const eq = pair.indexOf("=");
      return {
        name: pair.slice(0, eq),
        value: pair.slice(eq + 1),
        domain: origin.hostname,
        path: "/",
        httpOnly: true,
      };
    }),
  );
  await browserPage.goto(`${baseUrl}/`, { waitUntil: "networkidle2", timeout: 60000 });
  if (browserPage.url().includes("/auth")) throw new Error("auth failed");
}

async function ensureCaptionBar() {
  await page.evaluate(() => {
    if (document.getElementById("pm-demo-caption")) return;
    const style = document.createElement("style");
    style.id = "pm-demo-caption-style";
    style.textContent = `
      #pm-demo-caption {
        position: fixed; left: 0; right: 0; bottom: 0; z-index: 2147483646;
        padding: 14px 28px 18px;
        background: linear-gradient(transparent, rgba(0,0,0,.88) 28%);
        color: #fff; font: 600 18px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        text-align: center; pointer-events: none;
        text-shadow: 0 1px 4px #000;
      }
      #pm-demo-caption .line { display: block; }
      #pm-demo-caption .sub {
        display: block; margin-top: 4px; font-weight: 500; font-size: 15px; color: #d4d4d4;
      }
    `;
    document.head.appendChild(style);
    const el = document.createElement("div");
    el.id = "pm-demo-caption";
    el.innerHTML = `<span class="line"></span><span class="sub"></span>`;
    document.body.appendChild(el);
  });
}

async function setCaption(line, sub = "") {
  await ensureCaptionBar();
  await page.evaluate(
    (a, b) => {
      const el = document.getElementById("pm-demo-caption");
      el.querySelector(".line").textContent = a || "";
      el.querySelector(".sub").textContent = b || "";
    },
    line,
    sub,
  );
}

async function captureFrames(seconds) {
  const n = Math.max(1, Math.round(seconds * FPS));
  for (let i = 0; i < n; i++) {
    const file = path.join(framesDir, `f${String(frameIdx).padStart(5, "0")}.png`);
    await page.screenshot({ path: file, type: "png" });
    frameIdx += 1;
    if (i < n - 1) await new Promise((r) => setTimeout(r, 1000 / FPS));
  }
}

async function clickNav(label) {
  await page.goto(`${baseUrl}/`, { waitUntil: "networkidle2", timeout: 60000 }).catch(() => null);
  const clicked = await page.evaluate((text) => {
    const el = Array.from(document.querySelectorAll("a")).find((node) => {
      const content = (node.textContent || "").replace(/\s+/g, " ").trim();
      return content === text || content.includes(text);
    });
    if (!el) return false;
    el.click();
    return true;
  }, label);
  if (!clicked) throw new Error(`Nav missing: ${label}`);
  await page.waitForNetworkIdle({ idleTime: 600, timeout: 20000 }).catch(() => null);
  await ensureCaptionBar();
}

async function clickButton(pattern) {
  const reSource = pattern instanceof RegExp ? pattern.source : String(pattern);
  const clicked = await page.evaluate((source) => {
    const re = new RegExp(source, "i");
    const btn = Array.from(document.querySelectorAll("button")).find((node) =>
      re.test(node.textContent || ""),
    );
    if (!btn) return false;
    btn.click();
    return true;
  }, reSource);
  if (!clicked) throw new Error(`Button not found: ${reSource}`);
  await page.waitForNetworkIdle({ idleTime: 600, timeout: 25000 }).catch(() => null);
  await ensureCaptionBar();
}

async function scene(caption, sub, { before = 4, after = 6, action } = {}) {
  console.log(`• ${caption}`);
  await setCaption(caption, sub);
  await captureFrames(before);
  if (action) {
    await action();
    await ensureCaptionBar();
    await setCaption(caption, sub);
  }
  await captureFrames(after);
}

async function main() {
  const health = await fetch(`${baseUrl}/api/health`);
  if (!health.ok) throw new Error(`App not up at ${baseUrl}`);

  const browser = await puppeteer.launch({
    headless: true,
    defaultViewport: { width: W, height: H },
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", `--window-size=${W},${H}`],
  });
  page = await browser.newPage();
  await page.setViewport({ width: W, height: H });

  // --- Walkthrough (~3–4 min at FPS=3 with dwell) ---
  await scene("Sign in as CISO", "Persona gate: least-privilege entry into AI posture workflows", {
    before: 0,
    after: 6,
    action: async () => {
      await page.goto(`${baseUrl}/auth`, { waitUntil: "networkidle2", timeout: 60000 });
      await ensureCaptionBar();
      await setCaption("Sign in as CISO", "Persona gate: least-privilege entry into AI posture workflows");
      await captureFrames(3);
      await loginCiso(page);
      await ensureCaptionBar();
    },
  });

  await scene("Dashboard — CISO home", "Outcome surface: assets, criticals, alerts, and compliance at a glance", {
    before: 2,
    after: 10,
    action: async () => {
      await page.goto(`${baseUrl}/`, { waitUntil: "networkidle2", timeout: 60000 });
      await ensureCaptionBar();
    },
  });

  await scene("Quick Action → Run Asset Scan", "Primary job on the home surface: inventory → scan", {
    before: 4,
    after: 8,
    action: async () => {
      await clickButton(/Run Asset Scan|Scanning/);
      await page
        .waitForFunction(() => /Vulnerability|Scanning|scan/i.test(document.body.innerText), { timeout: 45000 })
        .catch(() => null);
    },
  });

  await scene("Vulnerabilities — analyst triage", "Severity rollups match how AppSec teams already work", {
    before: 2,
    after: 10,
    action: async () => {
      await clickNav("Vulnerabilities");
    },
  });

  await scene(
    "Prompt Checks — AI-specific proof",
    "Classify jailbreak / benign prompts → store alerts (controls, not paper policy)",
    {
      before: 2,
      after: 8,
      action: async () => {
        await clickNav("Prompt Checks");
      },
    },
  );

  await scene("Classify and store alerts", "Productizing threat testing into an auditable workflow", {
    before: 3,
    after: 8,
    action: async () => {
      await clickButton(/Classify and store alerts/);
      await page
        .waitForFunction(() => /blocked|benign|jailbreak|alert/i.test(document.body.innerText), { timeout: 20000 })
        .catch(() => null);
    },
  });

  await scene(
    "Health & Governance — differentiator",
    "Resident Fast Math <100ms in-loop; LLM kept off the critical path",
    {
      before: 2,
      after: 10,
      action: async () => {
        await clickNav("Health & Governance");
      },
    },
  );

  await scene("Run now — on-demand evidence", "Operator control for continuous posture without waiting for the 15m tick", {
    before: 3,
    after: 8,
    action: async () => {
      await clickButton(/^Run now$/);
      await page
        .waitForFunction(
          () => /within budget|manual|Monitoring cycle|finished/i.test(document.body.innerText),
          { timeout: 20000 },
        )
        .catch(() => null);
    },
  });

  await scene(
    "Generate GDPR / NIST report",
    "Async OpenRouter narrative for auditors — cost/latency product decision",
    {
      before: 3,
      after: 10,
      action: async () => {
        await clickButton(/Generate GDPR/);
        await page
          .waitForFunction(
            () => /queued|Report #|Audit-ready|Governance reports|processing|complete/i.test(document.body.innerText),
            { timeout: 30000 },
          )
          .catch(() => null);
      },
    },
  );

  await scene("Compliance — audit-ready evidence", "Framework scores + export for the compliance officer persona", {
    before: 2,
    after: 9,
    action: async () => {
      await clickNav("Compliance");
    },
  });

  await scene("Export Report", "Success metric: downloadable evidence, not another dashboard", {
    before: 3,
    after: 7,
    action: async () => {
      await clickButton(/Export Report/);
      await new Promise((r) => setTimeout(r, 800));
    },
  });

  await scene(
    "Agentic Workflows — next-wave risk",
    "Sequenced after the inventory/monitor spine; agents + MCP under zero-trust",
    {
      before: 2,
      after: 9,
      action: async () => {
        await clickNav("Agentic Workflows");
      },
    },
  );

  await scene(
    "Create Agent",
    "Compliance-gated registration — GDPR access policy required before the agent is created",
    {
      before: 3,
      after: 8,
      action: async () => {
        await clickButton(/Create Agent/);
        await page
          .waitForFunction(
            () => /Agent registered|Created agent/i.test(document.body.innerText),
            { timeout: 20000 },
          )
          .catch(() => null);
      },
    },
  );

  await scene("System Monitoring — trust the tool", "SPM must be observable: component health of the platform itself", {
    before: 2,
    after: 9,
    action: async () => {
      await clickNav("System Monitoring");
      await page
        .waitForFunction(() => /System Status|Components|Refresh|healthy|degraded/i.test(document.body.innerText), {
          timeout: 20000,
        })
        .catch(() => null);
    },
  });

  await scene("Refresh system health", "Operators can re-check posture of the security product on demand", {
    before: 3,
    after: 7,
    action: async () => {
      await clickButton(/^Refresh$/);
      await page.waitForNetworkIdle({ idleTime: 500, timeout: 10000 }).catch(() => null);
    },
  });

  await scene("Threat Configuration — CISO policy", "Role-gated: analysts monitor; CISOs set detection thresholds", {
    before: 2,
    after: 10,
    action: async () => {
      await clickNav("Threat Configuration");
    },
  });

  await scene(
    "Spine complete",
    "Inventory → detect → govern → evidence — designed from CISO & compliance pain",
    {
      before: 2,
      after: 12,
      action: async () => {
        await clickNav("Dashboard");
      },
    },
  );

  await browser.close();

  console.log(`\nCaptured ${frameIdx} frames @ ${FPS} fps`);
  const seconds = frameIdx / FPS;
  console.log(`Approx duration: ${seconds.toFixed(1)}s (${(seconds / 60).toFixed(1)} min)`);

  const listPath = path.join(framesDir, "frames.txt");
  const files = fs
    .readdirSync(framesDir)
    .filter((f) => f.endsWith(".png"))
    .sort();
  // ffmpeg concat demuxer for image sequence via -framerate is cleaner
  const finalVideo = path.join(outDir, "AI_SPM_PM_Demo.mp4");
  const pattern = path.join(framesDir, "f%05d.png");
  execFileSync(
    "ffmpeg",
    [
      "-y",
      "-framerate",
      String(FPS),
      "-i",
      pattern,
      "-c:v",
      "libx264",
      "-pix_fmt",
      "yuv420p",
      "-vf",
      "scale=1440:900:force_original_aspect_ratio=decrease,pad=1440:900:(ow-iw)/2:(oh-ih)/2",
      "-an",
      "-movflags",
      "+faststart",
      finalVideo,
    ],
    { stdio: "inherit" },
  );

  // Remove old SRT / raw / voiced artifacts if present
  for (const f of ["AI_SPM_PM_Demo.srt", "AI_SPM_PM_Demo_raw.mp4", "PM_DEMO_SCRIPT.md"]) {
    const p = path.join(outDir, f);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }

  console.log(`\nWrote silent walkthrough: ${finalVideo}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
