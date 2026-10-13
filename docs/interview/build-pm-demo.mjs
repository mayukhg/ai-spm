#!/usr/bin/env node
/**
 * Builds an interview demo MP4 with narration + burned-in subtitles.
 * Usage: node docs/interview/build-pm-demo.mjs
 */
import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import puppeteer from "puppeteer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "../..");
const outDir = __dirname;
const audioDir = path.join(outDir, "audio");
const framesDir = path.join(outDir, "frames");
const assetsDir = path.join(outDir, "assets");
const shots = path.join(root, "tests/regression/artifacts/integration");

for (const d of [audioDir, framesDir, assetsDir]) fs.mkdirSync(d, { recursive: true });

const VOICE = process.env.DEMO_VOICE || "Kathy";
const W = 1920;
const H = 1080;

/** @type {{ id: string, title: string, subtitleLines: string[], narration: string, image?: string, card?: { eyebrow: string, headline: string, bullets?: string[] } }[]} */
const scenes = [
  {
    id: "01-open",
    title: "Opening",
    narration:
      "Hi — I'm walking you through AI-SPM, an AI Security Posture Management product I designed from a real enterprise pain point. This is a product-management walkthrough: the customer problem, how I prioritized the solution, and how each workflow maps to an outcome.",
    card: {
      eyebrow: "Product Demo · Interview Walkthrough",
      headline: "AI Security Posture Management",
      bullets: ["Customer pain → product design", "Workflows that CISOs actually use", "Measurable security & compliance outcomes"],
    },
    subtitleLines: [
      "Walking through AI-SPM from a product-management lens.",
      "Pain point → prioritization → workflows → outcomes.",
    ],
  },
  {
    id: "02-pain",
    title: "Customer pain",
    narration:
      "The pain became clear in discovery with CISOs and compliance leads. Teams were shipping models and agents without a single inventory. Traditional AppSec tools were blind to prompt injection, jailbreaks, data poisoning, and drift. Audits for GDPR and NIST A.I. R.M.F. were manual and took months. The job to be done: give security leaders continuous visibility and evidence across the A.I. lifecycle — without blocking ML teams.",
    card: {
      eyebrow: "Discovery · Jobs To Be Done",
      headline: "What customers told us",
      bullets: [
        "No single inventory of models, datasets, endpoints",
        "AppSec blind to prompt injection, jailbreaks, poisoning",
        "GDPR / NIST AI RMF audits = months of manual work",
        "JTBD: continuous AI posture evidence without slowing ML",
      ],
    },
    subtitleLines: [
      "Discovery with CISOs & compliance: no AI inventory.",
      "AppSec blind to jailbreaks, poisoning, drift.",
      "JTBD: continuous posture evidence without blocking ML.",
    ],
  },
  {
    id: "03-skills",
    title: "PM craft",
    narration:
      "As P.M., I framed personas — CISO, analyst, engineer, compliance officer — and used outcome-based prioritization. We cut scope to a thin vertical: synthetic fixtures for trust, Practical Fast Math under one hundred milliseconds for resident monitoring, and async OpenRouter only for natural-language governance narratives. That separation of realtime versus async L.L.M. spend was a deliberate cost and latency decision.",
    card: {
      eyebrow: "PM Skills Applied",
      headline: "How the product was designed",
      bullets: [
        "Personas: CISO · Analyst · Engineer · Compliance",
        "Prioritize outcomes over feature sprawl",
        "Realtime path: Practical Fast Math <100ms",
        "Async path: OpenRouter only for GDPR/NIST narratives",
      ],
    },
    subtitleLines: [
      "Personas + outcome-based prioritization.",
      "Realtime: Fast Math <100ms. Async LLM for narratives only.",
    ],
  },
  {
    id: "04-dashboard",
    title: "Dashboard",
    image: "01-dashboard.png",
    narration:
      "The dashboard is the CISO home. Metrics cards answer: how many assets, how many critical findings, open alerts, compliance score. Quick Actions encode the primary jobs — run a scan, generate a governance report, open a security audit, configure policies — so the product leads the user into the right workflow instead of dumping them into a blank page.",
    subtitleLines: [
      "CISO home: assets, criticals, alerts, compliance.",
      "Quick Actions encode primary jobs — not dead buttons.",
    ],
  },
  {
    id: "05-assets",
    title: "AI Assets",
    image: "ui-nav-assets.png",
    narration:
      "Asset inventory was the first must-have from discovery. Models, datasets, and endpoints are first-class. From here a CISO or engineer can add an asset and kick off a scan — closing the loop from unknown sprawl to known, scannable inventory.",
    subtitleLines: [
      "First must-have: inventory of models, datasets, endpoints.",
      "Add asset → scan closes unknown sprawl.",
    ],
  },
  {
    id: "06-vulns",
    title: "Vulnerabilities",
    image: "ui-nav-vulns.png",
    narration:
      "Scan results land in Vulnerabilities with severity rollups. This is the triage workflow for analysts — critical and high first — and it mirrors how security teams already work in AppSec, so adoption friction stays low.",
    subtitleLines: [
      "Scan results → severity rollups for analyst triage.",
      "Familiar AppSec pattern to reduce adoption friction.",
    ],
  },
  {
    id: "07-monitoring",
    title: "Monitoring",
    image: "ui-nav-monitor.png",
    narration:
      "Monitoring is the realtime alert surface — jailbreaks, injections, anomalous behavior — with live polling that analysts can pause. Product decision: keep pause as a local attention control, not a fake backend switch.",
    subtitleLines: [
      "Realtime alerts: jailbreaks, injections, anomalies.",
      "Pause is an attention control — honest UX.",
    ],
  },
  {
    id: "08-prompts",
    title: "Prompt Checks",
    image: "ui-nav-prompt.png",
    narration:
      "Prompt Checks productizes A.I.-specific threat testing. Classify synthetic benign and jailbreak prompts, store alerts, and feed the dashboard. This came directly from the insight that customers needed proof of controls — not just policies on paper.",
    subtitleLines: [
      "AI-specific threat testing: classify → store alerts.",
      "Proof of controls, not policies on paper.",
    ],
  },
  {
    id: "09-health",
    title: "Health & Governance",
    image: "ui-nav-health.png",
    narration:
      "Health and Governance is the differentiator. A resident agent runs Practical Fast Math every fifteen minutes — isolation forest, L.O.F., and drift — always under one hundred milliseconds. Run now is for operators who need on-demand evidence. Generate G.D.P.R. and NIST report queues an async narrative via OpenRouter, so expensive L.L.M. calls never sit on the critical path.",
    subtitleLines: [
      "Resident agent every 15m: IF + LOF + drift <100ms.",
      "GDPR/NIST reports async via OpenRouter — off critical path.",
    ],
  },
  {
    id: "10-compliance",
    title: "Compliance",
    image: "ui-nav-compliance.png",
    narration:
      "Compliance maps frameworks to scores and assessments for compliance officers. Export, schedule assessment, and deep-link into governance reports — because the persona's success metric is audit-ready evidence, not more dashboards.",
    subtitleLines: [
      "Framework scores + assessments for compliance officers.",
      "Success metric: audit-ready evidence.",
    ],
  },
  {
    id: "11-agentic",
    title: "Agentic Workflows",
    image: "ui-nav-agentic.png",
    narration:
      "Agentic Workflows anticipates the next wave of risk — autonomous agents and M.C.P. contexts. Create Agent registers a supervised agent under zero-trust controls. As P.M., I sequenced this after core posture so we did not boil the ocean before the inventory and monitoring spine worked.",
    subtitleLines: [
      "Next-wave risk: agents + MCP under zero-trust.",
      "Sequenced after inventory & monitoring spine.",
    ],
  },
  {
    id: "12-sysmon",
    title: "System Monitoring",
    image: "ui-nav-sys.png",
    narration:
      "System Monitoring is platform reliability for the security product itself — components, health, acknowledge. Trust in an S.P.M. tool collapses if the tool is opaque, so we treated product health as a first-class workflow.",
    subtitleLines: [
      "Platform health of the SPM tool itself.",
      "Trust requires the product to be observable.",
    ],
  },
  {
    id: "13-threat",
    title: "Threat Configuration",
    image: "ui-nav-threat.png",
    narration:
      "Threat Configuration is CISO-gated. Enable threats, tune thresholds, reload config. Role-based access was a deliberate trust and least-privilege decision — analysts monitor; CISOs set policy.",
    subtitleLines: [
      "CISO-gated: enable threats, tune thresholds.",
      "Least privilege: analysts monitor; CISOs set policy.",
    ],
  },
  {
    id: "14-settings",
    title: "Settings & Users",
    image: "ui-nav-settings.png",
    narration:
      "Settings surfaces fixtures, OpenRouter status, and governance policies. User Management — also CISO-only — completes the operating model. Together they show how I designed admin surfaces around governance, not just feature toggles.",
    subtitleLines: [
      "Settings: fixtures, OpenRouter, policies.",
      "Admin surfaces designed for governance.",
    ],
  },
  {
    id: "15-close",
    title: "Close",
    narration:
      "To close: I started from customer pain — invisible A.I. risk and slow audits — then designed a persona-aware product with a clear architecture bet: fast math in the loop, L.L.M. out of band. The result is a walkable system from inventory to scan to alerts to compliance evidence. Happy to go deeper on discovery interviews, prioritization tradeoffs, or the roadmap next.",
    card: {
      eyebrow: "Outcomes · Interview Close",
      headline: "From pain to walkable product",
      bullets: [
        "Invisible AI risk → continuous posture",
        "Slow audits → async GDPR/NIST evidence",
        "Fast math in-loop · LLM out-of-band",
        "Ready for Q&A on discovery, tradeoffs, roadmap",
      ],
    },
    subtitleLines: [
      "Pain → persona design → architecture bet.",
      "Inventory → scan → alerts → compliance evidence.",
      "Happy to go deeper on discovery, tradeoffs, roadmap.",
    ],
  },
];

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function renderFrame(page, { card, bgDataUrl, captions }, outPath) {
  const captionHtml = (captions || [])
    .map((c) => `<div class="cap-line">${escHtml(c)}</div>`)
    .join("");
  let body;
  if (card) {
    const bullets = (card.bullets || []).map((b) => `<li>${escHtml(b)}</li>`).join("");
    body = `
      <div class="card-wrap">
        <div class="eyebrow">${escHtml(card.eyebrow)}</div>
        <h1>${escHtml(card.headline)}</h1>
        <ul>${bullets}</ul>
        <div class="footer">AI-SPM  ·  Product Management Demo</div>
      </div>
      <div class="caption">${captionHtml}</div>`;
  } else {
    body = `
      <div class="shot" style="background-image:url('${bgDataUrl}')"></div>
      <div class="caption">${captionHtml}</div>`;
  }
  await page.setContent(
    `<!DOCTYPE html><html><head><style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{width:${W}px;height:${H}px;background:#000;color:#f5f5f5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;overflow:hidden;position:relative}
      .card-wrap{padding:140px 120px 200px}
      .eyebrow{color:#93c5fd;font-size:34px;font-weight:600;margin-bottom:18px;letter-spacing:.02em}
      h1{font-size:58px;line-height:1.15;font-weight:700;margin-bottom:36px;max-width:1500px}
      ul{list-style:none;display:flex;flex-direction:column;gap:18px}
      li{font-size:30px;color:#c7c7c7;padding-left:28px;position:relative}
      li:before{content:"•";position:absolute;left:0;color:#3b82f6}
      .footer{position:absolute;left:120px;bottom:140px;color:#666;font-size:24px}
      .shot{position:absolute;inset:0 0 110px 0;background:#000 center/contain no-repeat}
      .caption{position:absolute;left:0;right:0;bottom:0;min-height:110px;padding:16px 80px 22px;background:linear-gradient(transparent,rgba(0,0,0,.92) 30%);display:flex;flex-direction:column;justify-content:flex-end;gap:6px}
      .cap-line{text-align:center;font-size:28px;font-weight:600;text-shadow:0 2px 8px #000;line-height:1.3}
    </style></head><body>${body}</body></html>`,
    { waitUntil: "load" },
  );
  await page.screenshot({ path: outPath, type: "png" });
}

function toDataUrl(filePath) {
  const buf = fs.readFileSync(filePath);
  const ext = path.extname(filePath).slice(1) || "png";
  return `data:image/${ext};base64,${buf.toString("base64")}`;
}

function sayToAiff(text, outAiff) {
  const tmpTxt = outAiff + ".txt";
  fs.writeFileSync(tmpTxt, text);
  execFileSync("say", ["-v", VOICE, "-f", tmpTxt, "-o", outAiff], { stdio: "inherit" });
  fs.unlinkSync(tmpTxt);
}

function aiffToWav(aiff, wav) {
  execFileSync("ffmpeg", ["-y", "-i", aiff, wav], { stdio: "inherit" });
}

function durationOf(file) {
  const out = execFileSync(
    "ffprobe",
    ["-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", file],
    { encoding: "utf8" },
  ).trim();
  return Math.max(0.5, parseFloat(out));
}

function formatSrtTime(sec) {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  const ms = Math.round((sec - Math.floor(sec)) * 1000);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")},${String(ms).padStart(3, "0")}`;
}

console.log(`Voice: ${VOICE}`);
console.log(`Scenes: ${scenes.length}`);

const browser = await puppeteer.launch({
  headless: true,
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
});
const page = await browser.newPage();
await page.setViewport({ width: W, height: H, deviceScaleFactor: 1 });

const durations = [];
const frameFiles = [];

for (let i = 0; i < scenes.length; i++) {
  const scene = scenes[i];
  const n = String(i + 1).padStart(2, "0");
  console.log(`\n=== Scene ${n}: ${scene.title} ===`);

  const framePath = path.join(framesDir, `${n}.png`);
  if (scene.card) {
    await renderFrame(page, { card: scene.card, captions: scene.subtitleLines }, framePath);
  } else if (scene.image) {
    const src = path.join(shots, scene.image);
    if (!fs.existsSync(src)) throw new Error(`Missing screenshot: ${src}`);
    await renderFrame(
      page,
      { bgDataUrl: toDataUrl(src), captions: scene.subtitleLines },
      framePath,
    );
  } else {
    throw new Error(`Scene ${scene.id} has no visual`);
  }
  frameFiles.push(framePath);

  const aiff = path.join(audioDir, `${n}.aiff`);
  const wav = path.join(audioDir, `${n}.wav`);
  sayToAiff(scene.narration, aiff);
  aiffToWav(aiff, wav);
  const dur = durationOf(wav);
  durations.push({ wav, dur, scene });
  console.log(`Duration: ${dur.toFixed(2)}s`);
}
await browser.close();

// Build per-scene video clips (image + audio)
const clipPaths = [];
for (let i = 0; i < scenes.length; i++) {
  const n = String(i + 1).padStart(2, "0");
  const clip = path.join(framesDir, `${n}.mp4`);
  const { wav, dur } = durations[i];
  // slight pad so last syllable isn't cut
  const hold = (dur + 0.35).toFixed(3);
  execFileSync(
    "ffmpeg",
    [
      "-y",
      "-loop",
      "1",
      "-i",
      frameFiles[i],
      "-i",
      wav,
      "-c:v",
      "libx264",
      "-tune",
      "stillimage",
      "-c:a",
      "aac",
      "-b:a",
      "192k",
      "-pix_fmt",
      "yuv420p",
      "-t",
      hold,
      "-shortest",
      clip,
    ],
    { stdio: "inherit" },
  );
  clipPaths.push(clip);
}

const listFile = path.join(framesDir, "concat.txt");
fs.writeFileSync(listFile, clipPaths.map((p) => `file '${p}'`).join("\n"));

const rawVideo = path.join(outDir, "AI_SPM_PM_Demo_raw.mp4");
execFileSync(
  "ffmpeg",
  ["-y", "-f", "concat", "-safe", "0", "-i", listFile, "-c", "copy", rawVideo],
  { stdio: "inherit" },
);

// Build SRT from scene subtitle lines + durations
let cursor = 0;
let srtIdx = 1;
const srtChunks = [];
for (let i = 0; i < durations.length; i++) {
  const { dur, scene } = durations[i];
  const hold = dur + 0.35;
  const lines = scene.subtitleLines.length ? scene.subtitleLines : [scene.narration.slice(0, 90) + "…"];
  const slice = hold / lines.length;
  for (let j = 0; j < lines.length; j++) {
    const start = cursor + j * slice;
    const end = cursor + (j + 1) * slice;
    srtChunks.push(
      `${srtIdx}\n${formatSrtTime(start)} --> ${formatSrtTime(end)}\n${lines[j]}\n`,
    );
    srtIdx += 1;
  }
  cursor += hold;
}
const srtPath = path.join(outDir, "AI_SPM_PM_Demo.srt");
fs.writeFileSync(srtPath, srtChunks.join("\n"));

// Soft-mux SRT (captions also burned into frames). Copy to final name.
const finalVideo = path.join(outDir, "AI_SPM_PM_Demo.mp4");
try {
  execFileSync(
    "ffmpeg",
    [
      "-y",
      "-i",
      rawVideo,
      "-i",
      srtPath,
      "-c:v",
      "copy",
      "-c:a",
      "copy",
      "-c:s",
      "mov_text",
      "-metadata:s:s:0",
      "language=eng",
      "-disposition:s:0",
      "default",
      finalVideo,
    ],
    { stdio: "inherit" },
  );
} catch {
  fs.copyFileSync(rawVideo, finalVideo);
  console.warn("Soft-subtitle mux failed; shipped video with burned-in frame captions only.");
}

// Script transcript for interview prep
const transcript = scenes
  .map((s, i) => `## ${i + 1}. ${s.title}\n\n${s.narration}\n\n**On-screen captions:**\n${s.subtitleLines.map((l) => `- ${l}`).join("\n")}\n`)
  .join("\n");
fs.writeFileSync(path.join(outDir, "PM_DEMO_SCRIPT.md"), `# AI-SPM PM Interview Demo Script\n\nVoice: ${VOICE}\nTotal scenes: ${scenes.length}\n\n${transcript}`);

const total = durations.reduce((a, d) => a + d.dur + 0.35, 0);
console.log(`\nDone.`);
console.log(`Video: ${finalVideo}`);
console.log(`Subtitles: ${srtPath}`);
console.log(`Approx duration: ${total.toFixed(1)}s (${(total / 60).toFixed(1)} min)`);
