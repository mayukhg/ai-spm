/**
 * Regression suite runner for AI-SPM changes:
 * - Practical Fast Math + resident agent
 * - Prompt/jailbreak classifier
 * - Async OpenRouter governance
 * - Dark UI pages
 *
 * Usage: npx tsx tests/regression/run-suite.ts
 * Env: BASE_URL (default http://127.0.0.1:5050)
 */
import "dotenv/config";
import fs from "fs";
import path from "path";
import { buildReport, toMarkdown } from "./harness";
import { runUnitFastMath } from "./unit-fast-math";
import { runFunctionalApi } from "./functional-api";
import { runUiPuppeteer } from "./ui-puppeteer";

const baseUrl = process.env.BASE_URL || "http://127.0.0.1:5050";
const outDir = path.resolve(process.cwd(), "tests/regression/artifacts");
const reportJson = path.resolve(process.cwd(), "docs/REGRESSION_VALIDATION_REPORT.json");
const reportMd = path.resolve(process.cwd(), "docs/REGRESSION_VALIDATION_REPORT.md");

async function ensureAppUp() {
  const response = await fetch(`${baseUrl}/api/health`);
  if (!response.ok) {
    throw new Error(`App not reachable at ${baseUrl}/api/health (HTTP ${response.status})`);
  }
}

async function main() {
  console.log(`\n=== AI-SPM Regression Suite ===\nBase URL: ${baseUrl}\n`);
  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(path.dirname(reportMd), { recursive: true });

  await ensureAppUp();

  console.log("\n-- Unit: Practical Fast Math --");
  await runUnitFastMath();

  console.log("\n-- Functional: API --");
  await runFunctionalApi(baseUrl);

  console.log("\n-- UI: Puppeteer headless --");
  await runUiPuppeteer(baseUrl);

  const report = buildReport(baseUrl);
  fs.writeFileSync(reportJson, JSON.stringify(report, null, 2));
  fs.writeFileSync(reportMd, toMarkdown(report));

  console.log("\n=== Summary ===");
  console.log(report.summary);
  console.log(`Markdown: ${reportMd}`);
  console.log(`JSON:     ${reportJson}`);
  console.log(`Screens:  ${outDir}`);

  if (report.summary.failed > 0) process.exit(1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
