/**
 * Minimal regression harness — no Jest required.
 * Collects pass/fail/skip results and writes a validation report.
 */

export type TestResult = {
  id: string;
  suite: "unit" | "functional" | "ui";
  name: string;
  status: "passed" | "failed" | "skipped";
  durationMs: number;
  error?: string;
  details?: Record<string, unknown>;
};

export type SuiteReport = {
  startedAt: string;
  finishedAt?: string;
  baseUrl: string;
  results: TestResult[];
  summary: { total: number; passed: number; failed: number; skipped: number };
};

const results: TestResult[] = [];
const startedAt = new Date().toISOString();

export function getResults() {
  return results;
}

export async function test(
  suite: TestResult["suite"],
  id: string,
  name: string,
  fn: () => Promise<void> | void,
  options: { skip?: boolean; details?: Record<string, unknown> } = {},
) {
  if (options.skip) {
    results.push({
      id,
      suite,
      name,
      status: "skipped",
      durationMs: 0,
      details: options.details,
    });
    console.log(`SKIP  [${suite}] ${id} — ${name}`);
    return;
  }

  const start = Date.now();
  try {
    await fn();
    results.push({
      id,
      suite,
      name,
      status: "passed",
      durationMs: Date.now() - start,
      details: options.details,
    });
    console.log(`PASS  [${suite}] ${id} — ${name} (${Date.now() - start}ms)`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    results.push({
      id,
      suite,
      name,
      status: "failed",
      durationMs: Date.now() - start,
      error: message,
      details: options.details,
    });
    console.error(`FAIL  [${suite}] ${id} — ${name}: ${message}`);
  }
}

export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function assertEqual<T>(actual: T, expected: T, message?: string) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

export function assertApprox(actual: number, expected: number, tolerance: number, message?: string) {
  if (Math.abs(actual - expected) > tolerance) {
    throw new Error(message || `Expected ~${expected}±${tolerance}, got ${actual}`);
  }
}

export function buildReport(baseUrl: string): SuiteReport {
  const summary = {
    total: results.length,
    passed: results.filter((r) => r.status === "passed").length,
    failed: results.filter((r) => r.status === "failed").length,
    skipped: results.filter((r) => r.status === "skipped").length,
  };
  return {
    startedAt,
    finishedAt: new Date().toISOString(),
    baseUrl,
    results,
    summary,
  };
}

export function toMarkdown(report: SuiteReport) {
  const lines: string[] = [];
  lines.push("# Regression Validation Report");
  lines.push("");
  lines.push(`Generated: ${report.finishedAt}`);
  lines.push(`Base URL: ${report.baseUrl}`);
  lines.push(`Window: ${report.startedAt} → ${report.finishedAt}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Total | Passed | Failed | Skipped |`);
  lines.push(`| --- | --- | --- | --- |`);
  lines.push(
    `| ${report.summary.total} | ${report.summary.passed} | ${report.summary.failed} | ${report.summary.skipped} |`,
  );
  lines.push("");
  lines.push(`**Verdict:** ${report.summary.failed === 0 ? "PASS" : "FAIL"}`);
  lines.push("");
  lines.push("## Coverage map (changes under test)");
  lines.push("");
  lines.push("| Change area | Suite cases |");
  lines.push("| --- | --- |");
  lines.push("| Practical Fast Math (quality, KS, Isolation Forest, LOF) | UNIT-* |");
  lines.push("| Resident agent health APIs + Run now | FUNC-HEALTH-* |");
  lines.push("| Async OpenRouter governance reports | FUNC-GOV-* |");
  lines.push("| Prompt / jailbreak / token classifier | FUNC-LLM-* |");
  lines.push("| Dashboard metrics / auth / theme / pages | FUNC-CORE-*, UI-* |");
  lines.push("| Health & Governance UI + Prompt Checks UI | UI-* |");
  lines.push("");

  for (const suite of ["unit", "functional", "ui"] as const) {
    const rows = report.results.filter((r) => r.suite === suite);
    if (!rows.length) continue;
    lines.push(`## ${suite.toUpperCase()} results`);
    lines.push("");
    lines.push("| ID | Name | Status | ms | Notes |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const row of rows) {
      const notes = row.error ? row.error.replace(/\|/g, "/") : "";
      lines.push(`| ${row.id} | ${row.name} | ${row.status} | ${row.durationMs} | ${notes} |`);
    }
    lines.push("");
  }

  if (report.summary.failed > 0) {
    lines.push("## Failures");
    lines.push("");
    for (const row of report.results.filter((r) => r.status === "failed")) {
      lines.push(`### ${row.id} — ${row.name}`);
      lines.push("");
      lines.push("```");
      lines.push(row.error || "unknown");
      lines.push("```");
      lines.push("");
    }
  }

  lines.push("## Environment notes");
  lines.push("");
  lines.push("- Functional and UI suites target the running app (default `http://127.0.0.1:5050`).");
  lines.push("- OpenRouter live completion is asserted when `OPENROUTER_API_KEY` is set; otherwise queued-status checks may be skipped.");
  lines.push("- UI suite uses Puppeteer headless Chromium.");
  lines.push("");
  return lines.join("\n");
}
