/**
 * Score live governance reports in Langfuse with the deterministic checks.
 *
 * The offline suites test fixed cases before a release. This script reads real
 * `governance.synthesize_report` observations from a time window and writes
 * `online_*` scores onto their traces, next to the reviewer verdicts
 * (`report_approved`, `report_review_reason`) from the Health & Governance page.
 *
 *   npm run langfuse:score-production -- --since-hours 24
 *   npm run langfuse:score-production -- --since-hours 1 --dry-run
 *
 * Score ids are derived from the trace id and score name, so re-running over the
 * same window overwrites the same scores instead of adding duplicates.
 */

import "dotenv/config";
import * as checks from "./checks";
import type { GovernanceReportInput } from "../../server/governance/report-synthesis";
import { getLangfuseClient } from "../../server/observability/langfuse";

const EXPERIMENT_ENVIRONMENT = "sdk-experiment";

export function scoreReport(input: GovernanceReportInput, markdown: string): Record<string, checks.Check> {
  return {
    online_structure: checks.structure(markdown, input.frameworks ?? []),
    online_no_unrequested_framework: checks.noUnrequestedFramework(markdown, input.frameworks ?? []),
    online_no_invented_numbers: checks.noInventedNumbers(markdown, input.evidence ?? {}),
    online_no_false_assurance: checks.noFalseAssurance(markdown, input.evidence ?? {}),
    online_no_fabricated_controls: checks.noFabricatedControls(markdown, input.evidence ?? {}),
    online_failures_called_out: checks.failuresCalledOut(markdown, input.evidence ?? {}),
    online_no_phantom_injection_flag: checks.noPhantomInjectionFlag(markdown, input.evidence ?? {}, input.assetName),
  };
}

function parse<T>(value: unknown): T | undefined {
  if (typeof value !== "string") return value as T;
  try {
    return JSON.parse(value) as T;
  } catch {
    return value as T;
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const get = (flag: string) => (argv.includes(flag) ? argv[argv.indexOf(flag) + 1] : undefined);
  const sinceHours = Number(get("--since-hours") ?? 24);
  const dryRun = argv.includes("--dry-run");
  const langfuse = getLangfuseClient();
  if (!langfuse) throw new Error("Set LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY and LANGFUSE_BASE_URL first.");
  const since = new Date(Date.now() - sinceHours * 3600_000).toISOString();
  const totals: Record<string, number[]> = {};
  let cursor: string | undefined;
  let scored = 0;
  do {
    const page = await langfuse.api.observations.getMany({
      name: "governance.synthesize_report",
      fields: "core,basic,io",
      fromStartTime: since,
      limit: 100,
      cursor,
    });
    for (const observation of page.data as unknown as Record<string, unknown>[]) {
      if (observation.environment === EXPERIMENT_ENVIRONMENT) continue;
      const input = parse<GovernanceReportInput>(observation.input);
      const markdown = parse<string>(observation.output);
      if (!input?.evidence || typeof markdown !== "string" || !markdown) continue;
      scored += 1;
      for (const [name, [value, comment]] of Object.entries(scoreReport(input, markdown))) {
        if (value === null) continue;
        (totals[name] ??= []).push(value);
        if (dryRun) {
          if (value < 1) console.log(`${observation.traceId} ${name}=${value.toFixed(2)} ${comment}`);
          continue;
        }
        langfuse.score.create({
          id: `${observation.traceId}-${name}`,
          traceId: String(observation.traceId),
          observationId: String(observation.id),
          name,
          value,
          dataType: "NUMERIC",
          comment: comment.slice(0, 500),
        });
      }
    }
    cursor = (page.meta as { cursor?: string } | undefined)?.cursor;
    if (!page.data.length) cursor = undefined;
  } while (cursor);
  await langfuse.flush();
  console.log(`Scored ${scored} live governance reports since ${since}`);
  for (const [name, values] of Object.entries(totals).sort()) {
    console.log(`  ${name}: ${(values.reduce((a, b) => a + b, 0) / values.length).toFixed(3)} over ${values.length}`);
  }
}

if (process.argv[1]?.endsWith("score-production.ts")) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
