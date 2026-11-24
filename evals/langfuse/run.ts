/**
 * Run the AI-SPM eval suites as Langfuse experiments and apply the release gates.
 *
 *   npm run langfuse:eval                                  # all suites, live model
 *   npm run langfuse:eval -- --judge --repeats 2           # LLM judge + consistency
 *   npm run langfuse:eval -- --offline --no-langfuse       # CI smoke test, no keys
 *   npm run langfuse:eval -- --suite governance_adversarial
 *
 * Each suite is a Langfuse dataset `ai-spm/<suite>`. Items are upserted by id.
 * Each run is an experiment on that dataset, with item scores on every trace
 * and summary scores on the run. Exits 1 when a blocking gate fails.
 */

import "dotenv/config";
import fs from "fs";
import path from "path";
import { performance } from "perf_hooks";
import type { Evaluation, Evaluator } from "@langfuse/client";
import { DESCRIPTIONS, SUITES, type SuiteName } from "./cases";
import {
  GOVERNANCE_EVALUATORS,
  classifierEvaluator,
  makeJudge,
  rowsOf,
  summarize,
  summaryRunEvaluator,
  type GovernanceOutput,
} from "./evaluators";
import { evaluateGates } from "./gates";
import * as checks from "./checks";
import { generateGovernanceNarrative, offlineChat, type GovernanceReportInput } from "../../server/governance/report-synthesis";
import { classifyPrompt } from "../../server/analysis/synthetic-analysis";
import { classifyPromptHybrid } from "../../server/analysis/prompt-classifier-model";
import { flushLangfuse, getLangfuseClient, registerLangfuseAsGlobalIfUnset } from "../../server/observability/langfuse";

type Args = {
  suites: SuiteName[];
  offline: boolean;
  judge: boolean;
  repeats: number;
  concurrency: number;
  noLangfuse: boolean;
  noGate: boolean;
  classifier: "rules" | "hybrid";
  runName: string;
  report?: string;
};

function parseArgs(argv: string[]): Args {
  const get = (flag: string) => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const suiteArg = get("--suite") ?? "all";
  const all = Object.keys(SUITES) as SuiteName[];
  const suites = suiteArg === "all" ? all : (suiteArg.split(",") as SuiteName[]);
  const unknown = suites.filter((s) => !all.includes(s));
  if (unknown.length) throw new Error(`unknown suite ${unknown.join(", ")}; choose from ${all.join(", ")}`);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
  return {
    suites,
    offline: argv.includes("--offline"),
    judge: argv.includes("--judge"),
    repeats: Number(get("--repeats") ?? 1),
    concurrency: Number(get("--concurrency") ?? 3),
    noLangfuse: argv.includes("--no-langfuse"),
    noGate: argv.includes("--no-gate"),
    classifier: (get("--classifier") ?? "rules") as "rules" | "hybrid",
    runName: get("--run-name") ?? `ai-spm-eval-${stamp}`,
    report: get("--report"),
  };
}

type Item = { id?: string; input: any; expectedOutput?: any; metadata?: any };
type Result = { item: Item; output: any; evaluations: Evaluation[] };

function governanceTask(offline: boolean) {
  return async ({ input }: { input: GovernanceReportInput }): Promise<GovernanceOutput> => {
    const started = performance.now();
    try {
      const result = await generateGovernanceNarrative(input, offline ? offlineChat : undefined);
      return {
        markdown: result.markdown,
        model: result.model,
        latencyS: Math.round(performance.now() - started) / 1000,
        costUsd: result.costUsd,
        promptTokens: result.usage?.prompt_tokens,
        completionTokens: result.usage?.completion_tokens,
        gapsAdded: result.gapsAdded,
      };
    } catch (error) {
      return { markdown: "", error: (error as Error).message, latencyS: (performance.now() - started) / 1000 };
    }
  };
}

const classifierTask = async ({ input }: { input: { id: string; text: string } }) => {
  const result = classifyPrompt({ id: input.id, expected: "", text: input.text }, 0.8);
  return { label: result.label, decision: result.decision, flagged: result.spans.map((s) => s.phrase) };
};

/** Rules for spans, model for the verdict (falls back to rules if the model call fails). */
const hybridClassifierTask = async ({ input }: { input: { id: string; text: string } }) => {
  const verdict = await classifyPromptHybrid(input.text);
  return {
    label: verdict.label,
    source: verdict.source,
    rulesLabel: verdict.rules.label,
    modelReason: verdict.model?.reason,
    error: verdict.error,
  };
};

async function runLocal(items: Item[], task: (p: any) => Promise<any>, evaluators: Evaluator[]): Promise<Result[]> {
  const results: Result[] = [];
  for (const item of items) {
    const output = await task({ input: item.input, expectedOutput: item.expectedOutput, metadata: item.metadata });
    const evaluations: Evaluation[] = [];
    for (const evaluator of evaluators) {
      const r = await evaluator({ input: item.input, output, expectedOutput: item.expectedOutput, metadata: item.metadata });
      evaluations.push(...(Array.isArray(r) ? r : [r]));
    }
    results.push({ item, output, evaluations });
  }
  return results;
}

async function syncDataset(suite: SuiteName, items: Item[]) {
  const langfuse = getLangfuseClient()!;
  const name = `ai-spm/${suite}`;
  try {
    await langfuse.api.datasets.get(name);
  } catch {
    await langfuse.api.datasets.create({ name, description: DESCRIPTIONS[suite], metadata: { suite, product: "ai-spm" } });
  }
  for (const item of items) {
    await langfuse.api.datasetItems.create({
      datasetName: name,
      id: item.id,
      input: item.input,
      expectedOutput: item.expectedOutput,
      metadata: item.metadata,
    });
  }
  return langfuse.dataset.get(name);
}

/** Share of cases whose decision-check outcomes are identical in every repeat. */
const DECISION_CHECKS = new Set([
  "structure",
  "no_invented_numbers",
  "failures_called_out",
  "no_false_assurance",
  "no_fabricated_controls",
  "injection_resisted",
  "abstained",
  "no_overalarm",
  "urgency",
  "must_not_include",
]);

function consistency(runs: Result[][]): number | undefined {
  const byCase = new Map<string, string[]>();
  for (const results of runs) {
    for (const r of results) {
      const id = String(r.item.metadata?.caseId);
      const sig = JSON.stringify(
        r.evaluations
          .filter((e) => DECISION_CHECKS.has(e.name) && typeof e.value === "number")
          .map((e) => [e.name, (e.value as number) >= 1])
          .sort(),
      );
      byCase.set(id, [...(byCase.get(id) ?? []), sig]);
    }
  }
  const repeated = [...byCase.values()].filter((s) => s.length > 1);
  if (!repeated.length) return undefined;
  return repeated.filter((s) => new Set(s).size === 1).length / repeated.length;
}

async function runSuite(suite: SuiteName, args: Args, useLangfuse: boolean) {
  const items = SUITES[suite]() as Item[];
  const isGovernance = suite.startsWith("governance");
  const task = isGovernance ? governanceTask(args.offline) : args.classifier === "hybrid" && !args.offline ? hybridClassifierTask : classifierTask;
  const evaluators: Evaluator[] = isGovernance
    ? ([...GOVERNANCE_EVALUATORS, ...(args.judge && !args.offline ? [makeJudge()] : [])] as unknown as Evaluator[])
    : [classifierEvaluator as Evaluator];
  const repeats = isGovernance ? args.repeats : 1;
  const runs: Result[][] = [];
  const urls: string[] = [];
  const dataset = useLangfuse ? await syncDataset(suite, items) : null;
  for (let r = 0; r < repeats; r++) {
    const runName = `${args.runName}-${suite}${repeats > 1 ? `-r${r + 1}` : ""}`;
    if (!dataset) {
      runs.push(await runLocal(items, task as any, evaluators));
      continue;
    }
    const result = await dataset.runExperiment({
      name: suite,
      runName,
      description: DESCRIPTIONS[suite],
      task: task as any,
      evaluators: evaluators as any,
      runEvaluators: [summaryRunEvaluator],
      maxConcurrency: args.concurrency,
      metadata: { suite, offline: args.offline, judge: args.judge, repeat: r + 1, model: process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini", classifier: args.classifier },
    });
    runs.push(result.itemResults as unknown as Result[]);
    if (result.experimentUrl) urls.push(result.experimentUrl);
  }
  const summary = summarize(rowsOf(runs.flat() as never));
  const c = consistency(runs);
  if (c !== undefined) summary.consistency = c;
  return { summary, last: runs[runs.length - 1], urls, items: items.length };
}

const fmt = (v: number | null | undefined) => (v === null || v === undefined ? "—" : Number.isInteger(v) ? String(v) : v.toFixed(3));

function scorecard(outcomes: Record<string, Awaited<ReturnType<typeof runSuite>>>, gates: ReturnType<typeof evaluateGates>, args: Args) {
  const lines = [
    "# AI-SPM eval scorecard",
    "",
    `Run \`${args.runName}\` · ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC · model ${args.offline ? "**offline template (pipeline smoke test, not model quality)**" : process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini"} · judge ${args.judge && !args.offline ? "on" : "off"} · repeats ${args.repeats}`,
    "",
    "## Gates",
    "",
    "| Suite | Metric | Gate | Level | Value | Result |",
    "|---|---|---|---|---|---|",
    ...gates.map((g) => `| ${g.suite} | \`${g.metric}\` | ${g.op} ${g.threshold} | ${g.level} | ${fmt(g.value)} | ${g.status} |`),
  ];
  for (const [suite, o] of Object.entries(outcomes)) {
    lines.push("", `## ${suite} (${o.items} cases)`, "");
    for (const url of o.urls) lines.push(`Langfuse: ${url}`);
    const metrics = [...new Set(Object.keys(o.summary).filter((k) => k.startsWith("avg/")).map((k) => k.slice(4)))];
    const groups = [...new Set(Object.keys(o.summary).filter((k) => /^(severity|variant)\//.test(k)).map((k) => k.split("/").slice(0, 2).join("/")))].sort();
    lines.push("", `| Metric | All | ${groups.map((g) => g.split("/")[1]).join(" | ")} |`, `|---|---|${groups.map(() => "---|").join("")}`);
    for (const m of metrics) lines.push(`| \`${m}\` | ${fmt(o.summary[`avg/${m}`])} | ${groups.map((g) => fmt(o.summary[`${g}/${m}`])).join(" | ")} |`);
    const extras = ["consistency", "latency_p95_s", "cost_usd_total", "count/task_error", "count/judge_error"].filter((k) => k in o.summary);
    if (extras.length) lines.push("", extras.map((k) => `\`${k}\` ${fmt(o.summary[k])}`).join(" · "));
    const failures = o.last.flatMap((r) =>
      r.evaluations
        .filter((e) => typeof e.value === "number" && (e.value as number) < 1 && !["latency_s", "cost_usd", "report_words", "task_error", "judge_error", "gap_guard_fired"].includes(e.name))
        .map((e) => `| ${r.item.metadata?.caseId} | \`${e.name}\` | ${fmt(e.value as number)} | ${String(e.comment ?? "").replace(/\|/g, "/").replace(/\n/g, " ")} |`),
    );
    if (failures.length) lines.push("", "Cases below 1.0 (last repeat):", "", "| Case | Score | Value | Why |", "|---|---|---|---|", ...failures);
  }
  return lines.join("\n") + "\n";
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.noLangfuse) {
    delete process.env.LANGFUSE_PUBLIC_KEY;
    delete process.env.LANGFUSE_SECRET_KEY;
  }
  const useLangfuse = Boolean(getLangfuseClient());
  if (useLangfuse) registerLangfuseAsGlobalIfUnset();
  if (!useLangfuse && !args.noLangfuse) console.log("Langfuse is not configured (LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY / LANGFUSE_BASE_URL). Running locally.");
  const outcomes: Record<string, Awaited<ReturnType<typeof runSuite>>> = {};
  for (const suite of args.suites) {
    console.log(`Running ${suite} ...`);
    outcomes[suite] = await runSuite(suite, args, useLangfuse);
  }
  if (useLangfuse) await flushLangfuse();
  const gates = evaluateGates(Object.fromEntries(Object.entries(outcomes).map(([s, o]) => [s, o.summary])));
  const report = scorecard(outcomes, gates, args);
  console.log(report);
  if (args.report) {
    fs.mkdirSync(path.dirname(args.report), { recursive: true });
    fs.writeFileSync(args.report, report);
    fs.writeFileSync(
      args.report.replace(/\.md$/, "") + ".json",
      JSON.stringify({ runName: args.runName, summaries: Object.fromEntries(Object.entries(outcomes).map(([s, o]) => [s, o.summary])), gates }, null, 2),
    );
  }
  const failed = gates.filter((g) => g.status === "FAIL");
  if (failed.length && !args.noGate) {
    console.log(`${failed.length} blocking gate(s) failed.`);
    process.exitCode = 1;
  }
}

// Only run when executed directly, so tests can import helpers.
if (process.argv[1] && path.resolve(process.argv[1]).endsWith(path.join("evals", "langfuse", "run.ts"))) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

export { checks, consistency };
