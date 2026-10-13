/**
 * Populate Phoenix with synthetic governance eval traces + local eval run artifacts.
 *
 * Usage:
 *   npx tsx scripts/seed-phoenix-eval.ts
 *
 * Requires Phoenix collector (default http://localhost:6006).
 * If OPENROUTER_API_KEY is set, live LLM spans are emitted; otherwise synthetic
 * LLM spans are created from fixture reference outputs (still visible in Phoenix).
 */
import "dotenv/config";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { context, trace, SpanStatusCode } from "@arizeai/phoenix-otel";
import {
  OpenInferenceSpanKind,
  LLM_MODEL_NAME,
  LLM_PROVIDER,
  LLM_TOKEN_COUNT_PROMPT,
  LLM_TOKEN_COUNT_COMPLETION,
  INPUT_VALUE,
  OUTPUT_VALUE,
} from "@arizeai/openinference-semantic-conventions";

const OPENINFERENCE_SPAN_KIND = "openinference.span.kind";
import { initPhoenixTracing, shutdownPhoenixTracing } from "../server/observability/tracer";
import { chatCompletion, openRouterConfigured } from "../server/governance/openrouter-client";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const datasetPath = path.join(root, "fixtures/synthetic/phoenix/eval-dataset.json");
const outputsPath = path.join(root, "fixtures/synthetic/phoenix/synthetic-outputs.json");
const outRunsPath = path.join(root, "fixtures/synthetic/phoenix/eval-runs.json");

type EvalExample = {
  id: string;
  input: Record<string, unknown>;
  reference_output: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

function systemPrompt() {
  return "You are a compliance documentation agent. Write clear, audit-ready markdown for external regulators. Use only the evidence JSON provided. Do not invent controls that lack evidence. Structure the document with Executive Summary, Evidence Summary, GDPR mapping, NIST AI RMF mapping, Gaps, and Recommended Remediation.";
}

async function emitSyntheticLlmSpan(opts: {
  tracerName: string;
  exampleId: string;
  model: string;
  messages: { role: string; content: string }[];
  output: string;
  latencyMs: number;
}) {
  const tracer = trace.getTracer(opts.tracerName);
  const span = tracer.startSpan("openrouter.chat.completions");
  span.setAttribute(OPENINFERENCE_SPAN_KIND, OpenInferenceSpanKind.LLM);
  span.setAttribute(LLM_MODEL_NAME, opts.model);
  span.setAttribute(LLM_PROVIDER, "openrouter");
  span.setAttribute(INPUT_VALUE, JSON.stringify(opts.messages));
  span.setAttribute(OUTPUT_VALUE, opts.output);
  span.setAttribute("eval.example_id", opts.exampleId);
  span.setAttribute("eval.synthetic", true);
  span.setAttribute("llm.latency_ms", opts.latencyMs);
  // Approximate token counts for synthetic fixtures
  const promptChars = opts.messages.reduce((n, m) => n + m.content.length, 0);
  span.setAttribute(LLM_TOKEN_COUNT_PROMPT, Math.ceil(promptChars / 4));
  span.setAttribute(LLM_TOKEN_COUNT_COMPLETION, Math.ceil(opts.output.length / 4));
  span.setStatus({ code: SpanStatusCode.OK });
  span.end();
}

async function main() {
  initPhoenixTracing();

  const dataset = JSON.parse(fs.readFileSync(datasetPath, "utf8")) as {
    dataset_name: string;
    examples: EvalExample[];
    evaluators: unknown[];
  };
  const outputs = JSON.parse(fs.readFileSync(outputsPath, "utf8")) as Record<string, string>;

  const live = openRouterConfigured();
  console.log(
    live
      ? "OPENROUTER_API_KEY set — emitting live instrumented OpenRouter spans"
      : "No OPENROUTER_API_KEY — emitting synthetic LLM spans from fixtures",
  );

  const tracer = trace.getTracer("ai-spm-phoenix-eval");
  const runs: unknown[] = [];

  for (const example of dataset.examples) {
    const messages = [
      { role: "system" as const, content: systemPrompt() },
      {
        role: "user" as const,
        content: JSON.stringify(
          {
            ...example.input,
            instructions:
              "Synthesize a professional compliance narrative. Call out statistical monitoring results as continuous monitoring evidence.",
          },
          null,
          2,
        ),
      },
    ];

    const parent = tracer.startSpan("governance.eval_case", {
      attributes: {
        [OPENINFERENCE_SPAN_KIND]: OpenInferenceSpanKind.CHAIN,
        "eval.example_id": example.id,
        "eval.dataset": dataset.dataset_name,
        ...(example.metadata
          ? Object.fromEntries(
              Object.entries(example.metadata).map(([k, v]) => [`eval.meta.${k}`, String(v)]),
            )
          : {}),
      },
    });

    const started = Date.now();
    let output = outputs[example.id] || "# Executive Summary\nSynthetic placeholder.\n";
    let model = process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini";
    let usage: unknown = undefined;
    let mode: "live" | "synthetic" = "synthetic";

    try {
      await context.with(trace.setSpan(context.active(), parent), async () => {
        if (live) {
          const result = await chatCompletion(messages, { temperature: 0.1, maxTokens: 1800 });
          output = result.content;
          model = result.model;
          usage = result.usage;
          mode = "live";
        } else {
          emitSyntheticLlmSpan({
            tracerName: "ai-spm-phoenix-eval",
            exampleId: example.id,
            model,
            messages,
            output,
            latencyMs: 40 + Math.floor(Math.random() * 80),
          });
        }
      });
      parent.setStatus({ code: SpanStatusCode.OK });
    } catch (error) {
      parent.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : String(error),
      });
      parent.recordException(error as Error);
      throw error;
    } finally {
      parent.end();
    }

    const mustInclude = (example.reference_output.must_include as string[] | undefined) || [];
    const structurePass = mustInclude.every((needle) =>
      output.toLowerCase().includes(String(needle).toLowerCase()),
    );

    runs.push({
      example_id: example.id,
      mode,
      model,
      latency_ms: Date.now() - started,
      usage,
      structure_sections_pass: structurePass,
      missing_sections: mustInclude.filter(
        (needle) => !output.toLowerCase().includes(String(needle).toLowerCase()),
      ),
      output_preview: output.slice(0, 280),
      scored_at: new Date().toISOString(),
    });

    console.log(`✓ ${example.id} (${mode}) structure=${structurePass ? "pass" : "fail"}`);
  }

  fs.writeFileSync(
    outRunsPath,
    JSON.stringify(
      {
        dataset: dataset.dataset_name,
        collector: process.env.PHOENIX_COLLECTOR_ENDPOINT || "http://localhost:6006",
        project: process.env.PHOENIX_PROJECT_NAME || "my-cursor-app",
        generated_at: new Date().toISOString(),
        runs,
      },
      null,
      2,
    ),
  );

  console.log(`\nWrote ${outRunsPath}`);
  console.log(
    "Open Phoenix UI and confirm traces under project:",
    process.env.PHOENIX_PROJECT_NAME || "my-cursor-app",
  );
  // Flush with timeout so offline collector cannot hang the script
  await shutdownPhoenixTracing(2000);
  process.exit(0);
}

main().catch(async (error) => {
  console.error(error);
  await shutdownPhoenixTracing(1500);
  process.exit(1);
});
