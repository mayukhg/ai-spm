/**
 * Langfuse tracing and scores for the async governance LLM path.
 *
 * Runs next to the Phoenix tracer in ./tracer.ts and never touches the global
 * OpenTelemetry tracer provider that Phoenix registers: Langfuse gets its own
 * NodeTracerProvider through setLangfuseTracerProvider().
 *
 * Off unless LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set. When off,
 * every helper is a no-op and report generation behaves exactly as before.
 *
 * Recorded per governance report:
 *   trace  `governance.synthesize_report` (chain): asset, frameworks, evidence
 *   child  `openrouter.governance_report` (generation): model, prompt, report,
 *          token usage and USD cost
 * The trace id is stored on the report row so compliance reviewers' verdicts
 * can be attached to it as Langfuse scores.
 */

import { context, trace, ProxyTracerProvider } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { LangfuseSpanProcessor, isLangfuseSpan } from "@langfuse/otel";
import { setLangfuseTracerProvider } from "@langfuse/tracing";
import { LangfuseClient } from "@langfuse/client";
import { LANGFUSE_SDK_NAME, LANGFUSE_SDK_VERSION } from "@langfuse/core";

let provider: NodeTracerProvider | null = null;
let processor: LangfuseSpanProcessor | null = null;
let client: LangfuseClient | null = null;
let initialized = false;

/** USD per million tokens. Override with OPENROUTER_PRICE_INPUT / _OUTPUT. */
const PRICES: Record<string, { input: number; output: number }> = {
  "openai/gpt-4o-mini": { input: 0.15, output: 0.6 },
  "openai/gpt-4.1": { input: 2.0, output: 8.0 },
  "openai/gpt-4.1-mini": { input: 0.4, output: 1.6 },
  "anthropic/claude-sonnet-5": { input: 2.0, output: 10.0 },
};

export function langfuseEnabled() {
  return Boolean(process.env.LANGFUSE_PUBLIC_KEY?.trim() && process.env.LANGFUSE_SECRET_KEY?.trim());
}

function baseUrl() {
  return (
    process.env.LANGFUSE_BASE_URL?.trim() ||
    process.env.LANGFUSE_HOST?.trim() ||
    "https://cloud.langfuse.com"
  );
}

/** Initialize the isolated Langfuse tracer provider. Safe to call repeatedly. */
export function initLangfuse() {
  if (initialized) return provider;
  initialized = true;
  if (!langfuseEnabled()) return null;
  // Phoenix registers a global context manager in the app. Scripts that do not
  // load Phoenix still need one so nested observations find their parent.
  context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable());
  processor = new LangfuseSpanProcessor({
    baseUrl: baseUrl(),
    exporter: proxiedExporter(),
    environment: process.env.LANGFUSE_TRACING_ENVIRONMENT || undefined,
    release: process.env.LANGFUSE_RELEASE || undefined,
    // Only Langfuse observations, never Phoenix/OpenInference spans.
    shouldExportSpan: ({ otelSpan }) => isLangfuseSpan(otelSpan),
  });
  provider = new NodeTracerProvider({ spanProcessors: [processor] });
  setLangfuseTracerProvider(provider);
  return provider;
}

/**
 * The default OTLP exporter builds its own HTTPS agent, which ignores
 * HTTPS_PROXY. Behind a proxy, export through an agent that honours it
 * (Node >= 22.21 `proxyEnv`). Without a proxy, Langfuse's default exporter is used.
 */
function proxiedExporter() {
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  if (!proxy) return undefined;
  const publicKey = process.env.LANGFUSE_PUBLIC_KEY ?? "";
  const secretKey = process.env.LANGFUSE_SECRET_KEY ?? "";
  return new OTLPTraceExporter({
    url: `${baseUrl().replace(/\/$/, "")}/api/public/otel/v1/traces`,
    headers: {
      Authorization: `Basic ${Buffer.from(`${publicKey}:${secretKey}`).toString("base64")}`,
      // Same identity headers as Langfuse's own exporter, so the project sees a
      // current v4-ingestion SDK rather than an unknown/outdated one.
      "x-langfuse-sdk-name": LANGFUSE_SDK_NAME,
      "x-langfuse-sdk-version": LANGFUSE_SDK_VERSION,
      "x-langfuse-public-key": publicKey,
      "x-langfuse-ingestion-version": "4",
    },
    httpAgentOptions: { keepAlive: true, proxyEnv: process.env } as never,
  });
}

/**
 * Langfuse's experiment runner only links item traces to the experiment when
 * a global tracer provider exists. In the app, Phoenix registers one. Scripts
 * that run without Phoenix (the eval runner) call this to register Langfuse's.
 */
export function registerLangfuseAsGlobalIfUnset() {
  if (!initLangfuse()) return false;
  let current = trace.getTracerProvider();
  if (current instanceof ProxyTracerProvider) current = current.getDelegate();
  if (current.constructor.name !== "NoopTracerProvider") return false;
  return trace.setGlobalTracerProvider(provider!);
}

export function getLangfuseClient() {
  if (!langfuseEnabled()) return null;
  initLangfuse();
  if (!client) client = new LangfuseClient({ baseUrl: baseUrl() });
  return client;
}

export function costUsd(model: string, usage?: { prompt_tokens?: number; completion_tokens?: number }) {
  const envInput = Number(process.env.OPENROUTER_PRICE_INPUT);
  const envOutput = Number(process.env.OPENROUTER_PRICE_OUTPUT);
  const price =
    Number.isFinite(envInput) && Number.isFinite(envOutput) && envInput > 0
      ? { input: envInput, output: envOutput }
      : PRICES[model] ?? PRICES[model.replace(/-\d{4}-\d{2}-\d{2}$/, "")];
  if (!price || !usage) return undefined;
  const input = ((usage.prompt_tokens ?? 0) * price.input) / 1_000_000;
  const output = ((usage.completion_tokens ?? 0) * price.output) / 1_000_000;
  return { input, output, total: input + output };
}

export const REVIEW_REASONS = [
  "fabricated_control",
  "wrong_numbers",
  "missed_failure",
  "overstated_risk",
  "missing_section",
  "wrong_framework",
  "unclear",
  "other",
] as const;

/**
 * Attach a compliance reviewer's verdict to the report's trace.
 * `report_approved` is 1/0; `report_review_reason` is recorded on rejection.
 */
export async function recordReportReview(
  traceId: string,
  approved: boolean,
  reason?: string,
  comment?: string,
) {
  const langfuse = getLangfuseClient();
  if (!langfuse || !traceId) return false;
  langfuse.score.create({ traceId, name: "report_approved", value: approved ? 1 : 0, dataType: "NUMERIC", comment });
  if (!approved) {
    const category = (REVIEW_REASONS as readonly string[]).includes(reason ?? "") ? reason! : "other";
    langfuse.score.create({ traceId, name: "report_review_reason", value: category, dataType: "CATEGORICAL", comment });
  }
  await langfuse.score.flush();
  return true;
}

export async function flushLangfuse() {
  await Promise.all([processor?.forceFlush(), client?.flush()]);
}

export async function shutdownLangfuse() {
  await Promise.all([processor?.shutdown(), client?.shutdown()]);
}
