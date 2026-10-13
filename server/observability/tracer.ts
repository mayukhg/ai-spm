/**
 * Arize Phoenix — Option 1 Application Tracing bootstrap.
 *
 * Must be imported before any OpenAI / OpenRouter client usage (ESM).
 * Exports spans via OTLP/HTTP to Phoenix (default http://localhost:6006).
 */

import {
  register,
  registerInstrumentations,
  type Headers,
  type NodeTracerProvider,
} from "@arizeai/phoenix-otel";
import { OpenAIInstrumentation } from "@arizeai/openinference-instrumentation-openai";
import OpenAI from "openai";

let provider: NodeTracerProvider | null = null;
let initialized = false;

function parseClientHeaders(raw: string | undefined): Headers {
  if (!raw?.trim()) return {};
  const headers: Headers = {};
  for (const part of raw.split(/[,;]/)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    // Support "api_key=..." → Authorization Bearer for Phoenix Cloud
    if (key.toLowerCase() === "api_key" || key.toLowerCase() === "apikey") {
      headers.Authorization = `Bearer ${value}`;
    } else {
      headers[key] = value;
    }
  }
  return headers;
}

/**
 * Initialize Phoenix OTEL + OpenInference OpenAI instrumentation.
 * Safe to call multiple times (no-ops after first success).
 */
export function initPhoenixTracing(): NodeTracerProvider | null {
  if (initialized) return provider;
  initialized = true;

  if (process.env.PHOENIX_TRACING_ENABLED === "false") {
    console.log("[phoenix] tracing disabled (PHOENIX_TRACING_ENABLED=false)");
    return null;
  }

  const url = process.env.PHOENIX_COLLECTOR_ENDPOINT?.trim() || "http://localhost:6006";
  const projectName = process.env.PHOENIX_PROJECT_NAME?.trim() || "my-cursor-app";
  const headers = parseClientHeaders(process.env.PHOENIX_CLIENT_HEADERS);
  const apiKey = process.env.PHOENIX_API_KEY?.trim();

  try {
    provider = register({
      projectName,
      url,
      apiKey: apiKey || undefined,
      headers: Object.keys(headers).length ? headers : undefined,
      // Simple processor for local/dev so spans flush without waiting for batch
      batch: process.env.NODE_ENV === "production",
      global: true,
    });

    // ESM requires manual OpenAI instrumentation
    const instrumentation = new OpenAIInstrumentation();
    instrumentation.manuallyInstrument(OpenAI);
    registerInstrumentations({ instrumentations: [instrumentation] });

    console.log(
      `[phoenix] tracing enabled → ${url} (project=${projectName})`,
    );
    return provider;
  } catch (error) {
    console.warn(
      "[phoenix] failed to initialize tracing:",
      error instanceof Error ? error.message : error,
    );
    provider = null;
    return null;
  }
}

export async function shutdownPhoenixTracing(timeoutMs = 2500) {
  if (!provider) return;
  try {
    await Promise.race([
      provider.shutdown(),
      new Promise((resolve) => setTimeout(resolve, timeoutMs)),
    ]);
  } catch {
    // ignore flush errors when Phoenix collector is offline
  }
}

// Side-effect bootstrap when imported first from server/index.ts
initPhoenixTracing();
