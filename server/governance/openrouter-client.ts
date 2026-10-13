/**
 * OpenRouter client for asynchronous natural-language synthesis only.
 * Real-time monitoring must never call this module.
 *
 * Uses the official OpenAI Node SDK pointed at OpenRouter so Arize Phoenix
 * OpenInference instrumentation can capture prompts, completions, and tokens.
 */

import OpenAI from "openai";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";

export type OpenRouterChatMessage = {
  role: "system" | "user" | "assistant";
  content: string;
};

export type OpenRouterResult = {
  content: string;
  model: string;
  elapsedMs: number;
  usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
};

export function openRouterConfigured() {
  return Boolean(process.env.OPENROUTER_API_KEY?.trim());
}

export function openRouterModel() {
  return process.env.OPENROUTER_MODEL?.trim() || "openai/gpt-4o-mini";
}

function createClient(apiKey: string) {
  return new OpenAI({
    apiKey,
    baseURL: "https://openrouter.ai/api/v1",
    defaultHeaders: {
      "HTTP-Referer": process.env.CORS_ORIGIN || "http://localhost:5050",
      "X-Title": "AI-SPM Governance Reports",
    },
  });
}

export async function chatCompletion(
  messages: OpenRouterChatMessage[],
  options: { temperature?: number; maxTokens?: number } = {},
): Promise<OpenRouterResult> {
  const apiKey = process.env.OPENROUTER_API_KEY?.trim();
  if (!apiKey) {
    throw new Error(
      "OPENROUTER_API_KEY is not set. Add it to the local .env file before generating governance reports.",
    );
  }

  const model = openRouterModel();
  const started = Date.now();
  const client = createClient(apiKey);

  const completion = await client.chat.completions.create({
    model,
    messages: messages as ChatCompletionMessageParam[],
    temperature: options.temperature ?? 0.2,
    max_tokens: options.maxTokens ?? 2500,
  });

  const content = completion.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") {
    throw new Error("OpenRouter returned an empty completion");
  }

  return {
    content,
    model: completion.model || model,
    elapsedMs: Date.now() - started,
    usage: completion.usage
      ? {
          prompt_tokens: completion.usage.prompt_tokens,
          completion_tokens: completion.usage.completion_tokens,
          total_tokens: completion.usage.total_tokens,
        }
      : undefined,
  };
}
