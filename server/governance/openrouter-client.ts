/**
 * OpenRouter client for asynchronous natural-language synthesis only.
 * Real-time monitoring must never call this module.
 */

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
  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": process.env.CORS_ORIGIN || "http://localhost:5050",
      "X-Title": "AI-SPM Governance Reports",
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: options.temperature ?? 0.2,
      max_tokens: options.maxTokens ?? 2500,
    }),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload?.error?.message || payload?.message || response.statusText;
    throw new Error(`OpenRouter request failed (${response.status}): ${detail}`);
  }

  const content = payload?.choices?.[0]?.message?.content;
  if (!content || typeof content !== "string") {
    throw new Error("OpenRouter returned an empty completion");
  }

  return {
    content,
    model: payload.model || model,
    elapsedMs: Date.now() - started,
    usage: payload.usage,
  };
}
