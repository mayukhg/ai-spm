import { randomUUID } from "crypto";
import mixpanelSdk from "mixpanel";

const token =
  process.env.MIXPANEL_PROJECT_TOKEN ||
  process.env.MIXPANEL_TOKEN ||
  "";

const init = mixpanelSdk.init ?? (mixpanelSdk as unknown as { default: typeof mixpanelSdk }).default?.init;
const client = token && init ? init(token) : null;

function distinctIdFromUser(user: { id?: number | string } | null | undefined): string {
  if (user?.id !== undefined && user?.id !== null) return String(user.id);
  return "anonymous";
}

export function trackServerEvent(
  distinctId: string | number | undefined | null,
  event: string,
  props: Record<string, unknown> = {},
) {
  if (!client) return;
  try {
    client.track(event, {
      distinct_id: String(distinctId ?? "anonymous"),
      $insert_id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...props,
    });
  } catch (err) {
    console.warn("[mixpanel] track failed:", err);
  }
}

export function setServerUser(
  distinctId: string | number,
  traits: Record<string, unknown>,
) {
  if (!client) return;
  try {
    client.people.set(String(distinctId), traits);
  } catch (err) {
    console.warn("[mixpanel] people.set failed:", err);
  }
}

export function trackForUser(
  user: { id?: number | string } | null | undefined,
  event: string,
  props: Record<string, unknown> = {},
) {
  trackServerEvent(distinctIdFromUser(user), event, props);
}

export function mapFramework(framework?: string | null): string {
  const f = (framework || "").toLowerCase();
  if (f.includes("openai")) return "openai";
  if (f.includes("hugging") || f === "hf") return "huggingface";
  if (f.includes("sagemaker") || f.includes("aws")) return "aws_sagemaker";
  if (f.includes("azure")) return "azure_ml";
  return "custom";
}

export function mapAssetType(type?: string | null): string {
  const t = (type || "").toLowerCase();
  if (t === "api" || t === "api_endpoint") return "api_endpoint";
  if (t === "model" || t === "dataset" || t === "pipeline") return t;
  return t || "model";
}
