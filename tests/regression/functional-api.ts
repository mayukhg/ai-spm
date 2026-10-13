import { classifyLlmPrompts } from "../../server/analysis/synthetic-analysis";
import { assert, assertEqual, test } from "./harness";

type Jar = { cookie: string };

async function login(baseUrl: string, jar: Jar, username = "ciso.synthetic", password = "Synthetic123!") {
  const response = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const setCookie = response.headers.getSetCookie?.() ?? [];
  const fallback = response.headers.get("set-cookie");
  const cookies = setCookie.length ? setCookie : fallback ? [fallback] : [];
  jar.cookie = cookies.map((value) => value.split(";")[0]).join("; ");
  assert(response.ok, `login failed ${response.status}`);
  return response.json();
}

async function api(baseUrl: string, jar: Jar, method: string, path: string, body?: unknown) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(jar.cookie ? { Cookie: jar.cookie } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { response, json };
}

export async function runFunctionalApi(baseUrl: string) {
  const jar: Jar = { cookie: "" };

  await test("functional", "FUNC-CORE-01", "Health endpoint returns ok", async () => {
    const { response, json } = await api(baseUrl, jar, "GET", "/api/health");
    assertEqual(response.status, 200);
    assertEqual(json.status, "ok");
  });

  await test("functional", "FUNC-CORE-02", "Login accepts synthetic CISO credentials", async () => {
    const user = await login(baseUrl, jar);
    assertEqual(user.username, "ciso.synthetic");
    assert(jar.cookie.length > 0, "session cookie missing");
  });

  await test("functional", "FUNC-CORE-03", "Dashboard metrics include synthetic posture fields", async () => {
    const { response, json } = await api(baseUrl, jar, "GET", "/api/dashboard/metrics");
    assertEqual(response.status, 200);
    assert(typeof json.totalAssets === "number", "totalAssets");
    assert(typeof json.complianceScore === "number", "complianceScore");
    assert(typeof json.assetChangePercent === "number", "assetChangePercent");
    assert(typeof json.complianceChangePercent === "number", "complianceChangePercent");
  });

  await test("functional", "FUNC-CORE-04", "Dashboard trend returns stored snapshots", async () => {
    const { response, json } = await api(baseUrl, jar, "GET", "/api/dashboard/trend");
    assertEqual(response.status, 200);
    assert(Array.isArray(json) && json.length > 0, "trend empty");
    assert(typeof json[0].securityScore === "number", "securityScore");
  });

  await test("functional", "FUNC-LLM-01", "Local prompt classifier matches fixture labels", () => {
    const report = classifyLlmPrompts();
    assertEqual(report.evaluated, 3);
    assertEqual(report.blocked, 2);
    assertEqual(report.allowed, 1);
    const byId = Object.fromEntries(report.results.map((row) => [row.id, row]));
    assertEqual(byId["benign-order-status"].label, "benign");
    assertEqual(byId["override-instructions"].label, "prompt_injection");
    assertEqual(byId["policy-bypass"].label, "jailbreak");
    assert(byId["override-instructions"].tokens.some((token) => token.flagged), "injection tokens");
    assert(byId["policy-bypass"].tokens.some((token) => token.flagged), "jailbreak tokens");
  });

  await test("functional", "FUNC-LLM-02", "GET /api/llm/classifications returns three scored prompts", async () => {
    const { response, json } = await api(baseUrl, jar, "GET", "/api/llm/classifications");
    assertEqual(response.status, 200);
    assertEqual(json.evaluated, 3);
    assertEqual(json.blocked, 2);
  });

  await test("functional", "FUNC-LLM-03", "POST /api/llm/classifications stores block alerts", async () => {
    const { response, json } = await api(baseUrl, jar, "POST", "/api/llm/classifications");
    assertEqual(response.status, 200);
    assert(json.alertsWritten >= 2, `alertsWritten ${json.alertsWritten}`);
    const alerts = await api(baseUrl, jar, "GET", "/api/security-alerts/recent");
    assertEqual(alerts.response.status, 200);
    const types = new Set(alerts.json.map((row: any) => row.type));
    assert(types.has("prompt_injection"), "missing prompt_injection alert");
    assert(types.has("jailbreak"), "missing jailbreak alert");
  });

  await test("functional", "FUNC-HEALTH-01", "Resident agent status exposes fast-math methods and no realtime LLM", async () => {
    const { response, json } = await api(baseUrl, jar, "GET", "/api/governance/health/status");
    assertEqual(response.status, 200);
    assertEqual(json.agent.intervalMinutes, 15);
    assertEqual(json.agent.llmOnRealtimePath, false);
    assertEqual(json.openrouter.realtimePathUsesLlm, false);
    assert(json.agent.methods.includes("isolation_forest"), "IF missing");
    assert(json.agent.methods.includes("local_outlier_factor"), "LOF missing");
    assert(json.agent.methods.includes("kolmogorov_smirnov"), "KS missing");
  });

  await test("functional", "FUNC-HEALTH-02", "Run now completes under 100ms and persists a cycle", async () => {
    const { response, json } = await api(baseUrl, jar, "POST", "/api/governance/health/run-now");
    assertEqual(response.status, 200);
    assert(json.withinBudget === true, `withinBudget ${json.withinBudget}`);
    assert(json.elapsedMs < 100, `elapsedMs ${json.elapsedMs}`);
    assertEqual(json.drift.status, "significant_drift");
    assert(json.isolationForest.anomalousCount >= 1, "IF count");
    assert(json.localOutlierFactor.anomalousCount >= 1, "LOF count");
    const cycles = await api(baseUrl, jar, "GET", "/api/governance/health/cycles?limit=5");
    assert(cycles.json.length >= 1, "no cycles");
    assertEqual(cycles.json[0].trigger, "manual");
  });

  await test("functional", "FUNC-GOV-01", "OpenRouter configuration is reported from env", async () => {
    const { json } = await api(baseUrl, jar, "GET", "/api/governance/health/status");
    assertEqual(json.openrouter.provider, "openrouter");
    assertEqual(json.openrouter.model, process.env.OPENROUTER_MODEL || "openai/gpt-4o-mini");
    assert(typeof json.openrouter.configured === "boolean", "configured flag");
  });

  await test(
    "functional",
    "FUNC-GOV-02",
    "POST /api/governance/reports queues async GDPR/NIST synthesis",
    async () => {
      const { response, json } = await api(baseUrl, jar, "POST", "/api/governance/reports", {
        frameworks: ["GDPR", "NIST AI RMF"],
      });
      if (response.status === 503 && json.needsOpenRouterKey) {
        throw new Error("OPENROUTER_API_KEY not loaded by the running server");
      }
      assert(response.status === 202 || response.status === 200, `status ${response.status}`);
      assert(json.id, "missing report id");
      assert(["running", "pending", "completed"].includes(json.status), `status ${json.status}`);

      let completed = json;
      for (let attempt = 0; attempt < 30; attempt += 1) {
        const poll = await api(baseUrl, jar, "GET", `/api/governance/reports/${json.id}`);
        completed = poll.json;
        if (completed.status === "completed" || completed.status === "failed") break;
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      assertEqual(completed.status, "completed");
      assert(typeof completed.bodyMarkdown === "string" && completed.bodyMarkdown.length > 200, "empty body");
      assert(/GDPR|NIST/i.test(completed.bodyMarkdown), "frameworks missing from body");
    },
    { details: { requiresOpenRouter: true } },
  );

  await test("functional", "FUNC-CORE-05", "Settings status exposes syntheticFixtures", async () => {
    const { response, json } = await api(baseUrl, jar, "GET", "/api/settings/status");
    assertEqual(response.status, 200);
    assert(typeof json.syntheticFixtures === "boolean", "syntheticFixtures");
  });
}
