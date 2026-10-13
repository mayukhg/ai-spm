import fs from "fs";
import path from "path";

export const fixtureRoot = path.resolve(process.cwd(), "fixtures/synthetic");

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(fixtureRoot, name), "utf8")) as T;
}

function parseCsv(filePath: string): Record<string, string>[] {
  const text = fs.readFileSync(filePath, "utf8").trim();
  const [header, ...lines] = text.split("\n");
  const columns = header.split(",");
  return lines.filter(Boolean).map((line) => {
    const cells = line.split(",");
    return Object.fromEntries(columns.map((column, index) => [column, cells[index] ?? ""]));
  });
}

export function demographicParity(csvPath: string) {
  const rows = parseCsv(csvPath);
  const groups = new Map<string, { total: number; positive: number }>();
  for (const row of rows) {
    const group = row.group;
    const current = groups.get(group) ?? { total: 0, positive: 0 };
    current.total += 1;
    if (row.y_pred === "1") current.positive += 1;
    groups.set(group, current);
  }
  const rates = Object.fromEntries(
    Array.from(groups.entries()).map(([group, value]) => [group, value.total ? value.positive / value.total : 0])
  );
  const values = Object.values(rates);
  const difference = values.length >= 2 ? Math.abs(Math.max(...values) - Math.min(...values)) : 0;
  return {
    difference: Math.round(difference * 100) / 100,
    status: difference >= 0.2 ? "fail" : "pass",
    groupRates: rates,
  };
}

export function qualityReport(csvPath: string) {
  const rows = parseCsv(csvPath);
  const allowed = new Set(["billing", "access", "shipping"]);
  const seen = new Map<string, number>();
  let missing = 0;
  let invalid = 0;
  for (const row of rows) {
    if (!row.text) missing += 1;
    if (!allowed.has(row.label)) invalid += 1;
    if (row.ticket_id) seen.set(row.ticket_id, (seen.get(row.ticket_id) ?? 0) + 1);
  }
  let duplicate = 0;
  for (const count of Array.from(seen.values())) {
    if (count > 1) duplicate += count;
  }
  const total = rows.length || 1;
  const affectedRecords = missing + duplicate + invalid;
  return {
    total,
    missing,
    duplicate,
    invalid,
    affectedRecords,
    completeness: Math.round((1 - missing / total) * 10000) / 10000,
    uniqueness: Math.round((1 - duplicate / total) * 10000) / 10000,
    validity: Math.round((1 - invalid / total) * 10000) / 10000,
  };
}

function kolmogorovSmirnov(left: number[], right: number[]) {
  const a = [...left].sort((x, y) => x - y);
  const b = [...right].sort((x, y) => x - y);
  let i = 0;
  let j = 0;
  let distance = 0;
  while (i < a.length && j < b.length) {
    if (a[i] <= b[j]) i += 1;
    else j += 1;
    distance = Math.max(distance, Math.abs(i / a.length - j / b.length));
  }
  return distance;
}

function mean(values: number[]) {
  return values.reduce((sum, value) => sum + value, 0) / (values.length || 1);
}

export function driftReport(baselinePath: string, currentPath: string) {
  const baseline = parseCsv(baselinePath).map((row) => Number(row.amount));
  const current = parseCsv(currentPath).map((row) => Number(row.amount));
  const ks = kolmogorovSmirnov(baseline, current);
  return {
    feature: "amount",
    ks: Math.round(ks * 1000000) / 1000000,
    baselineMean: Math.round(mean(baseline) * 100) / 100,
    currentMean: Math.round(mean(current) * 100) / 100,
    status: ks > 0.2 ? "significant_drift" : "stable",
    method: "kolmogorov_smirnov",
  };
}

export function poisoningIds() {
  const payload = readJson<{ samples: { id: string; planted?: boolean }[] }>("ticket-training-set-poisoned.json");
  return payload.samples.filter((sample) => sample.planted).map((sample) => sample.id);
}

export function evasionDecision() {
  const payload = readJson<{
    clean: { id: string };
    perturbed: { id: string; epsilon: number };
  }>("evasion-pair.json");
  return {
    allowedId: payload.clean.id,
    blockedId: payload.perturbed.id,
    epsilon: payload.perturbed.epsilon,
  };
}

export function membershipSuspects() {
  const payload = readJson<{ queries: { id: string; loss: number; member: boolean }[] }>("membership-queries.json");
  return payload.queries.filter((query) => query.member && query.loss < 0.05).map((query) => query.id);
}

export function inferredAttribute() {
  const payload = readJson<{
    queries: { prediction: string; age: number }[];
  }>("attribute-queries.json");
  const matched = payload.queries.filter((query) => (query.age >= 50) === (query.prediction === "positive")).length;
  const agreement = matched / payload.queries.length;
  return {
    attribute: agreement >= 0.8 ? "age" : "none",
    agreement: Math.round(agreement * 100) / 100,
  };
}

export function loadWizFixture() {
  return readJson<{
    resources: {
      name: string;
      type: string;
      environment: string;
      riskLevel: string;
      finding?: { title: string; severity: string; description: string };
    }[];
  }>("wiz-sync.json");
}

export function loadModelCard(cardPath: string) {
  return JSON.parse(fs.readFileSync(cardPath, "utf8")) as {
    framework?: string;
    version?: string;
    provenance?: string | null;
    declaredFindings?: {
      title: string;
      severity: string;
      category: string;
      description: string;
      recommendation: string;
    }[];
  };
}

export function nistEvidence(modelCardPath: string) {
  const processingRecord = path.join(fixtureRoot, "compliance-evidence/processing-record.json");
  const controls = [
    {
      control: "model_card",
      passed: fs.existsSync(modelCardPath),
    },
    {
      control: "data_processing_record",
      passed: fs.existsSync(processingRecord),
    },
  ];
  const passed = controls.filter((control) => control.passed).length;
  return {
    controls,
    score: Math.round((passed / controls.length) * 100),
    status: passed === controls.length ? "compliant" : "partially_compliant",
  };
}

const LLM_RULES: { category: "prompt_injection" | "jailbreak"; phrase: string }[] = [
  { category: "prompt_injection", phrase: "ignore the previous instructions" },
  { category: "prompt_injection", phrase: "print the system prompt" },
  { category: "jailbreak", phrase: "developer mode" },
  { category: "jailbreak", phrase: "bypass your safety policy" },
];

export type LlmToken = {
  text: string;
  start: number;
  end: number;
  flagged: boolean;
  category: "prompt_injection" | "jailbreak" | null;
};

export type LlmClassification = {
  id: string;
  text: string;
  expected: string;
  label: "benign" | "prompt_injection" | "jailbreak";
  score: number;
  decision: "allow" | "block";
  agreesWithExpected: boolean;
  title: string;
  summary: string;
  spans: { start: number; end: number; phrase: string; category: "prompt_injection" | "jailbreak" }[];
  tokens: LlmToken[];
};

function tokenize(text: string): { text: string; start: number; end: number }[] {
  const tokens: { text: string; start: number; end: number }[] = [];
  const pattern = /\S+/g;
  let match = pattern.exec(text);
  while (match) {
    tokens.push({ text: match[0], start: match.index, end: match.index + match[0].length });
    match = pattern.exec(text);
  }
  return tokens;
}

function classifyPrompt(
  prompt: { id: string; expected: string; text: string },
  threshold: number,
): LlmClassification {
  const lower = prompt.text.toLowerCase();
  const spans: LlmClassification["spans"] = [];
  for (const rule of LLM_RULES) {
    let from = 0;
    while (from < lower.length) {
      const index = lower.indexOf(rule.phrase, from);
      if (index < 0) break;
      spans.push({
        start: index,
        end: index + rule.phrase.length,
        phrase: rule.phrase,
        category: rule.category,
      });
      from = index + rule.phrase.length;
    }
  }

  const injectionCount = spans.filter((span) => span.category === "prompt_injection").length;
  const jailbreakCount = spans.filter((span) => span.category === "jailbreak").length;
  const label: LlmClassification["label"] = jailbreakCount > injectionCount
    ? "jailbreak"
    : injectionCount > 0
      ? "prompt_injection"
      : "benign";
  const score = label === "benign" ? 0.05 : 0.95;
  const decision = label !== "benign" && score >= threshold ? "block" : "allow";
  const tokens: LlmToken[] = tokenize(prompt.text).map((token) => {
    const span = spans.find((item) => token.start < item.end && item.start < token.end);
    return {
      ...token,
      flagged: Boolean(span),
      category: span?.category ?? null,
    };
  });
  const flagged = tokens.filter((token) => token.flagged).map((token) => token.text).join(" ");
  const title = label === "jailbreak"
    ? "Jailbreak attempt blocked"
    : label === "prompt_injection"
      ? "Prompt injection attempt blocked"
      : "Benign prompt allowed";
  const summary = decision === "block"
    ? `Classifier score ${score.toFixed(2)}. Flagged tokens: ${flagged}`
    : `Classifier score ${score.toFixed(2)}. Every token stayed below the block threshold.`;

  return {
    id: prompt.id,
    text: prompt.text,
    expected: prompt.expected,
    label,
    score,
    decision,
    agreesWithExpected: label === prompt.expected,
    title,
    summary,
    spans,
    tokens,
  };
}

export function classifyLlmPrompts() {
  const payload = readJson<{
    assetName: string;
    threshold: number;
    prompts: { id: string; expected: string; text: string }[];
  }>("llm-prompt-evals.json");
  const results = payload.prompts.map((prompt) => classifyPrompt(prompt, payload.threshold));
  const blocked = results.filter((result) => result.decision === "block").length;
  return {
    assetName: payload.assetName,
    threshold: payload.threshold,
    evaluated: results.length,
    blocked,
    allowed: results.length - blocked,
    results,
  };
}

export function siemEvent(alert: { type: string; severity: string; assetId: number | null; title: string }) {
  const configured = Boolean(process.env.SPLUNK_ENDPOINT && process.env.SPLUNK_TOKEN);
  return {
    forwarded: configured,
    connector: configured ? "splunk" : "not_configured",
    event: {
      type: alert.type,
      severity: alert.severity,
      assetId: alert.assetId,
      title: alert.title,
    },
  };
}
