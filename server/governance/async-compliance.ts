/**
 * Asynchronous governance reports via OpenRouter.
 *
 * LLMs are reserved for natural-language synthesis of GDPR / NIST documentation.
 * This path is never on the real-time monitoring hot path.
 */

import { desc, eq } from "drizzle-orm";
import { db, pool } from "../db";
import { storage } from "../storage";
import {
  complianceAssessments,
  dataAnomalyDetections,
  dataDriftMetrics,
  dataQualityMetrics,
  governanceReports,
  monitoringCycles,
} from "@shared/schema";
import { withSpan } from "@arizeai/phoenix-otel";
import { chatCompletion, openRouterConfigured, openRouterModel } from "./openrouter-client";
import { logger } from "../monitoring/logger";

async function ensureReportsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS governance_reports (
      id serial PRIMARY KEY,
      asset_id integer,
      frameworks jsonb NOT NULL,
      status text NOT NULL DEFAULT 'pending',
      title text NOT NULL,
      summary text,
      body_markdown text,
      evidence_snapshot jsonb,
      model text,
      provider text DEFAULT 'openrouter',
      elapsed_ms integer,
      error text,
      created_by integer,
      created_at timestamp NOT NULL DEFAULT NOW(),
      completed_at timestamp
    )
  `);
}

async function collectEvidence(assetId: number) {
  const quality = await db
    .select()
    .from(dataQualityMetrics)
    .where(eq(dataQualityMetrics.assetId, assetId))
    .orderBy(desc(dataQualityMetrics.collectedAt))
    .limit(12);
  const drift = await db
    .select()
    .from(dataDriftMetrics)
    .where(eq(dataDriftMetrics.assetId, assetId))
    .orderBy(desc(dataDriftMetrics.detectedAt))
    .limit(5);
  const anomalies = await db
    .select()
    .from(dataAnomalyDetections)
    .where(eq(dataAnomalyDetections.assetId, assetId))
    .orderBy(desc(dataAnomalyDetections.detectedAt))
    .limit(5);
  const assessments = await db
    .select()
    .from(complianceAssessments)
    .where(eq(complianceAssessments.assetId, assetId))
    .orderBy(desc(complianceAssessments.assessedAt))
    .limit(5);
  const cycles = await db
    .select()
    .from(monitoringCycles)
    .where(eq(monitoringCycles.assetId, assetId))
    .orderBy(desc(monitoringCycles.createdAt))
    .limit(3);

  return {
    quality: quality.map((row) => ({
      metricType: row.metricType,
      metricValue: row.metricValue,
      status: row.status,
      collectedAt: row.collectedAt,
    })),
    drift: drift.map((row) => ({
      driftScore: row.driftScore,
      status: row.status,
      detectionMethod: row.detectionMethod,
      detectedAt: row.detectedAt,
    })),
    anomalies: anomalies.map((row) => ({
      detectionMethod: row.detectionMethod,
      affectedRecords: row.affectedRecords,
      severity: row.severity,
      description: row.description,
    })),
    assessments: assessments.map((row) => ({
      score: row.score,
      status: row.status,
      findings: row.findings,
      assessedAt: row.assessedAt,
    })),
    recentCycles: cycles.map((row) => ({
      trigger: row.trigger,
      elapsedMs: row.elapsedMs,
      withinBudget: row.withinBudget,
      driftStatus: row.driftStatus,
      qualityOverall: row.qualityOverall,
    })),
  };
}

function extractSummary(markdown: string) {
  const lines = markdown.split("\n").map((line) => line.trim()).filter(Boolean);
  const paragraph = lines.find((line) => !line.startsWith("#") && !line.startsWith("-"));
  return (paragraph || lines[0] || "Governance report generated.").slice(0, 400);
}

export function governanceProviderStatus() {
  return {
    configured: openRouterConfigured(),
    provider: "openrouter",
    model: openRouterModel(),
    purpose: "async_natural_language_synthesis",
    realtimePathUsesLlm: false,
  };
}

export async function listGovernanceReports(limit = 20) {
  await ensureReportsTable();
  return db.select().from(governanceReports).orderBy(desc(governanceReports.createdAt)).limit(limit);
}

export async function getGovernanceReport(id: number) {
  await ensureReportsTable();
  const [report] = await db.select().from(governanceReports).where(eq(governanceReports.id, id));
  return report;
}

/**
 * Queue and run an async GDPR + NIST narrative report.
 * Returns immediately with a pending/running row; completion updates the same row.
 */
export async function startGovernanceReport(options: {
  assetId?: number;
  createdBy?: number;
  frameworks?: string[];
}) {
  await ensureReportsTable();

  if (!openRouterConfigured()) {
    throw new Error(
      "OPENROUTER_API_KEY is required for async governance reports. Add it to the local .env file.",
    );
  }

  const assets = await storage.getAllAiAssets();
  const asset =
    (options.assetId ? assets.find((item) => item.id === options.assetId) : undefined) ??
    assets.find((item) => item.name === "ticket-training-set") ??
    assets.find((item) => item.name === "support-assistant") ??
    assets[0];
  if (!asset) throw new Error("No AI asset available for governance reporting");

  const frameworks = options.frameworks ?? ["GDPR", "NIST AI RMF"];
  const [pending] = await db
    .insert(governanceReports)
    .values({
      assetId: asset.id,
      frameworks,
      status: "running",
      title: `Audit-ready ${frameworks.join(" / ")} report — ${asset.name}`,
      provider: "openrouter",
      model: openRouterModel(),
      createdBy: options.createdBy,
    })
    .returning();

  // Fire-and-forget async synthesis so the HTTP request stays responsive
  void synthesizeReport(pending.id, asset.id, asset.name, frameworks).catch(async (error) => {
    logger.error("Governance report synthesis failed", {
      reportId: pending.id,
      error: (error as Error).message,
    });
    await db
      .update(governanceReports)
      .set({
        status: "failed",
        error: (error as Error).message,
        completedAt: new Date(),
      })
      .where(eq(governanceReports.id, pending.id));
  });

  return pending;
}

const synthesizeReport = withSpan(
  async function synthesizeReport(
  reportId: number,
  assetId: number,
  assetName: string,
  frameworks: string[],
) {
  const evidence = await collectEvidence(assetId);
  const started = Date.now();

  const completion = await chatCompletion(
    [
      {
        role: "system",
        content:
          "You are a compliance documentation agent. Write clear, audit-ready markdown for external regulators. Use only the evidence JSON provided. Do not invent controls that lack evidence. Structure the document with Executive Summary, Evidence Summary, GDPR mapping, NIST AI RMF mapping, Gaps, and Recommended Remediation.",
      },
      {
        role: "user",
        content: JSON.stringify(
          {
            assetName,
            frameworks,
            evidence,
            instructions:
              "Synthesize a professional compliance narrative. Call out statistical monitoring results (KS drift, Isolation Forest, LOF, six quality dimensions) as continuous monitoring evidence.",
          },
          null,
          2,
        ),
      },
    ],
    { temperature: 0.2, maxTokens: 2500 },
  );

  const bodyMarkdown = completion.content;
  await db
    .update(governanceReports)
    .set({
      status: "completed",
      summary: extractSummary(bodyMarkdown),
      bodyMarkdown,
      evidenceSnapshot: evidence,
      model: completion.model,
      elapsedMs: Date.now() - started,
      completedAt: new Date(),
      error: null,
    })
    .where(eq(governanceReports.id, reportId));

  logger.info("Governance report completed", {
    reportId,
    model: completion.model,
    elapsedMs: Date.now() - started,
  });
},
  {
    name: "governance.synthesize_report",
    kind: "CHAIN",
  },
);
