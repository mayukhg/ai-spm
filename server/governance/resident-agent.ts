/**
 * Persistent resident agent for continuous pipeline health monitoring.
 *
 * Real-time path: Practical Fast Math only (quality dimensions, KS drift,
 * Isolation Forest, LOF). Never calls OpenRouter / LLMs.
 */

import fs from "fs";
import path from "path";
import { desc } from "drizzle-orm";
import { db, pool } from "../db";
import { storage } from "../storage";
import {
  dataAnomalyDetections,
  dataDriftMetrics,
  dataQualityMetrics,
  monitoringCycles,
} from "@shared/schema";
import { fixtureRoot } from "../analysis/synthetic-analysis";
import { runFastMathMonitor, type PipelineRow } from "../analysis/fast-math";
import { logger } from "../monitoring/logger";

const INTERVAL_MS = 15 * 60 * 1000;

type AgentState = {
  running: boolean;
  lastRunAt: string | null;
  lastElapsedMs: number | null;
  lastWithinBudget: boolean | null;
  nextRunAt: string | null;
  cyclesCompleted: number;
};

const state: AgentState = {
  running: false,
  lastRunAt: null,
  lastElapsedMs: null,
  lastWithinBudget: null,
  nextRunAt: null,
  cyclesCompleted: 0,
};

let timer: NodeJS.Timeout | null = null;

function parseCsv(filePath: string): PipelineRow[] {
  const text = fs.readFileSync(filePath, "utf8").trim();
  const [header, ...lines] = text.split("\n");
  const columns = header.split(",");
  return lines.filter(Boolean).map((line) => {
    const cells = line.split(",");
    return Object.fromEntries(columns.map((column, index) => [column, cells[index] ?? ""])) as PipelineRow;
  });
}

function resolvePipelinePaths(asset: { metadata: unknown; name: string }) {
  const metadata = (asset.metadata ?? {}) as {
    baselinePath?: string;
    currentPath?: string;
    dirtyPath?: string;
  };
  const baseline =
    metadata.baselinePath && fs.existsSync(metadata.baselinePath)
      ? metadata.baselinePath
      : path.join(fixtureRoot, "ticket-training-set-baseline.csv");
  const current =
    metadata.currentPath && fs.existsSync(metadata.currentPath)
      ? metadata.currentPath
      : path.join(fixtureRoot, "ticket-training-set-current.csv");
  return { baseline, current, dirty: metadata.dirtyPath };
}

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS monitoring_cycles (
      id serial PRIMARY KEY,
      asset_id integer NOT NULL,
      trigger text NOT NULL,
      elapsed_ms integer NOT NULL,
      within_budget boolean NOT NULL,
      quality_overall numeric(10,4) NOT NULL,
      drift_status text NOT NULL,
      isolation_anomalies integer NOT NULL,
      lof_anomalies integer NOT NULL,
      result jsonb NOT NULL,
      created_at timestamp NOT NULL DEFAULT NOW()
    )
  `);
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

export function getResidentAgentStatus() {
  return {
    ...state,
    intervalMinutes: 15,
    engine: "practical_fast_math",
    methods: [
      "six_quality_dimensions",
      "kolmogorov_smirnov",
      "isolation_forest",
      "local_outlier_factor",
    ],
    llmOnRealtimePath: false,
  };
}

export async function runMonitoringCycle(trigger: "scheduled" | "manual" = "manual") {
  await ensureTables();
  const assets = await storage.getAllAiAssets({ type: "dataset" });
  const asset =
    assets.find((item) => item.name === "ticket-training-set") ??
    assets[0];
  if (!asset) {
    throw new Error("No dataset asset available for resident monitoring");
  }

  const paths = resolvePipelinePaths(asset);
  const baseline = parseCsv(paths.baseline);
  const current = parseCsv(paths.current);
  const report = runFastMathMonitor({ baseline, current });

  const dimensions = [
    "completeness",
    "accuracy",
    "consistency",
    "validity",
    "uniqueness",
    "freshness",
  ] as const;

  for (const metricType of dimensions) {
    await db.insert(dataQualityMetrics).values({
      assetId: asset.id,
      datasetName: asset.name,
      metricType,
      metricValue: String(report.quality[metricType]),
      threshold: "0.9500",
      status: report.quality[metricType] < 0.95 ? "critical" : "normal",
      details: { source: "resident_agent", trigger },
      environment: asset.environment ?? "production",
    });
  }

  await db.insert(dataDriftMetrics).values({
    assetId: asset.id,
    datasetName: asset.name,
    referenceDatasetId: "baseline",
    currentDatasetId: "current",
    driftType: "feature_drift",
    driftScore: String(report.drift.ks),
    threshold: String(report.drift.threshold),
    status: report.drift.status,
    affectedFeatures: [report.drift.feature],
    detectionMethod: report.drift.method,
    statisticalTest: report.drift,
    environment: asset.environment ?? "production",
  });

  await db.insert(dataAnomalyDetections).values([
    {
      assetId: asset.id,
      datasetName: asset.name,
      anomalyType: "outlier",
      severity: report.isolationForest.anomalousCount > 5 ? "high" : "medium",
      confidence: "0.9000",
      description: `Isolation Forest flagged ${report.isolationForest.anomalousCount} rows on amount.`,
      affectedRecords: report.isolationForest.anomalousCount,
      totalRecords: current.length,
      detectionMethod: "isolation_forest",
      anomalyScore: String(report.isolationForest.threshold),
      threshold: String(report.isolationForest.threshold),
      features: { flaggedIndices: report.isolationForest.flaggedIndices.slice(0, 20) },
      context: { elapsedMs: report.elapsedMs },
      status: "detected",
      environment: asset.environment ?? "production",
    },
    {
      assetId: asset.id,
      datasetName: asset.name,
      anomalyType: "outlier",
      severity: report.localOutlierFactor.anomalousCount > 5 ? "high" : "medium",
      confidence: "0.9000",
      description: `Local Outlier Factor flagged ${report.localOutlierFactor.anomalousCount} rows on amount.`,
      affectedRecords: report.localOutlierFactor.anomalousCount,
      totalRecords: current.length,
      detectionMethod: "local_outlier_factor",
      anomalyScore: String(report.localOutlierFactor.threshold),
      threshold: String(report.localOutlierFactor.threshold),
      features: { flaggedIndices: report.localOutlierFactor.flaggedIndices.slice(0, 20), k: report.localOutlierFactor.k },
      context: { elapsedMs: report.elapsedMs },
      status: "detected",
      environment: asset.environment ?? "production",
    },
  ]);

  const [cycle] = await db
    .insert(monitoringCycles)
    .values({
      assetId: asset.id,
      trigger,
      elapsedMs: report.elapsedMs,
      withinBudget: report.withinBudget,
      qualityOverall: String(report.quality.overall),
      driftStatus: report.drift.status,
      isolationAnomalies: report.isolationForest.anomalousCount,
      lofAnomalies: report.localOutlierFactor.anomalousCount,
      result: report,
    })
    .returning();

  state.lastRunAt = new Date().toISOString();
  state.lastElapsedMs = report.elapsedMs;
  state.lastWithinBudget = report.withinBudget;
  state.cyclesCompleted += 1;
  if (state.running) {
    state.nextRunAt = new Date(Date.now() + INTERVAL_MS).toISOString();
  }

  logger.info("Resident agent monitoring cycle completed", {
    trigger,
    assetId: asset.id,
    elapsedMs: report.elapsedMs,
    withinBudget: report.withinBudget,
    drift: report.drift.status,
  });

  return {
    cycleId: cycle.id,
    assetId: asset.id,
    assetName: asset.name,
    trigger,
    ...report,
    status: getResidentAgentStatus(),
  };
}

export async function listRecentCycles(limit = 10) {
  await ensureTables();
  return db.select().from(monitoringCycles).orderBy(desc(monitoringCycles.createdAt)).limit(limit);
}

export function startResidentAgent() {
  if (timer) return getResidentAgentStatus();
  state.running = true;
  state.nextRunAt = new Date(Date.now() + INTERVAL_MS).toISOString();
  timer = setInterval(() => {
    runMonitoringCycle("scheduled").catch((error) => {
      logger.error("Scheduled resident monitoring failed", { error: (error as Error).message });
    });
  }, INTERVAL_MS);
  logger.info("Resident agent started", { intervalMinutes: 15 });
  // Kick an initial cycle so the dashboard is not empty after boot
  runMonitoringCycle("scheduled").catch((error) => {
    logger.error("Initial resident monitoring failed", { error: (error as Error).message });
  });
  return getResidentAgentStatus();
}

export function stopResidentAgent() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  state.running = false;
  state.nextRunAt = null;
  return getResidentAgentStatus();
}
