import fs from "fs";
import { db } from "../db";
import { storage } from "../storage";
import {
  aiAssets,
  dataDriftMetrics,
  dataIntegrityAlerts,
  dataQualityMetrics,
} from "@shared/schema";
import { eq } from "drizzle-orm";
import {
  classifyLlmPrompts,
  demographicParity,
  driftReport,
  loadModelCard,
  loadWizFixture,
  nistEvidence,
  qualityReport,
} from "./synthetic-analysis";

export async function persistScanFindings(assetId: number, modelPath?: string) {
  const asset = await storage.getAiAsset(assetId);
  const metadata = (asset?.metadata ?? {}) as { modelCardPath?: string; evaluationPath?: string };
  const cardPath = modelPath || metadata.modelCardPath;
  const existing = await storage.getVulnerabilitiesByAsset(assetId);
  const titles = new Set(existing.map((item) => item.title));

  if (cardPath && fs.existsSync(cardPath)) {
    const card = loadModelCard(cardPath);
    for (const finding of card.declaredFindings ?? []) {
      if (titles.has(finding.title)) continue;
      await storage.createVulnerability({
        assetId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: finding.category,
        status: "open",
        detectionMethod: "model_card",
        recommendation: finding.recommendation,
      });
      titles.add(finding.title);
    }
  }

  if (metadata.evaluationPath && fs.existsSync(metadata.evaluationPath)) {
    const bias = demographicParity(metadata.evaluationPath);
    if (bias.status === "fail" && !titles.has("Demographic parity failure")) {
      await storage.createVulnerability({
        assetId,
        title: "Demographic parity failure",
        description: `Demographic parity difference is ${bias.difference}.`,
        severity: "high",
        category: "model_security",
        status: "open",
        detectionMethod: "bias_evaluation",
        recommendation: "Retrain with a balanced evaluation set.",
        metadata: bias,
      });
    }
  }

  await storage.updateAiAsset(assetId, { lastScannedAt: new Date() });
}

export async function persistDatasetCheck(assetId: number, checkType: string) {
  const asset = await storage.getAiAsset(assetId);
  const metadata = (asset?.metadata ?? {}) as {
    dirtyPath?: string;
    baselinePath?: string;
    currentPath?: string;
  };

  if (checkType === "quality" && metadata.dirtyPath && fs.existsSync(metadata.dirtyPath)) {
    const report = qualityReport(metadata.dirtyPath);
    await db.insert(dataQualityMetrics).values([
      metricRow(assetId, "completeness", report.completeness),
      metricRow(assetId, "uniqueness", report.uniqueness),
      metricRow(assetId, "validity", report.validity),
    ]);
    await db.insert(dataIntegrityAlerts).values({
      assetId,
      alertType: "missing_data",
      severity: "high",
      title: "Training extract failed quality checks",
      description: `${report.affectedRecords} records failed completeness, uniqueness, or validity.`,
      impact: "model_performance",
      datasetName: asset?.name ?? "dataset",
      affectedRecords: report.affectedRecords,
      totalRecords: report.total,
      detectionSource: "quality_check",
      status: "active",
      priority: "high",
    });
    return report;
  }

  if (checkType === "drift" && metadata.baselinePath && metadata.currentPath) {
    const report = driftReport(metadata.baselinePath, metadata.currentPath);
    await db.insert(dataDriftMetrics).values({
      assetId,
      datasetName: asset?.name ?? "dataset",
      referenceDatasetId: "baseline",
      currentDatasetId: "current",
      driftType: "feature_drift",
      driftScore: report.ks.toFixed(6),
      threshold: "0.200000",
      status: report.status === "significant_drift" ? "significant_drift" : "stable",
      affectedFeatures: [report.feature],
      detectionMethod: report.method,
      statisticalTest: report,
      environment: asset?.environment ?? "development",
    });
    return report;
  }

  return null;
}

function metricRow(assetId: number, metricType: string, value: number) {
  return {
    assetId,
    datasetName: "ticket-training-set",
    metricType,
    metricValue: value.toFixed(4),
    threshold: "0.9500",
    status: value < 0.95 ? "critical" : "normal",
    environment: "training",
  };
}

export async function replayWizFixture() {
  const fixture = loadWizFixture();
  const created: string[] = [];
  for (const resource of fixture.resources) {
    const existing = await db.select().from(aiAssets).where(eq(aiAssets.name, resource.name));
    let assetId = existing[0]?.id;
    if (!assetId) {
      const asset = await storage.createAiAsset({
        name: resource.name,
        type: resource.type,
        description: "Imported from the synthetic Wiz fixture.",
        environment: resource.environment,
        status: "active",
        riskLevel: resource.riskLevel,
        owner: "Synthetic CISO",
        metadata: { source: "wiz-fixture" },
      });
      assetId = asset.id;
      created.push(resource.name);
    }
    if (resource.finding) {
      const vulns = await storage.getVulnerabilitiesByAsset(assetId);
      if (!vulns.some((item) => item.title === resource.finding?.title)) {
        await storage.createVulnerability({
          assetId,
          title: resource.finding.title,
          description: resource.finding.description,
          severity: resource.finding.severity,
          category: "infrastructure",
          status: "open",
          detectionMethod: "wiz",
          recommendation: "Remediate the cloud finding and rerun the sync.",
        });
      }
    }
  }
  return { imported: fixture.resources.map((resource) => resource.name), created };
}

export async function persistLlmClassifications() {
  const report = classifyLlmPrompts();
  const assets = await storage.getAllAiAssets();
  const asset = assets.find((item) => item.name === report.assetName);
  const existing = await storage.getAllSecurityAlerts();
  let written = 0;

  for (const result of report.results) {
    if (result.decision !== "block" || !asset) continue;
    const payload = {
      assetId: asset.id,
      type: result.label,
      severity: result.label === "jailbreak" ? "critical" : "high",
      title: result.title,
      description: result.summary,
      status: "active" as const,
      source: "llm_classifier",
      metadata: {
        promptId: result.id,
        score: result.score,
        spans: result.spans,
        tokens: result.tokens,
      },
    };
    const current = existing.find((alert) => alert.title === result.title && alert.assetId === asset.id);
    if (current) {
      await storage.updateSecurityAlert(current.id, payload);
    } else {
      await storage.createSecurityAlert(payload);
    }
    written += 1;
  }

  return { ...report, assetId: asset?.id ?? null, alertsWritten: written };
}

export async function evidenceAssessment(assetId: number, framework: string, assessedBy: number) {
  const asset = await storage.getAiAsset(assetId);
  const metadata = (asset?.metadata ?? {}) as { modelCardPath?: string };
  if (!framework.includes("nist") || !metadata.modelCardPath) return null;
  const evidence = nistEvidence(metadata.modelCardPath);
  const frameworks = await storage.getAllComplianceFrameworks();
  const nist = frameworks.find((item) => item.name.toLowerCase().includes("nist"));
  if (!nist) return evidence;
  const assessment = await storage.createComplianceAssessment({
    assetId,
    frameworkId: nist.id,
    score: evidence.score,
    status: evidence.status,
    assessedBy,
    findings: { source: "evidence-check", controls: evidence.controls },
    recommendations: evidence.controls.filter((control) => !control.passed).map((control) => `Add ${control.control}`).join("; "),
  });
  return { ...evidence, assessmentId: assessment.id };
}
