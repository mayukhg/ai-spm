import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth } from "./auth";
// Wiz integration now handled by Python microservice
import { z } from "zod";
import { 
  insertAiAssetSchema,
  insertVulnerabilitySchema,
  insertSecurityAlertSchema,
  insertComplianceFrameworkSchema,
  insertComplianceAssessmentSchema,
  insertGovernancePolicySchema
} from "@shared/schema";
// Import adversarial detection routes
import adversarialDetectionRoutes from './routes/adversarial-detection-routes';
// Import data quality monitoring routes
import { dataQualityRoutes } from './data-quality/data-quality-routes';
import { evidenceAssessment, persistDatasetCheck, persistLlmClassifications, persistScanFindings, replayWizFixture } from './analysis/persist-results';
import { classifyLlmPrompts, siemEvent } from './analysis/synthetic-analysis';

// Microservices integration - simplified for development
interface MicroserviceRequest extends Request {
  correlationId?: string;
}

/**
 * Middleware to ensure user is authenticated
 */
function requireAuth(req: any, res: any, next: any) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
}

/**
 * Middleware to ensure user has specific role
 */
function requireRole(roles: string[]) {
  return (req: any, res: any, next: any) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Authentication required" });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    
    next();
  };
}

/**
 * Log user action for audit trail
 */
async function logAction(userId: number, action: string, resourceType: string, resourceId?: number, details?: any) {
  try {
    await storage.createAuditLog({
      userId,
      action,
      resourceType,
      resourceId,
      details,
    });
  } catch (error) {
    console.error("Failed to log action:", error);
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup authentication routes
  setupAuth(app);

  // Dashboard metrics endpoint
  app.get("/api/dashboard/metrics", requireAuth, async (req, res, next) => {
    try {
      const metrics = await storage.getDashboardMetrics();
      res.json(metrics);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/dashboard/trend", requireAuth, async (_req, res, next) => {
    try {
      res.json(await storage.getPostureTrend());
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/settings/status", requireAuth, async (_req, res) => {
    res.json({
      authentication: "session",
      roles: ["ciso", "analyst", "engineer", "compliance_officer"],
      syntheticFixtures: process.env.SYNTHETIC_FIXTURES === "true",
      wiz: {
        configured: Boolean(process.env.WIZ_CLIENT_ID && process.env.WIZ_CLIENT_SECRET),
      },
      siem: {
        splunk: Boolean(process.env.SPLUNK_ENDPOINT && process.env.SPLUNK_TOKEN),
        qradar: Boolean(process.env.QRADAR_ENDPOINT && process.env.QRADAR_TOKEN),
        sentinel: Boolean(process.env.SENTINEL_WORKSPACE_ID && process.env.SENTINEL_SHARED_KEY),
      },
      services: {
        aiScanner: process.env.AI_SCANNER_URL || "http://127.0.0.1:8001",
        dataIntegrity: process.env.DATA_INTEGRITY_URL || "http://127.0.0.1:8002",
        wizIntegration: process.env.WIZ_INTEGRATION_URL || "http://127.0.0.1:8003",
        complianceEngine: process.env.COMPLIANCE_ENGINE_URL || "http://127.0.0.1:8004",
      },
    });
  });

  // AI Assets endpoints
  app.get("/api/ai-assets", requireAuth, async (req, res, next) => {
    try {
      const { type, environment, riskLevel, search } = req.query;
      const filters = {
        type: type as string,
        environment: environment as string,
        riskLevel: riskLevel as string,
        search: search as string,
      };

      // Remove undefined filters
      Object.keys(filters).forEach(key => {
        if (!filters[key as keyof typeof filters]) {
          delete filters[key as keyof typeof filters];
        }
      });

      const assets = await storage.getAllAiAssets(Object.keys(filters).length > 0 ? filters : undefined);
      res.json(assets);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/ai-assets/:id", requireAuth, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const asset = await storage.getAiAsset(id);
      
      if (!asset) {
        return res.status(404).json({ error: "Asset not found" });
      }

      res.json(asset);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/ai-assets", requireAuth, async (req, res, next) => {
    try {
      const validatedData = insertAiAssetSchema.parse(req.body);
      const asset = await storage.createAiAsset(validatedData);
      
      await logAction(req.user.id, "create_asset", "ai_asset", asset.id, { name: asset.name });
      
      res.status(201).json(asset);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
      next(error);
    }
  });

  app.patch("/api/ai-assets/:id", requireAuth, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      
      const asset = await storage.updateAiAsset(id, updates);
      if (!asset) {
        return res.status(404).json({ error: "Asset not found" });
      }

      await logAction(req.user.id, "update_asset", "ai_asset", id, { updates: Object.keys(updates) });
      
      res.json(asset);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/ai-assets/:id", requireRole(["ciso", "admin"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const success = await storage.deleteAiAsset(id);
      
      if (!success) {
        return res.status(404).json({ error: "Asset not found" });
      }

      await logAction(req.user.id, "delete_asset", "ai_asset", id);
      
      res.sendStatus(204);
    } catch (error) {
      next(error);
    }
  });

  // Vulnerabilities endpoints
  app.get("/api/vulnerabilities", requireAuth, async (req, res, next) => {
    try {
      const { severity, status, assignedTo } = req.query;
      const filters = {
        severity: severity as string,
        status: status as string,
        assignedTo: assignedTo ? parseInt(assignedTo as string) : undefined,
      };

      // Remove undefined filters
      Object.keys(filters).forEach(key => {
        if (filters[key as keyof typeof filters] === undefined) {
          delete filters[key as keyof typeof filters];
        }
      });

      const vulnerabilities = await storage.getAllVulnerabilities(Object.keys(filters).length > 0 ? filters : undefined);
      res.json(vulnerabilities);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/vulnerabilities/stats", requireAuth, async (req, res, next) => {
    try {
      const stats = await storage.getVulnerabilityStats();
      res.json(stats);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/vulnerabilities/:id", requireAuth, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const vulnerability = await storage.getVulnerability(id);
      
      if (!vulnerability) {
        return res.status(404).json({ error: "Vulnerability not found" });
      }

      res.json(vulnerability);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/vulnerabilities", requireAuth, async (req, res, next) => {
    try {
      const validatedData = insertVulnerabilitySchema.parse(req.body);
      const vulnerability = await storage.createVulnerability(validatedData);
      
      await logAction(req.user.id, "create_vulnerability", "vulnerability", vulnerability.id, { 
        severity: vulnerability.severity,
        assetId: vulnerability.assetId 
      });
      
      res.status(201).json(vulnerability);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
      next(error);
    }
  });

  app.patch("/api/vulnerabilities/:id", requireAuth, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      
      const vulnerability = await storage.updateVulnerability(id, updates);
      if (!vulnerability) {
        return res.status(404).json({ error: "Vulnerability not found" });
      }

      await logAction(req.user.id, "update_vulnerability", "vulnerability", id, { updates: Object.keys(updates) });
      
      res.json(vulnerability);
    } catch (error) {
      next(error);
    }
  });

  // Security alerts endpoints
  app.get("/api/security-alerts", requireAuth, async (req, res, next) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const alerts = await storage.getAllSecurityAlerts(limit);
      res.json(alerts);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/security-alerts/recent", requireAuth, async (req, res, next) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;
      const alerts = await storage.getRecentAlerts(limit);
      res.json(alerts);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/security-alerts", requireAuth, async (req, res, next) => {
    try {
      const validatedData = insertSecurityAlertSchema.parse(req.body);
      const alert = await storage.createSecurityAlert(validatedData);
      
      await logAction(req.user.id, "create_alert", "security_alert", alert.id, { 
        type: alert.type,
        severity: alert.severity 
      });
      
      res.status(201).json({ ...alert, siem: siemEvent(alert) });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
      next(error);
    }
  });

  app.get("/api/llm/classifications", requireAuth, async (req, res, next) => {
    try {
      res.json(classifyLlmPrompts());
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/llm/classifications", requireAuth, async (req, res, next) => {
    try {
      const report = await persistLlmClassifications();
      await logAction(req.user.id, "llm_classification", "ai_assets", report.assetId ?? undefined, {
        evaluated: report.evaluated,
        blocked: report.blocked,
      });
      res.json(report);
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/security-alerts/:id", requireAuth, async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      
      const alert = await storage.updateSecurityAlert(id, updates);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }

      await logAction(req.user.id, "update_alert", "security_alert", id, { updates: Object.keys(updates) });
      
      res.json(alert);
    } catch (error) {
      next(error);
    }
  });

  // Compliance endpoints
  app.get("/api/compliance/frameworks", requireAuth, async (req, res, next) => {
    try {
      const frameworks = await storage.getAllComplianceFrameworks();
      res.json(frameworks);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/compliance/overview", requireAuth, async (req, res, next) => {
    try {
      const overview = await storage.getComplianceOverview();
      res.json(overview);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/compliance/frameworks", requireRole(["ciso", "compliance_officer"]), async (req, res, next) => {
    try {
      const validatedData = insertComplianceFrameworkSchema.parse(req.body);
      const framework = await storage.createComplianceFramework(validatedData);
      
      await logAction(req.user.id, "create_framework", "compliance_framework", framework.id, { name: framework.name });
      
      res.status(201).json(framework);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
      next(error);
    }
  });

  app.post("/api/compliance/assessments", requireAuth, async (req, res, next) => {
    try {
      const validatedData = insertComplianceAssessmentSchema.parse({
        ...req.body,
        assessedBy: req.user.id
      });
      const assessment = await storage.createComplianceAssessment(validatedData);
      
      await logAction(req.user.id, "create_assessment", "compliance_assessment", assessment.id, { 
        assetId: assessment.assetId,
        frameworkId: assessment.frameworkId,
        score: assessment.score 
      });
      
      res.status(201).json(assessment);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
      next(error);
    }
  });

  // Governance policies endpoints
  app.get("/api/governance/policies", requireAuth, async (req, res, next) => {
    try {
      const policies = await storage.getAllGovernancePolicies();
      res.json(policies);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/governance/policies", requireRole(["ciso", "compliance_officer"]), async (req, res, next) => {
    try {
      const validatedData = insertGovernancePolicySchema.parse({
        ...req.body,
        createdBy: req.user.id
      });
      const policy = await storage.createGovernancePolicy(validatedData);
      
      await logAction(req.user.id, "create_policy", "governance_policy", policy.id, { 
        name: policy.name,
        category: policy.category 
      });
      
      res.status(201).json(policy);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
      next(error);
    }
  });

  app.patch("/api/governance/policies/:id", requireRole(["ciso", "compliance_officer"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      
      const policy = await storage.updateGovernancePolicy(id, updates);
      if (!policy) {
        return res.status(404).json({ error: "Policy not found" });
      }

      await logAction(req.user.id, "update_policy", "governance_policy", id, { updates: Object.keys(updates) });
      
      res.json(policy);
    } catch (error) {
      next(error);
    }
  });

  // User management endpoints
  app.get("/api/users", requireRole(["ciso", "admin"]), async (req, res, next) => {
    try {
      const users = await storage.getAllUsers();
      // Remove passwords from response
      const safeUsers = users.map(({ password, ...user }) => user);
      res.json(safeUsers);
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/users/:id", requireRole(["ciso", "admin"]), async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updates = req.body;
      
      // Don't allow password updates through this endpoint
      delete updates.password;
      
      const user = await storage.updateUser(id, updates);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      await logAction(req.user.id, "update_user", "user", id, { updates: Object.keys(updates) });
      
      // Remove password from response
      const { password, ...userResponse } = user;
      res.json(userResponse);
    } catch (error) {
      next(error);
    }
  });

  // Audit logs endpoint
  app.get("/api/audit-logs", requireRole(["ciso", "compliance_officer"]), async (req, res, next) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
      const logs = await storage.getAuditLogs(limit);
      res.json(logs);
    } catch (error) {
      next(error);
    }
  });

  // Python microservices. The gateway forwards these calls instead of returning stubs.
  const microserviceUrls: Record<string, string> = {
    "ai-scanner": process.env.AI_SCANNER_URL || process.env.AI_SCANNER_SERVICE_URL || "http://127.0.0.1:8001",
    "data-integrity": process.env.DATA_INTEGRITY_URL || process.env.DATA_INTEGRITY_SERVICE_URL || "http://127.0.0.1:8002",
    "wiz-integration": process.env.WIZ_INTEGRATION_URL || process.env.WIZ_INTEGRATION_SERVICE_URL || "http://127.0.0.1:8003",
    "compliance-engine": process.env.COMPLIANCE_ENGINE_URL || process.env.COMPLIANCE_ENGINE_SERVICE_URL || "http://127.0.0.1:8004",
  };

  async function callMicroservice(service: string, path: string, method = "GET", body?: unknown) {
    const baseUrl = microserviceUrls[service];
    if (!baseUrl) {
      const error = new Error(`Unknown microservice: ${service}`) as Error & { status?: number };
      error.status = 503;
      throw error;
    }

    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/json", "X-Forwarded-By": "ai-spm-gateway" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    const text = await response.text();
    let payload: any = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { message: text };
      }
    }

    if (!response.ok) {
      const error = new Error(
        payload?.detail ? `Service ${service} rejected the request` : `Service ${service} returned ${response.status}`
      ) as Error & { status?: number; payload?: unknown };
      error.status = response.status;
      error.payload = payload;
      throw error;
    }

    return payload;
  }

  function sendServiceError(res: any, error: any, next: any) {
    if (error?.status) {
      return res.status(error.status).json({
        error: error.message,
        service: error.payload ?? null,
      });
    }
    if (error?.cause?.code === "ECONNREFUSED" || error?.code === "ECONNREFUSED") {
      return res.status(503).json({ error: "Microservice is not reachable" });
    }
    next(error);
  }

  app.post("/api/ai-scanner/scan", requireAuth, async (req: any, res, next) => {
    try {
      const asset = await storage.getAiAsset(Number(req.body.asset_id));
      const metadata = (asset?.metadata ?? {}) as { modelCardPath?: string; framework?: string };
      const scanRequest = {
        asset_id: Number(req.body.asset_id),
        asset_type: req.body.asset_type || asset?.type,
        framework: req.body.framework || metadata.framework,
        model_path: req.body.model_path || metadata.modelCardPath,
        scan_depth: req.body.scan_depth || "standard",
        correlation_id: `scan-${Date.now()}`,
      };

      await logAction(req.user.id, "ai_scan_started", "ai_assets", scanRequest.asset_id, scanRequest);
      const result = await callMicroservice("ai-scanner", "/scan", "POST", scanRequest);
      let persisted = null;
      if (result?.scan_id) {
        for (let attempt = 0; attempt < 8; attempt += 1) {
          await new Promise((resolve) => setTimeout(resolve, 400));
          try {
            const completed = await callMicroservice("ai-scanner", `/scan/${encodeURIComponent(result.scan_id)}`);
            if (completed?.status === "completed" || completed?.status === "failed") break;
          } catch {
            break;
          }
        }
      }
      persisted = await persistScanFindings(scanRequest.asset_id, scanRequest.model_path);
      res.json({ ...result, service: "ai-scanner", persisted });
    } catch (error) {
      sendServiceError(res, error, next);
    }
  });

  app.get("/api/ai-scanner/scan/:scanId", requireAuth, async (req: any, res, next) => {
    try {
      const result = await callMicroservice("ai-scanner", `/scan/${encodeURIComponent(req.params.scanId)}`);
      res.json({ ...result, service: "ai-scanner" });
    } catch (error) {
      sendServiceError(res, error, next);
    }
  });

  app.post("/api/data-integrity/check", requireAuth, async (req: any, res, next) => {
    try {
      const checkRequest = {
        asset_id: Number(req.body.asset_id),
        data_source: req.body.data_source,
        check_type: req.body.check_type,
        dataset_path: req.body.dataset_path,
        correlation_id: `check-${Date.now()}`,
      };

      await logAction(req.user.id, "data_integrity_check_started", "ai_assets", checkRequest.asset_id, checkRequest);
      const result = await callMicroservice("data-integrity", "/check", "POST", checkRequest);
      const analysis = await persistDatasetCheck(checkRequest.asset_id, checkRequest.check_type);
      res.json({ ...result, service: "data-integrity", analysis });
    } catch (error) {
      sendServiceError(res, error, next);
    }
  });

  app.post("/api/wiz-integration/integrate", requireRole(["ciso", "analyst"]), async (req: any, res, next) => {
    try {
      const integrationRequest = {
        asset_id: Number(req.body.asset_id),
        integration_type: req.body.integration_type || "sync",
        cloud_provider: req.body.cloud_provider,
        resource_filters: req.body.resource_filters,
        sync_scope: req.body.sync_scope,
        correlation_id: `wiz-${Date.now()}`,
      };

      const useFixture = req.body.useFixture === true || process.env.SYNTHETIC_FIXTURES === "true";
      const hasCredentials = Boolean(process.env.WIZ_CLIENT_ID && process.env.WIZ_CLIENT_SECRET);
      if (!useFixture && !hasCredentials) {
        return res.status(422).json({
          status: "failed",
          message: "Wiz credentials not configured",
          imported: [],
        });
      }

      await logAction(req.user.id, "wiz_integration_started", "integrations", undefined, integrationRequest);
      if (useFixture && !hasCredentials) {
        const imported = await replayWizFixture();
        return res.json({ status: "completed", service: "wiz-integration", source: "fixture", ...imported });
      }
      const result = await callMicroservice("wiz-integration", "/integrate", "POST", integrationRequest);
      res.json({ ...result, service: "wiz-integration" });
    } catch (error) {
      sendServiceError(res, error, next);
    }
  });

  app.post("/api/compliance/assess", requireRole(["ciso", "compliance_officer"]), async (req: any, res, next) => {
    try {
      const assessmentRequest = {
        asset_id: Number(req.body.asset_id),
        framework: req.body.framework,
        assessment_type: req.body.assessment_type || "full",
        scope: req.body.scope,
        correlation_id: `comp-${Date.now()}`,
      };

      await logAction(req.user.id, "compliance_assessment_started", "ai_assets", assessmentRequest.asset_id, assessmentRequest);
      const evidence = await evidenceAssessment(assessmentRequest.asset_id, assessmentRequest.framework, req.user.id);
      const result = await callMicroservice("compliance-engine", "/assess", "POST", assessmentRequest);
      res.json({ ...result, service: "compliance-engine", evidence });
    } catch (error) {
      sendServiceError(res, error, next);
    }
  });

  app.get("/api/microservices/health", requireAuth, async (_req: any, res) => {
    const services: Record<string, boolean> = {};
    await Promise.all(
      Object.entries(microserviceUrls).map(async ([name, url]) => {
        try {
          const response = await fetch(`${url}/health`);
          services[name] = response.ok;
        } catch {
          services[name] = false;
        }
      })
    );

    const healthy = Object.values(services).filter(Boolean).length;
    res.json({
      gateway_status: "healthy",
      services,
      timestamp: new Date().toISOString(),
      total_services: Object.keys(services).length,
      healthy_services: healthy,
      architecture: "hybrid-microservices",
    });
  });

  // Legacy Wiz endpoints - now handled by microservices
  app.post("/api/integrations/wiz/sync-assets", requireRole(["ciso", "analyst", "engineer"]), async (req: any, res, next) => {
    try {
      await logAction(req.user.id, "wiz_asset_sync", "integration", undefined, req.body);

      const result = {
        message: "Wiz asset sync now handled by microservice",
        microservice_endpoint: "/api/wiz-integration/integrate",
        architecture: "hybrid-microservices"
      };
      
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Legacy Wiz Integration Endpoints (redirected to microservices)
  app.post("/api/integrations/wiz/sync-vulnerabilities", requireRole(["ciso", "analyst"]), async (req: any, res, next) => {
    try {
      await logAction(req.user.id, "wiz_vulnerability_sync", "integration", undefined, req.body);

      const result = {
        message: "Wiz vulnerability sync handled by microservice",
        microservice_endpoint: "/api/wiz-integration/integrate",
        architecture: "hybrid-microservices"
      };
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Legacy Wiz integration status endpoint
  app.get("/api/integrations/wiz/status", requireAuth, async (req: any, res, next) => {
    try {
      const hasCredentials = !!(process.env.WIZ_CLIENT_ID && process.env.WIZ_CLIENT_SECRET);
      
      res.json({
        configured: true,
        hasCredentials,
        status: "microservice",
        architecture: "hybrid-microservices",
        message: "Wiz integration now handled by dedicated microservice",
        microservice_endpoint: "/api/wiz-integration/integrate"
      });
    } catch (error) {
      next(error);
    }
  });

  // Mount adversarial detection routes
  app.use('/api/adversarial-detection', requireAuth, adversarialDetectionRoutes);

  // Mount data quality monitoring routes
  app.use('/api/data-quality', requireAuth, dataQualityRoutes);

  const httpServer = createServer(app);
  return httpServer;
}
