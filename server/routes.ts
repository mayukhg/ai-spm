import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth } from "./auth";
import { createWizIntegration } from "./integrations/wiz";
import { z } from "zod";
import { 
  insertAiAssetSchema,
  insertVulnerabilitySchema,
  insertSecurityAlertSchema,
  insertComplianceFrameworkSchema,
  insertComplianceAssessmentSchema,
  insertGovernancePolicySchema
} from "@shared/schema";
import { 
  MicroserviceRegistry, 
  ServiceProxy, 
  gatewayMiddleware, 
  gatewayErrorHandler,
  createHealthEndpoint,
  type GatewayRequest
} from "./microservices-gateway";

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
      
      res.status(201).json(alert);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: "Validation failed", details: error.errors });
      }
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

  // Microservices Integration Endpoints
  const serviceRegistry = new MicroserviceRegistry();
  const serviceProxy = new ServiceProxy(serviceRegistry);

  // AI Scanner Microservice Endpoints
  app.post("/api/ai-scanner/scan", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const scanRequest = {
        asset_id: req.body.asset_id,
        asset_type: req.body.asset_type,
        framework: req.body.framework,
        model_path: req.body.model_path,
        scan_depth: req.body.scan_depth || "standard",
        correlation_id: req.correlationId
      };

      await logAction(req.user!.id, "ai_scan_started", "ai_assets", scanRequest.asset_id, scanRequest);

      const response = await serviceProxy.proxyRequest(
        "ai-scanner", 
        "/scan", 
        "POST", 
        scanRequest,
        { "Authorization": `Bearer ${req.headers.authorization?.replace('Bearer ', '')}` }
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/ai-scanner/scan/:scanId", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const response = await serviceProxy.proxyRequest(
        "ai-scanner", 
        `/scan/${req.params.scanId}`, 
        "GET"
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Data Integrity Microservice Endpoints
  app.post("/api/data-integrity/check", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const checkRequest = {
        asset_id: req.body.asset_id,
        data_source: req.body.data_source,
        check_type: req.body.check_type,
        dataset_path: req.body.dataset_path,
        baseline_path: req.body.baseline_path,
        schema_definition: req.body.schema_definition,
        privacy_requirements: req.body.privacy_requirements,
        correlation_id: req.correlationId
      };

      await logAction(req.user!.id, "data_integrity_check_started", "ai_assets", checkRequest.asset_id, checkRequest);

      const response = await serviceProxy.proxyRequest(
        "data-integrity", 
        "/check", 
        "POST", 
        checkRequest
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/data-integrity/check/:checkId", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const response = await serviceProxy.proxyRequest(
        "data-integrity", 
        `/check/${req.params.checkId}`, 
        "GET"
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Wiz Integration Microservice Endpoints
  app.post("/api/wiz-integration/integrate", requireRole(["ciso", "analyst"]), async (req: GatewayRequest, res, next) => {
    try {
      const integrationRequest = {
        asset_id: req.body.asset_id,
        integration_type: req.body.integration_type || "sync",
        cloud_provider: req.body.cloud_provider,
        resource_filters: req.body.resource_filters,
        sync_scope: req.body.sync_scope,
        correlation_id: req.correlationId
      };

      await logAction(req.user!.id, "wiz_integration_started", "integrations", undefined, integrationRequest);

      const response = await serviceProxy.proxyRequest(
        "wiz-integration", 
        "/integrate", 
        "POST", 
        integrationRequest
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Compliance Engine Microservice Endpoints
  app.post("/api/compliance/assess", requireRole(["ciso", "compliance_officer"]), async (req: GatewayRequest, res, next) => {
    try {
      const assessmentRequest = {
        asset_id: req.body.asset_id,
        framework: req.body.framework,
        assessment_type: req.body.assessment_type || "full",
        scope: req.body.scope,
        baseline_date: req.body.baseline_date,
        correlation_id: req.correlationId
      };

      await logAction(req.user!.id, "compliance_assessment_started", "ai_assets", assessmentRequest.asset_id, assessmentRequest);

      const response = await serviceProxy.proxyRequest(
        "compliance-engine", 
        "/assess", 
        "POST", 
        assessmentRequest
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/compliance/assessment/:assessmentId", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const response = await serviceProxy.proxyRequest(
        "compliance-engine", 
        `/assessment/${req.params.assessmentId}`, 
        "GET"
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/compliance/frameworks", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const response = await serviceProxy.proxyRequest(
        "compliance-engine", 
        "/frameworks", 
        "GET"
      );

      const result = await response.json();
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Microservices Health Check Endpoint
  app.get("/api/microservices/health", requireAuth, async (req: GatewayRequest, res, next) => {
    try {
      const healthStatus = serviceRegistry.getHealthStatus();
      
      res.json({
        gateway_status: "healthy",
        services: healthStatus,
        timestamp: new Date().toISOString(),
        total_services: Object.keys(healthStatus).length,
        healthy_services: Object.values(healthStatus).filter(status => status).length
      });
    } catch (error) {
      next(error);
    }
  });

  // Sync only assets from Wiz
  app.post("/api/integrations/wiz/sync-assets", requireRole(["ciso", "analyst", "engineer"]), async (req, res, next) => {
    try {
      if (!wizIntegration) {
        return res.status(400).json({ 
          error: "Wiz integration not configured. Please set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables." 
        });
      }

      await logAction(req.user!.id, "wiz_asset_sync", "integration", undefined, req.body);

      const result = await wizIntegration.syncAssets(req.body);
      res.json({
        message: "Wiz asset sync completed successfully",
        result,
      });
    } catch (error) {
      next(error);
    }
  });

  // Sync only vulnerabilities from Wiz
  app.post("/api/integrations/wiz/sync-vulnerabilities", requireRole(["ciso", "analyst"]), async (req, res, next) => {
    try {
      if (!wizIntegration) {
        return res.status(400).json({ 
          error: "Wiz integration not configured. Please set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables." 
        });
      }

      await logAction(req.user!.id, "wiz_vulnerability_sync", "integration", undefined, req.body);

      const result = await wizIntegration.syncVulnerabilities(req.body);
      res.json({
        message: "Wiz vulnerability sync completed successfully",
        result,
      });
    } catch (error) {
      next(error);
    }
  });

  // Sync only security alerts from Wiz
  app.post("/api/integrations/wiz/sync-alerts", requireRole(["ciso", "analyst"]), async (req, res, next) => {
    try {
      if (!wizIntegration) {
        return res.status(400).json({ 
          error: "Wiz integration not configured. Please set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables." 
        });
      }

      await logAction(req.user!.id, "wiz_alert_sync", "integration", undefined, req.body);

      const result = await wizIntegration.syncSecurityAlerts(req.body);
      res.json({
        message: "Wiz security alert sync completed successfully",
        result,
      });
    } catch (error) {
      next(error);
    }
  });

  // Get Wiz integration status
  app.get("/api/integrations/wiz/status", requireAuth, async (req, res, next) => {
    try {
      const isConfigured = !!wizIntegration;
      const hasCredentials = !!(process.env.WIZ_CLIENT_ID && process.env.WIZ_CLIENT_SECRET);
      
      res.json({
        configured: isConfigured,
        hasCredentials,
        status: isConfigured ? "active" : "inactive",
        message: isConfigured 
          ? "Wiz integration is configured and ready" 
          : "Wiz integration requires WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables"
      });
    } catch (error) {
      next(error);
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
