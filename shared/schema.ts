import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Users table for authentication and role management
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  role: text("role").notNull().default("analyst"), // ciso, analyst, engineer, compliance_officer
  fullName: text("full_name").notNull(),
  department: text("department"),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// AI Assets - models, datasets, APIs, etc.
export const aiAssets = pgTable("ai_assets", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  type: text("type").notNull(), // model, dataset, api, pipeline
  description: text("description"),
  environment: text("environment").notNull(), // production, staging, development
  status: text("status").notNull().default("active"), // active, inactive, deprecated
  riskLevel: text("risk_level").notNull().default("medium"), // critical, high, medium, low
  version: text("version"),
  framework: text("framework"), // tensorflow, pytorch, huggingface, etc.
  modelType: text("model_type"), // llm, classification, regression, etc.
  dataClassification: text("data_classification"), // public, internal, confidential, restricted
  owner: text("owner").notNull(),
  contactEmail: text("contact_email"),
  location: text("location"), // cloud region, on-premise location
  tags: jsonb("tags"), // flexible tagging system
  metadata: jsonb("metadata"), // additional asset-specific data
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  lastScannedAt: timestamp("last_scanned_at"),
});

// Vulnerabilities detected in AI assets
export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(), // critical, high, medium, low
  category: text("category").notNull(), // model_security, data_privacy, infrastructure, etc.
  cveId: text("cve_id"), // if applicable
  status: text("status").notNull().default("open"), // open, investigating, resolved, false_positive
  detectionMethod: text("detection_method"), // automated_scan, manual_review, threat_intel
  impact: text("impact"),
  recommendation: text("recommendation"),
  assignedTo: integer("assigned_to").references(() => users.id),
  detectedAt: timestamp("detected_at").defaultNow().notNull(),
  resolvedAt: timestamp("resolved_at"),
  metadata: jsonb("metadata"),
});

// Security alerts and threat detections
export const securityAlerts = pgTable("security_alerts", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id),
  type: text("type").notNull(), // prompt_injection, data_poisoning, model_theft, etc.
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  status: text("status").notNull().default("active"), // active, investigating, resolved
  source: text("source"), // runtime_monitor, threat_detection, user_report
  detectedAt: timestamp("detected_at").defaultNow().notNull(),
  resolvedAt: timestamp("resolved_at"),
  metadata: jsonb("metadata"),
});

// Compliance frameworks and assessments
export const complianceFrameworks = pgTable("compliance_frameworks", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  version: text("version"),
  description: text("description"),
  category: text("category"), // ai_specific, data_privacy, security
  isActive: boolean("is_active").notNull().default(true),
});

export const complianceAssessments = pgTable("compliance_assessments", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  frameworkId: integer("framework_id").references(() => complianceFrameworks.id).notNull(),
  score: integer("score").notNull(), // percentage score 0-100
  status: text("status").notNull(), // compliant, non_compliant, partially_compliant
  assessedAt: timestamp("assessed_at").defaultNow().notNull(),
  assessedBy: integer("assessed_by").references(() => users.id).notNull(),
  findings: jsonb("findings"),
  recommendations: text("recommendations"),
});

// Governance policies
export const governancePolicies = pgTable("governance_policies", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  category: text("category").notNull(), // data_governance, model_governance, security
  policy: jsonb("policy").notNull(), // policy rules and configurations
  isActive: boolean("is_active").notNull().default(true),
  createdBy: integer("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Audit logs
export const auditLogs = pgTable("audit_logs", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: integer("resource_id"),
  details: jsonb("details"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
});

// Define relations
export const usersRelations = relations(users, ({ many }) => ({
  vulnerabilities: many(vulnerabilities),
  assessments: many(complianceAssessments),
  policies: many(governancePolicies),
  auditLogs: many(auditLogs),
}));

export const aiAssetsRelations = relations(aiAssets, ({ many }) => ({
  vulnerabilities: many(vulnerabilities),
  alerts: many(securityAlerts),
  assessments: many(complianceAssessments),
}));

export const vulnerabilitiesRelations = relations(vulnerabilities, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [vulnerabilities.assetId],
    references: [aiAssets.id],
  }),
  assignee: one(users, {
    fields: [vulnerabilities.assignedTo],
    references: [users.id],
  }),
}));

export const securityAlertsRelations = relations(securityAlerts, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [securityAlerts.assetId],
    references: [aiAssets.id],
  }),
}));

export const complianceAssessmentsRelations = relations(complianceAssessments, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [complianceAssessments.assetId],
    references: [aiAssets.id],
  }),
  framework: one(complianceFrameworks, {
    fields: [complianceAssessments.frameworkId],
    references: [complianceFrameworks.id],
  }),
  assessor: one(users, {
    fields: [complianceAssessments.assessedBy],
    references: [users.id],
  }),
}));

export const governancePoliciesRelations = relations(governancePolicies, ({ one }) => ({
  creator: one(users, {
    fields: [governancePolicies.createdBy],
    references: [users.id],
  }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, {
    fields: [auditLogs.userId],
    references: [users.id],
  }),
}));

// Insert schemas
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  email: true,
  password: true,
  role: true,
  fullName: true,
  department: true,
});

export const insertAiAssetSchema = createInsertSchema(aiAssets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
  detectedAt: true,
});

export const insertSecurityAlertSchema = createInsertSchema(securityAlerts).omit({
  id: true,
  detectedAt: true,
});

export const insertComplianceFrameworkSchema = createInsertSchema(complianceFrameworks).omit({
  id: true,
});

export const insertComplianceAssessmentSchema = createInsertSchema(complianceAssessments).omit({
  id: true,
  assessedAt: true,
});

export const insertGovernancePolicySchema = createInsertSchema(governancePolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({
  id: true,
  timestamp: true,
});

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type AiAsset = typeof aiAssets.$inferSelect;
export type InsertAiAsset = z.infer<typeof insertAiAssetSchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type SecurityAlert = typeof securityAlerts.$inferSelect;
export type InsertSecurityAlert = z.infer<typeof insertSecurityAlertSchema>;
export type ComplianceFramework = typeof complianceFrameworks.$inferSelect;
export type InsertComplianceFramework = z.infer<typeof insertComplianceFrameworkSchema>;
export type ComplianceAssessment = typeof complianceAssessments.$inferSelect;
export type InsertComplianceAssessment = z.infer<typeof insertComplianceAssessmentSchema>;
export type GovernancePolicy = typeof governancePolicies.$inferSelect;
export type InsertGovernancePolicy = z.infer<typeof insertGovernancePolicySchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;

// Additional types for API responses
export type VulnerabilityStats = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};
