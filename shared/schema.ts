import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar, uuid, decimal } from "drizzle-orm/pg-core";
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

// Compliance policies for specific frameworks
export const compliancePolicies = pgTable("compliance_policies", {
  id: serial("id").primaryKey(),
  frameworkId: integer("framework_id").references(() => complianceFrameworks.id).notNull(),
  controlId: text("control_id").notNull(), // e.g., "AI-1.1", "GDPR-32"
  controlName: text("control_name").notNull(),
  description: text("description").notNull(),
  requirements: jsonb("requirements").notNull(), // detailed requirements
  implementationGuidance: text("implementation_guidance"),
  evidenceRequirements: jsonb("evidence_requirements"), // types of evidence needed
  complianceLevel: text("compliance_level").notNull().default("mandatory"), // mandatory, recommended, optional
  category: text("category"), // governance, risk_management, security, etc.
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
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

// Data Quality Monitoring - tracks dataset quality metrics and validation results
export const dataQualityMetrics = pgTable("data_quality_metrics", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  datasetName: text("dataset_name").notNull(),
  datasetVersion: text("dataset_version"),
  metricType: text("metric_type").notNull(), // completeness, accuracy, consistency, validity, uniqueness, freshness
  metricValue: decimal("metric_value", { precision: 10, scale: 4 }).notNull(),
  threshold: decimal("threshold", { precision: 10, scale: 4 }).notNull(),
  status: text("status").notNull().default("normal"), // normal, warning, critical
  details: jsonb("details"), // specific metric details and context
  collectedAt: timestamp("collected_at").defaultNow().notNull(),
  environment: text("environment").notNull(), // training, inference, validation
});

// Data Drift Detection - monitors distribution changes over time
export const dataDriftMetrics = pgTable("data_drift_metrics", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  datasetName: text("dataset_name").notNull(),
  referenceDatasetId: text("reference_dataset_id").notNull(), // baseline dataset identifier
  currentDatasetId: text("current_dataset_id").notNull(), // current dataset identifier
  driftType: text("drift_type").notNull(), // feature_drift, prediction_drift, label_drift
  driftScore: decimal("drift_score", { precision: 10, scale: 6 }).notNull(),
  threshold: decimal("threshold", { precision: 10, scale: 6 }).notNull(),
  status: text("status").notNull().default("stable"), // stable, drifting, significant_drift
  affectedFeatures: jsonb("affected_features"), // list of features showing drift
  detectionMethod: text("detection_method").notNull(), // kolmogorov_smirnov, chi_square, psi, wasserstein
  statisticalTest: jsonb("statistical_test"), // test results and p-values
  recommendations: text("recommendations"),
  detectedAt: timestamp("detected_at").defaultNow().notNull(),
  environment: text("environment").notNull(),
});

// Data Anomaly Detection - identifies unusual patterns and outliers
export const dataAnomalyDetections = pgTable("data_anomaly_detections", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  datasetName: text("dataset_name").notNull(),
  anomalyType: text("anomaly_type").notNull(), // outlier, pattern_anomaly, temporal_anomaly, schema_anomaly
  severity: text("severity").notNull(), // low, medium, high, critical
  confidence: decimal("confidence", { precision: 5, scale: 4 }).notNull(), // 0.0 to 1.0
  description: text("description").notNull(),
  affectedRecords: integer("affected_records").notNull(),
  totalRecords: integer("total_records").notNull(),
  detectionMethod: text("detection_method").notNull(), // isolation_forest, local_outlier_factor, dbscan, statistical
  anomalyScore: decimal("anomaly_score", { precision: 10, scale: 6 }).notNull(),
  threshold: decimal("threshold", { precision: 10, scale: 6 }).notNull(),
  features: jsonb("features"), // affected features and their values
  context: jsonb("context"), // additional context about the anomaly
  status: text("status").notNull().default("detected"), // detected, investigating, resolved, false_positive
  detectedAt: timestamp("detected_at").defaultNow().notNull(),
  resolvedAt: timestamp("resolved_at"),
  environment: text("environment").notNull(),
});

// Data Integrity Alerts - critical issues that require immediate attention
export const dataIntegrityAlerts = pgTable("data_integrity_alerts", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  alertType: text("alert_type").notNull(), // data_corruption, schema_violation, missing_data, duplicate_data
  severity: text("severity").notNull(), // critical, high, medium, low
  title: text("title").notNull(),
  description: text("description").notNull(),
  impact: text("impact").notNull(), // model_performance, data_accuracy, system_availability
  datasetName: text("dataset_name").notNull(),
  affectedRecords: integer("affected_records"),
  totalRecords: integer("total_records"),
  detectionSource: text("detection_source").notNull(), // quality_check, drift_detection, anomaly_detection
  sourceId: integer("source_id"), // reference to the source detection record
  status: text("status").notNull().default("active"), // active, investigating, resolved, suppressed
  priority: text("priority").notNull().default("medium"), // urgent, high, medium, low
  assignedTo: integer("assigned_to").references(() => users.id),
  acknowledgedAt: timestamp("acknowledged_at"),
  resolvedAt: timestamp("resolved_at"),
  metadata: jsonb("metadata"), // additional alert context
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Data Validation Rules - configurable validation rules for datasets
export const dataValidationRules = pgTable("data_validation_rules", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  ruleName: text("rule_name").notNull(),
  ruleType: text("rule_type").notNull(), // schema_validation, range_check, format_validation, uniqueness_check
  fieldName: text("field_name"), // specific field/column name
  validationConfig: jsonb("validation_config").notNull(), // rule-specific configuration
  isActive: boolean("is_active").notNull().default(true),
  severity: text("severity").notNull().default("medium"), // critical, high, medium, low
  description: text("description"),
  createdBy: integer("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Data Quality Baselines - reference metrics for comparison
export const dataQualityBaselines = pgTable("data_quality_baselines", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => aiAssets.id).notNull(),
  datasetName: text("dataset_name").notNull(),
  baselineType: text("baseline_type").notNull(), // initial, periodic, golden_standard
  metricType: text("metric_type").notNull(),
  baselineValue: decimal("baseline_value", { precision: 10, scale: 4 }).notNull(),
  confidenceInterval: jsonb("confidence_interval"), // upper and lower bounds
  sampleSize: integer("sample_size").notNull(),
  validFrom: timestamp("valid_from").defaultNow().notNull(),
  validUntil: timestamp("valid_until"),
  isActive: boolean("is_active").notNull().default(true),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Define additional relations for data quality tables
export const dataQualityMetricsRelations = relations(dataQualityMetrics, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [dataQualityMetrics.assetId],
    references: [aiAssets.id],
  }),
}));

export const dataDriftMetricsRelations = relations(dataDriftMetrics, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [dataDriftMetrics.assetId],
    references: [aiAssets.id],
  }),
}));

export const dataAnomalyDetectionsRelations = relations(dataAnomalyDetections, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [dataAnomalyDetections.assetId],
    references: [aiAssets.id],
  }),
}));

export const dataIntegrityAlertsRelations = relations(dataIntegrityAlerts, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [dataIntegrityAlerts.assetId],
    references: [aiAssets.id],
  }),
  assignee: one(users, {
    fields: [dataIntegrityAlerts.assignedTo],
    references: [users.id],
  }),
}));

export const dataValidationRulesRelations = relations(dataValidationRules, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [dataValidationRules.assetId],
    references: [aiAssets.id],
  }),
  creator: one(users, {
    fields: [dataValidationRules.createdBy],
    references: [users.id],
  }),
}));

export const dataQualityBaselinesRelations = relations(dataQualityBaselines, ({ one }) => ({
  asset: one(aiAssets, {
    fields: [dataQualityBaselines.assetId],
    references: [aiAssets.id],
  }),
}));

// Insert schemas for data quality tables
export const insertDataQualityMetricSchema = createInsertSchema(dataQualityMetrics).omit({
  id: true,
  collectedAt: true,
});

export const insertDataDriftMetricSchema = createInsertSchema(dataDriftMetrics).omit({
  id: true,
  detectedAt: true,
});

export const insertDataAnomalyDetectionSchema = createInsertSchema(dataAnomalyDetections).omit({
  id: true,
  detectedAt: true,
});

export const insertDataIntegrityAlertSchema = createInsertSchema(dataIntegrityAlerts).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertDataValidationRuleSchema = createInsertSchema(dataValidationRules).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertDataQualityBaselineSchema = createInsertSchema(dataQualityBaselines).omit({
  id: true,
  createdAt: true,
});

// Types for data quality entities
export type DataQualityMetric = typeof dataQualityMetrics.$inferSelect;
export type InsertDataQualityMetric = z.infer<typeof insertDataQualityMetricSchema>;

export type DataDriftMetric = typeof dataDriftMetrics.$inferSelect;
export type InsertDataDriftMetric = z.infer<typeof insertDataDriftMetricSchema>;

export type DataAnomalyDetection = typeof dataAnomalyDetections.$inferSelect;
export type InsertDataAnomalyDetection = z.infer<typeof insertDataAnomalyDetectionSchema>;

export type DataIntegrityAlert = typeof dataIntegrityAlerts.$inferSelect;
export type InsertDataIntegrityAlert = z.infer<typeof insertDataIntegrityAlertSchema>;

export type DataValidationRule = typeof dataValidationRules.$inferSelect;
export type InsertDataValidationRule = z.infer<typeof insertDataValidationRuleSchema>;

export type DataQualityBaseline = typeof dataQualityBaselines.$inferSelect;
export type InsertDataQualityBaseline = z.infer<typeof insertDataQualityBaselineSchema>;

// Additional types for API responses
export type VulnerabilityStats = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};

export type DataQualityStats = {
  totalMetrics: number;
  qualityScore: number;
  driftDetections: number;
  anomalyDetections: number;
  activeAlerts: number;
  trends: {
    qualityTrend: 'improving' | 'stable' | 'degrading';
    driftTrend: 'stable' | 'increasing' | 'decreasing';
  };
};
