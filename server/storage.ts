import { 
  users, 
  aiAssets,
  vulnerabilities,
  securityAlerts,
  complianceFrameworks,
  complianceAssessments,
  governancePolicies,
  auditLogs,
  type User, 
  type InsertUser,
  type AiAsset,
  type InsertAiAsset,
  type Vulnerability,
  type InsertVulnerability,
  type SecurityAlert,
  type InsertSecurityAlert,
  type ComplianceFramework,
  type InsertComplianceFramework,
  type ComplianceAssessment,
  type InsertComplianceAssessment,
  type GovernancePolicy,
  type InsertGovernancePolicy,
  type AuditLog,
  type InsertAuditLog
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, or, like, count, sql } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { pool } from "./db";

const PostgresSessionStore = connectPg(session);

// Storage interface defining all CRUD operations
export interface IStorage {
  // User management
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, updates: Partial<User>): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;

  // AI Asset management
  getAiAsset(id: number): Promise<AiAsset | undefined>;
  getAllAiAssets(filters?: {
    type?: string;
    environment?: string;
    riskLevel?: string;
    search?: string;
  }): Promise<AiAsset[]>;
  createAiAsset(asset: InsertAiAsset): Promise<AiAsset>;
  updateAiAsset(id: number, updates: Partial<AiAsset>): Promise<AiAsset | undefined>;
  deleteAiAsset(id: number): Promise<boolean>;
  getAssetsByOwner(owner: string): Promise<AiAsset[]>;

  // Vulnerability management
  getVulnerability(id: number): Promise<Vulnerability | undefined>;
  getVulnerabilitiesByAsset(assetId: number): Promise<Vulnerability[]>;
  getAllVulnerabilities(filters?: {
    severity?: string;
    status?: string;
    assignedTo?: number;
  }): Promise<Vulnerability[]>;
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  updateVulnerability(id: number, updates: Partial<Vulnerability>): Promise<Vulnerability | undefined>;
  getVulnerabilityStats(): Promise<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  }>;

  // Security alerts
  getSecurityAlert(id: number): Promise<SecurityAlert | undefined>;
  getAllSecurityAlerts(limit?: number): Promise<SecurityAlert[]>;
  createSecurityAlert(alert: InsertSecurityAlert): Promise<SecurityAlert>;
  updateSecurityAlert(id: number, updates: Partial<SecurityAlert>): Promise<SecurityAlert | undefined>;
  getRecentAlerts(limit: number): Promise<SecurityAlert[]>;

  // Compliance management
  getComplianceFramework(id: number): Promise<ComplianceFramework | undefined>;
  getAllComplianceFrameworks(): Promise<ComplianceFramework[]>;
  createComplianceFramework(framework: InsertComplianceFramework): Promise<ComplianceFramework>;
  getComplianceAssessment(id: number): Promise<ComplianceAssessment | undefined>;
  getAssessmentsByAsset(assetId: number): Promise<ComplianceAssessment[]>;
  createComplianceAssessment(assessment: InsertComplianceAssessment): Promise<ComplianceAssessment>;
  getComplianceOverview(): Promise<{
    frameworkId: number;
    frameworkName: string;
    averageScore: number;
    totalAssessments: number;
  }[]>;

  // Governance policies
  getGovernancePolicy(id: number): Promise<GovernancePolicy | undefined>;
  getAllGovernancePolicies(): Promise<GovernancePolicy[]>;
  createGovernancePolicy(policy: InsertGovernancePolicy): Promise<GovernancePolicy>;
  updateGovernancePolicy(id: number, updates: Partial<GovernancePolicy>): Promise<GovernancePolicy | undefined>;

  // Audit logs
  createAuditLog(log: InsertAuditLog): Promise<AuditLog>;
  getAuditLogs(limit?: number): Promise<AuditLog[]>;

  // Dashboard metrics
  getDashboardMetrics(): Promise<{
    totalAssets: number;
    criticalVulnerabilities: number;
    activeThreats: number;
    complianceScore: number;
  }>;

  sessionStore: session.SessionStore;
}

// Database storage implementation
export class DatabaseStorage implements IStorage {
  sessionStore: session.SessionStore;

  constructor() {
    this.sessionStore = new PostgresSessionStore({ 
      pool, 
      createTableIfMissing: true 
    });
  }

  // User management
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async updateUser(id: number, updates: Partial<User>): Promise<User | undefined> {
    const [user] = await db
      .update(users)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user || undefined;
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users).orderBy(desc(users.createdAt));
  }

  // AI Asset management
  async getAiAsset(id: number): Promise<AiAsset | undefined> {
    const [asset] = await db.select().from(aiAssets).where(eq(aiAssets.id, id));
    return asset || undefined;
  }

  async getAllAiAssets(filters?: {
    type?: string;
    environment?: string;
    riskLevel?: string;
    search?: string;
  }): Promise<AiAsset[]> {
    let query = db.select().from(aiAssets);

    if (filters) {
      const conditions = [];
      
      if (filters.type) {
        conditions.push(eq(aiAssets.type, filters.type));
      }
      if (filters.environment) {
        conditions.push(eq(aiAssets.environment, filters.environment));
      }
      if (filters.riskLevel) {
        conditions.push(eq(aiAssets.riskLevel, filters.riskLevel));
      }
      if (filters.search) {
        conditions.push(
          or(
            like(aiAssets.name, `%${filters.search}%`),
            like(aiAssets.description, `%${filters.search}%`)
          )
        );
      }

      if (conditions.length > 0) {
        query = query.where(and(...conditions));
      }
    }

    return await query.orderBy(desc(aiAssets.updatedAt));
  }

  async createAiAsset(asset: InsertAiAsset): Promise<AiAsset> {
    const [newAsset] = await db
      .insert(aiAssets)
      .values(asset)
      .returning();
    return newAsset;
  }

  async updateAiAsset(id: number, updates: Partial<AiAsset>): Promise<AiAsset | undefined> {
    const [asset] = await db
      .update(aiAssets)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(aiAssets.id, id))
      .returning();
    return asset || undefined;
  }

  async deleteAiAsset(id: number): Promise<boolean> {
    const result = await db.delete(aiAssets).where(eq(aiAssets.id, id));
    return result.rowCount > 0;
  }

  async getAssetsByOwner(owner: string): Promise<AiAsset[]> {
    return await db.select().from(aiAssets).where(eq(aiAssets.owner, owner));
  }

  // Vulnerability management
  async getVulnerability(id: number): Promise<Vulnerability | undefined> {
    const [vulnerability] = await db.select().from(vulnerabilities).where(eq(vulnerabilities.id, id));
    return vulnerability || undefined;
  }

  async getVulnerabilitiesByAsset(assetId: number): Promise<Vulnerability[]> {
    return await db.select().from(vulnerabilities).where(eq(vulnerabilities.assetId, assetId));
  }

  async getAllVulnerabilities(filters?: {
    severity?: string;
    status?: string;
    assignedTo?: number;
  }): Promise<Vulnerability[]> {
    let query = db.select().from(vulnerabilities);

    if (filters) {
      const conditions = [];
      
      if (filters.severity) {
        conditions.push(eq(vulnerabilities.severity, filters.severity));
      }
      if (filters.status) {
        conditions.push(eq(vulnerabilities.status, filters.status));
      }
      if (filters.assignedTo) {
        conditions.push(eq(vulnerabilities.assignedTo, filters.assignedTo));
      }

      if (conditions.length > 0) {
        query = query.where(and(...conditions));
      }
    }

    return await query.orderBy(desc(vulnerabilities.detectedAt));
  }

  async createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability> {
    const [newVulnerability] = await db
      .insert(vulnerabilities)
      .values(vulnerability)
      .returning();
    return newVulnerability;
  }

  async updateVulnerability(id: number, updates: Partial<Vulnerability>): Promise<Vulnerability | undefined> {
    const [vulnerability] = await db
      .update(vulnerabilities)
      .set(updates)
      .where(eq(vulnerabilities.id, id))
      .returning();
    return vulnerability || undefined;
  }

  async getVulnerabilityStats(): Promise<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  }> {
    const stats = await db
      .select({
        severity: vulnerabilities.severity,
        count: count(vulnerabilities.id)
      })
      .from(vulnerabilities)
      .where(eq(vulnerabilities.status, 'open'))
      .groupBy(vulnerabilities.severity);

    const result = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    };

    stats.forEach(stat => {
      result[stat.severity as keyof typeof result] = stat.count;
      result.total += stat.count;
    });

    return result;
  }

  // Security alerts
  async getSecurityAlert(id: number): Promise<SecurityAlert | undefined> {
    const [alert] = await db.select().from(securityAlerts).where(eq(securityAlerts.id, id));
    return alert || undefined;
  }

  async getAllSecurityAlerts(limit?: number): Promise<SecurityAlert[]> {
    let query = db.select().from(securityAlerts).orderBy(desc(securityAlerts.detectedAt));
    
    if (limit) {
      query = query.limit(limit);
    }

    return await query;
  }

  async createSecurityAlert(alert: InsertSecurityAlert): Promise<SecurityAlert> {
    const [newAlert] = await db
      .insert(securityAlerts)
      .values(alert)
      .returning();
    return newAlert;
  }

  async updateSecurityAlert(id: number, updates: Partial<SecurityAlert>): Promise<SecurityAlert | undefined> {
    const [alert] = await db
      .update(securityAlerts)
      .set(updates)
      .where(eq(securityAlerts.id, id))
      .returning();
    return alert || undefined;
  }

  async getRecentAlerts(limit: number): Promise<SecurityAlert[]> {
    return await db
      .select()
      .from(securityAlerts)
      .where(eq(securityAlerts.status, 'active'))
      .orderBy(desc(securityAlerts.detectedAt))
      .limit(limit);
  }

  // Compliance management
  async getComplianceFramework(id: number): Promise<ComplianceFramework | undefined> {
    const [framework] = await db.select().from(complianceFrameworks).where(eq(complianceFrameworks.id, id));
    return framework || undefined;
  }

  async getAllComplianceFrameworks(): Promise<ComplianceFramework[]> {
    return await db.select().from(complianceFrameworks).where(eq(complianceFrameworks.isActive, true));
  }

  async createComplianceFramework(framework: InsertComplianceFramework): Promise<ComplianceFramework> {
    const [newFramework] = await db
      .insert(complianceFrameworks)
      .values(framework)
      .returning();
    return newFramework;
  }

  async getComplianceAssessment(id: number): Promise<ComplianceAssessment | undefined> {
    const [assessment] = await db.select().from(complianceAssessments).where(eq(complianceAssessments.id, id));
    return assessment || undefined;
  }

  async getAssessmentsByAsset(assetId: number): Promise<ComplianceAssessment[]> {
    return await db.select().from(complianceAssessments).where(eq(complianceAssessments.assetId, assetId));
  }

  async createComplianceAssessment(assessment: InsertComplianceAssessment): Promise<ComplianceAssessment> {
    const [newAssessment] = await db
      .insert(complianceAssessments)
      .values(assessment)
      .returning();
    return newAssessment;
  }

  async getComplianceOverview(): Promise<{
    frameworkId: number;
    frameworkName: string;
    averageScore: number;
    totalAssessments: number;
  }[]> {
    return await db
      .select({
        frameworkId: complianceFrameworks.id,
        frameworkName: complianceFrameworks.name,
        averageScore: sql<number>`AVG(${complianceAssessments.score})::integer`,
        totalAssessments: count(complianceAssessments.id)
      })
      .from(complianceFrameworks)
      .leftJoin(complianceAssessments, eq(complianceFrameworks.id, complianceAssessments.frameworkId))
      .where(eq(complianceFrameworks.isActive, true))
      .groupBy(complianceFrameworks.id, complianceFrameworks.name);
  }

  // Governance policies
  async getGovernancePolicy(id: number): Promise<GovernancePolicy | undefined> {
    const [policy] = await db.select().from(governancePolicies).where(eq(governancePolicies.id, id));
    return policy || undefined;
  }

  async getAllGovernancePolicies(): Promise<GovernancePolicy[]> {
    return await db.select().from(governancePolicies).where(eq(governancePolicies.isActive, true));
  }

  async createGovernancePolicy(policy: InsertGovernancePolicy): Promise<GovernancePolicy> {
    const [newPolicy] = await db
      .insert(governancePolicies)
      .values(policy)
      .returning();
    return newPolicy;
  }

  async updateGovernancePolicy(id: number, updates: Partial<GovernancePolicy>): Promise<GovernancePolicy | undefined> {
    const [policy] = await db
      .update(governancePolicies)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(governancePolicies.id, id))
      .returning();
    return policy || undefined;
  }

  // Audit logs
  async createAuditLog(log: InsertAuditLog): Promise<AuditLog> {
    const [newLog] = await db
      .insert(auditLogs)
      .values(log)
      .returning();
    return newLog;
  }

  async getAuditLogs(limit?: number): Promise<AuditLog[]> {
    let query = db.select().from(auditLogs).orderBy(desc(auditLogs.timestamp));
    
    if (limit) {
      query = query.limit(limit);
    }

    return await query;
  }

  // Dashboard metrics
  async getDashboardMetrics(): Promise<{
    totalAssets: number;
    criticalVulnerabilities: number;
    activeThreats: number;
    complianceScore: number;
  }> {
    // Get total assets
    const [assetCount] = await db
      .select({ count: count(aiAssets.id) })
      .from(aiAssets)
      .where(eq(aiAssets.status, 'active'));

    // Get critical vulnerabilities
    const [criticalVulnCount] = await db
      .select({ count: count(vulnerabilities.id) })
      .from(vulnerabilities)
      .where(and(
        eq(vulnerabilities.severity, 'critical'),
        eq(vulnerabilities.status, 'open')
      ));

    // Get active threats
    const [activeThreatsCount] = await db
      .select({ count: count(securityAlerts.id) })
      .from(securityAlerts)
      .where(eq(securityAlerts.status, 'active'));

    // Get average compliance score
    const [complianceAvg] = await db
      .select({ 
        avgScore: sql<number>`COALESCE(AVG(${complianceAssessments.score}), 0)::integer`
      })
      .from(complianceAssessments);

    return {
      totalAssets: assetCount.count,
      criticalVulnerabilities: criticalVulnCount.count,
      activeThreats: activeThreatsCount.count,
      complianceScore: complianceAvg.avgScore
    };
  }
}

export const storage = new DatabaseStorage();
