/**
 * Wiz Security Platform Integration
 * 
 * This module provides integration with Wiz cloud security platform to import
 * security findings, assets, and compliance data into the AI-SPM platform.
 * 
 * Wiz API Documentation: https://docs.wiz.io/wiz-docs/docs/api-reference
 */

import { storage } from "../storage";
import type { 
  InsertAiAsset, 
  InsertVulnerability, 
  InsertSecurityAlert,
  InsertComplianceAssessment 
} from "@shared/schema";

// Wiz API Configuration
const WIZ_API_BASE_URL = "https://api.app.wiz.io/graphql";

// Wiz API Types
interface WizAuthResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface WizAsset {
  id: string;
  name: string;
  type: string;
  cloudPlatform: string;
  subscriptionId: string;
  resourceGroup?: string;
  region: string;
  tags: Record<string, string>;
  status: string;
  riskFactors: string[];
  lastScanTime: string;
}

interface WizVulnerability {
  id: string;
  name: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  status: "OPEN" | "IN_PROGRESS" | "RESOLVED" | "RISK_ACCEPTED";
  firstDetected: string;
  lastDetected: string;
  affectedAssets: string[];
  cve?: string;
  cvssScore?: number;
  remediation?: string;
}

interface WizSecurityAlert {
  id: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "OPEN" | "IN_PROGRESS" | "RESOLVED";
  createdAt: string;
  updatedAt: string;
  affectedResources: string[];
  detectionMethod: string;
}

interface WizComplianceFindings {
  frameworkId: string;
  frameworkName: string;
  controlId: string;
  controlName: string;
  status: "PASS" | "FAIL" | "NOT_APPLICABLE";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  lastAssessed: string;
  affectedResources: string[];
}

/**
 * Wiz API Client for interacting with Wiz cloud security platform
 */
export class WizClient {
  private accessToken?: string;
  private tokenExpiry?: Date;

  constructor(
    private clientId: string,
    private clientSecret: string,
    private audience: string = "beyond-api"
  ) {}

  /**
   * Authenticate with Wiz API using OAuth2 client credentials flow
   */
  private async authenticate(): Promise<string> {
    try {
      const authUrl = "https://auth.app.wiz.io/oauth/token";
      
      const response = await fetch(authUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: this.clientId,
          client_secret: this.clientSecret,
          audience: this.audience,
        }),
      });

      if (!response.ok) {
        throw new Error(`Wiz authentication failed: ${response.statusText}`);
      }

      const authData: WizAuthResponse = await response.json();
      this.accessToken = authData.access_token;
      this.tokenExpiry = new Date(Date.now() + authData.expires_in * 1000);

      return this.accessToken;
    } catch (error) {
      console.error("Wiz authentication error:", error);
      throw new Error("Failed to authenticate with Wiz API");
    }
  }

  /**
   * Get valid access token, refreshing if necessary
   */
  private async getAccessToken(): Promise<string> {
    if (!this.accessToken || !this.tokenExpiry || this.tokenExpiry <= new Date()) {
      await this.authenticate();
    }
    return this.accessToken!;
  }

  /**
   * Execute GraphQL query against Wiz API
   */
  private async executeQuery<T>(query: string, variables?: Record<string, any>): Promise<T> {
    const token = await this.getAccessToken();

    const response = await fetch(WIZ_API_BASE_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query,
        variables,
      }),
    });

    if (!response.ok) {
      throw new Error(`Wiz API request failed: ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.errors) {
      throw new Error(`Wiz GraphQL errors: ${JSON.stringify(result.errors)}`);
    }

    return result.data;
  }

  /**
   * Fetch cloud assets from Wiz
   */
  async fetchAssets(filters?: {
    cloudPlatform?: string;
    subscriptionId?: string;
    resourceGroup?: string;
    limit?: number;
  }): Promise<WizAsset[]> {
    const query = `
      query GetCloudResources($first: Int, $filterBy: CloudResourceFilters) {
        cloudResources(first: $first, filterBy: $filterBy) {
          nodes {
            id
            name
            type
            cloudPlatform
            subscriptionId
            resourceGroup
            region
            tags
            status
            riskFactors
            lastScanTime
          }
        }
      }
    `;

    const variables = {
      first: filters?.limit || 100,
      filterBy: {
        cloudPlatform: filters?.cloudPlatform ? [filters.cloudPlatform] : undefined,
        subscriptionId: filters?.subscriptionId ? [filters.subscriptionId] : undefined,
        resourceGroup: filters?.resourceGroup ? [filters.resourceGroup] : undefined,
      },
    };

    const result = await this.executeQuery<{ cloudResources: { nodes: WizAsset[] } }>(
      query,
      variables
    );

    return result.cloudResources.nodes;
  }

  /**
   * Fetch vulnerabilities from Wiz
   */
  async fetchVulnerabilities(filters?: {
    severity?: string[];
    status?: string[];
    limit?: number;
  }): Promise<WizVulnerability[]> {
    const query = `
      query GetVulnerabilities($first: Int, $filterBy: VulnerabilityFilters) {
        vulnerabilities(first: $first, filterBy: $filterBy) {
          nodes {
            id
            name
            description
            severity
            status
            firstDetected
            lastDetected
            affectedAssets {
              id
            }
            cve
            cvssScore
            remediation
          }
        }
      }
    `;

    const variables = {
      first: filters?.limit || 100,
      filterBy: {
        severity: filters?.severity,
        status: filters?.status,
      },
    };

    const result = await this.executeQuery<{ vulnerabilities: { nodes: WizVulnerability[] } }>(
      query,
      variables
    );

    return result.vulnerabilities.nodes;
  }

  /**
   * Fetch security alerts from Wiz
   */
  async fetchSecurityAlerts(filters?: {
    severity?: string[];
    status?: string[];
    limit?: number;
  }): Promise<WizSecurityAlert[]> {
    const query = `
      query GetSecurityAlerts($first: Int, $filterBy: SecurityAlertFilters) {
        securityAlerts(first: $first, filterBy: $filterBy) {
          nodes {
            id
            title
            description
            severity
            status
            createdAt
            updatedAt
            affectedResources {
              id
            }
            detectionMethod
          }
        }
      }
    `;

    const variables = {
      first: filters?.limit || 100,
      filterBy: {
        severity: filters?.severity,
        status: filters?.status,
      },
    };

    const result = await this.executeQuery<{ securityAlerts: { nodes: WizSecurityAlert[] } }>(
      query,
      variables
    );

    return result.securityAlerts.nodes;
  }

  /**
   * Fetch compliance findings from Wiz
   */
  async fetchComplianceFindings(frameworkIds?: string[]): Promise<WizComplianceFindings[]> {
    const query = `
      query GetComplianceFindings($frameworkIds: [String!]) {
        complianceFindings(frameworkIds: $frameworkIds) {
          frameworkId
          frameworkName
          controlId
          controlName
          status
          severity
          lastAssessed
          affectedResources {
            id
          }
        }
      }
    `;

    const variables = { frameworkIds };

    const result = await this.executeQuery<{ complianceFindings: WizComplianceFindings[] }>(
      query,
      variables
    );

    return result.complianceFindings;
  }
}

/**
 * Wiz Data Sync Service for importing data into AI-SPM platform
 */
export class WizDataSyncService {
  constructor(private wizClient: WizClient) {}

  /**
   * Transform Wiz asset to AI-SPM asset format
   */
  private transformWizAsset(wizAsset: WizAsset): InsertAiAsset {
    // Map Wiz asset types to AI-SPM types
    const typeMapping: Record<string, "model" | "dataset" | "api" | "pipeline"> = {
      "MachineLearningModel": "model",
      "Dataset": "dataset",
      "APIGateway": "api",
      "Pipeline": "pipeline",
      "Container": "model", // Default mapping for containers
      "Function": "api", // Default mapping for functions
    };

    // Map Wiz risk factors to risk levels
    const riskLevel = wizAsset.riskFactors.some(rf => 
      rf.includes("CRITICAL") || rf.includes("HIGH_RISK")
    ) ? "critical" : 
    wizAsset.riskFactors.some(rf => rf.includes("MEDIUM")) ? "medium" : "low";

    return {
      name: wizAsset.name,
      type: typeMapping[wizAsset.type] || "model",
      description: `Imported from Wiz: ${wizAsset.type} in ${wizAsset.cloudPlatform}`,
      environment: wizAsset.status === "RUNNING" ? "production" : "development",
      status: wizAsset.status === "RUNNING" ? "active" : "inactive",
      riskLevel,
      version: "1.0.0", // Default version
      framework: wizAsset.cloudPlatform,
      modelType: wizAsset.type,
      dataClassification: riskLevel === "critical" ? "restricted" : "internal",
      owner: "Wiz Import",
      contactEmail: "security@company.com", // Default contact
      location: `${wizAsset.cloudPlatform}/${wizAsset.region}`,
      tags: Object.entries(wizAsset.tags).map(([k, v]) => `${k}:${v}`),
      metadata: {
        wizId: wizAsset.id,
        cloudPlatform: wizAsset.cloudPlatform,
        subscriptionId: wizAsset.subscriptionId,
        resourceGroup: wizAsset.resourceGroup,
        region: wizAsset.region,
        riskFactors: wizAsset.riskFactors,
        lastScanTime: wizAsset.lastScanTime,
        source: "wiz",
        importedAt: new Date().toISOString(),
      },
    };
  }

  /**
   * Transform Wiz vulnerability to AI-SPM vulnerability format
   */
  private transformWizVulnerability(wizVuln: WizVulnerability, assetId?: number): InsertVulnerability {
    const severityMapping: Record<string, "critical" | "high" | "medium" | "low"> = {
      "CRITICAL": "critical",
      "HIGH": "high",
      "MEDIUM": "medium",
      "LOW": "low",
      "INFORMATIONAL": "low",
    };

    const statusMapping: Record<string, "open" | "in_progress" | "resolved" | "false_positive"> = {
      "OPEN": "open",
      "IN_PROGRESS": "in_progress",
      "RESOLVED": "resolved",
      "RISK_ACCEPTED": "false_positive",
    };

    return {
      assetId: assetId || 1, // Default to first asset if no mapping found
      title: wizVuln.name,
      description: `${wizVuln.description}\n\nCVE: ${wizVuln.cve || "N/A"}\nCVSS Score: ${wizVuln.cvssScore || "N/A"}`,
      category: "Security Vulnerability", // Required field
      severity: severityMapping[wizVuln.severity] || "medium",
      status: statusMapping[wizVuln.status] || "open",
      assignedTo: 1, // Default to first user
      cveId: wizVuln.cve || null,
      metadata: {
        wizId: wizVuln.id,
        cve: wizVuln.cve,
        cvssScore: wizVuln.cvssScore,
        remediation: wizVuln.remediation,
        firstDetected: wizVuln.firstDetected,
        lastDetected: wizVuln.lastDetected,
        affectedAssets: wizVuln.affectedAssets,
        source: "wiz",
        importedAt: new Date().toISOString(),
      },
    };
  }

  /**
   * Transform Wiz security alert to AI-SPM security alert format
   */
  private transformWizSecurityAlert(wizAlert: WizSecurityAlert): InsertSecurityAlert {
    const severityMapping: Record<string, "critical" | "high" | "medium" | "low"> = {
      "CRITICAL": "critical",
      "HIGH": "high",
      "MEDIUM": "medium",
      "LOW": "low",
    };

    const statusMapping: Record<string, "open" | "investigating" | "resolved" | "false_positive"> = {
      "OPEN": "open",
      "IN_PROGRESS": "investigating",
      "RESOLVED": "resolved",
    };

    return {
      title: wizAlert.title,
      description: wizAlert.description,
      type: "Security Alert", // Required field
      severity: severityMapping[wizAlert.severity] || "medium",
      status: statusMapping[wizAlert.status] || "open",
      source: "wiz",
      metadata: {
        wizId: wizAlert.id,
        detectionMethod: wizAlert.detectionMethod,
        affectedResources: wizAlert.affectedResources,
        createdAt: wizAlert.createdAt,
        updatedAt: wizAlert.updatedAt,
        source: "wiz",
        importedAt: new Date().toISOString(),
      },
    };
  }

  /**
   * Sync assets from Wiz to AI-SPM platform
   */
  async syncAssets(filters?: Parameters<WizClient['fetchAssets']>[0]): Promise<{ 
    imported: number; 
    updated: number; 
    errors: string[] 
  }> {
    const result = { imported: 0, updated: 0, errors: [] as string[] };

    try {
      const wizAssets = await this.wizClient.fetchAssets(filters);

      for (const wizAsset of wizAssets) {
        try {
          // Check if asset already exists by Wiz ID
          const existingAssets = await storage.getAllAiAssets({
            search: wizAsset.id,
          });

          const existingAsset = existingAssets.find(asset => 
            asset.metadata && 
            typeof asset.metadata === 'object' && 
            'wizId' in asset.metadata && 
            asset.metadata.wizId === wizAsset.id
          );

          const transformedAsset = this.transformWizAsset(wizAsset);

          if (existingAsset) {
            // Update existing asset
            await storage.updateAiAsset(existingAsset.id, transformedAsset);
            result.updated++;
          } else {
            // Create new asset
            await storage.createAiAsset(transformedAsset);
            result.imported++;
          }
        } catch (error) {
          result.errors.push(`Failed to sync asset ${wizAsset.id}: ${error}`);
        }
      }
    } catch (error) {
      result.errors.push(`Failed to fetch assets from Wiz: ${error}`);
    }

    return result;
  }

  /**
   * Sync vulnerabilities from Wiz to AI-SPM platform
   */
  async syncVulnerabilities(filters?: Parameters<WizClient['fetchVulnerabilities']>[0]): Promise<{
    imported: number;
    updated: number;
    errors: string[];
  }> {
    const result = { imported: 0, updated: 0, errors: [] as string[] };

    try {
      const wizVulns = await this.wizClient.fetchVulnerabilities(filters);

      for (const wizVuln of wizVulns) {
        try {
          // Find corresponding AI-SPM asset by Wiz asset ID
          let assetId = 1; // Default fallback
          
          if (wizVuln.affectedAssets.length > 0) {
            const assets = await storage.getAllAiAssets();
            const matchingAsset = assets.find(asset => 
              asset.metadata && 
              typeof asset.metadata === 'object' && 
              'wizId' in asset.metadata && 
              wizVuln.affectedAssets.includes(asset.metadata.wizId as string)
            );
            
            if (matchingAsset) {
              assetId = matchingAsset.id;
            }
          }

          const transformedVuln = this.transformWizVulnerability(wizVuln, assetId);

          // Check if vulnerability already exists
          const existingVulns = await storage.getAllVulnerabilities();
          const existingVuln = existingVulns.find(vuln => 
            vuln.metadata && 
            typeof vuln.metadata === 'object' && 
            'wizId' in vuln.metadata && 
            vuln.metadata.wizId === wizVuln.id
          );

          if (existingVuln) {
            await storage.updateVulnerability(existingVuln.id, transformedVuln);
            result.updated++;
          } else {
            await storage.createVulnerability(transformedVuln);
            result.imported++;
          }
        } catch (error) {
          result.errors.push(`Failed to sync vulnerability ${wizVuln.id}: ${error}`);
        }
      }
    } catch (error) {
      result.errors.push(`Failed to fetch vulnerabilities from Wiz: ${error}`);
    }

    return result;
  }

  /**
   * Sync security alerts from Wiz to AI-SPM platform
   */
  async syncSecurityAlerts(filters?: Parameters<WizClient['fetchSecurityAlerts']>[0]): Promise<{
    imported: number;
    updated: number;
    errors: string[];
  }> {
    const result = { imported: 0, updated: 0, errors: [] as string[] };

    try {
      const wizAlerts = await this.wizClient.fetchSecurityAlerts(filters);

      for (const wizAlert of wizAlerts) {
        try {
          const transformedAlert = this.transformWizSecurityAlert(wizAlert);

          // Check if alert already exists
          const existingAlerts = await storage.getAllSecurityAlerts();
          const existingAlert = existingAlerts.find(alert => 
            alert.metadata && 
            typeof alert.metadata === 'object' && 
            'wizId' in alert.metadata && 
            alert.metadata.wizId === wizAlert.id
          );

          if (existingAlert) {
            await storage.updateSecurityAlert(existingAlert.id, transformedAlert);
            result.updated++;
          } else {
            await storage.createSecurityAlert(transformedAlert);
            result.imported++;
          }
        } catch (error) {
          result.errors.push(`Failed to sync alert ${wizAlert.id}: ${error}`);
        }
      }
    } catch (error) {
      result.errors.push(`Failed to fetch alerts from Wiz: ${error}`);
    }

    return result;
  }

  /**
   * Full sync from Wiz - imports assets, vulnerabilities, and alerts
   */
  async fullSync(options?: {
    assetFilters?: Parameters<WizClient['fetchAssets']>[0];
    vulnFilters?: Parameters<WizClient['fetchVulnerabilities']>[0];
    alertFilters?: Parameters<WizClient['fetchSecurityAlerts']>[0];
  }): Promise<{
    assets: { imported: number; updated: number; errors: string[] };
    vulnerabilities: { imported: number; updated: number; errors: string[] };
    alerts: { imported: number; updated: number; errors: string[] };
    totalErrors: number;
  }> {
    console.log("Starting full Wiz data sync...");

    const [assets, vulnerabilities, alerts] = await Promise.all([
      this.syncAssets(options?.assetFilters),
      this.syncVulnerabilities(options?.vulnFilters),
      this.syncSecurityAlerts(options?.alertFilters),
    ]);

    const totalErrors = assets.errors.length + vulnerabilities.errors.length + alerts.errors.length;

    console.log(`Wiz sync completed:
      Assets: ${assets.imported} imported, ${assets.updated} updated
      Vulnerabilities: ${vulnerabilities.imported} imported, ${vulnerabilities.updated} updated  
      Alerts: ${alerts.imported} imported, ${alerts.updated} updated
      Total errors: ${totalErrors}`);

    return {
      assets,
      vulnerabilities,
      alerts,
      totalErrors,
    };
  }
}

/**
 * Initialize Wiz integration with environment variables
 */
export function createWizIntegration(): WizDataSyncService | null {
  const clientId = process.env.WIZ_CLIENT_ID;
  const clientSecret = process.env.WIZ_CLIENT_SECRET;
  const audience = process.env.WIZ_AUDIENCE || "beyond-api";

  if (!clientId || !clientSecret) {
    console.warn("Wiz integration disabled: WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables required");
    return null;
  }

  const wizClient = new WizClient(clientId, clientSecret, audience);
  return new WizDataSyncService(wizClient);
}