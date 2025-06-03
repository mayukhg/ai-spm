// Common types used across the application

export interface DashboardMetrics {
  totalAssets: number;
  criticalVulnerabilities: number;
  activeThreats: number;
  complianceScore: number;
}

export interface VulnerabilityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ComplianceOverview {
  frameworkId: number;
  frameworkName: string;
  averageScore: number;
  totalAssessments: number;
}

export interface FilterOptions {
  type?: string;
  environment?: string;
  riskLevel?: string;
  severity?: string;
  status?: string;
  search?: string;
}

export interface TableColumn {
  key: string;
  title: string;
  sortable?: boolean;
  render?: (value: any, record: any) => React.ReactNode;
}

export interface ActionButton {
  label: string;
  icon?: string;
  onClick: () => void;
  variant?: "primary" | "secondary" | "danger";
  disabled?: boolean;
}

// Role-based permissions
export type UserRole = "ciso" | "analyst" | "engineer" | "compliance_officer" | "admin";

export interface RolePermissions {
  canCreateAssets: boolean;
  canDeleteAssets: boolean;
  canManageUsers: boolean;
  canViewAudits: boolean;
  canManagePolicies: boolean;
  canCreateReports: boolean;
}

// Chart data types for dashboard
export interface ChartDataPoint {
  name: string;
  value: number;
  timestamp?: string;
  category?: string;
}

export interface TimeSeriesData {
  timestamp: string;
  securityScore: number;
  vulnerabilities: number;
  threats: number;
  compliance: number;
}

// Alert types for real-time notifications
export interface AlertNotification {
  id: string;
  type: "success" | "warning" | "error" | "info";
  title: string;
  message: string;
  timestamp: Date;
  action?: {
    label: string;
    href: string;
  };
}

// Asset discovery and scanning
export interface ScanResult {
  assetId: number;
  status: "pending" | "running" | "completed" | "failed";
  startedAt: Date;
  completedAt?: Date;
  findings: {
    vulnerabilities: number;
    misconfigurations: number;
    complianceIssues: number;
  };
  metadata?: Record<string, any>;
}

// MLOps integration types
export interface MLOpsIntegration {
  id: string;
  name: string;
  type: "azure_ml" | "kubeflow" | "mlflow" | "sagemaker" | "vertex_ai";
  status: "connected" | "disconnected" | "error";
  lastSync: Date;
  config: Record<string, any>;
}

// Governance policy template
export interface PolicyTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  template: Record<string, any>;
  variables: {
    name: string;
    type: "string" | "number" | "boolean" | "select";
    required: boolean;
    options?: string[];
    defaultValue?: any;
  }[];
}

// Compliance framework mappings
export interface ComplianceMapping {
  frameworkId: number;
  controlId: string;
  controlName: string;
  requirements: string[];
  assessmentCriteria: string[];
  automatedCheck?: boolean;
}

// Report generation types
export interface ReportConfig {
  type: "security_posture" | "compliance" | "vulnerability" | "audit";
  format: "pdf" | "excel" | "json";
  dateRange: {
    from: Date;
    to: Date;
  };
  filters: Record<string, any>;
  recipients?: string[];
  schedule?: {
    frequency: "daily" | "weekly" | "monthly";
    dayOfWeek?: number;
    dayOfMonth?: number;
    time: string;
  };
}

// API response wrapper
export interface ApiResponse<T> {
  data: T;
  message?: string;
  meta?: {
    total?: number;
    page?: number;
    limit?: number;
  };
}

// Error handling types
export interface ApiError {
  error: string;
  details?: any;
  code?: string;
  timestamp?: string;
}

// Theme and UI preferences
export interface UserPreferences {
  theme: "light" | "dark" | "system";
  language: string;
  timezone: string;
  dashboardLayout: "compact" | "default" | "detailed";
  notifications: {
    email: boolean;
    browser: boolean;
    security: boolean;
    compliance: boolean;
  };
}
