/**
 * Comprehensive Metrics Collection System
 * Real-time metrics for performance, security, and business intelligence
 */

import { register, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';
import { logger } from './logger';

// Enable default system metrics
collectDefaultMetrics();

class MetricsCollector {
  // HTTP Request Metrics
  public httpRequestsTotal = new Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code', 'user_role']
  });

  public httpRequestDuration = new Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status_code'],
    buckets: [0.1, 0.5, 1, 2, 5, 10]
  });

  // Authentication Metrics
  public authAttempts = new Counter({
    name: 'auth_attempts_total',
    help: 'Total authentication attempts',
    labelNames: ['method', 'result', 'user_type']
  });

  public activeSessions = new Gauge({
    name: 'active_sessions_total',
    help: 'Number of active user sessions'
  });

  public mfaAttempts = new Counter({
    name: 'mfa_attempts_total',
    help: 'Multi-factor authentication attempts',
    labelNames: ['method', 'result']
  });

  // Security Metrics
  public securityEvents = new Counter({
    name: 'security_events_total',
    help: 'Total security events detected',
    labelNames: ['event_type', 'severity', 'source']
  });

  public threatDetections = new Counter({
    name: 'ai_threats_detected_total',
    help: 'AI-specific threats detected',
    labelNames: ['threat_type', 'severity', 'model_id', 'response_action']
  });

  public complianceViolations = new Counter({
    name: 'compliance_violations_total',
    help: 'Compliance violations detected',
    labelNames: ['framework', 'violation_type', 'severity']
  });

  public vulnerabilityScans = new Counter({
    name: 'vulnerability_scans_total',
    help: 'Vulnerability scans performed',
    labelNames: ['scan_type', 'target_type', 'result']
  });

  // AI Asset Metrics
  public aiAssetsTotal = new Gauge({
    name: 'ai_assets_total',
    help: 'Total number of AI assets',
    labelNames: ['asset_type', 'environment', 'status']
  });

  public modelInferences = new Counter({
    name: 'model_inferences_total',
    help: 'Total model inference requests',
    labelNames: ['model_id', 'model_type', 'status']
  });

  public modelPerformance = new Histogram({
    name: 'model_inference_duration_seconds',
    help: 'Model inference duration',
    labelNames: ['model_id', 'model_type'],
    buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
  });

  public biasDetectionResults = new Counter({
    name: 'bias_detection_results_total',
    help: 'Bias detection analysis results',
    labelNames: ['model_id', 'bias_type', 'severity']
  });

  // Agentic Workflow Metrics
  public agentWorkflows = new Counter({
    name: 'agent_workflows_total',
    help: 'Agent workflow executions',
    labelNames: ['workflow_type', 'agent_id', 'status']
  });

  public agentSecurityEvents = new Counter({
    name: 'agent_security_events_total',
    help: 'Security events from autonomous agents',
    labelNames: ['agent_id', 'event_type', 'severity']
  });

  public mcpContextOperations = new Counter({
    name: 'mcp_context_operations_total',
    help: 'Model Context Protocol operations',
    labelNames: ['operation_type', 'context_type', 'security_level']
  });

  public agentBehaviorAnomalies = new Counter({
    name: 'agent_behavior_anomalies_total',
    help: 'Agent behavior anomalies detected',
    labelNames: ['agent_id', 'anomaly_type', 'severity']
  });

  // Database Metrics
  public databaseConnections = new Gauge({
    name: 'database_connections_active',
    help: 'Active database connections'
  });

  public databaseQueries = new Counter({
    name: 'database_queries_total',
    help: 'Total database queries',
    labelNames: ['operation', 'table', 'status']
  });

  public databaseQueryDuration = new Histogram({
    name: 'database_query_duration_seconds',
    help: 'Database query duration',
    labelNames: ['operation', 'table'],
    buckets: [0.001, 0.01, 0.1, 0.5, 1, 2, 5]
  });

  // Microservice Metrics
  public microserviceRequests = new Counter({
    name: 'microservice_requests_total',
    help: 'Requests to microservices',
    labelNames: ['service_name', 'endpoint', 'status_code']
  });

  public microserviceHealth = new Gauge({
    name: 'microservice_health_status',
    help: 'Health status of microservices (1=healthy, 0=unhealthy)',
    labelNames: ['service_name']
  });

  public serviceDiscoveryEvents = new Counter({
    name: 'service_discovery_events_total',
    help: 'Service discovery events',
    labelNames: ['event_type', 'service_name']
  });

  // Business Metrics
  public userActivities = new Counter({
    name: 'user_activities_total',
    help: 'User activity events',
    labelNames: ['activity_type', 'user_role', 'department']
  });

  public complianceAssessments = new Counter({
    name: 'compliance_assessments_total',
    help: 'Compliance assessments performed',
    labelNames: ['framework', 'assessment_type', 'result']
  });

  public alertsGenerated = new Counter({
    name: 'alerts_generated_total',
    help: 'Alerts generated by the system',
    labelNames: ['alert_type', 'severity', 'channel']
  });

  public alertsAcknowledged = new Counter({
    name: 'alerts_acknowledged_total',
    help: 'Alerts acknowledged by users',
    labelNames: ['alert_type', 'severity', 'response_time_bucket']
  });

  // System Performance Metrics
  public systemLoad = new Gauge({
    name: 'system_load_average',
    help: 'System load average'
  });

  public memoryUsage = new Gauge({
    name: 'memory_usage_bytes',
    help: 'Memory usage in bytes',
    labelNames: ['type']
  });

  public errorRates = new Counter({
    name: 'errors_total',
    help: 'Total application errors',
    labelNames: ['error_type', 'component', 'severity']
  });

  // Cache Metrics
  public cacheOperations = new Counter({
    name: 'cache_operations_total',
    help: 'Cache operations',
    labelNames: ['operation', 'cache_type', 'result']
  });

  public cacheHitRate = new Gauge({
    name: 'cache_hit_rate',
    help: 'Cache hit rate percentage',
    labelNames: ['cache_type']
  });

  constructor() {
    this.startSystemMetricsCollection();
  }

  private startSystemMetricsCollection() {
    // Update system metrics every 15 seconds
    setInterval(() => {
      try {
        const memUsage = process.memoryUsage();
        this.memoryUsage.set({ type: 'heap_used' }, memUsage.heapUsed);
        this.memoryUsage.set({ type: 'heap_total' }, memUsage.heapTotal);
        this.memoryUsage.set({ type: 'external' }, memUsage.external);
        this.memoryUsage.set({ type: 'rss' }, memUsage.rss);

        // Get system load if available
        if (process.platform !== 'win32') {
          const os = require('os');
          this.systemLoad.set(os.loadavg()[0]);
        }
      } catch (error) {
        logger.error('Failed to collect system metrics', error);
      }
    }, 15000);
  }

  // HTTP Request tracking
  recordHttpRequest(method: string, route: string, statusCode: number, duration: number, userRole?: string) {
    this.httpRequestsTotal.inc({
      method,
      route,
      status_code: statusCode.toString(),
      user_role: userRole || 'anonymous'
    });

    this.httpRequestDuration.observe(
      { method, route, status_code: statusCode.toString() },
      duration / 1000
    );
  }

  // Authentication tracking
  recordAuthAttempt(method: string, result: 'success' | 'failure', userType: string = 'user') {
    this.authAttempts.inc({ method, result, user_type: userType });
  }

  recordMFAAttempt(method: string, result: 'success' | 'failure') {
    this.mfaAttempts.inc({ method, result });
  }

  updateActiveSessions(count: number) {
    this.activeSessions.set(count);
  }

  // Security event tracking
  recordSecurityEvent(eventType: string, severity: string, source: string) {
    this.securityEvents.inc({ event_type: eventType, severity, source });
  }

  recordThreatDetection(threatType: string, severity: string, modelId: string, responseAction: string) {
    this.threatDetections.inc({
      threat_type: threatType,
      severity,
      model_id: modelId,
      response_action: responseAction
    });
  }

  recordComplianceViolation(framework: string, violationType: string, severity: string) {
    this.complianceViolations.inc({
      framework,
      violation_type: violationType,
      severity
    });
  }

  // AI Asset tracking
  updateAIAssetCount(assetType: string, environment: string, status: string, count: number) {
    this.aiAssetsTotal.set({ asset_type: assetType, environment, status }, count);
  }

  recordModelInference(modelId: string, modelType: string, status: string, duration: number) {
    this.modelInferences.inc({ model_id: modelId, model_type: modelType, status });
    this.modelPerformance.observe({ model_id: modelId, model_type: modelType }, duration / 1000);
  }

  recordBiasDetection(modelId: string, biasType: string, severity: string) {
    this.biasDetectionResults.inc({ model_id: modelId, bias_type: biasType, severity });
  }

  // Agentic workflow tracking
  recordAgentWorkflow(workflowType: string, agentId: string, status: string) {
    this.agentWorkflows.inc({ workflow_type: workflowType, agent_id: agentId, status });
  }

  recordAgentSecurityEvent(agentId: string, eventType: string, severity: string) {
    this.agentSecurityEvents.inc({ agent_id: agentId, event_type: eventType, severity });
  }

  recordMCPOperation(operationType: string, contextType: string, securityLevel: string) {
    this.mcpContextOperations.inc({
      operation_type: operationType,
      context_type: contextType,
      security_level: securityLevel
    });
  }

  recordAgentAnomaly(agentId: string, anomalyType: string, severity: string) {
    this.agentBehaviorAnomalies.inc({ agent_id: agentId, anomaly_type: anomalyType, severity });
  }

  // Database tracking
  updateDatabaseConnections(count: number) {
    this.databaseConnections.set(count);
  }

  recordDatabaseQuery(operation: string, table: string, status: string, duration: number) {
    this.databaseQueries.inc({ operation, table, status });
    this.databaseQueryDuration.observe({ operation, table }, duration / 1000);
  }

  // Microservice tracking
  recordMicroserviceRequest(serviceName: string, endpoint: string, statusCode: number) {
    this.microserviceRequests.inc({
      service_name: serviceName,
      endpoint,
      status_code: statusCode.toString()
    });
  }

  updateMicroserviceHealth(serviceName: string, isHealthy: boolean) {
    this.microserviceHealth.set({ service_name: serviceName }, isHealthy ? 1 : 0);
  }

  // Business metrics
  recordUserActivity(activityType: string, userRole: string, department: string) {
    this.userActivities.inc({ activity_type: activityType, user_role: userRole, department });
  }

  recordComplianceAssessment(framework: string, assessmentType: string, result: string) {
    this.complianceAssessments.inc({ framework, assessment_type: assessmentType, result });
  }

  recordAlert(alertType: string, severity: string, channel: string) {
    this.alertsGenerated.inc({ alert_type: alertType, severity, channel });
  }

  recordAlertAcknowledgment(alertType: string, severity: string, responseTimeMs: number) {
    const responseTimeBucket = this.getResponseTimeBucket(responseTimeMs);
    this.alertsAcknowledged.inc({
      alert_type: alertType,
      severity,
      response_time_bucket: responseTimeBucket
    });
  }

  // Error tracking
  recordError(errorType: string, component: string, severity: string) {
    this.errorRates.inc({ error_type: errorType, component, severity });
  }

  // Cache metrics
  recordCacheOperation(operation: string, cacheType: string, result: string) {
    this.cacheOperations.inc({ operation, cache_type: cacheType, result });
  }

  updateCacheHitRate(cacheType: string, hitRate: number) {
    this.cacheHitRate.set({ cache_type: cacheType }, hitRate);
  }

  // Utility methods
  private getResponseTimeBucket(responseTimeMs: number): string {
    if (responseTimeMs < 1000) return '< 1s';
    if (responseTimeMs < 5000) return '1-5s';
    if (responseTimeMs < 30000) return '5-30s';
    if (responseTimeMs < 300000) return '30s-5m';
    return '> 5m';
  }

  // Get all metrics in Prometheus format
  getMetrics(): Promise<string> {
    return register.metrics();
  }

  // Clear all metrics (for testing)
  clearMetrics() {
    register.clear();
  }
}

// Export singleton instance
export const metrics = new MetricsCollector();

// Express middleware for automatic HTTP metrics collection
export const metricsMiddleware = (req: any, res: any, next: any) => {
  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const route = req.route?.path || req.path || 'unknown';
    const userRole = req.user?.role || 'anonymous';

    metrics.recordHttpRequest(req.method, route, res.statusCode, duration, userRole);
  });

  next();
};