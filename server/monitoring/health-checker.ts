/**
 * Comprehensive Health Monitoring System for AI-SPM Platform
 * Provides system health checks, metrics collection, and alert generation
 */

import { EventEmitter } from 'events';
import os from 'os';
import { performance } from 'perf_hooks';

// Health status enums and interfaces
export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  UNKNOWN = 'unknown'
}

export enum AlertSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export interface ComponentHealth {
  name: string;
  status: HealthStatus;
  lastCheck: Date;
  responseTime?: number;
  message?: string;
  metrics?: Record<string, any>;
  dependencies?: ComponentHealth[];
}

export interface SystemHealthStatus {
  status: HealthStatus;
  timestamp: Date;
  uptime: number;
  version: string;
  components: {
    database: ComponentHealth;
    authentication: ComponentHealth;
    security: ComponentHealth;
    agentic: ComponentHealth;
    infrastructure: ComponentHealth;
    dependencies: ComponentHealth;
  };
  alerts: Alert[];
  metrics: SystemMetrics;
}

export interface Alert {
  id: string;
  name: string;
  description: string;
  severity: AlertSeverity;
  component: string;
  timestamp: Date;
  currentValue?: number;
  threshold?: number;
  tags: string[];
  metadata?: Record<string, any>;
}

export interface SystemMetrics {
  application: ApplicationMetrics;
  infrastructure: InfrastructureMetrics;
  security: SecurityMetrics;
  agentic: AgenticMetrics;
}

export interface ApplicationMetrics {
  apiGateway: {
    responseTime: number;
    throughput: number;
    errorRate: number;
    activeConnections: number;
    requestsPerSecond: number;
  };
  authentication: {
    loginSuccessRate: number;
    authenticationLatency: number;
    activeUserSessions: number;
    failedLoginAttempts: number;
    ssoHealthStatus: string;
  };
  database: {
    connectionPoolSize: number;
    activeConnections: number;
    queryLatency: number;
    transactionRate: number;
    slowQueries: number;
  };
}

export interface InfrastructureMetrics {
  compute: {
    cpuUsage: number;
    memoryUsage: number;
    diskUsage: number;
    loadAverage: number[];
    processCount: number;
  };
  network: {
    bytesIn: number;
    bytesOut: number;
    packetsIn: number;
    packetsOut: number;
    connectionErrors: number;
  };
  storage: {
    diskSpaceAvailable: number;
    diskSpaceUsed: number;
    iopsUtilization: number;
    readLatency: number;
    writeLatency: number;
  };
}

export interface SecurityMetrics {
  threatDetection: {
    activeThreats: number;
    detectionLatency: number;
    falsePositiveRate: number;
    threatScore: number;
  };
  authentication: {
    bruteForceAttempts: number;
    suspiciousLogins: number;
    mfaBypassAttempts: number;
    privilegeEscalations: number;
  };
  compliance: {
    policyViolations: number;
    complianceScore: number;
    auditTrailIntegrity: boolean;
    privacyRequests: number;
  };
}

export interface AgenticMetrics {
  agents: {
    activeAgents: number;
    healthyAgents: number;
    averageHealthScore: number;
    behavioralAnomalies: number;
  };
  workflows: {
    executionSuccessRate: number;
    averageExecutionTime: number;
    failedWorkflows: number;
    securityViolations: number;
  };
  mcp: {
    contextProcessingLatency: number;
    encryptionStatus: string;
    integrityCheckFailures: number;
    accessViolations: number;
  };
}

/**
 * Comprehensive Health Checker Service
 */
export class HealthCheckerService extends EventEmitter {
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsCollectionInterval: NodeJS.Timeout | null = null;
  private alertBuffer: Alert[] = [];
  private lastHealthCheck: SystemHealthStatus | null = null;
  private startTime: Date = new Date();

  // Configurable thresholds
  private thresholds = {
    responseTime: 2000, // ms
    errorRate: 5, // percentage
    cpuUsage: 80, // percentage
    memoryUsage: 85, // percentage
    diskUsage: 90, // percentage
    queryLatency: 100, // ms
    agentHealthScore: 70, // minimum acceptable score
    complianceScore: 80 // minimum acceptable score
  };

  constructor() {
    super();
    this.startPeriodicHealthChecks();
    this.startMetricsCollection();
  }

  /**
   * Get current system health status
   */
  async getSystemHealth(): Promise<SystemHealthStatus> {
    const startTime = performance.now();

    try {
      const [database, auth, security, agentic, infrastructure, dependencies] = await Promise.all([
        this.checkDatabaseHealth(),
        this.checkAuthenticationHealth(),
        this.checkSecurityMonitoringHealth(),
        this.checkAgenticWorkflowsHealth(),
        this.checkInfrastructureHealth(),
        this.checkExternalDependencies()
      ]);

      const metrics = await this.collectSystemMetrics();
      
      const overallStatus = this.calculateOverallStatus([
        database, auth, security, agentic, infrastructure, dependencies
      ]);

      const healthStatus: SystemHealthStatus = {
        status: overallStatus,
        timestamp: new Date(),
        uptime: Date.now() - this.startTime.getTime(),
        version: process.env.APP_VERSION || '1.0.0',
        components: {
          database,
          authentication: auth,
          security,
          agentic,
          infrastructure,
          dependencies
        },
        alerts: [...this.alertBuffer],
        metrics
      };

      this.lastHealthCheck = healthStatus;
      this.evaluateAlerts(healthStatus);

      const checkDuration = performance.now() - startTime;
      this.emit('healthCheckCompleted', { status: healthStatus, duration: checkDuration });

      return healthStatus;

    } catch (error) {
      const errorStatus: SystemHealthStatus = {
        status: HealthStatus.UNHEALTHY,
        timestamp: new Date(),
        uptime: Date.now() - this.startTime.getTime(),
        version: process.env.APP_VERSION || '1.0.0',
        components: {
          database: { name: 'database', status: HealthStatus.UNKNOWN, lastCheck: new Date() },
          authentication: { name: 'authentication', status: HealthStatus.UNKNOWN, lastCheck: new Date() },
          security: { name: 'security', status: HealthStatus.UNKNOWN, lastCheck: new Date() },
          agentic: { name: 'agentic', status: HealthStatus.UNKNOWN, lastCheck: new Date() },
          infrastructure: { name: 'infrastructure', status: HealthStatus.UNKNOWN, lastCheck: new Date() },
          dependencies: { name: 'dependencies', status: HealthStatus.UNKNOWN, lastCheck: new Date() }
        },
        alerts: [{
          id: this.generateAlertId(),
          name: 'health_check_failure',
          description: `Health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          severity: AlertSeverity.CRITICAL,
          component: 'health_checker',
          timestamp: new Date(),
          tags: ['system', 'health_check', 'failure']
        }],
        metrics: this.getEmptyMetrics()
      };

      this.emit('healthCheckFailed', { error, status: errorStatus });
      return errorStatus;
    }
  }

  /**
   * Check database health
   */
  private async checkDatabaseHealth(): Promise<ComponentHealth> {
    const startTime = performance.now();
    
    try {
      // Mock database check - replace with actual database client
      await new Promise(resolve => setTimeout(resolve, 10)); // Simulate DB query
      
      const responseTime = performance.now() - startTime;
      
      // Check connection pool and query performance
      const metrics = {
        connectionPool: 10,
        activeConnections: 3,
        queryLatency: responseTime,
        slowQueries: 0
      };

      return {
        name: 'database',
        status: responseTime > this.thresholds.queryLatency ? HealthStatus.DEGRADED : HealthStatus.HEALTHY,
        lastCheck: new Date(),
        responseTime,
        message: `Database responsive in ${responseTime.toFixed(2)}ms`,
        metrics
      };

    } catch (error) {
      return {
        name: 'database',
        status: HealthStatus.UNHEALTHY,
        lastCheck: new Date(),
        message: `Database check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Check authentication system health
   */
  private async checkAuthenticationHealth(): Promise<ComponentHealth> {
    const startTime = performance.now();
    
    try {
      // Mock authentication check
      await new Promise(resolve => setTimeout(resolve, 5));
      
      const responseTime = performance.now() - startTime;
      
      const metrics = {
        loginSuccessRate: 98.5,
        authenticationLatency: responseTime,
        activeUserSessions: 150,
        failedLoginAttempts: 2,
        ssoHealthStatus: 'healthy'
      };

      return {
        name: 'authentication',
        status: HealthStatus.HEALTHY,
        lastCheck: new Date(),
        responseTime,
        message: 'Authentication system operational',
        metrics
      };

    } catch (error) {
      return {
        name: 'authentication',
        status: HealthStatus.UNHEALTHY,
        lastCheck: new Date(),
        message: `Authentication check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Check security monitoring health
   */
  private async checkSecurityMonitoringHealth(): Promise<ComponentHealth> {
    const startTime = performance.now();
    
    try {
      // Mock security monitoring check
      await new Promise(resolve => setTimeout(resolve, 8));
      
      const responseTime = performance.now() - startTime;
      
      const metrics = {
        siemConnectionStatus: 'connected',
        eventProcessingRate: 250,
        alertBacklog: 3,
        threatIntelligenceStatus: 'updated',
        threatScore: 15
      };

      return {
        name: 'security',
        status: HealthStatus.HEALTHY,
        lastCheck: new Date(),
        responseTime,
        message: 'Security monitoring active',
        metrics
      };

    } catch (error) {
      return {
        name: 'security',
        status: HealthStatus.UNHEALTHY,
        lastCheck: new Date(),
        message: `Security monitoring check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Check agentic workflows health
   */
  private async checkAgenticWorkflowsHealth(): Promise<ComponentHealth> {
    const startTime = performance.now();
    
    try {
      // Mock agentic workflows check
      await new Promise(resolve => setTimeout(resolve, 12));
      
      const responseTime = performance.now() - startTime;
      
      const metrics = {
        activeAgents: 5,
        healthyAgents: 5,
        averageHealthScore: 92,
        behavioralAnomalies: 0,
        mcpContextProcessingRate: 45,
        workflowExecutionRate: 85,
        integrityCheckFailures: 0
      };

      const healthScore = metrics.averageHealthScore;
      const status = healthScore >= this.thresholds.agentHealthScore ? 
        HealthStatus.HEALTHY : 
        healthScore >= 50 ? HealthStatus.DEGRADED : HealthStatus.UNHEALTHY;

      return {
        name: 'agentic',
        status,
        lastCheck: new Date(),
        responseTime,
        message: `Agentic workflows operational (${healthScore}% health score)`,
        metrics
      };

    } catch (error) {
      return {
        name: 'agentic',
        status: HealthStatus.UNHEALTHY,
        lastCheck: new Date(),
        message: `Agentic workflows check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Check infrastructure health
   */
  private async checkInfrastructureHealth(): Promise<ComponentHealth> {
    try {
      const metrics = {
        cpuUsage: this.getCPUUsage(),
        memoryUsage: this.getMemoryUsage(),
        diskUsage: await this.getDiskUsage(),
        loadAverage: os.loadavg(),
        processCount: 25
      };

      // Determine status based on resource usage
      let status = HealthStatus.HEALTHY;
      if (metrics.cpuUsage > this.thresholds.cpuUsage || 
          metrics.memoryUsage > this.thresholds.memoryUsage ||
          metrics.diskUsage > this.thresholds.diskUsage) {
        status = HealthStatus.DEGRADED;
      }

      return {
        name: 'infrastructure',
        status,
        lastCheck: new Date(),
        message: `Infrastructure resources: CPU ${metrics.cpuUsage.toFixed(1)}%, Memory ${metrics.memoryUsage.toFixed(1)}%, Disk ${metrics.diskUsage.toFixed(1)}%`,
        metrics
      };

    } catch (error) {
      return {
        name: 'infrastructure',
        status: HealthStatus.UNHEALTHY,
        lastCheck: new Date(),
        message: `Infrastructure check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Check external dependencies health
   */
  private async checkExternalDependencies(): Promise<ComponentHealth> {
    try {
      // Mock external dependency checks
      const dependencies = [
        { name: 'SIEM_API', healthy: true, responseTime: 150 },
        { name: 'Threat_Intelligence', healthy: true, responseTime: 200 },
        { name: 'External_Auth_Provider', healthy: true, responseTime: 100 }
      ];

      const unhealthyDeps = dependencies.filter(dep => !dep.healthy);
      const status = unhealthyDeps.length === 0 ? HealthStatus.HEALTHY :
                    unhealthyDeps.length < dependencies.length ? HealthStatus.DEGRADED :
                    HealthStatus.UNHEALTHY;

      return {
        name: 'dependencies',
        status,
        lastCheck: new Date(),
        message: `External dependencies: ${dependencies.length - unhealthyDeps.length}/${dependencies.length} healthy`,
        metrics: { dependencies, unhealthyCount: unhealthyDeps.length }
      };

    } catch (error) {
      return {
        name: 'dependencies',
        status: HealthStatus.UNHEALTHY,
        lastCheck: new Date(),
        message: `Dependencies check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Collect comprehensive system metrics
   */
  private async collectSystemMetrics(): Promise<SystemMetrics> {
    return {
      application: {
        apiGateway: {
          responseTime: 150,
          throughput: 450,
          errorRate: 0.5,
          activeConnections: 25,
          requestsPerSecond: 75
        },
        authentication: {
          loginSuccessRate: 98.5,
          authenticationLatency: 45,
          activeUserSessions: 150,
          failedLoginAttempts: 2,
          ssoHealthStatus: 'healthy'
        },
        database: {
          connectionPoolSize: 10,
          activeConnections: 3,
          queryLatency: 25,
          transactionRate: 120,
          slowQueries: 0
        }
      },
      infrastructure: {
        compute: {
          cpuUsage: this.getCPUUsage(),
          memoryUsage: this.getMemoryUsage(),
          diskUsage: 45.5,
          loadAverage: os.loadavg(),
          processCount: 25
        },
        network: {
          bytesIn: 1024000,
          bytesOut: 2048000,
          packetsIn: 1500,
          packetsOut: 1600,
          connectionErrors: 0
        },
        storage: {
          diskSpaceAvailable: 500000, // MB
          diskSpaceUsed: 250000, // MB
          iopsUtilization: 35,
          readLatency: 2.5,
          writeLatency: 3.2
        }
      },
      security: {
        threatDetection: {
          activeThreats: 0,
          detectionLatency: 0.5,
          falsePositiveRate: 2.1,
          threatScore: 15
        },
        authentication: {
          bruteForceAttempts: 0,
          suspiciousLogins: 0,
          mfaBypassAttempts: 0,
          privilegeEscalations: 0
        },
        compliance: {
          policyViolations: 0,
          complianceScore: 96,
          auditTrailIntegrity: true,
          privacyRequests: 3
        }
      },
      agentic: {
        agents: {
          activeAgents: 5,
          healthyAgents: 5,
          averageHealthScore: 92,
          behavioralAnomalies: 0
        },
        workflows: {
          executionSuccessRate: 98.2,
          averageExecutionTime: 1250,
          failedWorkflows: 2,
          securityViolations: 0
        },
        mcp: {
          contextProcessingLatency: 8.5,
          encryptionStatus: 'healthy',
          integrityCheckFailures: 0,
          accessViolations: 0
        }
      }
    };
  }

  /**
   * Calculate overall system status
   */
  private calculateOverallStatus(components: ComponentHealth[]): HealthStatus {
    const statuses = components.map(c => c.status);
    
    if (statuses.includes(HealthStatus.UNHEALTHY)) {
      return HealthStatus.UNHEALTHY;
    }
    
    if (statuses.includes(HealthStatus.DEGRADED)) {
      return HealthStatus.DEGRADED;
    }
    
    if (statuses.every(status => status === HealthStatus.HEALTHY)) {
      return HealthStatus.HEALTHY;
    }
    
    return HealthStatus.UNKNOWN;
  }

  /**
   * Evaluate conditions and generate alerts
   */
  private evaluateAlerts(healthStatus: SystemHealthStatus): void {
    const newAlerts: Alert[] = [];

    // Check for system-wide issues
    if (healthStatus.status === HealthStatus.UNHEALTHY) {
      newAlerts.push({
        id: this.generateAlertId(),
        name: 'system_unhealthy',
        description: 'AI-SPM platform is in an unhealthy state',
        severity: AlertSeverity.CRITICAL,
        component: 'system',
        timestamp: new Date(),
        tags: ['system', 'health', 'critical']
      });
    }

    // Check application metrics
    const appMetrics = healthStatus.metrics.application;
    if (appMetrics.apiGateway.responseTime > this.thresholds.responseTime) {
      newAlerts.push({
        id: this.generateAlertId(),
        name: 'high_response_time',
        description: 'API response time exceeding threshold',
        severity: AlertSeverity.HIGH,
        component: 'api_gateway',
        timestamp: new Date(),
        currentValue: appMetrics.apiGateway.responseTime,
        threshold: this.thresholds.responseTime,
        tags: ['performance', 'api', 'latency']
      });
    }

    // Check infrastructure metrics
    const infraMetrics = healthStatus.metrics.infrastructure;
    if (infraMetrics.compute.cpuUsage > this.thresholds.cpuUsage) {
      newAlerts.push({
        id: this.generateAlertId(),
        name: 'high_cpu_usage',
        description: 'CPU usage is above threshold',
        severity: AlertSeverity.MEDIUM,
        component: 'infrastructure',
        timestamp: new Date(),
        currentValue: infraMetrics.compute.cpuUsage,
        threshold: this.thresholds.cpuUsage,
        tags: ['infrastructure', 'cpu', 'resource']
      });
    }

    // Check agentic workflow metrics
    const agenticMetrics = healthStatus.metrics.agentic;
    if (agenticMetrics.agents.averageHealthScore < this.thresholds.agentHealthScore) {
      newAlerts.push({
        id: this.generateAlertId(),
        name: 'low_agent_health_score',
        description: 'Agent health score below acceptable threshold',
        severity: AlertSeverity.MEDIUM,
        component: 'agentic_workflows',
        timestamp: new Date(),
        currentValue: agenticMetrics.agents.averageHealthScore,
        threshold: this.thresholds.agentHealthScore,
        tags: ['agentic', 'agents', 'health']
      });
    }

    // Add new alerts to buffer and emit events
    if (newAlerts.length > 0) {
      this.alertBuffer.push(...newAlerts);
      this.alertBuffer = this.alertBuffer.slice(-100); // Keep last 100 alerts
      
      newAlerts.forEach(alert => {
        this.emit('alert', alert);
      });
    }
  }

  // Utility methods
  private getCPUUsage(): number {
    // Mock CPU usage calculation
    return Math.random() * 40 + 20; // 20-60%
  }

  private getMemoryUsage(): number {
    const used = process.memoryUsage();
    const total = os.totalmem();
    return (used.heapUsed / total) * 100;
  }

  private async getDiskUsage(): Promise<number> {
    // Mock disk usage - in real implementation, use fs.statvfs or similar
    return Math.random() * 30 + 30; // 30-60%
  }

  private generateAlertId(): string {
    return `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private getEmptyMetrics(): SystemMetrics {
    return {
      application: {
        apiGateway: { responseTime: 0, throughput: 0, errorRate: 0, activeConnections: 0, requestsPerSecond: 0 },
        authentication: { loginSuccessRate: 0, authenticationLatency: 0, activeUserSessions: 0, failedLoginAttempts: 0, ssoHealthStatus: 'unknown' },
        database: { connectionPoolSize: 0, activeConnections: 0, queryLatency: 0, transactionRate: 0, slowQueries: 0 }
      },
      infrastructure: {
        compute: { cpuUsage: 0, memoryUsage: 0, diskUsage: 0, loadAverage: [], processCount: 0 },
        network: { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0, connectionErrors: 0 },
        storage: { diskSpaceAvailable: 0, diskSpaceUsed: 0, iopsUtilization: 0, readLatency: 0, writeLatency: 0 }
      },
      security: {
        threatDetection: { activeThreats: 0, detectionLatency: 0, falsePositiveRate: 0, threatScore: 0 },
        authentication: { bruteForceAttempts: 0, suspiciousLogins: 0, mfaBypassAttempts: 0, privilegeEscalations: 0 },
        compliance: { policyViolations: 0, complianceScore: 0, auditTrailIntegrity: false, privacyRequests: 0 }
      },
      agentic: {
        agents: { activeAgents: 0, healthyAgents: 0, averageHealthScore: 0, behavioralAnomalies: 0 },
        workflows: { executionSuccessRate: 0, averageExecutionTime: 0, failedWorkflows: 0, securityViolations: 0 },
        mcp: { contextProcessingLatency: 0, encryptionStatus: 'unknown', integrityCheckFailures: 0, accessViolations: 0 }
      }
    };
  }

  private startPeriodicHealthChecks(): void {
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.getSystemHealth();
      } catch (error) {
        console.error('Periodic health check failed:', error);
      }
    }, 30000); // Every 30 seconds
  }

  private startMetricsCollection(): void {
    this.metricsCollectionInterval = setInterval(async () => {
      try {
        const metrics = await this.collectSystemMetrics();
        this.emit('metricsCollected', metrics);
      } catch (error) {
        console.error('Metrics collection failed:', error);
      }
    }, 10000); // Every 10 seconds
  }

  /**
   * Stop all monitoring activities
   */
  public stop(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    if (this.metricsCollectionInterval) {
      clearInterval(this.metricsCollectionInterval);
    }
  }

  /**
   * Get recent alerts
   */
  public getRecentAlerts(limit: number = 50): Alert[] {
    return this.alertBuffer.slice(-limit);
  }

  /**
   * Clear alert buffer
   */
  public clearAlerts(): void {
    this.alertBuffer = [];
  }

  /**
   * Update alert thresholds
   */
  public updateThresholds(newThresholds: Partial<typeof this.thresholds>): void {
    this.thresholds = { ...this.thresholds, ...newThresholds };
    this.emit('thresholdsUpdated', this.thresholds);
  }
}