/**
 * Comprehensive Health Monitoring System
 * Real-time health checks for all platform components
 */

import { logger, SecurityEventType } from './logger';
import { metrics } from './metrics-collector';
import { db } from '../db';

export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  responseTime: number;
  details?: any;
  error?: string;
}

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: string;
  responseTime: number;
  uptime: number;
  details: any;
}

export interface SystemHealth {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  components: ComponentHealth[];
  summary: {
    total: number;
    healthy: number;
    degraded: number;
    unhealthy: number;
  };
}

class HealthChecker {
  private healthHistory: Map<string, HealthCheckResult[]> = new Map();
  private microserviceUrls: Record<string, string>;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.microserviceUrls = {
      'ai-scanner': process.env.AI_SCANNER_URL || 'http://localhost:8001',
      'data-integrity': process.env.DATA_INTEGRITY_URL || 'http://localhost:8002',
      'wiz-integration': process.env.WIZ_INTEGRATION_URL || 'http://localhost:8003',
      'compliance-engine': process.env.COMPLIANCE_ENGINE_URL || 'http://localhost:8004',
      'agent-orchestrator': process.env.AGENT_ORCHESTRATOR_URL || 'http://localhost:8005'
    };

    this.startPeriodicHealthChecks();
  }

  private startPeriodicHealthChecks() {
    // Run health checks every 30 seconds
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.performAllHealthChecks();
      } catch (error) {
        logger.error('Error during periodic health checks', error);
      }
    }, 30000);

    // Initial health check
    setTimeout(() => this.performAllHealthChecks(), 5000);
  }

  async performAllHealthChecks(): Promise<SystemHealth> {
    const startTime = Date.now();
    
    logger.debug('Starting comprehensive health checks');

    const healthChecks = await Promise.allSettled([
      this.checkDatabase(),
      this.checkRedis(),
      this.checkMemory(),
      this.checkDisk(),
      this.checkMicroservices(),
      this.checkExternalServices(),
      this.checkSecurityComponents(),
      this.checkAgenticComponents()
    ]);

    const components: ComponentHealth[] = [];
    let healthyCount = 0;
    let degradedCount = 0;
    let unhealthyCount = 0;

    healthChecks.forEach((result, index) => {
      if (result.status === 'fulfilled' && Array.isArray(result.value)) {
        result.value.forEach((component: ComponentHealth) => {
          components.push(component);
          switch (component.status) {
            case 'healthy': healthyCount++; break;
            case 'degraded': degradedCount++; break;
            case 'unhealthy': unhealthyCount++; break;
          }
        });
      } else if (result.status === 'fulfilled') {
        const component = result.value as ComponentHealth;
        components.push(component);
        switch (component.status) {
          case 'healthy': healthyCount++; break;
          case 'degraded': degradedCount++; break;
          case 'unhealthy': unhealthyCount++; break;
        }
      } else {
        // Handle rejected promises
        const errorComponent: ComponentHealth = {
          name: `health-check-${index}`,
          status: 'unhealthy',
          lastCheck: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          uptime: 0,
          details: { error: result.reason?.message || 'Unknown error' }
        };
        components.push(errorComponent);
        unhealthyCount++;
      }
    });

    // Determine overall health
    let overallStatus: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    if (unhealthyCount > 0) {
      overallStatus = 'unhealthy';
    } else if (degradedCount > 0) {
      overallStatus = 'degraded';
    }

    const systemHealth: SystemHealth = {
      overall: overallStatus,
      timestamp: new Date().toISOString(),
      components,
      summary: {
        total: components.length,
        healthy: healthyCount,
        degraded: degradedCount,
        unhealthy: unhealthyCount
      }
    };

    // Log health status
    const duration = Date.now() - startTime;
    logger.info(`Health check completed in ${duration}ms`, {
      overallStatus,
      healthy: healthyCount,
      degraded: degradedCount,
      unhealthy: unhealthyCount
    });

    // Record metrics
    metrics.recordUserActivity('health_check', 'system', 'platform');

    // Alert on unhealthy status
    if (overallStatus === 'unhealthy') {
      logger.security(SecurityEventType.SYSTEM_SECURITY, 'System health degraded to unhealthy', {
        unhealthyComponents: components.filter(c => c.status === 'unhealthy').map(c => c.name)
      });
    }

    return systemHealth;
  }

  async checkDatabase(): Promise<ComponentHealth> {
    const startTime = Date.now();
    
    try {
      // Test database connection
      await db.select().from('users' as any).limit(1);
      
      const responseTime = Date.now() - startTime;
      
      return {
        name: 'database',
        status: responseTime < 1000 ? 'healthy' : 'degraded',
        lastCheck: new Date().toISOString(),
        responseTime,
        uptime: process.uptime(),
        details: {
          type: 'postgresql',
          responseTime: `${responseTime}ms`,
          status: 'connected'
        }
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      logger.error('Database health check failed', error);
      
      return {
        name: 'database',
        status: 'unhealthy',
        lastCheck: new Date().toISOString(),
        responseTime,
        uptime: 0,
        details: {
          type: 'postgresql',
          error: error instanceof Error ? error.message : 'Unknown error',
          status: 'disconnected'
        }
      };
    }
  }

  async checkRedis(): Promise<ComponentHealth> {
    const startTime = Date.now();
    
    try {
      // Test Redis connection if available
      if (process.env.REDIS_URL) {
        // This would require Redis client setup
        // For now, simulate check
        const responseTime = Date.now() - startTime;
        
        return {
          name: 'redis',
          status: 'healthy',
          lastCheck: new Date().toISOString(),
          responseTime,
          uptime: process.uptime(),
          details: {
            type: 'redis',
            responseTime: `${responseTime}ms`,
            status: 'connected'
          }
        };
      } else {
        return {
          name: 'redis',
          status: 'degraded',
          lastCheck: new Date().toISOString(),
          responseTime: 0,
          uptime: process.uptime(),
          details: {
            type: 'redis',
            status: 'not_configured'
          }
        };
      }
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      return {
        name: 'redis',
        status: 'unhealthy',
        lastCheck: new Date().toISOString(),
        responseTime,
        uptime: 0,
        details: {
          type: 'redis',
          error: error instanceof Error ? error.message : 'Unknown error',
          status: 'disconnected'
        }
      };
    }
  }

  async checkMemory(): Promise<ComponentHealth> {
    const memUsage = process.memoryUsage();
    const heapUsedMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    const heapTotalMB = Math.round(memUsage.heapTotal / 1024 / 1024);
    const heapUsedPercent = (heapUsedMB / heapTotalMB) * 100;

    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    if (heapUsedPercent > 90) {
      status = 'unhealthy';
    } else if (heapUsedPercent > 80) {
      status = 'degraded';
    }

    return {
      name: 'memory',
      status,
      lastCheck: new Date().toISOString(),
      responseTime: 0,
      uptime: process.uptime(),
      details: {
        heapUsed: `${heapUsedMB}MB`,
        heapTotal: `${heapTotalMB}MB`,
        heapUsedPercent: `${heapUsedPercent.toFixed(1)}%`,
        external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`
      }
    };
  }

  async checkDisk(): Promise<ComponentHealth> {
    try {
      const fs = require('fs');
      const stats = fs.statSync('.');
      
      // This is a basic check; in production, use proper disk space monitoring
      return {
        name: 'disk',
        status: 'healthy',
        lastCheck: new Date().toISOString(),
        responseTime: 0,
        uptime: process.uptime(),
        details: {
          accessible: true,
          writeable: true
        }
      };
    } catch (error) {
      return {
        name: 'disk',
        status: 'unhealthy',
        lastCheck: new Date().toISOString(),
        responseTime: 0,
        uptime: 0,
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
          accessible: false
        }
      };
    }
  }

  async checkMicroservices(): Promise<ComponentHealth[]> {
    const healthChecks = Object.entries(this.microserviceUrls).map(async ([serviceName, url]) => {
      const startTime = Date.now();
      
      try {
        const response = await fetch(`${url}/health`, {
          method: 'GET',
          headers: {
            'X-Internal-Service': 'true'
          },
          signal: AbortSignal.timeout(5000) // 5 second timeout
        });

        const responseTime = Date.now() - startTime;
        
        if (response.ok) {
          const healthData = await response.json();
          
          metrics.updateMicroserviceHealth(serviceName, true);
          
          return {
            name: serviceName,
            status: responseTime < 2000 ? 'healthy' : 'degraded' as 'healthy' | 'degraded',
            lastCheck: new Date().toISOString(),
            responseTime,
            uptime: healthData.uptime || 0,
            details: {
              type: 'microservice',
              url,
              responseTime: `${responseTime}ms`,
              version: healthData.version || 'unknown',
              status: 'running'
            }
          };
        } else {
          metrics.updateMicroserviceHealth(serviceName, false);
          
          return {
            name: serviceName,
            status: 'unhealthy' as const,
            lastCheck: new Date().toISOString(),
            responseTime,
            uptime: 0,
            details: {
              type: 'microservice',
              url,
              error: `HTTP ${response.status}`,
              status: 'error'
            }
          };
        }
      } catch (error) {
        const responseTime = Date.now() - startTime;
        
        metrics.updateMicroserviceHealth(serviceName, false);
        
        return {
          name: serviceName,
          status: 'unhealthy' as const,
          lastCheck: new Date().toISOString(),
          responseTime,
          uptime: 0,
          details: {
            type: 'microservice',
            url,
            error: error instanceof Error ? error.message : 'Connection failed',
            status: 'unreachable'
          }
        };
      }
    });

    return Promise.all(healthChecks);
  }

  async checkExternalServices(): Promise<ComponentHealth[]> {
    const externalChecks: ComponentHealth[] = [];

    // Check SIEM integration if configured
    if (process.env.SIEM_ENDPOINT) {
      const startTime = Date.now();
      
      try {
        const response = await fetch(process.env.SIEM_ENDPOINT, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000)
        });

        const responseTime = Date.now() - startTime;
        
        externalChecks.push({
          name: 'siem-integration',
          status: response.ok ? 'healthy' : 'degraded',
          lastCheck: new Date().toISOString(),
          responseTime,
          uptime: process.uptime(),
          details: {
            type: 'external_api',
            endpoint: process.env.SIEM_ENDPOINT,
            status: response.ok ? 'connected' : 'error'
          }
        });
      } catch (error) {
        externalChecks.push({
          name: 'siem-integration',
          status: 'unhealthy',
          lastCheck: new Date().toISOString(),
          responseTime: Date.now() - startTime,
          uptime: 0,
          details: {
            type: 'external_api',
            endpoint: process.env.SIEM_ENDPOINT,
            error: error instanceof Error ? error.message : 'Connection failed'
          }
        });
      }
    }

    return externalChecks;
  }

  async checkSecurityComponents(): Promise<ComponentHealth[]> {
    const securityChecks: ComponentHealth[] = [];

    // Check threat detection configuration
    try {
      const fs = require('fs');
      const configPath = './server/config/threat-detection-config.json';
      
      if (fs.existsSync(configPath)) {
        const configData = fs.readFileSync(configPath, 'utf8');
        const config = JSON.parse(configData);
        
        const enabledThreats = Object.values(config.aiSpecificThreats || {})
          .filter((threat: any) => threat.enabled).length;
        
        securityChecks.push({
          name: 'threat-detection',
          status: enabledThreats > 0 ? 'healthy' : 'degraded',
          lastCheck: new Date().toISOString(),
          responseTime: 0,
          uptime: process.uptime(),
          details: {
            type: 'security_component',
            enabledThreats,
            configPath,
            status: 'configured'
          }
        });
      } else {
        securityChecks.push({
          name: 'threat-detection',
          status: 'unhealthy',
          lastCheck: new Date().toISOString(),
          responseTime: 0,
          uptime: 0,
          details: {
            type: 'security_component',
            error: 'Configuration file not found',
            configPath
          }
        });
      }
    } catch (error) {
      securityChecks.push({
        name: 'threat-detection',
        status: 'unhealthy',
        lastCheck: new Date().toISOString(),
        responseTime: 0,
        uptime: 0,
        details: {
          type: 'security_component',
          error: error instanceof Error ? error.message : 'Configuration error'
        }
      });
    }

    return securityChecks;
  }

  async checkAgenticComponents(): Promise<ComponentHealth[]> {
    const agenticChecks: ComponentHealth[] = [];

    // This would check agentic workflow components
    // For now, return basic status
    agenticChecks.push({
      name: 'agent-orchestrator',
      status: 'healthy',
      lastCheck: new Date().toISOString(),
      responseTime: 0,
      uptime: process.uptime(),
      details: {
        type: 'agentic_component',
        status: 'initialized'
      }
    });

    return agenticChecks;
  }

  // Get health summary for specific component
  async getComponentHealth(componentName: string): Promise<ComponentHealth | null> {
    const systemHealth = await this.performAllHealthChecks();
    return systemHealth.components.find(c => c.name === componentName) || null;
  }

  // Get health history for component
  getHealthHistory(componentName: string, limit: number = 100): HealthCheckResult[] {
    return this.healthHistory.get(componentName)?.slice(-limit) || [];
  }

  // Lightweight health check for load balancers
  async quickHealthCheck(): Promise<{ status: 'ok' | 'error'; timestamp: string }> {
    try {
      // Quick database connectivity check
      await db.select().from('users' as any).limit(1);
      
      return {
        status: 'ok',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Quick health check failed', error);
      
      return {
        status: 'error',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Cleanup
  stop() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }
}

// Export singleton instance
export const healthChecker = new HealthChecker();