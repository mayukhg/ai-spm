/**
 * API Gateway - Central routing and orchestration for microservices
 * 
 * This gateway handles:
 * - Request routing to appropriate services
 * - Authentication and authorization
 * - Rate limiting and security
 * - Request/response transformation
 * - Service discovery and load balancing
 * - Centralized logging and monitoring
 */

import express from 'express';
import { Request, Response as ExpressResponse, NextFunction } from 'express';
import fetch from 'node-fetch';
import { z } from 'zod';

export interface ServiceConfig {
  name: string;
  url: string;
  healthEndpoint: string;
  timeout: number;
  retries: number;
}

export interface GatewayRequest extends Request {
  user?: any;
  serviceContext?: {
    correlationId: string;
    timestamp: number;
    service: string;
  };
}

/**
 * Service registry for microservices discovery and health monitoring
 */
export class ServiceRegistry {
  private services: Map<string, ServiceConfig> = new Map();
  private healthStatus: Map<string, boolean> = new Map();

  constructor() {
    this.initializeServices();
    this.startHealthChecks();
  }

  /**
   * Initialize default service configurations
   */
  private initializeServices() {
    const services: ServiceConfig[] = [
      {
        name: 'ai-scanner',
        url: process.env.AI_SCANNER_SERVICE_URL || 'http://localhost:8001',
        healthEndpoint: '/health',
        timeout: 30000,
        retries: 3
      },
      {
        name: 'data-integrity',
        url: process.env.DATA_INTEGRITY_SERVICE_URL || 'http://localhost:8002',
        healthEndpoint: '/health',
        timeout: 15000,
        retries: 2
      },
      {
        name: 'wiz-integration',
        url: process.env.WIZ_INTEGRATION_SERVICE_URL || 'http://localhost:8003',
        healthEndpoint: '/health',
        timeout: 10000,
        retries: 2
      },
      {
        name: 'compliance-engine',
        url: process.env.COMPLIANCE_ENGINE_SERVICE_URL || 'http://localhost:8004',
        healthEndpoint: '/health',
        timeout: 20000,
        retries: 3
      }
    ];

    services.forEach(service => {
      this.services.set(service.name, service);
      this.healthStatus.set(service.name, false);
    });
  }

  /**
   * Start periodic health checks for all registered services
   */
  private startHealthChecks() {
    setInterval(async () => {
      for (const [serviceName, config] of Array.from(this.services.entries())) {
        try {
          const response = await fetch(`${config.url}${config.healthEndpoint}`, {
            method: 'GET'
          });
          this.healthStatus.set(serviceName, response.ok);
        } catch (error) {
          console.warn(`Health check failed for service ${serviceName}:`, error);
          this.healthStatus.set(serviceName, false);
        }
      }
    }, 30000); // Check every 30 seconds
  }

  /**
   * Get service configuration by name
   */
  getService(name: string): ServiceConfig | undefined {
    return this.services.get(name);
  }

  /**
   * Check if service is healthy
   */
  isServiceHealthy(name: string): boolean {
    return this.healthStatus.get(name) || false;
  }

  /**
   * Get all services health status
   */
  getHealthStatus(): Record<string, boolean> {
    return Object.fromEntries(this.healthStatus);
  }
}

/**
 * Request proxy with retry logic and error handling
 */
export class ServiceProxy {
  constructor(private registry: ServiceRegistry) {}

  /**
   * Proxy request to microservice with retry logic
   */
  async proxyRequest(
    serviceName: string,
    path: string,
    method: string,
    body?: any,
    headers?: Record<string, string>
  ): Promise<Response> {
    const service = this.registry.getService(serviceName);
    if (!service) {
      throw new Error(`Service ${serviceName} not found in registry`);
    }

    if (!this.registry.isServiceHealthy(serviceName)) {
      throw new Error(`Service ${serviceName} is currently unhealthy`);
    }

    let lastError: Error;
    
    for (let attempt = 0; attempt < service.retries; attempt++) {
      try {
        const url = `${service.url}${path}`;
        const requestOptions: any = {
          method,
          headers: {
            'Content-Type': 'application/json',
            'X-Correlation-ID': this.generateCorrelationId(),
            ...headers
          },
          timeout: service.timeout
        };

        if (body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
          requestOptions.body = JSON.stringify(body);
        }

        const response = await fetch(url, requestOptions);
        
        if (!response.ok) {
          throw new Error(`Service ${serviceName} returned ${response.status}: ${response.statusText}`);
        }

        return response;
      } catch (error) {
        lastError = error as Error;
        console.warn(`Attempt ${attempt + 1} failed for ${serviceName}:`, error);
        
        if (attempt < service.retries - 1) {
          await this.delay(Math.pow(2, attempt) * 1000); // Exponential backoff
        }
      }
    }

    throw new Error(`Service ${serviceName} failed after ${service.retries} attempts: ${lastError.message}`);
  }

  /**
   * Generate unique correlation ID for request tracking
   */
  private generateCorrelationId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Delay utility for retry logic
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Gateway middleware for request context and logging
 */
export function gatewayMiddleware(req: GatewayRequest, res: Response, next: NextFunction) {
  // Add service context to request
  req.serviceContext = {
    correlationId: req.headers['x-correlation-id'] as string || 
                  `gw-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: Date.now(),
    service: 'api-gateway'
  };

  // Add correlation ID to response headers
  res.setHeader('X-Correlation-ID', req.serviceContext.correlationId);

  // Log incoming request
  console.log(`[${req.serviceContext.correlationId}] ${req.method} ${req.path} - ${req.ip}`);

  next();
}

/**
 * Error handler for gateway operations
 */
export function gatewayErrorHandler(
  error: Error,
  req: GatewayRequest,
  res: Response,
  next: NextFunction
) {
  const correlationId = req.serviceContext?.correlationId || 'unknown';
  
  console.error(`[${correlationId}] Gateway error:`, error);

  if (error.message.includes('not found in registry')) {
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'The requested service is not available',
      correlationId
    });
  }

  if (error.message.includes('unhealthy')) {
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'The requested service is temporarily unavailable',
      correlationId
    });
  }

  if (error.message.includes('timeout') || error.message.includes('failed after')) {
    return res.status(504).json({
      error: 'Gateway Timeout',
      message: 'The service request timed out',
      correlationId
    });
  }

  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected error occurred',
    correlationId
  });
}

/**
 * Health check endpoint for gateway and services
 */
export function createHealthEndpoint(registry: ServiceRegistry) {
  return (req: Request, res: Response) => {
    const servicesHealth = registry.getHealthStatus();
    const allHealthy = Object.values(servicesHealth).every(status => status);

    res.status(allHealthy ? 200 : 503).json({
      status: allHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      services: servicesHealth,
      gateway: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: process.env.npm_package_version || '1.0.0'
      }
    });
  };
}