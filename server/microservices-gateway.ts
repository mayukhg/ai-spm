/**
 * Microservices Gateway - Simplified routing and orchestration
 * 
 * This gateway provides:
 * - Service discovery and health monitoring
 * - Request routing to Python microservices
 * - Centralized logging and error handling
 * - Authentication context forwarding
 */

import { Request, Response, NextFunction } from 'express';

export interface ServiceConfig {
  name: string;
  url: string;
  healthEndpoint: string;
  timeout: number;
  retries: number;
}

export interface GatewayRequest extends Request {
  user?: any;
  correlationId?: string;
}

/**
 * Service registry for microservices management
 */
export class ServiceProxy {
  constructor(private registry: MicroserviceRegistry) {}

  async proxyRequest(serviceName: string, path: string, method: string, body?: any): Promise<any> {
    // Simplified proxy for development - in production this would make actual HTTP calls
    console.log(`Proxying ${method} ${path} to ${serviceName} service`);
    
    // Return mock response for development
    return {
      json: async () => ({
        message: `${serviceName} service response`,
        service: serviceName,
        path,
        method,
        timestamp: new Date().toISOString()
      })
    };
  }
}

export class MicroserviceRegistry {
  private services: Map<string, ServiceConfig> = new Map();
  private healthStatus: Map<string, boolean> = new Map();

  constructor() {
    this.initializeServices();
    this.startHealthMonitoring();
  }

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

  private startHealthMonitoring() {
    // Simplified health monitoring without fetch for now
    setInterval(() => {
      console.log('Health check cycle - microservices monitoring');
      // Health checks would be implemented when microservices are deployed
    }, 30000);
  }

  getService(name: string): ServiceConfig | undefined {
    return this.services.get(name);
  }

  isServiceHealthy(name: string): boolean {
    return this.healthStatus.get(name) || false;
  }

  getHealthStatus(): Record<string, boolean> {
    return Object.fromEntries(this.healthStatus);
  }
}

/**
 * Middleware for request correlation and context
 */
export function gatewayMiddleware(req: GatewayRequest, res: Response, next: NextFunction) {
  req.correlationId = req.headers['x-correlation-id'] as string || 
                     `gw-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  res.setHeader('X-Correlation-ID', req.correlationId);
  console.log(`[${req.correlationId}] ${req.method} ${req.path} - ${req.ip}`);
  
  next();
}

/**
 * Gateway error handler
 */
export function gatewayErrorHandler(
  error: Error,
  req: GatewayRequest,
  res: Response,
  next: NextFunction
) {
  const correlationId = req.correlationId || 'unknown';
  console.error(`[${correlationId}] Gateway error:`, error);

  if (error.message.includes('service unavailable')) {
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'The requested microservice is not available',
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
 * Health check endpoint
 */
export function createHealthEndpoint(registry: MicroserviceRegistry) {
  return (req: Request, res: Response) => {
    const servicesHealth = registry.getHealthStatus();
    const allHealthy = Object.values(servicesHealth).every(status => status);

    res.status(allHealthy ? 200 : 503).json({
      status: allHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      services: servicesHealth,
      gateway: {
        uptime: process.uptime(),
        version: '1.0.0'
      }
    });
  };
}