/**
 * Comprehensive Logging System for AI-SPM Platform
 * Structured logging with security event correlation and audit trails
 */

import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';

// Define log levels with severity
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  verbose: 4,
  debug: 5,
  silly: 6
};

// Security event types for structured logging
export enum SecurityEventType {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  DATA_ACCESS = 'data_access',
  AI_THREAT_DETECTION = 'ai_threat_detection',
  COMPLIANCE_VIOLATION = 'compliance_violation',
  SYSTEM_SECURITY = 'system_security',
  AGENT_SECURITY = 'agent_security',
  MCP_SECURITY = 'mcp_security'
}

// Log categories for organized logging
export enum LogCategory {
  APPLICATION = 'application',
  SECURITY = 'security',
  AUDIT = 'audit',
  PERFORMANCE = 'performance',
  BUSINESS = 'business',
  SYSTEM = 'system',
  AGENTIC = 'agentic'
}

interface LogMetadata {
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
  resource?: string;
  action?: string;
  category?: LogCategory;
  securityEvent?: SecurityEventType;
  agentId?: string;
  workflowId?: string;
  assetId?: string;
  threatType?: string;
  complianceFramework?: string;
  [key: string]: any;
}

class AISecurityLogger {
  private logger: winston.Logger;
  private securityLogger: winston.Logger;
  private auditLogger: winston.Logger;
  private performanceLogger: winston.Logger;
  private agenticLogger: winston.Logger;

  constructor() {
    this.setupLoggers();
  }

  private setupLoggers() {
    // Base log format
    const baseFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.errors({ stack: true }),
      winston.format.json(),
      winston.format.printf((info) => {
        const { timestamp, level, message, ...meta } = info;
        return JSON.stringify({
          timestamp,
          level: level.toUpperCase(),
          message,
          ...meta,
          environment: process.env.NODE_ENV || 'development',
          service: 'ai-spm-platform',
          version: process.env.APP_VERSION || '1.0.0'
        });
      })
    );

    // Console format for development
    const consoleFormat = winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'HH:mm:ss' }),
      winston.format.printf((info) => {
        const { timestamp, level, message, correlationId, category } = info;
        const prefix = correlationId ? `[${correlationId}]` : '';
        const categoryPrefix = category ? `[${category}]` : '';
        return `${timestamp} ${level}${prefix}${categoryPrefix}: ${message}`;
      })
    );

    // Create logs directory
    const logsDir = path.join(process.cwd(), 'logs');

    // Main application logger
    this.logger = winston.createLogger({
      levels: logLevels,
      level: process.env.LOG_LEVEL || 'info',
      format: baseFormat,
      transports: [
        // Console output for development
        new winston.transports.Console({
          format: process.env.NODE_ENV === 'development' ? consoleFormat : baseFormat,
          level: process.env.NODE_ENV === 'development' ? 'debug' : 'info'
        }),

        // Application logs with rotation
        new DailyRotateFile({
          filename: path.join(logsDir, 'application-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: '100m',
          maxFiles: '30d',
          level: 'info'
        }),

        // Error logs
        new DailyRotateFile({
          filename: path.join(logsDir, 'error-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: '50m',
          maxFiles: '90d',
          level: 'error'
        }),

        // Debug logs (development only)
        ...(process.env.NODE_ENV === 'development' ? [
          new DailyRotateFile({
            filename: path.join(logsDir, 'debug-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            maxSize: '200m',
            maxFiles: '7d',
            level: 'debug'
          })
        ] : [])
      ]
    });

    // Security-specific logger
    this.securityLogger = winston.createLogger({
      levels: logLevels,
      level: 'info',
      format: baseFormat,
      transports: [
        new DailyRotateFile({
          filename: path.join(logsDir, 'security-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: '200m',
          maxFiles: '365d', // Keep security logs for 1 year
          level: 'info'
        }),
        new winston.transports.Console({
          format: consoleFormat,
          level: 'warn'
        })
      ]
    });

    // Audit logger (immutable audit trail)
    this.auditLogger = winston.createLogger({
      levels: logLevels,
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
        winston.format.json(),
        winston.format.printf((info) => {
          return JSON.stringify({
            ...info,
            auditHash: this.generateAuditHash(info),
            immutable: true
          });
        })
      ),
      transports: [
        new DailyRotateFile({
          filename: path.join(logsDir, 'audit-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: '500m',
          maxFiles: '2555d', // Keep audit logs for 7 years for compliance
          level: 'info'
        })
      ]
    });

    // Performance logger
    this.performanceLogger = winston.createLogger({
      levels: logLevels,
      level: 'info',
      format: baseFormat,
      transports: [
        new DailyRotateFile({
          filename: path.join(logsDir, 'performance-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: '100m',
          maxFiles: '30d',
          level: 'info'
        })
      ]
    });

    // Agentic workflows logger
    this.agenticLogger = winston.createLogger({
      levels: logLevels,
      level: 'info',
      format: baseFormat,
      transports: [
        new DailyRotateFile({
          filename: path.join(logsDir, 'agentic-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxSize: '200m',
          maxFiles: '90d',
          level: 'info'
        }),
        new winston.transports.Console({
          format: consoleFormat,
          level: 'info'
        })
      ]
    });

    // Handle uncaught exceptions and rejections
    this.logger.exceptions.handle(
      new DailyRotateFile({
        filename: path.join(logsDir, 'exceptions-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxSize: '50m',
        maxFiles: '90d'
      })
    );

    this.logger.rejections.handle(
      new DailyRotateFile({
        filename: path.join(logsDir, 'rejections-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxSize: '50m',
        maxFiles: '90d'
      })
    );
  }

  private generateAuditHash(logEntry: any): string {
    // Simple hash for audit integrity (in production, use cryptographic hash)
    const crypto = require('crypto');
    const data = JSON.stringify(logEntry);
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  // Application logging methods
  info(message: string, metadata?: LogMetadata) {
    this.logger.info(message, { category: LogCategory.APPLICATION, ...metadata });
  }

  error(message: string, error?: Error, metadata?: LogMetadata) {
    this.logger.error(message, {
      category: LogCategory.APPLICATION,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack
      } : undefined,
      ...metadata
    });
  }

  warn(message: string, metadata?: LogMetadata) {
    this.logger.warn(message, { category: LogCategory.APPLICATION, ...metadata });
  }

  debug(message: string, metadata?: LogMetadata) {
    this.logger.debug(message, { category: LogCategory.APPLICATION, ...metadata });
  }

  // Security event logging
  security(eventType: SecurityEventType, message: string, metadata?: LogMetadata) {
    const securityMetadata = {
      category: LogCategory.SECURITY,
      securityEvent: eventType,
      severity: this.getSecuritySeverity(eventType),
      ...metadata
    };

    this.securityLogger.info(message, securityMetadata);
    
    // Also log to main logger for correlation
    this.logger.info(`SECURITY: ${message}`, securityMetadata);
  }

  // Audit trail logging (immutable)
  audit(action: string, resource: string, metadata?: LogMetadata) {
    const auditMetadata = {
      category: LogCategory.AUDIT,
      action,
      resource,
      compliance: true,
      ...metadata
    };

    this.auditLogger.info(`AUDIT: ${action} on ${resource}`, auditMetadata);
  }

  // Performance logging
  performance(operation: string, duration: number, metadata?: LogMetadata) {
    const perfMetadata = {
      category: LogCategory.PERFORMANCE,
      operation,
      duration,
      durationMs: duration,
      ...metadata
    };

    this.performanceLogger.info(`PERFORMANCE: ${operation} took ${duration}ms`, perfMetadata);
  }

  // Agentic workflow logging
  agentic(event: string, metadata?: LogMetadata) {
    const agenticMetadata = {
      category: LogCategory.AGENTIC,
      ...metadata
    };

    this.agenticLogger.info(`AGENTIC: ${event}`, agenticMetadata);
  }

  // AI threat detection logging
  threatDetection(threatType: string, severity: string, details: any, metadata?: LogMetadata) {
    const threatMetadata = {
      category: LogCategory.SECURITY,
      securityEvent: SecurityEventType.AI_THREAT_DETECTION,
      threatType,
      severity,
      details,
      ...metadata
    };

    this.securityLogger.warn(`AI THREAT DETECTED: ${threatType}`, threatMetadata);
    this.audit('threat_detected', `ai_threat:${threatType}`, threatMetadata);
  }

  // Compliance violation logging
  complianceViolation(framework: string, violation: string, metadata?: LogMetadata) {
    const complianceMetadata = {
      category: LogCategory.SECURITY,
      securityEvent: SecurityEventType.COMPLIANCE_VIOLATION,
      complianceFramework: framework,
      violation,
      ...metadata
    };

    this.securityLogger.error(`COMPLIANCE VIOLATION: ${framework} - ${violation}`, complianceMetadata);
    this.audit('compliance_violation', `framework:${framework}`, complianceMetadata);
  }

  // HTTP request logging
  http(method: string, url: string, statusCode: number, duration: number, metadata?: LogMetadata) {
    const httpMetadata = {
      category: LogCategory.APPLICATION,
      method,
      url,
      statusCode,
      duration,
      ...metadata
    };

    const level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info';
    this.logger.log(level, `${method} ${url} ${statusCode} - ${duration}ms`, httpMetadata);
  }

  private getSecuritySeverity(eventType: SecurityEventType): string {
    const severityMap = {
      [SecurityEventType.AI_THREAT_DETECTION]: 'high',
      [SecurityEventType.COMPLIANCE_VIOLATION]: 'critical',
      [SecurityEventType.AUTHENTICATION]: 'medium',
      [SecurityEventType.AUTHORIZATION]: 'high',
      [SecurityEventType.DATA_ACCESS]: 'medium',
      [SecurityEventType.SYSTEM_SECURITY]: 'high',
      [SecurityEventType.AGENT_SECURITY]: 'high',
      [SecurityEventType.MCP_SECURITY]: 'critical'
    };
    return severityMap[eventType] || 'medium';
  }

  // Create child logger with persistent metadata
  child(metadata: LogMetadata) {
    return {
      info: (message: string, additionalMeta?: LogMetadata) => 
        this.info(message, { ...metadata, ...additionalMeta }),
      error: (message: string, error?: Error, additionalMeta?: LogMetadata) => 
        this.error(message, error, { ...metadata, ...additionalMeta }),
      warn: (message: string, additionalMeta?: LogMetadata) => 
        this.warn(message, { ...metadata, ...additionalMeta }),
      debug: (message: string, additionalMeta?: LogMetadata) => 
        this.debug(message, { ...metadata, ...additionalMeta }),
      security: (eventType: SecurityEventType, message: string, additionalMeta?: LogMetadata) => 
        this.security(eventType, message, { ...metadata, ...additionalMeta }),
      audit: (action: string, resource: string, additionalMeta?: LogMetadata) => 
        this.audit(action, resource, { ...metadata, ...additionalMeta })
    };
  }
}

// Export singleton instance
export const logger = new AISecurityLogger();

// Export middleware for Express
export const requestLoggingMiddleware = (req: any, res: any, next: any) => {
  const startTime = Date.now();
  const correlationId = req.headers['x-correlation-id'] || 
    require('crypto').randomBytes(8).toString('hex');
  
  // Add correlation ID to request
  req.correlationId = correlationId;
  res.setHeader('X-Correlation-ID', correlationId);

  // Create request-scoped logger
  req.logger = logger.child({
    correlationId,
    requestId: req.id || correlationId,
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    sessionId: req.sessionID
  });

  // Log request
  req.logger.info(`Request started: ${req.method} ${req.originalUrl}`, {
    method: req.method,
    url: req.originalUrl,
    query: req.query,
    headers: {
      'content-type': req.get('Content-Type'),
      'content-length': req.get('Content-Length'),
      'authorization': req.get('Authorization') ? '[REDACTED]' : undefined
    }
  });

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(...args: any[]) {
    const duration = Date.now() - startTime;
    
    logger.http(req.method, req.originalUrl, res.statusCode, duration, {
      correlationId,
      userId: req.user?.id,
      responseSize: res.get('Content-Length')
    });

    originalEnd.apply(res, args);
  };

  next();
};

export { LogMetadata };