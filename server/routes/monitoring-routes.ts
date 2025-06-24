/**
 * Monitoring and Health Check API Routes
 * Provides endpoints for system health monitoring, metrics, and alerting
 */

import express from 'express';
import { HealthCheckerService, HealthStatus, AlertSeverity } from '../monitoring/health-checker';
import { NotificationManager } from '../monitoring/notification-manager';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

const router = express.Router();

// Initialize monitoring services
const healthChecker = new HealthCheckerService();
const notificationManager = new NotificationManager();

// Rate limiting for monitoring endpoints
const monitoringRateLimit = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // Limit each IP to 60 requests per minute
  message: 'Too many monitoring requests from this IP'
});

router.use(monitoringRateLimit);

// Validation schemas
const ThresholdUpdateSchema = z.object({
  responseTime: z.number().positive().optional(),
  errorRate: z.number().min(0).max(100).optional(),
  cpuUsage: z.number().min(0).max(100).optional(),
  memoryUsage: z.number().min(0).max(100).optional(),
  diskUsage: z.number().min(0).max(100).optional(),
  queryLatency: z.number().positive().optional(),
  agentHealthScore: z.number().min(0).max(100).optional(),
  complianceScore: z.number().min(0).max(100).optional()
});

const NotificationChannelSchema = z.object({
  name: z.string().min(1).max(50),
  type: z.enum(['email', 'slack', 'pagerduty', 'sms', 'webhook', 'teams', 'servicenow']),
  enabled: z.boolean().default(true),
  config: z.object({
    slack: z.object({
      webhookUrl: z.string().url(),
      channel: z.string(),
      username: z.string().optional(),
      iconEmoji: z.string().optional()
    }).optional(),
    email: z.object({
      smtp: z.object({
        host: z.string(),
        port: z.number(),
        secure: z.boolean(),
        auth: z.object({
          user: z.string(),
          pass: z.string()
        }),
        from: z.string().email(),
        to: z.array(z.string().email())
      })
    }).optional(),
    pagerduty: z.object({
      integrationKey: z.string(),
      severity: z.string().optional()
    }).optional(),
    webhook: z.object({
      url: z.string().url(),
      method: z.enum(['POST', 'PUT']),
      headers: z.record(z.string()),
      timeout: z.number().positive()
    }).optional()
  })
});

// Middleware for authentication (simplified for demo)
const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // In production, implement proper JWT verification
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Mock user context
  (req as any).user = { id: 'user-123', roles: ['admin'] };
  next();
};

// Middleware for admin permissions
const requireAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const user = (req as any).user;
  if (!user || !user.roles.includes('admin')) {
    return res.status(403).json({ error: 'Administrator permissions required' });
  }
  next();
};

// =============================================================================
// Health Check Endpoints
// =============================================================================

/**
 * Get comprehensive system health status
 */
router.get('/health', async (req, res) => {
  try {
    const healthStatus = await healthChecker.getSystemHealth();
    
    res.json({
      success: true,
      health: healthStatus,
      message: `System status: ${healthStatus.status}`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get system health',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get basic health check (lightweight)
 */
router.get('/health/basic', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    success: true,
    status: 'healthy',
    uptime: uptime,
    timestamp: new Date().toISOString(),
    memory: {
      used: Math.round(memoryUsage.heapUsed / 1024 / 1024),
      total: Math.round(memoryUsage.heapTotal / 1024 / 1024),
      external: Math.round(memoryUsage.external / 1024 / 1024)
    },
    version: process.env.APP_VERSION || '1.0.0'
  });
});

/**
 * Get health status for specific component
 */
router.get('/health/:component', async (req, res) => {
  try {
    const { component } = req.params;
    const healthStatus = await healthChecker.getSystemHealth();
    
    const componentHealth = healthStatus.components[component as keyof typeof healthStatus.components];
    
    if (!componentHealth) {
      return res.status(404).json({
        success: false,
        error: 'Component not found',
        available_components: Object.keys(healthStatus.components)
      });
    }
    
    res.json({
      success: true,
      component: componentHealth,
      message: `${component} status: ${componentHealth.status}`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get component health',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// =============================================================================
// Metrics Endpoints
// =============================================================================

/**
 * Get system metrics
 */
router.get('/metrics', async (req, res) => {
  try {
    const healthStatus = await healthChecker.getSystemHealth();
    
    res.json({
      success: true,
      metrics: healthStatus.metrics,
      timestamp: healthStatus.timestamp,
      message: 'Metrics retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get system metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get metrics for specific category
 */
router.get('/metrics/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const healthStatus = await healthChecker.getSystemHealth();
    
    const categoryMetrics = healthStatus.metrics[category as keyof typeof healthStatus.metrics];
    
    if (!categoryMetrics) {
      return res.status(404).json({
        success: false,
        error: 'Metrics category not found',
        available_categories: Object.keys(healthStatus.metrics)
      });
    }
    
    res.json({
      success: true,
      category,
      metrics: categoryMetrics,
      timestamp: healthStatus.timestamp,
      message: `${category} metrics retrieved successfully`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get category metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get Prometheus-formatted metrics
 */
router.get('/metrics/prometheus', async (req, res) => {
  try {
    const healthStatus = await healthChecker.getSystemHealth();
    
    // Convert metrics to Prometheus format
    const prometheusMetrics = convertToPrometheusFormat(healthStatus);
    
    res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(prometheusMetrics);
  } catch (error) {
    res.status(500).text('# Error: Failed to generate Prometheus metrics');
  }
});

// =============================================================================
// Alert Management Endpoints
// =============================================================================

/**
 * Get recent alerts
 */
router.get('/alerts', requireAuth, async (req, res) => {
  try {
    const { limit = 50, severity, component } = req.query;
    
    let alerts = healthChecker.getRecentAlerts(Number(limit));
    
    // Filter by severity if specified
    if (severity) {
      alerts = alerts.filter(alert => alert.severity === severity);
    }
    
    // Filter by component if specified
    if (component) {
      alerts = alerts.filter(alert => alert.component === component);
    }
    
    res.json({
      success: true,
      alerts,
      total: alerts.length,
      message: 'Alerts retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get alerts',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Acknowledge alert
 */
router.post('/alerts/:alertId/acknowledge', requireAuth, async (req, res) => {
  try {
    const { alertId } = req.params;
    const userId = (req as any).user.id;
    
    notificationManager.acknowledgeAlert(alertId, userId);
    
    res.json({
      success: true,
      message: 'Alert acknowledged successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to acknowledge alert',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Test alert notification
 */
router.post('/alerts/test', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { channels, severity = 'info' } = req.body;
    
    if (!Array.isArray(channels) || channels.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Channels array is required'
      });
    }
    
    const testAlert = {
      id: `test-${Date.now()}`,
      name: 'test_notification',
      description: 'This is a test notification from AI-SPM monitoring system',
      severity: severity as AlertSeverity,
      component: 'monitoring_system',
      timestamp: new Date(),
      tags: ['test', 'monitoring']
    };
    
    const results = await notificationManager.sendAlert(testAlert, channels);
    
    res.json({
      success: true,
      alert: testAlert,
      results,
      message: 'Test alert sent successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to send test alert',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// =============================================================================
// Configuration Endpoints
// =============================================================================

/**
 * Update alert thresholds
 */
router.put('/config/thresholds', requireAuth, requireAdmin, async (req, res) => {
  try {
    const thresholds = ThresholdUpdateSchema.parse(req.body);
    
    healthChecker.updateThresholds(thresholds);
    
    res.json({
      success: true,
      thresholds,
      message: 'Alert thresholds updated successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      });
    }
    
    res.status(500).json({
      success: false,
      error: 'Failed to update thresholds',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get notification channels
 */
router.get('/config/channels', requireAuth, async (req, res) => {
  try {
    const channels = notificationManager.getChannels();
    
    // Remove sensitive information
    const sanitizedChannels = channels.map(channel => ({
      ...channel,
      config: {
        ...Object.keys(channel.config).reduce((acc, key) => {
          acc[key] = '[CONFIGURED]';
          return acc;
        }, {} as any)
      }
    }));
    
    res.json({
      success: true,
      channels: sanitizedChannels,
      message: 'Notification channels retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get notification channels',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Add notification channel
 */
router.post('/config/channels', requireAuth, requireAdmin, async (req, res) => {
  try {
    const channelData = NotificationChannelSchema.parse(req.body);
    
    notificationManager.addChannel(channelData);
    
    res.status(201).json({
      success: true,
      channel: {
        ...channelData,
        config: '[CONFIGURED]' // Don't return sensitive config
      },
      message: 'Notification channel added successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      });
    }
    
    res.status(500).json({
      success: false,
      error: 'Failed to add notification channel',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Remove notification channel
 */
router.delete('/config/channels/:channelName', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { channelName } = req.params;
    
    notificationManager.removeChannel(channelName);
    
    res.json({
      success: true,
      message: 'Notification channel removed successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to remove notification channel',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get active escalations
 */
router.get('/escalations', requireAuth, async (req, res) => {
  try {
    const escalations = notificationManager.getActiveEscalations();
    
    res.json({
      success: true,
      escalations,
      total: escalations.length,
      message: 'Active escalations retrieved successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to get active escalations',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert metrics to Prometheus format
 */
function convertToPrometheusFormat(healthStatus: any): string {
  const lines: string[] = [];
  const timestamp = Date.now();
  
  // System health status
  lines.push(`# HELP ai_spm_system_health System health status (0=unhealthy, 1=degraded, 2=healthy)`);
  lines.push(`# TYPE ai_spm_system_health gauge`);
  const healthValue = healthStatus.status === 'healthy' ? 2 : healthStatus.status === 'degraded' ? 1 : 0;
  lines.push(`ai_spm_system_health ${healthValue} ${timestamp}`);
  
  // Application metrics
  const appMetrics = healthStatus.metrics.application;
  lines.push(`# HELP ai_spm_api_response_time_ms API response time in milliseconds`);
  lines.push(`# TYPE ai_spm_api_response_time_ms gauge`);
  lines.push(`ai_spm_api_response_time_ms ${appMetrics.apiGateway.responseTime} ${timestamp}`);
  
  lines.push(`# HELP ai_spm_api_throughput_rps API throughput in requests per second`);
  lines.push(`# TYPE ai_spm_api_throughput_rps gauge`);
  lines.push(`ai_spm_api_throughput_rps ${appMetrics.apiGateway.throughput} ${timestamp}`);
  
  lines.push(`# HELP ai_spm_api_error_rate_percent API error rate percentage`);
  lines.push(`# TYPE ai_spm_api_error_rate_percent gauge`);
  lines.push(`ai_spm_api_error_rate_percent ${appMetrics.apiGateway.errorRate} ${timestamp}`);
  
  // Infrastructure metrics
  const infraMetrics = healthStatus.metrics.infrastructure;
  lines.push(`# HELP ai_spm_cpu_usage_percent CPU usage percentage`);
  lines.push(`# TYPE ai_spm_cpu_usage_percent gauge`);
  lines.push(`ai_spm_cpu_usage_percent ${infraMetrics.compute.cpuUsage} ${timestamp}`);
  
  lines.push(`# HELP ai_spm_memory_usage_percent Memory usage percentage`);
  lines.push(`# TYPE ai_spm_memory_usage_percent gauge`);
  lines.push(`ai_spm_memory_usage_percent ${infraMetrics.compute.memoryUsage} ${timestamp}`);
  
  // Agentic workflow metrics
  const agenticMetrics = healthStatus.metrics.agentic;
  lines.push(`# HELP ai_spm_active_agents Number of active agents`);
  lines.push(`# TYPE ai_spm_active_agents gauge`);
  lines.push(`ai_spm_active_agents ${agenticMetrics.agents.activeAgents} ${timestamp}`);
  
  lines.push(`# HELP ai_spm_agent_health_score Average agent health score`);
  lines.push(`# TYPE ai_spm_agent_health_score gauge`);
  lines.push(`ai_spm_agent_health_score ${agenticMetrics.agents.averageHealthScore} ${timestamp}`);
  
  return lines.join('\n') + '\n';
}

// Set up event listeners for real-time monitoring
healthChecker.on('alert', (alert) => {
  console.log(`New alert generated: ${alert.name} (${alert.severity})`);
  
  // Auto-escalate critical alerts
  if (alert.severity === AlertSeverity.CRITICAL) {
    notificationManager.startEscalation(alert, 'critical').catch(error => {
      console.error('Failed to start escalation:', error);
    });
  }
});

healthChecker.on('healthCheckCompleted', (event) => {
  console.log(`Health check completed in ${event.duration.toFixed(2)}ms - Status: ${event.status.status}`);
});

notificationManager.on('notificationSent', (event) => {
  console.log(`Notification sent via ${event.channel} for alert ${event.alert.id}`);
});

notificationManager.on('escalationStarted', (event) => {
  console.log(`Escalation started for alert ${event.alert.id} using policy ${event.policy.name}`);
});

export { router as monitoringRoutes };