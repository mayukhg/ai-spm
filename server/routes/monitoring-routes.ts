/**
 * Monitoring and Observability API Routes
 * Comprehensive system monitoring and health endpoints
 */

import express from 'express';
import { logger, SecurityEventType } from '../monitoring/logger';
import { metrics } from '../monitoring/metrics-collector';
import { healthChecker } from '../monitoring/health-checker';
import { notificationManager } from '../monitoring/notification-manager';

const router = express.Router();

// Middleware for authentication (simplified for demo)
const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // In production, implement proper JWT verification
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Mock user context
  (req as any).user = { id: 'user-123', roles: ['security_admin'] };
  next();
};

/**
 * Get comprehensive system health status
 */
router.get('/health', async (req, res) => {
  try {
    const health = await healthChecker.performAllHealthChecks();
    
    // Log health check request
    logger.info('System health check requested', {
      overallStatus: health.overall,
      componentCount: health.components.length,
      requestedBy: (req as any).user?.id || 'anonymous'
    });
    
    res.status(health.overall === 'unhealthy' ? 503 : 200).json({
      success: true,
      health,
      message: 'System health status retrieved successfully'
    });
  } catch (error) {
    logger.error('Failed to get system health', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve system health',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get health status for specific component
 */
router.get('/health/:component', async (req, res) => {
  try {
    const { component } = req.params;
    const componentHealth = await healthChecker.getComponentHealth(component);
    
    if (!componentHealth) {
      return res.status(404).json({
        success: false,
        error: `Component '${component}' not found`
      });
    }
    
    res.json({
      success: true,
      component: componentHealth,
      message: `Health status for ${component} retrieved successfully`
    });
  } catch (error) {
    logger.error(`Failed to get health for component ${req.params.component}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve component health',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get system metrics in Prometheus format
 */
router.get('/metrics', async (req, res) => {
  try {
    const metricsData = await metrics.getMetrics();
    res.set('Content-Type', 'text/plain');
    res.send(metricsData);
  } catch (error) {
    logger.error('Failed to get metrics', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get system performance summary
 */
router.get('/performance', requireAuth, async (req, res) => {
  try {
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    const performanceData = {
      uptime: {
        seconds: uptime,
        human: formatUptime(uptime)
      },
      memory: {
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
        external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapUsedPercent: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100)
      },
      process: {
        pid: process.pid,
        version: process.version,
        platform: process.platform,
        arch: process.arch
      },
      environment: {
        nodeEnv: process.env.NODE_ENV || 'development',
        port: process.env.PORT || 5000
      }
    };
    
    res.json({
      success: true,
      performance: performanceData,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Failed to get performance data', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve performance data',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get active alerts
 */
router.get('/alerts', requireAuth, (req, res) => {
  try {
    const alerts = notificationManager.getActiveAlerts();
    
    res.json({
      success: true,
      alerts,
      count: alerts.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Failed to get alerts', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve alerts',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Acknowledge an alert
 */
router.post('/alerts/:alertId/acknowledge', requireAuth, async (req, res) => {
  try {
    const { alertId } = req.params;
    const acknowledgedBy = (req as any).user?.id || 'unknown';
    
    await notificationManager.acknowledgeAlert(alertId, acknowledgedBy);
    
    logger.audit('alert_acknowledged', `alert:${alertId}`, {
      alertId,
      acknowledgedBy,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      success: true,
      message: `Alert ${alertId} acknowledged successfully`,
      acknowledgedBy,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error(`Failed to acknowledge alert ${req.params.alertId}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to acknowledge alert',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Resolve an alert
 */
router.post('/alerts/:alertId/resolve', requireAuth, async (req, res) => {
  try {
    const { alertId } = req.params;
    const resolvedBy = (req as any).user?.id || 'unknown';
    
    await notificationManager.resolveAlert(alertId, resolvedBy);
    
    logger.audit('alert_resolved', `alert:${alertId}`, {
      alertId,
      resolvedBy,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      success: true,
      message: `Alert ${alertId} resolved successfully`,
      resolvedBy,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error(`Failed to resolve alert ${req.params.alertId}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to resolve alert',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Test notification channels
 */
router.post('/notifications/test/:channel', requireAuth, async (req, res) => {
  try {
    const { channel } = req.params;
    const success = await notificationManager.testChannel(channel);
    
    logger.audit('notification_test', `channel:${channel}`, {
      channel,
      success,
      testedBy: (req as any).user?.id,
      timestamp: new Date().toISOString()
    });
    
    res.json({
      success,
      message: success 
        ? `Test notification sent successfully to ${channel}`
        : `Test notification failed for ${channel}`,
      channel,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error(`Failed to test notification channel ${req.params.channel}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to test notification channel',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get notification channels status
 */
router.get('/notifications/channels', requireAuth, (req, res) => {
  try {
    const channels = notificationManager.getChannelsStatus();
    
    res.json({
      success: true,
      channels,
      count: channels.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Failed to get notification channels', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve notification channels',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Create test alert for demonstration
 */
router.post('/alerts/test', requireAuth, async (req, res) => {
  try {
    const { severity = 'medium', type = 'test', message = 'Test alert from monitoring system' } = req.body;
    
    const testAlert = {
      id: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      severity,
      title: 'Test Alert',
      message,
      source: 'monitoring-api',
      timestamp: new Date().toISOString(),
      metadata: {
        createdBy: (req as any).user?.id,
        test: true
      }
    };
    
    await notificationManager.sendAlert(testAlert);
    
    logger.audit('test_alert_created', 'alert:test', {
      alertId: testAlert.id,
      severity,
      createdBy: (req as any).user?.id
    });
    
    res.json({
      success: true,
      alert: testAlert,
      message: 'Test alert created and sent successfully'
    });
  } catch (error) {
    logger.error('Failed to create test alert', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create test alert',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get system logs (recent entries)
 */
router.get('/logs', requireAuth, (req, res) => {
  try {
    const { level = 'info', limit = 100, category } = req.query;
    
    // This would require implementing log reading functionality
    // For now, return mock recent logs
    const recentLogs = [
      {
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'System monitoring endpoint accessed',
        category: 'application',
        correlationId: 'monitor-123'
      },
      {
        timestamp: new Date(Date.now() - 60000).toISOString(),
        level: 'info',
        message: 'Health check completed successfully',
        category: 'system',
        correlationId: 'health-456'
      }
    ];
    
    res.json({
      success: true,
      logs: recentLogs,
      count: recentLogs.length,
      filters: { level, limit, category },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Failed to get logs', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve logs',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Utility function to format uptime
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0) parts.push(`${secs}s`);
  
  return parts.join(' ') || '0s';
}

export { router as monitoringRoutes };