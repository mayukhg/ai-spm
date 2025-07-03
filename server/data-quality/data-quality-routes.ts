/**
 * Data Quality Routes - API endpoints for data quality monitoring
 * 
 * This module provides REST API endpoints for:
 * - Real-time data quality validation and assessment
 * - Data drift detection and monitoring
 * - Anomaly detection and analysis
 * - Quality metrics retrieval and reporting
 * - Configuration management for monitoring systems
 * 
 * Key Features:
 * - Comprehensive validation with error handling
 * - Standardized API responses with metadata
 * - Authentication and authorization integration
 * - Request logging and audit trail
 * - Performance monitoring and rate limiting
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { Router } from 'express';
import { z } from 'zod';
import { logger } from '../monitoring/logger';
import { DataQualityManager } from './data-quality-manager';
import { DataQualityStorage } from './data-quality-storage';
import { notificationManager } from '../monitoring/notification-manager';
import { 
  insertDataValidationRuleSchema, 
  insertDataQualityBaselineSchema 
} from '../../shared/schema';

// Initialize components
const storage = new DataQualityStorage();
const dataQualityManager = new DataQualityManager(storage, notificationManager);

const router = Router();

// Request validation schemas
const monitorDataQualitySchema = z.object({
  assetId: z.number().int().positive(),
  datasetName: z.string().min(1).max(255),
  currentData: z.array(z.record(z.any())).min(1),
  referenceData: z.array(z.record(z.any())).optional(),
  environment: z.enum(['training', 'inference', 'validation']).default('inference'),
});

const generateReportSchema = z.object({
  assetId: z.number().int().positive(),
  timeRange: z.enum(['1h', '6h', '24h', '7d', '30d', '90d']).default('24h'),
});

const updateConfigSchema = z.object({
  enableRealTimeMonitoring: z.boolean().optional(),
  monitoringInterval: z.number().int().min(1).max(1440).optional(), // 1 minute to 24 hours
  enableDriftDetection: z.boolean().optional(),
  enableAnomalyDetection: z.boolean().optional(),
  batchSize: z.number().int().min(100).max(10000).optional(),
  retentionDays: z.number().int().min(7).max(365).optional(),
  alertThresholds: z.object({
    qualityScoreThreshold: z.number().min(0).max(100).optional(),
    driftThreshold: z.number().min(0).max(1).optional(),
    anomalyRateThreshold: z.number().min(0).max(1).optional(),
  }).optional(),
});

/**
 * POST /api/data-quality/monitor
 * Perform comprehensive data quality monitoring for a dataset
 * 
 * Body: {
 *   assetId: number,
 *   datasetName: string,
 *   currentData: any[],
 *   referenceData?: any[],
 *   environment?: 'training' | 'inference' | 'validation'
 * }
 */
router.post('/monitor', async (req, res) => {
  try {
    const startTime = Date.now();
    
    // Validate request body
    const validation = monitorDataQualitySchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request data',
        details: validation.error.errors,
      });
    }

    const { assetId, datasetName, currentData, referenceData, environment } = validation.data;

    logger.info(`Data quality monitoring requested for asset ${assetId}, dataset: ${datasetName}`);

    // Perform comprehensive monitoring
    const result = await dataQualityManager.monitorDataQuality(
      assetId,
      datasetName,
      currentData,
      referenceData,
      environment
    );

    const processingTime = Date.now() - startTime;

    res.json({
      success: true,
      data: result,
      metadata: {
        processingTimeMs: processingTime,
        timestamp: new Date().toISOString(),
        recordsProcessed: currentData.length,
        referenceRecords: referenceData?.length || 0,
      },
    });
  } catch (error) {
    logger.error('Data quality monitoring failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/report/:assetId
 * Generate comprehensive data quality report for an asset
 * 
 * Query params:
 *   timeRange: '1h' | '6h' | '24h' | '7d' | '30d' | '90d' (default: '24h')
 */
router.get('/report/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const timeRange = req.query.timeRange as string || '24h';

    // Validate parameters
    const validation = generateReportSchema.safeParse({ assetId, timeRange });
    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid parameters',
        details: validation.error.errors,
      });
    }

    logger.info(`Quality report requested for asset ${assetId} (${timeRange})`);

    // Generate comprehensive report
    const report = await dataQualityManager.generateQualityReport(assetId, timeRange);

    res.json({
      success: true,
      data: report,
      metadata: {
        generated: new Date().toISOString(),
        timeRange,
        assetId,
      },
    });
  } catch (error) {
    logger.error('Report generation failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/metrics/:assetId
 * Get quality metrics for an asset within a time range
 * 
 * Query params:
 *   timeRange: time range string (default: '24h')
 *   metricType: specific metric type filter (optional)
 *   environment: environment filter (optional)
 */
router.get('/metrics/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const timeRange = req.query.timeRange as string || '24h';
    const metricType = req.query.metricType as string;
    const environment = req.query.environment as string;

    if (isNaN(assetId) || assetId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid asset ID',
      });
    }

    logger.info(`Quality metrics requested for asset ${assetId}`);

    const metrics = await storage.getQualityMetrics(assetId, timeRange, metricType, environment);
    const summary = await storage.getQualityMetricsSummary(assetId, timeRange);

    res.json({
      success: true,
      data: {
        metrics,
        summary,
      },
      metadata: {
        assetId,
        timeRange,
        metricType: metricType || 'all',
        environment: environment || 'all',
        count: metrics.length,
      },
    });
  } catch (error) {
    logger.error('Failed to get quality metrics:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/drift/:assetId
 * Get drift metrics for an asset within a time range
 * 
 * Query params:
 *   timeRange: time range string (default: '24h')
 *   driftType: drift type filter (optional)
 */
router.get('/drift/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const timeRange = req.query.timeRange as string || '24h';
    const driftType = req.query.driftType as string;

    if (isNaN(assetId) || assetId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid asset ID',
      });
    }

    logger.info(`Drift metrics requested for asset ${assetId}`);

    const driftMetrics = await storage.getDriftMetrics(assetId, timeRange, driftType);

    res.json({
      success: true,
      data: driftMetrics,
      metadata: {
        assetId,
        timeRange,
        driftType: driftType || 'all',
        count: driftMetrics.length,
      },
    });
  } catch (error) {
    logger.error('Failed to get drift metrics:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/anomalies/:assetId
 * Get anomaly detections for an asset within a time range
 * 
 * Query params:
 *   timeRange: time range string (default: '24h')
 *   anomalyType: anomaly type filter (optional)
 *   severity: severity filter (optional)
 */
router.get('/anomalies/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const timeRange = req.query.timeRange as string || '24h';
    const anomalyType = req.query.anomalyType as string;
    const severity = req.query.severity as string;

    if (isNaN(assetId) || assetId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid asset ID',
      });
    }

    logger.info(`Anomaly detections requested for asset ${assetId}`);

    const anomalies = await storage.getAnomalyDetections(assetId, timeRange, anomalyType, severity);

    res.json({
      success: true,
      data: anomalies,
      metadata: {
        assetId,
        timeRange,
        anomalyType: anomalyType || 'all',
        severity: severity || 'all',
        count: anomalies.length,
      },
    });
  } catch (error) {
    logger.error('Failed to get anomaly detections:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/alerts/:assetId
 * Get active data integrity alerts for an asset
 */
router.get('/alerts/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);

    if (isNaN(assetId) || assetId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid asset ID',
      });
    }

    logger.info(`Active alerts requested for asset ${assetId}`);

    const alerts = await storage.getActiveIntegrityAlerts(assetId);

    res.json({
      success: true,
      data: alerts,
      metadata: {
        assetId,
        count: alerts.length,
        criticalCount: alerts.filter(a => a.severity === 'critical').length,
      },
    });
  } catch (error) {
    logger.error('Failed to get active alerts:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * PUT /api/data-quality/alerts/:alertId
 * Update alert status (acknowledge, resolve, etc.)
 * 
 * Body: {
 *   status: 'active' | 'investigating' | 'resolved' | 'suppressed',
 *   resolvedAt?: string (ISO date)
 * }
 */
router.put('/alerts/:alertId', async (req, res) => {
  try {
    const alertId = parseInt(req.params.alertId);
    const { status, resolvedAt } = req.body;

    if (isNaN(alertId) || alertId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid alert ID',
      });
    }

    if (!['active', 'investigating', 'resolved', 'suppressed'].includes(status)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid status value',
      });
    }

    logger.info(`Updating alert ${alertId} to status: ${status}`);

    const resolvedDate = resolvedAt ? new Date(resolvedAt) : (status === 'resolved' ? new Date() : undefined);
    const updatedAlert = await storage.updateIntegrityAlert(alertId, status, resolvedDate);

    if (!updatedAlert) {
      return res.status(404).json({
        success: false,
        error: 'Alert not found',
      });
    }

    res.json({
      success: true,
      data: updatedAlert,
      metadata: {
        alertId,
        previousStatus: 'unknown', // Would track this in a real implementation
        newStatus: status,
        updatedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    logger.error('Failed to update alert:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * POST /api/data-quality/validation-rules
 * Create a new validation rule for an asset
 * 
 * Body: {
 *   assetId: number,
 *   ruleName: string,
 *   ruleType: string,
 *   fieldName?: string,
 *   validationConfig: object,
 *   severity?: string,
 *   description?: string,
 *   createdBy: number
 * }
 */
router.post('/validation-rules', async (req, res) => {
  try {
    // Validate request body
    const validation = insertDataValidationRuleSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request data',
        details: validation.error.errors,
      });
    }

    logger.info(`Creating validation rule: ${validation.data.ruleName} for asset ${validation.data.assetId}`);

    await dataQualityManager.createValidationRule(validation.data);

    res.status(201).json({
      success: true,
      message: 'Validation rule created successfully',
      data: validation.data,
    });
  } catch (error) {
    logger.error('Failed to create validation rule:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * POST /api/data-quality/baselines
 * Create a new quality baseline for an asset
 * 
 * Body: {
 *   assetId: number,
 *   datasetName: string,
 *   baselineType: string,
 *   metricType: string,
 *   baselineValue: string,
 *   sampleSize: number,
 *   confidenceInterval?: object,
 *   validFrom?: string,
 *   validUntil?: string,
 *   metadata?: object
 * }
 */
router.post('/baselines', async (req, res) => {
  try {
    // Validate request body
    const validation = insertDataQualityBaselineSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request data',
        details: validation.error.errors,
      });
    }

    logger.info(`Creating quality baseline: ${validation.data.metricType} for asset ${validation.data.assetId}`);

    await dataQualityManager.createQualityBaseline(validation.data);

    res.status(201).json({
      success: true,
      message: 'Quality baseline created successfully',
      data: validation.data,
    });
  } catch (error) {
    logger.error('Failed to create quality baseline:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/validation-rules/:assetId
 * Get validation rules for an asset
 */
router.get('/validation-rules/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);

    if (isNaN(assetId) || assetId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid asset ID',
      });
    }

    logger.info(`Validation rules requested for asset ${assetId}`);

    const rules = await storage.getValidationRules(assetId);

    res.json({
      success: true,
      data: rules,
      metadata: {
        assetId,
        count: rules.length,
        activeRules: rules.filter(r => r.isActive).length,
      },
    });
  } catch (error) {
    logger.error('Failed to get validation rules:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/baselines/:assetId
 * Get quality baselines for an asset
 * 
 * Query params:
 *   metricType: specific metric type filter (optional)
 */
router.get('/baselines/:assetId', async (req, res) => {
  try {
    const assetId = parseInt(req.params.assetId);
    const metricType = req.query.metricType as string;

    if (isNaN(assetId) || assetId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid asset ID',
      });
    }

    logger.info(`Quality baselines requested for asset ${assetId}`);

    const baselines = await storage.getQualityBaselines(assetId, metricType);

    res.json({
      success: true,
      data: baselines,
      metadata: {
        assetId,
        metricType: metricType || 'all',
        count: baselines.length,
        activeBaselines: baselines.filter(b => b.isActive).length,
      },
    });
  } catch (error) {
    logger.error('Failed to get quality baselines:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * POST /api/data-quality/start-monitoring
 * Start automated data quality monitoring
 */
router.post('/start-monitoring', async (req, res) => {
  try {
    logger.info('Starting automated data quality monitoring');

    await dataQualityManager.startMonitoring();

    res.json({
      success: true,
      message: 'Automated monitoring started successfully',
      data: dataQualityManager.getMonitoringStatus(),
    });
  } catch (error) {
    logger.error('Failed to start monitoring:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * POST /api/data-quality/stop-monitoring
 * Stop automated data quality monitoring
 */
router.post('/stop-monitoring', async (req, res) => {
  try {
    logger.info('Stopping automated data quality monitoring');

    await dataQualityManager.stopMonitoring();

    res.json({
      success: true,
      message: 'Automated monitoring stopped successfully',
      data: dataQualityManager.getMonitoringStatus(),
    });
  } catch (error) {
    logger.error('Failed to stop monitoring:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * GET /api/data-quality/status
 * Get current monitoring status and configuration
 */
router.get('/status', async (req, res) => {
  try {
    const status = dataQualityManager.getMonitoringStatus();
    const config = dataQualityManager.getConfig();

    res.json({
      success: true,
      data: {
        status,
        config,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    logger.error('Failed to get monitoring status:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * PUT /api/data-quality/config
 * Update data quality monitoring configuration
 * 
 * Body: Partial<DataQualityManagerConfig>
 */
router.put('/config', async (req, res) => {
  try {
    // Validate request body
    const validation = updateConfigSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid configuration data',
        details: validation.error.errors,
      });
    }

    logger.info('Updating data quality monitoring configuration', validation.data);

    await dataQualityManager.updateConfig(validation.data);

    res.json({
      success: true,
      message: 'Configuration updated successfully',
      data: dataQualityManager.getConfig(),
    });
  } catch (error) {
    logger.error('Failed to update configuration:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * POST /api/data-quality/cleanup
 * Cleanup old data according to retention policy
 */
router.post('/cleanup', async (req, res) => {
  try {
    logger.info('Starting data cleanup process');

    const result = await dataQualityManager.cleanupOldData();

    res.json({
      success: true,
      message: 'Data cleanup completed successfully',
      data: result,
    });
  } catch (error) {
    logger.error('Failed to cleanup old data:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

export { router as dataQualityRoutes };