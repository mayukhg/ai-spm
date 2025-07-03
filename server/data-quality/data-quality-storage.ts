/**
 * Data Quality Storage Interface - Database operations for data quality monitoring
 * 
 * This module provides database storage and retrieval operations for:
 * - Data quality metrics and historical tracking
 * - Data validation rules and configurations
 * - Data integrity alerts and notifications
 * - Data quality baselines and thresholds
 * - Anomaly detection results and drift metrics
 * 
 * Features:
 * - Type-safe database operations using Drizzle ORM
 * - Optimized queries with proper indexing
 * - Batch operations for high-volume data processing
 * - Historical data management and retention policies
 * - Performance metrics and query optimization
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { db } from '../db';
import { 
  dataQualityMetrics, 
  dataDriftMetrics, 
  dataAnomalyDetections, 
  dataIntegrityAlerts, 
  dataValidationRules, 
  dataQualityBaselines,
  InsertDataQualityMetric,
  InsertDataDriftMetric,
  InsertDataAnomalyDetection,
  InsertDataIntegrityAlert,
  InsertDataValidationRule,
  InsertDataQualityBaseline,
  DataQualityMetric,
  DataDriftMetric,
  DataAnomalyDetection,
  DataIntegrityAlert,
  DataValidationRule,
  DataQualityBaseline,
  DataQualityStats
} from '../../shared/schema';
import { eq, and, gte, lte, desc, asc, count, avg, sum, sql } from 'drizzle-orm';
import { logger } from '../monitoring/logger';

export class DataQualityStorage {
  
  /**
   * Create a new data quality metric record
   * Stores quality measurements with timestamp and metadata
   * 
   * @param metric - Data quality metric to store
   * @returns Promise<DataQualityMetric> - Created metric record
   */
  async createQualityMetric(metric: InsertDataQualityMetric): Promise<DataQualityMetric> {
    try {
      const [created] = await db
        .insert(dataQualityMetrics)
        .values(metric)
        .returning();
      
      logger.debug(`Quality metric created: ${metric.metricType} for asset ${metric.assetId}`);
      return created;
    } catch (error) {
      logger.error('Failed to create quality metric:', error);
      throw new Error(`Failed to create quality metric: ${error.message}`);
    }
  }

  /**
   * Get quality metrics for an asset within a time range
   * Supports filtering by metric type and environment
   * 
   * @param assetId - ID of the asset
   * @param timeRange - Time range string (24h, 7d, 30d)
   * @param metricType - Optional metric type filter
   * @param environment - Optional environment filter
   * @returns Promise<DataQualityMetric[]> - Array of quality metrics
   */
  async getQualityMetrics(
    assetId: number, 
    timeRange: string = '24h',
    metricType?: string,
    environment?: string
  ): Promise<DataQualityMetric[]> {
    try {
      const timeThreshold = this.getTimeThreshold(timeRange);
      
      let query = db
        .select()
        .from(dataQualityMetrics)
        .where(
          and(
            eq(dataQualityMetrics.assetId, assetId),
            gte(dataQualityMetrics.collectedAt, timeThreshold)
          )
        );

      // Add optional filters
      if (metricType) {
        query = query.where(eq(dataQualityMetrics.metricType, metricType));
      }
      
      if (environment) {
        query = query.where(eq(dataQualityMetrics.environment, environment));
      }

      const metrics = await query.orderBy(desc(dataQualityMetrics.collectedAt));
      
      logger.debug(`Retrieved ${metrics.length} quality metrics for asset ${assetId}`);
      return metrics;
    } catch (error) {
      logger.error('Failed to get quality metrics:', error);
      throw new Error(`Failed to get quality metrics: ${error.message}`);
    }
  }

  /**
   * Get quality metrics summary with statistics
   * Provides aggregated metrics and trend analysis
   * 
   * @param assetId - ID of the asset
   * @param timeRange - Time range for analysis
   * @returns Promise<DataQualityStats> - Quality statistics summary
   */
  async getQualityMetricsSummary(assetId: number, timeRange: string = '24h'): Promise<DataQualityStats> {
    try {
      const timeThreshold = this.getTimeThreshold(timeRange);
      
      // Get total metrics count
      const [totalMetricsResult] = await db
        .select({ count: count() })
        .from(dataQualityMetrics)
        .where(
          and(
            eq(dataQualityMetrics.assetId, assetId),
            gte(dataQualityMetrics.collectedAt, timeThreshold)
          )
        );

      // Get average quality score
      const [avgScoreResult] = await db
        .select({ avgScore: avg(dataQualityMetrics.metricValue) })
        .from(dataQualityMetrics)
        .where(
          and(
            eq(dataQualityMetrics.assetId, assetId),
            eq(dataQualityMetrics.metricType, 'overall_score'),
            gte(dataQualityMetrics.collectedAt, timeThreshold)
          )
        );

      // Get drift detections count
      const [driftCountResult] = await db
        .select({ count: count() })
        .from(dataDriftMetrics)
        .where(
          and(
            eq(dataDriftMetrics.assetId, assetId),
            gte(dataDriftMetrics.detectedAt, timeThreshold)
          )
        );

      // Get anomaly detections count
      const [anomalyCountResult] = await db
        .select({ count: count() })
        .from(dataAnomalyDetections)
        .where(
          and(
            eq(dataAnomalyDetections.assetId, assetId),
            gte(dataAnomalyDetections.detectedAt, timeThreshold)
          )
        );

      // Get active alerts count
      const [activeAlertsResult] = await db
        .select({ count: count() })
        .from(dataIntegrityAlerts)
        .where(
          and(
            eq(dataIntegrityAlerts.assetId, assetId),
            eq(dataIntegrityAlerts.status, 'active')
          )
        );

      // Calculate trends (simplified - would need more sophisticated analysis in production)
      const qualityTrend = await this.calculateQualityTrend(assetId, timeRange);
      const driftTrend = await this.calculateDriftTrend(assetId, timeRange);

      return {
        totalMetrics: totalMetricsResult.count,
        qualityScore: Number(avgScoreResult.avgScore) || 0,
        driftDetections: driftCountResult.count,
        anomalyDetections: anomalyCountResult.count,
        activeAlerts: activeAlertsResult.count,
        trends: {
          qualityTrend,
          driftTrend,
        },
      };
    } catch (error) {
      logger.error('Failed to get quality metrics summary:', error);
      throw new Error(`Failed to get quality metrics summary: ${error.message}`);
    }
  }

  /**
   * Create a new data drift metric record
   * Stores drift detection results with statistical analysis
   * 
   * @param driftMetric - Data drift metric to store
   * @returns Promise<DataDriftMetric> - Created drift metric record
   */
  async createDriftMetric(driftMetric: InsertDataDriftMetric): Promise<DataDriftMetric> {
    try {
      const [created] = await db
        .insert(dataDriftMetrics)
        .values(driftMetric)
        .returning();
      
      logger.debug(`Drift metric created: ${driftMetric.driftType} for asset ${driftMetric.assetId}`);
      return created;
    } catch (error) {
      logger.error('Failed to create drift metric:', error);
      throw new Error(`Failed to create drift metric: ${error.message}`);
    }
  }

  /**
   * Get drift metrics for an asset within a time range
   * Supports filtering by drift type and status
   * 
   * @param assetId - ID of the asset
   * @param timeRange - Time range string
   * @param driftType - Optional drift type filter
   * @returns Promise<DataDriftMetric[]> - Array of drift metrics
   */
  async getDriftMetrics(
    assetId: number, 
    timeRange: string = '24h',
    driftType?: string
  ): Promise<DataDriftMetric[]> {
    try {
      const timeThreshold = this.getTimeThreshold(timeRange);
      
      let query = db
        .select()
        .from(dataDriftMetrics)
        .where(
          and(
            eq(dataDriftMetrics.assetId, assetId),
            gte(dataDriftMetrics.detectedAt, timeThreshold)
          )
        );

      if (driftType) {
        query = query.where(eq(dataDriftMetrics.driftType, driftType));
      }

      const metrics = await query.orderBy(desc(dataDriftMetrics.detectedAt));
      
      logger.debug(`Retrieved ${metrics.length} drift metrics for asset ${assetId}`);
      return metrics;
    } catch (error) {
      logger.error('Failed to get drift metrics:', error);
      throw new Error(`Failed to get drift metrics: ${error.message}`);
    }
  }

  /**
   * Create a new anomaly detection record
   * Stores anomaly detection results with confidence scores
   * 
   * @param anomaly - Anomaly detection to store
   * @returns Promise<DataAnomalyDetection> - Created anomaly record
   */
  async createAnomalyDetection(anomaly: InsertDataAnomalyDetection): Promise<DataAnomalyDetection> {
    try {
      const [created] = await db
        .insert(dataAnomalyDetections)
        .values(anomaly)
        .returning();
      
      logger.debug(`Anomaly detection created: ${anomaly.anomalyType} for asset ${anomaly.assetId}`);
      return created;
    } catch (error) {
      logger.error('Failed to create anomaly detection:', error);
      throw new Error(`Failed to create anomaly detection: ${error.message}`);
    }
  }

  /**
   * Get anomaly detections for an asset within a time range
   * Supports filtering by anomaly type and severity
   * 
   * @param assetId - ID of the asset
   * @param timeRange - Time range string
   * @param anomalyType - Optional anomaly type filter
   * @param severity - Optional severity filter
   * @returns Promise<DataAnomalyDetection[]> - Array of anomaly detections
   */
  async getAnomalyDetections(
    assetId: number, 
    timeRange: string = '24h',
    anomalyType?: string,
    severity?: string
  ): Promise<DataAnomalyDetection[]> {
    try {
      const timeThreshold = this.getTimeThreshold(timeRange);
      
      let query = db
        .select()
        .from(dataAnomalyDetections)
        .where(
          and(
            eq(dataAnomalyDetections.assetId, assetId),
            gte(dataAnomalyDetections.detectedAt, timeThreshold)
          )
        );

      if (anomalyType) {
        query = query.where(eq(dataAnomalyDetections.anomalyType, anomalyType));
      }

      if (severity) {
        query = query.where(eq(dataAnomalyDetections.severity, severity));
      }

      const detections = await query.orderBy(desc(dataAnomalyDetections.detectedAt));
      
      logger.debug(`Retrieved ${detections.length} anomaly detections for asset ${assetId}`);
      return detections;
    } catch (error) {
      logger.error('Failed to get anomaly detections:', error);
      throw new Error(`Failed to get anomaly detections: ${error.message}`);
    }
  }

  /**
   * Create a new data integrity alert
   * Stores alerts for data quality issues requiring attention
   * 
   * @param alert - Data integrity alert to store
   * @returns Promise<DataIntegrityAlert> - Created alert record
   */
  async createIntegrityAlert(alert: InsertDataIntegrityAlert): Promise<DataIntegrityAlert> {
    try {
      const [created] = await db
        .insert(dataIntegrityAlerts)
        .values(alert)
        .returning();
      
      logger.debug(`Integrity alert created: ${alert.alertType} for asset ${alert.assetId}`);
      return created;
    } catch (error) {
      logger.error('Failed to create integrity alert:', error);
      throw new Error(`Failed to create integrity alert: ${error.message}`);
    }
  }

  /**
   * Get active data integrity alerts for an asset
   * Returns alerts that require attention or action
   * 
   * @param assetId - ID of the asset
   * @returns Promise<DataIntegrityAlert[]> - Array of active alerts
   */
  async getActiveIntegrityAlerts(assetId: number): Promise<DataIntegrityAlert[]> {
    try {
      const alerts = await db
        .select()
        .from(dataIntegrityAlerts)
        .where(
          and(
            eq(dataIntegrityAlerts.assetId, assetId),
            eq(dataIntegrityAlerts.status, 'active')
          )
        )
        .orderBy(desc(dataIntegrityAlerts.createdAt));
      
      logger.debug(`Retrieved ${alerts.length} active integrity alerts for asset ${assetId}`);
      return alerts;
    } catch (error) {
      logger.error('Failed to get active integrity alerts:', error);
      throw new Error(`Failed to get active integrity alerts: ${error.message}`);
    }
  }

  /**
   * Update an integrity alert status
   * Allows marking alerts as resolved, investigating, etc.
   * 
   * @param alertId - ID of the alert to update
   * @param status - New status for the alert
   * @param resolvedAt - Optional resolution timestamp
   * @returns Promise<DataIntegrityAlert | null> - Updated alert or null if not found
   */
  async updateIntegrityAlert(
    alertId: number, 
    status: string, 
    resolvedAt?: Date
  ): Promise<DataIntegrityAlert | null> {
    try {
      const updateData: any = { status };
      if (resolvedAt) {
        updateData.resolvedAt = resolvedAt;
      }

      const [updated] = await db
        .update(dataIntegrityAlerts)
        .set(updateData)
        .where(eq(dataIntegrityAlerts.id, alertId))
        .returning();
      
      if (updated) {
        logger.debug(`Integrity alert ${alertId} updated to status: ${status}`);
      }
      
      return updated || null;
    } catch (error) {
      logger.error('Failed to update integrity alert:', error);
      throw new Error(`Failed to update integrity alert: ${error.message}`);
    }
  }

  /**
   * Get validation rules for an asset
   * Returns configured validation rules for data quality checking
   * 
   * @param assetId - ID of the asset
   * @returns Promise<DataValidationRule[]> - Array of validation rules
   */
  async getValidationRules(assetId: number): Promise<DataValidationRule[]> {
    try {
      const rules = await db
        .select()
        .from(dataValidationRules)
        .where(
          and(
            eq(dataValidationRules.assetId, assetId),
            eq(dataValidationRules.isActive, true)
          )
        )
        .orderBy(asc(dataValidationRules.ruleName));
      
      logger.debug(`Retrieved ${rules.length} validation rules for asset ${assetId}`);
      return rules;
    } catch (error) {
      logger.error('Failed to get validation rules:', error);
      throw new Error(`Failed to get validation rules: ${error.message}`);
    }
  }

  /**
   * Create a new validation rule
   * Stores configurable validation rules for data quality checking
   * 
   * @param rule - Validation rule to store
   * @returns Promise<DataValidationRule> - Created validation rule
   */
  async createValidationRule(rule: InsertDataValidationRule): Promise<DataValidationRule> {
    try {
      const [created] = await db
        .insert(dataValidationRules)
        .values(rule)
        .returning();
      
      logger.debug(`Validation rule created: ${rule.ruleName} for asset ${rule.assetId}`);
      return created;
    } catch (error) {
      logger.error('Failed to create validation rule:', error);
      throw new Error(`Failed to create validation rule: ${error.message}`);
    }
  }

  /**
   * Create a new quality baseline
   * Stores reference metrics for comparison and drift detection
   * 
   * @param baseline - Quality baseline to store
   * @returns Promise<DataQualityBaseline> - Created baseline record
   */
  async createQualityBaseline(baseline: InsertDataQualityBaseline): Promise<DataQualityBaseline> {
    try {
      const [created] = await db
        .insert(dataQualityBaselines)
        .values(baseline)
        .returning();
      
      logger.debug(`Quality baseline created: ${baseline.metricType} for asset ${baseline.assetId}`);
      return created;
    } catch (error) {
      logger.error('Failed to create quality baseline:', error);
      throw new Error(`Failed to create quality baseline: ${error.message}`);
    }
  }

  /**
   * Get quality baselines for an asset
   * Returns reference metrics for comparison and drift detection
   * 
   * @param assetId - ID of the asset
   * @param metricType - Optional metric type filter
   * @returns Promise<DataQualityBaseline[]> - Array of quality baselines
   */
  async getQualityBaselines(assetId: number, metricType?: string): Promise<DataQualityBaseline[]> {
    try {
      let query = db
        .select()
        .from(dataQualityBaselines)
        .where(
          and(
            eq(dataQualityBaselines.assetId, assetId),
            eq(dataQualityBaselines.isActive, true)
          )
        );

      if (metricType) {
        query = query.where(eq(dataQualityBaselines.metricType, metricType));
      }

      const baselines = await query.orderBy(desc(dataQualityBaselines.createdAt));
      
      logger.debug(`Retrieved ${baselines.length} quality baselines for asset ${assetId}`);
      return baselines;
    } catch (error) {
      logger.error('Failed to get quality baselines:', error);
      throw new Error(`Failed to get quality baselines: ${error.message}`);
    }
  }

  /**
   * Batch create quality metrics
   * Optimized for high-volume metric storage
   * 
   * @param metrics - Array of quality metrics to store
   * @returns Promise<DataQualityMetric[]> - Array of created metrics
   */
  async batchCreateQualityMetrics(metrics: InsertDataQualityMetric[]): Promise<DataQualityMetric[]> {
    try {
      const created = await db
        .insert(dataQualityMetrics)
        .values(metrics)
        .returning();
      
      logger.debug(`Batch created ${created.length} quality metrics`);
      return created;
    } catch (error) {
      logger.error('Failed to batch create quality metrics:', error);
      throw new Error(`Failed to batch create quality metrics: ${error.message}`);
    }
  }

  /**
   * Clean up old quality metrics
   * Removes metrics older than retention period
   * 
   * @param retentionDays - Number of days to retain metrics
   * @returns Promise<number> - Number of metrics deleted
   */
  async cleanupOldMetrics(retentionDays: number = 90): Promise<number> {
    try {
      const retentionDate = new Date();
      retentionDate.setDate(retentionDate.getDate() - retentionDays);

      const deleted = await db
        .delete(dataQualityMetrics)
        .where(lte(dataQualityMetrics.collectedAt, retentionDate));
      
      logger.info(`Cleaned up ${deleted.rowCount} old quality metrics`);
      return deleted.rowCount || 0;
    } catch (error) {
      logger.error('Failed to cleanup old metrics:', error);
      throw new Error(`Failed to cleanup old metrics: ${error.message}`);
    }
  }

  /**
   * Helper method to convert time range string to timestamp
   * 
   * @param timeRange - Time range string (24h, 7d, 30d, 90d)
   * @returns Date - Timestamp for the time threshold
   */
  private getTimeThreshold(timeRange: string): Date {
    const now = new Date();
    const timeValue = parseInt(timeRange.slice(0, -1));
    const timeUnit = timeRange.slice(-1);

    switch (timeUnit) {
      case 'h':
        return new Date(now.getTime() - timeValue * 60 * 60 * 1000);
      case 'd':
        return new Date(now.getTime() - timeValue * 24 * 60 * 60 * 1000);
      case 'w':
        return new Date(now.getTime() - timeValue * 7 * 24 * 60 * 60 * 1000);
      case 'm':
        return new Date(now.getTime() - timeValue * 30 * 24 * 60 * 60 * 1000);
      default:
        return new Date(now.getTime() - 24 * 60 * 60 * 1000); // Default to 24 hours
    }
  }

  /**
   * Calculate quality trend for an asset
   * Analyzes quality metrics over time to determine trend direction
   * 
   * @param assetId - ID of the asset
   * @param timeRange - Time range for trend analysis
   * @returns Promise<'improving' | 'stable' | 'degrading'> - Quality trend
   */
  private async calculateQualityTrend(assetId: number, timeRange: string): Promise<'improving' | 'stable' | 'degrading'> {
    try {
      const timeThreshold = this.getTimeThreshold(timeRange);
      const midpoint = new Date((timeThreshold.getTime() + Date.now()) / 2);

      // Get average quality score for first half of time range
      const [firstHalfResult] = await db
        .select({ avgScore: avg(dataQualityMetrics.metricValue) })
        .from(dataQualityMetrics)
        .where(
          and(
            eq(dataQualityMetrics.assetId, assetId),
            eq(dataQualityMetrics.metricType, 'overall_score'),
            gte(dataQualityMetrics.collectedAt, timeThreshold),
            lte(dataQualityMetrics.collectedAt, midpoint)
          )
        );

      // Get average quality score for second half of time range
      const [secondHalfResult] = await db
        .select({ avgScore: avg(dataQualityMetrics.metricValue) })
        .from(dataQualityMetrics)
        .where(
          and(
            eq(dataQualityMetrics.assetId, assetId),
            eq(dataQualityMetrics.metricType, 'overall_score'),
            gte(dataQualityMetrics.collectedAt, midpoint),
            lte(dataQualityMetrics.collectedAt, new Date())
          )
        );

      const firstHalfAvg = Number(firstHalfResult.avgScore) || 0;
      const secondHalfAvg = Number(secondHalfResult.avgScore) || 0;

      if (secondHalfAvg > firstHalfAvg * 1.05) return 'improving';
      if (secondHalfAvg < firstHalfAvg * 0.95) return 'degrading';
      return 'stable';
    } catch (error) {
      logger.error('Failed to calculate quality trend:', error);
      return 'stable'; // Default to stable on error
    }
  }

  /**
   * Calculate drift trend for an asset
   * Analyzes drift metrics over time to determine trend direction
   * 
   * @param assetId - ID of the asset
   * @param timeRange - Time range for trend analysis
   * @returns Promise<'stable' | 'increasing' | 'decreasing'> - Drift trend
   */
  private async calculateDriftTrend(assetId: number, timeRange: string): Promise<'stable' | 'increasing' | 'decreasing'> {
    try {
      const timeThreshold = this.getTimeThreshold(timeRange);
      const midpoint = new Date((timeThreshold.getTime() + Date.now()) / 2);

      // Get average drift score for first half of time range
      const [firstHalfResult] = await db
        .select({ avgScore: avg(dataDriftMetrics.driftScore) })
        .from(dataDriftMetrics)
        .where(
          and(
            eq(dataDriftMetrics.assetId, assetId),
            gte(dataDriftMetrics.detectedAt, timeThreshold),
            lte(dataDriftMetrics.detectedAt, midpoint)
          )
        );

      // Get average drift score for second half of time range
      const [secondHalfResult] = await db
        .select({ avgScore: avg(dataDriftMetrics.driftScore) })
        .from(dataDriftMetrics)
        .where(
          and(
            eq(dataDriftMetrics.assetId, assetId),
            gte(dataDriftMetrics.detectedAt, midpoint),
            lte(dataDriftMetrics.detectedAt, new Date())
          )
        );

      const firstHalfAvg = Number(firstHalfResult.avgScore) || 0;
      const secondHalfAvg = Number(secondHalfResult.avgScore) || 0;

      if (secondHalfAvg > firstHalfAvg * 1.1) return 'increasing';
      if (secondHalfAvg < firstHalfAvg * 0.9) return 'decreasing';
      return 'stable';
    } catch (error) {
      logger.error('Failed to calculate drift trend:', error);
      return 'stable'; // Default to stable on error
    }
  }
}