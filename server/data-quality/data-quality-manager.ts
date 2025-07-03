/**
 * Data Quality Manager - Orchestrates comprehensive data quality monitoring
 * 
 * This service coordinates all data quality monitoring components including:
 * - Real-time data validation and quality assessment
 * - Data drift detection and distribution analysis
 * - Anomaly detection using ensemble methods
 * - Data integrity alerting and notifications
 * - Quality metrics aggregation and reporting
 * 
 * Key Features:
 * - Unified interface for all data quality operations
 * - Automated monitoring workflows and scheduling
 * - Real-time quality scoring and threshold management
 * - Integration with alerting and notification systems
 * - Comprehensive logging and audit trail
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { DataQualityMonitor } from './data-quality-monitor';
import { DataDriftDetector } from './data-drift-detector';
import { AnomalyDetector } from './anomaly-detector';
import { DataQualityStorage } from './data-quality-storage';
import { AlertManager } from '../monitoring/alert-manager';
import { 
  DataQualityStats, 
  InsertDataValidationRule, 
  InsertDataQualityBaseline,
  DataIntegrityAlert
} from '../../shared/schema';

// Configuration for the data quality manager
interface DataQualityManagerConfig {
  enableRealTimeMonitoring: boolean;    // Enable continuous monitoring
  monitoringInterval: number;           // Monitoring interval in minutes
  enableDriftDetection: boolean;        // Enable drift detection
  enableAnomalyDetection: boolean;      // Enable anomaly detection
  batchSize: number;                   // Batch size for processing
  retentionDays: number;               // Data retention period in days
  alertThresholds: {
    qualityScoreThreshold: number;     // Minimum quality score
    driftThreshold: number;            // Maximum drift score
    anomalyRateThreshold: number;      // Maximum anomaly rate
  };
}

// Comprehensive data quality report
interface DataQualityReport {
  assetId: number;
  datasetName: string;
  generatedAt: Date;
  qualityOverview: {
    overallScore: number;
    status: 'excellent' | 'good' | 'warning' | 'critical';
    totalRecords: number;
    validRecords: number;
    qualityTrend: 'improving' | 'stable' | 'degrading';
  };
  qualityMetrics: {
    completeness: number;
    accuracy: number;
    consistency: number;
    validity: number;
    uniqueness: number;
    freshness: number;
  };
  driftAnalysis: {
    overallDriftScore: number;
    driftStatus: 'stable' | 'drifting' | 'significant_drift';
    driftedFeatures: number;
    totalFeatures: number;
    recommendations: string[];
  };
  anomalyAnalysis: {
    totalAnomalies: number;
    anomalyRate: number;
    severityDistribution: {
      low: number;
      medium: number;
      high: number;
      critical: number;
    };
    dominantAnomalyTypes: string[];
  };
  alerts: {
    activeAlerts: number;
    criticalAlerts: number;
    recentAlerts: DataIntegrityAlert[];
  };
  recommendations: string[];
}

// Monitoring result for a dataset
interface MonitoringResult {
  success: boolean;
  assetId: number;
  datasetName: string;
  processingTime: number;
  qualityScore: number;
  driftScore?: number;
  anomalyCount?: number;
  alertsGenerated: number;
  errors?: string[];
}

export class DataQualityManager {
  private qualityMonitor: DataQualityMonitor;
  private driftDetector: DataDriftDetector;
  private anomalyDetector: AnomalyDetector;
  private storage: DataQualityStorage;
  private alertManager: AlertManager;
  private config: DataQualityManagerConfig;
  private isMonitoring: boolean = false;
  private monitoringTimer?: NodeJS.Timeout;

  constructor(
    storage: DataQualityStorage,
    alertManager: AlertManager
  ) {
    this.storage = storage;
    this.alertManager = alertManager;
    
    // Initialize components
    this.qualityMonitor = new DataQualityMonitor(storage, alertManager);
    this.driftDetector = new DataDriftDetector(storage, alertManager);
    this.anomalyDetector = new AnomalyDetector(storage, alertManager);
    
    // Default configuration
    this.config = {
      enableRealTimeMonitoring: true,
      monitoringInterval: 15,           // 15 minutes
      enableDriftDetection: true,
      enableAnomalyDetection: true,
      batchSize: 1000,                 // Process 1000 records at a time
      retentionDays: 90,               // Keep data for 90 days
      alertThresholds: {
        qualityScoreThreshold: 85.0,   // 85% minimum quality score
        driftThreshold: 0.3,           // 30% maximum drift score
        anomalyRateThreshold: 0.05,    // 5% maximum anomaly rate
      },
    };

    logger.info('Data Quality Manager initialized successfully');
  }

  /**
   * Perform comprehensive data quality monitoring for a dataset
   * Orchestrates quality validation, drift detection, and anomaly detection
   * 
   * @param assetId - ID of the AI asset
   * @param datasetName - Name of the dataset
   * @param currentData - Current dataset to analyze
   * @param referenceData - Optional reference dataset for comparison
   * @param environment - Environment context (training, inference, validation)
   * @returns Promise<MonitoringResult> - Comprehensive monitoring results
   */
  async monitorDataQuality(
    assetId: number,
    datasetName: string,
    currentData: any[],
    referenceData?: any[],
    environment: string = 'inference'
  ): Promise<MonitoringResult> {
    const startTime = Date.now();
    const errors: string[] = [];
    let alertsGenerated = 0;

    try {
      logger.info(`Starting comprehensive data quality monitoring for dataset: ${datasetName}`);

      // 1. Data Quality Validation
      let qualityScore = 0;
      try {
        const qualityResult = await this.qualityMonitor.validateDataset(
          assetId,
          datasetName,
          currentData,
          environment
        );
        qualityScore = qualityResult.qualityMetrics.overallScore;
        alertsGenerated += qualityResult.alerts.length;
        
        logger.info(`Quality validation completed - Score: ${qualityScore.toFixed(2)}%`);
      } catch (error) {
        const errorMsg = `Quality validation failed: ${(error as Error).message}`;
        errors.push(errorMsg);
        logger.error(errorMsg);
      }

      // 2. Data Drift Detection (if enabled and reference data available)
      let driftScore: number | undefined;
      if (this.config.enableDriftDetection && referenceData && referenceData.length > 0) {
        try {
          const driftResult = await this.driftDetector.detectDrift(
            assetId,
            datasetName,
            referenceData,
            currentData,
            `ref_${Date.now()}`,
            `curr_${Date.now()}`,
            environment
          );
          driftScore = driftResult.overallDriftScore;
          alertsGenerated += driftResult.alerts.length;
          
          logger.info(`Drift detection completed - Score: ${driftScore.toFixed(4)}`);
        } catch (error) {
          const errorMsg = `Drift detection failed: ${(error as Error).message}`;
          errors.push(errorMsg);
          logger.error(errorMsg);
        }
      }

      // 3. Anomaly Detection (if enabled)
      let anomalyCount: number | undefined;
      if (this.config.enableAnomalyDetection) {
        try {
          const anomalyResult = await this.anomalyDetector.detectAnomalies(
            assetId,
            datasetName,
            currentData,
            referenceData,
            environment
          );
          anomalyCount = anomalyResult.anomalousRecords;
          alertsGenerated += anomalyResult.alerts.length;
          
          logger.info(`Anomaly detection completed - Found ${anomalyCount} anomalies`);
        } catch (error) {
          const errorMsg = `Anomaly detection failed: ${(error as Error).message}`;
          errors.push(errorMsg);
          logger.error(errorMsg);
        }
      }

      // 4. Generate overall health alerts
      await this.generateOverallHealthAlerts(assetId, datasetName, qualityScore, driftScore, anomalyCount);

      const processingTime = Date.now() - startTime;
      const success = errors.length === 0;

      const result: MonitoringResult = {
        success,
        assetId,
        datasetName,
        processingTime,
        qualityScore,
        driftScore,
        anomalyCount,
        alertsGenerated,
        ...(errors.length > 0 && { errors }),
      };

      logger.info(`Data quality monitoring completed for ${datasetName} in ${processingTime}ms - Success: ${success}`);
      return result;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      logger.error(`Data quality monitoring failed for ${datasetName}:`, error);
      
      return {
        success: false,
        assetId,
        datasetName,
        processingTime,
        qualityScore: 0,
        alertsGenerated: 0,
        errors: [(error as Error).message],
      };
    }
  }

  /**
   * Generate comprehensive data quality report
   * Aggregates all quality metrics and provides actionable insights
   * 
   * @param assetId - ID of the AI asset
   * @param timeRange - Time range for analysis (24h, 7d, 30d)
   * @returns Promise<DataQualityReport> - Comprehensive quality report
   */
  async generateQualityReport(assetId: number, timeRange: string = '24h'): Promise<DataQualityReport> {
    try {
      logger.info(`Generating data quality report for asset ${assetId} (${timeRange})`);

      // Get quality metrics summary
      const qualityStats = await this.storage.getQualityMetricsSummary(assetId, timeRange);
      
      // Get recent quality metrics for detailed analysis
      const recentMetrics = await this.storage.getQualityMetrics(assetId, timeRange);
      
      // Get drift metrics
      const driftMetrics = await this.storage.getDriftMetrics(assetId, timeRange);
      
      // Get anomaly detections
      const anomalyDetections = await this.storage.getAnomalyDetections(assetId, timeRange);
      
      // Get active alerts
      const activeAlerts = await this.storage.getActiveIntegrityAlerts(assetId);

      // Calculate quality overview
      const qualityOverview = this.calculateQualityOverview(qualityStats, recentMetrics);
      
      // Calculate drift analysis
      const driftAnalysis = this.calculateDriftAnalysis(driftMetrics);
      
      // Calculate anomaly analysis
      const anomalyAnalysis = this.calculateAnomalyAnalysis(anomalyDetections);
      
      // Generate recommendations
      const recommendations = this.generateOverallRecommendations(
        qualityOverview,
        driftAnalysis,
        anomalyAnalysis,
        activeAlerts
      );

      const report: DataQualityReport = {
        assetId,
        datasetName: `Asset_${assetId}`, // Would get actual name from asset metadata
        generatedAt: new Date(),
        qualityOverview,
        qualityMetrics: this.extractQualityMetrics(recentMetrics),
        driftAnalysis,
        anomalyAnalysis,
        alerts: {
          activeAlerts: activeAlerts.length,
          criticalAlerts: activeAlerts.filter(a => a.severity === 'critical').length,
          recentAlerts: activeAlerts.slice(0, 10), // Most recent 10 alerts
        },
        recommendations,
      };

      logger.info(`Data quality report generated successfully for asset ${assetId}`);
      return report;
    } catch (error) {
      logger.error(`Failed to generate quality report for asset ${assetId}:`, error);
      throw new Error(`Failed to generate quality report: ${(error as Error).message}`);
    }
  }

  /**
   * Start automated data quality monitoring
   * Enables continuous monitoring with configurable intervals
   */
  async startMonitoring(): Promise<void> {
    if (this.isMonitoring) {
      logger.warn('Data quality monitoring is already running');
      return;
    }

    if (!this.config.enableRealTimeMonitoring) {
      logger.info('Real-time monitoring is disabled');
      return;
    }

    this.isMonitoring = true;
    const intervalMs = this.config.monitoringInterval * 60 * 1000; // Convert minutes to milliseconds

    logger.info(`Starting automated data quality monitoring with ${this.config.monitoringInterval} minute intervals`);

    // Set up monitoring timer
    this.monitoringTimer = setInterval(async () => {
      try {
        await this.performScheduledMonitoring();
      } catch (error) {
        logger.error('Scheduled monitoring failed:', error);
      }
    }, intervalMs);

    // Perform initial monitoring
    await this.performScheduledMonitoring();
  }

  /**
   * Stop automated data quality monitoring
   */
  async stopMonitoring(): Promise<void> {
    if (!this.isMonitoring) {
      logger.warn('Data quality monitoring is not running');
      return;
    }

    this.isMonitoring = false;
    
    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.monitoringTimer = undefined;
    }

    logger.info('Automated data quality monitoring stopped');
  }

  /**
   * Create validation rule for an asset
   * Allows configuration of custom validation rules
   * 
   * @param rule - Validation rule configuration
   * @returns Promise<void>
   */
  async createValidationRule(rule: InsertDataValidationRule): Promise<void> {
    try {
      await this.storage.createValidationRule(rule);
      logger.info(`Validation rule created: ${rule.ruleName} for asset ${rule.assetId}`);
    } catch (error) {
      logger.error('Failed to create validation rule:', error);
      throw new Error(`Failed to create validation rule: ${(error as Error).message}`);
    }
  }

  /**
   * Create quality baseline for an asset
   * Establishes reference metrics for drift detection
   * 
   * @param baseline - Quality baseline configuration
   * @returns Promise<void>
   */
  async createQualityBaseline(baseline: InsertDataQualityBaseline): Promise<void> {
    try {
      await this.storage.createQualityBaseline(baseline);
      logger.info(`Quality baseline created: ${baseline.metricType} for asset ${baseline.assetId}`);
    } catch (error) {
      logger.error('Failed to create quality baseline:', error);
      throw new Error(`Failed to create quality baseline: ${(error as Error).message}`);
    }
  }

  /**
   * Update configuration for all monitoring components
   * Allows runtime configuration changes
   * 
   * @param newConfig - Updated configuration
   */
  async updateConfig(newConfig: Partial<DataQualityManagerConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    
    // Update component configurations
    if (newConfig.alertThresholds) {
      await this.qualityMonitor.updateConfig({
        completenessThreshold: newConfig.alertThresholds.qualityScoreThreshold || 95,
        accuracyThreshold: newConfig.alertThresholds.qualityScoreThreshold || 98,
      });
      
      await this.driftDetector.updateConfig({
        featureDriftThreshold: newConfig.alertThresholds.driftThreshold || 0.25,
      });
      
      await this.anomalyDetector.updateConfig({
        ensembleThreshold: newConfig.alertThresholds.anomalyRateThreshold || 0.1,
      });
    }

    // Restart monitoring if interval changed
    if (newConfig.monitoringInterval && this.isMonitoring) {
      await this.stopMonitoring();
      await this.startMonitoring();
    }

    logger.info('Data quality manager configuration updated', { newConfig });
  }

  /**
   * Get current configuration
   */
  getConfig(): DataQualityManagerConfig {
    return { ...this.config };
  }

  /**
   * Get monitoring status
   */
  getMonitoringStatus(): {
    isMonitoring: boolean;
    intervalMinutes: number;
    enabledFeatures: string[];
  } {
    const enabledFeatures: string[] = [];
    if (this.config.enableRealTimeMonitoring) enabledFeatures.push('real-time monitoring');
    if (this.config.enableDriftDetection) enabledFeatures.push('drift detection');
    if (this.config.enableAnomalyDetection) enabledFeatures.push('anomaly detection');

    return {
      isMonitoring: this.isMonitoring,
      intervalMinutes: this.config.monitoringInterval,
      enabledFeatures,
    };
  }

  /**
   * Cleanup old data according to retention policy
   */
  async cleanupOldData(): Promise<{ metricsDeleted: number }> {
    try {
      const metricsDeleted = await this.storage.cleanupOldMetrics(this.config.retentionDays);
      logger.info(`Cleanup completed - Deleted ${metricsDeleted} old metrics`);
      return { metricsDeleted };
    } catch (error) {
      logger.error('Failed to cleanup old data:', error);
      throw new Error(`Failed to cleanup old data: ${(error as Error).message}`);
    }
  }

  // Private helper methods

  private async performScheduledMonitoring(): Promise<void> {
    logger.info('Performing scheduled data quality monitoring');
    
    try {
      // In a real implementation, this would:
      // 1. Get list of assets to monitor
      // 2. Fetch recent data for each asset
      // 3. Perform monitoring for each dataset
      // 4. Generate summary reports
      
      // For now, we'll just log that monitoring is active
      logger.info('Scheduled monitoring cycle completed');
    } catch (error) {
      logger.error('Scheduled monitoring failed:', error);
    }
  }

  private async generateOverallHealthAlerts(
    assetId: number,
    datasetName: string,
    qualityScore: number,
    driftScore?: number,
    anomalyCount?: number
  ): Promise<void> {
    const alerts: Array<{ type: string; severity: string; message: string }> = [];

    // Quality score alert
    if (qualityScore < this.config.alertThresholds.qualityScoreThreshold) {
      alerts.push({
        type: 'low_quality_score',
        severity: qualityScore < 70 ? 'critical' : 'high',
        message: `Data quality score ${qualityScore.toFixed(1)}% is below threshold ${this.config.alertThresholds.qualityScoreThreshold}%`,
      });
    }

    // Drift score alert
    if (driftScore && driftScore > this.config.alertThresholds.driftThreshold) {
      alerts.push({
        type: 'high_drift_score',
        severity: driftScore > 0.5 ? 'critical' : 'high',
        message: `Data drift score ${driftScore.toFixed(3)} exceeds threshold ${this.config.alertThresholds.driftThreshold}`,
      });
    }

    // Anomaly rate alert
    if (anomalyCount) {
      const anomalyRate = anomalyCount / 1000; // Assuming 1000 total records for rate calculation
      if (anomalyRate > this.config.alertThresholds.anomalyRateThreshold) {
        alerts.push({
          type: 'high_anomaly_rate',
          severity: anomalyRate > 0.1 ? 'critical' : 'high',
          message: `Anomaly rate ${(anomalyRate * 100).toFixed(1)}% exceeds threshold ${(this.config.alertThresholds.anomalyRateThreshold * 100).toFixed(1)}%`,
        });
      }
    }

    // Send alerts
    for (const alert of alerts) {
      await this.alertManager.sendAlert({
        title: `Data Quality Alert: ${alert.type}`,
        description: alert.message,
        severity: alert.severity,
        source: 'data_quality_manager',
        metadata: {
          assetId,
          datasetName,
          alertType: alert.type,
          qualityScore,
          driftScore,
          anomalyCount,
        },
      });
    }
  }

  private calculateQualityOverview(qualityStats: DataQualityStats, recentMetrics: any[]): any {
    const overallScore = qualityStats.qualityScore || 0;
    
    let status: 'excellent' | 'good' | 'warning' | 'critical';
    if (overallScore >= 95) status = 'excellent';
    else if (overallScore >= 85) status = 'good';
    else if (overallScore >= 70) status = 'warning';
    else status = 'critical';

    return {
      overallScore,
      status,
      totalRecords: qualityStats.totalMetrics || 0,
      validRecords: Math.floor((qualityStats.totalMetrics || 0) * (overallScore / 100)),
      qualityTrend: qualityStats.trends?.qualityTrend || 'stable',
    };
  }

  private calculateDriftAnalysis(driftMetrics: any[]): any {
    const significantDrift = driftMetrics.filter(m => m.status === 'significant_drift');
    const overallDriftScore = driftMetrics.length > 0 ? 
      driftMetrics.reduce((sum, m) => sum + parseFloat(m.driftScore), 0) / driftMetrics.length : 0;

    let driftStatus: 'stable' | 'drifting' | 'significant_drift';
    if (overallDriftScore < 0.1) driftStatus = 'stable';
    else if (overallDriftScore < 0.3) driftStatus = 'drifting';
    else driftStatus = 'significant_drift';

    return {
      overallDriftScore,
      driftStatus,
      driftedFeatures: significantDrift.length,
      totalFeatures: driftMetrics.length,
      recommendations: this.generateDriftRecommendations(driftMetrics),
    };
  }

  private calculateAnomalyAnalysis(anomalyDetections: any[]): any {
    const severityDistribution = {
      low: anomalyDetections.filter(a => a.severity === 'low').length,
      medium: anomalyDetections.filter(a => a.severity === 'medium').length,
      high: anomalyDetections.filter(a => a.severity === 'high').length,
      critical: anomalyDetections.filter(a => a.severity === 'critical').length,
    };

    const anomalyTypes: { [key: string]: number } = {};
    for (const detection of anomalyDetections) {
      anomalyTypes[detection.anomalyType] = (anomalyTypes[detection.anomalyType] || 0) + 1;
    }

    const dominantAnomalyTypes = Object.entries(anomalyTypes)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3)
      .map(([type]) => type);

    return {
      totalAnomalies: anomalyDetections.length,
      anomalyRate: anomalyDetections.length / 1000, // Normalize to rate
      severityDistribution,
      dominantAnomalyTypes,
    };
  }

  private extractQualityMetrics(recentMetrics: any[]): any {
    const metricsByType: { [key: string]: number[] } = {};
    
    for (const metric of recentMetrics) {
      if (!metricsByType[metric.metricType]) {
        metricsByType[metric.metricType] = [];
      }
      metricsByType[metric.metricType].push(parseFloat(metric.metricValue));
    }

    const calculateAverage = (values: number[]) => 
      values.length > 0 ? values.reduce((sum, val) => sum + val, 0) / values.length : 0;

    return {
      completeness: calculateAverage(metricsByType.completeness || []),
      accuracy: calculateAverage(metricsByType.accuracy || []),
      consistency: calculateAverage(metricsByType.consistency || []),
      validity: calculateAverage(metricsByType.validity || []),
      uniqueness: calculateAverage(metricsByType.uniqueness || []),
      freshness: calculateAverage(metricsByType.freshness || []),
    };
  }

  private generateDriftRecommendations(driftMetrics: any[]): string[] {
    const recommendations: string[] = [];
    
    const significantDrift = driftMetrics.filter(m => m.status === 'significant_drift');
    if (significantDrift.length > 0) {
      recommendations.push('Consider retraining models due to significant data drift');
      recommendations.push('Investigate data collection processes for drift root causes');
    }

    if (driftMetrics.length > 5) {
      recommendations.push('Implement automated drift monitoring and alerting');
    }

    return recommendations;
  }

  private generateOverallRecommendations(
    qualityOverview: any,
    driftAnalysis: any,
    anomalyAnalysis: any,
    activeAlerts: DataIntegrityAlert[]
  ): string[] {
    const recommendations: string[] = [];

    if (qualityOverview.status === 'critical') {
      recommendations.push('URGENT: Address critical data quality issues immediately');
    }

    if (driftAnalysis.driftStatus === 'significant_drift') {
      recommendations.push('Investigate and address significant data drift patterns');
    }

    if (anomalyAnalysis.totalAnomalies > 50) {
      recommendations.push('High anomaly count detected - review data collection processes');
    }

    if (activeAlerts.length > 10) {
      recommendations.push('Multiple active alerts require attention - prioritize by severity');
    }

    if (recommendations.length === 0) {
      recommendations.push('Data quality is stable - continue monitoring for trends');
    }

    return recommendations;
  }
}