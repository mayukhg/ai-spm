/**
 * Data Quality Monitor - Real-time data validation and quality assessment
 * 
 * This service provides comprehensive data quality monitoring capabilities including:
 * - Real-time data validation against configurable rules
 * - Statistical quality metrics calculation and tracking
 * - Automated quality scoring and threshold monitoring
 * - Integration with alerting system for quality issues
 * 
 * Key Features:
 * - Completeness: Missing data detection and percentage calculation
 * - Accuracy: Data format validation and range checking
 * - Consistency: Cross-field validation and referential integrity
 * - Validity: Schema compliance and data type validation
 * - Uniqueness: Duplicate detection and uniqueness scoring
 * - Freshness: Data recency and staleness monitoring
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { DataQualityMetric, InsertDataQualityMetric, DataIntegrityAlert, InsertDataIntegrityAlert } from '../../shared/schema';
import { DataQualityStorage } from './data-quality-storage';
import { AlertManager } from '../monitoring/alert-manager';

// Configuration for data quality thresholds and rules
interface DataQualityConfig {
  completenessThreshold: number;  // Minimum percentage of non-null values (0-100)
  accuracyThreshold: number;      // Minimum percentage of valid format values (0-100)
  consistencyThreshold: number;   // Minimum percentage of consistent values (0-100)
  validityThreshold: number;      // Minimum percentage of schema-compliant values (0-100)
  uniquenessThreshold: number;    // Maximum percentage of duplicate values (0-100)
  freshnessThreshold: number;     // Maximum age in hours for fresh data
}

// Quality metrics calculation result
interface QualityMetrics {
  completeness: number;
  accuracy: number;
  consistency: number;
  validity: number;
  uniqueness: number;
  freshness: number;
  overallScore: number;
}

// Data validation result for a single rule
interface ValidationResult {
  ruleName: string;
  ruleType: string;
  fieldName: string;
  passed: boolean;
  score: number;
  violationCount: number;
  totalCount: number;
  details: any;
}

// Dataset validation summary
interface DatasetValidationSummary {
  datasetName: string;
  assetId: number;
  totalRecords: number;
  validationResults: ValidationResult[];
  qualityMetrics: QualityMetrics;
  alerts: Array<{
    alertType: string;
    severity: string;
    title: string;
    description: string;
  }>;
}

export class DataQualityMonitor {
  private storage: DataQualityStorage;
  private alertManager: AlertManager;
  private config: DataQualityConfig;

  constructor(storage: DataQualityStorage, alertManager: AlertManager) {
    this.storage = storage;
    this.alertManager = alertManager;
    
    // Default configuration - can be overridden
    this.config = {
      completenessThreshold: 95.0,   // 95% completeness required
      accuracyThreshold: 98.0,       // 98% accuracy required
      consistencyThreshold: 95.0,    // 95% consistency required
      validityThreshold: 99.0,       // 99% validity required
      uniquenessThreshold: 5.0,      // Max 5% duplicates allowed
      freshnessThreshold: 24.0,      // Data must be less than 24 hours old
    };

    logger.info('Data Quality Monitor initialized with default thresholds');
  }

  /**
   * Validate a dataset against configured quality rules
   * Performs comprehensive validation including completeness, accuracy, consistency, validity, uniqueness, and freshness
   * 
   * @param assetId - ID of the AI asset being validated
   * @param datasetName - Name of the dataset
   * @param data - Array of data records to validate
   * @param environment - Environment context (training, inference, validation)
   * @returns Promise<DatasetValidationSummary> - Complete validation results
   */
  async validateDataset(
    assetId: number,
    datasetName: string,
    data: any[],
    environment: string = 'inference'
  ): Promise<DatasetValidationSummary> {
    const startTime = Date.now();
    
    try {
      logger.info(`Starting data quality validation for dataset: ${datasetName} (${data.length} records)`);

      // Get validation rules for this asset
      const validationRules = await this.storage.getValidationRules(assetId);
      
      // Perform individual rule validations
      const validationResults: ValidationResult[] = [];
      
      for (const rule of validationRules) {
        const result = await this.validateRule(rule, data);
        validationResults.push(result);
      }

      // Calculate comprehensive quality metrics
      const qualityMetrics = this.calculateQualityMetrics(data, validationResults);

      // Store quality metrics in database
      await this.storeQualityMetrics(assetId, datasetName, qualityMetrics, environment);

      // Generate alerts for quality issues
      const alerts = await this.generateQualityAlerts(assetId, datasetName, qualityMetrics, validationResults);

      const validationSummary: DatasetValidationSummary = {
        datasetName,
        assetId,
        totalRecords: data.length,
        validationResults,
        qualityMetrics,
        alerts,
      };

      const processingTime = Date.now() - startTime;
      logger.info(`Data quality validation completed for ${datasetName} in ${processingTime}ms - Overall Score: ${qualityMetrics.overallScore.toFixed(2)}%`);

      return validationSummary;
    } catch (error) {
      logger.error(`Data quality validation failed for dataset ${datasetName}:`, error);
      throw new Error(`Data quality validation failed: ${error.message}`);
    }
  }

  /**
   * Validate data against a specific validation rule
   * Supports multiple rule types with configurable parameters
   * 
   * @param rule - Validation rule configuration
   * @param data - Dataset to validate
   * @returns ValidationResult - Rule validation outcome
   */
  private async validateRule(rule: any, data: any[]): Promise<ValidationResult> {
    const ruleConfig = rule.validationConfig;
    let passed = true;
    let score = 100;
    let violationCount = 0;
    let details: any = {};

    try {
      switch (rule.ruleType) {
        case 'schema_validation':
          // Validate data conforms to expected schema
          const result = this.validateSchema(data, ruleConfig);
          violationCount = result.violationCount;
          score = result.score;
          details = result.details;
          break;

        case 'range_check':
          // Validate numeric values fall within acceptable ranges
          const rangeResult = this.validateRange(data, rule.fieldName, ruleConfig);
          violationCount = rangeResult.violationCount;
          score = rangeResult.score;
          details = rangeResult.details;
          break;

        case 'format_validation':
          // Validate data format (regex, date formats, etc.)
          const formatResult = this.validateFormat(data, rule.fieldName, ruleConfig);
          violationCount = formatResult.violationCount;
          score = formatResult.score;
          details = formatResult.details;
          break;

        case 'uniqueness_check':
          // Validate field uniqueness constraints
          const uniqueResult = this.validateUniqueness(data, rule.fieldName, ruleConfig);
          violationCount = uniqueResult.violationCount;
          score = uniqueResult.score;
          details = uniqueResult.details;
          break;

        default:
          logger.warn(`Unknown validation rule type: ${rule.ruleType}`);
          score = 0;
          details = { error: 'Unknown rule type' };
      }

      // Rule passes if score meets threshold
      const threshold = ruleConfig.threshold || 95;
      passed = score >= threshold;

      return {
        ruleName: rule.ruleName,
        ruleType: rule.ruleType,
        fieldName: rule.fieldName || 'global',
        passed,
        score,
        violationCount,
        totalCount: data.length,
        details,
      };
    } catch (error) {
      logger.error(`Rule validation failed for ${rule.ruleName}:`, error);
      return {
        ruleName: rule.ruleName,
        ruleType: rule.ruleType,
        fieldName: rule.fieldName || 'global',
        passed: false,
        score: 0,
        violationCount: data.length,
        totalCount: data.length,
        details: { error: error.message },
      };
    }
  }

  /**
   * Calculate comprehensive quality metrics for a dataset
   * Combines multiple validation results into overall quality scores
   * 
   * @param data - Dataset being analyzed
   * @param validationResults - Results from individual rule validations
   * @returns QualityMetrics - Comprehensive quality assessment
   */
  private calculateQualityMetrics(data: any[], validationResults: ValidationResult[]): QualityMetrics {
    const totalRecords = data.length;
    
    // Calculate completeness - percentage of non-null values
    const completeness = this.calculateCompleteness(data);
    
    // Calculate accuracy - percentage of valid format values
    const accuracy = this.calculateAccuracy(validationResults);
    
    // Calculate consistency - percentage of consistent cross-field values
    const consistency = this.calculateConsistency(data, validationResults);
    
    // Calculate validity - percentage of schema-compliant values
    const validity = this.calculateValidity(validationResults);
    
    // Calculate uniqueness - percentage of unique values (100% = no duplicates)
    const uniqueness = this.calculateUniqueness(data);
    
    // Calculate freshness - based on data timestamps if available
    const freshness = this.calculateFreshness(data);
    
    // Calculate overall score as weighted average
    const overallScore = this.calculateOverallScore({
      completeness,
      accuracy,
      consistency,
      validity,
      uniqueness,
      freshness,
    });

    return {
      completeness,
      accuracy,
      consistency,
      validity,
      uniqueness,
      freshness,
      overallScore,
    };
  }

  /**
   * Calculate completeness percentage - measures missing data
   * Higher values indicate better data completeness
   */
  private calculateCompleteness(data: any[]): number {
    if (data.length === 0) return 0;

    let totalFields = 0;
    let nonNullFields = 0;

    for (const record of data) {
      const fields = Object.keys(record);
      totalFields += fields.length;
      
      for (const field of fields) {
        if (record[field] !== null && record[field] !== undefined && record[field] !== '') {
          nonNullFields++;
        }
      }
    }

    return totalFields > 0 ? (nonNullFields / totalFields) * 100 : 0;
  }

  /**
   * Calculate accuracy percentage from validation results
   * Measures how many values pass format and range validations
   */
  private calculateAccuracy(validationResults: ValidationResult[]): number {
    const accuracyRules = validationResults.filter(r => 
      r.ruleType === 'format_validation' || r.ruleType === 'range_check'
    );

    if (accuracyRules.length === 0) return 100;

    const totalScore = accuracyRules.reduce((sum, rule) => sum + rule.score, 0);
    return totalScore / accuracyRules.length;
  }

  /**
   * Calculate consistency percentage
   * Measures cross-field validation and referential integrity
   */
  private calculateConsistency(data: any[], validationResults: ValidationResult[]): number {
    // Check for common consistency issues
    let consistencyScore = 100;
    
    // Example: Check date consistency (created_at <= updated_at)
    const dateInconsistencies = data.filter(record => {
      if (record.created_at && record.updated_at) {
        return new Date(record.created_at) > new Date(record.updated_at);
      }
      return false;
    });

    if (dateInconsistencies.length > 0) {
      consistencyScore -= (dateInconsistencies.length / data.length) * 100;
    }

    return Math.max(0, consistencyScore);
  }

  /**
   * Calculate validity percentage from schema validation results
   * Measures compliance with expected data types and structures
   */
  private calculateValidity(validationResults: ValidationResult[]): number {
    const validityRules = validationResults.filter(r => r.ruleType === 'schema_validation');

    if (validityRules.length === 0) return 100;

    const totalScore = validityRules.reduce((sum, rule) => sum + rule.score, 0);
    return totalScore / validityRules.length;
  }

  /**
   * Calculate uniqueness percentage
   * Measures duplicate records and unique identifier compliance
   */
  private calculateUniqueness(data: any[]): number {
    if (data.length === 0) return 100;

    // Simple uniqueness check based on JSON serialization
    const uniqueRecords = new Set(data.map(record => JSON.stringify(record)));
    const uniquenessRatio = uniqueRecords.size / data.length;
    
    return uniquenessRatio * 100;
  }

  /**
   * Calculate freshness percentage
   * Measures how recent the data is based on timestamps
   */
  private calculateFreshness(data: any[]): number {
    if (data.length === 0) return 100;

    const now = Date.now();
    const freshnessThresholdMs = this.config.freshnessThreshold * 60 * 60 * 1000; // Convert hours to milliseconds
    
    let freshRecords = 0;
    let totalRecordsWithTimestamp = 0;

    for (const record of data) {
      // Check common timestamp fields
      const timestampFields = ['created_at', 'updated_at', 'timestamp', 'date'];
      let hasTimestamp = false;

      for (const field of timestampFields) {
        if (record[field]) {
          hasTimestamp = true;
          totalRecordsWithTimestamp++;
          
          const recordTime = new Date(record[field]).getTime();
          if (now - recordTime <= freshnessThresholdMs) {
            freshRecords++;
          }
          break;
        }
      }
    }

    // If no timestamps found, assume data is fresh
    if (totalRecordsWithTimestamp === 0) return 100;

    return (freshRecords / totalRecordsWithTimestamp) * 100;
  }

  /**
   * Calculate overall quality score as weighted average
   * Combines all quality dimensions into a single score
   */
  private calculateOverallScore(metrics: Omit<QualityMetrics, 'overallScore'>): number {
    // Configurable weights for different quality dimensions
    const weights = {
      completeness: 0.20,   // 20% weight
      accuracy: 0.25,       // 25% weight
      consistency: 0.15,    // 15% weight
      validity: 0.20,       // 20% weight
      uniqueness: 0.10,     // 10% weight
      freshness: 0.10,      // 10% weight
    };

    const weightedScore = 
      (metrics.completeness * weights.completeness) +
      (metrics.accuracy * weights.accuracy) +
      (metrics.consistency * weights.consistency) +
      (metrics.validity * weights.validity) +
      (metrics.uniqueness * weights.uniqueness) +
      (metrics.freshness * weights.freshness);

    return Math.round(weightedScore * 100) / 100; // Round to 2 decimal places
  }

  /**
   * Store quality metrics in database for historical tracking
   * Creates records for each quality dimension
   */
  private async storeQualityMetrics(
    assetId: number,
    datasetName: string,
    metrics: QualityMetrics,
    environment: string
  ): Promise<void> {
    const metricTypes = [
      { type: 'completeness', value: metrics.completeness, threshold: this.config.completenessThreshold },
      { type: 'accuracy', value: metrics.accuracy, threshold: this.config.accuracyThreshold },
      { type: 'consistency', value: metrics.consistency, threshold: this.config.consistencyThreshold },
      { type: 'validity', value: metrics.validity, threshold: this.config.validityThreshold },
      { type: 'uniqueness', value: metrics.uniqueness, threshold: 100 - this.config.uniquenessThreshold },
      { type: 'freshness', value: metrics.freshness, threshold: this.config.freshnessThreshold },
      { type: 'overall_score', value: metrics.overallScore, threshold: 90.0 },
    ];

    for (const metric of metricTypes) {
      const status = this.getMetricStatus(metric.value, metric.threshold, metric.type);
      
      const qualityMetric: InsertDataQualityMetric = {
        assetId,
        datasetName,
        metricType: metric.type,
        metricValue: metric.value.toString(),
        threshold: metric.threshold.toString(),
        status,
        environment,
        details: {
          timestamp: new Date().toISOString(),
          calculationMethod: 'automated',
        },
      };

      await this.storage.createQualityMetric(qualityMetric);
    }
  }

  /**
   * Determine metric status based on value and threshold
   */
  private getMetricStatus(value: number, threshold: number, metricType: string): string {
    // For uniqueness, lower values are better (fewer duplicates)
    if (metricType === 'uniqueness') {
      const duplicatePercentage = 100 - value;
      if (duplicatePercentage <= threshold) return 'normal';
      if (duplicatePercentage <= threshold * 1.5) return 'warning';
      return 'critical';
    }

    // For other metrics, higher values are better
    if (value >= threshold) return 'normal';
    if (value >= threshold * 0.8) return 'warning';
    return 'critical';
  }

  /**
   * Generate data integrity alerts for quality issues
   * Creates alerts for metrics that fall below thresholds
   */
  private async generateQualityAlerts(
    assetId: number,
    datasetName: string,
    metrics: QualityMetrics,
    validationResults: ValidationResult[]
  ): Promise<Array<{ alertType: string; severity: string; title: string; description: string }>> {
    const alerts: Array<{ alertType: string; severity: string; title: string; description: string }> = [];

    // Check each metric against thresholds
    const metricChecks = [
      { name: 'completeness', value: metrics.completeness, threshold: this.config.completenessThreshold },
      { name: 'accuracy', value: metrics.accuracy, threshold: this.config.accuracyThreshold },
      { name: 'consistency', value: metrics.consistency, threshold: this.config.consistencyThreshold },
      { name: 'validity', value: metrics.validity, threshold: this.config.validityThreshold },
      { name: 'freshness', value: metrics.freshness, threshold: this.config.freshnessThreshold },
    ];

    for (const check of metricChecks) {
      if (check.value < check.threshold) {
        const severity = this.calculateAlertSeverity(check.value, check.threshold);
        const impact = this.getQualityImpact(check.name);
        
        const alert = {
          alertType: 'data_quality_degradation',
          severity,
          title: `${check.name.charAt(0).toUpperCase() + check.name.slice(1)} Below Threshold`,
          description: `Data ${check.name} is ${check.value.toFixed(2)}%, below the required threshold of ${check.threshold}%. This may impact ${impact}.`,
        };

        alerts.push(alert);

        // Create database alert record
        const alertRecord: InsertDataIntegrityAlert = {
          assetId,
          alertType: 'data_quality_degradation',
          severity,
          title: alert.title,
          description: alert.description,
          impact: impact,
          datasetName,
          detectionSource: 'quality_check',
          metadata: {
            metricType: check.name,
            currentValue: check.value,
            threshold: check.threshold,
            qualityScore: metrics.overallScore,
          },
        };

        await this.storage.createIntegrityAlert(alertRecord);
      }
    }

    // Check for uniqueness issues (duplicates)
    const duplicatePercentage = 100 - metrics.uniqueness;
    if (duplicatePercentage > this.config.uniquenessThreshold) {
      const severity = this.calculateAlertSeverity(duplicatePercentage, this.config.uniquenessThreshold, true);
      
      const alert = {
        alertType: 'duplicate_data',
        severity,
        title: 'Duplicate Data Detected',
        description: `${duplicatePercentage.toFixed(2)}% of records are duplicates, exceeding the threshold of ${this.config.uniquenessThreshold}%. This may impact model training and accuracy.`,
      };

      alerts.push(alert);

      const alertRecord: InsertDataIntegrityAlert = {
        assetId,
        alertType: 'duplicate_data',
        severity,
        title: alert.title,
        description: alert.description,
        impact: 'model_performance',
        datasetName,
        detectionSource: 'quality_check',
        metadata: {
          duplicatePercentage,
          threshold: this.config.uniquenessThreshold,
          totalRecords: validationResults[0]?.totalCount || 0,
        },
      };

      await this.storage.createIntegrityAlert(alertRecord);
    }

    // Send notifications for critical alerts
    for (const alert of alerts.filter(a => a.severity === 'critical')) {
      await this.alertManager.sendAlert({
        title: alert.title,
        description: alert.description,
        severity: alert.severity,
        source: 'data_quality_monitor',
        metadata: {
          assetId,
          datasetName,
          alertType: alert.alertType,
        },
      });
    }

    return alerts;
  }

  /**
   * Calculate alert severity based on deviation from threshold
   */
  private calculateAlertSeverity(value: number, threshold: number, higherIsBad: boolean = false): string {
    const ratio = higherIsBad ? value / threshold : threshold / value;
    
    if (ratio >= 2.0) return 'critical';
    if (ratio >= 1.5) return 'high';
    if (ratio >= 1.2) return 'medium';
    return 'low';
  }

  /**
   * Get the impact description for a quality metric
   */
  private getQualityImpact(metricName: string): string {
    const impacts = {
      completeness: 'model accuracy and feature engineering',
      accuracy: 'model performance and prediction reliability',
      consistency: 'data reliability and system stability',
      validity: 'data processing and model training',
      uniqueness: 'model bias and training effectiveness',
      freshness: 'model relevance and prediction accuracy',
    };

    return impacts[metricName] || 'system performance';
  }

  // Individual validation methods for different rule types

  private validateSchema(data: any[], schemaConfig: any): { violationCount: number; score: number; details: any } {
    // Implement schema validation logic
    let violationCount = 0;
    const details: any = { missingFields: [], invalidTypes: [] };

    for (const record of data) {
      // Check required fields
      if (schemaConfig.requiredFields) {
        for (const field of schemaConfig.requiredFields) {
          if (!(field in record) || record[field] === null || record[field] === undefined) {
            violationCount++;
            if (!details.missingFields.includes(field)) {
              details.missingFields.push(field);
            }
          }
        }
      }

      // Check field types
      if (schemaConfig.fieldTypes) {
        for (const [field, expectedType] of Object.entries(schemaConfig.fieldTypes)) {
          if (field in record && record[field] !== null) {
            const actualType = typeof record[field];
            if (actualType !== expectedType) {
              violationCount++;
              details.invalidTypes.push({ field, expected: expectedType, actual: actualType });
            }
          }
        }
      }
    }

    const score = Math.max(0, (1 - violationCount / (data.length * 2)) * 100);
    return { violationCount, score, details };
  }

  private validateRange(data: any[], fieldName: string, rangeConfig: any): { violationCount: number; score: number; details: any } {
    let violationCount = 0;
    const details: any = { outOfRange: [] };

    for (const record of data) {
      if (fieldName in record && record[fieldName] !== null) {
        const value = parseFloat(record[fieldName]);
        if (!isNaN(value)) {
          if (rangeConfig.min !== undefined && value < rangeConfig.min) {
            violationCount++;
            details.outOfRange.push({ value, reason: 'below_minimum' });
          }
          if (rangeConfig.max !== undefined && value > rangeConfig.max) {
            violationCount++;
            details.outOfRange.push({ value, reason: 'above_maximum' });
          }
        }
      }
    }

    const score = Math.max(0, (1 - violationCount / data.length) * 100);
    return { violationCount, score, details };
  }

  private validateFormat(data: any[], fieldName: string, formatConfig: any): { violationCount: number; score: number; details: any } {
    let violationCount = 0;
    const details: any = { invalidFormats: [] };

    const pattern = new RegExp(formatConfig.pattern);

    for (const record of data) {
      if (fieldName in record && record[fieldName] !== null) {
        const value = record[fieldName].toString();
        if (!pattern.test(value)) {
          violationCount++;
          details.invalidFormats.push({ value, field: fieldName });
        }
      }
    }

    const score = Math.max(0, (1 - violationCount / data.length) * 100);
    return { violationCount, score, details };
  }

  private validateUniqueness(data: any[], fieldName: string, uniqueConfig: any): { violationCount: number; score: number; details: any } {
    const values = new Set();
    let violationCount = 0;
    const details: any = { duplicateValues: [] };

    for (const record of data) {
      if (fieldName in record && record[fieldName] !== null) {
        const value = record[fieldName];
        if (values.has(value)) {
          violationCount++;
          details.duplicateValues.push(value);
        } else {
          values.add(value);
        }
      }
    }

    const score = Math.max(0, (1 - violationCount / data.length) * 100);
    return { violationCount, score, details };
  }

  /**
   * Update quality monitoring configuration
   * Allows runtime adjustment of thresholds and rules
   */
  async updateConfig(newConfig: Partial<DataQualityConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    logger.info('Data quality monitoring configuration updated', { newConfig });
  }

  /**
   * Get current quality monitoring configuration
   */
  getConfig(): DataQualityConfig {
    return { ...this.config };
  }

  /**
   * Get quality metrics summary for an asset
   */
  async getQualityMetricsSummary(assetId: number, timeRange: string = '24h'): Promise<any> {
    return await this.storage.getQualityMetricsSummary(assetId, timeRange);
  }

  /**
   * Get active data integrity alerts for an asset
   */
  async getActiveAlerts(assetId: number): Promise<DataIntegrityAlert[]> {
    return await this.storage.getActiveIntegrityAlerts(assetId);
  }
}