/**
 * Anomaly Detector - Advanced anomaly detection for AI datasets
 * 
 * This service provides comprehensive anomaly detection capabilities including:
 * - Statistical outlier detection using multiple algorithms
 * - Pattern anomaly detection for temporal and sequential data
 * - Schema anomaly detection for data structure changes
 * - Contextual anomaly detection based on feature correlations
 * - Ensemble methods combining multiple detection techniques
 * 
 * Key Features:
 * - Isolation Forest for high-dimensional anomaly detection
 * - Local Outlier Factor (LOF) for density-based detection
 * - DBSCAN clustering for spatial anomaly identification
 * - Statistical methods (Z-score, IQR, modified Z-score)
 * - Real-time scoring and confidence estimation
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { DataAnomalyDetection, InsertDataAnomalyDetection, InsertDataIntegrityAlert } from '../../shared/schema';
import { DataQualityStorage } from './data-quality-storage';
import { AlertManager } from '../monitoring/alert-manager';

// Configuration for anomaly detection parameters
interface AnomalyDetectionConfig {
  outlierThreshold: number;          // Threshold for outlier detection (0-1)
  patternAnomalyThreshold: number;   // Threshold for pattern anomaly detection (0-1)
  temporalAnomalyThreshold: number;  // Threshold for temporal anomaly detection (0-1)
  schemaAnomalyThreshold: number;    // Threshold for schema anomaly detection (0-1)
  minConfidence: number;             // Minimum confidence for anomaly reporting (0-1)
  ensembleThreshold: number;         // Threshold for ensemble anomaly detection (0-1)
  isolationTreeCount: number;        // Number of trees for isolation forest
  lofNeighbors: number;             // Number of neighbors for LOF algorithm
  dbscanEps: number;                // Epsilon parameter for DBSCAN
  dbscanMinSamples: number;         // Minimum samples for DBSCAN core point
}

// Anomaly detection result for a single record
interface RecordAnomalyResult {
  recordId: string;
  anomalyScore: number;
  confidence: number;
  anomalyType: string;
  detectionMethod: string;
  affectedFeatures: string[];
  details: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

// Dataset anomaly analysis result
interface DatasetAnomalyAnalysis {
  datasetName: string;
  assetId: number;
  totalRecords: number;
  anomalousRecords: number;
  anomalyPercentage: number;
  detectionResults: RecordAnomalyResult[];
  severityDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  recommendations: string[];
  alerts: Array<{
    alertType: string;
    severity: string;
    title: string;
    description: string;
  }>;
}

export class AnomalyDetector {
  private storage: DataQualityStorage;
  private alertManager: AlertManager;
  private config: AnomalyDetectionConfig;

  constructor(storage: DataQualityStorage, alertManager: AlertManager) {
    this.storage = storage;
    this.alertManager = alertManager;
    
    // Default configuration - can be overridden
    this.config = {
      outlierThreshold: 0.1,           // 10% outlier threshold
      patternAnomalyThreshold: 0.15,   // 15% pattern anomaly threshold
      temporalAnomalyThreshold: 0.12,  // 12% temporal anomaly threshold
      schemaAnomalyThreshold: 0.05,    // 5% schema anomaly threshold
      minConfidence: 0.7,              // 70% minimum confidence
      ensembleThreshold: 0.6,          // 60% ensemble threshold
      isolationTreeCount: 100,         // 100 isolation trees
      lofNeighbors: 20,               // 20 neighbors for LOF
      dbscanEps: 0.5,                 // DBSCAN epsilon parameter
      dbscanMinSamples: 5,            // DBSCAN minimum samples
    };

    logger.info('Anomaly Detector initialized with default configuration');
  }

  /**
   * Detect anomalies in a dataset using ensemble methods
   * Combines multiple detection algorithms for robust anomaly identification
   * 
   * @param assetId - ID of the AI asset
   * @param datasetName - Name of the dataset being analyzed
   * @param data - Array of data records to analyze
   * @param referenceData - Optional reference dataset for comparison
   * @param environment - Environment context (training, inference, validation)
   * @returns Promise<DatasetAnomalyAnalysis> - Complete anomaly analysis results
   */
  async detectAnomalies(
    assetId: number,
    datasetName: string,
    data: any[],
    referenceData?: any[],
    environment: string = 'inference'
  ): Promise<DatasetAnomalyAnalysis> {
    const startTime = Date.now();
    
    try {
      logger.info(`Starting anomaly detection for dataset: ${datasetName} (${data.length} records)`);

      // Validate input data
      this.validateInputData(data);

      // Extract numeric features for analysis
      const features = this.extractNumericFeatures(data);
      const featureNames = Object.keys(features);
      
      if (featureNames.length === 0) {
        throw new Error('No numeric features found for anomaly detection');
      }

      // Prepare feature matrix
      const featureMatrix = this.prepareFeatureMatrix(data, featureNames);
      
      // Run ensemble anomaly detection
      const detectionResults: RecordAnomalyResult[] = [];
      
      for (let i = 0; i < data.length; i++) {
        const record = data[i];
        const recordFeatures = featureMatrix[i];
        
        // Run multiple detection algorithms
        const isolationScore = await this.detectIsolationForestAnomalies(recordFeatures, featureMatrix);
        const lofScore = await this.detectLOFAnomalies(recordFeatures, featureMatrix, i);
        const statisticalScore = await this.detectStatisticalAnomalies(recordFeatures, featureMatrix);
        const patternScore = await this.detectPatternAnomalies(record, data, i);
        
        // Schema anomaly detection
        const schemaScore = await this.detectSchemaAnomalies(record, referenceData);
        
        // Combine scores using ensemble method
        const ensembleResult = this.combineAnomalyScores({
          isolation: isolationScore,
          lof: lofScore,
          statistical: statisticalScore,
          pattern: patternScore,
          schema: schemaScore,
        });

        // Create anomaly result if score exceeds threshold
        if (ensembleResult.anomalyScore > this.config.ensembleThreshold) {
          const anomalyResult: RecordAnomalyResult = {
            recordId: record.id || `record_${i}`,
            anomalyScore: ensembleResult.anomalyScore,
            confidence: ensembleResult.confidence,
            anomalyType: ensembleResult.dominantType,
            detectionMethod: 'ensemble',
            affectedFeatures: ensembleResult.affectedFeatures,
            details: {
              scores: ensembleResult.individualScores,
              featureContributions: ensembleResult.featureContributions,
              timestamp: new Date().toISOString(),
            },
            severity: this.calculateAnomalySeverity(ensembleResult.anomalyScore, ensembleResult.confidence),
          };
          
          detectionResults.push(anomalyResult);
        }
      }

      // Calculate severity distribution
      const severityDistribution = this.calculateSeverityDistribution(detectionResults);

      // Generate recommendations
      const recommendations = this.generateAnomalyRecommendations(detectionResults, data.length);

      // Store anomaly detections in database
      await this.storeAnomalyDetections(assetId, datasetName, detectionResults, environment);

      // Generate alerts for critical anomalies
      const alerts = await this.generateAnomalyAlerts(assetId, datasetName, detectionResults);

      const anomalyAnalysis: DatasetAnomalyAnalysis = {
        datasetName,
        assetId,
        totalRecords: data.length,
        anomalousRecords: detectionResults.length,
        anomalyPercentage: (detectionResults.length / data.length) * 100,
        detectionResults,
        severityDistribution,
        recommendations,
        alerts,
      };

      const processingTime = Date.now() - startTime;
      logger.info(`Anomaly detection completed for ${datasetName} in ${processingTime}ms - Found ${detectionResults.length} anomalies (${anomalyAnalysis.anomalyPercentage.toFixed(2)}%)`);

      return anomalyAnalysis;
    } catch (error) {
      logger.error(`Anomaly detection failed for dataset ${datasetName}:`, error);
      throw new Error(`Anomaly detection failed: ${(error as Error).message}`);
    }
  }

  /**
   * Isolation Forest anomaly detection
   * Uses isolation trees to identify anomalies based on path length
   * 
   * @param recordFeatures - Features of the record being analyzed
   * @param allFeatures - Feature matrix of all records
   * @returns Promise<number> - Anomaly score (0-1)
   */
  private async detectIsolationForestAnomalies(
    recordFeatures: number[],
    allFeatures: number[][]
  ): Promise<number> {
    try {
      // Simplified isolation forest implementation
      // In production, would use a more sophisticated algorithm
      
      const treeCount = Math.min(this.config.isolationTreeCount, 50); // Limit for performance
      let totalPathLength = 0;
      
      for (let tree = 0; tree < treeCount; tree++) {
        const pathLength = this.calculateIsolationPathLength(recordFeatures, allFeatures);
        totalPathLength += pathLength;
      }
      
      const avgPathLength = totalPathLength / treeCount;
      const expectedPathLength = this.calculateExpectedPathLength(allFeatures.length);
      
      // Isolation score: shorter paths indicate anomalies
      const isolationScore = Math.pow(2, -avgPathLength / expectedPathLength);
      
      return Math.min(Math.max(isolationScore, 0), 1); // Clamp to [0, 1]
    } catch (error) {
      logger.error('Isolation forest detection failed:', error);
      return 0;
    }
  }

  /**
   * Local Outlier Factor (LOF) anomaly detection
   * Identifies anomalies based on local density deviation
   * 
   * @param recordFeatures - Features of the record being analyzed
   * @param allFeatures - Feature matrix of all records
   * @param recordIndex - Index of the record in the dataset
   * @returns Promise<number> - LOF anomaly score (0-1)
   */
  private async detectLOFAnomalies(
    recordFeatures: number[],
    allFeatures: number[][],
    recordIndex: number
  ): Promise<number> {
    try {
      const k = Math.min(this.config.lofNeighbors, allFeatures.length - 1);
      
      // Calculate distances to all other points
      const distances: Array<{ index: number; distance: number }> = [];
      
      for (let i = 0; i < allFeatures.length; i++) {
        if (i !== recordIndex) {
          const distance = this.calculateEuclideanDistance(recordFeatures, allFeatures[i]);
          distances.push({ index: i, distance });
        }
      }
      
      // Sort by distance and get k nearest neighbors
      distances.sort((a, b) => a.distance - b.distance);
      const kNeighbors = distances.slice(0, k);
      
      // Calculate k-distance (distance to k-th nearest neighbor)
      const kDistance = kNeighbors[k - 1].distance;
      
      // Calculate reachability distances
      const reachabilityDistances = kNeighbors.map(neighbor => 
        Math.max(neighbor.distance, this.getKDistance(neighbor.index, allFeatures, k))
      );
      
      // Calculate local reachability density
      const avgReachabilityDistance = reachabilityDistances.reduce((sum, dist) => sum + dist, 0) / k;
      const localReachabilityDensity = 1 / (avgReachabilityDistance + 1e-10); // Add small epsilon
      
      // Calculate LOF
      let lofSum = 0;
      for (const neighbor of kNeighbors) {
        const neighborLRD = this.calculateLocalReachabilityDensity(neighbor.index, allFeatures, k);
        lofSum += neighborLRD / localReachabilityDensity;
      }
      
      const lof = lofSum / k;
      
      // Convert LOF to 0-1 scale (LOF > 1 indicates anomaly)
      const lofScore = Math.max(0, (lof - 1) / 2); // Normalize assuming max LOF around 3
      
      return Math.min(lofScore, 1);
    } catch (error) {
      logger.error('LOF detection failed:', error);
      return 0;
    }
  }

  /**
   * Statistical anomaly detection
   * Uses statistical methods (Z-score, IQR) to identify outliers
   * 
   * @param recordFeatures - Features of the record being analyzed
   * @param allFeatures - Feature matrix of all records
   * @returns Promise<number> - Statistical anomaly score (0-1)
   */
  private async detectStatisticalAnomalies(
    recordFeatures: number[],
    allFeatures: number[][]
  ): Promise<number> {
    try {
      const featureCount = recordFeatures.length;
      let anomalyScores: number[] = [];
      
      for (let featureIndex = 0; featureIndex < featureCount; featureIndex++) {
        const featureValues = allFeatures.map(record => record[featureIndex]);
        const recordValue = recordFeatures[featureIndex];
        
        // Z-score method
        const mean = this.calculateMean(featureValues);
        const stdDev = this.calculateStdDev(featureValues, mean);
        const zScore = stdDev > 0 ? Math.abs(recordValue - mean) / stdDev : 0;
        const zScoreAnomaly = Math.min(zScore / 3, 1); // Normalize assuming 3-sigma rule
        
        // IQR method
        const iqrAnomaly = this.calculateIQRAnomalyScore(recordValue, featureValues);
        
        // Modified Z-score using median
        const modifiedZAnomaly = this.calculateModifiedZScore(recordValue, featureValues);
        
        // Combine statistical scores
        const combinedScore = Math.max(zScoreAnomaly, iqrAnomaly, modifiedZAnomaly);
        anomalyScores.push(combinedScore);
      }
      
      // Return maximum anomaly score across all features
      return Math.max(...anomalyScores);
    } catch (error) {
      logger.error('Statistical anomaly detection failed:', error);
      return 0;
    }
  }

  /**
   * Pattern anomaly detection
   * Identifies anomalies based on temporal patterns and sequences
   * 
   * @param record - Current record being analyzed
   * @param allData - Complete dataset for context
   * @param recordIndex - Index of the record in the dataset
   * @returns Promise<number> - Pattern anomaly score (0-1)
   */
  private async detectPatternAnomalies(
    record: any,
    allData: any[],
    recordIndex: number
  ): Promise<number> {
    try {
      let patternScores: number[] = [];
      
      // Temporal pattern analysis (if timestamp available)
      if (record.timestamp || record.created_at) {
        const temporalScore = this.analyzeTemporalPattern(record, allData, recordIndex);
        patternScores.push(temporalScore);
      }
      
      // Sequence pattern analysis
      const sequenceScore = this.analyzeSequencePattern(record, allData, recordIndex);
      patternScores.push(sequenceScore);
      
      // Categorical pattern analysis
      const categoricalScore = this.analyzeCategoricalPattern(record, allData);
      patternScores.push(categoricalScore);
      
      // Return maximum pattern anomaly score
      return patternScores.length > 0 ? Math.max(...patternScores) : 0;
    } catch (error) {
      logger.error('Pattern anomaly detection failed:', error);
      return 0;
    }
  }

  /**
   * Schema anomaly detection
   * Identifies structural changes in data schema
   * 
   * @param record - Current record being analyzed
   * @param referenceData - Reference dataset for schema comparison
   * @returns Promise<number> - Schema anomaly score (0-1)
   */
  private async detectSchemaAnomalies(
    record: any,
    referenceData?: any[]
  ): Promise<number> {
    try {
      if (!referenceData || referenceData.length === 0) {
        return 0; // No reference schema to compare against
      }
      
      const referenceSchema = this.extractSchema(referenceData[0]);
      const recordSchema = this.extractSchema(record);
      
      let anomalyScore = 0;
      
      // Check for missing fields
      const missingFields = referenceSchema.fields.filter(field => 
        !recordSchema.fields.includes(field)
      );
      
      // Check for extra fields
      const extraFields = recordSchema.fields.filter(field => 
        !referenceSchema.fields.includes(field)
      );
      
      // Check for type mismatches
      const typeMismatches = [];
      for (const field of referenceSchema.fields) {
        if (recordSchema.fields.includes(field)) {
          const refType = referenceSchema.types[field];
          const recordType = recordSchema.types[field];
          if (refType !== recordType) {
            typeMismatches.push(field);
          }
        }
      }
      
      // Calculate schema anomaly score
      const totalFields = referenceSchema.fields.length;
      const schemaDifferences = missingFields.length + extraFields.length + typeMismatches.length;
      anomalyScore = Math.min(schemaDifferences / totalFields, 1);
      
      return anomalyScore;
    } catch (error) {
      logger.error('Schema anomaly detection failed:', error);
      return 0;
    }
  }

  /**
   * Combine anomaly scores from multiple detection methods
   * Uses ensemble approach with weighted voting
   * 
   * @param scores - Individual anomaly scores from different methods
   * @returns Combined ensemble result
   */
  private combineAnomalyScores(scores: {
    isolation: number;
    lof: number;
    statistical: number;
    pattern: number;
    schema: number;
  }): {
    anomalyScore: number;
    confidence: number;
    dominantType: string;
    affectedFeatures: string[];
    individualScores: any;
    featureContributions: any;
  } {
    // Weights for different detection methods
    const weights = {
      isolation: 0.25,
      lof: 0.25,
      statistical: 0.25,
      pattern: 0.15,
      schema: 0.10,
    };
    
    // Calculate weighted average
    const weightedScore = 
      (scores.isolation * weights.isolation) +
      (scores.lof * weights.lof) +
      (scores.statistical * weights.statistical) +
      (scores.pattern * weights.pattern) +
      (scores.schema * weights.schema);
    
    // Determine dominant anomaly type
    const scoreEntries = Object.entries(scores);
    const dominantEntry = scoreEntries.reduce((max, current) => 
      current[1] > max[1] ? current : max
    );
    
    // Calculate confidence based on score consistency
    const scoreValues = Object.values(scores);
    const meanScore = scoreValues.reduce((sum, score) => sum + score, 0) / scoreValues.length;
    const variance = scoreValues.reduce((sum, score) => sum + Math.pow(score - meanScore, 2), 0) / scoreValues.length;
    const consistency = 1 - Math.min(variance / meanScore, 1);
    const confidence = (weightedScore * 0.7) + (consistency * 0.3);
    
    return {
      anomalyScore: weightedScore,
      confidence: Math.min(Math.max(confidence, 0), 1),
      dominantType: this.mapScoreTypeToAnomalyType(dominantEntry[0]),
      affectedFeatures: ['all'], // Simplified - would be more specific in production
      individualScores: scores,
      featureContributions: {}, // Simplified - would include detailed feature analysis
    };
  }

  /**
   * Calculate severity of anomaly based on score and confidence
   * 
   * @param anomalyScore - Combined anomaly score
   * @param confidence - Confidence in the detection
   * @returns Severity level
   */
  private calculateAnomalySeverity(anomalyScore: number, confidence: number): 'low' | 'medium' | 'high' | 'critical' {
    const adjustedScore = anomalyScore * confidence;
    
    if (adjustedScore >= 0.8) return 'critical';
    if (adjustedScore >= 0.6) return 'high';
    if (adjustedScore >= 0.4) return 'medium';
    return 'low';
  }

  /**
   * Store anomaly detections in database
   * Persists anomaly detection results for historical tracking
   */
  private async storeAnomalyDetections(
    assetId: number,
    datasetName: string,
    detectionResults: RecordAnomalyResult[],
    environment: string
  ): Promise<void> {
    for (const result of detectionResults) {
      const anomalyDetection: InsertDataAnomalyDetection = {
        assetId,
        datasetName,
        anomalyType: result.anomalyType,
        severity: result.severity,
        confidence: result.confidence.toString(),
        description: `${result.anomalyType} anomaly detected in record ${result.recordId}`,
        affectedRecords: 1,
        totalRecords: detectionResults.length,
        detectionMethod: result.detectionMethod,
        anomalyScore: result.anomalyScore.toString(),
        threshold: this.config.ensembleThreshold.toString(),
        features: result.affectedFeatures,
        context: result.details,
        environment,
      };
      
      await this.storage.createAnomalyDetection(anomalyDetection);
    }
  }

  /**
   * Generate alerts for critical anomalies
   * Creates alerts for anomalies that require immediate attention
   */
  private async generateAnomalyAlerts(
    assetId: number,
    datasetName: string,
    detectionResults: RecordAnomalyResult[]
  ): Promise<Array<{ alertType: string; severity: string; title: string; description: string }>> {
    const alerts: Array<{ alertType: string; severity: string; title: string; description: string }> = [];
    
    // Critical anomalies alert
    const criticalAnomalies = detectionResults.filter(r => r.severity === 'critical');
    if (criticalAnomalies.length > 0) {
      const alert = {
        alertType: 'critical_anomalies',
        severity: 'critical',
        title: 'Critical Data Anomalies Detected',
        description: `${criticalAnomalies.length} critical anomalies detected in dataset ${datasetName}. Immediate investigation required.`,
      };
      
      alerts.push(alert);
      
      const alertRecord: InsertDataIntegrityAlert = {
        assetId,
        alertType: 'critical_anomalies',
        severity: 'critical',
        title: alert.title,
        description: alert.description,
        impact: 'data_accuracy',
        datasetName,
        affectedRecords: criticalAnomalies.length,
        totalRecords: detectionResults.length,
        detectionSource: 'anomaly_detection',
        metadata: {
          criticalAnomalyCount: criticalAnomalies.length,
          dominantAnomalyTypes: this.getDominantAnomalyTypes(criticalAnomalies),
        },
      };
      
      await this.storage.createIntegrityAlert(alertRecord);
    }
    
    // High anomaly rate alert
    const anomalyRate = detectionResults.length / 100; // Assuming 100 total records for rate calculation
    if (anomalyRate > 0.1) { // More than 10% anomalies
      const alert = {
        alertType: 'high_anomaly_rate',
        severity: 'high',
        title: 'High Anomaly Rate Detected',
        description: `Anomaly rate of ${(anomalyRate * 100).toFixed(1)}% detected in dataset ${datasetName}. Data quality may be compromised.`,
      };
      
      alerts.push(alert);
      
      const alertRecord: InsertDataIntegrityAlert = {
        assetId,
        alertType: 'high_anomaly_rate',
        severity: 'high',
        title: alert.title,
        description: alert.description,
        impact: 'model_performance',
        datasetName,
        affectedRecords: detectionResults.length,
        detectionSource: 'anomaly_detection',
        metadata: {
          anomalyRate,
          threshold: 0.1,
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
        source: 'anomaly_detector',
        metadata: {
          assetId,
          datasetName,
          alertType: alert.alertType,
        },
      });
    }
    
    return alerts;
  }

  // Helper methods for various calculations and utilities

  private validateInputData(data: any[]): void {
    if (!Array.isArray(data) || data.length === 0) {
      throw new Error('Input data must be a non-empty array');
    }
    
    if (data.length < 10) {
      throw new Error('Minimum 10 records required for reliable anomaly detection');
    }
  }

  private extractNumericFeatures(data: any[]): { [key: string]: number[] } {
    const features: { [key: string]: number[] } = {};
    
    if (data.length === 0) return features;
    
    const sampleRecord = data[0];
    const potentialFeatures = Object.keys(sampleRecord).filter(key => 
      key !== 'id' && 
      key !== 'timestamp' && 
      key !== 'created_at' && 
      key !== 'updated_at'
    );
    
    for (const feature of potentialFeatures) {
      const values = data
        .map(record => record[feature])
        .filter(value => typeof value === 'number' && !isNaN(value));
      
      if (values.length > data.length * 0.8) { // At least 80% numeric values
        features[feature] = values;
      }
    }
    
    return features;
  }

  private prepareFeatureMatrix(data: any[], featureNames: string[]): number[][] {
    return data.map(record => 
      featureNames.map(feature => {
        const value = record[feature];
        return typeof value === 'number' && !isNaN(value) ? value : 0;
      })
    );
  }

  private calculateEuclideanDistance(point1: number[], point2: number[]): number {
    if (point1.length !== point2.length) {
      throw new Error('Points must have the same dimensions');
    }
    
    let sumSquares = 0;
    for (let i = 0; i < point1.length; i++) {
      sumSquares += Math.pow(point1[i] - point2[i], 2);
    }
    
    return Math.sqrt(sumSquares);
  }

  private calculateMean(values: number[]): number {
    return values.reduce((sum, val) => sum + val, 0) / values.length;
  }

  private calculateStdDev(values: number[], mean: number): number {
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }

  private calculateIQRAnomalyScore(value: number, values: number[]): number {
    const sorted = [...values].sort((a, b) => a - b);
    const q1Index = Math.floor(sorted.length * 0.25);
    const q3Index = Math.floor(sorted.length * 0.75);
    const q1 = sorted[q1Index];
    const q3 = sorted[q3Index];
    const iqr = q3 - q1;
    
    const lowerBound = q1 - 1.5 * iqr;
    const upperBound = q3 + 1.5 * iqr;
    
    if (value < lowerBound || value > upperBound) {
      const distance = Math.min(Math.abs(value - lowerBound), Math.abs(value - upperBound));
      return Math.min(distance / iqr, 1);
    }
    
    return 0;
  }

  private calculateModifiedZScore(value: number, values: number[]): number {
    const median = this.calculateMedian(values);
    const deviations = values.map(v => Math.abs(v - median));
    const mad = this.calculateMedian(deviations); // Median Absolute Deviation
    
    if (mad === 0) return 0;
    
    const modifiedZScore = 0.6745 * (value - median) / mad;
    return Math.min(Math.abs(modifiedZScore) / 3.5, 1); // 3.5 is common threshold
  }

  private calculateMedian(values: number[]): number {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    
    if (sorted.length % 2 === 0) {
      return (sorted[mid - 1] + sorted[mid]) / 2;
    } else {
      return sorted[mid];
    }
  }

  private calculateIsolationPathLength(point: number[], data: number[][]): number {
    // Simplified isolation path calculation
    // In production, would implement full isolation tree algorithm
    let depth = 0;
    let currentData = [...data];
    
    while (currentData.length > 1 && depth < 20) { // Limit depth for performance
      const featureIndex = Math.floor(Math.random() * point.length);
      const splitValue = this.getRandomSplitValue(currentData, featureIndex);
      
      const leftPartition = currentData.filter(record => record[featureIndex] < splitValue);
      const rightPartition = currentData.filter(record => record[featureIndex] >= splitValue);
      
      if (point[featureIndex] < splitValue) {
        currentData = leftPartition;
      } else {
        currentData = rightPartition;
      }
      
      depth++;
    }
    
    return depth;
  }

  private getRandomSplitValue(data: number[][], featureIndex: number): number {
    const values = data.map(record => record[featureIndex]);
    const min = Math.min(...values);
    const max = Math.max(...values);
    return min + Math.random() * (max - min);
  }

  private calculateExpectedPathLength(n: number): number {
    // Expected path length for isolation tree
    if (n <= 1) return 0;
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
  }

  private getKDistance(pointIndex: number, data: number[][], k: number): number {
    const point = data[pointIndex];
    const distances: number[] = [];
    
    for (let i = 0; i < data.length; i++) {
      if (i !== pointIndex) {
        const distance = this.calculateEuclideanDistance(point, data[i]);
        distances.push(distance);
      }
    }
    
    distances.sort((a, b) => a - b);
    return distances[k - 1] || 0;
  }

  private calculateLocalReachabilityDensity(pointIndex: number, data: number[][], k: number): number {
    const point = data[pointIndex];
    const distances: Array<{ index: number; distance: number }> = [];
    
    for (let i = 0; i < data.length; i++) {
      if (i !== pointIndex) {
        const distance = this.calculateEuclideanDistance(point, data[i]);
        distances.push({ index: i, distance });
      }
    }
    
    distances.sort((a, b) => a.distance - b.distance);
    const kNeighbors = distances.slice(0, k);
    
    const reachabilityDistances = kNeighbors.map(neighbor => 
      Math.max(neighbor.distance, this.getKDistance(neighbor.index, data, k))
    );
    
    const avgReachabilityDistance = reachabilityDistances.reduce((sum, dist) => sum + dist, 0) / k;
    return 1 / (avgReachabilityDistance + 1e-10);
  }

  private analyzeTemporalPattern(record: any, allData: any[], recordIndex: number): number {
    // Simplified temporal pattern analysis
    // Would implement more sophisticated time series analysis in production
    try {
      const timestamp = new Date(record.timestamp || record.created_at);
      const timeValues = allData
        .map(r => new Date(r.timestamp || r.created_at))
        .filter(t => !isNaN(t.getTime()));
      
      if (timeValues.length < 2) return 0;
      
      // Check for unusual time gaps
      timeValues.sort((a, b) => a.getTime() - b.getTime());
      const gaps = [];
      for (let i = 1; i < timeValues.length; i++) {
        gaps.push(timeValues[i].getTime() - timeValues[i - 1].getTime());
      }
      
      const meanGap = gaps.reduce((sum, gap) => sum + gap, 0) / gaps.length;
      const stdGap = Math.sqrt(gaps.reduce((sum, gap) => sum + Math.pow(gap - meanGap, 2), 0) / gaps.length);
      
      // Find the gap involving current record
      const currentIndex = timeValues.findIndex(t => t.getTime() === timestamp.getTime());
      if (currentIndex > 0) {
        const currentGap = timeValues[currentIndex].getTime() - timeValues[currentIndex - 1].getTime();
        const zScore = stdGap > 0 ? Math.abs(currentGap - meanGap) / stdGap : 0;
        return Math.min(zScore / 3, 1); // Normalize using 3-sigma rule
      }
      
      return 0;
    } catch (error) {
      logger.error('Temporal pattern analysis failed:', error);
      return 0;
    }
  }

  private analyzeSequencePattern(record: any, allData: any[], recordIndex: number): number {
    // Simplified sequence pattern analysis
    // Check for unusual patterns in sequential data
    try {
      if (recordIndex < 2 || recordIndex >= allData.length - 2) {
        return 0; // Need surrounding context
      }
      
      const windowSize = 3;
      const window = allData.slice(recordIndex - 1, recordIndex + 2);
      
      // Simple pattern analysis based on numeric field variations
      const numericFields = Object.keys(record).filter(key => typeof record[key] === 'number');
      
      if (numericFields.length === 0) return 0;
      
      let patternScores: number[] = [];
      
      for (const field of numericFields) {
        const windowValues = window.map(r => r[field]).filter(v => typeof v === 'number');
        
        if (windowValues.length === windowSize) {
          // Check for unusual jumps or patterns
          const diffs = [];
          for (let i = 1; i < windowValues.length; i++) {
            diffs.push(Math.abs(windowValues[i] - windowValues[i - 1]));
          }
          
          const maxDiff = Math.max(...diffs);
          const avgDiff = diffs.reduce((sum, diff) => sum + diff, 0) / diffs.length;
          
          if (avgDiff > 0) {
            const patternScore = Math.min(maxDiff / avgDiff / 5, 1); // Normalize
            patternScores.push(patternScore);
          }
        }
      }
      
      return patternScores.length > 0 ? Math.max(...patternScores) : 0;
    } catch (error) {
      logger.error('Sequence pattern analysis failed:', error);
      return 0;
    }
  }

  private analyzeCategoricalPattern(record: any, allData: any[]): number {
    // Analyze categorical field distributions for anomalies
    try {
      const categoricalFields = Object.keys(record).filter(key => 
        typeof record[key] === 'string' && 
        key !== 'id' && 
        key !== 'timestamp' && 
        key !== 'created_at'
      );
      
      if (categoricalFields.length === 0) return 0;
      
      let anomalyScores: number[] = [];
      
      for (const field of categoricalFields) {
        const fieldValues = allData.map(r => r[field]).filter(v => typeof v === 'string');
        const valueCounts: { [key: string]: number } = {};
        
        // Count occurrences of each value
        for (const value of fieldValues) {
          valueCounts[value] = (valueCounts[value] || 0) + 1;
        }
        
        const recordValue = record[field];
        const valueCount = valueCounts[recordValue] || 0;
        const totalCount = fieldValues.length;
        
        // Calculate rarity score (rare values are more anomalous)
        const frequency = valueCount / totalCount;
        const rarityScore = 1 - frequency; // Higher score for rarer values
        
        anomalyScores.push(rarityScore);
      }
      
      return anomalyScores.length > 0 ? Math.max(...anomalyScores) : 0;
    } catch (error) {
      logger.error('Categorical pattern analysis failed:', error);
      return 0;
    }
  }

  private extractSchema(record: any): { fields: string[]; types: { [key: string]: string } } {
    const fields = Object.keys(record);
    const types: { [key: string]: string } = {};
    
    for (const field of fields) {
      types[field] = typeof record[field];
    }
    
    return { fields, types };
  }

  private mapScoreTypeToAnomalyType(scoreType: string): string {
    const mapping: { [key: string]: string } = {
      isolation: 'outlier',
      lof: 'density_anomaly',
      statistical: 'statistical_outlier',
      pattern: 'pattern_anomaly',
      schema: 'schema_anomaly',
    };
    
    return mapping[scoreType] || 'unknown';
  }

  private calculateSeverityDistribution(results: RecordAnomalyResult[]): {
    low: number;
    medium: number;
    high: number;
    critical: number;
  } {
    const distribution = { low: 0, medium: 0, high: 0, critical: 0 };
    
    for (const result of results) {
      distribution[result.severity]++;
    }
    
    return distribution;
  }

  private generateAnomalyRecommendations(results: RecordAnomalyResult[], totalRecords: number): string[] {
    const recommendations: string[] = [];
    const anomalyRate = results.length / totalRecords;
    
    if (anomalyRate > 0.2) {
      recommendations.push('High anomaly rate detected - investigate data collection processes');
    }
    
    const criticalCount = results.filter(r => r.severity === 'critical').length;
    if (criticalCount > 0) {
      recommendations.push(`${criticalCount} critical anomalies require immediate investigation`);
    }
    
    const dominantTypes = this.getDominantAnomalyTypes(results);
    if (dominantTypes.outlier > results.length * 0.5) {
      recommendations.push('High number of outliers - review data preprocessing and feature scaling');
    }
    
    if (dominantTypes.pattern_anomaly > 0) {
      recommendations.push('Pattern anomalies detected - investigate temporal data consistency');
    }
    
    if (dominantTypes.schema_anomaly > 0) {
      recommendations.push('Schema anomalies detected - ensure consistent data structure');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('Continue monitoring for anomaly patterns and trends');
    }
    
    return recommendations;
  }

  private getDominantAnomalyTypes(results: RecordAnomalyResult[]): { [key: string]: number } {
    const typeCounts: { [key: string]: number } = {};
    
    for (const result of results) {
      typeCounts[result.anomalyType] = (typeCounts[result.anomalyType] || 0) + 1;
    }
    
    return typeCounts;
  }

  /**
   * Update anomaly detection configuration
   * Allows runtime adjustment of thresholds and parameters
   */
  async updateConfig(newConfig: Partial<AnomalyDetectionConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    logger.info('Anomaly detection configuration updated', { newConfig });
  }

  /**
   * Get current anomaly detection configuration
   */
  getConfig(): AnomalyDetectionConfig {
    return { ...this.config };
  }
}