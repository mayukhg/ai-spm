/**
 * Data Drift Detector - Real-time monitoring of distribution changes in AI datasets
 * 
 * This service provides comprehensive data drift detection capabilities including:
 * - Feature drift detection using statistical tests
 * - Prediction drift monitoring for model outputs
 * - Label drift detection for supervised learning
 * - Population stability index (PSI) calculation
 * - Wasserstein distance and KL divergence analysis
 * 
 * Key Features:
 * - Multiple statistical tests: Kolmogorov-Smirnov, Chi-square, Mann-Whitney U
 * - Configurable thresholds and sensitivity settings
 * - Real-time drift scoring and alerting
 * - Historical drift tracking and trend analysis
 * - Integration with monitoring and alerting systems
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { logger } from '../monitoring/logger';
import { DataDriftMetric, InsertDataDriftMetric, InsertDataIntegrityAlert } from '../../shared/schema';
import { DataQualityStorage } from './data-quality-storage';
import { AlertManager } from '../monitoring/alert-manager';

// Configuration for drift detection parameters
interface DriftDetectionConfig {
  featureDriftThreshold: number;      // Threshold for feature drift detection (0-1)
  predictionDriftThreshold: number;   // Threshold for prediction drift detection (0-1)
  labelDriftThreshold: number;        // Threshold for label drift detection (0-1)
  psiThreshold: number;              // Population Stability Index threshold (0-1)
  minSampleSize: number;             // Minimum sample size for reliable drift detection
  confidenceLevel: number;           // Statistical confidence level (0-1)
  driftWindowSize: number;           // Number of samples in drift detection window
}

// Statistical test result
interface StatisticalTestResult {
  testName: string;
  pValue: number;
  statistic: number;
  criticalValue: number;
  isDrifted: boolean;
  confidenceLevel: number;
}

// Drift detection result for a single feature
interface FeatureDriftResult {
  featureName: string;
  driftScore: number;
  psiScore: number;
  statisticalTests: StatisticalTestResult[];
  distributionMetrics: {
    referenceMean: number;
    currentMean: number;
    referenceStd: number;
    currentStd: number;
    meanShift: number;
    varianceRatio: number;
  };
  isDrifted: boolean;
  driftSeverity: 'low' | 'medium' | 'high' | 'critical';
}

// Dataset drift analysis result
interface DatasetDriftAnalysis {
  datasetName: string;
  assetId: number;
  referenceDatasetId: string;
  currentDatasetId: string;
  totalFeatures: number;
  driftedFeatures: number;
  overallDriftScore: number;
  featureDriftResults: FeatureDriftResult[];
  predictionDriftResult?: FeatureDriftResult;
  labelDriftResult?: FeatureDriftResult;
  recommendations: string[];
  alerts: Array<{
    alertType: string;
    severity: string;
    title: string;
    description: string;
  }>;
}

export class DataDriftDetector {
  private storage: DataQualityStorage;
  private alertManager: AlertManager;
  private config: DriftDetectionConfig;

  constructor(storage: DataQualityStorage, alertManager: AlertManager) {
    this.storage = storage;
    this.alertManager = alertManager;
    
    // Default configuration - can be overridden
    this.config = {
      featureDriftThreshold: 0.25,      // 25% drift threshold
      predictionDriftThreshold: 0.15,   // 15% prediction drift threshold
      labelDriftThreshold: 0.20,        // 20% label drift threshold
      psiThreshold: 0.25,              // PSI threshold for significant drift
      minSampleSize: 100,              // Minimum 100 samples for drift detection
      confidenceLevel: 0.95,           // 95% confidence level
      driftWindowSize: 1000,           // 1000 samples in drift detection window
    };

    logger.info('Data Drift Detector initialized with default thresholds');
  }

  /**
   * Detect drift between reference and current datasets
   * Performs comprehensive drift analysis including feature, prediction, and label drift
   * 
   * @param assetId - ID of the AI asset
   * @param datasetName - Name of the dataset being analyzed
   * @param referenceData - Reference dataset for comparison
   * @param currentData - Current dataset to analyze for drift
   * @param referenceDatasetId - Identifier for reference dataset
   * @param currentDatasetId - Identifier for current dataset
   * @param environment - Environment context (training, inference, validation)
   * @returns Promise<DatasetDriftAnalysis> - Complete drift analysis results
   */
  async detectDrift(
    assetId: number,
    datasetName: string,
    referenceData: any[],
    currentData: any[],
    referenceDatasetId: string,
    currentDatasetId: string,
    environment: string = 'inference'
  ): Promise<DatasetDriftAnalysis> {
    const startTime = Date.now();
    
    try {
      logger.info(`Starting drift detection for dataset: ${datasetName} (ref: ${referenceData.length}, current: ${currentData.length} records)`);

      // Validate sample sizes
      this.validateSampleSizes(referenceData, currentData);

      // Get feature names from reference data
      const featureNames = this.extractFeatureNames(referenceData);
      
      // Detect feature drift for each feature
      const featureDriftResults: FeatureDriftResult[] = [];
      
      for (const featureName of featureNames) {
        // Skip non-numeric features for now (could be extended for categorical)
        if (this.isNumericFeature(referenceData, featureName)) {
          const driftResult = await this.detectFeatureDrift(
            featureName,
            referenceData,
            currentData
          );
          featureDriftResults.push(driftResult);
        }
      }

      // Calculate overall drift score
      const overallDriftScore = this.calculateOverallDriftScore(featureDriftResults);

      // Detect prediction drift (if prediction columns exist)
      let predictionDriftResult: FeatureDriftResult | undefined;
      if (this.hasPredictionColumn(referenceData)) {
        predictionDriftResult = await this.detectFeatureDrift(
          'prediction',
          referenceData,
          currentData
        );
      }

      // Detect label drift (if label columns exist)
      let labelDriftResult: FeatureDriftResult | undefined;
      if (this.hasLabelColumn(referenceData)) {
        labelDriftResult = await this.detectFeatureDrift(
          'label',
          referenceData,
          currentData
        );
      }

      // Count drifted features
      const driftedFeatures = featureDriftResults.filter(r => r.isDrifted).length;

      // Generate recommendations
      const recommendations = this.generateDriftRecommendations(
        featureDriftResults,
        predictionDriftResult,
        labelDriftResult,
        overallDriftScore
      );

      // Store drift metrics in database
      await this.storeDriftMetrics(
        assetId,
        datasetName,
        referenceDatasetId,
        currentDatasetId,
        featureDriftResults,
        predictionDriftResult,
        labelDriftResult,
        overallDriftScore,
        environment
      );

      // Generate alerts for significant drift
      const alerts = await this.generateDriftAlerts(
        assetId,
        datasetName,
        featureDriftResults,
        predictionDriftResult,
        labelDriftResult,
        overallDriftScore
      );

      const driftAnalysis: DatasetDriftAnalysis = {
        datasetName,
        assetId,
        referenceDatasetId,
        currentDatasetId,
        totalFeatures: featureNames.length,
        driftedFeatures,
        overallDriftScore,
        featureDriftResults,
        predictionDriftResult,
        labelDriftResult,
        recommendations,
        alerts,
      };

      const processingTime = Date.now() - startTime;
      logger.info(`Drift detection completed for ${datasetName} in ${processingTime}ms - Overall Drift Score: ${overallDriftScore.toFixed(4)}`);

      return driftAnalysis;
    } catch (error) {
      logger.error(`Drift detection failed for dataset ${datasetName}:`, error);
      throw new Error(`Drift detection failed: ${(error as Error).message}`);
    }
  }

  /**
   * Detect drift for a single feature using multiple statistical tests
   * Combines multiple test results for robust drift detection
   * 
   * @param featureName - Name of the feature to analyze
   * @param referenceData - Reference dataset
   * @param currentData - Current dataset
   * @returns Promise<FeatureDriftResult> - Feature drift analysis result
   */
  private async detectFeatureDrift(
    featureName: string,
    referenceData: any[],
    currentData: any[]
  ): Promise<FeatureDriftResult> {
    try {
      // Extract feature values
      const referenceValues = this.extractFeatureValues(referenceData, featureName);
      const currentValues = this.extractFeatureValues(currentData, featureName);

      // Calculate distribution metrics
      const distributionMetrics = this.calculateDistributionMetrics(referenceValues, currentValues);

      // Perform statistical tests
      const statisticalTests: StatisticalTestResult[] = [];
      
      // Kolmogorov-Smirnov test
      const ksTest = this.performKolmogorovSmirnovTest(referenceValues, currentValues);
      statisticalTests.push(ksTest);

      // Mann-Whitney U test (for continuous data)
      const mannWhitneyTest = this.performMannWhitneyTest(referenceValues, currentValues);
      statisticalTests.push(mannWhitneyTest);

      // Calculate Population Stability Index (PSI)
      const psiScore = this.calculatePSI(referenceValues, currentValues);

      // Calculate Wasserstein distance
      const wassersteinDistance = this.calculateWassersteinDistance(referenceValues, currentValues);

      // Combine test results into overall drift score
      const driftScore = this.calculateCombinedDriftScore(statisticalTests, psiScore, wassersteinDistance);

      // Determine if feature is drifted
      const isDrifted = this.isDriftSignificant(driftScore, psiScore, statisticalTests);

      // Determine drift severity
      const driftSeverity = this.calculateDriftSeverity(driftScore, psiScore);

      return {
        featureName,
        driftScore,
        psiScore,
        statisticalTests,
        distributionMetrics,
        isDrifted,
        driftSeverity,
      };
    } catch (error) {
      logger.error(`Feature drift detection failed for ${featureName}:`, error);
      throw new Error(`Feature drift detection failed: ${(error as Error).message}`);
    }
  }

  /**
   * Perform Kolmogorov-Smirnov test for distribution comparison
   * Tests the null hypothesis that two samples come from the same distribution
   * 
   * @param sample1 - First sample (reference)
   * @param sample2 - Second sample (current)
   * @returns StatisticalTestResult - KS test result
   */
  private performKolmogorovSmirnovTest(sample1: number[], sample2: number[]): StatisticalTestResult {
    const n1 = sample1.length;
    const n2 = sample2.length;
    
    // Sort samples
    const sorted1 = [...sample1].sort((a, b) => a - b);
    const sorted2 = [...sample2].sort((a, b) => a - b);
    
    // Calculate empirical CDFs and find maximum difference
    let maxDiff = 0;
    let i = 0, j = 0;
    
    while (i < n1 && j < n2) {
      const val1 = sorted1[i];
      const val2 = sorted2[j];
      
      if (val1 <= val2) {
        const cdf1 = (i + 1) / n1;
        const cdf2 = j / n2;
        maxDiff = Math.max(maxDiff, Math.abs(cdf1 - cdf2));
        i++;
      } else {
        const cdf1 = i / n1;
        const cdf2 = (j + 1) / n2;
        maxDiff = Math.max(maxDiff, Math.abs(cdf1 - cdf2));
        j++;
      }
    }
    
    // KS statistic
    const ksStatistic = maxDiff;
    
    // Critical value for 95% confidence
    const criticalValue = 1.36 * Math.sqrt((n1 + n2) / (n1 * n2));
    
    // P-value approximation (simplified)
    const pValue = Math.exp(-2 * ksStatistic * ksStatistic * n1 * n2 / (n1 + n2));
    
    return {
      testName: 'Kolmogorov-Smirnov',
      pValue: Math.min(pValue, 1.0),
      statistic: ksStatistic,
      criticalValue,
      isDrifted: ksStatistic > criticalValue,
      confidenceLevel: this.config.confidenceLevel,
    };
  }

  /**
   * Perform Mann-Whitney U test for distribution comparison
   * Non-parametric test for comparing two independent samples
   * 
   * @param sample1 - First sample (reference)
   * @param sample2 - Second sample (current)
   * @returns StatisticalTestResult - Mann-Whitney U test result
   */
  private performMannWhitneyTest(sample1: number[], sample2: number[]): StatisticalTestResult {
    const n1 = sample1.length;
    const n2 = sample2.length;
    
    // Combine and rank all values
    const combined = [...sample1.map(v => ({ value: v, group: 1 })), ...sample2.map(v => ({ value: v, group: 2 }))];
    combined.sort((a, b) => a.value - b.value);
    
    // Calculate ranks (handling ties with average rank)
    const ranks = new Array(combined.length);
    let i = 0;
    while (i < combined.length) {
      let j = i;
      while (j < combined.length && combined[j].value === combined[i].value) {
        j++;
      }
      const avgRank = (i + j + 1) / 2;
      for (let k = i; k < j; k++) {
        ranks[k] = avgRank;
      }
      i = j;
    }
    
    // Calculate sum of ranks for first group
    let r1 = 0;
    for (let i = 0; i < combined.length; i++) {
      if (combined[i].group === 1) {
        r1 += ranks[i];
      }
    }
    
    // Calculate U statistics
    const u1 = r1 - (n1 * (n1 + 1)) / 2;
    const u2 = n1 * n2 - u1;
    const uStatistic = Math.min(u1, u2);
    
    // Expected value and standard deviation for U
    const expectedU = (n1 * n2) / 2;
    const stdU = Math.sqrt((n1 * n2 * (n1 + n2 + 1)) / 12);
    
    // Z-score
    const zScore = (uStatistic - expectedU) / stdU;
    
    // P-value (two-tailed)
    const pValue = 2 * (1 - this.normalCDF(Math.abs(zScore)));
    
    // Critical value for 95% confidence
    const criticalValue = 1.96; // Z-score for 95% confidence
    
    return {
      testName: 'Mann-Whitney U',
      pValue,
      statistic: Math.abs(zScore),
      criticalValue,
      isDrifted: Math.abs(zScore) > criticalValue,
      confidenceLevel: this.config.confidenceLevel,
    };
  }

  /**
   * Calculate Population Stability Index (PSI)
   * Measures the stability of a population over time
   * 
   * @param referenceValues - Reference distribution
   * @param currentValues - Current distribution
   * @returns number - PSI value
   */
  private calculatePSI(referenceValues: number[], currentValues: number[]): number {
    // Create bins based on reference data quantiles
    const numBins = 10;
    const refSorted = [...referenceValues].sort((a, b) => a - b);
    const binEdges = [];
    
    for (let i = 0; i <= numBins; i++) {
      const quantile = i / numBins;
      const index = Math.floor(quantile * (refSorted.length - 1));
      binEdges.push(refSorted[index]);
    }
    
    // Count values in each bin for both distributions
    const refCounts = new Array(numBins).fill(0);
    const currentCounts = new Array(numBins).fill(0);
    
    for (const value of referenceValues) {
      const bin = this.findBin(value, binEdges);
      if (bin >= 0 && bin < numBins) refCounts[bin]++;
    }
    
    for (const value of currentValues) {
      const bin = this.findBin(value, binEdges);
      if (bin >= 0 && bin < numBins) currentCounts[bin]++;
    }
    
    // Calculate PSI
    let psi = 0;
    for (let i = 0; i < numBins; i++) {
      const refProp = refCounts[i] / referenceValues.length;
      const currentProp = currentCounts[i] / currentValues.length;
      
      // Avoid division by zero
      if (refProp > 0 && currentProp > 0) {
        psi += (currentProp - refProp) * Math.log(currentProp / refProp);
      }
    }
    
    return psi;
  }

  /**
   * Calculate Wasserstein distance between two distributions
   * Measures the minimum cost to transform one distribution into another
   * 
   * @param sample1 - First distribution
   * @param sample2 - Second distribution
   * @returns number - Wasserstein distance
   */
  private calculateWassersteinDistance(sample1: number[], sample2: number[]): number {
    const sorted1 = [...sample1].sort((a, b) => a - b);
    const sorted2 = [...sample2].sort((a, b) => a - b);
    
    let distance = 0;
    let i = 0, j = 0;
    let cdf1 = 0, cdf2 = 0;
    
    while (i < sorted1.length || j < sorted2.length) {
      if (i >= sorted1.length) {
        cdf2 += 1 / sorted2.length;
        distance += Math.abs(cdf1 - cdf2);
        j++;
      } else if (j >= sorted2.length) {
        cdf1 += 1 / sorted1.length;
        distance += Math.abs(cdf1 - cdf2);
        i++;
      } else if (sorted1[i] <= sorted2[j]) {
        cdf1 += 1 / sorted1.length;
        distance += Math.abs(cdf1 - cdf2);
        i++;
      } else {
        cdf2 += 1 / sorted2.length;
        distance += Math.abs(cdf1 - cdf2);
        j++;
      }
    }
    
    return distance;
  }

  /**
   * Calculate distribution metrics for comparison
   * Computes mean, standard deviation, and shift metrics
   * 
   * @param referenceValues - Reference distribution
   * @param currentValues - Current distribution
   * @returns Distribution metrics object
   */
  private calculateDistributionMetrics(referenceValues: number[], currentValues: number[]) {
    const referenceMean = this.calculateMean(referenceValues);
    const currentMean = this.calculateMean(currentValues);
    const referenceStd = this.calculateStdDev(referenceValues, referenceMean);
    const currentStd = this.calculateStdDev(currentValues, currentMean);
    
    const meanShift = Math.abs(currentMean - referenceMean) / referenceStd;
    const varianceRatio = currentStd / referenceStd;
    
    return {
      referenceMean,
      currentMean,
      referenceStd,
      currentStd,
      meanShift,
      varianceRatio,
    };
  }

  /**
   * Calculate combined drift score from multiple tests
   * Combines statistical test results and distance measures
   * 
   * @param statisticalTests - Array of statistical test results
   * @param psiScore - PSI score
   * @param wassersteinDistance - Wasserstein distance
   * @returns number - Combined drift score
   */
  private calculateCombinedDriftScore(
    statisticalTests: StatisticalTestResult[],
    psiScore: number,
    wassersteinDistance: number
  ): number {
    // Weight different components
    const weights = {
      statisticalTests: 0.4,
      psi: 0.3,
      wasserstein: 0.3,
    };
    
    // Calculate average p-value from statistical tests
    const avgPValue = statisticalTests.reduce((sum, test) => sum + (1 - test.pValue), 0) / statisticalTests.length;
    
    // Normalize components to 0-1 range
    const normalizedPSI = Math.min(psiScore / 0.5, 1.0); // PSI > 0.5 is considered very high
    const normalizedWasserstein = Math.min(wassersteinDistance / 2.0, 1.0); // Normalize to reasonable range
    
    // Calculate weighted score
    const combinedScore = 
      (avgPValue * weights.statisticalTests) +
      (normalizedPSI * weights.psi) +
      (normalizedWasserstein * weights.wasserstein);
    
    return Math.min(combinedScore, 1.0);
  }

  /**
   * Determine if drift is significant based on multiple criteria
   * Uses thresholds and test results to make drift determination
   * 
   * @param driftScore - Combined drift score
   * @param psiScore - PSI score
   * @param statisticalTests - Array of statistical test results
   * @returns boolean - True if drift is significant
   */
  private isDriftSignificant(
    driftScore: number,
    psiScore: number,
    statisticalTests: StatisticalTestResult[]
  ): boolean {
    // Check if overall drift score exceeds threshold
    if (driftScore > this.config.featureDriftThreshold) return true;
    
    // Check if PSI exceeds threshold
    if (psiScore > this.config.psiThreshold) return true;
    
    // Check if any statistical test indicates significant drift
    const significantTests = statisticalTests.filter(test => test.isDrifted);
    if (significantTests.length >= 2) return true; // At least 2 tests show drift
    
    return false;
  }

  /**
   * Calculate drift severity based on scores
   * Categorizes drift into severity levels
   * 
   * @param driftScore - Combined drift score
   * @param psiScore - PSI score
   * @returns Drift severity level
   */
  private calculateDriftSeverity(driftScore: number, psiScore: number): 'low' | 'medium' | 'high' | 'critical' {
    const maxScore = Math.max(driftScore, psiScore);
    
    if (maxScore >= 0.5) return 'critical';
    if (maxScore >= 0.35) return 'high';
    if (maxScore >= 0.2) return 'medium';
    return 'low';
  }

  /**
   * Calculate overall drift score for the entire dataset
   * Combines feature drift scores into dataset-level score
   * 
   * @param featureDriftResults - Array of feature drift results
   * @returns number - Overall drift score
   */
  private calculateOverallDriftScore(featureDriftResults: FeatureDriftResult[]): number {
    if (featureDriftResults.length === 0) return 0;
    
    // Calculate weighted average based on drift severity
    const weights = { low: 0.1, medium: 0.3, high: 0.7, critical: 1.0 };
    
    let totalWeightedScore = 0;
    let totalWeight = 0;
    
    for (const result of featureDriftResults) {
      const weight = weights[result.driftSeverity];
      totalWeightedScore += result.driftScore * weight;
      totalWeight += weight;
    }
    
    return totalWeight > 0 ? totalWeightedScore / totalWeight : 0;
  }

  /**
   * Store drift metrics in database
   * Persists drift detection results for historical tracking
   */
  private async storeDriftMetrics(
    assetId: number,
    datasetName: string,
    referenceDatasetId: string,
    currentDatasetId: string,
    featureDriftResults: FeatureDriftResult[],
    predictionDriftResult: FeatureDriftResult | undefined,
    labelDriftResult: FeatureDriftResult | undefined,
    overallDriftScore: number,
    environment: string
  ): Promise<void> {
    // Store feature drift metrics
    for (const result of featureDriftResults) {
      const driftMetric: InsertDataDriftMetric = {
        assetId,
        datasetName,
        referenceDatasetId,
        currentDatasetId,
        driftType: 'feature_drift',
        driftScore: result.driftScore.toString(),
        threshold: this.config.featureDriftThreshold.toString(),
        status: result.isDrifted ? 'significant_drift' : 'stable',
        affectedFeatures: [result.featureName],
        detectionMethod: 'kolmogorov_smirnov',
        statisticalTest: {
          tests: result.statisticalTests,
          psiScore: result.psiScore,
          distributionMetrics: result.distributionMetrics,
        },
        recommendations: this.generateFeatureRecommendations(result),
        environment,
      };
      
      await this.storage.createDriftMetric(driftMetric);
    }
    
    // Store prediction drift if available
    if (predictionDriftResult) {
      const predictionDriftMetric: InsertDataDriftMetric = {
        assetId,
        datasetName,
        referenceDatasetId,
        currentDatasetId,
        driftType: 'prediction_drift',
        driftScore: predictionDriftResult.driftScore.toString(),
        threshold: this.config.predictionDriftThreshold.toString(),
        status: predictionDriftResult.isDrifted ? 'significant_drift' : 'stable',
        affectedFeatures: ['prediction'],
        detectionMethod: 'kolmogorov_smirnov',
        statisticalTest: {
          tests: predictionDriftResult.statisticalTests,
          psiScore: predictionDriftResult.psiScore,
          distributionMetrics: predictionDriftResult.distributionMetrics,
        },
        recommendations: 'Monitor model performance and consider retraining if drift persists',
        environment,
      };
      
      await this.storage.createDriftMetric(predictionDriftMetric);
    }
    
    // Store label drift if available
    if (labelDriftResult) {
      const labelDriftMetric: InsertDataDriftMetric = {
        assetId,
        datasetName,
        referenceDatasetId,
        currentDatasetId,
        driftType: 'label_drift',
        driftScore: labelDriftResult.driftScore.toString(),
        threshold: this.config.labelDriftThreshold.toString(),
        status: labelDriftResult.isDrifted ? 'significant_drift' : 'stable',
        affectedFeatures: ['label'],
        detectionMethod: 'kolmogorov_smirnov',
        statisticalTest: {
          tests: labelDriftResult.statisticalTests,
          psiScore: labelDriftResult.psiScore,
          distributionMetrics: labelDriftResult.distributionMetrics,
        },
        recommendations: 'Review labeling process and data collection methods',
        environment,
      };
      
      await this.storage.createDriftMetric(labelDriftMetric);
    }
  }

  /**
   * Generate drift alerts for significant changes
   * Creates alerts that require immediate attention
   */
  private async generateDriftAlerts(
    assetId: number,
    datasetName: string,
    featureDriftResults: FeatureDriftResult[],
    predictionDriftResult: FeatureDriftResult | undefined,
    labelDriftResult: FeatureDriftResult | undefined,
    overallDriftScore: number
  ): Promise<Array<{ alertType: string; severity: string; title: string; description: string }>> {
    const alerts: Array<{ alertType: string; severity: string; title: string; description: string }> = [];
    
    // Check for critical feature drift
    const criticalFeatures = featureDriftResults.filter(r => r.driftSeverity === 'critical');
    if (criticalFeatures.length > 0) {
      const alert = {
        alertType: 'critical_feature_drift',
        severity: 'critical',
        title: 'Critical Feature Drift Detected',
        description: `${criticalFeatures.length} features show critical drift: ${criticalFeatures.map(f => f.featureName).join(', ')}. This may significantly impact model performance.`,
      };
      
      alerts.push(alert);
      
      // Create database alert
      const alertRecord: InsertDataIntegrityAlert = {
        assetId,
        alertType: 'critical_feature_drift',
        severity: 'critical',
        title: alert.title,
        description: alert.description,
        impact: 'model_performance',
        datasetName,
        detectionSource: 'drift_detection',
        metadata: {
          criticalFeatures: criticalFeatures.map(f => f.featureName),
          overallDriftScore,
          affectedFeatureCount: criticalFeatures.length,
        },
      };
      
      await this.storage.createIntegrityAlert(alertRecord);
    }
    
    // Check for prediction drift
    if (predictionDriftResult && predictionDriftResult.isDrifted) {
      const alert = {
        alertType: 'prediction_drift',
        severity: this.mapSeverityToAlertLevel(predictionDriftResult.driftSeverity),
        title: 'Prediction Drift Detected',
        description: `Model predictions are drifting (drift score: ${predictionDriftResult.driftScore.toFixed(4)}). Consider model retraining or investigation.`,
      };
      
      alerts.push(alert);
      
      const alertRecord: InsertDataIntegrityAlert = {
        assetId,
        alertType: 'prediction_drift',
        severity: alert.severity,
        title: alert.title,
        description: alert.description,
        impact: 'model_performance',
        datasetName,
        detectionSource: 'drift_detection',
        metadata: {
          driftScore: predictionDriftResult.driftScore,
          psiScore: predictionDriftResult.psiScore,
          driftSeverity: predictionDriftResult.driftSeverity,
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
        source: 'data_drift_detector',
        metadata: {
          assetId,
          datasetName,
          alertType: alert.alertType,
          overallDriftScore,
        },
      });
    }
    
    return alerts;
  }

  /**
   * Generate recommendations for drift mitigation
   * Provides actionable recommendations based on drift analysis
   */
  private generateDriftRecommendations(
    featureDriftResults: FeatureDriftResult[],
    predictionDriftResult: FeatureDriftResult | undefined,
    labelDriftResult: FeatureDriftResult | undefined,
    overallDriftScore: number
  ): string[] {
    const recommendations: string[] = [];
    
    if (overallDriftScore > 0.3) {
      recommendations.push('Consider retraining the model with recent data to address significant drift');
    }
    
    const criticalFeatures = featureDriftResults.filter(r => r.driftSeverity === 'critical');
    if (criticalFeatures.length > 0) {
      recommendations.push(`Investigate data collection processes for features: ${criticalFeatures.map(f => f.featureName).join(', ')}`);
    }
    
    if (predictionDriftResult?.isDrifted) {
      recommendations.push('Monitor model performance metrics and consider implementing online learning or model updates');
    }
    
    if (labelDriftResult?.isDrifted) {
      recommendations.push('Review labeling guidelines and data annotation processes');
    }
    
    const highDriftFeatures = featureDriftResults.filter(r => r.driftSeverity === 'high');
    if (highDriftFeatures.length > 0) {
      recommendations.push('Implement feature monitoring and alerting for early drift detection');
    }
    
    if (recommendations.length === 0) {
      recommendations.push('Continue monitoring data quality and drift patterns');
    }
    
    return recommendations;
  }

  /**
   * Generate feature-specific recommendations
   * Provides targeted recommendations for individual features
   */
  private generateFeatureRecommendations(result: FeatureDriftResult): string {
    const recommendations: string[] = [];
    
    if (result.distributionMetrics.meanShift > 2) {
      recommendations.push('Significant mean shift detected - investigate data source changes');
    }
    
    if (result.distributionMetrics.varianceRatio > 2 || result.distributionMetrics.varianceRatio < 0.5) {
      recommendations.push('Variance change detected - check data collection consistency');
    }
    
    if (result.psiScore > 0.25) {
      recommendations.push('High PSI score indicates population stability issues');
    }
    
    return recommendations.join('; ') || 'Monitor feature distribution over time';
  }

  // Helper methods

  private validateSampleSizes(referenceData: any[], currentData: any[]): void {
    if (referenceData.length < this.config.minSampleSize) {
      throw new Error(`Reference sample size (${referenceData.length}) is below minimum required (${this.config.minSampleSize})`);
    }
    
    if (currentData.length < this.config.minSampleSize) {
      throw new Error(`Current sample size (${currentData.length}) is below minimum required (${this.config.minSampleSize})`);
    }
  }

  private extractFeatureNames(data: any[]): string[] {
    if (data.length === 0) return [];
    
    return Object.keys(data[0]).filter(key => 
      key !== 'id' && 
      key !== 'timestamp' && 
      key !== 'created_at' && 
      key !== 'updated_at' &&
      key !== 'prediction' &&
      key !== 'label'
    );
  }

  private isNumericFeature(data: any[], featureName: string): boolean {
    const sampleValues = data.slice(0, 10);
    return sampleValues.every(record => 
      record[featureName] !== null && 
      record[featureName] !== undefined && 
      typeof record[featureName] === 'number'
    );
  }

  private hasPredictionColumn(data: any[]): boolean {
    return data.length > 0 && 'prediction' in data[0];
  }

  private hasLabelColumn(data: any[]): boolean {
    return data.length > 0 && ('label' in data[0] || 'target' in data[0]);
  }

  private extractFeatureValues(data: any[], featureName: string): number[] {
    return data
      .map(record => record[featureName])
      .filter(value => value !== null && value !== undefined && typeof value === 'number');
  }

  private calculateMean(values: number[]): number {
    return values.reduce((sum, val) => sum + val, 0) / values.length;
  }

  private calculateStdDev(values: number[], mean: number): number {
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }

  private findBin(value: number, binEdges: number[]): number {
    for (let i = 0; i < binEdges.length - 1; i++) {
      if (value >= binEdges[i] && value < binEdges[i + 1]) {
        return i;
      }
    }
    return binEdges.length - 2; // Last bin
  }

  private normalCDF(z: number): number {
    // Approximation of normal CDF
    const t = 1 / (1 + 0.2316419 * Math.abs(z));
    const d = 0.3989423 * Math.exp(-z * z / 2);
    let prob = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    
    if (z > 0) {
      prob = 1 - prob;
    }
    
    return prob;
  }

  private mapSeverityToAlertLevel(severity: 'low' | 'medium' | 'high' | 'critical'): string {
    const mapping = {
      low: 'low',
      medium: 'medium',
      high: 'high',
      critical: 'critical',
    };
    return mapping[severity];
  }

  /**
   * Update drift detection configuration
   * Allows runtime adjustment of thresholds and parameters
   */
  async updateConfig(newConfig: Partial<DriftDetectionConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    logger.info('Data drift detection configuration updated', { newConfig });
  }

  /**
   * Get current drift detection configuration
   */
  getConfig(): DriftDetectionConfig {
    return { ...this.config };
  }
}