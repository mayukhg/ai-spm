/**
 * Adversarial Detection API Routes
 * ================================
 * 
 * REST API endpoints for adversarial attack detection and automated response management.
 * Provides comprehensive access to all detection engines with real-time threat analysis.
 * 
 * @author AI-SPM Security Team
 * @version 1.0.0
 */

import { Router, Request, Response } from 'express';
import { logger } from '../monitoring/logger';
import { AdversarialDetectionManager } from '../adversarial-detection/adversarial-detection-manager';
import { evasionDecision, inferredAttribute, membershipSuspects, poisoningIds } from '../analysis/synthetic-analysis';

const router = Router();
const detectionManager = new AdversarialDetectionManager();

/**
 * Analyze dataset for data poisoning attacks
 * POST /api/adversarial-detection/data-poisoning/analyze
 */
router.post('/data-poisoning/analyze', async (req: Request, res: Response) => {
  try {
    const { datasetId, samples, modelPredictions } = req.body;

    if (!datasetId || !samples || !Array.isArray(samples)) {
      return res.status(400).json({
        error: 'Missing required fields: datasetId, samples (array)',
        code: 'INVALID_REQUEST'
      });
    }

    const result = await detectionManager.analyzeDataset(
      datasetId,
      samples,
      modelPredictions
    );

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Data poisoning analysis failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/data-poisoning/analyze'
    });

    res.status(500).json({
      error: 'Data poisoning analysis failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'ANALYSIS_FAILED'
    });
  }
});

/**
 * Analyze input for model evasion attacks
 * POST /api/adversarial-detection/model-evasion/analyze
 */
router.post('/model-evasion/analyze', async (req: Request, res: Response) => {
  try {
    const { inputSample, predictions, baselineInput } = req.body;

    if (!inputSample || !predictions || !Array.isArray(predictions)) {
      return res.status(400).json({
        error: 'Missing required fields: inputSample, predictions (array)',
        code: 'INVALID_REQUEST'
      });
    }

    const result = await detectionManager.analyzeInput(
      inputSample,
      predictions,
      baselineInput
    );

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Model evasion analysis failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/model-evasion/analyze'
    });

    res.status(500).json({
      error: 'Model evasion analysis failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'ANALYSIS_FAILED'
    });
  }
});

/**
 * Analyze queries for membership inference attacks
 * POST /api/adversarial-detection/membership-inference/analyze
 */
router.post('/membership-inference/analyze', async (req: Request, res: Response) => {
  try {
    const { queryId, modelId, samples, shadowPredictions } = req.body;

    if (!queryId || !modelId || !samples || !Array.isArray(samples)) {
      return res.status(400).json({
        error: 'Missing required fields: queryId, modelId, samples (array)',
        code: 'INVALID_REQUEST'
      });
    }

    const result = await detectionManager.analyzeMembershipInference(
      queryId,
      modelId,
      samples,
      shadowPredictions
    );

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Membership inference analysis failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/membership-inference/analyze'
    });

    res.status(500).json({
      error: 'Membership inference analysis failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'ANALYSIS_FAILED'
    });
  }
});

/**
 * Analyze predictions for attribute inference attacks
 * POST /api/adversarial-detection/attribute-inference/analyze
 */
router.post('/attribute-inference/analyze', async (req: Request, res: Response) => {
  try {
    const { queryId, modelId, samples, targetAttributes } = req.body;

    if (!queryId || !modelId || !samples || !Array.isArray(samples) || !targetAttributes || !Array.isArray(targetAttributes)) {
      return res.status(400).json({
        error: 'Missing required fields: queryId, modelId, samples (array), targetAttributes (array)',
        code: 'INVALID_REQUEST'
      });
    }

    const result = await detectionManager.analyzeAttributeInference(
      queryId,
      modelId,
      samples,
      targetAttributes
    );

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Attribute inference analysis failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/attribute-inference/analyze'
    });

    res.status(500).json({
      error: 'Attribute inference analysis failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'ANALYSIS_FAILED'
    });
  }
});

/**
 * Get comprehensive threat detection statistics
 * GET /api/adversarial-detection/stats
 */
router.get('/stats', (req: Request, res: Response) => {
  try {
    const stats = detectionManager.getDetectionStats();

    res.json({
      success: true,
      data: stats,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Failed to get detection stats', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/stats'
    });

    res.status(500).json({
      error: 'Failed to get detection statistics',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'STATS_FAILED'
    });
  }
});

/**
 * Get quarantined assets
 * GET /api/adversarial-detection/quarantine
 */
router.get('/quarantine', (req: Request, res: Response) => {
  try {
    const quarantinedAssets = detectionManager.getQuarantinedAssets();

    res.json({
      success: true,
      data: quarantinedAssets,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Failed to get quarantined assets', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/quarantine'
    });

    res.status(500).json({
      error: 'Failed to get quarantined assets',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'QUARANTINE_FAILED'
    });
  }
});

/**
 * Release asset from quarantine
 * POST /api/adversarial-detection/quarantine/release
 */
router.post('/quarantine/release', (req: Request, res: Response) => {
  try {
    const { assetId, reason } = req.body;

    if (!assetId || !reason) {
      return res.status(400).json({
        error: 'Missing required fields: assetId, reason',
        code: 'INVALID_REQUEST'
      });
    }

    const success = detectionManager.releaseFromQuarantine(assetId, reason);

    if (success) {
      res.json({
        success: true,
        message: 'Asset released from quarantine',
        data: { assetId, reason },
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(404).json({
        error: 'Asset not found in quarantine',
        code: 'ASSET_NOT_QUARANTINED'
      });
    }

  } catch (error) {
    logger.error('Failed to release asset from quarantine', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/quarantine/release'
    });

    res.status(500).json({
      error: 'Failed to release asset from quarantine',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'RELEASE_FAILED'
    });
  }
});

/**
 * Get active security incidents
 * GET /api/adversarial-detection/incidents
 */
router.get('/incidents', (req: Request, res: Response) => {
  try {
    const incidents = detectionManager.getActiveIncidents();

    res.json({
      success: true,
      data: incidents,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Failed to get active incidents', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/incidents'
    });

    res.status(500).json({
      error: 'Failed to get active incidents',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'INCIDENTS_FAILED'
    });
  }
});

/**
 * Update response configuration
 * PUT /api/adversarial-detection/config
 */
router.put('/config', (req: Request, res: Response) => {
  try {
    const config = req.body;

    // Validate configuration structure
    if (typeof config !== 'object' || config === null) {
      return res.status(400).json({
        error: 'Invalid configuration format',
        code: 'INVALID_CONFIG'
      });
    }

    detectionManager.updateResponseConfiguration(config);

    res.json({
      success: true,
      message: 'Response configuration updated',
      data: config,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Failed to update response configuration', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/config'
    });

    res.status(500).json({
      error: 'Failed to update response configuration',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'CONFIG_UPDATE_FAILED'
    });
  }
});

/**
 * Clear blocked inputs (admin function)
 * POST /api/adversarial-detection/blocked-inputs/clear
 */
router.post('/blocked-inputs/clear', (req: Request, res: Response) => {
  try {
    detectionManager.clearBlockedInputs();

    res.json({
      success: true,
      message: 'All blocked inputs cleared',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Failed to clear blocked inputs', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/blocked-inputs/clear'
    });

    res.status(500).json({
      error: 'Failed to clear blocked inputs',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'CLEAR_FAILED'
    });
  }
});

/**
 * Test adversarial detection with sample data
 * POST /api/adversarial-detection/test
 */
router.post('/test', async (req: Request, res: Response) => {
  try {
    const { testType } = req.body;

    let result;

    switch (testType) {
      case 'data_poisoning':
        result = { affectedSampleIds: poisoningIds(), source: 'fixtures/synthetic/ticket-training-set-poisoned.json' };
        break;

      case 'model_evasion': {
        const decision = evasionDecision();
        result = { ...decision, blocked: true, source: 'fixtures/synthetic/evasion-pair.json' };
        break;
      }

      case 'membership_inference':
        result = { suspectedMemberIds: membershipSuspects(), source: 'fixtures/synthetic/membership-queries.json' };
        break;

      case 'attribute_inference':
        result = { ...inferredAttribute(), source: 'fixtures/synthetic/attribute-queries.json' };
        break;

      default:
        return res.status(400).json({
          error: 'Invalid test type. Must be one of: data_poisoning, model_evasion, membership_inference, attribute_inference',
          code: 'INVALID_TEST_TYPE'
        });
    }

    res.json({
      success: true,
      message: `${testType} test completed`,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Adversarial detection test failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      endpoint: '/api/adversarial-detection/test'
    });

    res.status(500).json({
      error: 'Adversarial detection test failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: 'TEST_FAILED'
    });
  }
});

export default router;