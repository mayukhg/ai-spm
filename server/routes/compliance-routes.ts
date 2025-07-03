/**
 * AI Security Posture Management Platform - Compliance Routes
 * ==========================================================
 * 
 * This module provides REST API endpoints for compliance assessment workflows
 * including evidence collection and comprehensive report generation for
 * regulatory frameworks like NIST AI RMF, EU AI Act, and GDPR.
 * 
 * Key Features:
 * - Evidence collection API endpoints
 * - Report generation in multiple formats (PDF, Excel, HTML, JSON)
 * - Framework-specific compliance assessments
 * - Real-time evidence validation
 * - Automated compliance gap analysis
 * - Scheduled evidence collection management
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { Router, Request, Response } from 'express';
import { logger } from '../monitoring/logger';
import { evidenceCollector, ComplianceFramework, EvidenceType } from '../compliance/evidence-collector';
import { complianceReportGenerator, ReportFormat, ReportType } from '../compliance/report-generator';
// Simple middleware placeholders - TODO: Implement proper authentication
const loginRequired = (req: any, res: any, next: any) => next();
const roleRequired = (roles: string[]) => (req: any, res: any, next: any) => next();

const router = Router();

/**
 * Collect evidence for a specific compliance framework
 * POST /api/compliance/evidence/collect
 * 
 * Request Body:
 * {
 *   "framework": "nist_ai_rmf" | "eu_ai_act" | "gdpr",
 *   "dateRange": {
 *     "startDate": "2024-01-01T00:00:00Z",
 *     "endDate": "2024-12-31T23:59:59Z"
 *   }
 * }
 */
router.post('/evidence/collect', loginRequired, roleRequired(['admin', 'ciso', 'compliance-officer']), async (req: Request, res: Response) => {
  try {
    const { framework, dateRange } = req.body;

    // Validate framework
    if (!framework || !Object.values(ComplianceFramework).includes(framework)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing compliance framework',
        availableFrameworks: Object.values(ComplianceFramework)
      });
    }

    // Parse date range if provided
    let parsedDateRange;
    if (dateRange) {
      try {
        parsedDateRange = {
          startDate: new Date(dateRange.startDate),
          endDate: new Date(dateRange.endDate)
        };
        
        // Validate dates
        if (isNaN(parsedDateRange.startDate.getTime()) || isNaN(parsedDateRange.endDate.getTime())) {
          throw new Error('Invalid date format');
        }
        
        if (parsedDateRange.startDate >= parsedDateRange.endDate) {
          throw new Error('Start date must be before end date');
        }
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: 'Invalid date range format. Use ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ)'
        });
      }
    }

    logger.info('Starting evidence collection', {
      framework,
      dateRange: parsedDateRange,
      userId: (req as any).user?.id,
      correlationId: `evidence-collect-${Date.now()}`
    });

    // Collect evidence
    const evidenceReport = await evidenceCollector.collectEvidence(framework, parsedDateRange);

    logger.info('Evidence collection completed', {
      framework,
      evidenceCount: evidenceReport.evidenceItems.length,
      completionPercentage: evidenceReport.completionPercentage,
      userId: (req as any).user?.id
    });

    res.json({
      success: true,
      data: evidenceReport,
      metadata: {
        collectionTime: new Date().toISOString(),
        requestedBy: (req as any).user?.email,
        framework
      }
    });

  } catch (error) {
    logger.error('Evidence collection failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      framework: req.body.framework,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Evidence collection failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Generate compliance report
 * POST /api/compliance/reports/generate
 * 
 * Request Body:
 * {
 *   "framework": "nist_ai_rmf" | "eu_ai_act" | "gdpr",
 *   "reportType": "executive_summary" | "detailed_technical" | "compliance_gap_analysis" | "evidence_inventory" | "risk_assessment" | "remediation_plan",
 *   "format": "pdf" | "excel" | "html" | "json",
 *   "includeEvidence": true,
 *   "includeRecommendations": true,
 *   "dateRange": {
 *     "startDate": "2024-01-01T00:00:00Z",
 *     "endDate": "2024-12-31T23:59:59Z"
 *   },
 *   "branding": {
 *     "companyName": "Your Company",
 *     "colors": {
 *       "primary": "#337ab7",
 *       "secondary": "#5bc0de"
 *     }
 *   }
 * }
 */
router.post('/reports/generate', loginRequired, roleRequired(['admin', 'ciso', 'compliance-officer']), async (req: Request, res: Response) => {
  try {
    const { 
      framework, 
      reportType = ReportType.EXECUTIVE_SUMMARY, 
      format = ReportFormat.PDF, 
      includeEvidence = true, 
      includeRecommendations = true, 
      dateRange,
      branding
    } = req.body;

    // Validate required fields
    if (!framework || !Object.values(ComplianceFramework).includes(framework)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing compliance framework',
        availableFrameworks: Object.values(ComplianceFramework)
      });
    }

    if (!Object.values(ReportType).includes(reportType)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid report type',
        availableTypes: Object.values(ReportType)
      });
    }

    if (!Object.values(ReportFormat).includes(format)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid report format',
        availableFormats: Object.values(ReportFormat)
      });
    }

    // Parse date range if provided
    let parsedDateRange;
    if (dateRange) {
      try {
        parsedDateRange = {
          startDate: new Date(dateRange.startDate),
          endDate: new Date(dateRange.endDate)
        };
        
        if (isNaN(parsedDateRange.startDate.getTime()) || isNaN(parsedDateRange.endDate.getTime())) {
          throw new Error('Invalid date format');
        }
        
        if (parsedDateRange.startDate >= parsedDateRange.endDate) {
          throw new Error('Start date must be before end date');
        }
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: 'Invalid date range format. Use ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ)'
        });
      }
    }

    logger.info('Starting compliance report generation', {
      framework,
      reportType,
      format,
      userId: (req as any).user?.id,
      correlationId: `report-gen-${Date.now()}`
    });

    // Create report configuration
    const reportConfig = {
      framework,
      reportType,
      format,
      includeEvidence,
      includeRecommendations,
      dateRange: parsedDateRange,
      branding: branding ? {
        companyName: branding.companyName || 'AI-SPM Platform',
        colors: {
          primary: branding.colors?.primary || '#337ab7',
          secondary: branding.colors?.secondary || '#5bc0de'
        }
      } : undefined
    };

    // Generate report
    const reportMetadata = await complianceReportGenerator.generateReport(reportConfig);

    logger.info('Compliance report generated successfully', {
      reportId: reportMetadata.id,
      framework,
      format,
      fileSize: reportMetadata.fileSize,
      evidenceCount: reportMetadata.evidenceCount,
      complianceScore: reportMetadata.complianceScore,
      userId: (req as any).user?.id
    });

    res.json({
      success: true,
      data: reportMetadata,
      metadata: {
        generationTime: new Date().toISOString(),
        requestedBy: (req as any).user?.email,
        config: reportConfig
      }
    });

  } catch (error) {
    logger.error('Report generation failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      framework: req.body.framework,
      reportType: req.body.reportType,
      format: req.body.format,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Report generation failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get evidence collection statistics
 * GET /api/compliance/evidence/stats
 * 
 * Query Parameters:
 * - framework (optional): Filter statistics by framework
 */
router.get('/evidence/stats', loginRequired, roleRequired(['admin', 'ciso', 'compliance-officer', 'analyst']), async (req: Request, res: Response) => {
  try {
    const { framework } = req.query;

    // Validate framework if provided
    if (framework && !Object.values(ComplianceFramework).includes(framework as ComplianceFramework)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid compliance framework',
        availableFrameworks: Object.values(ComplianceFramework)
      });
    }

    const stats = evidenceCollector.getEvidenceStatistics(framework as ComplianceFramework);

    res.json({
      success: true,
      data: stats,
      metadata: {
        retrievedAt: new Date().toISOString(),
        requestedBy: (req as any).user?.email
      }
    });

  } catch (error) {
    logger.error('Failed to get evidence statistics', {
      error: error instanceof Error ? error.message : 'Unknown error',
      framework: req.query.framework,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve evidence statistics',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Schedule evidence collection for a framework
 * POST /api/compliance/evidence/schedule
 * 
 * Request Body:
 * {
 *   "framework": "nist_ai_rmf" | "eu_ai_act" | "gdpr",
 *   "intervalHours": 24
 * }
 */
router.post('/evidence/schedule', loginRequired, roleRequired(['admin', 'ciso']), async (req: Request, res: Response) => {
  try {
    const { framework, intervalHours = 24 } = req.body;

    // Validate framework
    if (!framework || !Object.values(ComplianceFramework).includes(framework)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing compliance framework',
        availableFrameworks: Object.values(ComplianceFramework)
      });
    }

    // Validate interval
    if (typeof intervalHours !== 'number' || intervalHours < 1 || intervalHours > 168) {
      return res.status(400).json({
        success: false,
        error: 'Invalid interval. Must be between 1 and 168 hours (1 week)'
      });
    }

    evidenceCollector.scheduleEvidenceCollection(framework, intervalHours);

    logger.info('Evidence collection scheduled', {
      framework,
      intervalHours,
      userId: (req as any).user?.id
    });

    res.json({
      success: true,
      message: `Evidence collection scheduled for ${framework} every ${intervalHours} hours`,
      data: {
        framework,
        intervalHours,
        nextCollection: new Date(Date.now() + intervalHours * 60 * 60 * 1000).toISOString()
      }
    });

  } catch (error) {
    logger.error('Failed to schedule evidence collection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      framework: req.body.framework,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Failed to schedule evidence collection',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Stop scheduled evidence collection for a framework
 * DELETE /api/compliance/evidence/schedule/:framework
 */
router.delete('/evidence/schedule/:framework', loginRequired, roleRequired(['admin', 'ciso']), async (req: Request, res: Response) => {
  try {
    const { framework } = req.params;

    // Validate framework
    if (!Object.values(ComplianceFramework).includes(framework as ComplianceFramework)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid compliance framework',
        availableFrameworks: Object.values(ComplianceFramework)
      });
    }

    evidenceCollector.stopScheduledCollection(framework as ComplianceFramework);

    logger.info('Scheduled evidence collection stopped', {
      framework,
      userId: (req as any).user?.id
    });

    res.json({
      success: true,
      message: `Scheduled evidence collection stopped for ${framework}`,
      data: {
        framework,
        stoppedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('Failed to stop scheduled evidence collection', {
      error: error instanceof Error ? error.message : 'Unknown error',
      framework: req.params.framework,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Failed to stop scheduled evidence collection',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get report generation statistics
 * GET /api/compliance/reports/stats
 */
router.get('/reports/stats', loginRequired, roleRequired(['admin', 'ciso', 'compliance-officer', 'analyst']), async (req: Request, res: Response) => {
  try {
    const stats = complianceReportGenerator.getReportStatistics();

    res.json({
      success: true,
      data: stats,
      metadata: {
        retrievedAt: new Date().toISOString(),
        requestedBy: (req as any).user?.email
      }
    });

  } catch (error) {
    logger.error('Failed to get report generation statistics', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve report generation statistics',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Get available compliance frameworks
 * GET /api/compliance/frameworks
 */
router.get('/frameworks', loginRequired, async (req: Request, res: Response) => {
  try {
    const frameworks = complianceReportGenerator.getAvailableFrameworks();

    res.json({
      success: true,
      data: {
        frameworks,
        availableEvidenceTypes: Object.values(EvidenceType),
        availableReportTypes: Object.values(ReportType),
        availableReportFormats: Object.values(ReportFormat)
      },
      metadata: {
        retrievedAt: new Date().toISOString(),
        requestedBy: (req as any).user?.email
      }
    });

  } catch (error) {
    logger.error('Failed to get available frameworks', {
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve available frameworks',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Test evidence collection with sample data
 * POST /api/compliance/evidence/test
 * 
 * Request Body:
 * {
 *   "framework": "nist_ai_rmf" | "eu_ai_act" | "gdpr",
 *   "evidenceType": "configuration" | "audit_log" | "scan_result" | etc.
 * }
 */
router.post('/evidence/test', loginRequired, roleRequired(['admin', 'ciso']), async (req: Request, res: Response) => {
  try {
    const { framework, evidenceType } = req.body;

    // Validate framework
    if (!framework || !Object.values(ComplianceFramework).includes(framework)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing compliance framework',
        availableFrameworks: Object.values(ComplianceFramework)
      });
    }

    // Validate evidence type if provided
    if (evidenceType && !Object.values(EvidenceType).includes(evidenceType)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid evidence type',
        availableTypes: Object.values(EvidenceType)
      });
    }

    logger.info('Testing evidence collection', {
      framework,
      evidenceType,
      userId: (req as any).user?.id
    });

    // Collect evidence for testing (limited scope)
    const testDateRange = {
      startDate: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
      endDate: new Date()
    };

    const evidenceReport = await evidenceCollector.collectEvidence(framework, testDateRange);

    // Filter by evidence type if specified
    let filteredEvidence = evidenceReport.evidenceItems;
    if (evidenceType) {
      filteredEvidence = evidenceReport.evidenceItems.filter(item => item.type === evidenceType);
    }

    res.json({
      success: true,
      message: 'Evidence collection test completed',
      data: {
        framework,
        evidenceType: evidenceType || 'all',
        totalEvidence: filteredEvidence.length,
        validEvidence: filteredEvidence.filter(item => item.validationStatus === 'valid').length,
        invalidEvidence: filteredEvidence.filter(item => item.validationStatus === 'invalid').length,
        warningEvidence: filteredEvidence.filter(item => item.validationStatus === 'warning').length,
        sampleEvidence: filteredEvidence.slice(0, 5), // First 5 items as sample
        testResults: {
          collectionTime: evidenceReport.collectionDate,
          completionPercentage: evidenceReport.completionPercentage,
          missingEvidence: evidenceReport.missingEvidence
        }
      },
      metadata: {
        testExecutedAt: new Date().toISOString(),
        executedBy: (req as any).user?.email
      }
    });

  } catch (error) {
    logger.error('Evidence collection test failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      framework: req.body.framework,
      evidenceType: req.body.evidenceType,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Evidence collection test failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Download generated report file
 * GET /api/compliance/reports/download/:reportId
 */
router.get('/reports/download/:reportId', loginRequired, roleRequired(['admin', 'ciso', 'compliance-officer']), async (req: Request, res: Response) => {
  try {
    const { reportId } = req.params;

    // For this implementation, we'll assume the report file exists in the logs directory
    // In a production environment, you would store report metadata in the database
    // and retrieve the file path from there
    
    logger.info('Report download requested', {
      reportId,
      userId: (req as any).user?.id
    });

    // This is a simplified implementation
    // In production, you would:
    // 1. Query the database for report metadata by reportId
    // 2. Verify the user has permission to access the report
    // 3. Check if the file still exists
    // 4. Set appropriate headers for the file type
    // 5. Stream the file to the client

    res.status(501).json({
      success: false,
      error: 'Report download feature requires additional implementation',
      message: 'This feature would be implemented with proper report metadata storage and file serving capabilities'
    });

  } catch (error) {
    logger.error('Report download failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      reportId: req.params.reportId,
      userId: (req as any).user?.id
    });

    res.status(500).json({
      success: false,
      error: 'Report download failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export default router;