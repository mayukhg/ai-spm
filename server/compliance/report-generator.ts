/**
 * AI Security Posture Management Platform - Compliance Report Generator
 * ====================================================================
 * 
 * This module provides comprehensive compliance report generation capabilities
 * for various regulatory frameworks including NIST AI RMF, EU AI Act, and GDPR.
 * 
 * Key Features:
 * - PDF report generation with professional formatting
 * - Excel report generation with detailed data tables
 * - Framework-specific report templates
 * - Evidence mapping and cross-referencing
 * - Executive summary and detailed technical sections
 * - Compliance gap analysis and recommendations
 * - Automated evidence validation and integrity checks
 * 
 * @author AI-SPM Development Team
 * @version 1.0.0
 */

import { promises as fs } from 'fs';
import path from 'path';
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';
import * as XLSX from 'xlsx';
import { logger } from '../monitoring/logger';
import { metrics } from '../monitoring/metrics-collector';
import { 
  EvidenceCollector, 
  ComplianceFramework, 
  EvidenceType,
  evidenceCollector 
} from './evidence-collector';

/**
 * Report formats supported by the generator
 */
export enum ReportFormat {
  PDF = 'pdf',
  EXCEL = 'excel',
  HTML = 'html',
  JSON = 'json'
}

/**
 * Report types that can be generated
 */
export enum ReportType {
  EXECUTIVE_SUMMARY = 'executive_summary',
  DETAILED_TECHNICAL = 'detailed_technical',
  COMPLIANCE_GAP_ANALYSIS = 'compliance_gap_analysis',
  EVIDENCE_INVENTORY = 'evidence_inventory',
  RISK_ASSESSMENT = 'risk_assessment',
  REMEDIATION_PLAN = 'remediation_plan'
}

/**
 * Report generation configuration
 */
interface ReportConfig {
  framework: ComplianceFramework;
  reportType: ReportType;
  format: ReportFormat;
  includeEvidence: boolean;
  includeRecommendations: boolean;
  dateRange?: {
    startDate: Date;
    endDate: Date;
  };
  customSections?: string[];
  branding?: {
    companyName: string;
    logo?: string;
    colors?: {
      primary: string;
      secondary: string;
    };
  };
}

/**
 * Generated report metadata
 */
interface ReportMetadata {
  id: string;
  framework: ComplianceFramework;
  reportType: ReportType;
  format: ReportFormat;
  generatedAt: Date;
  generatedBy: string;
  version: string;
  pageCount?: number;
  fileSize: number;
  filePath: string;
  evidenceCount: number;
  complianceScore: number;
  validationStatus: 'valid' | 'invalid' | 'warning';
}

/**
 * Compliance report structure
 */
interface ComplianceReport {
  metadata: ReportMetadata;
  executiveSummary: {
    overallScore: number;
    criticalFindings: number;
    recommendationsCount: number;
    evidenceGaps: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  };
  frameworkCompliance: {
    framework: ComplianceFramework;
    totalControls: number;
    compliantControls: number;
    partiallyCompliantControls: number;
    nonCompliantControls: number;
    notApplicableControls: number;
    compliancePercentage: number;
  };
  evidenceSummary: {
    totalEvidence: number;
    validEvidence: number;
    invalidEvidence: number;
    warningEvidence: number;
    missingEvidence: number;
    evidenceByType: Record<EvidenceType, number>;
  };
  findings: ComplianceFinding[];
  recommendations: ComplianceRecommendation[];
  evidenceInventory: any[];
  appendices: {
    technicalDetails: any;
    evidenceDetails: any;
    glossary: any;
  };
}

/**
 * Compliance finding structure
 */
interface ComplianceFinding {
  id: string;
  control: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'compliant' | 'partially_compliant' | 'non_compliant' | 'not_applicable';
  description: string;
  evidence: string[];
  gaps: string[];
  riskImpact: string;
  recommendation: string;
}

/**
 * Compliance recommendation structure
 */
interface ComplianceRecommendation {
  id: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  control: string;
  title: string;
  description: string;
  implementation: string;
  timeline: string;
  effort: 'low' | 'medium' | 'high';
  cost: 'low' | 'medium' | 'high';
  dependencies: string[];
}

/**
 * Compliance Report Generator Class
 * Handles generation of comprehensive compliance reports in multiple formats
 */
export class ComplianceReportGenerator {
  private metricsCollector: typeof metrics;
  private evidenceCollector: EvidenceCollector;
  private reportTemplates: Map<ComplianceFramework, any>;

  constructor() {
    this.metricsCollector = metrics;
    this.evidenceCollector = evidenceCollector;
    this.reportTemplates = new Map();
    
    // Initialize report templates
    this.initializeReportTemplates();
  }

  /**
   * Initialize report templates for different compliance frameworks
   */
  private initializeReportTemplates(): void {
    // NIST AI RMF Report Template
    this.reportTemplates.set(ComplianceFramework.NIST_AI_RMF, {
      title: 'NIST AI Risk Management Framework Compliance Report',
      sections: [
        'Executive Summary',
        'AI Governance Framework',
        'Risk Assessment and Management',
        'AI System Security',
        'Model Monitoring and Validation',
        'Evidence Inventory',
        'Compliance Gaps',
        'Recommendations',
        'Implementation Roadmap'
      ],
      controls: [
        { id: 'AI-1.1', name: 'AI Governance Structure', category: 'Governance' },
        { id: 'AI-2.1', name: 'Risk Assessment Process', category: 'Risk Management' },
        { id: 'AI-3.1', name: 'Security Testing', category: 'Security' },
        { id: 'AI-4.1', name: 'Monitoring and Response', category: 'Operations' }
      ]
    });

    // EU AI Act Report Template
    this.reportTemplates.set(ComplianceFramework.EU_AI_ACT, {
      title: 'EU AI Act Compliance Report',
      sections: [
        'Executive Summary',
        'AI System Classification',
        'Risk Management System',
        'Data and Data Governance',
        'Record-keeping and Documentation',
        'Transparency and User Information',
        'Human Oversight',
        'Accuracy, Robustness and Cybersecurity',
        'Evidence Inventory',
        'Compliance Assessment',
        'Recommendations'
      ],
      controls: [
        { id: 'AIA-9.1', name: 'Risk Management System', category: 'Risk Management' },
        { id: 'AIA-10.1', name: 'Data Governance', category: 'Data Management' },
        { id: 'AIA-11.1', name: 'Record-keeping', category: 'Documentation' },
        { id: 'AIA-12.1', name: 'Cybersecurity', category: 'Security' }
      ]
    });

    // GDPR Report Template
    this.reportTemplates.set(ComplianceFramework.GDPR, {
      title: 'GDPR Compliance Report',
      sections: [
        'Executive Summary',
        'Data Protection Principles',
        'Lawful Basis for Processing',
        'Data Subject Rights',
        'Privacy by Design and Default',
        'Data Security Measures',
        'Data Breach Management',
        'Privacy Impact Assessments',
        'Evidence Inventory',
        'Compliance Status',
        'Recommendations'
      ],
      controls: [
        { id: 'GDPR-32', name: 'Security of Processing', category: 'Security' },
        { id: 'GDPR-30', name: 'Records of Processing', category: 'Documentation' },
        { id: 'GDPR-35', name: 'Data Protection Impact Assessment', category: 'Risk Assessment' },
        { id: 'GDPR-33', name: 'Breach Notification', category: 'Incident Response' }
      ]
    });

    logger.info('Report templates initialized', {
      frameworks: Array.from(this.reportTemplates.keys()),
      templateCount: this.reportTemplates.size
    });
  }

  /**
   * Generate a comprehensive compliance report
   * @param config - Report generation configuration
   * @returns Promise<ReportMetadata>
   */
  async generateReport(config: ReportConfig): Promise<ReportMetadata> {
    const startTime = Date.now();
    const reportId = `report-${config.framework}-${Date.now()}`;
    
    try {
      logger.info(`Starting compliance report generation`, {
        reportId,
        framework: config.framework,
        reportType: config.reportType,
        format: config.format,
        correlationId: `report-gen-${reportId}`
      });

      // Collect evidence for the framework
      const evidenceReport = await this.evidenceCollector.collectEvidence(
        config.framework,
        config.dateRange
      );

      // Generate the compliance report structure
      const complianceReport = await this.generateComplianceReport(
        config,
        evidenceReport,
        reportId
      );

      // Generate the actual report file based on format
      let filePath: string;
      let fileSize: number;
      
      switch (config.format) {
        case ReportFormat.PDF:
          filePath = await this.generatePDFReport(complianceReport, config);
          break;
        case ReportFormat.EXCEL:
          filePath = await this.generateExcelReport(complianceReport, config);
          break;
        case ReportFormat.HTML:
          filePath = await this.generateHTMLReport(complianceReport, config);
          break;
        case ReportFormat.JSON:
          filePath = await this.generateJSONReport(complianceReport, config);
          break;
        default:
          throw new Error(`Unsupported report format: ${config.format}`);
      }

      // Get file size
      const stats = await fs.stat(filePath);
      fileSize = stats.size;

      // Create report metadata
      const metadata: ReportMetadata = {
        id: reportId,
        framework: config.framework,
        reportType: config.reportType,
        format: config.format,
        generatedAt: new Date(),
        generatedBy: 'compliance-report-generator',
        version: '1.0.0',
        fileSize,
        filePath,
        evidenceCount: evidenceReport.evidenceItems.length,
        complianceScore: complianceReport.frameworkCompliance.compliancePercentage,
        validationStatus: 'valid'
      };

      // Record metrics
      this.metricsCollector.recordMetric('compliance_report_generated', 1, {
        framework: config.framework,
        reportType: config.reportType,
        format: config.format,
        duration: Date.now() - startTime,
        fileSize: fileSize,
        evidenceCount: evidenceReport.evidenceItems.length
      });

      logger.info(`Compliance report generated successfully`, {
        reportId,
        framework: config.framework,
        format: config.format,
        duration: Date.now() - startTime,
        fileSize: fileSize,
        filePath
      });

      return metadata;

    } catch (error) {
      logger.error(`Failed to generate compliance report`, {
        reportId,
        framework: config.framework,
        format: config.format,
        error: error instanceof Error ? error.message : 'Unknown error',
        duration: Date.now() - startTime
      });

      this.metricsCollector.recordMetric('compliance_report_generation_failed', 1, {
        framework: config.framework,
        reportType: config.reportType,
        format: config.format,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      throw error;
    }
  }

  /**
   * Generate compliance report structure from evidence
   * @param config - Report configuration
   * @param evidenceReport - Collected evidence report
   * @param reportId - Unique report identifier
   * @returns Promise<ComplianceReport>
   */
  private async generateComplianceReport(
    config: ReportConfig,
    evidenceReport: any,
    reportId: string
  ): Promise<ComplianceReport> {
    const template = this.reportTemplates.get(config.framework);
    if (!template) {
      throw new Error(`No template found for framework: ${config.framework}`);
    }

    // Analyze compliance based on evidence
    const findings = this.analyzeCompliance(config.framework, evidenceReport);
    const recommendations = this.generateRecommendations(findings);

    // Calculate compliance scores
    const compliantControls = findings.filter(f => f.status === 'compliant').length;
    const partiallyCompliantControls = findings.filter(f => f.status === 'partially_compliant').length;
    const nonCompliantControls = findings.filter(f => f.status === 'non_compliant').length;
    const notApplicableControls = findings.filter(f => f.status === 'not_applicable').length;
    const totalControls = template.controls.length;

    const compliancePercentage = Math.round(
      ((compliantControls + (partiallyCompliantControls * 0.5)) / totalControls) * 100
    );

    // Determine overall risk level
    const criticalFindings = findings.filter(f => f.severity === 'critical').length;
    const highFindings = findings.filter(f => f.severity === 'high').length;
    
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    if (criticalFindings > 0) riskLevel = 'critical';
    else if (highFindings > 2) riskLevel = 'high';
    else if (nonCompliantControls > totalControls * 0.3) riskLevel = 'medium';

    // Create evidence summary by type
    const evidenceByType: Record<EvidenceType, number> = {} as any;
    Object.values(EvidenceType).forEach(type => {
      evidenceByType[type] = evidenceReport.evidenceItems.filter(
        (item: any) => item.type === type
      ).length;
    });

    const complianceReport: ComplianceReport = {
      metadata: {
        id: reportId,
        framework: config.framework,
        reportType: config.reportType,
        format: config.format,
        generatedAt: new Date(),
        generatedBy: 'compliance-report-generator',
        version: '1.0.0',
        pageCount: 0,
        fileSize: 0,
        filePath: '',
        evidenceCount: evidenceReport.evidenceItems.length,
        complianceScore: compliancePercentage,
        validationStatus: 'valid'
      },
      executiveSummary: {
        overallScore: compliancePercentage,
        criticalFindings: criticalFindings,
        recommendationsCount: recommendations.length,
        evidenceGaps: evidenceReport.missingEvidence,
        riskLevel
      },
      frameworkCompliance: {
        framework: config.framework,
        totalControls,
        compliantControls,
        partiallyCompliantControls,
        nonCompliantControls,
        notApplicableControls,
        compliancePercentage
      },
      evidenceSummary: {
        totalEvidence: evidenceReport.evidenceItems.length,
        validEvidence: evidenceReport.validEvidence,
        invalidEvidence: evidenceReport.invalidEvidence,
        warningEvidence: evidenceReport.warningEvidence,
        missingEvidence: evidenceReport.missingEvidence,
        evidenceByType
      },
      findings,
      recommendations,
      evidenceInventory: evidenceReport.evidenceItems,
      appendices: {
        technicalDetails: {
          collectionDate: evidenceReport.collectionDate,
          collectionMethod: 'Automated Evidence Collection',
          frameworkVersion: '1.0.0',
          assessmentScope: 'Complete AI-SPM Platform'
        },
        evidenceDetails: evidenceReport.evidenceItems,
        glossary: this.getComplianceGlossary(config.framework)
      }
    };

    return complianceReport;
  }

  /**
   * Analyze compliance based on collected evidence
   * @param framework - Compliance framework
   * @param evidenceReport - Evidence collection report
   * @returns ComplianceFinding[]
   */
  private analyzeCompliance(framework: ComplianceFramework, evidenceReport: any): ComplianceFinding[] {
    const template = this.reportTemplates.get(framework);
    if (!template) return [];

    const findings: ComplianceFinding[] = [];

    template.controls.forEach((control: any) => {
      // Find evidence for this control
      const controlEvidence = evidenceReport.evidenceItems.filter(
        (item: any) => item.control === control.id
      );

      // Analyze compliance status
      let status: 'compliant' | 'partially_compliant' | 'non_compliant' | 'not_applicable' = 'non_compliant';
      let gaps: string[] = [];
      let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium';

      if (controlEvidence.length === 0) {
        status = 'non_compliant';
        gaps.push('No evidence found for this control');
        severity = 'high';
      } else {
        const validEvidence = controlEvidence.filter((item: any) => item.validationStatus === 'valid');
        const invalidEvidence = controlEvidence.filter((item: any) => item.validationStatus === 'invalid');
        
        if (validEvidence.length > 0 && invalidEvidence.length === 0) {
          status = 'compliant';
          severity = 'low';
        } else if (validEvidence.length > 0 && invalidEvidence.length > 0) {
          status = 'partially_compliant';
          severity = 'medium';
          gaps.push('Some evidence items failed validation');
        } else {
          status = 'non_compliant';
          severity = 'high';
          gaps.push('All evidence items are invalid');
        }
      }

      // Generate specific findings based on framework
      const finding: ComplianceFinding = {
        id: `finding-${control.id}-${Date.now()}`,
        control: control.id,
        title: control.name,
        severity,
        status,
        description: this.getControlDescription(framework, control.id),
        evidence: controlEvidence.map((item: any) => item.title),
        gaps,
        riskImpact: this.getRiskImpact(framework, control.id, status),
        recommendation: this.getControlRecommendation(framework, control.id, status)
      };

      findings.push(finding);
    });

    return findings;
  }

  /**
   * Generate recommendations based on compliance findings
   * @param findings - Compliance findings
   * @returns ComplianceRecommendation[]
   */
  private generateRecommendations(findings: ComplianceFinding[]): ComplianceRecommendation[] {
    const recommendations: ComplianceRecommendation[] = [];

    findings.forEach(finding => {
      if (finding.status !== 'compliant') {
        let priority: 'low' | 'medium' | 'high' | 'critical' = 'medium';
        let timeline = '30-60 days';
        let effort: 'low' | 'medium' | 'high' = 'medium';
        let cost: 'low' | 'medium' | 'high' = 'medium';

        // Adjust priority based on severity
        if (finding.severity === 'critical') {
          priority = 'critical';
          timeline = '1-2 weeks';
          effort = 'high';
          cost = 'high';
        } else if (finding.severity === 'high') {
          priority = 'high';
          timeline = '2-4 weeks';
          effort = 'medium';
          cost = 'medium';
        } else if (finding.severity === 'low') {
          priority = 'low';
          timeline = '60-90 days';
          effort = 'low';
          cost = 'low';
        }

        const recommendation: ComplianceRecommendation = {
          id: `rec-${finding.control}-${Date.now()}`,
          priority,
          control: finding.control,
          title: `Address ${finding.title} Compliance Gap`,
          description: `Implement measures to achieve compliance with ${finding.control}: ${finding.title}`,
          implementation: finding.recommendation,
          timeline,
          effort,
          cost,
          dependencies: []
        };

        recommendations.push(recommendation);
      }
    });

    // Sort recommendations by priority
    recommendations.sort((a, b) => {
      const priorityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });

    return recommendations;
  }

  /**
   * Generate PDF report
   * @param report - Compliance report data
   * @param config - Report configuration
   * @returns Promise<string> - File path
   */
  private async generatePDFReport(report: ComplianceReport, config: ReportConfig): Promise<string> {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4'
    });

    const template = this.reportTemplates.get(config.framework);
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;

    // Set font
    doc.setFont('helvetica');

    // Title page
    doc.setFontSize(24);
    doc.setTextColor(40, 40, 40);
    doc.text(template?.title || 'Compliance Report', pageWidth / 2, 60, { align: 'center' });

    doc.setFontSize(16);
    doc.setTextColor(80, 80, 80);
    doc.text(`Generated: ${report.metadata.generatedAt.toLocaleDateString()}`, pageWidth / 2, 80, { align: 'center' });
    doc.text(`Framework: ${config.framework.toUpperCase()}`, pageWidth / 2, 95, { align: 'center' });
    doc.text(`Report ID: ${report.metadata.id}`, pageWidth / 2, 110, { align: 'center' });

    // Executive Summary
    doc.addPage();
    doc.setFontSize(18);
    doc.setTextColor(40, 40, 40);
    doc.text('Executive Summary', margin, 30);

    doc.setFontSize(12);
    doc.setTextColor(60, 60, 60);
    
    const summaryY = 45;
    doc.text(`Overall Compliance Score: ${report.executiveSummary.overallScore}%`, margin, summaryY);
    doc.text(`Critical Findings: ${report.executiveSummary.criticalFindings}`, margin, summaryY + 7);
    doc.text(`Recommendations: ${report.executiveSummary.recommendationsCount}`, margin, summaryY + 14);
    doc.text(`Evidence Gaps: ${report.executiveSummary.evidenceGaps}`, margin, summaryY + 21);
    doc.text(`Risk Level: ${report.executiveSummary.riskLevel.toUpperCase()}`, margin, summaryY + 28);

    // Compliance Summary Table
    doc.setFontSize(14);
    doc.setTextColor(40, 40, 40);
    doc.text('Framework Compliance Status', margin, summaryY + 50);

    const complianceData = [
      ['Metric', 'Count', 'Percentage'],
      ['Total Controls', report.frameworkCompliance.totalControls.toString(), '100%'],
      ['Compliant', report.frameworkCompliance.compliantControls.toString(), 
       `${Math.round((report.frameworkCompliance.compliantControls / report.frameworkCompliance.totalControls) * 100)}%`],
      ['Partially Compliant', report.frameworkCompliance.partiallyCompliantControls.toString(),
       `${Math.round((report.frameworkCompliance.partiallyCompliantControls / report.frameworkCompliance.totalControls) * 100)}%`],
      ['Non-Compliant', report.frameworkCompliance.nonCompliantControls.toString(),
       `${Math.round((report.frameworkCompliance.nonCompliantControls / report.frameworkCompliance.totalControls) * 100)}%`]
    ];

    (doc as any).autoTable({
      head: [complianceData[0]],
      body: complianceData.slice(1),
      startY: summaryY + 55,
      theme: 'striped',
      headStyles: { fillColor: [51, 122, 183] },
      margin: { left: margin, right: margin }
    });

    // Findings Section
    doc.addPage();
    doc.setFontSize(18);
    doc.setTextColor(40, 40, 40);
    doc.text('Compliance Findings', margin, 30);

    const findingsData = [
      ['Control', 'Status', 'Severity', 'Description']
    ];

    report.findings.forEach(finding => {
      findingsData.push([
        finding.control,
        finding.status.replace('_', ' ').toUpperCase(),
        finding.severity.toUpperCase(),
        finding.description.substring(0, 100) + (finding.description.length > 100 ? '...' : '')
      ]);
    });

    (doc as any).autoTable({
      head: [findingsData[0]],
      body: findingsData.slice(1),
      startY: 40,
      theme: 'striped',
      headStyles: { fillColor: [51, 122, 183] },
      margin: { left: margin, right: margin },
      columnStyles: {
        0: { cellWidth: 25 },
        1: { cellWidth: 35 },
        2: { cellWidth: 25 },
        3: { cellWidth: 'auto' }
      }
    });

    // Recommendations Section
    doc.addPage();
    doc.setFontSize(18);
    doc.setTextColor(40, 40, 40);
    doc.text('Recommendations', margin, 30);

    const recommendationsData = [
      ['Priority', 'Control', 'Title', 'Timeline']
    ];

    report.recommendations.forEach(rec => {
      recommendationsData.push([
        rec.priority.toUpperCase(),
        rec.control,
        rec.title.substring(0, 50) + (rec.title.length > 50 ? '...' : ''),
        rec.timeline
      ]);
    });

    (doc as any).autoTable({
      head: [recommendationsData[0]],
      body: recommendationsData.slice(1),
      startY: 40,
      theme: 'striped',
      headStyles: { fillColor: [51, 122, 183] },
      margin: { left: margin, right: margin },
      columnStyles: {
        0: { cellWidth: 25 },
        1: { cellWidth: 25 },
        2: { cellWidth: 'auto' },
        3: { cellWidth: 30 }
      }
    });

    // Evidence Inventory Section
    doc.addPage();
    doc.setFontSize(18);
    doc.setTextColor(40, 40, 40);
    doc.text('Evidence Inventory', margin, 30);

    const evidenceData = [
      ['Type', 'Control', 'Title', 'Status']
    ];

    report.evidenceInventory.slice(0, 20).forEach((evidence: any) => {
      evidenceData.push([
        evidence.type.replace('_', ' ').toUpperCase(),
        evidence.control,
        evidence.title.substring(0, 40) + (evidence.title.length > 40 ? '...' : ''),
        evidence.validationStatus.toUpperCase()
      ]);
    });

    (doc as any).autoTable({
      head: [evidenceData[0]],
      body: evidenceData.slice(1),
      startY: 40,
      theme: 'striped',
      headStyles: { fillColor: [51, 122, 183] },
      margin: { left: margin, right: margin }
    });

    // Footer on all pages
    const pageCount = doc.internal.pages.length - 1;
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(128, 128, 128);
      doc.text(`Page ${i} of ${pageCount}`, pageWidth - margin, pageHeight - 10, { align: 'right' });
      doc.text(`Generated by AI-SPM Platform`, margin, pageHeight - 10);
    }

    // Save PDF
    const fileName = `compliance-report-${config.framework}-${Date.now()}.pdf`;
    const filePath = path.join(process.cwd(), 'logs', fileName);
    
    // Ensure logs directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    
    const pdfBuffer = doc.output('arraybuffer');
    await fs.writeFile(filePath, new Uint8Array(pdfBuffer));

    return filePath;
  }

  /**
   * Generate Excel report
   * @param report - Compliance report data
   * @param config - Report configuration
   * @returns Promise<string> - File path
   */
  private async generateExcelReport(report: ComplianceReport, config: ReportConfig): Promise<string> {
    const workbook = XLSX.utils.book_new();

    // Executive Summary Sheet
    const summaryData = [
      ['AI Security Posture Management - Compliance Report'],
      ['Framework:', config.framework.toUpperCase()],
      ['Generated:', report.metadata.generatedAt.toLocaleDateString()],
      ['Report ID:', report.metadata.id],
      [''],
      ['Executive Summary'],
      ['Overall Compliance Score:', `${report.executiveSummary.overallScore}%`],
      ['Critical Findings:', report.executiveSummary.criticalFindings],
      ['Recommendations:', report.executiveSummary.recommendationsCount],
      ['Evidence Gaps:', report.executiveSummary.evidenceGaps],
      ['Risk Level:', report.executiveSummary.riskLevel.toUpperCase()],
      [''],
      ['Framework Compliance Status'],
      ['Total Controls:', report.frameworkCompliance.totalControls],
      ['Compliant Controls:', report.frameworkCompliance.compliantControls],
      ['Partially Compliant:', report.frameworkCompliance.partiallyCompliantControls],
      ['Non-Compliant:', report.frameworkCompliance.nonCompliantControls],
      ['Not Applicable:', report.frameworkCompliance.notApplicableControls],
      ['Compliance Percentage:', `${report.frameworkCompliance.compliancePercentage}%`]
    ];

    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Executive Summary');

    // Compliance Findings Sheet
    const findingsData = [
      ['Control', 'Title', 'Status', 'Severity', 'Description', 'Evidence Count', 'Gaps', 'Risk Impact', 'Recommendation']
    ];

    report.findings.forEach(finding => {
      findingsData.push([
        finding.control,
        finding.title,
        finding.status.replace('_', ' ').toUpperCase(),
        finding.severity.toUpperCase(),
        finding.description,
        finding.evidence.length,
        finding.gaps.join('; '),
        finding.riskImpact,
        finding.recommendation
      ]);
    });

    const findingsSheet = XLSX.utils.aoa_to_sheet(findingsData);
    XLSX.utils.book_append_sheet(workbook, findingsSheet, 'Compliance Findings');

    // Recommendations Sheet
    const recommendationsData = [
      ['Priority', 'Control', 'Title', 'Description', 'Implementation', 'Timeline', 'Effort', 'Cost', 'Dependencies']
    ];

    report.recommendations.forEach(rec => {
      recommendationsData.push([
        rec.priority.toUpperCase(),
        rec.control,
        rec.title,
        rec.description,
        rec.implementation,
        rec.timeline,
        rec.effort.toUpperCase(),
        rec.cost.toUpperCase(),
        rec.dependencies.join('; ')
      ]);
    });

    const recommendationsSheet = XLSX.utils.aoa_to_sheet(recommendationsData);
    XLSX.utils.book_append_sheet(workbook, recommendationsSheet, 'Recommendations');

    // Evidence Inventory Sheet
    const evidenceData = [
      ['ID', 'Type', 'Framework', 'Control', 'Title', 'Description', 'Source', 'Collected At', 'Status', 'File Size']
    ];

    report.evidenceInventory.forEach((evidence: any) => {
      evidenceData.push([
        evidence.id,
        evidence.type.replace('_', ' ').toUpperCase(),
        evidence.framework,
        evidence.control,
        evidence.title,
        evidence.description,
        evidence.metadata.source,
        evidence.metadata.collectedAt,
        evidence.validationStatus.toUpperCase(),
        evidence.metadata.size
      ]);
    });

    const evidenceSheet = XLSX.utils.aoa_to_sheet(evidenceData);
    XLSX.utils.book_append_sheet(workbook, evidenceSheet, 'Evidence Inventory');

    // Evidence Summary by Type Sheet
    const evidenceTypeData = [
      ['Evidence Type', 'Count', 'Percentage']
    ];

    Object.entries(report.evidenceSummary.evidenceByType).forEach(([type, count]) => {
      const percentage = report.evidenceSummary.totalEvidence > 0 
        ? Math.round((count / report.evidenceSummary.totalEvidence) * 100)
        : 0;
      evidenceTypeData.push([
        type.replace('_', ' ').toUpperCase(),
        count,
        `${percentage}%`
      ]);
    });

    const evidenceTypeSheet = XLSX.utils.aoa_to_sheet(evidenceTypeData);
    XLSX.utils.book_append_sheet(workbook, evidenceTypeSheet, 'Evidence by Type');

    // Save Excel file
    const fileName = `compliance-report-${config.framework}-${Date.now()}.xlsx`;
    const filePath = path.join(process.cwd(), 'logs', fileName);
    
    // Ensure logs directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    
    XLSX.writeFile(workbook, filePath);

    return filePath;
  }

  /**
   * Generate HTML report
   * @param report - Compliance report data
   * @param config - Report configuration
   * @returns Promise<string> - File path
   */
  private async generateHTMLReport(report: ComplianceReport, config: ReportConfig): Promise<string> {
    const template = this.reportTemplates.get(config.framework);
    
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${template?.title || 'Compliance Report'}</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            .header { text-align: center; margin-bottom: 40px; }
            .title { font-size: 28px; color: #333; margin-bottom: 10px; }
            .subtitle { font-size: 16px; color: #666; }
            .section { margin-bottom: 30px; }
            .section h2 { color: #337ab7; border-bottom: 2px solid #337ab7; padding-bottom: 5px; }
            .summary-card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .metric { display: inline-block; margin: 10px 20px 10px 0; }
            .metric-value { font-size: 24px; font-weight: bold; color: #337ab7; }
            .metric-label { font-size: 14px; color: #666; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #337ab7; color: white; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .status-compliant { color: #28a745; font-weight: bold; }
            .status-partially-compliant { color: #ffc107; font-weight: bold; }
            .status-non-compliant { color: #dc3545; font-weight: bold; }
            .severity-critical { color: #dc3545; font-weight: bold; }
            .severity-high { color: #fd7e14; font-weight: bold; }
            .severity-medium { color: #ffc107; font-weight: bold; }
            .severity-low { color: #28a745; font-weight: bold; }
            .priority-critical { background-color: #dc3545; color: white; padding: 2px 6px; border-radius: 4px; }
            .priority-high { background-color: #fd7e14; color: white; padding: 2px 6px; border-radius: 4px; }
            .priority-medium { background-color: #ffc107; color: white; padding: 2px 6px; border-radius: 4px; }
            .priority-low { background-color: #28a745; color: white; padding: 2px 6px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="title">${template?.title || 'Compliance Report'}</h1>
            <p class="subtitle">Generated: ${report.metadata.generatedAt.toLocaleDateString()}</p>
            <p class="subtitle">Framework: ${config.framework.toUpperCase()}</p>
            <p class="subtitle">Report ID: ${report.metadata.id}</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-card">
                <div class="metric">
                    <div class="metric-value">${report.executiveSummary.overallScore}%</div>
                    <div class="metric-label">Overall Compliance Score</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.executiveSummary.criticalFindings}</div>
                    <div class="metric-label">Critical Findings</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.executiveSummary.recommendationsCount}</div>
                    <div class="metric-label">Recommendations</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.executiveSummary.evidenceGaps}</div>
                    <div class="metric-label">Evidence Gaps</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.executiveSummary.riskLevel.toUpperCase()}</div>
                    <div class="metric-label">Risk Level</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Framework Compliance Status</h2>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Total Controls</td>
                        <td>${report.frameworkCompliance.totalControls}</td>
                        <td>100%</td>
                    </tr>
                    <tr>
                        <td>Compliant</td>
                        <td>${report.frameworkCompliance.compliantControls}</td>
                        <td>${Math.round((report.frameworkCompliance.compliantControls / report.frameworkCompliance.totalControls) * 100)}%</td>
                    </tr>
                    <tr>
                        <td>Partially Compliant</td>
                        <td>${report.frameworkCompliance.partiallyCompliantControls}</td>
                        <td>${Math.round((report.frameworkCompliance.partiallyCompliantControls / report.frameworkCompliance.totalControls) * 100)}%</td>
                    </tr>
                    <tr>
                        <td>Non-Compliant</td>
                        <td>${report.frameworkCompliance.nonCompliantControls}</td>
                        <td>${Math.round((report.frameworkCompliance.nonCompliantControls / report.frameworkCompliance.totalControls) * 100)}%</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Compliance Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    ${report.findings.map(finding => `
                        <tr>
                            <td>${finding.control}</td>
                            <td>${finding.title}</td>
                            <td class="status-${finding.status.replace('_', '-')}">${finding.status.replace('_', ' ').toUpperCase()}</td>
                            <td class="severity-${finding.severity}">${finding.severity.toUpperCase()}</td>
                            <td>${finding.description}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Control</th>
                        <th>Title</th>
                        <th>Timeline</th>
                        <th>Effort</th>
                    </tr>
                </thead>
                <tbody>
                    ${report.recommendations.map(rec => `
                        <tr>
                            <td><span class="priority-${rec.priority}">${rec.priority.toUpperCase()}</span></td>
                            <td>${rec.control}</td>
                            <td>${rec.title}</td>
                            <td>${rec.timeline}</td>
                            <td>${rec.effort.toUpperCase()}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Evidence Summary</h2>
            <div class="summary-card">
                <div class="metric">
                    <div class="metric-value">${report.evidenceSummary.totalEvidence}</div>
                    <div class="metric-label">Total Evidence</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.evidenceSummary.validEvidence}</div>
                    <div class="metric-label">Valid Evidence</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.evidenceSummary.invalidEvidence}</div>
                    <div class="metric-label">Invalid Evidence</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${report.evidenceSummary.missingEvidence}</div>
                    <div class="metric-label">Missing Evidence</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Evidence by Type</h2>
            <table>
                <thead>
                    <tr>
                        <th>Evidence Type</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(report.evidenceSummary.evidenceByType).map(([type, count]) => {
                        const percentage = report.evidenceSummary.totalEvidence > 0 
                            ? Math.round((count / report.evidenceSummary.totalEvidence) * 100)
                            : 0;
                        return `
                            <tr>
                                <td>${type.replace('_', ' ').toUpperCase()}</td>
                                <td>${count}</td>
                                <td>${percentage}%</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Report Metadata</h2>
            <table>
                <tbody>
                    <tr><td><strong>Report ID</strong></td><td>${report.metadata.id}</td></tr>
                    <tr><td><strong>Framework</strong></td><td>${report.metadata.framework}</td></tr>
                    <tr><td><strong>Generated At</strong></td><td>${report.metadata.generatedAt.toISOString()}</td></tr>
                    <tr><td><strong>Generated By</strong></td><td>${report.metadata.generatedBy}</td></tr>
                    <tr><td><strong>Version</strong></td><td>${report.metadata.version}</td></tr>
                    <tr><td><strong>Evidence Count</strong></td><td>${report.metadata.evidenceCount}</td></tr>
                    <tr><td><strong>Compliance Score</strong></td><td>${report.metadata.complianceScore}%</td></tr>
                </tbody>
            </table>
        </div>

        <footer style="margin-top: 60px; text-align: center; color: #666; font-size: 12px;">
            <p>Generated by AI Security Posture Management Platform</p>
            <p>This report contains confidential information and is intended for authorized recipients only.</p>
        </footer>
    </body>
    </html>
    `;

    // Save HTML file
    const fileName = `compliance-report-${config.framework}-${Date.now()}.html`;
    const filePath = path.join(process.cwd(), 'logs', fileName);
    
    // Ensure logs directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    
    await fs.writeFile(filePath, html, 'utf-8');

    return filePath;
  }

  /**
   * Generate JSON report
   * @param report - Compliance report data
   * @param config - Report configuration
   * @returns Promise<string> - File path
   */
  private async generateJSONReport(report: ComplianceReport, config: ReportConfig): Promise<string> {
    const fileName = `compliance-report-${config.framework}-${Date.now()}.json`;
    const filePath = path.join(process.cwd(), 'logs', fileName);
    
    // Ensure logs directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    
    await fs.writeFile(filePath, JSON.stringify(report, null, 2), 'utf-8');

    return filePath;
  }

  /**
   * Get control description based on framework and control ID
   * @param framework - Compliance framework
   * @param controlId - Control identifier
   * @returns string - Control description
   */
  private getControlDescription(framework: ComplianceFramework, controlId: string): string {
    const descriptions: Record<string, Record<string, string>> = {
      [ComplianceFramework.NIST_AI_RMF]: {
        'AI-1.1': 'Establish AI governance structure with clear roles and responsibilities',
        'AI-2.1': 'Implement comprehensive AI risk assessment and management processes',
        'AI-3.1': 'Conduct regular AI system security testing and vulnerability assessments',
        'AI-4.1': 'Maintain continuous monitoring and incident response capabilities'
      },
      [ComplianceFramework.EU_AI_ACT]: {
        'AIA-9.1': 'Implement risk management system for high-risk AI applications',
        'AIA-10.1': 'Establish data governance and quality management processes',
        'AIA-11.1': 'Maintain comprehensive record-keeping and documentation',
        'AIA-12.1': 'Ensure accuracy, robustness and cybersecurity measures'
      },
      [ComplianceFramework.GDPR]: {
        'GDPR-32': 'Implement appropriate technical and organisational security measures',
        'GDPR-30': 'Maintain records of processing activities',
        'GDPR-35': 'Conduct data protection impact assessments where required',
        'GDPR-33': 'Implement personal data breach notification procedures'
      }
    };

    return descriptions[framework]?.[controlId] || 'Control description not available';
  }

  /**
   * Get risk impact based on framework, control, and status
   * @param framework - Compliance framework
   * @param controlId - Control identifier
   * @param status - Compliance status
   * @returns string - Risk impact description
   */
  private getRiskImpact(framework: ComplianceFramework, controlId: string, status: string): string {
    if (status === 'compliant') return 'Low risk - control is effectively implemented';
    if (status === 'partially_compliant') return 'Medium risk - control has gaps that need attention';
    return 'High risk - control is not implemented and poses significant compliance risk';
  }

  /**
   * Get control recommendation based on framework, control, and status
   * @param framework - Compliance framework
   * @param controlId - Control identifier
   * @param status - Compliance status
   * @returns string - Recommendation
   */
  private getControlRecommendation(framework: ComplianceFramework, controlId: string, status: string): string {
    if (status === 'compliant') return 'Maintain current implementation and monitor for changes';
    
    const recommendations: Record<string, Record<string, string>> = {
      [ComplianceFramework.NIST_AI_RMF]: {
        'AI-1.1': 'Establish formal AI governance committee with documented roles and responsibilities',
        'AI-2.1': 'Implement structured AI risk assessment methodology with regular reviews',
        'AI-3.1': 'Deploy automated AI security testing tools and regular vulnerability scans',
        'AI-4.1': 'Set up continuous monitoring dashboards and incident response procedures'
      },
      [ComplianceFramework.EU_AI_ACT]: {
        'AIA-9.1': 'Develop comprehensive risk management framework for AI applications',
        'AIA-10.1': 'Implement data quality controls and governance processes',
        'AIA-11.1': 'Establish comprehensive documentation and record-keeping systems',
        'AIA-12.1': 'Deploy security monitoring and robustness testing capabilities'
      },
      [ComplianceFramework.GDPR]: {
        'GDPR-32': 'Implement encryption, access controls, and security monitoring',
        'GDPR-30': 'Create and maintain processing activity records',
        'GDPR-35': 'Conduct DPIA for high-risk processing activities',
        'GDPR-33': 'Establish breach detection and notification procedures'
      }
    };

    return recommendations[framework]?.[controlId] || 'Implement appropriate controls to address compliance gap';
  }

  /**
   * Get compliance glossary for framework
   * @param framework - Compliance framework
   * @returns Object - Glossary terms
   */
  private getComplianceGlossary(framework: ComplianceFramework): Record<string, string> {
    const glossaries: Record<ComplianceFramework, Record<string, string>> = {
      [ComplianceFramework.NIST_AI_RMF]: {
        'AI System': 'An engineered system that generates outputs such as predictions, recommendations, or decisions for a given set of human-defined objectives',
        'AI Risk': 'The potential for AI systems to cause harm, including discrimination, privacy violations, or safety issues',
        'AI Governance': 'The processes, policies, and structures that guide the development and deployment of AI systems',
        'Bias': 'Systematic errors in AI systems that can lead to unfair treatment of individuals or groups'
      },
      [ComplianceFramework.EU_AI_ACT]: {
        'High-Risk AI System': 'AI systems that pose significant risks to fundamental rights, health, safety, or democratic values',
        'Conformity Assessment': 'The process of demonstrating that an AI system meets the requirements of the EU AI Act',
        'CE Marking': 'A marking that indicates conformity with EU legislation for AI systems',
        'Post-Market Monitoring': 'The continuous monitoring of AI systems after they are placed on the market'
      },
      [ComplianceFramework.GDPR]: {
        'Personal Data': 'Any information relating to an identified or identifiable natural person',
        'Data Controller': 'The entity that determines the purposes and means of processing personal data',
        'Data Processor': 'The entity that processes personal data on behalf of the data controller',
        'Data Subject': 'The natural person whose personal data is being processed'
      }
    };

    return glossaries[framework] || {};
  }

  /**
   * Get available report templates
   * @returns Array of available frameworks
   */
  getAvailableFrameworks(): ComplianceFramework[] {
    return Array.from(this.reportTemplates.keys());
  }

  /**
   * Get report generation statistics
   * @returns Object with generation statistics
   */
  getReportStatistics(): Record<string, any> {
    return {
      availableFrameworks: this.getAvailableFrameworks().length,
      supportedFormats: Object.values(ReportFormat).length,
      supportedReportTypes: Object.values(ReportType).length,
      lastGenerationAttempt: new Date().toISOString()
    };
  }
}

// Export singleton instance
export const complianceReportGenerator = new ComplianceReportGenerator();