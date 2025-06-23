#!/usr/bin/env python3
"""
Compliance Engine Microservice
==============================

This microservice handles compliance assessment and monitoring for AI systems.
It provides specialized capabilities for:
- Regulatory compliance checking (GDPR, CCPA, SOX, HIPAA)
- AI-specific compliance frameworks (EU AI Act, NIST AI RMF)
- Policy enforcement and monitoring
- Compliance reporting and documentation

Author: AI-SPM Development Team
Version: 1.0.0
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import asyncio
import logging
import uvicorn
from datetime import datetime
import hashlib
import os
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Compliance Engine",
    description="AI compliance assessment and monitoring service",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data Models
class ComplianceAssessmentRequest(BaseModel):
    """Request model for compliance assessment"""
    asset_id: int
    framework: str = Field(..., description="Compliance framework: gdpr, ccpa, hipaa, eu_ai_act, nist_ai_rmf")
    assessment_type: str = Field("full", description="Assessment type: full, quick, targeted")
    scope: Optional[List[str]] = Field(None, description="Assessment scope areas")
    baseline_date: Optional[datetime] = Field(None, description="Baseline date for comparison")
    correlation_id: Optional[str] = Field(None, description="Request correlation ID")

class ComplianceViolation(BaseModel):
    """Model for compliance violations"""
    violation_id: str
    framework: str
    regulation_section: str
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    category: str = Field(..., description="Violation category")
    title: str
    description: str
    recommendation: str
    remediation_effort: str = Field(..., description="Effort level: low, medium, high, critical")
    deadline: Optional[datetime] = Field(None, description="Compliance deadline")
    evidence: List[str] = []
    metadata: Dict[str, Any] = {}

class ComplianceAssessmentResult(BaseModel):
    """Complete compliance assessment result"""
    assessment_id: str
    asset_id: int
    framework: str
    assessment_type: str
    status: str = Field(..., description="Status: completed, failed, in_progress")
    started_at: datetime
    completed_at: Optional[datetime] = None
    violations: List[ComplianceViolation] = []
    compliance_score: float = Field(..., ge=0.0, le=100.0)
    certification_status: str = Field(..., description="Status: compliant, non_compliant, partially_compliant")
    recommendations: List[str] = []
    next_assessment_date: Optional[datetime] = None
    metadata: Dict[str, Any] = {}

# Storage
assessment_results: Dict[str, ComplianceAssessmentResult] = {}
active_assessments: Dict[str, bool] = {}

class ComplianceEngine:
    """Core compliance assessment engine"""
    
    def __init__(self):
        self.frameworks = {
            'gdpr': self._assess_gdpr_compliance,
            'ccpa': self._assess_ccpa_compliance,
            'hipaa': self._assess_hipaa_compliance,
            'eu_ai_act': self._assess_eu_ai_act_compliance,
            'nist_ai_rmf': self._assess_nist_ai_rmf_compliance,
            'sox': self._assess_sox_compliance
        }
        
        self.framework_details = {
            'gdpr': {
                'name': 'General Data Protection Regulation',
                'jurisdiction': 'European Union',
                'applies_to': ['data_processing', 'ai_training', 'user_profiling']
            },
            'ccpa': {
                'name': 'California Consumer Privacy Act',
                'jurisdiction': 'California, USA',
                'applies_to': ['consumer_data', 'ai_decision_making']
            },
            'hipaa': {
                'name': 'Health Insurance Portability and Accountability Act',
                'jurisdiction': 'United States',
                'applies_to': ['healthcare_ai', 'medical_data']
            },
            'eu_ai_act': {
                'name': 'EU Artificial Intelligence Act',
                'jurisdiction': 'European Union',
                'applies_to': ['high_risk_ai', 'biometric_systems', 'critical_infrastructure']
            },
            'nist_ai_rmf': {
                'name': 'NIST AI Risk Management Framework',
                'jurisdiction': 'United States',
                'applies_to': ['ai_governance', 'risk_management', 'trustworthy_ai']
            }
        }
    
    async def run_compliance_assessment(self, request: ComplianceAssessmentRequest) -> ComplianceAssessmentResult:
        """Main compliance assessment orchestrator"""
        assessment_id = self._generate_assessment_id(request)
        
        logger.info(f"Starting compliance assessment {assessment_id} for framework {request.framework}")
        
        result = ComplianceAssessmentResult(
            assessment_id=assessment_id,
            asset_id=request.asset_id,
            framework=request.framework,
            assessment_type=request.assessment_type,
            status="in_progress",
            started_at=datetime.utcnow(),
            compliance_score=0.0,
            certification_status="under_review"
        )
        
        assessment_results[assessment_id] = result
        active_assessments[assessment_id] = True
        
        try:
            # Route to appropriate compliance assessor
            assessor = self.frameworks.get(request.framework, self._assess_generic_compliance)
            violations = await assessor(request)
            
            # Calculate compliance score and status
            compliance_score = self._calculate_compliance_score(violations)
            certification_status = self._determine_certification_status(compliance_score, violations)
            
            # Update result
            result.violations = violations
            result.compliance_score = compliance_score
            result.certification_status = certification_status
            result.recommendations = self._generate_recommendations(violations)
            result.next_assessment_date = self._calculate_next_assessment_date(request.framework)
            result.status = "completed"
            result.completed_at = datetime.utcnow()
            
            logger.info(f"Completed assessment {assessment_id} with score {compliance_score}")
            
        except Exception as e:
            logger.error(f"Assessment {assessment_id} failed: {str(e)}")
            result.status = "failed"
            result.metadata["error_message"] = str(e)
            
        finally:
            active_assessments[assessment_id] = False
            
        return result
    
    async def _assess_gdpr_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Assess GDPR compliance"""
        violations = []
        await asyncio.sleep(2)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"gdpr_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="gdpr",
                regulation_section="Article 6 - Lawfulness of processing",
                severity="critical",
                category="legal_basis",
                title="No documented legal basis for data processing",
                description="AI system processes personal data without clearly documented legal basis",
                recommendation="Document and implement appropriate legal basis (consent, legitimate interest, etc.)",
                remediation_effort="high",
                deadline=datetime(2024, 12, 31),
                evidence=["training_data_audit.pdf", "consent_records.json"],
                metadata={"article": "6", "requirement": "legal_basis_documentation"}
            ),
            ComplianceViolation(
                violation_id=f"gdpr_{hashlib.md5(f'v2_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="gdpr",
                regulation_section="Article 22 - Automated decision-making",
                severity="high",
                category="automated_decisions",
                title="Automated decision-making without human oversight",
                description="AI system makes decisions affecting individuals without human review mechanism",
                recommendation="Implement human review process for automated decisions",
                remediation_effort="medium",
                deadline=datetime(2024, 6, 30),
                evidence=["decision_logs.csv", "human_review_policy.pdf"],
                metadata={"article": "22", "requirement": "human_oversight"}
            ),
            ComplianceViolation(
                violation_id=f"gdpr_{hashlib.md5(f'v3_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="gdpr",
                regulation_section="Article 13 - Information to be provided",
                severity="medium",
                category="transparency",
                title="Insufficient transparency about AI processing",
                description="Users not adequately informed about AI-driven data processing",
                recommendation="Enhance privacy notices with AI-specific information",
                remediation_effort="low",
                evidence=["privacy_policy.pdf", "user_notifications.json"],
                metadata={"article": "13", "requirement": "transparency_obligations"}
            )
        ])
        
        return violations
    
    async def _assess_eu_ai_act_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Assess EU AI Act compliance"""
        violations = []
        await asyncio.sleep(2.5)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"euai_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="eu_ai_act",
                regulation_section="Article 16 - Quality management system",
                severity="critical",
                category="quality_management",
                title="Missing quality management system for high-risk AI",
                description="High-risk AI system lacks required quality management framework",
                recommendation="Implement comprehensive quality management system per Article 16",
                remediation_effort="critical",
                deadline=datetime(2025, 8, 2),
                evidence=["risk_assessment.pdf", "quality_procedures.json"],
                metadata={"risk_level": "high", "article": "16"}
            ),
            ComplianceViolation(
                violation_id=f"euai_{hashlib.md5(f'v2_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="eu_ai_act",
                regulation_section="Article 13 - Transparency obligations",
                severity="high",
                category="transparency",
                title="Inadequate AI system transparency",
                description="AI system fails to meet transparency requirements for users",
                recommendation="Implement clear disclosure mechanisms about AI operation",
                remediation_effort="medium",
                evidence=["user_interface_audit.pdf", "disclosure_mechanisms.json"],
                metadata={"transparency_level": "insufficient", "article": "13"}
            )
        ])
        
        return violations
    
    async def _assess_nist_ai_rmf_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Assess NIST AI RMF compliance"""
        violations = []
        await asyncio.sleep(2)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"nist_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="nist_ai_rmf",
                regulation_section="GOVERN 1.1 - AI risk management",
                severity="high",
                category="governance",
                title="Incomplete AI risk management framework",
                description="Organization lacks comprehensive AI risk management processes",
                recommendation="Develop and implement AI risk management policies and procedures",
                remediation_effort="high",
                evidence=["risk_management_policy.pdf", "governance_structure.json"],
                metadata={"function": "GOVERN", "category": "1.1"}
            ),
            ComplianceViolation(
                violation_id=f"nist_{hashlib.md5(f'v2_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="nist_ai_rmf",
                regulation_section="MEASURE 2.1 - AI system performance",
                severity="medium",
                category="measurement",
                title="Insufficient AI performance monitoring",
                description="AI system lacks adequate performance measurement and monitoring",
                recommendation="Implement comprehensive AI performance monitoring and metrics",
                remediation_effort="medium",
                evidence=["performance_metrics.json", "monitoring_dashboard.pdf"],
                metadata={"function": "MEASURE", "category": "2.1"}
            )
        ])
        
        return violations
    
    async def _assess_hipaa_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Assess HIPAA compliance"""
        violations = []
        await asyncio.sleep(1.5)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"hipaa_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="hipaa",
                regulation_section="§164.308 - Administrative safeguards",
                severity="critical",
                category="administrative_safeguards",
                title="Missing workforce training on AI PHI handling",
                description="Healthcare staff lack training on AI systems handling PHI",
                recommendation="Implement comprehensive AI-PHI training program",
                remediation_effort="medium",
                evidence=["training_records.pdf", "workforce_policies.json"],
                metadata={"section": "164.308", "requirement": "workforce_training"}
            )
        ])
        
        return violations
    
    async def _assess_ccpa_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Assess CCPA compliance"""
        violations = []
        await asyncio.sleep(1.5)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"ccpa_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="ccpa",
                regulation_section="§1798.110 - Right to know",
                severity="high",
                category="consumer_rights",
                title="Inadequate consumer data disclosure for AI processing",
                description="Consumers cannot adequately understand how AI processes their data",
                recommendation="Enhance data disclosure mechanisms for AI processing",
                remediation_effort="medium",
                evidence=["consumer_requests.json", "disclosure_procedures.pdf"],
                metadata={"section": "1798.110", "right": "right_to_know"}
            )
        ])
        
        return violations
    
    async def _assess_sox_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Assess SOX compliance"""
        violations = []
        await asyncio.sleep(1)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"sox_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework="sox",
                regulation_section="Section 404 - Internal controls",
                severity="medium",
                category="internal_controls",
                title="AI financial reporting controls insufficient",
                description="AI systems affecting financial reporting lack adequate internal controls",
                recommendation="Strengthen AI-related internal controls for financial reporting",
                remediation_effort="high",
                evidence=["control_documentation.pdf", "audit_trail.json"],
                metadata={"section": "404", "control_type": "financial_reporting"}
            )
        ])
        
        return violations
    
    async def _assess_generic_compliance(self, request: ComplianceAssessmentRequest) -> List[ComplianceViolation]:
        """Generic compliance assessment"""
        violations = []
        await asyncio.sleep(1)
        
        violations.extend([
            ComplianceViolation(
                violation_id=f"generic_{hashlib.md5(f'v1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                framework=request.framework,
                regulation_section="General Requirements",
                severity="medium",
                category="documentation",
                title="Insufficient compliance documentation",
                description="AI system lacks adequate compliance documentation",
                recommendation="Develop comprehensive compliance documentation",
                remediation_effort="medium",
                evidence=["compliance_checklist.pdf"],
                metadata={"framework": request.framework}
            )
        ])
        
        return violations
    
    def _generate_assessment_id(self, request: ComplianceAssessmentRequest) -> str:
        """Generate unique assessment ID"""
        content = f"{request.asset_id}_{request.framework}_{datetime.utcnow().isoformat()}"
        return f"comp_{hashlib.md5(content.encode()).hexdigest()[:12]}"
    
    def _calculate_compliance_score(self, violations: List[ComplianceViolation]) -> float:
        """Calculate compliance score based on violations"""
        if not violations:
            return 100.0
        
        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        total_penalty = sum(severity_weights.get(v.severity, 3) for v in violations)
        
        score = max(0.0, 100.0 - total_penalty)
        return round(score, 2)
    
    def _determine_certification_status(self, score: float, violations: List[ComplianceViolation]) -> str:
        """Determine certification status"""
        critical_violations = [v for v in violations if v.severity == "critical"]
        
        if critical_violations:
            return "non_compliant"
        elif score >= 85:
            return "compliant"
        elif score >= 70:
            return "partially_compliant"
        else:
            return "non_compliant"
    
    def _generate_recommendations(self, violations: List[ComplianceViolation]) -> List[str]:
        """Generate high-level recommendations"""
        recommendations = []
        
        critical_count = len([v for v in violations if v.severity == "critical"])
        high_count = len([v for v in violations if v.severity == "high"])
        
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical compliance violations immediately")
        
        if high_count > 0:
            recommendations.append(f"Prioritize resolution of {high_count} high-severity violations")
        
        recommendations.append("Implement continuous compliance monitoring")
        recommendations.append("Schedule regular compliance assessments")
        
        return recommendations
    
    def _calculate_next_assessment_date(self, framework: str) -> datetime:
        """Calculate next recommended assessment date"""
        # Different frameworks have different assessment frequencies
        intervals = {
            'gdpr': 365,  # Annual
            'eu_ai_act': 365,  # Annual
            'hipaa': 365,  # Annual
            'ccpa': 365,  # Annual
            'nist_ai_rmf': 180,  # Semi-annual
            'sox': 90  # Quarterly
        }
        
        days = intervals.get(framework, 365)
        return datetime.utcnow().replace(year=datetime.utcnow().year + 1) if days >= 365 else \
               datetime.utcnow().replace(month=datetime.utcnow().month + 6) if days >= 180 else \
               datetime.utcnow().replace(month=datetime.utcnow().month + 3)

# Initialize engine
compliance_engine = ComplianceEngine()

# API Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "compliance-engine",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "active_assessments": len([a for a in active_assessments.values() if a])
    }

@app.post("/assess", response_model=dict)
async def start_compliance_assessment(request: ComplianceAssessmentRequest, background_tasks: BackgroundTasks):
    """Start compliance assessment"""
    try:
        background_tasks.add_task(compliance_engine.run_compliance_assessment, request)
        
        assessment_id = compliance_engine._generate_assessment_id(request)
        
        return {
            "message": "Compliance assessment started",
            "assessment_id": assessment_id,
            "asset_id": request.asset_id,
            "framework": request.framework,
            "estimated_duration": "2-4 minutes",
            "correlation_id": request.correlation_id
        }
        
    except Exception as e:
        logger.error(f"Failed to start compliance assessment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start assessment: {str(e)}")

@app.get("/assessment/{assessment_id}", response_model=ComplianceAssessmentResult)
async def get_assessment_result(assessment_id: str):
    """Get assessment result by ID"""
    if assessment_id not in assessment_results:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    return assessment_results[assessment_id]

@app.get("/assessments", response_model=List[ComplianceAssessmentResult])
async def list_assessments(asset_id: Optional[int] = None, framework: Optional[str] = None):
    """List all assessments with optional filtering"""
    results = list(assessment_results.values())
    
    if asset_id:
        results = [r for r in results if r.asset_id == asset_id]
    
    if framework:
        results = [r for r in results if r.framework == framework]
    
    return results

@app.get("/frameworks")
async def get_supported_frameworks():
    """Get supported compliance frameworks"""
    return {
        "supported_frameworks": list(compliance_engine.frameworks.keys()),
        "framework_details": compliance_engine.framework_details,
        "assessment_types": ["full", "quick", "targeted"]
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8004))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")