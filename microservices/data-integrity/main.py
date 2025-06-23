#!/usr/bin/env python3
"""
Data Integrity Checker Microservice
===================================

This microservice handles data validation and integrity checks for AI systems.
It provides specialized capabilities for:
- Training data validation
- Data drift detection  
- Schema validation and compliance
- Data quality metrics
- Privacy compliance checks

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
    title="Data Integrity Checker",
    description="Data validation and integrity verification service for AI systems",
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
class DataIntegrityRequest(BaseModel):
    """Request model for data integrity checks"""
    asset_id: int
    data_source: str = Field(..., description="Data source identifier")
    check_type: str = Field(..., description="Type of check: schema, quality, drift, privacy")
    dataset_path: Optional[str] = Field(None, description="Path to dataset")
    baseline_path: Optional[str] = Field(None, description="Path to baseline dataset for drift detection")
    schema_definition: Optional[Dict[str, Any]] = Field(None, description="Expected data schema")
    privacy_requirements: Optional[List[str]] = Field(None, description="Privacy compliance requirements")
    correlation_id: Optional[str] = Field(None, description="Request correlation ID")

class DataIssue(BaseModel):
    """Model for data integrity issues"""
    issue_type: str = Field(..., description="Type of issue: schema_violation, quality_issue, drift_detected, privacy_violation")
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    field_name: Optional[str] = Field(None, description="Affected data field")
    description: str
    recommendation: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    affected_records: int = Field(0, description="Number of affected records")
    metadata: Dict[str, Any] = {}

class IntegrityCheckResult(BaseModel):
    """Complete integrity check result"""
    check_id: str
    asset_id: int
    check_type: str
    status: str = Field(..., description="Check status: completed, failed, in_progress")
    started_at: datetime
    completed_at: Optional[datetime] = None
    issues: List[DataIssue] = []
    quality_score: float = Field(..., ge=0.0, le=10.0)
    summary: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}

# In-memory storage
check_results: Dict[str, IntegrityCheckResult] = {}
active_checks: Dict[str, bool] = {}

class DataIntegrityChecker:
    """Core data integrity checking engine"""
    
    def __init__(self):
        self.check_types = {
            'schema': self._check_schema_compliance,
            'quality': self._check_data_quality,
            'drift': self._check_data_drift,
            'privacy': self._check_privacy_compliance
        }
    
    async def run_integrity_check(self, request: DataIntegrityRequest) -> IntegrityCheckResult:
        """Main integrity check orchestrator"""
        check_id = self._generate_check_id(request)
        
        logger.info(f"Starting data integrity check {check_id} for asset {request.asset_id}")
        
        check_result = IntegrityCheckResult(
            check_id=check_id,
            asset_id=request.asset_id,
            check_type=request.check_type,
            status="in_progress",
            started_at=datetime.utcnow(),
            quality_score=0.0
        )
        
        check_results[check_id] = check_result
        active_checks[check_id] = True
        
        try:
            # Route to appropriate checker
            checker_func = self.check_types.get(request.check_type, self._check_data_quality)
            issues = await checker_func(request)
            
            # Calculate quality score
            quality_score = self._calculate_quality_score(issues)
            
            # Update result
            check_result.issues = issues
            check_result.quality_score = quality_score
            check_result.status = "completed"
            check_result.completed_at = datetime.utcnow()
            check_result.summary = self._generate_summary(issues, quality_score)
            
            logger.info(f"Completed check {check_id} with {len(issues)} issues found")
            
        except Exception as e:
            logger.error(f"Check {check_id} failed: {str(e)}")
            check_result.status = "failed"
            check_result.metadata["error_message"] = str(e)
            
        finally:
            active_checks[check_id] = False
            
        return check_result
    
    async def _check_schema_compliance(self, request: DataIntegrityRequest) -> List[DataIssue]:
        """Check data schema compliance"""
        issues = []
        await asyncio.sleep(1)  # Simulate processing
        
        if not request.schema_definition:
            issues.append(DataIssue(
                issue_type="schema_violation",
                severity="medium",
                description="No schema definition provided for validation",
                recommendation="Define expected data schema for comprehensive validation",
                confidence_score=1.0,
                metadata={"check_type": "schema"}
            ))
        else:
            # Simulate schema validation issues
            issues.extend([
                DataIssue(
                    issue_type="schema_violation",
                    severity="high",
                    field_name="user_email",
                    description="Email field contains invalid format entries",
                    recommendation="Implement email format validation before data ingestion",
                    confidence_score=0.9,
                    affected_records=47,
                    metadata={"invalid_format_count": 47, "total_records": 10000}
                ),
                DataIssue(
                    issue_type="schema_violation",
                    severity="medium",
                    field_name="created_date",
                    description="Date field has inconsistent format across records",
                    recommendation="Standardize date format to ISO 8601",
                    confidence_score=0.8,
                    affected_records=123,
                    metadata={"format_variations": ["YYYY-MM-DD", "MM/DD/YYYY", "DD-MM-YYYY"]}
                )
            ])
        
        return issues
    
    async def _check_data_quality(self, request: DataIntegrityRequest) -> List[DataIssue]:
        """Check overall data quality"""
        issues = []
        await asyncio.sleep(1.5)
        
        # Simulate data quality issues
        issues.extend([
            DataIssue(
                issue_type="quality_issue",
                severity="high",
                field_name="model_confidence",
                description="High percentage of missing values in critical field",
                recommendation="Investigate data collection process and implement imputation strategy",
                confidence_score=0.95,
                affected_records=892,
                metadata={"missing_percentage": 8.92, "field_importance": "critical"}
            ),
            DataIssue(
                issue_type="quality_issue",
                severity="medium",
                field_name="feature_vector",
                description="Outliers detected in feature distribution",
                recommendation="Review outlier detection thresholds and data preprocessing pipeline",
                confidence_score=0.7,
                affected_records=234,
                metadata={"outlier_percentage": 2.34, "z_score_threshold": 3.0}
            ),
            DataIssue(
                issue_type="quality_issue",
                severity="low",
                description="Duplicate records detected in dataset",
                recommendation="Implement deduplication process in data pipeline",
                confidence_score=0.85,
                affected_records=56,
                metadata={"duplicate_percentage": 0.56, "dedup_method": "exact_match"}
            )
        ])
        
        return issues
    
    async def _check_data_drift(self, request: DataIntegrityRequest) -> List[DataIssue]:
        """Check for data drift against baseline"""
        issues = []
        await asyncio.sleep(2)
        
        if not request.baseline_path:
            issues.append(DataIssue(
                issue_type="drift_detected",
                severity="medium",
                description="No baseline dataset provided for drift detection",
                recommendation="Provide baseline dataset for comprehensive drift analysis",
                confidence_score=1.0,
                metadata={"check_type": "drift"}
            ))
        else:
            # Simulate drift detection
            issues.extend([
                DataIssue(
                    issue_type="drift_detected",
                    severity="critical",
                    field_name="user_behavior_score",
                    description="Significant distribution shift detected in key feature",
                    recommendation="Retrain model with recent data or implement drift adaptation",
                    confidence_score=0.92,
                    affected_records=0,
                    metadata={
                        "kl_divergence": 0.45,
                        "threshold": 0.1,
                        "drift_magnitude": "high"
                    }
                ),
                DataIssue(
                    issue_type="drift_detected",
                    severity="medium",
                    field_name="transaction_amount",
                    description="Statistical properties have shifted beyond acceptable range",
                    recommendation="Monitor feature importance and consider model retraining",
                    confidence_score=0.78,
                    affected_records=0,
                    metadata={
                        "mean_shift": 1.23,
                        "std_shift": 0.87,
                        "statistical_test": "kolmogorov_smirnov"
                    }
                )
            ])
        
        return issues
    
    async def _check_privacy_compliance(self, request: DataIntegrityRequest) -> List[DataIssue]:
        """Check privacy compliance requirements"""
        issues = []
        await asyncio.sleep(1.2)
        
        # Simulate privacy compliance checks
        issues.extend([
            DataIssue(
                issue_type="privacy_violation",
                severity="critical",
                field_name="personal_identifier",
                description="Personally identifiable information detected in training data",
                recommendation="Remove or anonymize PII before model training",
                confidence_score=0.98,
                affected_records=1247,
                metadata={
                    "pii_types": ["email", "phone", "ssn_partial"],
                    "regulation": "GDPR",
                    "anonymization_required": True
                }
            ),
            DataIssue(
                issue_type="privacy_violation",
                severity="high",
                field_name="location_data",
                description="High-precision location data may violate privacy requirements",
                recommendation="Implement location data generalization or k-anonymity",
                confidence_score=0.85,
                affected_records=3456,
                metadata={
                    "precision_level": "GPS_exact",
                    "recommended_precision": "zip_code",
                    "privacy_risk": "high"
                }
            )
        ])
        
        return issues
    
    def _generate_check_id(self, request: DataIntegrityRequest) -> str:
        """Generate unique check ID"""
        content = f"{request.asset_id}_{request.check_type}_{datetime.utcnow().isoformat()}"
        return f"check_{hashlib.md5(content.encode()).hexdigest()[:12]}"
    
    def _calculate_quality_score(self, issues: List[DataIssue]) -> float:
        """Calculate data quality score"""
        if not issues:
            return 10.0
        
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_penalty = sum(severity_weights.get(issue.severity, 1) for issue in issues)
        
        # Score decreases with more severe issues
        quality_score = max(0.0, 10.0 - (total_penalty * 0.5))
        return round(quality_score, 2)
    
    def _generate_summary(self, issues: List[DataIssue], quality_score: float) -> Dict[str, Any]:
        """Generate check summary"""
        severity_counts = {}
        issue_types = {}
        
        for issue in issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
            issue_types[issue.issue_type] = issue_types.get(issue.issue_type, 0) + 1
        
        return {
            "total_issues": len(issues),
            "quality_score": quality_score,
            "severity_breakdown": severity_counts,
            "issue_type_breakdown": issue_types,
            "data_quality_status": "good" if quality_score >= 8 else "needs_attention" if quality_score >= 6 else "poor",
            "check_timestamp": datetime.utcnow().isoformat()
        }

# Initialize checker
checker = DataIntegrityChecker()

# API Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "data-integrity",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "active_checks": len([c for c in active_checks.values() if c])
    }

@app.post("/check", response_model=dict)
async def start_integrity_check(request: DataIntegrityRequest, background_tasks: BackgroundTasks):
    """Start a data integrity check"""
    try:
        background_tasks.add_task(checker.run_integrity_check, request)
        
        check_id = checker._generate_check_id(request)
        
        return {
            "message": "Data integrity check started",
            "check_id": check_id,
            "asset_id": request.asset_id,
            "check_type": request.check_type,
            "estimated_duration": "1-3 minutes",
            "correlation_id": request.correlation_id
        }
        
    except Exception as e:
        logger.error(f"Failed to start integrity check: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start check: {str(e)}")

@app.get("/check/{check_id}", response_model=IntegrityCheckResult)
async def get_check_result(check_id: str):
    """Get integrity check result by ID"""
    if check_id not in check_results:
        raise HTTPException(status_code=404, detail="Check not found")
    
    return check_results[check_id]

@app.get("/checks", response_model=List[IntegrityCheckResult])
async def list_checks(asset_id: Optional[int] = None, check_type: Optional[str] = None):
    """List all integrity checks with optional filtering"""
    results = list(check_results.values())
    
    if asset_id:
        results = [r for r in results if r.asset_id == asset_id]
    
    if check_type:
        results = [r for r in results if r.check_type == check_type]
    
    return results

@app.get("/capabilities")
async def get_capabilities():
    """Get checker capabilities"""
    return {
        "supported_check_types": list(checker.check_types.keys()),
        "issue_types": [
            "schema_violation",
            "quality_issue", 
            "drift_detected",
            "privacy_violation"
        ],
        "privacy_regulations": ["GDPR", "CCPA", "HIPAA"],
        "max_concurrent_checks": 5
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8002))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")