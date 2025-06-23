#!/usr/bin/env python3
"""
Wiz Integration Data Transformer Microservice
=============================================

This microservice handles Wiz cloud security data integration and transformation.
It provides specialized capabilities for:
- Wiz API data ingestion
- Cloud asset correlation
- Security finding normalization
- Risk scoring and prioritization

Author: AI-SPM Development Team
Version: 1.0.0
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import asyncio
import logging
import uvicorn
from datetime import datetime
import json
import hashlib
import os
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Wiz Integration Service",
    description="Cloud security data integration and transformation service",
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
class WizIntegrationRequest(BaseModel):
    """Request model for Wiz data integration"""
    asset_id: int
    integration_type: str = Field(..., description="Type: sync, scan, assessment")
    cloud_provider: str = Field(..., description="Cloud provider: aws, azure, gcp")
    resource_filters: Optional[Dict[str, Any]] = Field(None, description="Resource filtering criteria")
    sync_scope: Optional[List[str]] = Field(None, description="Scope of synchronization")
    correlation_id: Optional[str] = Field(None, description="Request correlation ID")

class CloudSecurityFinding(BaseModel):
    """Model for cloud security findings from Wiz"""
    finding_id: str
    resource_id: str
    resource_type: str
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    category: str = Field(..., description="Finding category")
    title: str
    description: str
    remediation: str
    status: str = Field(default="open", description="Finding status")
    cloud_provider: str
    region: str
    tags: Dict[str, str] = {}
    first_detected: datetime
    last_updated: datetime
    metadata: Dict[str, Any] = {}

class WizIntegrationResult(BaseModel):
    """Complete Wiz integration result"""
    integration_id: str
    asset_id: int
    integration_type: str
    status: str = Field(..., description="Status: completed, failed, in_progress")
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[CloudSecurityFinding] = []
    resources_processed: int = 0
    total_findings: int = 0
    risk_summary: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}

# Storage
integration_results: Dict[str, WizIntegrationResult] = {}
active_integrations: Dict[str, bool] = {}

class WizIntegrationService:
    """Core Wiz integration service"""
    
    def __init__(self):
        self.wiz_client_id = os.getenv("WIZ_CLIENT_ID")
        self.wiz_client_secret = os.getenv("WIZ_CLIENT_SECRET")
        self.wiz_api_url = os.getenv("WIZ_API_URL", "https://api.wiz.io")
        self.integration_types = {
            'sync': self._sync_cloud_resources,
            'scan': self._scan_cloud_assets,
            'assessment': self._run_security_assessment
        }
    
    async def run_integration(self, request: WizIntegrationRequest) -> WizIntegrationResult:
        """Main integration orchestrator"""
        integration_id = self._generate_integration_id(request)
        
        logger.info(f"Starting Wiz integration {integration_id} for asset {request.asset_id}")
        
        result = WizIntegrationResult(
            integration_id=integration_id,
            asset_id=request.asset_id,
            integration_type=request.integration_type,
            status="in_progress",
            started_at=datetime.utcnow(),
            resources_processed=0,
            total_findings=0
        )
        
        integration_results[integration_id] = result
        active_integrations[integration_id] = True
        
        try:
            # Check if Wiz credentials are available
            if not self.wiz_client_id or not self.wiz_client_secret:
                raise Exception("Wiz credentials not configured")
            
            # Route to appropriate integration handler
            handler = self.integration_types.get(
                request.integration_type, 
                self._sync_cloud_resources
            )
            
            findings = await handler(request)
            
            # Update result
            result.findings = findings
            result.total_findings = len(findings)
            result.resources_processed = self._calculate_resources_processed(findings)
            result.risk_summary = self._generate_risk_summary(findings)
            result.status = "completed"
            result.completed_at = datetime.utcnow()
            
            logger.info(f"Completed integration {integration_id} with {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Integration {integration_id} failed: {str(e)}")
            result.status = "failed"
            result.metadata["error_message"] = str(e)
            
        finally:
            active_integrations[integration_id] = False
            
        return result
    
    async def _sync_cloud_resources(self, request: WizIntegrationRequest) -> List[CloudSecurityFinding]:
        """Synchronize cloud resources from Wiz"""
        findings = []
        await asyncio.sleep(3)  # Simulate API calls
        
        # Simulate cloud resource findings
        base_findings = [
            {
                "finding_id": f"wiz-{hashlib.md5(f'finding1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_id": f"i-{hashlib.md5(f'instance1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_type": "ec2_instance",
                "severity": "high",
                "category": "configuration",
                "title": "EC2 Instance with Unrestricted Security Group",
                "description": "EC2 instance allows inbound traffic from 0.0.0.0/0",
                "remediation": "Restrict security group rules to specific IP ranges",
                "cloud_provider": request.cloud_provider,
                "region": "us-east-1",
                "tags": {"Environment": "production", "Team": "ai-platform"},
                "first_detected": datetime.utcnow(),
                "last_updated": datetime.utcnow(),
                "metadata": {"instance_type": "t3.large", "vpc_id": "vpc-123456"}
            },
            {
                "finding_id": f"wiz-{hashlib.md5(f'finding2_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_id": f"vol-{hashlib.md5(f'volume1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_type": "ebs_volume",
                "severity": "medium",
                "category": "encryption",
                "title": "Unencrypted EBS Volume",
                "description": "EBS volume is not encrypted at rest",
                "remediation": "Enable EBS encryption and migrate data to encrypted volume",
                "cloud_provider": request.cloud_provider,
                "region": "us-east-1",
                "tags": {"Environment": "production"},
                "first_detected": datetime.utcnow(),
                "last_updated": datetime.utcnow(),
                "metadata": {"volume_size": "500GB", "volume_type": "gp3"}
            }
        ]
        
        for finding_data in base_findings:
            findings.append(CloudSecurityFinding(**finding_data))
        
        return findings
    
    async def _scan_cloud_assets(self, request: WizIntegrationRequest) -> List[CloudSecurityFinding]:
        """Perform security scan of cloud assets"""
        findings = []
        await asyncio.sleep(4)
        
        # Simulate security scan findings
        scan_findings = [
            {
                "finding_id": f"wiz-scan-{hashlib.md5(f'scan1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_id": f"s3-{hashlib.md5(f'bucket1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_type": "s3_bucket",
                "severity": "critical",
                "category": "access_control",
                "title": "Publicly Accessible S3 Bucket",
                "description": "S3 bucket allows public read access to sensitive data",
                "remediation": "Remove public access permissions and implement proper IAM policies",
                "cloud_provider": request.cloud_provider,
                "region": "us-west-2",
                "tags": {"DataClassification": "confidential"},
                "first_detected": datetime.utcnow(),
                "last_updated": datetime.utcnow(),
                "metadata": {"bucket_size": "1.2TB", "object_count": 45678}
            },
            {
                "finding_id": f"wiz-scan-{hashlib.md5(f'scan2_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_id": f"rds-{hashlib.md5(f'database1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_type": "rds_instance",
                "severity": "high",
                "category": "network_security",
                "title": "RDS Database Publicly Accessible",
                "description": "RDS instance is configured with public accessibility enabled",
                "remediation": "Disable public accessibility and use VPC endpoints",
                "cloud_provider": request.cloud_provider,
                "region": "us-west-2",
                "tags": {"Environment": "production", "Database": "postgresql"},
                "first_detected": datetime.utcnow(),
                "last_updated": datetime.utcnow(),
                "metadata": {"engine": "postgresql", "version": "13.7"}
            }
        ]
        
        for finding_data in scan_findings:
            findings.append(CloudSecurityFinding(**finding_data))
        
        return findings
    
    async def _run_security_assessment(self, request: WizIntegrationRequest) -> List[CloudSecurityFinding]:
        """Run comprehensive security assessment"""
        findings = []
        await asyncio.sleep(5)
        
        # Simulate comprehensive assessment findings
        assessment_findings = [
            {
                "finding_id": f"wiz-assess-{hashlib.md5(f'assess1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_id": f"iam-role-{hashlib.md5(f'role1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_type": "iam_role",
                "severity": "medium",
                "category": "identity_access",
                "title": "Overprivileged IAM Role",
                "description": "IAM role has excessive permissions that violate least privilege principle",
                "remediation": "Review and reduce IAM role permissions to minimum required",
                "cloud_provider": request.cloud_provider,
                "region": "global",
                "tags": {"Service": "ai-training"},
                "first_detected": datetime.utcnow(),
                "last_updated": datetime.utcnow(),
                "metadata": {"attached_policies": 12, "unused_permissions": 8}
            },
            {
                "finding_id": f"wiz-assess-{hashlib.md5(f'assess2_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_id": f"lambda-{hashlib.md5(f'function1_{request.asset_id}'.encode()).hexdigest()[:8]}",
                "resource_type": "lambda_function",
                "severity": "low",
                "category": "configuration",
                "title": "Lambda Function Missing Error Handling",
                "description": "Lambda function lacks proper error handling and logging",
                "remediation": "Implement comprehensive error handling and CloudWatch logging",
                "cloud_provider": request.cloud_provider,
                "region": "us-east-1",
                "tags": {"Function": "data-processor"},
                "first_detected": datetime.utcnow(),
                "last_updated": datetime.utcnow(),
                "metadata": {"runtime": "python3.9", "memory": "512MB"}
            }
        ]
        
        for finding_data in assessment_findings:
            findings.append(CloudSecurityFinding(**finding_data))
        
        return findings
    
    def _generate_integration_id(self, request: WizIntegrationRequest) -> str:
        """Generate unique integration ID"""
        content = f"{request.asset_id}_{request.integration_type}_{datetime.utcnow().isoformat()}"
        return f"wiz_{hashlib.md5(content.encode()).hexdigest()[:12]}"
    
    def _calculate_resources_processed(self, findings: List[CloudSecurityFinding]) -> int:
        """Calculate number of unique resources processed"""
        unique_resources = set(finding.resource_id for finding in findings)
        return len(unique_resources)
    
    def _generate_risk_summary(self, findings: List[CloudSecurityFinding]) -> Dict[str, Any]:
        """Generate risk summary from findings"""
        severity_counts = {}
        category_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        # Calculate risk score
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        total_risk = sum(severity_weights.get(sev, 1) * count for sev, count in severity_counts.items())
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "risk_score": min(100, total_risk),
            "compliance_impact": self._assess_compliance_impact(findings),
            "summary_timestamp": datetime.utcnow().isoformat()
        }
    
    def _assess_compliance_impact(self, findings: List[CloudSecurityFinding]) -> Dict[str, Any]:
        """Assess compliance impact of findings"""
        high_impact_categories = ["access_control", "encryption", "network_security"]
        
        compliance_findings = [
            f for f in findings 
            if f.category in high_impact_categories and f.severity in ["critical", "high"]
        ]
        
        return {
            "compliance_at_risk": len(compliance_findings) > 0,
            "affected_standards": ["SOC2", "ISO27001", "PCI-DSS"] if compliance_findings else [],
            "remediation_priority": "high" if compliance_findings else "medium",
            "compliance_score": max(0, 100 - (len(compliance_findings) * 10))
        }

# Initialize service
wiz_service = WizIntegrationService()

# API Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "wiz-integration",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "active_integrations": len([i for i in active_integrations.values() if i]),
        "credentials_configured": bool(wiz_service.wiz_client_id and wiz_service.wiz_client_secret)
    }

@app.post("/integrate", response_model=dict)
async def start_integration(request: WizIntegrationRequest, background_tasks: BackgroundTasks):
    """Start Wiz cloud security integration"""
    try:
        background_tasks.add_task(wiz_service.run_integration, request)
        
        integration_id = wiz_service._generate_integration_id(request)
        
        return {
            "message": "Wiz integration started",
            "integration_id": integration_id,
            "asset_id": request.asset_id,
            "integration_type": request.integration_type,
            "estimated_duration": "3-7 minutes",
            "correlation_id": request.correlation_id
        }
        
    except Exception as e:
        logger.error(f"Failed to start Wiz integration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start integration: {str(e)}")

@app.get("/integration/{integration_id}", response_model=WizIntegrationResult)
async def get_integration_result(integration_id: str):
    """Get integration result by ID"""
    if integration_id not in integration_results:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    return integration_results[integration_id]

@app.get("/integrations", response_model=List[WizIntegrationResult])
async def list_integrations(asset_id: Optional[int] = None, integration_type: Optional[str] = None):
    """List all integrations with optional filtering"""
    results = list(integration_results.values())
    
    if asset_id:
        results = [r for r in results if r.asset_id == asset_id]
    
    if integration_type:
        results = [r for r in results if r.integration_type == integration_type]
    
    return results

@app.get("/capabilities")
async def get_capabilities():
    """Get integration capabilities"""
    return {
        "supported_integration_types": list(wiz_service.integration_types.keys()),
        "supported_cloud_providers": ["aws", "azure", "gcp"],
        "finding_categories": [
            "configuration",
            "encryption", 
            "access_control",
            "network_security",
            "identity_access"
        ],
        "max_concurrent_integrations": 3,
        "credentials_required": ["WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET"]
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8003))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")