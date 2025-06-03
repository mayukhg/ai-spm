"""
AI Security Posture Management Platform - Database Models
=========================================================

This module defines all database models for the AI-SPM platform using SQLAlchemy ORM.
The models represent the core entities of the security management system including
users, assets, vulnerabilities, compliance frameworks, and audit logs.

All models include comprehensive field validation, relationships, and helper methods
for common operations. The schema is designed for scalability and performance.

Author: AI-SPM Development Team
Version: 1.0.0
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Index, CheckConstraint
from sqlalchemy.dialects.postgresql import JSON, ARRAY
from sqlalchemy.ext.hybrid import hybrid_property
import json

# Initialize SQLAlchemy instance
db = SQLAlchemy()


class TimestampMixin:
    """
    Mixin class that adds created_at and updated_at timestamps to models.
    
    This mixin provides automatic timestamp management for all models that inherit it.
    The timestamps are automatically set on creation and updated on modification.
    """
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), 
                          onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class User(db.Model, TimestampMixin):
    """
    User model representing system users with role-based access control.
    
    This model handles authentication, authorization, and user profile management.
    Users are assigned roles that determine their access to different platform features.
    """
    __tablename__ = 'users'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    
    # Authentication fields
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile information
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    department = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    
    # Role-based access control
    # Roles: admin, ciso, analyst, engineer, compliance_officer, auditor
    role = db.Column(db.String(20), nullable=False, default='analyst')
    
    # Account status and security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    
    # Two-factor authentication
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))  # Base32 encoded secret for TOTP
    
    # User preferences and settings
    preferences = db.Column(JSON, default=dict)  # JSON field for user preferences
    notification_settings = db.Column(JSON, default=dict)  # Notification preferences
    
    # Relationships
    owned_assets = db.relationship('AiAsset', backref='owner_user', lazy='dynamic',
                                  foreign_keys='AiAsset.owner_id')
    assigned_vulnerabilities = db.relationship('Vulnerability', backref='assigned_user', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    # Database constraints
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'ciso', 'analyst', 'engineer', 'compliance_officer', 'auditor')",
                       name='valid_user_role'),
        Index('idx_user_role_active', 'role', 'is_active'),
    )
    
    def __init__(self, **kwargs):
        """Initialize user with default notification settings"""
        super().__init__(**kwargs)
        if not self.notification_settings:
            self.notification_settings = {
                'email_alerts': True,
                'slack_notifications': False,
                'critical_alerts': True,
                'weekly_reports': True
            }
    
    def set_password(self, password: str) -> None:
        """Hash and set user password using secure bcrypt algorithm"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Verify user password against stored hash"""
        return check_password_hash(self.password_hash, password)
    
    @hybrid_property
    def full_name(self) -> str:
        """Return user's full name combining first and last name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role or higher privileges"""
        role_hierarchy = {
            'auditor': 1,
            'analyst': 2,
            'engineer': 3,
            'compliance_officer': 4,
            'ciso': 5,
            'admin': 6
        }
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(role, 0)
    
    def can_access_asset(self, asset) -> bool:
        """Check if user can access specific asset based on role and ownership"""
        if self.role in ['admin', 'ciso']:
            return True
        if self.id == asset.owner_id:
            return True
        if self.department == asset.department:
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'department': self.department,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'mfa_enabled': self.mfa_enabled
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class AiAsset(db.Model, TimestampMixin):
    """
    AI Asset model representing AI/ML systems, models, datasets, and infrastructure.
    
    This model tracks all AI-related assets in the organization including their
    security posture, compliance status, and operational metrics.
    """
    __tablename__ = 'ai_assets'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    
    # Asset classification
    # Types: model, dataset, pipeline, api, infrastructure, endpoint
    asset_type = db.Column(db.String(50), nullable=False, index=True)
    
    # Environment and deployment information
    # Environments: development, staging, production, research
    environment = db.Column(db.String(50), nullable=False, default='development')
    
    # Status: active, inactive, deprecated, maintenance
    status = db.Column(db.String(20), nullable=False, default='active')
    
    # Ownership and responsibility
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    department = db.Column(db.String(100))
    business_unit = db.Column(db.String(100))
    
    # Technical details
    technology_stack = db.Column(ARRAY(db.String), default=list)  # e.g., ['Python', 'TensorFlow', 'Docker']
    version = db.Column(db.String(50))
    
    # Location and infrastructure
    cloud_provider = db.Column(db.String(50))  # AWS, Azure, GCP, on-premise
    region = db.Column(db.String(50))
    availability_zone = db.Column(db.String(50))
    
    # URLs and endpoints
    repository_url = db.Column(db.String(500))
    documentation_url = db.Column(db.String(500))
    api_endpoint = db.Column(db.String(500))
    monitoring_dashboard = db.Column(db.String(500))
    
    # Risk assessment
    # Risk levels: critical, high, medium, low
    risk_level = db.Column(db.String(20), default='medium', index=True)
    risk_score = db.Column(db.Float, default=0.0)  # 0-100 scale
    
    # Compliance and governance
    data_classification = db.Column(db.String(50))  # public, internal, confidential, restricted
    compliance_tags = db.Column(ARRAY(db.String), default=list)  # GDPR, HIPAA, SOX, etc.
    
    # Operational metrics
    last_scanned_at = db.Column(db.DateTime)
    scan_frequency = db.Column(db.String(20), default='weekly')  # daily, weekly, monthly
    uptime_percentage = db.Column(db.Float)
    performance_score = db.Column(db.Float)
    
    # Metadata and custom fields
    metadata = db.Column(JSON, default=dict)  # Flexible metadata storage
    tags = db.Column(ARRAY(db.String), default=list)  # Custom tags for categorization
    
    # External system identifiers
    external_id = db.Column(db.String(200))  # ID in external systems (Wiz, etc.)
    external_source = db.Column(db.String(100))  # Source system name
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy='dynamic',
                                    cascade='all, delete-orphan')
    security_alerts = db.relationship('SecurityAlert', backref='asset', lazy='dynamic')
    compliance_assessments = db.relationship('ComplianceAssessment', backref='asset', lazy='dynamic')
    
    # Database constraints and indexes
    __table_args__ = (
        CheckConstraint("asset_type IN ('model', 'dataset', 'pipeline', 'api', 'infrastructure', 'endpoint')",
                       name='valid_asset_type'),
        CheckConstraint("environment IN ('development', 'staging', 'production', 'research')",
                       name='valid_environment'),
        CheckConstraint("status IN ('active', 'inactive', 'deprecated', 'maintenance')",
                       name='valid_status'),
        CheckConstraint("risk_level IN ('critical', 'high', 'medium', 'low')",
                       name='valid_risk_level'),
        CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='valid_risk_score'),
        Index('idx_asset_type_env', 'asset_type', 'environment'),
        Index('idx_asset_risk', 'risk_level', 'risk_score'),
        Index('idx_asset_owner_dept', 'owner_id', 'department'),
    )
    
    def calculate_risk_score(self) -> float:
        """
        Calculate comprehensive risk score based on multiple factors.
        
        The risk score considers vulnerability count and severity, compliance status,
        environment criticality, and asset type sensitivity.
        """
        score = 0.0
        
        # Base score from environment criticality
        env_scores = {'production': 30, 'staging': 20, 'development': 10, 'research': 15}
        score += env_scores.get(self.environment, 10)
        
        # Add vulnerability-based scoring
        critical_vulns = self.vulnerabilities.filter_by(severity='critical').count()
        high_vulns = self.vulnerabilities.filter_by(severity='high').count()
        medium_vulns = self.vulnerabilities.filter_by(severity='medium').count()
        
        score += critical_vulns * 25  # Critical vulnerabilities heavily weighted
        score += high_vulns * 15
        score += medium_vulns * 5
        
        # Asset type sensitivity modifier
        type_multipliers = {'model': 1.2, 'api': 1.1, 'dataset': 1.0, 'pipeline': 0.9}
        score *= type_multipliers.get(self.asset_type, 1.0)
        
        # Compliance penalty
        if self.compliance_tags:
            # Penalty for compliance-regulated assets with vulnerabilities
            if critical_vulns > 0 or high_vulns > 2:
                score *= 1.3
        
        return min(score, 100.0)  # Cap at 100
    
    def update_risk_assessment(self) -> None:
        """Update risk score and risk level based on current vulnerabilities"""
        self.risk_score = self.calculate_risk_score()
        
        # Update risk level based on score
        if self.risk_score >= 80:
            self.risk_level = 'critical'
        elif self.risk_score >= 60:
            self.risk_level = 'high'
        elif self.risk_score >= 30:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'
    
    def get_vulnerability_summary(self) -> Dict[str, int]:
        """Get summary count of vulnerabilities by severity"""
        vulns = self.vulnerabilities
        return {
            'critical': vulns.filter_by(severity='critical', status='open').count(),
            'high': vulns.filter_by(severity='high', status='open').count(),
            'medium': vulns.filter_by(severity='medium', status='open').count(),
            'low': vulns.filter_by(severity='low', status='open').count(),
            'total': vulns.filter_by(status='open').count()
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert asset object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'asset_type': self.asset_type,
            'environment': self.environment,
            'status': self.status,
            'owner_id': self.owner_id,
            'department': self.department,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'cloud_provider': self.cloud_provider,
            'version': self.version,
            'vulnerability_summary': self.get_vulnerability_summary(),
            'last_scanned_at': self.last_scanned_at.isoformat() if self.last_scanned_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'tags': self.tags or [],
            'compliance_tags': self.compliance_tags or []
        }
    
    def __repr__(self):
        return f'<AiAsset {self.name}>'


class Vulnerability(db.Model, TimestampMixin):
    """
    Vulnerability model representing security weaknesses in AI assets.
    
    This model tracks discovered vulnerabilities, their severity, remediation
    status, and assignment for resolution.
    """
    __tablename__ = 'vulnerabilities'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    
    # Vulnerability classification
    # Severity: critical, high, medium, low, informational
    severity = db.Column(db.String(20), nullable=False, index=True)
    
    # Status: open, in_progress, resolved, false_positive, risk_accepted
    status = db.Column(db.String(20), nullable=False, default='open', index=True)
    
    # Asset relationship
    asset_id = db.Column(db.Integer, db.ForeignKey('ai_assets.id'), nullable=False, index=True)
    
    # Assignment and ownership
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Vulnerability details
    cve_id = db.Column(db.String(20), index=True)  # Common Vulnerabilities and Exposures ID
    cvss_score = db.Column(db.Float)  # Common Vulnerability Scoring System score (0-10)
    cwe_id = db.Column(db.String(20))  # Common Weakness Enumeration ID
    
    # Technical information
    affected_component = db.Column(db.String(200))
    affected_version = db.Column(db.String(100))
    vector = db.Column(db.String(50))  # network, adjacent, local, physical
    
    # Impact assessment
    confidentiality_impact = db.Column(db.String(20))  # none, low, high
    integrity_impact = db.Column(db.String(20))  # none, low, high
    availability_impact = db.Column(db.String(20))  # none, low, high
    
    # Remediation information
    remediation_effort = db.Column(db.String(20))  # low, medium, high
    remediation_priority = db.Column(db.String(20))  # low, medium, high, critical
    remediation_notes = db.Column(db.Text)
    fix_available = db.Column(db.Boolean, default=False)
    patch_available = db.Column(db.Boolean, default=False)
    
    # Timeline tracking
    first_discovered = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_detected = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    due_date = db.Column(db.DateTime)
    resolved_date = db.Column(db.DateTime)
    
    # External references
    external_references = db.Column(JSON, default=list)  # URLs, advisories, etc.
    tags = db.Column(ARRAY(db.String), default=list)
    
    # Source information
    discovery_method = db.Column(db.String(100))  # scan, manual, external_report
    scanner_name = db.Column(db.String(100))
    scan_id = db.Column(db.String(200))
    
    # External system identifiers
    external_id = db.Column(db.String(200))
    external_source = db.Column(db.String(100))
    
    # Database constraints
    __table_args__ = (
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'informational')",
                       name='valid_severity'),
        CheckConstraint("status IN ('open', 'in_progress', 'resolved', 'false_positive', 'risk_accepted')",
                       name='valid_status'),
        CheckConstraint("vector IN ('network', 'adjacent', 'local', 'physical')",
                       name='valid_vector'),
        CheckConstraint('cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)',
                       name='valid_cvss_score'),
        Index('idx_vuln_severity_status', 'severity', 'status'),
        Index('idx_vuln_asset_severity', 'asset_id', 'severity'),
        Index('idx_vuln_assigned_status', 'assigned_to', 'status'),
    )
    
    def calculate_sla_days(self) -> int:
        """Calculate SLA days for vulnerability remediation based on severity"""
        sla_days = {
            'critical': 1,      # 1 day for critical
            'high': 7,          # 1 week for high
            'medium': 30,       # 1 month for medium
            'low': 90,          # 3 months for low
            'informational': 180 # 6 months for informational
        }
        return sla_days.get(self.severity, 30)
    
    def is_overdue(self) -> bool:
        """Check if vulnerability remediation is overdue"""
        if self.status in ['resolved', 'false_positive']:
            return False
        
        if self.due_date:
            return datetime.now(timezone.utc) > self.due_date.replace(tzinfo=timezone.utc)
        
        # Calculate based on SLA if no due date set
        sla_days = self.calculate_sla_days()
        due_date = self.first_discovered + timedelta(days=sla_days)
        return datetime.now(timezone.utc) > due_date.replace(tzinfo=timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'asset_id': self.asset_id,
            'assigned_to': self.assigned_to,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'first_discovered': self.first_discovered.isoformat(),
            'last_detected': self.last_detected.isoformat(),
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'is_overdue': self.is_overdue(),
            'remediation_priority': self.remediation_priority,
            'fix_available': self.fix_available,
            'tags': self.tags or [],
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.title}>'


class SecurityAlert(db.Model, TimestampMixin):
    """
    Security Alert model representing real-time security incidents and threats.
    
    This model captures security events, incidents, and alerts from various
    sources including automated scanning tools and manual reporting.
    """
    __tablename__ = 'security_alerts'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    
    # Alert classification
    # Severity: critical, high, medium, low
    severity = db.Column(db.String(20), nullable=False, index=True)
    
    # Alert type: vulnerability, breach, anomaly, compliance, policy_violation
    alert_type = db.Column(db.String(50), nullable=False, index=True)
    
    # Status: open, investigating, resolved, false_positive
    status = db.Column(db.String(20), nullable=False, default='open', index=True)
    
    # Asset relationship (optional - some alerts may not be asset-specific)
    asset_id = db.Column(db.Integer, db.ForeignKey('ai_assets.id'), index=True)
    
    # Assignment and tracking
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Alert details
    source_system = db.Column(db.String(100))  # Source of the alert
    event_timestamp = db.Column(db.DateTime, nullable=False)
    
    # Impact assessment
    affected_systems = db.Column(ARRAY(db.String), default=list)
    impact_description = db.Column(db.Text)
    business_impact = db.Column(db.String(20))  # low, medium, high, critical
    
    # Evidence and forensics
    evidence_files = db.Column(JSON, default=list)  # File paths/URLs to evidence
    indicators_of_compromise = db.Column(JSON, default=list)  # IOCs
    
    # Response information
    response_actions = db.Column(JSON, default=list)  # Actions taken
    resolution_notes = db.Column(db.Text)
    lessons_learned = db.Column(db.Text)
    
    # Timeline
    acknowledged_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)
    
    # External references
    external_ticket_id = db.Column(db.String(100))  # JIRA, ServiceNow, etc.
    external_references = db.Column(JSON, default=list)
    
    # Metadata
    tags = db.Column(ARRAY(db.String), default=list)
    metadata = db.Column(JSON, default=dict)
    
    # External system identifiers
    external_id = db.Column(db.String(200))
    external_source = db.Column(db.String(100))
    
    # Database constraints
    __table_args__ = (
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')",
                       name='valid_alert_severity'),
        CheckConstraint("alert_type IN ('vulnerability', 'breach', 'anomaly', 'compliance', 'policy_violation')",
                       name='valid_alert_type'),
        CheckConstraint("status IN ('open', 'investigating', 'resolved', 'false_positive')",
                       name='valid_alert_status'),
        Index('idx_alert_severity_status', 'severity', 'status'),
        Index('idx_alert_type_timestamp', 'alert_type', 'event_timestamp'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security alert object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'alert_type': self.alert_type,
            'status': self.status,
            'asset_id': self.asset_id,
            'assigned_to': self.assigned_to,
            'event_timestamp': self.event_timestamp.isoformat(),
            'business_impact': self.business_impact,
            'source_system': self.source_system,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'tags': self.tags or [],
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<SecurityAlert {self.title}>'


class ComplianceFramework(db.Model, TimestampMixin):
    """
    Compliance Framework model representing regulatory and standards frameworks.
    
    This model defines compliance frameworks like NIST AI RMF, GDPR, SOC 2, etc.
    and their associated controls and requirements.
    """
    __tablename__ = 'compliance_frameworks'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    version = db.Column(db.String(20))
    
    # Framework details
    category = db.Column(db.String(50))  # security, privacy, ai_governance, industry
    authority = db.Column(db.String(100))  # Issuing organization
    mandatory = db.Column(db.Boolean, default=False)  # Regulatory requirement vs. best practice
    
    # Framework structure
    controls = db.Column(JSON, default=list)  # List of control definitions
    requirements = db.Column(JSON, default=list)  # Specific requirements
    
    # Applicability
    applicable_asset_types = db.Column(ARRAY(db.String), default=list)
    applicable_industries = db.Column(ARRAY(db.String), default=list)
    applicable_regions = db.Column(ARRAY(db.String), default=list)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    effective_date = db.Column(db.Date)
    
    # Relationships
    assessments = db.relationship('ComplianceAssessment', backref='framework', lazy='dynamic')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert compliance framework object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'category': self.category,
            'authority': self.authority,
            'mandatory': self.mandatory,
            'is_active': self.is_active,
            'control_count': len(self.controls) if self.controls else 0,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<ComplianceFramework {self.name}>'


class ComplianceAssessment(db.Model, TimestampMixin):
    """
    Compliance Assessment model representing compliance evaluations of assets.
    
    This model tracks compliance assessments of AI assets against specific
    frameworks and their compliance status over time.
    """
    __tablename__ = 'compliance_assessments'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    
    # Relationships
    asset_id = db.Column(db.Integer, db.ForeignKey('ai_assets.id'), nullable=False, index=True)
    framework_id = db.Column(db.Integer, db.ForeignKey('compliance_frameworks.id'), nullable=False, index=True)
    assessor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Assessment details
    assessment_date = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, in_progress, completed
    
    # Scoring
    overall_score = db.Column(db.Float)  # Percentage compliance score (0-100)
    max_possible_score = db.Column(db.Float)
    
    # Control assessments
    control_results = db.Column(JSON, default=dict)  # Per-control assessment results
    
    # Findings and recommendations
    findings = db.Column(JSON, default=list)  # List of compliance findings
    recommendations = db.Column(JSON, default=list)  # Remediation recommendations
    
    # Timeline
    due_date = db.Column(db.DateTime)
    completed_date = db.Column(db.DateTime)
    next_assessment_date = db.Column(db.DateTime)
    
    # Evidence
    evidence_files = db.Column(JSON, default=list)
    documentation_links = db.Column(JSON, default=list)
    
    # Database constraints
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'in_progress', 'completed')",
                       name='valid_assessment_status'),
        CheckConstraint('overall_score IS NULL OR (overall_score >= 0 AND overall_score <= 100)',
                       name='valid_overall_score'),
        Index('idx_assessment_asset_framework', 'asset_id', 'framework_id'),
        Index('idx_assessment_date_status', 'assessment_date', 'status'),
    )
    
    def calculate_compliance_percentage(self) -> float:
        """Calculate compliance percentage based on control results"""
        if not self.control_results:
            return 0.0
        
        total_controls = len(self.control_results)
        passed_controls = sum(1 for result in self.control_results.values() 
                            if result.get('status') == 'pass')
        
        return (passed_controls / total_controls * 100) if total_controls > 0 else 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert compliance assessment object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'framework_id': self.framework_id,
            'assessor_id': self.assessor_id,
            'assessment_date': self.assessment_date.isoformat(),
            'status': self.status,
            'overall_score': self.overall_score,
            'compliance_percentage': self.calculate_compliance_percentage(),
            'findings_count': len(self.findings) if self.findings else 0,
            'completed_date': self.completed_date.isoformat() if self.completed_date else None,
            'next_assessment_date': self.next_assessment_date.isoformat() if self.next_assessment_date else None,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<ComplianceAssessment {self.id}>'


class AuditLog(db.Model, TimestampMixin):
    """
    Audit Log model for tracking all user actions and system events.
    
    This model provides comprehensive audit trail functionality for
    compliance, security monitoring, and forensic analysis.
    """
    __tablename__ = 'audit_logs'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    
    # User and session information
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    session_id = db.Column(db.String(255), index=True)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(500))
    
    # Action details
    action = db.Column(db.String(100), nullable=False, index=True)  # create, read, update, delete, login, etc.
    resource_type = db.Column(db.String(50), nullable=False, index=True)  # asset, vulnerability, user, etc.
    resource_id = db.Column(db.String(100), index=True)  # ID of affected resource
    
    # Event details
    event_timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    success = db.Column(db.Boolean, nullable=False, default=True)
    
    # Additional context
    details = db.Column(JSON, default=dict)  # Additional event details
    changes = db.Column(JSON, default=dict)  # Before/after values for updates
    
    # Request information
    http_method = db.Column(db.String(10))
    endpoint = db.Column(db.String(200))
    request_id = db.Column(db.String(100))  # Correlation ID for request tracing
    
    # Risk and compliance
    risk_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    compliance_relevant = db.Column(db.Boolean, default=False)
    
    # Database constraints
    __table_args__ = (
        CheckConstraint("risk_level IN ('low', 'medium', 'high', 'critical')",
                       name='valid_audit_risk_level'),
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_timestamp_success', 'event_timestamp', 'success'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'event_timestamp': self.event_timestamp.isoformat(),
            'success': self.success,
            'ip_address': self.ip_address,
            'details': self.details or {},
            'risk_level': self.risk_level,
            'compliance_relevant': self.compliance_relevant
        }
    
    def __repr__(self):
        return f'<AuditLog {self.action} on {self.resource_type}>'


# Utility functions for database operations
def init_default_data():
    """
    Initialize database with default compliance frameworks and system data.
    
    This function creates default compliance frameworks and system configuration
    data that are required for the platform to function properly.
    """
    try:
        # Create default compliance frameworks
        default_frameworks = [
            {
                'name': 'NIST AI Risk Management Framework',
                'description': 'Framework for managing AI risks across the AI lifecycle',
                'version': '1.0',
                'category': 'ai_governance',
                'authority': 'NIST',
                'mandatory': False,
                'controls': [
                    {'id': 'GOV-1', 'title': 'AI Governance Structure', 'description': 'Establish AI governance'},
                    {'id': 'MAP-1', 'title': 'Risk Mapping', 'description': 'Map AI risks and impacts'},
                    {'id': 'MEA-1', 'title': 'Risk Measurement', 'description': 'Measure and assess AI risks'},
                    {'id': 'MAN-1', 'title': 'Risk Management', 'description': 'Manage identified AI risks'}
                ]
            },
            {
                'name': 'ISO 27001',
                'description': 'Information Security Management System standard',
                'version': '2013',
                'category': 'security',
                'authority': 'ISO',
                'mandatory': False,
                'controls': [
                    {'id': 'A.5.1', 'title': 'Information Security Policies', 'description': 'Management direction for information security'},
                    {'id': 'A.6.1', 'title': 'Organization of Information Security', 'description': 'Internal organization'},
                    {'id': 'A.8.1', 'title': 'Asset Management', 'description': 'Responsibility for assets'}
                ]
            }
        ]
        
        for framework_data in default_frameworks:
            existing = ComplianceFramework.query.filter_by(name=framework_data['name']).first()
            if not existing:
                framework = ComplianceFramework(**framework_data)
                db.session.add(framework)
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        raise e