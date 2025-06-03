"""
AI Security Posture Management Platform - API Module
====================================================

This module provides comprehensive REST API endpoints for the AI-SPM platform.
It includes full CRUD operations for all major entities, advanced filtering,
sorting, pagination, and comprehensive error handling.

Endpoints cover:
- Asset management and inventory
- Vulnerability tracking and remediation
- Security alert management
- Compliance assessment and reporting
- Dashboard metrics and analytics
- User and role management

Author: AI-SPM Development Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import and_, or_, desc, asc, func
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest, NotFound

from models import (
    db, User, AiAsset, Vulnerability, SecurityAlert, 
    ComplianceFramework, ComplianceAssessment, AuditLog
)
from auth import login_required, role_required, log_audit_event

# Configure logging
logger = logging.getLogger(__name__)

# Create API blueprint
api_bp = Blueprint('api', __name__)


class ValidationError(Exception):
    """Custom exception for data validation errors"""
    pass


def validate_pagination_params(page: int = 1, per_page: int = 20) -> Tuple[int, int]:
    """
    Validate and normalize pagination parameters.
    
    Args:
        page: Page number (1-based)
        per_page: Items per page
    
    Returns:
        Tuple of validated (page, per_page) values
    """
    page = max(1, page)  # Ensure page is at least 1
    per_page = min(max(1, per_page), 100)  # Limit per_page between 1-100
    return page, per_page


def apply_filters(query, model, filters: Dict[str, Any]):
    """
    Apply dynamic filters to SQLAlchemy query based on model attributes.
    
    Args:
        query: SQLAlchemy query object
        model: SQLAlchemy model class
        filters: Dictionary of filter criteria
    
    Returns:
        Modified query with applied filters
    """
    for key, value in filters.items():
        if hasattr(model, key) and value is not None:
            if isinstance(value, list):
                # Handle list values with IN clause
                query = query.filter(getattr(model, key).in_(value))
            elif isinstance(value, str) and key.endswith('_search'):
                # Handle text search fields
                field_name = key.replace('_search', '')
                if hasattr(model, field_name):
                    query = query.filter(getattr(model, field_name).ilike(f'%{value}%'))
            else:
                # Handle exact matches
                query = query.filter(getattr(model, key) == value)
    
    return query


def paginate_query(query, page: int, per_page: int) -> Dict[str, Any]:
    """
    Paginate query and return pagination metadata.
    
    Args:
        query: SQLAlchemy query object
        page: Page number
        per_page: Items per page
    
    Returns:
        Dictionary with paginated results and metadata
    """
    paginated = query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )
    
    return {
        'items': [item.to_dict() for item in paginated.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': paginated.total,
            'pages': paginated.pages,
            'has_next': paginated.has_next,
            'has_prev': paginated.has_prev,
            'next_page': paginated.next_num if paginated.has_next else None,
            'prev_page': paginated.prev_num if paginated.has_prev else None
        }
    }


# =============================================================================
# AI Asset Management Endpoints
# =============================================================================

@api_bp.route('/assets', methods=['GET'])
@login_required
def get_assets():
    """
    Get paginated list of AI assets with filtering and sorting.
    
    Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - asset_type: Filter by asset type
        - environment: Filter by environment
        - status: Filter by status
        - risk_level: Filter by risk level
        - owner_id: Filter by owner
        - department: Filter by department
        - search: Text search in name and description
        - sort_by: Field to sort by (default: created_at)
        - sort_order: asc or desc (default: desc)
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        page, per_page = validate_pagination_params(page, per_page)
        
        # Build base query
        query = AiAsset.query
        
        # Apply role-based filtering
        user = request.current_user
        if user.role not in ['admin', 'ciso']:
            # Non-admin users can only see assets they own or from their department
            query = query.filter(
                or_(
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department
                )
            )
        
        # Apply filters
        filters = {
            'asset_type': request.args.get('asset_type'),
            'environment': request.args.get('environment'),
            'status': request.args.get('status'),
            'risk_level': request.args.get('risk_level'),
            'owner_id': request.args.get('owner_id', type=int),
            'department': request.args.get('department')
        }
        
        query = apply_filters(query, AiAsset, filters)
        
        # Apply text search
        search_term = request.args.get('search')
        if search_term:
            query = query.filter(
                or_(
                    AiAsset.name.ilike(f'%{search_term}%'),
                    AiAsset.description.ilike(f'%{search_term}%')
                )
            )
        
        # Apply sorting
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc').lower()
        
        if hasattr(AiAsset, sort_by):
            sort_field = getattr(AiAsset, sort_by)
            if sort_order == 'asc':
                query = query.order_by(asc(sort_field))
            else:
                query = query.order_by(desc(sort_field))
        
        # Paginate results
        result = paginate_query(query, page, per_page)
        
        # Add summary statistics
        result['summary'] = {
            'total_assets': query.count(),
            'by_environment': db.session.query(
                AiAsset.environment, func.count(AiAsset.id)
            ).group_by(AiAsset.environment).all(),
            'by_risk_level': db.session.query(
                AiAsset.risk_level, func.count(AiAsset.id)
            ).group_by(AiAsset.risk_level).all()
        }
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error fetching assets: {str(e)}")
        return jsonify({'error': 'Failed to fetch assets'}), 500


@api_bp.route('/assets/<int:asset_id>', methods=['GET'])
@login_required
def get_asset(asset_id: int):
    """
    Get detailed information about a specific AI asset.
    
    Includes vulnerability summary, compliance status, and recent activity.
    """
    try:
        asset = AiAsset.query.get_or_404(asset_id)
        
        # Check if user can access this asset
        if not request.current_user.can_access_asset(asset):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get detailed asset information
        asset_data = asset.to_dict()
        
        # Add vulnerability details
        asset_data['vulnerabilities'] = {
            'summary': asset.get_vulnerability_summary(),
            'recent': [v.to_dict() for v in asset.vulnerabilities.order_by(
                desc(Vulnerability.created_at)
            ).limit(5)]
        }
        
        # Add security alerts
        asset_data['recent_alerts'] = [
            alert.to_dict() for alert in asset.security_alerts.order_by(
                desc(SecurityAlert.created_at)
            ).limit(5)
        ]
        
        # Add compliance assessments
        asset_data['compliance_assessments'] = [
            assessment.to_dict() for assessment in asset.compliance_assessments.order_by(
                desc(ComplianceAssessment.assessment_date)
            ).limit(3)
        ]
        
        return jsonify(asset_data), 200
        
    except Exception as e:
        logger.error(f"Error fetching asset {asset_id}: {str(e)}")
        return jsonify({'error': 'Failed to fetch asset'}), 500


@api_bp.route('/assets', methods=['POST'])
@login_required
@role_required(['admin', 'ciso', 'engineer'])
def create_asset():
    """
    Create a new AI asset with comprehensive validation.
    
    Required fields: name, asset_type, environment
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'asset_type', 'environment']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400
        
        # Validate enum values
        valid_asset_types = ['model', 'dataset', 'pipeline', 'api', 'infrastructure', 'endpoint']
        valid_environments = ['development', 'staging', 'production', 'research']
        
        if data['asset_type'] not in valid_asset_types:
            return jsonify({
                'error': 'Invalid asset_type',
                'valid_values': valid_asset_types
            }), 400
        
        if data['environment'] not in valid_environments:
            return jsonify({
                'error': 'Invalid environment',
                'valid_values': valid_environments
            }), 400
        
        # Create new asset
        asset = AiAsset(
            name=data['name'].strip(),
            description=data.get('description', '').strip(),
            asset_type=data['asset_type'],
            environment=data['environment'],
            status=data.get('status', 'active'),
            owner_id=data.get('owner_id', request.current_user.id),
            department=data.get('department', request.current_user.department),
            business_unit=data.get('business_unit', ''),
            technology_stack=data.get('technology_stack', []),
            version=data.get('version', ''),
            cloud_provider=data.get('cloud_provider', ''),
            region=data.get('region', ''),
            repository_url=data.get('repository_url', ''),
            documentation_url=data.get('documentation_url', ''),
            api_endpoint=data.get('api_endpoint', ''),
            data_classification=data.get('data_classification', ''),
            compliance_tags=data.get('compliance_tags', []),
            metadata=data.get('metadata', {}),
            tags=data.get('tags', [])
        )
        
        # Calculate initial risk assessment
        asset.update_risk_assessment()
        
        db.session.add(asset)
        db.session.commit()
        
        # Log asset creation
        log_audit_event(
            request.current_user.id, 
            'asset_create', 
            'asset', 
            str(asset.id),
            success=True,
            details={'name': asset.name, 'type': asset.asset_type}
        )
        
        logger.info(f"Asset created: {asset.name} by {request.current_user.username}")
        
        return jsonify({
            'message': 'Asset created successfully',
            'asset': asset.to_dict()
        }), 201
        
    except IntegrityError as e:
        db.session.rollback()
        logger.error(f"Asset creation integrity error: {str(e)}")
        return jsonify({'error': 'Asset with this name may already exist'}), 409
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Asset creation error: {str(e)}")
        return jsonify({'error': 'Failed to create asset'}), 500


@api_bp.route('/assets/<int:asset_id>', methods=['PUT'])
@login_required
@role_required(['admin', 'ciso', 'engineer'])
def update_asset(asset_id: int):
    """
    Update an existing AI asset with change tracking.
    """
    try:
        asset = AiAsset.query.get_or_404(asset_id)
        
        # Check if user can modify this asset
        if not request.current_user.can_access_asset(asset):
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        changes = {}
        
        # Track changes for audit log
        updatable_fields = [
            'name', 'description', 'status', 'version', 'technology_stack',
            'cloud_provider', 'region', 'repository_url', 'documentation_url',
            'api_endpoint', 'data_classification', 'compliance_tags', 'metadata', 'tags'
        ]
        
        for field in updatable_fields:
            if field in data:
                old_value = getattr(asset, field)
                new_value = data[field]
                
                if old_value != new_value:
                    changes[field] = {'old': old_value, 'new': new_value}
                    setattr(asset, field, new_value)
        
        # Recalculate risk assessment if relevant fields changed
        if any(field in changes for field in ['environment', 'compliance_tags']):
            asset.update_risk_assessment()
        
        db.session.commit()
        
        # Log asset update
        if changes:
            log_audit_event(
                request.current_user.id,
                'asset_update',
                'asset',
                str(asset.id),
                success=True,
                details={'changes': changes}
            )
        
        return jsonify({
            'message': 'Asset updated successfully',
            'asset': asset.to_dict(),
            'changes': changes
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Asset update error: {str(e)}")
        return jsonify({'error': 'Failed to update asset'}), 500


# =============================================================================
# Vulnerability Management Endpoints
# =============================================================================

@api_bp.route('/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities():
    """
    Get paginated list of vulnerabilities with advanced filtering.
    
    Query Parameters:
        - page, per_page: Pagination
        - severity: Filter by severity level
        - status: Filter by status
        - asset_id: Filter by specific asset
        - assigned_to: Filter by assigned user
        - overdue: Filter overdue vulnerabilities (true/false)
        - cve_id: Filter by CVE ID
        - search: Text search in title and description
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        page, per_page = validate_pagination_params(page, per_page)
        
        # Build base query with asset filtering based on user role
        query = Vulnerability.query.join(AiAsset)
        
        user = request.current_user
        if user.role not in ['admin', 'ciso']:
            # Filter based on asset access
            query = query.filter(
                or_(
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department,
                    Vulnerability.assigned_to == user.id
                )
            )
        
        # Apply filters
        filters = {
            'severity': request.args.get('severity'),
            'status': request.args.get('status'),
            'asset_id': request.args.get('asset_id', type=int),
            'assigned_to': request.args.get('assigned_to', type=int),
            'cve_id': request.args.get('cve_id')
        }
        
        query = apply_filters(query, Vulnerability, filters)
        
        # Filter overdue vulnerabilities
        if request.args.get('overdue') == 'true':
            # Add logic for overdue filtering based on SLA
            now = datetime.now(timezone.utc)
            query = query.filter(
                and_(
                    Vulnerability.status.in_(['open', 'in_progress']),
                    or_(
                        and_(
                            Vulnerability.due_date.isnot(None),
                            Vulnerability.due_date < now
                        ),
                        and_(
                            Vulnerability.due_date.is_(None),
                            # Calculate overdue based on creation date and severity
                            func.extract('epoch', now - Vulnerability.created_at) / 86400 > 
                            func.case(
                                (Vulnerability.severity == 'critical', 1),
                                (Vulnerability.severity == 'high', 7),
                                (Vulnerability.severity == 'medium', 30),
                                else_=90
                            )
                        )
                    )
                )
            )
        
        # Apply text search
        search_term = request.args.get('search')
        if search_term:
            query = query.filter(
                or_(
                    Vulnerability.title.ilike(f'%{search_term}%'),
                    Vulnerability.description.ilike(f'%{search_term}%'),
                    Vulnerability.cve_id.ilike(f'%{search_term}%')
                )
            )
        
        # Apply sorting
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc').lower()
        
        if hasattr(Vulnerability, sort_by):
            sort_field = getattr(Vulnerability, sort_by)
            if sort_order == 'asc':
                query = query.order_by(asc(sort_field))
            else:
                query = query.order_by(desc(sort_field))
        
        # Paginate results
        result = paginate_query(query, page, per_page)
        
        # Add vulnerability statistics
        result['statistics'] = get_vulnerability_statistics()
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {str(e)}")
        return jsonify({'error': 'Failed to fetch vulnerabilities'}), 500


@api_bp.route('/vulnerabilities/stats', methods=['GET'])
@login_required
def get_vulnerability_statistics():
    """
    Get comprehensive vulnerability statistics and metrics.
    """
    try:
        # Build base query with user access filtering
        base_query = Vulnerability.query.join(AiAsset)
        
        user = request.current_user
        if user.role not in ['admin', 'ciso']:
            base_query = base_query.filter(
                or_(
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department,
                    Vulnerability.assigned_to == user.id
                )
            )
        
        # Get severity distribution
        severity_stats = db.session.query(
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).join(AiAsset).filter(
            Vulnerability.status.in_(['open', 'in_progress'])
        ).group_by(Vulnerability.severity).all()
        
        # Get status distribution
        status_stats = db.session.query(
            Vulnerability.status,
            func.count(Vulnerability.id)
        ).join(AiAsset).group_by(Vulnerability.status).all()
        
        # Calculate overdue vulnerabilities
        now = datetime.now(timezone.utc)
        overdue_count = base_query.filter(
            and_(
                Vulnerability.status.in_(['open', 'in_progress']),
                or_(
                    and_(
                        Vulnerability.due_date.isnot(None),
                        Vulnerability.due_date < now
                    ),
                    and_(
                        Vulnerability.due_date.is_(None),
                        func.extract('epoch', now - Vulnerability.created_at) / 86400 > 
                        func.case(
                            (Vulnerability.severity == 'critical', 1),
                            (Vulnerability.severity == 'high', 7),
                            (Vulnerability.severity == 'medium', 30),
                            else_=90
                        )
                    )
                )
            )
        ).count()
        
        # Get trend data (last 30 days)
        thirty_days_ago = now - timedelta(days=30)
        daily_trend = db.session.query(
            func.date(Vulnerability.created_at).label('date'),
            func.count(Vulnerability.id).label('count')
        ).join(AiAsset).filter(
            Vulnerability.created_at >= thirty_days_ago
        ).group_by(func.date(Vulnerability.created_at)).all()
        
        return jsonify({
            'severity_distribution': dict(severity_stats),
            'status_distribution': dict(status_stats),
            'overdue_count': overdue_count,
            'total_open': base_query.filter(Vulnerability.status == 'open').count(),
            'total_in_progress': base_query.filter(Vulnerability.status == 'in_progress').count(),
            'total_resolved': base_query.filter(Vulnerability.status == 'resolved').count(),
            'daily_trend': [{'date': str(date), 'count': count} for date, count in daily_trend]
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching vulnerability statistics: {str(e)}")
        return jsonify({'error': 'Failed to fetch vulnerability statistics'}), 500


@api_bp.route('/vulnerabilities', methods=['POST'])
@login_required
@role_required(['admin', 'ciso', 'analyst', 'engineer'])
def create_vulnerability():
    """
    Create a new vulnerability with automatic SLA calculation.
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'description', 'severity', 'asset_id']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400
        
        # Validate asset exists and user has access
        asset = AiAsset.query.get_or_404(data['asset_id'])
        if not request.current_user.can_access_asset(asset):
            return jsonify({'error': 'Access denied to asset'}), 403
        
        # Validate severity
        valid_severities = ['critical', 'high', 'medium', 'low', 'informational']
        if data['severity'] not in valid_severities:
            return jsonify({
                'error': 'Invalid severity',
                'valid_values': valid_severities
            }), 400
        
        # Create vulnerability
        vulnerability = Vulnerability(
            title=data['title'].strip(),
            description=data['description'].strip(),
            severity=data['severity'],
            asset_id=data['asset_id'],
            assigned_to=data.get('assigned_to'),
            reporter_id=request.current_user.id,
            cve_id=data.get('cve_id', '').strip(),
            cvss_score=data.get('cvss_score'),
            cwe_id=data.get('cwe_id', '').strip(),
            affected_component=data.get('affected_component', '').strip(),
            affected_version=data.get('affected_version', '').strip(),
            vector=data.get('vector'),
            remediation_effort=data.get('remediation_effort'),
            remediation_priority=data.get('remediation_priority'),
            discovery_method=data.get('discovery_method', 'manual'),
            external_references=data.get('external_references', []),
            tags=data.get('tags', [])
        )
        
        # Calculate due date based on severity SLA
        sla_days = vulnerability.calculate_sla_days()
        vulnerability.due_date = vulnerability.first_discovered + timedelta(days=sla_days)
        
        db.session.add(vulnerability)
        db.session.commit()
        
        # Update asset risk assessment
        asset.update_risk_assessment()
        db.session.commit()
        
        # Log vulnerability creation
        log_audit_event(
            request.current_user.id,
            'vulnerability_create',
            'vulnerability',
            str(vulnerability.id),
            success=True,
            details={
                'title': vulnerability.title,
                'severity': vulnerability.severity,
                'asset_id': vulnerability.asset_id
            }
        )
        
        logger.info(f"Vulnerability created: {vulnerability.title} by {request.current_user.username}")
        
        return jsonify({
            'message': 'Vulnerability created successfully',
            'vulnerability': vulnerability.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Vulnerability creation error: {str(e)}")
        return jsonify({'error': 'Failed to create vulnerability'}), 500


# =============================================================================
# Security Alert Management Endpoints
# =============================================================================

@api_bp.route('/security-alerts', methods=['GET'])
@login_required
def get_security_alerts():
    """
    Get paginated list of security alerts with filtering.
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        page, per_page = validate_pagination_params(page, per_page)
        
        # Build base query
        query = SecurityAlert.query
        
        # Apply role-based filtering if needed
        user = request.current_user
        if user.role not in ['admin', 'ciso']:
            # Filter based on assignment or asset ownership
            query = query.outerjoin(AiAsset).filter(
                or_(
                    SecurityAlert.assigned_to == user.id,
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department
                )
            )
        
        # Apply filters
        filters = {
            'severity': request.args.get('severity'),
            'alert_type': request.args.get('alert_type'),
            'status': request.args.get('status'),
            'asset_id': request.args.get('asset_id', type=int),
            'assigned_to': request.args.get('assigned_to', type=int)
        }
        
        query = apply_filters(query, SecurityAlert, filters)
        
        # Apply text search
        search_term = request.args.get('search')
        if search_term:
            query = query.filter(
                or_(
                    SecurityAlert.title.ilike(f'%{search_term}%'),
                    SecurityAlert.description.ilike(f'%{search_term}%')
                )
            )
        
        # Apply sorting
        sort_by = request.args.get('sort_by', 'event_timestamp')
        sort_order = request.args.get('sort_order', 'desc').lower()
        
        if hasattr(SecurityAlert, sort_by):
            sort_field = getattr(SecurityAlert, sort_by)
            if sort_order == 'asc':
                query = query.order_by(asc(sort_field))
            else:
                query = query.order_by(desc(sort_field))
        
        # Paginate results
        result = paginate_query(query, page, per_page)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error fetching security alerts: {str(e)}")
        return jsonify({'error': 'Failed to fetch security alerts'}), 500


@api_bp.route('/security-alerts/recent', methods=['GET'])
@login_required
def get_recent_security_alerts():
    """
    Get recent security alerts for dashboard display.
    """
    try:
        limit = request.args.get('limit', 10, type=int)
        limit = min(limit, 50)  # Cap at 50
        
        # Build query with role-based filtering
        query = SecurityAlert.query
        
        user = request.current_user
        if user.role not in ['admin', 'ciso']:
            query = query.outerjoin(AiAsset).filter(
                or_(
                    SecurityAlert.assigned_to == user.id,
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department
                )
            )
        
        alerts = query.order_by(desc(SecurityAlert.event_timestamp)).limit(limit).all()
        
        return jsonify([alert.to_dict() for alert in alerts]), 200
        
    except Exception as e:
        logger.error(f"Error fetching recent alerts: {str(e)}")
        return jsonify({'error': 'Failed to fetch recent alerts'}), 500


# =============================================================================
# Dashboard and Analytics Endpoints
# =============================================================================

@api_bp.route('/dashboard/metrics', methods=['GET'])
@login_required
def get_dashboard_metrics():
    """
    Get comprehensive dashboard metrics and key performance indicators.
    """
    try:
        user = request.current_user
        
        # Build base queries with role-based filtering
        if user.role in ['admin', 'ciso']:
            # Admin users see all data
            asset_query = AiAsset.query
            vuln_query = Vulnerability.query
            alert_query = SecurityAlert.query
        else:
            # Regular users see filtered data
            asset_query = AiAsset.query.filter(
                or_(
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department
                )
            )
            vuln_query = Vulnerability.query.join(AiAsset).filter(
                or_(
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department,
                    Vulnerability.assigned_to == user.id
                )
            )
            alert_query = SecurityAlert.query.outerjoin(AiAsset).filter(
                or_(
                    SecurityAlert.assigned_to == user.id,
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department
                )
            )
        
        # Calculate key metrics
        total_assets = asset_query.count()
        
        # Asset distribution by environment
        asset_env_dist = db.session.query(
            AiAsset.environment,
            func.count(AiAsset.id)
        ).group_by(AiAsset.environment).all()
        
        # Vulnerability metrics
        critical_vulns = vuln_query.filter(
            and_(
                Vulnerability.severity == 'critical',
                Vulnerability.status.in_(['open', 'in_progress'])
            )
        ).count()
        
        total_vulns = vuln_query.filter(
            Vulnerability.status.in_(['open', 'in_progress'])
        ).count()
        
        # Security alert metrics
        active_alerts = alert_query.filter(
            SecurityAlert.status.in_(['open', 'investigating'])
        ).count()
        
        critical_alerts = alert_query.filter(
            and_(
                SecurityAlert.severity == 'critical',
                SecurityAlert.status.in_(['open', 'investigating'])
            )
        ).count()
        
        # Compliance score calculation
        compliance_assessments = ComplianceAssessment.query.filter(
            ComplianceAssessment.status == 'completed'
        ).all()
        
        avg_compliance_score = 0
        if compliance_assessments:
            total_score = sum(assessment.overall_score or 0 for assessment in compliance_assessments)
            avg_compliance_score = total_score / len(compliance_assessments)
        
        # Risk distribution
        risk_distribution = db.session.query(
            AiAsset.risk_level,
            func.count(AiAsset.id)
        ).group_by(AiAsset.risk_level).all()
        
        # Recent activity (last 7 days)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        
        recent_vulnerabilities = vuln_query.filter(
            Vulnerability.created_at >= seven_days_ago
        ).count()
        
        recent_alerts = alert_query.filter(
            SecurityAlert.event_timestamp >= seven_days_ago
        ).count()
        
        return jsonify({
            'total_assets': total_assets,
            'critical_vulnerabilities': critical_vulns,
            'total_vulnerabilities': total_vulns,
            'active_alerts': active_alerts,
            'critical_alerts': critical_alerts,
            'compliance_score': round(avg_compliance_score, 1),
            'asset_distribution': {
                'by_environment': dict(asset_env_dist),
                'by_risk_level': dict(risk_distribution)
            },
            'recent_activity': {
                'new_vulnerabilities': recent_vulnerabilities,
                'new_alerts': recent_alerts,
                'period_days': 7
            },
            'trends': {
                'vulnerability_trend': 'stable',  # Can be enhanced with actual trend calculation
                'alert_trend': 'stable',
                'compliance_trend': 'improving'
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching dashboard metrics: {str(e)}")
        return jsonify({'error': 'Failed to fetch dashboard metrics'}), 500


# =============================================================================
# Compliance Management Endpoints
# =============================================================================

@api_bp.route('/compliance/frameworks', methods=['GET'])
@login_required
def get_compliance_frameworks():
    """
    Get list of available compliance frameworks.
    """
    try:
        frameworks = ComplianceFramework.query.filter_by(is_active=True).all()
        
        return jsonify([framework.to_dict() for framework in frameworks]), 200
        
    except Exception as e:
        logger.error(f"Error fetching compliance frameworks: {str(e)}")
        return jsonify({'error': 'Failed to fetch compliance frameworks'}), 500


@api_bp.route('/compliance/overview', methods=['GET'])
@login_required
def get_compliance_overview():
    """
    Get compliance overview with assessment summaries.
    """
    try:
        user = request.current_user
        
        # Build base query with role-based filtering
        query = ComplianceAssessment.query.join(AiAsset)
        
        if user.role not in ['admin', 'ciso', 'compliance_officer']:
            query = query.filter(
                or_(
                    AiAsset.owner_id == user.id,
                    AiAsset.department == user.department
                )
            )
        
        # Get framework summaries
        framework_summaries = db.session.query(
            ComplianceFramework.id,
            ComplianceFramework.name,
            func.count(ComplianceAssessment.id).label('total_assessments'),
            func.avg(ComplianceAssessment.overall_score).label('avg_score')
        ).join(ComplianceAssessment).join(AiAsset).group_by(
            ComplianceFramework.id, ComplianceFramework.name
        ).all()
        
        # Get recent assessments
        recent_assessments = query.order_by(
            desc(ComplianceAssessment.assessment_date)
        ).limit(10).all()
        
        return jsonify({
            'framework_summaries': [
                {
                    'framework_id': framework_id,
                    'framework_name': framework_name,
                    'total_assessments': total_assessments,
                    'average_score': round(avg_score or 0, 1)
                }
                for framework_id, framework_name, total_assessments, avg_score in framework_summaries
            ],
            'recent_assessments': [assessment.to_dict() for assessment in recent_assessments]
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching compliance overview: {str(e)}")
        return jsonify({'error': 'Failed to fetch compliance overview'}), 500


# =============================================================================
# Audit Log Endpoints
# =============================================================================

@api_bp.route('/audit-logs', methods=['GET'])
@login_required
@role_required(['admin', 'ciso', 'auditor'])
def get_audit_logs():
    """
    Get paginated audit logs with filtering (admin/auditor only).
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        page, per_page = validate_pagination_params(page, per_page)
        
        # Build query
        query = AuditLog.query
        
        # Apply filters
        filters = {
            'user_id': request.args.get('user_id', type=int),
            'action': request.args.get('action'),
            'resource_type': request.args.get('resource_type'),
            'success': request.args.get('success', type=bool),
            'risk_level': request.args.get('risk_level')
        }
        
        query = apply_filters(query, AuditLog, filters)
        
        # Date range filtering
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                query = query.filter(AuditLog.event_timestamp >= start_dt)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                query = query.filter(AuditLog.event_timestamp <= end_dt)
            except ValueError:
                pass
        
        # Apply sorting
        query = query.order_by(desc(AuditLog.event_timestamp))
        
        # Paginate results
        result = paginate_query(query, page, per_page)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error fetching audit logs: {str(e)}")
        return jsonify({'error': 'Failed to fetch audit logs'}), 500


# =============================================================================
# Error Handlers
# =============================================================================

@api_bp.errorhandler(ValidationError)
def handle_validation_error(error):
    """Handle custom validation errors"""
    return jsonify({'error': str(error)}), 400


@api_bp.errorhandler(404)
def handle_not_found(error):
    """Handle resource not found errors"""
    return jsonify({'error': 'Resource not found'}), 404


@api_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors"""
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500