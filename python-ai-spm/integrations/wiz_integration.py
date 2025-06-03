"""
AI Security Posture Management Platform - Wiz Integration Module
===============================================================

This module provides comprehensive integration with Wiz cloud security platform
for importing security data including assets, vulnerabilities, and alerts.

The integration supports:
- OAuth2 authentication with Wiz API
- Asset discovery and import from cloud environments
- Vulnerability synchronization with risk assessment
- Security alert ingestion and mapping
- Configurable sync filters and transformations
- Error handling and retry mechanisms

Author: AI-SPM Development Team
Version: 1.0.0
"""

import os
import logging
import requests
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import time

from models import db, AiAsset, Vulnerability, SecurityAlert
from auth import log_audit_event

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class WizAsset:
    """Data class representing a Wiz cloud asset"""
    id: str
    name: str
    type: str
    cloud_platform: str
    subscription_id: str
    resource_group: Optional[str]
    region: str
    tags: Dict[str, str]
    status: str
    risk_factors: List[str]
    last_scan_time: str


@dataclass
class WizVulnerability:
    """Data class representing a Wiz vulnerability finding"""
    id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    status: str    # OPEN, IN_PROGRESS, RESOLVED, RISK_ACCEPTED
    first_detected: str
    last_detected: str
    affected_assets: List[str]
    cve: Optional[str]
    cvss_score: Optional[float]
    remediation: Optional[str]


@dataclass
class WizSecurityAlert:
    """Data class representing a Wiz security alert"""
    id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str    # OPEN, IN_PROGRESS, RESOLVED
    created_at: str
    updated_at: str
    affected_resources: List[str]
    detection_method: str


class WizAuthenticationError(Exception):
    """Exception raised for Wiz authentication failures"""
    pass


class WizAPIError(Exception):
    """Exception raised for Wiz API errors"""
    pass


class WizClient:
    """
    Wiz API client for interacting with Wiz cloud security platform.
    
    This client handles OAuth2 authentication, GraphQL queries, and data retrieval
    from the Wiz platform with proper error handling and rate limiting.
    """
    
    def __init__(self, client_id: str, client_secret: str, 
                 auth_url: str = "https://auth.app.wiz.io/oauth/token",
                 api_url: str = "https://api.us1.app.wiz.io/graphql",
                 audience: str = "wiz-api"):
        """
        Initialize Wiz API client with credentials.
        
        Args:
            client_id: Wiz OAuth2 client ID
            client_secret: Wiz OAuth2 client secret
            auth_url: Wiz authentication endpoint URL
            api_url: Wiz GraphQL API endpoint URL
            audience: OAuth2 audience parameter
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = auth_url
        self.api_url = api_url
        self.audience = audience
        
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        
        # Session for connection pooling and better performance
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'AI-SPM-Platform/1.0'
        })
        
        logger.info("Wiz client initialized")
    
    def _authenticate(self) -> str:
        """
        Authenticate with Wiz API using OAuth2 client credentials flow.
        
        Returns:
            Access token for API requests
            
        Raises:
            WizAuthenticationError: If authentication fails
        """
        try:
            auth_payload = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": self.audience
            }
            
            logger.debug("Authenticating with Wiz API")
            
            response = self.session.post(
                self.auth_url,
                json=auth_payload,
                timeout=30
            )
            
            if response.status_code != 200:
                error_msg = f"Wiz authentication failed with status {response.status_code}"
                logger.error(f"{error_msg}: {response.text}")
                raise WizAuthenticationError(error_msg)
            
            auth_data = response.json()
            
            # Extract token information
            access_token = auth_data.get('access_token')
            expires_in = auth_data.get('expires_in', 3600)  # Default 1 hour
            
            if not access_token:
                raise WizAuthenticationError("No access token received from Wiz")
            
            # Calculate token expiry with 5-minute buffer
            self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 300)
            
            logger.info("Successfully authenticated with Wiz API")
            return access_token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during Wiz authentication: {str(e)}")
            raise WizAuthenticationError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during Wiz authentication: {str(e)}")
            raise WizAuthenticationError(f"Authentication error: {str(e)}")
    
    def _get_access_token(self) -> str:
        """
        Get valid access token, refreshing if necessary.
        
        Returns:
            Valid access token for API requests
        """
        # Check if token exists and is still valid
        if (self.access_token and self.token_expiry and 
            datetime.now(timezone.utc) < self.token_expiry):
            return self.access_token
        
        # Token expired or doesn't exist, authenticate
        self.access_token = self._authenticate()
        return self.access_token
    
    def _execute_query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute GraphQL query against Wiz API.
        
        Args:
            query: GraphQL query string
            variables: Query variables (optional)
            
        Returns:
            GraphQL response data
            
        Raises:
            WizAPIError: If API request fails
        """
        try:
            access_token = self._get_access_token()
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'query': query,
                'variables': variables or {}
            }
            
            logger.debug(f"Executing Wiz GraphQL query")
            
            response = self.session.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=60
            )
            
            if response.status_code != 200:
                error_msg = f"Wiz API request failed with status {response.status_code}"
                logger.error(f"{error_msg}: {response.text}")
                raise WizAPIError(error_msg)
            
            data = response.json()
            
            # Check for GraphQL errors
            if 'errors' in data:
                error_msg = f"GraphQL errors: {data['errors']}"
                logger.error(error_msg)
                raise WizAPIError(error_msg)
            
            return data.get('data', {})
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during Wiz API request: {str(e)}")
            raise WizAPIError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during Wiz API request: {str(e)}")
            raise WizAPIError(f"API error: {str(e)}")
    
    def fetch_assets(self, filters: Optional[Dict[str, Any]] = None) -> List[WizAsset]:
        """
        Fetch cloud assets from Wiz platform.
        
        Args:
            filters: Optional filters for asset query
                - cloud_platform: AWS, Azure, GCP
                - subscription_id: Cloud subscription ID
                - resource_group: Resource group name
                - limit: Maximum number of assets to fetch
                
        Returns:
            List of WizAsset objects
        """
        try:
            # Build GraphQL query for assets
            query = """
            query GetAssets($first: Int, $after: String, $where: CloudResourceWhereInput) {
                cloudResources(first: $first, after: $after, where: $where) {
                    edges {
                        node {
                            id
                            name
                            type
                            cloudPlatform
                            subscriptionId
                            resourceGroup
                            region
                            tags
                            status
                            riskFactors
                            lastScanTime
                        }
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
            """
            
            # Build query variables
            variables = {
                'first': filters.get('limit', 100) if filters else 100,
                'where': {}
            }
            
            if filters:
                if 'cloud_platform' in filters:
                    variables['where']['cloudPlatform'] = {'equals': filters['cloud_platform']}
                if 'subscription_id' in filters:
                    variables['where']['subscriptionId'] = {'equals': filters['subscription_id']}
                if 'resource_group' in filters:
                    variables['where']['resourceGroup'] = {'equals': filters['resource_group']}
            
            logger.info(f"Fetching assets from Wiz with filters: {filters}")
            
            # Execute query
            data = self._execute_query(query, variables)
            
            # Parse response
            assets = []
            cloud_resources = data.get('cloudResources', {})
            edges = cloud_resources.get('edges', [])
            
            for edge in edges:
                node = edge.get('node', {})
                
                asset = WizAsset(
                    id=node.get('id', ''),
                    name=node.get('name', ''),
                    type=node.get('type', ''),
                    cloud_platform=node.get('cloudPlatform', ''),
                    subscription_id=node.get('subscriptionId', ''),
                    resource_group=node.get('resourceGroup'),
                    region=node.get('region', ''),
                    tags=node.get('tags', {}),
                    status=node.get('status', ''),
                    risk_factors=node.get('riskFactors', []),
                    last_scan_time=node.get('lastScanTime', '')
                )
                
                assets.append(asset)
            
            logger.info(f"Successfully fetched {len(assets)} assets from Wiz")
            return assets
            
        except Exception as e:
            logger.error(f"Error fetching assets from Wiz: {str(e)}")
            raise WizAPIError(f"Failed to fetch assets: {str(e)}")
    
    def fetch_vulnerabilities(self, filters: Optional[Dict[str, Any]] = None) -> List[WizVulnerability]:
        """
        Fetch vulnerabilities from Wiz platform.
        
        Args:
            filters: Optional filters for vulnerability query
                - severity: List of severity levels
                - status: List of status values
                - limit: Maximum number of vulnerabilities to fetch
                
        Returns:
            List of WizVulnerability objects
        """
        try:
            query = """
            query GetVulnerabilities($first: Int, $after: String, $where: VulnerabilityWhereInput) {
                vulnerabilities(first: $first, after: $after, where: $where) {
                    edges {
                        node {
                            id
                            name
                            description
                            severity
                            status
                            firstDetected
                            lastDetected
                            affectedAssets {
                                id
                            }
                            cve
                            cvssScore
                            remediation
                        }
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
            """
            
            variables = {
                'first': filters.get('limit', 100) if filters else 100,
                'where': {}
            }
            
            if filters:
                if 'severity' in filters:
                    variables['where']['severity'] = {'in': filters['severity']}
                if 'status' in filters:
                    variables['where']['status'] = {'in': filters['status']}
            
            logger.info(f"Fetching vulnerabilities from Wiz with filters: {filters}")
            
            data = self._execute_query(query, variables)
            
            vulnerabilities = []
            vuln_data = data.get('vulnerabilities', {})
            edges = vuln_data.get('edges', [])
            
            for edge in edges:
                node = edge.get('node', {})
                
                vuln = WizVulnerability(
                    id=node.get('id', ''),
                    name=node.get('name', ''),
                    description=node.get('description', ''),
                    severity=node.get('severity', ''),
                    status=node.get('status', ''),
                    first_detected=node.get('firstDetected', ''),
                    last_detected=node.get('lastDetected', ''),
                    affected_assets=[asset.get('id', '') for asset in node.get('affectedAssets', [])],
                    cve=node.get('cve'),
                    cvss_score=node.get('cvssScore'),
                    remediation=node.get('remediation')
                )
                
                vulnerabilities.append(vuln)
            
            logger.info(f"Successfully fetched {len(vulnerabilities)} vulnerabilities from Wiz")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities from Wiz: {str(e)}")
            raise WizAPIError(f"Failed to fetch vulnerabilities: {str(e)}")
    
    def fetch_security_alerts(self, filters: Optional[Dict[str, Any]] = None) -> List[WizSecurityAlert]:
        """
        Fetch security alerts from Wiz platform.
        
        Args:
            filters: Optional filters for alert query
                - severity: List of severity levels
                - status: List of status values
                - limit: Maximum number of alerts to fetch
                
        Returns:
            List of WizSecurityAlert objects
        """
        try:
            query = """
            query GetSecurityAlerts($first: Int, $after: String, $where: SecurityAlertWhereInput) {
                securityAlerts(first: $first, after: $after, where: $where) {
                    edges {
                        node {
                            id
                            title
                            description
                            severity
                            status
                            createdAt
                            updatedAt
                            affectedResources {
                                id
                            }
                            detectionMethod
                        }
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
            """
            
            variables = {
                'first': filters.get('limit', 50) if filters else 50,
                'where': {}
            }
            
            if filters:
                if 'severity' in filters:
                    variables['where']['severity'] = {'in': filters['severity']}
                if 'status' in filters:
                    variables['where']['status'] = {'in': filters['status']}
            
            logger.info(f"Fetching security alerts from Wiz with filters: {filters}")
            
            data = self._execute_query(query, variables)
            
            alerts = []
            alert_data = data.get('securityAlerts', {})
            edges = alert_data.get('edges', [])
            
            for edge in edges:
                node = edge.get('node', {})
                
                alert = WizSecurityAlert(
                    id=node.get('id', ''),
                    title=node.get('title', ''),
                    description=node.get('description', ''),
                    severity=node.get('severity', ''),
                    status=node.get('status', ''),
                    created_at=node.get('createdAt', ''),
                    updated_at=node.get('updatedAt', ''),
                    affected_resources=[res.get('id', '') for res in node.get('affectedResources', [])],
                    detection_method=node.get('detectionMethod', '')
                )
                
                alerts.append(alert)
            
            logger.info(f"Successfully fetched {len(alerts)} security alerts from Wiz")
            return alerts
            
        except Exception as e:
            logger.error(f"Error fetching security alerts from Wiz: {str(e)}")
            raise WizAPIError(f"Failed to fetch security alerts: {str(e)}")


class WizDataSyncService:
    """
    Service for synchronizing data from Wiz platform to AI-SPM database.
    
    This service handles the transformation and import of Wiz data into the
    AI-SPM data model with proper error handling and conflict resolution.
    """
    
    def __init__(self, wiz_client: WizClient):
        """
        Initialize sync service with Wiz client.
        
        Args:
            wiz_client: Configured WizClient instance
        """
        self.wiz_client = wiz_client
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def _transform_wiz_asset(self, wiz_asset: WizAsset, owner_id: int = 1) -> AiAsset:
        """
        Transform Wiz asset to AI-SPM asset format.
        
        Args:
            wiz_asset: Wiz asset data
            owner_id: Default owner ID for imported assets
            
        Returns:
            AiAsset object ready for database insertion
        """
        # Map Wiz asset types to AI-SPM asset types
        type_mapping = {
            'MachineLearningModel': 'model',
            'Dataset': 'dataset',
            'APIGateway': 'api',
            'Pipeline': 'pipeline',
            'Container': 'model',  # Default for containers
            'Function': 'api',     # Default for functions
            'Database': 'dataset', # Default for databases
        }
        
        # Map Wiz risk factors to risk levels
        risk_level = 'low'
        if any(factor in ['CRITICAL_VULNERABILITY', 'HIGH_EXPOSURE'] for factor in wiz_asset.risk_factors):
            risk_level = 'critical'
        elif any(factor in ['HIGH_VULNERABILITY', 'MEDIUM_EXPOSURE'] for factor in wiz_asset.risk_factors):
            risk_level = 'high'
        elif any(factor in ['MEDIUM_VULNERABILITY', 'LOW_EXPOSURE'] for factor in wiz_asset.risk_factors):
            risk_level = 'medium'
        
        # Map status
        environment = 'development'
        if wiz_asset.status == 'RUNNING':
            environment = 'production'
        elif wiz_asset.status in ['STOPPED', 'TERMINATED']:
            environment = 'development'
        
        # Parse last scan time
        last_scanned_at = None
        if wiz_asset.last_scan_time:
            try:
                last_scanned_at = datetime.fromisoformat(
                    wiz_asset.last_scan_time.replace('Z', '+00:00')
                )
            except ValueError:
                pass
        
        return AiAsset(
            name=wiz_asset.name or f"Wiz-Asset-{wiz_asset.id}",
            description=f"Asset imported from Wiz (Type: {wiz_asset.type})",
            asset_type=type_mapping.get(wiz_asset.type, 'infrastructure'),
            environment=environment,
            status='active' if wiz_asset.status == 'RUNNING' else 'inactive',
            owner_id=owner_id,
            department='Security',  # Default department for imported assets
            cloud_provider=wiz_asset.cloud_platform,
            region=wiz_asset.region,
            risk_level=risk_level,
            metadata={
                'wiz_id': wiz_asset.id,
                'subscription_id': wiz_asset.subscription_id,
                'resource_group': wiz_asset.resource_group,
                'risk_factors': wiz_asset.risk_factors,
                'import_source': 'wiz'
            },
            tags=list(wiz_asset.tags.keys()) if wiz_asset.tags else [],
            external_id=wiz_asset.id,
            external_source='wiz',
            last_scanned_at=last_scanned_at
        )
    
    def _transform_wiz_vulnerability(self, wiz_vuln: WizVulnerability, asset_id: Optional[int] = None) -> Vulnerability:
        """
        Transform Wiz vulnerability to AI-SPM vulnerability format.
        
        Args:
            wiz_vuln: Wiz vulnerability data
            asset_id: Associated asset ID (optional)
            
        Returns:
            Vulnerability object ready for database insertion
        """
        # Map Wiz severity to AI-SPM severity
        severity_mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFORMATIONAL': 'informational'
        }
        
        # Map Wiz status to AI-SPM status
        status_mapping = {
            'OPEN': 'open',
            'IN_PROGRESS': 'in_progress',
            'RESOLVED': 'resolved',
            'RISK_ACCEPTED': 'risk_accepted'
        }
        
        # Parse dates
        first_discovered = None
        last_detected = None
        
        if wiz_vuln.first_detected:
            try:
                first_discovered = datetime.fromisoformat(
                    wiz_vuln.first_detected.replace('Z', '+00:00')
                )
            except ValueError:
                pass
        
        if wiz_vuln.last_detected:
            try:
                last_detected = datetime.fromisoformat(
                    wiz_vuln.last_detected.replace('Z', '+00:00')
                )
            except ValueError:
                pass
        
        return Vulnerability(
            title=wiz_vuln.name or f"Wiz-Vulnerability-{wiz_vuln.id}",
            description=wiz_vuln.description or "Vulnerability imported from Wiz",
            severity=severity_mapping.get(wiz_vuln.severity, 'medium'),
            status=status_mapping.get(wiz_vuln.status, 'open'),
            asset_id=asset_id,
            cve_id=wiz_vuln.cve,
            cvss_score=wiz_vuln.cvss_score,
            remediation_notes=wiz_vuln.remediation,
            discovery_method='wiz_import',
            external_id=wiz_vuln.id,
            external_source='wiz',
            first_discovered=first_discovered or datetime.now(timezone.utc),
            last_detected=last_detected or datetime.now(timezone.utc),
            tags=['wiz-imported']
        )
    
    def _transform_wiz_security_alert(self, wiz_alert: WizSecurityAlert) -> SecurityAlert:
        """
        Transform Wiz security alert to AI-SPM security alert format.
        
        Args:
            wiz_alert: Wiz security alert data
            
        Returns:
            SecurityAlert object ready for database insertion
        """
        # Map Wiz severity to AI-SPM severity
        severity_mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        
        # Map Wiz status to AI-SPM status
        status_mapping = {
            'OPEN': 'open',
            'IN_PROGRESS': 'investigating',
            'RESOLVED': 'resolved'
        }
        
        # Parse timestamps
        event_timestamp = None
        if wiz_alert.created_at:
            try:
                event_timestamp = datetime.fromisoformat(
                    wiz_alert.created_at.replace('Z', '+00:00')
                )
            except ValueError:
                pass
        
        return SecurityAlert(
            title=wiz_alert.title or f"Wiz-Alert-{wiz_alert.id}",
            description=wiz_alert.description or "Security alert imported from Wiz",
            severity=severity_mapping.get(wiz_alert.severity, 'medium'),
            alert_type='vulnerability',  # Default type for Wiz alerts
            status=status_mapping.get(wiz_alert.status, 'open'),
            source_system='wiz',
            event_timestamp=event_timestamp or datetime.now(timezone.utc),
            affected_systems=wiz_alert.affected_resources,
            external_id=wiz_alert.id,
            external_source='wiz',
            metadata={
                'detection_method': wiz_alert.detection_method,
                'import_source': 'wiz'
            },
            tags=['wiz-imported']
        )
    
    def sync_assets(self, filters: Optional[Dict[str, Any]] = None, owner_id: int = 1) -> Dict[str, Any]:
        """
        Sync assets from Wiz to AI-SPM platform.
        
        Args:
            filters: Optional filters for asset query
            owner_id: Default owner ID for imported assets
            
        Returns:
            Dictionary with sync results and statistics
        """
        try:
            self.logger.info("Starting asset sync from Wiz")
            
            # Fetch assets from Wiz
            wiz_assets = self.wiz_client.fetch_assets(filters)
            
            imported_count = 0
            updated_count = 0
            errors = []
            
            for wiz_asset in wiz_assets:
                try:
                    # Check if asset already exists
                    existing_asset = AiAsset.query.filter_by(
                        external_id=wiz_asset.id,
                        external_source='wiz'
                    ).first()
                    
                    if existing_asset:
                        # Update existing asset
                        existing_asset.name = wiz_asset.name or existing_asset.name
                        existing_asset.cloud_provider = wiz_asset.cloud_platform
                        existing_asset.region = wiz_asset.region
                        existing_asset.metadata.update({
                            'wiz_id': wiz_asset.id,
                            'risk_factors': wiz_asset.risk_factors,
                            'last_sync': datetime.now(timezone.utc).isoformat()
                        })
                        existing_asset.last_scanned_at = datetime.now(timezone.utc)
                        
                        # Recalculate risk assessment
                        existing_asset.update_risk_assessment()
                        
                        updated_count += 1
                        self.logger.debug(f"Updated existing asset: {existing_asset.name}")
                        
                    else:
                        # Create new asset
                        new_asset = self._transform_wiz_asset(wiz_asset, owner_id)
                        new_asset.update_risk_assessment()
                        
                        db.session.add(new_asset)
                        imported_count += 1
                        self.logger.debug(f"Imported new asset: {new_asset.name}")
                    
                    # Commit each asset individually to handle errors gracefully
                    db.session.commit()
                    
                except Exception as e:
                    db.session.rollback()
                    error_msg = f"Failed to sync asset {wiz_asset.id}: {str(e)}"
                    self.logger.error(error_msg)
                    errors.append(error_msg)
            
            result = {
                'imported': imported_count,
                'updated': updated_count,
                'errors': errors,
                'total_processed': len(wiz_assets)
            }
            
            self.logger.info(f"Asset sync completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Asset sync failed: {str(e)}")
            raise WizAPIError(f"Asset sync failed: {str(e)}")
    
    def sync_vulnerabilities(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Sync vulnerabilities from Wiz to AI-SPM platform.
        
        Args:
            filters: Optional filters for vulnerability query
            
        Returns:
            Dictionary with sync results and statistics
        """
        try:
            self.logger.info("Starting vulnerability sync from Wiz")
            
            # Fetch vulnerabilities from Wiz
            wiz_vulnerabilities = self.wiz_client.fetch_vulnerabilities(filters)
            
            imported_count = 0
            updated_count = 0
            errors = []
            
            for wiz_vuln in wiz_vulnerabilities:
                try:
                    # Try to find associated asset
                    asset_id = None
                    if wiz_vuln.affected_assets:
                        # Find first matching asset by external_id
                        for wiz_asset_id in wiz_vuln.affected_assets:
                            asset = AiAsset.query.filter_by(
                                external_id=wiz_asset_id,
                                external_source='wiz'
                            ).first()
                            if asset:
                                asset_id = asset.id
                                break
                    
                    # Check if vulnerability already exists
                    existing_vuln = Vulnerability.query.filter_by(
                        external_id=wiz_vuln.id,
                        external_source='wiz'
                    ).first()
                    
                    if existing_vuln:
                        # Update existing vulnerability
                        existing_vuln.title = wiz_vuln.name or existing_vuln.title
                        existing_vuln.description = wiz_vuln.description or existing_vuln.description
                        existing_vuln.last_detected = datetime.now(timezone.utc)
                        
                        # Update status and severity if changed
                        status_mapping = {
                            'OPEN': 'open',
                            'IN_PROGRESS': 'in_progress',
                            'RESOLVED': 'resolved',
                            'RISK_ACCEPTED': 'risk_accepted'
                        }
                        new_status = status_mapping.get(wiz_vuln.status, existing_vuln.status)
                        existing_vuln.status = new_status
                        
                        updated_count += 1
                        self.logger.debug(f"Updated existing vulnerability: {existing_vuln.title}")
                        
                    else:
                        # Create new vulnerability
                        new_vuln = self._transform_wiz_vulnerability(wiz_vuln, asset_id)
                        db.session.add(new_vuln)
                        imported_count += 1
                        self.logger.debug(f"Imported new vulnerability: {new_vuln.title}")
                    
                    # Commit each vulnerability individually
                    db.session.commit()
                    
                    # Update associated asset risk assessment
                    if asset_id:
                        asset = AiAsset.query.get(asset_id)
                        if asset:
                            asset.update_risk_assessment()
                            db.session.commit()
                    
                except Exception as e:
                    db.session.rollback()
                    error_msg = f"Failed to sync vulnerability {wiz_vuln.id}: {str(e)}"
                    self.logger.error(error_msg)
                    errors.append(error_msg)
            
            result = {
                'imported': imported_count,
                'updated': updated_count,
                'errors': errors,
                'total_processed': len(wiz_vulnerabilities)
            }
            
            self.logger.info(f"Vulnerability sync completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Vulnerability sync failed: {str(e)}")
            raise WizAPIError(f"Vulnerability sync failed: {str(e)}")
    
    def sync_security_alerts(self, filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Sync security alerts from Wiz to AI-SPM platform.
        
        Args:
            filters: Optional filters for alert query
            
        Returns:
            Dictionary with sync results and statistics
        """
        try:
            self.logger.info("Starting security alert sync from Wiz")
            
            # Fetch security alerts from Wiz
            wiz_alerts = self.wiz_client.fetch_security_alerts(filters)
            
            imported_count = 0
            updated_count = 0
            errors = []
            
            for wiz_alert in wiz_alerts:
                try:
                    # Try to find associated asset
                    asset_id = None
                    if wiz_alert.affected_resources:
                        # Find first matching asset by external_id
                        for wiz_resource_id in wiz_alert.affected_resources:
                            asset = AiAsset.query.filter_by(
                                external_id=wiz_resource_id,
                                external_source='wiz'
                            ).first()
                            if asset:
                                asset_id = asset.id
                                break
                    
                    # Check if alert already exists
                    existing_alert = SecurityAlert.query.filter_by(
                        external_id=wiz_alert.id,
                        external_source='wiz'
                    ).first()
                    
                    if existing_alert:
                        # Update existing alert
                        existing_alert.title = wiz_alert.title or existing_alert.title
                        existing_alert.description = wiz_alert.description or existing_alert.description
                        
                        # Update status if changed
                        status_mapping = {
                            'OPEN': 'open',
                            'IN_PROGRESS': 'investigating',
                            'RESOLVED': 'resolved'
                        }
                        new_status = status_mapping.get(wiz_alert.status, existing_alert.status)
                        existing_alert.status = new_status
                        
                        updated_count += 1
                        self.logger.debug(f"Updated existing alert: {existing_alert.title}")
                        
                    else:
                        # Create new alert
                        new_alert = self._transform_wiz_security_alert(wiz_alert)
                        new_alert.asset_id = asset_id
                        
                        db.session.add(new_alert)
                        imported_count += 1
                        self.logger.debug(f"Imported new alert: {new_alert.title}")
                    
                    # Commit each alert individually
                    db.session.commit()
                    
                except Exception as e:
                    db.session.rollback()
                    error_msg = f"Failed to sync alert {wiz_alert.id}: {str(e)}"
                    self.logger.error(error_msg)
                    errors.append(error_msg)
            
            result = {
                'imported': imported_count,
                'updated': updated_count,
                'errors': errors,
                'total_processed': len(wiz_alerts)
            }
            
            self.logger.info(f"Security alert sync completed: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Security alert sync failed: {str(e)}")
            raise WizAPIError(f"Security alert sync failed: {str(e)}")
    
    def full_sync(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform full synchronization of all data types from Wiz.
        
        Args:
            options: Optional configuration for sync operations
                - asset_filters: Filters for asset sync
                - vuln_filters: Filters for vulnerability sync
                - alert_filters: Filters for alert sync
                - owner_id: Default owner ID for imported assets
                
        Returns:
            Dictionary with comprehensive sync results
        """
        try:
            self.logger.info("Starting full sync from Wiz")
            
            options = options or {}
            owner_id = options.get('owner_id', 1)
            
            results = {
                'assets': {},
                'vulnerabilities': {},
                'alerts': {},
                'total_errors': 0,
                'sync_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Sync assets first (required for vulnerability and alert association)
            try:
                asset_filters = options.get('asset_filters', {})
                results['assets'] = self.sync_assets(asset_filters, owner_id)
            except Exception as e:
                self.logger.error(f"Asset sync failed during full sync: {str(e)}")
                results['assets'] = {'error': str(e)}
            
            # Sync vulnerabilities
            try:
                vuln_filters = options.get('vuln_filters', {})
                results['vulnerabilities'] = self.sync_vulnerabilities(vuln_filters)
            except Exception as e:
                self.logger.error(f"Vulnerability sync failed during full sync: {str(e)}")
                results['vulnerabilities'] = {'error': str(e)}
            
            # Sync security alerts
            try:
                alert_filters = options.get('alert_filters', {})
                results['alerts'] = self.sync_security_alerts(alert_filters)
            except Exception as e:
                self.logger.error(f"Alert sync failed during full sync: {str(e)}")
                results['alerts'] = {'error': str(e)}
            
            # Calculate total errors
            for data_type in ['assets', 'vulnerabilities', 'alerts']:
                if 'errors' in results[data_type]:
                    results['total_errors'] += len(results[data_type]['errors'])
            
            self.logger.info(f"Full sync completed: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Full sync failed: {str(e)}")
            raise WizAPIError(f"Full sync failed: {str(e)}")


def create_wiz_integration() -> Optional[WizDataSyncService]:
    """
    Factory function to create Wiz integration instance.
    
    Returns:
        WizDataSyncService instance if credentials are configured, None otherwise
    """
    try:
        client_id = os.getenv('WIZ_CLIENT_ID')
        client_secret = os.getenv('WIZ_CLIENT_SECRET')
        
        if not client_id or not client_secret:
            logger.warning("Wiz integration disabled: WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables required")
            return None
        
        # Get optional configuration
        auth_url = os.getenv('WIZ_AUTH_URL', 'https://auth.app.wiz.io/oauth/token')
        api_url = os.getenv('WIZ_API_URL', 'https://api.us1.app.wiz.io/graphql')
        audience = os.getenv('WIZ_AUDIENCE', 'wiz-api')
        
        # Create Wiz client
        wiz_client = WizClient(
            client_id=client_id,
            client_secret=client_secret,
            auth_url=auth_url,
            api_url=api_url,
            audience=audience
        )
        
        # Create sync service
        sync_service = WizDataSyncService(wiz_client)
        
        logger.info("Wiz integration initialized successfully")
        return sync_service
        
    except Exception as e:
        logger.error(f"Failed to initialize Wiz integration: {str(e)}")
        return None