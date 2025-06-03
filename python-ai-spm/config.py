"""
AI Security Posture Management Platform - Configuration Module
==============================================================

This module contains all configuration settings for the AI-SPM platform.
It includes database configurations, security settings, API configurations,
and integration settings for external services like Wiz.

The configuration uses environment variables for security-sensitive settings
and provides sensible defaults for development environments.

Author: AI-SPM Development Team
Version: 1.0.0
"""

import os
from datetime import timedelta


class Config:
    """
    Base configuration class containing all application settings.
    
    This class defines configuration variables that are used throughout
    the application. Settings are loaded from environment variables with
    fallback defaults for development environments.
    """
    
    # Flask Core Configuration
    # ========================
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database Configuration
    # =====================
    # Primary database URL - supports PostgreSQL, MySQL, SQLite
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://ai_spm_user:password@localhost:5432/ai_spm_db'
    
    # Disable SQLAlchemy event system for better performance
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Enable SQL query logging in development (set to False in production)
    SQLALCHEMY_ECHO = os.environ.get('FLASK_ENV') == 'development'
    
    # Database connection pool settings for high-traffic applications
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,        # Number of connections to maintain in pool
        'pool_timeout': 20,     # Timeout for getting connection from pool
        'pool_recycle': 3600,   # Recycle connections after 1 hour
        'max_overflow': 20      # Additional connections beyond pool_size
    }
    
    # Session Configuration
    # ====================
    # Session type - can be 'filesystem', 'redis', 'memcached', 'sqlalchemy'
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'ai_spm:'
    SESSION_FILE_DIR = './session_files'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Security Configuration
    # =====================
    # Password hashing configuration
    BCRYPT_LOG_ROUNDS = 12  # Higher values = more secure but slower
    
    # JWT configuration for API tokens
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # CORS configuration for frontend integration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')
    CORS_SUPPORTS_CREDENTIALS = True
    
    # API Rate Limiting
    # ================
    # Rate limiting settings to prevent abuse
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    RATELIMIT_DEFAULT = "1000 per hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # File Upload Configuration
    # ========================
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'json'}
    
    # Logging Configuration
    # ====================
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = os.environ.get('LOG_FILE', 'ai_spm.log')
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Email Configuration (for notifications and alerts)
    # =================================================
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@ai-spm.com'
    
    # Wiz Integration Configuration
    # ============================
    # Wiz cloud security platform integration settings
    WIZ_CLIENT_ID = os.environ.get('WIZ_CLIENT_ID')
    WIZ_CLIENT_SECRET = os.environ.get('WIZ_CLIENT_SECRET')
    WIZ_AUTH_URL = os.environ.get('WIZ_AUTH_URL', 'https://auth.app.wiz.io/oauth/token')
    WIZ_API_URL = os.environ.get('WIZ_API_URL', 'https://api.us1.app.wiz.io/graphql')
    WIZ_AUDIENCE = os.environ.get('WIZ_AUDIENCE', 'wiz-api')
    
    # Wiz sync configuration
    WIZ_SYNC_ENABLED = os.environ.get('WIZ_SYNC_ENABLED', 'false').lower() == 'true'
    WIZ_SYNC_INTERVAL = int(os.environ.get('WIZ_SYNC_INTERVAL', '3600'))  # 1 hour default
    WIZ_MAX_ASSETS_PER_SYNC = int(os.environ.get('WIZ_MAX_ASSETS_PER_SYNC', '1000'))
    WIZ_MAX_VULNS_PER_SYNC = int(os.environ.get('WIZ_MAX_VULNS_PER_SYNC', '500'))
    
    # External API Configuration
    # =========================
    # Configuration for other security tool integrations
    
    # Splunk integration for log analysis
    SPLUNK_HOST = os.environ.get('SPLUNK_HOST')
    SPLUNK_PORT = int(os.environ.get('SPLUNK_PORT', '8089'))
    SPLUNK_USERNAME = os.environ.get('SPLUNK_USERNAME')
    SPLUNK_PASSWORD = os.environ.get('SPLUNK_PASSWORD')
    SPLUNK_INDEX = os.environ.get('SPLUNK_INDEX', 'ai_spm')
    
    # Jira integration for ticket management
    JIRA_SERVER = os.environ.get('JIRA_SERVER')
    JIRA_USERNAME = os.environ.get('JIRA_USERNAME')
    JIRA_API_TOKEN = os.environ.get('JIRA_API_TOKEN')
    JIRA_PROJECT_KEY = os.environ.get('JIRA_PROJECT_KEY', 'AISEC')
    
    # Slack integration for notifications
    SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
    SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', '#ai-security')
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    
    # Application Features Configuration
    # =================================
    # Feature flags for enabling/disabling functionality
    FEATURE_VULNERABILITY_SCANNING = os.environ.get('FEATURE_VULNERABILITY_SCANNING', 'true').lower() == 'true'
    FEATURE_COMPLIANCE_MONITORING = os.environ.get('FEATURE_COMPLIANCE_MONITORING', 'true').lower() == 'true'
    FEATURE_AUTOMATED_REMEDIATION = os.environ.get('FEATURE_AUTOMATED_REMEDIATION', 'false').lower() == 'true'
    FEATURE_ML_RISK_ASSESSMENT = os.environ.get('FEATURE_ML_RISK_ASSESSMENT', 'true').lower() == 'true'
    
    # Compliance Framework Configuration
    # =================================
    # Default compliance frameworks to initialize
    DEFAULT_COMPLIANCE_FRAMEWORKS = [
        'NIST AI RMF',
        'ISO 27001',
        'SOC 2',
        'GDPR',
        'CCPA',
        'HIPAA'
    ]
    
    # Risk Assessment Configuration
    # ============================
    # Risk scoring thresholds and weights
    RISK_SCORE_WEIGHTS = {
        'vulnerability_severity': 0.3,
        'asset_criticality': 0.25,
        'exposure_level': 0.2,
        'compliance_status': 0.15,
        'threat_intelligence': 0.1
    }
    
    # Vulnerability severity scoring
    VULNERABILITY_SEVERITY_SCORES = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'informational': 1
    }
    
    # Asset criticality levels
    ASSET_CRITICALITY_LEVELS = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'minimal': 1
    }
    
    # Monitoring and Alerting Configuration
    # ====================================
    # Alert thresholds and notification settings
    ALERT_THRESHOLDS = {
        'critical_vulnerabilities': 1,      # Alert on any critical vulnerability
        'high_vulnerabilities': 5,          # Alert when 5+ high vulnerabilities
        'failed_compliance_checks': 3,      # Alert when 3+ compliance failures
        'suspicious_activity_score': 8      # Alert when activity score > 8
    }
    
    # Notification channels for different alert types
    NOTIFICATION_CHANNELS = {
        'critical': ['email', 'slack', 'sms'],
        'high': ['email', 'slack'],
        'medium': ['email'],
        'low': ['dashboard']
    }
    
    # Cache Configuration
    # ==================
    # Redis cache settings for improved performance
    CACHE_TYPE = 'redis' if os.environ.get('REDIS_URL') else 'simple'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes default cache timeout
    
    # Celery Configuration (for background tasks)
    # ===========================================
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True


class DevelopmentConfig(Config):
    """
    Development environment configuration.
    
    Inherits from base Config class and overrides settings
    appropriate for development environments.
    """
    DEBUG = True
    TESTING = False
    
    # Use SQLite for development by default
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.getcwd(), 'ai_spm_dev.db')
    
    # Enable detailed error pages
    PROPAGATE_EXCEPTIONS = True
    
    # Relaxed CORS for development
    CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000']


class TestingConfig(Config):
    """
    Testing environment configuration.
    
    Configuration settings optimized for running automated tests
    with isolated database and disabled external integrations.
    """
    TESTING = True
    DEBUG = True
    
    # Use in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4
    
    # Disable external integrations in tests
    WIZ_SYNC_ENABLED = False
    FEATURE_AUTOMATED_REMEDIATION = False


class ProductionConfig(Config):
    """
    Production environment configuration.
    
    Configuration settings optimized for production deployment
    with enhanced security and performance settings.
    """
    DEBUG = False
    TESTING = False
    
    # Enhanced security settings for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Stronger password hashing
    BCRYPT_LOG_ROUNDS = 15
    
    # Production logging
    LOG_LEVEL = 'WARNING'
    
    # Production cache settings
    CACHE_TYPE = 'redis'
    CACHE_DEFAULT_TIMEOUT = 3600  # 1 hour cache timeout


# Configuration mapping for easy access
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}