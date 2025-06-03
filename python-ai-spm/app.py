"""
AI Security Posture Management Platform - Main Application
===========================================================

This is the main Flask application file that initializes and configures the AI-SPM platform.
The platform provides comprehensive security management for AI/ML systems including:
- Asset inventory and lifecycle management
- Vulnerability assessment and tracking
- Compliance monitoring and reporting
- Security alert management
- Governance policy enforcement

Author: AI-SPM Development Team
Version: 1.0.0
License: MIT
"""

import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest, Unauthorized, NotFound

# Import custom modules
from config import Config
from models import db, User, AiAsset, Vulnerability, SecurityAlert, ComplianceFramework
from auth import auth_bp, login_required, role_required
from api import api_bp
from integrations.wiz_integration import WizIntegration

# Configure logging for debugging and monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_spm.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def create_app(config_class=Config):
    """
    Application factory pattern for creating Flask application instances.
    
    This function creates and configures a Flask application with all necessary
    extensions, blueprints, and error handlers. It follows Flask best practices
    for application structure and configuration.
    
    Args:
        config_class: Configuration class to use (default: Config)
        
    Returns:
        Flask: Configured Flask application instance
    """
    # Initialize Flask application
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    CORS(app, supports_credentials=True)  # Enable CORS for frontend integration
    Session(app)  # Server-side session management
    
    # Register blueprints for modular application structure
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Initialize database tables on first run
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Create default admin user if none exists
            if not User.query.filter_by(role='admin').first():
                admin_user = User(
                    username='admin',
                    email='admin@ai-spm.com',
                    password_hash=generate_password_hash('admin123'),
                    role='admin',
                    department='Security',
                    is_active=True
                )
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Default admin user created")
                
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
    
    # Global error handlers for consistent API responses
    @app.errorhandler(400)
    def bad_request(error):
        """Handle bad request errors with consistent JSON response"""
        return jsonify({
            'error': 'Bad Request',
            'message': str(error.description) if error.description else 'Invalid request data',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle unauthorized access with consistent JSON response"""
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle forbidden access with consistent JSON response"""
        return jsonify({
            'error': 'Forbidden',
            'message': 'Insufficient permissions',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle not found errors with consistent JSON response"""
        return jsonify({
            'error': 'Not Found',
            'message': 'Resource not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle internal server errors with consistent JSON response"""
        db.session.rollback()  # Rollback any pending database transactions
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    # Health check endpoint for monitoring and load balancer integration
    @app.route('/health')
    def health_check():
        """
        Health check endpoint for application monitoring.
        
        Returns application status, database connectivity, and basic metrics.
        Used by load balancers and monitoring systems to verify service health.
        """
        try:
            # Test database connectivity
            db.session.execute('SELECT 1')
            db_status = 'healthy'
        except Exception:
            db_status = 'unhealthy'
        
        # Get basic application metrics
        total_assets = AiAsset.query.count()
        critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
        active_alerts = SecurityAlert.query.filter_by(status='open').count()
        
        return jsonify({
            'status': 'healthy' if db_status == 'healthy' else 'degraded',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'database': db_status,
            'metrics': {
                'total_assets': total_assets,
                'critical_vulnerabilities': critical_vulns,
                'active_alerts': active_alerts
            }
        })
    
    # Request logging middleware for audit trail
    @app.before_request
    def log_request_info():
        """Log incoming requests for security monitoring and debugging"""
        logger.info(f"Request: {request.method} {request.url} from {request.remote_addr}")
        
        # Skip logging for health checks and static files
        if request.endpoint in ['health_check', 'static']:
            return
            
        # Log user information for authenticated requests
        if 'user_id' in session:
            logger.info(f"Authenticated request from user ID: {session['user_id']}")
    
    # Response headers for security
    @app.after_request
    def set_security_headers(response):
        """Set security headers on all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    logger.info("AI-SPM Flask application initialized successfully")
    return app


if __name__ == '__main__':
    """
    Development server entry point.
    
    In production, use a WSGI server like Gunicorn or uWSGI instead of
    the Flask development server.
    """
    app = create_app()
    
    # Development server configuration
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting AI-SPM application on {host}:{port}")
    logger.info(f"Debug mode: {debug_mode}")
    
    app.run(
        host=host,
        port=port,
        debug=debug_mode,
        threaded=True  # Enable threading for better performance
    )