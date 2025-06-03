"""
AI Security Posture Management Platform - Authentication Module
==============================================================

This module provides comprehensive authentication and authorization functionality
for the AI-SPM platform including:
- User registration and login
- Session management
- Role-based access control (RBAC)
- Multi-factor authentication support
- Security middleware and decorators

Author: AI-SPM Development Team
Version: 1.0.0
"""

import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import List, Optional, Dict, Any
from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Unauthorized, Forbidden
import pyotp
import qrcode
import io
import base64

from models import db, User, AuditLog

# Configure logging
logger = logging.getLogger(__name__)

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__)


class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass


class AuthorizationError(Exception):
    """Custom exception for authorization errors"""
    pass


def log_audit_event(user_id: Optional[int], action: str, resource_type: str, 
                   resource_id: Optional[str] = None, success: bool = True,
                   details: Optional[Dict[str, Any]] = None) -> None:
    """
    Log user actions for audit trail and compliance monitoring.
    
    Args:
        user_id: ID of user performing action (None for anonymous actions)
        action: Action being performed (login, create, update, delete, etc.)
        resource_type: Type of resource being accessed
        resource_id: ID of specific resource (optional)
        success: Whether action was successful
        details: Additional context and details
    """
    try:
        audit_log = AuditLog(
            user_id=user_id,
            session_id=session.get('session_id'),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500],
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            success=success,
            details=details or {},
            http_method=request.method,
            endpoint=request.endpoint,
            risk_level='medium' if action in ['login', 'password_change'] else 'low',
            compliance_relevant=action in ['login', 'logout', 'password_change', 'role_change']
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Failed to log audit event: {str(e)}")
        db.session.rollback()


def login_required(f):
    """
    Decorator to require authentication for protected endpoints.
    
    This decorator checks if user is authenticated and adds user object
    to the request context for easy access in view functions.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'user_id' not in session:
            log_audit_event(None, 'unauthorized_access', 'endpoint', 
                          request.endpoint, success=False)
            return jsonify({'error': 'Authentication required'}), 401
        
        # Load user object and add to request context
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.clear()  # Clear invalid session
            log_audit_event(session.get('user_id'), 'invalid_session', 'auth', 
                          success=False)
            return jsonify({'error': 'Invalid or inactive user account'}), 401
        
        # Check if account is locked
        if user.account_locked_until and user.account_locked_until > datetime.now(timezone.utc):
            return jsonify({
                'error': 'Account temporarily locked due to failed login attempts',
                'locked_until': user.account_locked_until.isoformat()
            }), 423  # HTTP 423 Locked
        
        # Add user to request context
        request.current_user = user
        
        return f(*args, **kwargs)
    
    return decorated_function


def role_required(required_roles: List[str]):
    """
    Decorator to require specific roles for protected endpoints.
    
    Args:
        required_roles: List of roles that can access the endpoint
    
    Usage:
        @role_required(['admin', 'ciso'])
        def admin_only_view():
            pass
    """
    def decorator(f):
        @wraps(f)
        @login_required  # Ensure user is authenticated first
        def decorated_function(*args, **kwargs):
            user = request.current_user
            
            # Check if user has required role
            if user.role not in required_roles:
                log_audit_event(user.id, 'insufficient_privileges', 'endpoint',
                              request.endpoint, success=False,
                              details={'required_roles': required_roles, 'user_role': user.role})
                return jsonify({
                    'error': 'Insufficient privileges',
                    'required_roles': required_roles,
                    'user_role': user.role
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def check_rate_limit(user_id: int, action: str, limit: int, window_minutes: int) -> bool:
    """
    Check if user has exceeded rate limit for specific action.
    
    Args:
        user_id: User ID to check
        action: Action type (login_attempt, password_reset, etc.)
        limit: Maximum number of attempts allowed
        window_minutes: Time window in minutes
    
    Returns:
        True if within rate limit, False if exceeded
    """
    try:
        # Calculate time window
        since_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        
        # Count recent attempts
        recent_attempts = AuditLog.query.filter(
            AuditLog.user_id == user_id,
            AuditLog.action == action,
            AuditLog.event_timestamp >= since_time
        ).count()
        
        return recent_attempts < limit
        
    except Exception as e:
        logger.error(f"Rate limit check failed: {str(e)}")
        return True  # Allow on error to prevent lockout


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    User registration endpoint with comprehensive validation.
    
    Creates new user account with email verification and audit logging.
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'department']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400
        
        # Validate email format
        email = data['email'].lower().strip()
        if '@' not in email or '.' not in email.split('@')[1]:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Password strength validation
        password = data['password']
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Create new user
        user = User(
            username=data['username'].strip(),
            email=email,
            first_name=data.get('first_name', '').strip(),
            last_name=data.get('last_name', '').strip(),
            department=data['department'].strip(),
            job_title=data.get('job_title', '').strip(),
            phone=data.get('phone', '').strip(),
            role=data.get('role', 'analyst'),  # Default role
            is_active=True,
            is_verified=False  # Require email verification
        )
        
        # Set password hash
        user.set_password(password)
        
        # Save to database
        db.session.add(user)
        db.session.commit()
        
        # Log successful registration
        log_audit_event(user.id, 'user_registration', 'user', str(user.id),
                       success=True, details={'email': email, 'role': user.role})
        
        logger.info(f"New user registered: {user.username} ({email})")
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        
        log_audit_event(None, 'registration_failure', 'user', success=False,
                       details={'error': str(e), 'email': data.get('email')})
        
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User authentication endpoint with comprehensive security features.
    
    Handles login with rate limiting, account lockout, and audit logging.
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip()
        password = data['password']
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username.lower())
        ).first()
        
        # Rate limiting for failed attempts
        if user:
            if not check_rate_limit(user.id, 'login_attempt', 5, 15):  # 5 attempts per 15 minutes
                log_audit_event(user.id, 'rate_limit_exceeded', 'auth', success=False)
                return jsonify({
                    'error': 'Too many login attempts. Please try again later.'
                }), 429
        
        # Validate credentials
        if not user or not user.check_password(password):
            # Log failed attempt
            if user:
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.now(timezone.utc) + timedelta(hours=1)
                    logger.warning(f"Account locked for user: {user.username}")
                
                db.session.commit()
                
                log_audit_event(user.id, 'login_failure', 'auth', success=False,
                               details={'reason': 'invalid_password'})
            else:
                log_audit_event(None, 'login_failure', 'auth', success=False,
                               details={'reason': 'user_not_found', 'username': username})
            
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is active
        if not user.is_active:
            log_audit_event(user.id, 'login_failure', 'auth', success=False,
                           details={'reason': 'account_inactive'})
            return jsonify({'error': 'Account is disabled'}), 401
        
        # Check if account is locked
        if user.account_locked_until and user.account_locked_until > datetime.now(timezone.utc):
            log_audit_event(user.id, 'login_failure', 'auth', success=False,
                           details={'reason': 'account_locked'})
            return jsonify({
                'error': 'Account is temporarily locked',
                'locked_until': user.account_locked_until.isoformat()
            }), 423
        
        # Check MFA if enabled
        if user.mfa_enabled:
            mfa_code = data.get('mfa_code')
            if not mfa_code:
                return jsonify({
                    'error': 'MFA code required',
                    'mfa_required': True
                }), 200  # Not an error, just need MFA
            
            # Verify MFA code
            if not verify_mfa_code(user, mfa_code):
                log_audit_event(user.id, 'mfa_failure', 'auth', success=False)
                return jsonify({'error': 'Invalid MFA code'}), 401
        
        # Successful login - create session
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['session_id'] = generate_session_id()
        
        # Update user login information
        user.last_login = datetime.now(timezone.utc)
        user.failed_login_attempts = 0  # Reset failed attempts
        user.account_locked_until = None  # Clear any lock
        
        db.session.commit()
        
        # Log successful login
        log_audit_event(user.id, 'login_success', 'auth', success=True,
                       details={'ip': request.remote_addr})
        
        logger.info(f"User logged in: {user.username}")
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'session_expires': (datetime.now(timezone.utc) + 
                              current_app.permanent_session_lifetime).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    User logout endpoint with session cleanup and audit logging.
    """
    try:
        user = request.current_user
        session_id = session.get('session_id')
        
        # Log logout
        log_audit_event(user.id, 'logout', 'auth', success=True,
                       details={'session_id': session_id})
        
        # Clear session
        session.clear()
        
        logger.info(f"User logged out: {user.username}")
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """
    Get current user profile information.
    """
    try:
        user = request.current_user
        
        return jsonify({
            'user': user.to_dict(),
            'permissions': get_user_permissions(user),
            'session_info': {
                'session_id': session.get('session_id'),
                'last_activity': datetime.now(timezone.utc).isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Profile fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500


@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """
    Update user profile information with validation and audit logging.
    """
    try:
        user = request.current_user
        data = request.get_json()
        
        # Track changes for audit log
        changes = {}
        
        # Update allowed fields
        updatable_fields = ['first_name', 'last_name', 'phone', 'notification_settings']
        
        for field in updatable_fields:
            if field in data:
                old_value = getattr(user, field)
                new_value = data[field]
                
                if old_value != new_value:
                    changes[field] = {'old': old_value, 'new': new_value}
                    setattr(user, field, new_value)
        
        db.session.commit()
        
        # Log profile update
        if changes:
            log_audit_event(user.id, 'profile_update', 'user', str(user.id),
                           success=True, details={'changes': changes})
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Profile update failed'}), 500


@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """
    Change user password with security validation and audit logging.
    """
    try:
        user = request.current_user
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['current_password', 'new_password']):
            return jsonify({'error': 'Current and new passwords are required'}), 400
        
        # Verify current password
        if not user.check_password(data['current_password']):
            log_audit_event(user.id, 'password_change_failure', 'auth', success=False,
                           details={'reason': 'invalid_current_password'})
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        new_password = data['new_password']
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters long'}), 400
        
        # Set new password
        user.set_password(new_password)
        db.session.commit()
        
        # Log password change
        log_audit_event(user.id, 'password_change_success', 'auth', success=True)
        
        logger.info(f"Password changed for user: {user.username}")
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Password change error: {str(e)}")
        return jsonify({'error': 'Password change failed'}), 500


@auth_bp.route('/setup-mfa', methods=['POST'])
@login_required
def setup_mfa():
    """
    Setup Multi-Factor Authentication for user account.
    
    Generates TOTP secret and QR code for authenticator app setup.
    """
    try:
        user = request.current_user
        
        # Generate TOTP secret
        secret = pyotp.random_base32()
        
        # Create TOTP object
        totp = pyotp.TOTP(secret)
        
        # Generate provisioning URI for QR code
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="AI-SPM Platform"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Convert QR code to base64 image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        # Store secret temporarily (user needs to verify before enabling)
        session['mfa_setup_secret'] = secret
        
        return jsonify({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_data}",
            'backup_codes': generate_backup_codes()  # Generate backup codes
        }), 200
        
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}")
        return jsonify({'error': 'MFA setup failed'}), 500


@auth_bp.route('/verify-mfa', methods=['POST'])
@login_required
def verify_mfa_setup():
    """
    Verify MFA setup by validating TOTP code from authenticator app.
    """
    try:
        user = request.current_user
        data = request.get_json()
        
        mfa_code = data.get('mfa_code')
        if not mfa_code:
            return jsonify({'error': 'MFA code is required'}), 400
        
        # Get secret from session
        secret = session.get('mfa_setup_secret')
        if not secret:
            return jsonify({'error': 'MFA setup session expired'}), 400
        
        # Verify code
        totp = pyotp.TOTP(secret)
        if not totp.verify(mfa_code):
            return jsonify({'error': 'Invalid MFA code'}), 400
        
        # Enable MFA for user
        user.mfa_enabled = True
        user.mfa_secret = secret
        
        db.session.commit()
        
        # Clear setup session
        session.pop('mfa_setup_secret', None)
        
        # Log MFA enablement
        log_audit_event(user.id, 'mfa_enabled', 'auth', success=True)
        
        logger.info(f"MFA enabled for user: {user.username}")
        
        return jsonify({'message': 'MFA enabled successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"MFA verification error: {str(e)}")
        return jsonify({'error': 'MFA verification failed'}), 500


def verify_mfa_code(user: User, code: str) -> bool:
    """
    Verify MFA code for user authentication.
    
    Args:
        user: User object
        code: TOTP code from authenticator app
    
    Returns:
        True if code is valid, False otherwise
    """
    try:
        if not user.mfa_enabled or not user.mfa_secret:
            return False
        
        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(code)
        
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        return False


def generate_session_id() -> str:
    """Generate unique session ID for request tracking"""
    import uuid
    return str(uuid.uuid4())


def generate_backup_codes() -> List[str]:
    """Generate backup codes for MFA recovery"""
    import secrets
    return [secrets.token_hex(4).upper() for _ in range(10)]


def get_user_permissions(user: User) -> Dict[str, List[str]]:
    """
    Get user permissions based on role.
    
    Args:
        user: User object
    
    Returns:
        Dictionary of permissions organized by resource type
    """
    permissions = {
        'assets': [],
        'vulnerabilities': [],
        'compliance': [],
        'users': [],
        'admin': []
    }
    
    # Role-based permissions mapping
    role_permissions = {
        'admin': {
            'assets': ['create', 'read', 'update', 'delete'],
            'vulnerabilities': ['create', 'read', 'update', 'delete'],
            'compliance': ['create', 'read', 'update', 'delete'],
            'users': ['create', 'read', 'update', 'delete'],
            'admin': ['system_config', 'audit_logs', 'integrations']
        },
        'ciso': {
            'assets': ['create', 'read', 'update'],
            'vulnerabilities': ['create', 'read', 'update'],
            'compliance': ['create', 'read', 'update'],
            'users': ['read', 'update'],
            'admin': ['audit_logs']
        },
        'analyst': {
            'assets': ['read', 'update'],
            'vulnerabilities': ['create', 'read', 'update'],
            'compliance': ['read'],
            'users': ['read'],
            'admin': []
        },
        'engineer': {
            'assets': ['create', 'read', 'update'],
            'vulnerabilities': ['read', 'update'],
            'compliance': ['read'],
            'users': ['read'],
            'admin': []
        },
        'compliance_officer': {
            'assets': ['read'],
            'vulnerabilities': ['read'],
            'compliance': ['create', 'read', 'update'],
            'users': ['read'],
            'admin': []
        },
        'auditor': {
            'assets': ['read'],
            'vulnerabilities': ['read'],
            'compliance': ['read'],
            'users': ['read'],
            'admin': ['audit_logs']
        }
    }
    
    return role_permissions.get(user.role, permissions)