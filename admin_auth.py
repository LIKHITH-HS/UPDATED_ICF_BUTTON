"""
Admin Authentication Module for LinkSafetyShield Admin Panel

This module provides secure authentication functionality for the admin panel,
including login/logout, session management, and timeout handling.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, current_app, flash, redirect, url_for
import logging

logger = logging.getLogger(__name__)

class AdminAuth:
    """Admin authentication handler"""
    
    # Session keys
    SESSION_USER_KEY = 'admin_user'
    SESSION_LOGIN_TIME_KEY = 'admin_login_time'
    SESSION_LAST_ACTIVITY_KEY = 'admin_last_activity'
    SESSION_CSRF_TOKEN_KEY = 'admin_csrf_token'
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple:
        """
        Hash a password with salt for secure storage
        
        Args:
            password (str): Plain text password
            salt (str, optional): Salt for hashing. If None, generates new salt.
            
        Returns:
            tuple: (hashed_password, salt)
        """
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 with SHA-256 for secure password hashing
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100,000 iterations
        )
        
        return password_hash.hex(), salt
    
    @staticmethod
    def verify_password(password: str, hashed_password: str, salt: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password (str): Plain text password to verify
            hashed_password (str): Stored password hash
            salt (str): Salt used for hashing
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            computed_hash, _ = AdminAuth.hash_password(password, salt)
            return secrets.compare_digest(computed_hash, hashed_password)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    @staticmethod
    def authenticate(username: str, password: str) -> bool:
        """
        Authenticate admin user with username and password
        
        Args:
            username (str): Admin username
            password (str): Admin password
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            # Get admin credentials from config
            config_username = current_app.config.get('ADMIN_USERNAME', 'admin')
            config_password = current_app.config.get('ADMIN_PASSWORD', 'admin123')
            
            # Simple constant-time comparison for development
            # In production, you'd want to use hashed passwords
            username_match = secrets.compare_digest(username, config_username)
            password_match = secrets.compare_digest(password, config_password)
            
            if username_match and password_match:
                # Set session data
                session[AdminAuth.SESSION_USER_KEY] = username
                session[AdminAuth.SESSION_LOGIN_TIME_KEY] = datetime.utcnow().isoformat()
                session[AdminAuth.SESSION_LAST_ACTIVITY_KEY] = datetime.utcnow().isoformat()
                session[AdminAuth.SESSION_CSRF_TOKEN_KEY] = secrets.token_urlsafe(32)
                
                # Make session permanent but with timeout
                session.permanent = True
                current_app.permanent_session_lifetime = timedelta(
                    seconds=current_app.config.get('ADMIN_SESSION_TIMEOUT', 1800)
                )
                
                logger.info(f"Admin user '{username}' authenticated successfully")
                return True
            else:
                logger.warning(f"Failed authentication attempt for username: {username}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    @staticmethod
    def is_authenticated() -> bool:
        """
        Check if current session is authenticated and not expired
        
        Returns:
            bool: True if authenticated and session valid, False otherwise
        """
        try:
            # Check if user is in session
            if AdminAuth.SESSION_USER_KEY not in session:
                return False
            
            # Check session timeout
            if not AdminAuth._check_session_timeout():
                AdminAuth.logout()
                return False
            
            # Update last activity
            session[AdminAuth.SESSION_LAST_ACTIVITY_KEY] = datetime.utcnow().isoformat()
            
            return True
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False
    
    @staticmethod
    def _check_session_timeout() -> bool:
        """
        Check if session has timed out
        
        Returns:
            bool: True if session is still valid, False if timed out
        """
        try:
            last_activity_str = session.get(AdminAuth.SESSION_LAST_ACTIVITY_KEY)
            if not last_activity_str:
                return False
            
            last_activity = datetime.fromisoformat(last_activity_str)
            timeout_seconds = current_app.config.get('ADMIN_SESSION_TIMEOUT', 1800)
            timeout_delta = timedelta(seconds=timeout_seconds)
            
            return datetime.utcnow() - last_activity < timeout_delta
            
        except Exception as e:
            logger.error(f"Session timeout check error: {e}")
            return False
    
    @staticmethod
    def logout():
        """Clear admin session data"""
        try:
            username = session.get(AdminAuth.SESSION_USER_KEY, 'unknown')
            
            # Clear all admin session data
            session.pop(AdminAuth.SESSION_USER_KEY, None)
            session.pop(AdminAuth.SESSION_LOGIN_TIME_KEY, None)
            session.pop(AdminAuth.SESSION_LAST_ACTIVITY_KEY, None)
            session.pop(AdminAuth.SESSION_CSRF_TOKEN_KEY, None)
            
            logger.info(f"Admin user '{username}' logged out")
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
    
    @staticmethod
    def get_current_user() -> str:
        """
        Get current authenticated admin user
        
        Returns:
            str: Username of current admin user, or None if not authenticated
        """
        if AdminAuth.is_authenticated():
            return session.get(AdminAuth.SESSION_USER_KEY)
        return None
    
    @staticmethod
    def get_session_info() -> dict:
        """
        Get information about current admin session
        
        Returns:
            dict: Session information including login time, last activity, etc.
        """
        if not AdminAuth.is_authenticated():
            return {}
        
        try:
            login_time_str = session.get(AdminAuth.SESSION_LOGIN_TIME_KEY)
            last_activity_str = session.get(AdminAuth.SESSION_LAST_ACTIVITY_KEY)
            
            login_time = datetime.fromisoformat(login_time_str) if login_time_str else None
            last_activity = datetime.fromisoformat(last_activity_str) if last_activity_str else None
            
            timeout_seconds = current_app.config.get('ADMIN_SESSION_TIMEOUT', 1800)
            expires_at = last_activity + timedelta(seconds=timeout_seconds) if last_activity else None
            
            return {
                'username': session.get(AdminAuth.SESSION_USER_KEY),
                'login_time': login_time,
                'last_activity': last_activity,
                'expires_at': expires_at,
                'timeout_seconds': timeout_seconds,
                'csrf_token': session.get(AdminAuth.SESSION_CSRF_TOKEN_KEY)
            }
            
        except Exception as e:
            logger.error(f"Error getting session info: {e}")
            return {}
    
    @staticmethod
    def generate_csrf_token() -> str:
        """
        Generate or get CSRF token for current session
        
        Returns:
            str: CSRF token
        """
        if AdminAuth.SESSION_CSRF_TOKEN_KEY not in session:
            session[AdminAuth.SESSION_CSRF_TOKEN_KEY] = secrets.token_urlsafe(32)
        
        return session[AdminAuth.SESSION_CSRF_TOKEN_KEY]
    
    @staticmethod
    def validate_csrf_token(token: str) -> bool:
        """
        Validate CSRF token
        
        Args:
            token (str): CSRF token to validate
            
        Returns:
            bool: True if token is valid, False otherwise
        """
        session_token = session.get(AdminAuth.SESSION_CSRF_TOKEN_KEY)
        if not session_token or not token:
            return False
        
        return secrets.compare_digest(session_token, token)


def require_admin(f):
    """
    Decorator to require admin authentication for routes
    
    Usage:
        @app.route('/admin/dashboard')
        @require_admin
        def admin_dashboard():
            return render_template('admin/dashboard.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AdminAuth.is_authenticated():
            flash('Please log in to access the admin panel.', 'error')
            return redirect(url_for('admin_panel.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def require_csrf(f):
    """
    Decorator to require CSRF token validation for POST requests
    
    Usage:
        @app.route('/admin/settings', methods=['POST'])
        @require_admin
        @require_csrf
        def update_settings():
            # Handle settings update
            pass
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not AdminAuth.validate_csrf_token(csrf_token):
                flash('Invalid CSRF token. Please try again.', 'error')
                return redirect(request.referrer or url_for('admin_panel.dashboard'))
        return f(*args, **kwargs)
    return decorated_function