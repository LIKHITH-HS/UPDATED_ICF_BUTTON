"""
Admin Panel Middleware for LinkSafetyShield

This module provides middleware functions for the admin panel including
session timeout checking, CSRF protection, and security headers.
"""

from flask import request, session, current_app, g
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AdminMiddleware:
    """Admin panel middleware handler"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    @staticmethod
    def before_request():
        """
        Before request middleware for admin routes
        Handles session timeout checking and CSRF token generation
        """
        # Only apply to admin routes
        if not request.endpoint or not request.endpoint.startswith('admin_panel.'):
            return
        
        # Skip for login and static routes
        if request.endpoint in ['admin_panel.login', 'admin_panel.static']:
            return
        
        # Check session timeout for authenticated admin routes
        from admin_auth import AdminAuth
        
        if AdminAuth.SESSION_USER_KEY in session:
            if not AdminAuth._check_session_timeout():
                logger.info("Admin session timed out, clearing session")
                AdminAuth.logout()
                # The route decorator will handle the redirect
        
        # Store CSRF token in g for template access
        g.csrf_token = AdminAuth.generate_csrf_token()
    
    @staticmethod
    def after_request(response):
        """
        After request middleware for admin routes
        Adds security headers and handles session updates
        """
        # Only apply to admin routes
        if not request.endpoint or not request.endpoint.startswith('admin_panel.'):
            return response
        
        # Add security headers for admin panel
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add CSP header for admin panel
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp_policy
        
        return response


def setup_admin_session_config(app):
    """
    Configure Flask session settings for admin panel security
    
    Args:
        app: Flask application instance
    """
    # Session configuration for security
    app.config.update(
        SESSION_COOKIE_SECURE=not app.debug,  # HTTPS only in production
        SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS access to session cookie
        SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
        SESSION_COOKIE_NAME='admin_session',  # Custom session cookie name
        PERMANENT_SESSION_LIFETIME=timedelta(
            seconds=app.config.get('ADMIN_SESSION_TIMEOUT', 1800)
        )
    )
    
    logger.info("Admin session security configuration applied")


def log_admin_activity(action: str, details: str = None, ip_address: str = None):
    """
    Log admin panel activity for audit purposes
    
    Args:
        action (str): Action performed (e.g., 'login', 'logout', 'settings_update')
        details (str, optional): Additional details about the action
        ip_address (str, optional): IP address of the admin user
    """
    try:
        from admin_auth import AdminAuth
        
        username = AdminAuth.get_current_user() or 'anonymous'
        ip_addr = ip_address or request.remote_addr or 'unknown'
        timestamp = datetime.utcnow().isoformat()
        
        log_entry = {
            'timestamp': timestamp,
            'username': username,
            'action': action,
            'ip_address': ip_addr,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'details': details
        }
        
        # Log to application logger
        logger.info(f"Admin Activity: {username}@{ip_addr} - {action} - {details or 'N/A'}")
        
        # Store in Redis if available for audit trail
        if hasattr(current_app, 'redis') and current_app.redis:
            try:
                audit_key = f"admin_audit:{timestamp}:{username}"
                current_app.redis.setex(
                    audit_key, 
                    86400 * 30,  # Keep for 30 days
                    str(log_entry)
                )
            except Exception as e:
                logger.error(f"Failed to store audit log in Redis: {e}")
        
    except Exception as e:
        logger.error(f"Error logging admin activity: {e}")


class AdminRateLimiter:
    """Rate limiting specifically for admin panel to prevent brute force attacks"""
    
    @staticmethod
    def check_login_attempts(ip_address: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """
        Check if IP address has exceeded login attempt limits
        
        Args:
            ip_address (str): IP address to check
            max_attempts (int): Maximum login attempts allowed
            window_minutes (int): Time window in minutes
            
        Returns:
            bool: True if attempts are within limit, False if exceeded
        """
        try:
            if not hasattr(current_app, 'redis') or not current_app.redis:
                # If no Redis, allow all attempts (fallback)
                return True
            
            key = f"admin_login_attempts:{ip_address}"
            current_attempts = current_app.redis.get(key)
            
            if current_attempts is None:
                return True
            
            return int(current_attempts) < max_attempts
            
        except Exception as e:
            logger.error(f"Error checking login attempts: {e}")
            return True  # Allow on error
    
    @staticmethod
    def record_login_attempt(ip_address: str, success: bool, window_minutes: int = 15):
        """
        Record a login attempt
        
        Args:
            ip_address (str): IP address of the attempt
            success (bool): Whether the login was successful
            window_minutes (int): Time window in minutes
        """
        try:
            if not hasattr(current_app, 'redis') or not current_app.redis:
                return
            
            key = f"admin_login_attempts:{ip_address}"
            
            if success:
                # Clear attempts on successful login
                current_app.redis.delete(key)
            else:
                # Increment failed attempts
                pipe = current_app.redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, window_minutes * 60)
                pipe.execute()
                
        except Exception as e:
            logger.error(f"Error recording login attempt: {e}")
    
    @staticmethod
    def get_remaining_attempts(ip_address: str, max_attempts: int = 5) -> int:
        """
        Get remaining login attempts for IP address
        
        Args:
            ip_address (str): IP address to check
            max_attempts (int): Maximum attempts allowed
            
        Returns:
            int: Number of remaining attempts
        """
        try:
            if not hasattr(current_app, 'redis') or not current_app.redis:
                return max_attempts
            
            key = f"admin_login_attempts:{ip_address}"
            current_attempts = current_app.redis.get(key)
            
            if current_attempts is None:
                return max_attempts
            
            return max(0, max_attempts - int(current_attempts))
            
        except Exception as e:
            logger.error(f"Error getting remaining attempts: {e}")
            return max_attempts