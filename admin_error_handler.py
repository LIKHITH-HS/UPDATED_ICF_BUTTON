"""
Admin Panel Error Handler and User Feedback System

This module provides comprehensive error handling, user-friendly error messages,
validation feedback, and success notifications for the admin panel.
"""

import logging
import traceback
from datetime import datetime
from functools import wraps
from flask import request, flash, jsonify, redirect, url_for, current_app
from typing import Dict, Any, Optional, Tuple
import json

logger = logging.getLogger(__name__)

class AdminErrorHandler:
    """Comprehensive error handling for admin panel operations"""
    
    # Error categories
    ERROR_CATEGORIES = {
        'validation': 'Validation Error',
        'authentication': 'Authentication Error',
        'authorization': 'Authorization Error',
        'configuration': 'Configuration Error',
        'database': 'Database Error',
        'external_api': 'External API Error',
        'system': 'System Error',
        'network': 'Network Error',
        'timeout': 'Timeout Error',
        'rate_limit': 'Rate Limit Error'
    }
    
    # User-friendly error messages
    ERROR_MESSAGES = {
        'validation': {
            'required_field': 'This field is required and cannot be empty.',
            'invalid_format': 'The format of this field is invalid.',
            'invalid_email': 'Please enter a valid email address.',
            'invalid_url': 'Please enter a valid URL.',
            'invalid_number': 'Please enter a valid number.',
            'invalid_date': 'Please enter a valid date.',
            'password_weak': 'Password must be at least 8 characters long.',
            'passwords_mismatch': 'Passwords do not match.',
            'invalid_range': 'Value must be within the specified range.',
            'duplicate_entry': 'This entry already exists.'
        },
        'authentication': {
            'invalid_credentials': 'Invalid username or password. Please try again.',
            'session_expired': 'Your session has expired. Please log in again.',
            'account_locked': 'Account temporarily locked due to multiple failed attempts.',
            'insufficient_privileges': 'You do not have sufficient privileges for this action.'
        },
        'configuration': {
            'invalid_setting': 'Invalid configuration setting provided.',
            'missing_api_key': 'API key is missing or invalid.',
            'service_unavailable': 'External service is currently unavailable.',
            'connection_failed': 'Failed to connect to external service.'
        },
        'system': {
            'database_error': 'Database operation failed. Please try again.',
            'file_not_found': 'Requested file or resource not found.',
            'permission_denied': 'Permission denied for this operation.',
            'disk_full': 'Insufficient disk space to complete operation.',
            'memory_error': 'Insufficient memory to complete operation.'
        },
        'network': {
            'connection_timeout': 'Connection timed out. Please check your network.',
            'dns_error': 'DNS resolution failed. Please check the URL.',
            'ssl_error': 'SSL certificate verification failed.'
        }
    }
    
    @staticmethod
    def handle_error(error: Exception, category: str = 'system', 
                    context: str = None, user_message: str = None) -> Dict[str, Any]:
        """
        Handle and log errors with appropriate user feedback
        
        Args:
            error (Exception): The exception that occurred
            category (str): Error category for classification
            context (str): Additional context about where the error occurred
            user_message (str): Custom user-friendly message
            
        Returns:
            Dict: Error information for response
        """
        try:
            # Generate error ID for tracking
            error_id = f"ERR_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{id(error)}"
            
            # Get error details
            error_type = type(error).__name__
            error_message = str(error)
            error_traceback = traceback.format_exc()
            
            # Log the error
            logger.error(f"Admin Panel Error [{error_id}]: {error_type} in {context or 'unknown context'}")
            logger.error(f"Error message: {error_message}")
            logger.error(f"Traceback: {error_traceback}")
            
            # Store error in Redis for admin review if available
            AdminErrorHandler._store_error_log(error_id, {
                'timestamp': datetime.utcnow().isoformat(),
                'error_type': error_type,
                'error_message': error_message,
                'category': category,
                'context': context,
                'traceback': error_traceback,
                'user_agent': request.headers.get('User-Agent') if request else None,
                'ip_address': request.remote_addr if request else None,
                'endpoint': request.endpoint if request else None
            })
            
            # Get user-friendly message
            friendly_message = user_message or AdminErrorHandler._get_friendly_message(
                error_type, category, error_message
            )
            
            return {
                'error_id': error_id,
                'category': category,
                'type': error_type,
                'message': friendly_message,
                'technical_message': error_message,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in error handler: {e}")
            return {
                'error_id': 'HANDLER_ERROR',
                'category': 'system',
                'type': 'ErrorHandlerException',
                'message': 'An unexpected error occurred. Please contact support.',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    @staticmethod
    def _store_error_log(error_id: str, error_data: Dict[str, Any]):
        """Store error log in Redis for admin review"""
        try:
            if hasattr(current_app, 'redis') and current_app.redis:
                key = f"admin_errors:{error_id}"
                current_app.redis.setex(
                    key, 
                    86400 * 7,  # Keep for 7 days
                    json.dumps(error_data, default=str)
                )
        except Exception as e:
            logger.error(f"Failed to store error log: {e}")
    
    @staticmethod
    def _get_friendly_message(error_type: str, category: str, technical_message: str) -> str:
        """Get user-friendly error message based on error type and category"""
        try:
            # Check for specific error patterns
            technical_lower = technical_message.lower()
            
            # Validation errors
            if 'required' in technical_lower or 'missing' in technical_lower:
                return AdminErrorHandler.ERROR_MESSAGES['validation']['required_field']
            elif 'invalid' in technical_lower and 'email' in technical_lower:
                return AdminErrorHandler.ERROR_MESSAGES['validation']['invalid_email']
            elif 'invalid' in technical_lower and 'url' in technical_lower:
                return AdminErrorHandler.ERROR_MESSAGES['validation']['invalid_url']
            elif 'timeout' in technical_lower:
                return AdminErrorHandler.ERROR_MESSAGES['network']['connection_timeout']
            elif 'connection' in technical_lower and 'refused' in technical_lower:
                return AdminErrorHandler.ERROR_MESSAGES['configuration']['connection_failed']
            elif 'permission' in technical_lower or 'access' in technical_lower:
                return AdminErrorHandler.ERROR_MESSAGES['system']['permission_denied']
            
            # Category-based messages
            if category in AdminErrorHandler.ERROR_MESSAGES:
                category_messages = AdminErrorHandler.ERROR_MESSAGES[category]
                if 'default' in category_messages:
                    return category_messages['default']
                else:
                    # Return first message from category
                    return list(category_messages.values())[0]
            
            # Default message
            return f"An error occurred while processing your request. Please try again or contact support if the problem persists."
            
        except Exception as e:
            logger.error(f"Error generating friendly message: {e}")
            return "An unexpected error occurred. Please contact support."


class AdminNotificationSystem:
    """User feedback and notification system for admin panel"""
    
    # Notification types
    NOTIFICATION_TYPES = {
        'success': {
            'icon': 'fas fa-check-circle',
            'class': 'alert-success',
            'title': 'Success'
        },
        'info': {
            'icon': 'fas fa-info-circle',
            'class': 'alert-info',
            'title': 'Information'
        },
        'warning': {
            'icon': 'fas fa-exclamation-triangle',
            'class': 'alert-warning',
            'title': 'Warning'
        },
        'error': {
            'icon': 'fas fa-times-circle',
            'class': 'alert-danger',
            'title': 'Error'
        }
    }
    
    @staticmethod
    def success(message: str, details: str = None, auto_dismiss: bool = True):
        """Show success notification"""
        AdminNotificationSystem._flash_message('success', message, details, auto_dismiss)
    
    @staticmethod
    def info(message: str, details: str = None, auto_dismiss: bool = True):
        """Show info notification"""
        AdminNotificationSystem._flash_message('info', message, details, auto_dismiss)
    
    @staticmethod
    def warning(message: str, details: str = None, auto_dismiss: bool = True):
        """Show warning notification"""
        AdminNotificationSystem._flash_message('warning', message, details, auto_dismiss)
    
    @staticmethod
    def error(message: str, details: str = None, auto_dismiss: bool = False):
        """Show error notification"""
        AdminNotificationSystem._flash_message('error', message, details, auto_dismiss)
    
    @staticmethod
    def _flash_message(msg_type: str, message: str, details: str = None, auto_dismiss: bool = True):
        """Flash message with enhanced formatting"""
        try:
            notification_info = AdminNotificationSystem.NOTIFICATION_TYPES.get(msg_type, 
                AdminNotificationSystem.NOTIFICATION_TYPES['info'])
            
            # Create enhanced message with metadata
            enhanced_message = {
                'type': msg_type,
                'message': message,
                'details': details,
                'icon': notification_info['icon'],
                'title': notification_info['title'],
                'auto_dismiss': auto_dismiss,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Use Flask's flash with category
            flash(json.dumps(enhanced_message), msg_type)
            
        except Exception as e:
            logger.error(f"Error flashing message: {e}")
            # Fallback to simple flash
            flash(message, msg_type)


def admin_error_handler(category: str = 'system', user_message: str = None):
    """
    Decorator for comprehensive error handling in admin routes
    
    Args:
        category (str): Error category for classification
        user_message (str): Custom user-friendly message for errors
    
    Usage:
        @admin_error_handler(category='configuration', user_message='Failed to update settings')
        def update_settings():
            # Route implementation
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                # Handle the error
                error_info = AdminErrorHandler.handle_error(
                    e, category, f.__name__, user_message
                )
                
                # Show user-friendly error message
                AdminNotificationSystem.error(
                    error_info['message'],
                    f"Error ID: {error_info['error_id']}"
                )
                
                # Return appropriate response based on request type
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({
                        'status': 'error',
                        'message': error_info['message'],
                        'error_id': error_info['error_id'],
                        'category': error_info['category']
                    }), 500
                else:
                    # Redirect to appropriate page
                    if 'admin_panel.dashboard' in str(request.url_rule):
                        return redirect(url_for('admin_panel.dashboard'))
                    else:
                        return redirect(request.referrer or url_for('admin_panel.dashboard'))
        
        return decorated_function
    return decorator


def validate_admin_form(validation_rules: Dict[str, Dict[str, Any]]):
    """
    Decorator for form validation with user-friendly error messages
    
    Args:
        validation_rules (Dict): Validation rules for form fields
        
    Example:
        @validate_admin_form({
            'username': {'required': True, 'min_length': 3},
            'email': {'required': True, 'type': 'email'},
            'age': {'type': 'int', 'min': 18, 'max': 100}
        })
        def create_user():
            # Route implementation
            pass
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                validation_errors = []
                
                for field_name, rules in validation_rules.items():
                    field_value = request.form.get(field_name, '').strip()
                    
                    # Required field validation
                    if rules.get('required', False) and not field_value:
                        validation_errors.append(f"{field_name.title()} is required.")
                        continue
                    
                    # Skip other validations if field is empty and not required
                    if not field_value and not rules.get('required', False):
                        continue
                    
                    # Type validation
                    field_type = rules.get('type', 'string')
                    if field_type == 'email' and '@' not in field_value:
                        validation_errors.append(f"{field_name.title()} must be a valid email address.")
                    elif field_type == 'url' and not field_value.startswith(('http://', 'https://')):
                        validation_errors.append(f"{field_name.title()} must be a valid URL.")
                    elif field_type == 'int':
                        try:
                            int_value = int(field_value)
                            if 'min' in rules and int_value < rules['min']:
                                validation_errors.append(f"{field_name.title()} must be at least {rules['min']}.")
                            if 'max' in rules and int_value > rules['max']:
                                validation_errors.append(f"{field_name.title()} must be at most {rules['max']}.")
                        except ValueError:
                            validation_errors.append(f"{field_name.title()} must be a valid number.")
                    
                    # Length validation
                    if 'min_length' in rules and len(field_value) < rules['min_length']:
                        validation_errors.append(f"{field_name.title()} must be at least {rules['min_length']} characters long.")
                    if 'max_length' in rules and len(field_value) > rules['max_length']:
                        validation_errors.append(f"{field_name.title()} must be at most {rules['max_length']} characters long.")
                
                # If validation errors exist, show them and redirect
                if validation_errors:
                    for error in validation_errors:
                        AdminNotificationSystem.error(error)
                    
                    if request.is_json:
                        return jsonify({
                            'status': 'error',
                            'message': 'Validation failed',
                            'errors': validation_errors
                        }), 400
                    else:
                        return redirect(request.referrer or url_for('admin_panel.dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def confirm_action(message: str, redirect_url: str = None):
    """
    Decorator to require confirmation for destructive actions
    
    Args:
        message (str): Confirmation message to display
        redirect_url (str): URL to redirect to if not confirmed
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            confirmed = request.form.get('confirmed') == 'true'
            
            if not confirmed:
                AdminNotificationSystem.warning(
                    f"Please confirm: {message}",
                    "This action requires confirmation."
                )
                return redirect(redirect_url or request.referrer or url_for('admin_panel.dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def init_admin_error_handling(app):
    """Initialize admin error handling for the Flask app"""
    try:
        # Register error handlers for different HTTP status codes
        @app.errorhandler(400)
        def handle_bad_request(error):
            if request.path.startswith('/admin'):
                AdminNotificationSystem.error("Bad request. Please check your input.")
                return redirect(url_for('admin_panel.dashboard'))
            return error
        
        @app.errorhandler(403)
        def handle_forbidden(error):
            if request.path.startswith('/admin'):
                AdminNotificationSystem.error("Access denied. You don't have permission for this action.")
                return redirect(url_for('admin_panel.login'))
            return error
        
        @app.errorhandler(404)
        def handle_not_found(error):
            if request.path.startswith('/admin'):
                AdminNotificationSystem.error("Page not found.")
                return redirect(url_for('admin_panel.dashboard'))
            return error
        
        @app.errorhandler(500)
        def handle_internal_error(error):
            if request.path.startswith('/admin'):
                error_info = AdminErrorHandler.handle_error(error, 'system', 'Internal Server Error')
                AdminNotificationSystem.error(
                    "An internal server error occurred.",
                    f"Error ID: {error_info['error_id']}"
                )
                return redirect(url_for('admin_panel.dashboard'))
            return error
        
        logger.info("Admin error handling initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing admin error handling: {e}")