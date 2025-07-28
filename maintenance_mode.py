"""
Maintenance Mode Manager for LinkSafetyShield Admin Panel

This module provides maintenance mode functionality including:
- Toggle maintenance mode on/off
- Schedule maintenance windows
- Middleware to handle requests during maintenance
- Status display and countdown functionality
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any
from flask import current_app, request, jsonify, render_template, g
from functools import wraps
import threading
import time

logger = logging.getLogger(__name__)

class MaintenanceMode:
    """Maintenance mode management system"""
    
    # Redis keys for maintenance mode data
    MAINTENANCE_STATUS_KEY = "admin:maintenance:status"
    MAINTENANCE_SCHEDULE_KEY = "admin:maintenance:schedule"
    MAINTENANCE_MESSAGE_KEY = "admin:maintenance:message"
    
    # Default maintenance message
    DEFAULT_MESSAGE = "System is currently under maintenance. Please try again later."
    
    @staticmethod
    def get_redis_client():
        """Get Redis client from Flask app"""
        if hasattr(current_app, 'redis') and current_app.redis:
            return current_app.redis
        return None
    
    @classmethod
    def is_maintenance_active(cls) -> bool:
        """Check if maintenance mode is currently active"""
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return False
            
            # Check immediate maintenance mode
            status = redis_client.get(cls.MAINTENANCE_STATUS_KEY)
            if status and json.loads(status).get('active', False):
                return True
            
            # Check scheduled maintenance
            schedule = redis_client.get(cls.MAINTENANCE_SCHEDULE_KEY)
            if schedule:
                schedule_data = json.loads(schedule)
                if cls._is_scheduled_maintenance_active(schedule_data):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking maintenance status: {e}")
            return False
    
    @classmethod
    def _is_scheduled_maintenance_active(cls, schedule_data: Dict) -> bool:
        """Check if scheduled maintenance is currently active"""
        try:
            if not schedule_data.get('enabled', False):
                return False
            
            start_time_str = schedule_data.get('start_time')
            end_time_str = schedule_data.get('end_time')
            
            if not start_time_str or not end_time_str:
                return False
            
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.fromisoformat(end_time_str)
            current_time = datetime.utcnow()
            
            return start_time <= current_time <= end_time
            
        except Exception as e:
            logger.error(f"Error checking scheduled maintenance: {e}")
            return False
    
    @classmethod
    def enable_maintenance(cls, message: str = None, user: str = None) -> bool:
        """Enable immediate maintenance mode"""
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return False
            
            maintenance_data = {
                'active': True,
                'enabled_at': datetime.utcnow().isoformat(),
                'enabled_by': user or 'unknown',
                'message': message or cls.DEFAULT_MESSAGE,
                'type': 'immediate'
            }
            
            redis_client.set(
                cls.MAINTENANCE_STATUS_KEY,
                json.dumps(maintenance_data)
            )
            
            # Store custom message if provided
            if message:
                redis_client.set(cls.MAINTENANCE_MESSAGE_KEY, message)
            
            logger.info(f"Maintenance mode enabled by {user}")
            return True
            
        except Exception as e:
            logger.error(f"Error enabling maintenance mode: {e}")
            return False
    
    @classmethod
    def disable_maintenance(cls, user: str = None) -> bool:
        """Disable maintenance mode"""
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return False
            
            maintenance_data = {
                'active': False,
                'disabled_at': datetime.utcnow().isoformat(),
                'disabled_by': user or 'unknown',
                'type': 'immediate'
            }
            
            redis_client.set(
                cls.MAINTENANCE_STATUS_KEY,
                json.dumps(maintenance_data)
            )
            
            logger.info(f"Maintenance mode disabled by {user}")
            return True
            
        except Exception as e:
            logger.error(f"Error disabling maintenance mode: {e}")
            return False
    
    @classmethod
    def schedule_maintenance(cls, start_time: datetime, end_time: datetime, 
                           message: str = None, user: str = None) -> bool:
        """Schedule maintenance for a specific time window"""
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return False
            
            # Validate times
            if start_time >= end_time:
                raise ValueError("Start time must be before end time")
            
            if start_time <= datetime.utcnow():
                raise ValueError("Start time must be in the future")
            
            schedule_data = {
                'enabled': True,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'message': message or cls.DEFAULT_MESSAGE,
                'scheduled_by': user or 'unknown',
                'scheduled_at': datetime.utcnow().isoformat(),
                'type': 'scheduled'
            }
            
            redis_client.set(
                cls.MAINTENANCE_SCHEDULE_KEY,
                json.dumps(schedule_data)
            )
            
            logger.info(f"Maintenance scheduled from {start_time} to {end_time} by {user}")
            return True
            
        except Exception as e:
            logger.error(f"Error scheduling maintenance: {e}")
            return False
    
    @classmethod
    def cancel_scheduled_maintenance(cls, user: str = None) -> bool:
        """Cancel scheduled maintenance"""
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return False
            
            # Get current schedule
            schedule = redis_client.get(cls.MAINTENANCE_SCHEDULE_KEY)
            if schedule:
                schedule_data = json.loads(schedule)
                schedule_data['enabled'] = False
                schedule_data['cancelled_by'] = user or 'unknown'
                schedule_data['cancelled_at'] = datetime.utcnow().isoformat()
                
                redis_client.set(
                    cls.MAINTENANCE_SCHEDULE_KEY,
                    json.dumps(schedule_data)
                )
            
            logger.info(f"Scheduled maintenance cancelled by {user}")
            return True
            
        except Exception as e:
            logger.error(f"Error cancelling scheduled maintenance: {e}")
            return False
    
    @classmethod
    def get_maintenance_status(cls) -> Dict:
        """Get current maintenance status and schedule information"""
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return {
                    'active': False,
                    'type': 'none',
                    'message': cls.DEFAULT_MESSAGE,
                    'schedule': None
                }
            
            status = {
                'active': False,
                'type': 'none',
                'message': cls.DEFAULT_MESSAGE,
                'schedule': None,
                'immediate': None
            }
            
            # Check immediate maintenance
            immediate_status = redis_client.get(cls.MAINTENANCE_STATUS_KEY)
            if immediate_status:
                immediate_data = json.loads(immediate_status)
                status['immediate'] = immediate_data
                if immediate_data.get('active', False):
                    status['active'] = True
                    status['type'] = 'immediate'
                    status['message'] = immediate_data.get('message', cls.DEFAULT_MESSAGE)
            
            # Check scheduled maintenance
            schedule_data = redis_client.get(cls.MAINTENANCE_SCHEDULE_KEY)
            if schedule_data:
                schedule = json.loads(schedule_data)
                status['schedule'] = schedule
                
                if cls._is_scheduled_maintenance_active(schedule):
                    status['active'] = True
                    status['type'] = 'scheduled'
                    status['message'] = schedule.get('message', cls.DEFAULT_MESSAGE)
            
            # Add countdown information
            if status['schedule'] and status['schedule'].get('enabled', False):
                start_time = datetime.fromisoformat(status['schedule']['start_time'])
                end_time = datetime.fromisoformat(status['schedule']['end_time'])
                current_time = datetime.utcnow()
                
                if current_time < start_time:
                    # Maintenance is scheduled but not started
                    status['countdown'] = {
                        'type': 'until_start',
                        'seconds': int((start_time - current_time).total_seconds()),
                        'message': f"Maintenance starts in {cls._format_duration(start_time - current_time)}"
                    }
                elif current_time <= end_time:
                    # Maintenance is active
                    status['countdown'] = {
                        'type': 'until_end',
                        'seconds': int((end_time - current_time).total_seconds()),
                        'message': f"Maintenance ends in {cls._format_duration(end_time - current_time)}"
                    }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting maintenance status: {e}")
            return {
                'active': False,
                'type': 'error',
                'message': 'Error checking maintenance status',
                'error': str(e)
            }
    
    @classmethod
    def _format_duration(cls, duration: timedelta) -> str:
        """Format duration for display"""
        total_seconds = int(duration.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    @classmethod
    def get_maintenance_message(cls) -> str:
        """Get the current maintenance message"""
        try:
            status = cls.get_maintenance_status()
            return status.get('message', cls.DEFAULT_MESSAGE)
        except Exception as e:
            logger.error(f"Error getting maintenance message: {e}")
            return cls.DEFAULT_MESSAGE
    
    @classmethod
    def is_admin_request(cls) -> bool:
        """Check if the current request is from admin panel"""
        try:
            return request.path.startswith('/admin')
        except:
            return False


def maintenance_required(f):
    """Decorator to check maintenance mode for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip maintenance check for admin requests
        if MaintenanceMode.is_admin_request():
            return f(*args, **kwargs)
        
        # Check if maintenance mode is active
        if MaintenanceMode.is_maintenance_active():
            status = MaintenanceMode.get_maintenance_status()
            
            # Return JSON response for API endpoints
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({
                    'status': 'maintenance',
                    'message': status.get('message', MaintenanceMode.DEFAULT_MESSAGE),
                    'type': status.get('type', 'unknown'),
                    'countdown': status.get('countdown')
                }), 503
            
            # Return HTML page for regular requests
            return render_template('maintenance.html', 
                                 maintenance_status=status), 503
        
        return f(*args, **kwargs)
    
    return decorated_function


class MaintenanceMiddleware:
    """Middleware to handle maintenance mode for all requests"""
    
    def __init__(self, app):
        self.app = app
        self.init_app(app)
    
    def init_app(self, app):
        """Initialize maintenance middleware with Flask app"""
        app.before_request(self.before_request)
    
    def before_request(self):
        """Check maintenance mode before each request"""
        # Skip maintenance check for admin requests
        if MaintenanceMode.is_admin_request():
            return None
        
        # Skip maintenance check for static files
        if request.path.startswith('/static/'):
            return None
        
        # Check if maintenance mode is active
        if MaintenanceMode.is_maintenance_active():
            status = MaintenanceMode.get_maintenance_status()
            
            # Return JSON response for API endpoints
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({
                    'status': 'maintenance',
                    'message': status.get('message', MaintenanceMode.DEFAULT_MESSAGE),
                    'type': status.get('type', 'unknown'),
                    'countdown': status.get('countdown')
                }), 503
            
            # Return HTML page for regular requests
            try:
                return render_template('maintenance.html', 
                                     maintenance_status=status), 503
            except Exception as e:
                logger.error(f"Error rendering maintenance template: {e}")
                # Fallback to simple HTML response
                return f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>System Maintenance</title>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                        .maintenance {{ max-width: 600px; margin: 0 auto; }}
                        h1 {{ color: #e74c3c; }}
                        p {{ color: #666; font-size: 18px; }}
                    </style>
                </head>
                <body>
                    <div class="maintenance">
                        <h1>System Under Maintenance</h1>
                        <p>{status.get('message', MaintenanceMode.DEFAULT_MESSAGE)}</p>
                        {f"<p><strong>{status['countdown']['message']}</strong></p>" if status.get('countdown') else ""}
                    </div>
                </body>
                </html>
                """, 503
        
        return None


def init_maintenance_mode(app):
    """Initialize maintenance mode for the Flask app"""
    try:
        # Initialize middleware
        MaintenanceMiddleware(app)
        
        logger.info("Maintenance mode initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing maintenance mode: {e}")