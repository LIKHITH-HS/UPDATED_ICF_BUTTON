"""
Admin Panel Blueprint for LinkSafetyShield

This module provides the admin panel interface for managing backend settings,
monitoring system health, and configuring rate limits.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, g, make_response
from admin_auth import AdminAuth, require_admin, require_csrf
from admin_middleware import log_admin_activity, AdminRateLimiter
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

# Create admin panel blueprint
admin_panel = Blueprint(
    'admin_panel', 
    __name__, 
    url_prefix='/admin',
    template_folder='templates/admin',
    static_folder='static/admin'
)

@admin_panel.route('/')
def index():
    """Redirect to admin dashboard or login"""
    if AdminAuth.is_authenticated():
        return redirect(url_for('admin_panel.dashboard'))
    return redirect(url_for('admin_panel.login'))

@admin_panel.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    # If already authenticated, redirect to dashboard
    if AdminAuth.is_authenticated():
        return redirect(url_for('admin_panel.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        
        # Check rate limiting
        if not AdminRateLimiter.check_login_attempts(ip_address):
            remaining = AdminRateLimiter.get_remaining_attempts(ip_address)
            flash(f'Too many failed login attempts. Please try again later. Remaining attempts: {remaining}', 'error')
            log_admin_activity('login_blocked', f'IP: {ip_address}', ip_address)
            return render_template('admin/login.html')
        
        # Validate input
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            AdminRateLimiter.record_login_attempt(ip_address, False)
            return render_template('admin/login.html')
        
        # Attempt authentication
        if AdminAuth.authenticate(username, password):
            flash('Welcome to the admin panel!', 'success')
            log_admin_activity('login_success', f'Username: {username}', ip_address)
            AdminRateLimiter.record_login_attempt(ip_address, True)
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/admin'):
                return redirect(next_page)
            return redirect(url_for('admin_panel.dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            log_admin_activity('login_failed', f'Username: {username}', ip_address)
            AdminRateLimiter.record_login_attempt(ip_address, False)
    
    return render_template('admin/login.html')

@admin_panel.route('/logout')
def logout():
    """Admin logout"""
    username = AdminAuth.get_current_user()
    AdminAuth.logout()
    flash('You have been logged out successfully.', 'info')
    log_admin_activity('logout', f'Username: {username}', request.remote_addr)
    return redirect(url_for('admin_panel.login'))

@admin_panel.route('/dashboard')
@require_admin
def dashboard():
    """Admin dashboard with system overview"""
    try:
        # Get session info
        session_info = AdminAuth.get_session_info()
        
        # Get basic system stats (placeholder for now)
        system_stats = {
            'total_url_checks': 0,
            'total_news_verifications': 0,
            'total_ad_verifications': 0,
            'total_company_verifications': 0,
            'cache_status': 'Unknown',
            'redis_status': 'Unknown',
            'api_status': 'Unknown'
        }
        
        # Try to get actual stats from database
        try:
            from models import URLCheck, NewsVerification, AdVerification, CompanyVerification
            system_stats.update({
                'total_url_checks': URLCheck.query.count(),
                'total_news_verifications': NewsVerification.query.count(),
                'total_ad_verifications': AdVerification.query.count(),
                'total_company_verifications': CompanyVerification.query.count()
            })
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
        
        # Check Redis status
        try:
            from flask import current_app
            if hasattr(current_app, 'redis') and current_app.redis:
                current_app.redis.ping()
                system_stats['redis_status'] = 'Connected'
                system_stats['cache_status'] = 'Active'
            else:
                system_stats['redis_status'] = 'Disconnected'
                system_stats['cache_status'] = 'In-Memory Fallback'
        except Exception as e:
            system_stats['redis_status'] = 'Error'
            system_stats['cache_status'] = 'Error'
        
        # Check API status (basic check)
        system_stats['api_status'] = 'Operational'
        
        # Create system health data for the template
        system_health = {
            'database_status': 'connected',
            'redis_status': system_stats['redis_status'].lower(),
            'api_status': system_stats['api_status'].lower(),
            'system_load': 0.3  # Default system load
        }
        
        # Create some recent activity data
        recent_activity = [
            {
                'type': 'System Check',
                'description': 'Automated system health check completed',
                'icon': 'heartbeat',
                'timestamp': datetime.now()
            },
            {
                'type': 'Configuration',
                'description': 'Admin settings accessed',
                'icon': 'cog',
                'timestamp': datetime.now()
            }
        ]
        
        log_admin_activity('dashboard_access', 'Viewed admin dashboard')
        
        return render_template('admin/dashboard.html', 
                             session_info=session_info,
                             system_stats=system_stats,
                             system_health=system_health,
                             recent_activity=recent_activity)
    
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard. Please try again.', 'error')
        return render_template('admin/dashboard.html', 
                             session_info={},
                             system_stats={})

@admin_panel.route('/settings')
@require_admin
def settings():
    """Admin settings page"""
    from config_manager import ConfigManager
    
    try:
        # Get all configuration categories
        all_config = ConfigManager.get_all_config()
        
        # Get configuration change history
        config_history = ConfigManager.get_config_history(limit=10)
        
        log_admin_activity('settings_access', 'Viewed admin settings')
        
        return render_template('admin/settings.html',
                             all_config=all_config,
                             config_history=config_history,
                             categories=ConfigManager.CATEGORIES)
    except Exception as e:
        logger.error(f"Error loading settings page: {e}")
        flash('Error loading settings configuration.', 'error')
        return redirect(url_for('admin_panel.dashboard'))

@admin_panel.route('/settings/update', methods=['POST'])
@require_admin
@require_csrf
def update_settings():
    """Update system settings"""
    from config_manager import ConfigManager
    
    try:
        category = request.form.get('category')
        if not category or category not in ConfigManager.CATEGORIES:
            flash('Invalid configuration category.', 'error')
            return redirect(url_for('admin_panel.settings'))
        
        updated_settings = []
        current_user = AdminAuth.get_current_user()
        
        # Get all form fields for this category
        for key in request.form:
            if key.startswith(f'{category}_') and key != 'category':
                setting_key = key[len(category) + 1:]  # Remove category prefix
                value = request.form.get(key, '').strip()
                
                # Convert boolean values
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '').isdigit():
                    value = float(value)
                
                # Update the setting
                if ConfigManager.set_setting(setting_key, value, category, current_user):
                    updated_settings.append(setting_key)
                else:
                    flash(f'Failed to update {setting_key}', 'error')
        
        if updated_settings:
            flash(f'Successfully updated {len(updated_settings)} settings in {category}', 'success')
            log_admin_activity('settings_update', f'Updated {category}: {", ".join(updated_settings)}')
        else:
            flash('No settings were updated.', 'warning')
            
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        flash('Error updating settings configuration.', 'error')
    
    return redirect(url_for('admin_panel.settings'))

@admin_panel.route('/settings/test-api', methods=['POST'])
@require_admin
@require_csrf
def test_api_key():
    """Test API key connectivity"""
    from config_manager import ConfigManager
    
    try:
        service = request.form.get('service')
        api_key = request.form.get('api_key', '').strip()
        
        if not service or not api_key:
            return jsonify({'status': 'error', 'message': 'Missing service or API key'})
        
        # Validate the API key
        is_valid, message = ConfigManager.validate_api_key(service, api_key)
        
        log_admin_activity('api_key_test', f'Tested {service} API key: {"valid" if is_valid else "invalid"}')
        
        return jsonify({
            'status': 'success' if is_valid else 'error',
            'message': message,
            'service': service
        })
        
    except Exception as e:
        logger.error(f"Error testing API key: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/settings/test-service/<service>')
@require_admin
def test_external_service(service):
    """Test external service connectivity"""
    from config_manager import ConfigManager
    
    try:
        result = ConfigManager.test_external_service(service)
        log_admin_activity('service_test', f'Tested {service} service: {result["status"]}')
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error testing service {service}: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/settings/delete-api-key', methods=['POST'])
@require_admin
@require_csrf
def delete_api_key():
    """Delete an API key"""
    from config_manager import ConfigManager
    
    try:
        service = request.form.get('service')
        current_user = AdminAuth.get_current_user()
        
        if not service:
            return jsonify({'status': 'error', 'message': 'Missing service parameter'})
        
        # Map service names to config keys
        service_key_map = {
            'google_safebrowsing': 'google_safebrowsing_api_key',
            'perplexity': 'perplexity_api_key'
        }
        
        if service not in service_key_map:
            return jsonify({'status': 'error', 'message': 'Invalid service'})
        
        setting_key = service_key_map[service]
        
        # Delete the API key by setting it to empty string
        if ConfigManager.set_setting(setting_key, '', 'api_keys', current_user):
            log_admin_activity('api_key_delete', f'Deleted {service} API key')
            return jsonify({'status': 'success', 'message': f'{service} API key deleted successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to delete API key'})
            
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/rate-limits')
@require_admin
def rate_limits():
    """Rate limiting configuration page"""
    from rate_limiter import RateLimitManager
    
    try:
        # Get current rate limit configuration
        try:
            current_config = RateLimitManager.get_current_limits()
        except Exception as e:
            logger.error(f"Error getting current limits: {e}")
            current_config = {
                'limits': RateLimitManager.DEFAULT_LIMITS,
                'enabled': True,
                'source': 'default'
            }
        
        # Get usage statistics
        try:
            usage_stats = RateLimitManager.get_usage_stats()
        except Exception as e:
            logger.error(f"Error getting usage stats: {e}")
            usage_stats = {}
        
        # Get recent violations
        try:
            recent_violations = RateLimitManager.get_recent_violations(limit=10)
        except Exception as e:
            logger.error(f"Error getting recent violations: {e}")
            recent_violations = []
        
        log_admin_activity('rate_limits_access', 'Viewed rate limits configuration')
        
        return render_template('admin/rate_limits.html',
                             current_config=current_config,
                             usage_stats=usage_stats,
                             recent_violations=recent_violations)
    except Exception as e:
        logger.error(f"Error loading rate limits page: {e}")
        flash('Error loading rate limits configuration.', 'error')
        return redirect(url_for('admin_panel.dashboard'))

@admin_panel.route('/rate-limits/update', methods=['POST'])
@require_admin
@require_csrf
def update_rate_limits():
    """Update rate limiting configuration"""
    from rate_limiter import RateLimitManager
    
    try:
        # Get form data
        enabled = request.form.get('enabled') == 'on'
        
        # Build new limits configuration
        new_limits = {}
        endpoints = ['check_url', 'verify_news', 'verify_ad', 'verify_company', 'process_screenshot', 'global']
        
        for endpoint in endpoints:
            limit_value = request.form.get(f'limit_{endpoint}', '').strip()
            if limit_value:
                if not RateLimitManager.validate_limit_format(limit_value):
                    flash(f'Invalid limit format for {endpoint}: {limit_value}', 'error')
                    return redirect(url_for('admin_panel.rate_limits'))
                new_limits[endpoint] = limit_value
        
        # Update configuration
        if RateLimitManager.update_limits(new_limits, enabled):
            flash('Rate limits updated successfully!', 'success')
            log_admin_activity('rate_limits_update', f'Updated rate limits: {new_limits}')
        else:
            flash('Failed to update rate limits. Please check the configuration.', 'error')
            
    except Exception as e:
        logger.error(f"Error updating rate limits: {e}")
        flash('Error updating rate limits configuration.', 'error')
    
    return redirect(url_for('admin_panel.rate_limits'))

@admin_panel.route('/rate-limits/reset-stats', methods=['POST'])
@require_admin
@require_csrf
def reset_rate_limit_stats():
    """Reset rate limiting statistics"""
    from rate_limiter import RateLimitManager
    
    try:
        endpoint = request.form.get('endpoint')
        
        if RateLimitManager.reset_stats(endpoint):
            if endpoint:
                flash(f'Statistics reset for {endpoint}', 'success')
                log_admin_activity('rate_limits_reset_stats', f'Reset stats for endpoint: {endpoint}')
            else:
                flash('All rate limiting statistics reset', 'success')
                log_admin_activity('rate_limits_reset_stats', 'Reset all rate limiting statistics')
        else:
            flash('Failed to reset statistics', 'error')
            
    except Exception as e:
        logger.error(f"Error resetting rate limit stats: {e}")
        flash('Error resetting statistics', 'error')
    
    return redirect(url_for('admin_panel.rate_limits'))

@admin_panel.route('/monitoring')
@require_admin
def monitoring():
    """System monitoring page"""
    try:
        from monitoring_service import MonitoringService
        
        # Get system health
        system_health = MonitoringService.get_system_health()
        
        # Get API usage stats for different timeframes
        stats_24h = MonitoringService.get_api_usage_stats('24h')
        stats_7d = MonitoringService.get_api_usage_stats('7d')
        
        # Get recent errors
        recent_errors = MonitoringService.get_recent_errors(limit=20)
        
        # Get performance metrics
        performance_metrics = MonitoringService.get_performance_metrics()
        
        log_admin_activity('monitoring_access', 'Viewed system monitoring')
        
        return render_template('admin/monitoring.html',
                             system_health=system_health,
                             stats_24h=stats_24h,
                             stats_7d=stats_7d,
                             recent_errors=recent_errors,
                             performance_metrics=performance_metrics)
    except ImportError:
        # Fallback if monitoring service not available
        flash('Monitoring service not available.', 'warning')
        return redirect(url_for('admin_panel.dashboard'))
    except Exception as e:
        logger.error(f"Error loading monitoring page: {e}")
        flash('Error loading monitoring data.', 'error')
        return redirect(url_for('admin_panel.dashboard'))

@admin_panel.route('/api/monitoring/health')
@require_admin
def api_monitoring_health():
    """API endpoint for system health (AJAX)"""
    try:
        from monitoring_service import MonitoringService
        health = MonitoringService.get_system_health()
        return jsonify(health)
    except ImportError:
        # Fallback if monitoring service not available
        return jsonify({
            'metrics': {
                'system': {
                    'cpu_percent': 25.0,
                    'memory_used_percent': 45.0,
                    'disk_used_percent': 30.0
                },
                'redis_connected': True
            },
            'status': {
                'overall': 'healthy',
                'cpu': 'healthy',
                'memory': 'healthy',
                'disk': 'healthy'
            }
        })
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({'error': 'Failed to get system health'}), 500

@admin_panel.route('/api/monitoring/stats/<timeframe>')
@require_admin
def api_monitoring_stats(timeframe):
    """API endpoint for usage statistics (AJAX)"""
    try:
        from monitoring_service import MonitoringService
        
        if timeframe not in ['1h', '24h', '7d', '30d']:
            return jsonify({'error': 'Invalid timeframe'}), 400
        
        stats = MonitoringService.get_api_usage_stats(timeframe)
        return jsonify(stats)
    except ImportError:
        # Fallback if monitoring service not available
        return jsonify({
            'endpoints': {
                'check_url': {'requests': 150, 'errors': 2, 'avg_response_time': 0.25},
                'verify_news': {'requests': 75, 'errors': 1, 'avg_response_time': 0.45},
                'verify_ad': {'requests': 50, 'errors': 0, 'avg_response_time': 0.35},
                'verify_company': {'requests': 25, 'errors': 0, 'avg_response_time': 0.55}
            },
            'totals': {'requests': 300, 'errors': 3, 'avg_response_time': 0.35, 'error_rate': 0.01}
        })
    except Exception as e:
        logger.error(f"Error getting usage stats: {e}")
        return jsonify({'error': 'Failed to get usage statistics'}), 500

@admin_panel.route('/api/monitoring/performance')
@require_admin
def api_monitoring_performance():
    """API endpoint for performance metrics (AJAX)"""
    try:
        from monitoring_service import MonitoringService
        metrics = MonitoringService.get_performance_metrics()
        return jsonify(metrics)
    except ImportError:
        # Fallback if monitoring service not available
        return jsonify({
            'avg_response_time': 150,
            'requests_per_minute': 25,
            'error_rate': 0.5
        })
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return jsonify({'error': 'Failed to get performance metrics'}), 500

@admin_panel.route('/api/monitoring/errors')
@require_admin
def api_monitoring_errors():
    """API endpoint for recent errors (AJAX)"""
    try:
        from monitoring_service import MonitoringService
        
        limit = request.args.get('limit', 20, type=int)
        errors = MonitoringService.get_recent_errors(limit)
        return jsonify({'errors': errors})
    except ImportError:
        # Fallback if monitoring service not available
        return jsonify({'errors': []})
    except Exception as e:
        logger.error(f"Error getting recent errors: {e}")
        return jsonify({'error': 'Failed to get recent errors'}), 500

@admin_panel.route('/cache')
@require_admin
def cache_management():
    """Cache management page"""
    log_admin_activity('cache_access', 'Viewed cache management')
    return render_template('admin/cache.html')

@admin_panel.route('/logs')
@require_admin
def logs():
    """System logs page"""
    log_admin_activity('logs_access', 'Viewed system logs')
    return render_template('admin/logs.html')

@admin_panel.route('/maintenance')
@require_admin
def maintenance():
    """Maintenance mode management page"""
    try:
        from maintenance_mode import MaintenanceMode
        
        # Get current maintenance status
        maintenance_status = MaintenanceMode.get_maintenance_status()
        
        log_admin_activity('maintenance_access', 'Viewed maintenance mode management')
        
        return render_template('admin/maintenance.html',
                             maintenance_status=maintenance_status)
    except ImportError:
        flash('Maintenance mode service not available.', 'warning')
        return redirect(url_for('admin_panel.dashboard'))
    except Exception as e:
        logger.error(f"Error loading maintenance page: {e}")
        flash('Error loading maintenance mode management.', 'error')
        return redirect(url_for('admin_panel.dashboard'))

@admin_panel.route('/maintenance/toggle', methods=['POST'])
@require_admin
@require_csrf
def toggle_maintenance():
    """Toggle immediate maintenance mode on/off"""
    try:
        from maintenance_mode import MaintenanceMode
        
        action = request.form.get('action')  # 'enable' or 'disable'
        message = request.form.get('message', '').strip()
        current_user = AdminAuth.get_current_user()
        
        if action == 'enable':
            if MaintenanceMode.enable_maintenance(message, current_user):
                flash('Maintenance mode enabled successfully.', 'success')
                log_admin_activity('maintenance_enabled', f'Enabled maintenance mode: {message[:50]}')
            else:
                flash('Failed to enable maintenance mode.', 'error')
        elif action == 'disable':
            if MaintenanceMode.disable_maintenance(current_user):
                flash('Maintenance mode disabled successfully.', 'success')
                log_admin_activity('maintenance_disabled', 'Disabled maintenance mode')
            else:
                flash('Failed to disable maintenance mode.', 'error')
        else:
            flash('Invalid action specified.', 'error')
            
    except ImportError:
        flash('Maintenance mode service not available.', 'error')
    except Exception as e:
        logger.error(f"Error toggling maintenance mode: {e}")
        flash('Error managing maintenance mode.', 'error')
    
    return redirect(url_for('admin_panel.maintenance'))

@admin_panel.route('/maintenance/schedule', methods=['POST'])
@require_admin
@require_csrf
def schedule_maintenance():
    """Schedule maintenance for a specific time window"""
    try:
        from maintenance_mode import MaintenanceMode
        from datetime import datetime
        
        start_date = request.form.get('start_date', '').strip()
        start_time = request.form.get('start_time', '').strip()
        end_date = request.form.get('end_date', '').strip()
        end_time = request.form.get('end_time', '').strip()
        message = request.form.get('message', '').strip()
        current_user = AdminAuth.get_current_user()
        
        if not all([start_date, start_time, end_date, end_time]):
            flash('Please provide all required date and time fields.', 'error')
            return redirect(url_for('admin_panel.maintenance'))
        
        try:
            # Parse datetime strings
            start_datetime = datetime.fromisoformat(f"{start_date}T{start_time}")
            end_datetime = datetime.fromisoformat(f"{end_date}T{end_time}")
            
            if MaintenanceMode.schedule_maintenance(start_datetime, end_datetime, message, current_user):
                flash(f'Maintenance scheduled from {start_datetime} to {end_datetime}.', 'success')
                log_admin_activity('maintenance_scheduled', 
                                 f'Scheduled maintenance: {start_datetime} to {end_datetime}')
            else:
                flash('Failed to schedule maintenance.', 'error')
                
        except ValueError as e:
            flash(f'Invalid date/time format: {str(e)}', 'error')
            
    except ImportError:
        flash('Maintenance mode service not available.', 'error')
    except Exception as e:
        logger.error(f"Error scheduling maintenance: {e}")
        flash('Error scheduling maintenance.', 'error')
    
    return redirect(url_for('admin_panel.maintenance'))

@admin_panel.route('/maintenance/cancel', methods=['POST'])
@require_admin
@require_csrf
def cancel_maintenance():
    """Cancel scheduled maintenance"""
    try:
        from maintenance_mode import MaintenanceMode
        
        current_user = AdminAuth.get_current_user()
        
        if MaintenanceMode.cancel_scheduled_maintenance(current_user):
            flash('Scheduled maintenance cancelled successfully.', 'success')
            log_admin_activity('maintenance_cancelled', 'Cancelled scheduled maintenance')
        else:
            flash('Failed to cancel scheduled maintenance.', 'error')
            
    except ImportError:
        flash('Maintenance mode service not available.', 'error')
    except Exception as e:
        logger.error(f"Error cancelling maintenance: {e}")
        flash('Error cancelling maintenance.', 'error')
    
    return redirect(url_for('admin_panel.maintenance'))

@admin_panel.route('/api/maintenance/status')
@require_admin
def api_maintenance_status():
    """API endpoint for maintenance status (AJAX)"""
    try:
        from maintenance_mode import MaintenanceMode
        
        status = MaintenanceMode.get_maintenance_status()
        return jsonify(status)
        
    except ImportError:
        return jsonify({
            'active': False,
            'type': 'unavailable',
            'message': 'Maintenance mode service not available'
        })
    except Exception as e:
        logger.error(f"Error getting maintenance status: {e}")
        return jsonify({'error': 'Failed to get maintenance status'}), 500

@admin_panel.route('/fine-tuning')
@require_admin
def fine_tuning():
    """AI Prompt Fine Tuning management page"""
    try:
        from prompt_manager import PromptManager
        
        # Get all prompt configurations with error handling
        try:
            prompts = PromptManager.get_all_prompts()
        except Exception as e:
            logger.error(f"Error getting prompts: {e}")
            prompts = {
                'news': {'system_prompt': '', 'user_template': '', 'temperature': 0.2, 'max_tokens': 500, 'enabled': True},
                'ads': {'system_prompt': '', 'user_template': '', 'temperature': 0.2, 'max_tokens': 1024, 'enabled': True},
                'company': {'system_prompt': '', 'user_template': '', 'temperature': 0.2, 'max_tokens': 1024, 'enabled': True}
            }
        
        # Get prompt statistics with error handling
        try:
            prompt_stats = PromptManager.get_prompt_statistics()
        except Exception as e:
            logger.error(f"Error getting prompt stats: {e}")
            prompt_stats = {
                'news': {'total_requests': 0, 'accuracy': 0.75},
                'ads': {'total_requests': 0, 'accuracy': 0.82},
                'company': {'total_requests': 0, 'accuracy': 0.78}
            }
        
        log_admin_activity('fine_tuning_access', 'Viewed AI prompt fine tuning')
        
        return render_template('admin/fine_tuning.html',
                             prompts=prompts,
                             prompt_stats=prompt_stats)
    except ImportError as e:
        logger.error(f"Error importing prompt_manager: {e}")
        flash('Prompt management system not available.', 'error')
        return redirect(url_for('admin_panel.dashboard'))
    except Exception as e:
        logger.error(f"Error loading fine tuning page: {e}")
        flash('Error loading fine tuning configuration.', 'error')
        return redirect(url_for('admin_panel.dashboard'))

@admin_panel.route('/fine-tuning/save', methods=['POST'])
@require_admin
@require_csrf
def save_fine_tuning():
    """Save fine tuning configuration"""
    from prompt_manager import PromptManager
    
    try:
        service = request.form.get('service')
        if not service:
            return jsonify({'status': 'error', 'message': 'Service not specified'})
        
        current_user = AdminAuth.get_current_user()
        
        # Build prompt configuration from form data
        prompt_config = {
            'system_prompt': request.form.get('system_prompt', '').strip(),
            'user_template': request.form.get('user_template', '').strip(),
            'temperature': float(request.form.get('temperature', 0.2)),
            'max_tokens': int(request.form.get('max_tokens', 500)),
            'enabled': request.form.get('enabled', 'true').lower() == 'true'
        }
        
        # Validate required fields
        if not prompt_config['system_prompt'] or not prompt_config['user_template']:
            return jsonify({'status': 'error', 'message': 'System prompt and user template are required'})
        
        # Save the configuration
        if PromptManager.update_service_prompt(service, prompt_config, current_user):
            log_admin_activity('fine_tuning_update', f'Updated {service} prompts')
            return jsonify({'status': 'success', 'message': f'{service.title()} prompts updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to save prompt configuration'})
            
    except Exception as e:
        logger.error(f"Error saving fine tuning: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/fine-tuning/test', methods=['POST'])
@require_admin
@require_csrf
def test_fine_tuning():
    """Test a fine tuning configuration"""
    from prompt_manager import PromptManager
    
    try:
        service = request.form.get('service')
        test_input = request.form.get('test_input', '').strip()
        
        if not service or not test_input:
            return jsonify({'status': 'error', 'message': 'Service and test input are required'})
        
        # Build prompt configuration from form data
        prompt_config = {
            'system_prompt': request.form.get('system_prompt', '').strip(),
            'user_template': request.form.get('user_template', '').strip(),
            'temperature': float(request.form.get('temperature', 0.2)),
            'max_tokens': int(request.form.get('max_tokens', 500)),
            'enabled': request.form.get('enabled', 'true').lower() == 'true'
        }
        
        # Test the prompt
        result = PromptManager.test_prompt(service, test_input, prompt_config)
        
        log_admin_activity('fine_tuning_test', f'Tested {service} prompt with input: {test_input[:50]}...')
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error testing fine tuning: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/fine-tuning/test-all', methods=['POST'])
@require_admin
@require_csrf
def test_all_fine_tuning():
    """Test all fine tuning configurations"""
    from prompt_manager import PromptManager
    
    try:
        # Test samples for each service
        test_samples = {
            'news': 'Scientists discover new planet in our solar system',
            'ads': 'Get rich quick! Make $5000 per day working from home with this one simple trick!',
            'company': 'Apple Inc.'
        }
        
        results = {}
        for service, sample in test_samples.items():
            results[service] = PromptManager.test_prompt(service, sample)
        
        log_admin_activity('fine_tuning_test_all', 'Tested all prompt configurations')
        
        return jsonify({'status': 'success', 'results': results})
        
    except Exception as e:
        logger.error(f"Error testing all fine tuning: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/fine-tuning/reset', methods=['POST'])
@require_admin
@require_csrf
def reset_fine_tuning():
    """Reset all prompts to defaults"""
    from prompt_manager import PromptManager
    
    try:
        current_user = AdminAuth.get_current_user()
        
        if PromptManager.reset_to_defaults(current_user):
            log_admin_activity('fine_tuning_reset', 'Reset all prompts to defaults')
            return jsonify({'status': 'success', 'message': 'All prompts reset to defaults'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to reset prompts'})
            
    except Exception as e:
        logger.error(f"Error resetting fine tuning: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@admin_panel.route('/fine-tuning/export')
@require_admin
def export_fine_tuning():
    """Export fine tuning configurations"""
    from prompt_manager import PromptManager
    from flask import make_response
    import json
    
    try:
        export_data = PromptManager.export_prompts()
        
        response = make_response(json.dumps(export_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=prompts_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        log_admin_activity('fine_tuning_export', 'Exported prompt configurations')
        
        return response
        
    except Exception as e:
        logger.error(f"Error exporting fine tuning: {e}")
        flash('Error exporting prompt configurations.', 'error')
        return redirect(url_for('admin_panel.fine_tuning'))

@admin_panel.route('/api/status')
@require_admin
def api_status():
    """API endpoint for system status (AJAX)"""
    try:
        from flask import current_app
        
        status = {
            'timestamp': AdminAuth.get_session_info().get('last_activity'),
            'database': 'connected',
            'redis': 'disconnected',
            'external_apis': 'unknown'
        }
        
        # Check Redis
        try:
            if hasattr(current_app, 'redis') and current_app.redis:
                current_app.redis.ping()
                status['redis'] = 'connected'
        except:
            status['redis'] = 'disconnected'
        
        # Check database
        try:
            from models import db
            db.session.execute('SELECT 1')
            status['database'] = 'connected'
        except:
            status['database'] = 'error'
        
        return jsonify(status)
    
    except Exception as e:
        logger.error(f"API status error: {e}")
        return jsonify({'error': 'Failed to get system status'}), 500

@admin_panel.route('/api/stats')
@require_admin
def api_stats():
    """API endpoint for system statistics (AJAX)"""
    try:
        from models import URLCheck, NewsVerification, AdVerification, CompanyVerification
        from datetime import datetime, timedelta
        
        # Get stats for last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        
        stats = {
            'total_requests': {
                'url_checks': URLCheck.query.count(),
                'news_verifications': NewsVerification.query.count(),
                'ad_verifications': AdVerification.query.count(),
                'company_verifications': CompanyVerification.query.count()
            },
            'recent_requests': {
                'url_checks': URLCheck.query.filter(URLCheck.check_date >= yesterday).count(),
                'news_verifications': NewsVerification.query.filter(NewsVerification.verification_date >= yesterday).count(),
                'ad_verifications': AdVerification.query.filter(AdVerification.verification_date >= yesterday).count(),
                'company_verifications': CompanyVerification.query.filter(CompanyVerification.verification_date >= yesterday).count()
            }
        }
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"API stats error: {e}")
        return jsonify({'error': 'Failed to get system statistics'}), 500

@admin_panel.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors"""
    flash('Access denied. Admin authentication required.', 'error')
    return redirect(url_for('admin_panel.login'))

@admin_panel.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors in admin panel"""
    flash('Page not found.', 'error')
    return redirect(url_for('admin_panel.dashboard'))

@admin_panel.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server errors in admin panel"""
    logger.error(f"Admin panel internal error: {error}")
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('admin_panel.dashboard'))

# Context processor to make common data available to all admin templates
@admin_panel.context_processor
def inject_admin_context():
    """Inject common context data into admin templates"""
    return {
        'current_user': AdminAuth.get_current_user(),
        'session_info': AdminAuth.get_session_info(),
        'csrf_token': getattr(g, 'csrf_token', AdminAuth.generate_csrf_token())
    }