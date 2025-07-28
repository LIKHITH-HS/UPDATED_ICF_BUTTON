"""
Rate Limiting Management Module for LinkSafetyShield Admin Panel

This module provides dynamic rate limiting configuration and management
functionality for the admin panel.
"""

import json
import logging
from datetime import datetime, timedelta
from flask import current_app
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class RateLimitManager:
    """Manages dynamic rate limiting configuration"""
    
    # Redis key prefixes
    RATE_LIMIT_CONFIG_KEY = "admin:rate_limits:config"
    RATE_LIMIT_STATS_KEY = "admin:rate_limits:stats"
    RATE_LIMIT_VIOLATIONS_KEY = "admin:rate_limits:violations"
    
    # Default rate limits for different endpoints
    DEFAULT_LIMITS = {
        'check_url': '50 per minute',
        'verify_news': '30 per minute', 
        'verify_ad': '30 per minute',
        'verify_company': '30 per minute',
        'process_screenshot': '10 per minute',
        'global': '1000 per hour'
    }
    
    @staticmethod
    def get_redis_client():
        """Get Redis client from Flask app"""
        if hasattr(current_app, 'redis') and current_app.redis:
            return current_app.redis
        return None
    
    @classmethod
    def initialize_default_limits(cls):
        """Initialize default rate limits in Redis"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            logger.warning("Redis not available, cannot initialize rate limits")
            return False
        
        try:
            # Check if limits already exist
            existing_config = redis_client.get(cls.RATE_LIMIT_CONFIG_KEY)
            if existing_config:
                logger.info("Rate limit configuration already exists")
                return True
            
            # Set default limits
            config_data = {
                'limits': cls.DEFAULT_LIMITS,
                'enabled': True,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            redis_client.set(
                cls.RATE_LIMIT_CONFIG_KEY,
                json.dumps(config_data),
                ex=86400 * 30  # Expire in 30 days
            )
            
            logger.info("Default rate limits initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing default rate limits: {e}")
            return False
    
    @classmethod
    def get_current_limits(cls) -> Dict:
        """Get current rate limit configuration"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            # Try to get from file storage fallback
            return cls._get_limits_from_file()
        
        try:
            config_data = redis_client.get(cls.RATE_LIMIT_CONFIG_KEY)
            if config_data:
                config = json.loads(config_data)
                config['source'] = 'redis'
                return config
            else:
                # Initialize and return defaults
                cls.initialize_default_limits()
                return {
                    'limits': cls.DEFAULT_LIMITS,
                    'enabled': True,
                    'source': 'default'
                }
                
        except Exception as e:
            logger.error(f"Error getting current limits: {e}")
            # Fall back to file storage on Redis error
            return cls._get_limits_from_file()
    
    @classmethod
    def update_limits(cls, new_limits: Dict, enabled: bool = True) -> bool:
        """Update rate limit configuration"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            logger.warning("Redis not available, using file-based storage for rate limits")
            return cls._update_limits_fallback(new_limits, enabled)
        
        try:
            # Validate limit format
            for endpoint, limit in new_limits.items():
                if not cls.validate_limit_format(limit):
                    logger.error(f"Invalid limit format for {endpoint}: {limit}")
                    return False
            
            # Get current config
            current_config = cls.get_current_limits()
            
            # Update configuration
            config_data = {
                'limits': new_limits,
                'enabled': enabled,
                'created_at': current_config.get('created_at', datetime.utcnow().isoformat()),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            redis_client.set(
                cls.RATE_LIMIT_CONFIG_KEY,
                json.dumps(config_data),
                ex=86400 * 30  # Expire in 30 days
            )
            
            logger.info(f"Rate limits updated successfully: {new_limits}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating rate limits: {e}")
            return cls._update_limits_fallback(new_limits, enabled)
    
    @classmethod
    def _update_limits_fallback(cls, new_limits: Dict, enabled: bool = True) -> bool:
        """
        Fallback method to update rate limits when Redis is not available
        This will store rate limits in a local JSON file
        """
        try:
            import os
            from pathlib import Path
            
            # Create config directory if it doesn't exist
            config_dir = Path('instance/config')
            config_dir.mkdir(parents=True, exist_ok=True)
            
            # Config file path
            config_file = config_dir / 'rate_limits.json'
            
            # Validate limit format
            for endpoint, limit in new_limits.items():
                if not cls.validate_limit_format(limit):
                    logger.error(f"Invalid limit format for {endpoint}: {limit}")
                    return False
            
            # Load existing config or create new
            config_data = {}
            if config_file.exists():
                try:
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                except:
                    config_data = {}
            
            # Update configuration
            config_data.update({
                'limits': new_limits,
                'enabled': enabled,
                'created_at': config_data.get('created_at', datetime.utcnow().isoformat()),
                'updated_at': datetime.utcnow().isoformat(),
                'source': 'file'
            })
            
            # Save to file
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Fallback: Saved rate limits to {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error in fallback rate limits storage: {e}")
            return False

    @classmethod
    def _get_limits_from_file(cls) -> Dict:
        """Get rate limits from file storage"""
        try:
            from pathlib import Path
            config_file = Path('instance/config/rate_limits.json')
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                    config_data['source'] = 'file'
                    return config_data
        except Exception as e:
            logger.debug(f"Could not read from fallback file storage: {e}")
        
        return {
            'limits': cls.DEFAULT_LIMITS,
            'enabled': True,
            'source': 'default'
        }

    @staticmethod
    def validate_limit_format(limit_string: str) -> bool:
        """Validate rate limit string format (e.g., '100 per hour')"""
        try:
            parts = limit_string.strip().lower().split()
            if len(parts) != 3:
                return False
            
            # Check if first part is a number
            int(parts[0])
            
            # Check if second part is 'per'
            if parts[1] != 'per':
                return False
            
            # Check if third part is a valid time unit
            valid_units = ['second', 'minute', 'hour', 'day', 'month', 'year']
            if parts[2] not in valid_units:
                return False
            
            return True
            
        except (ValueError, IndexError):
            return False
    
    @classmethod
    def get_usage_stats(cls, endpoint: str = None) -> Dict:
        """Get rate limiting usage statistics"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            # Return default stats when Redis is not available
            default_stats = {}
            endpoints = ['check_url', 'verify_news', 'verify_ad', 'verify_company', 'process_screenshot', 'global']
            for ep in endpoints:
                default_stats[ep] = {'requests': 0, 'violations': 0}
            return default_stats
        
        try:
            stats = {}
            
            if endpoint:
                # Get stats for specific endpoint
                stats_key = f"{cls.RATE_LIMIT_STATS_KEY}:{endpoint}"
                endpoint_stats = redis_client.get(stats_key)
                if endpoint_stats:
                    try:
                        stats[endpoint] = json.loads(endpoint_stats)
                    except (json.JSONDecodeError, TypeError):
                        stats[endpoint] = {'requests': 0, 'violations': 0}
                else:
                    stats[endpoint] = {'requests': 0, 'violations': 0}
            else:
                # Get stats for all endpoints - provide default stats
                endpoints = ['check_url', 'verify_news', 'verify_ad', 'verify_company', 'process_screenshot', 'global']
                
                for ep in endpoints:
                    stats_key = f"{cls.RATE_LIMIT_STATS_KEY}:{ep}"
                    try:
                        endpoint_stats = redis_client.get(stats_key)
                        if endpoint_stats:
                            try:
                                stats[ep] = json.loads(endpoint_stats)
                            except (json.JSONDecodeError, TypeError):
                                stats[ep] = {'requests': 0, 'violations': 0}
                        else:
                            stats[ep] = {'requests': 0, 'violations': 0}
                    except Exception:
                        stats[ep] = {'requests': 0, 'violations': 0}
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting usage stats: {e}")
            # Return default stats on error
            default_stats = {}
            endpoints = ['check_url', 'verify_news', 'verify_ad', 'verify_company', 'process_screenshot', 'global']
            for ep in endpoints:
                default_stats[ep] = {'requests': 0, 'violations': 0}
            return default_stats
    
    @classmethod
    def record_request(cls, endpoint: str, violated: bool = False):
        """Record a rate limit request"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            return
        
        try:
            stats_key = f"{cls.RATE_LIMIT_STATS_KEY}:{endpoint}"
            
            # Get current stats
            current_stats = redis_client.get(stats_key)
            if current_stats:
                stats = json.loads(current_stats)
            else:
                stats = {'requests': 0, 'violations': 0, 'last_request': None}
            
            # Update stats
            stats['requests'] += 1
            if violated:
                stats['violations'] += 1
            stats['last_request'] = datetime.utcnow().isoformat()
            
            # Store updated stats
            redis_client.setex(
                stats_key,
                86400,  # Expire in 24 hours
                json.dumps(stats)
            )
            
            # Record violation details if applicable
            if violated:
                cls.record_violation(endpoint)
                
        except Exception as e:
            logger.error(f"Error recording request stats: {e}")
    
    @classmethod
    def record_violation(cls, endpoint: str, ip_address: str = None):
        """Record a rate limit violation"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            return
        
        try:
            violation_data = {
                'endpoint': endpoint,
                'ip_address': ip_address or 'unknown',
                'timestamp': datetime.utcnow().isoformat(),
                'user_agent': 'unknown'  # Could be enhanced to capture actual user agent
            }
            
            # Store violation with timestamp as part of key for uniqueness
            violation_key = f"{cls.RATE_LIMIT_VIOLATIONS_KEY}:{endpoint}:{datetime.utcnow().timestamp()}"
            redis_client.setex(
                violation_key,
                86400 * 7,  # Keep violations for 7 days
                json.dumps(violation_data)
            )
            
        except Exception as e:
            logger.error(f"Error recording violation: {e}")
    
    @classmethod
    def get_recent_violations(cls, limit: int = 50) -> List[Dict]:
        """Get recent rate limit violations"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            return []
        
        try:
            pattern = f"{cls.RATE_LIMIT_VIOLATIONS_KEY}:*"
            keys = redis_client.keys(pattern)
            
            violations = []
            for key in sorted(keys, reverse=True)[:limit]:
                violation_data = redis_client.get(key)
                if violation_data:
                    violations.append(json.loads(violation_data))
            
            return violations
            
        except Exception as e:
            logger.error(f"Error getting recent violations: {e}")
            return []
    
    @classmethod
    def reset_stats(cls, endpoint: str = None) -> bool:
        """Reset rate limiting statistics"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            return False
        
        try:
            if endpoint:
                # Reset stats for specific endpoint
                stats_key = f"{cls.RATE_LIMIT_STATS_KEY}:{endpoint}"
                redis_client.delete(stats_key)
                logger.info(f"Reset stats for endpoint: {endpoint}")
            else:
                # Reset all stats
                pattern = f"{cls.RATE_LIMIT_STATS_KEY}:*"
                keys = redis_client.keys(pattern)
                if keys:
                    redis_client.delete(*keys)
                logger.info("Reset all rate limiting stats")
            
            return True
            
        except Exception as e:
            logger.error(f"Error resetting stats: {e}")
            return False
    
    @classmethod
    def get_limit_for_endpoint(cls, endpoint: str) -> str:
        """Get rate limit for specific endpoint"""
        config = cls.get_current_limits()
        limits = config.get('limits', {})
        
        # Return specific limit or global limit
        return limits.get(endpoint, limits.get('global', '100 per hour'))
    
    @classmethod
    def is_rate_limiting_enabled(cls) -> bool:
        """Check if rate limiting is globally enabled"""
        config = cls.get_current_limits()
        return config.get('enabled', True)


def init_rate_limiting(app):
    """Initialize rate limiting for the Flask app"""
    try:
        with app.app_context():
            # Initialize default rate limits
            RateLimitManager.initialize_default_limits()
            logger.info("Rate limiting initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing rate limiting: {e}")


def get_rate_limit_key_func():
    """Custom key function for rate limiting"""
    from flask import request
    
    # Use IP address as the key
    return request.remote_addr or 'unknown'


def rate_limit_exceeded_handler(e):
    """Custom handler for rate limit exceeded errors"""
    from flask import jsonify, request
    
    # Log the violation
    endpoint = request.endpoint or 'unknown'
    RateLimitManager.record_request(endpoint, violated=True)
    
    # Return JSON error response
    return jsonify({
        'status': 'error',
        'message': 'Rate limit exceeded. Please try again later.',
        'error_code': 'RATE_LIMIT_EXCEEDED',
        'retry_after': e.retry_after if hasattr(e, 'retry_after') else 60
    }), 429