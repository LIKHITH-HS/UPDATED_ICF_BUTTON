"""
Configuration Management System for LinkSafetyShield Admin Panel

This module provides dynamic configuration management with Redis storage,
validation, and fallback to environment variables.
"""

import json
import logging
import os
import requests
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from flask import current_app
# Removed encryption dependencies

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages dynamic backend settings and configuration"""
    
    # Redis key prefixes
    CONFIG_KEY_PREFIX = "admin:config"
    # Removed encrypted config key
    CONFIG_HISTORY_KEY = "admin:config:history"
    
    # Configuration categories
    CATEGORIES = {
        'api_keys': 'External API Keys',
        'system': 'System Settings',
        'cache': 'Cache Configuration',
        'security': 'Security Settings',
        'monitoring': 'Monitoring Settings'
    }
    
    # Default configuration values
    DEFAULT_CONFIG = {
        'api_keys': {
            'google_safebrowsing_api_key': '',
            'perplexity_api_key': '',
        },
        'system': {
            'debug_mode': False,
            'log_level': 'INFO',
            'max_request_size': '16MB',
            'request_timeout': 30,
            'maintenance_mode': False,
            'maintenance_message': 'System is under maintenance. Please try again later.'
        },
        'cache': {
            'default_timeout': 3600,
            'max_cache_size': '100MB',
            'cache_key_prefix': 'linksafety:',
            'enable_cache_compression': True
        },
        'security': {
            'admin_session_timeout': 1800,
            'max_login_attempts': 5,
            'login_attempt_window': 900,
            'enable_csrf_protection': True,
            'secure_cookies': True
        },
        'monitoring': {
            'enable_metrics': True,
            'metrics_retention_days': 30,
            'alert_thresholds': {
                'error_rate': 0.05,
                'response_time': 5.0,
                'memory_usage': 0.8
            }
        }
    }
    
    # Sensitive keys that should be encrypted
    # Removed sensitive keys encryption
    
    @staticmethod
    def get_redis_client():
        """Get Redis client from Flask app"""
        if hasattr(current_app, 'redis') and current_app.redis:
            return current_app.redis
        return None
    
    # Removed all encryption/decryption methods
    
    @classmethod
    def initialize_default_config(cls) -> bool:
        """Initialize default configuration in Redis"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            logger.warning("Redis not available, cannot initialize configuration")
            return False
        
        try:
            # Check if config already exists
            for category in cls.DEFAULT_CONFIG:
                config_key = f"{cls.CONFIG_KEY_PREFIX}:{category}"
                if redis_client.exists(config_key):
                    continue
                
                # Set default configuration for this category
                config_data = {
                    'values': cls.DEFAULT_CONFIG[category],
                    'category': category,
                    'created_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat(),
                    'updated_by': 'system'
                }
                
                redis_client.setex(
                    config_key,
                    86400 * 365,  # Expire in 1 year
                    json.dumps(config_data)
                )
            
            logger.info("Default configuration initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing default configuration: {e}")
            return False
    
    @classmethod
    def get_setting(cls, key: str, category: str = None) -> Any:
        """
        Get a configuration setting value
        
        Args:
            key (str): Setting key (e.g., 'debug_mode')
            category (str, optional): Category (e.g., 'system'). If None, searches all categories.
            
        Returns:
            Any: Setting value or None if not found
        """
        redis_client = cls.get_redis_client()
        
        # If no Redis, fall back to environment variables and defaults
        if not redis_client:
            return cls._get_fallback_value(key, category)
        
        try:
            if category:
                # Search in specific category
                config_key = f"{cls.CONFIG_KEY_PREFIX}:{category}"
                config_data = redis_client.get(config_key)
                
                if config_data:
                    config = json.loads(config_data)
                    value = config.get('values', {}).get(key)
                    
                    # No encryption/decryption needed
                    
                    return value
            else:
                # Search all categories
                for cat in cls.DEFAULT_CONFIG:
                    value = cls.get_setting(key, cat)
                    if value is not None:
                        return value
            
            # Fall back to environment variables and defaults
            return cls._get_fallback_value(key, category)
            
        except Exception as e:
            logger.error(f"Error getting setting {key}: {e}")
            return cls._get_fallback_value(key, category)
    
    @classmethod
    def _get_fallback_value(cls, key: str, category: str = None) -> Any:
        """Get fallback value from file storage, environment variables or defaults"""
        # First try to get from file-based storage (our fallback storage)
        if category:
            try:
                from pathlib import Path
                config_file = Path('instance/config') / f'{category}.json'
                if config_file.exists():
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                        value = config_data.get('values', {}).get(key)
                        if value is not None:
                            # No encryption/decryption needed
                            return value
            except Exception as e:
                logger.debug(f"Could not read from fallback file storage: {e}")
        
        # Try environment variable
        env_key = key.upper()
        env_value = os.environ.get(env_key)
        if env_value is not None:
            return cls._convert_env_value(env_value)
        
        # Try with category prefix
        if category:
            env_key = f"{category.upper()}_{key.upper()}"
            env_value = os.environ.get(env_key)
            if env_value is not None:
                return cls._convert_env_value(env_value)
        
        # Fall back to default configuration
        if category and category in cls.DEFAULT_CONFIG:
            return cls.DEFAULT_CONFIG[category].get(key)
        
        # Search all default categories
        for cat, config in cls.DEFAULT_CONFIG.items():
            if key in config:
                return config[key]
        
        return None
    
    @staticmethod
    def _convert_env_value(value: str) -> Any:
        """Convert environment variable string to appropriate type"""
        # Boolean conversion
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass
        
        # JSON conversion
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Return as string
        return value
    
    @classmethod
    def set_setting(cls, key: str, value: Any, category: str, updated_by: str = 'admin') -> bool:
        """
        Set a configuration setting value
        
        Args:
            key (str): Setting key
            value (Any): Setting value
            category (str): Configuration category
            updated_by (str): User who updated the setting
            
        Returns:
            bool: True if successful, False otherwise
        """
        redis_client = cls.get_redis_client()
        if not redis_client:
            logger.warning("Redis not available, using fallback storage for configuration")
            return cls._set_setting_fallback(key, value, category, updated_by)
        
        try:
            config_key = f"{cls.CONFIG_KEY_PREFIX}:{category}"
            
            # Get current configuration
            current_config = {}
            config_data = redis_client.get(config_key)
            if config_data:
                current_config = json.loads(config_data)
            
            # Update the setting
            if 'values' not in current_config:
                current_config['values'] = {}
            
            # Store value directly without encryption
            current_config['values'][key] = value
            current_config['category'] = category
            current_config['updated_at'] = datetime.utcnow().isoformat()
            current_config['updated_by'] = updated_by
            
            if 'created_at' not in current_config:
                current_config['created_at'] = datetime.utcnow().isoformat()
            
            # Save updated configuration
            redis_client.setex(
                config_key,
                86400 * 365,  # Expire in 1 year
                json.dumps(current_config)
            )
            
            # Record change in history
            cls._record_config_change(category, key, value, updated_by)
            
            logger.info(f"Configuration updated: {category}.{key} by {updated_by}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting configuration {category}.{key}: {e}")
            return False
    
    @classmethod
    def _set_setting_fallback(cls, key: str, value: Any, category: str, updated_by: str = 'admin') -> bool:
        """
        Fallback method to set configuration when Redis is not available
        This will store settings in a local JSON file
        
        Args:
            key (str): Setting key
            value (Any): Setting value
            category (str): Configuration category
            updated_by (str): User who updated the setting
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import os
            import json
            from pathlib import Path
            
            # Create config directory if it doesn't exist
            config_dir = Path('instance/config')
            config_dir.mkdir(parents=True, exist_ok=True)
            
            # Config file path
            config_file = config_dir / f'{category}.json'
            
            # Load existing config or create new
            config_data = {}
            if config_file.exists():
                try:
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                except:
                    config_data = {}
            
            # Update the setting
            if 'values' not in config_data:
                config_data['values'] = {}
            
            # Store value directly without encryption
            config_data['values'][key] = value
            config_data['category'] = category
            config_data['updated_at'] = datetime.utcnow().isoformat()
            config_data['updated_by'] = updated_by
            
            if 'created_at' not in config_data:
                config_data['created_at'] = datetime.utcnow().isoformat()
            
            # Save to file
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Fallback: Saved {category}.{key} to {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error in fallback setting storage: {e}")
            return False

    @classmethod
    def _record_config_change(cls, category: str, key: str, value: Any, updated_by: str):
        """Record configuration change in history"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            return
        
        try:
            history_entry = {
                'category': category,
                'key': key,
                'value': value,
                'updated_by': updated_by,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            history_key = f"{cls.CONFIG_HISTORY_KEY}:{datetime.utcnow().timestamp()}"
            redis_client.setex(
                history_key,
                86400 * 30,  # Keep history for 30 days
                json.dumps(history_entry)
            )
            
        except Exception as e:
            logger.error(f"Error recording config change: {e}")
    
    @classmethod
    def get_category_config(cls, category: str) -> Dict:
        """Get all configuration for a specific category"""
        redis_client = cls.get_redis_client()
        
        if not redis_client:
            # Try to get from file storage fallback
            try:
                from pathlib import Path
                config_file = Path('instance/config') / f'{category}.json'
                if config_file.exists():
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                        
                    # No masking needed - values stored directly
                    config_data['source'] = 'file'
                    return config_data
            except Exception as e:
                logger.debug(f"Could not read from fallback file storage: {e}")
            
            # Return default configuration if no file storage
            return {
                'values': cls.DEFAULT_CONFIG.get(category, {}),
                'category': category,
                'source': 'default'
            }
        
        try:
            config_key = f"{cls.CONFIG_KEY_PREFIX}:{category}"
            config_data = redis_client.get(config_key)
            
            if config_data:
                config = json.loads(config_data)
                
                # No masking needed - values stored directly
                config['source'] = 'redis'
                return config
            else:
                # Initialize with defaults
                cls.initialize_default_config()
                return {
                    'values': cls.DEFAULT_CONFIG.get(category, {}),
                    'category': category,
                    'source': 'default'
                }
                
        except Exception as e:
            logger.error(f"Error getting category config {category}: {e}")
            return {
                'values': cls.DEFAULT_CONFIG.get(category, {}),
                'category': category,
                'source': 'error'
            }
    
    @classmethod
    def get_all_config(cls) -> Dict:
        """Get all configuration categories"""
        all_config = {}
        
        for category in cls.CATEGORIES:
            all_config[category] = cls.get_category_config(category)
        
        return all_config
    
    @classmethod
    def validate_api_key(cls, service: str, api_key: str) -> Tuple[bool, str]:
        """
        Validate an API key by testing connectivity
        
        Args:
            service (str): Service name ('google_safebrowsing', 'perplexity')
            api_key (str): API key to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, message)
        """
        if not api_key or api_key.strip() == '':
            return False, "API key is empty"
        
        try:
            if service == 'google_safebrowsing':
                return cls._validate_google_safebrowsing_key(api_key)
            elif service == 'perplexity':
                return cls._validate_perplexity_key(api_key)
            else:
                return False, f"Unknown service: {service}"
                
        except Exception as e:
            logger.error(f"Error validating {service} API key: {e}")
            return False, f"Validation error: {str(e)}"
    
    @staticmethod
    def _validate_google_safebrowsing_key(api_key: str) -> Tuple[bool, str]:
        """Validate Google Safe Browsing API key"""
        try:
            url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            # Test payload
            payload = {
                "client": {
                    "clientId": "test-client",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "http://example.com"}]
                }
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                return True, "API key is valid"
            elif response.status_code == 400:
                error_data = response.json()
                if 'error' in error_data:
                    return False, f"API Error: {error_data['error'].get('message', 'Invalid request')}"
                return False, "Invalid API key or request format"
            elif response.status_code == 403:
                return False, "API key is invalid or access denied"
            else:
                return False, f"API returned status code: {response.status_code}"
                
        except requests.exceptions.Timeout:
            return False, "Request timeout - API may be unavailable"
        except requests.exceptions.RequestException as e:
            return False, f"Network error: {str(e)}"
    
    @staticmethod
    def _validate_perplexity_key(api_key: str) -> Tuple[bool, str]:
        """Validate Perplexity API key"""
        try:
            url = "https://api.perplexity.ai/chat/completions"
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            # Test payload matching the format used in verification functions
            payload = {
                "model": "sonar",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a helpful assistant."
                    },
                    {
                        "role": "user",
                        "content": "Hello, this is a test message."
                    }
                ],
                "temperature": 0.2,
                "max_tokens": 10,
                "top_p": 0.9,
                "search_domain_filter": ["perplexity.ai"],
                "return_images": False,
                "return_related_questions": False,
                "search_recency_filter": "month",
                "top_k": 0,
                "stream": False,
                "presence_penalty": 0,
                "frequency_penalty": 1
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=15)
            
            if response.status_code == 200:
                return True, "API key is valid and working"
            elif response.status_code == 401:
                return False, "API key is invalid or unauthorized"
            elif response.status_code == 403:
                return False, "API key access denied or quota exceeded"
            elif response.status_code == 429:
                return True, "API key is valid (rate limited)"
            elif response.status_code == 400:
                # Get more details about the 400 error
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', 'Bad request')
                    return False, f"API request error: {error_msg}"
                except:
                    return False, "API request format error (400 Bad Request)"
            else:
                return False, f"API returned status code: {response.status_code}"
                
        except requests.exceptions.Timeout:
            return False, "Request timeout - API may be unavailable"
        except requests.exceptions.RequestException as e:
            return False, f"Network error: {str(e)}"
    
    @classmethod
    def test_external_service(cls, service: str) -> Dict:
        """
        Test connectivity to external service
        
        Args:
            service (str): Service name
            
        Returns:
            Dict: Test result with status and details
        """
        try:
            if service == 'google_safebrowsing':
                api_key = cls.get_setting('google_safebrowsing_api_key', 'api_keys')
                if not api_key:
                    return {'status': 'error', 'message': 'API key not configured'}
                
                is_valid, message = cls._validate_google_safebrowsing_key(api_key)
                return {
                    'status': 'success' if is_valid else 'error',
                    'message': message,
                    'service': service
                }
                
            elif service == 'perplexity':
                api_key = cls.get_setting('perplexity_api_key', 'api_keys')
                if not api_key:
                    return {'status': 'error', 'message': 'API key not configured'}
                
                is_valid, message = cls._validate_perplexity_key(api_key)
                return {
                    'status': 'success' if is_valid else 'error',
                    'message': message,
                    'service': service
                }
                
            else:
                return {'status': 'error', 'message': f'Unknown service: {service}'}
                
        except Exception as e:
            logger.error(f"Error testing service {service}: {e}")
            return {'status': 'error', 'message': str(e), 'service': service}
    
    @classmethod
    def get_config_history(cls, limit: int = 50) -> list:
        """Get configuration change history"""
        redis_client = cls.get_redis_client()
        if not redis_client:
            return []
        
        try:
            pattern = f"{cls.CONFIG_HISTORY_KEY}:*"
            keys = redis_client.keys(pattern)
            
            history = []
            for key in sorted(keys, reverse=True)[:limit]:
                history_data = redis_client.get(key)
                if history_data:
                    history.append(json.loads(history_data))
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting config history: {e}")
            return []


def init_config_management(app):
    """Initialize configuration management for the Flask app"""
    try:
        with app.app_context():
            # Initialize default configuration
            ConfigManager.initialize_default_config()
            logger.info("Configuration management initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing configuration management: {e}")