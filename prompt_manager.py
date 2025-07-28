"""
AI Prompt Management System for LinkSafetyShield

This module provides dynamic prompt management and fine-tuning capabilities
for different verification services.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from flask import current_app
from pathlib import Path

logger = logging.getLogger(__name__)

class PromptManager:
    """Manages AI prompts and fine-tuning configurations"""
    
    # Configuration file paths
    PROMPTS_CONFIG_FILE = "instance/config/prompts.json"
    PROMPTS_BACKUP_DIR = "instance/config/prompts_backup"
    
    # Default prompt configurations
    DEFAULT_PROMPTS = {
        'news': {
            'system_prompt': 'You are a news verification assistant. Analyze news statements and determine if they are real or fake. Be objective and provide evidence.',
            'user_template': 'Is the following news real or fake? Please verify the credibility with explanation: "{input}"',
            'temperature': 0.2,
            'max_tokens': 500,
            'enabled': True,
            'model': 'sonar'
        },
        'ads': {
            'system_prompt': '''You are an expert ad verification assistant. Analyze advertisements for credibility, authenticity, and potential misleading claims. 
Be precise and concise in your analysis. Structure your response in these sections:
1. Analysis: Provide a clear assessment of the advertisement
2. Company Association: Note if the ad appears genuinely connected to any mentioned companies
3. Red Flags: List any suspicious elements (if present)
4. Verdict: Clearly state if the ad is 'trustworthy', 'misleading', or 'uncertain' ''',
            'user_template': '''Please verify the credibility and trustworthiness of this advertisement:

"{input}"

Analyze whether it is genuinely associated with any mentioned company or contains misleading elements. Consider:
- Unrealistic claims or offers that seem "too good to be true"
- Discrepancies between the ad content and known company practices
- Unusual URLs or contact information
- Urgent or high-pressure tactics
- Poor grammar or unprofessional presentation (for established companies)

Is this a legitimate advertisement or potentially misleading?''',
            'temperature': 0.2,
            'max_tokens': 1024,
            'enabled': True,
            'model': 'sonar'
        },
        'company': {
            'system_prompt': 'Be precise and concise.',
            'user_template': '''Is the following company properly registered and legitimate? 
Please verify if it's a real business entity and if its public claims are credible.
Company name: "{input}"''',
            'temperature': 0.2,
            'max_tokens': 1024,
            'enabled': True,
            'model': 'sonar'
        }
    }
    
    @classmethod
    def get_redis_client(cls):
        """Get Redis client from Flask app"""
        if hasattr(current_app, 'redis') and current_app.redis:
            return current_app.redis
        return None
    
    @classmethod
    def initialize_default_prompts(cls) -> bool:
        """Initialize default prompt configurations"""
        try:
            # Create config directory if it doesn't exist
            config_dir = Path(cls.PROMPTS_CONFIG_FILE).parent
            config_dir.mkdir(parents=True, exist_ok=True)
            
            # Create backup directory
            backup_dir = Path(cls.PROMPTS_BACKUP_DIR)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Check if prompts file already exists
            if not Path(cls.PROMPTS_CONFIG_FILE).exists():
                cls._save_prompts_to_file(cls.DEFAULT_PROMPTS)
                logger.info("Default prompts initialized successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Error initializing default prompts: {e}")
            return False
    
    @classmethod
    def get_all_prompts(cls) -> Dict[str, Dict[str, Any]]:
        """Get all prompt configurations"""
        try:
            # Try to load from file first
            if Path(cls.PROMPTS_CONFIG_FILE).exists():
                with open(cls.PROMPTS_CONFIG_FILE, 'r') as f:
                    prompts = json.load(f)
                    
                # Merge with defaults to ensure all keys exist
                for service in cls.DEFAULT_PROMPTS:
                    if service not in prompts:
                        prompts[service] = cls.DEFAULT_PROMPTS[service].copy()
                    else:
                        # Ensure all default keys exist
                        for key, value in cls.DEFAULT_PROMPTS[service].items():
                            if key not in prompts[service]:
                                prompts[service][key] = value
                
                return prompts
            else:
                # Initialize with defaults
                cls.initialize_default_prompts()
                return cls.DEFAULT_PROMPTS.copy()
                
        except Exception as e:
            logger.error(f"Error loading prompts: {e}")
            return cls.DEFAULT_PROMPTS.copy()
    
    @classmethod
    def get_service_prompt(cls, service: str) -> Dict[str, Any]:
        """Get prompt configuration for a specific service"""
        all_prompts = cls.get_all_prompts()
        return all_prompts.get(service, cls.DEFAULT_PROMPTS.get(service, {}))
    
    @classmethod
    def update_service_prompt(cls, service: str, prompt_config: Dict[str, Any], updated_by: str = 'admin') -> bool:
        """Update prompt configuration for a specific service"""
        try:
            # Get current prompts
            all_prompts = cls.get_all_prompts()
            
            # Create backup before updating
            cls._create_backup(all_prompts, f"before_update_{service}")
            
            # Update the specific service
            if service not in all_prompts:
                all_prompts[service] = {}
            
            # Update with new configuration
            all_prompts[service].update(prompt_config)
            all_prompts[service]['updated_at'] = datetime.utcnow().isoformat()
            all_prompts[service]['updated_by'] = updated_by
            
            # Save to file
            cls._save_prompts_to_file(all_prompts)
            
            logger.info(f"Prompt configuration updated for service: {service}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating prompt for service {service}: {e}")
            return False
    
    @classmethod
    def reset_to_defaults(cls, updated_by: str = 'admin') -> bool:
        """Reset all prompts to default configurations"""
        try:
            # Create backup before resetting
            current_prompts = cls.get_all_prompts()
            cls._create_backup(current_prompts, "before_reset_all")
            
            # Reset to defaults
            default_prompts = cls.DEFAULT_PROMPTS.copy()
            for service in default_prompts:
                default_prompts[service]['updated_at'] = datetime.utcnow().isoformat()
                default_prompts[service]['updated_by'] = updated_by
            
            cls._save_prompts_to_file(default_prompts)
            
            logger.info("All prompts reset to defaults")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting prompts to defaults: {e}")
            return False
    
    @classmethod
    def test_prompt(cls, service: str, test_input: str, prompt_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Test a prompt configuration with sample input"""
        try:
            # Use provided config or get current config
            if prompt_config is None:
                prompt_config = cls.get_service_prompt(service)
            
            # Format the user prompt
            user_prompt = prompt_config['user_template'].format(input=test_input)
            
            # Simulate API call (you can integrate with actual API here)
            start_time = datetime.utcnow()
            
            # For now, return a mock response
            # In production, you would call the actual API here
            mock_response = f"Mock response for {service} verification of: {test_input}"
            
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            return {
                'status': 'success',
                'response': mock_response,
                'response_time': response_time,
                'tokens_used': len(user_prompt.split()) + len(mock_response.split()),
                'estimated_cost': 0.001,  # Mock cost
                'quality_score': 85,  # Mock quality score
                'system_prompt': prompt_config['system_prompt'],
                'user_prompt': user_prompt
            }
            
        except Exception as e:
            logger.error(f"Error testing prompt for service {service}: {e}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @classmethod
    def get_prompt_statistics(cls) -> Dict[str, Dict[str, Any]]:
        """Get statistics for prompt performance"""
        try:
            # This would typically come from your database
            # For now, return mock statistics
            return {
                'news': {
                    'total_requests': 150,
                    'accuracy': 0.85,
                    'avg_response_time': 1200,
                    'cost_per_request': 0.002
                },
                'ads': {
                    'total_requests': 89,
                    'accuracy': 0.82,
                    'avg_response_time': 1500,
                    'cost_per_request': 0.003
                },
                'company': {
                    'total_requests': 45,
                    'accuracy': 0.78,
                    'avg_response_time': 1100,
                    'cost_per_request': 0.002
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting prompt statistics: {e}")
            return {}
    
    @classmethod
    def export_prompts(cls) -> Dict[str, Any]:
        """Export all prompt configurations"""
        try:
            prompts = cls.get_all_prompts()
            export_data = {
                'prompts': prompts,
                'exported_at': datetime.utcnow().isoformat(),
                'version': '1.0'
            }
            return export_data
            
        except Exception as e:
            logger.error(f"Error exporting prompts: {e}")
            return {}
    
    @classmethod
    def import_prompts(cls, import_data: Dict[str, Any], updated_by: str = 'admin') -> bool:
        """Import prompt configurations"""
        try:
            if 'prompts' not in import_data:
                raise ValueError("Invalid import data format")
            
            # Create backup before importing
            current_prompts = cls.get_all_prompts()
            cls._create_backup(current_prompts, "before_import")
            
            # Import prompts
            imported_prompts = import_data['prompts']
            for service in imported_prompts:
                imported_prompts[service]['updated_at'] = datetime.utcnow().isoformat()
                imported_prompts[service]['updated_by'] = updated_by
            
            cls._save_prompts_to_file(imported_prompts)
            
            logger.info("Prompts imported successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error importing prompts: {e}")
            return False
    
    @classmethod
    def _save_prompts_to_file(cls, prompts: Dict[str, Any]):
        """Save prompts to configuration file"""
        with open(cls.PROMPTS_CONFIG_FILE, 'w') as f:
            json.dump(prompts, f, indent=2)
    
    @classmethod
    def _create_backup(cls, prompts: Dict[str, Any], backup_name: str):
        """Create a backup of current prompts"""
        try:
            backup_file = Path(cls.PROMPTS_BACKUP_DIR) / f"{backup_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_file, 'w') as f:
                json.dump(prompts, f, indent=2)
            logger.info(f"Backup created: {backup_file}")
        except Exception as e:
            logger.error(f"Error creating backup: {e}")


def init_prompt_management():
    """Initialize prompt management system"""
    try:
        PromptManager.initialize_default_prompts()
        logger.info("Prompt management system initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing prompt management: {e}")