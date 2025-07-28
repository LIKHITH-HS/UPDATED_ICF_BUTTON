import os
import redis
from flask import Flask

class Config:
    """Base configuration class"""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///linksafety.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    
    # Redis configuration
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    REDIS_HOST = os.environ.get('REDIS_HOST') or 'localhost'
    REDIS_PORT = int(os.environ.get('REDIS_PORT') or 6379)
    REDIS_DB = int(os.environ.get('REDIS_DB') or 0)
    REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD')
    
    # Rate limiting configuration
    RATELIMIT_STORAGE_URI = REDIS_URL
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_HEADERS_ENABLED = True
    
    # Admin panel configuration
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or 'admin'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'admin123'
    ADMIN_SESSION_TIMEOUT = int(os.environ.get('ADMIN_SESSION_TIMEOUT') or 1800)  # 30 minutes
    
    # External API configuration
    GOOGLE_SAFEBROWSING_API_KEY = os.environ.get('GOOGLE_SAFEBROWSING_API_KEY')
    PERPLEXITY_API_KEY = os.environ.get('PERPLEXITY_API_KEY')
    
    # Cache configuration
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT') or 3600)  # 1 hour
    CACHE_KEY_PREFIX = os.environ.get('CACHE_KEY_PREFIX') or 'linksafety:'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    REDIS_URL = 'redis://localhost:6379/1'  # Use different DB for testing

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_redis_connection():
    """Get Redis connection with error handling"""
    try:
        if Config.REDIS_URL:
            # Use Redis URL if provided
            r = redis.from_url(Config.REDIS_URL, decode_responses=True)
        else:
            # Use individual Redis parameters
            r = redis.Redis(
                host=Config.REDIS_HOST,
                port=Config.REDIS_PORT,
                db=Config.REDIS_DB,
                password=Config.REDIS_PASSWORD,
                decode_responses=True
            )
        
        # Test connection
        r.ping()
        return r
    except redis.ConnectionError as e:
        print(f"Redis connection error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected Redis error: {e}")
        return None

def init_redis(app: Flask):
    """Initialize Redis connection for Flask app"""
    try:
        redis_client = get_redis_connection()
        if redis_client:
            app.redis = redis_client
            print("✅ Redis connection established successfully")
        else:
            print("⚠️  Warning: Redis connection failed, using in-memory fallback")
            print("   Install and start Redis server for full functionality")
            app.redis = None
            # For development without Redis, use memory storage for rate limiting
            app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
    except Exception as e:
        print(f"Error initializing Redis: {e}")
        app.redis = None
        app.config['RATELIMIT_STORAGE_URI'] = 'memory://'