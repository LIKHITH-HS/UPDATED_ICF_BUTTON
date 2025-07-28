#!/usr/bin/env python3
"""
Redis connection health check utility for LinkSafetyShield admin panel
"""

import sys
from config import get_redis_connection

def check_redis_connection():
    """Check Redis connection and display status"""
    print("Checking Redis connection...")
    
    try:
        redis_client = get_redis_connection()
        
        if redis_client is None:
            print("❌ Redis connection failed - client is None")
            return False
        
        # Test basic operations
        redis_client.set("health_check", "ok", ex=10)
        result = redis_client.get("health_check")
        
        if result == "ok":
            print("✅ Redis connection successful")
            print(f"   Redis info: {redis_client.info('server')['redis_version']}")
            
            # Clean up test key
            redis_client.delete("health_check")
            return True
        else:
            print("❌ Redis connection test failed - could not read/write")
            return False
            
    except Exception as e:
        print(f"❌ Redis connection error: {e}")
        return False

def main():
    """Main function"""
    success = check_redis_connection()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()