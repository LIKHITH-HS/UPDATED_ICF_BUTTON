"""
Monitoring and Analytics Service for LinkSafetyShield Admin Panel

This module provides comprehensive system monitoring, metrics collection,
and analytics functionality for the admin panel.
"""

import json
import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import current_app, request, g
from functools import wraps
import threading
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class MonitoringService:
    """Comprehensive monitoring and analytics service"""
    
    # Redis key prefixes
    METRICS_KEY_PREFIX = "admin:metrics"
    SYSTEM_HEALTH_KEY = "admin:system_health"
    API_METRICS_KEY = "admin:api_metrics"
    ERROR_METRICS_KEY = "admin:error_metrics"
    PERFORMANCE_KEY = "admin:performance"
    
    # In-memory storage for when Redis is unavailable
    _memory_metrics = defaultdict(lambda: deque(maxlen=1000))
    _memory_health = {}
    _memory_errors = deque(maxlen=500)
    
    @staticmethod
    def get_redis_client():
        """Get Redis client from Flask app"""
        if hasattr(current_app, 'redis') and current_app.redis:
            return current_app.redis
        return None
    
    @classmethod
    def record_api_request(cls, endpoint: str, method: str, status_code: int, 
                          response_time: float, ip_address: str = None):
        """
        Record API request metrics
        
        Args:
            endpoint (str): API endpoint name
            method (str): HTTP method
            status_code (int): HTTP status code
            response_time (float): Response time in seconds
            ip_address (str, optional): Client IP address
        """
        try:
            timestamp = datetime.utcnow()
            
            metric_data = {
                'endpoint': endpoint,
                'method': method,
                'status_code': status_code,
                'response_time': response_time,
                'ip_address': ip_address or 'unknown',
                'timestamp': timestamp.isoformat(),
                'date': timestamp.strftime('%Y-%m-%d'),
                'hour': timestamp.strftime('%Y-%m-%d-%H')
            }
            
            redis_client = cls.get_redis_client()
            if redis_client:
                # Store in Redis with different time granularities
                cls._store_metric_redis(redis_client, metric_data)
            else:
                # Store in memory as fallback
                cls._store_metric_memory(metric_data)
                
        except Exception as e:
            logger.error(f"Error recording API request metric: {e}")
    
    @classmethod
    def _store_metric_redis(cls, redis_client, metric_data):
        """Store metrics in Redis"""
        try:
            # Store detailed metric
            metric_key = f"{cls.API_METRICS_KEY}:{metric_data['endpoint']}:{metric_data['timestamp']}"
            redis_client.setex(metric_key, 86400 * 7, json.dumps(metric_data))  # Keep for 7 days
            
            # Update hourly aggregates
            hourly_key = f"{cls.API_METRICS_KEY}:hourly:{metric_data['endpoint']}:{metric_data['hour']}"
            cls._update_aggregate_redis(redis_client, hourly_key, metric_data, 86400 * 30)  # Keep for 30 days
            
            # Update daily aggregates
            daily_key = f"{cls.API_METRICS_KEY}:daily:{metric_data['endpoint']}:{metric_data['date']}"
            cls._update_aggregate_redis(redis_client, daily_key, metric_data, 86400 * 90)  # Keep for 90 days
            
        except Exception as e:
            logger.error(f"Error storing metric in Redis: {e}")
    
    @classmethod
    def _update_aggregate_redis(cls, redis_client, key, metric_data, ttl):
        """Update aggregate metrics in Redis"""
        try:
            # Get existing aggregate
            existing = redis_client.get(key)
            if existing:
                aggregate = json.loads(existing)
            else:
                aggregate = {
                    'endpoint': metric_data['endpoint'],
                    'total_requests': 0,
                    'total_errors': 0,
                    'total_response_time': 0.0,
                    'min_response_time': float('inf'),
                    'max_response_time': 0.0,
                    'status_codes': defaultdict(int),
                    'first_request': metric_data['timestamp'],
                    'last_request': metric_data['timestamp']
                }
            
            # Update aggregate
            aggregate['total_requests'] += 1
            aggregate['total_response_time'] += metric_data['response_time']
            aggregate['last_request'] = metric_data['timestamp']
            
            if metric_data['response_time'] < aggregate['min_response_time']:
                aggregate['min_response_time'] = metric_data['response_time']
            if metric_data['response_time'] > aggregate['max_response_time']:
                aggregate['max_response_time'] = metric_data['response_time']
            
            if metric_data['status_code'] >= 400:
                aggregate['total_errors'] += 1
            
            aggregate['status_codes'][str(metric_data['status_code'])] += 1
            
            # Calculate averages
            aggregate['avg_response_time'] = aggregate['total_response_time'] / aggregate['total_requests']
            aggregate['error_rate'] = aggregate['total_errors'] / aggregate['total_requests']
            
            # Store updated aggregate
            redis_client.setex(key, ttl, json.dumps(aggregate, default=str))
            
        except Exception as e:
            logger.error(f"Error updating aggregate in Redis: {e}")
    
    @classmethod
    def _store_metric_memory(cls, metric_data):
        """Store metrics in memory as fallback"""
        try:
            endpoint = metric_data['endpoint']
            cls._memory_metrics[endpoint].append(metric_data)
        except Exception as e:
            logger.error(f"Error storing metric in memory: {e}")
    
    @classmethod
    def record_error(cls, error_type: str, error_message: str, endpoint: str = None, 
                    traceback: str = None, user_id: str = None):
        """
        Record error occurrence
        
        Args:
            error_type (str): Type of error (e.g., 'ValidationError', 'APIError')
            error_message (str): Error message
            endpoint (str, optional): Endpoint where error occurred
            traceback (str, optional): Error traceback
            user_id (str, optional): User ID if available
        """
        try:
            timestamp = datetime.utcnow()
            
            error_data = {
                'error_type': error_type,
                'error_message': error_message,
                'endpoint': endpoint,
                'traceback': traceback,
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'date': timestamp.strftime('%Y-%m-%d'),
                'hour': timestamp.strftime('%Y-%m-%d-%H')
            }
            
            redis_client = cls.get_redis_client()
            if redis_client:
                # Store error in Redis
                error_key = f"{cls.ERROR_METRICS_KEY}:{timestamp.timestamp()}"
                redis_client.setex(error_key, 86400 * 7, json.dumps(error_data))  # Keep for 7 days
                
                # Update error counts
                hourly_error_key = f"{cls.ERROR_METRICS_KEY}:hourly:{error_data['hour']}"
                redis_client.incr(hourly_error_key)
                redis_client.expire(hourly_error_key, 86400 * 30)
                
            else:
                # Store in memory
                cls._memory_errors.append(error_data)
                
        except Exception as e:
            logger.error(f"Error recording error metric: {e}")
    
    @classmethod
    def collect_system_health(cls):
        """Collect current system health metrics"""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get process-specific metrics
            process = psutil.Process()
            process_memory = process.memory_info()
            process_cpu = process.cpu_percent()
            
            health_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_used_gb': memory.used / (1024**3),
                    'memory_total_gb': memory.total / (1024**3),
                    'disk_percent': disk.percent,
                    'disk_used_gb': disk.used / (1024**3),
                    'disk_total_gb': disk.total / (1024**3)
                },
                'process': {
                    'cpu_percent': process_cpu,
                    'memory_mb': process_memory.rss / (1024**2),
                    'memory_percent': process.memory_percent(),
                    'num_threads': process.num_threads(),
                    'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0
                }
            }
            
            redis_client = cls.get_redis_client()
            if redis_client:
                # Store current health
                redis_client.setex(cls.SYSTEM_HEALTH_KEY, 300, json.dumps(health_data))  # Keep for 5 minutes
                
                # Store historical health data
                health_history_key = f"{cls.SYSTEM_HEALTH_KEY}:history:{datetime.utcnow().timestamp()}"
                redis_client.setex(health_history_key, 86400, json.dumps(health_data))  # Keep for 24 hours
            else:
                # Store in memory
                cls._memory_health = health_data
            
            return health_data
            
        except Exception as e:
            logger.error(f"Error collecting system health: {e}")
            return None
    
    @classmethod
    def get_api_usage_stats(cls, timeframe: str = '24h', endpoint: str = None) -> Dict:
        """
        Get API usage statistics
        
        Args:
            timeframe (str): Time frame ('1h', '24h', '7d', '30d')
            endpoint (str, optional): Specific endpoint to get stats for
            
        Returns:
            Dict: Usage statistics
        """
        try:
            redis_client = cls.get_redis_client()
            if not redis_client:
                return cls._get_memory_stats(timeframe, endpoint)
            
            # Calculate time range
            now = datetime.utcnow()
            if timeframe == '1h':
                start_time = now - timedelta(hours=1)
                granularity = 'hourly'
            elif timeframe == '24h':
                start_time = now - timedelta(days=1)
                granularity = 'hourly'
            elif timeframe == '7d':
                start_time = now - timedelta(days=7)
                granularity = 'daily'
            elif timeframe == '30d':
                start_time = now - timedelta(days=30)
                granularity = 'daily'
            else:
                start_time = now - timedelta(days=1)
                granularity = 'hourly'
            
            # Get aggregated stats
            stats = cls._get_aggregated_stats_redis(redis_client, start_time, now, granularity, endpoint)
            return stats
            
        except Exception as e:
            logger.error(f"Error getting API usage stats: {e}")
            return {}
    
    @classmethod
    def _get_aggregated_stats_redis(cls, redis_client, start_time, end_time, granularity, endpoint):
        """Get aggregated statistics from Redis"""
        try:
            stats = {
                'timeframe': f"{start_time.isoformat()} to {end_time.isoformat()}",
                'granularity': granularity,
                'endpoints': {},
                'totals': {
                    'requests': 0,
                    'errors': 0,
                    'avg_response_time': 0.0,
                    'error_rate': 0.0
                }
            }
            
            # Generate time keys to search
            current = start_time
            time_keys = []
            
            while current <= end_time:
                if granularity == 'hourly':
                    time_key = current.strftime('%Y-%m-%d-%H')
                    current += timedelta(hours=1)
                else:  # daily
                    time_key = current.strftime('%Y-%m-%d')
                    current += timedelta(days=1)
                time_keys.append(time_key)
            
            # Get stats for each endpoint or specific endpoint
            endpoints_to_check = [endpoint] if endpoint else ['check_url', 'verify_news', 'verify_ad', 'verify_company', 'process_screenshot']
            
            total_requests = 0
            total_errors = 0
            total_response_time = 0.0
            
            for ep in endpoints_to_check:
                endpoint_stats = {
                    'requests': 0,
                    'errors': 0,
                    'avg_response_time': 0.0,
                    'error_rate': 0.0,
                    'timeline': []
                }
                
                for time_key in time_keys:
                    key = f"{cls.API_METRICS_KEY}:{granularity}:{ep}:{time_key}"
                    data = redis_client.get(key)
                    
                    if data:
                        aggregate = json.loads(data)
                        endpoint_stats['requests'] += aggregate.get('total_requests', 0)
                        endpoint_stats['errors'] += aggregate.get('total_errors', 0)
                        total_response_time += aggregate.get('total_response_time', 0.0)
                        
                        endpoint_stats['timeline'].append({
                            'time': time_key,
                            'requests': aggregate.get('total_requests', 0),
                            'errors': aggregate.get('total_errors', 0),
                            'avg_response_time': aggregate.get('avg_response_time', 0.0)
                        })
                
                if endpoint_stats['requests'] > 0:
                    endpoint_stats['avg_response_time'] = total_response_time / endpoint_stats['requests']
                    endpoint_stats['error_rate'] = endpoint_stats['errors'] / endpoint_stats['requests']
                
                stats['endpoints'][ep] = endpoint_stats
                total_requests += endpoint_stats['requests']
                total_errors += endpoint_stats['errors']
            
            # Calculate totals
            stats['totals']['requests'] = total_requests
            stats['totals']['errors'] = total_errors
            if total_requests > 0:
                stats['totals']['avg_response_time'] = total_response_time / total_requests
                stats['totals']['error_rate'] = total_errors / total_requests
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting aggregated stats from Redis: {e}")
            return {}
    
    @classmethod
    def _get_memory_stats(cls, timeframe, endpoint):
        """Get statistics from memory storage"""
        try:
            stats = {
                'timeframe': timeframe,
                'source': 'memory',
                'endpoints': {},
                'totals': {'requests': 0, 'errors': 0, 'avg_response_time': 0.0, 'error_rate': 0.0}
            }
            
            # Calculate time cutoff
            now = datetime.utcnow()
            if timeframe == '1h':
                cutoff = now - timedelta(hours=1)
            elif timeframe == '24h':
                cutoff = now - timedelta(days=1)
            elif timeframe == '7d':
                cutoff = now - timedelta(days=7)
            else:
                cutoff = now - timedelta(days=1)
            
            endpoints_to_check = [endpoint] if endpoint else cls._memory_metrics.keys()
            
            for ep in endpoints_to_check:
                if ep in cls._memory_metrics:
                    metrics = cls._memory_metrics[ep]
                    
                    # Filter by time
                    recent_metrics = [
                        m for m in metrics 
                        if datetime.fromisoformat(m['timestamp']) >= cutoff
                    ]
                    
                    if recent_metrics:
                        requests = len(recent_metrics)
                        errors = sum(1 for m in recent_metrics if m['status_code'] >= 400)
                        avg_response_time = sum(m['response_time'] for m in recent_metrics) / requests
                        error_rate = errors / requests if requests > 0 else 0
                        
                        stats['endpoints'][ep] = {
                            'requests': requests,
                            'errors': errors,
                            'avg_response_time': avg_response_time,
                            'error_rate': error_rate
                        }
                        
                        stats['totals']['requests'] += requests
                        stats['totals']['errors'] += errors
            
            # Calculate total averages
            if stats['totals']['requests'] > 0:
                total_response_time = sum(
                    ep_stats['avg_response_time'] * ep_stats['requests']
                    for ep_stats in stats['endpoints'].values()
                )
                stats['totals']['avg_response_time'] = total_response_time / stats['totals']['requests']
                stats['totals']['error_rate'] = stats['totals']['errors'] / stats['totals']['requests']
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting memory stats: {e}")
            return {}
    
    @classmethod
    def get_system_health(cls) -> Dict:
        """Get current system health status"""
        try:
            redis_client = cls.get_redis_client()
            if redis_client:
                health_data = redis_client.get(cls.SYSTEM_HEALTH_KEY)
                if health_data:
                    return json.loads(health_data)
            
            # Fallback to memory or collect fresh data
            if cls._memory_health:
                return cls._memory_health
            else:
                return cls.collect_system_health()
                
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return {}
    
    @classmethod
    def get_recent_errors(cls, limit: int = 50) -> List[Dict]:
        """Get recent error occurrences"""
        try:
            redis_client = cls.get_redis_client()
            if redis_client:
                # Get error keys
                pattern = f"{cls.ERROR_METRICS_KEY}:*"
                keys = redis_client.keys(pattern)
                
                errors = []
                for key in sorted(keys, reverse=True)[:limit]:
                    if ':hourly:' not in key:  # Skip aggregate keys
                        error_data = redis_client.get(key)
                        if error_data:
                            errors.append(json.loads(error_data))
                
                return errors
            else:
                # Return from memory
                return list(cls._memory_errors)[-limit:]
                
        except Exception as e:
            logger.error(f"Error getting recent errors: {e}")
            return []
    
    @classmethod
    def get_performance_metrics(cls) -> Dict:
        """Get performance metrics and recommendations"""
        try:
            health = cls.get_system_health()
            stats = cls.get_api_usage_stats('24h')
            
            metrics = {
                'health_score': 100,  # Start with perfect score
                'recommendations': [],
                'alerts': [],
                'system': health.get('system', {}),
                'process': health.get('process', {}),
                'api_performance': stats.get('totals', {})
            }
            
            # Analyze system health
            if health:
                system = health.get('system', {})
                process = health.get('process', {})
                
                # CPU analysis
                cpu_percent = system.get('cpu_percent', 0)
                if cpu_percent > 80:
                    metrics['health_score'] -= 20
                    metrics['alerts'].append(f"High CPU usage: {cpu_percent:.1f}%")
                    metrics['recommendations'].append("Consider scaling up CPU resources")
                elif cpu_percent > 60:
                    metrics['health_score'] -= 10
                    metrics['recommendations'].append("Monitor CPU usage trends")
                
                # Memory analysis
                memory_percent = system.get('memory_percent', 0)
                if memory_percent > 85:
                    metrics['health_score'] -= 20
                    metrics['alerts'].append(f"High memory usage: {memory_percent:.1f}%")
                    metrics['recommendations'].append("Consider increasing memory allocation")
                elif memory_percent > 70:
                    metrics['health_score'] -= 10
                    metrics['recommendations'].append("Monitor memory usage patterns")
                
                # Disk analysis
                disk_percent = system.get('disk_percent', 0)
                if disk_percent > 90:
                    metrics['health_score'] -= 15
                    metrics['alerts'].append(f"Low disk space: {disk_percent:.1f}% used")
                    metrics['recommendations'].append("Clean up disk space or expand storage")
                elif disk_percent > 80:
                    metrics['health_score'] -= 5
                    metrics['recommendations'].append("Monitor disk usage")
            
            # Analyze API performance
            if stats:
                totals = stats.get('totals', {})
                error_rate = totals.get('error_rate', 0)
                avg_response_time = totals.get('avg_response_time', 0)
                
                # Error rate analysis
                if error_rate > 0.1:  # 10%
                    metrics['health_score'] -= 25
                    metrics['alerts'].append(f"High error rate: {error_rate:.1%}")
                    metrics['recommendations'].append("Investigate error causes and fix issues")
                elif error_rate > 0.05:  # 5%
                    metrics['health_score'] -= 10
                    metrics['recommendations'].append("Monitor error patterns")
                
                # Response time analysis
                if avg_response_time > 5.0:
                    metrics['health_score'] -= 15
                    metrics['alerts'].append(f"Slow response time: {avg_response_time:.2f}s")
                    metrics['recommendations'].append("Optimize API performance")
                elif avg_response_time > 2.0:
                    metrics['health_score'] -= 5
                    metrics['recommendations'].append("Consider performance optimizations")
            
            # Ensure health score doesn't go below 0
            metrics['health_score'] = max(0, metrics['health_score'])
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            return {}


def monitor_request(f):
    """Decorator to monitor API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            # Execute the function
            result = f(*args, **kwargs)
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Determine status code
            if hasattr(result, 'status_code'):
                status_code = result.status_code
            elif isinstance(result, tuple) and len(result) > 1:
                status_code = result[1]
            else:
                status_code = 200
            
            # Record the request
            MonitoringService.record_api_request(
                endpoint=request.endpoint or f.__name__,
                method=request.method,
                status_code=status_code,
                response_time=response_time,
                ip_address=request.remote_addr
            )
            
            return result
            
        except Exception as e:
            # Record error
            response_time = time.time() - start_time
            
            MonitoringService.record_api_request(
                endpoint=request.endpoint or f.__name__,
                method=request.method,
                status_code=500,
                response_time=response_time,
                ip_address=request.remote_addr
            )
            
            MonitoringService.record_error(
                error_type=type(e).__name__,
                error_message=str(e),
                endpoint=request.endpoint or f.__name__,
                traceback=str(e)
            )
            
            raise
    
    return decorated_function


def init_monitoring(app):
    """Initialize monitoring for the Flask app"""
    try:
        # Start background health collection
        def collect_health_periodically():
            while True:
                try:
                    with app.app_context():
                        MonitoringService.collect_system_health()
                    time.sleep(60)  # Collect every minute
                except Exception as e:
                    logger.error(f"Error in health collection thread: {e}")
                    time.sleep(60)
        
        # Start health collection thread
        health_thread = threading.Thread(target=collect_health_periodically, daemon=True)
        health_thread.start()
        
        logger.info("Monitoring service initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing monitoring service: {e}")