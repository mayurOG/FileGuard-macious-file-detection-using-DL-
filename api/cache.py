"""
Redis caching and rate limiting utilities
Author: Mayur Nhavalde
"""

import os
import json
from typing import Optional, Any
import redis
from functools import wraps
import hashlib
import time

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
except Exception as e:
    print(f"Warning: Could not connect to Redis: {e}")
    redis_client = None


class RedisCache:
    """Redis caching wrapper"""
    
    TTL = 3600  # 1 hour default
    
    @staticmethod
    def get(key: str) -> Optional[Any]:
        """Get value from cache"""
        if not redis_client:
            return None
        try:
            value = redis_client.get(key)
            return json.loads(value) if value else None
        except Exception:
            return None
    
    @staticmethod
    def set(key: str, value: Any, ttl: int = TTL):
        """Set value in cache"""
        if not redis_client:
            return
        try:
            redis_client.setex(key, ttl, json.dumps(value))
        except Exception:
            pass
    
    @staticmethod
    def delete(key: str):
        """Delete value from cache"""
        if not redis_client:
            return
        try:
            redis_client.delete(key)
        except Exception:
            pass
    
    @staticmethod
    def clear_pattern(pattern: str):
        """Delete all keys matching pattern"""
        if not redis_client:
            return
        try:
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)
        except Exception:
            pass


class RateLimiter:
    """Rate limiter using Redis"""
    
    @staticmethod
    def is_rate_limited(key: str, max_requests: int, window: int = 60) -> bool:
        """Check if request is rate limited
        
        Args:
            key: Rate limit key (e.g., user_id or IP)
            max_requests: Maximum requests allowed
            window: Time window in seconds
        """
        if not redis_client:
            return False
        
        try:
            current = redis_client.incr(f"rate_limit:{key}")
            if current == 1:
                redis_client.expire(f"rate_limit:{key}", window)
            return current > max_requests
        except Exception:
            return False
    
    @staticmethod
    def get_remaining(key: str, max_requests: int) -> int:
        """Get remaining requests"""
        if not redis_client:
            return max_requests
        
        try:
            current = redis_client.get(f"rate_limit:{key}")
            current = int(current) if current else 0
            return max(0, max_requests - current)
        except Exception:
            return max_requests


class FileDeduplication:
    """File caching and deduplication"""
    
    @staticmethod
    def get_cached_result(file_hash: str) -> Optional[dict]:
        """Get cached scan result for file hash"""
        if not redis_client:
            return None
        try:
            result = redis_client.get(f"scan_result:{file_hash}")
            return json.loads(result) if result else None
        except Exception:
            return None
    
    @staticmethod
    def cache_result(file_hash: str, result: dict, ttl: int = 2592000):
        """Cache scan result (30 days default)"""
        if not redis_client:
            return
        try:
            redis_client.setex(
                f"scan_result:{file_hash}",
                ttl,
                json.dumps(result)
            )
        except Exception:
            pass


def cache_decorator(ttl: int = 3600):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Create cache key from function name and args
            cache_key = f"{func.__name__}:{hashlib.md5(str((args, kwargs)).encode()).hexdigest()}"
            
            cached = RedisCache.get(cache_key)
            if cached is not None:
                return cached
            
            result = await func(*args, **kwargs)
            RedisCache.set(cache_key, result, ttl)
            return result
        
        return async_wrapper
    return decorator


def rate_limit_decorator(max_requests: int = 30, window: int = 60):
    """Decorator for rate limiting"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get rate limit key from request context if available
            request = kwargs.get("request")
            if request:
                key = f"user:{getattr(request.state, 'user_id', request.client.host)}"
                if RateLimiter.is_rate_limited(key, max_requests, window):
                    from fastapi import HTTPException, status
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded"
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator
