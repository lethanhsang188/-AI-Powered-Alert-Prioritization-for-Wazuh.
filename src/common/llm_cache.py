"""LLM response caching to improve performance for similar alerts."""
import hashlib
import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime, timedelta
from functools import lru_cache

logger = logging.getLogger(__name__)


class LLMCache:
    """
    Cache LLM responses for similar alerts to reduce API calls.
    
    Uses content-based hashing to identify similar alerts.
    """
    
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 1000):
        """
        Initialize LLM cache.
        
        Args:
            ttl_seconds: Time-to-live for cache entries (default: 1 hour)
            max_size: Maximum number of cache entries
        """
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_times: Dict[str, datetime] = {}
    
    def _generate_cache_key(self, alert_text: str, rule_context: Optional[Dict[str, Any]]) -> str:
        """
        Generate cache key from alert text and rule context.
        
        Uses normalized content to catch similar alerts.
        """
        # Normalize alert text (remove timestamps, IPs that change)
        normalized_text = self._normalize_alert_text(alert_text)
        
        # Add rule context
        context_str = ""
        if rule_context:
            context_str = json.dumps({
                "rule_id": rule_context.get("id"),
                "rule_level": rule_context.get("level"),
                "rule_groups": sorted(rule_context.get("groups", []))
            }, sort_keys=True)
        
        # Generate hash
        cache_string = f"{normalized_text}:{context_str}"
        return hashlib.sha256(cache_string.encode()).hexdigest()[:16]
    
    def _normalize_alert_text(self, text: str) -> str:
        """
        Normalize alert text to catch similar alerts.
        
        Removes:
        - Timestamps
        - IP addresses (replace with placeholders)
        - User-specific data
        """
        import re
        
        # Remove timestamps
        text = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}[.\d]*[Z+-]\d{2}:\d{2}', '[TIMESTAMP]', text)
        
        # Replace IP addresses with placeholder
        text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', text)
        
        # Remove UUIDs
        text = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '[UUID]', text)
        
        return text
    
    def get(self, alert_text: str, rule_context: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Get cached LLM response.
        
        Args:
            alert_text: Alert text
            rule_context: Rule context
            
        Returns:
            Cached LLM result or None
        """
        cache_key = self._generate_cache_key(alert_text, rule_context)
        
        if cache_key in self._cache:
            entry = self._cache[cache_key]
            cached_at = entry.get("_cached_at", 0)
            
            # Check TTL
            if datetime.utcnow().timestamp() - cached_at < self.ttl_seconds:
                self._access_times[cache_key] = datetime.utcnow()
                logger.debug(
                    f"LLM cache hit for key {cache_key}",
                    extra={
                        "component": "llm_cache",
                        "action": "cache_hit",
                        "cache_key": cache_key
                    }
                )
                return entry.get("result")
            else:
                # Expired, remove
                self._cache.pop(cache_key, None)
                self._access_times.pop(cache_key, None)
        
        return None
    
    def set(self, alert_text: str, rule_context: Optional[Dict[str, Any]], result: Dict[str, Any]):
        """
        Cache LLM response.
        
        Args:
            alert_text: Alert text
            rule_context: Rule context
            result: LLM result to cache
        """
        cache_key = self._generate_cache_key(alert_text, rule_context)
        
        # Evict oldest if cache is full
        if len(self._cache) >= self.max_size and cache_key not in self._cache:
            # Remove least recently used
            if self._access_times:
                oldest_key = min(self._access_times.items(), key=lambda x: x[1])[0]
                self._cache.pop(oldest_key, None)
                self._access_times.pop(oldest_key, None)
        
        self._cache[cache_key] = {
            "result": result,
            "_cached_at": datetime.utcnow().timestamp()
        }
        self._access_times[cache_key] = datetime.utcnow()
        
        logger.debug(
            f"LLM response cached for key {cache_key}",
            extra={
                "component": "llm_cache",
                "action": "cache_set",
                "cache_key": cache_key,
                "cache_size": len(self._cache)
            }
        )
    
    def clear(self):
        """Clear all cache entries."""
        self._cache.clear()
        self._access_times.clear()
        logger.info(
            "LLM cache cleared",
            extra={
                "component": "llm_cache",
                "action": "cache_clear"
            }
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds
        }


# Global cache instance
_llm_cache: Optional[LLMCache] = None


def get_llm_cache() -> LLMCache:
    """Get or create global LLM cache instance."""
    global _llm_cache
    if _llm_cache is None:
        from src.common.config import LLM_CACHE_TTL_SECONDS, LLM_CACHE_MAX_SIZE
        _llm_cache = LLMCache(
            ttl_seconds=LLM_CACHE_TTL_SECONDS,
            max_size=LLM_CACHE_MAX_SIZE
        )
    return _llm_cache

