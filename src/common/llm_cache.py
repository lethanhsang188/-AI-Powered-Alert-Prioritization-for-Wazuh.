"""Bộ nhớ đệm (cache) phản hồi LLM để cải thiện hiệu năng cho các cảnh báo tương tự."""
import hashlib
import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime, timedelta
from functools import lru_cache

logger = logging.getLogger(__name__)


class LLMCache:
    """
    Cache phản hồi LLM cho các cảnh báo tương tự để giảm số lần gọi API.
    
    Sử dụng băm dựa trên nội dung để nhận diện các cảnh báo tương tự.
    """
    
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 1000):
        """
        Khởi tạo cache LLM.
        
        Args:
            ttl_seconds: Thời gian tồn tại của mục cache (mặc định: 1 giờ)
            max_size: Số mục cache tối đa
        """
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_times: Dict[str, datetime] = {}
    
    def _generate_cache_key(self, alert_text: str, rule_context: Optional[Dict[str, Any]]) -> str:
        """
        Tạo khoá cache từ văn bản alert và ngữ cảnh rule.
        
        Dùng nội dung đã được chuẩn hoá để bắt các alert tương tự.
        """
        # Chuẩn hoá văn bản alert (loại bỏ timestamp, IP thay đổi)
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
        Chuẩn hoá văn bản alert để bắt các cảnh báo tương tự.
        
        Loại bỏ:
        - Timestamps
        - Địa chỉ IP (thay bằng placeholder)
        - Dữ liệu theo người dùng
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
            
            # Kiểm tra TTL
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
                # Hết hạn, xoá mục
                self._cache.pop(cache_key, None)
                self._access_times.pop(cache_key, None)
        
        return None
    
    def set(self, alert_text: str, rule_context: Optional[Dict[str, Any]], result: Dict[str, Any]):
        """
        Lưu phản hồi LLM vào cache.
        
        Args:
            alert_text: Văn bản alert
            rule_context: Ngữ cảnh rule
            result: Kết quả LLM để lưu vào cache
        """
        cache_key = self._generate_cache_key(alert_text, rule_context)
        
        # Xoá mục cũ nhất nếu cache đã đầy
        if len(self._cache) >= self.max_size and cache_key not in self._cache:
            # Xoá mục dùng ít nhất gần đây nhất
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
            f"Đã cache phản hồi LLM cho khoá {cache_key}",
            extra={
                "component": "llm_cache",
                "action": "cache_set",
                "cache_key": cache_key,
                "cache_size": len(self._cache)
            }
        )
    
    def clear(self):
        """Xoá tất cả mục cache."""
        self._cache.clear()
        self._access_times.clear()
        logger.info(
            "Đã xoá cache LLM",
            extra={
                "component": "llm_cache",
                "action": "cache_clear"
            }
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Lấy thống kê cache."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds
        }


# Global cache instance
_llm_cache: Optional[LLMCache] = None


def get_llm_cache() -> LLMCache:
    """Lấy hoặc tạo thể hiện global của cache LLM."""
    global _llm_cache
    if _llm_cache is None:
        from src.common.config import LLM_CACHE_TTL_SECONDS, LLM_CACHE_MAX_SIZE
        _llm_cache = LLMCache(
            ttl_seconds=LLM_CACHE_TTL_SECONDS,
            max_size=LLM_CACHE_MAX_SIZE
        )
    return _llm_cache

