"""Deterministic deduplication key generation."""
import hashlib
from datetime import datetime
from typing import Any, Dict

from src.common.timezone import LOCAL_TZ


def dedup_key(alert: Dict[str, Any]) -> str:
    """
    Generate deterministic deduplication key from alert.
    
    Format: rule.id + agent.id + srcip + current local day
    Returns: 16-character hex prefix of SHA256 hash
    """
    rule_id = str(alert.get("rule", {}).get("id", "")).strip()
    agent_id = str(alert.get("agent", {}).get("id", "")).strip()
    srcip = str(alert.get("srcip", "")).strip()
    
    # Current local day (YYYY-MM-DD) using configured timezone
    day = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d")
    
    # Concatenate components
    key_str = f"{rule_id}:{agent_id}:{srcip}:{day}"
    
    # Generate SHA256 hash and take first 16 chars
    hash_obj = hashlib.sha256(key_str.encode("utf-8"))
    return hash_obj.hexdigest()[:16]

