"""Optional LLM-based alert analysis."""
import logging
from typing import Any, Dict, Optional

from common.config import (
    OPENAI_API_BASE,
    OPENAI_API_KEY,
    LLM_MODEL,
    LLM_MAX_TOKENS,
    LLM_TIMEOUT_SEC,
    LLM_ENABLE,
)
from common.web import RetrySession

logger = logging.getLogger(__name__)


def triage_llm(alert_text: str) -> Dict[str, Any]:
    """
    Analyze alert using LLM (if enabled).
    
    Args:
        alert_text: Alert message/text (may be redacted)
        
    Returns:
        Dict with keys: summary, confidence (0.0-1.0), tags (list)
    """
    if not LLM_ENABLE:
        return {
            "summary": "LLM disabled",
            "confidence": 0.0,
            "tags": [],
        }
    
    if not OPENAI_API_KEY:
        logger.warning("LLM_ENABLE=true but OPENAI_API_KEY is not set")
        return {
            "summary": "LLM API key not configured",
            "confidence": 0.0,
            "tags": [],
        }
    
    # Prepare prompt
    prompt = f"""Analyze this security alert and provide:
1. A brief summary (1-2 sentences)
2. Confidence score (0.0-1.0) for threat level
3. Relevant tags (list)

Alert: {alert_text[:500]}

Respond in JSON format:
{{"summary": "...", "confidence": 0.0-1.0, "tags": ["tag1", "tag2"]}}
"""
    
    try:
        session = RetrySession()
        session.headers.update({
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        })
        
        url = f"{OPENAI_API_BASE.rstrip('/')}/chat/completions"
        payload = {
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": "You are a security analyst."},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": LLM_MAX_TOKENS,
            "temperature": 0.3,
        }
        
        response = session.request_with_backoff(
            "POST",
            url,
            json=payload,
            timeout=LLM_TIMEOUT_SEC,
        )
        response.raise_for_status()
        
        data = response.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Parse JSON response with error handling
        import json
        import re
        
        try:
            # Try to extract JSON from response (in case LLM wraps it in markdown)
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content, re.DOTALL)
            if json_match:
                content = json_match.group(0)
            
            result = json.loads(content)
        except (json.JSONDecodeError, AttributeError) as e:
            logger.warning(f"Failed to parse LLM JSON response: {e}. Content: {content[:200]}")
            # Return fallback result
            return {
                "summary": "LLM response parsing failed",
                "confidence": 0.0,
                "tags": [],
            }
        
        # Validate and normalize
        confidence = result.get("confidence", 0.0)
        try:
            confidence = float(confidence)
            confidence = max(0.0, min(1.0, confidence))  # Clamp to [0, 1]
        except (ValueError, TypeError):
            logger.warning(f"Invalid confidence value: {confidence}, using 0.0")
            confidence = 0.0
        
        tags = result.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        
        return {
            "summary": result.get("summary", "LLM analysis failed"),
            "confidence": confidence,
            "tags": tags,
        }
    
    except Exception as e:
        logger.error(f"LLM analysis failed: {e}", exc_info=True)
        return {
            "summary": f"LLM error: {str(e)[:50]}",
            "confidence": 0.0,
            "tags": [],
        }

