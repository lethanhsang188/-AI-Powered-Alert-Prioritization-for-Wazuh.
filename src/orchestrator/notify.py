"""n8n webhook notification for high-severity cases."""
import logging
from typing import Any, Dict, Optional

from ..common.config import N8N_WEBHOOK_URL, N8N_WEBHOOK_PUBLIC_URL
from ..common.web import RetrySession

logger = logging.getLogger(__name__)


def notify(alert: Dict[str, Any], triage: Dict[str, Any], case_id: Optional[str]) -> bool:
    """
    Send notification to n8n webhook if configured.
    
    Args:
        alert: Normalized alert dictionary
        triage: Triage result dictionary
        case_id: TheHive case ID (if created)
        
    Returns:
        True if notification sent (or skipped), False on error
    """
    if not N8N_WEBHOOK_URL:
        logger.debug("n8n webhook URL not configured, skipping notification")
        return True
    
    # Only notify for high-severity cases (score >= 0.7)
    score = triage.get("score", 0.0)
    if score < 0.7:
        logger.debug(f"Alert score {score} below threshold, skipping notification")
        return True
    
    payload = {
        "case_id": case_id,
        "score": score,
        "title": triage.get("title", ""),
        "summary": triage.get("summary", ""),
        "tags": triage.get("tags", []),
        "rule_id": alert.get("rule", {}).get("id", ""),
        "agent": alert.get("agent", {}).get("name", ""),
        "public_url": N8N_WEBHOOK_PUBLIC_URL,
    }
    
    try:
        session = RetrySession()
        response = session.request_with_backoff("POST", N8N_WEBHOOK_URL, json=payload)
        response.raise_for_status()
        logger.info(f"Sent notification to n8n webhook for case {case_id}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to send n8n notification: {e}", exc_info=True)
        return False

