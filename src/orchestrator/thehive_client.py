"""TheHive client for case creation and updates."""
import logging
from typing import Any, Dict, Optional, Tuple

from ..common.config import THEHIVE_URL, THEHIVE_API_KEY
from ..common.dedup import dedup_key
from ..common.web import RetrySession

logger = logging.getLogger(__name__)


class TheHiveClient:
    """Client for TheHive API."""
    
    def __init__(self):
        self.base_url = THEHIVE_URL.rstrip("/")
        self.session = RetrySession()
        self.session.headers.update({
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json",
        })
    
    def _search_case_by_dedup_key(self, dk: str) -> Optional[str]:
        """
        Search for existing open case with dedup key tag.
        
        Args:
            dk: Deduplication key
            
        Returns:
            Case ID if found, None otherwise
        """
        url = f"{self.base_url}/api/case/_search"
        # TheHive query DSL: find open cases with matching dedup key tag
        query = {
            "query": {
                "_and": [
                    {"_in": {"_field": "tags", "_values": [dk]}},
                    {"_eq": {"_field": "status", "_value": "Open"}}
                ]
            }
        }
        
        try:
            response = self.session.request_with_backoff("POST", url, json=query)
            response.raise_for_status()
            
            cases = response.json()
            if cases and len(cases) > 0:
                return cases[0].get("id")
            return None
        
        except Exception as e:
            logger.warning(f"Failed to search case: {e}")
            return None
    
    def _create_case(
        self,
        title: str,
        severity: int,
        tags: list,
        description: str,
    ) -> Optional[str]:
        """
        Create new case in TheHive.
        
        Args:
            title: Case title
            severity: Severity (1-4, where 4 is Critical)
            tags: List of tags
            description: Case description
            
        Returns:
            Case ID if successful, None otherwise
        """
        url = f"{self.base_url}/api/case"
        payload = {
            "title": title,
            "description": description,
            "tlp": 2,  # TLP Amber
            "severity": severity,
            "tags": tags,
            "flag": severity >= 3,  # Flag high/critical cases
        }
        
        try:
            response = self.session.request_with_backoff("POST", url, json=payload)
            response.raise_for_status()
            
            case = response.json()
            case_id = case.get("id")
            logger.info(f"Created TheHive case {case_id}: {title}")
            return case_id
        
        except Exception as e:
            logger.error(f"Failed to create case: {e}", exc_info=True)
            return None
    
    def _update_case(self, case_id: str, alert: Dict[str, Any], triage: Dict[str, Any]) -> bool:
        """
        Add task/comment to existing case.
        
        Args:
            case_id: TheHive case ID
            alert: Alert dictionary
            triage: Triage result dictionary
            
        Returns:
            True if successful
        """
        url = f"{self.base_url}/api/case/{case_id}/task"
        message = alert.get("message", "")
        
        payload = {
            "title": f"New alert: {triage.get('title', 'Unknown')}",
            "description": f"Alert: {message}\n\nTriage: {triage.get('summary', '')}",
        }
        
        try:
            response = self.session.request_with_backoff("POST", url, json=payload)
            response.raise_for_status()
            logger.info(f"Added task to TheHive case {case_id}")
            return True
        
        except Exception as e:
            logger.warning(f"Failed to add task to case: {e}")
            return False
    
    def create_or_update(
        self,
        alert: Dict[str, Any],
        triage: Dict[str, Any],
    ) -> Tuple[Optional[str], bool]:
        """
        Create or update case in TheHive based on dedup key.
        
        Args:
            alert: Normalized alert dictionary
            triage: Triage result dictionary
            
        Returns:
            (case_id, created_bool) tuple
        """
        # Compute dedup key
        dk = dedup_key(alert)
        
        # Search for existing case
        case_id = self._search_case_by_dedup_key(dk)
        
        if case_id:
            # Update existing case
            self._update_case(case_id, alert, triage)
            return (case_id, False)
        
        # Create new case
        title = triage.get("title", "Security Alert")
        score = triage.get("score", 0.0)
        
        # Map score to severity: >=0.85 = Critical (4), >=0.7 = High (3), else Medium (2)
        if score >= 0.85:
            severity = 4
        elif score >= 0.7:
            severity = 3
        else:
            severity = 2
        
        # Build tags
        tags = ["auto", "ai-apw", dk] + triage.get("tags", [])
        
        description = f"""
Alert Analysis Score: {score:.2f}

Summary: {triage.get('summary', 'N/A')}

Alert Details:
- Rule ID: {alert.get('rule', {}).get('id', 'N/A')}
- Level: {alert.get('rule', {}).get('level', 0)}
- Message: {alert.get('message', 'N/A')}
- Agent: {alert.get('agent', {}).get('name', 'N/A')}
- Source IP: {alert.get('srcip', 'N/A')}
"""
        
        case_id = self._create_case(title, severity, tags, description)
        return (case_id, True)

