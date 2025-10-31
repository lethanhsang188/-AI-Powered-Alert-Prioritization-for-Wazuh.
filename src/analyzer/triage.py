"""Fuse heuristic and LLM scores to produce final triage result."""
import logging
from typing import Any, Dict

from .heuristic import score as heuristic_score
from .llm import triage_llm
from ..common.config import HEURISTIC_WEIGHT, LLM_WEIGHT
from ..common.redaction import Redactor

logger = logging.getLogger(__name__)


def run(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run triage analysis on alert.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Dict with keys: title, score (0.0-1.0), summary, tags (list)
    """
    # Heuristic score
    h_score = heuristic_score(alert)
    
    # LLM analysis (with redaction if enabled)
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    message = alert.get("message", "")
    
    # Prepare text for LLM (redact PII)
    redactor = Redactor()
    alert_text = f"Rule ID: {rule.get('id', 'N/A')}, "
    alert_text += f"Level: {rule.get('level', 0)}, "
    alert_text += f"Message: {message}, "
    alert_text += f"Agent: {agent.get('name', 'N/A')}"
    
    redacted_text, _ = redactor.redact(alert_text)
    llm_result = triage_llm(redacted_text)
    
    # Fuse scores
    llm_confidence = llm_result.get("confidence", 0.0)
    final_score = (HEURISTIC_WEIGHT * h_score) + (LLM_WEIGHT * llm_confidence)
    final_score = max(0.0, min(1.0, final_score))  # Clamp [0, 1]
    
    # Build title
    rule_id = rule.get("id", "unknown")
    agent_name = agent.get("name", "unknown")
    title = f"[Auto-Triage] rule {rule_id} on {agent_name}"
    
    # Combine tags
    tags = llm_result.get("tags", [])
    
    logger.debug(
        f"Triage result: score={final_score:.2f} "
        f"(heuristic={h_score:.2f}, llm={llm_confidence:.2f})"
    )
    
    return {
        "title": title,
        "score": final_score,
        "summary": llm_result.get("summary", "No summary"),
        "tags": tags,
    }

