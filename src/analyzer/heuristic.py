"""Heuristic scoring for alerts based on rule level and groups."""
from typing import Any, Dict

# Rule groups that indicate higher severity
HIGH_SEVERITY_GROUPS = {"authentication_failed", "bruteforce"}


def score(alert: Dict[str, Any]) -> float:
    """
    Calculate heuristic score for alert.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Score between 0.0 and 1.0
    """
    rule = alert.get("rule", {})
    rule_level = rule.get("level", 0)
    
    # Base score: rule.level / 15.0 (cap at 1.0)
    base_score = min(rule_level / 15.0, 1.0)
    
    # Bonus for high-severity rule groups
    rule_groups = rule.get("groups", [])
    if isinstance(rule_groups, str):
        rule_groups = [rule_groups]
    
    # Check intersection with high-severity groups
    has_high_severity = bool(set(rule_groups) & HIGH_SEVERITY_GROUPS)
    if has_high_severity:
        base_score = min(base_score + 0.1, 1.0)
    
    return base_score

