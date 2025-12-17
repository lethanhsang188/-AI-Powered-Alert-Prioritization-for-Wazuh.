"""Heuristic scoring for alerts based on rule level and groups."""
import logging
from typing import Any, Dict, Set
from src.common.attack_type_normalizer import normalize_attack_type, get_attack_type_priority

logger = logging.getLogger(__name__)

# Rule groups categorized by severity level
# Critical groups: Most severe attacks that require immediate attention
CRITICAL_GROUPS: Set[str] = {
    "sql_injection",
    "sqlinjection",
    "attack",  # General attack group (includes successful attacks)
}

# High groups: Serious security issues
HIGH_GROUPS: Set[str] = {
    "authentication_failed",
    "bruteforce",
    "web_attack",
    "web_scan",
    "recon",
    "ids",
    "suricata",
}

# Medium groups: Suspicious activities that need review
MEDIUM_GROUPS: Set[str] = {
    "web",
    "invalid_access",
}

# All severity groups combined
HIGH_SEVERITY_GROUPS = CRITICAL_GROUPS | HIGH_GROUPS | MEDIUM_GROUPS

# Rule IDs that indicate successful attacks (should have higher multiplier)
SUCCESSFUL_ATTACK_RULES = {
    "31106",  # Web attack returned 200 (success)
}

# Rule IDs that are frequency-based (multiple events from same source)
FREQUENCY_BASED_RULES = {
    "31151",  # Multiple web server 400 error codes
    "31152",  # Multiple SQL injection attempts
    "31153",  # Multiple common web attacks
    "31154",  # Multiple XSS attempts
    "31161",  # Multiple 501 errors
    "31162",  # Multiple 500 errors
    "31163",  # Multiple 503 errors
}

# XSS detection rules (should have higher priority)
XSS_RULES = {
    "31105",  # XSS detection
    "31154",  # Multiple XSS attempts
}


def _calculate_base_score(rule_level: int) -> float:
    """
    Calculate base score with non-linear curve for high levels.
    
    For levels 12-15, use steeper curve to better differentiate critical alerts.
    """
    if rule_level <= 0:
        return 0.0
    
    if rule_level >= 15:
        return 1.0
    
    # Non-linear scoring: higher levels get steeper curve
    if rule_level >= 12:
        # Levels 12-14: Use curve to push scores higher
        # Level 12: 0.80 -> 0.85, Level 13: 0.87 -> 0.90, Level 14: 0.93 -> 0.95
        normalized = (rule_level - 12) / 3.0  # 0.0 to 1.0 for levels 12-14
        return 0.80 + (normalized * 0.15)  # 0.80 to 0.95
    else:
        # Levels 1-11: Linear scaling
        return min(rule_level / 15.0, 1.0)


def _calculate_group_bonus(rule_groups: list) -> float:
    """
    Calculate bonus score based on rule groups with weighted severity.
    
    Returns:
        Bonus score (0.0 to 0.15)
    """
    if not rule_groups:
        return 0.0
    
    if isinstance(rule_groups, str):
        rule_groups = [rule_groups]
    
    groups_set = set(rule_groups)
    
    # Check for critical groups (highest priority)
    if groups_set & CRITICAL_GROUPS:
        return 0.15  # Highest bonus for critical attacks
    
    # Check for high groups
    if groups_set & HIGH_GROUPS:
        return 0.10  # Standard bonus for high-severity
    
    # Check for medium groups
    if groups_set & MEDIUM_GROUPS:
        return 0.05  # Lower bonus for medium-severity
    
    return 0.0


def _calculate_rule_specific_multiplier(rule_id: str, rule_level: int) -> float:
    """
    Calculate multiplier for specific rules that indicate higher severity.
    
    Returns:
        Multiplier (1.0 to 1.25)
    """
    multiplier = 1.0
    
    # Successful attacks get higher multiplier
    if rule_id in SUCCESSFUL_ATTACK_RULES:
        multiplier = 1.15  # 15% boost for successful attacks
    
    # XSS attacks are high priority (can steal sessions, inject malware)
    elif rule_id in XSS_RULES:
        multiplier = 1.20  # 20% boost for XSS attacks
    
    # Frequency-based rules indicate persistent attacks
    elif rule_id in FREQUENCY_BASED_RULES:
        multiplier = 1.10  # 10% boost for frequency-based detection
    
    return multiplier


def score(alert: Dict[str, Any]) -> float:
    """
    Calculate heuristic score for alert based on MULTIPLE indicators (field-based analysis).
    
    SOC Perspective: Don't rely only on rule level - analyze network flow, HTTP context,
    Suricata severity, correlation, and other indicators to detect attacks early.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Score between 0.0 and 1.0
    """
    rule = alert.get("rule", {})
    rule_level = rule.get("level", 0)
    rule_id = str(rule.get("id", ""))
    rule_groups = rule.get("groups", [])
    
    # Normalize attack type to ensure consistent scoring across agents
    attack_type = normalize_attack_type(alert)
    attack_priority = get_attack_type_priority(attack_type)
    
    # Base score with non-linear curve
    base_score = _calculate_base_score(rule_level)
    
    # Attack type bonus (ensures same attack type gets similar score regardless of agent/rule)
    if attack_type:
        # Add bonus based on attack type priority (normalized, not rule-specific)
        attack_bonus = attack_priority * 0.01  # 0.01-0.10 bonus based on attack type
        base_score += attack_bonus
        logger.debug(
            "Attack type normalized: %s (priority: %d, bonus: %.3f)",
            attack_type,
            attack_priority,
            attack_bonus,
            extra={
                "component": "heuristic",
                "action": "attack_type_normalized",
                "attack_type": attack_type,
                "attack_priority": attack_priority,
                "bonus": attack_bonus,
            },
        )
    
    # === FIELD-BASED BONUSES ===
    
    # 1. Suricata severity bonus (independent of rule level)
    suricata_alert = alert.get("suricata_alert", {})
    if suricata_alert:
        suricata_severity = suricata_alert.get("severity", 0)
        if isinstance(suricata_severity, (int, float)):
            if suricata_severity >= 3:
                base_score += 0.15  # High severity Suricata alert
            elif suricata_severity >= 2:
                base_score += 0.10  # Medium severity
        
        # Alert action bonus: "allowed" = attack passed through firewall (more dangerous)
        alert_action = suricata_alert.get("action", "")
        if alert_action == "allowed":
            base_score += 0.10  # Attack passed through firewall
    
    # 2. HTTP context bonus
    http_context = alert.get("http", {})
    if http_context:
        # Suspicious user agents (attack tools)
        user_agent = http_context.get("user_agent", "").lower()
        attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "w3af", "acunetix"]
        if any(tool in user_agent for tool in attack_tools):
            base_score += 0.15  # Attack tool detected
        
        # Suspicious status codes
        status = str(http_context.get("status", ""))
        if status == "200":
            base_score += 0.10  # Successful request (possible exploitation)
        elif status.startswith("5"):
            base_score += 0.05  # Server error (possible exploitation attempt)
        
        # Suspicious URL patterns
        url = http_context.get("url", "").lower()
        attack_patterns = ["sqli", "xss", "union", "select", "exec", "cmd", "shell", "eval", "base64"]
        if any(pattern in url for pattern in attack_patterns):
            base_score += 0.15  # Attack pattern in URL
    
    # 3. Network flow bonus
    flow = alert.get("flow", {})
    if flow:
        # High bytes/packets = potential data exfiltration or large response
        bytes_toclient = flow.get("bytes_toclient", 0)
        if isinstance(bytes_toclient, (int, float)) and bytes_toclient > 10000:
            base_score += 0.10  # Large response (possible data exfiltration)
        
        # High bytes to server = potential upload/exploitation
        bytes_toserver = flow.get("bytes_toserver", 0)
        if isinstance(bytes_toserver, (int, float)) and bytes_toserver > 5000:
            base_score += 0.05  # Large request (possible exploitation)
    
    # 4. Correlation bonus (multiple alerts from same source = attack campaign)
    correlation = alert.get("correlation", {})
    if correlation and correlation.get("is_correlated"):
        group_size = correlation.get("group_size", 1)
        if isinstance(group_size, (int, float)):
            if group_size >= 5:
                base_score += 0.20  # Large attack campaign
            elif group_size >= 3:
                base_score += 0.10  # Multiple attacks from same source
        
        # NEW: Supply chain attack bonus (multiple attack types from same source)
        supply_chain = correlation.get("supply_chain")
        if supply_chain and supply_chain.get("is_supply_chain"):
            attack_types_count = len(supply_chain.get("attack_types", []))
            severity = supply_chain.get("severity", "low")
            
            if severity == "high":
                base_score += 0.25  # High severity supply chain (3+ attack types or critical combo)
            elif severity == "medium":
                base_score += 0.15  # Medium severity supply chain (2 attack types)
            else:
                base_score += 0.10  # Low severity supply chain
            
            logger.debug(
                f"Supply chain attack bonus applied: {attack_types_count} attack types, severity={severity}",
                extra={
                    "component": "heuristic",
                    "action": "supply_chain_bonus",
                    "attack_types": supply_chain.get("attack_types", []),
                    "severity": severity,
                    "bonus": 0.25 if severity == "high" else (0.15 if severity == "medium" else 0.10)
                }
            )
    
    # Group-based bonus (existing)
    group_bonus = _calculate_group_bonus(rule_groups)
    base_score = min(base_score + group_bonus, 1.0)
    
    # Rule-specific multiplier (existing)
    multiplier = _calculate_rule_specific_multiplier(rule_id, rule_level)
    final_score = min(base_score * multiplier, 1.0)
    
    return final_score

