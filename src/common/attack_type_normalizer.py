"""
Attack Type Normalizer - Đảm bảo cùng một loại tấn công được đánh giá giống nhau
không phụ thuộc vào agent type (WebServer vs pfSense) hay rule IDs khác nhau.
"""
from typing import Dict, Any, Optional, List
import re


def normalize_attack_type(alert: Dict[str, Any]) -> Optional[str]:
    """
    Normalize attack type từ nhiều nguồn để đảm bảo cùng một loại tấn công
    được nhận diện giống nhau dù rule ID, description, hay agent type khác nhau.
    
    Priority:
    1. Tags (đã được normalize từ signature/category)
    2. Suricata signature keywords
    3. Rule description keywords
    4. Rule groups
    5. Alert category
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Normalized attack type string (e.g., "xss", "sql_injection", "command_injection")
        hoặc None nếu không phải attack
    """
    # Extract components
    tags = alert.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    
    rule = alert.get("rule", {})
    rule_description = rule.get("description", "").lower()
    rule_groups = rule.get("groups", [])
    if not isinstance(rule_groups, list):
        rule_groups = []
    
    suricata_alert = alert.get("suricata_alert", {})
    suricata_signature = ""
    suricata_category = ""
    if suricata_alert:
        suricata_signature = (suricata_alert.get("signature", "") or "").lower()
        suricata_category = (suricata_alert.get("category", "") or "").lower()
    
    http_context = alert.get("http", {})
    http_url = (http_context.get("url", "") or "").lower() if http_context else ""
    
    # Priority 1: Check tags (đã được normalize)
    attack_type_tags = {
        "xss": "xss",
        "sql_injection": "sql_injection",
        "sqlinjection": "sql_injection",
        "command_injection": "command_injection",
        "path_traversal": "path_traversal",
        "csrf": "csrf",
        "web_attack": "web_attack",
    }
    
    for tag in tags:
        tag_lower = tag.lower() if isinstance(tag, str) else str(tag).lower()
        if tag_lower in attack_type_tags:
            return attack_type_tags[tag_lower]
    
    # Priority 2: Check Suricata signature keywords
    signature_text = suricata_signature
    if signature_text:
        # XSS patterns
        xss_patterns = [
            r"xss", r"cross-site", r"cross site", r"<script", r"onerror=",
            r"javascript:", r"<img.*onerror", r"xss_r", r"xss_d"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in xss_patterns):
            return "xss"
        
        # SQL Injection patterns
        sql_patterns = [
            r"sql.*injection", r"sqli", r"union.*select", r"or.*1=1",
            r"select.*from", r"insert.*into", r"delete.*from"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in sql_patterns):
            return "sql_injection"
        
        # Command Injection patterns
        cmd_patterns = [
            r"command.*injection", r"cmd.*exec", r"/bin/(sh|bash)", r"cmd\.exe",
            r"system\(|exec\(|eval\(", r"shell.*execution"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in cmd_patterns):
            return "command_injection"
        
        # Path Traversal patterns
        path_patterns = [
            r"path.*traversal", r"\.\./", r"\.\.\\\\", r"directory.*traversal"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in path_patterns):
            return "path_traversal"
        
        # CSRF patterns
        csrf_patterns = [
            r"csrf", r"cross-site.*request.*forgery", r"cross site.*request.*forgery",
            r"unauthorized.*state.*change", r"missing.*referer", r"origin.*mismatch"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in csrf_patterns):
            return "csrf"
    
    # Priority 3: Check HTTP URL patterns
    if http_url:
        # XSS in URL
        if any(pattern in http_url for pattern in ["xss", "<script", "onerror=", "javascript:"]):
            return "xss"
        
        # SQL Injection in URL
        if any(pattern in http_url for pattern in ["union", "select", "or 1=1", "sqli"]):
            return "sql_injection"
        
        # Command Injection in URL
        if any(pattern in http_url for pattern in ["cmd=", "exec=", "/bin/", "system("]):
            return "command_injection"
        
        # CSRF in URL (less common, but possible)
        if any(pattern in http_url for pattern in ["csrf", "cross-site"]):
            return "csrf"
    
    # Priority 4: Check rule description
    if rule_description:
        # XSS
        if any(keyword in rule_description for keyword in ["xss", "cross-site", "cross site"]):
            return "xss"
        
        # SQL Injection
        if any(keyword in rule_description for keyword in ["sql injection", "sqli", "sql injection"]):
            return "sql_injection"
        
        # Command Injection
        if any(keyword in rule_description for keyword in ["command injection", "cmd injection"]):
            return "command_injection"
        
        # CSRF
        if any(keyword in rule_description for keyword in ["csrf", "cross-site request forgery", "cross site request forgery"]):
            return "csrf"
    
    # Priority 5: Check rule groups
    for group in rule_groups:
        group_lower = group.lower() if isinstance(group, str) else str(group).lower()
        if group_lower in attack_type_tags:
            return attack_type_tags[group_lower]
        elif "sql" in group_lower and "injection" in group_lower:
            return "sql_injection"
        elif "command" in group_lower and "injection" in group_lower:
            return "command_injection"
    
    # Priority 6: Check Suricata category
    if suricata_category:
        if "web application attack" in suricata_category:
            # Generic web attack - try to be more specific from signature
            if suricata_signature:
                if any(keyword in suricata_signature for keyword in ["xss", "cross-site"]):
                    return "xss"
                elif any(keyword in suricata_signature for keyword in ["sql", "sqli"]):
                    return "sql_injection"
            return "web_attack"
    
    return None


def get_attack_type_priority(attack_type: Optional[str]) -> int:
    """
    Get priority score for attack type (higher = more critical).
    Used to ensure consistent scoring across different agents.
    """
    if not attack_type:
        return 0
    
    priority_map = {
        "sql_injection": 10,      # Highest - can lead to data breach
        "command_injection": 10,   # Highest - can lead to RCE
        "xss": 8,                  # High - can steal sessions, inject malware
        "path_traversal": 7,       # High - can access sensitive files
        "csrf": 6,                 # Medium-High - can perform actions as user
        "web_attack": 5,           # Medium - generic web attack
    }
    
    return priority_map.get(attack_type, 0)


def normalize_attack_type_for_scoring(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add normalized attack type to alert for consistent scoring.
    This ensures same attack type gets same base score regardless of agent/rule.
    """
    attack_type = normalize_attack_type(alert)
    attack_priority = get_attack_type_priority(attack_type)
    
    # Add to alert for use in scoring
    if "attack_type_normalized" not in alert:
        alert["attack_type_normalized"] = attack_type
        alert["attack_priority"] = attack_priority
    
    return alert

