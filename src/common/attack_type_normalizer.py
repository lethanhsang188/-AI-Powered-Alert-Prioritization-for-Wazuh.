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
        "lfi": "lfi",
        "local_file_inclusion": "lfi",
        "file_inclusion": "lfi",
        "file_upload": "file_upload",
        "webshell": "file_upload",
        "csrf": "csrf",
        "brute_force": "brute_force",
        "bruteforce": "brute_force",
        "ssh_bruteforce": "ssh_bruteforce",
        "auth_bruteforce": "brute_force",
        "syn_flood": "syn_flood",
        "dos": "dos",
        "ddos": "dos",
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
        
        # LFI (Local File Inclusion) patterns
        lfi_patterns = [
            r"local.*file.*inclusion", r"lfi", r"file.*inclusion", r"include.*file",
            r"php.*include", r"require.*file", r"\.\./.*etc/passwd", r"\.\./.*proc/self"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in lfi_patterns):
            return "lfi"
        
        # File Upload patterns
        file_upload_patterns = [
            r"file.*upload", r"webshell", r"suspicious.*upload", r"php.*upload",
            r"upload.*php", r"shell.*upload", r"malicious.*file"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in file_upload_patterns):
            return "file_upload"
        
        # CSRF patterns
        csrf_patterns = [
            r"csrf", r"cross-site.*request.*forgery", r"cross site.*request.*forgery",
            r"unauthorized.*state.*change", r"missing.*referer", r"origin.*mismatch"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in csrf_patterns):
            return "csrf"
        
        # Brute Force patterns
        brute_force_patterns = [
            r"brute.*force", r"bruteforce", r"authentication.*failed", r"login.*attempt",
            r"multiple.*failed.*login", r"password.*cracking"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in brute_force_patterns):
            return "brute_force"
        
        # SSH Brute Force patterns
        ssh_bruteforce_patterns = [
            r"ssh.*brute", r"ssh.*bruteforce", r"ssh.*authentication.*failed",
            r"sshd.*failed", r"invalid.*user.*ssh"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in ssh_bruteforce_patterns):
            return "ssh_bruteforce"
        
        # SYN Flood patterns
        syn_flood_patterns = [
            r"syn.*flood", r"synflood", r"tcp.*syn.*flood", r"possible.*syn.*flood",
            r"syn.*attack", r"connection.*flood"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in syn_flood_patterns):
            return "syn_flood"
        
        # DoS/DDoS patterns
        dos_patterns = [
            r"denial.*of.*service", r"dos", r"ddos", r"distributed.*denial",
            r"flood.*attack", r"http.*flood", r"tcp.*flood"
        ]
        if any(re.search(pattern, signature_text, re.IGNORECASE) for pattern in dos_patterns):
            return "dos"
    
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
        
        # LFI in URL
        if any(pattern in http_url for pattern in ["../", "..\\", "etc/passwd", "proc/self", "include=", "file="]):
            return "lfi"
        
        # File Upload in URL
        if any(pattern in http_url for pattern in ["upload", "file_upload", "fileupload", "webshell"]):
            return "file_upload"
        
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
        
        # LFI
        if any(keyword in rule_description for keyword in ["local file inclusion", "lfi", "file inclusion"]):
            return "lfi"
        
        # File Upload
        if any(keyword in rule_description for keyword in ["file upload", "suspicious upload", "webshell"]):
            return "file_upload"
        
        # CSRF
        if any(keyword in rule_description for keyword in ["csrf", "cross-site request forgery", "cross site request forgery"]):
            return "csrf"
        
        # Brute Force
        if any(keyword in rule_description for keyword in ["brute force", "bruteforce", "authentication failed", "login attempt"]):
            return "brute_force"
        
        # SSH Brute Force
        if any(keyword in rule_description for keyword in ["ssh brute", "ssh bruteforce", "ssh authentication failed"]):
            return "ssh_bruteforce"
        
        # SYN Flood
        if any(keyword in rule_description for keyword in ["syn flood", "synflood", "tcp syn flood"]):
            return "syn_flood"
        
        # DoS
        if any(keyword in rule_description for keyword in ["denial of service", "dos", "ddos", "flood attack"]):
            return "dos"
    
    # Priority 5: Check rule groups
    for group in rule_groups:
        group_lower = group.lower() if isinstance(group, str) else str(group).lower()
        if group_lower in attack_type_tags:
            return attack_type_tags[group_lower]
        elif "sql" in group_lower and "injection" in group_lower:
            return "sql_injection"
        elif "command" in group_lower and "injection" in group_lower:
            return "command_injection"
        elif "file" in group_lower and ("upload" in group_lower or "webshell" in group_lower):
            return "file_upload"
        elif ("file" in group_lower and "inclusion" in group_lower) or "lfi" in group_lower:
            return "lfi"
        elif ("brute" in group_lower or "bruteforce" in group_lower) and "ssh" in group_lower:
            return "ssh_bruteforce"
        elif "brute" in group_lower or "bruteforce" in group_lower or "authentication_failed" in group_lower:
            return "brute_force"
        elif "syn" in group_lower and "flood" in group_lower:
            return "syn_flood"
        elif "dos" in group_lower or "ddos" in group_lower:
            return "dos"
    
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
        "file_upload": 9,          # Very High - webshell upload can lead to RCE
        "lfi": 8,                  # High - can access sensitive files
        "xss": 8,                  # High - can steal sessions, inject malware
        "path_traversal": 7,       # High - can access sensitive files
        "dos": 7,                  # High - can cause service disruption
        "syn_flood": 7,            # High - DoS attack
        "ssh_bruteforce": 6,      # Medium-High - can lead to unauthorized access
        "brute_force": 6,          # Medium-High - can lead to account compromise
        "csrf": 6,                 # Medium-High - can perform actions as user
        "web_attack": 5,           # Medium - generic web attack
    }
    
    return priority_map.get(attack_type, 0)


def normalize_attack_type_for_scoring(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Thêm loại tấn công đã chuẩn hóa vào alert để tính điểm nhất quán.
    Điều này đảm bảo cùng một loại tấn công có cùng điểm cơ bản bất kể agent/rule.
    """
    attack_type = normalize_attack_type(alert)
    attack_priority = get_attack_type_priority(attack_type)
    
    # Add to alert for use in scoring
    if "attack_type_normalized" not in alert:
        alert["attack_type_normalized"] = attack_type
        alert["attack_priority"] = attack_priority
    
    return alert

