"""Heuristic scoring for alerts based on rule level and groups."""
import logging
from typing import Any, Dict, Set
from src.common.attack_type_normalizer import normalize_attack_type, get_attack_type_priority

logger = logging.getLogger(__name__)

# Các nhóm rule được phân loại theo mức độ nghiêm trọng
# Nhóm Critical: Các tấn công nghiêm trọng nhất cần xử lý ngay lập tức
CRITICAL_GROUPS: Set[str] = {
    "sql_injection",
    "sqlinjection",
    "attack",  # Nhóm tấn công chung (bao gồm các tấn công thành công)
}

# Nhóm High: Các vấn đề bảo mật nghiêm trọng
HIGH_GROUPS: Set[str] = {
    "authentication_failed",
    "bruteforce",
    "web_attack",
    "web_scan",
    "recon",
    "ids",
    "suricata",
}

# Nhóm Medium: Các hoạt động đáng ngờ cần xem xét
MEDIUM_GROUPS: Set[str] = {
    "web",
    "invalid_access",
}

# Tất cả các nhóm mức độ nghiêm trọng kết hợp
HIGH_SEVERITY_GROUPS = CRITICAL_GROUPS | HIGH_GROUPS | MEDIUM_GROUPS

# Rule IDs cho biết tấn công thành công (nên có multiplier cao hơn)
SUCCESSFUL_ATTACK_RULES = {
    "31106",  # Tấn công web trả về 200 (thành công)
}

# Rule IDs dựa trên tần suất (nhiều sự kiện từ cùng nguồn)
FREQUENCY_BASED_RULES = {
    "31151",  # Nhiều mã lỗi 400 từ web server
    "31152",  # Nhiều lần thử SQL injection
    "31153",  # Nhiều tấn công web phổ biến
    "31154",  # Nhiều lần thử XSS
    "31161",  # Nhiều lỗi 501
    "31162",  # Nhiều lỗi 500
    "31163",  # Nhiều lỗi 503
}

# Rules phát hiện XSS (nên có độ ưu tiên cao hơn)
XSS_RULES = {
    "31105",  # Phát hiện XSS
    "31154",  # Nhiều lần thử XSS
}


def _calculate_base_score(rule_level: int) -> float:
    """
    Tính điểm cơ bản với đường cong phi tuyến cho các mức cao.
    
    Đối với mức 12-15, sử dụng đường cong dốc hơn để phân biệt rõ hơn các cảnh báo quan trọng.
    """
    if rule_level <= 0:
        return 0.0
    
    if rule_level >= 15:
        return 1.0
    
    # Tính điểm phi tuyến: các mức cao hơn có đường cong dốc hơn
    if rule_level >= 12:
        # Mức 12-14: Sử dụng đường cong để đẩy điểm cao hơn
        # Mức 12: 0.80 -> 0.85, Mức 13: 0.87 -> 0.90, Mức 14: 0.93 -> 0.95
        normalized = (rule_level - 12) / 3.0  # 0.0 đến 1.0 cho mức 12-14
        return 0.80 + (normalized * 0.15)  # 0.80 đến 0.95
    else:
        # Mức 1-11: Tỷ lệ tuyến tính
        return min(rule_level / 15.0, 1.0)


def _calculate_group_bonus(rule_groups: list) -> float:
    """
    Tính điểm thưởng dựa trên các nhóm rule với trọng số mức độ nghiêm trọng.
    
    Returns:
        Điểm thưởng (0.0 đến 0.15)
    """
    if not rule_groups:
        return 0.0
    
    if isinstance(rule_groups, str):
        rule_groups = [rule_groups]
    
    groups_set = set(rule_groups)
    
    # Kiểm tra nhóm critical (ưu tiên cao nhất)
    if groups_set & CRITICAL_GROUPS:
        return 0.15  # Điểm thưởng cao nhất cho tấn công critical
    
    # Kiểm tra nhóm high
    if groups_set & HIGH_GROUPS:
        return 0.10  # Điểm thưởng chuẩn cho mức độ nghiêm trọng cao
    
    # Kiểm tra nhóm medium
    if groups_set & MEDIUM_GROUPS:
        return 0.05  # Điểm thưởng thấp hơn cho mức độ nghiêm trọng trung bình
    
    return 0.0


def _calculate_rule_specific_multiplier(rule_id: str, rule_level: int) -> float:
    """
    Tính multiplier cho các rule cụ thể cho thấy mức độ nghiêm trọng cao hơn.
    
    Returns:
        Multiplier (1.0 đến 1.25)
    """
    multiplier = 1.0
    
    # Tấn công thành công có multiplier cao hơn
    if rule_id in SUCCESSFUL_ATTACK_RULES:
        multiplier = 1.15  # Tăng 15% cho tấn công thành công
    
    # Tấn công XSS có độ ưu tiên cao (có thể đánh cắp session, inject malware)
    elif rule_id in XSS_RULES:
        multiplier = 1.20  # Tăng 20% cho tấn công XSS
    
    # Rules dựa trên tần suất cho thấy tấn công dai dẳng
    elif rule_id in FREQUENCY_BASED_RULES:
        multiplier = 1.10  # Tăng 10% cho phát hiện dựa trên tần suất
    
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
    
    # Chuẩn hóa loại tấn công để đảm bảo tính điểm nhất quán giữa các agent
    attack_type = normalize_attack_type(alert)
    attack_priority = get_attack_type_priority(attack_type)
    
    # Điểm cơ bản với đường cong phi tuyến
    base_score = _calculate_base_score(rule_level)
    
    # Điểm thưởng loại tấn công (đảm bảo cùng loại tấn công có điểm tương tự bất kể agent/rule)
    if attack_type:
        # Thêm điểm thưởng dựa trên độ ưu tiên loại tấn công (đã chuẩn hóa, không phụ thuộc rule)
        attack_bonus = attack_priority * 0.01  # Điểm thưởng 0.01-0.10 dựa trên loại tấn công
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
    
    # === ĐIỂM THƯỞNG DỰA TRÊN TRƯỜNG ===
    
    # 1. Điểm thưởng mức độ nghiêm trọng Suricata (độc lập với rule level)
    suricata_alert = alert.get("suricata_alert", {})
    if suricata_alert:
        suricata_severity = suricata_alert.get("severity", 0)
        if isinstance(suricata_severity, (int, float)):
            if suricata_severity >= 3:
                base_score += 0.15  # Cảnh báo Suricata mức độ cao
            elif suricata_severity >= 2:
                base_score += 0.10  # Mức độ trung bình
        
        # Điểm thưởng hành động cảnh báo: "allowed" = tấn công đã vượt qua firewall (nguy hiểm hơn)
        alert_action = suricata_alert.get("action", "")
        if alert_action == "allowed":
            base_score += 0.10  # Tấn công đã vượt qua firewall
    
    # 2. Điểm thưởng ngữ cảnh HTTP
    http_context = alert.get("http", {})
    if http_context:
        # User agent đáng ngờ (công cụ tấn công)
        user_agent = http_context.get("user_agent", "").lower()
        attack_tools = ["sqlmap", "nmap", "nikto", "burp", "metasploit", "w3af", "acunetix"]
        if any(tool in user_agent for tool in attack_tools):
            base_score += 0.15  # Phát hiện công cụ tấn công
        
        # Mã trạng thái đáng ngờ
        status = str(http_context.get("status", ""))
        if status == "200":
            base_score += 0.10  # Yêu cầu thành công (có thể bị khai thác)
        elif status.startswith("5"):
            base_score += 0.05  # Lỗi server (có thể là nỗ lực khai thác)
        
        # Mẫu URL đáng ngờ
        url = http_context.get("url", "").lower()
        attack_patterns = ["sqli", "xss", "union", "select", "exec", "cmd", "shell", "eval", "base64"]
        if any(pattern in url for pattern in attack_patterns):
            base_score += 0.15  # Mẫu tấn công trong URL
    
    # 3. Điểm thưởng luồng mạng
    flow = alert.get("flow", {})
    if flow:
        # Bytes/packets cao = có thể là rò rỉ dữ liệu hoặc phản hồi lớn
        bytes_toclient = flow.get("bytes_toclient", 0)
        if isinstance(bytes_toclient, (int, float)) and bytes_toclient > 10000:
            base_score += 0.10  # Phản hồi lớn (có thể là rò rỉ dữ liệu)
        
        # Bytes đến server cao = có thể là upload/khai thác
        bytes_toserver = flow.get("bytes_toserver", 0)
        if isinstance(bytes_toserver, (int, float)) and bytes_toserver > 5000:
            base_score += 0.05  # Yêu cầu lớn (có thể là khai thác)
    
    # 4. Điểm thưởng tương quan (nhiều cảnh báo từ cùng nguồn = chiến dịch tấn công)
    correlation = alert.get("correlation", {})
    if correlation and correlation.get("is_correlated"):
        group_size = correlation.get("group_size", 1)
        if isinstance(group_size, (int, float)):
            if group_size >= 5:
                base_score += 0.20  # Chiến dịch tấn công lớn
            elif group_size >= 3:
                base_score += 0.10  # Nhiều tấn công từ cùng nguồn
        
        # MỚI: Điểm thưởng tấn công chuỗi cung ứng (nhiều loại tấn công từ cùng nguồn)
        supply_chain = correlation.get("supply_chain")
        if supply_chain and supply_chain.get("is_supply_chain"):
            attack_types_count = len(supply_chain.get("attack_types", []))
            severity = supply_chain.get("severity", "low")
            
            if severity == "high":
                base_score += 0.25  # Chuỗi cung ứng mức độ cao (3+ loại tấn công hoặc kết hợp critical)
            elif severity == "medium":
                base_score += 0.15  # Chuỗi cung ứng mức độ trung bình (2 loại tấn công)
            else:
                base_score += 0.10  # Chuỗi cung ứng mức độ thấp
            
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
    
    # Điểm thưởng dựa trên nhóm (hiện có)
    group_bonus = _calculate_group_bonus(rule_groups)
    base_score = min(base_score + group_bonus, 1.0)
    
    # Multiplier cụ thể cho rule (hiện có)
    multiplier = _calculate_rule_specific_multiplier(rule_id, rule_level)
    final_score = min(base_score * multiplier, 1.0)
    
    return final_score

