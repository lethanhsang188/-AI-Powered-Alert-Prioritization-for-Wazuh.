"""False Positive Filtering Module - SOC-grade filtering with labeling (no silent drops)."""
import logging
from typing import Any, Dict, List, Optional, Tuple
from ipaddress import ip_address, AddressValueError

from src.common.config import SOC_MIN_LEVEL, SOC_MAX_LEVEL, INCLUDE_RULE_IDS, INCLUDE_RULE_ID_PREFIX

logger = logging.getLogger(__name__)

# Các signature lành tính phổ biến (có thể mở rộng qua config)
BENIGN_SIGNATURES = [
    "health-check",
    "monitoring",
    "keepalive",
    "heartbeat",
    "status-check",
]

# Các user agent lành tính phổ biến
BENIGN_USER_AGENTS = [
    "healthcheck",
    "monitoring",
    "uptime",
    "pingdom",
    "newrelic",
]


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal (RFC 1918)."""
    if not ip:
        return False
    
    try:
        addr = ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (ValueError, AddressValueError):
        # Fallback: kiểm tra đơn giản
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            # Dải IP private theo RFC 1918
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            # Localhost
            if first == 127:
                return True
        except ValueError:
            return False
        return False


def analyze_fp_risk(alert: Dict[str, Any], correlation_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Analyze false positive risk for alert.
    
    SOC Perspective: Label alerts with FP risk, but DO NOT drop silently.
    Even HIGH FP risk alerts should be analyzed by AI, but with context.
    
    Args:
        alert: Normalized alert dictionary
        correlation_info: Optional correlation info (for repetition detection)
        
    Returns:
        Dict with keys:
        - fp_risk: "LOW" | "MEDIUM" | "HIGH"
        - fp_reason: List of reasons
        - allowlist_hit: bool
        - noise_signals: List of noise indicators
    """
    fp_reasons: List[str] = []
    noise_signals: List[str] = []
    allowlist_hit = False
    
    # Trích xuất các trường
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    http_context = alert.get("http") or {}
    suricata_alert = alert.get("suricata_alert") or {}
    source = alert.get("source", {})
    src_ip = source.get("ip", "") or alert.get("srcip", "")
    
    # Special handling for pfSense Suricata rule 20101: inspect firedtimes, full_log, UA, action, payload indicators
    try:
        rule_id_val = str(rule.get("id", "") or "")
    except Exception:
        rule_id_val = ""
    try:
        firedtimes_val = int(rule.get("firedtimes", 0) or 0)
    except Exception:
        firedtimes_val = 0
    # raw/full log may be in different places depending on normalization
    raw_full_log = ""
    try:
        raw_full_log = (alert.get("raw", {}) or {}).get("full_log", "") or (alert.get("full_data", {}) or {}).get("full_log", "") or (alert.get("raw_json", {}) or {}).get("full_log", "") or ""
    except Exception:
        raw_full_log = ""
    http_ua = (http_context.get("user_agent") or "").lower() if http_context else ""
    suricata_action = (suricata_alert.get("action") or "").lower() if suricata_alert else ""

    # If this is the pfSense Suricata IDS rule 20101, do targeted checks to avoid false negatives
    if rule_id_val == "20101":
        indicators_found: List[str] = []
        # Keywords to consider as strong attack indicators
        indicator_keywords = [
            "sqlmap", "union select", "select ", " or ", "sleep(", "benchmark(", "' or '1'='1",
            "xss", "cross-site", "csrf", "syn flood", "synflood", "synn", "brute", "hydra", "ssh", "sql injection", "sqli"
        ]
        search_text = " ".join([raw_full_log or "", http_ua or "", suricata_action or "", str(alert.get("message", "") or "")]).lower()
        for kw in indicator_keywords:
            if kw in search_text:
                indicators_found.append(f"kw:{kw}")

        # firedtimes threshold - repeated firings increase confidence
        if firedtimes_val and firedtimes_val >= 3:
            indicators_found.append(f"firedtimes:{firedtimes_val}")

        # external source indicator
        if src_ip and not _is_internal_ip(src_ip):
            indicators_found.append("external_src")

        # If any indicators found -> treat as likely TRUE positive (do not add FP reasons)
        if indicators_found:
            noise_signals.append("20101_indicators:" + ",".join(indicators_found))
        else:
            # No clear indicators -> mark as potential noise but still allow analysis downstream
            fp_reasons.append("20101_no_indicators_possible_noise")
            noise_signals.append("20101_no_indicators")
    
    # Kiểm tra 1: IP nội bộ + HTTP 404 = Có thể là false positive từ internal scan
    if src_ip and _is_internal_ip(src_ip):
        if http_context and http_context.get("status") == "404":
            fp_reasons.append("IP nội bộ với HTTP 404 (có thể là internal scan)")
            noise_signals.append("internal_scan_404")
    
    # Kiểm tra 2: Signature lành tính
    signature = suricata_alert.get("signature", "") if suricata_alert else ""
    if signature:
        signature_lower = signature.lower()
        for benign_sig in BENIGN_SIGNATURES:
            if benign_sig.lower() in signature_lower:
                fp_reasons.append(f"Mẫu signature lành tính: {benign_sig}")
                noise_signals.append(f"benign_signature_{benign_sig}")
    
    # Kiểm tra 3: User agent lành tính
    user_agent = http_context.get("user_agent", "") if http_context else ""
    if user_agent:
        user_agent_lower = user_agent.lower()
        for benign_ua in BENIGN_USER_AGENTS:
            if benign_ua.lower() in user_agent_lower:
                fp_reasons.append(f"User agent lành tính: {benign_ua}")
                noise_signals.append(f"benign_user_agent_{benign_ua}")
    
    # Kiểm tra 4: Lặp lại (cùng signature từ cùng nguồn trong thời gian ngắn)
    if correlation_info and correlation_info.get("is_correlated"):
        group_size = correlation_info.get("group_size", 1)
        if group_size >= 10:
            fp_reasons.append(f"Lặp lại cao: {group_size} alerts từ cùng nguồn (có thể là noise)")
            noise_signals.append("high_repetition")
        elif group_size >= 5:
            fp_reasons.append(f"Lặp lại vừa: {group_size} alerts từ cùng nguồn")
            noise_signals.append("moderate_repetition")
    
    # Kiểm tra 5: Mẫu Cron/Job (nếu message chứa từ khóa cron)
    message = alert.get("message", "")
    if message:
        message_lower = message.lower()
        cron_keywords = ["cron", "scheduled task", "job", "at job"]
        for keyword in cron_keywords:
            if keyword in message_lower:
                fp_reasons.append(f"Phát hiện mẫu cron/job: {keyword}")
                noise_signals.append("cron_job_pattern")
    
    # Xác định mức độ rủi ro FP
    fp_risk = "LOW"
    if len(fp_reasons) >= 3 or any("high_repetition" in ns for ns in noise_signals):
        fp_risk = "HIGH"
    elif len(fp_reasons) >= 2 or any("moderate_repetition" in ns for ns in noise_signals):
        fp_risk = "MEDIUM"
    elif len(fp_reasons) >= 1:
        fp_risk = "LOW"
    
    return {
        "fp_risk": fp_risk,
        "fp_reason": fp_reasons,
        "allowlist_hit": allowlist_hit,
        "noise_signals": noise_signals,
    }

