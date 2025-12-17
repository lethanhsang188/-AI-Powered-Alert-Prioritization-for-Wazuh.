"""False Positive Filtering Module - SOC-grade filtering with labeling (no silent drops)."""
import logging
from typing import Any, Dict, List, Optional, Tuple
from ipaddress import ip_address, AddressValueError

from src.common.config import SOC_MIN_LEVEL, SOC_MAX_LEVEL, INCLUDE_RULE_IDS, INCLUDE_RULE_ID_PREFIX

logger = logging.getLogger(__name__)

# Common benign signatures (can be extended via config)
BENIGN_SIGNATURES = [
    "health-check",
    "monitoring",
    "keepalive",
    "heartbeat",
    "status-check",
]

# Common benign user agents
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
        # Fallback to simple check
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            # RFC 1918 private ranges
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
    
    # Extract fields
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    http_context = alert.get("http") or {}
    suricata_alert = alert.get("suricata_alert") or {}
    source = alert.get("source", {})
    src_ip = source.get("ip", "") or alert.get("srcip", "")
    
    # Check 1: Internal IP + HTTP 404 = Likely false positive from internal scan
    if src_ip and _is_internal_ip(src_ip):
        if http_context and http_context.get("status") == "404":
            fp_reasons.append("Internal IP with HTTP 404 (likely internal scan)")
            noise_signals.append("internal_scan_404")
    
    # Check 2: Benign signatures
    signature = suricata_alert.get("signature", "") if suricata_alert else ""
    if signature:
        signature_lower = signature.lower()
        for benign_sig in BENIGN_SIGNATURES:
            if benign_sig.lower() in signature_lower:
                fp_reasons.append(f"Benign signature pattern: {benign_sig}")
                noise_signals.append(f"benign_signature_{benign_sig}")
    
    # Check 3: Benign user agents
    user_agent = http_context.get("user_agent", "") if http_context else ""
    if user_agent:
        user_agent_lower = user_agent.lower()
        for benign_ua in BENIGN_USER_AGENTS:
            if benign_ua.lower() in user_agent_lower:
                fp_reasons.append(f"Benign user agent: {benign_ua}")
                noise_signals.append(f"benign_user_agent_{benign_ua}")
    
    # Check 4: Repetition (same signature from same source in short time)
    if correlation_info and correlation_info.get("is_correlated"):
        group_size = correlation_info.get("group_size", 1)
        if group_size >= 10:
            fp_reasons.append(f"High repetition: {group_size} alerts from same source (possible noise)")
            noise_signals.append("high_repetition")
        elif group_size >= 5:
            fp_reasons.append(f"Moderate repetition: {group_size} alerts from same source")
            noise_signals.append("moderate_repetition")
    
    # Check 5: Cron/Job patterns (if message contains cron keywords)
    message = alert.get("message", "")
    if message:
        message_lower = message.lower()
        cron_keywords = ["cron", "scheduled task", "job", "at job"]
        for keyword in cron_keywords:
            if keyword in message_lower:
                fp_reasons.append(f"Cron/job pattern detected: {keyword}")
                noise_signals.append("cron_job_pattern")
    
    # Determine FP risk level
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

