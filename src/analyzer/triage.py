"""Fuse heuristic and LLM scores to produce final triage result."""
import logging
import re
from typing import Any, Dict

from .heuristic import score as heuristic_score
from .llm import triage_llm
from src.common.config import HEURISTIC_WEIGHT, LLM_WEIGHT, CORRELATION_ENABLE, ENRICHMENT_ENABLE
from src.common.redaction import Redactor
from src.common.correlation import correlate_alert
from src.common.enrichment import enrich_alert
from src.common.fp_filtering import analyze_fp_risk
from src.common.attack_type_normalizer import normalize_attack_type, normalize_attack_type_for_scoring

logger = logging.getLogger(__name__)

# Threat level to score adjustment mapping
THREAT_LEVEL_ADJUSTMENTS = {
    "critical": 0.10,   # +10% for critical threats
    "high": 0.05,       # +5% for high threats
    "medium": 0.0,      # No adjustment
    "low": -0.05,       # -5% for low threats
    "none": -0.10,      # -10% for benign/noise
}


def run(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run triage analysis on alert.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Dict with keys: title, score (0.0-1.0), threat_level, summary, tags (list)
    """
    # Enrich alert with GeoIP and threat intelligence
    if ENRICHMENT_ENABLE:
        try:
            enrichment_data = enrich_alert(alert)
            # Add enrichment data to alert for later use
            alert["enrichment"] = enrichment_data
        except Exception as e:
            logger.debug(f"Enrichment failed: {e}", exc_info=True)
            alert["enrichment"] = {}
    
    # Correlate alert with existing groups
    correlation_info = {}
    if CORRELATION_ENABLE:
        try:
            correlation_info = correlate_alert(alert)
            alert["correlation"] = correlation_info
        except Exception as e:
            logger.debug(f"Correlation failed: {e}", exc_info=True)
            correlation_info = {"is_correlated": False, "group_size": 1}
    
    # FP Filtering (SOC-grade: label, don't drop)
    fp_result = {}
    try:
        fp_result = analyze_fp_risk(alert, correlation_info)
        alert["fp_filtering"] = fp_result
    except Exception as e:
        logger.debug(f"FP filtering failed: {e}", exc_info=True)
        fp_result = {"fp_risk": "LOW", "fp_reason": [], "allowlist_hit": False, "noise_signals": []}
    
    # Normalize attack type BEFORE scoring to ensure consistency across agents
    alert = normalize_attack_type_for_scoring(alert)
    normalized_attack_type = alert.get("attack_type_normalized")
    
    # Extract alert components
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    message = alert.get("message", "")
    srcip = alert.get("srcip", "")
    user = alert.get("user", "")
    http_context = alert.get("http")
    suricata_alert = alert.get("suricata_alert")
    
    # Extract additional context from alert
    rule_id = str(rule.get("id", "N/A"))
    rule_level = rule.get("level", 0)
    rule_description = rule.get("description", "")
    rule_groups = rule.get("groups", [])
    mitre = rule.get("mitre", {})
    
    # Extract HTTP status code if available (for web attacks)
    http_status = None
    if http_context and http_context.get("status"):
        http_status = http_context.get("status")
    elif isinstance(message, str):
        # Fallback: Try to extract HTTP status code from message
        status_match = re.search(r'\b(?:HTTP/[\d.]+|Status:?)\s+(\d{3})\b', message, re.IGNORECASE)
        if status_match:
            http_status = status_match.group(1)
    
    # Heuristic score
    h_score = heuristic_score(alert)
    
    # Prepare enhanced text for LLM (redact PII)
    redactor = Redactor()
    alert_text = f"Rule ID: {rule_id}, "
    alert_text += f"Level: {rule_level}, "
    alert_text += f"Groups: {rule_groups}, "
    if rule_description:
        alert_text += f"Description: {rule_description}, "
    if mitre:
        mitre_ids = mitre.get("id", [])
        if mitre_ids:
            alert_text += f"MITRE ATT&CK: {mitre_ids}, "
    
    # Add Suricata alert context (signature ID, signature name, category)
    if suricata_alert:
        if suricata_alert.get("signature_id"):
            alert_text += f"Suricata Signature ID: {suricata_alert.get('signature_id')}, "
        if suricata_alert.get("signature"):
            alert_text += f"Suricata Signature: {suricata_alert.get('signature')}, "
        if suricata_alert.get("category"):
            alert_text += f"Suricata Category: {suricata_alert.get('category')}, "
    
    # Add HTTP context (critical for web attack detection)
    if http_context:
        if http_context.get("url"):
            alert_text += f"HTTP URL: {http_context.get('url')}, "
        if http_context.get("method"):
            alert_text += f"HTTP Method: {http_context.get('method')}, "
        if http_context.get("status"):
            alert_text += f"HTTP Status: {http_context.get('status')}, "
        if http_context.get("hostname"):
            alert_text += f"HTTP Hostname: {http_context.get('hostname')}, "
        if http_context.get("referer"):
            alert_text += f"HTTP Referer: {http_context.get('referer')}, "
        if http_context.get("user_agent"):
            alert_text += f"HTTP User-Agent: {http_context.get('user_agent')}, "
        if http_context.get("redirect"):
            alert_text += f"HTTP Redirect: {http_context.get('redirect')}, "  # 302 redirect (important for SOC)
    
    # Add network information (CRITICAL for SOC) - using top-level fields
    if alert.get("src_ip"):
        alert_text += f"Network Src IP: {alert.get('src_ip')}, "
    if alert.get("dest_ip"):
        alert_text += f"Network Dest IP: {alert.get('dest_ip')}, "
    if alert.get("src_port"):
        alert_text += f"Network Src Port: {alert.get('src_port')}, "
    if alert.get("dest_port"):
        alert_text += f"Network Dest Port: {alert.get('dest_port')}, "
    if alert.get("direction"):
        alert_text += f"Network Direction: {alert.get('direction')}, "
    if alert.get("proto"):
        alert_text += f"Network Protocol: {alert.get('proto')}, "
    if alert.get("app_proto"):
        alert_text += f"Network App Protocol: {alert.get('app_proto')}, "
    
    # Add flow statistics (IMPORTANT for SOC network analysis)
    flow_info = alert.get("flow")
    if flow_info:
        if flow_info.get("bytes_toserver"):
            alert_text += f"Flow Bytes to Server: {flow_info.get('bytes_toserver')}, "
        if flow_info.get("bytes_toclient"):
            alert_text += f"Flow Bytes to Client: {flow_info.get('bytes_toclient')}, "
        if flow_info.get("pkts_toserver"):
            alert_text += f"Flow Packets to Server: {flow_info.get('pkts_toserver')}, "
        if flow_info.get("pkts_toclient"):
            alert_text += f"Flow Packets to Client: {flow_info.get('pkts_toclient')}, "
    
    # Add Suricata alert action (IMPORTANT for SOC)
    if suricata_alert and suricata_alert.get("action"):
        alert_text += f"Suricata Action: {suricata_alert.get('action')}, "  # "allowed" vs "blocked"
    
    # Add rule firedtimes (IMPORTANT for correlation)
    rule_firedtimes = rule.get("firedtimes", "")
    if rule_firedtimes:
        alert_text += f"Rule Fired Times: {rule_firedtimes}, "
    
    # Add HTTP anomaly count (IMPORTANT for SOC)
    if alert.get("http_anomaly_count"):
        alert_text += f"HTTP Anomaly Count: {alert.get('http_anomaly_count')}, "
    
    alert_text += f"Message: {message}, "
    alert_text += f"Agent: {agent.get('name', 'N/A')}, "
    alert_text += f"Src IP: {srcip}, "
    alert_text += f"User: {user}"
    
    redacted_text, _ = redactor.redact(alert_text)
    
    # Prepare rule context for LLM (include normalized attack type for consistent analysis)
    rule_context = {
        "id": rule_id,
        "level": rule_level,
        "description": rule_description,
        "groups": rule_groups,
        "mitre": mitre,
        "normalized_attack_type": normalized_attack_type,  # Add normalized attack type
    }
    
    # LLM analysis with rule context
    llm_result = triage_llm(redacted_text, rule_context=rule_context)
    
    # Get threat_level from LLM result
    threat_level = llm_result.get("threat_level", "medium")
    llm_confidence = llm_result.get("confidence", 0.0)
    tags = llm_result.get("tags", [])
    
    # Boost LLM confidence for specific rule types if LLM correctly identified them
    # This rewards LLM for correctly recognizing critical attacks
    if rule_id == "31105" and "xss" in tags:
        # LLM correctly identified XSS → Boost confidence
        original_confidence = llm_confidence
        llm_confidence = min(llm_confidence + 0.15, 1.0)
        logger.debug(
            "Boosted LLM confidence for XSS detection",
            extra={
                "component": "triage",
                "action": "llm_confidence_boost",
                "rule_id": rule_id,
                "original_confidence": round(original_confidence, 3),
                "boosted_confidence": round(llm_confidence, 3),
                "reason": "LLM correctly identified XSS attack"
            }
        )
    elif (rule_id in ["31103", "31104"] or normalized_attack_type == "sql_injection") and "sql_injection" in tags:
        # LLM correctly identified SQL injection → Boost confidence
        original_confidence = llm_confidence
        llm_confidence = min(llm_confidence + 0.20, 1.0)
        logger.debug(
            "Boosted LLM confidence for SQL injection detection",
            extra={
                "component": "triage",
                "action": "llm_confidence_boost",
                "rule_id": rule_id,
                "original_confidence": round(original_confidence, 3),
                "boosted_confidence": round(llm_confidence, 3),
                "reason": "LLM correctly identified SQL injection attack"
            }
        )
    elif rule_id in ["100144", "100145", "100146"] and "command_injection" in tags:
        # LLM correctly identified command injection → Boost confidence
        original_confidence = llm_confidence
        llm_confidence = min(llm_confidence + 0.20, 1.0)
        logger.debug(
            "Boosted LLM confidence for command injection detection",
            extra={
                "component": "triage",
                "action": "llm_confidence_boost",
                "rule_id": rule_id,
                "original_confidence": round(original_confidence, 3),
                "boosted_confidence": round(llm_confidence, 3),
                "reason": "LLM correctly identified command injection attack"
            }
        )
    
    # Dynamic weighting based on confidence and rule level
    # If LLM confidence is very low, rely more on heuristic
    # If LLM confidence is very high, rely more on LLM
    if llm_confidence < 0.3:
        # Low LLM confidence: increase heuristic weight
        effective_h_weight = min(HEURISTIC_WEIGHT + 0.2, 0.9)
        effective_l_weight = max(LLM_WEIGHT - 0.2, 0.1)
    elif llm_confidence > 0.8:
        # High LLM confidence: increase LLM weight
        effective_h_weight = max(HEURISTIC_WEIGHT - 0.1, 0.3)
        effective_l_weight = min(LLM_WEIGHT + 0.1, 0.7)
    else:
        # Normal confidence: use default weights
        effective_h_weight = HEURISTIC_WEIGHT
        effective_l_weight = LLM_WEIGHT
    
    # Fuse scores with dynamic weighting
    fused_score = (effective_h_weight * h_score) + (effective_l_weight * llm_confidence)
    
    # Apply threat level adjustment
    threat_adjustment = THREAT_LEVEL_ADJUSTMENTS.get(threat_level, 0.0)
    final_score = fused_score + threat_adjustment
    
    # Clamp to [0, 1]
    final_score = max(0.0, min(1.0, final_score))
    
    # Tags already extracted above (before confidence boost)
    
    # Build title - use improved title from alert formatter if available
    from src.common.alert_formatter import format_alert_card
    try:
        alert_card = format_alert_card(alert, {
            "score": final_score,
            "threat_level": threat_level,
            "tags": tags,
            "summary": llm_result.get("summary", "")
        })
        title = alert_card.get("title", f"[Auto-Triage] rule {rule_id} on {agent.get('name', 'unknown')}")
    except Exception as e:
        # Fallback to simple title if formatter fails
        logger.debug(f"Alert formatter failed, using fallback title: {e}")
        agent_name = agent.get("name", "unknown")
        title = f"[Auto-Triage] rule {rule_id} on {agent_name}"
    
    # Extract context for logging
    agent_id = agent.get("id", "unknown")
    agent_name = agent.get("name", "unknown")
    
    logger.info(
        "Triage analysis completed",
        extra={
            "component": "triage",
            "action": "analysis_complete",
            "rule_id": rule_id,
            "rule_level": rule_level,
            "agent_name": agent_name,
            "agent_id": agent_id,
            "score": round(final_score, 3),
            "threat_level": threat_level,
            "heuristic_score": round(h_score, 3),
            "llm_confidence": round(llm_confidence, 3),
            "llm_threat_level": threat_level,
            "llm_tags": tags,
            "llm_summary": llm_result.get("summary", "")[:200],
            "threat_adjustment": round(THREAT_LEVEL_ADJUSTMENTS.get(threat_level, 0.0), 3),
            "effective_h_weight": round(effective_h_weight, 3),
            "effective_l_weight": round(effective_l_weight, 3),
            "tags_count": len(tags)
        }
    )
    
    return {
        "title": title,
        "score": final_score,
        "threat_level": threat_level,
        "summary": llm_result.get("summary", "No summary"),
        "tags": tags,
        "llm_confidence": llm_confidence,  # Include for override logic
    }

